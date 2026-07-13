"""Cross-platform I/O backend for the runtime rings.

The runtime rings (rx_ring/tx_ring) and the socket layer call into this module instead of
``os.eventfd`` / ``os.read`` / ``os.writev`` directly. Those are Linux-specific: ``os.eventfd``
is Linux-only, and on Windows ``os.read`` / ``os.writev`` cannot touch a socket handle. Routing
the operations through here lets the stack run on macOS/Windows without an embedding host having
to monkeypatch the ``os`` module process-globally.

Fast path: on Linux with a real fd, every call delegates straight to ``os.*`` — no overhead.
On macOS/Windows the wakeup ``eventfd`` is emulated (non-blocking pipe, or socketpair where
``select`` only accepts sockets), and interface I/O for fds registered via
:func:`register_interface_fd` is routed through the socket's ``recv`` / ``sendall``.
"""

from __future__ import annotations

import errno
import os
import socket
from contextlib import suppress

EFD_NONBLOCK = getattr(os, "EFD_NONBLOCK", 0o4000)
EFD_CLOEXEC = getattr(os, "EFD_CLOEXEC", 0o2000000)


def needs_socket_io() -> bool:
    """Whether interface I/O must go through sockets rather than ``os.read`` / ``os.writev``.

    True on Windows (``os.writev`` is absent and ``os.read`` can't touch a socket handle). Set
    ``PYTCP_FORCE_SOCK_IO=1`` to exercise this path on Unix without a Windows box.
    """
    return os.name == "nt" or os.environ.get("PYTCP_FORCE_SOCK_IO") == "1"


# --- interface fd I/O ---------------------------------------------------------------------
_interface_fds: dict[int, socket.socket] = {}


def register_interface_fd(sock: socket.socket) -> None:
    """Route :func:`read` / :func:`writev` for ``sock``'s fd through the socket itself.
    No-op unless on the socket-I/O path."""
    if needs_socket_io():
        _interface_fds[sock.fileno()] = sock


def unregister_interface_fd(sock: socket.socket) -> None:
    """Drop ``sock`` (call before closing it, while the fileno is still valid)."""
    _interface_fds.pop(sock.fileno(), None)


def sock_for_fd(fd: int) -> socket.socket | None:
    """The registered socket backing ``fd`` on the socket-I/O path, else None. The runtime
    rings use this to pick their asyncio strategy: ``loop.sock_recv`` / ``loop.sock_sendall``
    for a registered socket (works on proactor loops), ``loop.add_reader`` / ``add_writer``
    on a plain fd."""
    return _interface_fds.get(fd)


def set_nonblocking(fd: int) -> None:
    """Put a plain fd into non-blocking mode (the rings' add_reader/add_writer path requires
    it). Registered sockets are switched via ``sock.setblocking`` by the caller instead."""
    os.set_blocking(fd, False)


def read(fd: int, n: int) -> bytes:
    sock = _interface_fds.get(fd)
    return sock.recv(n) if sock is not None else os.read(fd, n)


def writev(fd: int, buffers) -> int:
    sock = _interface_fds.get(fd)
    if sock is not None:
        data = b"".join(buffers)
        sock.sendall(data)
        return len(data)
    # Call-time lookup (not an import-time snapshot) so tests patching os.writev
    # keep working. os.writev is POSIX-only; landing here without it means fd is
    # gone from _interface_fds — i.e. unregister_interface_fd() already ran
    # (interface teardown) while a producer was still transmitting, e.g. the RSTs
    # stop()'s socket-abort walk emits. Raise the same closed-fd OSError the
    # os.writev path produces after teardown on POSIX, so callers' OSError
    # drop-handling applies, instead of an AttributeError that kills the TX Ring
    # worker (doronz88/pymobiledevice3#1756).
    os_writev = getattr(os, "writev", None)
    if os_writev is None:
        raise OSError(errno.EBADF, f"fd {fd} is not registered for socket I/O and os.writev is unavailable")
    return os_writev(fd, buffers)


# --- eventfd wakeup -----------------------------------------------------------------------
_HAVE_EVENTFD = hasattr(os, "eventfd") and not needs_socket_io()
_sock_pairs: dict[int, tuple[socket.socket, socket.socket]] = {}
_pipe_write_ends: dict[int, int] = {}


def eventfd(initval: int = 0, flags: int = 0) -> int:
    """A selectable wakeup fd. Real ``os.eventfd`` on Linux; non-blocking pipe / socketpair
    fallback elsewhere. Returns an int fileno usable with ``select`` / ``selectors``."""
    if _HAVE_EVENTFD:
        return os.eventfd(initval, flags)
    if needs_socket_io():
        r, w = socket.socketpair()
        r.setblocking(False)
        _sock_pairs[r.fileno()] = (r, w)
        for _ in range(initval):
            with suppress(OSError):
                w.send(b"\x01")
        return r.fileno()
    r_fd, w_fd = os.pipe()
    os.set_blocking(r_fd, False)
    os.set_blocking(w_fd, False)
    _pipe_write_ends[r_fd] = w_fd
    for _ in range(initval):
        with suppress(BlockingIOError):
            os.write(w_fd, b"\x01")
    return r_fd


def eventfd_write(fd: int, value: int = 1) -> None:
    if _HAVE_EVENTFD:
        os.eventfd_write(fd, value)
    elif fd in _sock_pairs:
        with suppress(OSError):  # already signaled / closed
            _sock_pairs[fd][1].send(b"\x01")
    else:
        with suppress(BlockingIOError):  # already signaled
            os.write(_pipe_write_ends[fd], b"\x01")


def eventfd_read(fd: int) -> int:
    if _HAVE_EVENTFD:
        return os.eventfd_read(fd)
    if fd in _sock_pairs:
        reader: socket.socket = _sock_pairs[fd][0]
        total = 0
        try:
            while True:
                chunk = reader.recv(4096)
                if not chunk:
                    break
                total += len(chunk)
        except (BlockingIOError, OSError):
            pass
        return total or 1
    total = 0
    try:
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            total += len(chunk)
    except BlockingIOError:
        pass
    return total or 1


def eventfd_close(fd: int) -> None:
    """Close a wakeup fd from :func:`eventfd`, including the hidden write end of the fallback
    pipe/socketpair (so neither leaks)."""
    if _HAVE_EVENTFD:
        os.close(fd)
        return
    if fd in _sock_pairs:
        for s in _sock_pairs.pop(fd):
            with suppress(OSError):
                s.close()
        return
    w_fd = _pipe_write_ends.pop(fd, None)
    for x in (fd, w_fd):
        if x is not None:
            with suppress(OSError):
                os.close(x)
