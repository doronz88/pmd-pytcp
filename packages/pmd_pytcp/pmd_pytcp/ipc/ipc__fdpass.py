################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains the IPC SCM_RIGHTS file-descriptor-passing primitive.

The data plane gives each client socket its own real, selectable fd: the
daemon creates a socketpair and passes one end to the client over the
control channel via an SCM_RIGHTS ancillary message. This module is that
transfer — a length-prefixed frame whose 4-byte prefix 'sendmsg' carries
exactly one descriptor, the payload following as a normal stream. The
receiver 'recvmsg's the prefix to capture the descriptor, then reads the
payload. Pinning the descriptor to the fixed-size prefix keeps capture
independent of the payload length.

Pure-asyncio transport ('docs/refactor/pure_asyncio.md'): asyncio
streams cannot carry ancillary data ('StreamReader' buffering drops
SCM_RIGHTS on the floor), so the descriptor-bearing prefix rides a raw
non-blocking 'sendmsg' / 'recvmsg' on the connection socket. On the
sending (daemon) side the connection is otherwise owned by a
'StreamWriter' transport; the raw 'sendmsg' is issued only once the
writer's buffer is verifiably empty (sequential per-connection serving
makes that a stable state), so the prefix cannot overtake buffered
response bytes, and EAGAIN is retried on a short sleep — the loop's
'add_writer' cannot be used on a transport-owned fd. On the receiving
(client) side no transport owns the socket, so readiness waits ride a
plain 'add_reader' future.

pmd_pytcp/ipc/ipc__fdpass.py

ver 3.0.7
"""

from __future__ import annotations

import array
import asyncio
import os
import socket
import struct

from pmd_net_proto.lib.buffer import Buffer
from pmd_pytcp.ipc.ipc__errors import IpcFrameError
from pmd_pytcp.ipc.ipc__frame import (
    IPC__FRAME__LENGTH_PREFIX_LEN,
    IPC__FRAME__LENGTH_PREFIX_STRUCT,
    IPC__FRAME__MAX_PAYLOAD_LEN,
    recv_exactly,
    unpack_frame_length,
)

IPC__FDPASS__FD_STRUCT: str = "i"

# Pacing for the (rare) EAGAIN retry paths that cannot use the loop's
# readiness callbacks: the daemon-side 'sendmsg' on a transport-owned
# fd, and the wait for the 'StreamWriter' buffer to flush.
IPC__FDPASS__RETRY_SLEEP__SEC: float = 0.001


async def _wait_readable(sock: socket.socket, /) -> None:
    """
    Await the socket becoming readable — the 'recvmsg' analogue of the
    loop's 'sock_recv' readiness wait (which cannot capture ancillary
    data itself).
    """

    loop = asyncio.get_running_loop()
    future: asyncio.Future[None] = loop.create_future()

    def _on_readable() -> None:
        if not future.done():
            future.set_result(None)

    loop.add_reader(sock.fileno(), _on_readable)
    try:
        await future
    finally:
        loop.remove_reader(sock.fileno())


def _writer_socket(writer: asyncio.StreamWriter, /) -> socket.socket:
    """
    Return a raw 'socket.socket' view over the connection owned by
    'writer'. The transport exposes only an 'asyncio.trsock.
    TransportSocket' wrapper (no 'sendmsg'), so the descriptor is
    re-wrapped without duplication — the caller MUST 'detach()' the
    returned socket instead of closing it, or the transport's fd would
    be closed out from under it.
    """

    transport_socket = writer.get_extra_info("socket")
    return socket.socket(fileno=transport_socket.fileno())


async def _flush_writer(writer: asyncio.StreamWriter, /) -> None:
    """
    Await the stream writer's buffer draining to EMPTY (not merely
    below the high-water mark, which is all 'drain()' guarantees), so a
    raw 'sendmsg' issued next cannot overtake buffered bytes.
    """

    await writer.drain()
    transport = writer.transport
    while transport.get_write_buffer_size() > 0:
        await asyncio.sleep(IPC__FDPASS__RETRY_SLEEP__SEC)


async def send_frame_with_fd(writer: asyncio.StreamWriter, payload: Buffer, fd: int, /) -> None:
    """
    Send a length-prefixed frame with a file descriptor attached over
    the connection owned by 'writer'.

    The descriptor rides the prefix's raw 'sendmsg' as an SCM_RIGHTS
    ancillary message (issued once the writer's buffer is verifiably
    empty); the payload follows as a normal stream write.
    """

    length = len(payload)

    if length > IPC__FRAME__MAX_PAYLOAD_LEN:
        raise IpcFrameError(
            f"Frame payload length {length} exceeds the maximum " f"of {IPC__FRAME__MAX_PAYLOAD_LEN} bytes.",
        )

    prefix = struct.pack(IPC__FRAME__LENGTH_PREFIX_STRUCT, length)

    await _flush_writer(writer)

    # The 4-byte prefix + one cmsg virtually always fits the send buffer,
    # but a backpressured connection can still EAGAIN — retry on a short
    # sleep ('add_writer' is unavailable on a transport-owned fd; a
    # partial 'sendmsg' of a 4-byte iov cannot happen: stream sendmsg
    # either queues the whole iov+cmsg or fails). The raw-socket view is
    # detached (never closed) — the transport still owns the fd.
    sock = _writer_socket(writer)
    try:
        while True:
            try:
                sock.sendmsg(
                    [prefix],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array(IPC__FDPASS__FD_STRUCT, [fd]))],
                )
                break
            except (BlockingIOError, InterruptedError):
                await asyncio.sleep(IPC__FDPASS__RETRY_SLEEP__SEC)
    finally:
        sock.detach()

    writer.write(bytes(payload))
    await writer.drain()


async def recv_frame_with_fd(sock: socket.socket, /) -> tuple[bytes, int | None]:
    """
    Receive a length-prefixed frame and the descriptor attached to it.

    Returns '(payload, fd)' where 'fd' is the received descriptor (a new
    descriptor in this process), or None when the frame carried no
    descriptor — an fd-less RESPONSE_ERROR on the otherwise fd-bearing
    socket-creation path is the canonical case. Raises 'IpcFrameError' on
    a truncated or oversize frame, or when the prefix carried more than
    one descriptor; a received descriptor is closed before raising so it
    does not leak.
    """

    prefix, fd = await _recv_prefix_with_fd(sock)

    try:
        length = unpack_frame_length(prefix)
    except IpcFrameError:
        if fd is not None:
            os.close(fd)
        raise

    payload = await recv_exactly(sock, length)

    if len(payload) < length:
        if fd is not None:
            os.close(fd)
        raise IpcFrameError(
            f"Stream closed mid-frame: expected {length} payload bytes, " f"got {len(payload)}.",
        )

    return payload, fd


async def _recv_prefix_with_fd(sock: socket.socket, /) -> tuple[bytes, int | None]:
    """
    Read the length prefix, capturing the SCM_RIGHTS descriptor if one is
    attached (zero or one; more than one is a protocol error).
    """

    chunks: list[bytes] = []
    fds = array.array(IPC__FDPASS__FD_STRUCT)
    remaining = IPC__FRAME__LENGTH_PREFIX_LEN
    ancillary_size = socket.CMSG_SPACE(struct.calcsize(IPC__FDPASS__FD_STRUCT))

    while remaining > 0:
        try:
            data, ancillary, _, _ = sock.recvmsg(remaining, ancillary_size)
        except (BlockingIOError, InterruptedError):
            await _wait_readable(sock)
            continue
        if not data:
            break
        chunks.append(data)
        remaining -= len(data)
        for level, ctype, cdata in ancillary:
            if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
                fds.frombytes(cdata[: len(cdata) - (len(cdata) % fds.itemsize)])

    prefix = b"".join(chunks)

    if len(prefix) < IPC__FRAME__LENGTH_PREFIX_LEN:
        for fd in fds:
            os.close(fd)
        raise IpcFrameError(
            "Stream closed mid-frame while reading the 4-byte length prefix.",
        )

    if len(fds) > 1:
        for fd in fds:
            os.close(fd)
        raise IpcFrameError(
            f"Expected at most one passed file descriptor, received {len(fds)}.",
        )

    return prefix, (fds[0] if fds else None)
