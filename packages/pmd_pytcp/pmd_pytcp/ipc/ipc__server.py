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
This module contains the IPC control-channel AF_UNIX server.

'IpcServer' listens on an AF_UNIX stream socket via
'asyncio.start_unix_server' and serves each accepted client on its own
connection task ('docs/refactor/pure_asyncio.md'): read a framed
request, route its op to a handler, write the framed response. It is the
daemon-side half of the boundary and — unlike the codec core — imports
the stack-resident 'SocketSession', so it stays pmd_pytcp-resident (see
docs/refactor/kernel_userspace_separation.md §2).

Lifecycle shape: the listen socket is bound synchronously in
'__init__' (so the AF_UNIX node exists — and clients can queue in the
backlog — as soon as the server is constructed); 'start()' is a
COROUTINE that arms the asyncio server on the running loop; 'stop()'
stays sync (close the server, cancel the per-client tasks, unlink the
node) and 'wait_stopped()' awaits the teardown's completion —
mirroring the runtime 'Subsystem' start/stop/wait_stopped shape.

pmd_pytcp/ipc/ipc__server.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import os
import socket
from collections.abc import Callable, Mapping
from typing_extensions import TypeAliasType

from pmd_pytcp.ipc.ipc__control import handle_control_call
from pmd_pytcp.ipc.ipc__enums import IpcMessageKind, IpcOp
from pmd_pytcp.ipc.ipc__errors import IpcFrameError, IpcMessageError
from pmd_pytcp.ipc.ipc__fdpass import send_frame_with_fd
from pmd_pytcp.ipc.ipc__frame import recv_frame, send_frame
from pmd_pytcp.ipc.ipc__message import IpcMessage
from pmd_pytcp.ipc.ipc__socket_session import SocketSession
from pmd_pytcp.lib.logger import log

# A handler takes the decoded request and returns the full response
# message, so it owns the response 'kind' (a control handler returns
# RESPONSE_OK or RESPONSE_ERROR depending on the call's outcome).
IpcRequestHandler = TypeAliasType("IpcRequestHandler", Callable[[IpcMessage], IpcMessage])

IPC__SERVER__LISTEN_BACKLOG: int = 64


def _handle_ping(request: IpcMessage, /) -> IpcMessage:
    """
    Handle a PING request — answer with a fixed 'PONG' body.
    """

    return IpcMessage(
        kind=IpcMessageKind.RESPONSE_OK,
        op=request.op,
        req_id=request.req_id,
        body=b"PONG",
    )


DEFAULT_HANDLERS: dict[int, IpcRequestHandler] = {
    IpcOp.PING: _handle_ping,
    IpcOp.CONTROL_CALL: handle_control_call,
}


class IpcServer:
    """
    The IPC control-channel AF_UNIX server.
    """

    _subsystem_name = "IPC Server"

    _socket_path: str
    _handlers: dict[int, IpcRequestHandler]
    _listen_socket: socket.socket
    _server: "asyncio.base_events.Server | None"
    _client_tasks: "set[asyncio.Task[None]]"
    _event__stop_subsystem: asyncio.Event

    def __init__(
        self,
        *,
        socket_path: str,
        handlers: Mapping[int, IpcRequestHandler] | None = None,
    ) -> None:
        """
        Bind and listen on the AF_UNIX control socket. The socket node
        exists (and connects queue in the backlog) from here on;
        serving begins once 'start()' arms the asyncio server.
        """

        self._socket_path = socket_path

        __debug__ and log("stack", f"Initializing {self._subsystem_name} [{socket_path}]")

        self._handlers = dict(DEFAULT_HANDLERS) if handlers is None else dict(handlers)
        self._server = None
        self._client_tasks = set()
        self._event__stop_subsystem = asyncio.Event()

        self._listen_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._unlink_socket_path()
        self._listen_socket.bind(socket_path)
        self._listen_socket.listen(IPC__SERVER__LISTEN_BACKLOG)
        self._listen_socket.setblocking(False)

    async def start(self) -> None:
        """
        Arm the asyncio server on the running loop; on return the
        server is accepting (connections already queued in the backlog
        get served immediately).
        """

        __debug__ and log("stack", f"Starting {self._subsystem_name}")

        assert self._server is None, f"{self._subsystem_name}.start() called while the server is already running."

        self._event__stop_subsystem.clear()
        self._server = await asyncio.start_unix_server(self._serve_client, sock=self._listen_socket)

        __debug__ and log("stack", f"Started {self._subsystem_name}")

    def stop(self) -> None:
        """
        Stop the server: set the stop event (unblocks the socket
        sessions' accept polls), close the listen socket, cancel every
        per-client connection task, and unlink the AF_UNIX socket node.
        Sync-safe from loop context — use 'wait_stopped()' to await the
        connection tasks' actual exit (each task's own 'finally' reaps
        its session sockets and closes its connection).
        """

        __debug__ and log("stack", f"Stopping {self._subsystem_name}")

        self._event__stop_subsystem.set()

        if self._server is not None:
            self._server.close()
            self._server = None
        else:
            # Never armed — the listen socket is still ours to close.
            try:
                self._listen_socket.close()
            except OSError:
                pass

        for task in list(self._client_tasks):
            if not task.done():
                task.cancel()

        self._unlink_socket_path()

        __debug__ and log("stack", f"Stopped {self._subsystem_name}")

    async def wait_stopped(self) -> None:
        """
        Await every per-client connection task's completion after
        'stop()'.
        """

        tasks = list(self._client_tasks)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _serve_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """
        Serve one client connection until it closes or the server stops:
        read a framed request, dispatch it, write the framed response.
        Each connection owns a 'SocketSession' (its open-socket table),
        reaped when the connection ends — the daemon's analogue of a
        kernel closing a process's fds on exit.

        Requests are read via the connection's 'StreamReader' (inbound
        frames never carry descriptors) and responses written via its
        'StreamWriter'; an fd-bearing response's SCM_RIGHTS prefix rides
        a raw 'sendmsg' issued only once the writer's buffer is
        verifiably empty (see 'ipc__fdpass').
        """

        task = asyncio.current_task()
        if task is not None:
            self._client_tasks.add(task)

        session = SocketSession(self._event__stop_subsystem)
        try:
            while not self._event__stop_subsystem.is_set():
                try:
                    payload = await recv_frame(reader)
                except (IpcFrameError, OSError):
                    break

                if payload is None:
                    break

                try:
                    request = IpcMessage.from_bytes(payload)
                except IpcMessageError:
                    # Structurally broken frame (bad kind / short
                    # header) — a protocol violation; drop the client.
                    break

                if request.op == IpcOp.SOCKET_CALL:
                    if not await self._serve_socket_call(writer, session, request):
                        break
                    continue

                try:
                    await send_frame(writer, self._dispatch(request).to_bytes())
                except OSError:
                    break
        except asyncio.CancelledError:
            pass  # Server teardown — fall through to the session reap.
        finally:
            session.close_all()
            try:
                writer.close()
            except OSError:
                pass
            if task is not None:
                self._client_tasks.discard(task)

    async def _serve_socket_call(
        self,
        writer: asyncio.StreamWriter,
        session: SocketSession,
        request: IpcMessage,
        /,
    ) -> bool:
        """
        Serve one SOCKET_CALL on the connection's session and write the
        response, passing the data-channel fd when the call opened a
        socket. Return False (stop serving) on a write error.

        The passed client-end socket is closed once handed off — the
        client now owns the kernel object via SCM_RIGHTS, so the daemon
        drops its reference whether or not the send succeeded.
        """

        response, fd_socket = await session.handle(request)
        try:
            if fd_socket is not None:
                await send_frame_with_fd(writer, response.to_bytes(), fd_socket.fileno())
            else:
                await send_frame(writer, response.to_bytes())
        except OSError:
            return False
        finally:
            if fd_socket is not None:
                try:
                    fd_socket.close()
                except OSError:
                    pass
        return True

    def _dispatch(self, request: IpcMessage, /) -> IpcMessage:
        """
        Route a request to its op handler and build the response.

        An op with no registered handler yields a RESPONSE_ERROR
        (ENOSYS-style) echoing the request's op and correlation id, so
        the client learns the op is unsupported rather than seeing the
        connection drop.
        """

        handler = self._handlers.get(request.op)

        if handler is None:
            return IpcMessage(
                kind=IpcMessageKind.RESPONSE_ERROR,
                op=request.op,
                req_id=request.req_id,
                body=f"unsupported op {request.op}".encode(),
            )

        return handler(request)

    def _unlink_socket_path(self) -> None:
        """
        Remove the AF_UNIX socket node if present (clears a stale node
        before bind and the live node after stop).
        """

        try:
            os.unlink(self._socket_path)
        except FileNotFoundError:
            pass
