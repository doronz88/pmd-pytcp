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
This module contains the IPC control-channel client connector.

'IpcClient' opens an AF_UNIX stream connection to the daemon and issues
request/response calls over it: send a framed request, await the
matching framed response, decode and return it. It is part of the
extraction-ready codec core — pmd_net_proto + stdlib only, no pmd_pytcp stack
reach-in (see docs/refactor/kernel_userspace_separation.md §2).

Pure-asyncio ('docs/refactor/pure_asyncio.md'): the request/response
methods are coroutines with the same names and parameters as the old
blocking API. The connection is a raw non-blocking socket driven by the
loop's sock APIs, NOT an 'asyncio.open_unix_connection' stream —
fd-bearing responses arrive as SCM_RIGHTS ancillary data on the same
byte stream, and a 'StreamReader'-owning transport reads eagerly with
plain 'recv', silently dropping any descriptor that arrives with the
buffered bytes. Construction is sync (no I/O); 'await client.open()'
connects.

pmd_pytcp/ipc/ipc__client.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import socket
from types import TracebackType
from typing import Awaitable, TypeVar
from typing_extensions import Self

from pmd_net_proto.lib.buffer import Buffer
from pmd_pytcp.ipc.ipc__enums import IpcMessageKind, IpcOp
from pmd_pytcp.ipc.ipc__errors import IpcConnectionError
from pmd_pytcp.ipc.ipc__fdpass import recv_frame_with_fd
from pmd_pytcp.ipc.ipc__frame import recv_frame_from_socket, send_frame_to_socket
from pmd_pytcp.ipc.ipc__message import IpcMessage

IPC__CLIENT__DEFAULT_TIMEOUT__SEC: float = 5.0
IPC__CLIENT__REQ_ID_MASK: int = 0xFFFFFFFF

_T = TypeVar("_T")


class IpcClient:
    """
    An asyncio IPC control-channel client connected to the daemon.
    """

    def __init__(
        self,
        *,
        socket_path: str,
        timeout: float = IPC__CLIENT__DEFAULT_TIMEOUT__SEC,
    ) -> None:
        """
        Prepare a client for the daemon control socket at 'socket_path'
        (no I/O happens here — 'await open()' connects).
        """

        self._socket_path = socket_path
        self._lock = asyncio.Lock()
        self._next_req_id = 0
        self._timeout = timeout
        self._socket: socket.socket | None = None

    async def open(self) -> Self:
        """
        Open the AF_UNIX stream connection to the daemon control
        socket. Returns self so callers can chain construction and
        connect.
        """

        assert self._socket is None, "IpcClient.open() called on an already-open client."

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            await self._with_timeout(asyncio.get_running_loop().sock_connect(sock, self._socket_path))
        except (OSError, asyncio.CancelledError):
            # Close the just-created socket so a failed connect (e.g. the
            # daemon not up yet) does not orphan an open descriptor.
            sock.close()
            raise
        self._socket = sock
        return self

    async def _with_timeout(self, awaitable: "Awaitable[_T]", /) -> _T:
        """
        Await 'awaitable' under the client's default timeout, raising
        the builtin 'TimeoutError' (the old 'socket.timeout') on expiry.
        """

        if self._timeout is None:
            return await awaitable
        try:
            return await asyncio.wait_for(_ensure_future(awaitable), self._timeout)
        except asyncio.TimeoutError:
            raise TimeoutError("timed out") from None

    def _require_socket(self) -> socket.socket:
        """
        Return the connected socket, or raise if the client is not open.
        """

        if self._socket is None:
            raise IpcConnectionError("The IPC client is not connected — call 'await open()' first.")
        return self._socket

    async def request(self, op: int, /, *, body: Buffer = b"") -> IpcMessage:
        """
        Send a request for 'op' and return the daemon's response.

        Serialised under a lock so the send-then-receive pair is atomic
        per call, making a single client safe to share across tasks.
        """

        sock = self._require_socket()

        async with self._lock:
            req_id = self._next_req_id
            self._next_req_id = (self._next_req_id + 1) & IPC__CLIENT__REQ_ID_MASK

            request = IpcMessage(
                kind=IpcMessageKind.REQUEST,
                op=op,
                req_id=req_id,
                body=bytes(body),
            )

            await self._with_timeout(send_frame_to_socket(sock, request.to_bytes()))

            payload = await self._with_timeout(recv_frame_from_socket(sock))
            if payload is None:
                raise IpcConnectionError(
                    "Daemon closed the control connection while awaiting a response.",
                )

            return IpcMessage.from_bytes(payload)

    async def request_with_fd(
        self,
        op: int,
        /,
        *,
        body: Buffer = b"",
        blocking: bool = False,
    ) -> tuple[IpcMessage, int | None]:
        """
        Send a request for 'op' and return the daemon's response together
        with the file descriptor passed alongside it (the data-channel
        end for a newly opened socket), or None when the response carried
        no descriptor (an fd-less error response). The returned fd is
        owned by the caller.

        'blocking' drops the response timeout for the round trip — used by
        'accept', whose response can take arbitrarily long (it waits for
        an inbound connection).

        Serialised under the same lock as 'request' so a fd-bearing call
        is atomic with respect to other calls on the shared client.
        """

        sock = self._require_socket()

        async with self._lock:
            req_id = self._next_req_id
            self._next_req_id = (self._next_req_id + 1) & IPC__CLIENT__REQ_ID_MASK

            request = IpcMessage(
                kind=IpcMessageKind.REQUEST,
                op=op,
                req_id=req_id,
                body=bytes(body),
            )

            if blocking:
                await send_frame_to_socket(sock, request.to_bytes())
                payload, fd = await recv_frame_with_fd(sock)
            else:
                await self._with_timeout(send_frame_to_socket(sock, request.to_bytes()))
                payload, fd = await self._with_timeout(recv_frame_with_fd(sock))

            return IpcMessage.from_bytes(payload), fd

    async def ping(self) -> bytes:
        """
        Issue a PING and return the response body.
        """

        return (await self.request(IpcOp.PING)).body

    def close(self) -> None:
        """
        Close the control connection to the daemon.
        """

        if self._socket is None:
            return
        try:
            self._socket.close()
        except OSError:
            pass
        self._socket = None

    async def __aenter__(self) -> Self:
        """
        Enter the client context, connecting if not yet open.
        """

        if self._socket is None:
            await self.open()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """
        Close the control connection on context exit.
        """

        self.close()


def _ensure_future(awaitable: "Awaitable[_T]", /) -> "asyncio.Future[_T]":
    """
    Wrap a bare awaitable for 'asyncio.wait_for' (a no-op passthrough
    for coroutines on every supported Python; kept explicit so the 3.9
    floor — where 'wait_for' insists on a future/coroutine — holds).
    """

    return asyncio.ensure_future(awaitable)
