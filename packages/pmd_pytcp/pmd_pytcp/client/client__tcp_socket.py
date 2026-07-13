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
This module contains the client-side TCP socket shim.

'ClientTcpSocket' mirrors the BSD-style 'TcpSocket' surface across the
process boundary. Its data path is a real kernel descriptor — the
client end of the daemon's socketpair, passed at open time — driven by
the loop's sock APIs under the pure-asyncio runtime
('docs/refactor/pure_asyncio.md'), so 'send' / 'recv' are coroutines and
'fileno()' remains selectable. Its control methods (bind / connect /
setsockopt / getsockopt / shutdown / getsockname / getpeername / close)
marshal over the SOCKET_CALL op keyed by the daemon-assigned handle —
all coroutines now, with the same names and parameters. Opening is a
coroutine too ('await ClientTcpSocket.open(client)'), because the
daemon round trip cannot happen in a constructor.

pmd_pytcp/client/client__tcp_socket.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import socket
from typing_extensions import Self

from pmd_net_proto.lib.enums import IpProto
from pmd_pytcp.client.client__data_channel import _DataChannel
from pmd_pytcp.ipc.ipc__client import IpcClient
from pmd_pytcp.ipc.ipc__socket_rpc import accept_socket, open_socket, socket_call
from pmd_pytcp.socket import AddressFamily, SocketType

# Default accept-queue depth when 'listen' is called without an explicit
# backlog (mirrors the daemon-side 'TCP__DEFAULT_BACKLOG').
IPC__CLIENT_TCP__DEFAULT_BACKLOG: int = 16


class ClientTcpSocket(_DataChannel):
    """
    A client-side TCP socket backed by a daemon socket over IPC.
    """

    def __init__(self, client: IpcClient, handle: int, data_fd: int, /) -> None:
        """
        Adopt an already-opened daemon socket handle and its passed
        data-channel descriptor (use 'await ClientTcpSocket.open(...)'
        to open a new daemon socket).
        """

        self._client = client
        self._handle = handle
        self._init_data_channel(socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=data_fd))

    @classmethod
    async def open(cls, client: IpcClient, /, *, family: AddressFamily = AddressFamily.INET4) -> Self:
        """
        Open a daemon-side TCP socket and adopt its passed data-channel
        descriptor as the shim's real, selectable fd.
        """

        handle, data_fd = await open_socket(client, family=family, type_=SocketType.STREAM)
        return cls(client, handle, data_fd)

    async def send(self, data: bytes) -> int:
        """
        Send 'data' to the connected peer over the data channel.
        """

        await self._wait_data(asyncio.get_running_loop().sock_sendall(self._data_socket, data))
        return len(data)

    async def recv(self, bufsize: int) -> bytes:
        """
        Receive up to 'bufsize' bytes from the connected peer over the
        data channel (b"" once the peer has closed and the stream drains).
        """

        return await self._wait_data(asyncio.get_running_loop().sock_recv(self._data_socket, bufsize))

    async def bind(self, address: tuple[str, int]) -> None:
        """
        Bind the daemon socket to a local address.
        """

        await socket_call(self._client, method="bind", handle=self._handle, args={"address": address})

    async def connect(self, address: tuple[str, int]) -> None:
        """
        Connect the daemon socket to a remote address.
        """

        await socket_call(self._client, method="connect", handle=self._handle, args={"address": address})

    async def listen(self, *, backlog: int = IPC__CLIENT_TCP__DEFAULT_BACKLOG) -> None:
        """
        Mark the daemon socket as a passive listener with an accept queue
        bounded by 'backlog'.
        """

        await socket_call(self._client, method="listen", handle=self._handle, args={"backlog": backlog})

    async def accept(self) -> tuple[Self, tuple[str, int]]:
        """
        Wait until an inbound connection completes, returning a new
        'ClientTcpSocket' for the accepted connection (its data path is
        the passed descriptor) and the peer's '(host, port)' address.
        """

        child_handle, peer, data_fd = await accept_socket(self._client, handle=self._handle)
        return type(self)(self._client, child_handle, data_fd), peer

    async def setsockopt(self, level: int | IpProto, optname: int, value: int | bytes, /) -> None:
        """
        Set a socket option on the daemon socket.
        """

        await socket_call(
            self._client,
            method="setsockopt",
            handle=self._handle,
            args={"level": level, "optname": optname, "value": value},
        )

    async def getsockopt(self, level: int | IpProto, optname: int, /) -> int | bytes:
        """
        Get a socket option from the daemon socket.
        """

        result: int | bytes = await socket_call(
            self._client,
            method="getsockopt",
            handle=self._handle,
            args={"level": level, "optname": optname},
        )
        return result

    async def shutdown(self, how: int, /) -> None:
        """
        Shut down one or both halves of the daemon connection.
        """

        await socket_call(self._client, method="shutdown", handle=self._handle, args={"how": how})

    async def getsockname(self) -> tuple[str, int]:
        """
        Get the daemon socket's local address and port.
        """

        result: tuple[str, int] = await socket_call(self._client, method="getsockname", handle=self._handle, args={})
        return result

    async def getpeername(self) -> tuple[str, int]:
        """
        Get the daemon socket's remote address and port.
        """

        result: tuple[str, int] = await socket_call(self._client, method="getpeername", handle=self._handle, args={})
        return result

    async def close(self) -> None:
        """
        Close the daemon socket and the local data-channel descriptor.
        """

        try:
            await socket_call(self._client, method="close", handle=self._handle, args={})
        finally:
            self._close_data_channel()
