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
This module contains the client-side AF_PACKET socket shim.

'ClientPacketSocket' mirrors the BSD-style 'PacketSocket' surface across
the process boundary. Its data path is the client end of the daemon's
SOCK_DGRAM socketpair; each link-layer frame is prefixed with its
'sockaddr_ll' (see 'ipc__packet_frame') so 'recvfrom' (how the frame
arrived) and 'sendto' (which interface to egress) carry the link-layer
address across. Under the pure-asyncio runtime
('docs/refactor/pure_asyncio.md') the waiting calls are coroutines with
the same names and parameters, the data path driven by the loop's sock
APIs; opening is 'await ClientPacketSocket.open(...)'. 'bind' (a
'SockAddrLl') and 'close' marshal over the SOCKET_CALL op keyed by the
daemon-assigned handle.

pmd_pytcp/client/client__packet_socket.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import socket
from typing_extensions import Self

from pmd_net_proto.lib.enums import EtherType
from pmd_pytcp.client.client__data_channel import _DataChannel
from pmd_pytcp.ipc.ipc__client import IpcClient
from pmd_pytcp.ipc.ipc__packet_bridge import IPC__PACKET_BRIDGE__CHUNK_SIZE
from pmd_pytcp.ipc.ipc__packet_frame import decode_packet, encode_packet
from pmd_pytcp.ipc.ipc__socket_rpc import open_socket, socket_call
from pmd_pytcp.socket import ETH_P_ALL, AddressFamily, SocketType
from pmd_pytcp.socket.sockaddr_ll import SockAddrLl


class ClientPacketSocket(_DataChannel):
    """
    A client-side AF_PACKET socket backed by a daemon socket over IPC.
    """

    def __init__(self, client: IpcClient, handle: int, data_fd: int, /) -> None:
        """
        Adopt an already-opened daemon AF_PACKET socket handle and its
        passed SOCK_DGRAM data-channel descriptor (use
        'await ClientPacketSocket.open(...)' to open a new one).
        """

        self._client = client
        self._handle = handle
        self._init_data_channel(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, fileno=data_fd))

    @classmethod
    async def open(cls, client: IpcClient, /, *, protocol: EtherType | int = ETH_P_ALL) -> Self:
        """
        Open a daemon-side AF_PACKET socket for the given ethertype
        filter and adopt its passed SOCK_DGRAM data-channel descriptor.
        """

        handle, data_fd = await open_socket(
            client,
            family=AddressFamily.PACKET,
            type_=SocketType.RAW,
            protocol=protocol,
        )
        return cls(client, handle, data_fd)

    async def sendto(self, data: bytes, address: SockAddrLl, /) -> int:
        """
        Send the link-layer frame 'data' out the interface named by
        'address'.
        """

        await self._wait_data(
            asyncio.get_running_loop().sock_sendall(self._data_socket, encode_packet(address, data))
        )
        return len(data)

    async def send(self, data: bytes) -> int:
        """
        Send the link-layer frame 'data' out the sole interface (an
        unbound egress).
        """

        await self._wait_data(
            asyncio.get_running_loop().sock_sendall(self._data_socket, encode_packet(SockAddrLl(), data))
        )
        return len(data)

    async def recvfrom(self, bufsize: int | None = None) -> tuple[bytes, SockAddrLl]:
        """
        Receive one link-layer frame with the 'sockaddr_ll' describing how
        it arrived, truncating the frame to 'bufsize'.
        """

        blob = await self._wait_data(
            asyncio.get_running_loop().sock_recv(self._data_socket, IPC__PACKET_BRIDGE__CHUNK_SIZE)
        )
        sockaddr_ll, frame = decode_packet(blob)
        return (frame if bufsize is None else frame[:bufsize]), sockaddr_ll

    async def recv(self, bufsize: int | None = None) -> bytes:
        """
        Receive one link-layer frame, truncated to 'bufsize'.
        """

        return (await self.recvfrom(bufsize))[0]

    async def bind(self, address: SockAddrLl) -> None:
        """
        Scope the daemon socket to '(address.ifindex, address.ethertype)'.
        """

        await socket_call(self._client, method="bind", handle=self._handle, args={"address": address})

    async def close(self) -> None:
        """
        Close the daemon socket and the local data-channel descriptor.
        """

        try:
            await socket_call(self._client, method="close", handle=self._handle, args={})
        finally:
            self._close_data_channel()
