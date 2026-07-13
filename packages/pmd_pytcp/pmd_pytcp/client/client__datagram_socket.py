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
This module contains the client-side datagram socket shims.

'ClientUdpSocket' and 'ClientRawSocket' mirror the BSD-style 'UdpSocket' /
'RawSocket' surfaces across the process boundary. They share the
'_ClientDatagramBase' plumbing: a data path over the client end of the
daemon's SOCK_DGRAM socketpair (boundary-preserving), with each datagram
framed by its peer address (see 'ipc__dgram_frame') so 'sendto' /
'recvfrom' carry the address; and control methods (bind / connect /
setsockopt / getsockopt / getsockname / getpeername / close) marshalled
over the SOCKET_CALL op keyed by the daemon-assigned handle. Under the
pure-asyncio runtime ('docs/refactor/pure_asyncio.md') the waiting calls
are coroutines with the same names and parameters, the data path driven
by the loop's sock APIs; opening is 'await ClientUdpSocket.open(...)' /
'await ClientRawSocket.open(...)' (the daemon round trip cannot happen
in a constructor). The two differ only in how they open: a UDP socket by
type, a raw socket by type plus an IANA next-header protocol.

pmd_pytcp/client/client__datagram_socket.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import socket
from typing_extensions import Self

from pmd_net_proto.lib.enums import IpProto
from pmd_pytcp.client.client__data_channel import _DataChannel
from pmd_pytcp.ipc.ipc__client import IpcClient
from pmd_pytcp.ipc.ipc__dgram_bridge import IPC__DGRAM_BRIDGE__CHUNK_SIZE
from pmd_pytcp.ipc.ipc__dgram_frame import decode_dgram, encode_dgram
from pmd_pytcp.ipc.ipc__socket_rpc import open_socket, socket_call
from pmd_pytcp.socket import AddressFamily, SocketType

# Default receive bound — the maximum UDP payload, so 'recvfrom' without
# an explicit bufsize never truncates a legal datagram.
IPC__CLIENT_DGRAM__MAX_PAYLOAD: int = 65535


class _ClientDatagramBase(_DataChannel):
    """
    Shared client-side datagram-socket plumbing (UDP and raw).
    """

    def __init__(self, client: IpcClient, handle: int, data_fd: int, family: AddressFamily, /) -> None:
        """
        Adopt the passed SOCK_DGRAM data-channel descriptor and bind the
        shim to its daemon handle. 'family' selects the recvmsg address
        shape (a 4-tuple for IPv6, mirroring stdlib).
        """

        self._client = client
        self._handle = handle
        self._family = family
        self._init_data_channel(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, fileno=data_fd))

    async def sendto(self, data: bytes, address: tuple[str, int], /) -> int:
        """
        Send 'data' as a datagram to 'address'.
        """

        await self._wait_data(
            asyncio.get_running_loop().sock_sendall(self._data_socket, encode_dgram(address, data))
        )
        return len(data)

    async def send(self, data: bytes) -> int:
        """
        Send 'data' as a datagram to the connected peer.
        """

        await self._wait_data(asyncio.get_running_loop().sock_sendall(self._data_socket, encode_dgram(None, data)))
        return len(data)

    async def recvfrom(self, bufsize: int = IPC__CLIENT_DGRAM__MAX_PAYLOAD) -> tuple[bytes, tuple[str, int]]:
        """
        Receive one datagram with the sender's '(host, port)' address,
        truncating the payload to 'bufsize'.
        """

        blob = await self._wait_data(
            asyncio.get_running_loop().sock_recv(self._data_socket, IPC__DGRAM_BRIDGE__CHUNK_SIZE)
        )
        address, _cmsg, payload = decode_dgram(blob)
        # The daemon's RX pump always frames a received datagram with its
        # sender address, so a None address here is a protocol violation.
        assert address is not None, "A received datagram frame carried no sender address."
        return payload[:bufsize], address

    async def recvmsg(
        self,
        bufsize: int = IPC__CLIENT_DGRAM__MAX_PAYLOAD,
        ancbufsize: int = 0,
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, tuple[str, int] | tuple[str, int, int, int]]:
        """
        Receive one datagram with its ancillary control messages and
        sender address, mirroring stdlib 'socket.recvmsg'. The IPv6
        address is a 4-tuple '(host, port, flowinfo, scope_id)' (flowinfo
        / scope_id are 0 — PyTCP does not track them per datagram).
        'ancbufsize' is advisory: the daemon already framed every cmsg the
        socket enabled.
        """

        _ = ancbufsize
        blob = await self._wait_data(
            asyncio.get_running_loop().sock_recv(self._data_socket, IPC__DGRAM_BRIDGE__CHUNK_SIZE)
        )
        address, cmsg, payload = decode_dgram(blob)
        assert address is not None, "A received datagram frame carried no sender address."

        out_address: tuple[str, int] | tuple[str, int, int, int] = (
            (address[0], address[1], 0, 0) if self._family is AddressFamily.INET6 else address
        )
        return payload[:bufsize], cmsg, 0, out_address

    async def recv(self, bufsize: int = IPC__CLIENT_DGRAM__MAX_PAYLOAD) -> bytes:
        """
        Receive one datagram's payload, truncated to 'bufsize'.
        """

        return (await self.recvfrom(bufsize))[0]

    async def bind(self, address: tuple[str, int]) -> None:
        """
        Bind the daemon socket to a local address.
        """

        await socket_call(self._client, method="bind", handle=self._handle, args={"address": address})

    async def connect(self, address: tuple[str, int]) -> None:
        """
        Set the daemon socket's default peer address.
        """

        await socket_call(self._client, method="connect", handle=self._handle, args={"address": address})

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

    async def getsockname(self) -> tuple[str, int]:
        """
        Get the daemon socket's local address and port.
        """

        result: tuple[str, int] = await socket_call(self._client, method="getsockname", handle=self._handle, args={})
        return result

    async def getpeername(self) -> tuple[str, int]:
        """
        Get the daemon socket's connected peer address and port.
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


class ClientUdpSocket(_ClientDatagramBase):
    """
    A client-side UDP socket backed by a daemon socket over IPC.
    """

    @classmethod
    async def open(cls, client: IpcClient, /, *, family: AddressFamily = AddressFamily.INET4) -> Self:
        """
        Open a daemon-side UDP socket and adopt its passed SOCK_DGRAM
        data-channel descriptor.
        """

        handle, data_fd = await open_socket(client, family=family, type_=SocketType.DGRAM)
        return cls(client, handle, data_fd, family)


class ClientRawSocket(_ClientDatagramBase):
    """
    A client-side raw IP socket backed by a daemon socket over IPC.
    """

    @classmethod
    async def open(
        cls,
        client: IpcClient,
        /,
        *,
        protocol: IpProto,
        family: AddressFamily = AddressFamily.INET4,
    ) -> Self:
        """
        Open a daemon-side raw socket for the given IANA next-header
        'protocol' and adopt its passed SOCK_DGRAM data-channel
        descriptor.
        """

        handle, data_fd = await open_socket(client, family=family, type_=SocketType.RAW, protocol=protocol)
        return cls(client, handle, data_fd, family)
