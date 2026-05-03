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
This package contains the PyTCP socket interface.

pytcp/socket/__init__.py

ver 3.0.4
"""

from abc import ABC
from enum import IntEnum
from types import TracebackType
from typing import Any, override

from net_addr import Ip4Address, Ip6Address, IpVersion
from net_proto.lib.enums import IpProto
from pytcp.lib.name_enum import NameEnum
from pytcp.socket.socket_id import SocketId

IPPROTO_IP = IpProto.IP4
IPPROTO_IP4 = IpProto.IP4
IPPROTO_ICMP = IpProto.ICMP4
IPPROTO_ICMP4 = IpProto.ICMP4
IPPROTO_TCP = IpProto.TCP
IPPROTO_UDP = IpProto.UDP
IPPROTO_IPV6 = IpProto.IP6
IPPROTO_IP6 = IpProto.IP6
IPPROTO_ICMPV6 = IpProto.ICMP6
IPPROTO_ICMP6 = IpProto.ICMP6
IPPROTO_RAW = IpProto.RAW

# BSD setsockopt 'level' parameter for socket-level options.
# Linux number, matching stdlib 'socket.SOL_SOCKET'. The TCP-
# level option counterpart reuses 'IPPROTO_TCP' (= IpProto.TCP
# = 6) above, keeping the existing module surface.
SOL_SOCKET: int = 1


class SocketOption(IntEnum):
    """
    BSD setsockopt 'optname' parameter values, by integer number
    matching Linux. Setsockopt validates the (level, optname)
    pair: socket-level options use 'SOL_SOCKET' as level, TCP-
    level options use 'IPPROTO_TCP'.
    """

    SO_KEEPALIVE = 9  # level=SOL_SOCKET; bool: enable keep-alive (RFC 1122 §4.2.3.6)
    TCP_KEEPIDLE = 4  # level=IPPROTO_TCP; int seconds: per-conn idle override
    TCP_KEEPINTVL = 5  # level=IPPROTO_TCP; int seconds: per-conn probe interval override
    TCP_KEEPCNT = 6  # level=IPPROTO_TCP; int count: per-conn max probes override


SO_KEEPALIVE = SocketOption.SO_KEEPALIVE
TCP_KEEPIDLE = SocketOption.TCP_KEEPIDLE
TCP_KEEPINTVL = SocketOption.TCP_KEEPINTVL
TCP_KEEPCNT = SocketOption.TCP_KEEPCNT


class gaierror(OSError):
    """
    BSD Socket error for compatibility.
    """


class AddressFamily(NameEnum):
    """
    Address family identifier.
    """

    INET4 = 1
    INET6 = 2

    @staticmethod
    def from_ver(ver: IpVersion) -> AddressFamily:
        """
        Get the address family from an IP version.
        """

        match ver:
            case IpVersion.IP4:
                return AddressFamily.INET4
            case IpVersion.IP6:
                return AddressFamily.INET6


class SocketType(NameEnum):
    """
    Socket type identifier.
    """

    STREAM = 1
    DGRAM = 2
    RAW = 3


AF_INET = AddressFamily.INET4
AF_INET4 = AddressFamily.INET4
AF_INET6 = AddressFamily.INET6

SOCK_STREAM = SocketType.STREAM
SOCK_DGRAM = SocketType.DGRAM
SOCK_RAW = SocketType.RAW


class socket(ABC):
    """
    The BSD socket API base class.
    """

    _address_family: AddressFamily
    _socket_type: SocketType
    _ip_proto: IpProto
    _local_ip_address: Ip4Address | Ip6Address
    _remote_ip_address: Ip4Address | Ip6Address
    _local_port: int
    _remote_port: int

    def __new__(
        cls,
        family: AddressFamily = AddressFamily.INET4,
        type: SocketType = SocketType.STREAM,
        protocol: IpProto | None = None,
        **__: Any,
    ) -> socket:
        """
        Create appropriate socket class object.
        """

        if cls is socket:
            from pytcp.socket.raw__socket import RawSocket
            from pytcp.socket.tcp__socket import TcpSocket
            from pytcp.socket.udp__socket import UdpSocket

            match family, type, protocol:
                case _, SocketType.STREAM, IpProto.TCP | None:
                    return cls.__new__(TcpSocket)
                case _, SocketType.DGRAM, IpProto.UDP | None:
                    return cls.__new__(UdpSocket)
                case (AddressFamily.INET6, SocketType.RAW, _):
                    return cls.__new__(RawSocket)
                case (AddressFamily.INET4, SocketType.RAW, _):
                    return cls.__new__(RawSocket)
                case _:
                    raise ValueError(f"Invalid socket {family=}, {type=}, {protocol=} combination.")

        return super().__new__(cls)

    def __enter__(self) -> socket:
        """
        Enter the socket runtime context.
        """

        return self

    def __exit__(
        self,
        exc_type: type[BaseException],
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """
        Exit the socket runtime context.
        """

    @override
    def __str__(self) -> str:
        """
        Get socket log string.
        """

        proto = f"{self._address_family}/{self._socket_type}/{self._ip_proto}"
        local = f"{self._local_ip_address}/{self._local_port}"
        remote = f"{self._remote_ip_address}/{self._remote_port}"
        return f"{proto}/{local}/{remote}"

    @override
    def __repr__(self) -> str:
        """
        Get socket string representation.
        """

        return str(self)

    @property
    def socket_id(self) -> SocketId:
        """
        Get the socket ID.
        """

        return SocketId(
            address_family=self._address_family,
            socket_type=self._socket_type,
            local_address=self._local_ip_address,
            local_port=self._local_port,
            remote_address=self._remote_ip_address,
            remote_port=self._remote_port,
        )

    @property
    def address_family(self) -> AddressFamily:
        """
        Get the '_address_family' attribute.
        """

        return self._address_family

    @property
    def socket_type(self) -> SocketType:
        """
        Get the '_socket_type' attribute.
        """

        return self._socket_type

    @property
    def ip_proto(self) -> IpProto:
        """
        Get the '_ip_proto' attribute.
        """

        return self._ip_proto

    @property
    def local_ip_address(self) -> Ip6Address | Ip4Address:
        """
        Get the '_local_ip_address' attribute.
        """

        return self._local_ip_address

    @property
    def remote_ip_address(self) -> Ip6Address | Ip4Address:
        """
        Get the '_remote_ip_address' attribute.
        """

        return self._remote_ip_address

    @property
    def local_port(self) -> int:
        """
        Get the '_local_port' attribute.
        """

        return self._local_port

    @property
    def remote_port(self) -> int:
        """
        Get the '_remote_port' attribute.
        """

        return self._remote_port

    ###############################
    ##  BSD socket API methods.  ##
    ###############################

    @property
    def family(self) -> AddressFamily:
        """
        Get the '_address_family' attribute.
        """

        return self._address_family

    @property
    def type(self) -> SocketType:
        """
        Get the '_socket_type' attribute.
        """

        return self._socket_type

    @property
    def proto(self) -> IpProto:
        """
        Get the '_ip_proto' attribute.
        """

        return self._ip_proto

    def getsockname(self) -> tuple[str, int]:
        """
        Get the local address and port.
        """

        return str(self._local_ip_address), self._local_port

    def getpeername(self) -> tuple[str, int]:
        """
        Get the remote address and port.
        """

        return str(self._remote_ip_address), self._remote_port

    def bind(
        self,
        address: tuple[str, int],
    ) -> None:
        """
        The 'bind()' socket API method placeholder.
        """

        raise NotImplementedError

    def connect(
        self,
        address: tuple[str, int],
    ) -> None:
        """
        The 'connect()' socket API method placeholder.
        """

        raise NotImplementedError

    def send(
        self,
        data: bytes,
    ) -> int:
        """
        The 'send()' socket API method placeholder.
        """

        raise NotImplementedError

    def recv(
        self,
        bufsize: int | None = None,
        timeout: float | None = None,
    ) -> bytes:
        """
        The 'recv()' socket API method placeholder.
        """

        raise NotImplementedError

    def recv__mv(
        self,
        bufsize: int | None = None,
        timeout: float | None = None,
    ) -> memoryview:
        """
        The 'recv__mv()' socket API method placeholder.
        """

        raise NotImplementedError

    def close(self) -> None:
        """
        The 'close()' socket API placeholder.
        """

        raise NotImplementedError

    def listen(self, *, backlog: int = 16) -> None:
        """
        The 'listen()' socket API placeholder.
        """

        raise NotImplementedError

    def accept(self, *, timeout: float | None = None) -> tuple[socket, tuple[str, int]]:
        """
        The 'accept()' socket API placeholder.
        """

        raise NotImplementedError

    def sendto(self, data: bytes, address: tuple[str, int]) -> int:
        """
        The 'sendto()' socket API placeholder.
        """

        raise NotImplementedError

    def recvfrom(
        self,
        bufsize: int | None = None,
        timeout: float | None = None,
    ) -> tuple[bytes, tuple[str, int]]:
        """
        The 'recvfrom()' socket API placeholder.
        """

        raise NotImplementedError

    def recvfrom__mv(
        self,
        bufsize: int | None = None,
        timeout: float | None = None,
    ) -> tuple[memoryview, tuple[str, int]]:
        """
        The 'recvfrom__mv()' socket API placeholder.
        """

        raise NotImplementedError
