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

import errno
import os
import socket as _stdlib_socket
from abc import ABC
from enum import IntEnum
from types import TracebackType
from typing import Any, override

from net_addr import Ip4Address, Ip6Address, IpVersion
from net_proto.lib.enums import IpProto
from pytcp.lib.name_enum import NameEnum
from pytcp.socket.socket_id import SocketId

# BSD '<netinet/in.h>' default-protocol sentinel: socket(family,
# type, IPPROTO_IP) selects the kernel's default protocol for the
# requested socket type (TCP for STREAM, UDP for DGRAM). Decoupled
# from 'IpProto' because the IANA next-header value 0 is HOPOPT
# (IPv6 Hop-by-Hop, RFC 8200 §4.3), not "default IP".
IPPROTO_IP: int = 0

IPPROTO_IPIP = IpProto.IP4  # RFC 2003 IPv4-in-IPv4 (Linux: socket.IPPROTO_IPIP).
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
    level options use 'IPPROTO_TCP'. SOL_SOCKET-level options
    that share an integer value with an IPPROTO_TCP-level option
    (e.g. SO_BROADCAST=6 vs TCP_KEEPCNT=6) live as plain ints
    below the enum to avoid IntEnum aliasing.
    """

    TCP_NODELAY = 1  # level=IPPROTO_TCP; bool: disable Nagle (RFC 1122 §4.2.3.4)
    TCP_KEEPIDLE = 4  # level=IPPROTO_TCP; int seconds: per-conn idle override
    TCP_KEEPINTVL = 5  # level=IPPROTO_TCP; int seconds: per-conn probe interval override
    TCP_KEEPCNT = 6  # level=IPPROTO_TCP; int count: per-conn max probes override
    SO_KEEPALIVE = 9  # level=SOL_SOCKET; bool: enable keep-alive (RFC 1122 §4.2.3.6)
    TCP_CONGESTION = 13  # level=IPPROTO_TCP; str: per-conn CC algorithm name (RFC 9438)
    TCP_FASTOPEN = 23  # level=IPPROTO_TCP; int qlen: TFO accept-queue depth (RFC 7413)


TCP_NODELAY = SocketOption.TCP_NODELAY
SO_KEEPALIVE = SocketOption.SO_KEEPALIVE
TCP_KEEPIDLE = SocketOption.TCP_KEEPIDLE
TCP_KEEPINTVL = SocketOption.TCP_KEEPINTVL
TCP_KEEPCNT = SocketOption.TCP_KEEPCNT
TCP_CONGESTION = SocketOption.TCP_CONGESTION
TCP_FASTOPEN = SocketOption.TCP_FASTOPEN

# SOL_SOCKET-level options sharing integer values with IPPROTO_TCP-
# level options (Linux numbers, disambiguated by 'level' parameter
# of setsockopt, not by the optname value itself).
SO_REUSEADDR: int = 2  # level=SOL_SOCKET; bool: bypass "address in use" on rebind
SO_BROADCAST: int = 6  # level=SOL_SOCKET; bool: allow UDP broadcast send
SO_SNDBUF: int = 7  # level=SOL_SOCKET; int: send-buffer cap (storage only)
SO_RCVBUF: int = 8  # level=SOL_SOCKET; int: recv-buffer cap (storage only)
SO_RCVTIMEO: int = 20  # level=SOL_SOCKET; float seconds: persistent recv timeout
SO_SNDTIMEO: int = 21  # level=SOL_SOCKET; float seconds: persistent send timeout


# BSD-socket 'shutdown(how)' constants per POSIX. Linux-numbered
# values matching stdlib 'socket.SHUT_*'. RFC 9293 §3.9.1
# half-close support: SHUT_WR triggers FIN emission like CLOSE
# but leaves the read side open; SHUT_RD discards inbound data.
SHUT_RD: int = 0
SHUT_WR: int = 1
SHUT_RDWR: int = 2


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

# DNS / hostname resolution lives outside the TCP/IP stack scope:
# 'getaddrinfo' / 'gethostbyname' / 'getnameinfo' / 'getfqdn' are
# re-exported verbatim from CPython's stdlib 'socket' so application
# code calling 'pytcp.socket.getaddrinfo("example.com", 80)' gets
# real DNS resolution. The resulting numeric IP string then flows
# back into PyTCP's 'bind' / 'connect' / 'sendto'.
getaddrinfo = _stdlib_socket.getaddrinfo
gethostbyname = _stdlib_socket.gethostbyname
gethostbyname_ex = _stdlib_socket.gethostbyname_ex
gethostname = _stdlib_socket.gethostname
getnameinfo = _stdlib_socket.getnameinfo
getfqdn = _stdlib_socket.getfqdn

# BSD '<arpa/inet.h>' INADDR_* constants (re-exported as plain ints
# matching CPython's stdlib 'socket.INADDR_*'). Apps that pass
# 'INADDR_ANY' to 'bind()' instead of the empty string are common
# in code ported from C; expose the constants so the same idiom
# works.
INADDR_ANY: int = 0
INADDR_BROADCAST: int = 0xFFFFFFFF
INADDR_LOOPBACK: int = 0x7F000001
INADDR_NONE: int = 0xFFFFFFFF


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
    _read_event_fd: int
    _blocking: bool
    _so_reuseaddr: bool
    _so_broadcast: bool
    _so_sndbuf: int | None
    _so_rcvbuf: int | None
    _so_rcvtimeo: float | None
    _so_sndtimeo: float | None

    def __init__(
        self,
        family: AddressFamily = AddressFamily.INET4,
        type: SocketType = SocketType.STREAM,
        protocol: IpProto | int | None = None,
        **__: Any,
    ) -> None:
        """
        Allocate the OS-level eventfd backing 'fileno()'. The
        descriptor signals readability for select / poll / epoll /
        selectors when data lands in the socket's RX queue. Counter
        starts at 0 (not readable); EFD_NONBLOCK + EFD_CLOEXEC match
        the default Linux socket FD flags. The 'family' / 'type' /
        'protocol' parameters mirror the '__new__' factory triple so
        calls like 'socket(family=..., type=..., protocol=...)' bind
        cleanly; the base class itself does not act on them — concrete
        Tcp/Udp/Raw subclasses consume them in their own '__init__'.
        Blocking mode defaults to True per POSIX 'socket(2)'.
        """

        del family, type, protocol  # consumed by concrete-class __init__.
        self._read_event_fd = os.eventfd(0, os.EFD_NONBLOCK | os.EFD_CLOEXEC)
        self._blocking = True
        self._so_reuseaddr = False
        self._so_broadcast = False
        self._so_sndbuf = None
        self._so_rcvbuf = None
        self._so_rcvtimeo = None
        self._so_sndtimeo = None

    def _sol_socket_setsockopt(self, optname: int, value: int, /) -> bool:
        """
        Apply a SOL_SOCKET-level setsockopt option; return True if
        handled or False if the optname is not a base-class option
        (subclasses then dispatch their TCP/UDP-specific options).
        """

        match optname:
            case _ if optname == SO_REUSEADDR:
                self._so_reuseaddr = bool(value)
                return True
            case _ if optname == SO_BROADCAST:
                self._so_broadcast = bool(value)
                return True
            case _ if optname == SO_SNDBUF:
                self._so_sndbuf = int(value)
                return True
            case _ if optname == SO_RCVBUF:
                self._so_rcvbuf = int(value)
                return True
            case _ if optname == SO_RCVTIMEO:
                self._so_rcvtimeo = float(value) if value else None
                return True
            case _ if optname == SO_SNDTIMEO:
                self._so_sndtimeo = float(value) if value else None
                return True
        return False

    def _sol_socket_getsockopt(self, optname: int, /) -> int | None:
        """
        Get a SOL_SOCKET-level option's stored value, or 'None' if
        the option is not a base-class option.
        """

        match optname:
            case _ if optname == SO_REUSEADDR:
                return int(self._so_reuseaddr)
            case _ if optname == SO_BROADCAST:
                return int(self._so_broadcast)
            case _ if optname == SO_SNDBUF:
                return self._so_sndbuf or 0
            case _ if optname == SO_RCVBUF:
                return self._so_rcvbuf or 0
            case _ if optname == SO_RCVTIMEO:
                return int(self._so_rcvtimeo) if self._so_rcvtimeo else 0
            case _ if optname == SO_SNDTIMEO:
                return int(self._so_sndtimeo) if self._so_sndtimeo else 0
        return None

    def __new__(
        cls,
        family: AddressFamily = AddressFamily.INET4,
        type: SocketType = SocketType.STREAM,
        protocol: IpProto | int | None = None,
        **__: Any,
    ) -> socket:
        """
        Create appropriate socket class object.
        """

        if cls is socket:
            from pytcp.socket.raw__socket import RawSocket
            from pytcp.socket.tcp__socket import TcpSocket
            from pytcp.socket.udp__socket import UdpSocket

            # Coerce the BSD 'IPPROTO_IP' (= 0) default-protocol
            # sentinel to None so STREAM/DGRAM dispatch picks the
            # canonical default and RAW falls into the explicit
            # EPROTONOSUPPORT branch.
            if protocol.__class__ is int and protocol == 0:
                protocol = None

            match family, type, protocol:
                case _, SocketType.STREAM, IpProto.TCP | None:
                    return cls.__new__(TcpSocket)
                case _, SocketType.DGRAM, IpProto.UDP | None:
                    return cls.__new__(UdpSocket)
                case _, SocketType.RAW, None:
                    raise OSError(errno.EPROTONOSUPPORT, os.strerror(errno.EPROTONOSUPPORT))
                case (AddressFamily.INET6 | AddressFamily.INET4, SocketType.RAW, IpProto()):
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

    def fileno(self) -> int:
        """
        Get the OS file descriptor backing this socket. Returns the
        underlying eventfd that signals readability when the RX
        queue is non-empty, suitable for 'select.select' /
        'select.poll' / 'select.epoll' / 'selectors.DefaultSelector'.
        """

        return self._read_event_fd

    def setblocking(self, flag: bool, /) -> None:
        """
        Set the socket's blocking mode per POSIX 'socket(2)' /
        CPython 'socket.setblocking'. With 'flag=True' (default),
        recv / accept calls block until data / a child is available;
        with 'flag=False', the same calls raise 'BlockingIOError'
        carrying 'errno.EAGAIN' when they would otherwise block.
        Non-bool truthy / falsy values are coerced to bool to match
        CPython's stdlib behavior.
        """

        self._blocking = bool(flag)

    def getblocking(self) -> bool:
        """
        Get the socket's current blocking mode per CPython
        'socket.getblocking'. Returns 'True' for blocking sockets
        (the default) and 'False' for non-blocking sockets.
        """

        return self._blocking

    def _signal_readable(self) -> None:
        """
        Mark the socket's eventfd as select-readable. The producer
        (stack-thread RX path) calls this whenever a new datagram /
        segment / accept-queue child lands. Best-effort: a closed fd
        is silently tolerated so the producer never crashes on a
        race with application-side close().
        """

        if (fd := self._read_event_fd) < 0:
            return
        try:
            os.eventfd_write(fd, 1)
        except OSError:
            pass

    def _drain_readable(self) -> None:
        """
        Return the socket's eventfd to the not-readable state. The
        consumer (application-thread recv / accept) calls this once
        the RX queue / accept queue has been drained empty so the
        next selector tick stops firing. Best-effort: a closed fd
        or already-zero counter (EAGAIN) is silently tolerated.
        """

        if (fd := self._read_event_fd) < 0:
            return
        try:
            os.eventfd_read(fd)
        except OSError:
            pass

    def _close_io_runtime(self) -> None:
        """
        Close the OS-level eventfd backing 'fileno()'. Idempotent
        so concrete 'close()' overrides can call it unconditionally
        without tracking whether the fd is still open.
        """

        if (fd := self._read_event_fd) < 0:
            return
        self._read_event_fd = -1
        try:
            os.close(fd)
        except OSError:
            pass

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
