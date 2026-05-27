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

ver 3.0.6
"""

import errno
import os
import socket as _stdlib_socket
import sys
import threading
from abc import ABC
from enum import IntEnum
from types import TracebackType
from typing import Any, override

from net_addr import Ip4Address, Ip6Address, IpVersion
from net_proto.lib.enums import EtherType, IpProto
from net_proto.protocols.ip4.ip4__errors import Ip4IntegrityError
from net_proto.protocols.ip4.ip4__header import IP4__HEADER__LEN
from net_proto.protocols.ip4.options.ip4__options import (
    IP4__OPTIONS__MAX_LEN,
    Ip4Options,
)
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

# BSD setsockopt 'level' parameter for UDP-level options
# (Linux number from <netinet/udp.h>, matching stdlib
# 'socket.SOL_UDP' / 'socket.IPPROTO_UDP' on Linux). Used as
# the 'level' argument for 'UDP_NO_CHECK6_TX' /
# 'UDP_NO_CHECK6_RX' (RFC 6935 §5 zero-cksum opt-in for
# tunnel encapsulations).
SOL_UDP: int = 17


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


class SolSocketOption(IntEnum):
    """
    SOL_SOCKET-level setsockopt 'optname' values that share
    integer space with IPPROTO_TCP-level options (Linux
    numbers from <sys/socket.h>; disambiguated by the
    'level' parameter of setsockopt, not by the optname
    value itself). The 'TCP_*' family lives on
    'SocketOption' above; this enum holds the rest of the
    socket-level surface that PyTCP supports.
    """

    SO_REUSEADDR = 2  # bool: bypass "address in use" on rebind
    SO_BROADCAST = 6  # bool: allow UDP broadcast send
    SO_SNDBUF = 7  # int: send-buffer cap (storage only)
    SO_RCVBUF = 8  # int: recv-buffer cap (storage only)
    SO_RCVTIMEO = 20  # float seconds: persistent recv timeout
    SO_SNDTIMEO = 21  # float seconds: persistent send timeout
    SO_BINDTODEVICE = 25  # bytes: pin socket egress / RX to an interface by name


SO_REUSEADDR = SolSocketOption.SO_REUSEADDR
SO_BROADCAST = SolSocketOption.SO_BROADCAST
SO_SNDBUF = SolSocketOption.SO_SNDBUF
SO_RCVBUF = SolSocketOption.SO_RCVBUF
SO_RCVTIMEO = SolSocketOption.SO_RCVTIMEO
SO_SNDTIMEO = SolSocketOption.SO_SNDTIMEO
SO_BINDTODEVICE = SolSocketOption.SO_BINDTODEVICE


class IpOption(IntEnum):
    """
    IPPROTO_IP-level setsockopt 'optname' values (Linux
    numbers from <netinet/ip.h>; matches Python stdlib
    'socket.IP_*' module-level constants on Linux).
    """

    IP_TOS = 1  # int: 8-bit DSCP+ECN (RFC 2474)
    IP_TTL = 2  # int 1-255: per-socket TTL override
    IP_OPTIONS = 4  # bytes: 0-40 raw IPv4 options block (RFC 1122 §4.1.3.2)
    IP_RECVOPTS = 6  # int 0/1: enable IP_OPTIONS cmsg on recvmsg (RFC 1122 §4.1.3.2)
    IP_RETOPTS = 7  # int 0/1: deprecated alias of IP_RECVOPTS (Linux compat)
    IP_RECVERR = 11  # int 0/1: enable error queue (recvmsg MSG_ERRQUEUE — Linux ip(7))
    IP_RECVTOS = 13  # int 0/1: enable IP_TOS cmsg on recvmsg (RFC 1122 §4.1.4 MAY)
    IP_MTU = 14  # int (getsockopt only): effective PMTU for connected peer (RFC 1122 §3.4 GET_MAXSIZES)
    IP_ADD_MEMBERSHIP = 35  # ip_mreq bytes: join an IPv4 multicast group (RFC 1112 / 3376)
    IP_DROP_MEMBERSHIP = 36  # ip_mreq bytes: leave an IPv4 multicast group (RFC 1112 / 3376)


IP_TOS = IpOption.IP_TOS
IP_TTL = IpOption.IP_TTL
IP_OPTIONS = IpOption.IP_OPTIONS
IP_RECVOPTS = IpOption.IP_RECVOPTS
IP_RETOPTS = IpOption.IP_RETOPTS
IP_RECVERR = IpOption.IP_RECVERR
IP_RECVTOS = IpOption.IP_RECVTOS
IP_MTU = IpOption.IP_MTU
IP_ADD_MEMBERSHIP = IpOption.IP_ADD_MEMBERSHIP
IP_DROP_MEMBERSHIP = IpOption.IP_DROP_MEMBERSHIP


class IpV6Option(IntEnum):
    """
    IPPROTO_IPV6-level setsockopt 'optname' values (Linux
    numbers from <netinet/in.h>; matches Python stdlib
    'socket.IPV6_*' module-level constants on Linux).
    """

    IPV6_UNICAST_HOPS = 16  # int 1-255: per-socket Hop-Limit override
    IPV6_MTU = 24  # int (getsockopt only): effective PMTU for connected peer
    IPV6_RECVERR = 25  # int 0/1: enable IPv6 error queue (recvmsg MSG_ERRQUEUE — Linux ipv6(7))
    IPV6_RECVTCLASS = 66  # int 0/1: enable IPV6_TCLASS cmsg on recvmsg (RFC 3542 §6.5)
    IPV6_TCLASS = 67  # int: 8-bit Traffic Class (DSCP+ECN, RFC 2474)


IPV6_UNICAST_HOPS = IpV6Option.IPV6_UNICAST_HOPS
IPV6_MTU = IpV6Option.IPV6_MTU
IPV6_RECVERR = IpV6Option.IPV6_RECVERR
IPV6_RECVTCLASS = IpV6Option.IPV6_RECVTCLASS
IPV6_TCLASS = IpV6Option.IPV6_TCLASS


class UdpOption(IntEnum):
    """
    SOL_UDP-level setsockopt 'optname' values (Linux numbers
    from <linux/udp.h>; matches stdlib socket.UDP_* module-
    level constants on Linux). PyTCP currently supports the
    RFC 6935 §5 zero-cksum opt-in pair for tunnel
    encapsulations.
    """

    UDP_NO_CHECK6_TX = 101  # int 0/1: sender emits cksum=0 instead of computing
    UDP_NO_CHECK6_RX = 102  # int 0/1: receiver accepts inbound cksum=0 on this port


UDP_NO_CHECK6_TX = UdpOption.UDP_NO_CHECK6_TX
UDP_NO_CHECK6_RX = UdpOption.UDP_NO_CHECK6_RX


class MsgFlag(IntEnum):
    """
    MSG_* flag bits for recvmsg / recvfrom / sendmsg (Linux
    numbers from <sys/socket.h>; matches Python stdlib
    'socket.MSG_*' module-level constants on Linux). PyTCP
    currently honors MSG_ERRQUEUE only; other flags are
    reserved for future surface.
    """

    MSG_ERRQUEUE = 0x2000


MSG_ERRQUEUE = MsgFlag.MSG_ERRQUEUE

# 'struct sock_extended_err.ee_origin' values (Linux
# <linux/errqueue.h>) live as 'SoEeOrigin' members in
# 'pytcp.socket.error_queue'. The constant is PyTCP-
# internal — Python stdlib 'socket' does not expose
# SO_EE_ORIGIN_*, so applications either define their own
# bare-int constants for stdlib portability or import
# 'pytcp.socket.error_queue.SoEeOrigin' for the typed
# enum. Use 'SoEeOrigin.ICMP' / 'SoEeOrigin.ICMP6' at
# PyTCP-side call sites.


def _validate_ip4_options_bytes(value: bytes, /) -> bytes:
    """
    Validate a raw IPv4 options block supplied to
    setsockopt(IPPROTO_IP, IP_OPTIONS, value). The block must be
    no longer than IP4__OPTIONS__MAX_LEN, 4-byte aligned (RFC 791
    requires the IPv4 header length be a 32-bit-word count), and
    parseable as a sequence of IPv4 options. The validated bytes
    are returned for the caller to store. Raises 'OSError(EINVAL)'
    on any violation, matching Linux's setsockopt behaviour.
    """

    if len(value) > IP4__OPTIONS__MAX_LEN:
        raise OSError(
            errno.EINVAL,
            f"IP_OPTIONS block must be 0..{IP4__OPTIONS__MAX_LEN} bytes, got {len(value)}",
        )

    if len(value) % 4 != 0:
        raise OSError(
            errno.EINVAL,
            f"IP_OPTIONS block must be 4-byte aligned, got {len(value)} bytes",
        )

    if not value:
        return value

    # Pre-pad a synthetic IPv4 header so the integrity walker reads
    # at IP4__HEADER__LEN like a real packet would.
    synthetic_frame = bytes(IP4__HEADER__LEN) + value
    synthetic_hlen = IP4__HEADER__LEN + len(value)

    try:
        Ip4Options.validate_integrity(frame=synthetic_frame, hlen=synthetic_hlen)
        Ip4Options.from_buffer(value)
    except Ip4IntegrityError as error:
        raise OSError(errno.EINVAL, f"IP_OPTIONS block is malformed: {error}") from error

    return value


def _resolve_membership_ifindex(interface_address: Ip4Address, /) -> int | None:
    """
    Resolve the ifindex for an IP_ADD/DROP_MEMBERSHIP 'imr_interface'
    address. INADDR_ANY (0.0.0.0) selects the first interface that owns
    an IPv4 address (else the first registered interface); a specific
    address selects the interface that owns it. Returns 'None' when no
    interface matches.
    """

    import pytcp.stack as _stack

    if interface_address.is_unspecified:
        for ifindex, handler in _stack.interfaces.items():
            if handler._ip4_unicast:
                return ifindex
        for ifindex, _handler in _stack.interfaces.items():
            return ifindex
        return None

    for ifindex, handler in _stack.interfaces.items():
        if interface_address in handler._ip4_unicast:
            return ifindex

    return None


class ShutdownHow(IntEnum):
    """
    BSD-socket 'shutdown(how)' values per POSIX (Linux-
    numbered, matching Python stdlib 'socket.SHUT_*'). RFC
    9293 §3.9.1 half-close support: SHUT_WR triggers FIN
    emission like CLOSE but leaves the read side open;
    SHUT_RD discards inbound data.
    """

    SHUT_RD = 0
    SHUT_WR = 1
    SHUT_RDWR = 2


SHUT_RD = ShutdownHow.SHUT_RD
SHUT_WR = ShutdownHow.SHUT_WR
SHUT_RDWR = ShutdownHow.SHUT_RDWR


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
    PACKET = 17  # Linux AF_PACKET (<bits/socket.h>): raw link-layer access.

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
AF_PACKET = AddressFamily.PACKET

SOCK_STREAM = SocketType.STREAM
SOCK_DGRAM = SocketType.DGRAM
SOCK_RAW = SocketType.RAW

# AF_PACKET ethertype protocol filter (Linux <linux/if_ether.h>;
# matches the stdlib 'socket.ETH_P_*' surface on Linux). The real
# ethertypes alias the 'EtherType' wire-codepoint members so the
# packet-socket filter shares one namespace with the parser layer;
# 'ETH_P_ALL' is the capture-all pseudo-ethertype sentinel (0x0003 is
# not a real wire ethertype, so it stays a plain int rather than an
# 'EtherType' member — analogous to the 'INADDR_*' sentinels).
ETH_P_ALL: int = 0x0003
ETH_P_IP = EtherType.IP4
ETH_P_ARP = EtherType.ARP
ETH_P_IPV6 = EtherType.IP6


class PacketType(IntEnum):
    """
    AF_PACKET 'struct sockaddr_ll.sll_pkttype' classification values
    (Linux <linux/if_packet.h>; matches the stdlib 'socket.PACKET_*'
    surface on Linux). Set on RX to describe how the frame was
    addressed relative to this host's interface.
    """

    PACKET_HOST = 0  # frame addressed to this host's unicast MAC
    PACKET_BROADCAST = 1  # frame addressed to the link broadcast MAC
    PACKET_MULTICAST = 2  # frame addressed to a multicast MAC this host joined
    PACKET_OTHERHOST = 3  # frame addressed to some other host (promiscuous)
    PACKET_OUTGOING = 4  # frame originated by this host (loopback of egress)


PACKET_HOST = PacketType.PACKET_HOST
PACKET_BROADCAST = PacketType.PACKET_BROADCAST
PACKET_MULTICAST = PacketType.PACKET_MULTICAST
PACKET_OTHERHOST = PacketType.PACKET_OTHERHOST
PACKET_OUTGOING = PacketType.PACKET_OUTGOING

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
    _ip_ttl: int | None
    _ip_tos: int
    _ip_options: bytes
    _ip_recvopts: bool
    _ip_recvtos: bool
    _ip_recverr: bool
    _ipv6_unicast_hops: int | None
    _ipv6_tclass: int
    _ipv6_recvtclass: bool
    _ipv6_recverr: bool
    _ip4_memberships: set[tuple[int, Ip4Address]]

    def __init__(
        self,
        family: AddressFamily = AddressFamily.INET4,
        type: SocketType = SocketType.STREAM,
        protocol: IpProto | EtherType | int | None = None,
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
        # Close-during-delivery drain (Phase 5): '_closed' is set under
        # '_lock__io' by 'close()' (via '_mark_closed'); the RX-side
        # delivery methods ('process_*_packet') take the same lock and
        # drop the datagram when '_closed' so a packet is never queued
        # onto a socket the application has already torn down. TCP
        # delivery is instead serialized by 'TcpSession._lock__fsm'.
        self._closed = False
        self._lock__io = threading.Lock()
        self._blocking = True
        self._so_reuseaddr = False
        self._so_broadcast = False
        self._so_sndbuf = None
        self._so_rcvbuf = None
        self._so_rcvtimeo = None
        self._so_sndtimeo = None
        self._ip_ttl = None
        self._ip_tos = 0
        self._ip_options = bytes()
        self._ip_recvopts = False
        self._ip_recvtos = False
        self._ip_recverr = False
        self._ipv6_unicast_hops = None
        self._ipv6_tclass = 0
        self._ipv6_recvtclass = False
        self._ipv6_recverr = False
        # Per-socket IPv4 multicast holds (ifindex, group) for the
        # reference-counted IP_ADD/DROP_MEMBERSHIP path (R3).
        self._ip4_memberships = set()
        # SO_BINDTODEVICE: when set, pins this socket's egress to one
        # interface by name (the resolved ifindex is the egress the
        # send path uses, bypassing FIB route selection). Empty / unset
        # means "any interface" (the default FIB-resolved egress).
        self._bound_interface_name: str | None = None
        self._egress_ifindex: int | None = None

    def _so_bindtodevice(self, value: int | bytes, /) -> None:
        """
        Apply SO_BINDTODEVICE (SOL_SOCKET): pin the socket's egress to
        the named interface, mirroring Linux's device-name binding. An
        empty name clears the binding. Raises 'OSError(ENODEV)' when no
        registered interface carries the given name.
        """

        import pytcp.stack as _stack

        name = value.decode() if isinstance(value, (bytes, bytearray)) else str(value)
        if not name:
            self._bound_interface_name = None
            self._egress_ifindex = None
            return

        for ifindex, handler in _stack.interfaces.items():
            if handler._interface_name == name:
                self._bound_interface_name = name
                self._egress_ifindex = ifindex
                return

        raise OSError(errno.ENODEV, f"SO_BINDTODEVICE: no such interface {name!r}")

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

    def _ipproto_ip_setsockopt(self, optname: int, value: int | bytes, /) -> bool:
        """
        Apply an IPPROTO_IP-level setsockopt option; return True if
        handled. Currently supports IP_TTL (1-255 per-socket
        override), IP_TOS (8-bit DSCP+ECN per-packet marking),
        IP_OPTIONS (0-40 raw IPv4 options block per RFC 1122
        §4.1.3.2), and IP_RECVOPTS / IP_RETOPTS (enable IP_OPTIONS
        cmsg on recvmsg).
        """

        match optname:
            case _ if optname == IP_TTL:
                if not isinstance(value, int):
                    raise OSError(errno.EINVAL, f"IP_TTL value must be int, got {type(value).__name__}")
                if not 0 < int(value) < 256:
                    raise OSError(errno.EINVAL, f"IP_TTL must be in 1..255, got {value!r}")
                self._ip_ttl = int(value)
                return True
            case _ if optname == IP_TOS:
                if not isinstance(value, int):
                    raise OSError(errno.EINVAL, f"IP_TOS value must be int, got {type(value).__name__}")
                self._ip_tos = int(value) & 0xFF
                return True
            case _ if optname == IP_OPTIONS:
                if not isinstance(value, (bytes, bytearray, memoryview)):
                    raise OSError(errno.EINVAL, f"IP_OPTIONS value must be bytes, got {type(value).__name__}")
                self._ip_options = _validate_ip4_options_bytes(bytes(value))
                return True
            case _ if optname in (IP_RECVOPTS, IP_RETOPTS):
                if not isinstance(value, int):
                    raise OSError(errno.EINVAL, f"IP_RECVOPTS value must be int, got {type(value).__name__}")
                self._ip_recvopts = bool(value)
                return True
            case _ if optname == IP_RECVTOS:
                if not isinstance(value, int):
                    raise OSError(errno.EINVAL, f"IP_RECVTOS value must be int, got {type(value).__name__}")
                self._ip_recvtos = bool(value)
                return True
            case _ if optname == IP_RECVERR:
                if not isinstance(value, int):
                    raise OSError(errno.EINVAL, f"IP_RECVERR value must be int, got {type(value).__name__}")
                self._ip_recverr = bool(value)
                return True
            case _ if optname in (IP_ADD_MEMBERSHIP, IP_DROP_MEMBERSHIP):
                if not isinstance(value, (bytes, bytearray, memoryview)):
                    raise OSError(
                        errno.EINVAL,
                        f"IP_ADD/DROP_MEMBERSHIP value must be an ip_mreq bytes object, got {type(value).__name__}",
                    )
                self._ipproto_ip_membership(optname, bytes(value))
                return True
        return False

    def _ipproto_ip_membership(self, optname: int, mreq: bytes, /) -> None:
        """
        Apply IP_ADD_MEMBERSHIP / IP_DROP_MEMBERSHIP by parsing the
        'ip_mreq' structure (4-byte imr_multiaddr + 4-byte
        imr_interface) and dispatching to the stack membership API on
        the interface 'imr_interface' selects, as a per-socket
        (reference-counted) hold. An imr_interface of 0.0.0.0
        (INADDR_ANY) selects the first IPv4-capable interface, mirroring
        the Linux "let the kernel pick" behaviour. The 12-byte 'ip_mreqn'
        form (… + imr_ifindex) is also accepted; a non-zero imr_ifindex
        selects the interface directly and takes precedence over
        imr_address (Linux 'ip_mreqn').

        This socket records each (ifindex, group) it joins so the
        interface only leaves a group when its last holder drops it.
        Joining a group this socket already holds raises EADDRINUSE, and
        dropping a group it does not hold raises EADDRNOTAVAIL (Linux
        'ip_mc_join_group' / 'ip_mc_leave_group' parity).
        """

        import pytcp.stack as _stack
        from pytcp.stack.membership import MembershipLimitError, MembershipRefKind

        if len(mreq) < 8:
            raise OSError(errno.EINVAL, f"ip_mreq must be at least 8 bytes, got {len(mreq)}")

        group = Ip4Address(mreq[0:4])
        interface_address = Ip4Address(mreq[4:8])

        # 'ip_mreqn' carries a host-order C-int imr_ifindex; when present
        # and non-zero it selects the interface directly, overriding the
        # imr_address selection used by the 8-byte 'ip_mreq'.
        imr_ifindex = int.from_bytes(mreq[8:12], sys.byteorder) if len(mreq) >= 12 else 0
        if imr_ifindex != 0:
            ifindex = imr_ifindex if imr_ifindex in _stack.interfaces else None
            if ifindex is None:
                raise OSError(errno.EADDRNOTAVAIL, f"No interface with ifindex {imr_ifindex}")
        else:
            ifindex = _resolve_membership_ifindex(interface_address)
            if ifindex is None:
                raise OSError(errno.EADDRNOTAVAIL, f"No IPv4 interface matches imr_interface {interface_address}")

        api = _stack.membership.interface(ifindex)
        membership = (ifindex, group)
        try:
            if optname == IP_ADD_MEMBERSHIP:
                if membership in self._ip4_memberships:
                    raise OSError(errno.EADDRINUSE, f"Socket already a member of {group} on interface {ifindex}")
                api.join(group=group, kind=MembershipRefKind.SOCKET)
                self._ip4_memberships.add(membership)
            else:
                if membership not in self._ip4_memberships:
                    raise OSError(errno.EADDRNOTAVAIL, f"Socket is not a member of {group} on interface {ifindex}")
                api.leave(group=group, kind=MembershipRefKind.SOCKET)
                self._ip4_memberships.discard(membership)
        except MembershipLimitError as error:
            raise OSError(errno.ENOBUFS, str(error)) from error
        except ValueError as error:
            raise OSError(errno.EINVAL, str(error)) from error

    def _ipproto_ip_getsockopt(self, optname: int, /) -> int | bytes | None:
        """
        Get an IPPROTO_IP-level option's stored value, or 'None' if
        the option is not handled here.
        """

        match optname:
            case _ if optname == IP_TTL:
                return self._ip_ttl or 0
            case _ if optname == IP_TOS:
                return self._ip_tos
            case _ if optname == IP_OPTIONS:
                return self._ip_options
            case _ if optname in (IP_RECVOPTS, IP_RETOPTS):
                return int(self._ip_recvopts)
            case _ if optname == IP_RECVTOS:
                return int(self._ip_recvtos)
            case _ if optname == IP_RECVERR:
                return int(self._ip_recverr)
            case _ if optname == IP_MTU:
                return self._effective_pmtu()
        return None

    def _ipproto_ipv6_setsockopt(self, optname: int, value: int, /) -> bool:
        """
        Apply an IPPROTO_IPV6-level setsockopt option; return True if
        handled. Currently supports IPV6_UNICAST_HOPS (1-255 per-socket
        override) and IPV6_TCLASS (8-bit Traffic Class).
        """

        match optname:
            case _ if optname == IPV6_UNICAST_HOPS:
                if not 0 < int(value) < 256:
                    raise OSError(errno.EINVAL, f"IPV6_UNICAST_HOPS must be in 1..255, got {value!r}")
                self._ipv6_unicast_hops = int(value)
                return True
            case _ if optname == IPV6_TCLASS:
                self._ipv6_tclass = int(value) & 0xFF
                return True
            case _ if optname == IPV6_RECVTCLASS:
                self._ipv6_recvtclass = bool(value)
                return True
            case _ if optname == IPV6_RECVERR:
                self._ipv6_recverr = bool(value)
                return True
        return False

    def _ipproto_ipv6_getsockopt(self, optname: int, /) -> int | None:
        """
        Get an IPPROTO_IPV6-level option's stored value, or 'None' if
        the option is not handled here.
        """

        match optname:
            case _ if optname == IPV6_UNICAST_HOPS:
                return self._ipv6_unicast_hops or 0
            case _ if optname == IPV6_TCLASS:
                return self._ipv6_tclass
            case _ if optname == IPV6_RECVTCLASS:
                return int(self._ipv6_recvtclass)
            case _ if optname == IPV6_RECVERR:
                return int(self._ipv6_recverr)
            case _ if optname == IPV6_MTU:
                return self._effective_pmtu()
        return None

    def _effective_ip_ttl(self) -> int | None:
        """
        Get the effective per-socket TTL (IPv4) or Hop-Limit (IPv6)
        override based on the socket's address family. Returns 'None'
        if no override is set, in which case the packet handler's
        default applies.
        """

        if self._address_family is AddressFamily.INET6:
            return self._ipv6_unicast_hops
        return self._ip_ttl

    def _effective_ip_ecn(self) -> int:
        """
        Get the effective ECN bits (low 2 bits of IP_TOS / IPV6_TCLASS)
        based on the socket's address family. Apps that set the full
        TOS/Traffic-Class byte get the ECN portion automatically.
        """

        if self._address_family is AddressFamily.INET6:
            return self._ipv6_tclass & 0x03
        return self._ip_tos & 0x03

    def _effective_pmtu(self) -> int:
        """
        Get the effective Path-MTU for this socket's connected
        peer: the value reported by 'stack.current_pmtu()'
        (which prefers the active PLPMTUD engine state in
        'stack.pmtu_state' and falls back to the legacy
        classical-PMTUD scalar in 'stack.pmtu_cache') when
        present, otherwise the link MTU of the interface the FIB
        selects to egress toward the peer
        ('stack.egress_interface_mtu()') as a link-layer fallback
        (matching Linux's IP_MTU semantics).

        Raises 'OSError(ENOTCONN)' when the socket has no
        connected remote, mirroring Linux 'ip(7)' / 'ipv6(7)' —
        the MTU surface is defined per-destination, so an
        unconnected socket has no meaningful value to return.
        """

        # Import here to avoid a top-level circular cycle between
        # pytcp.socket and pytcp.stack at module load.
        from pytcp import stack as _stack

        if self._remote_ip_address.is_unspecified:
            raise OSError(errno.ENOTCONN, "Socket is not connected — IP_MTU/IPV6_MTU has no peer")
        current = _stack.current_pmtu(self._remote_ip_address)
        if current is not None:
            return current
        # No PMTU signal yet — report the egress interface's link MTU
        # (per-destination on a multi-homed host). Falls back to the
        # default link MTU when no egress can be resolved, preserving the
        # retired 'stack.interface_mtu' default value.
        return _stack.egress_interface_mtu(self._remote_ip_address) or _stack.INTERFACE__TAP__MTU

    def _effective_ip4_options(self) -> Ip4Options | None:
        """
        Get the per-socket IPv4 options object set via
        'setsockopt(IPPROTO_IP, IP_OPTIONS, bytes)' for IPv4
        sockets, or 'None' for IPv6 sockets (IPv6 has no
        equivalent — extension headers are handled via a
        separate ancillary-data track, RFC 3542).
        """

        if self._address_family is not AddressFamily.INET4:
            return None
        if not self._ip_options:
            return None
        return Ip4Options.from_buffer(self._ip_options)

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
        protocol: IpProto | EtherType | int | None = None,
        **__: Any,
    ) -> socket:
        """
        Create appropriate socket class object.
        """

        if cls is socket:
            from pytcp.socket.packet__socket import PacketSocket
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
                case (AddressFamily.PACKET, SocketType.RAW, _):
                    return cls.__new__(PacketSocket)
                case (AddressFamily.PACKET, _, _):
                    raise ValueError(f"Invalid socket {family=}, {type=}, {protocol=} combination.")
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

    def _mark_closed(self) -> None:
        """
        Atomically mark the socket closed and release its OS-level
        runtime, under '_lock__io'. Concrete 'close()' overrides call
        this (after removing the socket from 'stack.sockets') so an
        in-flight RX delivery either completes before the socket is
        marked closed or observes '_closed' and drops the datagram —
        'close()' thus drains in-flight deliveries.
        """

        with self._lock__io:
            self._closed = True
            self._close_io_runtime()

        self._release_ip4_memberships()

    def _release_ip4_memberships(self) -> None:
        """
        Release every IPv4 multicast membership this socket still holds —
        the Linux 'ip_mc_drop_socket' equivalent run on close(). The
        interface leaves a group (and emits the state-change Leave) only
        when this socket was its last holder (R3). Idempotent: a socket
        that joined no group clears an empty set. Released outside
        '_lock__io' so the membership/timer path does not run under the
        socket IO lock.
        """

        if not self._ip4_memberships:
            return

        import pytcp.stack as _stack
        from pytcp.stack.membership import MembershipRefKind

        for ifindex, group in list(self._ip4_memberships):
            try:
                _stack.membership.interface(ifindex).leave(group=group, kind=MembershipRefKind.SOCKET)
            except KeyError, ValueError:
                # Best-effort cleanup: the interface may already be torn
                # down (KeyError) during stack shutdown, and a group that
                # cannot be left (e.g. the permanent all-systems group,
                # ValueError) needs no release. Mirrors the best-effort
                # nature of the Linux close-time drop.
                pass
        self._ip4_memberships.clear()

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
        address: Any,
    ) -> None:
        """
        The 'bind()' socket API method placeholder.

        The address is typed 'Any' because it is address-family
        dependent: IP sockets take '(ip_str, port)', while an
        AF_PACKET socket takes a 'SockAddrLl'. Each concrete subclass
        narrows the parameter to its own precise address type.
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

    def setsockopt(self, level: int | IpProto, optname: int, value: int | bytes, /) -> None:
        """
        The 'setsockopt()' socket API method placeholder. Each concrete
        IP socket implements the SOL_SOCKET / IPPROTO_* option surface;
        AF_PACKET sockets do not support socket options.
        """

        raise NotImplementedError

    def getsockopt(self, level: int | IpProto, optname: int, /) -> int | bytes:
        """
        The 'getsockopt()' socket API method placeholder. Symmetric to
        'setsockopt'.
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

    def sendto(self, data: bytes, address: Any) -> int:
        """
        The 'sendto()' socket API placeholder.

        The address is typed 'Any' because it is address-family
        dependent: IP sockets take '(ip_str, port)', while an
        AF_PACKET socket takes a 'SockAddrLl'. Each concrete subclass
        narrows the parameter to its own precise address type.
        """

        raise NotImplementedError

    def recvfrom(
        self,
        bufsize: int | None = None,
        timeout: float | None = None,
    ) -> tuple[bytes, Any]:
        """
        The 'recvfrom()' socket API placeholder.

        The address half is typed 'Any' because it is address-family
        dependent: IP sockets return '(ip_str, port)', while an
        AF_PACKET socket returns a 'SockAddrLl'. Each concrete subclass
        narrows the return to its own precise address type (mirroring
        typeshed's 'socket.recvfrom() -> tuple[bytes, Any]').
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
