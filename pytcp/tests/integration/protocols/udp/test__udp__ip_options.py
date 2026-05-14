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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
Integration tests for the UDP IP_OPTIONS / IP_RECVOPTS socket
options. Together they implement RFC 1122 §4.1.3.2 — UDP MUST
pass any IP option received from the IP layer transparently to
the application layer, an application MUST be able to specify
IP options to be sent in its UDP datagrams, and UDP MUST pass
these options to the IP layer.

PyTCP's surface:
- 'setsockopt(IPPROTO_IP, IP_OPTIONS, bytes)' stores the
  per-socket options block; 'sendto()' threads it into the
  outbound IPv4 packet handler.
- 'setsockopt(IPPROTO_IP, IP_RECVOPTS, 1)' enables
  IP_OPTIONS cmsg emission on 'recvmsg(ancbufsize=...)'.

pytcp/tests/integration/protocols/udp/test__udp__ip_options.py

ver 3.0.4
"""

from net_addr import Ip4Address, IpVersion, MacAddress
from net_proto import (
    EthernetAssembler,
    Ip4Assembler,
    Ip4OptionRouterAlert,
    Ip4Options,
    Ip4Parser,
    UdpAssembler,
)
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.socket import (
    IP_OPTIONS,
    IP_RECVOPTS,
    IPPROTO_IP,
    AddressFamily,
    IpProto,
    SocketType,
)
from pytcp.socket.udp__socket import UdpSocket
from pytcp.tests.lib.network_testcase import NetworkTestCase

_STACK_MAC = MacAddress("02:00:00:00:00:07")
_STACK_IP4 = Ip4Address("10.0.1.7")
_HOST_A_MAC = MacAddress("02:00:00:00:00:91")
_HOST_A_IP4 = Ip4Address("10.0.1.91")
_LOCAL_PORT = 4444
_REMOTE_PORT = 5555
_ROUTER_ALERT_BYTES = b"\x94\x04\x00\x00"


def _build_udp_frame_with_router_alert(*, payload: bytes) -> bytes:
    """
    Build an Ethernet/IPv4/UDP datagram from HOST_A → STACK
    carrying a Router Alert IPv4 option (RFC 2113).
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_HOST_A_MAC,
            ethernet__dst=_STACK_MAC,
            ethernet__payload=Ip4Assembler(
                ip4__src=_HOST_A_IP4,
                ip4__dst=_STACK_IP4,
                ip4__options=Ip4Options(Ip4OptionRouterAlert()),
                ip4__payload=UdpAssembler(
                    udp__sport=_REMOTE_PORT,
                    udp__dport=_LOCAL_PORT,
                    udp__payload=payload,
                ),
            ),
        )
    )


def _build_udp_frame_plain(*, payload: bytes) -> bytes:
    """
    Build an Ethernet/IPv4/UDP datagram from HOST_A → STACK
    with no IPv4 options.
    """

    return bytes(
        EthernetAssembler(
            ethernet__src=_HOST_A_MAC,
            ethernet__dst=_STACK_MAC,
            ethernet__payload=Ip4Assembler(
                ip4__src=_HOST_A_IP4,
                ip4__dst=_STACK_IP4,
                ip4__payload=UdpAssembler(
                    udp__sport=_REMOTE_PORT,
                    udp__dport=_LOCAL_PORT,
                    udp__payload=payload,
                ),
            ),
        )
    )


class TestUdpIpOptionsRecvmsgPassThrough(NetworkTestCase):
    """
    Inbound IPv4 options surface via 'recvmsg' as IP_OPTIONS cmsg.
    """

    def setUp(self) -> None:
        """
        Bind a UdpSocket so the RX dispatch hands the inbound
        datagram to the application-layer queue. Snapshot+clear
        'stack.sockets' to keep the per-test socket registration
        from leaking into sibling tests.
        """

        super().setUp()
        self._sockets_prior = dict(stack.sockets)
        stack.sockets.clear()
        self.addCleanup(self._restore_sockets)

        self._socket = UdpSocket(
            family=AddressFamily.INET4,
            type=SocketType.DGRAM,
            protocol=IpProto.UDP,
        )
        self._socket._local_ip_address = _STACK_IP4
        self._socket._local_port = _LOCAL_PORT
        stack.sockets[self._socket.socket_id] = self._socket

    def _restore_sockets(self) -> None:
        """Restore the snapshotted 'stack.sockets' dict."""
        stack.sockets.clear()
        stack.sockets.update(self._sockets_prior)

    def test__udp__ip_options__recvmsg_returns_cmsg_when_recvopts_enabled(self) -> None:
        """
        Ensure an inbound UDP datagram carrying IPv4 options
        surfaces through 'recvmsg(ancbufsize>0)' as an IP_OPTIONS
        ancillary-data cmsg when 'IP_RECVOPTS' is enabled on the
        receiving socket. The cmsg level / type / raw-bytes
        triple matches Linux's '<sys/socket.h>' shape.

        Reference: RFC 1122 §4.1.3.2 (UDP MUST pass received IP
        options to the application layer).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_RECVOPTS, 1)

        self._packet_handler._phrx_ethernet(PacketRx(_build_udp_frame_with_router_alert(payload=b"hello")))

        data, ancdata, _flags, address = self._socket.recvmsg(ancbufsize=256, timeout=0.5)

        self.assertEqual(
            data,
            b"hello",
            msg="recvmsg() must return the inbound UDP payload as bytes.",
        )
        self.assertEqual(
            address,
            (str(_HOST_A_IP4), _REMOTE_PORT),
            msg="recvmsg() address must be (host, port) for AF_INET.",
        )
        self.assertEqual(
            len(ancdata),
            1,
            msg="Datagram with IPv4 options must surface exactly one cmsg when IP_RECVOPTS=1.",
        )
        level, type_, value = ancdata[0]
        self.assertEqual(
            (level, type_, value),
            (int(IPPROTO_IP), int(IP_OPTIONS), _ROUTER_ALERT_BYTES),
            msg="IP_OPTIONS cmsg must carry (IPPROTO_IP, IP_OPTIONS, raw_options_bytes).",
        )

    def test__udp__ip_options__recvmsg_suppresses_cmsg_when_recvopts_disabled(self) -> None:
        """
        Ensure an inbound UDP datagram carrying IPv4 options
        delivers the payload through 'recvmsg' but omits the
        IP_OPTIONS cmsg when 'IP_RECVOPTS' is NOT set on the
        socket. Matches Linux's per-socket opt-in semantics —
        applications that do not request the cmsg do not see it.

        Reference: RFC 1122 §4.1.3.2 (IP_RECVOPTS gates the
        ancillary-data pass-through).
        """

        self._packet_handler._phrx_ethernet(PacketRx(_build_udp_frame_with_router_alert(payload=b"hello")))

        data, ancdata, _flags, _address = self._socket.recvmsg(ancbufsize=256, timeout=0.5)

        self.assertEqual(
            data,
            b"hello",
            msg="Payload must be delivered regardless of IP_RECVOPTS.",
        )
        self.assertEqual(
            ancdata,
            [],
            msg="ancdata must be empty when IP_RECVOPTS is not set.",
        )

    def test__udp__ip_options__recvmsg_no_cmsg_when_no_options(self) -> None:
        """
        Ensure 'recvmsg' returns empty ancdata when the inbound
        datagram carries no IPv4 options, even with IP_RECVOPTS=1
        on the socket. The cmsg is only emitted for datagrams
        that actually carried options.

        Reference: RFC 1122 §4.1.3.2 (cmsg surface limited to
        options actually carried).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_RECVOPTS, 1)

        self._packet_handler._phrx_ethernet(PacketRx(_build_udp_frame_plain(payload=b"hello")))

        data, ancdata, _flags, _address = self._socket.recvmsg(ancbufsize=256, timeout=0.5)

        self.assertEqual(
            data,
            b"hello",
            msg="Payload must be delivered when the datagram carried no IPv4 options.",
        )
        self.assertEqual(
            ancdata,
            [],
            msg="ancdata must be empty when no IPv4 options were carried.",
        )


class TestUdpIpOptionsSendto(NetworkTestCase):
    """
    Outbound UDP datagrams carry the per-socket IP_OPTIONS block.
    """

    def setUp(self) -> None:
        """
        Bind a UdpSocket so 'sendto' has a stack-known local
        address / port to source from.
        """

        super().setUp()
        self._socket = UdpSocket(
            family=AddressFamily.INET4,
            type=SocketType.DGRAM,
            protocol=IpProto.UDP,
        )
        self._socket._local_ip_address = _STACK_IP4
        self._socket._local_port = _LOCAL_PORT
        stack.sockets[self._socket.socket_id] = self._socket
        self.addCleanup(self._socket.close)

    def test__udp__ip_options__sendto_emits_options_block_on_wire(self) -> None:
        """
        Ensure a UDP socket with 'setsockopt(IP_OPTIONS, bytes)'
        emits the options block on every outbound datagram. The
        outbound IPv4 header carries the configured options;
        'hlen' is bumped to cover them; the parsed options block
        round-trips back to the configured bytes.

        Reference: RFC 1122 §4.1.3.2 (application MUST be able to
        specify IP options to be sent).
        """

        self._socket.setsockopt(IPPROTO_IP, IP_OPTIONS, _ROUTER_ALERT_BYTES)

        sent = self._socket.sendto(b"hello", (str(_HOST_A_IP4), _REMOTE_PORT))

        self.assertEqual(
            sent,
            len(b"hello"),
            msg="sendto() must report the full payload length when accepted by TxRing.",
        )
        self.assertEqual(
            len(self._frames_tx),
            1,
            msg="One outbound UDP datagram must be emitted.",
        )

        # Strip Ethernet header to feed the IPv4 portion into the parser.
        ip4_parser = Ip4Parser(PacketRx(self._frames_tx[0][14:]))
        self.assertEqual(
            ip4_parser.ver,
            IpVersion.IP4,
            msg="Outbound frame must be IPv4.",
        )
        self.assertEqual(
            ip4_parser.hlen,
            24,
            msg="hlen must be 24 (20-byte header + 4-byte Router Alert option).",
        )
        self.assertEqual(
            bytes(ip4_parser.options),
            _ROUTER_ALERT_BYTES,
            msg="Outbound IPv4 options block must equal the configured IP_OPTIONS bytes.",
        )

    def test__udp__ip_options__sendto_no_options_emits_unchanged_header(self) -> None:
        """
        Ensure a UDP socket without 'setsockopt(IP_OPTIONS, ...)'
        emits datagrams with the default 20-byte IPv4 header (no
        options). The default-empty IP_OPTIONS storage must not
        leak as an empty options block on the wire.

        Reference: RFC 1122 §4.1.3.2 (options are opt-in per
        socket).
        """

        sent = self._socket.sendto(b"hello", (str(_HOST_A_IP4), _REMOTE_PORT))

        self.assertEqual(
            sent,
            len(b"hello"),
            msg="sendto() must report the full payload length when accepted by TxRing.",
        )

        ip4_parser = Ip4Parser(PacketRx(self._frames_tx[0][14:]))
        self.assertEqual(
            ip4_parser.hlen,
            20,
            msg="hlen must be 20 (default IPv4 header, no options) when IP_OPTIONS is unset.",
        )
        self.assertEqual(
            bytes(ip4_parser.options),
            b"",
            msg="Outbound IPv4 options block must be empty when IP_OPTIONS is unset.",
        )
