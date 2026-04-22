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
This module contains unit tests for the 'PacketHandlerIp6Rx' mixin.

pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__ip6__rx.py

ver 3.0.4
"""


from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip6Address
from net_proto import Ip6Assembler, IpProto, RawAssembler
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.stack.packet_handler.packet_handler__ip6__rx import (
    PacketHandlerIp6Rx,
)

# Snapshot log channels so 'setUpModule' can silence output during this
# module's tests and 'tearDownModule' can restore the global state.
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """
    Silence log output for the duration of this module's tests.
    """

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the snapshot of log channels after this module's tests finish.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


STACK__IP6_ADDRESS = Ip6Address("2001:db8:0:1::7")
STACK__IP6_MULTICAST = Ip6Address("ff02::1")
HOST_A__IP6 = Ip6Address("2001:db8:0:1::91")
OFF_NET__IP6 = Ip6Address("2001:db8:ffff::99")


class _StubHandler(PacketHandlerIp6Rx):
    """
    Minimal concrete subclass of 'PacketHandlerIp6Rx' for testing.
    """

    def __init__(self) -> None:
        """
        Initialize the stub handler with dispatch spies.
        """

        self._packet_stats_rx = PacketStatsRx()
        self._ip6_unicast_list = [STACK__IP6_ADDRESS]
        self._ip6_multicast = [STACK__IP6_MULTICAST]

        self.dispatched: list[str] = []

    @property
    def _ip6_unicast(self) -> list[Ip6Address]:
        return self._ip6_unicast_list

    def _phrx_ip6_frag(self, packet_rx: PacketRx, /) -> None:
        self.dispatched.append("ip6_frag")

    def _phrx_icmp6(self, packet_rx: PacketRx, /) -> None:
        self.dispatched.append("icmp6")

    def _phrx_udp(self, packet_rx: PacketRx, /) -> None:
        self.dispatched.append("udp")

    def _phrx_tcp(self, packet_rx: PacketRx, /) -> None:
        self.dispatched.append("tcp")


def _ip6_frame(
    *,
    src: Ip6Address = HOST_A__IP6,
    dst: Ip6Address = STACK__IP6_ADDRESS,
    ip_proto: IpProto = IpProto.UDP,
    payload: bytes = b"",
) -> bytes:
    """
    Build an IPv6 wire frame carrying the given proto in the next-header
    field via a 'RawAssembler' tagged with 'ip_proto'.
    """

    return bytes(
        Ip6Assembler(
            ip6__src=src,
            ip6__dst=dst,
            ip6__payload=RawAssembler(raw__payload=payload, ip_proto=ip_proto),
        )
    )


class _Ip6RxTestBase(TestCase):
    """
    Common setUp for the IPv6 RX tests.
    """

    def setUp(self) -> None:
        """
        Build the stub handler and isolate the stack sockets dict.
        """

        self._handler = _StubHandler()
        self._sockets_patch = patch.object(stack, "sockets", dict[object, object]())
        self._sockets_patch.start()

    def tearDown(self) -> None:
        """
        Restore the stack sockets dict.
        """

        self._sockets_patch.stop()


class TestPacketHandlerIp6RxParseAndFilter(_Ip6RxTestBase):
    """
    The parse-and-filter branches of 'PacketHandlerIp6Rx._phrx_ip6'.
    """

    def test__stack__packet_handler__ip6__rx__parse_fail_drops(self) -> None:
        """
        Ensure a truncated IPv6 frame is counted in
        'ip6__failed_parse__drop'.
        """

        self._handler._phrx_ip6(PacketRx(b"\x60\x00\x00"))

        self.assertEqual(
            self._handler._packet_stats_rx.ip6__failed_parse__drop,
            1,
            msg="Truncated IPv6 frame must be counted in ip6__failed_parse__drop.",
        )

    def test__stack__packet_handler__ip6__rx__unknown_dst_drops(self) -> None:
        """
        Ensure a packet to an unowned IPv6 is dropped.
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(dst=OFF_NET__IP6)))

        self.assertEqual(
            self._handler._packet_stats_rx.ip6__dst_unknown__drop,
            1,
            msg="Unknown IPv6 destination must be counted in ip6__dst_unknown__drop.",
        )

    def test__stack__packet_handler__ip6__rx__unicast_dst_counts(self) -> None:
        """
        Ensure a packet to the stack unicast IPv6 increments
        'ip6__dst_unicast'.
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(dst=STACK__IP6_ADDRESS, payload=b"\x00" * 8)))

        self.assertEqual(self._handler._packet_stats_rx.ip6__dst_unicast, 1)

    def test__stack__packet_handler__ip6__rx__multicast_dst_counts(self) -> None:
        """
        Ensure a packet to a joined multicast group increments
        'ip6__dst_multicast'.
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(dst=STACK__IP6_MULTICAST, payload=b"\x00" * 8)))

        self.assertEqual(self._handler._packet_stats_rx.ip6__dst_multicast, 1)


class TestPacketHandlerIp6RxDispatch(_Ip6RxTestBase):
    """
    The protocol-dispatch branches.
    """

    def test__stack__packet_handler__ip6__rx__udp_dispatches(self) -> None:
        """
        Ensure a UDP packet dispatches to '_phrx_udp'.
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(ip_proto=IpProto.UDP, payload=b"\x00" * 8)))

        self.assertEqual(self._handler.dispatched, ["udp"])

    def test__stack__packet_handler__ip6__rx__tcp_dispatches(self) -> None:
        """
        Ensure a TCP packet dispatches to '_phrx_tcp'.
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(ip_proto=IpProto.TCP, payload=b"\x00" * 20)))

        self.assertEqual(self._handler.dispatched, ["tcp"])

    def test__stack__packet_handler__ip6__rx__icmp6_dispatches(self) -> None:
        """
        Ensure an ICMPv6 packet dispatches to '_phrx_icmp6'.
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(ip_proto=IpProto.ICMP6, payload=b"\x00" * 8)))

        self.assertEqual(self._handler.dispatched, ["icmp6"])

    def test__stack__packet_handler__ip6__rx__frag_dispatches(self) -> None:
        """
        Ensure an IPv6 fragment dispatches to '_phrx_ip6_frag'.
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(ip_proto=IpProto.IP6_FRAG, payload=b"\x00" * 8)))

        self.assertEqual(self._handler.dispatched, ["ip6_frag"])

    def test__stack__packet_handler__ip6__rx__unsupported_proto_drops(self) -> None:
        """
        Ensure an unsupported next-header drops with
        'ip6__no_proto_support__drop'.
        """

        self._handler._phrx_ip6(PacketRx(_ip6_frame(ip_proto=IpProto.RAW, payload=b"\x00" * 8)))

        self.assertEqual(
            self._handler._packet_stats_rx.ip6__no_proto_support__drop,
            1,
            msg="Unsupported IPv6 next-header must be counted in ip6__no_proto_support__drop.",
        )
        self.assertEqual(self._handler.dispatched, [])


class TestPacketHandlerIp6RxRawSocketMatch(_Ip6RxTestBase):
    """
    The RAW-socket fastpath tests.
    """

    def test__stack__packet_handler__ip6__rx__raw_socket_match_short_circuits(self) -> None:
        """
        Ensure a matching RAW socket consumes the packet and prevents
        upper-layer dispatch.
        """

        fake_socket = MagicMock()

        class _MatchAllDict(dict[object, object]):
            def get(self, key: object, default: object = None) -> object:
                return fake_socket

        self._sockets_patch.stop()
        self._sockets_patch = patch.object(stack, "sockets", _MatchAllDict())
        self._sockets_patch.start()

        self._handler._phrx_ip6(PacketRx(_ip6_frame(ip_proto=IpProto.UDP, payload=b"\x00" * 8)))

        self.assertEqual(
            self._handler._packet_stats_rx.raw__socket_match,
            1,
            msg="A matched RAW socket must increment raw__socket_match.",
        )
        fake_socket.process_raw_packet.assert_called_once()
        self.assertEqual(self._handler.dispatched, [])
