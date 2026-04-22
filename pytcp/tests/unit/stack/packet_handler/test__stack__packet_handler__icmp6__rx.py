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
This module contains unit tests for the 'PacketHandlerIcmp6Rx' mixin.

pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__icmp6__rx.py

ver 3.0.4
"""


import threading
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip6Address, MacAddress
from net_proto import (
    Icmp6Assembler,
    Icmp6MessageEchoReply,
    Icmp6MessageEchoRequest,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdMessageRouterAdvertisement,
    Icmp6NdOptions,
    Ip6Assembler,
    Ip6Parser,
)
from net_proto.lib.packet_rx import PacketRx
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.lib.tx_status import TxStatus
from pytcp.stack.packet_handler.packet_handler__icmp6__rx import (
    PacketHandlerIcmp6Rx,
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
STACK__MAC_UNICAST = MacAddress("02:00:00:00:00:07")
HOST_A__IP6 = Ip6Address("2001:db8:0:1::91")


class _StubHandler(PacketHandlerIcmp6Rx):
    """
    Minimal concrete subclass of 'PacketHandlerIcmp6Rx' for testing.
    """

    def __init__(self) -> None:
        self._packet_stats_rx = PacketStatsRx()
        self._mac_unicast = STACK__MAC_UNICAST
        self._icmp6_nd_dad__ip6_unicast_candidate = None
        self._icmp6_nd_dad__event = threading.Semaphore(0)
        self._icmp6_nd_dad__tlla = None
        self._icmp6_ra__event = threading.Semaphore(0)
        self._icmp6_ra__prefixes = []

        self.icmp6_tx_calls: list[dict[str, object]] = []

    @property
    def ip6_unicast(self) -> list[Ip6Address]:
        return [STACK__IP6_ADDRESS]

    def _phtx_icmp6(self, **kwargs: object) -> TxStatus:
        self.icmp6_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING


def _packet_rx_from_ip6_icmp6(ip6_frame: bytes) -> PacketRx:
    """
    Build a 'PacketRx' parsed through 'Ip6Parser' so that the frame
    pointer is positioned at the ICMPv6 header.
    """

    packet_rx = PacketRx(ip6_frame)
    Ip6Parser(packet_rx)
    return packet_rx


def _build_icmp6_frame(
    *,
    src: Ip6Address,
    dst: Ip6Address,
    message: object,
    hop: int = 255,
) -> bytes:
    """
    Build an IPv6+ICMPv6 wire frame carrying 'message'. Defaults the
    IPv6 hop limit to 255, which is required by RFC 4861 for ND
    messages; caller can override for non-ND packets.
    """

    return bytes(
        Ip6Assembler(
            ip6__src=src,
            ip6__dst=dst,
            ip6__hop=hop,
            ip6__payload=Icmp6Assembler(icmp6__message=message),  # type: ignore[arg-type]
        )
    )


class _Icmp6RxTestBase(TestCase):
    """
    Common setUp for the ICMPv6 RX tests.
    """

    def setUp(self) -> None:
        self._handler = _StubHandler()
        self._sockets_patch = patch.object(stack, "sockets", dict[object, object]())
        self._sockets_patch.start()
        self._nd_cache_patch = patch.object(stack, "nd_cache", object())
        self._nd_cache_patch.start()

    def tearDown(self) -> None:
        self._sockets_patch.stop()
        self._nd_cache_patch.stop()


class TestPacketHandlerIcmp6RxParse(_Icmp6RxTestBase):
    """
    The parse-failure tests.
    """

    def test__stack__packet_handler__icmp6__rx__parse_fail_drops(self) -> None:
        """
        Ensure a malformed ICMPv6 frame is counted in
        'icmp6__failed_parse__drop'.
        """

        ip6 = bytearray(
            _build_icmp6_frame(
                src=HOST_A__IP6,
                dst=STACK__IP6_ADDRESS,
                message=Icmp6MessageEchoRequest(id=1, seq=1, data=b"hello"),
            )
        )
        # Corrupt the ICMPv6 checksum (bytes 42-43 = IPv6 40-byte header + 2).
        ip6[42] = 0xDE
        ip6[43] = 0xAD

        self._handler._phrx_icmp6(_packet_rx_from_ip6_icmp6(bytes(ip6)))

        self.assertEqual(
            self._handler._packet_stats_rx.icmp6__pre_parse,
            1,
            msg="icmp6__pre_parse must be incremented before the parse attempt.",
        )
        self.assertEqual(
            self._handler._packet_stats_rx.icmp6__failed_parse__drop,
            1,
            msg="Malformed ICMPv6 must be counted in icmp6__failed_parse__drop.",
        )


class TestPacketHandlerIcmp6RxEcho(_Icmp6RxTestBase):
    """
    The ICMPv6 Echo Request/Reply dispatch tests.
    """

    def test__stack__packet_handler__icmp6__rx__echo_request_triggers_reply(self) -> None:
        """
        Ensure an ICMPv6 Echo Request produces an Echo Reply with
        src=our-dst and dst=peer.
        """

        ip6 = _build_icmp6_frame(
            src=HOST_A__IP6,
            dst=STACK__IP6_ADDRESS,
            message=Icmp6MessageEchoRequest(id=42, seq=7, data=b"hello"),
        )

        self._handler._phrx_icmp6(_packet_rx_from_ip6_icmp6(ip6))

        self.assertEqual(
            self._handler._packet_stats_rx.icmp6__echo_request__respond_echo_reply,
            1,
            msg="Echo Request must be counted in icmp6__echo_request__respond_echo_reply.",
        )
        self.assertEqual(
            len(self._handler.icmp6_tx_calls),
            1,
            msg="Echo Request must invoke exactly one _phtx_icmp6.",
        )
        call = self._handler.icmp6_tx_calls[0]
        self.assertEqual(call["ip6__src"], STACK__IP6_ADDRESS)
        self.assertEqual(call["ip6__dst"], HOST_A__IP6)
        self.assertIsInstance(call["icmp6__message"], Icmp6MessageEchoReply)


class TestPacketHandlerIcmp6RxNd(_Icmp6RxTestBase):
    """
    The ICMPv6 ND (Neighbor Discovery) dispatch tests.
    """

    def test__stack__packet_handler__icmp6__rx__router_advertisement_counted(self) -> None:
        """
        Ensure an ICMPv6 RA from a link-local source is dispatched and
        counted. Per RFC 4861 the parser requires the src to be link-
        local, so the fixture uses fe80::1 rather than a GUA.
        """

        ra_message = Icmp6NdMessageRouterAdvertisement(
            hop=64,
            flag_m=False,
            flag_o=False,
            router_lifetime=1800,
            reachable_time=0,
            retrans_timer=0,
            options=Icmp6NdOptions(),
        )
        ip6 = _build_icmp6_frame(
            src=Ip6Address("fe80::1"),
            dst=Ip6Address("ff02::1"),
            message=ra_message,
        )

        self._handler._phrx_icmp6(_packet_rx_from_ip6_icmp6(ip6))

        self.assertGreaterEqual(
            self._handler._packet_stats_rx.icmp6__nd_router_advertisement,
            1,
            msg="Router Advertisement must be counted in icmp6__nd_router_advertisement.",
        )

    def test__stack__packet_handler__icmp6__rx__neighbor_solicitation_counts(self) -> None:
        """
        Ensure an ICMPv6 NS targeting our address is counted. The RX
        handler exercises the DAD / ND-cache paths which are patched
        out via the stub _phtx_icmp6.
        """

        ns_message = Icmp6NdMessageNeighborSolicitation(
            target_address=STACK__IP6_ADDRESS,
            options=Icmp6NdOptions(),
        )
        ip6 = _build_icmp6_frame(
            src=HOST_A__IP6,
            dst=STACK__IP6_ADDRESS,
            message=ns_message,
        )

        self._handler._phrx_icmp6(_packet_rx_from_ip6_icmp6(ip6))

        self.assertGreaterEqual(
            self._handler._packet_stats_rx.icmp6__nd_neighbor_solicitation,
            1,
            msg="Neighbor Solicitation must be counted in icmp6__nd_neighbor_solicitation.",
        )
