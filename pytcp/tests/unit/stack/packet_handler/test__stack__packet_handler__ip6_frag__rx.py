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
This module contains unit tests for the 'PacketHandlerIp6FragRx' mixin.

pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__ip6_frag__rx.py

ver 3.0.4
"""

from unittest import TestCase

from net_addr import Ip6Address
from net_proto import Ip6Assembler, Ip6Parser, IpProto
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ip6_frag.ip6_frag__assembler import Ip6FragAssembler
from pytcp import stack
from pytcp.lib.ip_frag import IpFragData, IpFragFlowId
from pytcp.lib.packet_stats import PacketStatsRx
from pytcp.stack.packet_handler.packet_handler__ip6_frag__rx import (
    PacketHandlerIp6FragRx,
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
HOST_A__IP6 = Ip6Address("2001:db8:0:1::91")


class _StubHandler(PacketHandlerIp6FragRx):
    """
    Minimal concrete subclass of 'PacketHandlerIp6FragRx' for testing.
    """

    def __init__(self) -> None:
        self._packet_stats_rx = PacketStatsRx()
        self._ip6_frag_flows: dict[IpFragFlowId, IpFragData] = {}

        # Spy: record each reassembled packet forwarded to _phrx_ip6.
        self.ip6_reassembled: list[PacketRx] = []

    def _phrx_ip6(self, packet_rx: PacketRx, /) -> None:
        self.ip6_reassembled.append(packet_rx)


def _ip6_frag_packet_rx(
    *,
    src: Ip6Address = HOST_A__IP6,
    dst: Ip6Address = STACK__IP6_ADDRESS,
    frag_id: int,
    offset: int,
    flag_mf: bool,
    payload: bytes,
    next_proto: IpProto = IpProto.UDP,
) -> PacketRx:
    """
    Build a 'PacketRx' that looks like one just parsed by 'Ip6Parser':
    'packet_rx.frame' points at the fragment extension header and
    'packet_rx.ip6' is populated.
    """

    frame = bytes(
        Ip6Assembler(
            ip6__src=src,
            ip6__dst=dst,
            ip6__payload=Ip6FragAssembler(
                ip6_frag__next=next_proto,
                ip6_frag__offset=offset,
                ip6_frag__flag_mf=flag_mf,
                ip6_frag__id=frag_id,
                ip6_frag__payload=payload,
            ),
        )
    )
    packet_rx = PacketRx(frame)
    Ip6Parser(packet_rx)
    return packet_rx


class TestPacketHandlerIp6FragRx(TestCase):
    """
    The 'PacketHandlerIp6FragRx._phrx_ip6_frag' behaviour tests.
    """

    def setUp(self) -> None:
        self._handler = _StubHandler()

    def test__stack__packet_handler__ip6_frag__rx__first_fragment_stored(self) -> None:
        """
        Ensure the first of two fragments is stored in the flow table
        and does not trigger a reassembly.
        """

        packet_rx = _ip6_frag_packet_rx(
            frag_id=1111,
            offset=0,
            flag_mf=True,
            payload=b"\x00" * 8,
        )
        self._handler._phrx_ip6_frag(packet_rx)

        self.assertEqual(
            self._handler._packet_stats_rx.ip6_frag__pre_parse,
            1,
            msg="ip6_frag__pre_parse must be incremented on every inbound fragment.",
        )
        self.assertEqual(
            self._handler._packet_stats_rx.ip6_frag__defrag,
            0,
            msg="Incomplete fragment set must not trigger defrag counter.",
        )
        self.assertEqual(
            len(self._handler._ip6_frag_flows),
            1,
            msg="The first fragment must be stored in the flow table.",
        )
        self.assertEqual(
            self._handler.ip6_reassembled,
            [],
            msg="Incomplete fragment set must not dispatch to _phrx_ip6.",
        )

    def test__stack__packet_handler__ip6_frag__rx__full_reassembly_dispatches_ip6(self) -> None:
        """
        Ensure two in-order fragments reassemble into a single packet
        dispatched to '_phrx_ip6' and the flow is purged.
        """

        frag0 = _ip6_frag_packet_rx(
            frag_id=2222,
            offset=0,
            flag_mf=True,
            payload=b"\xaa" * 8,
        )
        frag1 = _ip6_frag_packet_rx(
            frag_id=2222,
            offset=8,
            flag_mf=False,
            payload=b"\xbb" * 8,
        )

        self._handler._phrx_ip6_frag(frag0)
        self._handler._phrx_ip6_frag(frag1)

        self.assertEqual(
            self._handler._packet_stats_rx.ip6_frag__defrag,
            1,
            msg="Successful reassembly must increment ip6_frag__defrag.",
        )
        self.assertEqual(
            self._handler._ip6_frag_flows,
            {},
            msg="Flow entry must be cleared after full reassembly.",
        )
        self.assertEqual(
            len(self._handler.ip6_reassembled),
            1,
            msg="Reassembled packet must be forwarded to _phrx_ip6 exactly once.",
        )

    def test__stack__packet_handler__ip6_frag__rx__out_of_order_pending(self) -> None:
        """
        Ensure the reassembler stays pending when the final fragment
        arrives before the first.
        """

        # Final fragment (offset=8) arrives first.
        frag1 = _ip6_frag_packet_rx(
            frag_id=3333,
            offset=8,
            flag_mf=False,
            payload=b"\xbb" * 8,
        )
        self._handler._phrx_ip6_frag(frag1)

        self.assertEqual(
            self._handler._packet_stats_rx.ip6_frag__defrag,
            0,
            msg="Out-of-order final fragment alone must not trigger reassembly.",
        )
        self.assertEqual(self._handler.ip6_reassembled, [])

    def test__stack__packet_handler__ip6_frag__rx__repeated_fragment_updates_in_place(self) -> None:
        """
        Ensure re-receiving the same fragment updates the stored bytes
        rather than creating a new flow entry.
        """

        frag = _ip6_frag_packet_rx(
            frag_id=4444,
            offset=0,
            flag_mf=True,
            payload=b"\xcc" * 8,
        )
        # Parse a fresh packet_rx for each call because the parser
        # advances 'frame'.
        self._handler._phrx_ip6_frag(frag)
        frag2 = _ip6_frag_packet_rx(
            frag_id=4444,
            offset=0,
            flag_mf=True,
            payload=b"\xdd" * 8,
        )
        self._handler._phrx_ip6_frag(frag2)

        self.assertEqual(
            len(self._handler._ip6_frag_flows),
            1,
            msg="Repeated fragment must not duplicate the flow entry.",
        )
