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
This module contains unit tests for the 'PacketHandlerIp6FragTx' mixin.

pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__ip6_frag__tx.py

ver 3.0.4
"""

from unittest import TestCase

from net_addr import Ip6Address
from net_proto import Ip6Assembler, Ip6FragAssembler, RawAssembler
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.stack.packet_handler.packet_handler__ip6_frag__tx import (
    PacketHandlerIp6FragTx,
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


class _StubHandler(PacketHandlerIp6FragTx):
    """
    Minimal concrete subclass of 'PacketHandlerIp6FragTx' for testing.
    """

    def __init__(self, *, interface_mtu: int = 200, ip6_tx_status: TxStatus | None = None) -> None:
        self._packet_stats_tx = PacketStatsTx()
        self._ip6_id = 0
        self._interface_mtu = interface_mtu

        self.ip6_tx_calls: list[dict[str, object]] = []
        self.ip6_tx_status: TxStatus = ip6_tx_status or TxStatus.PASSED__ETHERNET__TO_TX_RING

    def _phtx_ip6(self, **kwargs: object) -> TxStatus:
        self.ip6_tx_calls.append(kwargs)
        return self.ip6_tx_status


class TestPacketHandlerIp6FragTx(TestCase):
    """
    The 'PacketHandlerIp6FragTx._phtx_ip6_frag' behaviour tests.
    """

    def _build_ip6_packet(self, *, payload_size: int) -> Ip6Assembler:
        """
        Build an 'Ip6Assembler' carrying 'payload_size' bytes of RAW data.
        """

        return Ip6Assembler(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(raw__payload=b"\x11" * payload_size),
        )

    def test__stack__packet_handler__ip6_frag__tx__splits_into_multiple_fragments(self) -> None:
        """
        Ensure a payload that exceeds the per-fragment MTU is split into
        at least two fragments and each is forwarded to '_phtx_ip6'.
        """

        handler = _StubHandler(interface_mtu=200)
        ip6_packet = self._build_ip6_packet(payload_size=400)

        status = handler._phtx_ip6_frag(ip6_packet_tx=ip6_packet)

        self.assertEqual(
            status,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            msg="Fragmentation with every fragment passing must return PASSED__ETHERNET__TO_TX_RING.",
        )
        self.assertEqual(
            handler._packet_stats_tx.ip6_frag__pre_assemble,
            1,
            msg="ip6_frag__pre_assemble must be incremented once per outbound packet.",
        )
        self.assertGreaterEqual(
            handler._packet_stats_tx.ip6_frag__send,
            2,
            msg="At least two fragments must be sent for a payload exceeding one MTU.",
        )
        self.assertGreaterEqual(
            len(handler.ip6_tx_calls),
            2,
            msg="At least two '_phtx_ip6' calls must be issued (one per fragment).",
        )
        for call in handler.ip6_tx_calls:
            self.assertIsInstance(
                call["ip6__payload"],
                Ip6FragAssembler,
                msg="Every per-fragment call must pass an Ip6FragAssembler payload.",
            )

    def test__stack__packet_handler__ip6_frag__tx__id_incremented_per_send(self) -> None:
        """
        Ensure 'self._ip6_id' is incremented once per '_phtx_ip6_frag'
        call and every fragment reuses that id.
        """

        handler = _StubHandler(interface_mtu=200)
        handler._ip6_id = 0

        handler._phtx_ip6_frag(ip6_packet_tx=self._build_ip6_packet(payload_size=400))
        self.assertEqual(handler._ip6_id, 1, msg="First call must set ip6_id to 1.")

        handler._phtx_ip6_frag(ip6_packet_tx=self._build_ip6_packet(payload_size=400))
        self.assertEqual(handler._ip6_id, 2, msg="Second call must set ip6_id to 2.")

    def test__stack__packet_handler__ip6_frag__tx__returns_worst_status(self) -> None:
        """
        Ensure the handler returns the most severe TX status when per-
        fragment results differ (documents the priority order).
        """

        handler = _StubHandler(
            interface_mtu=200,
            ip6_tx_status=TxStatus.DROPED__ETHERNET__DST_ND_CACHE_MISS,
        )
        status = handler._phtx_ip6_frag(ip6_packet_tx=self._build_ip6_packet(payload_size=400))

        self.assertEqual(
            status,
            TxStatus.DROPED__ETHERNET__DST_ND_CACHE_MISS,
            msg="Worst per-fragment status must propagate to the caller.",
        )
