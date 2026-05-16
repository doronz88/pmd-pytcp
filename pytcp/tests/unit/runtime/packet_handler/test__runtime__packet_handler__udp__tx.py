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
This module contains unit tests for the 'PacketHandlerUdpTx' mixin.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__udp__tx.py

ver 3.0.5
"""

from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from net_proto import UdpAssembler
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.runtime.packet_handler.packet_handler__udp__tx import (
    PacketHandlerUdpTx,
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


STACK__IP4_ADDRESS = Ip4Address("10.0.1.7")
HOST_A__IP4 = Ip4Address("10.0.1.91")
STACK__IP6_ADDRESS = Ip6Address("2001:db8::7")
HOST_A__IP6 = Ip6Address("2001:db8::91")


class _StubHandler(PacketHandlerUdpTx):
    """
    Minimal concrete subclass of 'PacketHandlerUdpTx' for testing.
    """

    def __init__(self) -> None:
        self._packet_stats_tx = PacketStatsTx()
        self.ip4_tx_calls: list[dict[str, object]] = []
        self.ip6_tx_calls: list[dict[str, object]] = []

    def _phtx_ip4(self, **kwargs: object) -> TxStatus:
        self.ip4_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING

    def _phtx_ip6(self, **kwargs: object) -> TxStatus:
        self.ip6_tx_calls.append(kwargs)
        return TxStatus.PASSED__ETHERNET__TO_TX_RING


class TestPacketHandlerUdpTxRouting(TestCase):
    """
    The version-routing tests for 'PacketHandlerUdpTx._phtx_udp'.
    """

    def test__stack__packet_handler__udp__tx__ip4_routes_to_phtx_ip4(self) -> None:
        """
        Ensure a UDP datagram with IPv4 src/dst is forwarded to '_phtx_ip4'.
        """

        handler = _StubHandler()
        status = handler._phtx_udp(
            ip__src=STACK__IP4_ADDRESS,
            ip__dst=HOST_A__IP4,
            udp__sport=12345,
            udp__dport=54321,
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(len(handler.ip4_tx_calls), 1)
        self.assertEqual(handler.ip6_tx_calls, [])
        self.assertEqual(handler._packet_stats_tx.udp__send, 1)
        self.assertEqual(handler._packet_stats_tx.udp__pre_assemble, 1)
        self.assertIsInstance(handler.ip4_tx_calls[0]["ip4__payload"], UdpAssembler)

    def test__stack__packet_handler__udp__tx__ip6_routes_to_phtx_ip6(self) -> None:
        """
        Ensure a UDP datagram with IPv6 src/dst is forwarded to '_phtx_ip6'.
        """

        handler = _StubHandler()
        status = handler._phtx_udp(
            ip__src=STACK__IP6_ADDRESS,
            ip__dst=HOST_A__IP6,
            udp__sport=12345,
            udp__dport=54321,
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(len(handler.ip6_tx_calls), 1)
        self.assertEqual(handler.ip4_tx_calls, [])
        self.assertEqual(handler._packet_stats_tx.udp__send, 1)

    def test__stack__packet_handler__udp__tx__mixed_ip_versions_raises(self) -> None:
        """
        Ensure a mismatched IPv4 src / IPv6 dst raises ValueError.
        """

        handler = _StubHandler()
        with self.assertRaises(ValueError):
            handler._phtx_udp(
                ip__src=STACK__IP4_ADDRESS,
                ip__dst=HOST_A__IP6,
                udp__sport=12345,
                udp__dport=54321,
            )


class TestPacketHandlerUdpTxSendHelper(TestCase):
    """
    The public 'send_udp_packet' helper tests.
    """

    def test__stack__packet_handler__udp__tx__send_udp_packet_forwards(self) -> None:
        """
        Ensure 'send_udp_packet' forwards its arguments verbatim to
        '_phtx_udp'.
        """

        handler = _StubHandler()
        status = handler.send_udp_packet(
            ip__local_address=STACK__IP4_ADDRESS,
            ip__remote_address=HOST_A__IP4,
            udp__local_port=12345,
            udp__remote_port=54321,
            udp__payload=b"hello",
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(handler._packet_stats_tx.udp__send, 1)
        self.assertEqual(len(handler.ip4_tx_calls), 1)
        payload = handler.ip4_tx_calls[0]["ip4__payload"]
        assert isinstance(payload, UdpAssembler)
        self.assertEqual(payload.sport, 12345)
        self.assertEqual(payload.dport, 54321)
