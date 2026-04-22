#!/usr/bin/env python3

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
This module contains unit tests for the 'PacketHandlerIp6Tx' mixin.

pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__ip6__tx.py

ver 3.0.4
"""


from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip6Address, Ip6Host
from net_proto import Ip6Assembler, IpProto, RawAssembler
from pytcp import stack
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.stack.packet_handler.packet_handler__ip6__tx import (
    PacketHandlerIp6Tx,
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


STACK__IP6_HOST = Ip6Host("2001:db8:0:1::7/64")
STACK__IP6_HOST.gateway = Ip6Address("fe80::1")
STACK__IP6_ADDRESS = STACK__IP6_HOST.address
STACK__IP6_MULTICAST = Ip6Address("ff02::1")
HOST_A__IP6 = Ip6Address("2001:db8:0:1::91")
OFF_NET__IP6 = Ip6Address("2001:db8:ffff::99")


class _StubHandler(PacketHandlerIp6Tx):
    """
    Minimal concrete subclass of 'PacketHandlerIp6Tx' for testing.
    """

    def __init__(
        self,
        *,
        ip6_support: bool = True,
        interface_layer: InterfaceLayer = InterfaceLayer.L2,
        interface_mtu: int = 1500,
        ip6_hosts: list[Ip6Host] | None = None,
    ) -> None:
        self._packet_stats_tx = PacketStatsTx()
        self._ip6_support = ip6_support
        self._interface_layer = interface_layer
        self._interface_mtu = interface_mtu
        self._ip6_host = ip6_hosts if ip6_hosts is not None else [STACK__IP6_HOST]
        self._ip6_multicast = [STACK__IP6_MULTICAST]

        self.ethernet_tx_calls: list[dict[str, object]] = []
        self.frag_tx_calls: list[Ip6Assembler] = []
        self.ethernet_tx_status: TxStatus = TxStatus.PASSED__ETHERNET__TO_TX_RING
        self.frag_tx_status: TxStatus = TxStatus.PASSED__IP6__TO_TX_RING

    @property
    def _ip6_unicast(self) -> list[Ip6Address]:
        return [host.address for host in self._ip6_host]

    def _phtx_ethernet(self, **kwargs: object) -> TxStatus:
        self.ethernet_tx_calls.append(kwargs)
        return self.ethernet_tx_status

    def _phtx_ip6_frag(self, *, ip6_packet_tx: Ip6Assembler) -> TxStatus:
        self.frag_tx_calls.append(ip6_packet_tx)
        return self.frag_tx_status


class TestPacketHandlerIp6TxGating(TestCase):
    """
    The IPv6-support-flag gating tests.
    """

    def test__stack__packet_handler__ip6__tx__disabled_drops(self) -> None:
        """
        Ensure the handler drops when IPv6 support is disabled.
        """

        handler = _StubHandler(ip6_support=False)
        status = handler._phtx_ip6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.DROPED__IP6__NO_PROTOCOL_SUPPORT)
        self.assertEqual(handler._packet_stats_tx.ip6__no_proto_support__drop, 1)


class TestPacketHandlerIp6TxValidation(TestCase):
    """
    The source- and destination-address validation branches.
    """

    def setUp(self) -> None:
        self._handler = _StubHandler()

    def test__stack__packet_handler__ip6__tx__src_not_owned_drops(self) -> None:
        """
        Ensure an src not owned by the stack drops.
        """

        status = self._handler._phtx_ip6(
            ip6__src=OFF_NET__IP6,
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.DROPED__IP6__SRC_NOT_OWNED)
        self.assertEqual(self._handler._packet_stats_tx.ip6__src_not_owned__drop, 1)

    def test__stack__packet_handler__ip6__tx__src_multicast_replaced(self) -> None:
        """
        Ensure a multicast src is replaced with the stack unicast address.
        """

        self._handler._phtx_ip6(
            ip6__src=STACK__IP6_MULTICAST,
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(self._handler._packet_stats_tx.ip6__src_multicast__replace, 1)

    def test__stack__packet_handler__ip6__tx__src_multicast_no_unicast_drops(self) -> None:
        """
        Ensure a multicast src with no stack unicast drops.
        """

        handler = _StubHandler(ip6_hosts=[])
        status = handler._phtx_ip6(
            ip6__src=STACK__IP6_MULTICAST,
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.DROPED__IP6__SRC_MULTICAST)
        self.assertEqual(handler._packet_stats_tx.ip6__src_multicast__drop, 1)

    def test__stack__packet_handler__ip6__tx__src_unspec_local_dst_replaced(self) -> None:
        """
        Ensure an unspecified src with an in-network dst is replaced.
        """

        self._handler._phtx_ip6(
            ip6__src=Ip6Address(),
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(self._handler._packet_stats_tx.ip6__src_network_unspecified__replace_local, 1)

    def test__stack__packet_handler__ip6__tx__src_unspec_external_gateway_replaced(self) -> None:
        """
        Ensure an unspecified src with an external unicast dst picks
        the first gateway-having host.
        """

        self._handler._phtx_ip6(
            ip6__src=Ip6Address(),
            ip6__dst=OFF_NET__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(self._handler._packet_stats_tx.ip6__src_network_unspecified__replace_external, 1)

    def test__stack__packet_handler__ip6__tx__src_unspec_no_replacement_drops(self) -> None:
        """
        Ensure an unspecified src with no replacement candidate drops.
        """

        handler = _StubHandler(ip6_hosts=[])
        status = handler._phtx_ip6(
            ip6__src=Ip6Address(),
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.DROPED__IP6__SRC_UNSPECIFIED)
        self.assertEqual(handler._packet_stats_tx.ip6__src_unspecified__drop, 1)

    def test__stack__packet_handler__ip6__tx__dst_unspecified_drops(self) -> None:
        """
        Ensure an unspecified dst drops.
        """

        status = self._handler._phtx_ip6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=Ip6Address(),
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.DROPED__IP6__DST_UNSPECIFIED)
        self.assertEqual(self._handler._packet_stats_tx.ip6__dst_unspecified__drop, 1)


class TestPacketHandlerIp6TxSend(TestCase):
    """
    The successful-send tests.
    """

    def test__stack__packet_handler__ip6__tx__l2_forwards_to_ethernet(self) -> None:
        """
        Ensure an L2-layer stack forwards within-MTU packets to the
        Ethernet TX layer.
        """

        handler = _StubHandler(interface_layer=InterfaceLayer.L2)
        status = handler._phtx_ip6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            ip6__payload=RawAssembler(),
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(handler._packet_stats_tx.ip6__mtu_ok__send, 1)
        self.assertEqual(len(handler.ethernet_tx_calls), 1)

    def test__stack__packet_handler__ip6__tx__l3_enqueues_on_tx_ring(self) -> None:
        """
        Ensure an L3-layer stack enqueues IPv6 packets directly on the
        TX ring.
        """

        handler = _StubHandler(interface_layer=InterfaceLayer.L3)
        with patch.object(stack, "tx_ring", MagicMock()) as mock_tx_ring:
            status = handler._phtx_ip6(
                ip6__src=STACK__IP6_ADDRESS,
                ip6__dst=HOST_A__IP6,
                ip6__payload=RawAssembler(),
            )

        self.assertEqual(status, TxStatus.PASSED__IP6__TO_TX_RING)
        self.assertEqual(handler._packet_stats_tx.ip6__mtu_ok__send, 1)
        mock_tx_ring.enqueue.assert_called_once()

    def test__stack__packet_handler__ip6__tx__over_mtu_delegates_to_frag(self) -> None:
        """
        Ensure a packet exceeding the interface MTU is delegated to
        '_phtx_ip6_frag' and its TxStatus returned.
        """

        handler = _StubHandler(interface_mtu=200)
        payload = RawAssembler(raw__payload=b"\x00" * 400)
        handler.frag_tx_status = TxStatus.PASSED__IP6__TO_TX_RING
        status = handler._phtx_ip6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            ip6__payload=payload,
        )

        self.assertEqual(status, TxStatus.PASSED__IP6__TO_TX_RING)
        self.assertEqual(handler._packet_stats_tx.ip6__mtu_exceed__frag, 1)
        self.assertEqual(len(handler.frag_tx_calls), 1)
        self.assertIsInstance(handler.frag_tx_calls[0], Ip6Assembler)


class TestPacketHandlerIp6TxSendIp6PacketHelper(TestCase):
    """
    The public 'send_ip6_packet' interface used by RAW sockets.
    """

    def test__stack__packet_handler__ip6__tx__send_ip6_packet_builds_raw_assembler(self) -> None:
        """
        Ensure 'send_ip6_packet' wraps the caller's bytes payload in a
        RawAssembler tagged with the supplied next header.
        """

        handler = _StubHandler()
        status = handler.send_ip6_packet(
            ip6__local_address=STACK__IP6_ADDRESS,
            ip6__remote_address=HOST_A__IP6,
            ip6__next=IpProto.UDP,
            ip6__payload=b"\x00" * 8,
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(len(handler.ethernet_tx_calls), 1)
        payload = handler.ethernet_tx_calls[0]["ethernet__payload"]
        assert isinstance(payload, Ip6Assembler)
        self.assertEqual(payload.next, IpProto.UDP)
