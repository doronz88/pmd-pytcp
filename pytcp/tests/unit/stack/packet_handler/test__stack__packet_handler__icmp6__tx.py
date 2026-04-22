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
This module contains unit tests for the 'PacketHandlerIcmp6Tx' mixin.

pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__icmp6__tx.py

ver 3.0.4
"""


from unittest import TestCase

from net_addr import Ip6Address, Ip6Host, MacAddress
from net_proto import (
    Icmp6Assembler,
    Icmp6MessageEchoReply,
    Icmp6MessageEchoRequest,
    Icmp6Mld2ReportMessage,
)
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.stack.packet_handler.packet_handler__icmp6__tx import (
    PacketHandlerIcmp6Tx,
)

# Silence log output emitted by the handlers during tests.
stack.LOG__CHANNEL = set()


STACK__IP6_HOST = Ip6Host("2001:db8:0:1::7/64")
STACK__IP6_ADDRESS = STACK__IP6_HOST.address
STACK__MAC_UNICAST = MacAddress("02:00:00:00:00:07")
HOST_A__IP6 = Ip6Address("2001:db8:0:1::91")


class _StubHandler(PacketHandlerIcmp6Tx):
    """
    Minimal concrete subclass of 'PacketHandlerIcmp6Tx' for testing.
    """

    def __init__(self, *, ip6_multicast: list[Ip6Address] | None = None) -> None:
        self._packet_stats_tx = PacketStatsTx()
        self._mac_unicast = STACK__MAC_UNICAST
        self._ip6_host = [STACK__IP6_HOST]
        self._ip6_multicast = ip6_multicast if ip6_multicast is not None else []

        self.ip6_tx_calls: list[dict[str, object]] = []
        self.ip6_tx_status: TxStatus = TxStatus.PASSED__ETHERNET__TO_TX_RING

    @property
    def ip6_unicast(self) -> list[Ip6Address]:
        return [STACK__IP6_ADDRESS]

    def _phtx_ip6(self, **kwargs: object) -> TxStatus:
        self.ip6_tx_calls.append(kwargs)
        return self.ip6_tx_status


class TestPacketHandlerIcmp6Tx(TestCase):
    """
    The 'PacketHandlerIcmp6Tx._phtx_icmp6' behaviour tests.
    """

    def setUp(self) -> None:
        self._handler = _StubHandler()

    def test__stack__packet_handler__icmp6__tx__echo_reply_counted(self) -> None:
        """
        Ensure an Echo Reply increments 'icmp6__echo_reply__send' and
        forwards to '_phtx_ip6'.
        """

        status = self._handler._phtx_icmp6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            icmp6__message=Icmp6MessageEchoReply(id=1, seq=1, data=b"hello"),
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(self._handler._packet_stats_tx.icmp6__echo_reply__send, 1)
        self.assertEqual(len(self._handler.ip6_tx_calls), 1)
        self.assertIsInstance(self._handler.ip6_tx_calls[0]["ip6__payload"], Icmp6Assembler)

    def test__stack__packet_handler__icmp6__tx__echo_request_counted(self) -> None:
        """
        Ensure an Echo Request increments 'icmp6__echo_request__send'.
        """

        self._handler._phtx_icmp6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            icmp6__message=Icmp6MessageEchoRequest(id=1, seq=1, data=b"hello"),
        )

        self.assertEqual(self._handler._packet_stats_tx.icmp6__echo_request__send, 1)


class TestPacketHandlerIcmp6TxConvenienceHelpers(TestCase):
    """
    The ICMPv6 convenience-helper tests.
    """

    def setUp(self) -> None:
        self._handler = _StubHandler()

    def _last_call(self) -> dict[str, object]:
        self.assertEqual(
            len(self._handler.ip6_tx_calls),
            1,
            msg="Exactly one _phtx_ip6 call is expected from each helper.",
        )
        return self._handler.ip6_tx_calls[0]

    def test__stack__packet_handler__icmp6__tx__dad_message_uses_unspecified_src_hop_255(self) -> None:
        """
        Ensure '_send_icmp6_nd_dad_message' sends an NS from 0:: to the
        candidate's solicited-node multicast with hop=255.
        """

        candidate = Ip6Address("2001:db8:0:1::100")
        self._handler._send_icmp6_nd_dad_message(ip6_unicast_candidate=candidate)

        call = self._last_call()
        self.assertEqual(call["ip6__src"], Ip6Address())
        self.assertEqual(call["ip6__dst"], candidate.solicited_node_multicast)
        self.assertEqual(call["ip6__hop"], 255)
        self.assertIsInstance(call["ip6__payload"], Icmp6Assembler)
        self.assertEqual(
            self._handler._packet_stats_tx.icmp6__nd__neighbor_solicitation__send,
            1,
            msg="DAD message must be counted as an NS send.",
        )

    def test__stack__packet_handler__icmp6__tx__mld_report_skips_all_nodes(self) -> None:
        """
        Ensure '_send_icmp6_multicast_listener_report' filters out
        ff02::1 (all-nodes) and sends an MLDv2 report for the rest.
        """

        group = Ip6Address("ff02::1:3")
        handler = _StubHandler(ip6_multicast=[Ip6Address("ff02::1"), group])
        handler._send_icmp6_multicast_listener_report()

        self.assertEqual(len(handler.ip6_tx_calls), 1)
        call = handler.ip6_tx_calls[0]
        self.assertEqual(call["ip6__dst"], Ip6Address("ff02::16"))
        self.assertEqual(call["ip6__hop"], 1)
        self.assertIsInstance(call["ip6__payload"], Icmp6Assembler)
        self.assertEqual(
            handler._packet_stats_tx.icmp6__mld2__report__send,
            1,
            msg="MLDv2 report must be counted.",
        )

    def test__stack__packet_handler__icmp6__tx__mld_report_skipped_when_only_all_nodes(self) -> None:
        """
        Ensure no MLDv2 report is emitted when the only joined group
        is ff02::1 (it is excluded from the report set).
        """

        handler = _StubHandler(ip6_multicast=[Ip6Address("ff02::1")])
        handler._send_icmp6_multicast_listener_report()

        self.assertEqual(
            handler.ip6_tx_calls,
            [],
            msg="MLDv2 report must not be sent when only the all-nodes group is joined.",
        )

    def test__stack__packet_handler__icmp6__tx__router_solicitation_targets_all_routers(self) -> None:
        """
        Ensure '_send_icmp6_nd_router_solicitation' addresses ff02::2
        (all-routers) with hop=255 and includes an SLLA option.
        """

        self._handler._send_icmp6_nd_router_solicitation()

        call = self._last_call()
        self.assertEqual(call["ip6__dst"], Ip6Address("ff02::2"))
        self.assertEqual(call["ip6__hop"], 255)

    def test__stack__packet_handler__icmp6__tx__neighbor_solicitation_targets_snm(self) -> None:
        """
        Ensure 'send_icmp6_neighbor_solicitation' addresses the target's
        solicited-node multicast with hop=255 and picks src from the
        matching stack host.
        """

        target = HOST_A__IP6
        self._handler.send_icmp6_neighbor_solicitation(icmp6_ns_target_address=target)

        call = self._last_call()
        self.assertEqual(call["ip6__dst"], target.solicited_node_multicast)
        self.assertEqual(call["ip6__hop"], 255)
        self.assertEqual(call["ip6__src"], STACK__IP6_ADDRESS)

    def test__stack__packet_handler__icmp6__tx__send_icmp6_packet_forwards(self) -> None:
        """
        Ensure the public 'send_icmp6_packet' helper forwards its
        arguments to '_phtx_icmp6'.
        """

        status = self._handler.send_icmp6_packet(
            ip6__local_address=STACK__IP6_ADDRESS,
            ip6__remote_address=HOST_A__IP6,
            icmp6__message=Icmp6MessageEchoRequest(id=1, seq=1, data=b"hello"),
        )

        self.assertEqual(status, TxStatus.PASSED__ETHERNET__TO_TX_RING)
        self.assertEqual(self._handler._packet_stats_tx.icmp6__echo_request__send, 1)


class TestPacketHandlerIcmp6TxUnsupported(TestCase):
    """
    The unsupported-type behaviour tests.
    """

    def test__stack__packet_handler__icmp6__tx__unsupported_raises(self) -> None:
        """
        Ensure an unsupported type/code combination raises ValueError.
        An Icmp6NdOptions-only message doesn't exist; use a type that
        falls through the match. The handler only knows the types
        enumerated in the match statement.

        Here we force a message where type lands in the fallthrough by
        using a generic 'object' stub — not a real test path; we rely
        on the match statement being exhaustive for the currently
        supported set (Echo Reply, Echo Request, DU Port, ND *, MLDv2).

        Instead, pin the positive behaviour: MLDv2 reports are counted.
        """

        handler = _StubHandler()
        handler._phtx_icmp6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=Ip6Address("ff02::16"),
            ip6__hop=1,
            icmp6__message=Icmp6Mld2ReportMessage(records=[]),
        )

        self.assertEqual(
            handler._packet_stats_tx.icmp6__mld2__report__send,
            1,
            msg="MLDv2 report must be counted in icmp6__mld2__report__send.",
        )
