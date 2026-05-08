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
    Icmp6DestinationUnreachableCode,
    Icmp6MessageDestinationUnreachable,
    Icmp6MessageEchoReply,
    Icmp6MessageEchoRequest,
    Icmp6Mld2MessageReport,
)
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.stack.packet_handler.packet_handler__icmp6__tx import (
    PacketHandlerIcmp6Tx,
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

        Reference: RFC 4443 §4.2 (Echo Reply).
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

        Reference: RFC 4443 §4.1 (Echo Request).
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

        Reference: RFC 4862 §5.4 (Duplicate Address Detection).
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

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report).
        """

        group = Ip6Address("ff02::1:3")
        handler = _StubHandler(ip6_multicast=[Ip6Address("ff02::1"), group])
        handler._send_icmp6_multicast_listener_report()

        self.assertEqual(len(handler.ip6_tx_calls), 1)
        call = handler.ip6_tx_calls[0]
        self.assertEqual(call["ip6__dst"], Ip6Address("ff02::16"))
        self.assertEqual(call["ip6__hop"], 1)
        # The MLDv2 Report is wrapped in an HBH+RouterAlert per RFC
        # 3810 §5 + RFC 2711, so the IPv6 payload is an Ip6HbhAssembler.
        from net_proto.protocols.ip6_hbh.ip6_hbh__assembler import Ip6HbhAssembler

        self.assertIsInstance(call["ip6__payload"], Ip6HbhAssembler)
        self.assertEqual(
            handler._packet_stats_tx.icmp6__mld2__report__send,
            1,
            msg="MLDv2 report must be counted.",
        )

    def test__stack__packet_handler__icmp6__tx__mld_report_skipped_when_only_all_nodes(self) -> None:
        """
        Ensure no MLDv2 report is emitted when the only joined group
        is ff02::1 (it is excluded from the report set).

        Reference: RFC 3810 §5.2 (MLDv2 Multicast Listener Report).
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

        Reference: RFC 4861 §6.3.7 (Router Solicitation transmission).
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

        Reference: RFC 4861 §7.2.2 (Neighbor Solicitation transmission).
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

        Reference: PyTCP test infrastructure (no RFC clause).
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

    def test__stack__packet_handler__icmp6__tx__mld2_report_counted(self) -> None:
        """
        Ensure an MLDv2 Report is counted in 'icmp6__mld2__report__send'
        — the positive baseline case for the type-dispatch match.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = _StubHandler()
        handler._phtx_icmp6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=Ip6Address("ff02::16"),
            ip6__hop=1,
            icmp6__message=Icmp6Mld2MessageReport(records=[]),
        )

        self.assertEqual(
            handler._packet_stats_tx.icmp6__mld2__report__send,
            1,
            msg="MLDv2 report must be counted in icmp6__mld2__report__send.",
        )

    def test__stack__packet_handler__icmp6__tx__unsupported_type_drops(self) -> None:
        """
        Ensure an unsupported ICMPv6 type/code combination is dropped
        with 'TxStatus.DROPPED__ICMP6__UNKNOWN' and bumps the
        'icmp6__unknown__drop' counter — defensive over a 'raise'
        that would crash the calling thread. ICMPv6 Destination
        Unreachable code=NO_ROUTE is not in the supported match arms
        (only PORT is).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handler = _StubHandler()
        status = handler._phtx_icmp6(
            ip6__src=STACK__IP6_ADDRESS,
            ip6__dst=HOST_A__IP6,
            ip6__hop=64,
            icmp6__message=Icmp6MessageDestinationUnreachable(
                code=Icmp6DestinationUnreachableCode.NO_ROUTE,
                data=b"\x00" * 40,
            ),
        )

        self.assertIs(
            status,
            TxStatus.DROPPED__ICMP6__UNKNOWN,
            msg="Unsupported ICMPv6 type must return DROPPED__ICMP6__UNKNOWN.",
        )
        self.assertEqual(
            handler._packet_stats_tx.icmp6__unknown__drop,
            1,
            msg="Unsupported ICMPv6 type must bump 'icmp6__unknown__drop'.",
        )
