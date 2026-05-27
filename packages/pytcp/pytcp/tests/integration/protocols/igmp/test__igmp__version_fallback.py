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
This module contains integration tests for the RFC 3376 §7 Host
Compatibility Mode state machine — an IGMPv3 host falling back to
IGMPv1 / IGMPv2 behaviour in the presence of an older-version querier.

net_proto/../pytcp/tests/integration/protocols/igmp/test__igmp__version_fallback.py

ver 3.0.6
"""

from typing import override

from net_addr import Ip4Address, MacAddress
from net_proto import IgmpVersion, IpProto
from net_proto.lib.buffer import Buffer
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp.protocols.igmp import igmp__constants
from pytcp.stack import sysctl
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

_ALL_SYSTEMS = Ip4Address("224.0.0.1")
_ALL_SYSTEMS_MAC = MacAddress("01:00:5e:00:00:01")
_ROUTER_IP = Ip4Address("10.0.1.1")
_ROUTER_MAC = MacAddress("02:00:00:00:00:91")


def _general_query_frame(*, max_resp_code: int, v3: bool = False) -> bytes:
    """
    Build a General Query frame to 224.0.0.1. An 8-octet body is a
    v1 Query (max_resp_code 0) or v2 Query (non-zero); the 12-octet
    body (v3=True) carries the QRV/QQIC/source-count fixed tail.
    """

    body = b"\x11" + bytes([max_resp_code]) + b"\x00\x00" + b"\x00\x00\x00\x00"
    if v3:
        body += b"\x02\x7d\x00\x00"  # Resv|S|QRV=2, QQIC=125, sources=0
    cksum = inet_cksum(body)
    body = body[:2] + cksum.to_bytes(2, "big") + body[4:]

    ethernet = EthernetAssembler(
        ethernet__src=_ROUTER_MAC,
        ethernet__dst=_ALL_SYSTEMS_MAC,
        ethernet__payload=Ip4Assembler(
            ip4__src=_ROUTER_IP,
            ip4__dst=_ALL_SYSTEMS,
            ip4__ttl=1,
            ip4__payload=RawAssembler(raw__payload=body, ip_proto=IpProto.IGMP),
        ),
    )
    buffers: list[Buffer] = []
    ethernet.assemble(buffers)

    return b"".join(bytes(buf) for buf in buffers)


class TestIgmpVersionFallback(IcmpTestCase):
    """
    The RFC 3376 §7 Host Compatibility Mode state-machine tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and admit the all-systems multicast MAC so the
        Ethernet RX accepts a Query addressed to 224.0.0.1.
        """

        super().setUp()
        self._packet_handler._mac_multicast.append(_ALL_SYSTEMS_MAC)

    def test__igmp__mode__defaults_to_v3(self) -> None:
        """
        Ensure a freshly initialised interface with no older-version
        querier seen reports Host Compatibility Mode IGMPv3.

        Reference: RFC 3376 §7.2.1 (default mode is IGMPv3).
        """

        self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V3)

    def test__igmp__mode__v2_query_flips_to_v2(self) -> None:
        """
        Ensure receiving an IGMPv2 General Query (8 octets, non-zero Max
        Resp Code) switches the interface to Host Compatibility Mode
        IGMPv2.

        Reference: RFC 3376 §7.2.1 (IGMPv2 Querier Present → IGMPv2 mode).
        """

        self._drive_rx(frame=_general_query_frame(max_resp_code=100))

        self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V2)

    def test__igmp__mode__v1_query_flips_to_v1(self) -> None:
        """
        Ensure receiving an IGMPv1 General Query (8 octets, zero Max Resp
        Code) switches the interface to Host Compatibility Mode IGMPv1.

        Reference: RFC 3376 §7.2.1 (IGMPv1 Querier Present → IGMPv1 mode).
        """

        self._drive_rx(frame=_general_query_frame(max_resp_code=0))

        self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V1)

    def test__igmp__mode__reverts_to_v3_after_timeout(self) -> None:
        """
        Ensure the interface reverts to Host Compatibility Mode IGMPv3
        once the Older Version Querier Present timeout elapses with no
        further older-version Query.

        Reference: RFC 3376 §8.12 (Older Version Querier Present Timeout).
        """

        self._drive_rx(frame=_general_query_frame(max_resp_code=100))
        self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V2)

        # Timeout = RV * Query Interval + one Query Response Interval;
        # advance just past it.
        timeout_ms = igmp__constants.IGMP__ROBUSTNESS_VARIABLE * igmp__constants.IGMP__QUERY_INTERVAL__MS + 100 * 100
        self._advance(ms=timeout_ms + 1)

        self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V3)

    def test__igmp__mode__v3_query_does_not_lower_mode(self) -> None:
        """
        Ensure an IGMPv3 General Query never lowers the compatibility
        mode — a host already in IGMPv2 mode stays in IGMPv2.

        Reference: RFC 3376 §7.2.1 (mode lowers only on an older-version Query).
        """

        self._drive_rx(frame=_general_query_frame(max_resp_code=100))
        self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V2)

        self._drive_rx(frame=_general_query_frame(max_resp_code=100, v3=True))

        self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V2)

    def test__igmp__mode__forced_version_pins_mode(self) -> None:
        """
        Ensure a forced 'igmp.version' sysctl pins the compatibility mode
        regardless of the queriers heard.

        Reference: RFC 3376 §7.2.1 (administrative version override).
        """

        with sysctl.override("igmp.version", 2):
            self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V2)
        with sysctl.override("igmp.version", 1):
            self.assertIs(self._packet_handler._igmp_host_compatibility_mode(), IgmpVersion.V1)

    def test__igmp__mode__change_cancels_pending_state_change_retransmit(self) -> None:
        """
        Ensure a compatibility-mode change cancels the pending
        state-change retransmit train so a stale v3 retransmit cannot
        fire after the host has dropped to an older mode.

        Reference: RFC 3376 §7.2.1 (a mode change cancels all pending response and retransmission timers).
        """

        # Pin the v2 Query's response delay well outside the advance
        # window below so only the (cancelled) state-change retransmit
        # could fire during it — the query response itself is a separate
        # timer that must not confound this assertion.
        self._packet_handler._igmp_rx._igmp_query__pick_response_delay_ms = (  # type: ignore[method-assign]
            lambda max_resp_ms: 9000
        )

        # Join a group → immediate v3 Report + a pending robustness
        # retransmit (default RV=2 schedules one).
        self._packet_handler._assign_ip4_multicast(Ip4Address("239.1.1.1"))
        self.assertNotEqual(
            self._packet_handler._igmp_tx._igmp_state_change__pending,
            {},
            msg="The join must leave a pending state-change retransmit.",
        )

        # A v2 Query flips the mode → the pending retransmit is cancelled.
        self._drive_rx(frame=_general_query_frame(max_resp_code=100))

        self.assertEqual(
            self._packet_handler._igmp_tx._igmp_state_change__pending,
            {},
            msg="A mode change must clear the pending state-change retransmits.",
        )
        # The cancelled retransmit must never fire afterwards.
        self.assertEqual(
            len(self._advance(ms=igmp__constants.IGMP__UNSOLICITED_REPORT_INTERVAL__MS + 1)),
            0,
            msg="The cancelled state-change retransmit must not fire after a mode change.",
        )
