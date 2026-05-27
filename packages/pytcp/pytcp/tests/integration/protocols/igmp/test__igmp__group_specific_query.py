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
This module contains integration tests for the RFC 3376 §5.2 per-group
response timer — an IGMPv3 host answering a Group-Specific Query with a
Current-State Record for only the queried group.

net_proto/../pytcp/tests/integration/protocols/igmp/test__igmp__group_specific_query.py

ver 3.0.6
"""

from types import SimpleNamespace
from typing import override

from net_addr import Ip4Address, MacAddress
from net_proto import IgmpV3RecordType, IpProto
from net_proto.lib.buffer import Buffer
from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.igmp.igmp__parser import IgmpParser
from net_proto.protocols.igmp.message.igmp__message__v3_report import (
    IgmpMessageV3Report,
)
from net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp.stack import sysctl
from pytcp.tests.lib.icmp_testcase import IcmpTestCase

_GROUP_A = Ip4Address("239.1.1.1")
_GROUP_B = Ip4Address("239.2.2.2")
_GROUP_A_MAC = MacAddress("01:00:5e:01:01:01")
_GROUP_B_MAC = MacAddress("01:00:5e:02:02:02")
_ALL_SYSTEMS = Ip4Address("224.0.0.1")
_ALL_SYSTEMS_MAC = MacAddress("01:00:5e:00:00:01")
_ROUTER_IP = Ip4Address("10.0.1.1")
_ROUTER_MAC = MacAddress("02:00:00:00:00:91")


def _query_frame(*, group: Ip4Address, max_resp_code: int = 100) -> bytes:
    """
    Build a 12-octet IGMPv3 Query. A non-zero 'group' is a
    Group-Specific Query (sent to the group); 0.0.0.0 is a General
    Query (sent to 224.0.0.1).
    """

    body = b"\x11" + bytes([max_resp_code]) + b"\x00\x00" + bytes(group) + b"\x02\x7d\x00\x00"
    cksum = inet_cksum(body)
    body = body[:2] + cksum.to_bytes(2, "big") + body[4:]

    general = group.is_unspecified
    ethernet = EthernetAssembler(
        ethernet__src=_ROUTER_MAC,
        ethernet__dst=_ALL_SYSTEMS_MAC if general else _GROUP_A_MAC,
        ethernet__payload=Ip4Assembler(
            ip4__src=_ROUTER_IP,
            ip4__dst=_ALL_SYSTEMS if general else group,
            ip4__ttl=1,
            ip4__payload=RawAssembler(raw__payload=body, ip_proto=IpProto.IGMP),
        ),
    )
    buffers: list[Buffer] = []
    ethernet.assemble(buffers)

    return b"".join(bytes(buf) for buf in buffers)


def _parse_v3_report(frame: bytes) -> IgmpMessageV3Report:
    """Decode the IGMPv3 Report carried in an Ethernet/IPv4 frame."""

    ihl = (frame[14] & 0x0F) * 4
    igmp_bytes = frame[14 + ihl :]
    packet_rx = PacketRx(igmp_bytes)
    packet_rx.ip4 = SimpleNamespace(payload_len=len(igmp_bytes))  # type: ignore[assignment]
    IgmpParser(packet_rx)
    message = packet_rx.igmp.message
    assert isinstance(message, IgmpMessageV3Report)

    return message


class TestIgmpGroupSpecificQuery(IcmpTestCase):
    """
    The RFC 3376 §5.2 Group-Specific Query per-group response tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness, admit the group / all-systems MACs, and join
        two groups so a per-group response is distinguishable from the
        all-groups General-Query response.
        """

        super().setUp()
        # Robustness 1 so the setUp joins schedule no state-change
        # retransmit that would land in the response windows under test.
        self.enterContext(sysctl.override("igmp.robustness", 1))
        self._packet_handler._mac_multicast.append(_ALL_SYSTEMS_MAC)
        self._packet_handler._mac_multicast.append(_GROUP_A_MAC)
        self._packet_handler._mac_multicast.append(_GROUP_B_MAC)
        self._packet_handler._assign_ip4_multicast(_GROUP_A)
        self._packet_handler._assign_ip4_multicast(_GROUP_B)

    def _patch_delay(self, *, returns_ms: int) -> None:
        """Force the response-delay picker to a deterministic value."""

        self._packet_handler._igmp_rx._igmp_query__pick_response_delay_ms = (  # type: ignore[method-assign]
            lambda max_resp_ms: returns_ms
        )

    def test__igmp__group_query__responds_only_for_queried_group(self) -> None:
        """
        Ensure a Group-Specific Query elicits a Report carrying a
        Current-State Record for only the queried group, not every
        joined group.

        Reference: RFC 3376 §5.2 (group-timer expiry sends one record for the group).
        """

        self._patch_delay(returns_ms=0)

        before = len(self._frames_tx)
        self._drive_rx(frame=_query_frame(group=_GROUP_A))

        frames = self._frames_tx[before:]
        self.assertEqual(len(frames), 1, msg="A Group-Specific Query elicits one Report.")
        report = _parse_v3_report(frames[0])
        self.assertEqual(
            [record.multicast_address for record in report.records],
            [_GROUP_A],
            msg="The response must carry a record for only the queried group.",
        )
        self.assertEqual(report.records[0].type, IgmpV3RecordType.MODE_IS_EXCLUDE)

    def test__igmp__group_query__not_joined_group_no_response(self) -> None:
        """
        Ensure a Group-Specific Query for a group the interface has not
        joined elicits no response.

        Reference: RFC 3376 §5.2 (respond iff the interface has reception state for the group).
        """

        self._patch_delay(returns_ms=0)

        before = len(self._frames_tx)
        self._drive_rx(frame=_query_frame(group=Ip4Address("239.9.9.9")))

        self.assertEqual(
            len(self._frames_tx[before:]),
            0,
            msg="A Group-Specific Query for an unjoined group must elicit no Report.",
        )

    def test__igmp__group_query__deferred_fires_for_group(self) -> None:
        """
        Ensure a delayed Group-Specific Query response is scheduled on a
        per-group timer and fires for the queried group when the delay
        elapses.

        Reference: RFC 3376 §5.2 (per-group response timer).
        """

        self._patch_delay(returns_ms=500)

        self._drive_rx(frame=_query_frame(group=_GROUP_A))
        self.assertEqual(len(self._advance(ms=499)), 0, msg="No response before the per-group delay elapses.")

        tx = self._advance(ms=1)
        self.assertEqual(len(tx), 1, msg="The per-group response fires when the delay elapses.")
        report = _parse_v3_report(tx[0])
        self.assertEqual(
            [record.multicast_address for record in report.records],
            [_GROUP_A],
            msg="The deferred response must carry only the queried group.",
        )

    def test__igmp__group_query__absorbed_by_sooner_general_response(self) -> None:
        """
        Ensure a Group-Specific Query is not separately scheduled when a
        General-Query response is already pending sooner — the General
        response already covers the group.

        Reference: RFC 3376 §5.2 rule 1 (pending General response sooner absorbs the Query).
        """

        # A General Query schedules the interface response at 200 ms.
        self._patch_delay(returns_ms=200)
        self._drive_rx(frame=_query_frame(group=Ip4Address()))

        # A Group-Specific Query whose delay (500 ms) is later than the
        # pending General response must not schedule a per-group timer.
        self._patch_delay(returns_ms=500)
        self._drive_rx(frame=_query_frame(group=_GROUP_A))

        self.assertEqual(
            self._packet_handler._igmp_group_query__pending,
            {},
            msg="A Group-Specific Query must be absorbed by a sooner pending General response.",
        )
