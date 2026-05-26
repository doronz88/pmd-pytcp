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
This module contains integration tests for the IPv4 multicast
membership reference counting (R3 Phase A) — a group is held until the
last socket leaves, and an operator leave does not drop a group a
socket still holds.

net_proto/../pytcp/tests/integration/protocols/igmp/test__igmp__socket_membership_refcount.py

ver 3.0.6
"""

from types import SimpleNamespace
from typing import override

from net_addr import Ip4Address
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.igmp.igmp__parser import IgmpParser
from net_proto.protocols.igmp.message.igmp__message__v3_report import (
    IgmpMessageV3Report,
)
from net_proto.protocols.igmp.message.igmp__v3_group_record import (
    IgmpV3RecordType,
)
from pytcp import stack
from pytcp.socket import (
    AF_INET,
    IP_ADD_MEMBERSHIP,
    IP_DROP_MEMBERSHIP,
    IPPROTO_IP,
    SOCK_DGRAM,
    socket,
)
from pytcp.tests.lib.network_testcase import NetworkTestCase

_GROUP = Ip4Address("239.1.1.1")
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """Silence the stack / socket log channels for this module's tests."""

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """Restore the original log channels after this module's tests."""

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


def _ip_mreq(group: Ip4Address, interface: str = "0.0.0.0") -> bytes:
    """Pack an 8-byte ip_mreq (imr_multiaddr + imr_interface)."""

    return bytes(group) + bytes(Ip4Address(interface))


def _igmp_report_frames(frames: list[bytes]) -> list[IgmpMessageV3Report]:
    """Decode every IGMPv3 Report carried in the given Ethernet frames."""

    reports: list[IgmpMessageV3Report] = []
    for frame in frames:
        # Ethernet II IPv4 (ethertype 0x0800) carrying IGMP (proto 2).
        if frame[12:14] != b"\x08\x00" or frame[14 + 9] != 2:
            continue
        ihl = (frame[14] & 0x0F) * 4
        igmp_bytes = frame[14 + ihl :]
        packet_rx = PacketRx(igmp_bytes)
        packet_rx.ip4 = SimpleNamespace(payload_len=len(igmp_bytes))  # type: ignore[assignment]
        IgmpParser(packet_rx)
        message = packet_rx.igmp.message
        assert isinstance(message, IgmpMessageV3Report)
        reports.append(message)

    return reports


class TestIgmpSocketMembershipRefcount(NetworkTestCase):
    """
    The IPv4 multicast membership reference-counting tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and open two datagram sockets that will join
        the same multicast group.
        """

        super().setUp()
        self._socket_a = socket(AF_INET, SOCK_DGRAM)
        self.addCleanup(self._socket_a.close)
        self._socket_b = socket(AF_INET, SOCK_DGRAM)
        self.addCleanup(self._socket_b.close)

    def test__igmp__refcount__second_joiner_emits_no_report(self) -> None:
        """
        Ensure the second socket joining a group the interface already
        holds emits no additional state-change Report and adds no
        duplicate interface entry — only the first join crosses the
        not-joined→joined edge.

        Reference: RFC 3376 §5.1 (state-change Report on the join edge).
        """

        before = len(self._frames_tx)
        self._socket_a.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _ip_mreq(_GROUP))
        self._socket_b.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _ip_mreq(_GROUP))

        reports = _igmp_report_frames(self._frames_tx[before:])
        self.assertEqual(len(reports), 1, msg="Only the first joiner crosses the join edge and reports.")
        self.assertEqual(reports[0].records[0].type, IgmpV3RecordType.CHANGE_TO_EXCLUDE_MODE)
        self.assertEqual(
            self._packet_handler._ip4_multicast.count(_GROUP),
            1,
            msg="The group must appear once on the interface despite two joiners.",
        )

    def test__igmp__refcount__first_leaver_retains_group(self) -> None:
        """
        Ensure that when two sockets hold a group and one leaves, the
        group stays joined on the interface and no Leave Report is sent.

        Reference: RFC 3376 §5.1 (Leave fires only on the joined→not-joined edge).
        """

        self._socket_a.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _ip_mreq(_GROUP))
        self._socket_b.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _ip_mreq(_GROUP))

        before = len(self._frames_tx)
        self._socket_a.setsockopt(IPPROTO_IP, IP_DROP_MEMBERSHIP, _ip_mreq(_GROUP))

        self.assertEqual(
            len(_igmp_report_frames(self._frames_tx[before:])),
            0,
            msg="No Leave Report while another socket still holds the group.",
        )
        self.assertIn(
            _GROUP,
            self._packet_handler._ip4_multicast,
            msg="The group must remain joined while a holder remains.",
        )

    def test__igmp__refcount__last_leaver_drops_group(self) -> None:
        """
        Ensure the last socket leaving a group drops it from the
        interface and emits exactly one CHANGE_TO_INCLUDE_MODE Leave.

        Reference: RFC 3376 §5.1 (Leave on the joined→not-joined edge).
        """

        self._socket_a.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _ip_mreq(_GROUP))
        self._socket_b.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _ip_mreq(_GROUP))
        self._socket_a.setsockopt(IPPROTO_IP, IP_DROP_MEMBERSHIP, _ip_mreq(_GROUP))

        before = len(self._frames_tx)
        self._socket_b.setsockopt(IPPROTO_IP, IP_DROP_MEMBERSHIP, _ip_mreq(_GROUP))

        reports = _igmp_report_frames(self._frames_tx[before:])
        self.assertEqual(len(reports), 1, msg="The last leaver emits exactly one Leave Report.")
        self.assertEqual(reports[0].records[0].type, IgmpV3RecordType.CHANGE_TO_INCLUDE_MODE)
        self.assertNotIn(
            _GROUP,
            self._packet_handler._ip4_multicast,
            msg="The group must be dropped once the last holder leaves.",
        )

    def test__igmp__refcount__operator_leave_respects_socket_holder(self) -> None:
        """
        Ensure an operator-API leave does not drop a group a socket still
        holds — the unified interface refcount prevents the operator and
        socket planes from clobbering each other.

        Reference: RFC 3376 §5.1 (membership persists while any holder remains).
        """

        self._socket_a.setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, _ip_mreq(_GROUP))

        before = len(self._frames_tx)
        stack.membership.interface(self._packet_handler._ifindex).leave(group=_GROUP)

        self.assertEqual(
            len(_igmp_report_frames(self._frames_tx[before:])),
            0,
            msg="An operator leave must not emit a Leave while a socket holds the group.",
        )
        self.assertIn(
            _GROUP,
            self._packet_handler._ip4_multicast,
            msg="The group must remain joined for the socket holder after an operator leave.",
        )
