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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
End-to-end DEFEND_INTERVAL integration tests for the RFC 5227
§2.4(c) defensive-ARP rate-limit. Drive conflicting ARP frames
through the full RX path with the harness's controlled
'time.monotonic()' clock and observe the defensive gratuitous
ARPs in '_frames_tx'. Pins the rate-limit closed by commit
'87851caa' (rate-limit conflict-defense gratuitous ARPs to once
per DEFEND_INTERVAL) at the wire level.

The unit-level counterpart at
'pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__arp__rx.py::TestPacketHandlerArpRxDefendInterval'
spies on '_send_gratuitous_arp'; this file observes the actual
defensive frames the TX path emits, validating the entire
RX→defense→TX round-trip.

pytcp/tests/integration/protocols/arp/test__arp__defend_interval.py

ver 3.0.5
"""

from net_addr import Ip4Address, Ip4IfAddr, MacAddress
from net_proto import ArpOperation
from pytcp.tests.lib.arp_testcase import (
    HOST_A__MAC_ADDRESS,
    MAC__BROADCAST,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
    ArpTestCase,
)

# Second stack-owned IP used by the per-IP independence test.
_STACK_IP4_HOST_2 = Ip4IfAddr("10.0.1.8/24")
_PEER_B_MAC = MacAddress("02:00:00:00:00:93")


class TestArpDefendInterval(ArpTestCase):
    """
    The RFC 5227 §2.4(c) DEFEND_INTERVAL rate-limit tests —
    end-to-end. Drives conflicting ARP packets through the full
    RX path with controlled 'time.monotonic()' and observes
    defensive gratuitous ARPs in the TX wire log.
    """

    def _drive_conflict(
        self,
        *,
        spa: Ip4Address,
        sha: MacAddress = HOST_A__MAC_ADDRESS,
    ) -> None:
        """
        Drive a conflicting unicast ARP Reply: SPA matches a
        stack-owned IP, SHA != stack MAC. Triggers the §2.4
        ongoing-conflict-detection-and-defense path.
        """

        self._drive_arp(
            ethernet_dst=STACK__MAC_ADDRESS,
            ethernet_src=sha,
            arp_oper=ArpOperation.REPLY,
            arp_sha=sha,
            arp_spa=spa,
            arp_tha=STACK__MAC_ADDRESS,
            arp_tpa=spa,
        )

    def _count_defense_frames(self, *, ip4_unicast: Ip4Address) -> int:
        """
        Count defensive gratuitous-ARP frames in '_frames_tx'
        for the given stack IP. A defensive gratuitous ARP is a
        broadcast Reply with SPA == TPA == our IP and SHA ==
        our MAC.
        """

        from net_proto import ArpParser
        from net_proto.lib.packet_rx import PacketRx

        count = 0
        for frame_tx in self._frames_tx:
            packet_rx = PacketRx(frame_tx[14:])  # skip Ethernet header
            try:
                ArpParser(packet_rx)
            except Exception:  # pragma: no cover - defensive
                continue
            if (
                packet_rx.arp.oper is ArpOperation.REPLY
                and packet_rx.arp.spa == ip4_unicast
                and packet_rx.arp.tpa == ip4_unicast
                and packet_rx.arp.sha == STACK__MAC_ADDRESS
                and frame_tx[:6] == bytes(MAC__BROADCAST)
            ):
                count += 1
        return count

    def test__arp__defend_interval__first_conflict_emits_defense(self) -> None:
        """
        Ensure the first conflicting ARP packet for a given
        stack IP emits a defensive gratuitous ARP on the wire
        — the rate-limit only gates subsequent defenses within
        the window, not the first one.

        Reference: RFC 5227 §2.4 (ongoing conflict detection and defense).
        """

        self._set_monotonic(1000.0)
        self._drive_conflict(spa=STACK__IP4_HOST.address)

        self.assertEqual(
            self._count_defense_frames(ip4_unicast=STACK__IP4_HOST.address),
            1,
            msg=(
                "The first conflicting ARP packet must emit exactly one defensive "
                "gratuitous ARP on the wire. Got: "
                f"{self._count_defense_frames(ip4_unicast=STACK__IP4_HOST.address)} frames."
            ),
        )

    def test__arp__defend_interval__second_within_interval_skipped(self) -> None:
        """
        Ensure a second conflicting ARP packet for the same
        stack IP within DEFEND_INTERVAL seconds of the previous
        defense does NOT emit a second defensive gratuitous ARP
        — the rate-limit prevents the host from contributing
        to a broadcast storm under sustained conflict.

        Reference: RFC 5227 §2.4(c) (MUST NOT defend within DEFEND_INTERVAL).
        """

        self._set_monotonic(1000.0)
        self._drive_conflict(spa=STACK__IP4_HOST.address)
        self._set_monotonic(1005.0)
        self._drive_conflict(spa=STACK__IP4_HOST.address)

        self.assertEqual(
            self._count_defense_frames(ip4_unicast=STACK__IP4_HOST.address),
            1,
            msg=(
                "A second conflict 5 s after the first (within DEFEND_INTERVAL = 10 s) "
                "must NOT emit a second defensive gratuitous ARP. Got: "
                f"{self._count_defense_frames(ip4_unicast=STACK__IP4_HOST.address)} frames."
            ),
        )

    def test__arp__defend_interval__after_interval_re_emits(self) -> None:
        """
        Ensure a conflicting ARP packet arriving more than
        DEFEND_INTERVAL seconds after the previous defense
        re-arms the defense and emits a fresh gratuitous ARP,
        AND the re-arm correctly resets the timestamp so a
        third conflict immediately after the re-arm is
        suppressed (proving the dict was updated, not that
        the rate-limit is absent).

        Reference: RFC 5227 §2.4(c) (defense re-armed after DEFEND_INTERVAL).
        """

        self._set_monotonic(1000.0)
        self._drive_conflict(spa=STACK__IP4_HOST.address)
        self._set_monotonic(1010.5)
        self._drive_conflict(spa=STACK__IP4_HOST.address)
        self._set_monotonic(1011.0)
        self._drive_conflict(spa=STACK__IP4_HOST.address)

        self.assertEqual(
            self._count_defense_frames(ip4_unicast=STACK__IP4_HOST.address),
            2,
            msg=(
                "Conflicts at t=1000 and t=1010.5 must each emit a defense "
                "(10.5 s apart, past DEFEND_INTERVAL); the third at t=1011.0 "
                "(0.5 s after the re-arm) must be suppressed. Got: "
                f"{self._count_defense_frames(ip4_unicast=STACK__IP4_HOST.address)} frames."
            ),
        )

    def test__arp__defend_interval__per_ip_independence(self) -> None:
        """
        Ensure the rate-limit is per-IP: a defense on IP A
        does NOT suppress a defense on IP B even within the
        same DEFEND_INTERVAL window. Drives a 3-packet sequence
        (A, A, B) so the no-rate-limit case [A, A, B] is
        distinguishable from the per-IP rate-limit case
        [A, B] at the wire level.

        Reference: RFC 5227 §2.4 (ongoing conflict detection and defense).
        """

        self._packet_handler._ip4_host = [STACK__IP4_HOST, _STACK_IP4_HOST_2]

        self._set_monotonic(1000.0)
        self._drive_conflict(spa=STACK__IP4_HOST.address)
        self._set_monotonic(1001.0)
        self._drive_conflict(spa=STACK__IP4_HOST.address)
        self._set_monotonic(1002.0)
        self._drive_conflict(spa=_STACK_IP4_HOST_2.address, sha=_PEER_B_MAC)

        self.assertEqual(
            self._count_defense_frames(ip4_unicast=STACK__IP4_HOST.address),
            1,
            msg=(
                "IP_A: first conflict at t=1000 must defend; second at t=1001 "
                "(within DEFEND_INTERVAL) must be suppressed. Got: "
                f"{self._count_defense_frames(ip4_unicast=STACK__IP4_HOST.address)} frames."
            ),
        )
        self.assertEqual(
            self._count_defense_frames(ip4_unicast=_STACK_IP4_HOST_2.address),
            1,
            msg=(
                "IP_B: conflict at t=1002 must defend (separate per-IP bucket; "
                "not affected by IP_A's recent defense). Got: "
                f"{self._count_defense_frames(ip4_unicast=_STACK_IP4_HOST_2.address)} frames."
            ),
        )
