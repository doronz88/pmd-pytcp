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
End-to-end DAD-flow integration tests for the ARP probe / claim
sequence. Drive 'PacketHandlerL2._create_stack_ip4_addressing'
synchronously through the 'ArpTestCase._drive_dad' helper, with
optional conflicting RX frames injected into the probe window
via the per-iteration 'on_sleep' callback. Pin the RFC 5227
§2.1.1 probe-conflict-aborts-claim invariant — closed by commit
'cffd4841' (RX-vs-DAD set disconnect fix).

pytcp/tests/integration/protocols/arp/test__arp__dad.py

ver 3.0.4
"""

from net_proto import ArpOperation
from pytcp.tests.lib.arp_testcase import (
    HOST_A__MAC_ADDRESS,
    IP4__UNSPECIFIED,
    MAC__BROADCAST,
    MAC__UNSPECIFIED,
    STACK__IP4_HOST,
    STACK__IP4_HOST__CANDIDATE,
    STACK__MAC_ADDRESS,
    ArpTestCase,
)


class TestArpDad(ArpTestCase):
    """
    The DAD claim-flow tests — RFC 5227 §2.1 / §2.1.1 / §2.3
    end-to-end behaviour. Drives 'PacketHandlerL2._create_stack_ip4_addressing'
    synchronously and observes the resulting frames + state.
    """

    def test__arp__dad__no_conflict_admits_candidate(self) -> None:
        """
        Ensure the DAD flow with no conflicting RX frames during
        the probe window admits the candidate IP to '_ip4_host'
        and emits the announcement after the probe loop completes.
        Three probes + one announcement = four wire frames.

        Reference: RFC 5227 §2.1 (MUST probe before use).
        Reference: RFC 5227 §2.3 (MUST announce after probe).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address
        addresses_before = {host.address for host in self._packet_handler._ip4_host}
        self.assertNotIn(
            candidate_address,
            addresses_before,
            msg="Pre-condition: candidate IP must not already be in '_ip4_host'.",
        )

        self._drive_dad()

        addresses_after = {host.address for host in self._packet_handler._ip4_host}
        self.assertIn(
            candidate_address,
            addresses_after,
            msg=("Candidate IP must be admitted to '_ip4_host' once DAD completes " "without conflict."),
        )
        self.assertEqual(
            self._packet_handler._ip4_host_candidate,
            [],
            msg="'_ip4_host_candidate' must be drained once each candidate has been resolved.",
        )
        self.assertNotIn(
            candidate_address,
            self._packet_handler._arp_probe__unicast_conflict,
            msg="Candidate IP must not be flagged as conflicted on a successful claim.",
        )
        self.assertEqual(
            len(self._frames_tx),
            4,
            msg=(
                "Expected exactly four wire frames after DAD: 3 ARP Probes + 1 "
                f"ARP Announcement. Got: {len(self._frames_tx)} frames."
            ),
        )

    def test__arp__dad__gratuitous_request_conflict_aborts_claim(self) -> None:
        """
        Ensure a broadcast gratuitous ARP Request whose SPA
        matches our candidate IP and arrives during the probe
        window flags the candidate as conflicted and prevents
        admission to '_ip4_host'. Pins the RFC 5227 §2.1.1
        MUST end-to-end — the regression that commit cffd4841
        closed (RX-vs-DAD set disconnect).

        Reference: RFC 5227 §2.1.1 (probe-conflict aborts claim).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address

        def _inject_conflict(idx: int) -> None:
            if idx == 0:
                self._drive_arp(
                    ethernet_dst=MAC__BROADCAST,
                    ethernet_src=HOST_A__MAC_ADDRESS,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=HOST_A__MAC_ADDRESS,
                    arp_spa=candidate_address,
                    arp_tha=MAC__UNSPECIFIED,
                    arp_tpa=candidate_address,
                )

        self._drive_dad(on_sleep=_inject_conflict)

        addresses_after = {host.address for host in self._packet_handler._ip4_host}
        self.assertNotIn(
            candidate_address,
            addresses_after,
            msg=(
                "Candidate IP must NOT be admitted to '_ip4_host' when a "
                "conflicting gratuitous ARP Request is received during the probe window."
            ),
        )
        self.assertIn(
            candidate_address,
            self._packet_handler._arp_probe__unicast_conflict,
            msg=(
                "Conflicting candidate IP must be registered in the per-instance "
                "'_arp_probe__unicast_conflict' set so DAD aborts the claim."
            ),
        )

    def test__arp__dad__direct_reply_to_probe_conflict_aborts_claim(self) -> None:
        """
        Ensure a unicast ARP Reply addressed to us with SPA
        matching our candidate IP and TPA = unspecified (the
        canonical reply-to-our-probe shape) flags the candidate
        as conflicted and prevents admission to '_ip4_host'.

        Reference: RFC 5227 §2.1.1 (probe-conflict aborts claim).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address

        def _inject_conflict(idx: int) -> None:
            if idx == 0:
                self._drive_arp(
                    ethernet_dst=STACK__MAC_ADDRESS,
                    ethernet_src=HOST_A__MAC_ADDRESS,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=HOST_A__MAC_ADDRESS,
                    arp_spa=candidate_address,
                    arp_tha=STACK__MAC_ADDRESS,
                    arp_tpa=IP4__UNSPECIFIED,
                )

        self._drive_dad(on_sleep=_inject_conflict)

        addresses_after = {host.address for host in self._packet_handler._ip4_host}
        self.assertNotIn(
            candidate_address,
            addresses_after,
            msg=(
                "Candidate IP must NOT be admitted to '_ip4_host' when a "
                "unicast ARP Reply targeting our probe arrives during the probe window."
            ),
        )
        self.assertIn(
            candidate_address,
            self._packet_handler._arp_probe__unicast_conflict,
            msg=(
                "Conflicting candidate IP must be registered in the per-instance " "'_arp_probe__unicast_conflict' set."
            ),
        )

    def test__arp__dad__gratuitous_reply_conflict_aborts_claim(self) -> None:
        """
        Ensure a broadcast gratuitous ARP Reply (SPA == TPA ==
        candidate) arriving during the probe window flags the
        candidate as conflicted and prevents admission. Covers
        the third RFC 5227 §2.1.1 probe-conflict shape (the
        first two are gratuitous Request and direct Reply).

        Reference: RFC 5227 §2.1.1 (probe-conflict aborts claim).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address

        def _inject_conflict(idx: int) -> None:
            if idx == 0:
                self._drive_arp(
                    ethernet_dst=MAC__BROADCAST,
                    ethernet_src=HOST_A__MAC_ADDRESS,
                    arp_oper=ArpOperation.REPLY,
                    arp_sha=HOST_A__MAC_ADDRESS,
                    arp_spa=candidate_address,
                    arp_tha=MAC__UNSPECIFIED,
                    arp_tpa=candidate_address,
                )

        self._drive_dad(on_sleep=_inject_conflict)

        addresses_after = {host.address for host in self._packet_handler._ip4_host}
        self.assertNotIn(
            candidate_address,
            addresses_after,
            msg=(
                "Candidate IP must NOT be admitted to '_ip4_host' when a "
                "gratuitous ARP Reply for the candidate arrives during the probe window."
            ),
        )
        self.assertIn(
            candidate_address,
            self._packet_handler._arp_probe__unicast_conflict,
            msg=(
                "Conflicting candidate IP must be registered in the per-instance " "'_arp_probe__unicast_conflict' set."
            ),
        )

    def test__arp__dad__conflict_skips_remaining_probes(self) -> None:
        """
        Ensure that once a conflict is detected during the probe
        window, subsequent probe iterations skip the candidate
        (since 'ip4_unicast not in self._arp_probe__unicast_conflict'
        is now False). Pins that the probe loop honours the
        conflict-set as an early-exit gate, not just at claim
        time.

        Reference: RFC 5227 §2.1.1 (probe-conflict aborts claim).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address

        def _inject_conflict(idx: int) -> None:
            if idx == 0:
                self._drive_arp(
                    ethernet_dst=MAC__BROADCAST,
                    ethernet_src=HOST_A__MAC_ADDRESS,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=HOST_A__MAC_ADDRESS,
                    arp_spa=candidate_address,
                    arp_tha=MAC__UNSPECIFIED,
                    arp_tpa=candidate_address,
                )

        self._drive_dad(on_sleep=_inject_conflict)

        # Probes are broadcast Requests with SPA = 0.0.0.0;
        # filter the TX log to count just our probes.
        from net_proto import ArpParser
        from net_proto.lib.packet_rx import PacketRx

        probe_count = 0
        for frame_tx in self._frames_tx:
            packet_rx = PacketRx(frame_tx[14:])  # skip Ethernet header
            try:
                ArpParser(packet_rx)
            except Exception:  # pragma: no cover - defensive
                continue
            if (
                packet_rx.arp.oper is ArpOperation.REQUEST
                and packet_rx.arp.spa == IP4__UNSPECIFIED
                and packet_rx.arp.tpa == candidate_address
            ):
                probe_count += 1

        self.assertEqual(
            probe_count,
            1,
            msg=(
                "After conflict detection at iteration 0, subsequent probe "
                "iterations must skip the candidate. Expected 1 probe (the "
                f"one at iteration 0); got {probe_count}."
            ),
        )

    def test__arp__dad__candidate_already_in_ip4_host_unchanged(self) -> None:
        """
        Ensure DAD does not displace already-claimed addresses
        from '_ip4_host' regardless of probe outcome — the
        non-candidate stack IP set up by 'NetworkTestCase' must
        still be present after DAD runs.

        Reference: RFC 5227 §2.1 (probe scope is candidates only).
        """

        existing_address = STACK__IP4_HOST.address

        self._drive_dad()

        addresses_after = {host.address for host in self._packet_handler._ip4_host}
        self.assertIn(
            existing_address,
            addresses_after,
            msg=(
                "Pre-existing stack IPs must remain in '_ip4_host' across the "
                "DAD run; only candidates participate in the probe loop."
            ),
        )
