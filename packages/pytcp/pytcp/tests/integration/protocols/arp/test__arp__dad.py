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

ver 3.0.5
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
        the probe window admits the candidate IP to '_ip4_ifaddr'
        and emits the announcement after the probe loop completes.
        Three probes + one announcement = four wire frames.

        Reference: RFC 5227 §2.1 (MUST probe before use).
        Reference: RFC 5227 §2.3 (MUST announce after probe).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address
        addresses_before = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertNotIn(
            candidate_address,
            addresses_before,
            msg="Pre-condition: candidate IP must not already be in '_ip4_ifaddr'.",
        )

        self._drive_dad()

        addresses_after = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertIn(
            candidate_address,
            addresses_after,
            msg=("Candidate IP must be admitted to '_ip4_ifaddr' once DAD completes " "without conflict."),
        )
        self.assertEqual(
            self._packet_handler._ip4_ifaddr_candidate,
            [],
            msg="'_ip4_ifaddr_candidate' must be drained once each candidate has been resolved.",
        )
        self.assertFalse(
            self._packet_handler._ip4_arp_dad__registry.has_signal(candidate_address),
            msg="Candidate IP must not be flagged as conflicted on a successful claim.",
        )
        self.assertEqual(
            len(self._frames_tx),
            5,
            msg=(
                "Expected exactly five wire frames after DAD: 3 ARP Probes + 2 "
                f"ARP Announcements (RFC 5227 §2.3 ANNOUNCE_NUM). Got: "
                f"{len(self._frames_tx)} frames."
            ),
        )

    def test__arp__dad__gratuitous_request_conflict_aborts_claim(self) -> None:
        """
        Ensure a broadcast gratuitous ARP Request whose SPA
        matches our candidate IP and arrives during the probe
        window flags the candidate as conflicted and prevents
        admission to '_ip4_ifaddr' — end-to-end pin of the
        probe-conflict MUST that commit cffd4841 closed
        (RX-vs-DAD set disconnect).

        Reference: RFC 5227 §2.1.1 (probe-conflict aborts claim).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address

        def _inject_conflict(idx: int) -> None:
            if idx == 1:  # first inter-probe sleep — within probe window
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

        addresses_after = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertNotIn(
            candidate_address,
            addresses_after,
            msg=(
                "Candidate IP must NOT be admitted to '_ip4_ifaddr' when a "
                "conflicting gratuitous ARP Request is received during the probe window."
            ),
        )
        self.assertTrue(
            self._packet_handler._ip4_arp_dad__registry.has_signal(candidate_address),
            msg=("Conflicting candidate IP must be flagged in the DAD slot " "registry so DAD aborts the claim."),
        )

    def test__arp__dad__direct_reply_to_probe_conflict_aborts_claim(self) -> None:
        """
        Ensure a unicast ARP Reply addressed to us with SPA
        matching our candidate IP and TPA = unspecified (the
        canonical reply-to-our-probe shape) flags the candidate
        as conflicted and prevents admission to '_ip4_ifaddr'.

        Reference: RFC 5227 §2.1.1 (probe-conflict aborts claim).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address

        def _inject_conflict(idx: int) -> None:
            if idx == 1:  # first inter-probe sleep — within probe window
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

        addresses_after = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertNotIn(
            candidate_address,
            addresses_after,
            msg=(
                "Candidate IP must NOT be admitted to '_ip4_ifaddr' when a "
                "unicast ARP Reply targeting our probe arrives during the probe window."
            ),
        )
        self.assertTrue(
            self._packet_handler._ip4_arp_dad__registry.has_signal(candidate_address),
            msg="Conflicting candidate IP must be flagged in the DAD slot registry.",
        )

    def test__arp__dad__gratuitous_reply_conflict_aborts_claim(self) -> None:
        """
        Ensure a broadcast gratuitous ARP Reply (SPA == TPA ==
        candidate) arriving during the probe window flags the
        candidate as conflicted and prevents admission. Covers
        the third probe-conflict wire shape (the first two
        are gratuitous Request and direct Reply).

        Reference: RFC 5227 §2.1.1 (probe-conflict aborts claim).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address

        def _inject_conflict(idx: int) -> None:
            if idx == 1:  # first inter-probe sleep — within probe window
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

        addresses_after = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertNotIn(
            candidate_address,
            addresses_after,
            msg=(
                "Candidate IP must NOT be admitted to '_ip4_ifaddr' when a "
                "gratuitous ARP Reply for the candidate arrives during the probe window."
            ),
        )
        self.assertTrue(
            self._packet_handler._ip4_arp_dad__registry.has_signal(candidate_address),
            msg="Conflicting candidate IP must be flagged in the DAD slot registry.",
        )

    def test__arp__dad__conflict_skips_remaining_probes(self) -> None:
        """
        Ensure that once a conflict is detected during the probe
        window, subsequent probe iterations skip the candidate
        (the probe loop tests 'has_signal()' before each probe
        TX). Pins that the probe loop honours the conflict
        signal as an early-exit gate, not just at claim
        time.

        Reference: RFC 5227 §2.1.1 (probe-conflict aborts claim).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address

        def _inject_conflict(idx: int) -> None:
            if idx == 1:  # first inter-probe sleep — within probe window
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
        from '_ip4_ifaddr' regardless of probe outcome — the
        non-candidate stack IP set up by 'NetworkTestCase' must
        still be present after DAD runs.

        Reference: RFC 5227 §2.1 (probe scope is candidates only).
        """

        existing_address = STACK__IP4_HOST.address

        self._drive_dad()

        addresses_after = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertIn(
            existing_address,
            addresses_after,
            msg=(
                "Pre-existing stack IPs must remain in '_ip4_ifaddr' across the "
                "DAD run; only candidates participate in the probe loop."
            ),
        )

    def test__arp__dad__no_conflict_emits_two_announcements(self) -> None:
        """
        Ensure a successful DAD claim emits exactly
        ANNOUNCE_NUM = 2 ARP Announcements on the wire — the
        first lets the host begin using the IP immediately,
        the second insures against stale ARP cache entries on
        peers that may have missed the first.

        Reference: RFC 5227 §2.3 (MUST broadcast ANNOUNCE_NUM Announcements).
        """

        from net_proto import ArpOperation, ArpParser
        from net_proto.lib.packet_rx import PacketRx

        self._drive_dad()

        candidate_address = STACK__IP4_HOST__CANDIDATE.address
        announcement_count = 0
        for frame in self._frames_tx:
            if frame[12:14] != b"\x08\x06":
                continue
            packet_rx = PacketRx(frame[14:])
            ArpParser(packet_rx)
            # An RFC 5227 §2.3 Announcement is an ARP Request
            # with SPA == TPA == the address being claimed and
            # SHA == our MAC.
            if (
                packet_rx.arp.oper is ArpOperation.REQUEST
                and packet_rx.arp.spa == candidate_address
                and packet_rx.arp.tpa == candidate_address
                and packet_rx.arp.sha == STACK__MAC_ADDRESS
            ):
                announcement_count += 1

        self.assertEqual(
            announcement_count,
            2,
            msg=(
                "RFC 5227 §2.3 mandates ANNOUNCE_NUM = 2 ARP Announcements "
                f"per claim; got {announcement_count} on the wire."
            ),
        )

    def test__arp__dad__announcements_spaced_by_announce_interval(self) -> None:
        """
        Ensure the second ARP Announcement is sent
        ANNOUNCE_INTERVAL = 2 seconds after the first — pinning
        that the announcement loop uses the correct constant
        rather than 'time.sleep(0)' or a different value.

        Reference: RFC 5227 §2.3 (Announcements spaced ANNOUNCE_INTERVAL apart).
        """

        from pytcp.protocols.arp.arp__constants import ARP__ANNOUNCE_INTERVAL

        self._drive_dad()

        # Sleep order from '_create_stack_ip4_addressing':
        #   index 0       — PROBE_WAIT initial random delay
        #   indexes 1..3  — three inter-probe sleeps (PROBE_MIN..PROBE_MAX)
        #   index 4       — ANNOUNCE_WAIT post-probe quiet period
        #   index 5       — ANNOUNCE_INTERVAL between Announcements
        self.assertGreaterEqual(
            len(self._dad_sleep_durations),
            6,
            msg=(
                "Expected at least 6 'time.sleep' calls (1 PROBE_WAIT + 3 "
                "inter-probe + 1 ANNOUNCE_WAIT + 1 ANNOUNCE_INTERVAL). Got: "
                f"{len(self._dad_sleep_durations)}"
            ),
        )
        self.assertEqual(
            self._dad_sleep_durations[5],
            ARP__ANNOUNCE_INTERVAL,
            msg=(
                "Sleep between Announcements (index 5, after ANNOUNCE_WAIT) must "
                f"equal ARP__ANNOUNCE_INTERVAL = {ARP__ANNOUNCE_INTERVAL} s; "
                f"got {self._dad_sleep_durations[5]} s."
            ),
        )

    def test__arp__dad__probe_wait_initial_random_delay(self) -> None:
        """
        Ensure the host waits a uniform-random delay in
        [0, ARP__PROBE_WAIT] before sending the first ARP
        Probe — prevents a fleet of hosts powered on
        simultaneously from synchronising their probes.

        Reference: RFC 5227 §2.1.1 (PROBE_WAIT initial random delay).
        """

        from pytcp.protocols.arp.arp__constants import ARP__PROBE_WAIT

        self._drive_dad()

        self.assertGreaterEqual(
            len(self._dad_sleep_durations),
            1,
            msg="Expected at least 1 'time.sleep' call — index 0 is the PROBE_WAIT initial delay.",
        )
        self.assertGreaterEqual(
            self._dad_sleep_durations[0],
            0.0,
            msg=f"PROBE_WAIT initial delay must be >= 0; got {self._dad_sleep_durations[0]}.",
        )
        self.assertLessEqual(
            self._dad_sleep_durations[0],
            ARP__PROBE_WAIT,
            msg=(
                f"PROBE_WAIT initial delay must be <= ARP__PROBE_WAIT = {ARP__PROBE_WAIT} s; "
                f"got {self._dad_sleep_durations[0]} s."
            ),
        )

    def test__arp__dad__inter_probe_spacing_within_range(self) -> None:
        """
        Ensure the three inter-probe sleeps (sleep indices 1..3)
        each fall in [ARP__PROBE_MIN, ARP__PROBE_MAX] seconds.

        Reference: RFC 5227 §2.1.1 (PROBE_MIN..PROBE_MAX inter-probe spacing).
        """

        from pytcp.protocols.arp.arp__constants import ARP__PROBE_MAX, ARP__PROBE_MIN

        self._drive_dad()

        self.assertGreaterEqual(
            len(self._dad_sleep_durations),
            4,
            msg="Expected at least 4 'time.sleep' calls — indices 1..3 are inter-probe sleeps.",
        )
        for idx in (1, 2, 3):
            self.assertGreaterEqual(
                self._dad_sleep_durations[idx],
                ARP__PROBE_MIN,
                msg=(
                    f"Inter-probe sleep[{idx}] must be >= ARP__PROBE_MIN = {ARP__PROBE_MIN} s; "
                    f"got {self._dad_sleep_durations[idx]} s."
                ),
            )
            self.assertLessEqual(
                self._dad_sleep_durations[idx],
                ARP__PROBE_MAX,
                msg=(
                    f"Inter-probe sleep[{idx}] must be <= ARP__PROBE_MAX = {ARP__PROBE_MAX} s; "
                    f"got {self._dad_sleep_durations[idx]} s."
                ),
            )

    def test__arp__dad__announce_wait_post_probe_quiet_period(self) -> None:
        """
        Ensure the host waits ARP__ANNOUNCE_WAIT seconds after
        the last ARP Probe before emitting the first
        Announcement. Late conflicting ARPs arriving in this
        quiet window must still be observable so the claim can
        be aborted; without the wait, the host would commit to
        the address the instant the probe loop ends.

        Reference: RFC 5227 §2.1.1 (ANNOUNCE_WAIT post-probe quiet period).
        """

        from pytcp.protocols.arp.arp__constants import ARP__ANNOUNCE_WAIT

        self._drive_dad()

        self.assertGreaterEqual(
            len(self._dad_sleep_durations),
            5,
            msg=(
                "Expected at least 5 'time.sleep' calls — index 4 is the "
                "ANNOUNCE_WAIT post-probe quiet period. Got: "
                f"{len(self._dad_sleep_durations)}"
            ),
        )
        self.assertEqual(
            self._dad_sleep_durations[4],
            ARP__ANNOUNCE_WAIT,
            msg=(
                "Sleep at index 4 (post-probe-loop, pre-announce) must equal "
                f"ARP__ANNOUNCE_WAIT = {ARP__ANNOUNCE_WAIT} s; "
                f"got {self._dad_sleep_durations[4]} s."
            ),
        )

    def test__arp__dad__simultaneous_probe_aborts_claim(self) -> None:
        """
        Ensure a peer's ARP Probe whose TPA matches our
        candidate IP — but whose SPA is the all-zeroes
        unspecified address (the wire signal that the peer is
        also probing the same address) — flags the candidate
        as conflicted and prevents admission. Without the
        SPA = 0 detection branch the frame is silently dropped
        as 'tpa_unknown' (the candidate is not yet in the
        stack's unicast list during DAD).

        Reference: RFC 5227 §2.1.1 (simultaneous-probe conflict).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address

        def _inject_conflict(idx: int) -> None:
            if idx == 1:  # first inter-probe sleep — within probe window
                self._drive_arp(
                    ethernet_dst=MAC__BROADCAST,
                    ethernet_src=HOST_A__MAC_ADDRESS,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=HOST_A__MAC_ADDRESS,
                    arp_spa=IP4__UNSPECIFIED,
                    arp_tha=MAC__UNSPECIFIED,
                    arp_tpa=candidate_address,
                )

        self._drive_dad(on_sleep=_inject_conflict)

        addresses_after = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertNotIn(
            candidate_address,
            addresses_after,
            msg=(
                "Candidate IP must NOT be admitted to '_ip4_ifaddr' when a peer "
                "ARP Probe (SPA = 0) for the candidate arrives during the "
                "probe window."
            ),
        )
        self.assertTrue(
            self._packet_handler._ip4_arp_dad__registry.has_signal(candidate_address),
            msg=(
                "Simultaneous-probe candidate IP must be flagged in the " "DAD slot registry so DAD aborts the claim."
            ),
        )

    def test__arp__dad__conflict_during_announce_wait_aborts_claim(self) -> None:
        """
        Ensure a conflicting ARP packet arriving during the
        ANNOUNCE_WAIT post-probe quiet period — that is, after
        the last probe but before the first announcement —
        flags the candidate as conflicted and prevents
        admission. This is the late-conflict-detection branch
        the ANNOUNCE_WAIT window exists to enable.

        Reference: RFC 5227 §2.1.1 (late conflicts during ANNOUNCE_WAIT abort claim).
        """

        candidate_address = STACK__IP4_HOST__CANDIDATE.address

        def _inject_conflict(idx: int) -> None:
            if idx == 4:  # ANNOUNCE_WAIT sleep — after all probes, before announcements
                self._drive_arp(
                    ethernet_dst=MAC__BROADCAST,
                    ethernet_src=HOST_A__MAC_ADDRESS,
                    arp_oper=ArpOperation.REQUEST,
                    arp_sha=HOST_A__MAC_ADDRESS,
                    arp_spa=candidate_address,
                    arp_tha=MAC__UNSPECIFIED,
                    arp_tpa=candidate_address,
                )

        self._drive_dad(on_sleep=_inject_conflict, num_sleep_callbacks=5)

        addresses_after = {host.address for host in self._packet_handler._ip4_ifaddr}
        self.assertNotIn(
            candidate_address,
            addresses_after,
            msg=(
                "Candidate IP must NOT be admitted to '_ip4_ifaddr' when a "
                "conflicting ARP arrives during the ANNOUNCE_WAIT window."
            ),
        )
        self.assertTrue(
            self._packet_handler._ip4_arp_dad__registry.has_signal(candidate_address),
            msg=(
                "Late-conflict candidate IP must be flagged in the DAD slot "
                "registry so the post-window admit-loop skips it."
            ),
        )
