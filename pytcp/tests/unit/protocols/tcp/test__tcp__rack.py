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
This module contains unit tests for the RFC 8985 RACK per-segment
state primitives in 'pytcp/protocols/tcp/tcp__rack.py'.

Phase 1 of the RACK-TLP project (per
'.claude/rules/tcp_rack_tlp.md' §4) ships:

    INFINITE_TS                 0xFFFF_FFFF (RFC 8985 §5.2 marker)
    RackSegment                 frozen dataclass with end_seq,
                                xmit_ts, retransmitted, lost

The dataclass mirrors the RFC 8985 §5.2 'Segment' tuple. The
'INFINITE_TS' constant marks segments that are not currently in
flight (lost or pruned); RACK_sent_after lexicographic compare in
later phases skips segments whose xmit_ts equals INFINITE_TS.

Reference RFCs:
    RFC 8985 §5.2  Per-Segment Variables

pytcp/tests/unit/protocols/tcp/test__tcp__rack.py

ver 3.0.4
"""

from unittest import TestCase

from pytcp.protocols.tcp.tcp__rack import (
    INFINITE_TS,
    RackSegment,
    rack_sent_after,
    rack_update,
)


class TestRackConstants(TestCase):
    """
    Spot-checks on the module-level constants.
    """

    def test__rack__infinite_ts_is_uint32_max(self) -> None:
        """
        Ensure 'INFINITE_TS' equals 0xFFFF_FFFF so a lost or
        pruned segment's 'xmit_ts' field signals "not currently
        in flight" via the maximum 32-bit unsigned value.

        Reference: RFC 8985 §5.2 (invalid timestamp marker).
        """

        self.assertEqual(
            INFINITE_TS,
            0xFFFF_FFFF,
            msg=(
                "RFC 8985 §5.2 mandates an invalid-timestamp "
                "marker for segments that are not currently in "
                "flight; the canonical value is 0xFFFF_FFFF."
            ),
        )


class TestRackSegmentConstruction(TestCase):
    """
    Construction-time invariants of the 'RackSegment' frozen
    dataclass.
    """

    def test__rack__segment__construction_with_all_fields(self) -> None:
        """
        Ensure 'RackSegment' constructs with the four canonical
        fields (end_seq, xmit_ts, retransmitted, lost) and
        exposes them via attribute access.

        Reference: RFC 8985 §5.2 (Segment tuple fields).
        """

        seg = RackSegment(
            end_seq=0x0000_2000,
            xmit_ts=12345,
            retransmitted=False,
            lost=False,
        )

        self.assertEqual(
            seg.end_seq,
            0x0000_2000,
            msg="'end_seq' field must round-trip through construction.",
        )
        self.assertEqual(
            seg.xmit_ts,
            12345,
            msg="'xmit_ts' field must round-trip through construction.",
        )
        self.assertFalse(
            seg.retransmitted,
            msg="'retransmitted' field must round-trip through construction.",
        )
        self.assertFalse(
            seg.lost,
            msg="'lost' field must round-trip through construction.",
        )

    def test__rack__segment__retransmitted_and_lost_flags(self) -> None:
        """
        Ensure 'RackSegment' accepts True for 'retransmitted'
        and 'lost' so later RACK phases can mark a segment as
        retransmitted (Phase 2 Karn-style guard) or lost
        (Phase 3 time-based loss detection).

        Reference: RFC 8985 §5.2 (Segment.retransmitted, Segment.lost).
        """

        seg = RackSegment(
            end_seq=0,
            xmit_ts=0,
            retransmitted=True,
            lost=True,
        )

        self.assertTrue(
            seg.retransmitted,
            msg="'retransmitted=True' must round-trip.",
        )
        self.assertTrue(
            seg.lost,
            msg="'lost=True' must round-trip.",
        )

    def test__rack__segment__is_frozen(self) -> None:
        """
        Ensure 'RackSegment' is frozen so the per-segment state
        is immutable - mutations require constructing a fresh
        instance and replacing the dict entry. Mirrors the
        'RtoState' / 'SackBlock' immutability convention.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        seg = RackSegment(end_seq=0, xmit_ts=0, retransmitted=False, lost=False)

        with self.assertRaises(
            AttributeError,
            msg="RackSegment must be frozen; attribute writes must raise.",
        ):
            seg.lost = True  # type: ignore[misc]

    def test__rack__segment__equality_by_value(self) -> None:
        """
        Ensure two 'RackSegment' instances with identical field
        values compare equal so dict-like comparisons in tests
        work without identity-coupling.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = RackSegment(end_seq=100, xmit_ts=200, retransmitted=False, lost=False)
        b = RackSegment(end_seq=100, xmit_ts=200, retransmitted=False, lost=False)
        c = RackSegment(end_seq=100, xmit_ts=201, retransmitted=False, lost=False)

        self.assertEqual(
            a,
            b,
            msg="Two RackSegment instances with identical fields must compare equal.",
        )
        self.assertNotEqual(
            a,
            c,
            msg="RackSegment instances differing in 'xmit_ts' must compare unequal.",
        )

    def test__rack__segment__xmit_ts_can_be_infinite_ts(self) -> None:
        """
        Ensure 'RackSegment' accepts 'xmit_ts == INFINITE_TS'
        so a lost-marked segment's xmit_ts can be set to the
        invalid-timestamp marker per RFC 8985 §5.2.

        Reference: RFC 8985 §5.2 (xmit_ts = INFINITE_TS for lost segments).
        """

        seg = RackSegment(
            end_seq=0,
            xmit_ts=INFINITE_TS,
            retransmitted=False,
            lost=True,
        )

        self.assertEqual(
            seg.xmit_ts,
            INFINITE_TS,
            msg="A lost segment's xmit_ts must be settable to INFINITE_TS.",
        )


class TestRackSentAfter(TestCase):
    """
    The 'rack_sent_after' lexicographic comparison tests
    (RFC 8985 §6.2 step 2).
    """

    def test__rack__sent_after__later_xmit_ts_wins(self) -> None:
        """
        Ensure a later 'xmit_ts' makes one segment count as
        'sent after' another, regardless of seq.

        Reference: RFC 8985 §6.2 (RACK_sent_after by xmit_ts).
        """

        self.assertTrue(
            rack_sent_after(t1_xmit_ts=200, t1_end_seq=0, t2_xmit_ts=100, t2_end_seq=999),
            msg=("Later xmit_ts must win regardless of seq."),
        )

    def test__rack__sent_after__earlier_xmit_ts_loses(self) -> None:
        """
        Ensure an earlier 'xmit_ts' is NOT 'sent after' a
        later one.

        Reference: RFC 8985 §6.2 (RACK_sent_after by xmit_ts).
        """

        self.assertFalse(
            rack_sent_after(t1_xmit_ts=100, t1_end_seq=999, t2_xmit_ts=200, t2_end_seq=0),
            msg="Earlier xmit_ts must lose to a later one.",
        )

    def test__rack__sent_after__tie_broken_by_end_seq(self) -> None:
        """
        Ensure a tie on 'xmit_ts' breaks by modular comparison
        on 'end_seq': segment with higher end_seq is 'sent
        after'.

        Reference: RFC 8985 §6.2 (RACK_sent_after end_seq tiebreaker).
        """

        self.assertTrue(
            rack_sent_after(t1_xmit_ts=100, t1_end_seq=2000, t2_xmit_ts=100, t2_end_seq=1000),
            msg="On xmit_ts tie, higher end_seq must win.",
        )

    def test__rack__sent_after__identical_returns_false(self) -> None:
        """
        Ensure two identical (xmit_ts, end_seq) pairs are
        NOT 'sent after' each other (strict-greater semantics).

        Reference: RFC 8985 §6.2 (RACK_sent_after strict order).
        """

        self.assertFalse(
            rack_sent_after(t1_xmit_ts=100, t1_end_seq=1000, t2_xmit_ts=100, t2_end_seq=1000),
            msg="Identical pair must not be 'sent after' itself.",
        )


class TestRackUpdate(TestCase):
    """
    The 'rack_update' RFC 8985 §6.2 step 1-2 update tests.
    """

    def test__rack__update__empty_segments_returns_priors(self) -> None:
        """
        Ensure an empty 'newly_acked_segments' list leaves all
        scalars unchanged.

        Reference: RFC 8985 §6.2 (no update without newly-acked).
        """

        result = rack_update(
            newly_acked_segments=[],
            now_ms=12345,
            ts_recent_echo_ms=None,
            prior_min_rtt_ms=100,
            prior_rack_rtt_ms=120,
            prior_rack_xmit_ts=10000,
            prior_rack_end_seq=5000,
        )

        self.assertEqual(
            result,
            (100, 120, 10000, 5000),
            msg="Empty newly_acked must yield the prior scalars unchanged.",
        )

    def test__rack__update__single_fresh_sample_seeds_min_rtt(self) -> None:
        """
        Ensure a single non-retransmitted sample seeds
        'min_rtt' even when the prior min_rtt is the
        uninitialized sentinel (0).

        Reference: RFC 8985 §B.1 (min_RTT update).
        """

        seg = RackSegment(end_seq=1000, xmit_ts=200, retransmitted=False, lost=False)
        min_rtt_ms, rack_rtt_ms, rack_xmit_ts, rack_end_seq = rack_update(
            newly_acked_segments=[seg],
            now_ms=400,
            ts_recent_echo_ms=None,
            prior_min_rtt_ms=0,
            prior_rack_rtt_ms=0,
            prior_rack_xmit_ts=0,
            prior_rack_end_seq=0,
        )

        self.assertEqual(min_rtt_ms, 200, msg="First sample must seed min_rtt.")
        self.assertEqual(rack_rtt_ms, 200, msg="RACK.rtt must equal the sample RTT.")
        self.assertEqual(rack_xmit_ts, 200, msg="RACK.xmit_ts must advance.")
        self.assertEqual(rack_end_seq, 1000, msg="RACK.end_seq must advance.")

    def test__rack__update__retransmitted_with_stale_tsecr_skipped(self) -> None:
        """
        Ensure a retransmitted segment whose TSecr predates
        the segment's xmit_ts is skipped (RFC 8985 §6.2 step
        2 condition 1) and does not perturb the scalars.

        Reference: RFC 8985 §6.2 (Karn-style spurious-retransmit guard via TSecr).
        """

        seg = RackSegment(end_seq=1000, xmit_ts=200, retransmitted=True, lost=False)
        result = rack_update(
            newly_acked_segments=[seg],
            now_ms=400,
            ts_recent_echo_ms=100,  # < seg.xmit_ts -> skip
            prior_min_rtt_ms=50,
            prior_rack_rtt_ms=60,
            prior_rack_xmit_ts=10,
            prior_rack_end_seq=20,
        )

        self.assertEqual(
            result,
            (50, 60, 10, 20),
            msg="Stale-TSecr retransmit must leave scalars unchanged.",
        )

    def test__rack__update__retransmitted_with_small_rtt_skipped(self) -> None:
        """
        Ensure a retransmitted segment with rtt < min_rtt is
        skipped (RFC 8985 §6.2 step 2 condition 2 heuristic).

        Reference: RFC 8985 §6.2 (Karn-style guard via rtt < min_rtt).
        """

        # rtt = 400 - 350 = 50; min_rtt = 100; 50 < 100 -> skip.
        seg = RackSegment(end_seq=1000, xmit_ts=350, retransmitted=True, lost=False)
        result = rack_update(
            newly_acked_segments=[seg],
            now_ms=400,
            ts_recent_echo_ms=None,
            prior_min_rtt_ms=100,
            prior_rack_rtt_ms=110,
            prior_rack_xmit_ts=10,
            prior_rack_end_seq=20,
        )

        self.assertEqual(
            result,
            (100, 110, 10, 20),
            msg="Retransmit with rtt < min_rtt must be skipped.",
        )

    def test__rack__update__min_rtt_tracks_smallest(self) -> None:
        """
        Ensure 'min_rtt' tracks the smallest rtt across a
        burst of acked segments.

        Reference: RFC 8985 §B.1 (min_RTT minimum tracking).
        """

        segs = [
            RackSegment(end_seq=1000, xmit_ts=100, retransmitted=False, lost=False),
            RackSegment(end_seq=2000, xmit_ts=300, retransmitted=False, lost=False),
            RackSegment(end_seq=3000, xmit_ts=200, retransmitted=False, lost=False),
        ]
        min_rtt_ms, _, _, _ = rack_update(
            newly_acked_segments=segs,
            now_ms=400,
            ts_recent_echo_ms=None,
            prior_min_rtt_ms=0,
            prior_rack_rtt_ms=0,
            prior_rack_xmit_ts=0,
            prior_rack_end_seq=0,
        )

        # rtts: 300, 100, 200 -> min = 100.
        self.assertEqual(
            min_rtt_ms,
            100,
            msg="min_rtt must track the smallest rtt across a burst.",
        )

    def test__rack__update__rack_xmit_ts_tracks_latest_sent(self) -> None:
        """
        Ensure 'RACK.xmit_ts' / 'RACK.end_seq' track the
        segment with the latest 'sent_after' lexicographic
        order across a burst (not necessarily the highest
        seq, since RACK uses xmit_ts as the primary key).

        Reference: RFC 8985 §6.2 (RACK_sent_after primary).
        """

        # Three segments transmitted at 100, 300, 200 ms with
        # increasing seq. The lexicographically-latest is the
        # one at xmit_ts=300 with end_seq=2000.
        segs = [
            RackSegment(end_seq=1000, xmit_ts=100, retransmitted=False, lost=False),
            RackSegment(end_seq=2000, xmit_ts=300, retransmitted=False, lost=False),
            RackSegment(end_seq=3000, xmit_ts=200, retransmitted=False, lost=False),
        ]
        _, _, rack_xmit_ts, rack_end_seq = rack_update(
            newly_acked_segments=segs,
            now_ms=400,
            ts_recent_echo_ms=None,
            prior_min_rtt_ms=0,
            prior_rack_rtt_ms=0,
            prior_rack_xmit_ts=0,
            prior_rack_end_seq=0,
        )

        self.assertEqual(rack_xmit_ts, 300, msg="RACK.xmit_ts must equal max xmit_ts.")
        self.assertEqual(rack_end_seq, 2000, msg="RACK.end_seq must pair with RACK.xmit_ts.")
