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

from pytcp.protocols.tcp.tcp__rack import INFINITE_TS, RackSegment


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
