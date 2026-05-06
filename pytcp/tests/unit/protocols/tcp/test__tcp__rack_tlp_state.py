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
This module contains unit tests for the per-session RACK + TLP
state container in 'pytcp/protocols/tcp/tcp__rack_tlp_state.py'.

pytcp/tests/unit/protocols/tcp/test__tcp__rack_tlp_state.py

ver 3.0.4
"""

from unittest import TestCase

from pytcp.protocols.tcp.tcp__rack_tlp_state import (
    RACK__REO_WND_MULT_INITIAL,
    RACK__REO_WND_PERSIST_DEFAULT,
    TLP__MAX_ACK_DELAY_MS_DEFAULT,
    RackTlpState,
)


class TestRackTlpState__Defaults(TestCase):
    """
    Per-field default values pinning the post-construction state
    of 'RackTlpState'.
    """

    def setUp(self) -> None:
        """
        Construct a default state instance for every test.
        """

        self._state = RackTlpState()

    def test__rack_tlp_state__rack_segments_default_empty(self) -> None:
        """
        Ensure 'rack_segments' defaults to an empty dict so a
        freshly-constructed session has no scoreboard entries
        before any outbound segment fires.

        Reference: RFC 8985 §5.2 (per-segment scoreboard).
        """

        self.assertEqual(
            self._state.rack_segments,
            {},
            msg="RackTlpState.rack_segments must default to {}.",
        )

    def test__rack_tlp_state__rack_scalars_default_zero(self) -> None:
        """
        Ensure the §6.2 step 1-2 RACK scalars (min_rtt_ms,
        rtt_ms, xmit_ts, end_seq) all default to 0 — the
        uninitialised sentinel until the first newly-acked
        segment is observed and rack_update fires.

        Reference: RFC 8985 §6.2 step 1 (RACK scalar init).
        """

        self.assertEqual(
            self._state.rack_min_rtt_ms,
            0,
            msg="rack_min_rtt_ms must default to 0.",
        )
        self.assertEqual(
            self._state.rack_rtt_ms,
            0,
            msg="rack_rtt_ms must default to 0.",
        )
        self.assertEqual(
            self._state.rack_xmit_ts,
            0,
            msg="rack_xmit_ts must default to 0.",
        )
        self.assertEqual(
            self._state.rack_end_seq,
            0,
            msg="rack_end_seq must default to 0.",
        )

    def test__rack_tlp_state__acked_seqs_default_empty(self) -> None:
        """
        Ensure 'rack_acked_seqs' defaults to an empty set so
        every newly-acked segment on the first ACK contributes
        to the rack_update scalars.

        Reference: RFC 8985 §6.2 step 1-2 (newly-acknowledged guard).
        """

        self.assertEqual(
            self._state.rack_acked_seqs,
            set(),
            msg="rack_acked_seqs must default to set().",
        )

    def test__rack_tlp_state__reordering_state_default(self) -> None:
        """
        Ensure 'rack_reordering_seen' defaults to False and
        'rack_fack' to 0 so the §6.2 step 4 reo_wnd computation
        starts on the dup-ACK trigger path (reo_wnd=0) and
        switches to the time-based trigger only after the first
        observed reorder.

        Reference: RFC 8985 §6.2 step 3 (reordering detection).
        """

        self.assertFalse(
            self._state.rack_reordering_seen,
            msg="rack_reordering_seen must default to False.",
        )
        self.assertEqual(
            self._state.rack_fack,
            0,
            msg="rack_fack must default to 0.",
        )

    def test__rack_tlp_state__reo_wnd_persist_defaults(self) -> None:
        """
        Ensure the §6.2 step 4 reo_wnd_mult / reo_wnd_persist
        defaults are 1 and 16 respectively — the multiplier
        starts at the canonical neutral value and the persist
        counter at 16 consecutive-recoveries-without-DSACK
        decay window.

        Reference: RFC 8985 §6.2 step 4 (reo_wnd_persist decay).
        """

        self.assertEqual(
            self._state.rack_reo_wnd_mult,
            1,
            msg="rack_reo_wnd_mult must default to 1.",
        )
        self.assertEqual(
            self._state.rack_reo_wnd_persist,
            16,
            msg="rack_reo_wnd_persist must default to 16.",
        )
        self.assertEqual(
            RACK__REO_WND_MULT_INITIAL,
            1,
            msg="RACK__REO_WND_MULT_INITIAL must equal 1.",
        )
        self.assertEqual(
            RACK__REO_WND_PERSIST_DEFAULT,
            16,
            msg="RACK__REO_WND_PERSIST_DEFAULT must equal 16.",
        )

    def test__rack_tlp_state__dsack_round_default_none(self) -> None:
        """
        Ensure 'rack_dsack_round' defaults to None so a
        freshly-constructed session has no in-progress DSACK
        round; the next DSACK observation opens one and the
        next post-marker SND.UNA advance closes it.

        Reference: RFC 8985 §6.2 step 4 (DSACK-round marker).
        """

        self.assertIsNone(
            self._state.rack_dsack_round,
            msg="rack_dsack_round must default to None.",
        )

    def test__rack_tlp_state__tlp_state_default(self) -> None:
        """
        Ensure TLP state defaults to "no probe armed, no probe
        in flight": tlp_armed False, tlp_end_seq None,
        tlp_is_retrans False, tlp_max_ack_delay_ms 25 (Linux's
        canonical receiver-delay upper bound).

        Reference: RFC 8985 §7 (TLP per-connection state).
        """

        self.assertFalse(
            self._state.tlp_armed,
            msg="tlp_armed must default to False.",
        )
        self.assertIsNone(
            self._state.tlp_end_seq,
            msg="tlp_end_seq must default to None.",
        )
        self.assertFalse(
            self._state.tlp_is_retrans,
            msg="tlp_is_retrans must default to False.",
        )
        self.assertEqual(
            self._state.tlp_max_ack_delay_ms,
            25,
            msg="tlp_max_ack_delay_ms must default to 25 (Linux default).",
        )
        self.assertEqual(
            TLP__MAX_ACK_DELAY_MS_DEFAULT,
            25,
            msg="TLP__MAX_ACK_DELAY_MS_DEFAULT must equal 25.",
        )

    def test__rack_tlp_state__instances_own_independent_collections(self) -> None:
        """
        Ensure two distinct 'RackTlpState' instances own
        independent 'rack_segments' dicts and 'rack_acked_seqs'
        sets via 'default_factory'. A test fixture that replaces
        a session's state must not share the scoreboard with
        another session.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        state_a = RackTlpState()
        state_b = RackTlpState()
        self.assertIsNot(
            state_a.rack_segments,
            state_b.rack_segments,
            msg="Distinct RackTlpState instances must own distinct rack_segments.",
        )
        self.assertIsNot(
            state_a.rack_acked_seqs,
            state_b.rack_acked_seqs,
            msg="Distinct RackTlpState instances must own distinct rack_acked_seqs.",
        )
