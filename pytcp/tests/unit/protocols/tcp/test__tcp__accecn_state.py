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
This module contains unit tests for the per-session AccECN state
container in 'pytcp/protocols/tcp/tcp__accecn_state.py'.

pytcp/tests/unit/protocols/tcp/test__tcp__accecn_state.py

ver 3.0.4
"""

from unittest import TestCase

from pytcp.protocols.tcp.tcp__accecn_state import (
    ACCECN__COUNTER_MASK,
    ACCECN__INITIAL_BYTE_COUNTER,
    ACCECN__INITIAL_CE_BYTE_COUNTER,
    ACCECN__INITIAL_CEP,
    ACCECN__LAST_EMIT_SENTINEL,
    AccEcnState,
)


class TestAccEcnState__Defaults(TestCase):
    """
    Per-field default values pinning the post-construction state
    of 'AccEcnState'.
    """

    def setUp(self) -> None:
        """
        Construct a default state instance for every test.
        """

        self._state = AccEcnState()

    def test__accecn_state__enabled_default_false(self) -> None:
        """
        Ensure 'enabled' defaults to False so a freshly-constructed
        session does not believe AccECN was negotiated. Only the
        SYN+ACK handshake path flips this.

        Reference: RFC 9768 §3.1.1 (AccECN bilateral negotiation).
        """

        self.assertFalse(
            self._state.enabled,
            msg="AccEcnState.enabled must default to False.",
        )

    def test__accecn_state__synack_codepoint_default_zero(self) -> None:
        """
        Ensure 'synack_codepoint' defaults to 0 (Not-ECT) so a
        fresh listener has no captured codepoint to encode into a
        SYN+ACK before an AccECN-setup SYN actually arrives.

        Reference: RFC 9768 §3.1.1 (passive-side codepoint capture).
        """

        self.assertEqual(
            self._state.synack_codepoint,
            0,
            msg="AccEcnState.synack_codepoint must default to 0 (Not-ECT).",
        )

    def test__accecn_state__handshake_ack_pending_default_none(self) -> None:
        """
        Ensure 'handshake_ack_pending' defaults to None so post-
        handshake segments fall back to the regular 'r.cep & 7'
        ACE encoding rather than reusing a stale Table-3 value.

        Reference: RFC 9768 §3.2.2.1 (active-side handshake ACE).
        """

        self.assertIsNone(
            self._state.handshake_ack_pending,
            msg="AccEcnState.handshake_ack_pending must default to None.",
        )

    def test__accecn_state__r_cep_default_five(self) -> None:
        """
        Ensure 'r_cep' defaults to 5 (binary 101) so a freshly-
        negotiated session is distinguishable from value 0
        (special meaning) and from middlebox-zeroed fields. The
        low 3 bits 101 are the wire-emitted ACE on the third-leg
        ACK before any CE marks are seen.

        Reference: RFC 9768 §3.2.1 (initial cep value).
        """

        self.assertEqual(
            self._state.r_cep,
            5,
            msg="AccEcnState.r_cep must default to 5.",
        )
        self.assertEqual(
            ACCECN__INITIAL_CEP,
            5,
            msg="ACCECN__INITIAL_CEP constant must equal 5.",
        )

    def test__accecn_state__receiver_byte_counters_default_initial(self) -> None:
        """
        Ensure receiver-side per-codepoint byte counters default
        to (1, 0, 1) for (ECT(0), CE, ECT(1)) so a freshly-
        negotiated session is distinguishable from middlebox-
        zeroed fields. r.ce_b starts at 0 because zero CE marks
        is the expected steady state at connection start; r.e0b
        and r.e1b start at 1 to seed the §3.2.1 initial state.

        Reference: RFC 9768 §3.2.1 (initial byte counter values).
        """

        self.assertEqual(
            self._state.r_ect0_b,
            1,
            msg="AccEcnState.r_ect0_b must default to 1.",
        )
        self.assertEqual(
            self._state.r_ce_b,
            0,
            msg="AccEcnState.r_ce_b must default to 0.",
        )
        self.assertEqual(
            self._state.r_ect1_b,
            1,
            msg="AccEcnState.r_ect1_b must default to 1.",
        )
        self.assertEqual(
            ACCECN__INITIAL_BYTE_COUNTER,
            1,
            msg="ACCECN__INITIAL_BYTE_COUNTER constant must equal 1.",
        )
        self.assertEqual(
            ACCECN__INITIAL_CE_BYTE_COUNTER,
            0,
            msg="ACCECN__INITIAL_CE_BYTE_COUNTER constant must equal 0.",
        )

    def test__accecn_state__last_emit_default_sentinel(self) -> None:
        """
        Ensure last-emit trackers default to the -1 sentinel
        (outside the uint24 range of real counters) so the very
        first AccECN-option emission always sees 'changed' for
        all three slots and emits the full Length=11 form,
        seeding the peer with our initial state.

        Reference: RFC 9768 §3.2.3 (last-emit tracker semantics).
        """

        self.assertEqual(
            self._state.r_last_emit_e0b,
            -1,
            msg="AccEcnState.r_last_emit_e0b must default to -1.",
        )
        self.assertEqual(
            self._state.r_last_emit_ceb,
            -1,
            msg="AccEcnState.r_last_emit_ceb must default to -1.",
        )
        self.assertEqual(
            self._state.r_last_emit_e1b,
            -1,
            msg="AccEcnState.r_last_emit_e1b must default to -1.",
        )
        self.assertEqual(
            ACCECN__LAST_EMIT_SENTINEL,
            -1,
            msg="ACCECN__LAST_EMIT_SENTINEL constant must equal -1.",
        )

    def test__accecn_state__sender_state_default(self) -> None:
        """
        Ensure sender-side fields default to the §3.2.1 initial
        state: s.cep=5, s.e0b=1, s.e1b=1, s.ce_b=0, s.disabled
        False, mangling_detected False. A fresh session must
        compute deltas against a baseline matching what the peer
        would report on its first emission.

        Reference: RFC 9768 §3.2.1 (sender-side initial counters).
        Reference: RFC 9768 §3.2.2.1 (s.disabled sentinel).
        Reference: RFC 9768 §3.2.2.3 (mangling detector).
        """

        self.assertEqual(
            self._state.s_cep,
            5,
            msg="AccEcnState.s_cep must default to 5.",
        )
        self.assertEqual(
            self._state.s_ect0_b,
            1,
            msg="AccEcnState.s_ect0_b must default to 1.",
        )
        self.assertEqual(
            self._state.s_ect1_b,
            1,
            msg="AccEcnState.s_ect1_b must default to 1.",
        )
        self.assertEqual(
            self._state.s_ce_b,
            0,
            msg="AccEcnState.s_ce_b must default to 0.",
        )
        self.assertFalse(
            self._state.s_disabled,
            msg="AccEcnState.s_disabled must default to False.",
        )
        self.assertFalse(
            self._state.mangling_detected,
            msg="AccEcnState.mangling_detected must default to False.",
        )

    def test__accecn_state__counter_mask_is_uint24(self) -> None:
        """
        Ensure ACCECN__COUNTER_MASK encodes the 24-bit width of
        the AccECN option's counter slots. All r.* / s.* counter
        increments mask against this so they wrap at 2^24 per
        the option wire format.

        Reference: RFC 9768 §3.2.3 (counter wire-format width).
        """

        self.assertEqual(
            ACCECN__COUNTER_MASK,
            0xFF_FFFF,
            msg="ACCECN__COUNTER_MASK must equal 0xFF_FFFF (uint24).",
        )

    def test__accecn_state__instances_are_independent(self) -> None:
        """
        Ensure two distinct 'AccEcnState' instances do not share
        mutable state — each session must own its own counters.
        Slots-based dataclasses use fresh integer fields per
        instance; this test guards against accidental class-level
        defaults that would alias across sessions.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        state_a = AccEcnState()
        state_b = AccEcnState()
        state_a.r_cep = 99
        state_a.r_ce_b = 42
        self.assertEqual(
            state_b.r_cep,
            5,
            msg="Mutating one AccEcnState must not affect another.",
        )
        self.assertEqual(
            state_b.r_ce_b,
            0,
            msg="Mutating one AccEcnState must not affect another.",
        )
