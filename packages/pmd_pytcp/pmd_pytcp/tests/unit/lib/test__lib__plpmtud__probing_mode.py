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
Unit tests for the 'PmtuSearch' engine's active-probing mode —
the behaviours added for grow-through-validation MSS discovery:

  * 'probing=True' seeds the working PLPMTU at BASE_PLPMTU (or at
    the operator-declared 'plpmtu_seed'), never at the interface
    MTU; 'probing=False' keeps the classical interface-MTU seed.
  * SEARCHING candidates commit only after VALIDATION_ACKS
    consecutive probe ACKs of the same size; a loss in between
    voids the streak.
  * 'confirm_current' never raises 'current_mtu' and never raises
    'ack_size' past it (only validated probes may raise the
    working size).
  * 'on_black_hole_suspected' revokes a probe-raised PLPMTU back
    to the seed, caps the search below the revoked size and
    resumes SEARCHING; it is a no-op at/below the seed and in
    classical mode.
  * MAX_PROBES black-hole detection clamps to the seed (not the
    family floor) in probing mode.
  * 'probe_timer_expired' honours the per-engine
    'probe_timer_sec' override.

pmd_pytcp/tests/unit/lib/test__lib__plpmtud__probing_mode.py

ver 3.0.7
"""

from __future__ import annotations

from unittest import TestCase

from pmd_net_addr import Ip6Address
from pmd_pytcp.lib.plpmtud import (
    BASE_PLPMTU__IP6,
    MAX_PROBES,
    VALIDATION_ACKS,
    PmtuSearch,
    PmtuState,
)

_IP6_DST = Ip6Address("2001:db8::91")

_SEED = 1400
_IFACE_MTU = 16000


def _searching_engine() -> PmtuSearch:
    """
    Build a probing-mode engine and implicit-confirm it straight
    into SEARCHING (the way a TCP session's acked cold-start data
    segments do), so tests can exercise the candidate ladder.
    """

    engine: PmtuSearch = PmtuSearch(
        address=_IP6_DST,
        interface_mtu=_IFACE_MTU,
        probing=True,
        plpmtu_seed=_SEED,
    )
    engine.confirm_current(_SEED, now=0.0)
    assert engine.state is PmtuState.SEARCHING
    return engine


def _validate_candidate(engine: PmtuSearch, *, now: float) -> int:
    """
    Ack the engine's current candidate VALIDATION_ACKS times
    (the full validation streak) and return the committed size.
    """

    size = engine.candidate_mtu
    assert size is not None
    for _ in range(VALIDATION_ACKS):
        engine.on_probe_ack(size, now=now)
    return size


class TestPmtuSearch__ProbingSeed(TestCase):
    """
    The probing-mode working-PLPMTU seed.
    """

    def test__plpmtud__probing_seeds_current_at_base(self) -> None:
        """
        Ensure probing mode without an explicit seed starts the
        working PLPMTU at BASE_PLPMTU — NOT at the interface MTU,
        which would let the transport send at a size the path
        never validated and permanently disarm the grow-on-ack
        hook (no probe ack can exceed the interface MTU).
        """

        engine: PmtuSearch = PmtuSearch(address=_IP6_DST, interface_mtu=_IFACE_MTU, probing=True)

        self.assertEqual(
            engine.current_mtu,
            BASE_PLPMTU__IP6,
            msg="probing=True without a seed MUST start current_mtu at BASE_PLPMTU.",
        )

    def test__plpmtud__probing_seeds_current_at_operator_seed(self) -> None:
        """
        Ensure 'plpmtu_seed' (the operator-declared-safe cold-start
        packet size, e.g. TCP's 'tcp.base_mss' + overhead) becomes
        the probing-mode working PLPMTU.
        """

        engine: PmtuSearch = PmtuSearch(
            address=_IP6_DST, interface_mtu=_IFACE_MTU, probing=True, plpmtu_seed=_SEED
        )

        self.assertEqual(
            engine.current_mtu,
            _SEED,
            msg="probing=True with plpmtu_seed MUST start current_mtu at the seed.",
        )

    def test__plpmtud__classical_mode_keeps_interface_mtu_seed(self) -> None:
        """
        Ensure classical (shrink-only) mode still seeds the
        working PLPMTU at the interface MTU — the link MTU is the
        best estimate until ICMP says otherwise.
        """

        engine: PmtuSearch = PmtuSearch(address=_IP6_DST, interface_mtu=_IFACE_MTU, probing=False)

        self.assertEqual(
            engine.current_mtu,
            _IFACE_MTU,
            msg="probing=False MUST keep the classical interface-MTU seed.",
        )

    def test__plpmtud__seed_is_clamped_to_engine_bounds(self) -> None:
        """
        Ensure a pathological seed below BASE_PLPMTU (or above the
        interface MTU) is clamped into the engine's legal range.
        """

        engine: PmtuSearch = PmtuSearch(
            address=_IP6_DST, interface_mtu=_IFACE_MTU, probing=True, plpmtu_seed=100
        )

        self.assertEqual(
            engine.current_mtu,
            BASE_PLPMTU__IP6,
            msg="A sub-base plpmtu_seed MUST clamp up to BASE_PLPMTU.",
        )


class TestPmtuSearch__ValidationStreak(TestCase):
    """
    The VALIDATION_ACKS consecutive-ack commit gate (guards
    against paths that deliver an oversized packet only
    intermittently — RFC 4821 §7.7).
    """

    def test__plpmtud__single_ack_does_not_commit(self) -> None:
        """
        Ensure fewer than VALIDATION_ACKS acks of a SEARCHING
        candidate raise neither 'ack_size' nor 'current_mtu' —
        one lucky delivery of an oversized probe must not raise
        the working PLPMTU.
        """

        engine = _searching_engine()
        candidate = engine.candidate_mtu
        assert candidate is not None

        for _ in range(VALIDATION_ACKS - 1):
            engine.on_probe_ack(candidate, now=1.0)

        self.assertEqual(
            engine.current_mtu,
            _SEED,
            msg="current_mtu MUST NOT rise before VALIDATION_ACKS consecutive acks.",
        )
        self.assertEqual(
            engine.candidate_mtu,
            candidate,
            msg="The candidate MUST stay armed (re-probed) until validated.",
        )

    def test__plpmtud__full_streak_commits_and_advances(self) -> None:
        """
        Ensure the VALIDATION_ACKS-th consecutive ack commits the
        candidate (raises current_mtu) and advances the ladder to
        a larger candidate.
        """

        engine = _searching_engine()
        committed = _validate_candidate(engine, now=1.0)

        self.assertEqual(
            engine.current_mtu,
            committed,
            msg="The full validation streak MUST commit the candidate into current_mtu.",
        )
        next_candidate = engine.candidate_mtu
        assert next_candidate is not None
        self.assertGreater(
            next_candidate,
            committed,
            msg="After a commit the binary search MUST propose a larger candidate.",
        )

    def test__plpmtud__loss_voids_partial_streak(self) -> None:
        """
        Ensure a probe loss between validation acks voids the
        partial streak: subsequent acks must start a fresh count,
        so a flappy size cannot accumulate acks across losses.
        """

        engine = _searching_engine()
        candidate = engine.candidate_mtu
        assert candidate is not None

        engine.on_probe_ack(candidate, now=1.0)
        engine.on_probe_ack(candidate, now=1.1)
        engine.on_probe_loss(now=1.2)

        # The ladder narrowed to a new candidate; ack it
        # VALIDATION_ACKS - 1 times — with a carried-over streak
        # this would (wrongly) commit.
        narrowed = engine.candidate_mtu
        assert narrowed is not None
        for _ in range(VALIDATION_ACKS - 1):
            engine.on_probe_ack(narrowed, now=1.3)

        self.assertEqual(
            engine.current_mtu,
            _SEED,
            msg="A loss MUST void the validation streak — no commit from a carried count.",
        )


class TestPmtuSearch__ImplicitConfirmBounds(TestCase):
    """
    'confirm_current' bounds in probing mode: implicit feedback
    may advance the search floor only up to the working PLPMTU,
    and never the working PLPMTU itself.
    """

    def test__plpmtud__confirm_never_raises_current(self) -> None:
        """
        Ensure an implicit confirmation larger than 'current_mtu'
        raises nothing: after a black-hole revert, cum-ACKs of old
        in-flight segments at the revoked (larger) size must not
        reinstate it.
        """

        engine = _searching_engine()

        engine.confirm_current(8696, now=1.0)

        self.assertEqual(
            engine.current_mtu,
            _SEED,
            msg="confirm_current MUST NOT raise current_mtu (only validated probes may).",
        )
        self.assertLessEqual(
            engine._ack_size,
            _SEED,
            msg="confirm_current MUST NOT raise ack_size past current_mtu.",
        )


class TestPmtuSearch__BlackHoleRevert(TestCase):
    """
    'on_black_hole_suspected' — the RTO-driven revocation of a
    probe-raised PLPMTU (paths that ack an oversized probe in
    isolation yet drop that size under sustained load).
    """

    def test__plpmtud__revert_restores_seed_and_caps_search(self) -> None:
        """
        Ensure the revert drops the working PLPMTU back to the
        seed, caps 'search_high' below the revoked size, and
        resumes SEARCHING with a smaller candidate.
        """

        engine = _searching_engine()
        revoked = _validate_candidate(engine, now=1.0)
        assert engine.current_mtu == revoked

        engine.on_black_hole_suspected(now=2.0)

        self.assertEqual(
            engine.current_mtu,
            _SEED,
            msg="Black-hole revert MUST restore current_mtu to the seed.",
        )
        self.assertLess(
            engine._search_high,
            revoked,
            msg="Black-hole revert MUST cap search_high below the revoked size.",
        )
        self.assertIs(
            engine.state,
            PmtuState.SEARCHING,
            msg="Black-hole revert MUST resume SEARCHING (the connection continues).",
        )
        next_candidate = engine.candidate_mtu
        assert next_candidate is not None
        self.assertLess(
            next_candidate,
            revoked,
            msg="Post-revert candidates MUST stay below the revoked size.",
        )

    def test__plpmtud__revert_noop_at_seed(self) -> None:
        """
        Ensure an RTO while running AT the seed (ordinary loss,
        nothing probe-raised) leaves the engine untouched — the
        heuristic must not react to normal congestion.
        """

        engine = _searching_engine()
        state_before = engine.state
        candidate_before = engine.candidate_mtu

        engine.on_black_hole_suspected(now=2.0)

        self.assertEqual(
            engine.current_mtu,
            _SEED,
            msg="A revert at the seed must leave current_mtu unchanged.",
        )
        self.assertIs(
            engine.state,
            state_before,
            msg="A revert at the seed must not change the engine state.",
        )
        self.assertEqual(
            engine.candidate_mtu,
            candidate_before,
            msg="A revert at the seed must not disturb the candidate ladder.",
        )

    def test__plpmtud__revert_noop_in_classical_mode(self) -> None:
        """
        Ensure classical (probing=False) engines ignore the
        black-hole signal entirely — shrink-only PMTUD has no
        probe-raised size to revoke.
        """

        engine: PmtuSearch = PmtuSearch(address=_IP6_DST, interface_mtu=_IFACE_MTU, probing=False)

        engine.on_black_hole_suspected(now=2.0)

        self.assertEqual(
            engine.current_mtu,
            _IFACE_MTU,
            msg="Classical mode MUST ignore on_black_hole_suspected.",
        )


class TestPmtuSearch__ErrorClampsToSeed(TestCase):
    """
    MAX_PROBES black-hole detection in probing mode.
    """

    def test__plpmtud__max_probes_error_clamps_to_seed(self) -> None:
        """
        Ensure MAX_PROBES consecutive probe losses enter ERROR
        with the working PLPMTU clamped to the operator seed —
        the trusted fallback (same contract as a static send-MSS
        cap) — instead of the family floor used in classical
        mode.
        """

        engine = _searching_engine()
        for _ in range(MAX_PROBES):
            engine.on_probe_loss(now=1.0)

        self.assertIs(
            engine.state,
            PmtuState.ERROR,
            msg="MAX_PROBES consecutive losses MUST enter ERROR.",
        )
        self.assertEqual(
            engine.current_mtu,
            _SEED,
            msg="Probing-mode ERROR MUST clamp current_mtu to the seed, not the floor.",
        )


class TestPmtuSearch__ProbeTimer(TestCase):
    """
    The per-engine PROBE_TIMER override and its expiry query.
    """

    def test__plpmtud__probe_timer_expired_honours_override(self) -> None:
        """
        Ensure 'probe_timer_expired' fires against the
        constructor's 'probe_timer_sec' override — low-RTT
        transports shorten the RFC's 30 s default so a
        black-holed probe cannot park the search.
        """

        engine: PmtuSearch = PmtuSearch(
            address=_IP6_DST,
            interface_mtu=_IFACE_MTU,
            probing=True,
            probe_timer_sec=0.5,
        )
        armed = engine.next_probe_size(now=0.0)
        assert armed is not None

        self.assertFalse(
            engine.probe_timer_expired(now=0.4),
            msg="The probe timer must NOT be expired before probe_timer_sec elapses.",
        )
        self.assertTrue(
            engine.probe_timer_expired(now=0.6),
            msg="The probe timer MUST be expired once probe_timer_sec has elapsed.",
        )
