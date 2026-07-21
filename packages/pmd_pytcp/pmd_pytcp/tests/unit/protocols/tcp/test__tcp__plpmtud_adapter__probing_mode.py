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
Unit tests for the TCP PLPMTUD adapter's probing-mode
behaviours — the glue added for grow-through-validation MSS
discovery:

  * 'on_range_retransmitted' declares exactly the overlapped
    in-flight probes lost (repairs elsewhere in the stream leave
    the probe alone) and voids an overlapped implicit-confirm
    slot.
  * 'note_data_segment' keeps the single largest fresh segment;
    'check_implicit_confirm' dispatches it once cum-ACKed —
    confirming BASE without a dedicated base probe.
  * 'on_rto_timeout' voids the implicit slot and feeds the
    engine's black-hole revert.
  * 'maybe_probe' fires the PROBE_TIMER: an in-flight probe past
    its deadline is declared lost from the emit-path poll.
  * 'limit_max' caps the engine's search at the peer-advertised
    packet size.

pmd_pytcp/tests/unit/protocols/tcp/test__tcp__plpmtud_adapter__probing_mode.py

ver 3.0.7
"""

from __future__ import annotations

from unittest import TestCase

from pmd_net_addr import Ip6Address
from pmd_pytcp.lib.plpmtud import VALIDATION_ACKS, PmtuState
from pmd_pytcp.protocols.tcp.tcp__plpmtud_adapter import TcpPlpmtudAdapter

_IP6_DST = Ip6Address("2001:db8::91")

_SEED = 1400
_IFACE_MTU = 16000


def _probing_adapter(**overrides) -> TcpPlpmtudAdapter:
    """
    Build a probing-mode adapter the way 'TcpSession.__init__'
    does for an active-probing session.
    """

    kwargs = dict(
        remote_ip_address=_IP6_DST,
        interface_mtu=_IFACE_MTU,
        probing=True,
        plpmtu_seed=_SEED,
    )
    kwargs.update(overrides)
    return TcpPlpmtudAdapter(**kwargs)


def _open_search(adapter: TcpPlpmtudAdapter) -> None:
    """
    Implicit-confirm the seed so the engine leaves BASE — the
    same path a session's acked cold-start data segments drive.
    """

    adapter.confirm_current(_SEED, now=0.0)
    assert adapter.state is PmtuState.SEARCHING


class TestTcpPlpmtudAdapter__RangeRetransmitted(TestCase):
    """
    Precise probe-loss detection on retransmission overlap.
    """

    def test__adapter__overlapping_repair_declares_probe_lost(self) -> None:
        """
        Ensure a retransmission covering an in-flight probe's
        range removes it and feeds engine probe-loss — its bytes
        are being repaired at regular size, so its later cum-ACK
        must not read as a probe ACK (the false positive that
        raises the MSS into a black hole).
        """

        adapter = _probing_adapter()
        _open_search(adapter)
        candidate = adapter.maybe_probe(now=1.0)
        assert candidate is not None
        adapter.record_emitted_probe(seq=2000, size=candidate, seq_start=1000)

        adapter.on_range_retransmitted(seq_start=900, seq_end=1100, now=1.1)

        self.assertEqual(
            adapter.in_flight_probe_sizes,
            (),
            msg="A repair overlapping the probe range MUST remove the in-flight probe.",
        )
        narrowed = adapter.engine.candidate_mtu
        assert narrowed is not None
        self.assertLess(
            narrowed,
            candidate,
            msg="The overlapped probe MUST count as lost (ladder narrowed).",
        )

    def test__adapter__non_overlapping_repair_leaves_probe_alone(self) -> None:
        """
        Ensure a repair elsewhere in the stream does NOT touch
        the in-flight probe — ordinary congestion loss must not
        spuriously narrow the search or trip MAX_PROBES (a SACKed
        probe still collects its genuine ACK later).
        """

        adapter = _probing_adapter()
        _open_search(adapter)
        candidate = adapter.maybe_probe(now=1.0)
        assert candidate is not None
        adapter.record_emitted_probe(seq=2000, size=candidate, seq_start=1000)

        adapter.on_range_retransmitted(seq_start=500, seq_end=900, now=1.1)

        self.assertEqual(
            adapter.in_flight_probe_sizes,
            (candidate,),
            msg="A repair outside the probe range MUST leave the probe in flight.",
        )
        self.assertEqual(
            adapter.engine.candidate_mtu,
            candidate,
            msg="A repair outside the probe range MUST NOT narrow the ladder.",
        )

    def test__adapter__overlapping_repair_voids_implicit_slot(self) -> None:
        """
        Ensure a repair overlapping the pending implicit-confirm
        slot voids it — its ACK would otherwise confirm a packet
        size the path never carried in one piece.
        """

        adapter = _probing_adapter()
        adapter.note_data_segment(seq_start=100, end_seq=200, packet_size=_SEED)

        adapter.on_range_retransmitted(seq_start=150, seq_end=180, now=0.5)
        adapter.check_implicit_confirm(new_snd_una=300, now=0.6)

        self.assertIs(
            adapter.state,
            PmtuState.BASE,
            msg="A voided implicit slot MUST NOT confirm BASE when later cum-ACKed.",
        )


class TestTcpPlpmtudAdapter__ImplicitConfirm(TestCase):
    """
    The single-slot RFC 4821 §7.1 implicit-probe feedback.
    """

    def test__adapter__acked_fresh_segment_confirms_base(self) -> None:
        """
        Ensure a fresh data segment of >= BASE_PLPMTU packet size,
        once cum-ACKed, confirms BASE and opens the search — the
        deadlock fix for transports whose working MSS exceeds the
        base probe size (the base probe can never pass the
        candidate-larger-than-MSS emit gate).
        """

        adapter = _probing_adapter()
        adapter.note_data_segment(seq_start=100, end_seq=200, packet_size=_SEED)

        adapter.check_implicit_confirm(new_snd_una=200, now=0.5)

        self.assertIs(
            adapter.state,
            PmtuState.SEARCHING,
            msg="An acked >= BASE_PLPMTU fresh segment MUST confirm BASE via the slot.",
        )

    def test__adapter__slot_keeps_largest_segment(self) -> None:
        """
        Ensure the single slot keeps the LARGEST pending segment —
        confirming the largest size subsumes the smaller ones.
        """

        adapter = _probing_adapter()
        adapter.note_data_segment(seq_start=100, end_seq=200, packet_size=_SEED)
        adapter.note_data_segment(seq_start=200, end_seq=250, packet_size=600)

        assert adapter._implicit_confirm is not None
        self.assertEqual(
            adapter._implicit_confirm[2],
            _SEED,
            msg="A smaller later segment MUST NOT displace the larger pending slot.",
        )

    def test__adapter__unacked_slot_does_not_confirm(self) -> None:
        """
        Ensure the slot only dispatches once cum-ACK actually
        passes its terminal seq.
        """

        adapter = _probing_adapter()
        adapter.note_data_segment(seq_start=100, end_seq=200, packet_size=_SEED)

        adapter.check_implicit_confirm(new_snd_una=150, now=0.5)

        self.assertIs(
            adapter.state,
            PmtuState.BASE,
            msg="A slot whose terminal seq is not yet cum-ACKed MUST NOT confirm.",
        )


class TestTcpPlpmtudAdapter__RtoBlackHole(TestCase):
    """
    RTO as the black-hole signal for a probe-raised PLPMTU.
    """

    def test__adapter__rto_reverts_probe_raised_mtu(self) -> None:
        """
        Ensure an RTO after a validated raise revokes it: the
        working PLPMTU returns to the seed (a size can ack
        isolated probes yet drop under sustained load — the
        stall IS the evidence).
        """

        adapter = _probing_adapter()
        _open_search(adapter)
        candidate = adapter.maybe_probe(now=1.0)
        assert candidate is not None
        # Validate the candidate through the full streak — each
        # ack consumes the in-flight entry, so re-emit per round.
        for i in range(VALIDATION_ACKS):
            adapter.record_emitted_probe(seq=1000 + i, size=candidate, seq_start=900 + i)
            adapter.on_snd_una_advance(new_snd_una=1000 + i, now=1.0 + i)
        assert adapter.current_mtu == candidate

        adapter.on_rto_timeout(now=10.0)

        self.assertEqual(
            adapter.current_mtu,
            _SEED,
            msg="An RTO MUST revoke a probe-raised working PLPMTU back to the seed.",
        )

    def test__adapter__rto_voids_implicit_slot(self) -> None:
        """
        Ensure an RTO voids the pending implicit-confirm slot —
        the rewound retransmission is about to repair its range.
        """

        adapter = _probing_adapter()
        adapter.note_data_segment(seq_start=100, end_seq=200, packet_size=_SEED)

        adapter.on_rto_timeout(now=1.0)
        adapter.check_implicit_confirm(new_snd_una=300, now=1.1)

        self.assertIs(
            adapter.state,
            PmtuState.BASE,
            msg="The implicit slot MUST NOT survive an RTO.",
        )


class TestTcpPlpmtudAdapter__ProbeTimer(TestCase):
    """
    PROBE_TIMER firing from the 'maybe_probe' emit-path poll.
    """

    def test__adapter__expired_probe_declared_lost_on_poll(self) -> None:
        """
        Ensure an in-flight probe past its PROBE_TIMER deadline is
        declared lost by the next 'maybe_probe' poll — the engine
        has no timer wheel of its own, and without this a probe
        whose loss produces no recovery event (nothing else in
        flight) would park the search forever.
        """

        adapter = _probing_adapter(probe_timer_sec=0.5)
        _open_search(adapter)
        candidate = adapter.maybe_probe(now=1.0)
        assert candidate is not None
        adapter.record_emitted_probe(seq=2000, size=candidate, seq_start=1000)

        adapter.maybe_probe(now=2.0)

        self.assertEqual(
            adapter.in_flight_probe_sizes,
            (),
            msg="A probe past its PROBE_TIMER MUST be declared lost by the poll.",
        )
        narrowed = adapter.engine.candidate_mtu
        assert narrowed is not None
        self.assertLess(
            narrowed,
            candidate,
            msg="The timed-out probe MUST count as a loss (ladder narrowed).",
        )


class TestTcpPlpmtudAdapter__PeerLimit(TestCase):
    """
    The peer-advertised-MSS ceiling on the probe ladder.
    """

    def test__adapter__limit_max_caps_search(self) -> None:
        """
        Ensure 'limit_max' (fed peer MSS + overhead at handshake)
        caps the search so probes never propose a packet the
        peer's own segment-size limit forbids.
        """

        adapter = _probing_adapter()
        adapter.limit_max(2000)
        _open_search(adapter)

        candidate = adapter.engine.candidate_mtu
        assert candidate is not None
        self.assertLessEqual(
            candidate,
            2000,
            msg="Post-limit candidates MUST stay at or below the peer's packet limit.",
        )
