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
The TCP-side PLPMTUD adapter. 'TcpPlpmtudAdapter' wraps a
'PmtuSearch' engine and tracks per-session in-flight probe
segments so 'TcpSession' can drive RFC 4821 §3 / §5 / §7
active probing alongside the classical RFC 1191 / RFC 8201
ICMP-driven PMTUD that already exists.

The adapter exposes a thin API on top of 'PmtuSearch':
'maybe_probe(now)' queries whether a probe should be emitted
now; 'record_emitted_probe(seq, size, now)' records that an
emitted probe carries 'size' bytes at sequence number 'seq';
'on_snd_una_advance(new_snd_una, now)' detects probe-ack
events by checking whether any in-flight probe's terminal
sequence has been acknowledged; 'on_rto_timeout(now)'
declares any still-in-flight probes as lost. The adapter
keeps the engine and the TcpSession decoupled — the engine
owns the state-machine logic, the adapter owns the in-flight
probe bookkeeping, and the session glues the two to its
segment-emit and ack-processing paths.

Design rationale and per-phase migration plan:
docs/refactor/plpmtud_unified_engine.md

pmd_pytcp/protocols/tcp/tcp__plpmtud_adapter.py

ver 3.0.7
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

from pmd_net_addr import Ip4Address, Ip6Address
from pmd_pytcp.lib.plpmtud import PmtuSearch, PmtuState


class TcpPlpmtudAdapter:
    """
    Per-session PLPMTUD adapter. Owns the 'PmtuSearch'
    engine for the session's remote address and the
    in-flight probe-tracking dict.
    """

    __slots__ = ("_engine", "_in_flight", "_implicit_confirm")

    _engine: PmtuSearch[Ip4Address] | PmtuSearch[Ip6Address]
    _in_flight: Dict[int, Tuple[int, int]]
    _implicit_confirm: Optional[Tuple[int, int, int]]

    def __init__(
        self,
        *,
        remote_ip_address: Ip4Address | Ip6Address,
        interface_mtu: int,
        probing: bool = False,
        probe_timer_sec: Optional[float] = None,
        plpmtu_seed: Optional[int] = None,
    ) -> None:
        """
        Initialize the adapter for one session. 'remote_ip_address'
        is the session's peer; the engine's family floor (1280 for
        IPv6 / 576 for IPv4) is selected automatically from the
        address type. 'interface_mtu' is the local link MTU, used
        as the engine's MAX_PLPMTU ceiling. 'probing' mirrors the
        session's 'tcp.mtu_probing' enable into the engine so its
        working PLPMTU seeds at BASE_PLPMTU (grow-through-validation)
        instead of the interface MTU (classical shrink-only).
        'probe_timer_sec' overrides the RFC 8899 §5.1.1 PROBE_TIMER
        (None keeps the engine's 30 s default); sessions feed it
        from the 'tcp.plpmtud.probe_timer_ms' sysctl.
        'plpmtu_seed' is the operator-declared-safe starting
        PLPMTU (probing mode; sessions feed 'tcp.base_mss' plus
        header overhead) so the working size starts at the proven
        cold-start value instead of BASE_PLPMTU.
        """

        engine_kwargs: dict = {"interface_mtu": interface_mtu, "probing": probing}
        if probe_timer_sec is not None:
            engine_kwargs["probe_timer_sec"] = probe_timer_sec
        if plpmtu_seed is not None:
            engine_kwargs["plpmtu_seed"] = plpmtu_seed
        if isinstance(remote_ip_address, Ip6Address):
            engine_ip6: PmtuSearch[Ip6Address] = PmtuSearch(
                address=remote_ip_address,
                **engine_kwargs,
            )
            self._engine = engine_ip6
        else:
            engine_ip4: PmtuSearch[Ip4Address] = PmtuSearch(
                address=remote_ip_address,
                **engine_kwargs,
            )
            self._engine = engine_ip4
        self._in_flight = {}
        self._implicit_confirm = None

    @property
    def engine(self) -> PmtuSearch[Ip4Address] | PmtuSearch[Ip6Address]:
        """
        Get the underlying PLPMTUD engine instance. Test
        fixtures and the per-destination registry on
        'stack.pmtu_state' need direct access; ordinary
        callers should prefer the adapter's own API surface.
        """

        return self._engine

    @property
    def current_mtu(self) -> int:
        """
        Get the engine's current PLPMTU — what the session's
        segment factory should size data segments against.
        """

        return self._engine.current_mtu

    @property
    def state(self) -> PmtuState:
        """
        Get the engine's current state.
        """

        return self._engine.state

    @property
    def candidate_mtu(self) -> int | None:
        """
        Get the engine's current candidate probe size
        without committing (no PROBE_TIMER arming). Callers
        check this before deciding whether they have enough
        application data to fill the probe; only after the
        feasibility check do they call 'maybe_probe' to
        actually reserve the probe slot.
        """

        return self._engine.candidate_mtu

    @property
    def in_flight_probe_sizes(self) -> tuple[int, ...]:
        """
        Get a snapshot of in-flight probe sizes for RFC 4821
        §7.4 cwnd-exempt accounting — callers subtract the
        sum of these sizes from 'bytes_in_flight' so a
        probe-sized segment does not consume the congestion
        window.
        """

        return tuple(size for _, size in self._in_flight.values())

    def maybe_probe(self, *, now: float) -> int | None:
        """
        Query whether a probe should be emitted now. Returns
        the probe size if the engine is ready to probe, or
        None if no probe should be emitted (probe in flight,
        idle in SEARCH_COMPLETE / ERROR / DISABLED, etc.).

        An in-flight probe that has outlived the engine's
        PROBE_TIMER is declared lost here, first — this poll
        is the PROBE_TIMER's firing point (the engine has no
        timer wheel of its own), and it runs on the segment-
        emit path so an active transfer checks it constantly.

        The caller is responsible for actually emitting a
        segment of the returned size and then calling
        'record_emitted_probe' with the chosen sequence
        number.
        """

        if self._in_flight and self._engine.probe_timer_expired(now=now):
            for _ in self._in_flight:
                self._engine.on_probe_loss(now=now)
            self._in_flight.clear()
        return self._engine.next_probe_size(now=now)

    def record_emitted_probe(self, *, seq: int, size: int, seq_start: Optional[int] = None) -> None:
        """
        Record that a probe segment of 'size' bytes was emitted
        with terminal sequence number 'seq' (and first sequence
        'seq_start', when the caller supplies it). The adapter
        tracks this entry so 'on_snd_una_advance' can detect when
        the probe is acknowledged, 'on_rto_timeout' /
        'on_range_retransmitted' can declare it lost, and the range
        is available for overlap checks.
        """

        self._in_flight[seq] = (seq if seq_start is None else seq_start, size)

    def on_snd_una_advance(self, *, new_snd_una: int, now: float) -> None:
        """
        Notify the adapter that 'snd.una' has advanced. Any
        in-flight probe whose terminal seq is now <= new_snd_una
        (modulo TCP's 32-bit wraparound — handled by treating
        'seq < new_snd_una' as "acked" within the active
        session's seq-space window) is declared acknowledged
        and the engine's 'on_probe_ack(size)' is dispatched.

        This is only a valid probe ACK because every repair
        path ('on_rto_timeout' / 'on_range_retransmitted')
        removes in-flight probes BEFORE any retransmission
        covers their range — otherwise a lost probe whose
        bytes were re-sent as smaller segments would advance
        'snd.una' past the probe seq and read as a success
        for a size the path actually drops.
        """

        acked_seqs: list[int] = []
        for seq, (_, size) in self._in_flight.items():
            if _seq_le(seq, new_snd_una):
                acked_seqs.append(seq)
                self._engine.on_probe_ack(size, now=now)
        for seq in acked_seqs:
            del self._in_flight[seq]

    def on_rto_timeout(self, *, now: float) -> None:
        """
        Notify the adapter that the session's retransmit
        timer fired. Any still-in-flight probe is declared
        lost and 'engine.on_probe_loss(now)' is dispatched;
        the pending implicit-confirm slot is voided (its
        range is about to be repaired). After this call the
        in-flight dict is empty — RTO is a loss event for
        every outstanding probe.

        An RTO is additionally the black-hole signal for a
        probe-raised working PLPMTU ('on_black_hole_suspected'):
        paths exist that ACK an oversized probe in isolation
        yet drop that size under sustained load, and the
        resulting stall surfaces as an RTO with no probe in
        flight at all.
        """

        self._implicit_confirm = None
        if self._in_flight:
            for _ in self._in_flight.values():
                self._engine.on_probe_loss(now=now)
            self._in_flight.clear()
        self._engine.on_black_hole_suspected(now=now)

    def on_range_retransmitted(self, *, seq_start: int, seq_end: int, now: float) -> None:
        """
        Notify the adapter that a retransmission covering
        '[seq_start, seq_end)' was just emitted. An in-flight
        probe overlapping that range is declared lost NOW —
        its bytes are being repaired at regular size, and once
        the repair advances 'snd.una' past the probe seq,
        'on_snd_una_advance' could no longer tell a genuine
        probe ACK from a repaired hole (the false-positive
        that would raise the MSS into a black hole). Probes
        OUTSIDE the retransmitted range are left alone:
        ordinary congestion repairs elsewhere in the stream
        must not spuriously narrow the search or trip the
        MAX_PROBES black-hole counter (a SACKed probe still
        collects its genuine ACK).

        The pending implicit-confirm slot is voided when the
        repair overlaps ITS range, for the same reason: its
        ACK would confirm a packet size the path never
        carried in one piece.
        """

        if self._implicit_confirm is not None:
            ic_start, ic_end, _ = self._implicit_confirm
            if _ranges_overlap(seq_start, seq_end, ic_start, ic_end):
                self._implicit_confirm = None
        if not self._in_flight:
            return
        lost = [
            probe_end
            for probe_end, (probe_start, _) in self._in_flight.items()
            if _ranges_overlap(seq_start, seq_end, probe_start, probe_end)
        ]
        for probe_end in lost:
            del self._in_flight[probe_end]
            self._engine.on_probe_loss(now=now)

    def note_data_segment(self, *, seq_start: int, end_seq: int, packet_size: int) -> None:
        """
        Record the largest regular (non-probe, fresh) data
        segment currently awaiting acknowledgement, as a
        single (start-seq, terminal-seq, IP-packet-size)
        slot. When 'snd.una' passes the recorded terminal
        seq, 'check_implicit_confirm' feeds the size to the
        engine as RFC 4821 §7.1 implicit-probe feedback —
        which is what confirms the BASE state without a
        dedicated base probe. Single slot on purpose:
        confirming the largest in-flight size subsumes the
        smaller ones, and the hot send path should not grow
        a per-segment structure.
        """

        if self._implicit_confirm is None or packet_size > self._implicit_confirm[2]:
            self._implicit_confirm = (seq_start, end_seq, packet_size)

    def check_implicit_confirm(self, *, new_snd_una: int, now: float) -> None:
        """
        Dispatch the pending implicit confirmation once
        'snd.una' has advanced past its recorded terminal
        seq. Cheap no-op (one tuple check) when nothing is
        pending.
        """

        if self._implicit_confirm is None:
            return
        _, end_seq, packet_size = self._implicit_confirm
        if _seq_le(end_seq, new_snd_una):
            self._implicit_confirm = None
            self._engine.confirm_current(packet_size, now=now)

    def limit_max(self, mtu: int) -> None:
        """
        Pass-through to the engine's search-ceiling clamp.
        Called at handshake completion with the peer's
        advertised MSS plus IP+TCP overhead, so probes never
        exceed the packet size the peer invited.
        """

        self._engine.limit_max(mtu)

    def on_classical_pmtu(self, mtu: int, *, now: float) -> None:
        """
        Pass-through to the engine's classical-PMTUD handler.
        Called by TcpSession._apply_pmtu_update so the engine
        absorbs RFC 1191 / RFC 8201 PTB signals.
        """

        self._engine.on_classical_pmtu(mtu, now=now)

    def confirm_current(self, size: int, *, now: float = 0.0) -> None:
        """
        Pass-through to the engine's regular-data
        confirmation. Called by TcpSession when a non-probe
        segment is acknowledged; the largest such size
        advances ack_size per RFC 4821 §7.1 implicit-probe
        feedback (and confirms BASE, opening the search).
        """

        self._engine.confirm_current(size, now=now)


def _ranges_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    """
    Check whether the half-open seq ranges '[a_start, a_end)'
    and '[b_start, b_end)' overlap, under TCP's 32-bit modular
    ordering: 'a_start < b_end and b_start < a_end'. Probe and
    repair ranges are tiny fractions of the sequence space, so
    the half-space comparison is unambiguous.
    """

    return (
        _seq_le(a_start, b_end)
        and a_start != b_end
        and _seq_le(b_start, a_end)
        and b_start != a_end
    )


def _seq_le(seq_a: int, seq_b: int) -> bool:
    """
    32-bit modular sequence comparison: returns True when
    'seq_a <= seq_b' under TCP's RFC 9293 §3.4 wraparound-
    aware ordering. The valid window is half the sequence
    space (2^31), so a "small" forward distance from 'seq_a'
    to 'seq_b' means 'seq_a' is <=; the symmetric backward
    distance means 'seq_a' is >. The single-byte tolerance
    above the modular comparison handles the inclusive
    "<=" check.
    """

    return ((seq_b - seq_a) & 0xFFFFFFFF) < 0x80000000
