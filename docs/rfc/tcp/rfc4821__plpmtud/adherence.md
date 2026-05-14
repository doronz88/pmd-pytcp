# RFC 4821 — Packetization Layer Path MTU Discovery (PLPMTUD)

| Field       | Value                                  |
|-------------|----------------------------------------|
| RFC number  | 4821                                   |
| Title       | Packetization Layer Path MTU Discovery |
| Category    | Standards Track                        |
| Date        | March 2007                             |
| Source text | [`rfc4821.txt`](rfc4821.txt)           |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 4821. The audit was performed by
reading the RFC text fresh against the codebase under
`pytcp/` and `net_proto/` directly. Sections that
contain no normative content (Introduction, Terminology,
References, Security Considerations boilerplate) are
omitted.

---

## Top-line adherence

PyTCP has **the substrate but not active PLPMTUD
probing**. After the Phases 1-8 ICMP-demux + PMTUD
refactor and the TCP-side IP_RECVERR work (commits
through `b2473cf6` on `PyTCP_3_0__pre_release`), the
classical RFC 1191 / RFC 8201 callbacks are wired and
the per-destination MTU cache exists; what is missing
is the active probing engine that RFC 4821 specifies.

| Mechanism                                              | Status                                  |
|--------------------------------------------------------|-----------------------------------------|
| Per-destination MTU cache (`stack.pmtu_cache`)         | present (RFC 4821 §5.2)                 |
| TCP `_apply_pmtu_update` callback                      | present (classical PMTUD only)          |
| UDP `notify_pmtu` callback                             | present (classical PMTUD only)          |
| `_effective_pmtu()` socket accessor (IP_MTU/IPV6_MTU)  | present                                 |
| Active probing engine (search_low/search_high/eff_pmtu)| **not implemented**                     |
| Probe-segment emit + ACK detection                     | **not implemented**                     |
| Black-hole detection (full-stop timeout)               | **not implemented**                     |
| Re-probe periodically (raise timer)                    | **not implemented**                     |

The "PmtuSearch unified engine" plan at
`docs/refactor/plpmtud_unified_engine.md` is the
implementation track for the gaps above. Phase 0
of that plan is the refresh that produced this audit.

---

## §5.2 Storing PMTU Information

> "The IP layer SHOULD be used to store the cached PMTU
> value and other shared state such as MTU values
> reported by ICMP PTB messages.[...] An implementation
> MAY use the destination address as the local
> representation of a path."

**Adherence:** met (substrate). `stack.pmtu_cache:
dict[Ip4Address | Ip6Address, int]` keys on
destination address (`pytcp/stack/__init__.py:299`).
ICMPv4 Frag-Needed and ICMPv6 Packet-Too-Big handlers
populate it via `TcpSession._apply_pmtu_update`
(`pytcp/protocols/tcp/tcp__session.py:779-816`) and
`UdpSocket.notify_pmtu`
(`pytcp/socket/udp__socket.py:879`).

> "Network or subnet numbers MUST NOT be used as
> representations of a path[...]"

**Adherence:** met. PyTCP keys on the exact
`Ip4Address` / `Ip6Address` of the remote, never on a
prefix.

---

## §7.1 Packet Size Ranges (search_low / search_high / eff_pmtu)

> "search_low: The smallest useful probe size, minus
> one. The network is expected to be able to deliver
> packets of size search_low."
>
> "search_high: The greatest useful probe size. Packets
> of size search_high are expected to be too large for
> the network to deliver."
>
> "eff_pmtu: The effective PMTU for this flow. This is
> the largest non-probe packet permitted by PLPMTUD for
> the path."

**Adherence:** not implemented. PyTCP stores only the
classical-PMTUD scalar — `pmtu_cache[dst]` is the
single value, no search-range state. The plan
introduces `PmtuSearch[A]` at `pytcp/lib/plpmtud.py`
with `_min_mtu` / `_candidate_mtu` / `_max_mtu` /
`_ack_size` corresponding to RFC 4821's three state
variables.

---

## §7.2 Selecting Initial Values

> "It is RECOMMENDED that search_low be initially set to
> an MTU size that is likely to work over a very wide
> range of environments. Given today's technologies, a
> value of 1024 bytes is probably safe enough."

**Adherence:** not implemented (no active probing
engine).

> "There SHOULD be per-protocol and per-route
> configuration options to override initial values for
> eff_pmtu and other PLPMTUD state variables."

**Adherence:** not implemented. Plan provides a
constructor-parameter override for the engine; sysctl
exposure is deferred to a follow-on commit.

---

## §7.3 Selecting Probe Size

> "A simple strategy might be to do a binary search
> halving the probe size range with each probe."
>
> "Each Packetization Layer MUST determine when probing
> has converged, that is, when the probe size range is
> small enough that further probing is no longer worth
> its cost."

**Adherence:** not implemented. Plan's `PmtuSearch`
engine performs the binary search (search_low /
search_high midpoint per RFC 8899 §5.3.1) with 8-byte
granularity.

> "When the timer expires, search_high should be reset
> to its initial value (described above) so that
> probing can resume."

**Adherence:** not implemented. Plan's
`PMTU_RAISE_TIMER` (default 600 s per RFC 8899 §5.1.1)
re-enters SEARCHING from SEARCH_COMPLETE.

---

## §7.4 Probe Preconditions

> "Protocols MAY delay sending non-probes in order to
> accumulate enough data to meet the pre-conditions for
> probing."

**Adherence:** not implemented. The cwnd-exempt
accounting for probe segments (no consumption of
congestion window) is a Phase 3 plan item: probes will
be tagged on the in-flight record so
`bytes_in_flight()` skips them. Without that, a probe
of 9000 bytes on a 14000-byte cwnd would consume ~64%
of cwnd for diagnostic traffic — RFC 4821 §7.4
explicitly forbids this.

---

## §7.5 Conducting a Probe

> "Once a probe size in the appropriate range has been
> selected, and the above preconditions have been met,
> the Packetization Layer MAY conduct a probe. To do
> so, it creates a probe packet such that its size,
> including the outermost IP headers, is equal to the
> probe size."

**Adherence:** not implemented. PyTCP does not
construct probe segments — only data segments sized to
the current MSS via `tcp__session.py` segment-factory
TX path. Plan adds `build_probe_segment(seq, size)` and
gates emit on adapter `maybe_probe(now)`.

---

## §7.6 Response to Probe Results

> "When the probe is delivered, it is an indication
> that the Path MTU is at least as large as the probe
> size. Set search_low to the probe size. If the probe
> size is larger than the eff_pmtu, raise eff_pmtu to
> the probe size."

**Adherence:** not implemented. Plan's
`PmtuSearch.on_probe_ack(size)` advances `_ack_size`
and raises `_current_mtu` to it.

> "When only the probe is lost, it is treated as an
> indication that the Path MTU is smaller than the probe
> size. In this case alone, the loss SHOULD NOT be
> interpreted as congestion signal."

**Adherence:** not implemented. The "probe loss is not
a congestion signal" requirement is critical and is
the Phase 3 separate-probe-RTO mechanism: probe loss
detected by probe-specific timer, not by data-RTO
inheritance, so cwnd is not halved on a probe loss.

---

## §7.7 Full-Stop Timeout (black-hole detection)

> "Under all conditions, a full-stop timeout (also known
> as a 'persistent timeout' in other documents) SHOULD
> be taken as an indication of some significantly
> disruptive event in the network[...]"
>
> "The response to a detected black hole depends on the
> current values for search_low and eff_pmtu. If
> eff_pmtu is larger than search_low, set eff_pmtu to
> search_low. Otherwise, set both eff_pmtu and
> search_low to the initial value for search_low."
>
> "Upon additional successive timeouts, search_low and
> eff_pmtu SHOULD be halved, with a lower bound of 68
> bytes for IPv4 and 1280 bytes for IPv6."

**Adherence:** not implemented. PyTCP's RFC 6298 RTO
machinery retransmits at the same MSS; there is no
size-reduction fallback on persistent timeout. Plan's
engine ERROR state clamps to `_min_mtu` (1280 IPv6 /
576 IPv4) on consecutive probe loss; plan does NOT
implement progressive halving — the RFC 8899 floor is
a hard clamp that better matches Linux behaviour.

---

## §7.8 MTU Verification

> "To be robust [against multi-path or non-
> deterministic MTU paths], the Packetization Layer
> SHOULD conduct MTU verification as described in
> Section 7.8."

**Adherence:** not implemented and not planned. Path
forking is rare on host-stack workloads; deferred until
Phase 2 (router parity) makes it relevant.

---

## §10 Application-layer considerations

The §10 application-layer guidance (10.1 datagram
applications, 10.2 connection setup, 10.3 stream
applications) is informational. The plan's UDP adapter
(Phase 4) exposes a manual probe API consistent with
§10.1's recommendation that "the simplest applications
might just use static MTU values" — applications that
have an ACK channel (QUIC, SCTP, app-layer
echo/heartbeat) can drive PLPMTUD via the adapter; the
"vanilla UDP without an app ACK" case is honestly
unaddressable per §10.1 and the plan does not pretend
otherwise.

---

## Test coverage audit

No PLPMTUD-active-probing tests exist today. The
substrate is locked in by:

### §5.2 per-destination cache

- **Unit:** `pytcp/tests/unit/stack/test__pmtu_cache.py`
  — pins cache shape, lifetime, IPv4/IPv6 keying.
- **Integration:**
  `pytcp/tests/integration/protocols/icmp4/test__icmp4__pmtud.py`,
  `pytcp/tests/integration/protocols/icmp6/test__icmp6__pmtud.py`
  — ICMP Frag-Needed / Packet-Too-Big populates cache.

**Status:** locked in (substrate); active probing tests
to come in Phase 3.

### §7.1-§7.7 active probing

**No test surface — gap not yet closed.** The plan's
§7.5 "Test matrix" enumerates the ~46 test methods that
will lock in active probing across Phase 1 (engine
unit), Phase 2 (registry), Phase 3 (TCP adapter
integration), and Phase 4 (UDP adapter integration).
The canonical mapping:

| Clause                             | Future test                                                                                 |
|------------------------------------|---------------------------------------------------------------------------------------------|
| §3 / §7.5 Probing without ICMP     | `test__tcp__plpmtud__established_probe_emitted_after_timer` (Phase 3)                       |
| §5 / §7.5 Probe segment generation | `test__tcp__plpmtud__probe_segment_size_matches_candidate` (Phase 3)                        |
| §7.1 search_low/high state vars    | `test__plpmtud__on_probe_ack_advances_search_low` + sibling (Phase 1)                       |
| §7.3 Binary search convergence     | `test__plpmtud__binary_search_ladder_convergence` (Phase 1)                                 |
| §7.4 Probes excluded from cwnd     | `test__tcp__plpmtud__bytes_in_flight_excludes_probe_segment` (Phase 3)                      |
| §7.5 Probe-loss → engine           | `test__tcp__plpmtud__probe_rto_calls_on_probe_loss` (Phase 3)                               |
| §7.5 Data-RTO does NOT feed engine | `test__tcp__plpmtud__data_rto_does_not_feed_probe_loss` (Phase 3)                           |
| §7.7 Black-hole clamp to min       | `test__tcp__plpmtud__black_hole_clamps_to_min_pmtu` (Phase 3)                               |
| §7.3 Re-probe (raise timer)        | `test__tcp__plpmtud__search_complete_raise_timer_reprobes` (Phase 3)                        |

### Test coverage summary

| Aspect                                              | Coverage                  |
|-----------------------------------------------------|---------------------------|
| §5.2 per-destination MTU cache                      | locked in (substrate)     |
| §7.1 search_low/high/eff_pmtu state                 | n/a (gap; planned Phase 1)|
| §7.3 binary-search probe size                       | n/a (gap; planned Phase 1)|
| §7.4 cwnd-exempt probes                             | n/a (gap; planned Phase 3)|
| §7.5 probe segment emit + ACK / loss feedback       | n/a (gap; planned Phase 3)|
| §7.6 probe-success / probe-failure response         | n/a (gap; planned Phase 1)|
| §7.7 full-stop timeout / black-hole detection       | n/a (gap; planned Phase 3)|

---

## Overall assessment

| Aspect                                          | Status                  |
|-------------------------------------------------|-------------------------|
| §5.2 Per-destination MTU cache                  | met (substrate)         |
| §7.1 Active probing state machine               | not implemented         |
| §7.3 Binary-search probe selection              | not implemented         |
| §7.4 Probes excluded from cwnd                  | not implemented         |
| §7.5 Probe-segment emit                         | not implemented         |
| §7.6 Probe-result feedback to engine            | not implemented         |
| §7.7 Black-hole detection on full-stop timeout  | not implemented         |
| §7.8 MTU verification across multi-path         | not implemented (not planned) |

**Principal gap:** the active probing engine and its
TCP / UDP adapters. Closed by the
`plpmtud_unified_engine.md` plan Phases 1-4
(~3-4 days total). Phase 5 of that plan refreshes this
audit again to flip the "not implemented" rows above to
"met" once the implementation ships.
