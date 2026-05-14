# PLPMTUD — unified engine + TCP/UDP onboarding plan

Authored 2026-05-14 after the UDP punch list close-out
(`b804f565..0f2631ae` on `PyTCP_3_0__pre_release`). This
plan is the canonical implementation guide for active
Packetization-Layer PMTUD across both transports.

The two relevant RFCs and their PyTCP audit records:

- **RFC 4821** — Packetization Layer Path MTU Discovery
  (TCP-focused, 2007). Audit:
  `docs/rfc/tcp/rfc4821__plpmtud/adherence.md` — top-line
  "zero PLPMTUD support".
- **RFC 8899** — Packetization Layer PMTUD for Datagram
  Transports (DCCP / SCTP / QUIC / UDP, 2020). Audit:
  `docs/rfc/tcp/rfc8899__dplpmtud/adherence.md` — top-line
  "substrate present (pmtu_cache + classical-PMTUD wiring)
  but no active probing".

RFC 8899 generalises the RFC 4821 technique to any
packetization layer and explicitly identifies TCP as one
such layer. Modern Linux runs a unified PLPMTUD engine
across TCP and UDP/QUIC. PyTCP follows that pattern.

---

## 1. Why a unified engine

About 80% of the algorithm is transport-agnostic:

| Concern                                              | Shared |
|------------------------------------------------------|:------:|
| Per-destination search-state machine (RFC 8899 §5)   | yes    |
| Candidate MTU ladder (binary search base..max)       | yes    |
| MIN_PMTU floor (1280 v6 / 576 v4) + ceiling          | yes    |
| PROBE_TIMER + PROBE_COUNT retry                      | yes    |
| Black-hole detection (consecutive probe loss)        | yes    |
| Interaction with classical PMTUD (ICMP feedback)     | yes    |
| Per-destination cache (`stack.pmtu_cache`)           | yes (already shared) |
| **Probe-segment emit**                               | transport-specific |
| **Probe ACK / loss detection**                       | transport-specific |

The remaining 20% (the two "transport-specific" rows) is
the difference between RFC 4821 and RFC 8899: how a
packet of size N gets onto the wire, and how the engine
learns it made it (or didn't).

Splitting into two engines (one per RFC) would duplicate
the state machine, search ladder, timer logic, and
black-hole detection. Wrong move. Unified engine + per-
transport adapter is the right factoring.

---

## 2. Non-goals

- **ICMP-blackhole resilience as a marketing feature.**
  The classical-PMTUD path (RFC 1191 / RFC 8201) is
  already wired and continues to feed `stack.pmtu_cache`.
  PLPMTUD is complementary, not a replacement.
- **Per-packet probing for short flows.** RFC 8899 §4.6
  notes probing is a long-running activity; we don't try
  to fit a search into a 3-packet TFO exchange.
- **UDP without an application ACK channel.** The UDP
  adapter exposes a manual probe API; it does NOT try to
  invent an ACK mechanism. Real PLPMTUD users on UDP
  (QUIC, SCTP) have their own PING/HEARTBEAT frames.
- **MTU discovery via traceroute-style TTL probing.** RFC
  4821 explicitly forbids this; we don't entertain it.
- **MIN_PMTU below the RFC-mandated floors.** Never.
- **PLPMTUD for raw sockets.** Out of scope; raw is for
  ICMP / diagnostic tools, not bulk data.

---

## 3. Architecture

### 3.1 Shared engine — `net_proto/lib/plpmtud.py`

PEP 695 generic over the address type:

```python
class PmtuSearch[A: Ip4Address | Ip6Address]:
    """Per-destination DPLPMTUD search engine."""

    _state: PmtuState           # see §3.2
    _current_mtu: int           # the value the transport should use NOW
    _candidate_mtu: int | None  # mtu being probed (None when idle)
    _max_mtu: int               # ceiling (= interface_mtu)
    _min_mtu: int               # floor (1280 v6 / 576 v4)
    _probe_count: int           # consecutive losses on _candidate_mtu
    _probe_timer_expiry: float | None  # monotonic clock; None when idle
    _ack_size: int              # largest size successfully ACK'd

    def next_probe_size(self, now: float) -> int | None: ...
    def on_probe_ack(self, size: int) -> None: ...
    def on_probe_loss(self, now: float) -> None: ...
    def on_classical_pmtu(self, mtu: int) -> None: ...
    def confirm_current(self, size: int) -> None: ...   # any non-probe ACK
```

Properties:

- `current_mtu` — what TCP segment factory / UDP TX path
  reads when sizing the next packet. Always at least
  `_min_mtu`, at most `_max_mtu`.
- `is_probing` — True while `_candidate_mtu is not None`.
  Helps transport adapters short-circuit "do not emit a
  fresh probe yet" decisions.

All state mutations are inside the engine; transport
adapters never touch private fields directly.

### 3.2 The search state machine (RFC 8899 §5)

```
            ┌─────────────┐
            │  DISABLED   │  (set MTU = max; no probing)
            └──────┬──────┘
                   │ enabled at construction
                   ▼
            ┌─────────────┐
            │    BASE     │  (current = base_mtu; probe to confirm)
            └──────┬──────┘
                   │ probe_ack
                   ▼
            ┌─────────────┐    probe_loss × PROBE_COUNT
            │  SEARCHING  │ ─────────────────┐
            │             │                  │
            │  binary     │ probe_ack        │
            │  search     │ ↑                │
            │  base..max  │ │                │
            └──────┬──────┘ │                │
                   │ converged                │
                   ▼                          │
            ┌─────────────┐                  │
            │   SEARCH_   │                  │
            │   COMPLETE  │                  │
            └─────────────┘                  │
                                              │
            ┌─────────────┐                  │
            │    ERROR    │ ◄────────────────┘
            │ (clamp min) │
            └─────────────┘
```

`BASE` state requires confirming the base MTU works
before any larger probe is attempted. `SEARCHING`
implements the binary-search ramp. `SEARCH_COMPLETE`
is the steady state; periodic re-probing (the "raise"
phase, RFC 8899 §5.3) can transition back to
`SEARCHING` on a timer (default 600 s, RFC 8899
`PMTU_RAISE_TIMER`).

`ERROR` is entered when consecutive losses indicate a
black hole; the engine clamps to `_min_mtu` and stays
there until either an ICMP signal arrives or the raise
timer elapses.

### 3.3 Transport-adapter contract

```python
class PmtuAdapter[A: Ip4Address | Ip6Address](ABC):
    """Transport-side glue for PmtuSearch."""

    @abstractmethod
    def emit_probe(self, *, dst: A, size: int) -> bool:
        """
        Send a probe of 'size' bytes (IP + transport payload)
        to 'dst'. Return True if the probe was emitted, False
        if the transport is not currently able to (e.g.
        zero-window for TCP, no-app-handshake for UDP).
        """

    @abstractmethod
    def on_search_complete(self, *, dst: A, mtu: int) -> None:
        """Notify the transport that a probe converged."""

    @abstractmethod
    def on_search_error(self, *, dst: A, mtu: int) -> None:
        """Notify the transport that a black hole was detected."""
```

The adapter owns the "when to probe" rhythm (timer
firing in the subsystem loop). The engine owns "what
size to probe and which state to transition to."

### 3.4 Per-destination registry

Today `stack.pmtu_cache: dict[A, int]` stores the
current MTU. PLPMTUD needs the full search state per
destination, not just the scalar MTU. Promote to:

```python
stack.pmtu_state: dict[Ip4Address | Ip6Address, PmtuSearch[...]] = {}

# Backward-compat read accessor for code that just wants
# the current scalar MTU (TX path, IP fragmentation
# decision):
def current_pmtu(dst: Ip4Address | Ip6Address) -> int | None: ...
```

The `pmtu_cache` dict is **deprecated in favor of
`pmtu_state`**; the cache becomes a derived view. Phase
2 migrates the existing consumers (`TcpSession._apply_pmtu_update`,
`UdpSocket.notify_pmtu`, `_effective_pmtu`).

---

## 4. Phased delivery

Each phase is one focused commit (or one tests-first +
one fix pair) per the project's tests-first / commit-
discipline rules. Phases are mechanically reversible.

### Phase 0 — Audit refresh

**Goal:** lift the per-RFC adherence records into
"what we now have / what is still missing" rather than
"top-line not implemented." Build the gap punch list.

**Touches:**
- `docs/rfc/tcp/rfc4821__plpmtud/adherence.md` — refresh
  the per-section verdicts now that the classical-PMTUD
  substrate exists.
- `docs/rfc/tcp/rfc8899__dplpmtud/adherence.md` — same.
- This plan doc — record the punch list inline (§7
  below).

**Tests:** none. Documentation only.

**Effort:** ~1-2 hours.

### Phase 1 — `PmtuSearch` shared engine

**Goal:** ship the state machine as a pure dataclass
under `net_proto/lib/plpmtud.py` with full unit-test
coverage. No integration.

**Touches:**
- `net_proto/lib/plpmtud.py` — new file. PEP 695 generic
  class, RFC 8899 §5 state machine, candidate MTU
  ladder, timer machinery, black-hole detection, ICMP
  signal absorption.
- `net_proto/tests/unit/lib/test__lib__plpmtud.py` —
  per-state transition tests, ladder convergence,
  black-hole entry/exit, ICMP-signal short-circuit.

**Test plan:**

1. Construction: state=BASE, current=base_mtu (1280 v6 /
   576 v4 + Linux's bump to 1500 if interface MTU
   allows), candidate=None.
2. `next_probe_size()` from BASE → returns base_mtu (we
   probe the base first per RFC 8899 §5.2).
3. `on_probe_ack(base_mtu)` → state → SEARCHING,
   ack_size = base_mtu, candidate = midpoint.
4. Probe ladder: alternating ack/loss converges on the
   true MTU (parameterised over several true-MTU
   values).
5. `on_probe_loss` × PROBE_COUNT → state → ERROR,
   current clamped to min_mtu.
6. `on_classical_pmtu(mtu)` while SEARCHING → engine
   clamps candidate to mtu, advances to SEARCH_COMPLETE
   if classical MTU is below current ack_size.
7. `on_classical_pmtu(mtu)` while in ERROR → recover to
   SEARCHING with classical mtu as the new start.

**Effort:** ~half-day. Pure code, no async or threading.

### Phase 2 — Promote `pmtu_cache` to `pmtu_state`

**Goal:** the per-destination registry stores
`PmtuSearch` instances. Existing consumers keep working
via a backward-compat accessor.

**Touches:**
- `pytcp/stack/__init__.py` — add `pmtu_state` dict +
  `current_pmtu(dst)` helper. Mark `pmtu_cache` as
  deprecated alias (`pmtu_cache` becomes a property /
  view derived from `pmtu_state`).
- `pytcp/protocols/tcp/tcp__session.py::_apply_pmtu_update`
  — call into `pmtu_state[dst].on_classical_pmtu(mtu)`
  instead of writing the scalar directly.
- `pytcp/socket/udp__socket.py::notify_pmtu` — same.
- `pytcp/socket/__init__.py::_effective_pmtu` — read via
  `current_pmtu(dst)`.
- Both `_apply_pmtu_update` and `notify_pmtu` call sites
  need to lazy-create the `PmtuSearch` on first ICMP
  signal for the destination.

**Test plan:**
- Existing classical-PMTUD tests stay green (no
  behavioural change).
- New unit test in
  `pytcp/tests/unit/lib/test__lib__pmtu_state.py`:
  on-classical-pmtu lazily allocates a PmtuSearch in
  state=SEARCH_COMPLETE with current=mtu.
- Integration: existing
  `test__tcp__session__icmp__pmtu.py` /
  `test__icmp6__pmtud.py` should pass unchanged.

**Test-harness snapshot/restore:** new module-level
state `stack.pmtu_state` requires the same commit to
update `TcpSessionTestCase` / `IcmpTestCase` /
`NetworkTestCase` `setUp`/`tearDown` to
snapshot+clear+restore — see `integration_testing.md`
§5.4 and the project memory note. Failure mode if
omitted: passes-alone / fails-in-suite.

**Effort:** ~half-day.

### Phase 3 — TCP adapter + probe emission

**Goal:** active PLPMTUD probing for TCP, hooked into
`TcpSession`. End-to-end probe → wire → ACK →
state transition.

**Touches:**
- `pytcp/protocols/tcp/tcp__plpmtud_adapter.py` — new
  file. Subclass `PmtuAdapter[Ip4Address | Ip6Address]`,
  bind to a `TcpSession`.
- `pytcp/protocols/tcp/tcp__session.py`:
  - Construct the adapter at session init; arm a
    `PMTU_PROBE_TIMER` (RFC 4821 §7.1 default 60 s).
  - In the session's per-tick logic, call
    `adapter.maybe_probe(now)` which consults
    `engine.next_probe_size(now)` and emits a probe
    when non-None.
  - When `snd.una` advances past a probe's seq, call
    `engine.on_probe_ack(probe_size)`. Track
    in-flight probes in a small dict keyed by seq.
  - When RTO fires on a probe-only segment, call
    `engine.on_probe_loss(now)`. **Probes do NOT
    count against cwnd** (RFC 4821 §7.4) — see §5
    below.
- `tcp__segment_factory.py` (new file or extend
  existing TX path) — `build_probe_segment(seq,
  size)` that pads the segment to `size` bytes with
  zero bytes from a static buffer. The probe-seq is
  one byte past `snd.nxt` so the ACK signal is
  unambiguous; RFC 4821 §7.5 calls this "the
  probe-seq trick."

**Subtle:** RFC 4821 says probes "SHOULD NOT consume
sequence-number space the peer will need to re-ACK on
loss." PyTCP's pragmatic choice: probes DO consume seq
space (matches Linux), but the engine's loss decision
is based on probe-only RTO, not on regular RTO.

**Test plan:**

1. Integration:
   `pytcp/tests/integration/protocols/tcp/test__tcp__session__plpmtud.py`
   - Drive a session to ESTABLISHED; advance the
     PMTU_PROBE_TIMER; assert a probe-segment is
     emitted with the candidate size.
   - ACK the probe; assert engine state advances.
   - Drop the probe (no ACK); assert RTO fires and
     engine records loss.
   - Repeat × PROBE_COUNT; assert ERROR state +
     `current_mtu` clamps to min_mtu.
   - Classical PMTUD signal interleaved with active
     probing: assert correct state convergence.
2. Unit: `tcp__segment_factory.py::build_probe_segment`
   — output bytes shape, header field correctness,
   payload-padding pattern.

**Test-harness snapshot/restore:** Phase 3 doesn't add
new module-level state (only Phase 2 does); the
session-internal adapter is per-instance.

**Effort:** ~1.5-2 days. The probe-emit + ACK detection
path is the longest single piece of work in this plan.

### Phase 4 — UDP adapter (manual probe API)

**Goal:** expose a per-socket probe API so application
protocols that have their own ACK channel (QUIC-style,
echo-server-style) can drive PLPMTUD.

**Touches:**
- `pytcp/protocols/udp/udp__plpmtud_adapter.py` — new
  file. Subclass `PmtuAdapter[...]`, bind to a
  `UdpSocket`.
- `pytcp/socket/udp__socket.py`:
  - `UdpSocket.probe_pmtu(size: int)` — emits a
    `sendto`-style probe of the given size. Tracks
    the in-flight probe.
  - `UdpSocket.ack_probe(size: int)` — application
    calls when its app-level ACK indicates the
    probe arrived.
  - `UdpSocket.timeout_probe()` — application calls
    when its app-level timer fires before the ACK
    came in.

**Why "manual":** vanilla UDP has no native ACK; an
application-driven API is honest about the constraint.
QUIC's PATH_CHALLENGE / PATH_RESPONSE frames or
SCTP's HEARTBEAT chunks are the production model.

**Test plan:**

1. Integration:
   `pytcp/tests/integration/protocols/udp/test__udp__plpmtud.py`
   - Bind a socket; call `probe_pmtu(1500)`; assert a
     1500-byte UDP datagram is on the wire.
   - Call `ack_probe(1500)`; assert
     `current_pmtu(dst)` advances.
   - Call `timeout_probe()` × PROBE_COUNT; assert
     ERROR state and current_mtu clamp.

**Effort:** ~half-day. Smaller than Phase 3 because
the search engine already exists and there's no FSM
to wire into.

### Phase 5 — Audit ripple

**Goal:** reflect the shipped surface in the per-RFC
records.

**Touches:**
- `docs/rfc/tcp/rfc4821__plpmtud/adherence.md` — flip
  the §3 / §5 / §7 rows from "not implemented" to
  "met" with the TCP integration tests as the
  locking surface.
- `docs/rfc/tcp/rfc8899__dplpmtud/adherence.md` — flip
  the state-machine + algorithm rows; the UDP-side
  remains "partial — manual probe API only" because
  the spec implicitly assumes a transport with native
  ACK.
- `docs/refactor/socket_linux_parity_audit.md` — close
  the PLPMTUD deficiency row.
- `docs/refactor/post_udp_session_followups.md` — mark
  UDP #7 as SHIPPED.
- This plan doc — mark each phase SHIPPED in turn.

**Effort:** ~1-2 hours total over the phases.

---

## 5. Subtle design points

### 5.1 Probe-segment cwnd accounting

RFC 4821 §7.4: "An implementation MUST NOT include
probe segments in its computation of the congestion
window." PyTCP's RFC 9438 CUBIC pipe accounting must
exempt probe-only segments. Implementation: tag the
probe with a `flags.probe = True` bit on the in-flight
record; `bytes_in_flight()` skips probe-flagged
entries.

If we miss this, a probe of 9000 bytes on a 14000-byte
cwnd would consume ~64% of cwnd for diagnostic data —
unacceptable.

### 5.2 Probe RTO vs regular RTO

RFC 4821 §7.5: probe loss is detected by **probe-
specific** RTO, not by regular RTO inheritance.
Otherwise a single coincident data-segment loss would
look like a probe loss and prematurely shrink the MTU.

Implementation: the probe has its own retransmit
timer (default `PROBE_TIMER = 30 s` per RFC 8899
§5.1.1). Regular RTO continues for data segments.
The probe-tracking dict keeps `(seq, size, expiry)`.

### 5.3 Coexistence with classical PMTUD

When a classical ICMP Frag-Needed / Packet-Too-Big
arrives:

- If `state is BASE` and the ICMP MTU < base: state →
  ERROR, current = max(min_mtu, icmp_mtu).
- If `state is SEARCHING` and ICMP MTU < candidate:
  abandon current probe, recompute candidate ≤ icmp_mtu,
  stay in SEARCHING.
- If `state is SEARCH_COMPLETE` and ICMP MTU < current:
  state → SEARCHING with new ceiling = icmp_mtu.

The engine never trusts ICMP blindly — it's a hint
that joins the ack/loss feedback loop, not an override.

### 5.4 IPv6 vs IPv4 MIN_PMTU

| Family | RFC-mandated floor | Notes |
|--------|--------------------|-------|
| IPv4   | 68 bytes (RFC 791) | Use 576 in practice (RFC 8899 §5.1.2 "BASE_PMTU = 1024 with floor 576"). Linux uses `min_pmtu = 552` configurable via sysctl. |
| IPv6   | 1280 bytes (RFC 8200 §5) | Hard floor — never go below. RFC 8899 §5.1.1 sets `MIN_PLPMTU = 1280` for IPv6. |

Engine respects these per family — passed in via the
PEP 695 type bound + a constructor parameter.

### 5.5 PROBE_TIMER cadence

RFC 8899 §5.1.1 suggests `PROBE_TIMER = 30 s` (default
for an active search). Probing every 30 s on every
TCP session would generate substantial probe traffic.
Linux's pragmatic choice: probe on the first few RTTs
after connection setup, then once per `PMTU_RAISE_TIMER
= 600 s` thereafter.

PyTCP should match Linux's cadence. The engine exposes
`next_probe_size(now)` returning `None` until the
timer expires, so the adapter's per-tick loop is
cheap; the engine's internal timer logic makes the
"when" decision.

### 5.6 Probe size schedule (binary search)

RFC 8899 §5.3.1 binary search:

```
SEARCH_LOW = ack_size
SEARCH_HIGH = max_mtu
candidate = (SEARCH_LOW + SEARCH_HIGH) // 2
on ack: SEARCH_LOW = candidate (raise floor)
on loss × PROBE_COUNT: SEARCH_HIGH = candidate (lower ceiling)
converged when SEARCH_HIGH - SEARCH_LOW < granularity (default 8 bytes)
```

This is the algorithm both adapters consume; no
transport-specific tweak needed.

### 5.7 What if the application sends a giant write before SEARCH_COMPLETE?

TCP transport tier: the segment factory consults
`current_pmtu(dst)` to size segments. While in
SEARCHING, `current_pmtu` returns `ack_size` (the
largest confirmed-OK size). The application's giant
write is fragmented into `ack_size`-sized segments;
PLPMTUD is doing its work in parallel.

UDP transport tier: same — `sendto(payload)` consults
`current_pmtu(dst)`. If `len(payload) > current_pmtu`,
the IPv4 path either fragments (DF=0) or fails with
EMSGSIZE (DF=1; RFC 1191 §3 + `IP_PMTUDISC` socket-
option behaviour, deferred). IPv6 has no fragmentation
without an explicit Fragment header — same EMSGSIZE
behaviour.

---

## 6. Failure modes the design must prevent

| Failure mode | Phase | Mitigation |
|---|---|---|
| Probe consumes cwnd → starves real data | 3 | Tag probe in in-flight record; `bytes_in_flight` skips it (§5.1) |
| Probe RTO triggered by coincident data loss | 3 | Separate probe-timer; data-RTO doesn't feed probe-loss (§5.2) |
| ICMP signal overrides ack-confirmed MTU | 1 / 5.3 | Engine prefers ack feedback; ICMP only shrinks |
| Black-hole detection fires on transient loss burst | 1 | PROBE_COUNT default = 3 (RFC 8899); only consecutive losses on same candidate count |
| pmtu_state leaks across tests | 2 | TcpSessionTestCase / IcmpTestCase snapshot+restore |
| IPv6 MIN_PMTU violated by engine arithmetic | 1 / 5.4 | Hard clamp inside engine; assertion in unit tests |
| Probe sent before SYN ACK → wasted segment | 3 | Adapter gate: only probe in ESTABLISHED |
| UDP manual API races on `probe_pmtu` while one in flight | 4 | API rejects re-probe while engine `is_probing` |

---

## 7. Per-RFC punch list

Direct cross-reference against the audit records, refreshed
when Phase 0 lands.

### RFC 4821 (TCP PLPMTUD)

| Clause | Today | After plan |
|--------|-------|-----------|
| §3 Probing without ICMP | not implemented | met (Phase 3) |
| §5 Probe segment generation | not implemented | met (Phase 3) |
| §7.1 PROBE_TIMER | not implemented | met (Phase 1 + 3) |
| §7.4 Probes excluded from cwnd | not implemented | met (Phase 3, §5.1) |
| §7.5 Black-hole detection | not implemented | met (Phase 1, §5.3) |
| §7.6 Re-probe periodically (raise) | not implemented | met (Phase 1 raise timer) |

### RFC 8899 (Datagram-transport PLPMTUD)

| Clause | Today | After plan |
|--------|-------|-----------|
| §4 Substrate (per-dest cache) | met | met |
| §4.6.4 BASE_PMTU floor | not enforced | met (Phase 1) |
| §5 State machine | not implemented | met (Phase 1) |
| §5.1 PROBE_COUNT / PROBE_TIMER constants | not implemented | met (Phase 1) |
| §5.3 Binary search | not implemented | met (Phase 1, §5.6) |
| §5.4 SEARCH_COMPLETE → raise | not implemented | met (Phase 1) |
| §6 Datagram transport API (probe send / ack / loss) | not implemented | met for TCP (Phase 3) + manual UDP (Phase 4) |
| §7 Black-hole detection | not implemented | met (Phase 1) |

---

## 8. Out-of-scope items recorded for future work

- **IP_PMTUDISC** socket option (Linux `<netinet/in.h>`
  `IP_PMTUDISC_*` family) — controls DF=0/1 per socket
  + interaction with PLPMTUD. Useful follow-on but
  orthogonal to the engine.
- **Path-MTU per-route caching** vs per-destination —
  Linux caches per route entry (a step above per
  destination). PyTCP's flat per-destination dict is
  the right starting point; per-route can come with
  Phase-2 router parity.
- **QUIC integration.** If PyTCP ever grows a QUIC
  stack, the UDP adapter is the substrate but QUIC
  drives the probe rhythm via PATH_CHALLENGE /
  PATH_RESPONSE.
- **SACK-based probe-ACK detection.** RFC 4821 §7.5
  notes SACK can pin probe vs non-probe loss more
  precisely; PyTCP's RFC 2018 SACK implementation
  could feed the engine. Not on the critical path.

---

## 9. Total effort + sequencing

| Phase | Effort | Depends on |
|-------|--------|-----------|
| 0 — Audit refresh | ~1-2 h | — |
| 1 — PmtuSearch shared engine | ~half-day | 0 |
| 2 — `pmtu_state` registry | ~half-day | 1 |
| 3 — TCP adapter | ~1.5-2 days | 1, 2 |
| 4 — UDP adapter | ~half-day | 1, 2 |
| 5 — Audit ripple | ~1-2 h | 3, 4 |

**Total: ~3-4 days** end-to-end. Phase 3 is the bulk;
Phases 1 + 2 + 4 + 5 combined are about a day.

**Recommended ordering:** 0 → 1 → 2 → 3 → 5a (TCP audit
record only) → 4 → 5b (UDP audit record + final close).
Shipping TCP first means PLPMTUD goes live for the
session-bearing transport before UDP's no-native-ACK
adapter lands; the UDP adapter is shippable
independently after that.

---

## 10. Cross-references

- `docs/rfc/tcp/rfc4821__plpmtud/adherence.md` — TCP
  PLPMTUD audit (refresh in Phase 0).
- `docs/rfc/tcp/rfc8899__dplpmtud/adherence.md` —
  Datagram PLPMTUD audit (refresh in Phase 0).
- `docs/refactor/icmp_demux_pmtud_plan.md` — the
  classical-PMTUD substrate this plan builds on
  (`pmtu_cache`, `_apply_pmtu_update`, `notify_pmtu`).
- `docs/refactor/socket_linux_parity_audit.md` — has
  the per-socket PMTUD discovery option entries.
- `docs/refactor/post_udp_session_followups.md` Item
  #3 — the UDP #7 reference that motivated this plan.
- `.claude/rules/feature_implementation.md` — tests-
  first workflow and the modernise-on-touch rule.
- `.claude/rules/integration_testing.md` §5.4 — the
  snapshot/restore rule when adding `stack.pmtu_state`.
- RFC 4821 §3-§7, RFC 8899 §4-§7 — the normative
  source texts.
