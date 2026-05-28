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

### 3.1 Shared engine — `packages/pytcp/pytcp/lib/plpmtud.py`

`PmtuSearch` is stateful runtime machinery — per-destination
state, timer-driven, ACK-feedback-driven, registered on
`stack.pmtu_state`. That places it in `packages/pytcp/pytcp/`, not
`packages/net_proto/net_proto/` (which is the stateless packet
parse/assemble/validate library — see `CLAUDE.md` package
boundaries). The canonical precedent is the generic
`NeighborCache[A, P]` base at `packages/pytcp/pytcp/lib/neighbor.py`: same
PEP 695 shape, same stateful-runtime classification, same
consumed-by-stack-level-adapters pattern.

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

### Phase 0 — Audit refresh — SHIPPED 2026-05-14

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

**Shipped:** both adherence records refreshed against
the current substrate (`stack.pmtu_cache`,
`_apply_pmtu_update`, `notify_pmtu`, `_effective_pmtu`).
Per-RFC punch list (§7 below) and test matrix (§7.5)
cross-reference back into both audits. Substrate rows
flipped from "not implemented" to "met (substrate)";
active-probing rows remain "not implemented" with a
forward pointer to Phases 1-4.

### Phase 1 — `PmtuSearch` shared engine — SHIPPED 2026-05-14

**Goal:** ship the state machine as a stateful runtime
class under `packages/pytcp/pytcp/lib/plpmtud.py` with full unit-test
coverage. No integration.

**Shipped:** `packages/pytcp/pytcp/lib/plpmtud.py` (`PmtuSearch[A]` +
`PmtuState` + module-level RFC-default constants) plus
21 unit tests at `packages/pytcp/pytcp/tests/unit/lib/test__lib__plpmtud.py`
covering the §7.5 Phase-1 test matrix. Engine initializes
with `current_mtu = interface_mtu` so it stays
compatible with classical-PMTUD callers; the BASE_PLPMTU
constant is the size of the initial probe, not the
working PLPMTU.

**Touches:**
- `packages/pytcp/pytcp/lib/plpmtud.py` — new file. PEP 695 generic
  class, RFC 8899 §5 state machine, candidate MTU
  ladder, timer machinery, black-hole detection, ICMP
  signal absorption. Sits alongside
  `packages/pytcp/pytcp/lib/neighbor.py` as a peer stateful-runtime
  helper.
- `packages/pytcp/pytcp/tests/unit/lib/test__lib__plpmtud.py` —
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

### Phase 2 — Promote `pmtu_cache` to `pmtu_state` — SHIPPED 2026-05-14

**Goal:** the per-destination registry stores
`PmtuSearch` instances. Existing consumers keep working
via a backward-compat accessor.

**Shipped:** `stack.pmtu_state` registry +
`stack.current_pmtu(dst)` helper land alongside the
legacy `pmtu_cache`; `_apply_pmtu_update` (TCP) and
`notify_pmtu` (UDP) mirror every classical PTB into the
registry; `_effective_pmtu()` reads via the precedence
helper (engine state preferred, cache as fallback). The
three socket-touching test harnesses
(`IcmpTestCase` / `TcpTestCase` / `UdpTestCase`)
snapshot+clear+restore `stack.pmtu_state` alongside
`pmtu_cache` so the new module state cannot leak
across tests. Six new unit tests at
`packages/pytcp/pytcp/tests/unit/lib/test__lib__pmtu_state.py` pin the
registry shape, lazy fallback to legacy cache,
per-destination isolation, and IPv4 / IPv6 keying.

**Touches:**
- `packages/pytcp/pytcp/stack/__init__.py` — add `pmtu_state` dict +
  `current_pmtu(dst)` helper. Mark `pmtu_cache` as
  deprecated alias (`pmtu_cache` becomes a property /
  view derived from `pmtu_state`).
- `packages/pytcp/pytcp/protocols/tcp/tcp__session.py::_apply_pmtu_update`
  — call into `pmtu_state[dst].on_classical_pmtu(mtu)`
  instead of writing the scalar directly.
- `packages/pytcp/pytcp/socket/udp__socket.py::notify_pmtu` — same.
- `packages/pytcp/pytcp/socket/__init__.py::_effective_pmtu` — read via
  `current_pmtu(dst)`.
- Both `_apply_pmtu_update` and `notify_pmtu` call sites
  need to lazy-create the `PmtuSearch` on first ICMP
  signal for the destination.

**Test plan:**
- Existing classical-PMTUD tests stay green (no
  behavioural change).
- New unit test in
  `packages/pytcp/pytcp/tests/unit/lib/test__lib__pmtu_state.py`:
  on-classical-pmtu lazily allocates a PmtuSearch in
  state=SEARCH_COMPLETE with current=mtu.
- Integration: existing
  `test__tcp__session__icmp__pmtu.py` /
  `test__icmp6__pmtud.py` should pass unchanged.

**Test-harness snapshot/restore:** new module-level
state `stack.pmtu_state` requires the same commit to
update `TcpTestCase` / `IcmpTestCase` /
`NetworkTestCase` `setUp`/`tearDown` to
snapshot+clear+restore — see `integration_testing.md`
§5.4 and the project memory note. Failure mode if
omitted: passes-alone / fails-in-suite.

**Effort:** ~half-day.

### Phase 3 — TCP adapter + probe emission — SHIPPED 2026-05-14 / 2026-05-28

> **Close-out 2026-05-28.** The operator-facing enable that
> made the active-probing gate REACHABLE in default
> deployments — `tcp.mtu_probing` tristate sysctl +
> `tcp.base_mss` cold-start seed + `_mss_ceiling()`
> helper that keeps the seed alive past the handshake —
> shipped under the close-out plan at
> `docs/refactor/plpmtud_closeout.md` (Phases 1-2,
> commits `0f02938e` + `59466338`). The "Known
> limitation" paragraph in §3c-minimum below was the
> precise gap this close-out plan closed.

**Shipped (3a + 3b):**
- `packages/pytcp/pytcp/protocols/tcp/tcp__plpmtud_adapter.py` — adapter
  class wrapping `PmtuSearch` engine + in-flight probe
  tracking. 12 unit tests at
  `packages/pytcp/pytcp/tests/unit/protocols/tcp/test__tcp__plpmtud_adapter.py`.
- `TcpSession.__init__` constructs a per-session adapter.
- `_apply_pmtu_update` routes classical-PMTUD signals
  through the adapter + mirrors the engine into
  `stack.pmtu_state`.
- snd.una advance hook (in the canonical
  `_process_ack_packet` site) calls
  `adapter.on_snd_una_advance` so probes whose seq is
  acked dispatch as `on_probe_ack`.
- RTO firing hook (in the canonical retransmit-counter
  increment site) calls `adapter.on_rto_timeout` so
  in-flight probes are declared lost; no-op when no
  probes in flight (RFC 4821 §7.5).
- 5 integration tests at
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__plpmtud_wiring.py`.

**3c-minimum (SHIPPED 2026-05-14):**
- Probe-segment emit hook in `TcpSession._transmit_data`:
  when the engine has a candidate AND `probe_payload
  > snd_mss` AND enough application data is buffered to
  fill the probe, the next emitted segment carries
  `probe_payload` bytes (sized at the probe instead of
  the regular MSS).
- `adapter.record_emitted_probe(seq, size)` called after
  successful emit; the snd.una hook (already wired in
  Phase 3b) then detects the probe-ack.
- `PmtuSearch.candidate_mtu` / `TcpPlpmtudAdapter.candidate_mtu`
  peek properties (do not arm PROBE_TIMER) so the
  feasibility check can run before committing.
- 4 integration tests at
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__plpmtud_probe_emit.py`.

**Known limitation (CLOSED 2026-05-28):** the
probe-emit gate `probe_payload > snd_mss` only fires
when `snd_mss` is below the engine's candidate. As
originally shipped (Phase 3c-min) `snd_mss` saturated at
`interface_mtu - overhead` once the handshake clamp
ran, so probe-emit fired only under artificially-
shrunken `snd_mss` conditions (or post-ICMP shrink with
search-band headroom — rare in practice).
**Closed** by `docs/refactor/plpmtud_closeout.md`
Phases 1-2 (2026-05-28): the new `tcp.mtu_probing`
sysctl + `tcp.base_mss` cold-start seed +
`TcpSession._mss_ceiling()` helper consumed by the
four handshake `snd_mss`-clamp sites mean operators
flipping `tcp.mtu_probing=2` get an `snd_mss` seeded
below `interface_mtu - overhead` and the seed survives
the handshake — the gate trips on the first
sufficiently-buffered data send.

**3d Linux-aligned (SHIPPED 2026-05-14):**
- Engine fix: `on_classical_pmtu` now shrinks
  `current_mtu` only (NOT `search_high`). Matches Linux's
  `tcp_mtu_probing` behaviour where ICMP narrows
  `mss_cache` but leaves the PLPMTUD upper bound alone;
  probe-loss is the only way `search_high` narrows. This
  means after an ICMP shrink the engine still has
  headroom to probe upward toward `interface_mtu`.
- Per-session `_plpmtud_probing_enabled` flag (default
  `False` matching Linux `tcp_mtu_probing=0`); the
  probe-emit hook in `_transmit_data` gates on this so
  default behaviour is unchanged.
- snd_mss grow-on-probe-ack hook: after
  `adapter.on_snd_una_advance`, if the engine's
  `current_mtu` increased (probe was acked), `snd_mss`
  grows to `current_mtu - overhead`. Matches Linux's
  `tcp_mtu_probe_success` equivalent. Uses a
  before/after snapshot so the hook only fires on actual
  probe-ack, not on every snd.una advance.
- 4 new integration tests at
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__plpmtud_linux.py`
  covering default-off behavior, search_high invariance,
  probe-ack snd_mss growth, post-ICMP upward probing.

**Deliberate RFC §7.4/§7.5 deviation:** Linux-aligned
PLPMTUD does NOT exempt probes from cwnd (RFC 4821 §7.4
MUST) and does NOT use a separate probe-only RTO timer
(RFC 4821 §7.5). Linux has shipped this pragmatic
deviation for ~15 years without operational issues; the
RFC requirements exist for theoretical worst-case
scenarios (small-cwnd probe starvation) that don't
materially affect real workloads. Documented in the
adherence records as "met (Linux-pragmatic; RFC §7.4 /
§7.5 strict deviation per Linux precedent)".

**Goal:** active PLPMTUD probing for TCP, hooked into
`TcpSession`. End-to-end probe → wire → ACK →
state transition.

**Touches:**
- `packages/pytcp/pytcp/protocols/tcp/tcp__plpmtud_adapter.py` — new
  file. Subclass `PmtuAdapter[Ip4Address | Ip6Address]`,
  bind to a `TcpSession`.
- `packages/pytcp/pytcp/protocols/tcp/tcp__session.py`:
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
   `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__plpmtud.py`
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

### Phase 4 — UDP adapter (manual probe API) — SHIPPED 2026-05-14

**Goal:** expose a per-socket probe API so application
protocols that have their own ACK channel (QUIC-style,
echo-server-style) can drive PLPMTUD.

**Shipped:**
- `packages/pytcp/pytcp/protocols/udp/udp__plpmtud_adapter.py` —
  `UdpPlpmtudAdapter` wrapping `PmtuSearch` with a
  single-outstanding-probe slot. 13 unit tests at
  `packages/pytcp/pytcp/tests/unit/protocols/udp/test__udp__plpmtud_adapter.py`.
- `UdpSocket` gains lazy-allocated `_plpmtud_adapter`,
  `_ensure_plpmtud_adapter` helper, and three public
  methods:
  - `probe_pmtu(size=N)` — emits a zero-padded UDP
    datagram of size N (engine recommendation when size
    is None).
  - `ack_probe()` — application's app-layer ACK confirms
    the in-flight probe.
  - `timeout_probe()` — application's app-layer timer
    expired without an ACK.
- `notify_pmtu` routes the classical PMTU signal through
  the per-socket adapter and mirrors the engine into
  `stack.pmtu_state`.
- 6 integration tests at
  `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__plpmtud.py`
  cover probe-emit (sized datagram on wire), ack → state
  transition, MAX_PROBES timeouts → ERROR + min clamp,
  concurrent-probe rejection, unconnected-socket
  rejection, ack-then-reprobe chain.

**Touches:**
- `packages/pytcp/pytcp/protocols/udp/udp__plpmtud_adapter.py` — new
  file. Subclass `PmtuAdapter[...]`, bind to a
  `UdpSocket`.
- `packages/pytcp/pytcp/socket/udp__socket.py`:
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
   `packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__plpmtud.py`
   - Bind a socket; call `probe_pmtu(1500)`; assert a
     1500-byte UDP datagram is on the wire.
   - Call `ack_probe(1500)`; assert
     `current_pmtu(dst)` advances.
   - Call `timeout_probe()` × PROBE_COUNT; assert
     ERROR state and current_mtu clamp.

**Effort:** ~half-day. Smaller than Phase 3 because
the search engine already exists and there's no FSM
to wire into.

### Phase 5 — Audit ripple — SHIPPED 2026-05-14

**Goal:** reflect the shipped surface in the per-RFC
records.

**Shipped:** RFC 4821 / RFC 8899 adherence records
refreshed; UDP #7 marked SHIPPED in
`docs/refactor/post_udp_session_followups.md`; Phase 5
of the plan doc marked SHIPPED. The Principal Gap row
on both audits is now "TCP TX-path probe-segment emit
(Phase 3c)", with the engine / adapter framework /
classical PMTU coexistence / UDP manual API all locked
in.

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
| pmtu_state leaks across tests | 2 | TcpTestCase / IcmpTestCase snapshot+restore |
| IPv6 MIN_PMTU violated by engine arithmetic | 1 / 5.4 | Hard clamp inside engine; assertion in unit tests |
| Probe sent before SYN ACK → wasted segment | 3 | Adapter gate: only probe in ESTABLISHED |
| UDP manual API races on `probe_pmtu` while one in flight | 4 | API rejects re-probe while engine `is_probing` |

---

## 7. Per-RFC punch list

Direct cross-reference against the audit records, refreshed
when Phase 0 lands.

### RFC 4821 (TCP PLPMTUD)

| Clause                              | Today           | After plan                |
|-------------------------------------|-----------------|---------------------------|
| §3 Probing without ICMP             | not implemented | met (Phase 3)             |
| §5 Probe segment generation         | not implemented | met (Phase 3)             |
| §7.1 PROBE_TIMER                    | not implemented | met (Phase 1 + 3)         |
| §7.4 Probes excluded from cwnd      | not implemented | met (Phase 3, §5.1)       |
| §7.5 Black-hole detection           | not implemented | met (Phase 1, §5.3)       |
| §7.6 Re-probe periodically (raise)  | not implemented | met (Phase 1 raise timer) |

### RFC 8899 (Datagram-transport PLPMTUD)

| Clause                                              | Today           | After plan                                            |
|-----------------------------------------------------|-----------------|-------------------------------------------------------|
| §4 Substrate (per-dest cache)                       | met             | met                                                   |
| §4.6.4 BASE_PMTU floor                              | not enforced    | met (Phase 1)                                         |
| §5 State machine                                    | not implemented | met (Phase 1)                                         |
| §5.1 PROBE_COUNT / PROBE_TIMER constants            | not implemented | met (Phase 1)                                         |
| §5.3 Binary search                                  | not implemented | met (Phase 1, §5.6)                                   |
| §5.4 SEARCH_COMPLETE → raise                        | not implemented | met (Phase 1)                                         |
| §6 Datagram transport API (probe send / ack / loss) | not implemented | met for TCP (Phase 3) + manual UDP (Phase 4)          |
| §7 Black-hole detection                             | not implemented | met (Phase 1)                                         |

### Test matrix

Every met-after-plan row above is locked in by a specific
test method. Names are placeholders pending implementation;
Phase 5 audit refresh greps the actual `path::TestClass::test_method`
strings against this matrix. **Tests are written before the
code they pin**, per `feature_implementation.md` §2 — each
row's test is in the same commit (or the immediately
preceding tests-first commit) as the implementation that
flips it green.

#### Phase 1 — engine unit tests (`packages/pytcp/pytcp/tests/unit/lib/test__lib__plpmtud.py`)

| Clause / failure mode                              | TestClass                       | test_method                                                       |
|----------------------------------------------------|---------------------------------|-------------------------------------------------------------------|
| RFC 8899 §4.6.4 IPv6 floor (≥ 1280)                | TestPmtuSearch__Construction    | test__plpmtud__ip6_floor_min_pmtu_1280                            |
| RFC 8899 §4.6.4 IPv4 floor (≥ 576)                 | TestPmtuSearch__Construction    | test__plpmtud__ip4_floor_min_pmtu_576                             |
| RFC 8899 §5 state=BASE on construction             | TestPmtuSearch__Construction    | test__plpmtud__initial_state_is_base                              |
| RFC 8899 §5 BASE → SEARCHING on ack(base)          | TestPmtuSearch__Base            | test__plpmtud__base__ack_transitions_to_searching                 |
| RFC 8899 §5 SEARCHING → SEARCH_COMPLETE            | TestPmtuSearch__Searching       | test__plpmtud__searching__converges_to_search_complete            |
| RFC 8899 §5 SEARCHING → ERROR on PROBE_COUNT loss  | TestPmtuSearch__Searching       | test__plpmtud__searching__probe_count_losses_enter_error          |
| RFC 8899 §5.1 PROBE_COUNT default = 3              | TestPmtuSearch__Constants       | test__plpmtud__probe_count_default_is_3                           |
| RFC 8899 §5.1 PROBE_TIMER default = 30 s           | TestPmtuSearch__Constants       | test__plpmtud__probe_timer_default_is_30s                         |
| RFC 8899 §5.1 next_probe_size pre-timer = None     | TestPmtuSearch__Timer           | test__plpmtud__next_probe_size_pre_timer_is_none                  |
| RFC 8899 §5.3 binary-search ladder convergence     | TestPmtuSearch__Ladder          | test__plpmtud__binary_search_ladder_convergence                   |
| RFC 8899 §5.3 8-byte granularity convergence       | TestPmtuSearch__Ladder          | test__plpmtud__ladder_converges_at_8_byte_granularity             |
| RFC 8899 §5.4 SEARCH_COMPLETE → raise re-search    | TestPmtuSearch__Raise           | test__plpmtud__raise_timer_re_enters_searching                    |
| RFC 8899 §6 on_probe_ack advances SEARCH_LOW       | TestPmtuSearch__Api             | test__plpmtud__on_probe_ack_advances_search_low                   |
| RFC 8899 §6 on_probe_loss advances probe_count     | TestPmtuSearch__Api             | test__plpmtud__on_probe_loss_advances_probe_count                 |
| RFC 8899 §6 on_classical_pmtu lowers SEARCH_HIGH   | TestPmtuSearch__Api             | test__plpmtud__on_classical_pmtu_shrinks_search_high              |
| RFC 8899 §7 three consecutive losses → ERROR       | TestPmtuSearch__BlackHole       | test__plpmtud__three_consecutive_losses_enter_error               |
| RFC 8899 §7 ERROR → SEARCHING on ICMP recovery     | TestPmtuSearch__BlackHole       | test__plpmtud__error__icmp_signal_recovers_to_searching           |
| §5.3 ICMP signal in SEARCHING shrinks ceiling      | TestPmtuSearch__IcmpInterleave  | test__plpmtud__searching__icmp_signal_shrinks_search_high         |
| §6 IPv6 MIN_PMTU invariant under any input         | TestPmtuSearch__Construction    | test__plpmtud__ip6_min_pmtu_invariant_under_lower_icmp_signal     |
| §6 Transient single-loss does NOT enter ERROR      | TestPmtuSearch__BlackHole       | test__plpmtud__single_loss_does_not_enter_error                   |

#### Phase 2 — registry tests (`packages/pytcp/pytcp/tests/unit/lib/test__lib__pmtu_state.py`)

| Concern                                            | TestClass                       | test_method                                                       |
|----------------------------------------------------|---------------------------------|-------------------------------------------------------------------|
| RFC 8899 §4 lazy allocation on classical PMTU      | TestPmtuStateRegistry           | test__pmtu_state__lazy_allocation_on_classical_pmtu               |
| Backward-compat current_pmtu scalar accessor       | TestPmtuStateRegistry           | test__pmtu_state__current_pmtu_returns_scalar                     |
| Distinct PmtuSearch per destination                | TestPmtuStateRegistry           | test__pmtu_state__per_destination_isolation                       |
| Harness setUp clears stack.pmtu_state              | TestPmtuStateHarness            | test__pmtu_state__harness_setup_clears_registry                   |
| Harness tearDown restores stack.pmtu_state         | TestPmtuStateHarness            | test__pmtu_state__harness_teardown_restores_registry              |

#### Phase 3 — TCP adapter integration tests (`packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__plpmtud.py`)

| Clause / failure mode                              | TestClass                       | test_method                                                       |
|----------------------------------------------------|---------------------------------|-------------------------------------------------------------------|
| RFC 4821 §3 Probing without ICMP                   | TestTcpPlpmtud__ProbeEmit       | test__tcp__plpmtud__established_probe_emitted_after_timer         |
| RFC 4821 §5 Probe-segment size matches candidate   | TestTcpPlpmtud__ProbeEmit       | test__tcp__plpmtud__probe_segment_size_matches_candidate          |
| RFC 4821 §7.1 PROBE_TIMER 30 s cadence             | TestTcpPlpmtud__Timer           | test__tcp__plpmtud__probe_timer_30s_cadence                       |
| RFC 4821 §7.4 Probe excluded from cwnd             | TestTcpPlpmtud__CwndExempt      | test__tcp__plpmtud__probe_does_not_consume_cwnd                   |
| RFC 4821 §7.4 bytes_in_flight skips probe          | TestTcpPlpmtud__CwndExempt      | test__tcp__plpmtud__bytes_in_flight_excludes_probe_segment        |
| RFC 4821 §7.5 Probe-seq at snd.nxt - 1             | TestTcpPlpmtud__ProbeSeq        | test__tcp__plpmtud__probe_seq_is_snd_nxt_minus_one                |
| RFC 4821 §7.5 Probe ACK → engine.on_probe_ack      | TestTcpPlpmtud__LossDetection   | test__tcp__plpmtud__probe_ack_calls_on_probe_ack                  |
| RFC 4821 §7.5 Probe-RTO → engine.on_probe_loss     | TestTcpPlpmtud__LossDetection   | test__tcp__plpmtud__probe_rto_calls_on_probe_loss                 |
| RFC 4821 §7.5 Data-RTO does NOT feed probe-loss    | TestTcpPlpmtud__LossDetection   | test__tcp__plpmtud__data_rto_does_not_feed_probe_loss             |
| RFC 4821 §7.5 Black-hole clamps to min_pmtu        | TestTcpPlpmtud__BlackHole       | test__tcp__plpmtud__black_hole_clamps_to_min_pmtu                 |
| RFC 4821 §7.6 Raise timer re-probes               | TestTcpPlpmtud__Raise           | test__tcp__plpmtud__search_complete_raise_timer_reprobes          |
| §5.3 Classical PMTUD interleave                    | TestTcpPlpmtud__IcmpInterleave  | test__tcp__plpmtud__icmp_packet_too_big_shrinks_during_search     |
| §6 No probe before ESTABLISHED                     | TestTcpPlpmtud__StateGates      | test__tcp__plpmtud__no_probe_before_established                   |
| §6 IPv4 + IPv6 parallel destinations independent   | TestTcpPlpmtud__Multidest       | test__tcp__plpmtud__ip4_ip6_parallel_search_states                |

Plus segment-factory unit tests at `packages/net_proto/net_proto/tests/unit/protocols/tcp/test__tcp__segment_factory__plpmtud.py`:

| Aspect                                             | TestClass                       | test_method                                                       |
|----------------------------------------------------|---------------------------------|-------------------------------------------------------------------|
| build_probe_segment size matches request           | TestTcpSegmentFactory__Probe    | test__tcp__segment_factory__probe_size_matches_request            |
| build_probe_segment zero-padded payload            | TestTcpSegmentFactory__Probe    | test__tcp__segment_factory__probe_payload_is_zero_padded          |
| build_probe_segment seq = snd.nxt - 1              | TestTcpSegmentFactory__Probe    | test__tcp__segment_factory__probe_seq_is_snd_nxt_minus_one        |

#### Phase 4 — UDP adapter integration tests (`packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__plpmtud.py`)

| Clause / failure mode                              | TestClass                       | test_method                                                       |
|----------------------------------------------------|---------------------------------|-------------------------------------------------------------------|
| RFC 8899 §6 probe_pmtu emits sized datagram        | TestUdpPlpmtud__ProbeEmit       | test__udp__plpmtud__probe_pmtu_emits_sized_datagram               |
| RFC 8899 §6 ack_probe advances current_pmtu        | TestUdpPlpmtud__Api             | test__udp__plpmtud__ack_probe_advances_current_pmtu               |
| RFC 8899 §6 timeout_probe × PROBE_COUNT → ERROR    | TestUdpPlpmtud__BlackHole       | test__udp__plpmtud__timeout_probe_count_enters_error              |
| RFC 8899 §7 ERROR → SEARCHING on app recovery      | TestUdpPlpmtud__BlackHole       | test__udp__plpmtud__error__ack_recovers_to_searching              |
| §6 Re-probe while in-flight rejected               | TestUdpPlpmtud__Api             | test__udp__plpmtud__probe_pmtu_rejects_concurrent_probe           |
| §6 Probe in DISABLED state rejected                | TestUdpPlpmtud__StateGates      | test__udp__plpmtud__probe_pmtu_disabled_returns_error             |

Total new test surface: **~46 methods across 6 files**
(20 engine unit, 5 registry unit, 14 TCP integration, 3
segment-factory unit, 6 UDP integration). Phase 5's audit
refresh maps every "met (Phase N)" row above to the
corresponding `path::TestClass::test_method` string in
`docs/rfc/tcp/rfc4821__plpmtud/adherence.md` and
`docs/rfc/tcp/rfc8899__dplpmtud/adherence.md`.

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
