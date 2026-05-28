# TCP Session Decomposition — Plan

**Status:** ✅ COMPLETE. Written 2026-05-27. All five phases
shipped the same day. Supersedes the "fold T2 into the TCP
decomposition" deferral noted in
`no_gil_thread_safety_audit.md` §3 (item T2).

**Progress (2026-05-27):**
- **Phase 1 — `TcpTimerService` + close no-GIL T2: SHIPPED.**
  Commit `b11f5aba`. 9 timer helpers + deadline map + coalesced
  service handle on `session/tcp__session__timers.py` with its
  own `threading.Lock`; `_kick_pump` no longer needs `_lock__fsm`.
- **Phase 2 — `TcpTxEngine`: SHIPPED.** Commit `d1921440`. 11
  methods + ~1100 LOC moved to `session/tcp__session__tx.py`:
  `transmit_packet` + the six `_phase0..5` segment-construction
  helpers, `transmit_data`, `delayed_ack`, `build_sack_blocks`,
  `emit_challenge_ack`. Session keeps thin delegators
  (`_transmit_packet`/`_transmit_data`/etc.). Pure structural
  extraction — no behaviour or lock change.
- **Phase 3 — `TcpAckProcessor`: SHIPPED.** Commit `5492c4d1`.
  6 methods + ~690 LOC moved to `session/tcp__session__ack.py`:
  `process_ack_packet` + the five `_phase1..5` inbound-ACK
  helpers (cum-ACK side effects, F-RTO spurious-RTO detection,
  RTT-sample harvest, loss-detection + recovery-exit, segment
  consume + delayed-ACK postprocess). Session keeps the thin
  `_process_ack_packet` delegator. Pure structural extraction —
  no behaviour or lock change.
- **Phase 4 — `TcpSegmentValidator`: SHIPPED.** Commit
  `6f2ed20b`. 5 methods + ~310 LOC moved to
  `session/tcp__session__validate.py`: `is_seq_in_window`
  (public, called from ICMP RX handlers) +
  `check_segment_acceptability` + `check_paws_and_update_ts_recent`
  + `check_rst_acceptability` + `reinit_for_rfc6191_reuse`.
  Session keeps thin delegators (`is_seq_in_window` public;
  the four underscore methods private). Pure structural
  extraction — no behaviour or lock change.
- **Phase 5 — `TcpRetransmitter`: SHIPPED.** 5 methods +
  ~670 LOC moved to `session/tcp__session__retransmit.py`:
  `retransmit_packet_timeout` (RFC 6298 §5 RTO timeout + RFC
  1122 §4.2.3.5 R2 abort + RFC 5682 §2.1 F-RTO snapshot +
  RFC 9438 §4.6/§4.7 CUBIC loss-event ssthresh + RFC 6582
  §3.2 step 4 recover marker), `retransmit_packet_request`
  (RFC 5681 §3.2 / RFC 6675 §3 fast-retransmit + RFC 3042
  Limited Transmit + PRR entry), `tlp_pto_tick` (RFC 8985
  §7.3 Tail Loss Probe firing), `rack_reorder_tick` (RFC
  8985 §6.2 step 5 reordering timer), `rack_process_ack`
  (RFC 8985 §6.2 step 1-2 / step 5 per-ACK update + loss
  detect). Session keeps thin delegators
  (`_retransmit_packet_timeout` / `_retransmit_packet_request`
  / `_tlp_pto_tick` / `_rack_reorder_tick` /
  `_rack_process_ack`). Pure structural extraction — no
  behaviour or lock change. 11757 tests passing (+3
  collaborator-seam parity tests at
  `test__tcp__session__retransmitter.py`).

**Session line-count progression:** 4423 (start) → 4435
(Phase 1 +12 wiring) → 3380 (Phase 2 -1055) → 2683 (Phase 3
-697) → 2373 (Phase 4 -310) → **1751 (Phase 5 -622, final)**.
Net reduction: 4423 → 1751 = -2672 lines (60% smaller). The
final TcpSession holds the BSD-facade methods (listen /
connect / send / receive / close / shutdown / abort), the
`tcp_fsm` gateway, `_change_state` / `_apply_pmtu_update`,
the RX-buffer / SACK-ingest helpers, the keepalive /
hystart / neighbor helpers, and the wiring that constructs
the five collaborators.

## 1. Why

`packages/pytcp/pytcp/protocols/tcp/tcp__session.py` is a single
**4423-line** class (`TcpSession`, 66 methods). It is the last
god-class in the stack and the home of the one remaining no-GIL
backlog item (**T2** — timer/CC/retransmit state lock discipline).
The two goals are coupled: T2 cannot be fixed cleanly by bolting a
lock onto a 4423-line class whose timer state, FSM dispatch, TX
pump and ACK processing all interleave through one `_lock__fsm`
umbrella. Decomposing first gives each concern a single owner, and
the lock discipline is then designed once, per owner.

## 2. What is already factored out (do NOT re-extract)

The session is already a *composition* of:

- **`state/tcp__state__*.py`** — 15 per-concern state dataclasses
  (`CcState`, `RecvSeqState`, `SendSeqState`, `TxBufferState`,
  `WindowState`, `TimestampsState`, `AdvertiseState`,
  `KeepaliveState`, `FastOpenState`, `PersistState`,
  `RackTlpState`, `RttSampleState`, `ClassicEcnState`,
  `AccEcnState`, `ShutdownState`). These hold the *data*.
- **`fsm/tcp__fsm*.py`** — per-state FSM handlers as free functions
  that take the session and call back into it. The dispatch table
  (`tcp__fsm.py`) is invoked by `TcpSession.tcp_fsm`.
- **Algorithm modules** — `tcp__cubic`, `tcp__newreno`, `tcp__cwnd`,
  `tcp__hystart`, `tcp__rack`, `tcp__sack`, `tcp__rto`,
  `tcp__loss_recovery`, `tcp__fastopen`, `tcp__iss`,
  `tcp__plpmtud_adapter`, `tcp__seq`.

So the decomposition is **not** about the algorithms or the state
data — those are done. It is about the remaining **behavioural
orchestration** still inline on `TcpSession`.

## 3. What still lives on `TcpSession` (the target of this work)

| Bucket | Methods (count) | Approx lines |
|---|---|---|
| BSD-facade syscalls | `listen`/`connect`/`send`/`receive`/`close`/`shutdown`/`abort` (7) | ~200 |
| FSM gateway | `tcp_fsm` (1) | ~160 |
| Timer service | `_arm_timer`/`_timer_expired`/`_timer_armed`/`_cancel_timer`/`_cancel_all_timers`/`_reschedule_service`/`_has_pump_work`/`_pump_tail`/`_kick_pump` (9) | ~150 |
| TX engine | `_transmit_packet` + `_phase0..5` + `_transmit_data` + `_delayed_ack` + `_build_sack_blocks` (11) | ~900 |
| ACK processing | `_process_ack_packet` + `_phase1..5` (6) | ~700 |
| Segment validation | `_check_segment_acceptability`/`_check_paws_and_update_ts_recent`/`_check_rst_acceptability`/`is_seq_in_window`/`_reinit_for_rfc6191_reuse` (5) | ~350 |
| Retransmit / loss | `_retransmit_packet_timeout`/`_retransmit_packet_request` (2) | ~470 |
| RACK + TLP ticks | `_rack_process_ack`/`_rack_reorder_tick`/`_tlp_pto_tick` (3) | ~230 |
| Keep-alive / persist / challenge / hystart / neighbor | (6) | ~250 |
| RX buffer + SACK ingest | `_enqueue_rx_buffer`/`_ingest_sack_info`/`_prune_sack_scoreboard`/`_advance_snd_nxt_past_sacked` (4) | ~200 |
| state-change + pmtu + misc props | `_change_state`/`_apply_pmtu_update` + properties (rest) | ~400 |

## 4. Design approach (the decision needing sign-off)

**Collaborators that take the session as their context** — NOT a
full "Transmission Control Block (TCB)" data migration.

Each extracted concern becomes a class constructed with a back-
reference to the session (e.g. `TcpTxEngine(session)`), reading and
writing the session's state dataclasses (`session._cc`,
`session._snd_seq`, …) the same way the **`fsm/` free functions
already do today**. The session shrinks to: the BSD-facade
methods, the `tcp_fsm` gateway, and the wiring that constructs and
holds the collaborators.

**Why this over a TCB migration:**

- It matches the **existing, accepted pattern** — the `fsm/`
  handlers already take the session and touch its privates; the
  codebase already treats "sibling TCP modules reach into session
  state" as normal. A TCB migration would introduce a *second*
  state-access idiom.
- It is **mechanically reversible per phase** — each extraction
  moves a cohesive method cluster to a new file + leaves a thin
  delegator, with no change to the 15 state dataclasses or the
  46 attributes.
- A TCB migration (gathering 46 attributes into one object and
  rewiring 66 methods + 11 fsm handlers + the socket facade) is a
  single enormous non-reversible churn with no intermediate green
  state — the opposite of the phased discipline.

**Trade-off accepted:** collaborators access `session._private`
state. This is a known smell, but it is the *same* smell the
`fsm/` package already embodies, so the decomposition does not
make the boundary worse — it makes the files smaller and the
ownership explicit, which is the actual goal.

**File layout:** a new `protocols/tcp/session/` subpackage (mirrors
the existing `fsm/` and `state/` subdirs), one module per
collaborator: `tcp__session__timers.py`, `tcp__session__tx.py`,
`tcp__session__ack.py`, `tcp__session__validate.py`,
`tcp__session__retransmit.py`. (Open to flat `tcp__*` naming
instead — noted as a sign-off point.)

## 5. Invariants every phase must hold

1. **The `TcpSocket` facade is frozen.** `listen`/`connect`/`send`/
   `receive`/`close`/`shutdown`/`abort`/`tcp_fsm` + the read-only
   properties + the setsockopt attribute writes
   (`_cc.cc_mode`, `_tcp_nodelay`, `_keepalive.*`, `_tx.buffer`)
   stay exactly as they are. `tcp__socket.py` is not touched.
2. **Tests-first, full suite green after every phase.** The TCP
   integration suite (`tests/integration/protocols/tcp/`) is the
   regression net; it must pass unchanged after each phase (the
   behaviour is identical — only the file a method lives in
   changes). New collaborator-level tests pin the seam.
3. **Each phase is one commit (or a tests+impl pair), reversible.**
4. **No behaviour change inside a phase** except the explicit T2
   lock-discipline change in Phase 1, which is itself tests-first
   (lock-discipline test red→green).
5. **`make lint` (mypy strict) + §7.2 docstring audit clean** per
   commit. Modernise-on-touch applies.

## 6. Phasing (ordered by value × independence)

### Phase 1 — `TcpTimerService` + close T2  ← proposed first
Extract the 9 timer methods + `_timer_deadlines` + `_service_handle`
into `TcpTimerService`, owned by the session. Give the timer-
deadline map its **own lock** (`_lock__timer`) instead of riding the
`_lock__fsm` overload, and **audit + document** whether the CC /
RTO / SACK / RACK state the timer thread touches is already covered
by `_lock__fsm` (the timer callbacks dispatch through
`tcp_fsm(timer=True)` which holds `_lock__fsm` for the whole body —
the deadline-map mutation in `_reschedule_service` from non-FSM
context is the actual exposed gap). This is the most self-contained
cluster and the precondition for the rest. **Closes no-GIL T2.**

### Phase 2 — `TcpTxEngine` ✅ SHIPPED 2026-05-27
Moved `_transmit_packet` + `_phase0..5` + `_transmit_data` +
`_delayed_ack` + `_build_sack_blocks` + `_emit_challenge_ack`
into `TcpTxEngine` at `session/tcp__session__tx.py`. Session
keeps thin delegators (`_transmit_packet`/`_transmit_data`/
`_delayed_ack`/`_build_sack_blocks`/`_emit_challenge_ack`)
so `fsm/` handlers and retransmit-path callers are
untouched; the six `_phase0..5` segment-construction helpers
are engine-internal (no delegators). Pure structural
extraction — no behaviour or lock change.
**Not moved (deferred):** `_keepalive_arm_idle` /
`_keepalive_tick` (the keepalive timer-handler family —
arguably its own collaborator, not strictly "TX engine"; can
be folded later if the lines warrant it). Persist-probe
logic was already inline in `_transmit_data` (zero-window
branch); it moves with the engine.
Pinned by `test__tcp__session__tx_engine.py` (4 seam tests):
session owns a `TcpTxEngine` reachable as `session._tx_engine`,
back-reference correct, delegators emit the expected wire
effect, the §5961 §3 rate-limit gate fires through the engine.

### Phase 3 — `TcpAckProcessor` ✅ SHIPPED 2026-05-27
Moved `_process_ack_packet` + `_phase1..5` into `TcpAckProcessor`
at `session/tcp__session__ack.py`. Session keeps the thin
`_process_ack_packet` delegator so `fsm/` handlers continue to
call it unchanged; the five `_phase1..5` helpers are
engine-internal (no delegators). Pure structural extraction —
no behaviour or lock change. The five phases comprise: Phase 1
(cum-ACK side effects: SND.UNA advance, RFC 9406 round-boundary
rotate, RFC 6582 recover_seq decay, RFC 6937 PRR delivered
accumulation, RFC 9438 / 5681 / 6928 cwnd growth, RFC 6298
retransmit-timer manage, RFC 8985 §7.2/§7.4 TLP loss-detect /
repair / cancel); Phase 2 (RFC 5682 F-RTO spurious-RTO
detection); Phase 3 (RFC 6298 §4 + RFC 7323 §4 RTT-sample
harvest + HyStart++ fold); Phase 4 (RACK fold + recovery exit);
Phase 5 (segment consume + delayed-ACK + ooo-queue drain).
Pinned by `test__tcp__session__ack_processor.py` (3 seam tests):
session owns a `TcpAckProcessor` reachable as
`session._ack_processor`, back-reference correct, an inbound
peer data segment routes through the delegator into the engine
and advances RCV.NXT (Phase 5 consume), and the delegator
invokes the engine's `process_ack_packet` with the same packet
object (no shadow path).

### Phase 4 — `TcpSegmentValidator` ✅ SHIPPED 2026-05-27
Moved `is_seq_in_window` (public, RFC 5927 §4 — called from
ICMP4/ICMP6 RX handlers), `_check_segment_acceptability`
(RFC 9293 §3.10.7.4 step 1), `_check_paws_and_update_ts_recent`
(RFC 7323 §5 PAWS + §4.3 _ts_recent refresh),
`_check_rst_acceptability` (RFC 9293 §3.10.7.4 / RFC 5961 §3.2
three-way RST), and `_reinit_for_rfc6191_reuse` (RFC 6191 §3
TIME-WAIT 4-tuple reuse re-init) into `TcpSegmentValidator`
at `session/tcp__session__validate.py`. Session keeps thin
delegators (`is_seq_in_window` public; the four underscore
methods private). Pure structural extraction — no behaviour
or lock change. Pinned by `test__tcp__session__validator.py`
(3 seam tests): session owns a `TcpSegmentValidator` reachable
as `session._validator`, back-reference correct, the public
`is_seq_in_window` delegator and the engine's helper agree on
both in-window and out-of-window seq values, and the
`_check_segment_acceptability` delegator invokes the engine's
`check_segment_acceptability` with the same packet object (no
shadow path).

### Phase 5 — `TcpRetransmitter` ✅ SHIPPED 2026-05-27
Moved `_retransmit_packet_timeout`, `_retransmit_packet_request`,
`_tlp_pto_tick`, `_rack_reorder_tick`, `_rack_process_ack` into
`TcpRetransmitter` at `session/tcp__session__retransmit.py`.
Session keeps the thin delegators for all five so the seven
fsm/ handlers and the Phase-3 ACK processor's `_rack_process_ack`
call site are untouched. The function-local
`from pytcp.protocols.tcp.tcp__rack import INFINITE_TS` shadow
inside `_retransmit_packet_timeout` is promoted to a module-top
import on the engine (modernise-on-touch). Pure structural
extraction — no behaviour or lock change. Pinned by
`test__tcp__session__retransmitter.py` (3 seam tests): session
owns a `TcpRetransmitter` reachable as `session._retransmitter`,
back-reference correct, the `_retransmit_packet_timeout` and
`_rack_process_ack` delegators invoke the engine's methods
verbatim (no shadow path).

After Phase 5 the session is ~the facade + `tcp_fsm` gateway +
`_change_state`/`_apply_pmtu_update` + RX-buffer/SACK-ingest +
collaborator wiring — on the order of 800–1000 lines.

## 7. Non-goals

- No change to the wire behaviour, the FSM transition table, or the
  algorithm modules.
- No TCB data migration (see §4).
- Not touching `tcp__socket.py` (the facade).
- No new sysctls / no RFC-conformance changes (this is structural).

## 8. Risks

- **The phase methods mutate shared state via `self._*`.** Moving
  them to a collaborator means the collaborator writes
  `session._cc` etc. The risk is a missed attribute or an altered
  call order changing behaviour. Mitigation: the integration suite
  is exhaustive (FSM transitions, retransmit, SACK, RACK, ECN,
  fast-open, keep-alive, PAWS) and runs green after each phase;
  any behavioural drift surfaces immediately.
- **`tcp_fsm` holds `_lock__fsm` across the whole dispatch**, and
  collaborator methods are called from within it. Re-entrancy and
  lock-ordering must be preserved exactly (Phase 1 documents the
  ordering: FSM → TX-buffer, and adds timer as a sibling).
- **Context/back-reference cycles** (session ↔ collaborator) — fine
  in Python (GC handles cycles), matches the `fsm/` pattern.

## 9. Sign-off points

1. **Approach:** collaborators-take-session (§4) vs. a TCB data
   migration. Plan assumes the former.
2. **Layout:** `session/` subpackage vs. flat `tcp__*` modules.
3. **First phase:** Phase 1 (`TcpTimerService`, carries T2) — or a
   different starting point.
