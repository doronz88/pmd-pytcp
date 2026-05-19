# TCP Timer-Client Migration — Coalesced Deadline-Driven Service Tick

| Field             | Value                                                                                                                                                                                 |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Status            | **Phases 0-3 SHIPPED 2026-05-15** (Phase 0 0e0fe396 / 22b46c7c, Phase 1 5a0161f8, Phase 2 719afd7c, Phase 3 9b22bcca). **Phase 4 attempt #1 ROLLED BACK** (post-mortem `2743f936`); **REDESIGNED — §5.6 `tx_pump`. Phase 4a SHIPPED** (`8b24ad2c`); **Phase 4b attempt #1 ROLLED BACK** (392→3, narrow residual; §7 Phase-4b post-mortem); **redesigned — §5.7 `_kick_pump`. Phase 4 SHIPPED** via §5.6+§5.7: Phase 4c-a `75f1f679` (non-tcp_fsm-mutator pins), Phase 4c-b `8435a321` (trigger flip: coalesced `_service_handle` + `tx_pump` pace-while-work + 1 ms delay floor + `_kick_pump`; TCP integration byte-identical 489 OK, full suite 11027/0). **Phase 5 SHIPPED** (`d6a55490` — `_tcp_fsm_handle` periodic-handle + its no-op CLOSED-teardown deleted; behaviour-neutral). **Phase 6 SHIPPED** (`1962d17f` — named-flag shim `register_timer`/`is_expired`/`unregister_timers_with_prefix`/`pending_timers`/`_legacy_named_flags`/`_PRIO__NAMED_FLAG` deleted from `Timer`+`FakeTimer`; shim tests + vestigial SimpleNamespace fixture attrs + stale shim prose removed; lint clean, full suite 11012/0/4, §7.2 audit clean). **Phase 6 deferred tidy LANDED** (`4f434c8f` — comment/docstring-only: the remaining FSM-comment + test-prose mentions of the dead `is_expired`/`stack.timer._timers` API reworded to the live `_timer_expired`/`_timer_armed`/`_timer_deadlines` helpers; also fixed a pre-existing §7.2 inline-RFC violation surfaced on a touched file; behaviour-neutral, 11012/0/4). **MIGRATION COMPLETE — the TCP FSM is fully event-driven; no polling tick, no named-flag shim; zero stale shim-API references outside the two deliberate `was removed` archaeology notes in `timer.py`/`fake_timer.py`.** |
| Plan author       | Timer-rewrite follow-up (the deliberately-deferred §12 track from `docs/refactor/timer_rewrite_plan.md`)                                                                               |
| Source motivation | The heap-based `Timer` is event-driven, but every TCP timer still uses the polling `register_timer` / `is_expired` named-flag shim, driven by a 1 ms `call_periodic(tcp_fsm, timer=True)` tick that exists only to scan flags |
| Target branch     | `PyTCP_3_0__pre_release`                                                                                                                                                              |
| Touch points      | `packages/pytcp/pytcp/protocols/tcp/tcp__session.py` (~30 call sites), `packages/pytcp/pytcp/protocols/tcp/fsm/tcp__fsm__*.py` (7 state timer handlers + the TIME_WAIT poll), `packages/pytcp/pytcp/tests/lib/fake_timer.py` (no API change; behaviour-parity only), TCP integration suite |
| Risk              | **High** — wide surface, FSM thread/ordering invariants are implicit in the single locked tick, `is_expired` conflation is load-bearing at several sites, the integration suite pins exact wire timing |
| Phases            | 0 (this plan) → 1 (deadline-map helper, still 1 ms-driven, zero behaviour change) → 2 (migrate independent timers' *checks* to the helper) → 3 (migrate the coupled retransmit/rack/tlp cluster) → 4 (flip the trigger: 1 ms periodic → coalesced `call_later`) → 5 (delete the periodic, teardown via handle registry) → 6 (docs + close-out) |

This document is the implementation plan for migrating the TCP
session's timer clients off the polling `register_timer` /
`is_expired` / `unregister_timers_with_prefix` named-flag shim
and onto the event-driven `pytcp.runtime.timer` core, while
**preserving the exact wire-observable behaviour** the
integration suite pins.

It is intentionally self-contained: a fresh-context agent
should be able to execute it end-to-end without re-deriving
design choices. See §13 for the resumption prompt.

The companion document `docs/refactor/timer_rewrite_plan.md`
(SHIPPED 2026-05-15) delivered the heap-based scheduler and
explicitly deferred this client migration to "its own plan"
(that doc's §12). This is that plan.

---

## 1. Goal

Replace the per-millisecond *poll* of named-timer flags with
an event-driven, coalesced, per-session **service tick**:

1. **No 1 ms polling.** The session arms ONE timer handle for
   the soonest of its logical-timer deadlines. When it fires,
   the existing ordered service sequence runs once, then the
   handle is re-armed for the next-soonest deadline. Idle
   sessions consume zero timer wakeups.
2. **Ordering preserved.** The per-state handler bodies (the
   fixed `_retransmit_packet_timeout → _transmit_data →
   _delayed_ack → _keepalive_tick → _rack_reorder_tick →
   _tlp_pto_tick` sequence) are unchanged. Only the *trigger*
   and the *expiry check* change.
3. **De-conflated timer state.** `is_expired(name)` (which
   collapses "never armed" with "fired") is replaced by an
   explicit per-session deadline map: `None` = not armed,
   `now < deadline` = pending, `now >= deadline` = fired.
4. **Same thread, same lock.** The service callback runs on
   the Timer worker thread (exactly where `tcp_fsm(timer=True)`
   runs today) and takes `_lock__fsm` once, exactly as the
   current periodic tick does. No new thread, no new lock.
5. **Teardown via handle, not prefix sweep.**
   `unregister_timers_with_prefix(f"{self}-")` becomes
   `stack.timer.cancel(self._service_handle)` plus clearing
   the deadline map.

## 2. Non-goals

- **No change to TCP wire behaviour.** Every RTO, persist,
  keep-alive, TIME_WAIT, delayed-ACK, TLP, RACK, challenge-ACK
  fire time and fire count is preserved. The integration suite
  proves this at every phase.
- **No change to the `pytcp.runtime.timer` public API.**
  `call_later` / `call_periodic` / `cancel` / `now_ms` are
  used as-is. The legacy named-flag shim
  (`register_timer` / `is_expired` /
  `unregister_timers_with_prefix`) is *removed from the TCP
  consumers* by this plan and then becomes dead; deleting the
  shim itself from `Timer` / `FakeTimer` is a trivial Phase-6
  close-out (no other consumer exists — verified §4.6).
- **No FSM state-machine redesign.** State handlers keep
  their structure; the per-state timer handler keeps calling
  the same tick methods in the same order.
- **No coalescing across sessions.** Each `TcpSession` owns
  one service handle. Cross-session timer-wheel optimisation
  is a separate, much later concern (out of scope, §12).

## 3. Current state — issues this plan addresses

1. **Polling on top of an event-driven core.** The Timer is
   event-driven, but `tcp_fsm(timer=True)` is a
   `call_periodic(1, …)` (see `tcp__session.py:489`) whose
   *only* timer-related job is to call the per-state handler
   which scans `is_expired(f"{self}-X")` for up to 6 logical
   timers every millisecond. Every ESTABLISHED session burns
   1000 service calls/sec almost all of which early-return.
2. **`is_expired` conflates "never armed" with "fired".**
   Documented at `tcp__session.py:2705-2712` (retransmit),
   `tcp__state__rack_tlp.py:152`, `tcp__state__keepalive.py:76`.
   Consumers bolt on a second guard (`snd_una != snd_max`,
   etc.) to disambiguate. Some of those second guards are
   *also* genuine RFC conditions, so they cannot be blindly
   deleted — each must be audited (§5.5).
3. **Ordering invariants are implicit.** Every per-state
   timer handler runs the tick methods in a fixed order
   (retransmit before transmit-data; RACK reorder before TLP
   PTO). N independent `call_later` callbacks would interleave
   by `(deadline, seq)` and silently break invariants such as
   "a retransmit re-fills the pipe before `_transmit_data`
   recomputes what to send this tick". The single locked tick
   provides this ordering for free today.
4. **State-scoped servicing is implicit.** A logical timer is
   only serviced in the states whose `fsm__<state>__timer`
   handler calls its tick method (e.g. TLP/RACK/keepalive only
   in ESTABLISHED; retransmit in SYN_SENT/SYN_RCVD/ESTABLISHED/
   CLOSE_WAIT/FIN_WAIT_1/LAST_ACK; time_wait only in
   TIME_WAIT — see §4.3). A raw `call_later` callback fires
   regardless of the session's current state and could act
   after a transition that should have suppressed it.
5. **Teardown is a string-prefix sweep.**
   `unregister_timers_with_prefix(f"{self}-")` at
   `tcp__session.py:940` (CLOSED) and `:1970`, plus the
   selective `f"{self}-retransmit"` / `f"{self}-tlp"` sweeps
   at `:3693` / `:3700`. Stringly-typed and O(all timers).
6. **`_transmit_data()` is mis-grouped with timers.** It is
   called in every per-state timer handler *but it is not a
   timeout* — it is the TX self-clock (also invoked on
   packet-RX and syscall paths: `tcp__session.py:3067`,
   `:3239`). Naively "deleting the 1 ms periodic" would stop
   the self-clock. Resolving how `_transmit_data` is driven
   post-migration is the central design question (§5.4).

## 4. Current callers — exhaustive inventory

Grepped 2026-05-15 against `PyTCP_3_0__pre_release`.

### 4.1 Logical timers (8)

| Logical timer        | Name expression                    | Armed by (register_timer)                                                    | Polled by (is_expired)                          | Action on expiry |
|----------------------|------------------------------------|------------------------------------------------------------------------------|-------------------------------------------------|------------------|
| retransmit (RTO)     | `f"{self}-retransmit"`             | `tcp__session.py:1623`, `:2830`, `:3373`, `:3703`                            | `:1622`, `:2714`                                | `_retransmit_packet_timeout()` |
| time_wait (2·MSL)    | `f"{session}-time_wait"`          | `fsm__fin_wait_1:137`, `fsm__fin_wait_2:113`, `fsm__closing:100`, `fsm__time_wait:155` | `fsm__time_wait:58`                  | `_change_state(CLOSED)` |
| persist (ZWP)        | `f"{self}-persist"` (persist_timer) | `:2651`, `:2668`                                                            | `:2656`                                         | persist probe in `_transmit_data` path |
| delayed_ack          | `f"{self}-delayed_ack"`           | `:1609`, `:2692`, `:4039`                                                   | `:2685`                                         | `_delayed_ack()` emits the held ACK |
| challenge_ack (rate) | `f"{self}-challenge_ack"`         | `:2137`                                                                     | `:2130`                                         | pure rate-limit gate (no action; gate only) |
| keepalive            | `f"{self}-keepalive"`             | `:2155`, `:2217`                                                            | `:2191`                                         | `_keepalive_tick()` probe / abort |
| tlp (PTO)            | `f"{self}-tlp"`                   | `:1671`, `:3249`                                                            | `:3194`                                         | `_tlp_pto_tick()` tail-loss probe |
| rack (reorder)       | `f"{self}-rack"` / `f"{session}-rack"` | `:3281`, `:3373` (region)                                              | `:3264`                                         | `_rack_reorder_tick()` re-runs loss detection |

(Line numbers are indicative anchors as of the grep date;
re-grep before editing — the migration itself shifts them.)

### 4.2 `unregister_timers_with_prefix` (4 sites)

| Site | Purpose | Replacement |
|------|---------|-------------|
| `tcp__session.py:940`  | CLOSED transition — cancel ALL session timers | `self._cancel_all_timers()` (§5.3) |
| `tcp__session.py:1970` | secondary teardown path — cancel ALL | `self._cancel_all_timers()` |
| `tcp__session.py:3693` | cum-ACK drains in-flight — cancel `-retransmit` | `self._cancel_timer("retransmit")` |
| `tcp__session.py:3700` | same path — cancel `-tlp` | `self._cancel_timer("tlp")` |

### 4.3 State-scope matrix (which handler services which timer)

From `FSM_TIMER_HANDLERS` (`tcp__fsm.py:156`) and the
per-state handler bodies:

| State        | tick sequence in `fsm__<state>__timer`                                                                 |
|--------------|--------------------------------------------------------------------------------------------------------|
| SYN_SENT     | `_retransmit_packet_timeout` → `_transmit_data`                                                        |
| SYN_RCVD     | `_retransmit_packet_timeout` → `_transmit_data`                                                        |
| ESTABLISHED  | `_retransmit_packet_timeout` → `_transmit_data` → `_delayed_ack` → `_keepalive_tick` → `_rack_reorder_tick` → `_tlp_pto_tick` |
| CLOSE_WAIT   | `_retransmit_packet_timeout` → `_transmit_data` → `_delayed_ack`                                        |
| FIN_WAIT_1   | `_retransmit_packet_timeout` → `_transmit_data`                                                        |
| LAST_ACK     | `_retransmit_packet_timeout` → `_transmit_data`                                                        |
| TIME_WAIT    | `if is_expired(f"{session}-time_wait"): _change_state(CLOSED)`                                          |
| FIN_WAIT_2 / CLOSING | no tick-method calls (state-change only, driven elsewhere)                                      |
| CLOSED / LISTEN / SYN_RCVD(pre) | absent from `FSM_TIMER_HANDLERS` → no-op                                            |

**This table is the authoritative ordering + scoping
contract the migration must preserve.**

### 4.4 `_transmit_data()` drivers (the self-clock)

`_transmit_data()` is invoked from: every per-state timer
handler (6 states, §4.3), and the packet/syscall paths
`tcp__session.py:3067` and `:3239`. It is **periodic work,
not a timeout** — see §5.4 for how it is driven post-migration.

### 4.5 `tcp_fsm` entry / lock / thread

`tcp__session.py:4095` `def tcp_fsm(...)`; takes
`self._lock__fsm` (RLock, `:470`) at `:4106`; dispatches
`timer` → `tcp_fsm_dispatch_timer(self)` (`:4244`) →
`FSM_TIMER_HANDLERS[state](session)`. Invoked every 1 ms by
`self._tcp_fsm_handle = stack.timer.call_periodic(1, self.tcp_fsm, timer=True)` (`:489`), i.e. **on the Timer worker
thread**. Cancelled on CLOSED via
`stack.timer.cancel(self._tcp_fsm_handle)` (`:951`).

### 4.6 No non-TCP consumer of the named-flag shim

Grepped: `register_timer` / `is_expired` /
`unregister_timers_with_prefix` appeared only under
`packages/pytcp/pytcp/protocols/tcp/`. The shim went dead at Phase 5 and
**Phase 6 (SHIPPED) deleted it from `Timer` / `FakeTimer`
outright** along with `pending_timers` /
`_legacy_named_flags` / `_PRIO__NAMED_FLAG`.

## 5. Target architecture

### 5.1 Per-session deadline map + helper trio

Add to `TcpSession`:

```python
# Absolute monotonic-ms deadlines for the session's logical
# timers. None == not armed. Keyed by the bare logical name
# ("retransmit", "time_wait", "persist", "delayed_ack",
# "challenge_ack", "keepalive", "tlp", "rack").
self._timer_deadlines: dict[str, int] = {}

# The single coalesced service handle (Phase 4+). Until then
# this is None and the legacy 1 ms periodic still drives.
self._service_handle: TimerHandle | None = None
```

Helper trio (replaces register_timer / is_expired /
unregister_timers_with_prefix at the call sites):

```python
def _arm_timer(self, name: str, delay_ms: int, /) -> None:
    """Arm/re-arm a logical timer 'delay_ms' from now."""
    self._timer_deadlines[name] = stack.timer.now_ms + delay_ms
    self._reschedule_service()          # no-op until Phase 4

def _timer_expired(self, name: str, /) -> bool:
    """
    True iff the logical timer has fired. NOT armed -> False
    (this is the de-conflation: 'never armed' is no longer
    collapsed with 'fired'; callers that relied on the old
    True-when-unarmed behaviour are audited in §5.5).
    """
    deadline = self._timer_deadlines.get(name)
    return deadline is not None and stack.timer.now_ms >= deadline

def _timer_armed(self, name: str, /) -> bool:
    """True iff armed and not yet fired (the 'is it running?' query)."""
    deadline = self._timer_deadlines.get(name)
    return deadline is not None and stack.timer.now_ms < deadline

def _cancel_timer(self, name: str, /) -> None:
    self._timer_deadlines.pop(name, None)
    self._reschedule_service()          # no-op until Phase 4

def _cancel_all_timers(self) -> None:
    self._timer_deadlines.clear()
    if self._service_handle is not None:
        stack.timer.cancel(self._service_handle)
        self._service_handle = None
```

> **Semantics note.** The old `is_expired(name)` returned
> `True` when *unarmed*. The new split is deliberate:
> `_timer_expired` (fired) vs `_timer_armed` (running). Every
> migrated call site is classified in §5.5 as needing one or
> the other; the second-guards that existed only to undo the
> conflation are removed, the ones that are real RFC
> conditions are kept.

### 5.2 The coalesced service tick (Phase 4 target)

`_reschedule_service()` keeps exactly one `call_later`
outstanding, at the soonest pending deadline that the
*current state* would actually service:

```python
def _reschedule_service(self) -> None:
    if self._service_handle is not None:
        stack.timer.cancel(self._service_handle)
        self._service_handle = None
    relevant = _SERVICED_TIMERS_BY_STATE.get(self._state, frozenset())
    pending = [d for n, d in self._timer_deadlines.items() if n in relevant]
    if not pending:
        return                          # nothing armed in this state
    now = stack.timer.now_ms
    delay = max(0, min(pending) - now)
    self._service_handle = stack.timer.call_later(delay, self.tcp_fsm, timer=True)
```

`_SERVICED_TIMERS_BY_STATE` is the §4.3 scope matrix made
explicit (data, not control flow). `tcp_fsm(timer=True)` is
unchanged — it still takes `_lock__fsm` and calls the same
per-state handler, which still runs the same ordered tick
sequence. The *only* change inside the tick is that each
tick method now consults `_timer_expired(...)` instead of
`stack.timer.is_expired(f"{self}-…")`, and after the
sequence runs the handler ends by re-arming the service
handle (one call to `_reschedule_service()` at the tail of
`tcp_fsm`, after dispatch, while still under the lock).

Because the per-state handler runs the *whole* ordered
sequence on every service event (just as it does on every
1 ms tick today), and each tick method early-returns unless
its own `_timer_expired` is true, **the observable behaviour
is identical to the 1 ms poll** — only the wakeup cadence
changes (soonest-deadline instead of every ms).

`_transmit_data()` self-clock: see §5.4.

### 5.3 Migration ordering (low-risk first)

1. **time_wait** — single state (TIME_WAIT), single arm
   sites, single poll, single action (`_change_state(CLOSED)`),
   zero ordering coupling, no `_transmit_data` interaction.
   The canonical pilot.
2. **challenge_ack** — pure rate-limit gate, no action, not
   in any per-state handler sequence (queried inline on the
   RST/SYN challenge path). Trivial.
3. **keepalive**, **persist**, **delayed_ack** — independent
   of the retransmit/rack/tlp ordering cluster; each has a
   clear single action.
4. **retransmit + tlp + rack** — the coupled cluster. Migrate
   together, last, with the §4.3 ordering matrix as the pinned
   contract and the integration suite as the gate.

### 5.4 `_transmit_data()` — the self-clock decision

`_transmit_data()` must keep being driven. It is **not** a
timeout; it drains the TX buffer subject to cwnd/rwnd. It is
already event-driven on the dominant paths (ACK arrival →
`tcp__session.py:3067`; syscall send → `:3239`; and it runs
inside every serviced timer tick). The residual cases where
*only* the periodic currently re-drives it:

- cwnd opened by an ACK that itself triggers `_transmit_data`
  (already covered — ACK path calls it).
- application `send()` while cwnd-limited, then cwnd opens
  with no further inbound segment (rare; covered by the
  retransmit/persist timers which *are* armed in that state).

> **⚠ REVERSED by §5.6 (Phase-4 attempt #1 post-mortem).**
> The decision below was wrong — `_transmit_data` /
> FSM progression DOES need a dedicated pump (the `tx_pump`
> one-shot, §5.6), because the 1 ms periodic was a
> load-bearing FSM pump, not just a timer-service poll. The
> original reasoning is retained verbatim for the audit
> trail; read §5.6 for the adopted design.

**Decision (SUPERSEDED): do not give `_transmit_data` its own timer.**
Keep it in the per-state service sequence (unchanged). The
service handle is armed whenever ANY logical timer is armed;
in every state where the session has un-ACKed data or a
buffered write there is always an armed retransmit or persist
timer, so `_transmit_data` is serviced at least as often as
it can make progress. The one explicit safety net: when
`_transmit_data` leaves bytes buffered that it *could* send
once cwnd/rwnd allows but no timer is armed (provably
reachable only via the persist path), the persist timer is
armed by the existing logic — verify via the §6 persist
integration tests. **Phase 3 includes an explicit
investigation task that enumerates, with an integration
test per case, every state in which the TX buffer is
non-empty but no logical timer is armed; if any genuine gap
exists, arm a short "tx-drain" logical timer for that case
rather than resurrecting the 1 ms periodic.**

> **SHIPPED (Phase 3):** the gap audit
> (`test__tcp__session__timer_ordering.py::
> TestTcpTransmitDataGapAudit`) checked in-flight (`retransmit`
> armed) / zero-window (`persist` armed) / CLOSE_WAIT.
>
> **⚠ SUPERSEDED by the Phase-4 attempt #1 post-mortem (see
> §7 Phase 4).** The Phase-3 audit was **incomplete**: it
> only covered states where data was already in flight or
> buffered-under-zero-window. It MISSED the *just-transitioned,
> `_transmit_data` has work, nothing armed yet* pump case —
> archetype: active-open CONNECT does only
> `_change_state(SYN_SENT)`; the SYN is emitted by
> `fsm__syn_sent__timer → _transmit_data()`, which in the old
> model only ran because the 1 ms periodic pumped it. **A
> genuine gap therefore EXISTS** and the "Decision: do not
> give `_transmit_data` its own timer" above does NOT hold.
> The §5.4/§9 tx-drain/FSM-pump fallback is REQUIRED for any
> Phase-4 redesign.

### 5.5 Per-site `is_expired` audit (de-conflation)

Each of the 8 `is_expired` reads is classified:

| Site | Old form | New form | Second-guard disposition |
|------|----------|----------|--------------------------|
| `:1622` retransmit (arm-gate "not already running") | `is_expired(...)` used as "no timer running" | `not self._timer_armed("retransmit")` | n/a (was using the unarmed=True conflation as the signal — now explicit) |
| `:2714` retransmit (fire) | `if not is_expired: return` then `if snd_una==snd_max: return` | `if not self._timer_expired("retransmit"): return` | **keep** `snd_una==snd_max` guard — it is the genuine RFC 6298 §5 "nothing in flight" condition, not just disambiguation |
| `fsm__time_wait:58` | `if is_expired(time_wait): _change_state(CLOSED)` | `if self._timer_expired("time_wait"): …` | none |
| `:2656` persist | `elif is_expired(persist)` | `elif self._timer_expired("persist")` | audit surrounding `_persist.active` flag — keep |
| `:2685` delayed_ack | `if is_expired(delayed_ack):` | `if not self._timer_armed("delayed_ack"):` | **corrected in Phase 1**: the original audit said `_timer_expired`/none; the integration oracle (`test__close_passive__peer_fin_first_walks_through_close_wait_last_ack_closed`) proved the unarmed→flush behaviour is load-bearing — a tick with no delayed-ACK window in progress must flush the held ACK immediately, so this is `not _timer_armed` (fired OR never-armed), not `_timer_expired` |
| `:2130` challenge_ack | `if not is_expired(rate):` (rate-limit gate) | `if self._timer_armed("challenge_ack"):` (inverted: armed&unfired ⇒ within rate-limit window ⇒ suppress) | re-derive truth table carefully (§6 test) |
| `:2191` keepalive | `if not is_expired(keepalive): return` | `if not self._timer_expired("keepalive"): return` | keep idle/probe state guards |
| `:3194` tlp | `if not is_expired(tlp): return` | `if not self._timer_expired("tlp"): return` | keep tail-state guards |
| `:3264` rack | `if not is_expired(rack): return` | `if not self._timer_expired("rack"): return` | keep pending-candidate guard |

The `challenge_ack` inversion (`:2130`) is the single
trickiest semantic flip and gets its own dedicated unit +
integration test (§6) written **first**, asserting the rate
window suppresses exactly as before.

### 5.6 Phase-4 redesign — the `tx_pump` one-shot (attempt #2)

Attempt #1 (coalesced-only, §5.2) was rolled back: the 1 ms
periodic was a load-bearing **FSM pump**, not just a
timer-service poll (see the §7 Phase-4 post-mortem). This
section is the corrected design.

**The two jobs the 1 ms periodic did.** (1) *Timer
servicing* — poll logical-timer deadlines and act when due.
The coalesced `_service_handle` (§5.2) handles this
correctly and is **kept**. (2) *FSM pump / self-clock* —
run `_transmit_data()` / FSM progression promptly after an
event that carries no packet and arms no logical timer.
Canonical case: active-open CONNECT does only
`_change_state(SYN_SENT)`; the SYN is emitted by the *next*
`fsm__syn_sent__timer → _transmit_data()`. Attempt #1
dropped job (2) entirely.

**The completeness claim.** Every FSM progression that the
old periodic drove originates from exactly one of:
a packet (already runs `tcp_fsm(packet)` — covered), a
logical timer (covered by `_service_handle`), **a state
entry**, or **a syscall**. There is no progression path
that is none of these — within a stable state, further
`_transmit_data` runs are ACK-clocked (packet) or
timer-driven (persist/retransmit, both logical). So the
*complete* pump trigger set is **{any `_change_state`
during a dispatch, any syscall dispatch}** — small,
enumerable, and detectable at one place.

**Mechanism — `tx_pump`, a one-shot logical timer.** Add a
reserved logical-timer name `"tx_pump"`, in
`_SERVICED_TIMERS_BY_STATE` for **every** state
(over-inclusion is harmless per §5.5's rule; FIN_WAIT_2 /
CLOSING have empty handlers so a `tx_pump` fire there is a
harmless no-op). It is purely a wake mechanism — **no tick
method ever reads `_timer_expired("tx_pump")`**. The
`tcp_fsm` tail (all dispatch kinds, under `_lock__fsm`)
runs, in order:

1. Snapshot `state_at_entry = self._state` at the top of
   `tcp_fsm` (before dispatch).
2. After dispatch: `self._cancel_timer("tx_pump")` —
   **consume** it (it has done its wake job for this
   dispatch; this is what prevents the busy-loop a naive
   past-deadline re-arm would cause).
3. `pump = (self._state is not state_at_entry) or
   (syscall is not None)` — re-pump iff this dispatch
   changed state or was a syscall.
4. `self._reschedule_service()` (logical timers, unchanged
   from §5.2).
5. `if pump: self._arm_timer("tx_pump", 0)` then
   `self._reschedule_service()` again so the 0-deadline
   `tx_pump` is folded into `_service_handle` and fires on
   the very next worker/`advance` step.

**Why it terminates (no busy-loop).** `tx_pump` is
re-armed only when the just-finished dispatch *changed
state* or *was a syscall*. A timer dispatch that changes
nothing does **not** re-arm it, so a quiescent state stops
pumping. A chain of state changes is bounded by the FSM
(each transition emits its segment and stabilises into a
state whose handler makes no further `_change_state`
without a new external stimulus), so the chain
terminates — e.g. CONNECT→SYN_SENT (stable: retransmit
armed) ; peer-ACK→ESTABLISHED (stable) ;
close→…→FIN_WAIT_1 (stable: retransmit armed).

**Why zero-idle-CPU is preserved.** A fully quiescent
session (ESTABLISHED, no data, not closing, no logical
timer armed) has no state change and no syscall → `tx_pump`
not armed, no logical timer armed → `_reschedule_service`
arms nothing → **no `_service_handle`, zero wakeups**. The
original Phase-1 goal still holds for the common idle case.

**Why it is byte-identical where the pump matters.** A
0-delay `tx_pump` makes the per-state timer handler run on
the immediately-next `advance`/worker step — exactly the
~1 ms latency the old periodic gave the pump. The handler
body is unchanged (§4.3 ordering preserved by the Phase-3
pin). So the SYN/FIN/etc. are emitted on the same
`_advance(ms=1)` step the old model emitted them.

This is the §5.4 / §9 "tx-drain timer" fallback, now
**adopted as required** (not optional), routed through the
existing deadline-map machinery rather than a scattered
side-channel of explicit kick calls.

## 6. File-by-file changes & test plan

### 6.0 Testing discipline (MANDATORY, per-phase)

This migration is overwhelmingly **behaviour-preserving
refactor**, so the dominant discipline is not "write a
failing test" but **"prove the safety net is strong on the
*unchanged* code first, then require it stays green."** The
rules below are non-negotiable; a phase commit that skips
any of them is a blocker, not a polish item.

**Rule 1 — Coverage-strength precondition (test weak ⇒ fix
tests FIRST).** Before the refactor commit of any phase, the
characterization net for the timers that phase touches MUST
be audited and proven strong *against the current,
pre-change code*:
- Run targeted coverage on the touched source
  (`coverage run --source=pytcp.protocols.tcp.<file> …`) and
  enumerate, per touched timer, whether the existing tests
  exercise: arm, re-arm (overwrite), fire, cancel,
  fire-after-state-change, the `is_expired` conflation
  boundary, and every `register_timer` / `is_expired`
  call site listed in §4.1.
- If that net is **not** strong enough to detect a
  behavioural regression in that timer (missing edge,
  uncovered branch, no wire-level assertion on fire ms /
  fire effect), the **first commit of the phase is a
  test-hardening commit** that adds those tests **against
  the unchanged production code** and shows them green
  there. The migration commit lands only *after* the net is
  demonstrably strong. Weak coverage is never "discovered
  and worked around mid-refactor" — it is closed up front,
  on the old code, as its own reviewable commit.
- A test-hardening commit is itself gated by §8 and the
  §7.2 audit; its message states which timer's net it
  strengthens and which gaps it closed.

**Rule 2 — Behaviour-changing delta: tests-first failing.**
The only genuine behavioural change in this plan is the
`challenge_ack` `is_expired` inversion (§5.5). It follows
`feature_implementation.md` §2 verbatim: the test is written
**first**, run, and **verified to fail for the predicted
reason**, then the inversion makes it green. Any other
behavioural delta the §5.5 audit surfaces is treated
identically.

**Rule 3 — Pins exist green on the pre-change commit.** For
every behaviour-preserving phase (1, 3, 4, 5) the relevant
pin / characterization tests MUST be present and green on
the commit *before* the refactor commit (i.e. landed in the
prior phase or as the phase's own first test-hardening
commit per Rule 1). The refactor commit's sole job is
"still green — nothing first-written here."

**Rule 4 — Phase 4 is a pure stays-identical proof.** The
ordering pin (§6.4 Phase 3), the per-timer parity pins
(§6.4 Phase 2), and the stat-counter snapshot baseline (§8
gate 5) MUST all already exist and be green at the end of
Phase 3. Phase 4 writes no new test to "prove" the flip; it
only requires the existing nets stay byte-identical.

**Rule 5 — After every phase: the full §8 gate.** No phase
commits without `make lint` + full `make test` + §7.2 audit
+ coverage-held, all green.

> Net effect: every timer is migrated only across a safety
> net that was *already proven to catch a regression in that
> timer on the old code*. "We think the suite covers it" is
> not acceptable — it must be shown, per timer, before the
> code moves.

### 6.1 `packages/pytcp/pytcp/protocols/tcp/tcp__session.py`

- Add `_timer_deadlines`, `_service_handle` attributes
  (declared in the class annotation block, initialised in
  `__init__`). **Per `.claude/rules/pytcp.md` §6.1 / the
  stack-module-state memory: these are per-session instance
  attributes, NOT module/stack state — no harness
  snapshot/restore needed.** Confirm `TcpSession.__init__`
  is the only construction path.
- Add the helper trio (§5.1) + `_reschedule_service` (§5.2)
  + `_SERVICED_TIMERS_BY_STATE` constant (§4.3 as data).
- Phase 1: implement helpers backed by the deadline map but
  leave `_reschedule_service` a no-op; keep the 1 ms
  `call_periodic`. Replace every `register_timer` with
  `_arm_timer`, every `is_expired` with
  `_timer_expired`/`_timer_armed` per §5.5, every
  `unregister_timers_with_prefix` per §4.2. **Behaviour is
  byte-identical** because the 1 ms tick still runs the same
  sequence and `_timer_expired` against `now_ms` reproduces
  the old countdown-to-zero semantics exactly (the heap
  Timer's `now_ms` is the same clock the old shim decremented
  against).
- `__init__`: `self._tcp_fsm_handle` semantics unchanged in
  Phases 1-3.
- Phase 4: implement `_reschedule_service`; change
  `__init__` to NOT `call_periodic`; arm the service handle
  lazily (first `_arm_timer`). Add the `_reschedule_service()`
  call at the tail of `tcp_fsm` after dispatch (still under
  `_lock__fsm`).
- Phase 5: `_change_state(CLOSED)` cancels via
  `_cancel_all_timers()` (already in place from Phase 1's
  §4.2 swap) — confirm `_tcp_fsm_handle` is gone and only
  `_service_handle` remains.

### 6.2 `packages/pytcp/pytcp/protocols/tcp/fsm/tcp__fsm__*.py`

- `fsm__time_wait.py:58`: `is_expired` →
  `session._timer_expired("time_wait")` (Phase 2 pilot).
- All `register_timer(name=f"{session}-time_wait", …)` in
  `fsm__fin_wait_1`, `fsm__fin_wait_2`, `fsm__closing`,
  `fsm__time_wait` → `session._arm_timer("time_wait", …)`.
- No state-handler *body* reordering — the §4.3 sequence is
  the contract and stays verbatim.

### 6.3 `packages/pytcp/pytcp/tests/lib/fake_timer.py`

- **No API change.** FakeTimer already exposes
  `call_later` / `cancel` / `now_ms`. The migrated session
  uses `stack.timer.now_ms` for `_timer_expired` and
  `call_later` for the service handle — both already
  supported.
- The `_PRIO__NAMED_FLAG` band becomes unused for TCP once
  no `register_timer` remains, but the band stays (other
  semantics depend on the ordering rule; removing it is a
  fake_timer cleanup, not part of this plan).
- **Parity is the gate.** After Phase 4 the session arms
  `call_later(delay, tcp_fsm, timer=True)`; FakeTimer's
  `advance(ms)` must fire it at the same virtual ms the old
  1 ms-periodic-plus-flag-poll did. The exhaustive existing
  TCP integration suite is the oracle (§8).

### 6.4 Test plan

The TCP integration suite under
`packages/pytcp/pytcp/tests/integration/protocols/tcp/` is the primary
spec-pin and **must stay 100% green at every phase**. It
already exercises RTO, persist, keepalive, TIME_WAIT,
delayed-ACK, TLP, RACK, challenge-ACK at wire level via
`FakeTimer.advance(ms=N)`.

New tests (added in the phase that introduces the behaviour):

**Phase 1 — helper unit tests**
(`packages/pytcp/pytcp/tests/unit/protocols/tcp/test__tcp__session__timers.py`,
new file):
- `test__tcp__timers__arm_sets_absolute_deadline`
- `test__tcp__timers__expired_false_when_unarmed` (the
  de-conflation — pins the NEW semantic)
- `test__tcp__timers__expired_true_at_or_after_deadline`
- `test__tcp__timers__armed_true_only_while_pending`
- `test__tcp__timers__cancel_clears_deadline`
- `test__tcp__timers__cancel_all_clears_map_and_handle`
- `test__tcp__timers__rearm_overwrites_deadline`
Each Shape-A (mock `stack.timer.now_ms`); §7.2-compliant
docstrings (`Reference: PyTCP test infrastructure (no RFC
clause).`).

**Phase 2 — per-timer behavioural parity (integration)**
For time_wait / challenge_ack / keepalive / persist /
delayed_ack: a focused integration test per timer asserting
the fire ms and fire effect are identical pre/post.

SHIPPED outcome (audit-in-lockstep): the §6.0 Rule-1 audit
found that four of the five independent timers **already
have crisp deadline-exact boundary pins** in their dedicated
files — these ARE the per-timer parity pins and Phase 4's
Rule-4 precondition points at them directly:

| Timer | Existing deadline-exact pin |
|-------|------------------------------|
| time_wait | `test__tcp__session__close__time_wait.py:158` (advance `TIME_WAIT_DELAY-1` no-fire, then fire) |
| delayed_ack | `test__tcp__session__data_transfer__recv.py:148/162` (advance `DELAYED_ACK_DELAY//2` held, then `DELAYED_ACK_DELAY` flush) |
| keepalive | `test__tcp__session__keepalive.py:178/189` (advance `IDLE-1` no-probe, then probe) |
| persist | `test__tcp__session__data_transfer__send.py:385` (cross persist-timeout boundary, exactly one probe) |

Duplicating these would be redundant and brittle (the
project north star explicitly resists dedicated sweeps), so
Phase 2 added new coverage **only** for the one genuinely
thin net: challenge_ack. The challenge_ack gate (§5.5) gets
its dedicated truth-table — a unit gate truth-table in
`test__tcp__session__timers.py`
(`test__tcp__timers__challenge_ack_gate_truth_table`) plus
an integration file
`test__tcp__session__challenge_ack_window.py` (3 tests:
unarmed→emit/within-window→suppress, re-emit after window,
exact `CHALLENGE_ACK_RATE_LIMIT_MS-1` vs boundary). The
challenge_ack swap already landed behaviour-preservingly in
Phase 1 (same truth set as `not is_expired`); these tests
pin it explicitly and pass on the existing code (a
characterization pin per §6.0 Rule 3, not a
tests-first-failing case — there is no behavioural delta to
fail against, the burst pin `blind_attacks.py:553` already
proved Phase-1 parity). Phase 2 made **zero code changes**.

**Phase 3 — retransmit/rack/tlp ordering pin**
A new integration test pins the `_retransmit → _transmit_data
→ _delayed_ack → _keepalive → _rack → _tlp` ordering. This is
the regression net for the hardest phase. Plus the
`_transmit_data` no-armed-timer gap investigation (§5.4)
lands one integration test per enumerated state.

SHIPPED outcome (audit-in-lockstep): the ordering pin landed
as `test__tcp__session__timer_ordering.py::
TestTcpTimerHandlerOrdering::
test__timer_ordering__established_tick_runs_canonical_sequence`.
Rather than a brittle wire-sequence scenario, it wraps the
six tick methods with order-recorders and drives one
ESTABLISHED service, asserting the recorded order equals the
§4.3 contract `_ESTABLISHED_TICK_ORDER`. This pins the exact
invariant Phase 4 must preserve — Phase 4 changes only the
trigger, never the handler body, so "the handler runs the
full ordered sequence per service event" is the precise
property at risk, and this test asserts it literally
(robust, not scenario-dependent). It is the Phase-4 Rule-4
regression net.

The §5.4 gap audit landed as
`TestTcpTransmitDataGapAudit` (3 tests): in-flight data →
`_timer_armed("retransmit")`; zero-window buffered data →
`_timer_armed("persist")`; CLOSE_WAIT in-flight →
`_timer_armed("retransmit")`. **Conclusion: no genuine gap
exists — retransmit (in-flight) and persist (zero-window)
cover every state in which the TX buffer is non-empty, so
the Phase-4 coalesced service handle is always armed when
`_transmit_data` has work. No "tx-drain" logical timer is
needed** (§5.4's expected outcome confirmed). Phase 3 made
zero code changes.

**Phase 4 — coalesced-trigger equivalence**
The whole TCP integration suite is the test. Additionally:
- `test__tcp__timers__service_armed_at_soonest_deadline`
- `test__tcp__timers__service_rearmed_after_each_fire`
- `test__tcp__timers__no_service_handle_when_no_timer_armed`
  (the zero-idle-wakeup property)
- `test__tcp__timers__service_scope_respects_state_matrix`
  (a timer armed but not serviced in the current state does
  NOT wake the session)

**Every phase**: `make lint` clean, full `make test` clean,
§7.2 audit clean on touched test files, per-touched-source
coverage stays 100% where it already is.

## 7. Phase plan

Each phase obeys the §6.0 testing discipline: audit the
touched timers' net first, land a test-hardening commit on
the *unchanged* code if that net is weak (Rule 1), pins
green on the pre-change commit (Rule 3), then the refactor
commit, then the full §8 gate (Rule 5). Every phase ends
`make lint && make test` clean and is an independent,
revertible commit (a phase may be a commit pair or triple:
optional test-hardening → optional tests-first-failing →
refactor-green).

### Phase 0 — This plan (no code)
Commit this document. Lock the architecture (coalesced
per-session service handle; deadline map; helper trio;
preserved ordering matrix).

### Phase 1 — Deadline-map helper, zero behaviour change
Add attributes + helper trio + `_SERVICED_TIMERS_BY_STATE`;
`_reschedule_service` is a no-op. Swap ALL `register_timer`
→ `_arm_timer`, `is_expired` → `_timer_expired`/`_timer_armed`
(§5.5), `unregister_timers_with_prefix` → `_cancel_timer`/
`_cancel_all_timers` (§4.2). The 1 ms `call_periodic` still
drives `tcp_fsm`; the per-state handlers are untouched.
**Net wire behaviour: identical** (proven by the unchanged
integration suite). Per §6.0: first audit the existing
timer net (Rule 1) — land a test-hardening commit on the
*unchanged* code for any timer whose net is weak — then add
the Phase-1 helper unit tests, then the mechanical swap.
The integration suite is the parity oracle; the helper unit
tests pin the new `_timer_expired`/`_timer_armed`
de-conflation semantics.
Commit(s): optional `pytcp.tests…: harden <timer> net
(Phase 1 pre-work)` then `pytcp.protocols.tcp: deadline-map
timer helpers (Phase 1 of TCP timer-client migration)`.

### Phase 2 — Independent-timer audit & inversion
No structural change; this phase is the §5.5 audit made
concrete: add the dedicated challenge_ack truth-table test
and the per-timer parity integration tests for time_wait /
challenge_ack / keepalive / persist / delayed_ack. Fix any
parity bug the audit surfaces. (Most likely zero code change
beyond Phase 1 — this phase exists to *prove* the
independent timers are correct before the risky trigger
flip.)
Commit: `pytcp.tests.integration.tcp: per-timer parity pins
+ challenge_ack inversion test (Phase 2 …)`.

### Phase 3 — Coupled cluster + `_transmit_data` gap proof
Add the retransmit/rack/tlp ordering integration pin. Run
the §5.4 investigation: enumerate every state with a
non-empty TX buffer and no armed logical timer; add an
integration test per case; if a real gap exists, add a
"tx-drain" logical timer (rare — expected: none, because
persist/retransmit cover it). No trigger change yet.
Commit: `pytcp.tests.integration.tcp: retransmit/rack/tlp
ordering pin + tx-drain gap audit (Phase 3 …)`.

### Phase 4 — Flip the trigger (the risky step)
Implement `_reschedule_service`; stop the 1 ms
`call_periodic` in `__init__`; arm the coalesced service
handle lazily from `_arm_timer`/`_cancel_timer` and re-arm
at the tail of `tcp_fsm`. The per-state handlers still run
the full ordered sequence on each service event.
**Validation: the entire TCP integration suite must remain
byte-identical.** Any single failure ⇒ the coalescing or
re-arm logic diverged ⇒ pinpoint & fix or roll back Phase 4
only (Phases 1-3 stand alone).
Commit: `pytcp.protocols.tcp: coalesced event-driven service
tick (Phase 4 …)`.

> **POST-MORTEM — Phase 4 attempt #1 ROLLED BACK (2026-05-15).**
> Implemented exactly as specified (`_reschedule_service` per
> §5.2, `__init__` periodic dropped, re-arm at the `tcp_fsm`
> tail + before the icmp early-return, `_SERVICED_TIMERS_BY_STATE`
> widened so `persist` is in scope for every `_transmit_data`
> state). Lint clean, **no busy-loop / hang**, but the TCP
> integration suite returned **392 failures / 5 errors** — a
> systemic divergence, not a pinpoint bug, so per this phase's
> own rule the code was reverted to the Phase-3 commit
> `9b22bcca` and Phases 1-3 stand intact (suite green again).
>
> **Root cause: the 1 ms periodic was a load-bearing FSM
> *pump*, not merely a timer-service poll.** Canonical proof:
> active-open `fsm__closed__syscall` CONNECT does only
> `_change_state(SYN_SENT)` — it does **not** emit the SYN. The
> SYN is emitted later by `fsm__syn_sent__timer →
> _transmit_data()`. In the old model the always-on 1 ms
> periodic fired that handler within ~1 ms of CONNECT. In the
> coalesced model **nothing is armed after CONNECT** (no SYN
> sent yet ⇒ no retransmit timer), so the service handle is
> never armed, `_advance(ms=1)` fires nothing, the SYN never
> goes out, and every handshake stalls at SYN_SENT. More
> broadly: many call sites and tests rely on a near-immediate
> `tcp_fsm(timer=True)` tick to pump `_transmit_data` / FSM
> progression even when **no logical-timer deadline is due**.
>
> **§5.4 conclusion "no tx-drain timer needed" is DISPROVEN.**
> The Phase-3 gap audit was insufficient: it only checked
> states with data already in flight (retransmit armed) or
> zero-window (persist armed); it never covered the
> *just-transitioned, `_transmit_data` has work, nothing armed
> yet* pump case (CONNECT→SYN_SENT is the archetype). The
> §5.4 / §9 "tx-drain timer" fallback is therefore **REQUIRED,
> not optional**.
>
> **Corrected design direction for attempt #2 (must be
> re-planned, tests-first, before any code):** a coalesced
> timer handle alone is insufficient. Add an explicit
> FSM-pump / "tx-kick": every event that in the old model
> relied on "the next 1 ms tick" to make progress — at
> minimum every `_change_state(...)` transition, the CONNECT
> syscall, and a buffered `send()` that could not go out —
> must arm a near-immediate (delay-0) service kick. The
> enumeration of pump points is exactly the hard, error-prone
> surface that made the 1 ms periodic exist; the redesign
> must either (a) pin that complete set tests-first, or
> (b) reconsider whether deleting the periodic is worth the
> risk versus keeping a coarse self-clock (e.g. a single
> low-frequency `call_periodic` retained purely as the
> pump, with the coalesced handle layered on top for
> precise timer servicing). This is a planning task, not a
> hack-forward; Phase 4 stays BLOCKED until re-planned.

#### Phase 4 — attempt #2 (REDESIGNED, tests-first)

Design: §5.6 (`tx_pump` one-shot kicked at the `tcp_fsm`
tail on state-change-or-syscall). Two commits, in order;
the §6.0 testing discipline is mandatory.

**Phase 4a — strengthen the net on the UNCHANGED Phase-3
code (§6.0 Rule 1; tests-only, zero production change).**
The original §5.4 gap audit was the weak spot that let
attempt #1 through — it never pinned the *pump* behaviour.
Before any redesign code, land characterization pins that
**pass on the current Phase-3 periodic code** and would
have caught attempt #1's 392-failure cascade:

- `test__pump__connect_emits_syn_on_first_advance` — active
  open: `tcp_fsm(syscall=CONNECT)` then `_advance(ms=1)`
  MUST emit the SYN (the exact archetype that broke).
- `test__pump__handshake_completes_through_first_advance` —
  full `_drive_handshake_to_established` reaches ESTABLISHED
  (guards the 392-failure class wholesale).
- `test__pump__close_with_empty_buffer_emits_fin` — `close()`
  in ESTABLISHED with a drained TX buffer then `_advance`
  MUST emit the FIN (the close→FIN_WAIT_1 timer-driven
  transition).
- `test__pump__close_with_pending_data_drains_then_fins` —
  multi-step progression: buffered data drains, then FIN
  (chained state changes).
- `test__pump__quiescent_established_session_is_idle` —
  characterise the zero-idle property on the periodic code
  as a baseline (idle ESTABLISHED produces no spurious TX
  across a long advance) so attempt #2's zero-idle claim is
  measured against a pinned baseline.

These go in a new
`packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__fsm_pump.py`.
They are green on Phase-3 code (characterization pins, §6.0
Rule 3). Commit:
`pytcp.tests.integration.tcp: FSM-pump characterization pins
(Phase 4a — strengthen-on-unchanged-code)`.

**Phase 4b — implement the §5.6 redesign.** Only after 4a
is green and committed:

- Implement `_reschedule_service` (§5.2 logical-timer
  coalescing) + the `tx_pump` consume/conditional-re-arm at
  the `tcp_fsm` tail (§5.6 steps 1-5) + snapshot
  `state_at_entry`; add `"tx_pump"` to every
  `_SERVICED_TIMERS_BY_STATE` entry; drop the 1 ms
  `call_periodic` from `__init__`.
- New-mechanism unit tests in
  `test__tcp__session__timers.py`:
  `test__tcp__timers__tx_pump_armed_on_state_change`,
  `…tx_pump_armed_on_syscall`,
  `…tx_pump_one_shot_consumed_at_tcp_fsm_tail`,
  `…tx_pump_not_rearmed_when_quiescent`,
  `…no_service_handle_when_nothing_armed`,
  `…service_armed_at_soonest_serviced_deadline`,
  `…service_scope_excludes_out_of_state_timers`.
- **Gate (Rule 4 + §8 gate 5):** the 4a pins, the Phase-2
  per-timer pins, the Phase-3 ordering pin, and the **entire
  TCP integration suite MUST stay byte-identical** (the
  attempt-#1 failure count is the canonical regression
  signal: must return to 0). Run the TCP integration suite
  under a timeout to catch any residual busy-loop. Any
  systemic failure ⇒ roll back 4b only (4a stands), do not
  hack-forward.
- Commit: `pytcp.protocols.tcp: tx_pump FSM-pump + coalesced
  service tick (Phase 4b — trigger flip, attempt #2)`.

Rollback: 4b is the single risky independently-revertible
commit; 4a (tests-only) and Phases 1-3 stand alone.

> **POST-MORTEM — Phase 4b attempt #1 ROLLED BACK (2026-05-15).**
> The §5.6 design was implemented and then iteratively
> hardened by three *principled, kept* refinements that cut
> the TCP-integration divergence **392 → 51 → 35 → 3**:
>
> 1. **1 ms delay floor in `_reschedule_service`** (`max(1,
>    …)`, never 0). The old periodic never serviced a timer
>    instantly — it ticked at 1 ms granularity. A handler may
>    legally no-op on an expired timer without re-arming /
>    cancelling it (harmless under the poll); the coalesced
>    handle would then spin at delay 0 forever (busy-loop /
>    hang — observed: the TCP suite timed out at 420 s).
>    Flooring at 1 ms makes every service fire advance the
>    clock ≥ 1 ms, so `advance(N)` terminates in ≤ N fires,
>    exactly like the periodic. **Fixed the hang; 392→51.**
> 2. **Pump on every external dispatch, not just
>    state-change/syscall.** §5.6's completeness claim was
>    wrong: a *packet* that doesn't change state can leave
>    deferred `_transmit_data` work (NewReno retransmit,
>    ACK-clocked send) that the per-state TIMER handler — not
>    the packet handler — emits on the follow-up tick. **51→35.**
> 3. **`tx_pump` is a pace-while-work pump, not a one-shot.**
>    `_transmit_data` emits **one segment per tick**, so the
>    periodic was a continuous send-pacing clock. `tx_pump`
>    must re-arm while `_has_pump_work()` (unsent buffer /
>    in-flight data / closing) and stop only when fully
>    quiescent (zero-idle preserved). **35→3.**
>
> **Residual (3) — narrow, precisely root-caused.** One is
> the known `close_rst` test-infra reach-through (asserts on
> the now-always-None `_tcp_fsm_handle`; trivially re-pointed
> at `_service_handle` / `_timer_deadlines`). The other two
> (`test__rto__idle_longer_than_rto_resets_state_to_initial`,
> `test__cwnd__rfc5681_restart_window_reduces_cwnd_after_idle`)
> share **one cause**: `TcpSession.send()` (lines ~700-719)
> does **not** route through `tcp_fsm` — it only
> `self._tx.buffer.extend(data)`. So `_pump_tail` (which
> lives at the `tcp_fsm` tail) is never invoked by `send()`.
> After an idle period `send()` buffers data but arms no
> service handle → `advance(ms=1)` fires nothing → the data
> is never transmitted → `_phase0_pre_send_hygiene` (the RFC
> 6298 §5.7 idle-reset / RFC 5681 §4.1 restart-window, which
> only runs when a segment is actually emitted) never
> executes. The periodic masked this by ticking every ms
> regardless of whether `send()` routed through `tcp_fsm`.
> The three refinements above are **correct and retained**;
> the residual is solely the **non-`tcp_fsm` mutator gap**.
>
> Decision: roll back 4b (single revertible commit), keep
> Phases 0-4a, re-plan a focused 4c. No code change shipped
> (tcp__session.py reverted to Phase-3 / commit `9b22bcca`
> content; the Phase-4a `test__tcp__session__fsm_pump.py`
> pins stand).

### 5.7 Phase-4c redesign — `_kick_pump` for non-`tcp_fsm` mutators

The §5.6 design (coalesced `_service_handle` + `tx_pump`)
**plus the three Phase-4b refinements** (delay-floor,
pump-on-external, pace-while-work) is sound. The only gap is
that some session entry points mutate FSM-relevant state
**without routing through `tcp_fsm`**, so `_pump_tail` never
runs to arm the pump. Phase-4b proved exactly one such
entry: `TcpSession.send()`.

**Mechanism.** Add a tiny `_kick_pump(self)`:
`self._arm_timer(_PUMP, 1)` (which already calls
`_reschedule_service`), guarded `if self._state is not
FsmState.CLOSED`. Call it from every non-`tcp_fsm` entry
point that can leave FSM-progression work. Phase-4c step 1
is an **audit, tests-first**, enumerating those entries; the
known member is `send()`. Candidate audit list (confirm each
by code-read, not assumption): `send()`, any direct
`_tx.buffer` mutation outside `tcp_fsm`, socket-facade
`sendto`/`write` shims, `shutdown`. Entries that already
route through `tcp_fsm` (`close()` → `tcp_fsm(syscall=CLOSE)`,
CONNECT, packet RX, ICMP) are already covered by
`_pump_tail` and need no kick.

**Completeness restated.** Post-4c, every FSM progression
originates from: a packet / syscall / ICMP dispatch (→
`_pump_tail` via `tcp_fsm`), a logical-timer expiry (→
coalesced `_service_handle`), a state entry (→ `_pump_tail`
state-change branch), pace-while-work (`_has_pump_work` →
`_pump_tail` re-arm), **or a non-`tcp_fsm` mutator (→
`_kick_pump`)**. That set is now closed.

#### Phase 4c — attempt #2 (tests-first)

**Phase 4c-a — non-`tcp_fsm` mutator audit pins (tests-only,
green on UNCHANGED Phase-3 periodic code; §6.0 Rule 1).**
Add characterization pins that exercise the gap class on the
periodic code (where they pass) and would fail under a
coalesced model lacking `_kick_pump`:
- `test__pump__send_after_idle_transmits_and_resets_rto` —
  send + ack, idle > RTO, `send()` again, `advance(ms=1)`:
  the data MUST be transmitted and `_rto_state` reset to
  `initial_state()` (the exact `test__rto__idle_longer…`
  scenario, generalised into the pump pin file).
- `test__pump__send_after_idle_applies_restart_window` — the
  `test__cwnd__rfc5681_restart_window…` scenario.
- `test__pump__bare_send_with_no_other_activity_transmits` —
  the minimal gap: handshake, (quiesce), `send()`,
  `advance(ms=1)` → exactly one data segment out.
Commit: `pytcp.tests.integration.tcp: non-tcp_fsm mutator
pins (Phase 4c-a)`.

**Phase 4c-b — implement §5.6 + the three Phase-4b
refinements + §5.7 `_kick_pump`.** Re-apply the (known-good)
4b code: `_reschedule_service` with the **1 ms floor**,
`_pump_tail` with **external = packet|syscall|icmp** and the
**`_has_pump_work` pace-while-work re-arm**, `tx_pump` in
every `_SERVICED_TIMERS_BY_STATE` entry, drop the periodic;
**add `_kick_pump` and call it from every audited non-
`tcp_fsm` mutator (`send()` confirmed)**. Fix the
`close_rst` test-infra reach-through (re-point at
`_service_handle is None` / `_timer_deadlines == {}` on
CLOSED — same pattern as the timer-rewrite reach-through
fixes). New-mechanism unit tests in
`test__tcp__session__timers.py` (tx_pump arm/consume/
pace-while-work, `_kick_pump` arms on `send()`,
delay-floor ≥ 1, zero service handle when quiescent).
**Gate (Rule 4 / §8 gate 5): the Phase-4a + 4c-a pins, the
Phase-2/3 pins, and the entire TCP integration suite MUST
return to 0 failures, byte-identical; TCP suite run under a
timeout for busy-loop.** Any systemic regression ⇒ roll
back 4c-b only.
Commit: `pytcp.protocols.tcp: tx_pump + _kick_pump
event-driven service tick (Phase 4c-b — trigger flip)`.

Rollback: 4c-b is the single risky revertible commit;
4c-a (tests-only) and Phases 1-4a stand alone.

### Phase 5 — Delete the periodic + handle-registry teardown
Remove `self._tcp_fsm_handle` (`call_periodic`) entirely;
only `_service_handle` remains. Confirm `_cancel_all_timers`
on CLOSED fully tears down. Drop now-dead code.
Commit: `pytcp.protocols.tcp: drop the 1 ms FSM periodic —
service tick is event-driven (Phase 5 …)`.

### Phase 6 — Delete the dead named-flag shim + docs
`register_timer` / `is_expired` /
`unregister_timers_with_prefix` now have zero consumers
(§4.6). Delete them from `Timer` and `FakeTimer`; delete
their shim tests; flip this doc's Status to SHIPPED with
SHAs; update `.claude/rules/pytcp.md` if it references the
shim; refresh the `project_timer_rewrite` memory note
(named-flag shim no longer "deliberately retained" — now
removed).
Commit: `pytcp.runtime.timer: drop the dead named-flag shim
(Phase 6 …)` + `docs: TCP timer-client migration shipped`.

**SHIPPED** (`1962d17f`). The shim + tests + vestigial
fixture attrs + the direct-touch shim prose were removed in
that commit; a comment/docstring-only follow-up
(`4f434c8f`) then reworded the remaining FSM-comment +
test-prose mentions of the dead `is_expired` /
`stack.timer._timers` API in functions untouched by the
mechanical migration to the live `_timer_expired` /
`_timer_armed` / `_timer_deadlines` helpers (and fixed a
pre-existing §7.2 inline-RFC violation surfaced on a touched
file). Both are behaviour-neutral (11012/0/4). The only
remaining shim mentions are the two deliberate "was removed"
archaeology notes in `timer.py` / `fake_timer.py` that
explain the retained `_PRIO__METHOD` artifact.

## 8. Validation gates

Per phase, before commit:
0. **§6.0 Rule 1 satisfied** — the touched timers'
   characterization net was audited and proven strong on the
   pre-change code; if it was weak, the test-hardening
   commit landed first (green on old code). This gate is
   checked *before* the refactor commit is written, not
   after.
1. `make lint` — codespell + isort + black + flake8 + mypy
   strict + pylint.
2. `make test` — full suite. Currently **10997 passing /
   4 skipped / 0 failures** post timer-rewrite. The count
   only grows (new tests); never regresses.
3. §7.2 docstring audit on every touched/new test file.
4. Coverage: any source file already at 100% stays at 100%.
5. **Phase 4 extra gate**: a diff of the TCP integration
   suite's emitted-frame logs (or stat-counter snapshots)
   pre/post must be empty. The suite's strict
   `_assert_packet_stats_*(exact=True)` assertions already
   enforce this; treat any delta as a hard stop.

## 9. Risks & mitigations

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Coalesced re-arm fires at a different ms than the old 1 ms poll | Medium-High | `_timer_expired` uses the SAME `now_ms` clock the old shim decremented; the per-state sequence is unchanged; soonest-deadline `call_later` fires at exactly the ms `is_expired` would first have returned True. Pinned by the full integration suite + Phase-4 stat-snapshot gate. |
| Ordering invariant broken (retransmit vs transmit, rack vs tlp) | Medium | The per-state handler bodies are NOT touched — the ordered sequence runs intact on every service event. The Phase-3 ordering integration pin is the regression net. |
| State-scope leak: timer fires after a transition that should suppress it | Medium | `_reschedule_service` filters by `_SERVICED_TIMERS_BY_STATE[self._state]`; a timer armed but not serviced in the new state does not wake the session, exactly matching the old per-state dispatch no-op. Dedicated Phase-4 test. |
| `is_expired` de-conflation changes a load-bearing second guard | Medium | §5.5 classifies every site; genuine RFC guards (e.g. `snd_una==snd_max`) are KEPT; only pure disambiguation guards removed. challenge_ack inversion gets a tests-first truth-table. |
| `_transmit_data` self-clock starvation | Low-Medium | §5.4 decision + Phase-3 enumerated-gap proof with an integration test per state; add a narrow tx-drain timer only if a real gap is proven (expected: none). |
| FakeTimer fire-sequence drift | Low | No FakeTimer API change; it already supports the exact primitives; the integration suite IS the FakeTimer oracle. |
| Hidden module/stack state added | Low | The new state is per-`TcpSession` instance state, not module/stack state — no harness snapshot/restore needed (confirm in Phase 1 review against the stack-state memory note). |

## 10. Rollback

Each phase is an independent commit. Phases 1-3 are pure
refactor/parity-proof and safe to keep even if Phase 4 is
reverted (`_reschedule_service` stays a no-op; the 1 ms
periodic still drives). Phase 4 is the single risky,
independently-revertible commit (`git revert <p4>` restores
the periodic; Phases 5-6 depend on it and revert first).
`make test` validates each revert.

## 11. Estimated effort

| Phase | Eng | Review | Risk |
|-------|-----|--------|------|
| 0 plan                         | done | — | none |
| 1 helpers + mechanical swap    | ~6 h | ~2 h | Low |
| 2 independent audit + inversion| ~5 h | ~2 h | Medium |
| 3 cluster pin + gap proof      | ~6 h | ~2 h | Medium |
| 4 trigger flip                 | ~6 h | ~3 h | High |
| 5 delete periodic              | ~2 h | ~1 h | Low |
| 6 delete shim + docs           | ~2 h | ~1 h | Low |
| **Total**                      | **~27 h** | **~11 h** | **High** |

## 12. Out-of-scope follow-ups

- Cross-session timer-wheel / hierarchical-timing-wheel
  coalescing (one global wheel vs one handle per session).
  Only relevant at very high connection counts; the heap
  scales fine for Phase-1/2 north-star targets.
- Per-logical-timer callbacks (rejected here in favour of
  the coalesced service tick because independent callbacks
  lose the §4.3 ordering guarantee). Revisit only if a
  future need for per-timer isolation appears.
- `_transmit_data` becoming fully ACK-clocked with no timer
  backstop — a larger TCP-pacing redesign, not this plan.

## 13. Resumption prompt

```
Execute the TCP timer-client migration per the plan at
docs/refactor/tcp_timer_client_migration.md.

Read the entire plan first, §6.0 especially. It is the
deferred §12 follow-up from
docs/refactor/timer_rewrite_plan.md (SHIPPED). Proceed phase
by phase under the §6.0 testing discipline (NON-NEGOTIABLE):
for each phase FIRST audit the touched timers'
characterization net on the current code; if weak, land a
test-hardening commit on the UNCHANGED production code
(green there) before any refactor — never work around weak
coverage mid-refactor. challenge_ack is the only true
behavioural change → tests-first failing, verified to fail
for the predicted reason, then green. Phase 4 writes no new
test (Rule 4): the ordering pin, per-timer parity pins, and
stat-snapshot baseline must already be green at end of
Phase 3. Every phase ends `make lint && make test` clean
(currently 10997 passing / 4 skipped / 0 failures), §7.2
audit clean on touched test files, coverage held; a phase
may be a commit pair/triple (harden → tests-first →
refactor).

- Phase 0 done (this plan, SHA <fill after Phase 0 lands>).
- Phase 1: add _timer_deadlines / _service_handle to
  TcpSession + the helper trio (§5.1) + _SERVICED_TIMERS_
  BY_STATE (§4.3 as data) + _reschedule_service as a NO-OP.
  Mechanically swap ALL register_timer→_arm_timer,
  is_expired→_timer_expired/_timer_armed per the §5.5 audit
  table, unregister_timers_with_prefix per §4.2. Keep the
  1 ms call_periodic. Behaviour MUST stay byte-identical —
  the integration suite is the oracle. New unit file
  test__tcp__session__timers.py (§6.4 Phase-1 list).
- Phase 2: §5.5 audit proven — per-timer parity integration
  tests for time_wait/challenge_ack/keepalive/persist/
  delayed_ack; challenge_ack inversion truth-table test
  written tests-first.
- Phase 3: retransmit/rack/tlp ordering integration pin +
  the §5.4 _transmit_data no-armed-timer gap enumeration
  (one integration test per state; add a tx-drain timer
  only if a real gap is proven).
- Phase 4 (RISKY): implement _reschedule_service; drop the
  1 ms call_periodic from __init__; arm the coalesced
  service handle lazily + re-arm at the tail of tcp_fsm
  under _lock__fsm. The ENTIRE TCP integration suite must
  stay byte-identical (Phase-4 stat-snapshot gate §8.5).
  Any single failure ⇒ pinpoint or revert Phase 4 only.
- Phase 5: delete _tcp_fsm_handle / the periodic; teardown
  via _cancel_all_timers on CLOSED only.
- Phase 6: delete the now-dead register_timer/is_expired/
  unregister_timers_with_prefix shim from Timer+FakeTimer
  and their shim tests; flip this doc Status→SHIPPED with
  SHAs; refresh .claude/rules/pytcp.md + the
  project_timer_rewrite memory note.

Locked design (do NOT re-litigate): coalesced per-session
service handle (NOT per-timer callbacks); explicit deadline
map keyed by bare logical name; helper trio
_arm_timer/_timer_expired/_timer_armed/_cancel_timer/
_cancel_all_timers; the §4.3 per-state ordered tick
sequence is preserved verbatim; _transmit_data stays in the
sequence (NOT given its own timer); same Timer worker
thread + same _lock__fsm; new state is per-session instance
state (no harness snapshot/restore). Commit-sign with
'Co-Authored-By: Claude Opus 4.7 (1M context)
<noreply@anthropic.com>'. Push after each green phase.
Resume from the latest phase-N commit; pick up at N+1.
```

## 14. Cross-references

- `docs/refactor/timer_rewrite_plan.md` — the SHIPPED
  heap-scheduler rewrite; its §12 deferred this plan.
- `packages/pytcp/pytcp/protocols/tcp/tcp__session.py` — the ~30 call
  sites + `tcp_fsm` dispatcher (`:4095`) + `_lock__fsm`.
- `packages/pytcp/pytcp/protocols/tcp/fsm/tcp__fsm.py` —
  `FSM_TIMER_HANDLERS` (`:156`), `dispatch_timer` (`:212`).
- `packages/pytcp/pytcp/protocols/tcp/fsm/tcp__fsm__*.py` — the 7 per-state
  timer handlers (the §4.3 ordering contract).
- `packages/pytcp/pytcp/runtime/timer.py` — `call_later` / `cancel` /
  `now_ms`; the named-flag shim deleted in Phase 6.
- `packages/pytcp/pytcp/tests/lib/fake_timer.py` — unchanged API; the
  integration-parity oracle.
- `.claude/rules/pytcp.md` §2/§6 — Subsystem + per-session
  vs stack state; `feature_implementation.md` §2 —
  tests-first; `unit_testing.md` §7.2 — docstring audit.
- Project memory `project_timer_rewrite.md` — records that
  the named-flag shim was *deliberately retained* pending
  exactly this migration; Phase 6 updates it.
