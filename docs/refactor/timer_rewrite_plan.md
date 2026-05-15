# Timer Rewrite — Heap-Based Deadline Scheduler

| Field             | Value                                                                                                                                                                |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Status            | **PROPOSAL** — drafted 2026-05-14; not yet started                                                                                                                   |
| Plan author       | Post-restructure timer-architecture review                                                                                                                           |
| Source motivation | Current `pytcp/runtime/timer.py` uses a 1 ms tick-and-decrement loop with O(N)-per-tick scans and ~1000 idle-wakeups/sec. Six structural issues identified in review |
| Target branch     | `PyTCP_3_0__pre_release`                                                                                                                                             |
| Touch points      | `pytcp/runtime/timer.py`, `pytcp/tests/lib/fake_timer.py`, `pytcp/tests/unit/runtime/test__runtime__timer.py`, ~25 consumer call-site rewrites in `pytcp/protocols/tcp/` + `pytcp/runtime/packet_handler/packet_handler__icmp6__rx.py` |
| Risk              | **Medium-High** — wide consumer surface (25+ call sites), test-harness behavior change (FakeTimer semantics shift), TCP integration tests rely on tick-by-tick `advance(ms=N)` semantics |
| Phases            | 0 (decisions) → 1 (heap-based core w/ legacy shims) → 2 (FakeTimer rewrite) → 3 (consumer migration) → 4 (drop legacy shims) → 5 (docs + close-out)                  |

This document is the implementation plan for replacing the
current tick-and-decrement `Timer` with a heap-based
deadline scheduler that wakes on demand. The rewrite
preserves the user-observable behaviour (TCP timers fire at
their RFC-mandated millisecond schedules; ICMPv6 MLD2
deferred sends still fire on the configured deadline) while
fixing six structural issues catalogued in §3.

This plan is intentionally self-contained: a fresh-context
agent invocation should be able to execute it end-to-end
without re-deriving design choices. See §13 for the
canonical resumption prompt.

---

## 1. Goal

Replace the polling timer with an event-driven scheduler:

1. **Idle CPU → 0.** Worker thread blocks on a
   `threading.Event.wait(timeout=<next_deadline>)` rather
   than spinning `time.sleep(0.001)` 1000×/sec.
2. **Drift-free.** Deadlines are absolute (`now_ms + delay`)
   not relative tick counters. A timer registered to fire
   in 1 s fires at the correct wall-clock time regardless
   of host load.
3. **O(log N) registration + per-tick.** `heapq` push for
   register; pop only due tasks per worker iteration.
4. **Cancel by handle.** `call_later` returns a
   `TimerHandle`; `cancel(handle)` flags lazy removal.
5. **One API for callbacks; legacy name/flag form is a
   shim.** `call_later(delay_ms, method, *args, **kwargs)`
   becomes the canonical entry. The existing
   `register_timer(name=, timeout=)` + `is_expired(name)`
   flag-style API stays as a thin shim over the new core
   so the bulk of TCP consumers don't churn in the same
   commit.

## 2. Non-goals

- **No API removal in the same plan.** Legacy
  `register_method` / `register_timer` / `is_expired` /
  `unregister_method` / `unregister_timers_with_prefix`
  stay callable through Phase 3. Phase 4 drops the shims
  only after consumers migrate.
- **No semantic change to TCP timer behaviour.** RTO,
  persist, keepalive, TIME_WAIT, delayed-ACK, RACK/TLP —
  all keep their existing fire times and fire counts.
  Tests prove this.
- **No new features.** No coalescing API, no QoS, no
  per-task threads. Just a better scheduler under the
  existing surface.
- **`delay_exp` (exponential backoff) and `stop_condition`
  are DROPPED.** Grepped 2026-05-14: zero production
  consumers use either of them. The `Timer` test corpus
  exercises them; those tests get deleted as dead-feature
  coverage.

## 3. Current state — issues this plan addresses

Recap of the six issues from the timer review (commit-`fd6db020`
era — post the thread-safety + assert fixes but pre-rewrite):

1. **Wall-clock drift.** `time.sleep(0.001)` + GIL +
   scheduling means each "tick" is actually 1-10+ ms on a
   busy system. `register_method(delay=1000)` fires at
   1000 ticks of variable real duration; no bound on the
   total elapsed time.
2. **Idle CPU waste.** ~1000 wakeups/sec doing nothing
   when no timers are pending. Bad for embedded.
3. **O(N) per tick.** Every tick iterates every
   registered task + every named timer, regardless of
   whether any is about to fire.
4. **Polling consumer API.** `is_expired(name)` requires
   consumers to poll. TCP session has its own
   per-millisecond FSM tick that polls.
5. **No per-registration cancel.** `unregister_method`
   removes ALL registrations of a method.
6. **Single-thread bottleneck.** Tick holds the lock
   while invoking task methods. A slow callback delays
   every other timer. (RLock helps re-entrance but not
   isolation.)

## 4. Current callers — exhaustive inventory

Grepped 2026-05-14 against `PyTCP_3_0__pre_release`:

### 4.1 `register_method` (2 production callers)

| Site | Form | Mapped to new API |
|------|------|-------------------|
| `pytcp/protocols/tcp/tcp__session.py:488` | `stack.timer.register_method(method=self.tcp_fsm, kwargs={"timer": True})` — default `delay=1`, `repeat_count=-1` (infinite) | `stack.timer.call_periodic(period_ms=1, method=self.tcp_fsm, kwargs={"timer": True})` — store handle on `self._tcp_fsm_handle` |
| `pytcp/runtime/packet_handler/packet_handler__icmp6__rx.py:1275` | `stack.timer.register_method(method=self._mld2_query__deferred_send, delay=delay_ms, repeat_count=0)` — one-shot | `stack.timer.call_later(delay_ms=delay_ms, method=self._mld2_query__deferred_send)` — store handle on `self._mld2_query__handle` |

### 4.2 `unregister_method` (2 production callers)

| Site | Migration |
|------|-----------|
| `pytcp/protocols/tcp/tcp__session.py:950` | `stack.timer.unregister_method(self.tcp_fsm)` → `stack.timer.cancel(self._tcp_fsm_handle)` |
| `pytcp/runtime/packet_handler/packet_handler__icmp6__rx.py:1271` | `stack.timer.unregister_method(self._mld2_query__deferred_send)` → `stack.timer.cancel(self._mld2_query__handle)` |

### 4.3 `register_timer` (20+ call sites in tcp__session + 4 fsm states)

Examples:
- `register_timer(name=f"{self}-delayed_ack", timeout=tcp__constants.DELAYED_ACK_DELAY)`
- `register_timer(name=f"{session}-time_wait", timeout=tcp__constants.TIME_WAIT_DELAY)`
- `register_timer(name=rate_limit_timer, timeout=tcp__constants.CHALLENGE_ACK_RATE_LIMIT_MS)`

All use named string timers + paired `is_expired(name)`
polling. **These STAY on the legacy `register_timer` API
through Phase 3** — they get the new heap-based core via
the shim. Migrating 24 call sites + the corresponding
`is_expired` polls to event-driven callbacks is its own
follow-up track, out of scope for this plan.

### 4.4 `is_expired` (10+ call sites)

All in `pytcp/protocols/tcp/tcp__session.py`. Same as 4.3
— stays on the legacy API via shim.

### 4.5 `unregister_timers_with_prefix` (2 call sites)

- `pytcp/protocols/tcp/tcp__session.py:939` (CLOSED transition)
- `pytcp/protocols/tcp/tcp__session.py:1968` (cleanup)

Stays on legacy API via shim.

### 4.6 `delay_exp` (0 production callers) — DROP

### 4.7 `stop_condition` (0 production callers) — DROP

### 4.8 `repeat_count` other than -1 and 0 (0 production callers) — DROP

The current `TimerTask` supports `repeat_count > 0` (fire
N times then stop). Zero consumers use this; only `-1`
(infinite) and `0` (one-shot) appear. The new
`call_periodic(period_ms, ...)` handles infinite-repeat;
`call_later(delay_ms, ...)` handles one-shot. The
finite-repeat case is not supported and not needed.

## 5. Target architecture

### 5.1 Core data structure

A min-heap of `_HeapEntry` objects keyed by `(deadline_ms,
seq)`. `seq` is a monotonic counter ensuring FIFO order
among same-deadline entries (Python's `heapq` is not
stable; the seq tiebreaker makes the ordering
deterministic).

```python
import heapq
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(slots=True)
class TimerHandle:
    """
    Cancellation handle returned by 'call_later' /
    'call_periodic'. Pass to 'Timer.cancel(handle)' to
    deactivate the entry; cancellation is lazy (the
    worker skips cancelled entries when they reach the
    top of the heap).
    """

    method: Callable[..., None]
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    period_ms: int | None  # None for one-shot; non-None for periodic
    deadline_ms: int       # current absolute deadline (rescheduled for periodic)
    seq: int               # tiebreaker for stable ordering
    cancelled: bool = False


@dataclass(slots=True, order=True)
class _HeapEntry:
    """
    Wraps a TimerHandle for heapq ordering. Compares on
    (deadline_ms, seq) only.
    """

    deadline_ms: int
    seq: int
    handle: TimerHandle = field(compare=False)
```

### 5.2 Worker-loop body

```python
@override
def _subsystem_loop(self) -> None:
    while True:
        with self._lock:
            now = self.now_ms
            # Pop and dispatch every due entry.
            due: list[TimerHandle] = []
            while self._heap and self._heap[0].deadline_ms <= now:
                entry = heapq.heappop(self._heap)
                if entry.handle.cancelled:
                    continue
                due.append(entry.handle)
            # Reschedule periodic entries.
            for handle in due:
                if handle.period_ms is not None and not handle.cancelled:
                    handle.deadline_ms = now + handle.period_ms
                    handle.seq = self._next_seq()
                    heapq.heappush(self._heap, _HeapEntry(handle.deadline_ms, handle.seq, handle))
            # Compute wait time.
            if self._heap:
                wait_s = max(0.0, (self._heap[0].deadline_ms - now) / 1000.0)
            else:
                wait_s = _IDLE_WAKEUP__SEC  # 60 s, see §5.3

        # Invoke callbacks WITHOUT the lock so handlers can call back.
        for handle in due:
            try:
                handle.method(*handle.args, **handle.kwargs)
            except Exception:
                # Don't let a misbehaving handler take down the timer.
                __debug__ and log(
                    "timer",
                    f"<r>Handler raised: {handle.method.__name__}</>",
                )

        # Wait until next deadline OR a new registration wakes us.
        self._wakeup.clear()
        self._wakeup.wait(timeout=wait_s)
        if self._event__stop_subsystem.is_set():
            return
```

Key properties:
- **Lock held only while mutating the heap.** Callback
  invocations happen lock-free; consumers calling
  `call_later` from a callback land on a clean heap.
- **No `time.sleep`.** The Event-based wait wakes either
  on next deadline OR on a registration `set()` call.
- **Single-iteration "drain due, reschedule periodics,
  invoke, wait again."** No nested polling loop.

### 5.3 Idle-wakeup cap

When the heap is empty, the worker would block forever
on `Event.wait(timeout=None)`. We use a 60 s ceiling
(`_IDLE_WAKEUP__SEC = 60.0`) as a heartbeat so:
- The stop event is checked at least every minute even
  on a completely idle stack.
- Unit tests using a real Timer (rare) don't hang.

### 5.4 New public API

```python
class Timer(Subsystem):
    def call_later(
        self,
        delay_ms: int,
        method: Callable[..., None],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> TimerHandle:
        """
        Schedule 'method(*args, **kwargs)' to fire once after
        'delay_ms' milliseconds. Returns a cancellation handle.
        """

    def call_periodic(
        self,
        period_ms: int,
        method: Callable[..., None],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> TimerHandle:
        """
        Schedule 'method(*args, **kwargs)' to fire every
        'period_ms' milliseconds, starting 'period_ms' from
        now. Returns a cancellation handle.
        """

    def cancel(self, handle: TimerHandle, /) -> None:
        """
        Mark 'handle' as cancelled. The worker drops it on
        the next pop. No-op if already cancelled.
        """

    @property
    def now_ms(self) -> int:
        """Unchanged — monotonic milliseconds."""
```

### 5.5 Legacy shims (Phase 1, removed Phase 4)

```python
def register_method(self, *, method, args=None, kwargs=None, delay=1,
                    delay_exp=False, repeat_count=-1, stop_condition=None) -> None:
    """
    LEGACY. Shim over call_later / call_periodic.

    - 'delay_exp' must be False (asserted; no production caller).
    - 'stop_condition' must be None (asserted; no production caller).
    - 'repeat_count' must be -1 (periodic) or 0 (one-shot); asserted.

    Stores the handle on a private '_legacy_method_handles' dict
    keyed by 'method' so 'unregister_method' can find it. Multiple
    registrations of the same method append.
    """

def register_timer(self, *, name, timeout) -> None:
    """
    LEGACY. Shim over call_later that sets a flag instead of
    invoking a method.

    Maintains a '_legacy_named_flags: dict[str, TimerHandle]'.
    'is_expired' reads this dict.
    """

def is_expired(self, name) -> bool:
    """
    LEGACY. True iff name unregistered OR the corresponding
    timer has already fired (cleared its flag).
    """

def unregister_method(self, method) -> None:
    """
    LEGACY. Cancels every TimerHandle stored under 'method'
    in '_legacy_method_handles'.
    """

def unregister_timers_with_prefix(self, prefix) -> None:
    """
    LEGACY. Cancels every TimerHandle in '_legacy_named_flags'
    whose name starts with 'prefix'.
    """
```

### 5.6 Migration from `delay_exp` and `repeat_count`

- **`delay_exp`**: not used in production. Drop. Assert in shim.
- **`stop_condition`**: not used in production. Drop. Assert in shim.
- **`repeat_count`**: production uses only `-1` and `0`. The
  shim maps:
  - `repeat_count == -1` → `call_periodic(delay_ms=delay, ...)`
  - `repeat_count == 0` → `call_later(delay_ms=delay, ...)`
  - Any other value → AssertionError.

### 5.7 Why `(deadline_ms, seq)` not `(deadline_ms,)` for the heap key

`heapq` is **not stable** — entries with equal keys come
out in arbitrary order. For deterministic test behaviour
(critical for `FakeTimer.advance(ms=N)` semantics where
many timers can hit the same deadline), we add a per-Timer
monotonic `seq` counter that breaks ties FIFO.

### 5.8 Race / safety analysis

Threading model:
- One worker thread (the `Subsystem` thread) does the
  heap pop + callback dispatch + wait.
- Many caller threads (TCP session threads, packet
  handlers, `stack.stop()`) call `call_later` /
  `call_periodic` / `cancel`.

Protected by `self._lock` (RLock):
- `self._heap` mutation: push (caller), pop (worker).
- `self._next_seq()`: read/increment.
- `self._legacy_method_handles` (shim): read/write.
- `self._legacy_named_flags` (shim): read/write.

NOT protected (intentional):
- Callback invocation (worker drops lock before calling).
  A callback re-acquiring the lock via `call_later` is
  fine (RLock).
- `handle.cancelled` write by `cancel()` is unprotected
  (single boolean attribute write is atomic in CPython).
  Worker reads `entry.handle.cancelled` after `heappop` —
  may see stale `False`, will invoke the callback once.
  Acceptable.

`self._wakeup` is the cross-thread signal:
- Caller: `self._wakeup.set()` after every push/cancel.
- Worker: `self._wakeup.wait(timeout=...)` then `clear()`.

The set/wait race: if worker computes `wait_s` from
current heap, then before `wait()` a caller pushes a
shorter-deadline entry + `set()`, the worker's `wait()`
returns immediately (Event was set). Correct.

## 6. File-by-file changes

### 6.1 `pytcp/runtime/timer.py` — rewrite

Full replacement. Old `TimerTask` + tick-decrement logic
deleted. New file:

- Module constants: `_IDLE_WAKEUP__SEC = 60.0`.
- Public types: `TimerHandle` (frozen=False, slots, default
  `cancelled=False`).
- Internal types: `_HeapEntry` (order=True, slots,
  compare-by-(deadline_ms, seq)).
- `Timer(Subsystem)` with the new API (§5.4) + legacy
  shims (§5.5) + the worker loop (§5.2).

Line budget: ~250 lines including legacy shims, vs. ~260
in the current file. Net neutral.

### 6.2 `pytcp/tests/lib/fake_timer.py` — rewrite

Existing FakeTimer maintains parallel `_tasks` + `_timers`
matching the legacy Timer's structure. New FakeTimer
maintains the same heap-based core as the real Timer but
swaps the worker thread for a deterministic
`advance(ms: int)` method that pops + dispatches all
entries with `deadline_ms <= self._now_ms + ms` in
deadline order.

Must support both the legacy API (so existing TCP
integration tests continue to work) AND the new API (so
new tests can use it directly).

Critical: `FakeTimer.advance(ms=N)` semantics MUST match
the production Timer's behaviour at the granularity of
"fire all callbacks with deadlines ≤ now + ms, in
deadline order, with periodics rescheduling at exact
absolute deadlines." This is the heart of TCP integration
test determinism.

Edge case: a callback inside `advance()` calls
`call_later(delay_ms=0, ...)`. The new handle has
`deadline_ms = self._now_ms` which is `<= now + ms` so
it fires in the same `advance()` call. Match production
behaviour (where the worker re-pops a 0-delay entry on
the next loop iteration almost immediately).

### 6.3 `pytcp/tests/unit/runtime/test__runtime__timer.py` — rewrite

Existing tests cover the old `TimerTask` tick logic, the
old `_tasks` / `_timers` mutation paths, and the §7.2
`Reference:` lines added in commit `fd6db020`. After the
rewrite:

- Delete tests for: `delay_exp`, `stop_condition`, finite
  `repeat_count`, `TimerTask.tick`-as-an-isolated-unit.
- Keep / port: `now_ms` (3 tests), `is_expired` semantics
  (3 tests; via legacy shim), `register_timer` /
  `register_method` registration (2 tests; via legacy
  shim).
- New tests for the new API: `call_later`, `call_periodic`,
  `cancel`, handle reuse, simultaneous deadlines, deadlines
  in the past, idle wakeup cap, callback exception
  isolation, lock-free callback dispatch (reentrant
  registration from inside a callback).
- New tests for the legacy shim: `repeat_count != -1, 0`
  asserts, `delay_exp=True` asserts, `stop_condition`
  asserts, `unregister_method` correctly cancels all
  handles for a method, `unregister_timers_with_prefix`
  matches by prefix.

Target: 100% line coverage on the new `timer.py` and full
§7.2 audit compliance.

### 6.4 Consumer migrations (Phase 3)

**`pytcp/protocols/tcp/tcp__session.py`** — line 488 and
line 950:
```python
# OLD
self.stack.timer.register_method(method=self.tcp_fsm, kwargs={"timer": True})
# ... later ...
self.stack.timer.unregister_method(self.tcp_fsm)

# NEW
self._tcp_fsm_handle = self.stack.timer.call_periodic(
    1, self.tcp_fsm, timer=True
)
# ... later ...
self.stack.timer.cancel(self._tcp_fsm_handle)
```

**`pytcp/runtime/packet_handler/packet_handler__icmp6__rx.py`**
— line 1271 and 1275:
```python
# OLD
stack.timer.unregister_method(self._mld2_query__deferred_send)
# ...
stack.timer.register_method(
    method=self._mld2_query__deferred_send,
    delay=delay_ms,
    repeat_count=0,
)

# NEW
if self._mld2_query__handle is not None:
    stack.timer.cancel(self._mld2_query__handle)
self._mld2_query__handle = stack.timer.call_later(
    delay_ms, self._mld2_query__deferred_send
)
```

The 24+ `register_timer` / `is_expired` /
`unregister_timers_with_prefix` call sites in
`pytcp/protocols/tcp/` STAY on the legacy shim
through this plan. Migrating them to event-driven
callbacks is a follow-up.

### 6.5 Documentation updates (Phase 5)

- `.claude/rules/pytcp.md` — update §3 ("The `Subsystem`
  base class") if it mentions `time.sleep` semantics.
  Update §2 if it references `register_method`'s legacy
  shape.
- `docs/refactor/timer_rewrite_plan.md` — flip Status
  field to "Shipped" with commit SHAs.
- `MEMORY.md` — add a `project_timer_rewrite.md` entry.

## 6a. Detailed unit test plan

Concrete inventory of every test method to add/keep/delete
in Phases 1 and 2. Each row names the test, the assertion
shape, and the fixture/patch setup. Every test uses
`unittest.TestCase` (no pytest). Every test docstring
follows `unit_testing.md` §7 — opens with `Ensure ...` +
trailing `Reference: PyTCP test infrastructure (no RFC clause).`
line (every test in this domain is plumbing — no RFC clause
applies). All file paths assume the canonical
`pytcp/tests/unit/runtime/test__runtime__timer.py`.

### 6a.1 Tests to DELETE in Phase 1

Currently 29 tests in
`pytcp/tests/unit/runtime/test__runtime__timer.py` (post
commit `fd6db020`). The following 9 test `TimerTask`
internals or dropped features:

| Test | Why drop |
|------|----------|
| `test__timer__task_tick_decrements_remaining_delay` | TimerTask no longer exists |
| `test__timer__task_tick_invokes_method_at_zero` | TimerTask no longer exists |
| `test__timer__task_tick_not_yet_at_zero_skips_method` | TimerTask no longer exists |
| `test__timer__task_tick_stop_condition_aborts_countdown` | `stop_condition` dropped |
| `test__timer__task_tick_infinite_repeat_resets_delay` | TimerTask no longer exists |
| `test__timer__task_tick_finite_repeat_decrements` | Finite `repeat_count` dropped |
| `test__timer__task_tick_exponential_backoff` | `delay_exp` dropped |
| `test__timer__non_exp_task_does_not_grow_factor` | `delay_exp` dropped |
| `test__timer__exp_task_grows_factor_each_iteration` | `delay_exp` dropped |
| `test__timer__task_delay_negative_rejected` | TimerTask no longer exists — but: keep an equivalent test on `register_method(delay=-1)` shim asserting through to AssertionError |

### 6a.2 Tests to KEEP unchanged (8)

These exercise the legacy shim's public contract; the shim
delegates to the new core but the contract is unchanged.

| Test | Setup | Assertion |
|------|-------|-----------|
| `test__timer__register_timer_stores_timeout` | `Timer()` + log patch; `register_timer(name="x", timeout=5)` | `timer._legacy_named_flags["x"]` corresponds to a non-cancelled handle (replace internal-state probe with public `is_expired("x") is False`) |
| `test__timer__is_expired_true_for_missing` | fresh Timer | `timer.is_expired("never_registered") is True` |
| `test__timer__is_expired_false_while_counting_down` | `register_timer(name="x", timeout=10)`, no advance | `timer.is_expired("x") is False` |
| `test__timer__is_expired_true_after_timeout_zeroed` | register, advance past deadline via patched `now_ms` | `timer.is_expired("x") is True` |
| `test__timer__register_method_appends_task` | `register_method(method=m, delay=5)` | `m` is scheduled (one handle exists in `_legacy_method_handles[m]`) |
| `test__timer__register_method_defaults` | `register_method(method=m)` with no other kwargs | default `delay=1`, `repeat_count=-1` resolves to `call_periodic(period_ms=1, method=m)` |
| `test__timer__register_timer_timeout_zero_rejected` | n/a | `register_timer(name="x", timeout=0)` raises `AssertionError` ("timeout must be >= 1") |
| `test__timer__task_delay_zero_rejected` | rename to `test__timer__register_method_delay_zero_rejected` | `register_method(method=m, delay=0)` raises `AssertionError` ("delay must be >= 1") |

### 6a.3 Tests to KEEP with semantic adjustment (3)

`now_ms` tests — already covered the contract well; keep
verbatim:
- `test__timer__now_ms_returns_int`
- `test__timer__now_ms_is_monotonic`
- `test__timer__now_ms_uses_monotonic_ns`

### 6a.4 Tests to PORT (rewrite, same intent) (4)

The legacy `_subsystem_loop` tests need to migrate. The
new loop pops + dispatches + waits — the assertions
change shape but the intent (registered methods fire,
named timers decrement, finished tasks are purged) carries
forward via the shim. Reuse the same test names but
rebuild the bodies:

| Test | New body (sketch) |
|------|-------------------|
| `test__timer__loop_decrements_registered_timers` | Replace direct `_timers` decrement assertion with: register a 10 ms timer, patch `now_ms` to advance 5 ms, drive one `_subsystem_loop` iteration via a controlled `_wakeup.set()`, assert `is_expired("x") is False`. Then patch `now_ms` to 11 ms, drive another iteration, assert `is_expired("x") is True`. |
| `test__timer__loop_purges_expired_timers` | After the test above, assert the internal `_legacy_named_flags` no longer has an entry (purged on fire). |
| `test__timer__loop_ticks_registered_tasks` | Register a method via `call_periodic(period_ms=5, ...)`, patch `now_ms` to advance, drive one loop iteration, assert the method was called once. |
| `test__timer__loop_purges_finished_tasks` | Register a one-shot via `call_later(delay_ms=5, ...)`, advance, drive loop, assert the heap is empty afterwards. |

### 6a.5 NEW tests — core API (`call_later`, `call_periodic`, `cancel`) (15)

The heart of the new test surface. Every test patches
`pytcp.runtime.subsystem.log` to silence init logs and
either patches `time.monotonic_ns` (for deterministic
clock) or uses a custom `_advance_clock(ms)` helper that
overwrites the patched return value.

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 1 | `test__timer__call_later_returns_handle` | `Timer()` | `handle = timer.call_later(100, method)` returns a `TimerHandle` instance with `cancelled is False`, `period_ms is None`, `deadline_ms == now_ms + 100`. |
| 2 | `test__timer__call_periodic_returns_handle` | as above | `handle = timer.call_periodic(50, method)` returns `TimerHandle` with `period_ms == 50`, `cancelled is False`, `deadline_ms == now_ms + 50`. |
| 3 | `test__timer__call_later_zero_delay_fires_immediately` | patch `now_ms` to 1000; `call_later(0, m)` | run one loop iteration; `m` was called once. |
| 4 | `test__timer__call_later_in_the_past_fires_immediately` | patch `now_ms` to 1000; manually push entry with `deadline_ms=500` | one loop iteration → `m` called once. |
| 5 | `test__timer__cancel_prevents_firing` | `handle = call_later(100, m); cancel(handle)`; advance clock past 100 | `m` was NEVER called. |
| 6 | `test__timer__cancel_is_idempotent` | `cancel(handle); cancel(handle)` | no exception; `handle.cancelled is True` after both. |
| 7 | `test__timer__cancel_after_fire_is_noop` | call_later, advance, fire, then cancel | no exception; flag set; one fire only. |
| 8 | `test__timer__call_periodic_fires_repeatedly` | `call_periodic(50, m)`, advance clock 200 ms across multiple loop drives | `m.call_count == 4` (fires at 50, 100, 150, 200). |
| 9 | `test__timer__call_periodic_reschedules_at_absolute_deadline` | `call_periodic(50, m)`, advance to 60 ms (past first deadline), drive loop, advance to 110 ms | second fire at deadline 100 not deadline 110 (no drift). |
| 10 | `test__timer__cancel_periodic_stops_reschedule` | `handle = call_periodic(50, m)`, drive 1 fire, `cancel(handle)`, advance + drive | `m.call_count == 1` after all advances. |
| 11 | `test__timer__same_deadline_fires_in_registration_order` | `m1 = MagicMock(); m2 = MagicMock(); m3 = MagicMock(); call_later(50, m1); call_later(50, m2); call_later(50, m3)`; advance + drive | `mock_calls` order is `[m1(), m2(), m3()]`. |
| 12 | `test__timer__multiple_deadlines_fire_in_deadline_order` | `call_later(100, m_late); call_later(50, m_early); call_later(75, m_mid)`; advance to 100 + drive | `mock_calls` order is `[m_early(), m_mid(), m_late()]`. |
| 13 | `test__timer__callback_invokes_call_later_reentrantly` | callback body: `timer.call_later(50, inner_m)`; advance + drive twice | inner_m fired once. |
| 14 | `test__timer__callback_exception_isolated` | `m1.side_effect = RuntimeError("boom"); m2 = MagicMock()`; both at same deadline | both fire; `m2` was called despite `m1` raising; loop didn't crash; log("timer", "Handler raised: m1") emitted. |
| 15 | `test__timer__handle_reuse_across_periodics` | `handle = call_periodic(50, m)`; drive 3 fires; verify `handle.deadline_ms` advances each cycle but the same handle object is returned by `call_periodic` (NOT a new handle per cycle). |

### 6a.6 NEW tests — worker loop + wakeup semantics (6)

These test the Subsystem-thread machinery: the worker
wakes on registration, blocks on `Event.wait`, computes
the correct wait timeout.

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 1 | `test__timer__worker_blocks_on_empty_heap` | `Timer()` started, no registrations | `_wakeup.is_set() is False`; thread is alive but not consuming CPU (verified by checking the heap pop count stays at 0 across a 100 ms real sleep) |
| 2 | `test__timer__register_wakes_worker` | `Timer()` started, empty heap; `call_later(10, m)` from main thread | worker wakes within 50 ms of registration and fires `m` after ~10 ms total |
| 3 | `test__timer__cancel_wakes_worker_if_top` | register entry deadline=100ms, cancel before it fires, check that the worker correctly re-computes next deadline. Optional optimisation — current design lets the worker fire-and-skip; this test pins that semantic. |
| 4 | `test__timer__idle_wakeup_ceiling` | empty heap; mock `_IDLE_WAKEUP__SEC = 0.05`; start worker | verify `_wakeup.wait()` was called with `timeout=0.05` (probe `mock_event.wait.call_args`). |
| 5 | `test__timer__stop_breaks_out_of_wait` | `Timer()` started, no registrations; `stop()` from main | `stop()` returns within ~100 ms; thread state is dead. |
| 6 | `test__timer__simultaneous_register_during_dispatch` | callback registers a new entry while inside dispatch loop | new entry is on the heap after the current dispatch batch completes; fires on next iteration. |

### 6a.7 NEW tests — thread safety (3)

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 1 | `test__timer__concurrent_register_no_loss` | 100 caller threads each calling `call_later(0, m)` once; worker runs in parallel | every registration eventually fires; `m.call_count == 100`. |
| 2 | `test__timer__concurrent_cancel_no_double_fire` | `call_periodic(1, m)`; spawn 10 threads each calling `cancel(handle)` concurrently | `m.call_count` does not exceed an upper bound (verified by sampling at a deterministic later wall-time); no exception. |
| 3 | `test__timer__lock_held_during_heap_mutation_not_callback` | callback body: `time.sleep(0.05); register inside`; advance + drive | second registration succeeded (lock was released during callback). |

### 6a.8 NEW tests — legacy shim correctness (8)

The shim layer is where most current consumers live. Pin
the contract carefully.

| # | Test | Setup | Assertion |
|---|------|-------|-----------|
| 1 | `test__timer__register_method_repeat_count_minus_one_maps_to_periodic` | mock `Timer.call_periodic`; `register_method(method=m, delay=5, repeat_count=-1)` | `call_periodic` was called once with `period_ms=5, m`. |
| 2 | `test__timer__register_method_repeat_count_zero_maps_to_call_later` | mock `Timer.call_later`; `register_method(method=m, delay=5, repeat_count=0)` | `call_later` was called once with `delay_ms=5, m`. |
| 3 | `test__timer__register_method_finite_repeat_rejected` | `register_method(method=m, repeat_count=3)` | raises `AssertionError("repeat_count must be -1 or 0")`. |
| 4 | `test__timer__register_method_delay_exp_rejected` | `register_method(method=m, delay_exp=True)` | raises `AssertionError("delay_exp not supported")`. |
| 5 | `test__timer__register_method_stop_condition_rejected` | `register_method(method=m, stop_condition=lambda: True)` | raises `AssertionError("stop_condition not supported")`. |
| 6 | `test__timer__unregister_method_cancels_all_handles_for_method` | register the same method 3× via `register_method(method=m)`; `unregister_method(m)` | all 3 handles have `cancelled is True`; the `_legacy_method_handles[m]` list is cleared. |
| 7 | `test__timer__unregister_timers_with_prefix_cancels_matching` | register 3 named timers `s1-a, s1-b, other`; `unregister_timers_with_prefix("s1-")` | handles for `s1-a` and `s1-b` are cancelled; `other` survives. |
| 8 | `test__timer__is_expired_when_handle_fires` | `register_timer(name="x", timeout=5)`; advance + drive past 5 ms | `is_expired("x") is True` (flag-clear hook fires when the timer pops). |

### 6a.9 NEW tests — TimerHandle dataclass (3)

| # | Test | Assertion |
|---|------|-----------|
| 1 | `test__timer_handle__has_slots` | `TimerHandle` has `__slots__` defined; `handle.foo = 1` raises `AttributeError` |
| 2 | `test__timer_handle__cancelled_starts_false` | freshly-constructed handle has `cancelled is False` |
| 3 | `test__timer_handle__period_ms_none_means_one_shot` | dataclass default `period_ms=None` |

### 6a.10 Test count totals

| Category | Count |
|----------|-------|
| Deleted in Phase 1 | 9 |
| Kept verbatim | 8 |
| Kept (now_ms unchanged) | 3 |
| Ported (same names, new bodies) | 4 |
| New: core API | 15 |
| New: worker loop + wakeup | 6 |
| New: thread safety | 3 |
| New: legacy shim | 8 |
| New: TimerHandle | 3 |
| **Total after Phase 1** | **50** (was 29; net +21) |

### 6a.11 FakeTimer test plan (Phase 2)

The FakeTimer rewrite lands its own test file at
`pytcp/tests/unit/lib/test__lib__fake_timer.py`. Currently
this file does not exist (FakeTimer's coverage is
incidental, via TCP integration tests using
`advance(ms=N)`). Phase 2 adds direct tests:

| # | Test | Assertion |
|---|------|-----------|
| 1 | `test__fake_timer__now_ms_starts_at_zero` | new instance has `now_ms == 0` |
| 2 | `test__fake_timer__advance_increments_now_ms` | `advance(ms=100)` makes `now_ms == 100` |
| 3 | `test__fake_timer__advance_negative_rejected` | `advance(ms=-1)` raises AssertionError |
| 4 | `test__fake_timer__call_later_fires_at_advance` | `call_later(50, m); advance(50)` → m called once |
| 5 | `test__fake_timer__call_later_does_not_fire_before_deadline` | `call_later(50, m); advance(49)` → m never called |
| 6 | `test__fake_timer__same_deadline_fires_in_registration_order` | `call_later(50, m1); call_later(50, m2); advance(50)` → m1 before m2 |
| 7 | `test__fake_timer__advance_fires_periodics_multiple_times` | `call_periodic(50, m); advance(150)` → m.call_count == 3 |
| 8 | `test__fake_timer__advance_partial_period_keeps_handle_live` | `call_periodic(50, m); advance(25)` → m never called; advance(25) more → m called once |
| 9 | `test__fake_timer__cancel_prevents_fire` | `handle = call_later(50, m); cancel(handle); advance(100)` → m never called |
| 10 | `test__fake_timer__callback_can_call_later_during_advance` | callback body: `fake_timer.call_later(0, inner_m); advance(50)` (first fire registers inner; inner fires later in same advance) → inner_m called once |
| 11 | `test__fake_timer__legacy_register_method_periodic_form` | `register_method(method=m, delay=10, repeat_count=-1); advance(30)` → m.call_count == 3 |
| 12 | `test__fake_timer__legacy_register_method_oneshot_form` | `register_method(method=m, delay=10, repeat_count=0); advance(20)` → m.call_count == 1 |
| 13 | `test__fake_timer__legacy_register_timer_and_is_expired` | `register_timer(name="x", timeout=10); is_expired("x") is False; advance(10); is_expired("x") is True` |
| 14 | `test__fake_timer__legacy_unregister_method` | register m twice; `unregister_method(m); advance(50)` → m never called |
| 15 | `test__fake_timer__legacy_unregister_timers_with_prefix` | register `s1-a`, `s1-b`, `other`; `unregister_timers_with_prefix("s1-"); advance(...); is_expired("s1-a") is True; is_expired("other") is True (after its own advance)` |

Plus the §7.2 docstring audit on every new test.

### 6a.12 Per-test fixture patterns

Every new test follows one of these three shapes:

**Shape A — pure unit test (no Subsystem thread):**
```python
class TestTimerCallLater(TestCase):
    def setUp(self) -> None:
        self._log_patch = patch("pytcp.runtime.subsystem.log")
        self._log_patch.start()
        self.addCleanup(self._log_patch.stop)
        self._timer_log_patch = patch("pytcp.runtime.timer.log")
        self._timer_log_patch.start()
        self.addCleanup(self._timer_log_patch.stop)
        self._timer = Timer()
```

**Shape B — clock-controlled (no worker thread):**
```python
class TestTimerDispatch(TestCase):
    def setUp(self) -> None:
        # ... same log patches ...
        self._now_ns = 1_000_000_000_000  # 1 sec
        self._monotonic_patch = patch(
            "pytcp.runtime.timer.time.monotonic_ns",
            side_effect=lambda: self._now_ns,
        )
        self._monotonic_patch.start()
        self.addCleanup(self._monotonic_patch.stop)
        self._timer = Timer()

    def _advance(self, ms: int) -> None:
        self._now_ns += ms * 1_000_000

    def _drive_loop(self) -> None:
        # Manually invoke one iteration of _subsystem_loop
        # without spawning the worker thread. Stop event
        # check inside _subsystem_loop must return True
        # after one iteration so the function returns.
        self._timer._event__stop_subsystem.set()
        self._timer._subsystem_loop()
        self._timer._event__stop_subsystem.clear()
```

**Shape C — full lifecycle (real worker thread):**
```python
class TestTimerLifecycle(TestCase):
    def setUp(self) -> None:
        self._log_buf = io.StringIO()
        self._log_patch = patch("pytcp.stack.LOG__OUTPUT", self._log_buf)
        self._log_patch.start()
        self.addCleanup(self._log_patch.stop)

    def tearDown(self) -> None:
        # Drain any worker thread the test left running.
        for thread in list(threading.enumerate()):
            if thread is threading.main_thread() or thread is threading.current_thread():
                continue
            thread.join(timeout=2.0)
```

Shape A is the default. Shape B for any test that needs
to advance the clock or dispatch entries deterministically.
Shape C only for the thread-safety + lifecycle tests
(§6a.6 + §6a.7).

### 6a.13 Mocking discipline

Per `unit_testing.md` §6a:
- Every Mock is `create_autospec(Cls, spec_set=True)` or
  `patch(..., autospec=True, spec_set=True)`.
- Methods passed to `register_method` /
  `call_later` use `MagicMock()` only if they need
  call-tracking; otherwise use a plain function.
- Bound methods for `register_method` tests: define
  small `_TestCallback` class with `__call__` and
  per-instance call counter so bound-method equality
  semantics are tested explicitly.

### 6a.14 Coverage target

Phase 1 must land with `pytcp/runtime/timer.py` at 100%
line coverage. Coverage is measured via:

```bash
PYTHONPATH=. coverage run --source=pytcp.runtime.timer \
    -m unittest pytcp.tests.unit.runtime.test__runtime__timer
coverage report -m
```

If any line is uncovered, the corresponding test gap is
a blocker for the Phase 1 commit.

Phase 2 must land with `pytcp/tests/lib/fake_timer.py` at
100% line coverage measured against the new
`test__lib__fake_timer.py`.

### 6a.15 §7.2 docstring audit gate

Every new test file passes the audit script from
`unit_testing.md` §7.2 (recently used in commits
`44441a5d`, `fd6db020`, `465d1560`). Specifically:
- Every test method docstring starts with `Ensure `.
- Every test method docstring ends with
  `Reference: PyTCP test infrastructure (no RFC clause).`
  on its own trailing line.
- No `[FLAGS BUG]` markers.
- No inline `Per RFC X §Y` / `RFC X §Y` citation in the
  description body.

The audit script is non-negotiable; treat any non-empty
output as a blocker for the commit.

## 7. Phase plan

Each phase ends with `make lint && make test` clean.
Phase boundaries are commit boundaries.

### Phase 0 — This plan (no code)

Commit this plan doc. Lock the design (heap + Event, lazy
cancel, drop dead features). Open with confirmation that
no consumer needs `delay_exp` / `stop_condition` / finite
`repeat_count` — confirmed in §4.

### Phase 1 — New core + legacy shims

Rewrite `pytcp/runtime/timer.py` with:
- New `Timer.call_later` / `.call_periodic` / `.cancel` /
  `.now_ms` (§5.4).
- Legacy `register_method` / `register_timer` / `is_expired`
  / `unregister_method` / `unregister_timers_with_prefix`
  shims (§5.5).

All existing consumers see the legacy API; their wire-level
behaviour is unchanged. Tests pass through the shims.

Commit message scope: `pytcp.runtime.timer: heap-based
scheduler with event-driven wakeup (Phase 1 of timer
rewrite)`.

Risk: Phase 1's test suite is the existing 29-test
`test__runtime__timer.py`. Some tests test the legacy
`TimerTask` directly (e.g. `test__timer__task_tick_*`);
those must be ported or deleted because `TimerTask` no
longer exists. Plan: delete the `TimerTask`-internal
tests in Phase 1 (they test implementation, not contract).
Keep all `register_method` / `register_timer` / `is_expired`
end-to-end tests since they exercise the shim contract.

### Phase 2 — FakeTimer rewrite

Rewrite `pytcp/tests/lib/fake_timer.py` to:
- Maintain a heap matching the production Timer.
- Expose both the new API (call_later/call_periodic/cancel)
  and the legacy shim API.
- `advance(ms: int)` deterministically pops + invokes all
  entries with `deadline_ms <= self._now_ms + ms` in
  `(deadline_ms, seq)` order, rescheduling periodics
  inline.

Critical: this is the riskiest phase for the integration
suite. Every TCP integration test that calls
`fake_timer.advance(ms=N)` MUST observe the same fire
sequence and timing as before.

Validation: full `make test` clean (10970+ tests). If any
integration test fails, the FakeTimer semantics drifted.

Commit message: `pytcp.tests.lib.fake_timer: heap-based
deterministic clock (Phase 2 of timer rewrite)`.

### Phase 3 — Consumer migration (2 sites)

Migrate the 2 production `register_method` / `unregister_method`
call sites to `call_periodic` / `call_later` / `cancel`
(see §6.4):

- `pytcp/protocols/tcp/tcp__session.py` — TCP FSM periodic.
- `pytcp/runtime/packet_handler/packet_handler__icmp6__rx.py`
  — MLD2 one-shot.

Add a `TimerHandle | None` instance attribute on each
consumer to hold the handle for cancellation.

Update unit tests for both consumers.

The 24+ `register_timer` / `is_expired` call sites stay
on the legacy shim. Not migrated in this plan.

Commit message: `pytcp.protocols + runtime: migrate
register_method consumers to call_later / call_periodic
(Phase 3 of timer rewrite)`.

### Phase 4 — Drop unused legacy shims

After Phase 3, the legacy `register_method` /
`unregister_method` shim no longer has any consumer (all
2 migrated). Delete:

- `Timer.register_method` and its `_legacy_method_handles` dict.
- `Timer.unregister_method`.
- `FakeTimer.register_method` and `unregister_method`.

The `register_timer` / `is_expired` /
`unregister_timers_with_prefix` shims STAY — their 24+
consumers haven't migrated.

Commit message: `pytcp.runtime.timer: drop register_method
shim — all callers migrated (Phase 4 of timer rewrite)`.

### Phase 5 — Documentation + rules sweep

- `.claude/rules/pytcp.md` — update timer references if
  any.
- `docs/refactor/timer_rewrite_plan.md` — Status →
  Shipped.
- `MEMORY.md` — add `project_timer_rewrite.md` entry.

Commit message: `docs: timer rewrite shipped (Phase 5)`.

## 8. Validation gates

Each phase MUST pass before commit:

1. `make lint` — codespell + isort + black + flake8 + mypy
   strict + pylint.
2. `make test` — full suite. Currently 10970 passing /
   4 skipped / 0 failures. The Phase 1 commit removes
   ~7 TimerTask-internal tests (`test__timer__task_tick_*`,
   `delay_exp`, `stop_condition`, finite `repeat_count`)
   so the total drops by ~7. Phase 2 + 3 should not
   reduce the count further.
3. §7.2 docstring audit on every new test file.
4. Per-phase coverage check on `pytcp/runtime/timer.py`
   stays at 100%.

## 9. Risks and mitigations

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| FakeTimer semantics drift breaks integration tests | High | Phase 2 lands FakeTimer separately from any new test additions; run full integration suite immediately after the FakeTimer commit. If any test fails, the production semantics changed too — pinpoint and roll back. |
| Heap pop ordering is non-deterministic in tests | Medium | `(deadline_ms, seq)` tiebreaker via monotonic `_next_seq()` makes ordering deterministic. Add a test asserting two timers registered at the same deadline fire in registration order. |
| Lock release during callback enables re-entrancy bugs | Medium | RLock allows the same thread to re-enter. Add a test where a callback calls `call_later` and verify the new entry fires on the next wakeup. |
| Idle-wakeup cap of 60 s is too aggressive / too lax | Low | 60 s matches the worst-case stop-event-check latency on a fully idle stack. Existing stack.stop() callers tolerate seconds, not minutes. If problems surface, tune. |
| `cancel(handle)` race: callback already fired, then cancel called | Low | `cancel(handle)` sets `handle.cancelled = True` regardless. If the callback already ran, the flag is a no-op (the handle has been popped from the heap; no re-pop happens for one-shots). For periodics, the next reschedule pushes a fresh entry that already sees `cancelled = True` and skips. |
| Consumers store handles incorrectly (handle goes out of scope) | Medium | Document the contract: `call_later` returns a handle the caller MUST store if they want to cancel. Garbage collection of the handle does NOT cancel — the entry remains on the heap. Same as `asyncio.call_later`. |
| `delay_ms=0` semantics | Medium | New API allows `delay_ms=0` (fires on the next worker iteration, basically immediately). Document this. The legacy shim's `register_method(delay=0)` asserts → AssertionError; the new API does not. |
| Thread safety bug in heap mutation | Medium | All push/pop under RLock; `cancel` is a flag write (CPython atomic). Add a thread-safety unit test that hammers `call_later` from N threads while the worker dispatches. |

## 10. Rollback procedure

Each phase commits independently. To roll back:

- Phase 1: `git revert <phase-1-sha>`. Restores the
  tick-based timer; Phase 2/3 commits must be reverted
  first (they depend on Phase 1's API surface).
- Phase 2: `git revert <phase-2-sha>`. Restores the
  legacy FakeTimer.
- Phase 3: `git revert <phase-3-sha>`. Restores the
  legacy `register_method` consumers; legacy shim still
  works.
- Phase 4: `git revert <phase-4-sha>`. Restores the legacy
  `register_method` shim.

`make test` validates each revert.

## 11. Estimated effort

| Phase | Engineering | Review | Risk |
|-------|-------------|--------|------|
| 0 (plan + this doc)          | ~2 h    | ~30 min | None |
| 1 (heap core + shims)        | ~6 h    | ~2 h    | Medium |
| 2 (FakeTimer rewrite)        | ~5 h    | ~2 h    | High |
| 3 (2 consumer migrations)    | ~2 h    | ~30 min | Low |
| 4 (drop register_method shim)| ~1 h    | ~15 min | Low |
| 5 (docs + close-out)         | ~1 h    | ~15 min | None |
| **Total**                    | **~17 h** | **~5 h** | **Medium-High** |

Could land in 2 focused sessions if Phase 2's
test-determinism work doesn't surface integration-suite
fallout.

## 12. Out-of-scope follow-ups

- **`register_timer` / `is_expired` migration to callback
  form.** ~24 TCP session call sites. Big refactor;
  separate plan.
- **Coalescing.** If timer wakeups become a hot spot,
  group nearby deadlines.
- **Per-task threads.** If a callback blocks the worker
  for too long, hoist to a thread pool.
- **`is_expired` legacy semantics drift.** The current
  API returns `True` for an unknown name (collapses
  "never registered" with "expired"). The shim preserves
  this. Documented in §4.4.
- **Future Phase-2 (router) demands** — many more
  concurrent timers (per-flow PMTUD probes, NUD timers,
  route-cache GC). The heap design scales; this plan
  doesn't need revision.

## 13. Resumption prompt

**Use this prompt to start (or restart) the timer rewrite
work in a fresh agent session.** It is intentionally
verbose so the agent doesn't need to re-derive design
choices.

```
I want you to execute the PyTCP timer rewrite per the plan
at docs/refactor/timer_rewrite_plan.md.

Read the entire plan first. Then proceed phase by phase:

- Phase 0 is already done — the plan was committed at SHA
  <fill in after Phase 0 lands>.
- Phase 1 next: rewrite pytcp/runtime/timer.py with the
  heap-based core (§5.1, §5.2) + the legacy shims (§5.5).
  Test work in Phase 1 is COMPLETELY SPECIFIED in §6a —
  follow it exactly. §6a.1 names the 9 tests to delete,
  §6a.2 the 8 tests to keep verbatim, §6a.3 the 3 now_ms
  tests to keep, §6a.4 the 4 loop tests to port, and
  §6a.5-§6a.9 enumerate 38 NEW test methods covering:
  core API (15 tests — call_later, call_periodic, cancel,
  deterministic ordering, callback exception isolation,
  reentrant registration, handle reuse), worker loop +
  wakeup semantics (6), thread safety (3), legacy shim
  correctness (8), and TimerHandle dataclass (3). §6a.10
  shows the totals (50 tests after Phase 1, was 29).
  §6a.12 documents the three setUp/tearDown shapes
  (pure unit, clock-controlled via patched
  time.monotonic_ns, full lifecycle with real worker
  thread); pick the right one per test category. §6a.13
  enforces create_autospec + MagicMock discipline.
  §6a.14 requires 100% line coverage on the rewritten
  timer.py. §6a.15 the §7.2 docstring audit (Reference:
  line, Ensure opener, no inline RFC citations).
- Phase 2: rewrite pytcp/tests/lib/fake_timer.py to match
  the production heap-based Timer (§6.2). CRITICAL: every
  TCP integration test calling fake_timer.advance(ms=N)
  must observe the same fire sequence as before. Run the
  full integration suite immediately after the FakeTimer
  commit and roll back if anything fails. Phase 2 also
  adds a NEW pytcp/tests/unit/lib/test__lib__fake_timer.py
  with 15 direct tests (currently FakeTimer's coverage
  is incidental via TCP integration tests); §6a.11 lists
  all 15 test names, intents, and key fixtures. The 100%
  line coverage target applies here too.
- Phase 3: migrate the 2 production register_method
  callers (§6.4) — TCP session line 488/950 and ICMPv6
  MLD2 query at packet_handler__icmp6__rx.py line
  1271/1275. Store TimerHandle on the consumer instance;
  call self.stack.timer.cancel(handle) instead of
  unregister_method(method).
- Phase 4: drop the legacy register_method / unregister_method
  shim from Timer + FakeTimer (their only consumers
  migrated in Phase 3). The register_timer /
  unregister_timers_with_prefix / is_expired shims STAY
  — their 24+ TCP consumers are out of scope.
- Phase 5: sweep .claude/rules/pytcp.md, this plan doc
  (flip Status to Shipped + commit SHAs), and MEMORY.md.

Constraints throughout:
- make lint clean (codespell + isort + black + flake8 +
  mypy strict + pylint) after every phase commit.
- make test clean after every phase commit. Currently
  10970 passing / 4 skipped / 0 failures. Phase 1 drops
  ~7 TimerTask-internal tests; later phases should not
  reduce the count further.
- §7.2 docstring audit clean on every new/modified test
  file (the audit pattern is in unit_testing.md §7.2 and
  recent commits 44441a5d, fd6db020 use the same shape).
- Module docstrings use 'ver 3.0.4' (current). Update path
  strings for any moved files.
- Commit message style: follow the project convention
  (see commits 71d9e6f9 / fd6db020 for examples).
- Sign every commit with the
  'Co-Authored-By: Claude Opus 4.7 (1M context)
   <noreply@anthropic.com>' footer.

Design decisions already locked (do NOT re-litigate; they
are documented in detail in the plan):
- Heap-based scheduler with threading.Event wakeup, not
  asyncio. Subsystem base class stays; only the loop body
  changes.
- Absolute deadlines (now_ms + delay_ms), not tick
  counters.
- Lazy cancellation via handle.cancelled flag.
- RLock for the lock; lock released during callback
  invocation.
- _IDLE_WAKEUP__SEC = 60.0 idle ceiling.
- (deadline_ms, seq) tiebreaker for deterministic
  ordering at the same deadline.
- New API: call_later / call_periodic / cancel.
- Legacy shims: register_method / register_timer /
  is_expired / unregister_method /
  unregister_timers_with_prefix.
- Drop dead features: delay_exp, stop_condition, finite
  repeat_count (zero production consumers).
- 60 s idle ceiling NOT 10 s NOT 5 minutes.

Resume from whatever phase the branch is at. Check git
log for the most recent phase-N commit and pick up from
phase N+1. Push to origin after each phase passes its
validation gates.
```

## 14. Cross-references

- `pytcp/runtime/timer.py` — current implementation.
- `pytcp/tests/unit/runtime/test__runtime__timer.py` —
  current tests (29 methods after commit fd6db020).
- `pytcp/tests/lib/fake_timer.py` — current FakeTimer.
- `pytcp/runtime/subsystem.py` — the `Subsystem` base;
  unchanged by this plan. The `start()` / `stop()`
  lifecycle and the `_subsystem_loop()` abstract method
  are the contract `Timer` implements.
- `docs/refactor/pytcp_directory_restructure.md` — the
  recently-completed restructure; established the
  `pytcp/runtime/` namespace this plan operates in.
- `unit_testing.md` §7 / §7.2 — the docstring audit
  pattern every new test must satisfy.
- `.claude/rules/pytcp.md` §3 — the `Subsystem`
  authoring rule.
