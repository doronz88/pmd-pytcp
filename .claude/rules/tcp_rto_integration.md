# PyTCP — RFC 6298 RTO Full Integration Plan

Self-contained handoff plan for replacing PyTCP's per-seq retransmit
machinery with a session-level RFC 6298 RTO estimator. The pure-
function helper module (`pytcp/protocols/tcp/tcp__rto.py`) is
already shipped in commits `8f52a81` (tests-first) + `cbecdf4`
(impl). This plan covers the FSM-integration follow-up that the
original sketch deferred.

---

## 1. Mission

Today PyTCP's retransmit timer is **per-seq**:

```python
# tcp__session.py:831-834
self._tx_retransmit_timeout_counter[seq] = (
    self._tx_retransmit_timeout_counter.get(seq, -1) + 1
)
stack.timer.register_timer(
    name=f"{self}-retransmit_seq-{seq}",
    timeout=tcp__constants.PACKET_RETRANSMIT_TIMEOUT
            * (1 << self._tx_retransmit_timeout_counter[seq]),
)
```

Each unacked seq has its own backoff counter and its own timer
entry. Cadence is fixed: 1 s, 2 s, 4 s, 8 s, 16 s, 32 s, 64 s
regardless of actual RTT.

RFC 6298 specifies **session-level** RTO computation and a
**single retransmit timer per socket** (Linux's model). To wire
in the helper from `pytcp/protocols/tcp/tcp__rto.py`, the per-seq
machinery must be replaced with:

1. One `_rto_state: RtoState` per session.
2. One outstanding sample tracker `(seq, send_time_ms,
   retransmitted)` for RFC 6298 §4 "one sample per RTT".
3. One retransmit timer `f"{self}-retransmit"` driven by
   `_rto_state.rto_ms`.
4. Karn's algorithm (RFC 6298 §3): retransmits invalidate the
   pending sample; ACKs of retransmitted segments don't yield
   samples.
5. Restart-after-idle (RFC 6298 §5.7): on resumed transmit after
   long idle, reset to `INITIAL_RTO_MS`.

---

## 2. Standing principles (preserved)

1. **Tests-first per phase.** Each phase opens with a tests-first
   commit asserting RFC 6298 invariants on the new behaviour.
   Failures are marked `[FLAGS BUG]` until the fix commit.
2. **Suite invariant.** Suite count and pass count never drop
   across a green commit boundary. Baseline at the start of this
   plan is 7882 passing, 17 skipped, 0 failures (after the helper
   was shipped).
3. **Existing retransmit-test scenarios must keep passing OR
   their assertions update with explicit RFC justification.**
   `test__tcp__session__data_transfer__retransmit_timeout.py`
   currently asserts "RTO=1000ms × 2^count" cadence. Post-RFC-6298
   the cadence is "RTO=`rto_ms`, doubled per backoff". For mocked
   handshakes the SYN+ACK RTT is sub-millisecond, the first
   sample yields a sub-second RTO that clamps to MIN_RTO_MS=1000,
   so cadence MAY look unchanged on those tests — but the
   underlying mechanism is different. Audit each retransmit test
   for hidden assumptions on the static formula.
4. **No mid-flight visible-state changes for existing
   ESTABLISHED tests.** Sessions that don't take RTT samples
   (e.g. tests that drive only one segment then go silent) MUST
   keep RTO=INITIAL_RTO_MS so existing assertions pass.

---

## 3. Target architecture (final state)

```
TcpSession new state:
    _rto_state: RtoState                    # initial_state() in __init__
    _rtt_sample_seq: Seq32 | None = None    # seq we're sampling
    _rtt_sample_send_time_ms: int | None = None
    _rtt_sample_retransmitted: bool = False # Karn's flag
    _last_send_time_ms: int                 # for §5.7 idle-reset

TcpSession dropped state:
    _tx_retransmit_timeout_counter: dict[Seq32, int]   # per-seq counter
    # The 'f"{self}-retransmit_seq-{seq}"' timer family

Hook points:
    _transmit_packet:
        - If consumed > 0 (flag_syn / flag_fin / data) AND
          _rtt_sample_seq is None AND not retransmit:
            record (seq, now, retransmitted=False).
        - Always: register f"{self}-retransmit" timer with
          _rto_state.rto_ms (replaces per-seq registration).
        - Update _last_send_time_ms.

    _retransmit_packet_timeout:
        - If _rtt_sample_seq matches the seq being retransmitted:
            mark _rtt_sample_retransmitted = True (Karn).
        - Replace the doubled-static-formula with:
            _rto_state = back_off(_rto_state)
            re-register timer with _rto_state.rto_ms.
        - Keep R2 abort logic: if retransmit count exceeds
          PACKET_RETRANSMIT_MAX_COUNT, abort.

    _process_ack_packet:
        - If _rtt_sample_seq is not None AND ack > _rtt_sample_seq:
            sample harvested.
            If not _rtt_sample_retransmitted:
                _rto_state = update(_rto_state, now - send_time)
            Clear pending sample (seq=None, time=None,
            retransmitted=False).
        - On any ACK that advances SND.UNA, the per-seq timer
          family no longer applies; instead, if SND.UNA == SND.NXT
          (everything acked), unregister f"{self}-retransmit".
          Else, re-register with current rto_ms.

    _transmit_data (or wherever new outbound data is fired):
        - On idle restart: if (now - _last_send_time_ms) > rto_ms,
          reset RTO via initial_state() per RFC 6298 §5.7.
```

---

## 4. Phase-by-phase plan

### Phase 2 — Sample collection (no behavior change yet)

Add the sample tracker fields. Hook outbound `_transmit_packet` to
record. Hook inbound `_process_ack_packet` to harvest. Hook
retransmit to set Karn's flag. The retransmit timer logic stays
unchanged for now — `_rto_state` is observable but unused by the
existing per-seq machinery.

**Tests-first** (`test__tcp__session__rto.py`, ~6 unit tests):

  1. Outbound data segment in ESTABLISHED records pending sample.
  2. ACK covering the pending sample harvests it; `_rto_state`
     transitions from `(None, None, INITIAL_RTO_MS)` to a
     post-`update()` value.
  3. While a sample is pending, additional outbound data does NOT
     start a new sample (RFC 6298 §4).
  4. After harvest, the next outbound starts a fresh sample.
  5. Retransmit (driven via `_retransmit_packet_timeout`) marks
     pending sample with `_rtt_sample_retransmitted = True`.
  6. ACK of a Karn-tainted sample harvests but does NOT update
     `_rto_state` (unchanged value).

**Fix commit:** add fields + hooks. ~80 LOC. No existing test
should change behavior because `_rto_state.rto_ms` isn't read by
the retransmit machinery yet.

Estimated: 2 commits (test + impl).

### Phase 3 — Wire dynamic RTO into retransmit timer

Replace the per-seq `_tx_retransmit_timeout_counter` machinery and
the `f"{self}-retransmit_seq-{seq}"` timer family with a single
session-level `f"{self}-retransmit"` timer driven by
`_rto_state.rto_ms`.

This is the disruptive commit. It touches every retransmit test
because the cadence-formula source changes.

**Tests-first updates:**

The existing `test__tcp__session__data_transfer__retransmit_timeout.py`
scenarios assert "1, 3, 7, 15, 31 s cadence on a silent peer."
On a mocked harness, the SYN+ACK RTT is ~1 ms, so SRTT is
clamped to 1000 ms by MIN_RTO_MS, and cadence stays 1, 3, 7,
15, 31 s. The tests should still pass with no assertion changes
**but** the docstrings need updating to cite RFC 6298 §5.5
(binary backoff, capped at MAX_RTO_MS) instead of the legacy
fixed-formula explanation.

New tests:

  - `test__rto__short_rtt_yields_short_rto` — drive a session
    with mocked sub-1s RTT (e.g., advance 5 ms between SYN and
    SYN+ACK), assert `_rto_state.rto_ms == MIN_RTO_MS` (clamp
    floor stays).
  - `test__rto__long_rtt_yields_long_rto` — drive with a 5 s
    SYN+ACK delay, assert `_rto_state.rto_ms` is around
    `5000 + 4 * 2500 = 15000` (no clamp).
  - `test__rto__retransmit_timer_uses_rto_state_value` — assert
    the `f"{self}-retransmit"` timer was registered with
    `_rto_state.rto_ms` (not the legacy constant).

**Fix commit:** drop `_tx_retransmit_timeout_counter`, replace
timer registration in `_transmit_packet`, replace
`_retransmit_packet_timeout` body. Audit the cleanup in
`_change_state(CLOSED)` to drop the new timer name. Audit
`_retransmit_packet_request` (fast retransmit) — that's RFC 5681
territory and should NOT use `back_off()`.

Estimated: 3-4 commits (test + impl + cleanup audit + cross-check).

### Phase 4 — Restart-after-idle (RFC 6298 §5.7)

When a session goes idle longer than the current RTO and then
resumes transmitting, RFC 6298 §5.7 says reset RTO to
`INITIAL_RTO_MS` so a stale (possibly short) `rto_ms` doesn't
trigger spurious retransmits in the new burst.

**Tests-first** (~2-3 unit tests):

  1. Session idle for > rto_ms wall-clock time; next transmit
     observes `_rto_state` reset to `initial_state()`.
  2. Session idle for < rto_ms; next transmit preserves the
     prior `_rto_state`.
  3. Reset clears `_last_send_time_ms` accounting.

**Fix commit:** small hook in `_transmit_packet` — check `now -
_last_send_time_ms > _rto_state.rto_ms` and reset before
recording the new sample.

Estimated: 1-2 commits.

### Phase 5 — Documentation + memory

Update `MEMORY.md`, the RFC coverage report sections affected
(RFC 6298 row, RFC 1122 §4.2.3.1 row), and the
`tcp_session_integration_tests.md` §6 plan note for
`data_transfer__retransmit_timeout.py` (it's no longer "deferred"
since RFC 6298 is now wired).

Estimated: 1 commit.

---

## 5. Existing-test impact audit

Files that may need updates beyond docstrings:

| File                                                         | Likely impact                                                                  |
|--------------------------------------------------------------|--------------------------------------------------------------------------------|
| `data_transfer__retransmit_timeout.py`                       | Cadence stays via MIN_RTO_MS clamp; docstrings update with RFC 6298 cite       |
| `data_transfer__retransmit_dupack.py`                        | Fast-retransmit path unchanged; double-check no static-formula assumptions    |
| `data_transfer__send.py`                                     | Inline ACKs trigger sampling; verify no spurious sample-pending state         |
| `data_transfer__recv.py`                                     | Same as send.py shape                                                          |
| `close__simultaneous.py`, `close__time_wait.py`              | RTO reset on TIME_WAIT entry — verify the new timer family cleanups            |
| `seq_wraparound.py`                                          | RTT sample math uses now-send_time which is wall-clock, not seq; should be safe |
| `harness_smoke.py`                                           | The `_force_iss` helper is unaffected; may want a `_force_rto_state` analog    |

The new test file `test__tcp__session__rto.py` is the canonical
home for phase-2/3/4 unit tests. Integration tests for
end-to-end cadence under various RTT regimes go alongside the
existing data_transfer tests.

---

## 6. Anti-patterns to avoid

- **Don't keep `_tx_retransmit_timeout_counter` for backward
  compat.** The dict is legacy per-seq state. Drop it cleanly in
  phase 3; the new design is one counter implicit in
  `_rto_state.rto_ms` doubling.

- **Don't sample on every ACK.** RFC 6298 §4 says one sample per
  RTT. The pending-sample mechanism (single seq tracker) enforces
  this naturally. Don't try to sample multiple in-flight
  segments — that's RFC 7323 timestamp territory.

- **Don't conflate Karn's algorithm with the dup-ACK counter.**
  Karn (RFC 6298 §3) invalidates RTT SAMPLES from retransmitted
  segments. The dup-ACK counter (RFC 5681 §3.2) drives fast
  retransmit. Independent mechanisms.

- **Don't sample SYN handshake RTT on a mocked clock without
  patching.** The harness's `FakeTimer` advances only when
  `_advance` is called. Tests that don't advance between SYN and
  SYN+ACK will produce a 0 ms or 1 ms RTT, which after the K=4
  rule yields RTO ~1 ms unclamped, clamped to 1000 ms. That's
  fine for cadence assertions but obscures whether the
  estimator is actually tracking. The `_force_rto_state` analog
  (or direct `session._rto_state = RtoState(srtt_ms=N, ...)`)
  may be useful.

- **Don't forget RFC 6298 §3.4 mentions "When a TCP sender
  detects segment loss using the retransmission timer and the
  given segment has not yet been resent by way of the retransmission
  timer, the value of ssthresh MUST be set to no more than ssthresh
  reduced..."** This is RFC 5681 cwnd interaction — out of scope
  for the RTO project per se, but flag it for the future RFC 5681
  cwnd-rework project.

---

## 7. Re-orient command for new sessions

```bash
git log --oneline -10
ls pytcp/protocols/tcp/tcp__rto.py            # helper exists
grep -n "_rto_state\|_rtt_sample_seq" pytcp/protocols/tcp/tcp__session.py 2>/dev/null
grep -n "_tx_retransmit_timeout_counter" pytcp/protocols/tcp/tcp__session.py 2>/dev/null
ls pytcp/tests/unit/protocols/tcp/test__tcp__session__rto.py 2>/dev/null
make test 2>&1 | tail -5
```

What it tells you:

  - `_rto_state` not in tcp__session.py → phase 2 not started.
  - `_rto_state` present, `_tx_retransmit_timeout_counter` still
    present → phase 2 done, phase 3 not started.
  - Both `_rto_state` AND no `_tx_retransmit_timeout_counter` →
    phase 3 done.
  - `test__tcp__session__rto.py` shape tells phase progress.

Match against §4 to pick up where the prior session left off.

---

## 8. Cross-references

- Helper module shipped: `pytcp/protocols/tcp/tcp__rto.py` +
  `pytcp/tests/unit/protocols/tcp/test__tcp__rto.py`. Commits
  `8f52a81` (tests-first) and `cbecdf4` (impl).
- Coding style: `.claude/rules/coding_style.md`.
- Unit test authoring: `.claude/rules/unit_tests.md`.
- Integration test plan: `.claude/rules/tcp_session_integration_tests.md`
  (§6.x retransmit_timeout plan note becomes obsolete after this).
- Pairs with future work:
  - **RFC 7323 timestamps** — once shipped, sampling becomes
    much simpler (peer echoes original send time).
  - **RFC 8985 RACK-TLP** — needs SRTT for tail-loss-probe
    interval. Blocked on this RTO work.
  - **RFC 5681 cwnd rework** — RFC 6298 §3.4 mentions the
    cwnd-on-RTO interaction; future RFC 5681 project will
    consume it.
