# PyTCP — RFC 6298 RTO Integration: Project Record

**Status: SHIPPED** (helper module + Phase 2 sample collection +
Phase 3 session-level retransmit timer + Phase 4 §5.7
restart-after-idle).

This document was originally a handoff plan to execute the full
RFC 6298 RTO wiring; it has now been rewritten as a completion
record so a future session that wants to **extend** the RTO
machinery (e.g. land RFC 7323 timestamps, RFC 8985 RACK-TLP, or
the RFC 5681 cwnd interaction with `back_off`) has a clean
starting point. The implementation history, phase-by-phase
commit map, test inventory, and explicitly-deferred-work list
are all captured below.

---

## 1. Scope and references

| RFC      | Title                                              | Use |
|----------|----------------------------------------------------|-----|
| RFC 6298 | Computing TCP's Retransmission Timer               | Canonical for RTO estimator + Karn + timer lifecycle |
| RFC 1122 | Host requirements                                  | §4.2.3.1 RTO bound, §4.2.3.5 R2 abort floor |
| RFC 5681 | TCP Congestion Control                             | §3.1 cwnd reset on RTO (PyTCP keeps simplified `_snd_ewn`) |
| RFC 9293 | TCP (consolidated)                                 | §3.8.4 references RFC 6298 by inclusion |

PyTCP now computes RTO from observed RTT samples per §2, applies
Karn's algorithm per §3, drives a single session-level
retransmit timer per §5.1–§5.6, applies binary backoff with a
60 s cap per §5.5, and resets the smoothed estimator on
extended idle per §5.7.

---

## 2. Standing principles (preserved for future extensions)

1. **Pure-function helper, immutable state.** The `tcp__rto`
   module exposes `RtoState` (frozen dataclass) and three
   operations: `initial_state()`, `update(state, sample_ms)`,
   `back_off(state)`. No mutation, no side effects. The
   integration into `TcpSession` is hook-style: the helper
   computes, the session stores.
2. **Single-sample-per-RTT cadence.** Only one in-flight RTT
   sample at a time. Subsequent in-flight segments do not
   overwrite the pending sample's seq/send-time; a retransmit
   of the sampled segment lands with the tracker already set
   so no fresh sample is recorded.
3. **Karn's algorithm via taint flag.** Retransmit of a
   sampled segment flips `_rtt_sample_retransmitted` rather
   than clearing the tracker. The covering ACK's harvest path
   reads the flag and skips `update()` — the smoothed estimate
   stays untouched until a fresh non-retransmitted sample
   arrives.
4. **Session-level timer, not per-seq.** One named timer
   `f"{session}-retransmit"` keyed on `_rto_state.rto_ms`
   replaces the legacy per-seq family. Lifecycle rules from
   RFC 6298 §5 govern arm/restart/stop transitions.
5. **R2 abort via `_retransmit_count`.** Independent counter
   from the smoothed estimator; resets on every cum-ACK that
   advances `SND.UNA` (peer's progress is fresh evidence of
   liveness). The abort threshold remains
   `PACKET_RETRANSMIT_MAX_COUNT`.
6. **Fast retransmit stays back_off-free.** RFC 5681 §3.2 fast
   retransmit (third dup-ACK or SACK byte rule) does NOT
   trigger `back_off()` and does NOT increment
   `_retransmit_count`. The retransmit timer keeps counting
   down from its original arm time.

---

## 3. Architecture (final state)

```
pytcp/
    protocols/tcp/
        tcp__rto.py                  RFC 6298 §2 helper:
                                        INITIAL_RTO_MS, MIN_RTO_MS, MAX_RTO_MS
                                        K, ALPHA_NUM/DEN, BETA_NUM/DEN
                                        RtoState dataclass
                                        initial_state(), update(), back_off(), clamp_rto()
        tcp__session.py              Session-level RTO state + hooks (see §6)
    stack/
        timer.py                     Production 'Timer.now_ms' (time.monotonic_ns // 1e6)
    tests/
        unit/protocols/tcp/
            test__tcp__rto.py        20 unit tests on the helper formulas
        integration/protocols/tcp/
            test__tcp__session__rto.py             13 RTO integration tests
            test__tcp__session__data_transfer__retransmit_timeout.py
                                                    Updated for session-level state
        lib/
            fake_timer.py            'now_ms' property mirrors production
```

---

## 4. Phase-by-phase completion record

| Phase | Description                                          | Commits           | Tests added |
|-------|------------------------------------------------------|-------------------|-------------|
| 1     | Helper module (RtoState + update/back_off/clamp)     | `8f52a81` + `cbecdf4` | 20 unit |
| 2     | Sample collection (no behaviour change)              | `62f879b` + `8b7f6e6` | 7 integration |
| 3     | Session-level retransmit timer + back_off            | `799266e` + `6c5d5db` | 3 integration (-1 obsolete) |
| 4     | RFC 6298 §5.7 restart-after-idle                     | `3022f7a` + `4c573e3` | 3 integration |

Total: **8 code commits + 1 plan commit (`171309f`), 33
RTO-specific tests, ~150 LOC of production code in
`tcp__session.py` + 50 LOC in `tcp__rto.py`.**

The integration was intentionally tests-first per phase: every
fix commit is paired with a preceding `[FLAGS BUG]` tests-first
commit so the behavioural invariant is captured in executable
form before the implementation lands.

---

## 5. Test inventory (final)

### Unit tests in `test__tcp__rto.py` (20)

Cover the pure helper formulas: initial state defaults,
first-sample case (§2.2 SRTT/RTTVAR/RTO), subsequent-sample
EWMA (§2.3 with α=1/8, β=1/4, K=4), backoff doubling and the
MAX_RTO_MS cap, clamp boundaries, convergence on a steady
sample stream.

### Integration tests in `test__tcp__session__rto.py` (13)

| #  | Class                              | Test name                                                      |
|----|------------------------------------|----------------------------------------------------------------|
| 1  | TestTcpRtoSampling                 | outbound_data_segment_records_pending_sample                   |
| 2  | TestTcpRtoSampling                 | ack_covering_pending_sample_harvests_and_updates_rto_state     |
| 3  | TestTcpRtoSampling                 | additional_data_while_sample_pending_does_not_overwrite        |
| 4  | TestTcpRtoSampling                 | post_harvest_next_outbound_starts_fresh_sample                 |
| 5  | TestTcpRtoSampling                 | retransmit_marks_pending_sample_as_karn_tainted                |
| 6  | TestTcpRtoSampling                 | ack_of_karn_tainted_sample_clears_but_does_not_update_state    |
| 7  | TestTcpRtoInitialization           | fresh_session_initializes_rto_state_to_initial                 |
| 8  | TestTcpRtoRetransmitTimer          | data_transmit_arms_session_level_retransmit_timer              |
| 9  | TestTcpRtoRetransmitTimer          | cumulative_ack_draining_in_flight_stops_retransmit_timer       |
| 10 | TestTcpRtoRetransmitTimer          | retransmit_timeout_backs_off_rto_state                         |
| 11 | TestTcpRtoRestartAfterIdle         | idle_longer_than_rto_resets_state_to_initial                   |
| 12 | TestTcpRtoRestartAfterIdle         | idle_shorter_than_rto_preserves_state                          |
| 13 | TestTcpRtoRestartAfterIdle         | transmit_updates_last_send_time                                |

### Cross-references covered indirectly

- `test__tcp__session__data_transfer__retransmit_timeout.py`
  — six existing integration tests that verify cadence /
  payload preservation / FIN retransmit / sub-MSS retransmit
  / 0-window flow control / FIN seq-mod walkback. Test #2
  (`peer_ack_mid_back_off_clears_counters_and_grows_window`)
  was rewritten in commit `6c5d5db` to assert against the
  session-level state shape (`_retransmit_count`,
  `f"{session}-retransmit"` timer key).
- `test__tcp__session__seq_wraparound.py` — the obsolete
  `TestTcpSeqWraparound__Purge` class was deleted in commit
  `6c5d5db`; the wrap-aware behaviour of the still-present
  `_tx_retransmit_request_counter` (fast retransmit) is
  covered transitively by the surrounding wrap tests.

---

## 6. Production code map (where RTO lives in `tcp__session.py`)

| Attribute / method                      | Purpose                                                       |
|-----------------------------------------|---------------------------------------------------------------|
| `_rto_state: RtoState`                  | RFC 6298 §2 estimator (SRTT, RTTVAR, RTO)                     |
| `_rtt_sample_seq: Seq32 \| None`        | Pending-sample seq (None means tracker idle)                  |
| `_rtt_sample_send_time_ms: int \| None` | Virtual-clock value at sample's send moment                   |
| `_rtt_sample_retransmitted: bool`       | Karn taint flag (§3)                                          |
| `_retransmit_count: int`                | R2 abort counter; resets on cum-ACK progress                  |
| `_last_send_time_ms: int \| None`       | §5.7 idle baseline; updated on every data/SYN/FIN             |

Hook points:

- **`_transmit_packet`**:
  - §5.7 reset check (idle > rto_ms → reset to initial_state).
  - §4 sample-record (single-pending-sample gate).
  - §5.7 last-send tracking refresh.
  - §5.1 timer arm-if-not-running (`f"{self}-retransmit"`).
- **`_process_ack_packet`**:
  - On `lt32(_snd_una, ack)`: reset `_retransmit_count` to 0.
  - §5.2 stop timer iff `_snd_una == _snd_max` else §5.3
    restart with current `rto_ms`.
  - §4 sample harvest with Karn-skip.
- **`_retransmit_packet_timeout`**:
  - Gate on `is_expired(f"{self}-retransmit")` AND
    `_snd_una != _snd_max`.
  - R2 abort if `_retransmit_count >=
    PACKET_RETRANSMIT_MAX_COUNT`.
  - §3 Karn taint of in-flight sample.
  - §5.5 `back_off(_rto_state)` and `_retransmit_count += 1`.
  - §5.6 re-arm timer with new `rto_ms`.
  - Slow-start cwnd reset, recovery point clear, SYN/FIN
    seq-mod walkback (PyTCP-specific bookkeeping preserved
    from pre-Phase-3).
- **`_retransmit_packet_request`** (fast retransmit, RFC 5681
  §3.2): does NOT touch `_rto_state` or `_retransmit_count`;
  the timer is left running per the audit (a still-running
  timer is correct under §5.1 and §5.3 doesn't apply because
  dup-ACKs do not advance SND.UNA).

---

## 7. Deferred work (out of scope for "the RTO project")

These items were considered and explicitly skipped. They belong
to adjacent projects, not RTO polish.

### 7.1 RFC 5681 cwnd interaction with back_off

PyTCP's `_snd_ewn` collapses to `min(_snd_mss, _snd_wnd)` on
RTO, mirroring the RFC 5681 §3.1 slow-start re-entry. A proper
RFC 5681 implementation would also track `ssthresh` and apply
`ssthresh = max(FlightSize/2, 2*SMSS)` on RTO before the cwnd
collapse. The full RFC 5681 cwnd rework is a separate project
(see `.claude/rules/tcp_sack_implementation.md` §7.1 for the
broader rationale).

When that project lands, the natural integration point with
RTO is in `_retransmit_packet_timeout` after `back_off()`:
the same code path that doubles `rto_ms` should also halve
`ssthresh`. The current `_snd_ewn` collapse line stays as the
cwnd post-event value; the new `ssthresh` line goes alongside.

### 7.2 RFC 7323 timestamps option (TSopt)

Phase 2's sample collection records send-time at the
TcpSession level using the FakeTimer / production `now_ms`
clock. RFC 7323 §3 specifies the TSopt option that lets peers
echo each other's send timestamps at the wire level, removing
the need for sender-side clock tracking and avoiding Karn's
ambiguity entirely (the timestamp on the ACK identifies which
transmission it acknowledges).

When TSopt lands:
- `_rtt_sample_seq` / `_rtt_sample_send_time_ms` /
  `_rtt_sample_retransmitted` become advisory; the canonical
  RTT measurement is `now_ms - tcp__tsecr` from the inbound
  ACK's option.
- Karn's algorithm in `_retransmit_packet_timeout` still
  applies for legacy non-TSopt peers.
- The covering-ACK harvest in `_process_ack_packet` adds a
  TSopt-preferred path before falling back to the §4 tracker.

Estimated effort: ~6-8 commits including option parser/
assembler + TcpSession integration. Frame as **"RFC 7323
project"**.

### 7.3 RFC 8985 RACK-TLP

RACK (Recent ACKnowledgement) and TLP (Tail Loss Probe) replace
the dup-ACK + RTO duo with a more aggressive loss-detection
model that reduces tail latency on bursty drop patterns. RACK
needs SRTT and a per-segment send-time (already available
post-Phase-2), and TLP arms a timer at `min(2*SRTT,
PACKET_RETRANSMIT_TIMEOUT/2)` — both of which the current RTO
integration provides as building blocks.

This is a future direction, not RTO polish.

### 7.4 SYN-RTO 3-second floor (RFC 6298 §5.7 second sentence)

RFC 6298 §5.7 actually has TWO clauses:
1. The restart-after-idle clause we implemented in Phase 4.
2. "If the timer expires awaiting the ACK of a SYN segment
   and the TCP implementation is using an RTO less than 3
   seconds, the RTO MUST be re-initialized to 3 seconds when
   data transmission begins."

The second clause specifies a SYN-RTO floor: after a SYN
retransmit timeout, if the in-flight rto_ms was < 3000 ms, set
it to 3000 ms before the first post-handshake data send. PyTCP
does NOT currently enforce this floor.

The impact is modest: with the MIN_RTO_MS = 1000 ms clamp,
post-handshake rto_ms is always ≥ 1000 (and typically exactly
1000 due to the SYN+ACK RTT clamp), so the worst-case RTO is
1000 ms vs the §5.7 mandate of 3000 ms. Real-world workloads
usually reach 3000 ms via subsequent RTT-driven backoffs.

If a future session decides to land this clause, the hook
point is `_tcp_fsm_syn_sent` after the ESTABLISHED transition:
if `_retransmit_count > 0` (we retransmitted the SYN at least
once) and `_rto_state.rto_ms < 3000`, set
`_rto_state.rto_ms = 3000` explicitly. ~5 LOC + 1 test.

---

## 8. Anti-patterns (preserved for future extensions)

- **Don't conflate `_rtt_sample_seq` with `_snd_una`.** The
  sample tracker holds the seq of ONE specific in-flight
  segment; SND.UNA is the cumulative-ACK boundary. They
  coincide on the first transmit but diverge once peer's ACK
  arrives (sample is harvested, snd_una advances).

- **Don't apply `back_off()` outside the retransmit timeout
  path.** Fast retransmit (RFC 5681) is a different mechanism
  with its own cwnd rules; touching `_rto_state` there would
  double-penalise.

- **Don't forget Karn's algorithm.** RFC 6298 §3 is
  load-bearing. A naive harvest-on-ACK without the taint check
  would feed retransmit-derived RTTs into the EWMA, biasing
  the estimator low (because the retransmit's send-time is
  closer to the ACK than the original's), shortening RTO,
  causing more retransmits — a positive feedback loop.

- **Don't unregister the retransmit timer in
  `_retransmit_packet_request`.** Fast retransmit is a
  different mechanism; the timer is correctly left running.
  RFC 6298 §5.3 specifies "restart on cum-ACK that advances
  SND.UNA" — dup-ACKs do not advance SND.UNA.

- **Don't initialise `_last_send_time_ms` to `0`.** Use `None`.
  `0` is a legitimate `now_ms` value (FakeTimer starts at 0)
  and would spuriously satisfy the `is not None` guard. The
  §5.7 reset would then fire on the very first send if rto_ms
  happened to be smaller than the first-send time, which is
  the opposite of what §5.7 mandates.

- **Don't forget the production `Timer.now_ms`.** PyTCP runs
  in production with `pytcp.stack.Timer`, not `FakeTimer`. The
  helper module's invariants depend on `now_ms` returning a
  monotonically increasing integer. `time.monotonic_ns() //
  1_000_000` is the canonical implementation; do not switch
  to `time.time()` (subject to wall-clock adjustments) or
  `time.monotonic()` (float).

---

## 9. Extender's re-orient command

If you want to extend the RTO machinery (e.g. land RFC 7323
timestamps, RFC 5681 cwnd interaction, or the SYN-RTO 3 s
floor), start with:

```bash
git log --oneline --grep="RTO\|RFC 6298" 8f52a81~..HEAD
make test 2>&1 | tail -5
ls pytcp/protocols/tcp/tcp__rto.py
grep -n "_rto_state\|_retransmit_count\|_last_send_time_ms" \
    pytcp/protocols/tcp/tcp__session.py | head
```

Read the docstrings of:
- `pytcp/protocols/tcp/tcp__rto.py` (helper module)
- `pytcp/protocols/tcp/tcp__session.py::TcpSession.__init__`
  (RTO field declarations near the SACK / DSACK fields)
- `pytcp/protocols/tcp/tcp__session.py::_retransmit_packet_timeout`
  (the canonical §5.5 backoff implementation)

Then decide whether the extension fits the deferred-work
taxonomy in §7 above, or is a new direction entirely.

---

## 10. Cross-references

- Workflow + reporting format:
  `.claude/rules/tcp_session_integration_tests.md` §7
- Coding style: `.claude/rules/coding_style.md`
- Unit test authoring: `.claude/rules/unit_tests.md`
- SACK shipped record (similar phased plan, similar shape):
  `.claude/rules/tcp_sack_implementation.md`
- Modular sequence arithmetic:
  `pytcp/protocols/tcp/tcp__seq.py` +
  `pytcp/tests/unit/protocols/tcp/test__tcp__seq.py`
- TCP session split + per-FSM-state files:
  `.claude/rules/tcp_session_split.md`
