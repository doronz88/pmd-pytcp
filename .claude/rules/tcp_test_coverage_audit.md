# PyTCP — TCP Test Coverage Audit + Fill-In Plan

Self-contained handoff plan for closing the test-coverage gaps
identified in the 2026-05-03 post-NewReno audit. Execute after
`/compact` resets context. Each phase lands as 1-2 commits;
total ~12 commits, ~3-4 hours of focused work.

The audit was comprehensive across all shipped TCP RFCs (1122,
1337, 2018, 2883, 5681, 5961, 6298, 6528, 6582, 6675, 6691,
6928, 7323, 7414, 8961, 9293). Gaps fall into three buckets:

  - **Bucket A: helper extractions** — formulas currently inline
    in `tcp__session.py` that warrant their own unit-test
    surface. Mirrors the project pattern set by `tcp__rto.py`,
    `tcp__sack.py`, `tcp__loss_recovery.py`, `tcp__newreno.py`.
  - **Bucket B: cross-RFC interaction tests** — corners where
    two shipped RFCs interact and no test pins the behaviour.
  - **Bucket C: real RFC-conformance gaps** — cases where PyTCP
    deviates from spec (not just test gaps; fix + tests).

---

## 0. Pre-flight

Suite baseline at start of this plan:
**7937 passing, 0 failures, 17 skipped** at HEAD `171c2ae`.

After every commit in this project:
- `make lint` clean.
- `make test` shows the same pass count as before, plus any
  new tests added in that commit.
- No regressions on existing tests.

Re-orient command for new sessions:

```bash
git log --oneline -20
ls pytcp/protocols/tcp/tcp__cwnd.py 2>/dev/null
ls pytcp/tests/unit/protocols/tcp/test__tcp__cwnd.py 2>/dev/null
make test 2>&1 | tail -5
```

What it tells you:
- `tcp__cwnd.py` exists → Phase A1 done.
- `test__tcp__cwnd.py` exists → Phase A2 done.
- Suite count > 7937 → some phases shipped; match commit
  messages against §1 below.

---

## 1. Phase-by-phase plan

### Phase A1 — Extract `tcp__cwnd.py` helper module

Pure refactor + unit tests. No behaviour change. 1 commit (or
2: helper-only first, then unit tests, depending on user
preference).

**New file: `pytcp/protocols/tcp/tcp__cwnd.py`**

```python
"""
RFC 5681 / RFC 6928 congestion-control formulas as pure
functions. Composed of three operations the caller invokes
from '_process_ack_packet', '_retransmit_packet_request',
'_retransmit_packet_timeout', and the FSM init points:

    cwnd_grow_per_ack(cwnd, ssthresh, bytes_acked, smss) -> int
        RFC 5681 §3.1: slow-start vs CA growth on cum-ACK.
        if cwnd < ssthresh: cwnd += min(bytes_acked, smss)
        else:               cwnd += max(1, smss*smss // cwnd)

    compute_loss_event_ssthresh(flight_size, smss) -> int
        RFC 5681 §3.1 / §3.2 step 2: ssthresh halving on RTO
        and fast-retransmit entry.
        ssthresh = max(flight_size // 2, 2 * smss)

    initial_window(smss) -> int
        RFC 6928 §2: post-handshake cwnd.
        IW = min(10 * smss, max(2 * smss, 14600))
"""

INITIAL_WINDOW_FACTOR = 10
INITIAL_WINDOW_BYTES = 14600


def cwnd_grow_per_ack(cwnd: int, ssthresh: int, bytes_acked: int, smss: int) -> int:
    assert cwnd > 0 and ssthresh > 0 and smss > 0 and bytes_acked >= 0
    if cwnd < ssthresh:
        return cwnd + min(bytes_acked, smss)
    return cwnd + max(1, smss * smss // cwnd)


def compute_loss_event_ssthresh(flight_size: int, smss: int) -> int:
    assert flight_size >= 0 and smss > 0
    return max(flight_size // 2, 2 * smss)


def initial_window(smss: int) -> int:
    assert smss > 0
    return min(INITIAL_WINDOW_FACTOR * smss, max(2 * smss, INITIAL_WINDOW_BYTES))
```

**Refactor call sites in `tcp__session.py`:**

1. `_process_ack_packet` slow-start vs CA branch → call
   `cwnd_grow_per_ack`.
2. `_retransmit_packet_request` entry inflation → call
   `compute_loss_event_ssthresh` for the ssthresh half.
3. `_retransmit_packet_timeout` ssthresh halving → call
   `compute_loss_event_ssthresh`.
4. `tcp__fsm__syn_sent.py` and `tcp__fsm__syn_rcvd.py` IW
   assignment → call `initial_window`.
5. Remove `INITIAL_WINDOW_FACTOR` and `INITIAL_WINDOW_BYTES`
   from `tcp__constants.py` (now live in `tcp__cwnd.py`).

**New file: `pytcp/tests/unit/protocols/tcp/test__tcp__cwnd.py`**

~20-25 unit tests across 3 TestCase classes. Target edges:

- `TestCwndGrowPerAck`: slow-start (`cwnd < ssthresh`) cap at
  smss, CA (`cwnd >= ssthresh`) integer floor-div edges (small
  cwnd = bigger grow, large cwnd → 1-byte floor), boundary
  `cwnd == ssthresh`, `bytes_acked == 0`, `bytes_acked` very
  large (capped at smss in slow-start).
- `TestComputeLossEventSsthresh`: `flight_size = 0` (clamps to
  `2*smss`), `flight_size = smss` (still clamps), `flight_size
  >> smss` (FlightSize/2 dominates), boundary `flight_size ==
  4*smss` (transition point).
- `TestInitialWindow`: canonical 1460 MSS → 14600, very small
  MSS (`smss = 100` → 14600 floor), very large MSS (`smss =
  9000` → 90000 cap=10*smss, since `2*smss=18000 > 14600`),
  jumbo MSS (`smss = 65535`).

**Existing integration tests adjusted:** none. The cwnd
integration tests (15 in `test__tcp__session__cwnd.py`) all
exercise the same call sites; refactor is behaviour-preserving.

Commit message template:

```
Extract RFC 5681 / RFC 6928 cwnd helpers + 20 unit tests

The Phase 5 cleanup of the cwnd project. Formulas previously
inline in '_process_ack_packet' / '_retransmit_packet_request'
/ '_retransmit_packet_timeout' / FSM init points are now pure
functions in 'tcp__cwnd.py' with unit-test coverage matching
the project pattern set by tcp__rto, tcp__sack,
tcp__loss_recovery, tcp__newreno.
```

Estimated: 1-2 commits. Risk: low (pure refactor).

### Phase A2 — Bonus helper extractions (optional)

Lower-priority extractions identified in the audit:

- **TS clock arithmetic** — `(now_ms - tsecr) & 0xFFFF_FFFF`
  is trivial; not worth extracting.
- **PAWS comparison** — uses `lt32` from `tcp__seq.py` which
  has unit tests via `test__tcp__seq.py`. Not worth a new
  helper.
- **RFC 5681 §3.2 step 4 dup-ACK inflation** — `cwnd += smss`.
  One-line; not worth extracting.

Decision: SKIP Phase A2. Phase A1 alone closes the
helper-vs-inline asymmetry for cwnd, which is the most
consequential category.

### Phase B1 — Cross-RFC interaction tests

Add 4-5 integration tests that pin behaviours at the
intersections of shipped RFCs. Each test goes in its
canonical file:

| Test | File | Rationale |
|---|---|---|
| `newreno_plus_rto_during_recovery` | `test__tcp__session__cwnd.py` | RTO during fast recovery must clear `_recovery_point`, reset cwnd to LW, halve ssthresh, AND prevent the NewReno deflation from firing on the next cum-ACK. |
| `tsopt_plus_wscale_plus_sack_on_syn_round_trip` | `test__tcp__session__handshake__active.py` | All three options on outbound SYN parse correctly through `_parse_tx`. |
| `paws_plus_dsack_stale_segment_dropped_no_dsack` | `test__tcp__session__sack.py` | PAWS-stale segment that's also a DSACK candidate gets dropped before the DSACK detector fires; no DSACK report on next outbound ACK. |
| `keepalive_probe_during_fast_recovery_does_not_clear_recovery_point` | `test__tcp__session__keepalive.py` | The keepalive probe (which calls `_transmit_packet` directly) must not interfere with `_recovery_point` state. |
| `timestamps_passive_open_negotiation` | `test__tcp__session__timestamps.py` | The deferred passive-open scenarios from RFC 7323 Phase 1 — peer SYN with TSopt → our SYN+ACK echoes; peer SYN without TSopt → our SYN+ACK omits. Two tests under a `TestTcpTimestampsPhase1Passive` class using the `LISTEN__PORT` pattern from `handshake__passive.py`. |

Each test is straightforward to write once the harness is set
up. Estimated: 2 commits (one for cwnd/timestamps, one for
sack/keepalive) or 1 if combined.

### Phase B2 — Cross-RFC interaction docs

Update memory pointer files (`reference_tcp_rfc7323_timestamps.md`,
`reference_tcp_rfc5681_cwnd.md`) §7 to note these tests now
exist (so the deferred-work taxonomy stays accurate).

Estimated: 1 commit, trivial.

### Phase C1 — RFC 5961 RST acceptance hardening

This is a **real RFC-conformance gap**, not just a test gap.

Current code: RST in synchronized states is accepted only
when `seq == rcv_nxt` (strict equality). Per RFC 9293
§3.10.7.4 / RFC 5961 §3, RST should be accepted when SEQ is
**in the receive window** `[rcv_nxt, rcv_nxt + rcv_wnd)`,
otherwise drop with challenge-ACK.

**Tests-first** (`test__tcp__session__robustness__blind_attacks.py`):

  1. `test__rst__in_window_seq_not_at_rcv_nxt_resets_connection`
     [FLAGS BUG] — RST with SEQ in receive window but != rcv_nxt
     MUST reset the connection (currently silently dropped).
  2. `test__rst__in_window_off_path_attack_emits_challenge_ack`
     [FLAGS BUG] — RST with SEQ in window but with bogus ACK
     elicits challenge-ACK rather than reset (RFC 5961 §3.2).
  3. Existing `test__rst__seq_at_rcv_nxt_resets` regression
     guard already covers the strict-equality path.

**Fix** (`tcp__session.py`): in the inbound segment
acceptability check, change RST handling from
`seq == rcv_nxt` to `rcv_nxt <= seq < rcv_nxt + rcv_wnd`
(modular). ~5 LOC.

Estimated: 2 commits (test + fix). Risk: low-medium.

### Phase C2 — RFC 6691 IPv6 MSS calculation

This is a **real RFC-conformance gap**.

Current: IPv6 path uses `MTU - 40` (assumes IPv4-style 20
header bytes). Should be `MTU - 60` (IPv6 base header is 40
bytes, TCP header is 20 bytes).

**Tests-first** (`test__tcp__session__ipv6.py`):

  1. `test__mss__ipv6_clamp_uses_mtu_minus_60` [FLAGS BUG] —
     advertised MSS on IPv6 SYN equals `interface_mtu - 60`
     (= 1440 for canonical 1500 MTU), not 1460.

**Fix**: locate the IPv4 vs IPv6 MSS branch (currently uses
`session._ip_tcp_overhead`) and ensure IPv6 path subtracts 60
not 40. ~3 LOC.

Estimated: 2 commits. Risk: low.

### Phase C3 — RFC 9293 SYN-on-synchronized in half-close states

Current: SYN-on-synchronized challenge-ACK fires only in
ESTABLISHED, SYN_RCVD, TIME_WAIT. Per RFC 9293 §3.10.7.4 it
should fire in ALL synchronized states: FIN_WAIT_1,
FIN_WAIT_2, CLOSE_WAIT, CLOSING, LAST_ACK too.

**Tests-first** (split across the close-state test files):

  1. `close__rst.py::test__syn__in_fin_wait_1_elicits_challenge_ack` [FLAGS BUG]
  2. `close__rst.py::test__syn__in_fin_wait_2_elicits_challenge_ack` [FLAGS BUG]
  3. `close__rst.py::test__syn__in_close_wait_elicits_challenge_ack` [FLAGS BUG]
  4. `close__rst.py::test__syn__in_closing_elicits_challenge_ack` [FLAGS BUG]
  5. `close__rst.py::test__syn__in_last_ack_elicits_challenge_ack` [FLAGS BUG]

(TIME_WAIT is already covered by the RFC 1337 commit; the 5
half-close states need their own.)

**Fix**: add the existing SYN-handling branch to each of the 5
half-close FSM modules. The branch is a copy of the one in
`tcp__fsm__established.py`. ~5 LOC per file × 5 files = ~25
LOC.

Estimated: 2 commits. Risk: low (mechanical replication).

### Phase D1 — Extend RFC 7323 to non-`_process_ack_packet` paths

The completion record `tcp_rfc7323_timestamps.md` §7.4 / §7.5
flagged two scope-limited paths:

  - PAWS check applies only to segments routed through
    `_process_ack_packet`; dup-ACK / OOO / TIME-WAIT paths
    bypass.
  - `_ts_recent` updates only in `_process_ack_packet`; per
    RFC 7323 §4.3 it should update on ANY accepted in-window
    segment.

**Approach**: extract a session-level helper
`_ts_check_and_update(packet_rx_md) -> bool` that returns
True if the segment passes PAWS, and updates `_ts_recent` as
a side effect. Call it at the top of every FSM state handler's
accepted-segment branch.

**Tests-first**: 3 [FLAGS BUG] tests:
  1. `test__paws__dup_ack_with_stale_tsval_dropped` — peer's
     dup-ACK with stale TSval dropped at the FSM dispatcher.
  2. `test__ts_recent__updated_on_dup_ack_with_fresh_tsval` —
     dup-ACK with fresh TSval updates `_ts_recent`.
  3. `test__paws__time_wait_late_segment_dropped` — late
     stale-TSval segment in TIME_WAIT dropped by PAWS (also
     covers part of RFC 1337 PAWS-strengthened mitigation).

Estimated: 2-3 commits, medium risk (touches multiple FSM
modules).

### Phase D2 — RFC 5961 ACK-acceptability hardening

Beyond the RST hardening in Phase C1, RFC 5961 §5 specifies
ACK-acceptability hardening: an ACK with `seg.ack` outside
`[snd_una - max_window, snd_nxt]` MUST elicit a challenge-ACK
rather than be silently dropped. PyTCP fix #12 (commit
`7893c97` per the integration tests record) addressed part of
this — the unacceptable-ACK -> empty-ACK-reply path. RFC 5961
§5 is more nuanced: the "blind data injection" attack vector
needs the `max_window` lookback, not just the strict `snd_nxt`
upper bound.

**Tests-first** (`robustness__blind_attacks.py`):

  1. `test__ack__blind_in_window_below_snd_una_emits_challenge_ack`
     [FLAGS BUG] — RFC 5961 §5: ACK below `snd_una -
     max_window` triggers challenge-ACK, not silent drop.
  2. `test__ack__above_snd_nxt_emits_challenge_ack` regression
     guard — already implemented per fix #12.

**Fix**: extend the existing acceptable-ACK gate to the RFC
5961 §5 window. Track `_max_window` (the largest `snd_wnd`
ever seen) and use `[snd_una - max_window, snd_nxt]` as the
acceptable range. ~10 LOC.

Estimated: 2 commits. Risk: low-medium.

---

## 2. Project ordering and commit budget

Execute every phase. No deferrals. Recommended order
(foundation → real RFC gaps → coverage → docs):

| Phase | Description | Commits | Risk |
|---|---|---|---|
| A1 | `tcp__cwnd.py` helper + ~20 unit tests | 1-2 | low |
| C1 | RFC 5961 RST in-window acceptance | 2 | low-medium |
| C2 | RFC 6691 IPv6 MSS = MTU - 60 | 2 | low |
| C3 | SYN-on-synchronized in 5 half-close states | 2 | low |
| D1 | Extend PAWS + `_ts_recent` to non-`_process_ack_packet` paths | 2-3 | medium |
| D2 | RFC 5961 §5 ACK-acceptability hardening | 2 | low-medium |
| B1 | 5 cross-RFC interaction tests | 1-2 | low |
| B2 | Memory pointer + completion-record updates | 1 | trivial |

**Total: 13-16 commits, ~5-7 hours of focused work.**

Stop conditions (when to pause and report rather than push
through):
  - `make test` fails with regressions on existing tests AND
    the failure isn't trivially fixable in <30 LOC. Capture
    the failure and ask before deviating from the plan.
  - A phase's [FLAGS BUG] tests pass against current code
    (would mean the bug is already fixed). Audit the existing
    code path to confirm, mark the test as a regression
    guard, continue.

---

## 3. Anti-patterns to avoid

- **Don't bundle Phase A1 with behaviour changes.** The cwnd
  helper extraction is pure refactor; the formulas must be
  identical to the inline versions. If you discover a bug in
  the formula during extraction, revert the extraction and
  fix the bug as a separate commit.

- **Don't write unit tests that just re-test what integration
  already covers.** Unit tests should target edge cases that
  are hard to hit through integration: integer floor-div
  boundaries, very large/small inputs, defensive asserts.

- **Don't lower the strictness of the RST-acceptance check
  too far.** RFC 5961 §3.2 specifies in-window acceptance
  PLUS a challenge-ACK for "unacceptable RST" cases (e.g.
  in-window but ack-out-of-window). The fix is a relaxation
  of the SEQ check, not a wholesale acceptance.

- **Don't add `_ts_recent` updates to handlers that legitimately
  drop segments.** §4.3 requires update only on "accepted"
  segments (passed the receive-acceptability check AND in
  receive sequence space). Out-of-window segments must not
  update.

- **Don't extract helpers for one-liners.** RFC 5681 §3.2 step
  4 (`cwnd += smss`) and the TSecr arithmetic
  (`(now_ms - tsecr) & 0xFFFFFFFF`) are too simple to warrant
  separate functions. The bar is "edge cases worth pinning at
  the unit level."

---

## 4. Cross-references

- Integration test workflow:
  `.claude/rules/tcp_session_integration_tests.md` §7
- Coding style: `.claude/rules/coding_style.md`
- Unit test authoring: `.claude/rules/unit_tests.md`
- Adjacent shipped projects (helpers + unit tests pattern):
  - `.claude/rules/tcp_rto_integration.md`
  - `.claude/rules/tcp_sack_implementation.md`
  - `.claude/rules/tcp_rfc5681_cwnd.md`
  - `.claude/rules/tcp_rfc7323_timestamps.md`
- The audit conversation that produced this plan: see git
  log around HEAD `171c2ae` (the post-NewReno extended
  integration tests commit).

---

## 5. Quick-start (one-shot execution)

After `/compact`, a fresh session can execute the plan with:

```
Execute every phase of .claude/rules/tcp_test_coverage_audit.md
in this order: A1 -> C1 -> C2 -> C3 -> D1 -> D2 -> B1 -> B2.
Do not skip or defer any phase. Pause and report only on
unrecoverable test regressions (existing tests breaking with
no <30-LOC fix available).
```

Total deliverable: ~55 new tests (~20 unit + ~35 integration),
4 RFC-conformance fixes (5961 §3 RST, 5961 §5 ACK, 6691 IPv6
MSS, 9293 SYN-in-half-close), and the long-deferred PAWS /
`_ts_recent` extension to all FSM paths. Final suite count
target: ~7990-8000.
