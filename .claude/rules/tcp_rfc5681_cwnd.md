# PyTCP — RFC 5681 Congestion Control: Phased Plan

Self-contained handoff plan for landing **proper RFC 5681
congestion control** in PyTCP. Replaces the simplified
`_snd_ewn`-doubling stand-in with separate `_cwnd` /
`_ssthresh` tracking, slow-start vs congestion-avoidance phase
distinction, fast-recovery cwnd inflation / deflation, and
RFC 6928's IW = 10 initial window.

This is the largest deferred TCP item per
`tcp_sack_implementation.md` §7.1 and `tcp_rto_integration.md`
§7.1. Landing it transitively unblocks RFC 6928 (initial
window), RFC 6937 (PRR), RFC 9438 (CUBIC), and tightens the
pipe-bounded `_snd_ewn` interaction with the SACK scoreboard.

---

## 1. Mission

PyTCP's current `_snd_ewn` field conflates two distinct
concepts:

  - **cwnd** — the congestion window (sender-side flow-control
    bound that throttles us according to network capacity).
  - **snd_wnd** — peer's advertised receive window (their
    flow-control bound).

The effective send window is `min(cwnd, snd_wnd)` per RFC 9293
§3.8.4, and `_snd_ewn` carries that combined value. The
problems:

  1. **No slow-start vs CA distinction** (RFC 5681 §3.1).
     Current code: `_snd_ewn = min(_snd_ewn << 1, _snd_wnd)`
     on every cum-ACK — pure exponential. RFC mandates
     additive increase (linear) once cwnd ≥ ssthresh.
  2. **No `ssthresh` tracking** at all. Without it, RTO and
     fast-retransmit cannot halve the threshold per §3.1 /
     §3.2 step 2.
  3. **No fast-recovery cwnd handling** (RFC 5681 §3.2 step
     2-4). On 3rd dup-ACK we currently leave `_snd_ewn`
     untouched and just rewind `SND.NXT`. The RFC mandates:
       - `ssthresh = max(FlightSize/2, 2*SMSS)`
       - `cwnd = ssthresh + 3*SMSS` (inflate)
       - `cwnd += SMSS` per additional dup-ACK
       - `cwnd = ssthresh` on cum-ACK exiting recovery
         (deflate)
  4. **Initial Window stuck at 1 MSS**. RFC 6928 raised IW to
     10 MSS for fast-start; PyTCP doesn't.

After this project ships, `cwnd` and `ssthresh` are
independent first-class state, the four growth/reduction
phases of RFC 5681 each have explicit hook points, and IW = 10
is the default (with an opt-out for legacy / RFC 5681 §3.1
strict mode).

---

## 2. Standing principles (preserved)

1. **Tests-first per phase.** Each phase opens with a
   `[FLAGS BUG]` tests-first commit, then the impl flips them
   green. Mirror the SACK / RTO project workflow.
2. **Suite invariant.** Pass count never drops across a green
   commit boundary. Baseline at the start of this plan: 7894
   passing, 17 skipped, 0 failures.
3. **`_snd_ewn` stays as the effective-window field.**
   Existing callers (`_transmit_data`, `_retransmit_packet_timeout`)
   and many tests reference it as the bound `min(cwnd, snd_wnd)`.
   Phase 1 keeps that surface — the new code computes
   `_snd_ewn = min(_cwnd, _snd_wnd)` whenever `_cwnd` or
   `_snd_wnd` changes. Tests that set
   `session._snd_ewn = PEER__WIN` to bypass slow-start
   continue to work as direct effective-window overrides;
   they just don't bypass `_cwnd` itself anymore.
4. **`_cwnd` is the canonical congestion window.** All RFC
   5681 §3 growth / reduction logic touches `_cwnd`, never
   `_snd_ewn` directly.
5. **No bug fixes during the migration.** Anything surfaced
   that isn't strictly RFC 5681 compliance gets recorded and
   deferred to a separate fix branch. Each phase commit is
   reversible with a single revert.

---

## 3. Architecture (target final state)

```
TcpSession new state:
    _cwnd: int              # RFC 5681 congestion window
    _ssthresh: int          # RFC 5681 slow-start threshold
    _flight_size: int       # SND.MAX - SND.UNA (computed property OR cached)

TcpSession derived state (replaces direct _snd_ewn mutation):
    _snd_ewn: int           # = min(_cwnd, _snd_wnd); recomputed
                              on cwnd / snd_wnd change.

Hook points:

    _process_ack_packet (on lt32(_snd_una, ack)):
        - flight_size = SND.MAX - SND.UNA (post-ack)
        - if _recovery_point != 0 and ack >= _recovery_point:
            # Exit recovery (RFC 5681 §3.2 step 6)
            _cwnd = _ssthresh
        - elif _cwnd < _ssthresh:
            # Slow start (§3.1): cwnd += min(N, SMSS) per ACK
            _cwnd += min(bytes_acked, _snd_mss)
        - else:
            # Congestion avoidance (§3.1): cwnd += SMSS*SMSS/cwnd
            _cwnd += max(1, _snd_mss * _snd_mss // _cwnd)
        - _snd_ewn = min(_cwnd, _snd_wnd)

    _retransmit_packet_request (3rd dup-ACK / SACK byte rule):
        - ssthresh = max(FlightSize / 2, 2 * SMSS)
        - cwnd = ssthresh + 3 * SMSS  # inflate
        - _snd_ewn = min(_cwnd, _snd_wnd)
        (existing rewind / NextSeg logic unchanged)

    Fast-recovery dup-ACK inflation (in _retransmit_packet_request
    or a new helper, depending on phase 3 design):
        - _cwnd += _snd_mss  # per additional dup-ACK in recovery
        - _snd_ewn = min(_cwnd, _snd_wnd)

    _retransmit_packet_timeout (RTO):
        - ssthresh = max(FlightSize / 2, 2 * SMSS)
        - cwnd = LW = 1 * SMSS  # slow-start re-entry per §3.1
        - _snd_ewn = min(_cwnd, _snd_wnd)
        (existing back_off / rewind logic unchanged)

    Handshake completion (in tcp__fsm__syn_sent / __listen):
        - cwnd = IW (RFC 6928: min(10*SMSS, max(2*SMSS, 14600)))
                 OR fall back to RFC 5681 §3.1 IW (1-4*SMSS)
        - ssthresh = INITIAL_SSTHRESH (peer's advertised
                     window OR a large constant like 0x7FFF)
```

---

## 4. Phase-by-phase plan

### Phase 1 — Add `_cwnd` / `_ssthresh` fields + slow-start vs CA

Tests-first commit + fix commit.

**Tests** (`pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py`,
new file):

  1. `test__cwnd__post_handshake_initialises_cwnd_to_one_mss`
     [FLAGS BUG] - field exists with default `_snd_mss`.
  2. `test__cwnd__post_handshake_initialises_ssthresh_high`
     [FLAGS BUG] - `_ssthresh` defaults to a large value
     (peer's win OR 0x7FFF) so first cum-ACKs run in
     slow-start phase.
  3. `test__cwnd__slow_start_phase_grows_cwnd_by_mss_per_ack`
     [FLAGS BUG] - on cum-ACK while `cwnd < ssthresh`, cwnd
     grows by `min(bytes_acked, MSS)`. Currently `_snd_ewn`
     doubles, which is "exponential per cum-ACK" not "+MSS
     per cum-ACK". The doubling-vs-additive distinction
     matters once we also track ssthresh transitions.
  4. `test__cwnd__congestion_avoidance_phase_grows_cwnd_linearly`
     [FLAGS BUG] - once `cwnd >= ssthresh`, cwnd grows by
     `SMSS*SMSS/cwnd` per ACK (≈ +1 MSS per RTT for a stream
     of MSS-sized cum-ACKs).
  5. `test__cwnd__snd_ewn_tracks_min_of_cwnd_and_snd_wnd`
     [FLAGS BUG] - `_snd_ewn` always equals
     `min(_cwnd, _snd_wnd)` after any cwnd or snd_wnd
     change. Validates the "effective window stays derived"
     invariant.

**Fix commit:** add the fields + slow-start / CA logic in
`_process_ack_packet`. Replace `_snd_ewn` doubling with
explicit `_cwnd` adjustment + `_snd_ewn` recompute. Update
the three FSM init points (`tcp__fsm__syn_sent.py` x2,
`tcp__fsm__listen.py`) to set `_cwnd` and `_ssthresh`
alongside `_snd_ewn`.

Estimated: 2-3 commits. Risk: medium. Touches 3 FSM modules
+ 1 process_ack hook + 5+ test fixtures.

### Phase 2 — RTO ssthresh reduction (RFC 5681 §3.1)

Tests-first commit + fix commit.

**Tests:**

  1. `test__cwnd__rto_sets_ssthresh_to_half_flight_size`
     [FLAGS BUG] - on RTO, `ssthresh = max(FlightSize/2,
     2*SMSS)`. Today RTO collapses `_snd_ewn` but doesn't
     touch ssthresh.
  2. `test__cwnd__rto_resets_cwnd_to_one_mss`
     - regression guard for the existing slow-start re-entry
     (cwnd post-RTO = 1 SMSS).
  3. `test__cwnd__rto_with_minimal_flight_size_clamps_ssthresh_floor`
     [FLAGS BUG] - if FlightSize/2 < 2*SMSS, `ssthresh =
     2*SMSS` (the §3.1 floor).

**Fix commit:** ~5 LOC in `_retransmit_packet_timeout` after
`back_off` runs.

Estimated: 1-2 commits. Risk: low.

### Phase 3 — Fast-recovery cwnd inflation/deflation (RFC 5681 §3.2)

Tests-first commit + fix commit. Most invasive phase.

**Tests:**

  1. `test__cwnd__fast_retransmit_halves_ssthresh_and_inflates_cwnd`
     [FLAGS BUG] - on 3rd dup-ACK entering recovery,
     `ssthresh = max(FlightSize/2, 2*SMSS)` and
     `cwnd = ssthresh + 3*SMSS`.
  2. `test__cwnd__additional_dup_ack_during_recovery_inflates_cwnd_by_one_mss`
     [FLAGS BUG] - 4th, 5th, ... dup-ACKs in recovery each
     bump cwnd by 1 SMSS (lets the sender transmit one new
     segment per dup-ACK).
  3. `test__cwnd__cum_ack_exiting_recovery_deflates_cwnd_to_ssthresh`
     [FLAGS BUG] - on cum-ACK that advances SND.UNA past
     `_recovery_point`, `cwnd = ssthresh` (deflate per §3.2
     step 6).
  4. `test__cwnd__fast_retransmit_byte_rule_path_also_halves_ssthresh`
     [FLAGS BUG] - the SACK byte-rule trigger (RFC 6675 §3
     IsLost) hits the same RFC 5681 §3.2 cwnd / ssthresh
     adjustments as the count-based trigger.

**Fix commit:** modify `_retransmit_packet_request` to apply
the §3.2 step 2 reduction; add a dup-ACK inflation hook; add
the deflation path in `_process_ack_packet` recovery exit.

Estimated: 2-3 commits. Risk: medium-high (interacts with the
existing RFC 6675 NextSeg path).

### Phase 4 — RFC 6928 Initial Window 10

Tests-first commit + fix commit. Cleanest phase, separate so
it can be reverted independently.

**Tests:**

  1. `test__cwnd__post_handshake_initialises_cwnd_to_iw_10`
     [FLAGS BUG] - default `cwnd` post-handshake is
     `min(10*MSS, max(2*MSS, 14600))` per RFC 6928. With MSS
     = 1460: IW = `min(14600, max(2920, 14600))` = 14600
     (= 10 MSS exactly).
  2. `test__cwnd__post_handshake_iw_10_clamped_by_peer_win`
     - regression guard: if peer advertises a tiny win,
     `_snd_ewn = min(IW, peer_win)` still respects peer's
     flow-control.

**Fix commit:** change the IW constant in `tcp__constants.py`
or wherever the post-handshake `_cwnd = MSS` line lives.
~3 LOC + test fixture updates.

Estimated: 1 commit. Risk: low.

### Phase 5 — Documentation

Convert this plan to a completion record (mirror
`tcp_sack_implementation.md` / `tcp_rto_integration.md`) once
phases 1-4 ship. Update memory pointer. Estimated: 1 commit.

---

## 5. Existing-test impact audit

Files likely to need updates in the fix commits:

| File                                                         | Likely impact                                                                  |
|--------------------------------------------------------------|--------------------------------------------------------------------------------|
| `data_transfer__send.py`                                     | Multiple tests set `_snd_ewn = PEER__WIN`. With Phase 1 they keep working as direct effective-window overrides; with Phase 4 (IW=10) some `len(initial_tx) == 1` assertions may need to grow to multiple segments depending on payload size |
| `data_transfer__retransmit_dupack.py`                        | Phase 3 cwnd inflation changes the post-recovery cwnd value. Asserts on `_snd_ewn` after fast-retransmit may need updating |
| `data_transfer__retransmit_timeout.py`                       | Phase 2 ssthresh reduction. Test #2 may need a fresh assertion that ssthresh halved post-RTO |
| `sack.py` (integration)                                      | Phase 3 fast-recovery byte-rule path interacts with SACK NextSeg; one or two assertions on `_snd_ewn` value during recovery may need updating |
| `data_transfer__window.py`                                   | Phase 1 tightens the `_snd_ewn = min(cwnd, snd_wnd)` invariant. Tests that mutate `_snd_wnd` directly should still work |
| `harness_smoke.py`                                           | Should be unaffected; it doesn't touch `_snd_ewn` |

---

## 6. Anti-patterns to avoid

- **Don't merge cwnd and ssthresh into a single field.** They
  encode independent concepts: cwnd is "how much can I send
  right now" and ssthresh is "the slow-start / CA boundary".
  PyTCP's `_snd_ewn`-only model worked only because the
  fast-retransmit + RTO paths bypassed the §3.1 ssthresh
  rules entirely.

- **Don't apply fast-retransmit cwnd inflation on every
  dup-ACK from the start.** RFC 5681 §3.2 specifies that the
  inflation begins on the THIRD dup-ACK (the one that
  triggers fast-retransmit), not the first. The PyTCP entry
  point for that is `_retransmit_packet_request`'s existing
  `count_trigger == 3` / `sack_trigger` gates.

- **Don't forget the §3.2 step 6 deflation.** When SND.UNA
  advances past `_recovery_point`, cwnd MUST drop back to
  ssthresh. Without the deflate, cwnd stays inflated post-
  recovery and the sender becomes too aggressive.

- **Don't apply §3.1 cwnd growth on dup-ACKs.** Slow-start /
  CA growth fires only on cum-ACKs that ADVANCE SND.UNA. The
  existing `_process_ack_packet` already gates on
  `lt32(_snd_una, ack)` — keep using that gate.

- **Don't change the wire-level effective-window contract.**
  `_transmit_data` still gates on `_snd_ewn`. If we ever
  remove `_snd_ewn` and recompute on every transmit, do it
  in a separate refactor commit AFTER the cwnd / ssthresh
  semantics are stable.

- **Don't over-eager IW=10 in Phase 4 without checking peer
  win.** RFC 6928 says IW = `min(10*MSS, max(2*MSS, 14600))`,
  but `_snd_ewn` is then `min(IW, snd_wnd)` — peer's
  advertised window still bounds the actual transmittable
  amount. Tests that assert on the FIRST burst of segments
  need to confirm peer's win is large enough.

---

## 7. Estimated effort

| Phase | Description                                       | Commits | Risk    |
|-------|---------------------------------------------------|---------|---------|
| 1     | cwnd/ssthresh fields + slow-start vs CA           | 2-3     | medium  |
| 2     | RTO ssthresh reduction                            | 1-2     | low     |
| 3     | Fast-recovery cwnd inflation/deflation            | 2-3     | medium-high |
| 4     | RFC 6928 IW = 10                                  | 1       | low     |
| 5     | Convert plan to completion record                 | 1       | trivial |

Total: **7-10 commits**, ~4-6 hours of focused work.

---

## 8. Re-orient command for new sessions

```bash
git log --oneline --grep="cwnd\|RFC 5681\|congestion" master..HEAD
ls pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py 2>/dev/null
grep -n "_cwnd\|_ssthresh" pytcp/protocols/tcp/tcp__session.py | head
make test 2>&1 | tail -5
```

What it tells you:
- No cwnd grep matches → Phase 1 not started.
- `_cwnd` exists but no `test__rto__rto_sets_ssthresh_to_half_flight_size` → Phase 2 not started.
- All four phases visible → Phase 5 (docs) is the wrap-up.

Match against §4 to pick up where the prior session left off.

---

## 9. Cross-references

- Coding style: `.claude/rules/coding_style.md`
- Unit test authoring: `.claude/rules/unit_tests.md`
- Integration test workflow: `.claude/rules/tcp_session_integration_tests.md`
- Adjacent: `.claude/rules/tcp_rto_integration.md` §7.1 (cwnd
  interaction with `back_off`); `.claude/rules/tcp_sack_implementation.md`
  §7.1 (broader cwnd rework rationale).
