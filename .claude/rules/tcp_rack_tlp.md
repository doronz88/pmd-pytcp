# PyTCP — RFC 8985 RACK-TLP: Project Plan

Detailed handoff plan for implementing strict RFC 8985
(Recent ACKnowledgment + Tail Loss Probe) in PyTCP. Reads
as a self-contained project brief; a fresh post-compact
session should pick this file up and execute the phases
below verbatim.

The RFC 8985 text is available at
`docs/rfc/tcp/rfc8985__rack_tlp/rfc8985.txt`. All section
references in this plan refer to that document.

---

## 1. Mission

Implement strict RFC 8985 RACK-TLP loss detection and tail
loss probing on top of PyTCP's existing TCP stack. The
target end-state:

1. **RACK** replaces RFC 5681 §3.2's three-dup-ACK
   fast-retransmit trigger with a time-based scheme: a
   segment is declared lost if a later-sent segment was
   delivered AND a sufficient reordering window has
   elapsed.
2. **TLP** sends a probe at `2*SRTT` (`+ max_ack_delay` if
   `FlightSize == 1`) when there is unacked data but no
   new data to send, eliciting an ACK that lets RACK
   detect tail-of-flow losses much faster than the RTO
   timer.
3. **Timer arbitration** per §8: RACK reordering timer,
   TLP PTO, and RTO are mutually exclusive on a session;
   the implementation maintains one active timer with a
   type tag.
4. Existing fast-retransmit (RFC 5681 §3.2 / RFC 6675),
   RTO recovery (RFC 6298), and F-RTO (RFC 5682) continue
   to function alongside RACK-TLP per the §9.2
   coexistence guidance.

End state preserves all currently-passing tests; the new
RACK-TLP machinery adds 9 phases of incremental
behaviour, each pinned by an integration test.

---

## 2. Standing principles

1. **Tests-first per phase.** Each phase opens with a
   `[FLAGS BUG]` failing test commit, followed by a fix
   commit. The fix names the test it flips green in its
   commit body. Mirrors the workflow shipped on every
   prior phased project (SACK, ECN, AccECN, F-RTO, ABE).

2. **Strict RFC 8985.** The pseudocode in §6 and §7 is
   the ground truth. Where Linux deviates, follow the
   RFC. Where the RFC is silent, prefer the conservative
   choice (bigger reo_wnd, longer PTO, etc.).

3. **Suite invariant.** After every commit:
   `make lint` clean. `make test` passes (existing tests
   never regress; new tests flip green per their phase).

4. **Test-count baseline at project start.** 8155 passing
   (from `08b174a`). Each phase adds tests; final target
   approximately +25 to +35 tests.

5. **Per-segment data structure.** A new `dict[Seq32,
   RackSegment]` lives on `TcpSession`. The dict is the
   ground truth for the per-segment state RACK needs:
   `xmit_ts`, `lost`, `retransmitted`, `end_seq`. SACK
   scoreboard remains for SACK block storage; the RACK
   segment dict is a separate concern.

6. **No mixing with F-RTO state.** F-RTO's recovery
   snapshot fields (`_frto_active`, `_frto_pre_*`) stay
   independent. RACK loss-detection runs ALONGSIDE F-RTO
   (different scenarios). Per RFC 8985 §7.2, TLP is
   skipped when F-RTO is in progress (`_frto_active`).

7. **Test docstring format.** Per `unit_tests.md` §7:
   ``Ensure ...`` description + blank line + ``Reference:
   RFC 8985 §<X> (<short>).`` line.

---

## 3. Target architecture (final state)

### 3.1 New module: `pytcp/protocols/tcp/tcp__rack.py`

Pure-function helpers (parallel to the `tcp__rto.py`,
`tcp__cwnd.py`, `tcp__sack.py`, `tcp__newreno.py`,
`tcp__loss_recovery.py` pattern). Exposes:

```python
@dataclass(frozen=True, kw_only=True, slots=True)
class RackSegment:
    """Per-segment RACK state per RFC 8985 §5.2."""
    end_seq: int                 # Segment.end_seq
    xmit_ts: int                 # Segment.xmit_ts (ms; INFINITE_TS if lost)
    retransmitted: bool          # Segment.retransmitted
    lost: bool                   # Segment.lost

INFINITE_TS = 0xFFFF_FFFF       # Per §5.2 "invalid timestamp" marker

def rack_sent_after(t1, seq1, t2, seq2) -> bool:
    """RFC 8985 §6.2 step 2 helper: lexicographic (xmit_ts, end_seq)."""

def rack_compute_reo_wnd(*, reordering_seen, reo_wnd_mult,
                          min_rtt_ms, srtt_ms,
                          segs_sacked, dup_thresh,
                          in_recovery) -> int:
    """RFC 8985 §6.2 step 4 RACK_update_reo_wnd()."""

def rack_detect_loss(segments: dict[int, RackSegment],
                     rack_xmit_ts: int, rack_end_seq: int,
                     rack_rtt_ms: int, reo_wnd_ms: int,
                     now_ms: int) -> int:
    """RFC 8985 §6.2 step 5 RACK_detect_loss(); returns
    timeout (ms) for the reordering timer (0 means none).
    Marks segments lost in-place via .lost = True."""

def tlp_calc_pto(*, srtt_ms, flight_size, smss,
                 max_ack_delay_ms, rto_expiration_ms,
                 now_ms) -> int:
    """RFC 8985 §7.2 TLP_calc_PTO()."""
```

### 3.2 New TcpSession fields (~13)

```python
# Per-segment storage (§5.2).
self._rack_segments: dict[Seq32, RackSegment] = {}

# Per-connection state (§5.3).
self._rack_xmit_ts: int = 0          # RACK.xmit_ts
self._rack_end_seq: Seq32 = 0        # RACK.end_seq
self._rack_segs_sacked: int = 0      # RACK.segs_sacked
self._rack_fack: Seq32 = 0           # RACK.fack
self._rack_min_rtt_ms: int = 0       # RACK.min_RTT
self._rack_rtt_ms: int = 0           # RACK.rtt
self._rack_reordering_seen: bool = False
self._rack_reo_wnd_ms: int = 0       # RACK.reo_wnd
self._rack_dsack_round: Seq32 | None = None
self._rack_reo_wnd_mult: int = 1
self._rack_reo_wnd_persist: int = 16

# TLP state (§5.3 / §7.1).
self._tlp_is_retrans: bool = False
self._tlp_end_seq: Seq32 | None = None
self._tlp_max_ack_delay_ms: int = 25  # Linux default
```

### 3.3 Timer additions (§5.4)

Two new named timers, mutually exclusive with the existing
RTO timer per §8:

- `f"{self}-rack"`: RACK reordering timer
- `f"{self}-tlp"`: TLP PTO timer

`_rearm_session_timer()` helper that picks ONE of {RACK,
TLP, RTO} and arms it; cancels the others.

### 3.4 Hook points in `tcp__session.py`

- `_transmit_packet`: insert a `RackSegment` for every
  outbound data segment (new + retransmit).
- `_process_ack_packet`: run `rack_update()` (§6.2 step
  1-4), `rack_detect_loss()` (§6.2 step 5), then
  `tlp_process_ack()` (§7.4).
- `_retransmit_packet_timeout`: run
  `rack_mark_losses_on_RTO()` (§6.3); coordinate with
  existing F-RTO snapshot.
- New timer callbacks: `_on_rack_reorder_timer()` and
  `_on_tlp_pto_timer()`.

---

## 4. Phase-by-phase plan

Each phase is one tests-first commit + one fix commit
(some phases combine multiple sub-steps into a single
commit pair when the change set is naturally atomic).

### Phase 1: Per-segment xmit_ts substrate (§6.1)

**Goal**: every outbound data segment is tracked with its
xmit_ts; the dict stays consistent on cum-ACK pruning
(removes acked segments).

**New state**:
- `pytcp/protocols/tcp/tcp__rack.py` with `RackSegment`
  dataclass + `INFINITE_TS` constant
- `TcpSession._rack_segments: dict[Seq32, RackSegment]`

**Hooks**:
- `_transmit_packet` after `send_tcp_packet`: insert
  `RackSegment(end_seq=snd_nxt+payload_len, xmit_ts=now_ms,
  retransmitted=is_retransmit, lost=False)` keyed by the
  segment's starting seq.
- `_process_ack_packet` after SND.UNA advances: prune
  entries with `end_seq <= SND.UNA` (modular).

**Tests** (new `test__tcp__session__rack.py` integration):
1. `test__rack__outbound_data_segment_records_rack_segment`
   [FLAGS BUG] — drives an active-open + send, asserts
   `session._rack_segments` contains an entry with the
   expected `xmit_ts` and `end_seq`.
2. `test__rack__cumulative_ack_prunes_acked_segments`
   [FLAGS BUG] — sends 3 segments, peer ACKs all,
   asserts dict is empty.

**Unit tests** (new `test__tcp__rack.py`): RackSegment
construction asserts; INFINITE_TS constant value.

### Phase 2: RACK Step 1-2 — min_rtt / rtt / xmit_ts / end_seq tracking

**Goal**: on every accepted ACK, update RACK
per-connection scalars per §6.2 steps 1-2.

**New helper** in `tcp__rack.py`:
```python
def rack_update(*, segments, ack_ts_ms, ack_seq, sack_blocks,
                ts_recent_echo_ms, min_rtt_ms, prior_rack_xmit_ts,
                prior_rack_end_seq) -> tuple[int, int, int, int]:
    """
    Returns (new_min_rtt, new_rack_rtt, new_rack_xmit_ts, new_rack_end_seq).
    Implements pseudocode:
        For each newly-acked Segment in ascending xmit_ts order:
            rtt = now - Segment.xmit_ts
            If Segment.retransmitted:
                If TSecr < Segment.xmit_ts: continue
                If rtt < min_rtt: continue
            RACK.rtt = rtt
            If RACK_sent_after(Segment.xmit_ts, Segment.end_seq,
                               RACK.xmit_ts, RACK.end_seq):
                RACK.xmit_ts = Segment.xmit_ts
                RACK.end_seq = Segment.end_seq
    """
```

**Hooks**:
- `_process_ack_packet`: call `rack_update()` after
  `_rack_segments` cleanup, fold result into
  `_rack_min_rtt_ms` / `_rack_rtt_ms` / `_rack_xmit_ts` /
  `_rack_end_seq`.

**Tests**:
1. `test__rack__cum_ack_updates_rack_xmit_ts_and_rtt`
   [FLAGS BUG] — drives a send + cum-ACK; asserts
   `_rack_xmit_ts` matches the send's xmit_ts, `_rack_rtt_ms`
   matches the elapsed time.
2. `test__rack__retransmit_with_stale_tsecr_skipped` — a
   retransmitted segment whose ACK has TSecr indicating
   the original (not the retransmit) is skipped per §6.2
   step 2 condition 1.
3. `test__rack__min_rtt_tracks_smallest_observed` — over
   multiple ACKs, `_rack_min_rtt_ms` stays at the lowest.

### Phase 3: RACK Step 5 — time-based loss detection (no reordering)

**Goal**: implement `rack_detect_loss()` with `reo_wnd =
0` (no reordering tracking yet). On every ACK, mark
segments lost if `Segment.xmit_ts + RACK.rtt - now <= 0`
AND `RACK_sent_after(RACK.xmit_ts, RACK.end_seq,
Segment.xmit_ts, Segment.end_seq)`.

**Behaviour change**: when RACK detects a loss, the
segment is queued for retransmit via the existing
`_retransmit_packet_request()` machinery (or a new
`_retransmit_rack_lost_segments()` helper that walks
`_rack_segments` for `lost=True` entries).

**Tests**:
1. `test__rack__time_based_loss_detection_marks_old_segment_lost`
   [FLAGS BUG] — sends 2 segments back-to-back; peer
   SACKs only the second; asserts the first is marked
   lost AND retransmitted (the time-based RACK trigger,
   replacing the dup-ACK trigger).

### Phase 4: RACK Step 3-4 — reordering detection + reo_wnd adaptation

**Goal**: implement `rack_detect_reordering()` (§6.2 step
3) and `rack_update_reo_wnd()` (§6.2 step 4) including
DSACK-driven adaptation.

**New helper**: `rack_compute_reo_wnd()` per §6.2 step 4
pseudocode (full DSACK round handling).

**Hooks**:
- `_process_ack_packet`: track `_rack_fack` (highest
  selectively/cumulatively acked seq); set
  `_rack_reordering_seen = True` on out-of-order
  delivery.
- DSACK detection (existing `_pending_dsack` /
  `_dsack_received` substrate from RFC 2883) feeds the
  DSACK round update.

**Tests**:
1. `test__rack__reordering_detected_when_segment_below_fack_acked`
   [FLAGS BUG] — sends 3 segments, peer SACKs 1 and 3,
   then later cum-ACKs all; asserts
   `_rack_reordering_seen = True`.
2. `test__rack__reo_wnd_grows_on_dsack` [FLAGS BUG] —
   peer's DSACK indicates spurious retransmit;
   `_rack_reo_wnd_mult` increments.
3. `test__rack__reo_wnd_resets_after_16_recoveries` —
   regression guard for `_rack_reo_wnd_persist`.

### Phase 5: RACK reordering timer (§6.2 last paragraph)

**Goal**: when `rack_detect_loss()` returns a positive
`timeout`, arm a RACK reordering timer that re-runs the
detection on expiry. The timer is mutually exclusive with
the existing RTO timer per §8.

**New hooks**:
- `_on_rack_reorder_timer()`: callback that re-invokes
  `rack_detect_loss()` and either retransmits losses or
  re-arms the timer.
- `_rearm_session_timer()`: helper that picks ONE of
  {RACK, TLP, RTO} based on the current state and arms
  it; cancels the others.

**Tests**:
1. `test__rack__reorder_timer_arms_when_segment_below_threshold`
   [FLAGS BUG] — sends a segment, peer SACKs a later one
   but `RACK.rtt + reo_wnd` hasn't elapsed for the
   earlier one; asserts the RACK timer is registered.
2. `test__rack__reorder_timer_fires_and_marks_lost` —
   advance time past the timer; assert the segment is
   marked lost on timer expiry.

### Phase 6: TLP PTO scheduling (§7.2)

**Goal**: implement `tlp_calc_pto()` and arm the TLP timer
on data send / cum-ACK as specified in §7.2.

**New helper**:
```python
def tlp_calc_pto(*, srtt_ms, flight_size, smss,
                  max_ack_delay_ms,
                  rto_expiration_ms, now_ms) -> int:
    """
    If SRTT available:
        PTO = 2 * SRTT
        If FlightSize == 1 segment:
            PTO += max_ack_delay
    Else:
        PTO = 1000 ms
    If now + PTO > rto_expiration:
        PTO = rto_expiration - now
    """
```

**Hooks**:
- `_transmit_packet` after data send: arm TLP timer
  (`f"{self}-tlp"`) iff none of: in fast recovery, RTO
  recovery, `RACK.segs_sacked > 0`, F-RTO active.
- `_process_ack_packet` on cum-ACK that drains all
  in-flight: cancel TLP timer.

**Tests**:
1. `test__tlp__pto_timer_armed_after_data_send` [FLAGS
   BUG] — drives a send, asserts `f"{session}-tlp"` is
   registered with the expected timeout.
2. `test__tlp__pto_calc_uses_2_srtt` — verify the
   computed PTO matches `2 * SRTT` for typical case.
3. `test__tlp__pto_inflated_for_single_segment_flightsize`
   — when FlightSize is one segment, PTO includes
   `max_ack_delay`.

### Phase 7: TLP probe emission (§7.3)

**Goal**: when the TLP PTO fires, send the probe per §7.3:
prefer new data (segment starting at `SND.NXT`), fall
back to retransmit of the highest-seq segment. Set
`TLP.is_retrans` and `TLP.end_seq` accordingly.

**New hook**: `_on_tlp_pto_timer()` callback.

**Tests**:
1. `test__tlp__probe_sends_new_data_when_available` —
   queue more data than cwnd allows, advance to PTO,
   assert probe is the new (next-after-SND.NXT) segment.
2. `test__tlp__probe_retransmits_highest_seq_when_no_new_data`
   — no data to send, advance to PTO, assert probe is
   the highest-seq segment retransmitted, `_tlp_is_retrans
   = True`.
3. `test__tlp__probe_re_arms_rto_after_send` — per §7.3
   "After attempting to send a loss probe ... re-arm the
   RTO timer".

### Phase 8: TLP loss detection (§7.4)

**Goal**: on each inbound ACK, run `tlp_process_ack()` per
§7.4 to clear `TLP.end_seq` in the appropriate cases AND
trigger the congestion control response when the probe
itself repaired a single tail loss (§7.4.2).

**New helper** in `tcp__rack.py`:
```python
def tlp_process_ack(*, tlp_end_seq, tlp_is_retrans,
                     ack_seq, dsack_blocks, sack_blocks
                    ) -> tuple[Seq32 | None, bool]:
    """Returns (new_tlp_end_seq, should_invoke_cc_response)."""
```

Implements §7.4.2 pseudocode:
- If `ack >= tlp_end_seq` AND not is_retrans: clear
  `tlp_end_seq` (probe of new data delivered; no loss).
- Elif ACK has DSACK matching tlp_end_seq: clear,
  spurious retransmit (Case 1).
- Elif `ack > tlp_end_seq`: clear, single-loss-repaired,
  invoke CC response (Case 3 in pseudocode).
- Elif ACK is dup-ACK without SACK: clear (Case 2).

**Tests**:
1. `test__tlp__cc_response_fires_on_single_loss_probe_repair`
   [FLAGS BUG] — drives a tail-loss scenario (1 segment
   lost, probe = retransmit of it, peer ACKs the probe);
   asserts ssthresh halved (the §7.4.2 CC response).
2. `test__tlp__dsack_match_clears_state_no_cc_response`
   — peer's DSACK matches `tlp_end_seq`, asserts
   `_tlp_end_seq = None` and ssthresh unchanged.
3. `test__tlp__dup_ack_without_sack_clears_state` —
   regression guard for §7.4.2 Case 2.

### Phase 9: RTO integration (§6.3 + §8 timer arbitration)

**Goal**: `rack_mark_losses_on_RTO()` per §6.3 marks all
segments lost (or just the oldest if their xmit_ts +
rtt + reo_wnd is past). Plus full §8 timer arbitration:
RACK / TLP / RTO are mutually exclusive at all times.

**Hooks**:
- `_retransmit_packet_timeout`: after the existing F-RTO
  snapshot, walk `_rack_segments` and apply the §6.3
  rule.
- `_rearm_session_timer()` consolidates timer arbitration.

**Tests**:
1. `test__rack__rto_marks_first_segment_and_old_others_lost`
   [FLAGS BUG] — drives an RTO, asserts the first
   segment is marked lost regardless, others only if
   `xmit_ts + rtt + reo_wnd <= now`.
2. `test__rack_tlp__timers_are_mutually_exclusive` —
   regression guard: assert at most one of
   `f"{self}-rack"`, `f"{self}-tlp"`, `f"{self}-retransmit"`
   is registered at any time.

---

## 5. Implementation effort

| Phase | Test files touched | New code (LOC est) | Commits |
|---|---|---|---|
| 1 | `tcp__rack.py` (new) + 1 integration | ~80 | 2 |
| 2 | `tcp__rack.py` + integration | ~60 | 2 |
| 3 | `tcp__rack.py` + integration | ~80 | 2 |
| 4 | `tcp__rack.py` + integration | ~120 | 2 |
| 5 | session + integration | ~60 | 2 |
| 6 | `tcp__rack.py` + integration | ~70 | 2 |
| 7 | session + integration | ~80 | 2 |
| 8 | `tcp__rack.py` + integration | ~70 | 2 |
| 9 | session + integration | ~60 | 2 |

**Total**: ~18 commits, ~700 LOC of production code +
unit tests + ~25-35 integration tests. The largest
single project shipped on this branch.

---

## 6. Anti-patterns to avoid

- **Don't reuse the SACK scoreboard for RACK segment
  storage.** They serve different purposes: SACK
  scoreboard tracks peer's SACK blocks; RACK segments
  track our own outbound transmission timestamps. Keep
  them separate; the lifecycle differs (RACK segments
  are removed on cum-ACK or marked lost; SACK blocks
  are pruned on cum-ACK only).

- **Don't conflict with F-RTO recovery_point.** F-RTO's
  `_frto_active` flag and the RACK loss-detection are
  independent. RACK runs on every ACK; F-RTO runs once
  per RTO event. Both can be true simultaneously without
  conflict (F-RTO restoration on spurious RTO + RACK
  loss detection on partial ACK both fire correctly).

- **Don't fire fast-retransmit twice** for the same
  segment. Phase 3's RACK loss detection effectively
  replaces (or fires faster than) the RFC 5681 §3.2
  three-dup-ACK trigger. Per §6.2 step 4: when no
  reordering has been observed, RACK behaves like the
  classic dup-ACK trigger by setting `reo_wnd = 0` and
  letting `segs_sacked >= DupThresh` fire fast recovery.
  When reordering is observed, RACK is the SOLE trigger
  (the dup-ACK path is suppressed). Implement this
  gating explicitly in `_retransmit_packet_request()`.

- **Don't skip the §6.2 step 2 spurious-retransmit
  guards.** The two conditions (TSecr stale, RTT < min_rtt)
  prevent the RACK.rtt from being polluted by spurious-
  retransmit RTTs. Skipping them would cause RACK.rtt to
  collapse on every spurious retransmit and cascade
  spurious loss declarations.

- **Don't use floating-point math in `compute_reo_wnd`.**
  The RFC pseudocode reads `min_RTT/4` etc. — use
  integer division (`min_rtt_ms // 4`). PyTCP's
  established convention is integer-only timer arithmetic.

- **Don't mix the RACK timer with the existing
  retransmit timer.** §8 mandates mutual exclusion.
  Use a NEW timer key (`f"{self}-rack"`); cancel the RTO
  timer when arming RACK reorder timer. The
  `_rearm_session_timer()` helper centralises this.

- **Don't split the per-segment dict by RTO event.** A
  single `_rack_segments` dict holds all in-flight
  segments. RTO doesn't reset it; only cum-ACK or
  loss-mark removes entries.

- **Don't add a dependency on RFC 7323 timestamps.**
  RACK works without timestamps (the second §6.2 step 2
  condition handles that). The TSecr check is a fast-
  path optimization for connections that negotiated
  timestamps; the `rtt < min_rtt` heuristic is the
  non-timestamps fallback.

- **Don't forget `Segment.xmit_ts = INFINITE_TS` on
  loss-mark.** Per §5.2, a lost segment has its xmit_ts
  set to INFINITE_TS to indicate "not currently in
  flight". Subsequent ACK processing uses this to skip
  the segment.

---

## 7. Re-orient command for new sessions

After loading this rule, run:

```bash
git log --oneline --grep="RACK\|RFC 8985\|TLP" master..HEAD
make test 2>&1 | tail -5
ls pytcp/protocols/tcp/tcp__rack.py 2>/dev/null
ls pytcp/tests/integration/protocols/tcp/test__tcp__session__rack.py 2>/dev/null
ls pytcp/tests/integration/protocols/tcp/test__tcp__session__tlp.py 2>/dev/null
```

What it tells you:
- No `tcp__rack.py` → Phase 1 not started.
- `tcp__rack.py` exists but no `_rack_xmit_ts` field on
  TcpSession → Phase 2 not started.
- ... (match against §4 to find current phase).

---

## 8. Cross-references

- RFC text: `docs/rfc/tcp/rfc8985__rack_tlp/rfc8985.txt`
- Adjacent shipped: `tcp_sack_implementation.md` (RFC
  2018 + 6675 SACK; RACK uses the SACK scoreboard
  events as input).
- Adjacent shipped: `tcp_rfc7323_timestamps.md` (RFC
  7323 timestamps; RACK §6.2 step 2 uses TSecr for the
  spurious-retransmit guard).
- Adjacent shipped: `tcp_rto_integration.md` (RFC 6298
  RTO; RACK reuses the RTO state for `srtt_ms` /
  `min_rtt_ms`).
- Adjacent shipped: F-RTO is in commit `e34fdb4`
  (substrate ready for §7.2's F-RTO-active TLP skip).
- Workflow + reporting format:
  `tcp_session_integration_tests.md` §7.
- Coding style: `coding_style.md`.
- Unit test authoring: `unit_tests.md`.
- Test docstring rule: `unit_tests.md` §7 + §7.1.

---

## 9. Quick-start for fresh post-compact session

```
Implement strict RFC 8985 RACK-TLP per
.claude/rules/tcp_rack_tlp.md. Start at the earliest
unstarted phase per the §7 re-orient command. Tests-
first per phase, fix-second. Do not deviate from the
phase plan or the strict-RFC-8985 directive.
```

After loading the rule, the agent should know exactly
where to start and what each commit looks like.

---

## 10. Test-file naming

Per `unit_tests.md` §3 (mapping for `pytcp/protocols/tcp/`):

- Unit tests for `tcp__rack.py`:
  `pytcp/tests/unit/protocols/tcp/test__tcp__rack.py`
- Integration tests:
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__rack.py`
  (RACK detection + reordering + RTO)
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__tlp.py`
  (TLP PTO + probe + loss detection)

The integration tests split into two files because the
test surfaces are large enough that a single file would
exceed the project's typical ~600 line per-file budget.
