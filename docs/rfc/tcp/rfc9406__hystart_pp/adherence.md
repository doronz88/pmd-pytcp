# RFC 9406 — HyStart++: Modified Slow Start for TCP

| Field       | Value                                            |
|-------------|--------------------------------------------------|
| RFC number  | 9406                                             |
| Title       | HyStart++: Modified Slow Start for TCP           |
| Category    | Standards Track                                  |
| Date        | May 2023                                         |
| Source text | [`rfc9406.txt`](rfc9406.txt)                     |

This document records, paragraph by paragraph, how
the current PyTCP codebase relates to each normative
statement in RFC 9406. The audit was performed by
reading the RFC text fresh and inspecting the
codebase under `packages/pytcp/pytcp/protocols/tcp/` directly; no
prior memory or rule-file content was reused.
Sections without normative content (Abstract, §1
Introduction, §2 Terminology, §3 Definitions, §5
Deployments narrative, §6 Security narrative, §7
IANA, §8 References, Acknowledgments) are omitted.

---

## §4.2 HyStart++ Algorithm — Round tracking

### Round-end via SND.NXT marker

> "Define windowEnd as a sequence number initialized
> to SND.NXT. When windowEnd is ACKed, the current
> round ends and windowEnd is set to SND.NXT."

**Adherence:** met. `packages/pytcp/pytcp/protocols/tcp/tcp__session.py`
maintains `_hystart_state.window_end_seq` (a Seq32
field on the `HyStartState` dataclass). The session's
cum-ACK branch in `_process_ack_packet` bootstraps
the marker on the first cum-ACK in slow-start
(`window_end_seq = self._snd_nxt`) and rotates via
`tcp__hystart.rotate_round` whenever SND.UNA reaches
or passes the marker — exactly the §4.2 "windowEnd
ACKed → set windowEnd to SND.NXT" flow.

### Per-round RTT tracking

> "lastRoundMinRTT = currentRoundMinRTT;
> currentRoundMinRTT = infinity; rttSampleCount = 0"

**Adherence:** met. The `HyStartState` dataclass
carries `last_round_min_rtt_ms`, `current_round_min_rtt_ms`,
and `rtt_sample_count`. `tcp__hystart.fold_rtt_sample`
updates these on every fresh RTT sample (called from
both the TSecr-driven RTTM site and the Karn-style
sample-tracker harvest in `_process_ack_packet`).
`tcp__hystart.rotate_round` rotates them at each
round boundary per the §4.2 init formula. The
infinity sentinel is encoded as `-1`.

---

## §4.2 Slow-start exit trigger

> "if ((rttSampleCount >= N_RTT_SAMPLE) AND
>     (currentRoundMinRTT != infinity) AND
>     (lastRoundMinRTT != infinity))
>   RttThresh = max(MIN_RTT_THRESH,
>     min(lastRoundMinRTT / MIN_RTT_DIVISOR, MAX_RTT_THRESH))
>   if (currentRoundMinRTT >= (lastRoundMinRTT + RttThresh))
>     cssBaselineMinRtt = currentRoundMinRTT
>     exit slow start and enter CSS"

**Adherence:** met. `tcp__hystart.should_exit_slow_start_to_css`
encodes the §4.2 trigger: gates on `rtt_sample_count
>= N_RTT_SAMPLE`, both per-round minRTTs not at the
infinity sentinel, and computes `RttThresh` via
`tcp__hystart.rtt_thresh_ms` (the max/min clamp
formula). The session's `_hystart_check_phase_transition`
helper calls this after every fold and, on True,
invokes `tcp__hystart.enter_css` which records
`cssBaselineMinRtt = currentRoundMinRTT` and
initialises `css_rounds_remaining = CSS_ROUNDS`.

---

## §4.2 Conservative Slow Start (CSS) phase

> "For each arriving ACK in CSS, where N is the number
> of previously unacknowledged bytes acknowledged in
> the arriving ACK:
>   cwnd = cwnd + (min(N, L * SMSS) / CSS_GROWTH_DIVISOR)"

**Adherence:** met. The session's cum-ACK cwnd-update
branch checks `if self._cwnd < self._ssthresh and
self._hystart_state.in_css` and, when both, calls
`tcp__hystart.css_growth_increment(bytes_acked, smss)`
which returns `min(N, SMSS) // CSS_GROWTH_DIVISOR`
— the §4.2 formula with L=1 (the conservative
non-ABC variant; the L=8 ABC-style boost is
orthogonal to delay-detection and not enabled).

---

## §4.2 CSS resume-slow-start trigger

> "if (currentRoundMinRTT < cssBaselineMinRtt)
>   cssBaselineMinRtt = infinity
>   resume slow start including HyStart++"

**Adherence:** met. `tcp__hystart.should_resume_slow_start_from_css`
encodes the §4.2 spurious-exit check: gates on
`in_css`, `rtt_sample_count >= N_RTT_SAMPLE`, and
`current_round_min_rtt_ms < css_baseline_min_rtt_ms`.
The session's `_hystart_check_phase_transition`
calls this on every fold; on True it invokes
`tcp__hystart.resume_slow_start` which clears
`in_css`, sets `css_baseline_min_rtt_ms` back to the
infinity sentinel, and zeros `css_rounds_remaining`.

---

## §4.2 CSS-rounds-exhausted exit to CA

> "If CSS_ROUNDS rounds are complete, enter congestion
> avoidance by setting the ssthresh to the current
> cwnd. ssthresh = cwnd"

**Adherence:** met. The session's round-boundary
detection block in `_process_ack_packet` decrements
`css_rounds_remaining` on each rotation while
`in_css` (handled inside `tcp__hystart.rotate_round`).
When the counter reaches 0 at rotation, the session
sets `self._ssthresh = self._cwnd` and calls
`tcp__hystart.resume_slow_start` to clear CSS state
— exactly the §4.2 ssthresh-pinning entry into CA.

---

## §4.3 Tuning Constants

> "MIN_RTT_THRESH = 4 msec; MAX_RTT_THRESH = 16 msec;
> MIN_RTT_DIVISOR = 8; N_RTT_SAMPLE = 8;
> CSS_GROWTH_DIVISOR = 4; CSS_ROUNDS = 5;
> L = infinity if paced, L = 8 if non-paced"

**Adherence:** met. The §4.3 RECOMMENDED constants
are encoded in `packages/pytcp/pytcp/protocols/tcp/tcp__hystart.py`
as module-level integers:
`HYSTART__MIN_RTT_THRESH_MS = 4`,
`HYSTART__MAX_RTT_THRESH_MS = 16`,
`HYSTART__MIN_RTT_DIVISOR = 8`,
`HYSTART__N_RTT_SAMPLE = 8`,
`HYSTART__CSS_GROWTH_DIVISOR = 4`,
`HYSTART__CSS_ROUNDS = 5`. The `L` parameter is
implicitly 1 (PyTCP follows the non-ABC standard
slow-start cap; the §4.3 alternative `L = 8` for
non-paced or `L = infinity` for paced is not
enabled — orthogonal to the delay-detection mechanism
this audit covers).

---

## Test coverage audit

### §4.2 algorithm helpers

- **Unit:**
  `packages/pytcp/pytcp/tests/unit/protocols/tcp/test__tcp__hystart.py`
  contains 22 tests covering every helper in
  `tcp__hystart.py`: the §4.3 constants, the
  `rtt_thresh_ms` clamp formula across small / mid /
  large RTT inputs, `fold_rtt_sample` infinity
  sentinel handling and minimum tracking, round
  rotation (slow-start and CSS variants),
  `should_exit_slow_start_to_css` gate cases (sample
  count below N_RTT_SAMPLE, infinity sentinels,
  delta-exceeds-threshold), the symmetric
  `should_resume_slow_start_from_css` cases,
  `enter_css` baseline + counter init, `resume_slow_start`
  state clear, and `css_growth_increment` formula
  (full-SMSS and multi-SMSS cap-then-divide).

### §4.2 session integration

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__hystart.py`
  contains 5 tests pinning the session-level wiring:
  - `test__hystart__initial_state_is_slow_start` —
    post-handshake state is in slow-start, no CSS,
    no rotated round.
  - `test__hystart__rtt_sample_folded_during_slow_start`
    — TSecr-driven RTT samples flow into HyStart
    state.
  - `test__hystart__delay_increase_triggers_ss_to_css_transition`
    — `_hystart_check_phase_transition` enters CSS
    when the §4.2 trigger fires.
  - `test__hystart__css_resume_to_slow_start_on_rtt_recovery`
    — `_hystart_check_phase_transition` resumes SS
    on RTT recovery.
  - `test__hystart__stable_rtt_does_not_trigger_css`
    — negative control: stable RTT across rounds
    must not false-positive.

### Test coverage summary

| Aspect                                 | Coverage                                |
|----------------------------------------|-----------------------------------------|
| §4.2 round tracking via SND.NXT marker | locked in (unit + integration)          |
| §4.2 per-round min-RTT                 | locked in (unit fold + integration)     |
| §4.2 delay-based slow-start exit       | locked in (unit + integration)          |
| §4.2 CSS phase cwnd growth             | locked in (unit `css_growth_increment`) |
| §4.2 CSS resume-slow-start trigger     | locked in (unit + integration)          |
| §4.2 CSS-rounds-exhausted exit to CA   | locked in by construction (rotate decr) |
| §4.3 tuning constants                  | locked in (unit pin against RFC values) |

---

## Overall assessment

| Aspect                                 | Status                                    |
|----------------------------------------|-------------------------------------------|
| §4.2 round tracking                    | met (window_end_seq + rotate_round)       |
| §4.2 per-round min-RTT tracking        | met (fold_rtt_sample + rotate_round)      |
| §4.2 delay-based slow-start exit       | met (should_exit_slow_start_to_css)       |
| §4.2 CSS phase + 1/N growth            | met (css_growth_increment, divisor 4)     |
| §4.2 CSS resume-slow-start             | met (should_resume_slow_start_from_css)   |
| §4.2 CSS-rounds exhaustion exit to CA  | met (rotate_round decrements + ssthresh=cwnd) |
| §4.3 tuning constants                  | met (HYSTART__* constants pinned)         |
| §4.3 L parameter (paced/non-paced)     | n/a (L=1 standard slow-start cap)         |

PyTCP implements RFC 9406 HyStart++ at the algorithm
level: per-round minRTT tracking, the §4.2 delay-
increase trigger that exits slow-start to CSS, the
1/CSS_GROWTH_DIVISOR conservative growth in CSS, the
spurious-exit recovery that resumes slow-start when
RTT drops back, and the CSS_ROUNDS exhaustion that
sets ssthresh = cwnd to enter congestion avoidance.
Helper logic is decomposed into `tcp__hystart.py` as
pure functions over a `HyStartState` dataclass; the
session-level wiring lives in `_process_ack_packet`
(round-boundary detection, fold sites, cwnd-growth
override) and the `_hystart_check_phase_transition`
helper (called after each fold).

The L parameter is implicitly 1 (RFC 5681 standard
slow-start cap). The §4.3 alternative L=8 (non-paced
ABC-style boost) or L=infinity (paced) is not
enabled — orthogonal to the delay-detection
mechanism, can be added in a future commit if
appropriate-byte-counting is desired.

This is a known and intentional gap — RFC 9438 §4.10
(CUBIC) recommends HyStart++ as a companion, and
PyTCP's CUBIC implementation references the gap as
deferred work. Estimated effort to land: ~6-8
commits with new state fields, RTT-tracking
integration, and a CSS phase added to
`tcp__cwnd.py`.
