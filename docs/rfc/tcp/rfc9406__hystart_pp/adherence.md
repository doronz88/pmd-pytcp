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
codebase under `pytcp/protocols/tcp/` directly; no
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

**Adherence:** not implemented. PyTCP has no
`_hystart_window_end` or equivalent round-tracking
state on `TcpSession`. A grep across
`pytcp/protocols/tcp/` returns no `HyStart` /
`hystart` / `windowEnd` references.

### Per-round RTT tracking

> "lastRoundMinRTT = currentRoundMinRTT;
> currentRoundMinRTT = infinity; rttSampleCount = 0"

**Adherence:** not implemented. PyTCP tracks SRTT and
RTTVAR via the RFC 6298 RTO machinery (`_rto_state`)
and a min RTT for RACK (`_rack_min_rtt_ms`), but does
NOT track the separate per-round `lastRoundMinRTT` /
`currentRoundMinRTT` / `rttSampleCount` HyStart++
needs.

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

**Adherence:** not implemented. PyTCP exits slow start
only when `cwnd >= ssthresh` per the canonical RFC
5681 §3.1 path in
`pytcp/protocols/tcp/tcp__cwnd.py:cwnd_grow_per_ack`.
There is no delay-based slow-start exit.

---

## §4.2 Conservative Slow Start (CSS) phase

> "For each arriving ACK in CSS, where N is the number
> of previously unacknowledged bytes acknowledged in
> the arriving ACK:
>   cwnd = cwnd + (min(N, L * SMSS) / CSS_GROWTH_DIVISOR)"

**Adherence:** not implemented. PyTCP has only two
cwnd-growth phases: slow-start (RFC 5681 §3.1) and
congestion-avoidance (RFC 5681 §3.1 / RFC 9438 CUBIC).
The intermediate CSS phase that grows cwnd at
1/CSS_GROWTH_DIVISOR rate is absent.

---

## §4.2 CSS resume-slow-start trigger

> "if (currentRoundMinRTT < cssBaselineMinRtt)
>   cssBaselineMinRtt = infinity
>   resume slow start including HyStart++"

**Adherence:** not implemented (no CSS phase exists).

---

## §4.2 CSS-rounds-exhausted exit to CA

> "If CSS_ROUNDS rounds are complete, enter congestion
> avoidance by setting the ssthresh to the current
> cwnd. ssthresh = cwnd"

**Adherence:** not implemented (no CSS phase exists).

---

## §4.3 Tuning Constants

> "MIN_RTT_THRESH = 4 msec; MAX_RTT_THRESH = 16 msec;
> MIN_RTT_DIVISOR = 8; N_RTT_SAMPLE = 8;
> CSS_GROWTH_DIVISOR = 4; CSS_ROUNDS = 5;
> L = infinity if paced, L = 8 if non-paced"

**Adherence:** not implemented. None of these
constants exist in `pytcp/protocols/tcp/`.

---

## Test coverage audit

No HyStart++ tests exist in the codebase. The slow-
start path is tested through the RFC 5681 / RFC 6928
integration tests in
`pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py`
which verify the canonical exponential growth and
ssthresh-driven exit.

### Test coverage summary

| Aspect                                  | Coverage   |
|-----------------------------------------|------------|
| §4.2 round tracking via SND.NXT marker  | n/a (gap)  |
| §4.2 per-round min-RTT                  | n/a (gap)  |
| §4.2 delay-based slow-start exit        | n/a (gap)  |
| §4.2 CSS phase cwnd growth              | n/a (gap)  |
| §4.2 CSS resume-slow-start trigger      | n/a (gap)  |
| §4.2 CSS-rounds-exhausted exit to CA    | n/a (gap)  |
| §4.3 tuning constants                   | n/a (gap)  |

---

## Overall assessment

| Aspect                                | Status          |
|---------------------------------------|-----------------|
| §4.2 round tracking                   | not implemented |
| §4.2 per-round min-RTT tracking       | not implemented |
| §4.2 delay-based slow-start exit      | not implemented |
| §4.2 CSS phase + 1/N growth           | not implemented |
| §4.2 CSS resume-slow-start            | not implemented |
| §4.2 CSS-rounds exhaustion exit to CA | not implemented |
| §4.3 tuning constants                 | not implemented |
| §4.3 implementation in initial-SS only | n/a            |

PyTCP does not implement HyStart++. Slow start uses
the canonical RFC 5681 §3.1 exponential growth and
exits only when `cwnd >= ssthresh`. The performance
benefits HyStart++ provides (reduced packet loss
during slow-start overshoot) are not available in
PyTCP.

This is a known and intentional gap — RFC 9438 §4.10
(CUBIC) recommends HyStart++ as a companion, and
PyTCP's CUBIC implementation references the gap as
deferred work. Estimated effort to land: ~6-8
commits with new state fields, RTT-tracking
integration, and a CSS phase added to
`tcp__cwnd.py`.
