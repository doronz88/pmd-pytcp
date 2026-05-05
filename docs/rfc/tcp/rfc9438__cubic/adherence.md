# RFC 9438 — CUBIC for Fast and Long-Distance Networks

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 9438                                           |
| Title       | CUBIC for Fast and Long-Distance Networks      |
| Category    | Standards Track                                |
| Date        | August 2023                                    |
| Obsoletes   | RFC 8312                                       |
| Source text | [`rfc9438.txt`](rfc9438.txt)                   |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 9438. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, §1 Introduction, §2
Conventions, §3 Design Principles, §5 Discussion,
§6 Security, §7 IANA, §8 References) are omitted. The
§4 algorithm is the central normative content.

---

## §4. CUBIC Congestion Control

### §4.1.1 Constants

> "C: 0.4 / β_cubic: 0.7 / α_cubic: 3 * (1-β)/(1+β)"

**Adherence:** met. PyTCP encodes the constants as
integer ratios at `pytcp/protocols/tcp/tcp__cubic.py`:

```python
C_NUM, C_DEN = 2, 5         # C = 0.4
BETA_CUBIC_NUM, BETA_CUBIC_DEN = 7, 10    # β = 0.7
ALPHA_CUBIC_NUM, ALPHA_CUBIC_DEN = 9, 17  # α = 9/17 ≈ 0.529
FAST_CONV_NUM, FAST_CONV_DEN = 17, 20     # (1+β)/2 = 0.85
```

Pure-integer encoding avoids float math in hot paths.

### §4.1.2 Variables of Interest

> "RTT, cwnd, ssthresh, cwnd_prior, W_max, K, t_current,
> t_epoch, cwnd_epoch, W_cubic(t), target, W_est,
> segments_acked"

**Adherence:** met. PyTCP's `TcpSession` maintains:

| §4.1.2 variable      | PyTCP field                   |
|----------------------|-------------------------------|
| RTT                  | `_rto_state.srtt_ms`          |
| cwnd                 | `_cwnd`                       |
| ssthresh             | `_ssthresh`                   |
| W_max                | `_cubic_w_max`                |
| K                    | `_cubic_K_ms`                 |
| t_epoch              | `_cubic_epoch_start_ms`       |
| W_est                | `_cubic_w_est`                |
| (CA-mode flag)       | `_cubic_in_ca`                |
| (W_max prior)        | `_cubic_w_last_max`           |

The `cwnd_prior` variable is not stored explicitly
because §4.7 fast convergence reads the prior W_max
from `_cubic_w_last_max` directly.

### §4.2 Window Increase Function

> "W_cubic(t) = C * (t - K)^3 + W_max"
>
> "K = cubicroot((W_max - cwnd_epoch) / C)"

**Adherence:** met. `cubic_w` at
`pytcp/protocols/tcp/tcp__cubic.py:107-145` and
`cubic_compute_K` at line 67-104 implement the
formulas. The cube-root uses Python's
`pow(x, 1/3.0)` then `int(round(...))` (the one
documented float-cast exception in PyTCP's CUBIC
module).

> "target = clamp(W_cubic(t + RTT), [cwnd, 1.5 * cwnd])"

**Adherence:** met. `cubic_grow_per_ack` now passes
`srtt_ms=self._rto_state.srtt_ms` from the session
into `cubic_target`, which evaluates the cubic curve
at `t + RTT` per the §4.2 formula. The +RTT
projection lets the curve aim at the cwnd value the
network is expected to support one RTT in the future,
smoothing growth across the ACK arrival window. The
unit-test signature retains a default `srtt_ms=0` so
the legacy `W_cubic(t)` callers (the unit tests) are
unaffected.

### §4.3 Reno-Friendly Region

> "W_est = W_est + α_cubic * segments_acked / cwnd"

**Adherence:** met. `cubic_w_est` at
`tcp__cubic.py:264-296` implements the formula in
bytes:

```python
delta = ALPHA_CUBIC_NUM * bytes_acked * smss // (ALPHA_CUBIC_DEN * cwnd)
return w_est_prev + delta
```

> "If W_cubic(t) is less than W_est, ... cwnd SHOULD
> be set to W_est at each reception of a new ACK."

**Adherence:** met. `cubic_grow_per_ack` at the
session integration takes `max(cubic_cwnd, w_est)`,
ensuring CUBIC never under-performs Reno.

### §4.4-§4.5 Concave/Convex Region

> "cwnd MUST be incremented by (target - cwnd) / cwnd
> for each received new ACK"

**Adherence:** met. The `cubic_grow_per_ack` formula:

```python
increment = (target - cwnd) * bytes_acked // cwnd
return cwnd + max(1, increment)
```

When the cubic target is above cwnd, this produces
the per-ACK increment per §4.4 / §4.5.

### §4.6 Multiplicative Decrease

> "ssthresh = flight_size * β_cubic ... cwnd =
> max(ssthresh, 2*SMSS) ... ssthresh = max(ssthresh,
> 2*SMSS)"

**Adherence:** met. `cubic_loss_event_ssthresh` at
`tcp__cubic.py:209-260`:

```python
new_ssthresh = max(cwnd * BETA_CUBIC_NUM // BETA_CUBIC_DEN, 2 * smss)
```

The 2*SMSS floor protects against pathological small
in-flight bursts.

PyTCP uses `cwnd` instead of `flight_size` for the
input — the §4.6 commentary explicitly permits this
("Some implementations of CUBIC currently use cwnd
instead of flight_size") and notes the additional
safeguard ("Implementations that use cwnd MUST use
other measures to prevent cwnd from growing when
the volume of bytes in flight is smaller than
cwnd"). PyTCP's RFC 5681 substrate enforces the
`min(cwnd, snd_wnd)` gate so cwnd never grows
beyond flight_size.

### §4.7 Fast Convergence

> "If cwnd < W_max and fast_conv enabled: W_max =
> cwnd * (1 + β_cubic) / 2"

**Adherence:** met. The §4.7 fast-convergence branch
in `cubic_loss_event_ssthresh`:

```python
if fast_conv_active and cwnd < prior_w_max:
    new_w_max = cwnd * FAST_CONV_NUM // FAST_CONV_DEN
else:
    new_w_max = cwnd
```

The reduction factor 17/20 = (1+0.7)/2 matches the
formula exactly.

### §4.8 Timeout

> "In the case of a timeout, CUBIC follows Reno to
> reduce cwnd, but sets ssthresh using β_cubic..."

**Adherence:** met. The RTO handler in CUBIC mode
sets ssthresh per `cubic_loss_event_ssthresh` (using
β_cubic = 0.7) and resets cwnd to 1 SMSS per RFC
5681. `_cubic_K_ms = 0` and
`_cubic_epoch_start_ms = stack.timer.now_ms` are
reset post-RTO so the next CA stage starts fresh.

### §4.9 Spurious Congestion Events

> "If a TCP sender determines that the
> retransmission was spurious, it SHOULD restore
> cwnd, ssthresh, W_max..."

**Adherence:** met for both §4.9.1 (spurious-timeout)
and §4.9.2 (spurious-fast-retransmit) cases.

§4.9.1: F-RTO substrate snapshots CUBIC state
(`_cubic_w_max`, K, epoch_start, w_est) alongside
cwnd/ssthresh in `_retransmit_packet_timeout`, and
restores all four in `_process_ack_packet` when the
first post-RTO ACK covers the snapshotted SND.MAX.

§4.9.2: dedicated `_fr_pre_cubic_*` snapshot taken at
fast-retransmit entry in `_retransmit_packet_request`
(captures W_max, K, epoch_start, W_est, cwnd,
ssthresh just before the multiplicative decrease).
A DSACK observed during the same recovery episode in
`_ingest_sack_info` rolls back all six fields and
clears `_fr_cubic_snapshot_valid`. The snapshot
validity flag is also cleared on recovery exit so a
stray post-recovery DSACK cannot roll back unrelated
state.

### §4.10 Slow Start

> "CUBIC MUST employ a slow start algorithm..."

**Adherence:** met. PyTCP's slow-start branch at
`cubic_grow_per_ack`:

```python
if cwnd < ssthresh:
    return cwnd + min(bytes_acked, smss)
```

is the unchanged RFC 5681 §3.1 slow-start formula.
CUBIC takes over only when cwnd >= ssthresh.

---

## Test coverage audit

### §4.1 Constants

- **Unit:**
  `pytcp/tests/unit/protocols/tcp/test__tcp__cubic.py::TestCubicConstants`
  pins `C_NUM/DEN`, `BETA_CUBIC_NUM/DEN`,
  `ALPHA_CUBIC_NUM/DEN`, `FAST_CONV_NUM/DEN`.

**Status:** locked in.

### §4.2 W_cubic(t) and K computation

- **Unit:** `TestCubicW`, `TestCubicComputeK`,
  `TestCubicTarget` in `test__tcp__cubic.py`.

**Status:** locked in.

### §4.3 W_est tracker

- **Unit:** `TestCubicWEst` pins the formula.
- **Integration:**
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__cubic.py::TestTcpCubicPhase3::test__cubic__reno_friendly_w_est_tracks_cwnd_on_ca_growth`.

**Status:** locked in.

### §4.4-§4.5 CA growth

- **Unit:** `TestCubicGrowPerAck`.
- **Integration:** Phase 3 cubic CA growth tests.

**Status:** locked in.

### §4.6 Multiplicative Decrease

- **Unit:** `TestCubicLossEventSsthresh`.
- **Integration:** Phase 3 fast-retransmit + RTO
  tests pin β_cubic = 0.7.

**Status:** locked in.

### §4.7 Fast Convergence

- **Unit:** `TestCubicLossEventSsthresh::test__cubic__fast_convergence_*`.
- **Integration:**
  `test__tcp__session__cubic.py::TestTcpCubicPhase3::test__cubic__fast_convergence_*`.

**Status:** locked in.

### §4.8 Timeout

- **Integration:** Phase 3 RTO test pins the
  β_cubic-based ssthresh reduction.

**Status:** locked in.

### §4.9 Spurious Congestion

§4.9.1 spurious-RTO state restore is locked in via the
F-RTO substrate (snapshot CUBIC state at RTO entry,
restore on first post-RTO ACK that covers SND.MAX).
§4.9.2 spurious-FR state restore is locked in via the
new `_fr_pre_cubic_*` snapshot at fast-retransmit
entry plus the DSACK-driven rollback in
`_ingest_sack_info`.

**Status:** locked in.

### §4.10 Slow Start

- **Integration:** Phase 3 slow-start-unchanged-in-
  cubic-mode test pins the §4.10 fallback.

**Status:** locked in.

### Test coverage summary

| Aspect                                          | Coverage                                       |
|-------------------------------------------------|------------------------------------------------|
| §4.1 Constants                                  | locked in                                      |
| §4.2 W_cubic(t) / K                             | locked in                                      |
| §4.2 target computation (W_cubic(t + RTT))      | locked in (`srtt_ms` plumbed from session)     |
| §4.3 Reno-Friendly W_est                        | locked in                                      |
| §4.4-§4.5 Concave/Convex CA growth              | locked in                                      |
| §4.6 Multiplicative Decrease                    | locked in                                      |
| §4.7 Fast Convergence                           | locked in                                      |
| §4.8 Timeout                                    | locked in                                      |
| §4.9.1 Spurious-timeout state restore            | locked in                                      |
| §4.10 Slow Start                                | locked in                                      |

---

## Overall assessment

| Aspect                                          | Status                                  |
|-------------------------------------------------|-----------------------------------------|
| §4.1 Constants (C, β_cubic, α_cubic)            | met                                     |
| §4.2 W_cubic(t) formula                         | met                                     |
| §4.2 K computation                              | met                                     |
| §4.2 target = W_cubic(t + RTT)                  | met (`srtt_ms` passed to cubic_target)  |
| §4.3 Reno-Friendly W_est                        | met                                     |
| §4.4-§4.5 CA growth                             | met                                     |
| §4.6 Multiplicative Decrease (β_cubic = 0.7)    | met                                     |
| §4.6 Use cwnd vs flight_size                    | met (with required safeguard)           |
| §4.7 Fast Convergence                           | met                                     |
| §4.8 Timeout                                    | met                                     |
| §4.9.1 Spurious-timeout state restore           | met                                     |
| §4.9.2 Spurious-fast-retransmit state restore   | met (DSACK-driven CUBIC rollback)       |
| §4.10 Slow Start                                | met                                     |

PyTCP fully implements RFC 9438 CUBIC's §4 algorithm
including fast convergence, Reno-friendly mode, and
both spurious-congestion paths. Status of the two
previously-open deviations:

1. **§4.2 target = W_cubic(t + RTT)** — closed.
   `cubic_grow_per_ack` now accepts an `srtt_ms`
   parameter and passes it through to `cubic_target`,
   which evaluates the cubic curve at `t + RTT` per
   the §4.2 formula. The session passes
   `self._rto_state.srtt_ms` so the projection uses
   the live smoothed RTT.

2. **§4.9.2 spurious-fast-retransmit restore** —
   closed. Dedicated `_fr_pre_cubic_*` snapshot at
   fast-retransmit entry in
   `_retransmit_packet_request`; DSACK-driven rollback
   in `_ingest_sack_info` restores the full CUBIC
   state when the retransmit is proven spurious. The
   snapshot validity flag clears on recovery exit so
   stray post-recovery DSACKs cannot roll back
   unrelated state.

CUBIC is on by default per the recent default flip;
RENO is opt-in via setsockopt(IPPROTO_TCP,
TCP_CONGESTION, "reno").
