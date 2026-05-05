# PyTCP — RFC 9438 CUBIC: Project Plan

Detailed handoff plan for implementing strict RFC 9438
(CUBIC for Fast and Long-Distance Networks) in PyTCP.
Reads as a self-contained project brief; a fresh post-
compact session should pick this file up and execute the
phases below verbatim.

The RFC 9438 text lives at
`docs/rfc/tcp/rfc9438__cubic/rfc9438.txt`; if absent,
fetch from `https://www.rfc-editor.org/rfc/rfc9438.txt`.

---

## 1. Mission

Implement strict RFC 9438 CUBIC congestion control on top
of PyTCP's existing RFC 5681 Reno substrate. The target
end-state:

1. **CUBIC growth function** replaces RFC 5681 §3.1's
   linear congestion-avoidance growth with the cubic
   function `W_cubic(t) = C * (t - K)^3 + W_max`, where
   `K = cubicroot(W_max * (1 - beta_cubic) / C)`.
2. **CUBIC loss-event response** halves cwnd by
   `beta_cubic = 0.7` (vs RFC 5681's 0.5), preserving
   more in-flight data for high-bandwidth-delay-product
   paths.
3. **Reno-friendly mode** (RFC 9438 §4.2) tracks a parallel
   Reno-equivalent cwnd `W_est`; when the CUBIC formula
   yields a smaller cwnd than Reno would, fall back to the
   Reno value so CUBIC never under-performs Reno on small-
   BDP paths.
4. **Fast convergence** (RFC 9438 §4.7) lets new flows
   ramp faster after a loss event by reducing `W_max` to
   `W_max * (1 + beta_cubic) / 2` when the new W_max is
   smaller than the prior one.
5. **CC-mode selector** allows the application (or test
   harness) to choose between Reno and CUBIC via a session-
   level enum field; default ships as CUBIC (matching Linux
   default since kernel 2.6.18).
6. **RACK-TLP / SACK / RTO interaction** preserved: the
   existing recovery substrate continues to function;
   CUBIC's only contribution is the cwnd growth + loss-
   event reduction formulas.

End state preserves all currently-passing tests; the new
CUBIC machinery adds 7 phases of incremental behaviour,
each pinned by an integration test.

---

## 2. Standing principles

1. **Tests-first per phase.** Each phase opens with a
   `[FLAGS BUG]` failing test commit, followed by a fix
   commit. Mirrors the workflow shipped on RACK-TLP, F-RTO,
   ABE, AccECN, ECN, and SACK projects.

2. **Strict RFC 9438.** The pseudocode in §4 is the ground
   truth. Where Linux deviates, follow the RFC. Where the
   RFC is silent, prefer the conservative choice.

3. **Suite invariant.** After every commit:
   `make lint` clean. `make test` passes (existing tests
   never regress; new tests flip green per their phase).

4. **Test-count baseline at project start.** 8210 passing
   (from RACK-TLP completion `ac2165d`). Each phase adds
   tests; final target approximately +30 to +40 tests.

5. **Default switch to CUBIC last.** Phases 1-6 ship CUBIC
   as a per-session opt-in. Phase 7 flips the default. This
   ordering means existing tests (which assume Reno
   behaviour) keep passing through phases 1-6; phase 7
   updates only the few tests that pin specific cwnd
   values, leaving the bulk green.

6. **Helper module for math.** All cubic math goes in
   `pytcp/protocols/tcp/tcp__cubic.py` as pure functions on
   immutable inputs. No session reference inside the helper;
   the session calls helpers and stores results.

7. **RACK-TLP substrate is reused, not duplicated.** CUBIC
   reads the existing `_rto_state.srtt_ms` for its time
   parameter and the existing `_rack_min_rtt_ms` for the
   Reno-friendly comparison; do not introduce parallel RTT
   tracking.

---

## 3. Target architecture (final state)

### 3.1 New module: `pytcp/protocols/tcp/tcp__cubic.py`

Pure-function helpers (parallel to `tcp__cwnd.py`,
`tcp__rack.py`, `tcp__rto.py`). Exposes:

```python
# RFC 9438 §4.1 / §5 constants
C: float = 0.4         # cubic scaling factor
BETA_CUBIC: float = 0.7  # multiplicative decrease factor

# Integer-arithmetic ratios so the codebase stays float-free
# in hot paths. C is encoded as numerator/denominator (2/5)
# so the cube term integer math is exact.
C_NUM: int = 2
C_DEN: int = 5
BETA_CUBIC_NUM: int = 7
BETA_CUBIC_DEN: int = 10


def cubic_compute_K(w_max: int, smss: int) -> int:
    """RFC 9438 §4.2: K = cubicroot(W_max * (1 - beta) / C),
    in milliseconds. W_max in segments via cwnd / smss."""

def cubic_w(t_ms: int, w_max: int, K_ms: int, smss: int) -> int:
    """RFC 9438 §4.2: W(t) = C * (t - K)^3 + W_max,
    returned in BYTES."""

def cubic_grow_per_ack(
    cwnd: int, ssthresh: int,
    w_max: int, K_ms: int,
    epoch_start_ms: int, now_ms: int,
    bytes_acked: int, smss: int,
) -> int:
    """RFC 9438 §4.2 / §4.6 cwnd growth on cum-ACK in CA.
    Combines cubic and Reno-friendly responses; returns
    new cwnd."""

def cubic_loss_event_ssthresh(
    cwnd: int, smss: int, fast_conv_active: bool,
    prior_w_max: int,
) -> tuple[int, int]:
    """RFC 9438 §4.5 / §4.6: on loss event, return
    (new_ssthresh, new_w_max). 'fast_conv_active' triggers
    §4.7 fast-convergence W_max reduction."""

def cubic_w_est(
    w_est_prev: int, w_max: int,
    smss: int, bytes_acked: int,
    rtt_ms: int,
) -> int:
    """RFC 9438 §4.2 W_est tracker for Reno-friendly mode.
    On every cum-ACK, advances W_est by alpha_cubic *
    bytes_acked / smss segments where alpha_cubic =
    3 * (1 - beta) / (1 + beta) = 3 * 0.3 / 1.7 ≈ 0.529."""
```

### 3.2 New TcpSession fields (8 new)

```python
# RFC 9438 §4 CUBIC state. Active when '_cc_mode == CUBIC';
# in 'RENO' mode all fields stay at their initial values
# and the existing RFC 5681 cwnd helpers run unchanged.
self._cc_mode: CcMode = CcMode.CUBIC  # enum (RENO | CUBIC)
self._cubic_w_max: int = 0            # W_max in bytes
self._cubic_w_last_max: int = 0       # for §4.7 fast convergence
self._cubic_K_ms: int = 0             # K in ms (post-loss-event)
self._cubic_epoch_start_ms: int = 0   # virtual-clock anchor
self._cubic_w_est: int = 0            # Reno-friendly tracker
# RFC 9438 §4.6 CA-mode flag: True post-handshake (after
# slow-start exit), False during slow-start. Tracked
# explicitly so the CUBIC growth path knows whether to
# apply the cubic formula or yield to slow-start.
self._cubic_in_ca: bool = False
```

### 3.3 New enum: `pytcp/protocols/tcp/tcp__enums.py`

```python
class CcMode(Enum):
    """Congestion-control algorithm selector."""

    RENO = 0    # RFC 5681 Reno (legacy)
    CUBIC = 1   # RFC 9438 CUBIC (default)
```

### 3.4 Hook points in `tcp__session.py`

- `_process_ack_packet` cum-ACK growth branch:
  - Slow-start (cwnd < ssthresh): unchanged Reno behaviour.
  - Congestion-avoidance (cwnd >= ssthresh) AND
    `_cc_mode == CUBIC`: call `cubic_grow_per_ack`.
  - CA AND `_cc_mode == RENO`: existing
    `cwnd_grow_per_ack` from `tcp__cwnd.py`.

- `_retransmit_packet_request` (fast retransmit) +
  `_retransmit_packet_timeout` (RTO):
  - When `_cc_mode == CUBIC`: call
    `cubic_loss_event_ssthresh` instead of
    `compute_loss_event_ssthresh`. Updates `_cubic_w_max`,
    `_cubic_w_last_max`, `_cubic_K_ms`, `_cubic_epoch_start_ms`.
  - When `_cc_mode == RENO`: existing path.

- Slow-start exit detection: when `cwnd >= ssthresh` for
  the first time, set `_cubic_in_ca = True` and reset the
  CUBIC epoch.

### 3.5 New socket-API hook (Phase 7)

- `setsockopt(IPPROTO_TCP, TCP_CONGESTION, value)` accepts
  string `"reno"` or `"cubic"` and updates `_cc_mode` on
  the underlying session. Mirrors Linux's `tcp_cong.c`
  contract.

---

## 4. Phase-by-phase plan

Each phase is one tests-first commit + one fix commit
(some phases bundle into a single commit when the change
set is naturally atomic).

### Phase 1: `tcp__cubic.py` helper + unit tests

**Goal**: pure-function math primitives plus unit tests.
No session integration yet; existing tests untouched.

**New code**:
- `pytcp/protocols/tcp/tcp__cubic.py` with the four
  helpers above plus the `C_NUM` / `C_DEN` / `BETA_*`
  constants.

**Unit tests** (new
`pytcp/tests/unit/protocols/tcp/test__tcp__cubic.py`):
- `cubic_compute_K` boundary values: K=0 when
  `w_max == cwnd_at_loss`, K monotone in W_max, integer-
  arithmetic correctness vs reference floats.
- `cubic_w` evaluations at canonical (t, W_max, K)
  triples with hand-verified expected outputs.
- `cubic_grow_per_ack` slow-start vs CA branches; cubic-
  greater-than-Reno-friendly vs cubic-less-than path
  selection.
- `cubic_loss_event_ssthresh` with fast-conv off/on;
  ssthresh = max(cwnd * 7/10, 2 * smss) floor verified.
- `cubic_w_est` linear growth at alpha_cubic ≈ 0.529.

~20 unit tests, all passing on landing.

**Commits**: 1 (helper + unit tests bundled).

### Phase 2: Session fields + CcMode enum + RENO default

**Goal**: declare all CUBIC state on TcpSession, default to
`_cc_mode = CcMode.RENO` so behaviour is unchanged.

**New code**:
- `tcp__enums.py`: add `CcMode` enum.
- `tcp__session.py.__init__`: add the 8 fields per §3.2,
  default `_cc_mode = CcMode.RENO`.

**Tests**:
- 1 unit test pinning `_cc_mode` initial value.
- 1 integration test: `test__cubic__fresh_session_defaults_to_reno`
  asserts a fresh `TcpSession._cc_mode is CcMode.RENO`
  (changes to CUBIC in Phase 7).

**Commits**: 1 (no [FLAGS BUG] - field declarations only).

### Phase 3: CUBIC CA growth

**Goal**: when `_cc_mode == CcMode.CUBIC` AND cwnd is in
CA phase, replace the linear Reno growth with the cubic
formula.

**Behaviour**: per cum-ACK that advances SND.UNA in CA,
compute `t = now_ms - _cubic_epoch_start_ms`, evaluate
`cubic_grow_per_ack`, set `_cwnd` to the result.

**Tests** (new
`pytcp/tests/integration/protocols/tcp/test__tcp__session__cubic.py`):
- `test__cubic__ca_growth_follows_cubic_curve` [FLAGS BUG]
  - sets `_cc_mode = CcMode.CUBIC`, drives a long CA
    burst, asserts cwnd grows along the cubic curve (not
    the linear Reno curve).
- `test__cubic__slow_start_phase_unchanged` regression -
  in slow-start, CUBIC and Reno behave identically.
- `test__cubic__reno_mode_unaffected` regression - with
  `_cc_mode = CcMode.RENO`, growth follows existing
  Reno path.

**Commits**: 2 (test + fix).

### Phase 4: CUBIC loss-event response (beta_cubic = 0.7)

**Goal**: on fast retransmit OR RTO, when
`_cc_mode == CcMode.CUBIC`, set ssthresh =
`max(cwnd * 7/10, 2 * smss)` and update `_cubic_w_max` /
`_cubic_K_ms` / `_cubic_epoch_start_ms`.

**Behaviour**: replaces the `compute_loss_event_ssthresh`
call in `_retransmit_packet_request` and
`_retransmit_packet_timeout` with a CcMode-aware dispatch.

**Tests**:
- `test__cubic__fast_retransmit_uses_beta_cubic` [FLAGS BUG]
  - drives a 3-dup-ACK fast-retransmit; asserts new
    ssthresh equals `cwnd * 7/10` (vs Reno's 1/2).
- `test__cubic__rto_uses_beta_cubic` [FLAGS BUG]
  - drives an RTO; asserts ssthresh halved by 0.7 not 0.5.
- `test__cubic__loss_event_records_w_max` [FLAGS BUG]
  - asserts `_cubic_w_max` captures pre-loss cwnd; K
    computed correctly.

**Commits**: 2.

### Phase 5: Fast convergence (RFC 9438 §4.7)

**Goal**: when the new `_cubic_w_max` is smaller than the
prior `_cubic_w_last_max`, reduce W_max further to
`W_max * (1 + beta_cubic) / 2` to leave room for new flows.

**Tests**:
- `test__cubic__fast_convergence_reduces_w_max_on_decline`
  [FLAGS BUG]
  - drives two consecutive loss events with the second
    cwnd lower than the first; asserts the second event's
    `_cubic_w_max` was further reduced per §4.7.
- `test__cubic__fast_convergence_inactive_on_increase`
  regression - if cwnd at second loss is ≥ prior W_max, no
  fast-convergence reduction.

**Commits**: 2.

### Phase 6: Reno-friendly mode (RFC 9438 §4.2 / §4.6)

**Goal**: track `_cubic_w_est` (parallel Reno-equivalent
cwnd) on every cum-ACK; when `cubic_w(t) < _cubic_w_est`,
use `_cubic_w_est` as the cwnd value so CUBIC never falls
below Reno on short-RTT / small-BDP paths.

**Tests**:
- `test__cubic__reno_friendly_mode_kicks_in_on_short_rtt`
  [FLAGS BUG]
  - drives a connection with very low RTT; asserts cwnd
    growth tracks Reno (not the slower cubic curve).
- `test__cubic__reno_friendly_w_est_tracks_alpha_cubic`
  [FLAGS BUG]
  - per-ACK W_est advance equals `alpha_cubic *
    bytes_acked / smss` (≈ 0.529 segments).

**Commits**: 2.

### Phase 7: Default to CUBIC + setsockopt(TCP_CONGESTION)

**Goal**: flip the default `_cc_mode` from RENO to CUBIC,
expose the selector via `setsockopt(IPPROTO_TCP,
TCP_CONGESTION, "reno" | "cubic")`, mirroring Linux's
`tcp_cong.c`.

**New code**:
- `pytcp/socket/__init__.py`: add `TCP_CONGESTION = 13`
  constant to the existing `SocketOption` enum.
- `pytcp/socket/tcp__socket.py`: extend `setsockopt` /
  `getsockopt` to handle TCP_CONGESTION; store on
  `_cc_mode` field; propagate to TcpSession on `connect()`
  / `listen()` (mirror the keepalive socket-API pattern).
- `tcp__session.py`: change default `_cc_mode = CcMode.CUBIC`.

**Tests**:
- `test__cubic__setsockopt_tcp_congestion_round_trip`
  [FLAGS BUG]
  - getsockopt before setsockopt returns "cubic" (default);
  - setsockopt to "reno" then getsockopt returns "reno";
  - subsequent connect() applies the override to the
    session.
- `test__cubic__post_handshake_cc_mode_matches_socket`
  regression - `session._cc_mode` matches the socket's
  configured mode.
- Update existing tests that pin specific cwnd values to
  account for the CUBIC default. Estimated 5-8 tests
  needing adjustment (the post-loss ssthresh halving
  factor changes from 0.5 to 0.7).

**Commits**: 2-3 (test + fix + existing-test updates).

---

## 5. Implementation effort

| Phase | Description | Commits | Risk | Tests |
|---|---|---|---|---|
| 1 | tcp__cubic.py + unit tests | 1 | low | 20 unit |
| 2 | Session fields + CcMode | 1 | trivial | 2 |
| 3 | CUBIC CA growth | 2 | medium | 3 |
| 4 | Loss-event beta_cubic | 2 | medium | 3 |
| 5 | Fast convergence | 2 | low | 2 |
| 6 | Reno-friendly mode | 2 | medium | 2 |
| 7 | Default CUBIC + setsockopt | 2-3 | low-medium | 2 + ~5 updates |

**Total**: ~12-13 commits, ~600 LOC of production code +
unit tests + ~14-15 integration tests. Comparable in
scope to RACK-TLP Phase 7 in complexity.

---

## 6. Anti-patterns to avoid

- **Don't use floating-point math in CUBIC's hot path.**
  PyTCP's convention is integer-only. Encode `C = 2/5`
  and `beta_cubic = 7/10` as numerator/denominator pairs.
  The cube root computation is the one exception; use
  Python's `int()` cast on `pow(x, 1/3)` and accept the
  off-by-one rounding error.

- **Don't conflate `_cubic_w_max` with `_cwnd`.** They
  encode independent concepts: cwnd is the current window;
  W_max is the inflection-point anchor for the cubic
  curve. Mutate cwnd via the helper; W_max only updates on
  loss events.

- **Don't fire CUBIC math during slow-start.** RFC 9438
  §4.6: CUBIC's CA formula is invalid for cwnd < ssthresh.
  The `_cubic_in_ca` flag gates the dispatch; before the
  first loss event (or first cwnd >= ssthresh crossing),
  slow-start exits via the existing Reno path.

- **Don't apply fast convergence on increasing W_max.**
  Per §4.7, only when the NEW W_max is smaller than the
  PRIOR W_max. An expanding flow does not benefit from
  giving up bandwidth.

- **Don't break Reno mode.** Phases 1-6 must keep
  `_cc_mode = CcMode.RENO` behaving exactly as before.
  The dispatch at every hook point gates on `_cc_mode`;
  the RENO branch calls existing helpers unchanged.

- **Don't forget the §4.3 epoch reset.** `_cubic_epoch_start_ms`
  resets on every loss event AND on every recovery exit.
  Without this reset, the cubic curve treats the post-
  recovery state as if no time had elapsed, growing too
  fast.

- **Don't apply CUBIC's growth-per-ACK to non-data ACKs.**
  Per §4.6, CUBIC growth fires only on cum-ACKs that
  advance SND.UNA (i.e. delivered new data). Dup-ACKs and
  bare window updates do not contribute. The existing
  `_process_ack_packet` cum-ACK gate already enforces
  this.

- **Don't make CUBIC the default before Phase 7.** Tests
  that assume Reno's 0.5 ssthresh halving will break en
  masse; staging the default flip to phase 7 with explicit
  test updates is mandatory.

---

## 7. Re-orient command for new sessions

After loading this rule, run:

```bash
git log --oneline --grep="CUBIC\|RFC 9438" master..HEAD
make test 2>&1 | tail -5
ls pytcp/protocols/tcp/tcp__cubic.py 2>/dev/null
ls pytcp/tests/unit/protocols/tcp/test__tcp__cubic.py 2>/dev/null
ls pytcp/tests/integration/protocols/tcp/test__tcp__session__cubic.py 2>/dev/null
grep -n "_cc_mode\|CcMode" pytcp/protocols/tcp/tcp__session.py | head
grep -n "TCP_CONGESTION" pytcp/socket/__init__.py 2>/dev/null
```

What it tells you:
- No `tcp__cubic.py` → Phase 1 not started.
- `tcp__cubic.py` exists but no `_cc_mode` field → Phase 2
  not started.
- `_cc_mode` exists and defaults to RENO → Phase 3-6
  pending; the default-flip + setsockopt is Phase 7.
- `_cc_mode` defaults to CUBIC AND `TCP_CONGESTION` exists
  → all phases shipped.

---

## 8. Cross-references

- RFC text (download before phase 1):
  `https://www.rfc-editor.org/rfc/rfc9438.txt`
- Adjacent shipped: `.claude/rules/tcp_rfc5681_cwnd.md`
  (the Reno cwnd substrate CUBIC builds on; CcMode-aware
  dispatch lives at the same hook points).
- Adjacent shipped: `.claude/rules/tcp_rack_tlp.md`
  (RACK-TLP loss detection feeds CUBIC via the existing
  loss-event hooks; `_rack_min_rtt_ms` may serve as the
  Reno-friendly RTT input).
- Adjacent shipped:
  `.claude/rules/tcp_keepalive_socket_api.md` (canonical
  setsockopt pattern; phase 7 mirrors this for
  TCP_CONGESTION).
- Workflow + reporting format:
  `.claude/rules/tcp_session_integration_tests.md` §7.
- Coding style: `.claude/rules/coding_style.md`.
- Unit test authoring: `.claude/rules/unit_tests.md`.
- Test docstring rule: `.claude/rules/unit_tests.md` §7
  + §7.1.

---

## 9. Deferred work (out of scope)

- **Hystart++ (RFC 9406)**: slow-start exit detection
  via inter-RTT spacing analysis. RFC 9438 §4.10 mentions
  it as a recommended companion. Estimated ~6 commits;
  ship as a separate project after CUBIC core lands.
- **CUBIC + ECN interaction tweaks**: the existing ABE
  (RFC 8511) helper applies regardless of CC mode; some
  RFC-9438-specific ECN-mark tuning is out of scope.
- **DCTCP (RFC 8257)**: data-center variant; requires a
  full ECN-feedback-driven cwnd reduction loop. Distinct
  project.
- **BBR**: Google's loss-agnostic congestion control. Not
  RFC-mandated; deferred indefinitely.

---

## 10. Test-file naming

Per `unit_tests.md` §3 (mapping for `pytcp/protocols/tcp/`):

- Unit tests for `tcp__cubic.py`:
  `pytcp/tests/unit/protocols/tcp/test__tcp__cubic.py`
- Integration tests:
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__cubic.py`

---

## 11. Quick-start prompt for fresh post-compact session

```
Implement strict RFC 9438 CUBIC per
.claude/rules/tcp_rfc9438_cubic.md. Start at the earliest
unstarted phase per the §7 re-orient command. Tests-first
per phase, fix-second. Do not flip the default '_cc_mode'
to CUBIC before Phase 7. Do not deviate from the phase
plan or the strict-RFC-9438 directive.
```

After loading the rule, the agent should know exactly
where to start and what each commit looks like.
