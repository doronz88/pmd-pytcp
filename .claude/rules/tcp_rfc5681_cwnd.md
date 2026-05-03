# PyTCP — RFC 5681 Congestion Control: Project Record

**Status: SHIPPED** (Phase 1 cwnd/ssthresh fields + slow-start
vs CA + Phase 2 RTO ssthresh halving + Phase 3 fast-recovery
inflate/deflate + Phase 4 RFC 6928 IW = 10).

This document was originally a phased plan; it has been
rewritten as a completion record for future sessions that
want to **extend** the congestion-control surface (e.g. land
RFC 6582 NewReno fallback, RFC 6937 PRR, or RFC 9438 CUBIC).
The implementation history, phase-by-phase commit map, test
inventory, and explicitly-deferred-work list are all captured
below.

---

## 1. Scope and references

| RFC      | Title                                              | Use |
|----------|----------------------------------------------------|-----|
| RFC 5681 | TCP Congestion Control                             | §3.1 slow-start vs CA + §3.1 RTO + §3.2 fast-recovery |
| RFC 6928 | Increasing TCP's Initial Window                    | §2 IW = min(10*MSS, max(2*MSS, 14600)) |
| RFC 9293 | TCP (consolidated)                                 | §3.8.4 effective window = min(cwnd, snd_wnd) |

PyTCP now maintains 'cwnd' and 'ssthresh' as separate
first-class state, applies the §3.1 slow-start vs
congestion-avoidance growth-rate distinction on cum-ACKs,
halves ssthresh on RTO and fast-retransmit per §3.1 / §3.2
step 2, inflates cwnd by SMSS per dup-ACK during recovery
per §3.2 step 4, deflates cwnd to ssthresh on recovery exit
per §3.2 step 6, and starts at the RFC 6928 IW = 10*SMSS
post-handshake.

---

## 2. Standing principles (preserved for future extensions)

1. **`_snd_ewn` is the derived effective window.** The
   wire-level transmit gate in `_transmit_data` reads
   `_snd_ewn = min(_cwnd, _snd_wnd)`. Every code path that
   mutates `_cwnd` or `_snd_wnd` recomputes `_snd_ewn`
   immediately so the invariant always holds.
2. **`_cwnd` is the canonical congestion window.** All RFC
   5681 §3 growth / reduction logic touches `_cwnd`, never
   `_snd_ewn` directly. Tests that override `_snd_ewn` to
   constrain the effective window continue to work, but the
   semantically-correct override is `_cwnd`.
3. **§3.1 growth fires only on cum-ACK that advances
   SND.UNA.** Dup-ACKs and in-order data segments without
   ack-advance do not grow cwnd (RFC 5681 §3.1 wording: "for
   each ACK received that cumulatively acknowledges new
   data").
4. **Recovery exit deflate via the recovery_point check.**
   The RFC 6675 §5 RecoveryPoint marker (set on
   fast-retransmit entry, cleared in `_process_ack_packet`
   when SND.UNA passes it) is the trigger for the §3.2 step
   6 cwnd = ssthresh deflation. Mid-recovery partial cum-ACKs
   leave cwnd alone (NewReno-style; RFC 6582 partial deflate
   is deferred — see §7.1).
5. **RFC 6928 IW set after handshake-ack-processing.** The
   active-open path in `tcp__fsm__syn_sent` and the passive /
   simultaneous-open path in `tcp__fsm__syn_rcvd` set
   `_cwnd = IW` AFTER `_process_ack_packet` runs, so the
   §3.1 growth on the SYN-ack-advance does not inflate cwnd
   above IW.
6. **Fast-retransmit stays tightly scoped.** RFC 5681 §3.2
   triggers (3rd dup-ACK or SACK byte rule per RFC 6675 §3)
   and reductions apply once per loss event, gated on the
   one-shot RecoveryPoint marker. Multiple back-to-back
   triggers in the same loss event do not re-fire the
   ssthresh halving.

---

## 3. Architecture (final state)

```
TcpSession state:
    _cwnd: int                # RFC 5681 congestion window
    _ssthresh: int            # RFC 5681 slow-start threshold
    _snd_ewn: int             # = min(_cwnd, _snd_wnd) (derived)
    _snd_wnd: int             # peer's advertised window (post-wscale)
    _recovery_point: Seq32    # RFC 6675 §5 marker (Phase 3 deflate trigger)

Constants (in tcp__cwnd.py, post-Phase-6):
    INITIAL_WINDOW_FACTOR = 10        # RFC 6928 §2 multiplier
    INITIAL_WINDOW_BYTES = 14600      # RFC 6928 §2 floor for small MSS

Helper module (post-Phase-6):
    pytcp/protocols/tcp/tcp__cwnd.py
        cwnd_grow_per_ack(cwnd, ssthresh, bytes_acked, smss) -> int
        compute_loss_event_ssthresh(flight_size, smss) -> int
        initial_window(smss) -> int

Hook points:

    _process_ack_packet (cum-ACK on lt32(_snd_una, ack)):
        bytes_acked = (ack - _snd_una) & 0xFFFF_FFFF
        _snd_una = ack
        if _cwnd < _ssthresh:
            _cwnd += min(bytes_acked, _snd_mss)        # §3.1 slow-start
        else:
            _cwnd += max(1, _snd_mss² // _cwnd)        # §3.1 CA
        _snd_ewn = min(_cwnd, _snd_wnd)

    _process_ack_packet (snd_wnd update):
        _snd_wnd = packet_rx_md.tcp__win << _snd_wsc
        _snd_ewn = min(_cwnd, _snd_wnd)

    _process_ack_packet (recovery exit):
        if _recovery_point != 0 and le32(_recovery_point, _snd_una):
            _cwnd = _ssthresh                          # §3.2 step 6
            _snd_ewn = min(_cwnd, _snd_wnd)
            _recovery_point = 0

    _retransmit_packet_request (entry, count or SACK byte trigger):
        flight_size = (_snd_max - _snd_una) & 0xFFFF_FFFF
        _ssthresh = max(flight_size // 2, 2 * _snd_mss)  # §3.2 step 2
        _cwnd = _ssthresh + 3 * _snd_mss                  # §3.2 step 3
        _snd_ewn = min(_cwnd, _snd_wnd)

    _retransmit_packet_request (additional dup-ACK in recovery):
        _cwnd += _snd_mss                              # §3.2 step 4
        _snd_ewn = min(_cwnd, _snd_wnd)

    _retransmit_packet_timeout (RTO):
        flight_size = (_snd_max - _snd_una) & 0xFFFF_FFFF
        _ssthresh = max(flight_size // 2, 2 * _snd_mss)  # §3.1 step 1
        _cwnd = _snd_mss                                  # §3.1 LW
        _snd_ewn = min(_cwnd, _snd_wnd)

    tcp__fsm__syn_sent (active-open ESTABLISHED transition):
        # After _process_ack_packet on SYN+ACK:
        _cwnd = min(10 * _snd_mss, max(2 * _snd_mss, 14600))  # RFC 6928
        _snd_ewn = min(_cwnd, _snd_wnd)

    tcp__fsm__syn_rcvd (passive / simultaneous-open ESTABLISHED transition):
        # After _process_ack_packet on third-leg ACK: same IW assignment.
```

---

## 4. Phase-by-phase completion record

| Phase | Description                                             | Commits             | Tests added |
|-------|---------------------------------------------------------|---------------------|-------------|
| 1     | `_cwnd`/`_ssthresh` fields + §3.1 slow-start vs CA      | `76a9ad2` + `c14ff2f` + `5b5f411` | 6 (3 [FLAGS BUG] flipped) |
| 2     | §3.1 RTO ssthresh halving                               | `a3d08eb` + `006e452` | 2 |
| 3     | §3.2 fast-recovery inflate/deflate                      | `8470ddc` + `6a16323` | 3 |
| 4     | RFC 6928 §2 Initial Window 10                           | `5712ecb` + `4fea806` | 2 |
| 5     | Convert plan to completion record                       | (rewrite commit)    | 0 |
| 6     | Helper extraction `tcp__cwnd.py` + 27 unit tests        | `f824537`           | 27 unit |

Total: **10 code commits, 40 RFC-5681-specific tests, ~40 LOC
of production code in `tcp__session.py` + ~20 LOC across
three FSM modules + the dedicated `tcp__cwnd.py` helper module
(64 LOC + 27 unit tests).**

---

## 5. Test inventory (final)

All 13 tests live in
`pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py`:

### TestTcpCwndPhase1 (6 tests)
- `fields_exist_post_handshake` — regression guard
- `slow_start_grows_cwnd_by_one_mss_per_cum_ack` — §3.1 slow-start
- `congestion_avoidance_grows_cwnd_sublinearly` — §3.1 CA
- `snd_ewn_tracks_min_of_cwnd_and_snd_wnd` — RFC 9293 §3.8.4
- `post_handshake_starts_in_slow_start_phase` — regression guard
- `cum_ack_recomputes_snd_ewn_from_cwnd_via_runtime_path` — runtime-driven §3.8.4

### TestTcpCwndPhase2 (2 tests)
- `rto_sets_ssthresh_to_half_flight_size` — §3.1 step 1 main path
- `rto_with_minimal_flight_size_clamps_ssthresh_to_floor` — §3.1 step 1 floor

### TestTcpCwndPhase3 (3 tests)
- `fast_retransmit_halves_ssthresh_and_inflates_cwnd` — §3.2 steps 2+3
- `additional_dup_ack_in_recovery_inflates_cwnd_by_one_mss` — §3.2 step 4
- `cum_ack_exiting_recovery_deflates_cwnd_to_ssthresh` — §3.2 step 6

### TestTcpCwndPhase4 (2 tests)
- `post_handshake_initialises_cwnd_to_iw_10` — RFC 6928 §2
- `post_handshake_iw_10_clamped_by_peer_win` — RFC 9293 §3.8.4 with IW=10

### Cross-references covered indirectly

- `data_transfer__send.py` tests that pin `_snd_ewn`
  directly continue to work — the override happens at the
  effective-window layer, post-Phase-1 the runtime computes
  this from `min(_cwnd, _snd_wnd)` only on cum-ACKs that
  advance SND.UNA.
- `data_transfer__retransmit_dupack.py` integration tests
  cover the fast-retransmit triggers; Phase 3's cwnd
  inflation/deflation is added on top.
- `data_transfer__retransmit_timeout.py` tests cover RTO
  cadence; Phase 2 adds ssthresh tracking on top.

---

## 6. Production code map

| File                                              | Purpose                                       |
|---------------------------------------------------|-----------------------------------------------|
| `pytcp/protocols/tcp/tcp__cwnd.py`                | `cwnd_grow_per_ack`, `compute_loss_event_ssthresh`, `initial_window` (post-Phase-6 helper module; `INITIAL_WINDOW_FACTOR` / `INITIAL_WINDOW_BYTES` moved here from `tcp__constants.py`) |
| `pytcp/protocols/tcp/tcp__session.py:__init__`    | `_cwnd`, `_ssthresh` field declarations       |
| `pytcp/protocols/tcp/tcp__session.py:_process_ack_packet` | §3.1 cwnd growth + §3.2 step 6 deflate + §3.8.4 snd_ewn recompute |
| `pytcp/protocols/tcp/tcp__session.py:_retransmit_packet_request` | §3.2 step 2-4 ssthresh halve + cwnd inflate |
| `pytcp/protocols/tcp/tcp__session.py:_retransmit_packet_timeout` | §3.1 step 1 ssthresh halve + cwnd LW reset |
| `pytcp/protocols/tcp/tcp__fsm__syn_sent.py`       | RFC 6928 IW assignment (active-open + simultaneous-open init) |
| `pytcp/protocols/tcp/tcp__fsm__syn_rcvd.py`       | RFC 6928 IW assignment (passive-open + simultaneous-open ESTABLISHED) |
| `pytcp/protocols/tcp/tcp__fsm__listen.py`         | `_cwnd = _snd_mss` init at SYN arrival (handshake not yet complete) |

---

## 7. Deferred work (out of scope for "the RFC 5681 project")

These items were considered and explicitly skipped. They
belong to adjacent projects, not RFC 5681 polish.

### 7.1 RFC 6582 NewReno partial-cum-ACK handling

PyTCP's Phase 3 deflate fires only on cum-ACK that crosses
RecoveryPoint. RFC 6582 specifies a more nuanced response:
on a partial cum-ACK during recovery (advances SND.UNA but
does not cross RecoveryPoint), deflate cwnd by bytes_acked
(less SMSS) and retransmit the next gap. PyTCP currently
leaves cwnd untouched on partial cum-ACK during recovery.

The impact: on multi-gap loss with non-SACK peers, recovery
takes one extra RTT per additional lost segment. With SACK
peers (the common case post-bilateral negotiation), RFC 6675
NextSeg drives the multi-gap recovery directly via the
scoreboard, so RFC 6582 is mostly moot.

When to land: if PyTCP's RFC 6675 SACK byte-rule path
proves insufficient against non-SACK peers in real-world
testing. ~2-3 commits, modest test surface.

### 7.2 RFC 6937 Proportional Rate Reduction (PRR)

PRR replaces the §3.2 step 4 dup-ACK "+SMSS" inflation with
a more precise pacing algorithm that tracks how much data is
in flight vs how much was lost, and grows cwnd in proportion.
The result is smoother send pacing during recovery and
faster total loss recovery.

When to land: after the deferred-work item below (CUBIC)
since CUBIC and PRR are typically deployed together. ~3-4
commits, larger test surface.

### 7.3 RFC 9438 CUBIC congestion control

CUBIC replaces Reno's linear CA growth with a cubic function
of time-since-last-loss. Default congestion control on Linux
and Windows; very different cwnd dynamics from RFC 5681.

The cleanest path: keep the `_cwnd / _ssthresh` substrate
shipped here as the "Reno-style mode" and add a CC-mode
selector that switches to CUBIC. The §3.2 fast-retransmit
inflation/deflation and §3.1 RTO ssthresh halving are
shared between Reno and CUBIC; only the CA-phase growth
formula changes.

When to land: separate "RFC 9438 CUBIC project". ~10+
commits with substantial test surface (CUBIC's cubic-curve
math has multiple regions).

### 7.4 RFC 8312 BBR (informational)

BBR (Bottleneck Bandwidth and Round-trip propagation time)
is Google's loss-agnostic congestion control. Not RFC-
mandated; deferred indefinitely.

---

## 8. Anti-patterns (preserved for future extensions)

- **Don't conflate `_cwnd` with `_snd_ewn`.** They encode
  independent concepts: cwnd is the network bound, snd_ewn
  is the wire-level transmit gate (= min(cwnd, snd_wnd)).
  Mutate cwnd, recompute snd_ewn.

- **Don't apply §3.1 cwnd growth on the recovery-exit
  cum-ACK.** Per §3.2 step 6 the recovery exit unilaterally
  sets cwnd = ssthresh, bypassing §3.1. PyTCP's
  `_process_ack_packet` order ensures the §3.1 growth fires
  first (then the deflate overrides if exiting recovery);
  if the order is ever swapped, ensure the deflate is the
  last cwnd write.

- **Don't compute FlightSize after the SND.NXT rewind.**
  Both `_retransmit_packet_request` (Phase 3) and
  `_retransmit_packet_timeout` (Phase 2) compute
  `flight_size = SND.MAX - SND.UNA` BEFORE rewinding
  SND.NXT to SND.UNA, so the value reflects the unacked-
  bytes count at the moment of loss detection. After the
  rewind, SND.NXT == SND.UNA and the modular subtraction
  would yield 0.

- **Don't apply RFC 6928 IW at the `_cwnd = _snd_mss` init
  lines in the FSM modules.** Those run BEFORE
  `_process_ack_packet` on the handshake ACK, which fires
  §3.1 growth; setting cwnd = IW there would result in a
  post-handshake cwnd of IW + 1 (the +1 from the SYN-ack-
  advance). The IW assignment lives at the ESTABLISHED
  transition in `tcp__fsm__syn_sent` (active-open) and
  `tcp__fsm__syn_rcvd` (passive / simultaneous-open) so
  the post-handshake value is exactly IW.

- **Don't forget the §3.2 step 2 floor `2*SMSS`.** A small
  in-flight burst at fast-retransmit time would otherwise
  set ssthresh below the canonical minimum and cause the
  post-recovery slow-start to exit immediately into CA.

- **Don't double-count the §3.2 entry inflation.** When the
  3rd dup-ACK fires the trigger, §3.2 step 3 sets cwnd =
  ssthresh + 3*SMSS. Each subsequent dup-ACK in recovery
  adds SMSS via the early-return branch of
  `_retransmit_packet_request` (Phase 3 hook). The 3rd
  dup-ACK MUST NOT also fire the additional-dup-ACK path
  (the trigger gate at line 1716/1717 of `tcp__session.py`
  short-circuits before the early-return branch).

---

## 9. Extender's re-orient command

If you want to extend the congestion control surface (e.g.
land RFC 6582 NewReno fallback, RFC 6937 PRR, or RFC 9438
CUBIC), start with:

```bash
git log --oneline --grep="cwnd\|RFC 5681\|RFC 6928" master..HEAD
make test 2>&1 | tail -5
ls pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py
grep -n "_cwnd\|_ssthresh" pytcp/protocols/tcp/tcp__session.py | head
```

Read the docstrings of:
- `pytcp/protocols/tcp/tcp__session.py::_process_ack_packet`
  (§3.1 growth + §3.2 deflate)
- `pytcp/protocols/tcp/tcp__session.py::_retransmit_packet_request`
  (§3.2 entry + dup-ACK inflation)
- `pytcp/protocols/tcp/tcp__session.py::_retransmit_packet_timeout`
  (§3.1 RTO ssthresh halving)
- `pytcp/protocols/tcp/tcp__fsm__syn_rcvd.py` (RFC 6928 IW
  assignment at passive-open ESTABLISHED transition)

Then decide whether the extension fits the deferred-work
taxonomy in §7 above, or is a new direction entirely.

---

## 10. Cross-references

- Workflow + reporting format:
  `.claude/rules/tcp_session_integration_tests.md` §7
- Coding style: `.claude/rules/coding_style.md`
- Unit test authoring: `.claude/rules/unit_tests.md`
- Adjacent shipped: `.claude/rules/tcp_rto_integration.md`
  (RFC 6298 RTO estimator that drives the retransmit timer
  whose RTO halves ssthresh in Phase 2 here).
- Adjacent shipped: `.claude/rules/tcp_sack_implementation.md`
  (RFC 2018 + 6675 SACK that provides the byte-rule trigger
  for fast-retransmit and NextSeg for multi-gap recovery
  in Phase 3 here).
