# PyTCP — RFC 7323 §3 Timestamps Option: Project Record

**Status: SHIPPED** (Phase 1 bilateral negotiation + Phase 2
per-segment emission + `_ts_recent` tracking + Phase 3
TSecr-driven RTTM + Phase 4 PAWS).

This document was originally a phased plan; it has been
rewritten as a completion record for future sessions that
want to **extend** PyTCP's timestamps surface (e.g. land RFC
1337 PAWS-based TIME-WAIT mitigation, RFC 6191 timestamps-
based TIME-WAIT 4-tuple reuse, or RFC 8985 RACK-TLP).

---

## 1. Scope and references

| RFC      | Title                                              | Use |
|----------|----------------------------------------------------|-----|
| RFC 7323 | TCP Extensions for High Performance                | §3 TSopt wire + negotiation, §4 RTTM, §5 PAWS |
| RFC 6298 | Computing TCP's Retransmission Timer               | §3 Karn obviated by §4 TSecr; §2 update reused as fold function |
| RFC 9293 | TCP (consolidated)                                 | §3.10 acceptability, §3.8.4 effective window |
| RFC 1337 | TIME-WAIT assassination                            | Mitigation now possible via PAWS (deferred extension) |
| RFC 6191 | Reducing TIME-WAIT via timestamps                  | 4-tuple reuse if peer's TS clock advanced (deferred extension) |

---

## 2. Standing principles (preserved for future extensions)

1. **Bilateral-negotiation gate.** All TSopt emission AND
   TSopt ingestion gates on `_send_ts` (set during handshake
   when both sides advertised). Asymmetric guard:
   `_advertise_ts` is the application opt-out flag (default
   True); `_send_ts` is the post-negotiation result.
2. **TS clock = `stack.timer.now_ms`.** Same monotonic source
   the RFC 6298 RTO sampler uses. 32-bit truncation via
   `& 0xFFFFFFFF` for wire emission; modular comparison via
   `lt32` from `tcp__seq`.
3. **`_ts_recent` updates only on segments through
   `_process_ack_packet`.** This is the canonical "accepted
   inbound" path for in-sequence data + cum-ACK + SACK. Dup-
   ACK / wnd-update paths bypass; full §4.3 conformance for
   those paths is a deferred cleanup (real-world impact
   small — peer's TSval refreshes on the next data segment).
4. **TSecr RTTM supersedes the Phase-2 sample tracker.** When
   bilateral TSopt is enabled, every cum-ACK with TSecr
   drives RFC 6298 §2 update directly. The Phase-2 sample
   tracker is cleared after to prevent double-folding.
5. **PAWS at `_process_ack_packet`'s top, before state
   mutation.** Stale-TSval segments are dropped silently;
   no ACK is generated (RFC 7323 §5.4 leaves this optional).

---

## 3. Architecture (final state)

```
TcpSession state:
    _advertise_ts: bool = True       # application opt-out flag
    _send_ts: bool = False           # bilateral-success flag
    _ts_recent: int = 0              # peer's most-recently-seen TSval

TcpMetadata fields:
    tcp__tsval: int | None           # peer's TSval (None if no TSopt)
    tcp__tsecr: int | None           # peer's TSecr

Hook points:

    _transmit_packet:
        SYN-only (active-open): emit TSopt iff _advertise_ts
            (tsval=now_ms, tsecr=0)
        SYN+ACK (passive/simultaneous): emit TSopt iff _send_ts
            (tsval=now_ms, tsecr=_ts_recent)
        Non-SYN segments: emit TSopt iff _send_ts
            (tsval=now_ms, tsecr=_ts_recent)

    _process_ack_packet (top, before state mutation):
        # PAWS (§5)
        if _send_ts and tsval is not None and lt32(tsval, _ts_recent):
            return  # drop stale segment

        # _ts_recent update (§4.3)
        if _send_ts and tsval is not None:
            _ts_recent = tsval

    _process_ack_packet (after _snd_una update):
        # TSecr-driven RTTM (§4)
        if _send_ts and tsecr is not None and tsecr != 0:
            rtt = (now_ms - tsecr) & 0xFFFFFFFF
            _rto_state = update(_rto_state, rtt)
            # Clear Phase-2 sample tracker to prevent double-fold.
            _rtt_sample_seq = None
            _rtt_sample_send_time_ms = None
            _rtt_sample_retransmitted = False

    tcp__fsm__syn_sent (active-open SYN+ACK arrival):
        if _advertise_ts and tcp__tsval is not None:
            _send_ts = True
            _ts_recent = tcp__tsval

    tcp__fsm__listen (passive-open SYN arrival):
        if _advertise_ts and tcp__tsval is not None:
            _send_ts = True
            _ts_recent = tcp__tsval

    Wire-level (already shipped in net_proto):
        TcpOptionTimestamps in net_proto/protocols/tcp/options/
        TcpOptions.timestamps accessor on parser side
```

---

## 4. Phase-by-phase completion record

| Phase | Description                                   | Commits             | Tests added |
|-------|-----------------------------------------------|---------------------|-------------|
| 1     | Bilateral negotiation                         | `a36c248` + `4929f97` | 4 |
| 2     | Per-segment emission + `_ts_recent` tracking  | `18ac216` + `fcdcf27` | 3 |
| 3     | TSecr-driven RTTM                             | `d870992` + `f7c0d8b` | 2 |
| 4     | PAWS receive-side check                       | `be0453a` + `79ed38e` | 2 |
| 5     | Convert plan to completion record             | this commit          | 0 |

Total: **9 code commits, 11 timestamps-specific integration
tests, ~80 LOC of production code in `tcp__session.py` +
~30 LOC across FSM modules + metadata + packet handlers.**

---

## 5. Test inventory (final)

All 11 tests live in
`pytcp/tests/integration/protocols/tcp/test__tcp__session__timestamps.py`:

### TestTcpTimestampsPhase1Active (4 tests)
- `active_open_syn_carries_tsopt` — outbound SYN with TSval=now_ms, TSecr=0
- `bilateral_send_ts_set_post_handshake_when_peer_supports` — `_send_ts=True` post-handshake
- `peer_no_tsopt_disables_send_ts` — `_send_ts=False` if peer omits TSopt
- `advertise_opt_out_disables_outbound_tsopt` — `_advertise_ts=False` suppresses outbound TSopt + asymmetric guard

### TestTcpTimestampsPhase2 (3 tests)
- `post_handshake_data_segment_carries_tsopt` — regression guard
- `ts_recent_updated_on_accepted_inbound_segment` — RFC 7323 §4.3
- `post_update_outbound_segment_echoes_new_ts_recent` — TSecr reflects `_ts_recent`

### TestTcpTimestampsPhase3 (2 tests)
- `karn_tainted_retransmit_measures_rtt_via_tsecr` — RFC 7323 §4 obviates Karn
- `non_tsopt_peer_falls_back_to_sample_tracker` — regression guard

### TestTcpTimestampsPhase4 (2 tests)
- `stale_tsval_segment_dropped` — RFC 7323 §5 PAWS
- `current_tsval_segment_accepted` — regression guard

### Cross-references covered indirectly

- `pytcp/tests/integration/protocols/tcp/test__tcp__session__harness_smoke.py`
  has a Timestamps-option round-trip test that replaced the
  legacy `paws_ts` placeholder.
- All existing handshake / data-transfer / SACK / RTO /
  cwnd integration tests continue to work unchanged because
  legacy peers in those tests do not advertise TSopt
  (`_send_ts` stays False for them).

---

## 6. Production code map

| File                                                | Purpose                                       |
|-----------------------------------------------------|-----------------------------------------------|
| `pytcp/socket/tcp__metadata.py`                     | `tcp__tsval` / `tcp__tsecr` fields            |
| `pytcp/stack/packet_handler/packet_handler__tcp__rx.py` | Populates metadata from `packet_rx.tcp.options.timestamps` |
| `pytcp/stack/packet_handler/packet_handler__tcp__tx.py` | `tcp__tsval` / `tcp__tsecr` kwargs emit TcpOptionTimestamps; `tcp__opt_timestamps` stat |
| `pytcp/lib/packet_stats.py`                         | `tcp__opt_timestamps` counter                 |
| `pytcp/protocols/tcp/tcp__session.py:__init__`      | `_advertise_ts`, `_send_ts`, `_ts_recent` fields |
| `pytcp/protocols/tcp/tcp__session.py:_transmit_packet` | TSopt emission gating per segment kind     |
| `pytcp/protocols/tcp/tcp__session.py:_check_paws_and_update_ts_recent` | RFC 7323 §5 PAWS + §4.3 `_ts_recent` refresh helper, called from `_process_ack_packet`, `_tcp_fsm_established`, and `_tcp_fsm_time_wait` |
| `pytcp/protocols/tcp/tcp__session.py:_process_ack_packet` | TSecr RTTM (PAWS + `_ts_recent` delegated to the helper) |
| `pytcp/protocols/tcp/tcp__fsm__syn_sent.py`         | Active-open + simultaneous-open negotiation    |
| `pytcp/protocols/tcp/tcp__fsm__listen.py`           | Passive-open negotiation                      |
| `pytcp/tests/lib/tcp_segment_factory.py`            | `tsval` / `tsecr` kwargs in `build_tcp4` / `build_tcp6` |
| `pytcp/tests/lib/tcp_session_testcase.py`           | `TcpProbe.tsval` / `TcpProbe.tsecr` fields    |

---

## 7. Deferred work

### 7.1 RFC 1337 TIME-WAIT assassination mitigation

PAWS-based protection: when a TIME-WAIT session receives a
segment from peer with stale TSval, drop it (already
covered by the Phase 4 PAWS check if the session is in
TIME-WAIT, but the `_process_ack_packet` path may not be
the one that handles TIME-WAIT segments). Audit needed.
~2-3 commits.

### 7.2 RFC 6191 TIME-WAIT 4-tuple reuse

Allow a new SYN from the same 4-tuple to take over a
TIME-WAIT session if peer's TSval has clearly advanced past
the TIME-WAIT's `_ts_recent`. Useful for short-lived
connection storms. ~3-4 commits.

### 7.3 RFC 8985 RACK-TLP

RACK uses per-segment send-times to detect tail loss faster
than RFC 5681's 3-dup-ACK trigger. Phase 1's TSval emission
is the building block; full RACK requires per-segment
send-time tracking and a separate scoreboard. ~10+ commits;
substantial new substrate.

### 7.4 PAWS in dup-ACK / OOO / TIME-WAIT paths — SHIPPED

Closed by Phase D1 of the test-coverage audit (commits
`eb48e62` + `d598e15`). The `_check_paws_and_update_ts_recent`
session helper is now invoked from `_process_ack_packet`,
`_tcp_fsm_established` (covers dup-ACK + OOO), and
`_tcp_fsm_time_wait`.

### 7.5 `_ts_recent` update for non-`_process_ack_packet` paths — SHIPPED

Closed alongside Phase 7.4 by the same `_check_paws_and_update_ts_recent`
helper, which refreshes `_ts_recent` as a side effect on every
accepted segment carrying TSopt.

---

## 8. Anti-patterns (preserved for future extensions)

- **Don't emit TSopt unilaterally.** Bilateral negotiation
  gates via `_send_ts`; emitting on a non-TSopt peer would
  see TSecr ignored or, worse, cause the peer to close the
  connection if it has strict option validation.

- **Don't update `_ts_recent` on out-of-window segments.**
  Per §4.3, only segments in receive sequence space update
  the cache. PyTCP's `_process_ack_packet` is called only on
  acceptable segments, so the gate is implicit; future
  extensions adding `_ts_recent` updates in other paths
  must explicitly check sequence acceptability first.

- **Don't apply PAWS during the SYN exchange.** PAWS only
  applies to segments arriving in synchronized states. The
  SYN exchange itself establishes `_ts_recent` for both
  sides, and TSval=0 on a SYN+ACK after a SYN with TSval=N
  would otherwise look "stale" relative to N.

- **Don't conflate `_advertise_ts` with `_send_ts`.**
  `_advertise_ts` is the application-level opt-out flag.
  `_send_ts` is the post-handshake bilateral-success flag.
  Outbound SYN gates on `_advertise_ts`; outbound non-SYN
  segments and inbound TSopt ingestion gate on `_send_ts`.

- **Don't forget modular comparison on TS values.** TSval
  is a 32-bit field that wraps every 24 days at 1 ms
  granularity. Use `lt32` from `tcp__seq` for `<`
  comparisons; raw Python `<` is wrong post-wrap.

---

## 9. Extender's re-orient command

```bash
git log --oneline --grep="timestamp\|RFC 7323\|TSopt\|PAWS" master..HEAD
make test 2>&1 | tail -5
ls pytcp/tests/integration/protocols/tcp/test__tcp__session__timestamps.py
grep -n "_send_ts\|_ts_recent\|tcp__tsval" pytcp/protocols/tcp/tcp__session.py | head
```

Read the docstrings of:
- `pytcp/protocols/tcp/tcp__session.py:_transmit_packet`
  (TSopt emission gating)
- `pytcp/protocols/tcp/tcp__session.py:_process_ack_packet`
  (PAWS + `_ts_recent` update + TSecr RTTM, all at the top)
- `pytcp/protocols/tcp/tcp__fsm__syn_sent.py` /
  `tcp__fsm__listen.py` (bilateral negotiation hooks)

Then decide whether the extension fits the deferred-work
taxonomy in §7 above, or is a new direction entirely.

---

## 10. Cross-references

- Workflow + reporting format:
  `.claude/rules/tcp_session_integration_tests.md` §7
- Coding style: `.claude/rules/coding_style.md`
- Adjacent shipped: `.claude/rules/tcp_rto_integration.md`
  (RFC 6298 RTO; the §4 sample tracker is the fallback for
  non-TSopt peers).
- Adjacent shipped: `.claude/rules/tcp_rfc5681_cwnd.md`
  (RFC 5681 cwnd; uses the same RTT estimator that benefits
  from §4 RTTM).
- Wire-level:
  `net_proto/protocols/tcp/options/tcp__option__timestamps.py`
