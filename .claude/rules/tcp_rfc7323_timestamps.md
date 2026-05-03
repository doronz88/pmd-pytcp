# PyTCP — RFC 7323 §3 Timestamps Option: Phased Plan

Self-contained handoff plan for landing **RFC 7323 §3
Timestamps option** (TSopt) in PyTCP. The wire-level
`TcpOptionTimestamps` already exists in `net_proto`; this
plan wires it into `TcpSession` for bilateral negotiation,
per-segment emission, RTTM (Round-Trip Time Measurement) via
TSecr, and PAWS (Protection Against Wrapped Sequence numbers)
on the receive side.

Landing this transitively unblocks RFC 1337 (TIME-WAIT
assassination mitigation needs PAWS), RFC 6191 (TIME-WAIT
4-tuple reuse needs timestamps), and RFC 8985 (RACK-TLP
benefits from per-segment timestamps).

---

## 1. Mission

RFC 7323 §3 specifies the Timestamps option (TSopt) as a
10-byte option carrying `<TSval, TSecr>`:

  - **TSval** — sender's current "TS clock" value (a 32-bit
    counter that ticks at any rate from 1 ms to 1 s; PyTCP
    will use `stack.timer.now_ms`).
  - **TSecr** — most-recently-seen peer TSval, echoed back
    so peer can compute exact RTT from `now_ms - TSecr`.

The four invariants the project must satisfy:

  1. **Bilateral negotiation** (§2.2 / §3): TSopt carried on
     SYN and SYN+ACK iff both sides advertise it. Once
     bilaterally agreed, every post-handshake segment MUST
     carry it.
  2. **Per-segment emission** (§3): outbound segments
     populate TSval = `now_ms` and TSecr = `_ts_recent`.
  3. **RTTM via TSecr** (§4): on cum-ACK, RTT = `now_ms -
     TSecr` (peer's echoed timestamp identifies which
     transmission it acknowledges, eliminating Karn's
     ambiguity for retransmitted segments). The RFC 6298
     Phase 2 sample-tracker becomes a fallback for non-TSopt
     peers.
  4. **PAWS** (§5): inbound segments with `TSval <
     _ts_recent` (modular 32-bit) are dropped to defend
     against wrapped-sequence attacks across the 4 GB seq
     space.

After this project ships, PyTCP's RFC 6298 RTO estimator
gets exact per-segment RTT measurements (no Karn ambiguity,
no single-sample-per-RTT cadence limit), and the 4 GB
seq-wrap window expands to 24 days at 10 Gbit/s (the §5
PAWS protection scales with the TS clock, not the seq
space).

---

## 2. Standing principles (preserved)

1. **Tests-first per phase.** Each phase opens with a
   `[FLAGS BUG]` tests-first commit, then the impl flips
   them green. Mirror the SACK / RTO / cwnd workflow.
2. **Suite invariant.** Pass count never drops across a
   green commit boundary. Baseline at the start of this
   plan: 7907 passing, 17 skipped, 0 failures.
3. **Bilateral negotiation guard.** TSopt is gated on
   bilateral agreement: PyTCP advertises iff `_advertise_ts`
   is True (default True), peer echoes on its SYN+ACK iff
   it also advertises. Post-handshake `_send_ts` is True iff
   both sides advertised. All TSopt emission AND TSopt
   ingestion is gated on `_send_ts`.
4. **TS clock = `stack.timer.now_ms`.** Already monotonic,
   already used by the RFC 6298 RTO sampler (`now_ms` since
   commit `4c573e3`). 32-bit truncation suffices for the
   §3.2 wrap-around analysis (the modular comparison is
   handled the same way as Seq32).
5. **`_ts_recent` update is gated by acceptability.** Per
   §4.3 update only when the segment passes the receive-
   acceptability check AND `SEG.SEQ <= last_ack_sent`. This
   avoids stale TSval values from out-of-window segments
   poisoning the PAWS check.
6. **TSopt-driven RTTM is preferred but not required.** The
   RFC 6298 §4 sample-tracker (Phase 2 in
   `tcp_rto_integration.md`) remains in place for non-TSopt
   peers. When `_send_ts` is True AND peer's ACK carries
   TSecr, the TSopt path supersedes the tracker.

---

## 3. Architecture (target final state)

```
TcpSession new state:
    _advertise_ts: bool = True       # opt-out flag set by application
    _send_ts: bool                   # bilateral-success flag
    _ts_recent: int                  # peer's most-recently-seen TSval

TcpMetadata new fields:
    tcp__tsval: int | None           # peer's TSval from TSopt (None if absent)
    tcp__tsecr: int | None           # peer's TSecr from TSopt

Hook points:

    _transmit_packet (SYN active-open):
        Emit TSopt iff _advertise_ts. tsval=now_ms, tsecr=0.

    _transmit_packet (SYN+ACK passive-open):
        Emit TSopt iff peer's SYN had TSopt AND _advertise_ts.

    _transmit_packet (post-handshake non-SYN):
        Emit TSopt iff _send_ts. tsval=now_ms, tsecr=_ts_recent.

    _process_ack_packet (or earlier in inbound dispatch):
        Update _ts_recent on accepted segment per §4.3:
            if _send_ts and tcp__tsval is not None
                    and seq <= rcv_nxt (covers acceptable segment):
                _ts_recent = max(_ts_recent, tcp__tsval)  # modular max

    _process_ack_packet (RTTM via TSecr):
        if _send_ts and tcp__tsecr is not None:
            rtt = (now_ms - tcp__tsecr) & 0xFFFF_FFFF
            _rto_state = update(_rto_state, rtt)
            # Skip the Phase-2 sample-tracker harvest for this ACK.

    fsm__listen / fsm__syn_sent / fsm__syn_rcvd:
        Set _send_ts on bilateral negotiation success during
        the SYN exchange (mirroring _send_sack handling).

    Inbound segment acceptability (PAWS check):
        if _send_ts and tcp__tsval is not None
                and lt32_ts(tcp__tsval, _ts_recent):
            # Stale TSval - discard, send dup-ACK with current
            # state per RFC 7323 §5.4.
            ...
```

---

## 4. Phase-by-phase plan

### Phase 1 — Bilateral negotiation

Tests-first commit + fix commit.

**Tests** (new file
`pytcp/tests/integration/protocols/tcp/test__tcp__session__timestamps.py`):

  1. `test__ts__active_open_syn_carries_tsopt` [FLAGS BUG] -
     outbound SYN includes TSopt with tsval=now_ms, tsecr=0.
  2. `test__ts__passive_open_syn_ack_mirrors_peer_tsopt`
     [FLAGS BUG] - SYN+ACK echoes peer's TSval as TSecr.
  3. `test__ts__bilateral_send_ts_set_on_handshake_success`
     [FLAGS BUG] - `_send_ts == True` post-handshake when
     both sides advertised.
  4. `test__ts__peer_no_tsopt_disables_send_ts` [FLAGS BUG] -
     `_send_ts == False` if peer's SYN+ACK had no TSopt.
  5. `test__ts__advertise_opt_out_disables_outbound_tsopt`
     regression guard - setting `_advertise_ts = False`
     before connect prevents outbound TSopt emission.

**Fix commit:**
  - Add `_advertise_ts`, `_send_ts`, `_ts_recent` fields in
    TcpSession.__init__.
  - Add `tcp__tsval`, `tcp__tsecr` fields in TcpMetadata
    (with `None` default for non-TSopt peers).
  - Wire `packet_handler__tcp__rx.py` to populate these
    fields from `packet_rx.tcp.options.timestamps`.
  - Wire `packet_handler__tcp__tx.py` with `tcp__tsval` /
    `tcp__tsecr` kwargs that emit a `TcpOptionTimestamps`
    when both are not None.
  - Wire SYN emission in `_transmit_packet`: if `flag_syn`,
    emit TSopt with tsval=now_ms, tsecr=0.
  - Wire SYN+ACK emission and bilateral negotiation in
    `tcp__fsm__listen.py` and `tcp__fsm__syn_sent.py`.

Estimated: 2 commits. Risk: medium.

### Phase 2 — Emission on every post-handshake segment

Tests-first commit + fix commit.

**Tests:**

  1. `test__ts__post_handshake_data_segment_carries_tsopt`
     [FLAGS BUG] - data segment includes TSopt with
     tsval=now_ms, tsecr=peer's last TSval.
  2. `test__ts__ts_recent_updated_on_accepted_inbound_segment`
     [FLAGS BUG] - peer's TSval becomes `_ts_recent` after a
     valid inbound segment.
  3. `test__ts__ts_recent_not_updated_on_rejected_segment`
     [FLAGS BUG] - out-of-window segment's TSval does NOT
     update `_ts_recent`.

**Fix commit:**
  - Wire post-handshake TSopt emission in `_transmit_packet`
    (gated on `_send_ts`).
  - Add `_ts_recent` update in `_process_ack_packet`.

Estimated: 2 commits. Risk: low.

### Phase 3 — TSecr-driven RTTM

Tests-first commit + fix commit.

**Tests:**

  1. `test__ts__cum_ack_with_tsecr_drives_rttm` [FLAGS BUG] -
     ACK with TSecr=our_send_time updates `_rto_state` via
     `update(rto_state, now_ms - tsecr)`.
  2. `test__ts__retransmitted_segments_tsecr_path_avoids_karn_taint`
     [FLAGS BUG] - TSecr-based RTT is used even when the
     segment was retransmitted (§4 obviates Karn).
  3. `test__ts__non_tsopt_peer_falls_back_to_phase_2_sampler`
     regression guard - sample-tracker still works when
     TSopt is not negotiated.

**Fix commit:**
  - Add TSecr-based RTTM hook in `_process_ack_packet`.
  - Gate the Phase-2 sample-tracker harvest on `not _send_ts`
    (so TSopt path takes precedence when both available).

Estimated: 2 commits. Risk: medium.

### Phase 4 — PAWS receive-side check

Tests-first commit + fix commit.

**Tests:**

  1. `test__paws__stale_tsval_segment_dropped` [FLAGS BUG] -
     inbound segment with `TSval < _ts_recent` (modular)
     is silently dropped.
  2. `test__paws__current_tsval_segment_accepted` regression
     guard - inbound segment with `TSval >= _ts_recent` is
     accepted normally.
  3. `test__paws__wrap_aware_modular_comparison` [FLAGS BUG]
     - PAWS check uses 32-bit modular `lt32_ts`, not raw
     `<`, so a TSval that has wrapped past `_ts_recent` is
     correctly accepted.

**Fix commit:**
  - Add PAWS check in inbound segment dispatch (in the FSM
    state handlers' early acceptability check).
  - Add `lt32_ts` helper if needed (or reuse the existing
    `tcp__seq.lt32` since both are 32-bit modular).

Estimated: 2 commits. Risk: medium.

### Phase 5 — Documentation

Convert this plan to a completion record. Update memory
pointer. Update RFC table. Estimated: 1 commit.

---

## 5. Anti-patterns to avoid

- **Don't emit TSopt unilaterally.** RFC 7323 §3: "TS
  Options MUST NOT be sent on segments that do not have ACK
  bit set ... unless they are also part of the TCP three-way
  handshake (i.e., SYN segments)." Bilateral negotiation
  required for non-SYN segments.

- **Don't update `_ts_recent` on every inbound TSval.** §4.3
  specifies the update happens only on an "acceptable
  segment that the receiver believes can be (i.e., is in
  sequence and otherwise acceptable)". Stale or out-of-order
  segments must NOT update.

- **Don't drop the RFC 6298 Phase-2 sample tracker.** Some
  peers (older Linux without TSopt, embedded TCP stacks) do
  not negotiate TSopt. The sample tracker is the fallback;
  Phase 3 gates its harvest on `not _send_ts` rather than
  removing it.

- **Don't forget modular arithmetic on TS values.** TSval is
  a 32-bit field that wraps. The `lt32_ts(a, b)` comparison
  uses `((a - b) & 0xFFFF_FFFF) >= 0x8000_0000` (the same
  modular-half-distance trick as Seq32 in `tcp__seq.py`).

- **Don't apply PAWS during handshake.** RFC 7323 §5: PAWS
  applies only to segments arriving in synchronized states
  (ESTABLISHED, FIN_WAIT_1/2, CLOSE_WAIT, CLOSING, LAST_ACK,
  TIME_WAIT). The SYN exchange itself is not subject to
  PAWS — both sides establish `_ts_recent` from the
  exchange.

- **Don't conflate `_advertise_ts` with `_send_ts`.**
  `_advertise_ts` is the application-level opt-out flag
  (default True). `_send_ts` is the bilateral-success flag
  set by the FSM after the handshake. Outbound SYN gates on
  `_advertise_ts`; outbound non-SYN segments and TSopt
  ingestion gate on `_send_ts`.

---

## 6. Estimated effort

| Phase | Description                                      | Commits | Risk    |
|-------|--------------------------------------------------|---------|---------|
| 1     | Bilateral negotiation                            | 2       | medium  |
| 2     | Per-segment emission + _ts_recent tracking       | 2       | low     |
| 3     | TSecr-driven RTTM                                | 2       | medium  |
| 4     | PAWS receive-side check                          | 2       | medium  |
| 5     | Convert plan to completion record                | 1       | trivial |

Total: **9 commits**, ~3-5 hours of focused work.

---

## 7. Cross-references

- Coding style: `.claude/rules/coding_style.md`
- Unit test authoring: `.claude/rules/unit_tests.md`
- Adjacent shipped: `.claude/rules/tcp_rto_integration.md`
  (RFC 6298 RTO; the §4 sample tracker becomes the fallback
  path for non-TSopt peers).
- Adjacent shipped: `.claude/rules/tcp_rfc5681_cwnd.md`
  (RFC 5681 cwnd; unaffected by TSopt but uses the same RTT
  estimator that benefits from §4 RTTM).
- Wire-level: `net_proto/protocols/tcp/options/tcp__option__timestamps.py`
  (already shipped; just needs stack-level wiring).

---

## 8. Re-orient command for new sessions

```bash
git log --oneline --grep="timestamp\|RFC 7323\|TSopt\|PAWS" master..HEAD
ls pytcp/tests/integration/protocols/tcp/test__tcp__session__timestamps.py 2>/dev/null
grep -n "_send_ts\|_ts_recent\|tcp__tsval" pytcp/protocols/tcp/tcp__session.py 2>/dev/null | head
make test 2>&1 | tail -5
```

What it tells you:
- No `_send_ts` matches → Phase 1 not started.
- `_send_ts` exists, no PAWS check → Phase 4 not started.
- All four phases visible → Phase 5 (docs) is the wrap-up.

Match against §4 to pick up where the prior session left off.
