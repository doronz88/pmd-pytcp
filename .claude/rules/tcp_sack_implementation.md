# PyTCP — SACK Implementation: Project Record

**Status: SHIPPED** (RFC 2018 phases 1-6 + RFC 2883 phase 7 + RFC 6675
NextSeg / IsLost / Pipe helpers + multi-gap recovery primitive).

This document was originally a handoff plan to execute the SACK
implementation; it has now been rewritten as a completion record so a
future session that wants to **extend** SACK (rather than build it) has
a clean starting point. The implementation history, phase-by-phase
commit map, test inventory, and explicitly-deferred-work list are all
captured below.

---

## 1. Scope and references

| RFC      | Title                                              | Use |
|----------|----------------------------------------------------|-----|
| RFC 2018 | TCP Selective Acknowledgment Options               | Wire format + bilateral negotiation |
| RFC 2883 | DSACK extension                                    | Duplicate-segment reporting (phase 7) |
| RFC 6675 | Conservative Loss Recovery using SACK              | Sender-side scoreboard / NextSeg / IsLost / Pipe |
| RFC 9293 | TCP (consolidated)                                 | Canonical for FSM behaviour |
| RFC 7323 | Window Scale + timestamps                          | WSCALE done; timestamps still out of scope |

PyTCP receives and emits SACK blocks correctly, uses inbound SACK to
drive scoreboard-based loss recovery (with byte-rule and count-rule
triggers), skips already-SACKed bytes during multi-gap recovery, and
detects + reports duplicate ranges via RFC 2883 DSACK.

---

## 2. Standing principles (preserved for future extensions)

1. **100% RFC-compliant.** Tests assert the spec, not the current
   code. Failing tests are the spec citation in executable form.
2. **Option A workflow.** Tests-first per file, then 1-N fix commits.
3. **Wire-level assertions only at the test level.** Visible state
   (`session.<attr>`, `_rx_buffer`, `_snd_una`, etc.) is the contract;
   internals are described in the docstring `[FLAGS BUG]` section.
4. **One test method, one behavioural guarantee.**
5. **All seq arithmetic via `pytcp.lib.tcp_seq`.** Use the `Seq32`
   type alias on every annotation (PEP 695 transparent alias for
   `int`, defined in `tcp_seq.py`).

---

## 3. Architecture (final state)

```
pytcp/
    lib/
        tcp_seq.py                    Seq32 alias + lt32/le32/gt32/ge32/add32/sub32/in_range32 helpers
        tcp_sack.py                   SackScoreboard helper (RFC 2018 §3 modular range storage)
        tcp_loss_recovery.py          is_lost / next_seg / pipe predicates (RFC 6675 §3-§4)
    socket/
        tcp__metadata.py              tcp__sackperm + tcp__sack_blocks fields
    protocols/tcp/
        tcp__session.py               SACK attributes / helpers / FSM integration (see §6)
    stack/packet_handler/
        packet_handler__tcp__rx.py    Populates tcp__sackperm + tcp__sack_blocks from parser
        packet_handler__tcp__tx.py    SACK-Permitted + SACK option encoding
    tests/
        lib/
            tcp_segment_factory.py    sack_blocks= kwarg
            tcp_session_testcase.py   TcpProbe.sack_blocks field
        unit/
            lib/
                test__lib__tcp_sack.py            49 tests
                test__lib__tcp_loss_recovery.py   18 tests
        integration/socket/
            test__socket__tcp__session__sack.py   19 integration scenarios
```

---

## 4. Phase-by-phase completion record

| Phase | Description                          | Commits | Tests added |
|-------|--------------------------------------|---------|-------------|
| 1     | Wire-format groundwork               | `22672f3` | 1 smoke + 2 phase-1 |
| 2     | SackScoreboard + unit tests          | `679fcf3` | 49 unit |
| 3     | Receive-side SACK emission           | `a097b70` (test), `5eed4b7` (impl) | 7 integration |
| 4     | Send-side SACK ingestion             | `6fff58f` (test), `a8785e9` (impl) | 4 integration |
| 5     | RFC 6675 helpers + NextSeg wiring    | `f8df967` | 18 unit + 2 integration |
| 5b    | IsLost byte-rule + RecoveryPoint     | `4d98858` | 1 integration |
| 5c    | Skip SACKed bytes during recovery    | `90e24de` | 1 integration |
| 6     | Default-advertise flip               | (folded into phase 3) | (fixture updates only) |
| —     | `Seq32` PEP 695 type alias           | `c89e1d3` | (annotation refactor) |
| 7     | DSACK (RFC 2883)                     | `f27eec3` | 3 integration |

Total: **11 commits, 87 SACK-related tests, ~1500 lines of production
code.**

---

## 5. Test inventory (final)

### Integration tests in `test__socket__tcp__session__sack.py` (19)

| #  | Test name                                                                | Phase  |
|----|--------------------------------------------------------------------------|--------|
| 1  | `inbound_sack_option_does_not_crash_parser`                              | 1      |
| 2  | `inbound_sack_blocks_silently_consumed_when_send_sack_disabled`          | 4      |
| 3  | `outbound_syn_advertises_sack_permitted`                                 | 3      |
| 4  | `bilateral_sack_negotiation_sets_send_sack`                              | 3      |
| 5  | `out_of_order_data_segment_elicits_sack_block_in_outbound_ack`           | 3      |
| 6  | `multiple_ooo_segments_yield_multiple_sack_blocks`                       | 3      |
| 7  | `cumulative_ack_drains_ooo_queue_clears_sack_blocks`                     | 3      |
| 8  | `passive_open_mirrors_peer_sack_permitted_offer`                         | 3      |
| 9  | `passive_open_omits_sack_when_peer_did_not_offer`                        | 3      |
| 10 | `inbound_sack_block_updates_scoreboard`                                  | 4      |
| 11 | `cumulative_ack_prunes_scoreboard_below_snd_una`                         | 4      |
| 12 | `out_of_window_sack_block_silently_dropped`                              | 4      |
| 13 | `three_dup_sacks_above_gap_trigger_fast_retransmit`                      | 5      |
| 14 | `pipe_excludes_sacked_bytes_from_in_flight_estimate`                     | 5      |
| 15 | `byte_rule_triggers_fast_retransmit_on_first_dup_sack`                   | 5b     |
| 16 | `recovery_skips_already_sacked_bytes`                                    | 5c     |
| 17 | `dsack__fully_duplicate_segment_elicits_dsack_in_outbound_ack`           | 7      |
| 18 | `dsack__inbound_dsack_below_snd_una_detected_and_not_ingested`           | 7      |
| 19 | `dsack__inbound_dsack_contained_in_outer_block_detected`                 | 7      |

### Unit tests

- `test__lib__tcp_sack.py` — 49 tests covering empty state,
  add_block (single / disjoint / adjacent / overlap / nested /
  bridge / cross-wrap / asserts), is_sacked matrix at every edge
  class, prune_below partition, first_gap walk, blocks snapshot
  semantics, insert-sequence end-to-end matrix.

- `test__lib__tcp_loss_recovery.py` — 18 tests covering IsLost
  count rule + byte rule + below-seq filter, NextSeg
  empty/three-block/below-thresh/at-snd_max/byte-rule, Pipe
  empty/single/multi-block/out-of-window/OOB-args.

### Cross-references covered indirectly

- Cross-wrap modular behaviour: covered exhaustively by the
  scoreboard + loss-recovery unit tests (multiple cross-wrap
  scenarios) plus the existing `seq_wraparound.py` integration
  file. No dedicated SACK-cross-wrap integration test was added;
  the unit-level coverage is more thorough.

- `options.py` scenario #3 (`peer_sack_permitted_on_inbound_syn_silently_ignored`)
  pins the asymmetric-guard invariant ("we don't echo when we
  didn't advertise") with `_advertise_sack=False` opt-out, mirroring
  the WSCALE pattern.

---

## 6. Production code map (where SACK lives in `tcp__session.py`)

| Attribute / method            | Purpose                                                |
|-------------------------------|--------------------------------------------------------|
| `_advertise_sack: bool = True`| Opt-out flag for outbound SACK-Permitted               |
| `_send_sack: bool`            | Bilateral-success flag (set in listen / syn_sent)      |
| `_sack_scoreboard: SackScoreboard` | Send-side scoreboard                              |
| `_recovery_point: Seq32`      | RFC 6675 §5 RecoveryPoint (one-shot guard, `0` = idle) |
| `_pending_dsack: tuple[Seq32, Seq32] \| None` | DSACK report awaiting next ACK         |
| `_dsack_received: int`        | Counter of inbound DSACK detections (observability)    |
| `_build_sack_blocks()`        | Builds option blocks: pending DSACK first, then OOO    |
| `_ingest_sack_info(md)`       | Adds blocks to scoreboard; detects + skips DSACK       |
| `_prune_sack_scoreboard()`    | Drops blocks at/below SND.UNA                          |
| `_advance_snd_nxt_past_sacked()` | Skips SND.NXT past SACKed bytes during recovery     |

`_transmit_packet` gates SACK-Permitted on (active SYN +
`_advertise_sack`) OR (passive SYN+ACK + `_send_sack`); gates SACK
option emission on (`_send_sack` AND (OOO queue OR `_pending_dsack`)).

`_retransmit_packet_request` enters recovery on (count-rule OR
byte-rule) AND not-already-in-recovery; uses `next_seg(...)` to pick
the retransmit seq.

`_process_ack_packet` runs prune+ingest after SND.UNA update; clears
`_recovery_point` once SND.UNA crosses it; sets `_pending_dsack` on
overlap-prefix duplicates.

`_tcp_fsm_established` unacceptable-segment handler sets
`_pending_dsack` and emits ACK on fully-duplicate data segments.

---

## 7. Deferred work (out of scope for "the SACK project")

These items were considered and explicitly skipped. They belong to
adjacent projects, not SACK polish.

### 7.1 RFC 5681 cwnd rework (LARGEST deferred item)

PyTCP's current `_snd_ewn` is a placeholder ("doubles on every
cum-ACK"). Doing RFC 5681 properly requires:
- Separating `cwnd` from `_snd_ewn`, adding `ssthresh` tracking.
- Slow-start vs congestion-avoidance state machine.
- Loss-event cwnd halving.
- Fast-recovery cwnd inflation per RFC 5681 §3.2 step 4.
- Recovery-exit deflation per RFC 5681 §3.2 step 6.

This would unlock:
- **Pipe-bounded `_snd_ewn`** during recovery (RFC 6675 §6 step
  C.2): bound usable window by `cwnd - pipe()` so dup-ACK-driven
  cwnd inflation doesn't over-commit.
- **Spurious-retransmit cwnd recovery** via Eifel detection (RFC
  3522 et al), which would wire the `_dsack_received` counter into
  cwnd state so a spurious retransmit doesn't trigger congestion
  collapse.

Estimated effort: ~10 commits, full new test surface (slow-start /
congestion-avoidance / recovery / retransmit-after-RTO matrix). Frame
this as **"RFC 5681 conformance project"**, not SACK polish.

### 7.2 DSACK case-2 generation

Phase 7 lands the SENDER-side detection of both DSACK signatures
(below cum-ACK + contained-in-outer) but only generates case-1 on
the RECEIVER side (duplicate below cum-ACK). Case-2 generation —
emitting DSACK when peer retransmits bytes already in our OOO queue
— is not implemented.

To add: when an OOO segment arrives whose range overlaps an existing
OOO-queue entry, set `_pending_dsack = (overlap_left, overlap_right)`.
The generated SACK option will have the inner DSACK first, followed
by the outer OOO block(s), naturally matching the RFC 2883 §4 case-2
signature.

Estimated effort: 1-2 commits, ~2 integration tests. Defer until a
real interop need arises.

### 7.3 Formal RFC 6675 NextSeg loop

PyTCP today retransmits the first gap on the fast-retransmit trigger
and then uses the SACK-skip in `_transmit_data` to walk past SACKed
bytes for subsequent transmissions. This produces the same wire
output as RFC 6675's formal NextSeg-driven loop in canonical multi-
gap scenarios. Replacing the current approach with a literal NextSeg
loop is purely cosmetic — same wire output, more code.

**Recommendation: don't.** The current SACK-skip is correct,
contained, and cheap.

---

## 8. Anti-patterns (preserved for future extensions)

- **Don't conflate SACK with DSACK.** RFC 2018 SACK is the sender-
  side recovery mechanism; RFC 2883 DSACK is the receiver-side
  reporting of duplicates. They share an option format but the
  algorithms are separate. Phase 7's DSACK lives in dedicated paths
  (`_pending_dsack`, the unacceptable-segment handler, the DSACK
  detector in `_ingest_sack_info`); don't co-mingle them with the
  RFC 2018 SACK paths.

- **Don't store SACK blocks in `TcpSession` directly.** Use the
  `SackScoreboard` helper. The merge logic is non-trivial (modular
  arithmetic, adjacent-block coalescing, prune-below).

- **Don't forget the modular arithmetic.** All SACK seq comparisons
  go through `pytcp.lib.tcp_seq`. A SACK block straddling the 32-
  bit wrap is a real production-relevant case; the unit tests
  cover it. Use the `Seq32` type alias on every annotation that
  holds a sequence number — it signals "use the modular helpers,
  not Python's built-in `<`".

- **Don't conflate `_advertise_sack` with `_send_sack`.**
  `_advertise_sack` is the opt-out flag set by the application
  before CONNECT/LISTEN. `_send_sack` is the bilateral-success
  flag set by the FSM during handshake. The TX path uses
  `_advertise_sack` for the active-open SYN (peer's view is not
  yet known) and `_send_sack` for the passive-open SYN+ACK and
  every subsequent non-SYN ACK.

- **Don't forget DSACK is "advisory".** RFC 2883 §4: "A receiver
  uses the D-SACK option simply to report a duplicate". Generating
  DSACK is mandatory when the receiver has SACK support; consuming
  it on the sender side is informational. Don't gate functional
  behaviour on `_dsack_received`.

---

## 9. Extender's re-orient command

If you want to extend SACK (e.g. land deferred case-2 generation,
wire `_dsack_received` into Eifel-style spurious-retransmit recovery,
or add timestamps-with-SACK interop), start with:

```bash
git log --oneline --grep="SACK\|sack\|DSACK" master..HEAD
make test 2>&1 | tail -5
ls pytcp/lib/tcp_*
ls pytcp/tests/integration/socket/test__socket__tcp__session__sack.py
```

Read the docstrings of:
- `pytcp/lib/tcp_sack.py::SackScoreboard`
- `pytcp/lib/tcp_loss_recovery.py` (all three predicates)
- `pytcp/protocols/tcp/tcp__session.py::TcpSession.__init__` (SACK attributes
  with their inline docstrings)

Then decide whether the extension fits the deferred-work taxonomy in
§7 above, or is a new direction entirely.

---

## 10. Cross-references

- Workflow + reporting format:
  `.claude/rules/tcp_session_integration_tests.md` §7
- Coding style: `.claude/rules/coding_style.md`
- Unit test authoring: `.claude/rules/unit_tests.md`
- Modular sequence arithmetic:
  `pytcp/lib/tcp_seq.py` + `pytcp/tests/unit/lib/test__lib__tcp_seq.py`
- WSCALE precedent (the closest pattern for SACK's bilateral
  negotiation): commits `5b5bf5e` (test) + `4159d14` (impl).
