# PyTCP — SACK Implementation Plan

Detailed handoff plan for adding TCP Selective Acknowledgment
(RFC 2018) and Conservative Loss Recovery (RFC 6675) to PyTCP.
Reads as a self-contained project brief; a post-compact session
should pick this file up alongside
`.claude/rules/tcp_session_integration_tests.md` and execute the
phases below.

---

## 1. Scope and references

| RFC      | Title                                              | Use |
|----------|----------------------------------------------------|-----|
| RFC 2018 | TCP Selective Acknowledgment Options               | Wire format + bilateral negotiation |
| RFC 2883 | DSACK extension                                    | Optional — may defer to phase 7 |
| RFC 6675 | Conservative Loss Recovery using SACK              | Sender-side scoreboard / NextSeg / IsLost / Pipe |
| RFC 9293 | TCP (consolidated)                                 | Already canonical for FSM behaviour |
| RFC 7323 | Window Scale + timestamps                          | WSCALE done; timestamps still out of scope |

Project goal: PyTCP receives and emits SACK blocks correctly,
uses inbound SACK to drive RFC 6675 loss recovery, and
interoperates with conformant SACK-capable peers (Linux,
FreeBSD, etc.). DSACK (RFC 2883) is a phase-7 stretch goal.

---

## 2. Standing principles (carry over from
`tcp_session_integration_tests.md`)

1. **100% RFC-compliant.** Tests assert the spec, not the
   current code. Failing tests are the spec citation in
   executable form.
2. **Option A workflow.** Tests-first per file, then 1-N fix
   commits. Every `[FLAGS BUG]` test is paired with a fix that
   names it in the commit body.
3. **Reporting format.** After each scenario lands, give the
   user a `●`-led summary block plus end-of-file box-drawn
   matrix per `tcp_session_integration_tests.md` §7.6.
4. **One test method, one behavioural guarantee.**
5. **Wire-level assertions only at the test level.** Visible
   state (`session.<attr>`, `_rx_buffer`, `_snd_una`, etc.) is
   the contract; internals are documented in the docstring's
   `[FLAGS BUG]` section but not directly asserted.

---

## 3. Architecture (where the code lands)

```
pytcp/
    lib/
        tcp_seq.py                    (already done — modular comparators)
        tcp_sack.py                   NEW — SackScoreboard + helpers
        tcp_loss_recovery.py          NEW (phase 5) — RFC 6675 NextSeg / IsLost / Pipe
    socket/
        tcp__session.py               TcpSession integrated changes
    stack/packet_handler/
        packet_handler__tcp__tx.py    SACK option emission
        packet_handler__tcp__rx.py    (no changes; parser already decodes SACK)
    tests/
        lib/
            tcp_segment_factory.py    Wire up the `sack_block=` slot
        unit/
            lib/
                test__lib__tcp_sack.py        NEW — scoreboard unit tests
                test__lib__tcp_loss_recovery.py  NEW (phase 5)
        integration/socket/
            test__socket__tcp__session__sack.py  NEW — integration scenarios
```

Helper modules are pure logic and can be unit-tested in
isolation — keep them tight, don't import `TcpSession`.

---

## 4. Implementation phases

Order matters: each phase's tests assume the prior phase's
helpers exist. Phases 1-4 land SACK as a passive feature
(emit / receive blocks correctly without changing recovery
behaviour). Phases 5-6 turn it into active loss recovery.
Phase 7 is DSACK and may be deferred.

### Phase 1 — Wire-format groundwork

**Helper changes:**

1. `pytcp/tests/lib/tcp_segment_factory.py` — replace the
   `sack_block=` `NotImplementedError` with a real
   implementation:
   - Accept `sack_blocks: Iterable[tuple[int, int]] | None = None`
     (a list of `(left_edge, right_edge)` pairs).
   - When non-None, append a `TcpOptionSack(blocks=...)` to
     the options list.
   - Pad with NOPs to 4-byte alignment per the existing
     pattern.

2. `pytcp/tests/lib/tcp_session_testcase.py` — extend
   `TcpProbe`:
   ```python
   sack_blocks: tuple[tuple[int, int], ...]  # empty if absent
   ```
   `_parse_tx` reads
   `packet_rx.tcp._options.sack` (returns the list of blocks
   or `None`) and converts to a `tuple` of pairs.

3. `_assert_segment` gets a `sack_blocks=` parameter.

**No production-code changes in phase 1.** Tests using the new
factory parameter exercise the receive-side SACK option only.

**Phase-1 test scenarios in `test__socket__tcp__session__sack.py`:**

  - Inbound segment with SACK option does NOT crash the parser
    (positive control regression guard for the existing
    `TcpOptionSack` parser support).
  - Inbound segment with SACK option does NOT yet update any
    scoreboard state (current code has no scoreboard, so this
    is also a positive control documenting where the wire-level
    behaviour stops short).

### Phase 2 — `SackScoreboard` data structure

**Helper module:** `pytcp/lib/tcp_sack.py`

API:

```python
class SackScoreboard:
    """
    A SACK scoreboard tracking non-contiguous 'acked' ranges in
    32-bit modular sequence space. RFC 2018 §3 / RFC 6675 §3.
    Ranges are stored as [left_edge, right_edge) half-open
    intervals, sorted in modular order, never overlapping.
    """

    def __init__(self) -> None: ...

    def add_block(self, left: int, right: int) -> None:
        """
        Add a [left, right) SACK block, merging with adjacent
        / overlapping existing blocks per RFC 2018's union
        semantics.
        """

    def is_sacked(self, seq: int) -> bool:
        """
        True iff 'seq' falls in any tracked range.
        """

    def prune_below(self, snd_una: int) -> None:
        """
        Remove ranges entirely below SND.UNA after a cumulative
        ACK advances. Trim ranges that straddle SND.UNA.
        """

    def blocks(self) -> list[tuple[int, int]]:
        """
        Snapshot the current ranges, RFC 2018 ordering (most
        recent first per §4 if we choose to track recency; or
        sorted ascending modular for pure data view - decide
        per RFC 2018 §4 implementation note).
        """

    def first_gap(self, snd_una: int) -> int | None:
        """
        Return the lowest seq >= SND.UNA NOT covered by any
        block, or None if everything is covered. Used by RFC
        6675 §3's NextSeg.
        """
```

All comparisons / arithmetic use `pytcp.lib.tcp_seq` modular
helpers (`lt32`, `le32`, `add32`, `in_range32`).

**Phase-2 unit tests** — `test__lib__tcp_sack.py`:

- Empty scoreboard: `is_sacked` returns False for everything.
- Single block: contains-check works at edges, modular
  comparisons handled.
- Two non-adjacent blocks: order preserved, no merge.
- Two adjacent blocks: merge into one.
- Two overlapping blocks: merge into the union.
- `prune_below`: range entirely below pruned, range
  straddling trimmed, range entirely above kept.
- `first_gap`: returns SND.UNA when no blocks, returns
  block_end when first block starts at SND.UNA.
- Cross-wrap: blocks with `right < left` numerically (they
  wrap modularly) — verify `is_sacked` and `add_block` work
  per modular semantics.
- ~30-40 unit tests targeting 100% line coverage of
  `tcp_sack.py`.

### Phase 3 — Receive-side SACK emission

**TcpSession changes:**

1. New attributes:
   - `self._send_sack: bool` — True iff bilateral
     SACK-Permitted negotiation succeeded (we and peer both
     advertised on SYN).
   - `self._advertise_sack: bool = True` — opt-out flag,
     analogous to `_advertise_wscale`.

2. Update SYN / SYN+ACK transmit path:
   - `_transmit_packet` adds a new `tcp__sackperm` parameter
     (or, equivalently, a new bool that tells the TX path to
     emit SACK-Permitted).
   - On outbound SYN: emit SACK-Permitted iff
     `self._advertise_sack`.
   - On outbound SYN+ACK: emit SACK-Permitted iff
     `self._advertise_sack` AND peer's SYN had it
     (passive-open mirror, matching WSCALE pattern).

3. Update `_tcp_fsm_listen` and `_tcp_fsm_syn_sent`:
   - Set `self._send_sack` to True iff bilateral negotiation
     succeeded (parallel to `_snd_wsc` setting in WSCALE
     phase 6).
   - Else clear to False.

4. New method:
   ```python
   def _build_sack_blocks(self) -> list[tuple[int, int]]:
       """
       Compute the SACK blocks for our next outbound ACK from
       the current '_ooo_packet_queue' contents. Each queue
       entry's seq + payload length is a block.
       """
   ```

5. Update `_transmit_packet`'s outbound-ACK path to include
   SACK option iff `self._send_sack` AND
   `self._ooo_packet_queue` is non-empty.

6. Update `packet_handler__tcp__tx.py` to encode SACK blocks
   into a `TcpOptionSack` option (same options-stacking
   pattern as MSS+WSCALE).

**Phase-3 integration tests:**

- SACK-Permitted advertised on outbound SYN.
- Bilateral SACK negotiation sets `_send_sack=True`.
- Inbound out-of-order data segment causes outbound ACK to
  carry the SACK option with the correct `[seq,
  seq+payload_len)` block.
- Multiple OOO segments → multiple SACK blocks in outbound
  ACK (max 4 per RFC 2018, or 3 if timestamps were used).
- Cumulative ACK on `_ooo_packet_queue` drain causes SACK
  blocks to clear from subsequent ACKs.
- Asymmetric: peer didn't offer → we don't emit SACK
  (positive control / existing
  `data_transfer__window.py`-style asymmetric guard).

### Phase 4 — Send-side SACK ingestion

**TcpSession changes:**

1. New attribute: `self._sack_scoreboard: SackScoreboard`.

2. In `_process_ack_packet`:
   - Read SACK option from `packet_rx_md.tcp__sack_blocks`
     (will need a new metadata field — update
     `TcpMetadata` and `_phrx_tcp` to populate it).
   - For each block, call
     `self._sack_scoreboard.add_block(left, right)`.
   - On cumulative-ACK advance:
     `self._sack_scoreboard.prune_below(self._snd_una)`.

**Phase-4 integration tests:**

- Inbound ACK with one SACK block updates the scoreboard.
- Inbound ACK with multiple SACK blocks updates all of them.
- Cumulative ACK prunes blocks below `_snd_una`.
- SACK blocks that fall outside `[SND.UNA, SND.MAX]` are
  silently dropped (RFC 2018 §5: "Be liberal in what you
  accept" — but we don't have to act on out-of-window
  blocks).

### Phase 5 — RFC 6675 Conservative Loss Recovery

**Helper module:** `pytcp/lib/tcp_loss_recovery.py`

API:

```python
def is_lost(seq: int, scoreboard: SackScoreboard, snd_una: int, mss: int, dup_thresh: int = 3) -> bool:
    """
    RFC 6675 §3 IsLost(SeqNum) predicate: a segment is "lost"
    iff at least 'dup_thresh' SACK blocks above 'seq' have been
    reported. Replaces the legacy dup-ACK counter.
    """

def next_seg(scoreboard: SackScoreboard, snd_una: int, snd_max: int, mss: int) -> int | None:
    """
    RFC 6675 §3 NextSeg(): return the lowest unacked-and-
    unsacked seq, or None if everything is covered.
    """

def pipe(scoreboard: SackScoreboard, snd_una: int, snd_max: int, mss: int) -> int:
    """
    RFC 6675 §4 Pipe(): an estimate of bytes "in flight" that
    are not known to be SACKed. Excludes both delivered (below
    SND.UNA) and SACKed (in the scoreboard) ranges.
    """
```

**TcpSession changes:**

1. Replace fast-retransmit's dup-ACK counter with
   `is_lost(snd_una, ...)` check.
2. Use `next_seg(...)` to choose what to retransmit (replaces
   the current `_snd_nxt = _snd_una` reset in
   `_retransmit_packet_request`).
3. Use `pipe(...)` to bound `_snd_ewn` during recovery
   (cwnd inflation phase per RFC 5681 §3.2).

**Phase-5 integration tests:**

- 3 dup-SACKs above a gap trigger fast retransmit (replaces
  the existing 3-dup-ACK threshold from
  `data_transfer__retransmit_dupack.py`).
- After fast retransmit, NextSeg picks the actual gap (not
  always SND.UNA when SACK reveals later loss).
- Pipe excludes SACKed bytes when computing usable window.

### Phase 6 — SACK-Permitted advertise default flip

**Default-on:** `self._advertise_sack: bool = True`.

**Existing test fixture updates:**

- `data_transfer__window.py` scenario #2 (the
  `peer_wscale_ignored_when_we_did_not_advertise` test) is
  the WSCALE asymmetric guard. The SACK equivalent is the
  test in `options.py` scenario #3
  (`peer_sack_permitted_on_inbound_syn_silently_ignored`)
  and the `_advertise_sack=False` opt-out path. Mirror the
  WSCALE pattern: flip `_advertise_sack=False` in the
  scenario #3 setup so its semantics survive the
  default-advertise change.

### Phase 7 — DSACK (optional, may defer)

RFC 2883 extends RFC 2018 to allow the SACK option to also
report duplicate-data ranges (e.g. peer received the same
segment twice and reports it). The first SACK block on a
DSACK-bearing ACK carries the duplicate range; subsequent
blocks carry normal SACK information.

DSACK is useful for:
  - Distinguishing real loss from network reordering.
  - Better RTO estimation (don't shrink cwnd on a spurious
    retransmit).

**Defer recommendation:** SACK without DSACK is already
useful. DSACK adds complexity without changing the basic loss
recovery behaviour. Land phases 1-6, then revisit DSACK if
testing surfaces a need.

---

## 5. Test scenario matrix (target ~12-15 scenarios in
`test__socket__tcp__session__sack.py`)

| #  | Test name (suffix after `test__sack__`)                          | Phase | Type        |
|----|------------------------------------------------------------------|-------|-------------|
| 1  | `outbound_syn_advertises_sack_permitted`                         | 3     | [FLAGS BUG] |
| 2  | `bilateral_sack_negotiation_sets_send_sack`                      | 3     | [FLAGS BUG] |
| 3  | `out_of_order_data_segment_elicits_sack_block_in_outbound_ack`   | 3     | [FLAGS BUG] |
| 4  | `multiple_ooo_segments_yield_multiple_sack_blocks`               | 3     | [FLAGS BUG] |
| 5  | `cumulative_ack_drains_ooo_queue_clears_sack_blocks`             | 3     | [FLAGS BUG] |
| 6  | `passive_open_mirrors_peer_sack_permitted_offer`                 | 3     | [FLAGS BUG] |
| 7  | `passive_open_omits_sack_when_peer_did_not_offer`                | 3     | regression  |
| 8  | `inbound_sack_block_updates_scoreboard`                          | 4     | [FLAGS BUG] |
| 9  | `cumulative_ack_prunes_scoreboard_below_snd_una`                 | 4     | [FLAGS BUG] |
| 10 | `out_of_window_sack_block_silently_dropped`                      | 4     | regression  |
| 11 | `three_dup_sacks_above_gap_trigger_fast_retransmit`              | 5     | [FLAGS BUG] |
| 12 | `next_seg_selects_actual_gap_not_just_snd_una`                   | 5     | [FLAGS BUG] |
| 13 | `pipe_excludes_sacked_bytes_from_in_flight_estimate`             | 5     | [FLAGS BUG] |
| 14 | `asymmetric_offer_we_disabled_advertising_ignores_peer_sack`     | 6     | regression  |
| 15 | `sack_blocks_across_seq_wrap_handled_modularly`                  | 2/3   | [FLAGS BUG] |

Workflow per scenario follows
`tcp_session_integration_tests.md` §7.2 — write one test, run
the dedicated test, run full suite, run lint, commit, then
the corresponding fix commit. Use the §7.6 reporting format
for the user-facing summary.

---

## 6. Pre-existing fixture updates anticipated

### `options.py` scenario #3
Currently (`d1d6648`) tests "peer SACK-Permitted on SYN+ACK
ignored when we don't advertise." Once we default-advertise,
this needs to flip `_advertise_sack=False` to preserve
semantics. Mirror the WSCALE pattern from `4159d14`.

### `data_transfer__retransmit_dupack.py`
The existing 3-dup-ACK fast-retransmit threshold tests will
still hold but their semantics change subtly: dup-ACKs without
SACK information continue to use the count threshold, while
dup-ACKs WITH SACK use IsLost (which is more permissive). The
existing tests do not include SACK in the peer's dup-ACK
frames, so they continue to assert the count-based path. Any
test that wants to exercise the SACK-based path lives in
`sack.py` scenario #11.

### `data_transfer__retransmit_timeout.py`
RTO machinery is unchanged by SACK at the wire level. SACKed
ranges are just extra information for NextSeg / IsLost; RTO
still fires on absolute timeout. Existing tests continue to
pass without changes.

### Harness factory tests (`harness_smoke.py`)
Add a smoke test for the new `sack_blocks=` factory param if
the existing pattern-set is incomplete.

---

## 7. Estimated effort and milestones

| Phase | Description                          | Test count | Commits |
|-------|--------------------------------------|------------|---------|
| 1     | Wire-format groundwork               | ~2         | ~1      |
| 2     | SackScoreboard + unit tests          | 0 (unit)   | ~2      |
| 3     | Receive-side SACK emission           | ~6         | ~3      |
| 4     | Send-side SACK ingestion             | ~3         | ~2      |
| 5     | RFC 6675 Conservative Loss Recovery  | ~3         | ~3      |
| 6     | Default-advertise flip + fixture upd | 0          | ~1      |
| 7     | DSACK (optional)                     | ~2         | ~2      |

Total: ~14-16 integration tests, 30-40 unit tests, 12-14
commits. Probably 200-400k tokens of work in a fresh-context
session. Plan for a compact mid-way through.

---

## 8. Re-orient command for new sessions

After loading this rule, run:

```bash
git log --oneline -10
make test 2>&1 | tail -5
ls pytcp/lib/tcp_*
ls pytcp/tests/integration/socket/test__socket__tcp__session__*
```

Confirms the tcp_seq / WSCALE foundations are in place and
shows whether `tcp_sack.py` already exists (phase progress
indicator). Match against §4's phase ordering to pick up where
the prior session left off.

---

## 9. Anti-patterns to avoid

- **Don't merge SACK with retransmit_dupack.py logic in one
  commit.** The fast-retransmit-via-SACK path is RFC 6675
  Conservative Loss Recovery and lives in phase 5; the legacy
  3-dup-ACK count path stays for non-SACK peers. Keep them
  parallel.

- **Don't conflate SACK with DSACK.** RFC 2018 SACK is the
  sender-side recovery mechanism; RFC 2883 DSACK is the
  receiver-side reporting of duplicates. They share an option
  format but the algorithms are separate. Phases 1-6 land
  RFC 2018 only.

- **Don't store SACK blocks in `TcpSession` directly as a
  list.** Use the `SackScoreboard` helper. The merge logic is
  non-trivial (modular arithmetic, adjacent-block coalescing,
  prune-below) and earns a dedicated test surface.

- **Don't forget the modular arithmetic.** All SACK seq
  comparisons go through `pytcp.lib.tcp_seq` per the migration
  in `91abbc4`. A SACK block straddling the 32-bit wrap is a
  real production-relevant case; phase 2's unit tests cover
  it.

- **Don't break the tests-first invariant.** Each `[FLAGS
  BUG]` test must currently fail for the predicted reason
  before its fix lands.

---

## 10. Cross-references

- Workflow + reporting format:
  `.claude/rules/tcp_session_integration_tests.md` §7
- Coding style: `.claude/rules/coding_style.md`
- Unit test authoring:
  `.claude/rules/unit_tests.md`
- Modular sequence arithmetic:
  `pytcp/lib/tcp_seq.py` + `pytcp/tests/unit/lib/test__lib__tcp_seq.py`
- WSCALE implementation pattern (the closest precedent for
  SACK): commits `5b5bf5e` (test) + `4159d14` (impl).
