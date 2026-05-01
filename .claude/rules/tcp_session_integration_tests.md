# PyTCP — TCP Session Integration Test Plan & Implementation Guide

This document is a self-contained handoff for the
`tcp__session.py` integration-testing project. A future session can
pick up from any point by reading this file plus the test files
already landed under
`pytcp/tests/integration/socket/test__socket__tcp__session__*.py`.

---

## 1. Mission

Build a comprehensive integration-test suite for
`pytcp/socket/tcp__session.py` that:

1. Drives the TCP FSM end-to-end through the real packet handler
   (TX out via mocked `TxRing`, RX in via real `_phrx_ethernet`).
2. Asserts **RFC 9293** behaviour, not the current implementation's
   behaviour. Tests are written to the spec; failures are the
   surfacing of real bugs in `tcp__session.py`.
3. Each surfaced bug is fixed in a follow-up commit that names the
   failing test it makes pass.

Reference RFCs (cite in test docstrings, in this order of
precedence):

- **RFC 9293** — TCP, the consolidated spec. Default citation.
- **RFC 6298** — RTO computation. Cited for retransmit cadence.
- **RFC 7323** — Window scale + timestamps + PAWS.
- **RFC 1122** — Host requirements. Still cited for delayed-ACK
  timing, Nagle, R2 floor, PSH placement (clauses 9293 references
  but doesn't replace).
- **RFC 6691** — MSS calculation from MTU.
- **RFC 5681** — Congestion control / fast retransmit / 3 dup-ACK
  threshold.
- **RFC 5961** — Blind-attack robustness (folded into 9293; still
  useful for the original attack scenarios).
- All RFCs in plain text under `docs/rfc/tcp/` for offline
  reference.

---

## 2. Standing principles (DO NOT deviate)

1. **100% RFC compliant** is the directive. If the spec mandates a
   behaviour, the test asserts it - even when the current code does
   not implement it. Failing tests are the *intended outcome*; they
   are the spec citation in executable form.

2. **RFC 9293 is the target spec** for TCP. Cite 9293 sections;
   don't cite the obsolete 793 / 1122-TCP-section / 5961 separately
   when 9293 incorporates them. (The exceptions in §1 above stay
   separate because 9293 references but doesn't supersede them.)

3. **Workflow is "Option A": tests-first, then fixes-second.**
   Per file:
   - Land all scenarios in one commit, with expected failures
     marked `[FLAGS BUG]` in the docstring.
   - Then 1-N follow-up fix commits, each:
     - names the test it makes pass in the commit body
     - is minimal: fixes the root cause, no surrounding cleanup
     - includes any test-fixture updates needed (e.g. unit tests
       that pinned the buggy value need to be updated to the
       RFC value with new docstring rationale)
   - Lint clean and full suite green after each commit.

4. **Each test docstring** must:
   - Lead with `Ensure ...` (imperative).
   - Cite the RFC clause(s) the test encodes.
   - Have a `[FLAGS BUG]` section when the test is expected to fail
     today, explaining: (a) what current code does, (b) what the
     RFC requires, (c) the fix outline.
   - For passing tests, include a "regression guard" note.

5. **Wire-level assertions only at the test level.** Don't assert
   internal helper invariants directly - assert the outbound
   segment shape and the visible state (`session.state`,
   `_rx_buffer`, `_snd_una`, etc.). The `[FLAGS BUG]` section can
   reference internals; the assertions stick to the contract.

6. **Don't apply `tcp_seq` modular comparators yet.** The
   `pytcp/lib/tcp_seq.py` module exists and is unit-tested, but the
   migration of `tcp__session.py` to use it is deferred until the
   `seq_wraparound` test file (in §6 below) lands and forces it.
   See `project_tcp_target_spec.md` memory for context.

---

## 3. Architecture

### 3.1 Harness modules (under `pytcp/tests/lib/`)

| File | Role |
|---|---|
| `fake_timer.py` | Deterministic in-memory replacement for `pytcp.stack.timer.Timer`. Time advances via `advance(ms)`. |
| `tcp_segment_factory.py` | Peer-side frame builders: `build_tcp4(...)` and `build_tcp6(...)`. Wraps EthernetAssembler / Ip[46]Assembler / TcpAssembler. Reserved `paws_ts=` and `sack_block=` slots raise `NotImplementedError`. |
| `tcp_session_testcase.py` | `TcpSessionTestCase(NetworkTestCase)` base. Provides `_drive_rx`, `_advance`, `_parse_tx`, `_assert_segment`, `_assert_no_tx`, `_force_iss`. Snapshots/clears `stack.sockets` and `stack.interface_mtu` per test. |

### 3.2 Test directory layout

```
pytcp/tests/integration/socket/
    test__socket__tcp__session__harness_smoke.py
    test__socket__tcp__session__handshake__active.py
    test__socket__tcp__session__handshake__passive.py
    test__socket__tcp__session__data_transfer__send.py
    test__socket__tcp__session__data_transfer__recv.py
    test__socket__tcp__session__data_transfer__out_of_order.py
    test__socket__tcp__session__data_transfer__retransmit_timeout.py
    ... (more files per §6 matrix)
```

### 3.3 Per-file structure (every file follows this)

1. Standard 80-char copyright block, module docstring with
   `ver 3.0.4` and the file path.
2. Module-level constants:
   ```python
   STACK__IP: Ip4Address = STACK__IP4_HOST.address
   STACK__PORT: int = 12345
   PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
   PEER__PORT: int = 80
   LOCAL__ISS: int = 0x0000_1000   # sometimes 0x0000_3000 for passive
   PEER__ISS: int = 0x0000_2000   # sometimes 0x0000_4000 for passive
   PEER__WIN: int = 64240
   PEER__MSS: int = 1460
   ```
3. One `TestCase` class per file. Class name pattern:
   `TestTcp<Aspect>__<Variant>` (e.g. `TestTcpDataTransfer__Send`).
4. Two helper methods at top of class (copy-paste OK; promote to
   harness only when 4+ files use the same shape):
   - `_make_active_session(*, iss)` — constructs CLOSED session,
     registers in `stack.sockets`.
   - `_drive_handshake_to_established(*, iss, peer_iss)` — runs
     CONNECT + advance + drive SYN+ACK; returns ESTABLISHED session.
5. One test method per RFC scenario. Method name pattern:
   `test__<aspect>__<scenario_description>`.

### 3.4 Test-method idioms

- Always start with the fixture call (`_make_active_session` or
  `_drive_handshake_to_established`).
- For send-side tests, often `session._snd_ewn = PEER__WIN` to
  bypass slow-start when not testing it.
- Use `_drive_rx(frame=...)` to feed peer frames; returns inline TX
  list.
- Use `_advance(ms=N)` to tick the virtual clock; returns TX list
  produced during the advance.
- Use `_parse_tx(frame) -> TcpProbe` to inspect outbound segments.
- Use `_assert_segment(probe, flags=..., seq=..., ack=..., ...)` for
  fluent assertions. `_UNSET` sentinel skips a field; explicit
  `None` asserts an option is absent.
- End with state assertion: `self.assertIs(session.state, ...)`.

### 3.5 Conventions surfaced during development

- **Force ISS to a known value** with `self._force_iss(LOCAL__ISS)`
  before constructing the session, so `random.randint` returns a
  deterministic ISS.
- **MSS = 1460 for IPv4** (1500 MTU - 20 IPv4 - 20 TCP). For IPv6
  use 1440 (1500 - 40 - 20). The `interface_mtu` patch in the
  harness sets it to 1500.
- **Module-level baseline frame fixtures** are not required for
  programmatically-built frames; the factory generates them.
- **Empty TX assertion**: `self.assertEqual(tx, [], msg=...)` is
  the canonical form. `_assert_no_tx` checks `self._frames_tx` is
  globally empty (rarely useful since `_drive_rx` and `_advance`
  return only delta).
- **Per-test isolation**: harness clears `stack.sockets`, restores
  `stack.interface_mtu`, stops `mock.patch` handles registered via
  `_start_patch`. Tests must NOT rely on cross-test state.

---

## 4. Bugs fixed so far

Each row corresponds to one fix commit. Always paired with a
preceding test-landing commit per Option A workflow.

| # | Commit | Bug | RFC clause |
|---|---|---|---|
| 1 | `efb8343` | `PACKET_RETRANSMIT_MAX_COUNT` was 3 → 6 | RFC 1122 §4.2.3.5 R2 ≥ 100s |
| 2 | `ed54376` | No challenge ACK on SYN-in-established | RFC 9293 §3.10.7.4 |
| 3 | `ce2976e` | Step-1 ACK acceptability not lifted in SYN_SENT | RFC 9293 §3.10.7.3 step 1 |
| 4 | `2b99196` | Challenge ACK on SYN-in-syn_rcvd | RFC 9293 §3.10.7.4 |
| 5 | `ed9a246` | SYN-with-data rejected in LISTEN | RFC 9293 §3.10.7.2 step 3 |
| 6 | `b5c8ec5` | Wrong RST shape for ACK-bearing no-socket-match | RFC 9293 §3.10.7.1 |
| 7 | `f24bc90` | `send()` accepted writes after `close()` | RFC 9293 §3.10.6 |
| 8 | `1cba94f` | PSH not set on last segment of write | RFC 1122 §4.2.2.2 |
| 9 | `07a6077` | Nagle (Minshall variant) not implemented | RFC 1122 §4.2.3.4 |
| 10 | `bb8b6f8` | Zero-window persist timer not implemented | RFC 9293 §3.8.6.1 |
| 11 | `2b17b75` | Delayed-ACK first-segment + every-other-segment | RFC 1122 §4.2.3.2 |
| 12 | `7893c97` | Unacceptable-ACK silently dropped (no empty-ACK reply) | RFC 9293 §3.10.7.4 |
| 13 | `e3ea1b8` | Overlap segments rejected; rcv_nxt rewind on stale | RFC 9293 §3.10.7.4 |

Other commits (no production fix):
- `c51633c` RFC docs in `docs/rfc/tcp/` (26 files).
- `f3c9484` `pytcp/lib/tcp_seq.py` modular-arithmetic helpers + 112
  unit tests. Unused by production code yet.
- `89ef072` Initial harness modules + 14 smoke tests.
- `be1a3d7` Harness extension (sentinel, mtu patch, options-via-
  container).
- `c9d8044` Harness `stack.sockets` snapshot/clear.
- `06659bc`, `306eab7`, `f344bd4`, `35d747d`, `932a8b9`, `5926aa7`
  test-file commits.

---

## 5. Files completed (status snapshot)

| File | Tests | Status | New bugs surfaced |
|---|---|---|---|
| `harness_smoke.py` | 14 | ✓ all pass | — |
| `handshake__active.py` | 6 | ✓ all pass | 4 (R2, challenge-ACK, bare-ACK-RST, bogus-SYN+ACK-RST) |
| `handshake__passive.py` | 6 | ✓ all pass | 3 (RST shape, SYN-with-data, SYN-in-syn_rcvd) |
| `data_transfer__send.py` | 7 | ✓ all pass | 4 (PSH, persist, Nagle, send-after-close) |
| `data_transfer__recv.py` | 4 | ✓ all pass | 3 (delayed-ACK first-seg, every-other, unacceptable-ACK) |
| `data_transfer__out_of_order.py` | 3 | ✓ all pass | 1 (overlap rejected) |
| `data_transfer__retransmit_timeout.py` | 3 | ✓ all pass | 0 (positive-control regression guards) |

Total: 43 integration tests + 14 smoke + 112 `tcp_seq` unit tests
landed. Production-bug fix commits: 13.

Branch state at last checkpoint: 24 commits ahead of `master`,
7634/7634 full suite passing, lint clean.

---

## 6. Files remaining (plan §3.x mapping)

Each entry: file name, plan §, brief scope, expected `[FLAGS BUG]`
count from initial plan analysis. Adjust per actual code reading.

### 6.1 `data_transfer__retransmit_dupack.py` (§3.8)

Three duplicate ACKs from peer (same ack, no data) trigger fast
retransmit. Current code uses `> 1` (i.e. fires on 2nd dup-ACK);
RFC 5681 §3.2 mandates the 3rd. **Bug.** Test asserts strict 3-dup
threshold.

### 6.2 `data_transfer__window.py` (§3.9)

- Peer shrinks `RCV.WND` mid-flight: don't send past new edge
  (RFC 1122 §4.2.2.16).
- We advertise our receive window correctly as `_rx_buffer` fills.
  **Bug**: current code advertises constant 65535 regardless of
  buffer occupancy.
- WSCALE on SYN: we don't advertise → must ignore peer's wscale.
  **Bug**: current code blindly applies `_snd_wsc =
  packet_rx_md.tcp__wscale` (`_tcp_fsm_listen` and
  `_tcp_fsm_syn_sent`).
- WSCALE round-trip when both advertise — currently we don't
  advertise (per active-open #1 documented choice) so this case is
  vacuous; assert peer's wscale=N is ignored when we advertised
  none.

### 6.3 `close__normal.py` (§3.10)

- Active close: ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT.
  Wire-level shape of each segment.
- Passive close: ESTABLISHED + peer FIN → CLOSE_WAIT, then
  `close()` → LAST_ACK → CLOSED.
- Active close with TX buffer non-empty: data drains before FIN
  emitted.
- Active close while peer's win=0: must still respect persist
  behaviour (interaction with persist timer fix).

### 6.4 `close__simultaneous.py` (§3.11)

- Both sides FIN before either ACKs: ESTABLISHED → FIN_WAIT_1 →
  CLOSING (on peer FIN before we ACK ours) → TIME_WAIT (on ACK
  of our FIN).
- **Possible bug**: `_tcp_fsm_closing` requires `tcp__ack ==
  self._snd_nxt` strictly; may miss valid acks.

### 6.5 `close__rst.py` (§3.12)

- RST received in each state from SYN_RCVD through LAST_ACK: drops
  to CLOSED, raises pending recv/connect.
- RFC 9293 §3.10.7.4 RST acceptance: SEQ must be in receive
  window; otherwise challenge-ACK. **Bug**: current code's RST
  acceptance is too strict (`seq == rcv_nxt` only).

### 6.6 `close__time_wait.py` (§3.13)

- TIME_WAIT delay expiry → CLOSED, socket unregistered.
- Late retransmitted FIN from peer in TIME_WAIT: must respond ACK
  + re-arm timer per RFC 9293 §3.10.7.5. **Bug**: current
  `_tcp_fsm_time_wait` ignores incoming packets.
- Test parameterizes `TIME_WAIT_DELAY` via `mock.patch` to a small
  value, asserts behaviour at virtual-clock boundaries (just
  before/after expiry) rather than the literal 30s value.

### 6.7 `robustness__blind_attacks.py` (§3.14)

(Renamed from `robustness__rfc5961.py` per the plan; cite RFC 9293
§3.10.7.4 since it folds in 5961.)

- Blind RST with in-window seq but != rcv_nxt → challenge-ACK, no
  state change. **Bug**.
- Blind data injection: data with valid seq, ack out of window →
  drop, send ACK. (Already handled by §3.5 scenario #4 fix.)
- SYN-on-established → challenge-ACK. (Already covered by
  scenario `handshake__active.py` #4.)

### 6.8 `robustness__bad_segments.py` (§3.15)

- Bad checksum → parser drops; FSM never sees → no state change.
  (Verify integration; the parser tests already cover the parser.)
- All-zero-flags segment → drop.
- Reserved/ECN flag bits → ignore reserved bits, otherwise process.
- Payload with FIN+RST set → drop.
- Truncated TCP options → parser raises; verify `_frames_tx` empty.

### 6.9 `options.py` (§3.16)

- MSS clamping: peer MSS=9000 on 1500-MTU interface → effective
  `_snd_mss = 1460` (IPv4). For IPv6 should be 1440. **Bug** for
  IPv6 case (test in `ipv6.py`).
- MSS=0 from peer → SHOULD treat as 536 (RFC 9293 §3.7.1). **Bug**:
  current code passes 0 through.
- WSCALE only honoured when both sides advertise (covered in §3.9
  too).
- Unknown TCP option of even/odd length → parser skips; FSM
  unaffected.
- SACK-permitted on inbound SYN → silently ignored; we don't
  advertise SACK-permitted on outbound SYN (out of scope for SACK
  per project decision).

### 6.10 `listener__multi_child.py` (§3.17)

- Already partially covered by `handshake__passive.py` #5a (3
  concurrent SYNs). May be redundant - verify before writing. The
  remaining differentiator is: `accept()` returns the children in
  arrival order via `_tcp_accept` list; backlog has no cap (one
  test documenting this).

### 6.11 `ipv6.py` (§3.18)

- Re-runs canonical scenarios over IPv6: handshake, ESTABLISHED,
  close. Catches the IPv6 MSS bug (mtu - 60 vs current mtu - 40).
- Use `build_tcp6` factory (already supported).
- IPv6 addressing fixtures: `STACK__IP6_HOST`, `HOST_A__IP6`.

### 6.12 `seq_wraparound.py`

(Added during planning - covers the 32-bit modular arithmetic
gaps. Multiple `[FLAGS BUG]`.)

Three TestCase classes:

- **`__Seq`**: outbound seq wrap. Force `_snd_ini = 0xFFFFFF00`
  via `_force_iss`. Send 1KB; assert wire seq wraps correctly,
  TX-buffer offsets stay non-negative.
- **`__Ack`**: ACK handling across wrap. Test cases:
  - Peer ACK 0x10 with snd_una=0xFFFFFFE0, snd_max=0x20 must be
    accepted.
  - `_snd_una = max(snd_una, ack)` with raw `max` is wrong
    post-wrap; modular update needed.
  - Dup-ACK fast-retransmit counter dict purge across wrap.
  - FIN-ack across wrap.
- **`__SeqAndAck`**: both sides wrap simultaneously, bidirectional
  exchange.

These tests will fail at `struct.pack("!I", ...)` (raw int
overflow) until `tcp__session.py` is migrated to use
`pytcp.lib.tcp_seq` comparators. The migration is the production
fix; it's expected to land as item #14+ in the bugs-fixed list.

---

## 7. How to continue (concrete recipe)

### 7.1 Pick the next file from §6

Plan order recommended (matches existing momentum):

1. `data_transfer__retransmit_dupack.py` — small, focused, real
   bug to surface.
2. `data_transfer__window.py` — exposes 2-3 real bugs.
3. `close__normal.py` — large, mostly positive control.
4. `close__simultaneous.py`.
5. `close__rst.py` — exposes RST-acceptance bugs.
6. `close__time_wait.py` — exposes TIME_WAIT incoming-segment bug.
7. `robustness__blind_attacks.py`.
8. `robustness__bad_segments.py`.
9. `options.py`.
10. `listener__multi_child.py` (if not redundant).
11. `seq_wraparound.py` — last; triggers the `tcp_seq` migration.
12. `ipv6.py` — last positive-control sweep.

### 7.2 Per-file workflow

Per the user's established cadence:

1. Read the relevant `tcp__session.py` code paths first.
2. Pick the first scenario from the plan section.
3. Write ONE test method. Pause for user confirmation.
4. Run the test. Verify it fails for the predicted reason (or
   passes if positive control).
5. Run lint + full suite. Lint must be clean; no test
   regressions.
6. Repeat for each scenario in the file.
7. After all scenarios in a file are landed: ask user to commit
   the test file as a checkpoint (Option A workflow). User has
   consistently said "y" to this.
8. Then implement fixes one at a time. Each fix is its own commit
   that names the failing test it makes pass. Lint clean and full
   suite green after each.
9. After file is fully green, summarise and proceed to next file.

### 7.3 Standard helpers in every test file

Copy-paste from a sibling file (e.g.
`data_transfer__send.py`):

- Module-level constants block.
- `class Test...(TcpSessionTestCase): ...`
- `_make_active_session(*, iss)`.
- `_drive_handshake_to_established(*, iss, peer_iss)`.

These ARE intentionally duplicated across files. Promote to
`TcpSessionTestCase` only when ≥4 files use the identical shape -
premature abstraction is worse than a few copies.

### 7.4 Frequent gotchas

1. **`_snd_ewn` slow-start**: after handshake `_snd_ewn = 1 *
   MSS`. Most tests need to bypass this with `session._snd_ewn =
   PEER__WIN` so the test can focus on its actual concern.

2. **Delayed-ACK first segment**: post-fix #11, the delayed-ACK
   timer is armed when data is enqueued. Tests that send data and
   immediately check for an ACK on the next tick will see no ACK
   for the first ~`DELAYED_ACK_DELAY` ms. Use `_advance` past the
   interval if you want the ACK.

3. **Every-other-segment**: post-fix #11, two back-to-back data
   segments fire an inline ACK on the second arrival. Tests that
   expect a single inline ACK per segment will fail; structure
   tests to either (a) drive one segment at a time and check
   delayed-ACK, or (b) drive two and check the inline cumulative
   ACK.

4. **`stack.sockets` registration**: tests that use
   `_make_*_session` must register the socket in `stack.sockets`
   (the helper does this). Forgetting causes RX dispatch to miss
   the session.

5. **`_force_iss` patches `random.randint`**: must be called
   BEFORE `TcpSession.__init__` (which is where the patched call
   happens). The session helper does this in correct order; if
   you write a custom session-construction path, mirror the
   ordering.

6. **`_advance(ms=N)` vs precise timing**: each `ms` ticks
   (a) decrements all timers, then (b) fires registered methods
   whose delay reaches 0. Be careful with off-by-one when asserting
   "no TX in first N-1 ms, TX in Nth ms" - the boundary tick fires
   the action.

7. **Outbound packet inspection**: use `_parse_tx(frame)` to get
   a `TcpProbe`; never parse bytes directly in tests. The probe
   surfaces option presence as `mss=None` (option absent) vs
   `mss=536` (option present with value 536).

### 7.5 Commit message template

Test-landing commit:
```
Add <aspect> RFC-conformance integration tests

<aspect> scenario file for the TCP session integration suite,
covering <scope> per RFC 9293 §<...>.

Test method matrix (N of N <aspect> scenarios):

  1. test__<...>_<...>
     PASS / FAIL (intentional - flag bug). <description>

  ...

Net new bugs surfaced (M, excluding duplicates):
  - <bug 1> (RFC §<...>).
  ...

'make lint' clean. Test results on this commit:
  - <file>: N tests, P passing, F expected failures.
  - All other tests: <count> passing, 0 regressions.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

Fix commit:
```
<one-line summary> per RFC 9293 §<...>

<paragraph explaining the bug, citing the spec, and the fix>

Resolves the failing test added by commit '<hash>':

  test__<...>

<paragraph on the fix mechanics, edge cases, etc.>

'make lint' clean. Full test suite: <N> tests passing, +<delta>
from the previous commit (<file> #<scenario> flipped green).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

### 7.6 Per-scenario reporting format

After each scenario lands (test written, run, lint+suite green
or with the predicted [FLAGS BUG] failure), give the user a
structured report in this exact shape so they can scan progress
without reading code. The leading `●` is mandatory - it is the
visual marker the user looks for.

```
● Lint clean, <N> passing, <M> expected failures. Pausing.

  Summary

  Scenario #<N> added — `<test_method_name>`.

  Encodes RFC <X> §<Y> — <one-sentence spec citation>:

  <One paragraph walking the scenario: 'Drives ... peer sends
  ... session ...'>. Asserts:

  1. <wire-level or visible-state assertion>.
  2. <next assertion>.
  N. <last assertion>.

  <Pass/fail status>. <If fail: bug description with line refs.
  If pass: 'Passes today as positive control / regression
  guard for <thing>'>.

  <Optional fix outline section if [FLAGS BUG]:>
  Fix outline: <one paragraph + code skeleton in fenced block>.

  Status: <N> passing, <M> expected failures, lint clean.

  <One sentence on what is left in this file, then 'Continue
  with #<next>?'>
```

After all scenarios in a file are landed, include a
`final summary table` with the file's scenario matrix:

```
┌─────┬─────────────────────────────────────────────────────┬────────────┬──────────────────────────────────────────────────────┐
│  #  │                       Test                          │   Status   │                  Issue surfaced                      │
├─────┼─────────────────────────────────────────────────────┼────────────┼──────────────────────────────────────────────────────┤
│ 1   │ <test_method_short_name>                            │ ✓ pass     │ — (regression guard)                                 │
├─────┼─────────────────────────────────────────────────────┼────────────┼──────────────────────────────────────────────────────┤
│ 2   │ <test_method_short_name>                            │ ✗ fail [B] │ <one-line bug description>                           │
└─────┴─────────────────────────────────────────────────────┴────────────┴──────────────────────────────────────────────────────┘
```

Status column legend: `✓ pass` for green; `✗ fail [B]` for an
intentional [FLAGS BUG]. Right-align column borders by padding
to the widest cell content; do not let any cell wrap. Use box-
drawing characters (`┌─┬┐│├┼┤└┴┘`), not ASCII pipes.

After fixes land for a [FLAGS BUG] file, include a `commits
landed` table summarising the test-and-fix sequence:

```
┌──────────┬──────────────────────────────────────────────────────────────────┐
│  Commit  │                            Summary                               │
├──────────┼──────────────────────────────────────────────────────────────────┤
│ <hash>   │ Test file (N scenarios, M expected failures marked [FLAGS BUG])  │
├──────────┼──────────────────────────────────────────────────────────────────┤
│ <hash>   │ Fix #1: <one-line fix description>                               │
├──────────┼──────────────────────────────────────────────────────────────────┤
│ <hash>   │ Fix #2: <one-line fix description>                               │
└──────────┴──────────────────────────────────────────────────────────────────┘

  Final state:
  - Full suite: **<N> passing, 0 failures, 17 skipped** (was <M>
    + 17 before this work; +<delta> net).
  - `make lint` clean.
  - Branch now <K> commits ahead of `master`.

  <What's next per §6 plan>. Continue?
```

Tone notes for the per-scenario report:

- Keep paragraphs tight (1-3 sentences each). The reader is
  scanning for "does this need my attention".
- Always quote test names in backticks.
- Always cite RFC section in `§X.Y` form.
- For `[FLAGS BUG]` failures, include line refs (`tcp__session.py:N`)
  so the user can jump to the bug.
- For positive controls, lead the explanation with the phrase
  "Passes today as positive control / regression guard for X".
- The closing question is always `Continue with #<next>?` so
  the user can answer with a single `y`.

---

## 8. Things to watch out for

- **Don't apply `pytcp.lib.tcp_seq` comparators in
  `tcp__session.py`** until the `seq_wraparound.py` test file
  forces it. Plain `>` / `<=` comparisons are fine for the linear
  range exercised by current tests; the modular migration is one
  big focused commit later.

- **TIME_WAIT delay** stays at 30s - documented as a deviation
  from RFC's 2*MSL ≈ 240s, in the source comment. Tests that
  depend on TIME_WAIT timing patch `TIME_WAIT_DELAY` via
  `mock.patch` rather than relying on the literal value.

- **WSCALE semantics**: tests pin "we don't advertise WSCALE; we
  ignore peer's WSCALE" — NOT "we advertise WSCALE per RFC 7323".
  RFC 7323 makes it OPTIONAL.

- **SACK is out of scope.** Don't write tests that rely on SACK
  blocks in the TCP options. The factory's `sack_block=` slot
  raises `NotImplementedError`; one explicit test in `options.py`
  asserts SACK-permitted on inbound SYN is silently ignored and
  we don't advertise SACK-permitted on outbound SYN.

- **MPTCP, TCP-AO, L4S** are explicitly skipped per the project
  decision recorded in commit `c51633c`'s body.

- **Listener backlog has no cap.** `_tcp_accept` is unbounded.
  Confirmed during passive-open #5b research. One documenting
  test in `listener__multi_child.py` (or similar) pins this; the
  DoS implication is a future-work item, not in this test suite's
  scope.

- **Production-code fixes that surfaced but are NOT yet
  scheduled** (track in this doc when you start a new file):
  - Modular seq/ack arithmetic migration to `tcp_seq`
    (triggered by `seq_wraparound.py`).
  - IPv6 MSS calculation (mtu-60 vs mtu-40), triggered by
    `ipv6.py` and `options.py`.
  - `_rcv_wnd` shrinking as buffer fills (RFC 1122 §4.2.2.16),
    triggered by `data_transfer__window.py`.
  - SYN-on-synchronized challenge-ACK extension to FIN_WAIT_1,
    FIN_WAIT_2, CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT
    (currently only ESTABLISHED + SYN_RCVD have it). Triggered by
    `close__rst.py` / `close__time_wait.py`.

---

## 9. Quick re-orient command

After loading this rule, run:

```bash
git log --oneline -30
make test 2>&1 | tail -5
ls pytcp/tests/integration/socket/
```

That tells you exactly where the project is: which test files
exist, how many tests pass, and which commits have landed. Then
match against §5 above to pick up where the prior session left off.
