# PyTCP — TCP Test Docstring RFC-Citation Rule

Self-contained handoff for the in-progress task of adding
uniform `Reference: RFC <N> §<S> (<short desc>).` lines to
every TCP test method's docstring across 39 files.

---

## 1. Goal

Every test method docstring in the TCP test surface MUST have
the canonical shape:

```python
def test__example__behaviour(self) -> None:
    """
    Ensure <one-or-more sentences describing what the test verifies>.
    No inline RFC mentions in the description.

    Reference: RFC <number> §<section> (<short description>).
    """
```

Critical invariants:

1. **Description first, blank line, single `Reference:` line** at
   the end before closing `"""`.
2. **No duplicate RFC info.** If the description mentions an
   RFC inline (e.g. "Per RFC 5681 §3.1 (...)"), strip it. The
   `Reference:` line is the canonical citation.
3. **No `[FLAGS BUG]` markers.** They were tests-first workflow
   markers; once tests pass, they're misleading historical
   noise. Strip them.
4. **One `Reference:` line per RFC clause.** Cross-RFC tests
   may have multiple `Reference:` lines, one per clause.
5. **Plumbing/setup tests** (constructor defaults, mock fixture
   sanity, etc.) cite either:
   - `Reference: PyTCP test infrastructure (no RFC clause).` — for
     pure harness tests
   - `Reference: RFC 9293 §3.9 (User/TCP interface).` — for
     socket-API plumbing

---

## 2. Progress (as of handoff)

### ✓ Done (8 files, 169 tests, 5 commits)

- `pytcp/tests/unit/protocols/tcp/test__tcp__seq.py` (26 tests)
- `pytcp/tests/unit/protocols/tcp/test__tcp__rto.py` (20 tests)
- `pytcp/tests/unit/protocols/tcp/test__tcp__cwnd.py` (27 tests)
- `pytcp/tests/unit/protocols/tcp/test__tcp__newreno.py` (12 tests)
- `pytcp/tests/unit/protocols/tcp/test__tcp__iss.py` (12 tests)
- `pytcp/tests/unit/protocols/tcp/test__tcp__sack.py` (37 tests)
- `pytcp/tests/unit/protocols/tcp/test__tcp__loss_recovery.py` (18 tests)
- `pytcp/tests/unit/protocols/tcp/test__tcp__fsm.py` (17 tests)

### ◻ Pending (31 files, ~258 tests)

**Unit (3 files):**

| File | Tests | Reference: count | Per RFC count | [FLAGS BUG] count |
|---|---|---|---|---|
| test__tcp__enums.py | 11 | 7 | 3 | 0 |
| test__tcp__session__lifecycle.py | 11 | 8 | 3 | 0 |
| test__tcp__session__syscalls.py | 15 | 3 | 12 | 0 |

**Integration (25 files):**

| File | Tests |
|---|---|
| test__tcp__session__abort_api.py | 9 |
| test__tcp__session__close__normal.py | 18 |
| test__tcp__session__close__rst.py | 16 |
| test__tcp__session__close__simultaneous.py | 5 |
| test__tcp__session__close__time_wait.py | 4 |
| test__tcp__session__cwnd.py | 19 |
| test__tcp__session__data_transfer__out_of_order.py | 4 |
| test__tcp__session__data_transfer__recv.py | 4 |
| test__tcp__session__data_transfer__retransmit_dupack.py | 5 |
| test__tcp__session__data_transfer__retransmit_timeout.py | 6 |
| test__tcp__session__data_transfer__send.py | 11 |
| test__tcp__session__data_transfer__window.py | 8 |
| test__tcp__session__handshake__active.py | 14 |
| test__tcp__session__handshake__passive.py | 8 |
| test__tcp__session__harness_smoke.py | 14 |
| test__tcp__session__ipv6.py | 6 |
| test__tcp__session__keepalive.py | 9 |
| test__tcp__session__listener__multi_child.py | 3 |
| test__tcp__session__options.py | 3 |
| test__tcp__session__robustness__bad_segments.py | 3 |
| test__tcp__session__robustness__blind_attacks.py | 9 |
| test__tcp__session__rto.py | 18 |
| test__tcp__session__sack.py | 23 |
| test__tcp__session__seq_wraparound.py | 9 |
| test__tcp__session__shutdown_api.py | 10 |
| test__tcp__session__status_api.py | 7 |
| test__tcp__session__timestamps.py | 18 |
| test__tcp__session__wscale.py | 10 |

---

## 3. Per-file workflow

For each file:

1. **Audit pass.** Run:
   ```bash
   grep -nc "    def test__" <file>           # count tests
   grep -nc "Reference:" <file>               # count canonical refs
   grep -nc "Per RFC " <file>                 # count duplicate inline refs
   grep -nc "\[FLAGS BUG\]" <file>            # count workflow markers
   ```
   Aim for: `Reference: == def test__` count, `Per RFC == 0`,
   `[FLAGS BUG] == 0`.

2. **Read the full file** to understand each test's intent.

3. **Per test method**, apply the four cleanup patterns:

   **Pattern A — Strip `[FLAGS BUG]` block:**
   Use `Edit replace_all=True` once per file:
   ```python
   Edit(file_path=..., old_string='        """\n        [FLAGS BUG]\n\n        Ensure',
        new_string='        """\n        Ensure', replace_all=True)
   ```

   **Pattern B — Strip inline `Per RFC ...` line, add `Reference:`:**
   Per-test Edit. Convert:
   ```
   description text.
   Per RFC <N> §<S> (<...>).
   """
   ```
   to:
   ```
   description text.

   Reference: RFC <N> §<S> (<short desc>).
   """
   ```

   **Pattern C — Strip inline `RFC X §Y:` prefix in description:**
   Convert:
   ```
   """
   RFC 6298 §2.1: the initial RTO before any RTT
   sample MUST be 1 second.
   ...
   ```
   to:
   ```
   """
   Ensure the initial RTO before any RTT sample is 1 second.
   ...
   ```
   (Description should describe what the test does, not cite RFC.)

   **Pattern D — Add missing blank line before `Reference:`:**
   Tests where docstring ends with description directly
   followed by `Reference:` (no blank line) — insert the blank
   line.

4. **Verify** after each file:
   ```bash
   PYTHONPATH=. python -m unittest <module-path> 2>&1 | tail -3
   ```

5. **Module docstrings**: also strip historical `[FLAGS BUG]`
   narrative from module-level docstrings (the tests-first
   phase is over).

6. **Commit per logical batch** (3-5 files per commit, grouped
   by topic area — e.g. all data_transfer files together, all
   close files together, all handshake files together).

   Commit message template:
   ```
   Standardize Reference: lines on <area> tests

   Apply the canonical docstring shape (description + blank
   line + single Reference: line) to all <N> test methods
   across <files>. Strip duplicate inline 'Per RFC' citations,
   strip [FLAGS BUG] markers, ensure Reference: line is
   preceded by a blank line.

   Files:
     - <file 1> (<N> tests, RFC <X>)
     - ...

   'make lint' clean. <N> tests pass.

   Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
   ```

7. Final verification: `make lint` clean, `make test` shows
   8024 passing.

---

## 4. RFC inventory (cite this clause for what)

| RFC | Section | When to cite |
|---|---|---|
| RFC 9293 | §3.1 | Header format, wire-level field layout |
| RFC 9293 | §3.3.2 | FSM state machine dispatch |
| RFC 9293 | §3.4 | Sequence-number arithmetic, modular comparison |
| RFC 9293 | §3.4.1 | ISS selection (also RFC 6528) |
| RFC 9293 | §3.4.3 | Quiet Time MAY-skip alternative |
| RFC 9293 | §3.5 | Establishing a connection (active/passive open) |
| RFC 9293 | §3.6 | Closing a connection |
| RFC 9293 | §3.7.1 | MSS option |
| RFC 9293 | §3.7.4 | Nagle algorithm |
| RFC 9293 | §3.7.5 | IPv6 jumbograms |
| RFC 9293 | §3.8.1 | Retransmission timeout (also RFC 6298) |
| RFC 9293 | §3.8.4 | Keep-alive |
| RFC 9293 | §3.8.6.1 | Zero-window probing (persist timer) |
| RFC 9293 | §3.8.6.2 | Silly Window Syndrome avoidance |
| RFC 9293 | §3.9.1 | OPEN/SEND/RECEIVE/CLOSE/STATUS/ABORT/shutdown user-API |
| RFC 9293 | §3.10.1 | OPEN call processing |
| RFC 9293 | §3.10.4 | CLOSE call processing per state |
| RFC 9293 | §3.10.7.x | Per-state segment processing |
| RFC 1122 | §4.2.2.2 | PSH on last segment of write |
| RFC 1122 | §4.2.2.16 | TCP MUST be robust against shrinking windows |
| RFC 1122 | §4.2.3.2 | Delayed-ACK |
| RFC 1122 | §4.2.3.3 | Receiver SWS avoidance (sub-MSS-floor) |
| RFC 1122 | §4.2.3.4 | Nagle algorithm (Minshall variant) |
| RFC 1122 | §4.2.3.5 | R2 ≥ 100s retransmit abort |
| RFC 1122 | §4.2.3.6 | Keep-alive |
| RFC 1337 | §3 | TIME-WAIT assassination mitigations |
| RFC 2018 | §3 | SACK option wire format, scoreboard semantics |
| RFC 2018 | §4 | SACK block ordering |
| RFC 2675 | §5 | IPv6 jumbogram MSS=65535 wire signal |
| RFC 2883 | §3-§5 | DSACK detection / generation (case-1, case-2) |
| RFC 5681 | §2 | SMSS definition |
| RFC 5681 | §3.1 | Slow-start vs CA, RTO ssthresh halving |
| RFC 5681 | §3.2 | Fast-retransmit / fast-recovery |
| RFC 5681 | §4.2 | Immediate ACK on OOO segment |
| RFC 5961 | §3 | RST acceptability hardening |
| RFC 5961 | §4 | SYN-in-synchronized challenge ACK |
| RFC 5961 | §5 | ACK acceptability hardening (snd_una - max_window) |
| RFC 6298 | §2.1 | Initial RTO = 1 second |
| RFC 6298 | §2.2 | First-sample formula |
| RFC 6298 | §2.3 | EWMA update (alpha=1/8, beta=1/4, K=4) |
| RFC 6298 | §2.4 | RTO lower-bound clamp |
| RFC 6298 | §2.5 | RTO upper-bound clamp |
| RFC 6298 | §3 | Karn's algorithm |
| RFC 6298 | §5.5 | Binary backoff |
| RFC 6298 | §5.7 | Idle reset + SYN-RTO 3-second floor |
| RFC 6528 | §3 | Hash-based ISS generator (4-tuple binding) |
| RFC 6582 | §3 | NewReno step-3b deflation (partial cum-ACK) |
| RFC 6675 | §3 | IsLost predicate (count rule + byte rule) |
| RFC 6675 | §3 | NextSeg procedure |
| RFC 6675 | §4 | Pipe estimate of FlightSize |
| RFC 6675 | §6 | Cumulative-ACK absorption |
| RFC 6691 | §2 | MSS calculation from MTU |
| RFC 6928 | §2 | Initial Window of 10 segments / 14600 bytes |
| RFC 7323 | §2 | WSCALE bilateral negotiation |
| RFC 7323 | §3 | Timestamps option wire format |
| RFC 7323 | §4 | RTTM via TSecr |
| RFC 7323 | §4.3 | _ts_recent update |
| RFC 7323 | §5 | PAWS |
| RFC 8961 | §2 | Initial RTO best practices |

---

## 5. Suggested commit grouping

To keep commits reviewable, group by topic area:

**Commit 1**: enums + lifecycle + syscalls (3 unit files, ~37 tests)

**Commit 2**: handshake__active + handshake__passive + harness_smoke (3 files, ~36 tests)

**Commit 3**: close__normal + close__rst + close__simultaneous + close__time_wait (4 files, ~43 tests)

**Commit 4**: data_transfer__send + data_transfer__recv + data_transfer__out_of_order + data_transfer__window (4 files, ~27 tests)

**Commit 5**: data_transfer__retransmit_dupack + data_transfer__retransmit_timeout + rto + cwnd (integration; 4 files, ~48 tests)

**Commit 6**: sack + timestamps + wscale + seq_wraparound (4 files, ~60 tests)

**Commit 7**: keepalive + listener__multi_child + options + ipv6 (4 files, ~28 tests)

**Commit 8**: robustness__bad_segments + robustness__blind_attacks + status_api + abort_api + shutdown_api (5 files, ~38 tests)

---

## 6. Verification checklist

After ALL files are processed:

```bash
# No more inline duplicates
grep -rn "Per RFC " pytcp/tests/unit/protocols/tcp pytcp/tests/integration/protocols/tcp | wc -l
# Expected: 0

# No more FLAGS BUG markers
grep -rn "\[FLAGS BUG\]" pytcp/tests/unit/protocols/tcp pytcp/tests/integration/protocols/tcp | wc -l
# Expected: 0

# Reference: count ≈ test method count (some tests may have multiple Reference lines for cross-RFC)
grep -rn "Reference:" pytcp/tests/unit/protocols/tcp pytcp/tests/integration/protocols/tcp | wc -l
# Expected: ≥ ~430 (one per test minimum)

# Lint + suite still clean
make lint
make test 2>&1 | tail -5
# Expected: 8024 passing, 0 failures, 17 skipped, lint clean
```

---

## 7. Anti-patterns to avoid

- **Don't fabricate RFC citations.** If unsure which clause
  applies, prefer `Reference: RFC 9293 §3.9 (User/TCP interface).`
  for syscall plumbing or `Reference: PyTCP test
  infrastructure (no RFC clause).` for harness-only tests.
- **Don't keep `Per RFC ...` lines** "for reading clarity".
  The `Reference:` line is the canonical citation; duplicating
  it in the description is what the user explicitly forbade.
- **Don't merge multiple `Reference:` lines into one.** A test
  citing two RFCs gets two `Reference:` lines (one per clause).
- **Don't change test method names, signatures, or bodies.**
  Only docstrings.
- **Don't widen scope.** Don't add new tests, don't refactor
  helpers, don't fix bugs found during reading. Bug findings
  belong in a separate commit on a separate branch.
- **Don't skip the `make lint` / `make test` checks.** The
  test count drift would mask a regression.

---

## 8. Re-orient command for new sessions

```bash
# Audit the remaining work
for f in pytcp/tests/unit/protocols/tcp/test__tcp__*.py pytcp/tests/integration/protocols/tcp/test__tcp__*.py; do
  total=$(grep -c "    def test__" "$f")
  refs=$(grep -c "Reference:" "$f")
  per=$(grep -c "Per RFC " "$f")
  bug=$(grep -c "\[FLAGS BUG\]" "$f")
  echo "$f tests=$total refs=$refs per=$per bug=$bug"
done | column -t

# Files needing work: where refs < tests OR per > 0 OR bug > 0.
```

Then pick the next file from the pending list in §2 above and
apply the §3 workflow.

---

## 9. Cross-references

- Project coding style: `.claude/rules/coding_style.md`
- Unit test authoring: `.claude/rules/unit_tests.md`
- TCP target spec memory:
  `/root/.claude/projects/-root-PyTCP/memory/project_tcp_target_spec.md`
