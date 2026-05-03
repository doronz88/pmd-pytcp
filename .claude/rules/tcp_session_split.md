# PyTCP — TCP Session Move + Split Plan

Detailed handoff plan for moving `tcp__session.py` out of
`pytcp/socket/` and splitting its 3031-line monolith into
per-aspect files following PyTCP conventions. Reads as a self-
contained project brief; a post-compact session should pick this
file up and execute the phases below.

---

## 1. Mission

Two changes, executed as one coherent refactor:

1. **Move:** `pytcp/socket/tcp__session.py` is a protocol runtime
   (RFC 9293 FSM, retransmission, SACK, RX/TX buffers), not a BSD
   socket facade. Move it to `pytcp/protocols/tcp/` to mirror the
   `net_proto/protocols/tcp/` parser/assembler tree on the
   runtime side. `pytcp/socket/tcp__socket.py` stays where it is
   and becomes a true facade that imports the session from its
   new location.

2. **Split:** Decompose the 3031-line `TcpSession` class into:
   - `tcp__enums.py` — `FsmState`, `SysCall`, `ConnError`,
     `TcpSessionError`.
   - `tcp__tracing.py` — `trace_fsm`, `trace_win` decorators.
   - `tcp__fsm__<state>.py` × 11 — one file per FSM state,
     each exposing a free function `fsm__<state>(session: TcpSession,
     *, packet_rx_md, syscall) -> None`.
   - `tcp__fsm.py` — small dispatcher (dict[FsmState, Callable])
     replacing `TcpSession.tcp_fsm()`.
   - `tcp__session.py` — `TcpSession` class with everything else
     (init, properties, dunders, BSD syscalls, transmit /
     retransmit / ack-processing / acceptability machinery).

Tests follow source: rename + relocate to
`pytcp/tests/unit/protocols/tcp/` and
`pytcp/tests/integration/protocols/tcp/`.

---

## 2. Standing principles (preserved)

1. **Pure rename, no behaviour change.** Phases 1-5 must keep
   wire output and FSM behaviour identical. The only allowed
   deltas in this project are file/symbol moves, import paths,
   and the FSM-handler-as-free-function dispatch shape. Any
   protocol bug surfaced during the move is recorded but
   **deferred** to a separate fix commit on the next branch.

2. **Free functions for FSM states, methods for everything
   else.** No mixins — see `.claude/rules/coding_style.md` and
   the analysis of the packet_handler mixin pattern in
   conversation history. The FSM state handlers are pure
   transitions on session state, perfect free-function shape.
   Transmit / ack-processing / acceptability stay as methods on
   `TcpSession` because they mutate and call each other heavily;
   peeling them risks reintroducing the TYPE_CHECKING-shadow
   problem that mixins would create.

3. **PEP 420 namespace package for `pytcp/protocols/tcp/`.** No
   `__init__.py` — matches `net_proto/protocols/tcp/` and
   `net_proto/protocols/udp/`. Filename self-identification via
   the `tcp__` prefix is the project rule.

4. **One commit per phase.** Each phase is mechanically
   reversible. Lint clean and full suite green after each.

5. **Reporting format.** After each phase lands, give the user a
   `●`-led summary block per
   `tcp_session_integration_tests.md` §7.6 with diff stats and
   suite count.

---

## 3. Target architecture (final state)

```
pytcp/
    protocols/                       NEW — namespace package
        tcp/                         NEW — namespace package, no __init__.py
            tcp__enums.py            FsmState, SysCall, ConnError, TcpSessionError
            tcp__tracing.py          trace_fsm, trace_win
            tcp__session.py          TcpSession class (~1750 LOC after split)
            tcp__fsm.py              FSM dispatch table + tcp_fsm() helper
            tcp__fsm__closed.py      11 free-function modules:
            tcp__fsm__listen.py        def fsm__<state>(session, *, packet_rx_md, syscall) -> None
            tcp__fsm__syn_sent.py
            tcp__fsm__syn_rcvd.py
            tcp__fsm__established.py
            tcp__fsm__fin_wait_1.py
            tcp__fsm__fin_wait_2.py
            tcp__fsm__closing.py
            tcp__fsm__close_wait.py
            tcp__fsm__last_ack.py
            tcp__fsm__time_wait.py
    socket/
        tcp__socket.py               Imports TcpSession from pytcp.protocols.tcp
        tcp__metadata.py             Unchanged
        ...                          udp__*, raw__* unchanged
    tests/
        unit/
            protocols/               NEW
                tcp/                 NEW
                    test__tcp__enums.py             (renamed from socket/test__socket__tcp__session__enums.py)
                    test__tcp__session__lifecycle.py
                    test__tcp__session__syscalls.py
                    test__tcp__fsm.py
            socket/
                test__socket__tcp__socket.py        Stays; imports updated
                test__socket__socket_id.py          Unchanged
                test__socket__udp__*.py             Unchanged
                test__socket__raw__*.py             Unchanged
        integration/
            protocols/               NEW
                tcp/                 NEW
                    test__tcp__session__handshake__active.py    (× 21 files renamed)
                    ...
            socket/                  (becomes empty? — see §6 below)
```

---

## 4. Phase-by-phase plan

### Phase 0 — Create the directory + move file as-is

Single commit, single rename, full suite must pass after.

1. `mkdir -p pytcp/protocols/tcp` (no `__init__.py`).
2. `git mv pytcp/socket/tcp__session.py pytcp/protocols/tcp/tcp__session.py`.
3. Update every importer of `pytcp.socket.tcp__session` to
   `pytcp.protocols.tcp.tcp__session`. Confirmed importer set:
   - `pytcp/socket/tcp__socket.py`
   - `pytcp/lib/tcp_seq.py`
   - All 25 test files under
     `pytcp/tests/{unit,integration}/socket/test__socket__tcp__session*`
4. `make lint && make test` clean.

Phase 0 is reversible with a single revert. Estimated: ~30 lines
of import edits, 1 commit.

### Phase 1 — Extract `tcp__enums.py`

1. Create `pytcp/protocols/tcp/tcp__enums.py` with the four
   classes: `TcpSessionError`, `SysCall`, `FsmState`, `ConnError`.
2. Replace their definitions in `tcp__session.py` with a single
   `from pytcp.protocols.tcp.tcp__enums import (...)` line.
3. Update test importers — most test files import these via
   `from pytcp.socket.tcp__session import FsmState, SysCall, ...`
   and were updated to `pytcp.protocols.tcp.tcp__session` in
   phase 0. Now they need to point to `tcp__enums` directly OR
   keep importing from `tcp__session` (which re-exports the
   enums via the import statement). **Decision: re-export via
   `tcp__session` to minimise churn.** Each test file already
   has the right import path after phase 0; no further test
   edits needed.
4. Lint + test clean.

### Phase 2 — Extract `tcp__tracing.py`

1. Move `trace_fsm` and `trace_win` decorators to
   `pytcp/protocols/tcp/tcp__tracing.py`.
2. Import them back into `tcp__session.py`.
3. Lint + test clean.

### Phase 3 — Extract 11 FSM state handlers as free functions

The largest phase. Per state, in this exact order (smallest →
largest, so dispatch table can grow incrementally):

| File                          | Source method (in current `tcp__session.py`) | Approx LOC |
|-------------------------------|----------------------------------------------|------------|
| `tcp__fsm__closed.py`         | `_tcp_fsm_closed`                            | ~15        |
| `tcp__fsm__time_wait.py`      | `_tcp_fsm_time_wait`                         | ~50        |
| `tcp__fsm__last_ack.py`       | `_tcp_fsm_last_ack`                          | ~70        |
| `tcp__fsm__closing.py`        | `_tcp_fsm_closing`                           | ~80        |
| `tcp__fsm__fin_wait_2.py`     | `_tcp_fsm_fin_wait_2`                        | ~90        |
| `tcp__fsm__fin_wait_1.py`     | `_tcp_fsm_fin_wait_1`                        | ~110       |
| `tcp__fsm__close_wait.py`     | `_tcp_fsm_close_wait`                        | ~145       |
| `tcp__fsm__listen.py`         | `_tcp_fsm_listen`                            | ~155       |
| `tcp__fsm__syn_rcvd.py`       | `_tcp_fsm_syn_rcvd`                          | ~130       |
| `tcp__fsm__syn_sent.py`       | `_tcp_fsm_syn_sent`                          | ~225       |
| `tcp__fsm__established.py`    | `_tcp_fsm_established`                       | ~205       |

Per-state recipe:

1. Create `tcp__fsm__<state>.py` exposing a single free function:
   ```python
   from typing import TYPE_CHECKING

   from net_proto import PacketRx
   from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall

   if TYPE_CHECKING:
       from pytcp.protocols.tcp.tcp__session import TcpSession

   def fsm__<state>(
       session: TcpSession,
       *,
       packet_rx_md: TcpMetadata | None,
       syscall: SysCall | None,
   ) -> None:
       """
       TCP FSM <STATE> state handler.
       """
       ...
   ```
2. Body is verbatim `_tcp_fsm_<state>` with `self.` → `session.`
   substitutions. **No logic changes.** Tests verify equivalence.
3. Delete `_tcp_fsm_<state>` from `TcpSession`.
4. (Phase 3 deliberately does NOT yet update `tcp_fsm()`; that's
   phase 4. During phase 3, the dispatcher in `tcp_fsm()`
   continues to call methods that no longer exist — so phase 3
   commits land in a temporarily-broken state at the dispatcher.
   To avoid this, run phases 3 and 4 as a single commit OR keep
   the methods as shims:
   ```python
   def _tcp_fsm_listen(self, *, packet_rx_md, syscall) -> None:
       fsm__listen(self, packet_rx_md=packet_rx_md, syscall=syscall)
   ```
   **Decision: use shims so each state lands as its own commit;
   the shims disappear in phase 4.**)
5. Lint + test clean after each state.

11 commits in phase 3, one per state.

### Phase 4 — Replace `tcp_fsm()` dispatcher with a table

1. Create `pytcp/protocols/tcp/tcp__fsm.py`:
   ```python
   from collections.abc import Callable

   from pytcp.protocols.tcp.tcp__enums import FsmState
   from pytcp.protocols.tcp.tcp__fsm__closed import fsm__closed
   from pytcp.protocols.tcp.tcp__fsm__listen import fsm__listen
   # ... all 11 states

   FSM_HANDLERS: dict[FsmState, Callable[..., None]] = {
       FsmState.CLOSED: fsm__closed,
       FsmState.LISTEN: fsm__listen,
       # ... all 11
   }
   ```
2. Replace `TcpSession.tcp_fsm()` body with:
   ```python
   def tcp_fsm(self, *, packet_rx_md=None, syscall=None) -> None:
       FSM_HANDLERS[self._state](
           self, packet_rx_md=packet_rx_md, syscall=syscall,
       )
   ```
3. Delete the 11 `_tcp_fsm_<state>` shim methods on `TcpSession`.
4. Lint + test clean.

1 commit in phase 4.

### Phase 5 — Test relocation + rename

This phase is mechanical but touches 25 files. Run as a single
commit because git's rename detection works best when filename
similarity is high.

**Renames** (drop `socket__` prefix, add `protocols/tcp/` path,
keep `tcp__session__` infix):

| Old path                                                                | New path                                                                            |
|-------------------------------------------------------------------------|-------------------------------------------------------------------------------------|
| unit/socket/test__socket__tcp__session__enums.py                        | unit/protocols/tcp/test__tcp__enums.py                                              |
| unit/socket/test__socket__tcp__session__lifecycle.py                    | unit/protocols/tcp/test__tcp__session__lifecycle.py                                 |
| unit/socket/test__socket__tcp__session__syscalls.py                     | unit/protocols/tcp/test__tcp__session__syscalls.py                                  |
| unit/socket/test__socket__tcp__session__fsm.py                          | unit/protocols/tcp/test__tcp__fsm.py                                                |
| integration/socket/test__socket__tcp__session__close__normal.py         | integration/protocols/tcp/test__tcp__session__close__normal.py                      |
| integration/socket/test__socket__tcp__session__close__rst.py            | integration/protocols/tcp/test__tcp__session__close__rst.py                         |
| integration/socket/test__socket__tcp__session__close__simultaneous.py   | integration/protocols/tcp/test__tcp__session__close__simultaneous.py                |
| integration/socket/test__socket__tcp__session__close__time_wait.py      | integration/protocols/tcp/test__tcp__session__close__time_wait.py                   |
| integration/socket/test__socket__tcp__session__data_transfer__*.py      | integration/protocols/tcp/test__tcp__session__data_transfer__*.py (× 6 files)       |
| integration/socket/test__socket__tcp__session__handshake__active.py     | integration/protocols/tcp/test__tcp__session__handshake__active.py                  |
| integration/socket/test__socket__tcp__session__handshake__passive.py    | integration/protocols/tcp/test__tcp__session__handshake__passive.py                 |
| integration/socket/test__socket__tcp__session__harness_smoke.py         | integration/protocols/tcp/test__tcp__session__harness_smoke.py                      |
| integration/socket/test__socket__tcp__session__ipv6.py                  | integration/protocols/tcp/test__tcp__session__ipv6.py                               |
| integration/socket/test__socket__tcp__session__listener__multi_child.py | integration/protocols/tcp/test__tcp__session__listener__multi_child.py              |
| integration/socket/test__socket__tcp__session__options.py               | integration/protocols/tcp/test__tcp__session__options.py                            |
| integration/socket/test__socket__tcp__session__robustness__*.py         | integration/protocols/tcp/test__tcp__session__robustness__*.py (× 2 files)          |
| integration/socket/test__socket__tcp__session__sack.py                  | integration/protocols/tcp/test__tcp__session__sack.py                               |
| integration/socket/test__socket__tcp__session__seq_wraparound.py        | integration/protocols/tcp/test__tcp__session__seq_wraparound.py                     |
| integration/socket/test__socket__tcp__session__wscale.py                | integration/protocols/tcp/test__tcp__session__wscale.py                             |

Total: 4 unit + 21 integration = **25 file renames**.

**Stays** (not session-related, not affected by the move):
- `unit/socket/test__socket__tcp__socket.py`
- `unit/socket/test__socket__socket_id.py`
- `unit/socket/test__socket__udp__*.py`
- `unit/socket/test__socket__raw__*.py`

**Update inside each renamed file:**
1. The relative-path note in the module docstring.
2. The class names if the test class refers to the old path
   (rare; most use `TestTcpSession__<aspect>`).
3. No import updates needed if phase 0 already pointed imports
   to `pytcp.protocols.tcp.tcp__session`.

**Rule update:** add a clause to
`.claude/rules/unit_tests.md` §3 capturing the new mapping:

| Source location              | Test filename pattern                       |
|------------------------------|---------------------------------------------|
| `pytcp/protocols/tcp/*.py`   | `test__tcp__<source>__<aspect>.py`          |

placed under `pytcp/tests/unit/protocols/tcp/` or
`pytcp/tests/integration/protocols/tcp/`. This is a small
amendment to the existing test-naming table.

1 commit in phase 5 — `git mv` + import-path edits + rule
amendment. Run `make test` afterwards: identical pass/fail
count, just a different shape.

### Phase 6 — Update memory + cross-references

1. Update `MEMORY.md` to add a pointer to this document.
2. Mark `tcp_session_integration_tests.md` §3.2 (test directory
   layout) with a note that the integration tests now live under
   `pytcp/tests/integration/protocols/tcp/` after this refactor.
3. Update `CLAUDE.md` if it references the old path explicitly
   (grep first; current text uses generic patterns).

1 small commit in phase 6.

---

## 5. Importer update map (phase 0 — exhaustive list)

Confirmed importers of `pytcp.socket.tcp__session` from the
current codebase scan:

| File                                                                                                   | Symbols imported                                  |
|--------------------------------------------------------------------------------------------------------|---------------------------------------------------|
| `pytcp/socket/tcp__socket.py`                                                                          | `TcpSession`, `FsmState`, `TcpSessionError`       |
| `pytcp/lib/tcp_seq.py`                                                                                 | docstring reference only                          |
| `pytcp/tests/unit/socket/test__socket__tcp__socket.py`                                                 | `FsmState`, `TcpSessionError`                     |
| `pytcp/tests/unit/socket/test__socket__tcp__session__enums.py`                                         | enum surface                                      |
| `pytcp/tests/unit/socket/test__socket__tcp__session__lifecycle.py`                                     | `TcpSession`, enums                               |
| `pytcp/tests/unit/socket/test__socket__tcp__session__syscalls.py`                                      | `TcpSession`, enums                               |
| `pytcp/tests/unit/socket/test__socket__tcp__session__fsm.py`                                           | `TcpSession`, `FsmState`                          |
| `pytcp/tests/integration/socket/test__socket__tcp__session__*` (× 21 files)                            | `TcpSession`, `FsmState`, `SysCall`, `ConnError`  |
| `pytcp/tests/integration/socket/test__socket__tcp__session__harness_smoke.py:309`                      | runtime patch of `random` module reference        |
| `pytcp/tests/lib/tcp_session_testcase.py`                                                              | `TcpSession`                                      |

The `harness_smoke.py:309` site uses
`from pytcp.socket.tcp__session import random as tcp_session_random`
to patch `random.randint` for ISS injection — verify the patched
module name updates correctly to `pytcp.protocols.tcp.tcp__session`.

Total: ~30 import statements to rewrite (most files have 1
import each).

---

## 6. Open questions for phase 6 / future work

1. **Should `pytcp/protocols/` mirror `net_proto/protocols/`
   for udp and raw too?** No — UDP and Raw are stateless, their
   "session" fits inside `udp__socket.py` / `raw__socket.py`
   respectively. The `protocols/` directory only makes sense for
   protocols with a runtime layer below the BSD facade. TCP is
   currently the only such protocol.

2. **Should transmit / ack-processing / acceptability be
   peeled too?** Out of scope for this project. The free-
   function pattern is wrong for them (they call each other
   heavily and would force a giant TYPE_CHECKING shadow surface).
   If `tcp__session.py` post-split feels too large (~1750 LOC),
   revisit as a separate "TcpSession concern split" project
   later. The natural moment is when RFC 5681 cwnd rework lands
   and adds significant new state — at that point a `cwnd.py`
   peel plus a `transmit.py` peel may be warranted.

3. **Should `tests/integration/socket/` be deleted or kept?**
   After phase 5 it's empty for TCP-session tests but still
   contains nothing. **Decision: delete the empty directory in
   phase 6.** `socket/` integration tests for `udp__socket.py`
   and `raw__socket.py` don't currently exist; if added later
   they'd recreate the directory.

---

## 7. Test-pass invariant

After **every** commit in this project:
- `make lint` clean.
- `make test` reports the same pass/fail count as before phase 0
  (currently the SACK shipping baseline — see
  `tcp_sack_implementation.md` §5 for the canonical number).
- No new `[FLAGS BUG]` test failures introduced.

Any deviation = abort + revert. This is a pure refactor.

---

## 8. Estimated effort

| Phase | Description                          | Commits | Risk    |
|-------|--------------------------------------|---------|---------|
| 0     | Move file as-is                      | 1       | low     |
| 1     | Extract enums                        | 1       | low     |
| 2     | Extract tracing decorators           | 1       | low     |
| 3     | Extract 11 FSM handlers              | 11      | medium  |
| 4     | FSM dispatch table                   | 1       | low     |
| 5     | Test relocation + rename             | 1       | low     |
| 6     | Memory + rule cross-ref updates      | 1       | trivial |

Total: **17 commits**, ~3-4 hours of focused work in a fresh
context, mostly mechanical. Phase 3 is the only one requiring
care — the `self.` → `session.` substitution in 1300 lines of
control flow has to be exact.

---

## 9. Anti-patterns to avoid

- **Don't introduce TYPE_CHECKING shadow stubs.** The packet_handler
  mixin pattern uses them and they silently drift from real
  signatures. Free functions take a typed `session: TcpSession`
  parameter — mypy resolves attribute access once.

- **Don't add an `__init__.py` to `pytcp/protocols/tcp/`.** PEP
  420 namespace package, mirroring `net_proto/protocols/tcp/`.

- **Don't rename symbols during the move.** `_tcp_fsm_listen`
  becoming `fsm__listen` (free function) is a deliberate shape
  change. Everything else — `TcpSession`, `FsmState`,
  `_transmit_packet`, etc. — keeps its current name. Symbol
  renaming is a separate PR.

- **Don't fix bugs found during the move.** Record them, defer
  to a separate fix branch. This refactor must be reversible
  with a single revert.

- **Don't merge phases.** Each phase is a clean commit with a
  clear purpose. The 11 FSM-handler commits in phase 3 are
  intentional — they isolate any per-state breakage to a single
  commit boundary.

- **Don't drop the `tcp__` prefix on filenames inside
  `pytcp/protocols/tcp/`.** Self-identification is required by
  the project's filename rule (see `unit_tests.md` §3 and
  `coding_style.md` §23).

---

## 10. Re-orient command for new sessions

After loading this rule, run:

```bash
git log --oneline -20
ls pytcp/protocols/tcp/ 2>/dev/null
ls pytcp/socket/tcp__session.py 2>/dev/null
make test 2>&1 | tail -5
```

This tells you which phases have landed:
- `pytcp/socket/tcp__session.py` exists, `pytcp/protocols/tcp/`
  doesn't → phase 0 not started.
- `pytcp/protocols/tcp/tcp__session.py` exists, no `tcp__enums.py`
  → phase 1 not started.
- 11 `tcp__fsm__*.py` files present, no `tcp__fsm.py` → phase 4
  not started.
- Integration tests still under `pytcp/tests/integration/socket/`
  → phase 5 not started.

Match against §4 to pick up where the prior session left off.

---

## 11. Cross-references

- Coding style: `.claude/rules/coding_style.md` (filename
  conventions §22, no-mixin precedent for new code §28).
- Unit test authoring: `.claude/rules/unit_tests.md` (test
  file naming §3 — needs amendment in phase 6).
- TCP integration test plan:
  `.claude/rules/tcp_session_integration_tests.md` (§3.2 needs
  cross-ref update in phase 6).
- TCP SACK implementation record:
  `.claude/rules/tcp_sack_implementation.md` (current shipped
  baseline; the test count in §5 is the invariant for phase 7).
- Packet handler mixin precedent (the anti-pattern that
  motivated free-functions for FSM): `pytcp/stack/packet_handler/`
  — see the TYPE_CHECKING shadow stubs in `packet_handler__tcp__rx.py:48-84`.
