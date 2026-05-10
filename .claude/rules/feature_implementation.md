# PyTCP — Feature Implementation Rule

Canonical workflow for implementing new features, closing
spec-conformance gaps, and shipping behaviour changes in
PyTCP. Every non-trivial code change should follow it.

Companion rules — read these for the topical specifics this
rule references:

- [`unit_testing.md`](unit_testing.md) — unit test
  authoring (framework, file layout, mocking discipline,
  isolation, the §7.2 docstring audit).
- [`integration_testing.md`](integration_testing.md) —
  integration test authoring (harness hierarchy, drive_rx /
  probe / fluent-assert pattern, stat-counter assertions).
- [`python_features.md`](python_features.md) — Python
  3.10–3.14 language features PyTCP MUST use; forbidden
  pre-3.10 fallbacks.
- [`typing.md`](typing.md) — type-system discipline (PEP 604
  unions, PEP 585 generics, PEP 695 generic syntax,
  `Self` / `@override`, `Protocol` / `TypedDict`, `cast`
  policy, `# type: ignore` policy, forward references).
- [`source_files.md`](source_files.md) — general source-file
  mechanics (file skeleton, copyright block, module
  docstring, imports, naming, formatting, inline comments).
- [`protocol_architecture.md`](protocol_architecture.md) —
  `net_proto/` per-protocol six-file layout (`*Header` /
  `*HeaderProperties` / `*Base` / `*Parser` / `*Assembler` /
  `*Errors`), options, enums, validation helpers, error
  templates, buffer/struct conventions.
- [`stack_runtime.md`](stack_runtime.md) — `pytcp/` runtime
  services (`Subsystem`, packet-handler mixins, BSD socket
  facade, sysctl registry, stack configuration).

---

## 1. Spec grounding

PyTCP targets strict RFC conformance. Before writing any
code:

1. **Identify the governing RFC clause.** State it in the
   commit message and in test docstrings as
   `Reference: RFC <number> §<section> (<short description>).`
2. **Read the RFC text directly.** Never paraphrase from
   training data — section numbers and normative wording
   drift between revisions. The text lives at
   `docs/rfc/tcp/rfcXXXX__*/rfcXXXX.txt` for TCP RFCs;
   download fresh if the folder is missing.
3. **Check the per-RFC adherence audit.** If
   `docs/rfc/tcp/rfcXXXX__*/adherence.md` exists, read it
   for the gap inventory. If a gap is being closed, the
   audit should be updated in the same commit.
4. **Use the [`rfc_adherence_audit`](../skills/rfc_adherence_audit/SKILL.md)
   skill** to add or refresh the audit when the work
   substantially changes adherence status.

When the RFC and the existing implementation disagree,
the RFC wins. Document any deliberate deviation in a
comment with the rationale, not the rule violation.

**Linux is the tiebreaker for ambiguity.** When the RFC
is silent, offers SHOULD/MAY choices, or has multiple
defensible interpretations, follow what default Linux
does. Cite the Linux file / sysctl in the commit body
(e.g. `net/ipv6/exthdrs.c::ipv6_destopt_rcv` or
`net.ipv4.tcp_mtu_probing`). PyTCP's project-level
north star is Linux stack parity — see `CLAUDE.md`
"Project North Star".

**Phase-2 awareness.** PyTCP is a host stack today, a
router-grade stack tomorrow. Design decisions that
would foreclose Phase 2 (router/forwarding parity)
must be flagged: parser code that drops fields a
forwarder would need to preserve, dispatch code that
conflates "deliver" with "process", or per-destination
state crammed into single-gateway shortcuts. Mark
Phase-1 simplifications with `# Phase 2: ...` so the
upgrade path is greppable.

## 2. Tests-first (MUST)

**A code change without a preceding failing test is a
violation of this rule, regardless of how trivial the
change appears.** The test exists to *expose* the
missing feature, bug, or spec gap that the code is
meant to address; if it cannot be made to fail before
the fix, it is not pinning anything. Reviewers and
the §7.2 audit treat the absent-test case as a
blocker, not a polish item.

This applies to: new features, RFC-conformance work,
bug fixes, refactors that change observable
behaviour, and any code path that did not previously
exist. It does **not** apply to pure-internal
renames, formatting passes, or doc-only edits.

Every behavioural change opens with one or more failing
tests that pin the spec requirement:

1. Write the test against the spec, not the current code.
   The test's purpose is to fail until the implementation
   matches the RFC.
2. Run the test. **Verify it fails for the predicted
   reason** — wrong-failure-mode tests don't lock anything
   in. If it unexpectedly passes, the gap was already
   closed (rare; double-check before claiming "done").
3. Test docstrings follow `unit_testing.md` §7: opening
   `Ensure …`, blank line, trailing
   `Reference: RFC X §Y (desc).` line per cited clause.
4. Run the §7.2 audit script before staging.

### 2.1 Both layers, where applicable

PyTCP has two distinct test layers; new features need
coverage at **every layer that applies**, not just one:

| Layer       | Path                                                     | Harness                                                                | What it covers                                                                                |
|-------------|----------------------------------------------------------|------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| Unit        | `<pkg>/tests/unit/...`                                   | `unittest.TestCase`                                                    | Pure-function helpers, dataclass invariants, parser / assembler wire format, header asserts   |
| Integration | `pytcp/tests/integration/...`                            | `NetworkTestCase` / `IcmpTestCase` / `NdTestCase` / `ArpTestCase` / `TcpSessionTestCase` (see [`integration_testing.md`](integration_testing.md) §4) | FSM transitions, wire-level RX→TX interactions, timer-driven behaviour, socket-API plumbing  |

Heuristic for which layer(s) apply:

- **Pure helper / formula / dataclass.** Unit tests
  alone cover it (e.g. `tcp__cwnd.py` formulas, RFC 6298
  RTO update math, modular sequence arithmetic).
- **Wire-format change** (new option, header field
  meaning).  Unit tests on the parser/assembler **plus**
  integration tests verifying the option appears on the
  right outbound segments and is consumed correctly on
  inbound.
- **FSM transition / session-state change** (new
  syscall path, RFC clause that gates state changes).
  Integration tests are mandatory; unit tests only if
  the change peels into a pure helper.
- **Cross-RFC interaction** (RFC X behaviour gates on
  RFC Y state). Integration tests at the interaction
  point.
- **Socket-API plumbing** (`setsockopt`, BSD facade).
  Unit tests on the `TcpSocket` plumbing **plus**
  integration tests verifying propagation into
  `TcpSession`.

For TCP work specifically, the bias is toward
integration tests — protocol behaviour is
fundamentally about wire-level interactions and FSM
state, and unit-only coverage of session-touching
features routinely misses real bugs. When in doubt,
write the integration test; add a unit test on top
if a helper extraction emerges.

A feature commit that ships only unit tests for a
protocol-level behaviour is incomplete. Reviewers
should ask "what's the integration test?" — if the
answer is "n/a, this is pure helper math", that's a
valid answer; if the answer is "I forgot", land the
integration test before claiming done.

### 2.2 Test paths

| Source location                                | Test path                                                                                                              |
|------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|
| `net_proto/protocols/<proto>/*.py`             | `net_proto/tests/unit/protocols/<proto>/test__<proto>__<aspect>.py`                                                    |
| `net_proto/lib/*.py`                           | `net_proto/tests/unit/lib/test__lib__<source>.py`                                                                      |
| `net_addr/*.py`                                | `net_addr/tests/unit/test__<source>.py`                                                                                |
| `pytcp/lib/*.py`                               | `pytcp/tests/unit/lib/test__lib__<source>.py`                                                                          |
| `pytcp/socket/*.py`                            | `pytcp/tests/unit/socket/test__socket__<source>.py` (unit) and integration via `TcpSessionTestCase` under `protocols/tcp/...` |
| `pytcp/protocols/tcp/*.py`                     | `pytcp/tests/unit/protocols/tcp/...` (unit) **and** `pytcp/tests/integration/protocols/tcp/test__tcp__session__<scenario>.py` (integration) |
| `pytcp/protocols/icmp6/nd/*.py`                | `pytcp/tests/unit/protocols/icmp6/nd/...` (unit) **and** `pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__<mechanism>.py` (integration) |
| `pytcp/stack/packet_handler/packet_handler__<proto>__<rx\|tx>.py` | `pytcp/tests/integration/test__packet_handler__<proto>__<rx\|tx>.py` (per-handler smoke)              |
| Cross-cutting RFC mechanism                    | `pytcp/tests/integration/protocols/<proto>/test__<proto>__<rfc-mechanism>.py`                                          |

The full per-aspect splits for `net_proto` per-protocol
files (header / parser / assembler / options) live in
[`unit_testing.md`](unit_testing.md) §3. The full
integration-test path matrix lives in
[`integration_testing.md`](integration_testing.md) §3.

Test docstring conventions (`Ensure …` opener, trailing
`Reference:` line, no inline RFC citations, no
`[FLAGS BUG]` markers) apply at **both** layers identically.
The §7.2 audit script runs against any test file you write
or modify, regardless of layer.

## 3. Implementation

Once the failing tests are in place:

1. **Make the smallest change that flips them green.** No
   surrounding cleanup, no incidental refactors, no
   speculative abstractions. A bug fix doesn't need a
   helper extraction.
2. **Trust framework guarantees and internal callers.**
   Validate at system boundaries (parser, socket API),
   not deep inside the call graph.
3. **Cite the RFC clause with an inline comment** at the
   hook point if the *why* is non-obvious. Don't narrate
   *what* the code does — names and types do that.
4. **Follow the modern-Python / typing rules.** New code
   uses the forms documented in
   [`python_features.md`](python_features.md) (PEP 604
   unions, PEP 585 lowercase generics, PEP 695 generic
   syntax, `match`/`case`, `int.bit_count()`, etc.) and
   [`typing.md`](typing.md) (mypy strict, `Self`,
   `@override`, `Protocol`, `TypedDict`, `cast` policy,
   `# type: ignore` policy). On-touch in legacy code: fix
   the obsolete forms (`Optional`, `Union`, `TypeVar`,
   `Generic`, `from __future__ import annotations` + the
   `TYPE_CHECKING` trio) in the same commit.
5. **Match PyTCP source-file conventions** for any new
   file — file skeleton, copyright block, module docstring,
   imports, naming, formatting per
   [`source_files.md`](source_files.md); the per-protocol
   six-file layout + dataclass shape per
   [`protocol_architecture.md`](protocol_architecture.md);
   the `Subsystem` / packet-handler / socket / sysctl
   patterns per [`stack_runtime.md`](stack_runtime.md).
6. Verify the originally-failing tests now pass and the
   full suite still passes (`make validate`).

When a feature is large enough to warrant phasing, each
phase is one tests-first commit + one fix commit (or a
single combined commit if naturally atomic). Phases are
mechanically reversible.

## 4. Commit discipline

| Rule | Why |
|------|-----|
| One concern per commit | Reverts and bisects stay clean |
| Tests + impl together when atomic | Reader sees the spec mapping in one place |
| Cite the RFC clause in commit body | Future archaeology has the link |
| `make lint` + `make test` clean before commit | No broken intermediate states |
| §7.2 docstring audit clean before commit | Test docstrings stay greppable |
| Modernise legacy forms on touch (not in a separate sweep commit) | The fix lands with the feature that touched the file |
| Never `--no-verify`, never `--no-gpg-sign`, never amend published commits | Hooks and signatures are load-bearing |
| User-explicit only for `git push` | Never push without a clear ask |

Commit message body should say what flipped green and
which RFC clause it pins. The "<N> passing, <M> skipped"
counts line is a convention worth keeping.

**Modernisation-on-touch.** When you edit a file that
contains an obsolete typing form (`Optional`, `Union`,
`List`, `Dict`, `TypeVar`, `Generic`,
`from __future__ import annotations` + `TYPE_CHECKING`
trio in a file without a real circular import, etc.), fix
it in the same commit. Do not file a follow-up "modernise
typing in X" task — the next person to touch the file is
you, the fix is mechanical, and a separate sweep commit
loses the lockstep with the feature work. See
[`python_features.md`](python_features.md) §22 and
[`typing.md`](typing.md) §23 for the full forbidden-form
catalogue.

## 5. Scope discipline

The scope rules from `CLAUDE.md` apply with extra
emphasis here:

- **Don't expand the task mid-flight.** If you discover
  an adjacent gap, capture it (note in the commit body
  or open a new task) but ship the original change as-is.
- **Don't add features beyond what the test pins.** If
  the test only covers one codepoint, the implementation
  shouldn't silently handle four — that's untested
  behaviour walking into the codebase.
- **Don't backwards-compat-shim.** Internal callers can
  be updated in the same commit; there's no installed
  base.

## 6. Anti-patterns

- **Implementing before testing.** A test written after
  the fact is a regression guard, not a spec-compliance
  pin. The order matters.
- **Tests that pin the deviation.** A test that asserts
  the current (wrong) value codifies the bug. Update the
  test to match the spec; the failure surfaces the work.
- **Bypassing safety checks.** No `--no-verify` to skip
  hooks, no bare `# type: ignore` (see
  [`typing.md`](typing.md) §21 for the narrow forms that
  are acceptable), no `try: …; except: pass` to make a
  failing path quiet. Fix the root cause.
- **Citing the RFC inline AND in `Reference:`.** The
  trailing `Reference:` line is canonical; duplicating in
  the description is forbidden by
  [`unit_testing.md`](unit_testing.md) §7 and
  [`integration_testing.md`](integration_testing.md) §9.
- **Skipping the integration test for a protocol-level
  behaviour.** A wire-format change / FSM transition /
  socket-API change MUST land with an integration test —
  see §2.1. Unit-only coverage of session-touching code
  routinely misses real bugs.
- **Adding module-level state to `pytcp/stack/__init__.py`
  without updating the test harness in the same commit.**
  Snapshots and restores live in
  `NetworkTestCase` / `IcmpTestCase` setUp/tearDown — see
  [`integration_testing.md`](integration_testing.md) §5.4.
  Without the harness update, the test passes alone and
  fails in suite (or vice versa).
- **Bare `MagicMock()` in tests.** Always
  `create_autospec(Cls, spec_set=True)` or
  `patch(..., autospec=True, spec_set=True)` — see
  [`unit_testing.md`](unit_testing.md) §6a.
- **Reusing rule-file or prior-record content for an
  audit or test.** Re-derive from code and the RFC.
  Prior records can sanity-check after the fact.

## 7. Reporting

After each phase lands, give the user a `●`-led summary:

```
● Lint clean, <N> passing, <M> skipped.

Phase <N> — <one-line summary>.

Reference: RFC X §Y (clause).

<one paragraph: what changed, what flipped green>.
```

Be specific about the RFC clause. Don't summarise what
the diff says — say what the test now pins that wasn't
pinned before.

## 8. Cross-references

- Unit-test authoring:
  [`unit_testing.md`](unit_testing.md) — framework, file
  layout, parameterization pattern, byte-frame
  annotations, mocking discipline (§6a), test isolation
  (§10a), modern Python features in tests (§10b), the §7.2
  docstring audit.
- Integration-test authoring:
  [`integration_testing.md`](integration_testing.md) —
  harness hierarchy (`NetworkTestCase`/`IcmpTestCase`/
  `NdTestCase`/`ArpTestCase`/`TcpSessionTestCase`),
  drive_rx / advance / probe / fluent-assert pattern,
  stat-counter assertions, frame builders.
- Python language-feature inventory:
  [`python_features.md`](python_features.md) — modern
  Python 3.10–3.14 features PyTCP MUST use; pre-3.10
  fallbacks that are forbidden.
- Typing discipline: [`typing.md`](typing.md) — mypy
  strict, annotation discipline, PEP 604 / 585 / 695
  generic syntax, `Self`, `@override`, `Protocol`,
  `TypedDict`, `cast` policy, `# type: ignore` policy,
  forward references / PEP 649 lazy annotations.
- General source-file authoring:
  [`source_files.md`](source_files.md) — file skeleton,
  copyright block, module docstring, imports, naming,
  formatting, inline comments, source docstrings.
- Protocol authoring (under `net_proto/protocols/`):
  [`protocol_architecture.md`](protocol_architecture.md) —
  the per-protocol six-file layout, dataclass shape,
  parser three-phase pipeline, assembler kw-only ctor,
  error / options / enums patterns, validation helpers,
  error message templates, buffer / struct conventions.
- Stack-runtime authoring (under `pytcp/`):
  [`stack_runtime.md`](stack_runtime.md) — `Subsystem`
  base, packet-handler mixin composition, BSD socket
  facade, sysctl registry, stack configuration.
- Per-RFC adherence audits:
  `docs/rfc/<family>/rfcXXXX__*/adherence.md` (TCP, IP6,
  ICMP6, ICMP4, ARP families). The
  [`rfc_adherence_audit`](../skills/rfc_adherence_audit/SKILL.md)
  skill adds or refreshes an entry.
- Sysctl knob workflow:
  [`sysctl_knob`](../skills/sysctl_knob/SKILL.md) skill.
