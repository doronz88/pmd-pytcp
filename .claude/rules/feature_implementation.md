# PyTCP — Feature Implementation Rule

Canonical workflow for implementing new features, closing
spec-conformance gaps, and shipping behaviour changes in
PyTCP. Every non-trivial code change should follow it.

For test-file specifics see
[`unit_tests.md`](unit_tests.md). For source-file
authoring conventions see
[`coding_style.md`](coding_style.md).

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

## 2. Tests-first

Every behavioural change opens with one or more failing
tests that pin the spec requirement:

1. Write the test against the spec, not the current code.
   The test's purpose is to fail until the implementation
   matches the RFC.
2. Run the test. **Verify it fails for the predicted
   reason** — wrong-failure-mode tests don't lock anything
   in. If it unexpectedly passes, the gap was already
   closed (rare; double-check before claiming "done").
3. Test docstrings follow `unit_tests.md` §7: opening
   `Ensure …`, blank line, trailing
   `Reference: RFC X §Y (desc).` line per cited clause.
4. Run the §7.2 audit script before staging.

Tests live under:

| Source location              | Test path                                                        |
|------------------------------|------------------------------------------------------------------|
| `net_proto/protocols/<p>/`   | `net_proto/tests/unit/protocols/<p>/`                            |
| `pytcp/protocols/tcp/*.py`   | `pytcp/tests/unit/protocols/tcp/` (unit) and `…/integration/…/` |
| `pytcp/socket/*.py`          | `pytcp/tests/unit/socket/`                                       |

Unit tests cover pure-function logic and per-helper
edges; integration tests drive the FSM end-to-end via
the `TcpSessionTestCase` harness. Both kinds usually
exist for non-trivial features.

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
4. Verify the originally-failing tests now pass and the
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
| Never `--no-verify`, never `--no-gpg-sign`, never amend published commits | Hooks and signatures are load-bearing |
| User-explicit only for `git push` | Never push without a clear ask |

Commit message body should say what flipped green and
which RFC clause it pins. The §7.2 audit line ("X tests
passing, Y skipped") is a convention worth keeping.

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
  hooks, no `# type: ignore` without a one-line WHY, no
  `try: …; except: pass` to make a failing path quiet.
  Fix the root cause.
- **Citing the RFC inline AND in `Reference:`.** The
  trailing `Reference:` line is canonical;
  duplicating in the description is forbidden by
  `unit_tests.md` §7.
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

- Test authoring: [`unit_tests.md`](unit_tests.md)
- Source authoring: [`coding_style.md`](coding_style.md)
- Per-RFC adherence: `docs/rfc/tcp/rfcXXXX__*/adherence.md`
- Audit skill:
  [`rfc_adherence_audit`](../skills/rfc_adherence_audit/SKILL.md)
