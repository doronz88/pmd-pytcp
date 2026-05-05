---
name: rfc_adherence_audit
description: Author and maintain per-RFC adherence records under docs/rfc/<group>/rfc_XXXX__<name>/ — paragraph-by-paragraph audit of how PyTCP code complies with each normative statement, including a parallel test-coverage audit. Invoke when creating a new RFC adherence record, refreshing an existing one after code changes, or filling in the catalog for an RFC that has no record yet.
---

# RFC Adherence Audit Skill

This skill captures the methodology for producing a single
RFC adherence record under
`docs/rfc/<group>/rfc_XXXX__<name>/adherence.md`. The
output is a self-contained document that (a) walks every
normative paragraph of the RFC and (b) audits the
unit/integration test surface that locks each met
requirement in.

## When to invoke

- A user asks for an "adherence record" / "compliance
  audit" / "RFC walkthrough" for any RFC.
- An RFC text already lives under `docs/rfc/<group>/`
  but has no adherence record alongside it.
- An adherence record exists but needs refreshing after
  a code change touched the relevant area.
- The catalog audit needs to be extended to a previously
  unaudited RFC (see the inventory in `MEMORY.md`'s
  index).

## When NOT to invoke

- For project workflow / coding-style rules — those go
  in `.claude/rules/` not `docs/rfc/`.
- For SHIPPED *plans* (CUBIC, RACK-TLP, SACK records) —
  those are migration targets, not new audits. Use this
  skill only when starting from scratch with no prior
  rule-file content.
- For RFCs PyTCP doesn't implement and never will (e.g.
  TCP-AO, MPTCP) — there's no audit surface.

## Output layout

```
docs/rfc/<group>/rfc_XXXX__<short_name>/
  rfcXXXX.txt          # source RFC (copy from docs/rfc/<group>/rfcXXXX.txt)
  adherence.md         # the audit record
```

Folder naming convention:
`rfc<number>__<snake_case_topic_name>` — `rfc` runs
straight into the number with no separator (tight
binding), double underscore as separator, snake_case
topic name on the right. Examples:

- `rfc6691__tcp_options_and_mss`
- `rfc9438__cubic`
- `rfc8985__rack_tlp`
- `rfc2018__sack`

Group is the protocol family directory under `docs/rfc/`
(`tcp`, `udp`, `ip`, etc.).

## adherence.md structure (canonical template)

Every adherence record has these sections in this order.
Sections without normative content are simply omitted —
do NOT pad with "narrative — no implementation surface"
boilerplate.

```markdown
# RFC <number> — <Title>

| Field       | Value                                |
|-------------|--------------------------------------|
| RFC number  | <number>                             |
| Title       | <Title>                              |
| Category    | <Standards Track / Informational / ...> |
| Date        | <Month YYYY>                         |
| Updates     | <list> | (or remove row if none)    |
| Source text | [`rfcXXXX.txt`](rfcXXXX.txt)         |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC <number>. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `pytcp/` and `net_proto/` directly; no prior
memory or rule-file content was reused. Adherence
levels are described in plain language. Sections that
contain no normative content (Introduction, Terminology,
References, historical commentary, Security
Considerations boilerplate) are omitted.

---

## §<N>. <Section Title>

> "<verbatim quote of the normative paragraph>"

**Adherence:** <descriptive prose: met / not met /
partial / not implemented / vacuous>. <Concrete file:line
references that justify the call.>

---

[... one §-section per normative paragraph ...]

---

## Test coverage audit

[For each requirement claimed as met or partial:]

### §<N> <short label>

- **Unit / integration:**
  `<full path>::<TestClass>::<test_method>`
  <one-sentence summary of what it asserts>

**Status:** <locked in / locked in indirectly / n/a (not
implemented) / n/a (gap not closed; add test with fix)>.

[For unmet requirements that might be fixed later, sketch
the natural test that should accompany the fix.]

### Test coverage summary

| Aspect             | Coverage |
|--------------------|----------|
| <per-requirement>  | ...      |

---

## Overall assessment

| Aspect             | Status |
|--------------------|--------|
| <per-requirement>  | ...    |

<Closing paragraph: principal compliance gap, if any,
with a concrete fix sketch (file:line + a few lines of
diff hint). Or "all normative requirements met" when
appropriate.>
```

## Methodology — six rules

### 1. Read the RFC fresh

Open `docs/rfc/<group>/rfcXXXX.txt` in full. Do not rely
on memorized RFC content — paraphrasing from training
data introduces subtle errors (wrong section numbers,
slightly off normative wording, deprecated text).

### 2. Do not reuse rule files or memories

If `.claude/rules/tcp_<rfc-topic>.md` exists for this
RFC, do NOT read it before drafting the adherence
record. Likewise for any per-RFC memory files. The
audit must be a code-and-RFC-only exercise so it
captures the current state of the codebase, not a
historical record of what was once shipped.

After the draft is complete, the rule file can be
cross-referenced as a sanity check — but findings come
from the audit, not from the rule.

### 3. List only normative paragraphs

A "normative paragraph" is one containing MUST / MUST
NOT / SHOULD / SHOULD NOT / MAY language, OR a concrete
algorithmic statement, OR a wire-format definition.

Skip:

- Introduction / abstract
- Terminology / RFC 2119 boilerplate
- References sections
- Security Considerations boilerplate ("does not
  introduce any new security concerns")
- Historical commentary (RFC X said Y, this corrects it
  to Z) — restate as a §-pointer to the corrected
  requirement instead of duplicating
- Author addresses / IANA registration paragraphs

The disclaimer in the preamble must explicitly note
which sections were skipped so a reader does not wonder
if they were missed.

### 4. Code audit by inspection, not memory

For each normative paragraph, find the corresponding
code path by `grep` / `Read` and cite the file:line.
Verify by reading the surrounding context — do not
trust function names alone. Common pitfalls:

- A constant exists but is never read in the relevant
  path.
- A check is present but is gated on a flag that is
  never set.
- A "wire-overflow guard" looks like deliberate spec
  signaling but is just a uint16 cap.
- A field is initialized but the FSM transition that
  would consume it is unreachable.

When in doubt, search for *all* assignments and reads of
the relevant symbol before claiming adherence.

### 5. Descriptive language, not scores

Do not invent a 0-5 / A-F scale. Use plain English with
consistent shorthand:

- **met** — code does exactly what the RFC requires.
- **not met** — RFC requires X, code does Y or nothing.
- **partial** — some sub-requirements met, others not;
  always explain which.
- **not implemented** — feature is wholly absent (PMTUD,
  jumbograms, MPTCP-style features).
- **vacuous (single MTU)** / similar — requirement
  applies only to a configuration PyTCP doesn't model;
  trivially satisfied.
- **inherits §X** — cross-references another section's
  status (used for sub-paragraphs that restate a parent
  requirement; avoid for new normative content).

### 6. Verify claims by re-reading

After the draft is complete, re-grep every file:line
reference and re-read the surrounding code. Catches
that come up routinely:

- "DF is set" claim with no `flag_df=` assignment
  anywhere in TX path.
- "Sentinel emitted" claim that is actually a wire-
  field overflow guard.
- "Tested" claim where the test exists but exercises a
  different branch.

Document the corrections in the same edit pass — do not
ship the draft without re-verification.

## Test coverage audit — required

Every adherence record MUST include a "Test coverage
audit" section after the per-section implementation
audit and before the overall assessment.

For each requirement claimed as **met** or **partial**:

1. Find the unit / integration tests that exercise the
   behaviour. Search both
   `pytcp/tests/{unit,integration}/` and
   `net_proto/tests/unit/` (wire-level option tests
   live in net_proto).
2. List each test with its full
   `path::TestClass::test_method` path.
3. Summarize what the test asserts in one sentence.
4. Mark coverage status: **locked in** (dedicated test),
   **locked in indirectly** (no dedicated test but a
   broader test would catch a regression),
   **n/a (not implemented)**, or
   **n/a (gap not closed; add test with fix)**.

For unmet requirements that might be fixed later,
sketch the test that should accompany the fix:

```markdown
**No test surface — gap not yet closed.** When the gap
is fixed, the natural test is one that:

1. <setup that triggers the path>
2. <assertion that pins the corrected behaviour>
```

End the section with a "Test coverage summary" table
mirroring the implementation overall-assessment table:

```markdown
### Test coverage summary

| Aspect             | Coverage |
|--------------------|----------|
| <per-requirement>  | ...      |
```

## Format conventions

### Markdown tables MUST be column-aligned

Pad every cell to the column's max content width so the
source reads as a clean grid. The renderer doesn't care
but the user reads raw markdown frequently. See the
`feedback_table_alignment` memory entry for the
algorithm.

```markdown
# GOOD
| Field       | Value                                      |
|-------------|--------------------------------------------|
| RFC number  | 6691                                       |
| Title       | TCP Options and Maximum Segment Size (MSS) |

# BAD (renders identically but ugly source)
| Field | Value |
|---|---|
| RFC number | 6691 |
| Title | TCP Options and Maximum Segment Size (MSS) |
```

### File:line references

Use the inline-code form: `pytcp/protocols/tcp/tcp__session.py:144-147`.
For multi-site references, list each separately rather
than collapsing into a range.

### Verbatim quotes

Use markdown blockquote (`> ...`) for verbatim RFC text.
Wrap to ~60 chars per line for readability. Do not
paraphrase normative text — paraphrase invites subtle
distortion.

### File / class / method names

Inline-code (backticks). Test method names use the full
`path::TestClass::test_method` form so they are
greppable.

## Self-verification checklist

Before declaring the audit done, run through:

- [ ] Every normative paragraph of the RFC has a
      corresponding §-section in adherence.md.
- [ ] Every met/partial requirement has at least one
      test reference, OR is explicitly marked "locked
      in indirectly" with the broader test that would
      catch a regression.
- [ ] Every unmet/not-implemented requirement is
      explicit (no silent omissions).
- [ ] Every file:line reference resolves and points at
      the code described.
- [ ] All markdown tables are column-aligned.
- [ ] No `[FLAGS BUG]` markers (those are tests-first
      indicators, not adherence content).
- [ ] No "narrative — no implementation surface"
      filler — narrative paragraphs are omitted, the
      preamble notes this.
- [ ] The disclaimer in the preamble lists what was
      skipped (Introduction, Terminology, References,
      Security boilerplate).
- [ ] Overall-assessment table covers every section the
      audit kept (no requirement falls off).

## Pitfalls to avoid

- **Reusing rule-file content.** The audit must be a
  fresh code+RFC exercise. If you find yourself
  repeating phrases from `.claude/rules/tcp_<rfc>.md`,
  stop and re-derive from the code.
- **Padding with narrative entries.** Sections without
  normative content are skipped, not stub-listed.
- **Inferring adherence from a function name.** Always
  Read the implementation to confirm.
- **Trusting "the test mentions RFC 6691".** A test
  that cites the RFC in a docstring is not the same as
  a test that pins the requirement. Read the assertion
  body.
- **Collapsing two requirements into one row.** RFC §2
  often contains 3+ distinct normative statements;
  give each its own audit block.
- **Skipping the test coverage audit.** It is
  mandatory, not optional.
- **Misaligned tables.** Re-pad after every edit that
  changes a cell's content length.

## Pre-existing skill resources

If the RFC has an existing `.claude/rules/<topic>.md`
record, treat it as out-of-scope until after the draft
is complete. Then cross-reference for sanity:

- Does the rule's "shipped commits" list match the
  audit's findings?
- Are deferred items in the rule consistent with
  "not implemented" or "partial" calls in the audit?
- If they conflict, the AUDIT is authoritative —
  rule files become stale faster than code.

## Cross-references

- `feedback_table_alignment.md` — markdown table
  alignment algorithm.
- `feedback_rfc_adherence_includes_test_audit.md` —
  test-coverage audit requirement.
- `docs/rfc/tcp/rfc6691__tcp_options_and_mss/adherence.md` —
  the canonical reference example produced under this
  skill.
