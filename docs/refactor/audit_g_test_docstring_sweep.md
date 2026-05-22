# Audit G — Test docstring §7.2 wholesale sweep

**Status:** planning doc (2026-05-21). Drafted during the
audit-G survey when the scale (1989 violations across 195
files) made it clear the work was too big for a single
session.

This doc captures the full survey output, the scope
tradeoffs, the per-package sub-audit breakdown, and the
restart prompts so the work can be picked up
sub-audit-at-a-time across separate sessions.

---

## Background

The §7.2 docstring audit (codified in
`.claude/rules/unit_testing.md` §7.2) checks four invariants
on every `test__*` method docstring:

1. **`Reference:` line present** — every test method has a
   trailing `Reference: RFC <n> §<s> (<desc>).` line, or one
   of two acceptable fallback citations.
2. **`Ensure ` opener** — description starts with `Ensure `.
3. **No `[FLAGS BUG]` markers** — that tests-first transient
   marker must be stripped before commit.
4. **No inline RFC citations in the description** — the
   trailing `Reference:` line is canonical; duplicating it
   inline as `Per RFC X §Y`, `RFC X §Y`, or `RFC X figure N`
   is forbidden.

Past audits (A, B, C, F) have left §7.2 debt behind by
virtue of focused scoping — audit A explicitly deferred the
pre-existing §7.2 debt in the touched header-asserts files
to this audit. Audit G is where that debt finally clears.

---

## Survey results (2026-05-21)

Ran the §7.2 audit script against the full test corpus
(`packages/**/test__*.py`).

| Package | Total files | Files with violations | Violations |
|---------|------------:|----------------------:|-----------:|
| `net_addr` | 16 | **0** | **0** |
| `net_proto` | 228 | 144 | 1606 |
| `pytcp` | 250 | 51 | 383 |
| **Total** | 494 | 195 | 1989 |

**net_addr is already clean** — the recent net_addr test
work (the value-type test rewrites, the abstract-stubs
test, etc.) all applied §7.2 discipline from the start.

**Violation types across all packages:**

| Type | Count | % |
|------|------:|--:|
| missing `Reference:` line | 1938 | 97.4 % |
| inline `RFC X §Y` in description | 31 | 1.6 % |
| missing `Ensure ` opener | 11 | 0.6 % |
| inline `Per RFC X` in description | 11 | 0.6 % |
| `[FLAGS BUG]` markers | 7 | 0.4 % |

The dominant drift is missing `Reference:` lines (97 % of
all violations). The other four categories together total
60 violations and are tractable manually.

**Footnote on the audit-script undercount.** The canonical
§7.2 audit script in `unit_testing.md` matches signatures
of the form `def test__foo(self) -> None:` on a single line.
Test methods written with the multi-line form

```python
def test__foo(
    self,
) -> None:
```

slip past the regex and are not counted by the survey. The
G-net_proto-lib sweep (commit `b6853c01`) found 50 such
methods in the lib batch alone (~30% over the survey's
162 count). Per-family sweeps should use a tolerant
pattern — `def (test__\w+)\([^)]*\)\s*->\s*None:` — to
catch both forms in the same pass. A future cleanup can
tighten the canonical §7.2 audit script in the rule file
to use the tolerant pattern, but the change is non-
load-bearing: once every per-family sweep is complete the
two patterns produce the same (zero) violation count.

**Top 30 files by violation count (preview):**

```
67  pytcp/pytcp/tests/unit/socket/test__socket__tcp__socket.py
46  net_proto/net_proto/tests/unit/protocols/ip4/test__ip4__assembler__operation.py
35  pytcp/pytcp/tests/unit/socket/test__socket__base.py
34  net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__header__asserts.py
32  net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__operation.py
32  pytcp/pytcp/tests/unit/socket/test__socket__udp__socket.py
31  net_proto/net_proto/tests/unit/lib/test__lib__proto_option.py
28  net_proto/net_proto/tests/unit/protocols/tcp/test__tcp__assembler__operation.py
27  net_proto/net_proto/tests/unit/protocols/icmp6/test__icmp6__nd__option__pi.py
27  net_proto/net_proto/tests/unit/protocols/tcp/test__tcp__header__asserts.py
... (165 more files)
```

---

## Strategy

The 1938 missing-Reference violations are too many to
author manually per-method in one session. The §7.2 rule
allows two fallback citations:

- `Reference: PyTCP test infrastructure (no RFC clause).`
- `Reference: RFC 9293 §3.9 (User/TCP interface).` (for
  socket-API plumbing)

But blanket-applying the infrastructure fallback to all
1938 tests defeats the rule's archaeology purpose (the
trailing `Reference:` line is supposed to let `grep -r 'RFC
X §Y' packages/*/tests/` return every test pinning that
clause).

**The realistic compromise is per-file judgement**: read
each file's class docstring + 2-3 sample test docstrings to
decide the canonical reference for that file, then apply
that reference to every test method missing one in that
file. Files that mix concerns get per-method treatment;
files that test a single subject get bulk-applied
references.

This still produces "coarse-but-fitting" references rather
than fully-accurate per-method clauses, but it captures the
file-level archaeology signal which is enough for grep-based
spec mapping.

---

## Per-package sub-audit breakdown

### Sub-audit G-net_addr

**Scope:** `packages/net_addr/net_addr/tests/` (16 files).

**Status:** **verified clean 2026-05-21.** Re-ran the §7.2
audit script against
`packages/net_addr/net_addr/tests/`: 16 files, 464 test
methods scanned, **0 violations**. No code changes.

**Action:** verification-only. Re-run the §7.2 audit script
against the package, confirm clean, record the verification
in this doc (or a commit message). No code changes expected.

**Estimated effort:** 5 minutes.

### Sub-audit G-net_proto

**Scope:** `packages/net_proto/net_proto/tests/` (228 files,
144 with violations).

**Suggested family breakdown** (each as a separate commit):

| Sub-batch | Files (approx) | Violations (approx) | Notes |
|-----------|---------------:|--------------------:|-------|
| G-net_proto-lib | 13 | 212 (b6853c01) | `tests/unit/lib/*.py` — `PyTCP test infrastructure (no RFC clause).` fallback (12 files); `RFC 1071 (Internet checksum algorithm).` for `test__lib__inet_cksum.py`. **completed 2026-05-21**. |
| G-net_proto-arp | 5 | 51 (3d347b74) | `RFC 826` per-file (wire format / header fields / Packet Reception); integrity_checks and sanity_checks were already clean. **completed 2026-05-21**. |
| G-net_proto-dhcp4 | ~25 | ~400 | mostly `RFC 2131 §2 (DHCPv4 header) / §3.1 (message flow)` + `RFC 2132 §<N>` for per-option files |
| G-net_proto-ethernet | 5 | 49 (894b1b5f) | `RFC 894` (Ethernet II framing) per-file; integrity/sanity keep specific `IEEE 802.3 / RFC 1042` type/length-boundary clauses. **completed 2026-05-21**. |
| G-net_proto-ethernet_802_3 | 5 | 55 (8be0373e) | `IEEE 802.3 §3` per-file; sanity_checks already clean. **completed 2026-05-21**. |
| G-net_proto-icmp4 | 25 | 107 (2d8b1ee0) | `RFC 792` per-message-type (type 3/0/8/unknown). parameter_problem, time_exceeded, unknown parsers, sanity_checks already clean. **completed 2026-05-21**. |
| G-net_proto-icmp6 | ~30 | ~300 | apply `RFC 4443 / RFC 4861 / RFC 3810` per-message-family |
| G-net_proto-ip4 | 16 | 141 (fede712e) | `RFC 791 §3.1` per-file (header / options / EOL / NOP / unknown). lsrr/rr/ssrr/timestamp (RFC 791 §3.1), router_alert (RFC 2113), cipso (FIPS-188), sanity_checks already clean. **completed 2026-05-21**. |
| G-net_proto-ip6 (incl. ext-headers) | ~25 | ~250 | apply `RFC 8200 §3 / §4.x` per-file |
| G-net_proto-llc | 5 | 0 | already clean (mix of `IEEE 802.2 §3 LLC frame format` for wire-format tests + `PyTCP test infrastructure (no RFC clause)` for header asserts). **verified clean 2026-05-21**. |
| G-net_proto-snap | 5 | 0 | already clean (mix of `RFC 1042 §"Header Format"` for wire-format tests + `PyTCP test infrastructure` for asserts + non-RFC `Cisco CDP encapsulation` for vendor-OUI tests). **verified clean 2026-05-21**. |
| G-net_proto-tcp | ~20 | ~250 | apply `RFC 9293 §3.1 (TCP header wire format).` per-file; per-option files use option-RFC clause |
| G-net_proto-udp | 5 | 30 (2ff3ad6a) | `RFC 768` per-file (wire format / header / integrity / parse / sanity). **completed 2026-05-21**. |

**Estimated effort:** 1–2 sessions, ~13 commits if per-family.

### Sub-audit G-pytcp

**Scope:** `packages/pytcp/pytcp/tests/` (250 files, 51 with
violations).

**Suggested family breakdown:**

| Sub-batch | Files (approx) | Violations (approx) | Notes |
|-----------|---------------:|--------------------:|-------|
| G-pytcp-socket | ~10 | ~200 | apply `RFC 9293 §3.9 (User/TCP interface).` for socket-API tests; some warrant specific clauses |
| G-pytcp-lib | ~10 | ~50 | apply `PyTCP test infrastructure (no RFC clause).` |
| G-pytcp-integration-tcp | ~10 | ~50 | TCP session integration tests — apply `RFC 9293 §<state>` per-file |
| G-pytcp-integration-icmp4 | ~5 | ~30 | apply `RFC 792 / RFC 1122 §3.2.2` per-file |
| G-pytcp-integration-icmp6-nd | ~5 | ~30 | apply `RFC 4861 §<section>` per-file |
| G-pytcp-runtime | ~5 | ~25 | apply per-handler RFC |

**Estimated effort:** 1 session, ~6 commits if per-family.

### Sub-audit G-stage2 (non-Reference cleanup)

**Scope:** the 51 non-Reference violations
(`Ensure` opener missing, inline RFC citations, `[FLAGS BUG]`
markers) — concentrated mostly in
`pytcp/pytcp/tests/unit/socket/test__socket__tcp__socket.py`
(19 violations) and the TCP session/cwnd/rack integration
tests.

**Action:** manual review of each violation; fix in place.

**Status:** **completed 2026-05-21.** 22 files / 60 non-
Reference violations cleared across 4 commits (the final
audit script counted 60 distinct items because several
methods triggered both `inline_per_rfc` and
`inline_rfc_section` for the same prose). Final whole-
corpus audit (494 files, 5750 methods) confirms 0 non-
Reference violations remain. Commits:

- `d6a50291` — test(socket): G-stage2 — strip [FLAGS BUG]
  markers + inline RFC (11 violations in
  test__socket__tcp__socket.py).
- `3e194045` — test(tcp): G-stage2 — strip inline RFC
  citations in TCP integration (18 violations across 8 TCP
  session integration files).
- `ef1b64ed` — test(pytcp): G-stage2 — strip inline RFC in
  unit + icmp4 RX tests (10 violations across 9 unit /
  integration test files).
- `077b9093` — test(net_proto): G-stage2 — strip inline RFC
  + missing Ensure (4 violations across 4 net_proto unit
  files; closes the residual `Ensure ` opener gaps).

**Estimated effort:** 30-60 minutes; 1-2 commits.

---

## Workflow expectations

For each sub-audit:

1. **Re-run the §7.2 audit script** scoped to the sub-batch
   directory to get the current violation list.
2. **For each file in the sub-batch:**
   a. Read the file's class docstring + 2-3 sample test
      docstrings to determine the canonical reference.
   b. Apply that reference to every test method missing
      one. Use `Edit` per method (preferred for accuracy) or
      a scripted bulk-replace if the file is uniform.
   c. Verify the file is §7.2-clean post-edit.
3. **Make one commit per sub-batch** (per family). Each
   commit message lists the files touched and the canonical
   reference applied.
4. **Verify `make test` + `make lint` clean** after each
   commit — doc-only changes shouldn't break anything but
   it's a 30-second sanity check.
5. **§7.2 audit on the modified files** (the standard
   workflow check, redundant here but harmless).

---

## Restart prompt — G-net_addr (verification)

```
I want to run sub-audit G-net_addr from
docs/refactor/audit_g_test_docstring_sweep.md.

This is the verification-only sub-audit — the survey says
net_addr is already §7.2-clean (16 files, 0 violations).

Workflow:
1. Re-run the §7.2 audit script (from
   .claude/rules/unit_testing.md §7.2) scoped to
   packages/net_addr/net_addr/tests/ to confirm 0 violations.
2. If 0 violations confirmed: no code changes. Record the
   verification by updating
   docs/refactor/audit_g_test_docstring_sweep.md with a
   "verified clean YYYY-MM-DD" note next to the G-net_addr
   sub-audit entry.
3. If any violations surface (unexpected — survey was clean):
   fix them in a focused commit per the standard audit-G
   workflow.

One commit (the plan-doc verification note) regardless of
outcome; commit and push when done.
```

---

## Restart prompt — G-net_proto-<family> (per-family sweep)

Replace `<family>` with one of `lib`, `arp`, `dhcp4`,
`ethernet`, `ethernet_802_3`, `icmp4`, `icmp6`, `ip4`,
`ip6`, `llc`, `snap`, `tcp`, `udp`.

```
I want to run sub-audit G-net_proto-<family> from
docs/refactor/audit_g_test_docstring_sweep.md.

Workflow:
1. Re-run the §7.2 audit script scoped to
   packages/net_proto/net_proto/tests/unit/protocols/<family>/
   (or tests/unit/lib/ for the lib batch).
2. Survey first — list the affected files and their
   violation counts. Propose a canonical Reference line per
   file based on the file's purpose (protocol RFC for
   wire-format tests; option RFC for per-option tests; the
   infrastructure fallback for lib tests).
3. Wait for me to approve the per-file references.
4. Apply the canonical Reference to every test method
   missing one in each file (per the §7.2 form: trailing
   line, blank line above, exactly 'Reference: RFC X §Y
   (descr).' or one of the two fallbacks).
5. One commit for the family. make test + make lint clean.
6. Re-run the §7.2 audit on the touched files to confirm
   they're clean.

Doc-only change; no production code touched.
```

---

## Restart prompt — G-pytcp-<family>

Replace `<family>` with one of `socket`, `lib`,
`integration-tcp`, `integration-icmp4`,
`integration-icmp6-nd`, `runtime`.

```
I want to run sub-audit G-pytcp-<family> from
docs/refactor/audit_g_test_docstring_sweep.md.

Workflow:
1. Re-run the §7.2 audit script scoped to the relevant
   subdirectory under packages/pytcp/pytcp/tests/.
2. Survey first — list affected files and violation counts.
   Propose a canonical Reference per file.
3. Wait for approval; apply; one commit per family.
4. make test + make lint clean; §7.2 audit on touched files.
```

---

## Restart prompt — G-stage2 (non-Reference cleanup)

```
I want to run sub-audit G-stage2 from
docs/refactor/audit_g_test_docstring_sweep.md.

This is the non-Reference cleanup: ~51 violations total
across the `Ensure ` opener, inline RFC citation, and
`[FLAGS BUG]` marker categories. Most concentrate in
pytcp/pytcp/tests/unit/socket/test__socket__tcp__socket.py
(19 violations) and the TCP session/cwnd/rack integration
tests.

Workflow:
1. Re-run the §7.2 audit, filter to non-Reference
   violations.
2. For each violation, read the surrounding test method
   and decide:
   - Missing `Ensure ` opener: rewrite the description to
     start with 'Ensure ' (preserving meaning).
   - Inline `RFC X §Y` / `Per RFC X` in description: remove
     the inline citation; confirm the trailing `Reference:`
     line carries it.
   - `[FLAGS BUG]` marker: strip the marker (tests-first
     transient that should not have been left in).
3. Bundle by file family; one commit per family or one
   bundled commit if total volume is small.
4. make test + make lint clean.
```

---

## Cross-references

- `.claude/rules/unit_testing.md` §7.2 — the docstring audit
  script and the four invariants it enforces.
- `.claude/rules/feature_implementation.md` §2 — the
  tests-first workflow that motivates §7.2 (`Reference:`
  lines tie tests back to spec clauses).
- `docs/refactor/net_proto_remaining_audits.md` — the
  parent audit-plan doc listing audits A through L.
