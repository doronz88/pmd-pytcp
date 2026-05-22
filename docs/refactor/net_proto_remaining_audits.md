# `net_proto` — Remaining Audit Passes

**Status:** planning doc (2026-05-21). Tracks the audit work
remaining after the parser RFC-adherence pass, the assembler
audit pass, the `*_header` / option / message doc audit, the
PEP 420 → regular packages migration, the diagram-label
harmonization, and the wire-input vs programmer-input
error-discipline codification all closed on 2026-05-20 /
2026-05-21.

This doc enumerates eleven follow-up audits, ordered by
expected defect yield. Each audit is self-contained: an
audit can be picked up independently of the others.

---

## Completed audits (for context)

These are CLOSED. Don't re-do them; the memory files and
adherence docs are canonical.

| Pass | Closed | Tracking |
|---|---|---|
| Parser RFC-adherence pass | 2026-05-20 | `docs/refactor/net_proto_rfc_adherence_pass.md`; memory `project_net_proto_rfc_adherence_pass.md` |
| Assembler audit pass | 2026-05-21 | memory `project_net_proto_assembler_audit_pass.md` |
| `*_header` / option / message doc audit | 2026-05-21 | bundled in the assembler-audit-pass memory under "Follow-up 2026-05-21" |
| PEP 420 → regular packages | 2026-05-21 | memory `project_pep420_to_regular_packages.md` |
| Diagram-label capitalization sweep | 2026-05-21 | commits `0838d8f7` |
| Wire-input vs programmer-input error discipline | 2026-05-21 | `.claude/rules/net_proto.md` §9.1 + §17 anti-patterns |
| Audits A–G (roundtrip, base, errors, lib, enums, prop-docstrings, §7.2 test-docstring sweep) | 2026-05-21 | A/E confirmed via git; B/C/D/F prior session; G fully closed (see `docs/refactor/audit_g_test_docstring_sweep.md`) |
| Audit H — module-docstring path / `ver` accuracy | 2026-05-21 | commit `b7d5cecc` — 24 stale paths + 1 convention outlier fixed (all in pytcp); net_addr/net_proto were clean; all `ver` lines already 3.0.6 |
| Audit I — class-docstring consistency | 2026-05-21 | **verified clean, no changes.** AST-walked all 3 packages (484 classes): 0 missing docstrings, 0 missing-period, all open with a noun-phrase first line. The 117 multi-line docstrings all carry intentional context (RFC citations, error-extension rationale per net_proto.md §9.1, Phase markers) — not drift. |

---

## Tier 1 — most likely to surface real defects

### Audit A — `__buffer__` / `from_buffer` roundtrip symmetry

**Goal:** Confirm every header's wire-format symmetry: for
every realistic input `b`,
`bytes(<Proto>Header.from_buffer(b))` MUST equal `b` (modulo
checksum injection at the base-class layer). Catches
field-reorder defects, bit-pack misalignments, padding
errors, and struct-format-vs-field-list mismatches that
mypy can't see.

**Files:** all 14 `*__header.py` files under
`packages/net_proto/net_proto/protocols/*/`.

**Method:** for each header, generate a corpus of realistic
input frames (existing assembler-operation parametric test
matrices are a good source). Round-trip:

```python
parsed = HeaderCls.from_buffer(frame)
reassembled = bytes(parsed)
assert reassembled == frame[:HEADER_LEN]
```

Where `HEADER_LEN` is the fixed-prefix size. For checksum
fields, the parser stores them but `__buffer__` packs `0` at
the checksum offset; tests must compare with the checksum
zeroed out.

**Existing coverage:** every `test__<proto>__assembler__operation.py`
has a `__bytes__` aspect in its `_results` dict that pins
the expected wire bytes. That's the TX-side check
(construct-then-bytes). The audit adds the RX-side check
(from-buffer-then-bytes-roundtrip).

**Expected outcome:** likely clean (the parser pass and
assembler pass already touched every header). Worth running
to confirm. Failure mode would be a mis-packed bit field
that happens to round-trip but produces wrong on-wire bytes
under specific input.

**Exit criteria:** all 14 headers have an explicit roundtrip
test method (`test__<proto>__header__roundtrip`) in the
`test__<proto>__header__asserts.py` file or a dedicated
`test__<proto>__header__roundtrip.py` file. §7.2 audit
clean on the new tests.

---

### Audit B — `*_base.py` files

**Goal:** Audit the per-protocol `<Proto>` base class
files — these compose `Header` + optional `Options` +
`payload` and implement the whole-packet
`__len__` / `__str__` / `__repr__` / `__buffer__` dunders.
This is the one file group we never systematically swept.

**Files:** all `*__base.py` files (≈ 14 total):

```
packages/net_proto/net_proto/protocols/<proto>/<proto>__base.py
```

**Method:** for each `*__base.py`:

1. Verify the class signature matches the project pattern:
   `class <Proto>(Proto, <Proto>HeaderProperties[, <Proto>OptionsProperties]):`.
2. Verify `__len__` correctly sums header + options + payload
   (or header + payload for protocols without options).
3. Verify `__str__` is a single-line log format consistent
   with other protocols' style.
4. Verify `__repr__` is the constructor-callable form
   (`<Proto>(header=..., payload=...)` plus `options=` for
   protocols with options).
5. Verify `__buffer__` correctly injects the checksum into
   the canonical offset and returns a `memoryview`.
6. Verify the `header` / `payload` / `options` properties
   return the underlying `_header` / `_payload` / `_options`
   attributes (no transformation).
7. Verify class-level attribute annotations are declared
   (`_header: <Proto>Header`, `_payload: Buffer`, etc.).
8. Verify `pshdr_sum: int = 0` is declared at class level
   for protocols that need it (UDP / TCP / ICMPv4 / ICMPv6).

**Expected outcome:** mostly consistent. Possible findings:
inconsistent `__str__` formatting, missing class-level
annotations, missed `pshdr_sum` declaration.

**Exit criteria:** all 14 base files conform to the §5
pattern in `.claude/rules/net_proto.md`; any drift fixed.

---

### Audit C — `*_errors.py` consistency

**Goal:** Verify every protocol's error-class file follows
the exact pattern in `.claude/rules/net_proto.md` §9.

**Files:** all 9 `*__errors.py` files (one per protocol —
ARP, DHCPv4, Ethernet II, Ethernet 802.3, ICMPv4, ICMPv6,
IPv4, IPv6 + ext-headers, TCP, UDP). Plus per-ext-header
error files (e.g. `ip6_hbh__errors.py`,
`ip6_dest_opts__errors.py`, `ip6_frag__errors.py`,
`ip6_routing__errors.py`).

**Method:** for each file:

1. Verify exactly two public classes:
   `<Proto>IntegrityError(PacketIntegrityError)` and
   `<Proto>SanityError(PacketSanityError)`. Some protocols
   carry additional error subclasses (e.g. UDP's
   `UdpZeroCksumIp6Error`); those need an inline RFC comment.
2. Verify constructor signature is exactly
   `def __init__(self, message: str, /) -> None:` (positional-only).
3. Verify the prefix prepended is exactly `"[<PROTO>] "`
   (single trailing space, no `[INTEGRITY ERROR]` /
   `[SANITY ERROR]` duplication — those come from the base).
4. Verify docstrings are present on each class and use the
   canonical phrasing
   (`"Exception raised when <PROTO> packet integrity check fails."`).

**Expected outcome:** likely clean. Possible drift in the
trailing-space convention or the docstring wording.

**Exit criteria:** all error files identical except for
the `<PROTO>` substring; any drift fixed.

---

### Audit D — `lib/` shared infrastructure

**Goal:** Sweep the foundational code that every protocol
consumes. Defects here propagate to all 9 protocols.

**Files:** under `packages/net_proto/net_proto/lib/`:

```
buffer.py
enums.py            # IpProto, EtherType, IpVersion
errors.py           # PacketIntegrityError, PacketSanityError bases
inet_cksum.py
int_checks.py       # is_uintN predicates + bound constants
packet_rx.py        # PacketRx context
packet_stats_rx.py
packet_stats_tx.py
proto.py            # Proto ABC
proto_assembler.py
proto_enum.py       # ProtoEnum / ProtoEnumByte / ProtoEnumWord
proto_option.py
proto_options.py
proto_parser.py
proto_struct.py
tracker.py
```

**Method:** for each file:

1. Module docstring present + RFC citation where applicable
   (most are infrastructure, not RFC-bound).
2. Class docstrings present.
3. Method docstrings present.
4. Type annotations complete (mypy strict catches this).
5. No dead code (unused exports, unused parameters).
6. Public surface matches the project's invariant (e.g.,
   `ProtoEnum._missing_` hook documented per §11 of
   `.claude/rules/net_proto.md`).
7. Constants documented with RFC citation if RFC-bound
   (e.g., `is_uint16` bounds derived from RFC field widths).
8. For `enums.py`: IpProto / EtherType / IpVersion should
   have per-codepoint RFC comments (like the recent
   TCP/DHCPv4/ICMPv6-ND option type sweep).

**Expected outcome:** likely surfaces missing RFC comments
on IpProto / EtherType members. Possibly module-docstring
gaps on infrastructure files.

**Exit criteria:** every lib file conforms to
`.claude/rules/source_files.md` §4 (module docstring) and
§6 (class / method docstrings). Per-codepoint RFC comments
on every public enum member.

---

## Tier 2 — medium value

### Audit E — `*_enums.py` per-codepoint RFC docs

**Goal:** Mirror the recent doc commit (e36ae001) that
added per-member RFC comments to `TcpOptionType` /
`Dhcp4OptionType` / `Icmp6NdOptionType`. Apply the same to
every other protocol-specific enum.

**Files:** all `*__enums.py` under
`packages/net_proto/net_proto/protocols/*/` plus the relevant
enums in subdirectories:

```
arp/arp__enums.py            # ArpHardwareType, ArpOperation
dhcp4/dhcp4__enums.py        # Dhcp4Operation, Dhcp4MessageType
ethernet/ethernet__enums.py  # EtherType (lives in lib/enums.py actually)
icmp4/message/icmp4__message.py  # Icmp4Type, Icmp4Code (+ per-code subclasses)
icmp6/message/icmp6__message.py  # Icmp6Type, Icmp6Code (+ per-code subclasses)
ip6_routing/ip6_routing__enums.py  # Ip6RoutingType
llc/llc__enums.py            # LlcSap, LlcControl
snap/snap__enums.py          # SnapOui
tcp/options/tcp__option.py   # TcpOptionType (DONE)
```

Plus the various per-message `*Code` enums under
`icmp4/message/` and `icmp6/message/` (e.g.,
`Icmp4DestinationUnreachableCode`,
`Icmp6ParameterProblemCode`, etc.).

**Method:** for each enum, ensure every member has an
inline `# RFC N §X` comment.

**Expected outcome:** moderate — most ICMP codes have RFC
comments already; ARP and DHCPv4 operations may not.

**Exit criteria:** every member of every enum has a
per-codepoint RFC comment.

---

### Audit F — Property-mixin docstring consistency

**Goal:** Per `.claude/rules/source_files.md` §6, every
`@property` getter on a `*HeaderProperties` mixin has a
docstring of exactly the form
`Get the <PROTO> header '<field>' field.` Sweep for drift.

**Files:** every `*__header.py` file's `*HeaderProperties`
ABC class (plus the `*OptionsProperties` mixins for
protocols with options).

**Method:** AST-walk each properties class. For each
`@property` getter, verify the docstring matches the
canonical pattern. Allow for `"option"` vs `"header"` based
on which mixin it is.

**Expected outcome:** likely clean (this was enforced
during the parser pass per-property).

**Exit criteria:** every property docstring matches the
canonical pattern.

---

### Audit G — Test docstring §7.2 wholesale audit

**Goal:** Run the §7.2 audit script (in
`.claude/rules/unit_testing.md` §7.2) against every test
file in `packages/net_proto/net_proto/tests/` AND
`packages/net_addr/net_addr/tests/` AND
`packages/pytcp/pytcp/tests/`. Surface old test files with
`[FLAGS BUG]` markers, missing `Reference:` lines, inline
RFC citations from pre-§7.2 commits.

**Files:** every `test__*.py` file across the 3 packages.

**Method:** run the §7.2 audit script in
`.claude/rules/unit_testing.md` §7.2 against the full
filesystem (not just one file). Fix every violation in the
same commit.

**Expected outcome:** likely a handful of older tests with
inline RFC citations or missing `Reference:` lines.

**Exit criteria:** §7.2 audit clean across the entire test
corpus.

---

### Audit H — Module path / version string accuracy

**Goal:** Verify every module docstring's
`<relative-path>` line matches the file's actual location,
and that the `ver 3.0.x` line is current.

**Files:** every `.py` file under
`packages/net_addr/net_addr/`,
`packages/net_proto/net_proto/`,
`packages/pytcp/pytcp/`.

**Method:** for each file, regex-extract the path line
from the module docstring and compare to the file's actual
relative path. Same for `ver 3.0.x`.

**Expected outcome:** likely a few stale paths (from the
historical pytcp/ directory restructure or the
packages/<x>/<x>/ flattening). The version-string drift
may be ≈ 0 since most files were touched recently.

**Exit criteria:** every module docstring's path matches
reality; every `ver` line is current.

---

## Tier 3 — lower value, cosmetic

### Audit I — Class docstring consistency

**Goal:** Per `.claude/rules/source_files.md` §6, class
docstrings are one-line noun phrases ending in a period.
Sweep for drift.

**Method:** AST-walk every class. Surface multi-line class
docstrings (which are legitimate when they describe
non-trivial context, but should be intentional).

---

### Audit J — `@override` decorator visual sweep

**Goal:** mypy strict catches missing `@override`
mechanically. Manual sweep would only find decorator
misplacement edge cases (e.g., `@override` on a method that
ISN'T overriding anything).

**Likely low-yield; skip unless reviewer judgment changes.**

---

### Audit K — `Buffer` type alias adoption

**Goal:** Sweep for places re-spelling
`bytes | bytearray | memoryview` instead of using the
`Buffer` alias from `net_proto.lib.buffer`.

**Method:** `grep -r 'bytes | bytearray | memoryview'
packages/`. Replace with `Buffer` everywhere.

**Likely low-yield; the alias is well-adopted.**

---

### Audit L — `*Options` / `*OptionsProperties` lookup-property layout

**Goal:** Surfaced by audit F's docstring sweep. The
lookup-property layout for TLV-option containers drifts
across families:

| Family | `*Options` container | `*OptionsProperties` mixin |
|--------|----------------------|----------------------------|
| TCP | 7 lookup properties | 5 properties (with default-fallback wrappers) |
| DHCPv4 | 13 lookup properties | 13 properties (delegating 1:1) |
| ICMPv6 ND | 4 lookup properties | empty (mixin defines only `_options`) |
| IPv4 | none | 6 lookup properties |
| IPv6 HBH | 3 lookup properties | empty |
| IPv6 DestOpts | 1 lookup property | empty |

Five distinct layouts for the same architectural role.
Consumers reading `packet_rx.tcp.options.mss` see one
surface; consumers reading `packet_rx.tcp.mss` see
another. The two surfaces don't always agree on naming
(`Dhcp4Options.server_id` ≠ `Dhcp4OptionsProperties.srv_id`)
or on return-type semantics (TCP's mixin adds default
fallbacks the container doesn't).

**Method:** decide which layout is canonical for net_proto
(probably: lookup properties live on the `*Options`
container only; the `*OptionsProperties` mixin re-exports
them at the protocol-class level via property delegation
when needed), then migrate the divergent families. Each
family migration is one focused commit:

- TCP: collapse the 5 mixin default-fallback wrappers into
  the container or into the `Tcp` base class properties.
  Drop the 5 mixin duplicates that delegate to the
  container 1:1.
- DHCPv4: drop the 13 mixin duplicates (they all delegate
  1:1 to the container) and reconcile the
  `server_id` / `srv_id` naming.
- IPv4: move the 6 lookup properties from the mixin to a
  new `Ip4Options` container layer (the family currently
  has no container-level properties at all).
- IPv6 HBH / DestOpts / ICMPv6 ND: already container-only;
  no migration needed.

**Expected outcome:** Reduce ~24 redundant mixin
properties to ~0; consolidate the 5-way layout drift to a
single canonical pattern.

**Likely Tier-1-ish work** because it's a real
architectural inconsistency that affects every consumer
of the option lookups. Defer-able but not deferable
forever.

---

## Workflow expectations

For each audit pass:

1. **Survey first** — present the user with a structured
   findings table before any code changes. Each finding
   should cite the file, the concern, and the proposed
   fix. Let the user pick scope.
2. **Tests-first** — every behavioural change opens with
   one or more failing tests. Doc-only changes don't need
   tests but should be verified with `make test` + `make
   lint` clean.
3. **One concern per commit** — keep diffs reviewable.
   Wait for explicit "commit and push" between commits.
4. **§7.2 audit** — run the docstring audit script on any
   test file written or modified.
5. **Adherence-doc lockstep** — RFC-governed code changes
   require the relevant
   `docs/rfc/<family>/rfcXXXX__*/adherence.md` updated in
   the SAME commit.

## Cross-references

- `.claude/rules/feature_implementation.md` — tests-first
  workflow, modernise-on-touch, commit discipline.
- `.claude/rules/net_proto.md` — per-protocol six-file
  pattern, dataclass shape, error discipline §9.1.
- `.claude/rules/source_files.md` — file skeleton,
  docstring shape, naming, `__init__.py` rule §2.4.
- `.claude/rules/unit_testing.md` §7.2 — docstring audit
  script.
- `~/.claude/projects/-root-PyTCP/memory/MEMORY.md` —
  cumulative project memory index.
- `~/.claude/projects/-root-PyTCP/memory/project_net_proto_assembler_audit_pass.md`
  — canonical archaeology for the completed sweeps + the
  6 recurring patterns + the universally-skipped
  concerns.

---

## Restart prompt template

Use the following self-contained prompt to resume any
single audit in a fresh session (paste verbatim, fill in
the audit letter):

```
I want to run audit <X> from docs/refactor/net_proto_remaining_audits.md
against packages/net_proto.

Workflow:
1. Read docs/refactor/net_proto_remaining_audits.md for the
   full plan. Audit <X> is the one I want to run.
2. Survey the relevant files first — present findings as a
   structured table before any code changes. Cite each
   file + concern + proposed fix.
3. Wait for me to pick scope.
4. Tests-first for any behavioural change; doc-only changes
   verified with make test + make lint clean.
5. One concern per commit; wait for explicit "commit and
   push" between commits.
6. Run the §7.2 docstring audit (.claude/rules/
   unit_testing.md §7.2) on any test file modified.
7. Update relevant adherence doc in the same commit if
   the change is RFC-governed.

Start with the survey.
```

Replace `<X>` with the audit letter (A through K). The
audits are independent and can be run in any order, though
Tier-1 first is recommended for highest defect yield.
