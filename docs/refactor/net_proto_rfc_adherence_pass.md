# `net_proto` per-protocol RFC integrity/sanity adherence pass

Per-protocol review of every parser's `_validate_integrity` and
`_validate_sanity` blocks under
`packages/net_proto/net_proto/protocols/`, alphabetically. For each
protocol:

1. Audit existing checks against the governing RFCs.
2. Annotate each surviving check with a one-line `# RFC ...` citation.
3. Fill clear gaps with RFC-backed new checks (tests-first per
   `feature_implementation.md` §2).
4. Update the corresponding `docs/rfc/<family>/.../adherence.md`.
5. Run `make lint`, `make test`, and the §7.2 docstring audit on any
   touched test file.
6. Commit + push when the user explicitly asks ("commit and push").

All work is on branch `PyTCP_3_0_6`. The branch is pushed.

---

## Done

| Order | Protocol | Commit | Net change |
|---|---|---|---|
| 1 | **ARP** | `a7b809d7` | Annotated 5 integrity + 8 sanity checks; reorganised by field (SHA → SPA → TPA); added 3 new sanity rejections (`spa.is_loopback`, `tpa.is_multicast`, `tpa.is_limited_broadcast`); **dropped** the PyTCP-only `sha == ethernet.src` hardening (not RFC-normative, not Linux behaviour). |
| 2 | **DHCPv4** | `54d8d5c6` | Annotated integrity checks; filled previously empty `_validate_sanity` with 15 RFC-backed rejections (operation unknown, 4 IP fields × 3 forbidden classes, 2 chaddr classes); switched `Dhcp4Header.from_buffer` from strict `Dhcp4Operation(value)` to tolerant `Dhcp4Operation.from_int(value)` so unknown opcodes route to sanity. |
| 3 | **Ethernet II + 802.3** | `1a6aff7e` | Annotated 1 (II) / 3 (802.3) integrity checks + 1 (II) sanity; added 3 src-non-unicast sanity checks per parser; fixed existing fixture MACs `11:12:...` and `77:88:...` which were multicast (group bit set). Integration tests for ARP-via-Ethernet updated. |
| 4 | **ICMPv4** | `e18903e8` | Annotated parser integrity; filled empty `validate_sanity` in 5 known message types with `code.is_unknown` rejection; **`Icmp4MessageUnknown.validate_sanity` raises** per RFC 1122 §3.2.2 "MUST silently discard unknown-type ICMP". Integration tests that pinned `icmp4__unknown` counter updated to `icmp4__failed_parse__drop`. The `__phrx_icmp4__unknown` path + counter are now dead but retained. |
| 5 | **ICMPv6** | `4d03adf4` | Annotated parser integrity; filled 6 empty `validate_sanity` methods (DU, PTB, TE, PP, Echo Req, Echo Reply) with `code.is_unknown` rejection. ND messages + MLDv2 Report already had rich sanity; left intact. **Unknown-type NOT rejected** at parser sanity per RFC 4443 §2.4(b/c) split (unknown error messages MUST be passed to upper layer; only unknown informational MUST be discarded). |
| 6 | **ICMPv6 RFC 7112 follow-up** | `25f906ed` | Added `Icmp6ParameterProblemCode.INCOMPLETE_HEADER_CHAIN = 3` per RFC 7112 §3. PyTCP now accepts PP code 3 inbound (matches Linux `ICMPV6_HDR_INCOMP`). Active emission deferred to Phase 2 — matches Linux which also doesn't actively emit, just silent-drops on reassembly failure. |
| 7 | **IPv4** | `a4c0d639` | Annotated 5 integrity + 6 sanity branches with RFC citations. Added two new RFC 1122 §3.2.1.3 src rejections: `src.is_loopback` (127/8, clause (g)) and `src.is_invalid` (0.0.0.1–0.255.255.255, clause (a) minus the DHCPv4 0.0.0.0 carve-out). Closed the documented-but-not-enforced loopback gap (the RFC 791 adherence doc had wrongly claimed 127/8 was covered by `is_reserved`). Sanity checks reordered to ascending address-space order. Cascade: moved the "Loopback source 127.0.0.1" case in `test__icmp4__error_gates.py` from `__Suppressed` to `__DefenseInDepth`. |

Test count after the pass: **11092 passing**.

---

## Remaining (alphabetical)

In order:

1. **IPv6** (`packages/net_proto/net_proto/protocols/ip6/`) and the
   four sibling extension-header subpackages
   (`ip6_dest_opts`, `ip6_frag`, `ip6_hbh`, `ip6_routing`)
2. **TCP** (`packages/net_proto/net_proto/protocols/tcp/`) — large
   surface, RFC 9293 primary
3. **UDP** (`packages/net_proto/net_proto/protocols/udp/`)

---

## Workflow / pattern

For each protocol:

1. Read parser, header, errors, message subdirs.
2. Survey existing checks — categorise as integrity (structural, before
   parse) or sanity (semantic, after parse).
3. Grep for the corresponding `docs/rfc/<family>/.../adherence.md`
   records.
4. Present an analysis to the user laying out:
   - Current state (table of checks vs RFC backing).
   - RFC verdict (which checks are correct, which are stale).
   - Gaps (what could be added at sanity).
   - Nuances / divergence points (e.g. Linux differs here).
5. **Use `AskUserQuestion`** to confirm direction. Options usually
   include: "annotate only", "annotate + add the gaps", "full pass".
6. Tests-first:
   - Write failing test(s) for new rules in
     `<pkg>/tests/unit/protocols/<proto>/test__<proto>__parser__sanity_checks.py`
     (consolidated when multiple message types, or per-aspect when
     pre-existing layout uses that).
   - Run, confirm "X not raised" for the predicted reason.
7. Implement annotations + new rules.
8. Run `make lint`, `make test`, §7.2 docstring audit.
9. Update the adherence doc with the new "Parser validation" section
   (or refresh the existing one).
10. Commit when the user says so. Use the existing convention:
    ```
    refactor(<proto>): RFC-align integrity/sanity ...

    <body with bullet list of changes + RFC citations>

    NNNN passing, lint clean, §7.2 audit clean.

    Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
    ```
11. Push when commit lands.

---

## Lessons / gotchas

- **Linux is the tiebreaker.** When a rule could be added but Linux
  doesn't enforce it, default to NOT adding it; document the rationale
  in the adherence doc. Examples: ARP's sha-vs-ethernet (Linux
  doesn't enforce — removed); ICMPv6 PP code 3 emit (Linux doesn't
  actively emit — deferred to Phase 2).
- **Tests-first means tests-first.** Write the test, confirm it fails
  for the predicted reason, THEN implement. The `Icmp4MessageUnknown`
  sanity rejection followed this; so did every per-code unknown check.
- **§7.2 docstring audit MANDATORY on touched test files.** The audit
  script in `unit_testing.md` §7.2 must come back exit-0 before
  commit. Scope it to genuinely-modified files; don't take on
  pre-existing-violation sweeps unless the user asks.
- **Fixture surprises.** During the Ethernet pass, the long-standing
  fixture MACs `11:12:13:14:15:16` and `77:88:99:aa:bb:cc` turned
  out to be multicast (LSB of first octet = 1 = I/G bit set). They'd
  silently been used as src for years. Fix on touch but DON'T sed
  globally across all integration tests — the byte sequence
  `\x11\x12\x13\x14\x15\x16` legitimately appears in ICMP payloads
  (ascending-byte test patterns). Limit byte substitutions to files
  in `packages/net_proto/net_proto/tests/unit/protocols/ethernet*/`.
- **Counter telemetry shifts.** When a sanity rule moves from
  packet-handler to parser (e.g. ICMPv4 Unknown-type), integration
  tests that pinned the old counter (e.g. `icmp4__unknown=1`) need
  to be updated to the parser counter
  (e.g. `icmp4__failed_parse__drop=1`).
- **ICMPv4 vs ICMPv6 unknown-type handling diverges.** RFC 1122 §3.2.2
  says "MUST silently discard" for ICMPv4 (so PyTCP rejects at parser
  sanity). RFC 4443 §2.4(b/c) splits it for ICMPv6 — unknown error
  messages (type 1..127) MUST be passed to upper layer; only unknown
  informational (type >= 128) MUST be silently discarded. PyTCP
  therefore does NOT reject ICMPv6 unknown types at parser sanity.
- **`code.is_unknown` is the canonical pattern** when rejecting
  out-of-IANA-range code/oper bytes. Available on every
  `ProtoEnum`-derived enum via `_missing_` materialisation.
- **Adherence docs decay fast.** When you change a parser-level
  enforcement rule, the corresponding `adherence.md` MUST be updated
  in the SAME commit (per `feedback_audit_in_lockstep_with_code.md`).
- **`make lint` is autoformatting.** It will reformat files in
  place. Run it before commits; don't be surprised when files
  reformat.

---

## Restart prompt

To resume this work in a fresh session, paste:

> Resume the `net_proto` per-protocol RFC integrity/sanity adherence
> pass on branch `PyTCP_3_0_6`. State and workflow are documented at
> `docs/refactor/net_proto_rfc_adherence_pass.md`. Read that file
> first. Last protocol completed: **IPv4** (commit `a4c0d639`,
> which closed two RFC 1122 §3.2.1.3 src gaps (loopback 127/8 and
> 0/8-minus-0.0.0.0 "this network") and corrected the RFC 791
> adherence doc's misclaim about `is_reserved` covering loopback).
> Next alphabetically: **IPv6** (and the four sibling
> extension-header subpackages — `ip6_dest_opts`, `ip6_frag`,
> `ip6_hbh`, `ip6_routing`). Follow the established workflow:
> survey → present analysis → `AskUserQuestion` to confirm
> direction → tests-first → implement → adherence-doc refresh →
> run lint + `make test` + §7.2 docstring audit → wait for
> explicit "commit and push" before committing. Begin with reading
> `packages/net_proto/net_proto/protocols/ip6/ip6__parser.py`,
> `ip6__header.py`, `ip6__errors.py`, the four extension-header
> subpackages' parsers, `docs/rfc/ip6/`, and the existing unit
> tests under `packages/net_proto/net_proto/tests/unit/protocols/ip6/`.
> Do **not** start changing code; present the analysis first and
> use `AskUserQuestion` to confirm direction.
