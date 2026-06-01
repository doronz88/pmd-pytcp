# PyTCP 3.0.6 — Release-Readiness Review (per-package)

**Authored:** 2026-05-25 on `PyTCP_3_0_6` (HEAD `b181d4b8`).
**Goal:** ship all three dists today — `PyTCP-net_addr`, `PyTCP-net_proto`,
`PyTCP` — after a per-package release-readiness pass. For **each** package,
in order **net_addr → net_proto → pytcp**, do three things and only move on
when the package is 100% done:

1. **Bug / issue sweep** — read the package's source for correctness,
   run its suite + coverage in isolation, check rule-conformance, grep
   for `TODO`/`FIXME`/`XXX`, fix anything real.
2. **Doc + RFC completeness for *this phase*** — confirm nothing in
   `docs/refactor/*.md` or `docs/rfc/**/adherence.md` that *belongs to
   Phase 1 (host-stack parity)* is left unfinished, stale, or falsely
   claimed. Phase-2 (router/forwarding) and Phase-3 (kernel-boundary
   cleanups beyond what shipped) are explicitly OUT — but every open
   item must be a **conscious, documented defer**, not an oversight.
3. **README refresh** — bring the package-specific `README.md` to "100%
   current state" (richer, accurate, complete API surface) **and** keep
   the relevant section of the **main** `README.md` accurate.

"Belongs to this phase" = Phase 1 host-stack parity per `CLAUDE.md`
North Star. The bar per package: no Phase-1 gap left open, no stale/false
doc claim, no half-finished in-scope refactor.

> **Reconciled 2026-05-30:** since this readiness pass (HEAD `b181d4b8`)
> three tracks landed and are NOT covered by the dated snapshot below:
> (1) the **DHCPv6 RFC 8415 host client** reached fully-met — the pass
> predates it (adherence `docs/rfc/dhcp6/rfc8415__dhcpv6/adherence.md`;
> plan `dhcp6_client.md`); (2) **DHCPv4 DNAv4** shipped and its last
> Phase-3 reach-through was closed (the probe now runs over
> `Ip4Acd.probe_reachable` on the AF_PACKET raw socket, commit
> `e2998736`); (3) **PLPMTUD closeout CLOSED 2026-05-28** (see
> `v3_0_6_remaining_work.md` §2.1). The original body below is retained
> as the dated readiness snapshot.

---

## 0. Baseline & preconditions

- Branch `PyTCP_3_0_6`; HEAD `b181d4b8`; **11312 tests passing, `make lint`
  clean** (last full run this session).
- All three `__version__` are already `3.0.6`
  (`packages/<p>/<p>/__init__.py`).
- **UNPUSHED:** `b181d4b8` (remove-at-runtime example) is committed locally
  but **not pushed**. Push it as part of release prep (step 5).
- Dists / imports (one invariant: folder == import name):
  `packages/net_addr` → `PyTCP-net_addr` → `net_addr` (23 source files,
  16 test files); `packages/net_proto` → `PyTCP-net_proto` → `net_proto`
  (221 source, 228 test); `packages/pytcp` → `PyTCP` → `pytcp` (157 source,
  265 test). `PyTCP` depends on the other two in lockstep.

## 1. Standing discipline (unchanged)

Tests-first (a failing test pinning the spec before any behavioural fix);
one logical unit per commit; `make lint` + **full** `make test` + the §7.2
docstring audit clean before **each** commit; commit trailer
`Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`;
**push only when the user explicitly says so**. Modernise legacy
typing/Python forms on touch. RFC-ground every behavioural claim. README /
doc-only changes don't need a failing test but still go through lint +
suite + a focused commit.

## 2. Cross-cutting reference state (survey, 2026-05-25)

**READMEs in scope:** main `README.md` (664 lines); `packages/net_addr/
README.md` (71), `packages/net_proto/README.md` (44), `packages/pytcp/
README.md` (51). Also present (touch only if a claim drifted): `docs/api/
README.md` (91), `examples/README.md` (139).

**RFC adherence records:** 118 `adherence.md` across 9 families — arp 6,
dhcp4 11, ethernet 2, icmp4 6, icmp6 17, ip4 17, ip6 11, tcp 43, udp 5.
**No RFC directory is missing its `adherence.md`** (structural coverage is
complete). Known *content* gap: **RFC 8504 (IPv6 Node Requirements) has no
adherence record** — flagged in `v3_0_6_remaining_work.md` §2.3; decide in
the pytcp pass (author via the `rfc_adherence_audit` skill, or consciously
defer).

**Refactor docs:** 35 in `docs/refactor/`. Nearly all `SHIPPED` / `CLOSED` /
`COMPLETE`. The ones with non-shipped headers or open items (must be
classified in/out this pass):

| Doc | Header / open item | Package |
|---|---|---|
| `dhcp4_client_full_parity.md` | "Plan — not yet started" header is **stale**; Phases 0–4.x shipped, **§5–§8 open** (INIT-REBOOT/lease cache, DNAv4, Classless Static Routes, option polish) | pytcp |
| `rfc3927_link_local_autoconfig.md` | "Plan — not yet started" header — but `stack.link_local` / `Ip4LinkLocal` + ACD exist; **reconcile actual state** | pytcp |
| `arp_linux_parity.md` | §1 #8 simultaneous-probe detection (RFC 5227 §2.1.1) open | pytcp |
| `plpmtud_unified_engine.md` | "remaining 20% (two transport-specific rows)" | pytcp |
| `socket_linux_parity_audit.md` | Phase 1 shipped; HIGH/MED/LOW tail + X1 thread-safety audit deferred | pytcp |
| `tcp_codebase_improvement_plan.md` | internal code-quality refactors deferred (not conformance) | pytcp |
| `nud_state_machine.md`, `icmp_remaining_issues.md`, `v6_remaining_items.md`, `post_udp_session_followups.md`, `ip4_audit_punchlist.md`, `net_proto_remaining_audits.md` | snapshots — confirm each open item is deferred-with-rationale, not a Phase-1 gap | per-doc |

**Authoritative ledger — `docs/refactor/archive/v3_0_6_remaining_work.md` — is
DRIFTED** (authored 2026-05-24, before this session's work). It must be
reconciled in the pytcp pass: since it was written we (a) confirmed the
privileged singletons already retired, (b) shipped the `remove_interface`
RTM_DELLINK cascade + a while-running integration test, (c) removed the
control-tool sole-interface fallback (1:1 Linux `ip … dev`), (d) made
egress purely FIB-driven (removed its sole-interface fallback), (e)
lock-guarded the FIB (`RouteTable`) for free-threaded safety, (f) added
the remove-at-runtime example. The plan doc `dreamy-jingling-steele.md`
(`~/.claude/plans/`) is up to date on the multi-interface track and is the
source of truth for it.

## 3. Package ↔ doc/RFC mapping (so each pass knows its surface)

- **net_addr** — pure value-type library. **No `docs/rfc` records**
  (the protocol-family records are net_proto/pytcp). Addressing-RFC
  fidelity (RFC 4291 scopes, 5952 canonical text, 4007 zones, 1918/4193
  classification, 7217/8981 IID generation) lives in **code + the
  `net_addr.md` rule + its unit tests**, not in `docs/rfc`. Smallest pass.
- **net_proto** — wire-format parse/assemble/validate. Owns the
  **header/parser/assembler/options** rows of the RFC records + the
  net_proto-specific audit docs (`net_proto_rfc_adherence_pass.md` CLOSED,
  `net_proto_remaining_audits.md`). Per-protocol six-file completeness.
- **pytcp** — the runtime. Owns **most** refactor docs + the
  **behavioural/runtime** rows of every RFC record + the control-plane
  APIs + multi-interface + sockets + sysctl. Largest pass; carries the
  ledger reconciliation and the open-item decisions.

---

## 4. Work blocks

### Package A — `net_addr`

**A1 — bug/issue sweep.**
- Read all 23 source files (ABC chain `Base`/`Ip`/`Address`/`IpAddress`/
  `IpNetwork`/`IfAddr`/`IpMask`/`IpWildcard` + concrete leaves +
  `errors.py` + `click_types.py` + `ip_version.py`).
- `PYTHONPATH=. python -m unittest` the net_addr suite alone; `coverage
  run --source=packages/net_addr/net_addr … ; coverage report -m` — note
  the % for the README "current state".
- Rule conformance (`net_addr.md`): every `raise` is a `NetAddrError`
  subclass (§7.1) — grep for bare-builtin raises; every concrete leaf is
  `@final` (§4.4) + the `test__abstract_stubs.py` leaf-finality test;
  multi-form `__init__` on every value type (§4.2); no public setters
  (§4.3); no `net_proto`/`pytcp` import.
- `grep -rn 'TODO\|FIXME\|XXX'` under `packages/net_addr/net_addr/`.
- Spot-check addressing-RFC fidelity (4291 scope predicates, 5952 text,
  4007 zone id, 7217/8981 IID, 1918/4193 classification) against the RFC
  text for any predicate that looks off.

**A2 — doc/RFC completeness.** net_addr has no `docs/rfc` records — confirm
this is the **conscious** decision (addressing fidelity is rule-encoded +
unit-tested) and note it in the README/commit so it reads as intentional,
not a gap. Confirm no refactor doc has an open net_addr item (the IfAddr
rename + directory-restructure + monorepo split are all shipped).

**A3 — README refresh.**
- `packages/net_addr/README.md` → expand to 100% current state: the ABC
  hierarchy diagram, the **complete** public API surface (from
  `net_addr/__init__.py` `__all__`), the one-tree exception model, the
  3.0.6-specific facts (IfAddr is now a **pure value type** — gateway
  removed, lives in the FIB; `@final` leaves; the `Ip4/6Wildcard` ACL
  type), coverage/test stats, and a pointer to `.claude/rules/net_addr.md`.
- Main `README.md` → verify the net_addr row/section is accurate.

**A4** — commit (one logical unit; doc commit may bundle README + any
fix-commits kept separate/tests-first).

---

### Package B — `net_proto`

**B1 — bug/issue sweep.**
- Per-protocol six-file conformance (`*__header` / `*HeaderProperties` /
  `*__base` / `*__parser` / `*__assembler` / `*__errors` (+ enums/options))
  across all protocols under `protocols/` (arp, dhcp4, ethernet,
  ethernet_802_3, icmp4, icmp6, ip4, ip6, ip6_{hbh,dest_opts,routing,frag},
  llc, snap, raw, tcp, udp).
- Run the net_proto suite alone + coverage; note %.
- **§9.2 wire-vs-programmer-input discipline** — confirm no `AssertionError`
  / `UnicodeDecodeError` / `NetAddrError` leaks past any `_parse` (the
  `net_proto_rfc_adherence_pass` closed these; re-verify by grepping
  `_validate_integrity`/`_validate_sanity` use `raise *Error`, not
  `assert`, and `__post_init__` wire-reachable bounds are mirrored).
- §17 anti-patterns; enum discipline (`enums.md`); `TODO`/`FIXME` grep.

**B2 — doc/RFC completeness.**
- Reconcile `net_proto_rfc_adherence_pass.md` (CLOSED) +
  `net_proto_remaining_audits.md` — confirm every protocol's wire-format
  audit is "met"/closed and there is **no open net_proto audit pass**.
- For each RFC adherence record, sanity-check the **wire-format rows**
  (header layout, parser integrity/sanity, assembler, options) still match
  the current code, and that the record's **test-coverage audit** points at
  tests that exist (per the standing "RFC adherence records include test
  audit" rule).
- Confirm every `protocols/<proto>` has its full six-file set **and** the
  mandated test matrix (header asserts / parser integrity+sanity+operation
  / assembler operation / options container + per-option).

**B3 — README refresh.**
- `packages/net_proto/README.md` → expand: the six-file authoring pattern,
  the **full protocol list with governing RFCs**, the two-axis error tree
  (`[INTEGRITY ERROR]` / `[SANITY ERROR]`), `ProtoEnum` (native
  `_missing_` for unknown wire codepoints), the wire-vs-programmer-input
  (`python -O`) discipline, `py.typed`, test/coverage stats, pointers to
  `.claude/rules/net_proto.md` and `docs/rfc/`.
- Main `README.md` → verify protocol-coverage claims are accurate.

**B4** — commit(s).

---

### Package C — `pytcp` (the big one)

**C1 — bug/issue sweep.**
- Runtime services: `Subsystem`, packet handlers (composed sub-handlers),
  sockets (TCP/UDP/raw/packet), `sysctl` registry, `timer`, RX/TX rings,
  FIB, ARP/ND caches, the per-interface model + control APIs.
- Run the pytcp unit **and** integration suites + coverage; note %.
- Test-isolation / determinism (`unit_testing.md` §10a): no leaked time
  mocks / threads (see the OOM history note in memory), module-state
  snapshot/restore, log silencing.
- Phase-3 boundary: no consumer reach-through into
  `runtime.packet_handler.*` / `tcp__session` internals; config mutations
  go through the sanctioned APIs.
- `sysctl` registry completeness vs the migration policy; `TODO`/`FIXME`.

**C2 — doc/RFC completeness (carries the decisions).**
- **Reconcile `v3_0_6_remaining_work.md` to as-shipped reality** (it's
  drifted — see §2 above). Update §1 (done-this-sweep), §2 (open items),
  §3 (on-touch), §4 (deferred), and the headline.
- Walk **every** refactor doc; confirm each status header is accurate and
  each open item is classified **Phase-1-in-scope (fix now)** vs
  **Phase-2/3 deferred-with-rationale**. Decisions to FORCE (do not leave
  silent — these are the "genuinely open, optional" items the user wants a
  conscious in/out on):
  - **DHCPv4 §5–§8** (`dhcp4_client_full_parity.md`) — ship in 3.0.6 or
    explicitly defer? (Largest in-scope-if-desired item. A
    `dhcp4__lease_cache.py` already exists — assess how much of §5 is
    already done.)
  - **RFC 3927 link-local** (`rfc3927_link_local_autoconfig.md`) — the
    header says "not started" but the client/ACD exist; reconcile the
    real state and decide in/out.
  - **ARP simultaneous-probe** (`arp_linux_parity.md` §1 #8) — in/out.
  - **PLPMTUD "remaining 20%"** — classify (likely deferred).
  - `socket_linux_parity_audit`, `tcp_codebase_improvement_plan`,
    `nud_state_machine`, `icmp_remaining_issues`, `v6_remaining_items`,
    `post_udp_session_followups`, `ip4_audit_punchlist` — confirm every
    open item is deferred-with-rationale, not a Phase-1 gap.
  - **RFC 8504 adherence record** — author now (skill) or defer.
- Fix any genuine Phase-1 gap found; update the relevant adherence record
  in the **same commit** (standing "audit-in-lockstep" rule).

**C3 — README refresh.**
- `packages/pytcp/README.md` → expand substantially: the runtime
  architecture (`Subsystem`, RX/TX rings, composed packet handlers, the
  per-interface "handler IS the interface" model), the **Phase-3
  control-plane APIs** (`stack.link` / `stack.address` / `stack.route` /
  `stack.neighbor` / `stack.sysctl` + lifecycle `init` / `add_interface` /
  `remove_interface` / `start` / `stop`), the daemon / multi-homed shape
  (zero-interface init, runtime add/remove, `make run` / `run_multi`), the
  socket API surface (BSD facade — TCP/UDP/raw/`AF_PACKET`), the no-GIL
  story (per-interface single-writer + lock-guarded global tables),
  examples, test/coverage stats, pointers to `.claude/rules/` and
  `docs/rfc/`.
- Main `README.md` → full current-state refresh: the Features region
  (lines ~32–113), the 3-dist architecture, install/examples, the current
  protocol + RFC coverage, and a "current state" line (test count, lint,
  RFC-record count). Reconcile any claim that drifted since 3.0.x.

**C4** — commit(s).

---

## 5. Final release-prep (after all three packages)

- Final reconcile of `v3_0_6_remaining_work.md` (the post-review truth).
- Confirm `__version__ == "3.0.6"` in all three `__init__.py` **and** the
  lockstep dep pins in `packages/pytcp/pyproject.toml`
  (`PyTCP-net_proto==3.0.6`, `PyTCP-net_addr==3.0.6`).
- **Push** `b181d4b8` + every review commit (only on the user's explicit
  go).
- The release itself (the `publish.yml` tag-gated OIDC jobs) is the
  **user's** trigger — do not attempt to publish.

## 6. Deliverable cadence

One package **fully** done (sweep + doc/RFC reconcile + README, committed)
before starting the next. After each package, give a `●`-led summary:
what was swept, what (if anything) was fixed, which docs/RFCs were
reconciled, and the README delta. Surface the §C2 decisions to the user as
soon as the pytcp pass reaches them (or earlier if the user wants to
pre-decide DHCPv4 §5–§8).

---

## 7. Resume prompt (paste verbatim in a fresh session after compaction)

```
Read docs/refactor/archive/v3_0_6_release_readiness.md end to end — it is the
authoritative per-package release-readiness plan for shipping the three
PyTCP 3.0.6 dists today (net_addr, net_proto, pytcp). Then read CLAUDE.md
(North Star) and the relevant .claude/rules/ files.

Baseline: branch PyTCP_3_0_6, HEAD b181d4b8, 11312 tests passing, lint
clean. NOTE b181d4b8 (remove-at-runtime example) is committed locally but
NOT pushed yet.

Work ONE package at a time, in order net_addr → net_proto → pytcp. For each:
(1) bug/issue sweep (read source, run that package's suite + coverage,
check rule-conformance, grep TODO/FIXME/XXX, fix real issues tests-first);
(2) confirm nothing in docs/refactor/*.md or docs/rfc/**/adherence.md that
belongs to Phase 1 is unfinished/stale/falsely-claimed — every open item a
conscious documented defer (Phase-2/3 = out); (3) refresh the
package-specific README.md to 100% current state AND keep the main
README.md section accurate. Don't start the next package until the current
one is fully done + committed.

Standing discipline: tests-first, one logical unit per commit, make lint +
full make test + the §7.2 docstring audit clean before each commit, commit
trailer "Co-Authored-By: Claude Opus 4.7 (1M context)
<noreply@anthropic.com>", push ONLY when I explicitly say so.

Start with net_addr. Before the pytcp pass, surface the open in/out
decisions in §C2 (DHCPv4 §5–§8, RFC 3927 link-local, ARP simultaneous-probe,
RFC 8504 record) — I want a conscious call on each, since the bar is
"nothing unfinished that belongs to this phase." The v3_0_6_remaining_work.md
ledger is DRIFTED (pre-dates this session's cascade/fallback/FIB-lock work) —
reconcile it in the pytcp pass. Re-verify every claim against code; the
plan is a snapshot.
```

---

## 8. Cross-references

- `CLAUDE.md` — North Star (Phase 1 host / Phase 2 router / Phase 3
  kernel-boundary); the conformance precedence (RFC → Linux tiebreaker).
- `docs/refactor/archive/v3_0_6_remaining_work.md` — the (drifted) remaining-work
  ledger to reconcile.
- `~/.claude/plans/dreamy-jingling-steele.md` — up-to-date multi-interface
  migration record (no-GIL story, control/egress de-fallback, remove
  cascade, FIB lock, remove-at-runtime example).
- `.claude/rules/{net_addr,net_proto,pytcp,source_files,unit_testing,
  integration_testing,enums,typing,python_features,feature_implementation}.md`.
- `.claude/skills/rfc_adherence_audit` — author/refresh an RFC adherence
  record (RFC 8504, or any reconcile).
