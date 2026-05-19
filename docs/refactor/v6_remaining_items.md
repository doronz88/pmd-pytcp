# IPv6 Punch List — Remaining Items After Extension-Header Deployment

**Status: ALL ITEMS SHIPPED.** Originally tracked six follow-
ups (#281-#286) deferred from the extension-header
deployment; all closed in the work block on top of commit
`60077ad7`. This document is retained for archaeology — see
the per-item sections below for the commit hashes that
landed each one.

**Branch:** `PyTCP_3_0__pre_release`.
**Final commits:** `604eebbf` / `909c3e06` / `d23d17bb` /
`88d09251` / `3459cddf` (plus this doc commit). The
fragmentation rework that #281 / #282 build on lives in
`9a19194a` / `c2216640` / `8b72fa99` / `dd5dda8f` /
`6c1c8634` / `8842c8f1`.

---

## State at deployment-plan completion (commit `60077ad7`)

| Area | Status |
|---|---|
| `IpProto` enum (extension-header next-header values) | shipped — Phase -1 / 0 |
| `ip6_hbh` package (header / parser / assembler / errors / 5 options) | shipped — Phases 1-4 |
| `ip6_dest_opts` package (header / parser / assembler / errors / 3 options) | shipped — Phases 5-6 |
| `ip6_routing` package + RH0 hard-drop | shipped — Phase 7 |
| Chain-walker dispatch in IPv6 RX | shipped — Phase 8 |
| MLDv2 outbound HBH+RouterAlert | shipped — Phase 9 |
| Adherence records for RFC 8200 §4 + RFC 5095 | shipped — Phase 10 |

Tests: 9317 passing, 4 skipped, 0 failed. `make lint` clean.

---

## Remaining items (priority order)

### #281 — Overlap fragment detection (RFC 5722 / RFC 8504 §16)

**Why first:** security MUST. Closes a known fragmentation-
attack vector. RFC 5722 §3 mandates silent discard of the
entire datagram (including fragments not yet received) on
any overlap.

**Implementation sketch (paused mid-design):**

1. Add a `discarded: bool = False` field to `IpFragData` in
   `packages/pytcp/pytcp/lib/ip_frag.py`, plus a `mark_discarded()` helper
   (frozen-dataclass mutation via `object.__setattr__`).
2. In `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6_frag__rx.py::__defragment_ip6_packet`:
   - On entry, check `if flow_id in self._ip6_frag_flows
     and self._ip6_frag_flows[flow_id].discarded:` — bump
     `ip6_frag__overlap__drop` counter and return None.
   - Before storing a new fragment, walk existing fragments
     and check overlap (two ranges `[a, b)` and `[c, d)`
     overlap iff `a < d and c < b`).
   - On overlap: call `mark_discarded()`, clear the
     `payload` dict to free memory, bump counter, return
     None. Subsequent fragments hit the discarded-flow
     check above and silently drop.
3. Add `ip6_frag__overlap__drop: int = 0` to
   `packages/pytcp/pytcp/lib/packet_stats.py::PacketStatsRx` and bump the
   `field_count` constant in
   `packages/pytcp/pytcp/tests/unit/lib/test__lib__packet_stats.py` (was
   134 after Phase 8a; will be 135 after this).

**Strict-vs-lenient:** RFC 5722 strict reading discards even
exact-duplicate fragments (offset=A, len=L received twice).
Linux is somewhat lenient. **Pick strict** for security; a
benign retransmit still discards the in-progress datagram
but the sender will retransmit the whole thing. Cite "RFC
5722 §3" in the commit body.

**Latent bug encountered during this investigation, NOT in
scope for #281 but worth a separate follow-up commit:**

The flow-cleanup expression at line 95 of
`packet_handler__ip6_frag__rx.py` is inverted:
`self._ip6_frag_flows[flow].timestamp - time() < stack.IP6__FRAG_FLOW_TIMEOUT`
is `negative_age < positive_timeout` — always true. So
expired flows are never reaped. The fix is
`time() - timestamp < IP6__FRAG_FLOW_TIMEOUT`. This impacts
RFC 8504 §16's "reassembly MUST be possible in 60 seconds
or less" implicitly (the flow buffer just grows). Mention in
the #281 commit body or split into its own commit.

**Tests-first per CLAUDE.md MUST:**

Write integration tests at
`packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rx__overlap_fragments.py`
(create the file). Test cases:

- Two fragments where the second overlaps the first → no TX,
  counter `ip6_frag__overlap__drop == 1`, flow marked
  discarded.
- Three fragments where third overlaps first → same.
- Same-offset duplicate → strict RFC 5722 path: drop.
- Subsequent fragment after discard → silently dropped (no
  reassembly even if the new fragment would complete the
  datagram).
- Regression: non-overlapping multi-fragment still
  reassembles cleanly (counter `ip6_frag__defrag` bumps;
  transport handler runs).

§7.2 audit script before staging, as for every other test
file in this project.

**Reference clauses for commit body / test docstrings:**

- `Reference: RFC 5722 §3 (silent-discard on fragment overlap).`
- `Reference: RFC 8504 §16 (reassembly time limit + buffer hygiene).`

### #282 — Atomic fragment fast-path (RFC 8200 §4.5)

A fragment with `Offset=0` AND `M=0` is a complete datagram
in a single fragment. RFC 8200 §4.5 says these MAY bypass
the reassembly buffer entirely.

**Implementation sketch:** in
`__defragment_ip6_packet`, add an early-return when the
parser produces `offset=0, flag_mf=False`: build the
synthetic reassembled `PacketRx` directly from the single
fragment's payload bytes (no flow-table allocation, no
storage, no deletion). The existing slow path still handles
multi-fragment datagrams.

**Test surface:** integration test for atomic-fragment
delivery; verify no flow-table entry is created. Counter
`ip6_frag__atomic__defrag` (new).

`Reference: RFC 8200 §4.5 (atomic fragment fast-path optimisation).`

### #283 — RA prefix lifetime validation (RFC 4862 §5.5.3)

PyTCP's RA processing currently ingests prefix options
without validating preferred-vs-valid lifetime ordering or
the 2-hour rule on extending an existing prefix's lifetime.

**Implementation sketch:** in the RA-handler (find via
`grep RouterAdvertisement packages/pytcp/pytcp/stack/`), per RFC 4862
§5.5.3 step (e):

- If `preferred_lifetime > valid_lifetime` → silently ignore
  this prefix option (don't update SLAAC state).
- If the option would extend `valid_lifetime` of an existing
  prefix beyond 2 hours past now AND the option's
  `valid_lifetime > 2 hours` → cap the new `valid_lifetime`
  at `max(2 hours, current_remaining_lifetime)`.

**Tests:** unit-test the per-prefix lifetime validation
helper. Integration: send an RA with bad lifetimes; assert
prefix not added (or added with capped lifetime).

`Reference: RFC 4862 §5.5.3 (Router Advertisement prefix lifetime processing).`

### #284 — NS DAD validation (RFC 4861 §7.2.3)

Today's NS handler doesn't enforce all the §7.2.3 invariants
for DAD-context Neighbor Solicitations:
- Source Address MUST be unspecified (`::`) for DAD NS.
- The Target Address MUST NOT be a multicast address.
- ICMPv6 Hop Limit MUST be 255 (already validated via
  RFC 4861 §6.1.1 / §7.1.1 pre-existing checks — verify).

**Implementation sketch:** add the missing validations to
the NS RX handler. On failure: silent drop + counter bump
(do NOT emit ICMP — `Source Address == ::` is the legitimate
DAD case, but a NON-DAD NS with `Source == ::` is malformed;
silent drop matches Linux).

**Tests:** integration tests with various NS frames covering
each invariant.

`Reference: RFC 4861 §7.2.3 (NS validation rules).`

### #285 — MLDv2 RX stub cleanup + Phase-2 marker

Today the MLDv2 RX handler is a no-op stub. Mark it
`# Phase 2: MLDv2 querier role goes here`, document why
host-stack scope doesn't process incoming MLD2 messages
(host doesn't run a multicast querier — that's a router-
mode feature), and tighten the stub to bump the right
counter rather than silently dropping into the unknown-type
path.

**Implementation:** small change in the ICMPv6 RX dispatch.
No new tests; just touches the comment + counter.

`Reference: RFC 3810 §5 (MLDv2 querier role; Phase 2 host-stack non-goal).`

### #286 — RFC 8504 adherence record + v6 deliberate-skip docs

Per the RFC adherence audit pattern (see
`docs/rfc/ip6/rfc8200__ipv6/adherence.md` as the canonical
example), write
`docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` covering
all RFC 8504 host-requirement clauses. For each, mark
`shipped` / `deferred` / `deliberately skipped` with citation.

The "deliberately skipped" category should explicitly cite
PyTCP's North Star non-goals (e.g. mobility extensions →
RFC 6275 RH2 not implemented; AH/ESP non-goals; etc.).

**No code changes.** Pure documentation. Follows the
`rfc_adherence_audit` skill at `.claude/skills/`.

`Reference: RFC 8504 (IPv6 Node Requirements).`

---

## Cross-cutting reminders for the next session

These are gotchas that bit me during the deployment plan; a
fresh agent will hit them too without warning.

1. **Tests-first MUST applies (CLAUDE.md).** Every behavioural
   change opens with a failing test. The §7.2 audit script in
   `.claude/rules/unit_testing.md` runs against any test file
   you write or modify. No `Per RFC X §Y` inline in
   docstrings — use the trailing `Reference:` line.

2. **Black reformats long messages.** When `make lint`
   reports an `E501 line too long`, wrap the offending
   `msg=` to a multi-line string literal (parenthesised
   `f"...""..."` form). Black's reformat is benign but it
   does happen.

3. **`from_proto` updates land with each protocol.** When
   adding a new protocol package that shows up as an IPv6
   payload, also add the matching `isinstance` arm to
   `IpProto.from_proto` in `packages/net_proto/net_proto/lib/enums.py`. This
   bit me in Phase 8b — Phase 0 deferred the wiring with
   "as packages ship" but I forgot until the integration
   test caught it.

4. **`packet_stats.py::field_count` test guard.** Adding any
   new counter requires bumping the constant in
   `packages/pytcp/pytcp/tests/unit/lib/test__lib__packet_stats.py`
   (currently 134 after Phase 8a). The test fails loudly if
   you forget.

5. **Chain walker `_payload` re-anchoring.** The chain
   walker in `_phrx_ip6__walk_chain` mutates
   `packet_rx.ip6._payload` after each extension header to
   reflect the post-header frame, so downstream transport
   parsers' integrity check (which compares `ip6.dlen`
   against `len(frame)`) doesn't trip on chain-consumed
   frames. If a future extension-header parser is added,
   the chain-walker's re-anchor branch handles it for free
   (it's at the end of the loop body).

6. **`IP6__FRAG_FLOW_TIMEOUT` cleanup is broken** — see
   the #281 entry above. Worth fixing in the #281 commit
   or splitting out.

7. **Phase 8a left a partial gap on RX-side HBH+transport.**
   The #279 commit message documents that the chain walker
   had a latent bug for HBH+ICMP6 (and HBH+UDP, HBH+TCP) on
   the RX side because transport parsers' integrity check
   uses `ip6.dlen` not `len(frame)`. The Phase 9 commit
   `_payload` re-anchor fix closed it. If a regression
   re-breaks this, the commit-message archaeology (`git log
   --grep="_payload re-anchor"`) is the breadcrumb.

8. **Commit cadence.** One concern per commit. Each commit
   ships with `make lint` + full test suite passing + §7.2
   audit clean. Push only on explicit user request.

---

## §99 Resume prompt (paste verbatim after `/compact`)

```
I'm resuming PyTCP's v6 punch-list work from a context-
compacted state. The IPv6 extension-header deployment plan
(docs/refactor/ipv6_extension_headers_plan.md) is COMPLETE
through commit 60077ad7. The remaining v6 items are tracked
at docs/refactor/v6_remaining_items.md.

Read these in order before any code:

  1. docs/refactor/v6_remaining_items.md (this file's source
     of truth — what's done, what's left, gotchas)
  2. CLAUDE.md (Project North Star: Linux parity in two
     phases; Tests First MUST; coding conventions index)
  3. .claude/rules/feature_implementation.md (commit
     discipline; tests-first procedure; "Linux as tiebreaker"
     rule)
  4. .claude/rules/unit_testing.md (test-authoring rule;
     §7.2 self-audit script is non-negotiable per commit)
  5. `.claude/rules/source_files.md` / `net_proto.md` / `pytcp.md` (source-authoring rule)

After reading, confirm you understand:

  - Which task IDs (#281-#286) remain and what each one is.
  - The cross-cutting reminders listed in
    'v6_remaining_items.md §"Cross-cutting reminders"'
    (8 gotchas).
  - The §7.2 audit script blocks every commit.

Then ask the user which item to start with. If they say
"go" or "next", start with #281 (overlap fragment
detection — security MUST).

Branch: PyTCP_3_0__pre_release
Tasks: see #281-#286 in the task list (all currently pending
or in_progress for #281 if it was started).

Do NOT push without explicit user request. Commit after
each phase; user pushes when ready.
```

---

End of remaining-items document.
