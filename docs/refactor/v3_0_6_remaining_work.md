# PyTCP 3.0.6 — Remaining Work Ledger

**Authored:** 2026-05-24 on `PyTCP_3_0_6` (HEAD `081c5059`).
**Reconciled:** 2026-05-25 during the per-package release-readiness pass
(`v3_0_6_release_readiness.md`) — §2 is now empty (all formerly-open
optional items shipped or were already present); see §1.2.
**Suite:** ~11,370 passing, lint clean, source tree zero TODO/FIXME/XXX.
**Purpose:** the single authoritative "what's left for 3.0.6" list,
produced by a full staleness sweep of all `docs/refactor/*.md` (each
claim cross-checked against the actual code + referenced commits).

---

## 0. Headline

**Nothing blocks 3.0.6, and the optional host-stack tail is now also
closed.** Every major feature/conformance track shipped; the host stack
is feature-complete. As of the 2026-05-25 release-readiness pass the
three items the 2026-05-24 ledger listed as "genuinely open optional"
(§2) are all resolved. The branch is green, lint-clean, and the source
tree carries no TODO markers.

If the answer to "is 3.0.6 done?" is needed in one word: **yes** (host
stack). What remains (§3 on-touch, §4 future-phase) is by-design out of
3.0.6 host scope.

---

## 1. Done

### 1.1 The 2026-05-24 reconciliation sweep

Corrected six stale status lines + one snapshot annotation (commit
`081c5059`). Bodies kept as archaeology; only the headers changed:

| Doc | Corrected to | Verifying evidence |
|-----|--------------|--------------------|
| `address_api_unification.md` | SHIPPED | unified `AddressApi`; `5d3cb453` + `5dd20b22` |
| `ipv6_extension_headers_plan.md` | SHIPPED | `ip6_hbh/` `ip6_dest_opts/` `ip6_routing/` parsers + RX chain-walker + RFC 8200/5095 records |
| `icmp_demux_pmtud_plan.md` | SHIPPED | demux + `pmtu_cache`; PMTUD RFCs via `plpmtud_unified_engine.md` |
| `packet_handler_composition.md` | SHIPPED | composed sub-handlers, `6a7f13d8..3abdcf5c` |
| `packet_handler_rewrite_plan.md` | SUPERSEDED/DELIVERED | shipped incrementally; Phase-2 forwarding stays a stub |
| `raw_link_socket.md` | COMPLETE | full sd-ipv4acd end state; RX detector deleted `0d0aef0b` |
| `icmp_remaining_issues.md` | closed historical snapshot | no open ICMP issues remain |

**Note:** `v6_remaining_items.md` *looks* stale ("ALL ITEMS SHIPPED" over
a body full of implementation sketches) but is actually **correct** — the
body lists per-item commit hashes; the sketches are archaeology. Left
untouched. Don't "fix" it.

### 1.2 The 2026-05-25 release-readiness pass

Closed the entire §2 optional tail and refreshed the package READMEs.
Per-package (net_addr → net_proto → pytcp):

- **net_addr** — value-type coverage gaps closed to 100% on the touched
  files (`2bf975e6`); README refreshed (`4e0c8a70`).
- **net_proto** — README expanded; `net_proto_remaining_audits.md` status
  corrected to CLOSED (all twelve A–L audits done); §9.2 wire-vs-
  programmer-input discipline re-confirmed AST-clean (`09bc4b1e`).
- **DHCPv4 Phase 7 — Classless Static Routes (RFC 3442, option 121)** —
  the largest formerly-open item. Shipped across the option-121 codec
  (`bb99cb34`), RFC 3396 concatenation / Phase 8.3 (`a9eae78f`), the
  client request/install with option-3 suppression (`1560422f`), and the
  adherence + plan reconciliation (`938d5165`). (Phases 5 INIT-REBOOT +
  lease cache and 6 DNAv4 had already shipped before this ledger was
  first written — the 2026-05-24 §2.1 text under-counted them.)
- **`fib.py`** — removed an unreachable `return` in `RouteTable.snapshot`
  (`084f68b8`).
- **stack** — re-exported `Route` / `RouteProtocol` / `RouteScope` from
  the sanctioned `pytcp.stack` surface so consumers (e.g.
  `examples/stack.py`) no longer reach into `pytcp.runtime.fib`
  (`02b244ce`).

---

## 2. Genuinely open — optional host-stack items

**None.** The three items the 2026-05-24 ledger listed here are resolved:

- **DHCPv4 Phases 5–8** — Phases 5 (INIT-REBOOT + `dhcp4__lease_cache.py`),
  6 (DNAv4), 7 (Classless Static Routes), and 8.1/8.2/8.3 are shipped.
  Only **8.4 (Option Overload parse)** and **Phase 9 (RFCs 4702 / 3203 /
  8910)** remain, both explicitly deferred — see
  `dhcp4_client_full_parity.md`.
- **ARP simultaneous-probe detection (RFC 5227 §2.1.1)** — shipped
  (commit `3f051584`); `arp_linux_parity.md` §0 status table records it.
  (The 2026-05-24 §2.2 entry and the `arp_linux_parity.md` §1 prose were
  both stale; the §1 prose is the remaining cleanup, tracked in that doc.)
- **RFC 8504 adherence record** — already present at
  `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md`; the 2026-05-24
  §2.3 "deferred, doc-only" claim was stale.

`arp_linux_parity` §3 item #10 (`MAX_CONFLICTS` / `RATE_LIMIT_INTERVAL`)
remains **dormant by design** — there is no candidate-rotation path to
rate-limit yet. Leave until that exists.

---

## 3. On-touch ongoing — by design, NOT a dedicated sweep

Do **not** open these as standalone tasks — the rules forbid piecemeal
sweeps (`pytcp.md` §2.4, `sysctl_framework.md` §8). They land naturally
as feature work touches the relevant package.

- **sysctl Phase-3 per-package constant migration** — TCP / ICMP4 /
  ICMP6 / UDP `*__constants.py` policy constants not yet registry-backed.
  Migrate the *whole* touched package's policy constants in the same
  commit when you touch it for any other reason. `sysctl_framework.md`.
- **Enum migration on touch** — bare-int → IntEnum/ProtoEnum per
  `enums.md` §5; fix in the same commit when you touch a file.
- **Legacy typing modernisation on touch** — `python_features.md` §22 /
  `typing.md` §23.
- **Phase-3 boundary cleanups** — land on-touch; resist dedicated sweeps
  (the `pytcp.stack` Route re-export in §1.2 is an example landed at the
  boundary).

---

## 4. Deferred / future-phase — OUT of 3.0.6 host-stack scope

Tracked, not deferrable-within-3.0.6 — these are Phase-2/Phase-3 North
Star items (see `CLAUDE.md`). Do not start without an explicit decision
to expand scope.

- **Phase-2 router/forwarding** behind the RFC 1812 `forward_or_deliver`
  seam (currently a deliver-locally-or-drop stub): FIB transit routes,
  IP forwarding, ICMP Redirect generation, PMTU on transit, IGMP/MLD
  querier role. DHCPv4 option-121 router-0.0.0.0 (on-link) routes also
  wait on the Phase-2 per-interface oif on DHCP-learned routes.
- **Socket Linux parity — HIGH/MEDIUM/LOW tail** + the **X1 stack-thread-
  safety audit** (overlaps packet-handler concurrency review). Phase 1
  fully shipped, Phase 2 mostly; the rest is deferred-with-rationale.
  `socket_linux_parity_audit.md`.
- **TCP god-class decomposition** (`tcp_codebase_improvement_plan.md`
  #1–#5). These are **internal code-quality refactors, not conformance**;
  status partly *unverified* — re-audit before treating any as "open".
  Deferrable.
- **DHCPv4 Phase 8.4 / Phase 9** (Option Overload parse; RFCs 4702 / 3203
  / 8910) — deferred per `dhcp4_client_full_parity.md`.

---

## 5. Cross-references

- `CLAUDE.md` — Project North Star (Phase 1 host / Phase 2 router /
  Phase 3 kernel-boundary).
- `v3_0_6_release_readiness.md` — the 2026-05-25 per-package pass that
  closed §2.
- `dhcp4_client_full_parity.md` — DHCPv4 phase status (Phases 0–7 +
  8.1/8.2/8.3 shipped).
- `arp_linux_parity.md` — ARP parity status (#8 shipped).
- `v6_remaining_items.md` — IPv6 Node Requirements context (accurate, not
  stale).
- `socket_linux_parity_audit.md`, `tcp_codebase_improvement_plan.md` —
  §4 deferred tracks.
- `sysctl_framework.md` — §3 on-touch migration policy.
