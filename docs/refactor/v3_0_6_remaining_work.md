# PyTCP 3.0.6 — Remaining Work Ledger

**Authored:** 2026-05-24 on `PyTCP_3_0_6` (HEAD `081c5059`).
**Reconciled:** 2026-05-25 (per-package release-readiness pass,
`v3_0_6_release_readiness.md`) and **2026-05-27** (IGMP track closed —
§9 source-specific multicast + the §3.1 data-plane RX source filter
shipped; §2.0 now records the IGMP host stack as feature-complete).
**Suite:** ~11,687 passing, lint clean, source tree zero TODO/FIXME/XXX.
**HEAD at last reconcile:** `678a6550`.
**Purpose:** the single authoritative "what's left for 3.0.6" list,
produced by a full staleness sweep of all `docs/refactor/*.md` (each
claim cross-checked against the actual code + referenced commits).

---

## 0. Headline

**Nothing blocks 3.0.6.** Every major feature/conformance track
shipped; the host data path is feature-complete and the branch is
green, lint-clean, with no source TODO markers. The three items the
2026-05-24 ledger listed as "genuinely open optional" (§2) are
resolved.

**IGMP / IPv4 multicast group membership is now feature-complete**
(the IPv4 analog of the shipped MLDv2 listener): the host membership
machine, RFC 3376 §7 v1/v2 querier fallback, the §5.2 timers, §9
source-specific multicast (control plane), and the §3.1 data-plane RX
source-delivery filter (`ip_mc_sf_allow`, UDP) all shipped (see §2.0).
A 2026-05-25 freshness sweep of the refactor docs also corrected
several stale claims (§1.2).

If the answer to "is 3.0.6 done?" is needed in one word: **yes** for
the host data path; the IGMP host stack is complete (the RAW-socket
data-plane source gate is a natural extension with no current
consumer, and the IGMPv3 router/querier role is Phase-2).

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
- **Refactor-doc freshness sweep** — a full per-doc re-verification
  against code (prompted by the 2026-05-24 sweep having missed the
  stale `rfc3927` / `arp #8` headers) corrected: `tcp_codebase_
  improvement_plan.md` Concern #5 (falsely claimed PMTUD / ICMP→TCP
  demux "Missing" with `# TODO`s — all shipped, zero TODOs);
  `rfc6724_source_selection.md` (stale "single remaining piece" intro
  — all phases shipped); `nd_session_resume.md` / `nd_tier3_resume.md`
  (listed shipped Optimistic-DAD / RFC 8981 / RFC 6724 / Tier 3 work
  as "what's left"). And surfaced the IGMP gap (§2.0) the prior sweep
  missed.

---

## 2. Genuinely open Phase-1 items — deferred with a plan (not blocking)

### 2.0 IGMP — IPv4 multicast group membership  (host stack complete)

Source of truth: `docs/refactor/igmp_host_membership.md` (detailed
phased plan, authored 2026-05-25). **Substantially shipped 2026-05-25/26**
(`2477b18e`..`70763cd8`): the net_proto IGMP codec (Phase 0), the
per-interface IPv4 group state + L2 mapping (Phase 1), the
`stack.membership` API + `IP_ADD/DROP_MEMBERSHIP` socket options
(Phase 2), the RX query-response state machine (Phase 3), the
unsolicited state-change Reports on join/leave (Phase 4), and the
sysctls + RFC 3376 §5.1 robustness retransmit (Phase 5), with the
RFC 1112 / 2236 / 3376 adherence records (Phase 6). PyTCP now reaches
RFC 1112 **Level 2** (multicast send + receive + IGMP group management,
the IPv4 analog of the shipped MLDv2).

**The RFC 3376 §7 older-version (IGMPv1/v2) querier-interoperation
gap is now closed** (shipped 2026-05-26, plan
`igmp_version_fallback.md`): the per-interface Host Compatibility Mode
machine, v2-form per-group Reports, the IGMPv2 Leave Group to
224.0.0.2, v1/v2 report suppression, and the `igmp.version` /
`igmp.query_interval` knobs. The §5.2 Group-Specific Query per-group
response timer is also shipped (2026-05-26).

**The §9 source-specific multicast gap is now closed (control plane)**
— shipped 2026-05-26/27 across five phases, plan
`igmp_source_specific_multicast.md`: the per-socket / per-interface
source-filter model + RFC 3376 §3.2 merge, the source-filter socket
options (`IP_ADD_SOURCE_MEMBERSHIP` / `IP_DROP_SOURCE_MEMBERSHIP` /
`IP_BLOCK_SOURCE` / `IP_UNBLOCK_SOURCE`), the §5.1 source-bearing
state-change records (ALLOW / BLOCK / CHANGE_TO_*), and the §5.2
Group-and-Source-Specific Query IS_IN(A∩B) / IS_IN(B−A) math. The
**data-plane** RX source-delivery filter (`ip_mc_sf_allow` — dropping a
received multicast datagram from a non-admitted source before socket
delivery) also shipped for UDP (`Ip4MulticastFilter.allows` gating
`UdpRxHandler`, counter `udp__multicast_source_filtered__drop`). RFC
3376 adherence flipped to met for §3.1 / §3.2 / §4.2.12 / §5.1 / §5.2 /
§9 (control plane + UDP data-plane filter). The IGMP host stack is now
feature-complete; the RAW-socket data-plane source gate is a natural
extension with no current consumer, and the IGMPv3 router/querier role
is Phase-2 / future work. (Surfaced and decided during the 2026-05-25
release-readiness pass; the 2026-05-24 ledger missed it — it lived only
in `ip4_audit_punchlist.md` item E.)

### 2.1 PLPMTUD active probe-segment emit  (lower-stakes)

`plpmtud_unified_engine.md` "remaining 20%" — the two transport-specific
rows (probe-segment emit + probe ACK/loss detection, the RFC 4821 /
8899 *active* path). **Passive** ICMP-driven PMTUD (RFC 1191 / 8201) is
shipped; the active packetization-layer probe is the enhancement on top
and is often disabled-by-default even on Linux (`tcp_mtu_probing`).
Deferred.

### 2.2 Resolved since the 2026-05-24 ledger

The three items that ledger listed as open are resolved:

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

## 5. Resume prompt (paste verbatim in a fresh session)

```
Read docs/refactor/v3_0_6_remaining_work.md end to end — it is the
authoritative "what's left for PyTCP 3.0.6" ledger (reconciled 2026-05-27,
HEAD 678a6550 on PyTCP_3_0_6). Then read CLAUDE.md (Project North Star)
and the relevant rule files in .claude/rules/.

Context: 3.0.6 is feature-complete for a host stack — suite green
(~11,687), lint clean, zero source TODOs, every major host track shipped.
The IGMP host stack closed out 2026-05-27 (§2.0): membership + §7 v1/v2
fallback + §5.2 timers + §9 source-specific multicast (control plane) +
the §3.1 UDP data-plane RX source-delivery filter. There is NO blocking
or in-scope-required host work left.

The only genuinely-open OPTIONAL host item is §2.1 — PLPMTUD active
probe-segment emit (RFC 4821 / 8899; passive ICMP-driven PMTUD already
ships, the active packetization-layer probe is the enhancement on top,
disabled-by-default even on Linux). Everything else is either §3
on-touch-only (do NOT open as a standalone task) or §4 deferred
future-phase (Phase-2 router/forwarding, the socket Linux-parity tail +
X1 stack-thread-safety audit, TCP god-class decomposition, DHCPv4
8.4/Phase 9) — do not start a §4 track without an explicit decision to
expand scope beyond the 3.0.6 host stack.

I want to work on: <PICK ONE, or state a new task>
  - 2.1 PLPMTUD active probe — source of truth
        docs/refactor/plpmtud_unified_engine.md ("remaining 20%").
  - a §4 deferred track (name it + confirm the scope-expansion decision).
  - something else entirely (state it).

Follow the standing discipline: tests-first (a failing test that pins the
RFC clause before any fix), one logical unit per commit, make lint + full
make test + the §7.2 docstring audit clean before each commit, modernise
legacy typing/Python forms on touch, RFC-ground every behavioural claim,
commit trailer "Co-Authored-By: Claude Opus 4.7 (1M context)
<noreply@anthropic.com>", and push only when I explicitly say so. Refresh
the relevant adherence record in the same commit as the code when an
RFC-governed behaviour changes. Touch this ledger to tick an item off
when it lands.

Before writing code, confirm the chosen item is still open (re-grep /
re-read the source-of-truth doc) — this ledger is a snapshot and may have
drifted.
```

---

## 6. Cross-references

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
