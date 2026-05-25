# PyTCP 3.0.6 — Remaining Work Ledger

**Authored:** 2026-05-24 on `PyTCP_3_0_6` (HEAD `081c5059`).
**Suite:** ~11,300 passing, lint clean, source tree zero TODO/FIXME/XXX.
**Purpose:** the single authoritative "what's left for 3.0.6" list,
produced by a full staleness sweep of all 34 `docs/refactor/*.md`
(each claim cross-checked against the actual code + referenced
commits). Use the resume prompt in §5 to pick this up in a fresh
session.

---

## 0. Headline

**Nothing blocks 3.0.6.** Every major feature/conformance track shipped;
the host stack is feature-complete. The branch is in sync with origin,
the suite is green, and the source tree carries no TODO markers. The
items below are all **optional** — they are catalogued so the choice of
"what next" is greppable, not because anything is unfinished or broken.

If the answer to "is 3.0.6 done?" is needed in one word: **yes** (host
stack). The remaining buckets are polish, deferred-by-design, and
future-phase.

---

## 1. Done this sweep (2026-05-24)

A reconciliation pass corrected six stale status lines + one snapshot
annotation (commit `081c5059`). Bodies kept as archaeology; only the
headers changed. The docs whose status now reflects as-shipped reality:

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
body lists per-item commit hashes (`604eebbf` etc.); the sketches are
archaeology. Left untouched. Don't "fix" it.

---

## 2. Genuinely open — optional, in-scope-if-desired (none blocking)

Ordered by size / value. Each is a real host-stack item that *could* land
in 3.0.6; none is required for it.

### 2.1 DHCPv4 client — Phases 5–8  (largest open track)

Source of truth: `docs/refactor/dhcp4_client_full_parity.md` §5–§8.
Phases 0–4.x shipped (CID-in-REQUEST, xid validation, NAK handler,
lease-time dataclass, retransmission backoff, DHCPDECLINE+ACD via
`Ip4Acd`, DUID/IAID, lifecycle FSM + per-interface client + multi-homed
egress via `SO_BINDTODEVICE`). Outstanding:

- **Phase 5 — INIT-REBOOT + cached-lease persistence.** On restart,
  reuse a stored lease (DHCPREQUEST in INIT-REBOOT state) instead of a
  fresh DISCOVER. Needs a lease-cache store (no `dhcp4_lease_cache.py`
  exists today). RFC 2131 §3.2.
- **Phase 6 — DNAv4** (RFC 4436). Fast reconfirm of a cached lease via
  ARP probe of the recorded gateway before committing to INIT-REBOOT.
- **Phase 7 — Classless Static Routes** (RFC 3442, option 121). Now
  **unblocked** — the host-mode FIB + Route API shipped
  (`routing_table_host_mode.md`), so installing DHCP-supplied routes has
  a home. Parse option 121, install via the Route API.
- **Phase 8 — option polish.** Remaining standard options
  (domain-search, NTP, etc.) the audit flagged as low-value.

Phase 9 (RFCs 4702 / 3203 / 8910) is explicitly **deferred** — leave it.

### 2.2 ARP simultaneous-probe detection  (small parity gap)

Source: `docs/refactor/arp_linux_parity.md` §1 item #8. RFC 5227 §2.1.1
— detect another host probing the *same* candidate address concurrently
during ACD and treat it as a conflict. Implementation sketch is in the
doc. Needs an `arp__op_request__simultaneous_probe` stat counter + RX
branch in the `Ip4Acd` probe window. Small, self-contained, tests-first.

(`arp_linux_parity` §3 item #10 — `MAX_CONFLICTS` / `RATE_LIMIT_INTERVAL`
— is **dormant by design**: there is no candidate-rotation path to rate-
limit yet. Leave until that exists.)

### 2.3 RFC 8504 adherence record  (doc-only)

Source: `docs/refactor/v6_remaining_items.md` #286. The IPv6 Node
Requirements implementation work (#281–#285) shipped; only the per-RFC
**adherence record** under `docs/rfc/ip6/` was deferred. Use the
`rfc_adherence_audit` skill. Pure documentation; no code.

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

---

## 4. Deferred / future-phase — OUT of 3.0.6 host-stack scope

Tracked, not deferrable-within-3.0.6 — these are Phase-2/Phase-3 North
Star items (see `CLAUDE.md`). Do not start without an explicit decision
to expand scope.

- **Phase-2 router/forwarding** behind the RFC 1812 `forward_or_deliver`
  seam (currently a deliver-locally-or-drop stub): FIB transit routes,
  IP forwarding, ICMP Redirect generation, PMTU on transit, IGMP/MLD
  querier role. `packet_handler_rewrite_plan.md`.
- **Socket Linux parity — HIGH/MEDIUM/LOW tail** + the **X1 stack-thread-
  safety audit** (overlaps packet-handler concurrency review). Phase 1
  fully shipped, Phase 2 mostly; the rest is deferred-with-rationale.
  `socket_linux_parity_audit.md`.
- **TCP god-class decomposition** (`tcp_codebase_improvement_plan.md`
  #1–#5): extract `CcState`, split `_process_ack_packet`, decompose
  `_transmit_packet`, etc. `tcp__session.py` is ~4.4k lines. These are
  **internal code-quality refactors, not conformance** — status partly
  *unverified* (e.g. `TcpStack` does exist, contrary to a quick grep), so
  re-audit before treating any as "open". Deferrable.
- **Phase-3 boundary cleanups** — land on-touch; resist dedicated sweeps.

---

## 5. Resume prompt (paste verbatim in a fresh session)

```
Read docs/refactor/v3_0_6_remaining_work.md end to end — it is the
authoritative "what's left for PyTCP 3.0.6" ledger (authored 2026-05-24,
HEAD 081c5059). Then read CLAUDE.md (Project North Star) and the relevant
rule files in .claude/rules/.

Context: 3.0.6 is feature-complete for a host stack — suite green
(~11,300), lint clean, zero source TODOs, all major tracks shipped. The
ledger's §2 lists the only genuinely-open OPTIONAL items (none blocking);
§3 is on-touch-only; §4 is deferred future-phase.

I want to work on: <PICK ONE of §2>
  - 2.1 DHCPv4 Phases 5-8 (INIT-REBOOT + lease cache / DNAv4 / Classless
        Static Routes / option polish) — largest track; source of truth
        docs/refactor/dhcp4_client_full_parity.md §5-8.
  - 2.2 ARP simultaneous-probe detection (RFC 5227 §2.1.1) — small;
        docs/refactor/arp_linux_parity.md §1 #8.
  - 2.3 RFC 8504 adherence record — doc-only; use the rfc_adherence_audit
        skill.

Follow the standing discipline: tests-first (a failing test that pins the
RFC clause before any fix), one logical unit per commit, make lint + full
make test + the §7.2 docstring audit clean before each commit, commit
trailer "Co-Authored-By: Claude Opus 4.7 (1M context)
<noreply@anthropic.com>", and push only when I explicitly say so. Touch
docs/refactor/v3_0_6_remaining_work.md to tick the item off when it lands.

Before writing code, confirm the chosen item is still open (re-grep /
re-read the source-of-truth doc) — this ledger is a snapshot and may have
drifted.
```

---

## 6. Cross-references

- `CLAUDE.md` — Project North Star (Phase 1 host / Phase 2 router /
  Phase 3 kernel-boundary).
- `dhcp4_client_full_parity.md` — §2.1 source of truth.
- `arp_linux_parity.md` — §2.2 source of truth.
- `v6_remaining_items.md` — §2.3 context (note: accurate, not stale).
- `socket_linux_parity_audit.md`, `tcp_codebase_improvement_plan.md`,
  `packet_handler_rewrite_plan.md` — §4 deferred tracks.
- `sysctl_framework.md` — §3 on-touch migration policy.
