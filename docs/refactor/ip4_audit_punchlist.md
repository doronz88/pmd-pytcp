# IPv4 Audit Punch List

This document captures the inventory of remaining work after
the 2026-05-11 IPv4 audit-and-fix session. It is the
canonical reference for picking up the next track without
re-deriving the gap analysis.

The session shipped 8 commits forming a coherent "IPv4 audit
set + Phase-1 gap closures + IPv6 bonus" story on
`PyTCP_3_0__pre_release` (origin tip: `77ee76bc` after push).

## Session-shipped commits (newest first)

| Hash | Title |
|------|-------|
| `77ee76bc` | IPv6 TX: RFC 4007 §6 / RFC 4291 §2.5.6 link-local scope gate |
| `858308b0` | IPv4 fragmentation: RFC 791 §3.1 option-copy-flag + RFC 815 §6 reassembly preservation |
| `95a62524` | IPv4 TX: RFC 1112 §6.1 multicast TTL=1 + RFC 6864 §4.1 atomic ID=0 test |
| `c6628b2e` | RFC 3168 adherence: refresh §5.3 status to met |
| `e2dc5971` | IPv4/IPv6 reassembly: RFC 3168 §5.3 ECN aggregation |
| `ef855d30` | IPv4/IPv6 TX: extract iter_fragment_chunks helper |
| `435bbfd1` | IPv4 RFC adherence: add 16 audit records |

## What shipped — by audit topic

- **RFC 791 §3.1** — option copy-flag on TX fragmentation + RFC
  815 §6 option preservation on RX reassembly. `Ip4Option.copy_flag`
  property, `Ip4Options.with_copy_flag(bool)` filter,
  `Ip4FragAssembler` options serialization, RX header rewrite
  preserves first-fragment IHL.
- **RFC 815** — reassembly machinery audited; §6 options
  preservation flipped from "stripped" to "preserved" via the
  fix above.
- **RFC 1112 §6.1** — outbound multicast TTL defaults to 1
  (was using `IP4__DEFAULT_TTL=64` for all destinations).
  `_phtx_ip4` resolves the `None` sentinel based on dst scope.
- **RFC 1191** — PMTUD audit existed pre-session; not touched.
- **RFC 1122 §3** — host requirements audited; §3.2.1.7 TTL
  configurability noted as informally met (module constant).
- **RFC 3168 §5.3** — ECN aggregation on reassembly. Shared
  IpFragTable now tracks per-offset ECN; aggregator follows
  Linux `ip_frag_ecn_table[]`; ECN_MIXED__DROP outcome for the
  §5.3 second branch. Benefits both IPv4 and IPv6.
- **RFC 6864 §4.1** — atomic-datagram ID=0 dedicated test added.
- **RFC 4007 §6 / RFC 4291 §2.5.6** — IPv6 link-local scope
  gate (bonus, not in the original 5-item list). RFC 6724
  selector returns `None` when no candidate has scope ≥ dst;
  explicit-src gate rejects scope mismatches with
  `DROPPED__IP6__SRC_SCOPE_MISMATCH`.

## What's left — by tier

### Phase-1 sharpenings — small, doable next

| # | Item | RFC | Effort | Notes |
|---|------|-----|--------|-------|
| A | `ip4.default_ttl` sysctl | 1122 §3.2.1.7 | ~30 min | Use the `sysctl_knob` skill. "MUST be configurable" met informally via module constant; sysctl makes it operator-visible. |
| B | RFC 3168 §5.3 wire-level integration test | 3168 §5.3 | ~1 hour | Honest gap from `e2dc5971`. Unit coverage is comprehensive; the wire-level RX integration test (mixed-ECN fragments → reassembled with correct ECN bits, ECN_MIXED__DROP path) was deferred. Per CLAUDE.md feature_implementation §2.1 "wire-format change → integration tests mandatory". |
| C | `ip4.allow_broadcast` policy gate | 919/922 | ~1 hour | No public broadcast API today; gate aligns with Linux `net.ipv4.conf.*.bc_forwarding`. |

### Phase-1 features — bigger, dedicated tracks

| # | Item | RFC | Effort | Notes |
|---|------|-----|--------|-------|
| D | **IPv4 link-local autoconfig** | 3927 | 2-4 days | Closes the deferred IPv4 #5 (TX scope gate) alongside. Needs `docs/refactor/rfc3927_link_local_autoconfig.md` plan doc first, then phased commits. Real Linux-parity gap. |
| E | Multicast group membership API + IGMPv2/v3 | 1112 / 2236 / 3376 | Multi-day | All-hosts (224.0.0.1) preconfigured today; runtime JOIN/LEAVE / Reports / Queries deferred. |
| F | IPv6 audit set parity sweep | — | 1-2 days | This session wrote 16 IPv4 audits but didn't refresh IPv6 audits in parallel. Symmetric topics (RFC 8200, RFC 8504) likely have similar Phase-1 sharpenings worth surfacing. |

### Phase-2 items (project north-star — deferred until forwarding plane)

- **RFC 1812 §5** — full forwarding plane (the big one)
- **RFC 791 §3.1 / RFC 1812 §4.2.2.9** — forward-path TTL
  decrement + ICMP Time Exceeded emission
- **RFC 1122 §3.3.1.5 + RFC 1812 §4.3.3.2** — ICMP Redirect
  emission + RX route-cache update
- **RFC 6864 §4.3** — per-tuple non-atomic IPv4 ID partitioning
- **RFC 1122 §3.3.5** — source-route forwarding (LSRR/SSRR
  pointer advance)
- **RFC 1122 §3.3.4** — multihoming
- **RFC 3168 §9** — IP-in-IP tunnel ECN decapsulation
- **RFC 7126** — per-option drop knobs (RR/Timestamp/Stream ID)
- **RFC 6890** — special-purpose block predicates (CGN,
  Documentation, Benchmark) — host-side low-impact, becomes
  relevant for firewall plane

### From earlier in this session — DHCP track

The DHCPv4 client (multi-commit track that preceded the IPv4
audit work) is feature-complete through Phase 8.x with the
following items deferred:

- **DHCPv4 Phase 7** — multi-default-gateway / route-table
  integration. Blocked on PyTCP gaining a real route-table layer.
- **DHCPv4 Phase 9** — DHCPINFORM (§3.4). Niche, no PyTCP
  consumer for DNS/NTP/etc. config today. Discussed in this
  session.

See `docs/rfc/dhcp4/rfc2131__dhcp/adherence.md` for the
full DHCPv4 adherence record.

## Cross-track context

### Autoconfiguration coverage

PyTCP supports two of the three main IP autoconfiguration
mechanisms today:

1. **DHCPv4** — full client, shipped in earlier session.
2. **IPv6 SLAAC** (RFC 4862) — shipped via ND track (memory:
   "ND parity Tier 1-6 shipped 2026-05-10").
3. **IPv4 link-local autoconfig** (RFC 3927) — outstanding
   (item D above).

### IPv4 #5 scope gate (deferred from this session)

The IPv4 link-local TX-source scope gate (RFC 3927 §2.6) was
explicitly deferred per CLAUDE.md "don't add validation for
scenarios that can't happen" — without RFC 3927 autoconfig
the stack never owns a 169.254/16 source. The gate lands
naturally with item D above. The symmetric IPv6 gate (RFC
4007 §6 / RFC 4291 §2.5.6) was reachable via the SLAAC code
path and shipped in commit `77ee76bc`.

## Recommended next-track sequencing

1. **Small win first:** items A + B + C as a single
   focused commit. ~2-3 hours total. Closes the last
   honest Phase-1 gaps from this session.

2. **Big substantive feature:** item D (RFC 3927) as a
   dedicated phased track. Mirror the DHCPv4 sequencing —
   plan doc first, then commits phased like the DHCP work.
   2-4 days.

3. **Or: audit-set parity:** item F (sweep IPv6 audits for
   symmetric gaps). Likely surfaces 3-5 Phase-1 items
   worth shipping symmetrically.

## Cross-references

- `docs/rfc/ip4/` — 17 audit records (16 added this session +
  pre-existing RFC 1191 PMTUD)
- `docs/rfc/dhcp4/rfc2131__dhcp/adherence.md` — DHCPv4
  adherence record
- `docs/refactor/rfc6724_source_selection.md` — IPv4 source
  selection track (per memory)
- `docs/refactor/socket_linux_parity_audit.md` — socket-API
  Linux parity (per memory; Phase-1 resume prompt at the doc head)
