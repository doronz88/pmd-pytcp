# IGMP — Source-Specific Multicast (RFC 3376 §9 / §3) — Implementation Plan

| Field        | Value                                                                 |
|--------------|-----------------------------------------------------------------------|
| Status       | Plan — implementation phased; the last IGMP host-side partial          |
| Plan author  | IGMP §9 track (2026-05-26)                                            |
| Target       | RFC 3376 source-filter membership: §3.1 (socket state), §3.2 (interface-state merge), §4.2.12 (Group Records), §5.1 (source state-change reports), §5.2 rule 5 + group-timer expiry table |
| Parent       | `docs/refactor/igmp_host_membership.md` (host shipped) + the §7 fallback (`igmp_version_fallback.md`) + §5.2 per-group timer (shipped). This closes the EXCLUDE{}-only simplification. |
| North Star   | Phase 1 (host parity). The Linux source-filter socket API (`IP_ADD_SOURCE_MEMBERSHIP` etc.). |

## 0. What this closes

Today PyTCP's multicast membership is **presence-based, EXCLUDE{} only**:
a joined group is "listen to all sources" (`_ip4_multicast:
list[Ip4Address]` + the R3 per-socket presence refcount). RFC 3376 adds
**per-(interface, group) source filtering**: a group has a *filter mode*
(INCLUDE or EXCLUDE) and a *source list*. INCLUDE{S} = receive only from
sources in S; EXCLUDE{S} = receive from all except S. The host signals
this to routers with source-bearing Group Records and answers
Group-and-Source-Specific Queries with the source-intersection math.

The **wire codec is already complete** — `IgmpV3GroupRecord` carries
`source_addresses`, all six `IgmpV3RecordType`s exist
(MODE_IS_INCLUDE/EXCLUDE, CHANGE_TO_INCLUDE/EXCLUDE_MODE,
ALLOW_NEW_SOURCES, BLOCK_OLD_SOURCES), and the Query parser reads source
lists. This track is purely the **host runtime**.

## 1. Design model

### 1.1 Per-socket filter (RFC 3376 §3.1)

Each socket holds, per (ifindex, group), a filter: a mode
(INCLUDE/EXCLUDE) and a source set. The socket source options mutate it:

| Socket option (Linux number)      | Effect on the socket filter for (group, ifindex)            |
|------------------------------------|-------------------------------------------------------------|
| `IP_ADD_MEMBERSHIP` (35)           | EXCLUDE{} (any-source join) — today's behaviour             |
| `IP_DROP_MEMBERSHIP` (36)          | drop the membership entirely                                |
| `IP_ADD_SOURCE_MEMBERSHIP` (39)    | INCLUDE mode; add source S to the include set               |
| `IP_DROP_SOURCE_MEMBERSHIP` (40)   | remove S from the include set; empty ⇒ drop the membership  |
| `IP_BLOCK_SOURCE` (38)             | EXCLUDE mode; add S to the exclude set                      |
| `IP_UNBLOCK_SOURCE` (37)           | remove S from the exclude set                               |

`ip_mreq_source` = `imr_multiaddr`(4) + `imr_interface`(4) +
`imr_sourceaddr`(4) = 12 bytes. Mixing modes on one socket for one group
is an error (`EINVAL`), mirroring Linux. The MSFv1 (`IP_MSFILTER`) and
protocol-independent `MCAST_*` APIs are **out of scope** (deferred).

### 1.2 Interface-state merge (RFC 3376 §3.2)

The interface filter for a group is the merge of all socket filters:

- If **any** socket is in EXCLUDE mode → interface is EXCLUDE with
  sources = (intersection of the EXCLUDE source-lists) − (union of the
  INCLUDE source-lists).
- If **all** sockets are INCLUDE → interface is INCLUDE with sources =
  (union of the INCLUDE source-lists).

This replaces the R3 presence refcount: the interface filter is derived
from the live set of per-socket filters. The operator API
(`stack.membership`) contributes an EXCLUDE{} reference as today.

### 1.3 Interface membership state

Replace the flat `_ip4_multicast: list[Ip4Address]` reception view with a
per-group record `{group: (mode, sources)}`. Keep a derived
"has reception state" predicate (mode EXCLUDE, or INCLUDE with non-empty
sources) driving the existing L2 MAC mapping + the `_ip4_multicast`
readers (228 call sites read it as "joined groups" — preserve that view
as a property/derived list to avoid a wide blast radius). 224.0.0.1 stays
permanent EXCLUDE{}.

### 1.4 State-change reports (RFC 3376 §5.1 / §4.2.12)

On a filter change, emit the record dictated by the transition
(`igmpv3_send_report` semantics):

- Filter-mode change → `CHANGE_TO_INCLUDE_MODE` / `CHANGE_TO_EXCLUDE_MODE`
  carrying the new source list.
- Source-list change within a mode → `ALLOW_NEW_SOURCES` (sources added
  to the reception set) and/or `BLOCK_OLD_SOURCES` (sources removed).

These supersede / coalesce through the existing R1 recompute-at-fire
retransmit map (which today stores a single `record_type` per group →
extend it to carry the source list).

### 1.5 Query response (RFC 3376 §5.2 + §4.2.12)

- Current-state records gain the real mode + source list:
  `MODE_IS_INCLUDE` (sources) / `MODE_IS_EXCLUDE` (sources).
- Group-and-Source-Specific Query (the deferred §5.2 rule 5 + the
  expiry table): record the queried source list per group; on expiry
  send `IS_IN(A*B)` for an INCLUDE interface state, `IS_IN(B-A)` for
  EXCLUDE; empty result ⇒ no response.

## 2. Scope boundary

- **Control plane only.** This track is the IGMP *signalling* of source
  filters. Data-plane RX source filtering (dropping a received datagram
  from a non-included source before socket delivery) is a **separate**
  follow-on — Linux enforces it in `ip_mc_sf_allow`; PyTCP's UDP/raw RX
  delivery filter-by-source is noted but not in this track.
- MSFv1 `IP_MSFILTER` / `MCAST_*` protocol-independent API: deferred.
- IGMPv1/v2 compatibility mode: source filters collapse to the
  any-source form (v1/v2 have no source concept) — a source membership
  reported in v1/v2 mode degrades to the group Report (already the
  fallback form).

## 3. Phased plan

Each phase one tests-first commit (or tests+impl pair); lint + full
suite + §7.2 audit clean before each.

### Phase 1 — interface source-filter data model

Per-group `_Ip4MulticastFilter` (mode + frozenset of sources) on the
interface; `_ip4_multicast` becomes a derived view. The R3 refcount
becomes a per-(socket) filter registry that merges (§3.2) into the
interface filter. `_assign/_remove_ip4_multicast` reframed as
"recompute interface filter from the merged socket filters, emit the
state-change delta". Tests: the merge table (§3.2) — INCLUDE∪INCLUDE,
EXCLUDE∩EXCLUDE−INCLUDE, mixed.

### Phase 2 — source socket options

`IP_ADD/DROP_SOURCE_MEMBERSHIP`, `IP_BLOCK/UNBLOCK_SOURCE` (IpOption
37-40) parsing the 12-byte `ip_mreq_source`; per-socket filter mutation
+ `EINVAL` on mode conflict; `close()` releases source filters. Tests:
each option's effect on the socket + interface filter; mode-conflict
errno.

### Phase 3 — source state-change reports

Emit ALLOW_NEW_SOURCES / BLOCK_OLD_SOURCES / CHANGE_TO_* with source
lists on filter deltas; extend the R1 retransmit map to carry sources.
Tests: add a source → ALLOW; block a source → BLOCK; INCLUDE→EXCLUDE →
CHANGE_TO_EXCLUDE with sources.

### Phase 4 — query-response source math

Current-state MODE_IS_INCLUDE/EXCLUDE with sources; Group-and-Source-
Specific Query records the source list and applies the §5.2 expiry
table (IS_IN(A*B) / IS_IN(B-A)); empty ⇒ no response. Closes the §5.2
rule-5 deferral. Tests: GSSQ for included vs non-included sources.

### Phase 5 — adherence + ledger sweep

Flip RFC 3376 §9 + §4.2.12 + §5.2 rule 5 + §3.1/§3.2 to met; update the
host-membership ledger + `v3_0_6_remaining_work.md` §2.0; note the
data-plane RX source-filter follow-on.

## 4. Key decisions / risks

- **`_ip4_multicast` blast radius.** ~228 readers treat it as a flat
  joined-group list. Keep it as a derived read-only view (property) over
  the new filter map so only the membership/IGMP code changes.
- **R3 refcount rework.** The presence refcount becomes the per-socket
  filter registry; the interface filter is derived by the §3.2 merge.
  The R3 close-release + EADDRINUSE/EADDRNOTAVAIL semantics carry over
  per (group) with the filter attached.
- **MAC mapping unchanged.** L2 still maps by group address (source
  filtering is above the MAC layer); a group has reception state iff its
  merged filter is non-empty.

## 5. Cross-references

- `docs/refactor/igmp_host_membership.md`, `igmp_version_fallback.md`,
  `igmp_r3_socket_refcounting.md` — the prior IGMP tracks.
- `docs/rfc/ip4/rfc3376__igmp_v3/adherence.md` §9 / §3 / §5.2 — the
  clauses this flips to met.
- Linux `net/ipv4/igmp.c` (`ip_mc_source`, `ip_mc_msfilter`,
  `igmpv3_*`), `net/ipv4/ip_sockglue.c` (the source socket options).
- `.claude/skills/rfc_adherence_audit` — refresh on landing.
