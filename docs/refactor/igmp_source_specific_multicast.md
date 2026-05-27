# IGMP — Source-Specific Multicast (RFC 3376 §9 / §3) — Implementation Plan

| Field        | Value                                                                 |
|--------------|-----------------------------------------------------------------------|
| Status       | Phased — Phases 1-4 SHIPPED (data model + §3.2 merge + source socket options + §5.1 source state-change reports + §5.2 query-response source math); Phase 5 (adherence sweep) open |
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

### Phase 1 — interface source-filter data model  (SHIPPED)

Per-group `Ip4MulticastFilter` (mode + frozenset of sources) at
`pytcp/lib/ip4_multicast_filter.py`, with the pure RFC 3376 §3.2
`Ip4MulticastFilter.merge(...)` classmethod (any-EXCLUDE → EXCLUDE
intersection minus INCLUDE union; all-INCLUDE → INCLUDE union;
empty → INCLUDE{} = no reception). The handler keeps a materialized
`_ip4_multicast_filters: dict[Ip4Address, Ip4MulticastFilter]` as the
reception source of truth; `_ip4_multicast` is now a derived read-only
property over its keys (only 6 files read it, far fewer than the feared
~228). The R3 refcount dataclass became `_Ip4GroupMembership`
(operator hold + per-socket `socket_filters` list); `_mc_ref_acquire` /
`_mc_ref_release` re-derive the merged filter via `.merge(contributors())`
and drive the join / leave edge off `has_reception`. Phase 1 is
behaviour-preserving — every join is still EXCLUDE{} (any-source), so the
same `CHANGE_TO_EXCLUDE` / `CHANGE_TO_INCLUDE` Reports fire; the merge
plumbing and the data model are what is new. Tests: the §3.2 merge table
(unit, `test__lib__ip4_multicast_filter.py`) + the live join/leave/derived-
view wiring (integration, `test__igmp__source_filter_model.py`). The §9 /
§3.2 adherence flip waits for Phase 5 (no user-facing source filters until
Phase 2).

### Phase 2 — source socket options  (SHIPPED)

`IP_UNBLOCK_SOURCE` (37) / `IP_BLOCK_SOURCE` (38) /
`IP_ADD_SOURCE_MEMBERSHIP` (39) / `IP_DROP_SOURCE_MEMBERSHIP` (40)
added to `IpOption` + bare aliases, parsing the 12-byte `ip_mreq_source`
(imr_multiaddr + imr_sourceaddr + imr_interface). The socket facade
holds `_ip4_source_filters: dict[(ifindex, group), Ip4MulticastFilter]`
(replacing the old presence-set `_ip4_memberships`) and runs the
per-option state machine + errno mapping in `_apply_source_op`; the
resulting filter (or its absence) is pushed to the interface §3.2 merge
through the new membership-API surface `set_socket_filter` /
`clear_socket_filter` (keyed by `id(socket)`). The handler keys
per-socket filters by that token (`_Ip4GroupMembership.socket_filters:
dict[int, Ip4MulticastFilter]`); the operator hold stays a separate
boolean. `MembershipRefKind` is gone — operator (`join`/`leave`) and
socket (`set_socket_filter`/`clear_socket_filter`) are now distinct
API methods. `close()` releases every source filter (Linux
`ip_mc_drop_socket`).

Per-socket state machine (cur = the socket's filter for the group;
`ip_mc_source` errno parity):

| Option | cur = none | cur = INCLUDE{S} | cur = EXCLUDE{S} |
|--------|-----------|------------------|------------------|
| ADD_MEMBERSHIP | set EXCLUDE{}; join | EADDRINUSE | EADDRINUSE |
| DROP_MEMBERSHIP | EADDRNOTAVAIL | clear; leave | clear; leave |
| ADD_SOURCE (s) | set INCLUDE{s}; join | add s (idempotent) | **EINVAL** |
| DROP_SOURCE (s) | EADDRNOTAVAIL | remove s (empty ⇒ leave); s∉S ⇒ EADDRNOTAVAIL | **EINVAL** |
| BLOCK_SOURCE (s) | **EINVAL** | **EINVAL** | add s (idempotent) |
| UNBLOCK_SOURCE (s) | **EINVAL** | **EINVAL** | remove s; s∉S ⇒ EADDRNOTAVAIL |

A non-multicast group or a short `ip_mreq_source` is EINVAL. Reports
stay the Phase-1 coarse reception-edge form (CHANGE_TO_EXCLUDE on join,
CHANGE_TO_INCLUDE on leave); the interface filter materializes the true
merged §3.2 value but the source-bearing state-change records
(ALLOW/BLOCK/CHANGE_TO_* with sources) are Phase 3. Tests:
`test__igmp__source_socket_opts.py` (each option's socket + interface
effect, the §3.2 merge across two sockets, the errno table, close-release).

### Phase 3 — source state-change reports  (SHIPPED)

The state-change emission is now filter-delta-aware per the RFC 3376
§5.1 table (the "non-existent" state is INCLUDE{}):
`IgmpTxHandler._state_change_records(group, old, new)` computes the
difference records — a filter-mode change → one CHANGE_TO_INCLUDE_MODE /
CHANGE_TO_EXCLUDE_MODE carrying the new source list; a within-mode source
change → ALLOW_NEW_SOURCES and/or BLOCK_OLD_SOURCES (empty records
omitted). `_send_igmp_state_change(group, old=, new=)` emits them (IGMPv3
mode) or degrades to the coarse join-Report / leave (IGMPv1/v2 mode,
keyed off the reception edge). The R1 recompute-at-fire retransmit map
(`_IgmpPendingChange`) now carries the source-bearing `records` tuple +
the coarse fallback `coarse_type`; the fire path re-emits them in the
current mode.

`_assign_ip4_multicast` / `_remove_ip4_multicast` stayed the join/leave
emission points (computing the merged filter via
`_ip4_multicast_filter_for` and reporting the INCLUDE{}↔filter
transition), so the any-source path — and every existing test — is
behaviour-preserving; `_mc_recompute` additionally emits the §5.1 delta
when a still-joined group's merged filter changes (a source add/drop or
an interface mode flip). The supersede-on-change model (a new change
overwrites the pending train) is the PyTCP simplification of the §5.1
difference-report merge.

Tests: `test__igmp__source_state_change.py` — ALLOW on source add /
unblock, BLOCK on source drop / block, CHANGE_TO_EXCLUDE on an
INCLUDE→EXCLUDE interface mode flip, and a retransmit carrying the
source list. The §9 / §3.2 adherence flip waits for Phase 5.

### Phase 4 — query-response source math  (SHIPPED)

Current-State Records now carry the real filter mode + source list:
`IgmpTxHandler._current_state_record(group)` builds MODE_IS_INCLUDE /
MODE_IS_EXCLUDE from the merged interface filter, used by the General-
Query response (`_send_igmp_v3_report`, §5.2 expiry rule 1) and the
Group-Specific response (`_send_igmp_v3_group_current_state`, rule 2).
The Group-and-Source-Specific path records the queried source list on
the per-group pending state (`IgmpGroupQueryPending.sources`, RX §5.2
rules 3-5 record/clear/augment) and applies the rule-3 table on expiry:
an INCLUDE(A) interface answers IS_IN(A∩B), an EXCLUDE(A) interface
answers IS_IN(B−A), an empty result sends no response. This closes the
§5.2 rule-5 / GSSQ deferral.

The per-group pending tuple became the `IgmpGroupQueryPending` dataclass
(deadline + handle + recorded sources). Tests:
`test__igmp__source_query_response.py` — General/Group-Specific
current-state with INCLUDE/EXCLUDE sources, GSSQ A∩B and B−A, and the
empty-result no-response case. The §9 / §3.2 adherence flip waits for
Phase 5.

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
