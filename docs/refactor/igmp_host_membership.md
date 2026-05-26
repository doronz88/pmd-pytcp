# IGMP — IPv4 Multicast Group Membership (host side) — Implementation Plan

| Field           | Value                                                                |
|-----------------|----------------------------------------------------------------------|
| Status          | In progress — Phase 0 (net_proto wire codec) shipped 2026-05-25; Phases 1-6 remain |
| Plan author     | Release-readiness pass (2026-05-25)                                  |
| Target RFCs     | RFC 1112 (host multicast model), RFC 2236 (IGMPv2), RFC 3376 (IGMPv3) |
| Template        | the shipped IPv6 counterpart — MLDv2 (`net_proto .../icmp6/message/mld2/`) + the `stack.address` join/report pattern |
| Touch points    | new `packages/net_proto/net_proto/protocols/igmp/`, new `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__igmp__{rx,tx}.py`, a multicast-membership API surface, a report/query listener subsystem, the IPv4 RX proto-demux, sysctl framework, RFC 1112 / 2236 / 3376 adherence records |
| North Star      | Phase 1 (host-stack parity). IGMP is the IPv4 analog of the already-shipped MLDv2 listener; this closes the IPv4/IPv6 host-multicast asymmetry. |

## 0. Why this is in scope (and why it was deferred)

A default Linux host that joins an IPv4 multicast group (e.g. via
`setsockopt(IP_ADD_MEMBERSHIP)`) emits IGMP Membership Reports and
answers IGMP Membership Queries; the kernel runs an IGMPv3 host
state machine per group (RFC 3376 §6) with v2/v1 querier-version
fallback (§7). PyTCP today:

- **has** the all-hosts group `224.0.0.1` preconfigured on the
  per-interface `_ip4_multicast` list, the RFC 1112 §6.4
  IPv4→multicast-MAC mapping (`Ip4Address.multicast_mac`), and the
  RFC 1112 §6.1 TTL=1 default for outbound multicast
  (`packet_handler__ip4__tx.py`);
- **lacks** any IGMP protocol codec, any runtime JOIN/LEAVE, and any
  report/query handling.

So PyTCP can *receive* traffic for a statically-configured group but
cannot *signal* membership — an IGMP-snooping switch or a multicast
router would never forward a group's traffic to it. The IPv6 side
(**MLDv2 — shipped**) does exactly this, so the gap is a host-parity
asymmetry, not a missing-by-design choice.

**Deferred (not dropped)** because it is a multi-day track (a new
net_proto protocol family + a membership API + a timer-driven host
state machine + version fallback), too large to land safely on the
3.0.6 release day. Tracked in `v3_0_6_remaining_work.md` §4.

## 1. Target: IGMPv3 primary, v2/v1 query interop

Mirror the MLDv2 decision: **IGMPv3 (RFC 3376) is the primary host
protocol** (MLDv2 *is* the IPv6 transliteration of IGMPv3, so the
wire structures and the host state machine map almost 1:1). RFC 3376
§7 mandates querier-version interop: a host MUST honour an older
querier and drop to IGMPv2 (RFC 2236) / IGMPv1 (RFC 1112) report
behaviour for as long as that querier is present. Source-specific
multicast (INCLUDE/EXCLUDE filter modes, RFC 3376 §2) is modelled in
the records but the host data path can ship EXCLUDE{} ("join any
source") first — the common `IP_ADD_MEMBERSHIP` case — with
source-filter `setsockopt`s (`IP_ADD_SOURCE_MEMBERSHIP` etc.) as a
follow-on.

### Structural note — IGMP is NOT inside ICMP

Unlike MLDv2 (which rides ICMPv6, so it lived under
`protocols/icmp6/message/mld2/`), IGMP is its own IANA IP protocol
number **2**, carried directly in IPv4. So it is a **new top-level
protocol family** `net_proto/protocols/igmp/` and a **new
per-protocol packet handler** demuxed from the IPv4 RX path by
`IpProto.IGMP`, exactly as ICMP/TCP/UDP are. IGMP messages carry the
**IPv4 Router Alert option** (RFC 2113) and TTL=1 (RFC 3376 §4).

## 2. Phased plan

Each phase is one tests-first commit (or a tests+impl pair), lint +
full suite + §7.2 audit clean before each, per the standing
discipline.

### Phase 0 — net_proto IGMP wire codec (RFC 3376 §4) — SHIPPED 2026-05-25

Shipped across seven commits (`2477b18e` IpProto.IGMP=2 → `252fb199`
base/parser/assembler + wiring). The new `net_proto/protocols/igmp/`
family follows the six-file pattern with `IgmpType` / `IgmpVersion` /
`IgmpV3RecordType` enums, `IgmpV3GroupRecord`, the `IgmpMessageQuery`
(v1/v2/v3 length discrimination + §4.1.1/§4.1.7 float decode),
`IgmpMessageV3Report`, the legacy `IgmpMessageGroup` (V2 Report / V2
Leave / V1 Report) and `IgmpMessageUnknown`, plus `Igmp` /
`IgmpParser` / `IgmpAssembler` and the full `net_proto.__all__` export
surface. 198 IGMP unit tests. RFC 2236 / 3376 text fetched into
`docs/rfc/ip4/`. Original sketch:

New `net_proto/protocols/igmp/` following the six-file pattern
(`net_proto.md`); the MLDv2 files are the field-by-field template.

- `igmp__enums.py` — `IgmpType` (`MEMBERSHIP_QUERY=0x11`,
  `V3_MEMBERSHIP_REPORT=0x22`, `V2_MEMBERSHIP_REPORT=0x16`,
  `V2_LEAVE_GROUP=0x17`, `V1_MEMBERSHIP_REPORT=0x12`) as a
  `ProtoEnumByte`; `IgmpV3RecordType`
  (`MODE_IS_INCLUDE=1` … `BLOCK_OLD_SOURCES=6`).
- `igmp__header.py` — the shared `type` byte + the per-type bodies:
  - **Membership Query (§4.1)** — max-resp-code, checksum, group
    address, S/QRV/QQIC, N sources. (v2/v1 queries are the same
    8-byte prefix with N=0 and the older max-resp-code semantics —
    distinguished by message length per §7.1.)
  - **V3 Membership Report (§4.2)** — checksum, N group records;
    each `IgmpV3GroupRecord` = record-type, aux-data-len, N sources,
    multicast address, source list, aux data (the direct analog of
    `Icmp6Mld2MulticastAddressRecord`).
  - **V2 Report / Leave (RFC 2236 §2)** and **V1 Report** — the
    legacy 8-byte forms for querier-version fallback TX.
- `igmp__parser.py` / `igmp__assembler.py` / `igmp__errors.py` —
  three-phase parser (integrity = length/checksum/type bounds with
  typed `IgmpIntegrityError`; sanity = field invariants), kw-only
  assembler with checksum injection. Max-resp-code / QQIC use the
  RFC 3376 §4.1.1 floating-point exp/mant decode (the MLDv2 helper
  is the template).
- Add `IpProto.IGMP = 2` to the `net_proto.lib.enums.IpProto` enum
  (absent today — the members jump ICMP4=1 → IP4=4) and wire the
  IPv4 RX dispatch + `net_proto.__all__`.
- Tests: header asserts, parser integrity+sanity+operation,
  assembler operation, the §4.1.1 code↔value table, v2/v1 vs v3
  length discrimination.

### Phase 1 — per-interface IPv4 group state + L2 mapping — SHIPPED 2026-05-25

Added `_assign_ip4_multicast` / `_remove_ip4_multicast` (abstract on
`PacketHandler`, concrete on `PacketHandlerL2` with the RFC 1112 §6.4
Ethernet multicast-MAC mapping and on `PacketHandlerL3` without it),
and the boot-time join of the all-systems group `224.0.0.1` in both
`_create_stack_ip4_addressing` paths (RFC 1112 §4) — aligning the real
boot with the test-harness fixture that already preseeded it. The
per-group filter-mode/source/timer membership record is deferred to
Phases 3-4 (the host state machine that consumes it). The IGMP
report-on-join hook is marked `# Phase 4:` at both assign sites; the
all-systems group is never reported (RFC 3376 §6). Original sketch:

- Add `_assign_ip4_multicast(group)` / `_remove_ip4_multicast(group)`
  on the packet handler — the IPv4 analog of the existing
  `_assign_ip6_multicast` / `_remove_ip6_multicast`. Maintain the
  group on `_ip4_multicast` (already the RX-accept set) and program
  the Ethernet multicast MAC via the existing
  `Ip4Address.multicast_mac` (RFC 1112 §6.4).
- A per-group membership record (filter mode + source list + the
  per-group timers) — model on the MLDv2 record. `224.0.0.1`
  (all-hosts) is a permanent, never-reported group (RFC 3376 §6 —
  the all-systems group is exempt).

### Phase 2 — membership API (the kernel/userspace boundary)

The user-facing JOIN/LEAVE surface, on the sanctioned Phase-3
boundary (never a direct handler attribute):

- **Socket options** — `IP_ADD_MEMBERSHIP` / `IP_DROP_MEMBERSHIP`
  (and later `IP_ADD_SOURCE_MEMBERSHIP` / `IP_DROP_SOURCE_MEMBERSHIP`
  / `MCAST_*`) on the BSD socket facade, mirroring stdlib `socket`
  constants (`enums.md` §2.2 bare-alias parity). This is the Linux
  app-facing path.
- **Stack-level group API** — a coarse `stack`-level join/leave for
  stack-internal / example consumers, parallel to how
  `stack.address` assigns addresses. Decide during Phase 2 whether
  this is a distinct API or folded into the address surface; the
  IPv6 side joins solicited-node groups implicitly on address-add,
  whereas IPv4 group membership is an explicit app action — so a
  dedicated membership verb is the likelier fit.
- Joining a group calls `_assign_ip4_multicast` (Phase 1) and arms
  the unsolicited-report burst (Phase 4).

### Phase 3 — IGMP RX handler (query processing)

New `packet_handler__igmp__rx.py`, demuxed from the IPv4 RX handler
on `IpProto.IGMP`:

- Parse the message; per-protocol stat counters (`igmp__pre_parse`,
  `igmp__membership_query`, `igmp__*_report`, `igmp__failed_*__drop`)
  on `packet_stats_rx`, asserted exactly by integration tests.
- **General Query** (group = 0.0.0.0) → schedule a per-group report
  for every joined group at a random delay in `[0, max-resp-time]`
  (RFC 3376 §5.2), with report suppression on hearing another host's
  report (v1/v2 compat only; v3 does not suppress).
- **Group-specific / Group-and-Source-specific Query** → schedule a
  report for that group/sources only.
- **Querier-version detection** (§7.1): a v1/v2 query arms the
  older-version-querier-present timer and switches that group's
  report TX to the legacy form for its duration.

### Phase 4 — IGMP TX + report/query listener subsystem

A `Subsystem` (the MLDv2 listener + the ND/timer subsystems are the
template) driving the host state machine:

- On JOIN: send the unsolicited V3 Report (`ALLOW_NEW_SOURCES` /
  `CHANGE_TO_EXCLUDE_MODE`) `[Robustness]` times spaced by the
  unsolicited-report interval (RFC 3376 §5.1).
- On LEAVE: send the state-change report (`BLOCK_OLD_SOURCES` /
  `CHANGE_TO_INCLUDE_MODE{}`); under v2-querier-present, send a
  Leave Group (RFC 2236 §3) to `224.0.0.2`.
- On a scheduled query response: emit the current-state report.
- All reports go to `224.0.0.22` (IGMPv3) / the group (v2) with the
  Router Alert option, TTL=1, source = the interface primary
  address (RFC 3376 §4 / §9).
- Wake on the nearest timer via the event-driven `Timer` (no polling
  tick).

### Phase 5 — robustness / version fallback / sysctls

- RFC 3376 §8 timing constants as **sysctls** (use the `sysctl_knob`
  skill): `igmp.robustness` (RV, default 2), `igmp.query_interval`,
  `igmp.query_response_interval`,
  `igmp.unsolicited_report_interval`, `igmp.version` (force
  v1/v2/v3, default v3 with auto-fallback — the Linux
  `force_igmp_version` analog), `igmp.max_memberships`. Mark
  `# Phase 2: per-interface` per the namespace plan.
- The §7 older-querier-present state machine (v1/v2 timers) so a host
  behind an old querier interoperates.

### Phase 6 — adherence records + integration tests

- Author `docs/rfc/ip4/rfc1112__*/`, `rfc2236__*/`, `rfc3376__*/`
  adherence records via the `rfc_adherence_audit` skill, each with
  the per-clause met/deferred table and the test-coverage audit
  (the standing "records include a test audit" rule).
- Integration tests on a new harness path (the ND/MLD integration
  tests are the template): JOIN emits the unsolicited report burst;
  a General Query elicits a delayed report; LEAVE emits the
  state-change/Leave; v2-querier fallback; report suppression
  (v2); the all-hosts group is never reported; stat-counter exact
  assertions throughout.

## 3. New / touched files inventory

**New (net_proto):** `protocols/igmp/igmp__{enums,header,base,parser,
assembler,errors}.py` + message/record submodules as the MLDv2
layout suggests; matching `tests/unit/protocols/igmp/`.

**New (pytcp):** `runtime/packet_handler/packet_handler__igmp__{rx,
tx}.py`; an IGMP membership listener `Subsystem`; the membership API
module; `tests/integration/protocols/igmp/`.

**Touched (pytcp):** IPv4 RX proto-demux (`IpProto.IGMP` case), the
packet handler's `_assign/_remove_ip4_multicast` + group state, the
socket facade (`IP_ADD_MEMBERSHIP` family + `MsgFlag`/`IpOption`
enum entries), `packet_stats.py` (the `igmp__*` counters), the
sysctl registry, `stack.init` / lifecycle for the listener
subsystem + teardown cascade (an interface removal must drop its
group memberships — extend `_purge_interface_state`).

## 4. Sequencing / dependencies

Phase 0 (codec) and Phase 1 (group state) are independent and can land
in either order; Phase 2 (API) depends on Phase 1; Phases 3–4 (RX/TX
state machine) depend on 0+1; Phase 5 (sysctls/fallback) layers on
3+4; Phase 6 (records/tests) lands incrementally with each phase
(adherence-in-lockstep), with a final sweep.

## 5. Cross-references

- `v3_0_6_remaining_work.md` §4 — where this track is tracked as a
  deferred Phase-1 item.
- `ip4_audit_punchlist.md` item E — the original gap inventory.
- MLDv2 (the shipped IPv6 counterpart) — `net_proto .../icmp6/
  message/mld2/`, the icmp6 RX/TX handler MLD paths, and the IPv6
  group-join pattern in `stack/address.py` are the implementation
  template.
- `.claude/rules/net_proto.md` (six-file codec), `.claude/rules/
  pytcp.md` (Subsystem / packet-handler / sysctl), `.claude/skills/
  sysctl_knob`, `.claude/skills/rfc_adherence_audit`.
- `CLAUDE.md` — North Star (Phase 1 host parity); `enums.md` §2.2 for
  the stdlib-parity socket-option constants.
