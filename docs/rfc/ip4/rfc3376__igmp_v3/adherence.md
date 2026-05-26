# RFC 3376 — Internet Group Management Protocol, Version 3 (IGMPv3)

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 3376                                           |
| Title       | Internet Group Management Protocol, Version 3  |
| Category    | Standards Track                                |
| Date        | October 2002                                   |
| Updates     | RFC 2236                                        |
| Source text | [`rfc3376.txt`](rfc3376.txt)                   |

This document records, clause by clause, how the PyTCP codebase
relates to each normative statement in RFC 3376 relevant to the
**host** role. The audit was performed by reading the RFC text
fresh and inspecting `packages/net_proto/net_proto/protocols/igmp/`,
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__igmp__{rx,tx}.py`,
`packages/pytcp/pytcp/stack/membership.py`, and
`packages/pytcp/pytcp/protocols/igmp/igmp__constants.py` directly.

**Scope.** PyTCP implements the IGMPv3 **host** (group member)
role. The IGMPv3 **router / querier** role (sending Queries,
maintaining group membership state for forwarding, the querier
election) is Phase-2 router work and is marked out-of-scope per
clause. The host today joins groups in EXCLUDE{} ("any-source")
mode — the common `IP_ADD_MEMBERSHIP` case; source-specific
filters (INCLUDE / source lists) are modelled in the wire codec
but not yet driven by a source-filter socket API.

---

## Top-line adherence

| Section  | Topic                                                    | Status |
|----------|----------------------------------------------------------|--------|
| §4       | Messages carried in IPv4, protocol 2, TTL 1, Router Alert | met |
| §4.1     | Membership Query parsing (v1/v2/v3 by length)            | met (RX) |
| §4.1.1 / §4.1.7 | Max Resp Code / QQIC floating-point decode        | met |
| §4.1.12  | Accept Query to 224.0.0.1 / any interface address        | met |
| §4.2     | Version 3 Membership Report format                       | met |
| §4.2.14  | Reports sent to 224.0.0.22                               | met |
| §5.1     | State-change Report on join/leave + robustness retransmit | met |
| §5.2     | Random-delay response to a Query                         | met (general / group; combined per-group nuance partial) |
| §6       | Host state — all-systems group never reported            | met (host); router state out of scope |
| §7       | Older-version (v1/v2) querier interoperation             | not implemented (deferred) |
| §8       | Timing / robustness constants                            | met (sysctls) |
| §9       | Source-Specific Multicast (INCLUDE / source filters)     | partial (EXCLUDE{} only) |

---

## §4. Message Formats

> "IGMP messages are encapsulated in IPv4 datagrams, with an IP
> protocol number of 2.  Every IGMP message described in this
> document is sent with an IP Time-to-Live of 1, ... and carries
> an IP Router Alert option [RFC-2113] in its IP header."

**Adherence:** met. `IpProto.IGMP = 2`
(`packages/net_proto/net_proto/lib/enums.py`) and `IpProto.from_proto` maps the
`Igmp` assembler to it, so an IGMP message rides IPv4 with
Protocol = 2. The TX path
(`packet_handler__igmp__tx.py::_emit_v3_report`) sends every
Report to its destination with `ip4__ttl=1` and
`ip4__options=Ip4Options(Ip4OptionRouterAlert())`.

> "Unrecognized message types MUST be silently ignored."

**Adherence:** met. The parser routes an unrecognised type byte
to `IgmpMessageUnknown`, whose `validate_sanity` raises; the RX
handler catches the validation error and drops the frame
(`packet_handler__igmp__rx.py::_phrx_igmp`, counter
`igmp__failed_parse__drop`).

## §4.1. Membership Query Message

> "[Query wire format: Type=0x11, Max Resp Code, Checksum, Group
> Address, Resv|S|QRV, QQIC, Number of Sources, Source
> Address[]]"

**Adherence:** met (RX). `IgmpMessageQuery.from_buffer`
(`igmp__message__query.py`) decodes the 8-octet v1/v2 form and
the ≥12-octet v3 form, exposing `group_address`, `s_flag`,
`qrv`, `qqic`, and the source list. The host is a listener, so
the Query is RX-only; `assemble` raises (querier emission is
Phase-2 router work).

### §4.1.1 / §4.1.7 Max Resp Code / QQIC

> "If Max Resp Code >= 128, Max Resp Code represents a
> floating-point value ... Max Resp Time = (mant | 0x10) <<
> (exp + 3)."

**Adherence:** met. `decode_igmp_float_code`
(`igmp__message__query.py`) implements the 8-bit
`(mant | 0x10) << (exp + 3)` decode for both Max Resp Code and
QQIC; `IgmpMessageQuery.max_response_time` /
`.querier_query_interval` expose the decoded values.

### §4.1.12 IP Destination Addresses for Queries

> "a system MUST accept and process any Query whose IP
> Destination Address field contains *any* of the addresses
> (unicast or multicast) assigned to the interface on which the
> Query arrives."

**Adherence:** met. General Queries arrive at 224.0.0.1, which
the host joins permanently (on `_ip4_multicast`), and the IPv4
RX path admits any datagram destined to a joined multicast
group or an interface unicast address before the IGMP demux
runs (`packet_handler__ip4__rx.py`).

## §4.2. Version 3 Membership Report Message

> "[Report wire format: Type=0x22, Reserved, Checksum, Reserved,
> Number of Group Records, Group Record[]]"

**Adherence:** met. `IgmpMessageV3Report` (`igmp__message__
v3_report.py`) and `IgmpV3GroupRecord` (`igmp__v3_group_record.py`)
assemble and parse the Report and its records, including the
Aux Data Len in 32-bit words and the N×4-byte source list.

### §4.2.14 IP Destination Addresses for Reports

> "Version 3 Reports are sent with an IP destination address of
> 224.0.0.22, to which all IGMPv3-capable multicast routers
> listen."

**Adherence:** met. `_emit_v3_report` sends every Report to
`224.0.0.22` (`IGMP__ALL_IGMPV3_ROUTERS`).

## §5.1. Action on Change of Interface State

> "A change of interface state causes the system to immediately
> transmit a State-Change Report from that interface."

**Adherence:** met. `_assign_ip4_multicast` emits a
CHANGE_TO_EXCLUDE_MODE state-change Report on join and
`_remove_ip4_multicast` a CHANGE_TO_INCLUDE_MODE Report on leave
(`packet_handler/__init__.py`), via
`IgmpTxHandler._send_igmp_v3_state_change`.

> "INCLUDE (A) → EXCLUDE (B): TO_EX (B); EXCLUDE (A) → INCLUDE
> (B): TO_IN (B)."

**Adherence:** met for the any-source model. A join is the
non-existent→EXCLUDE{} transition (TO_EX{}), a leave the
EXCLUDE{}→non-existent (≡ INCLUDE{}, TO_IN{}) transition; both
emit a single record with an empty source list. The
source-list-delta rows (ALLOW/BLOCK) belong to source-specific
filtering — see §9.

> "To cover the possibility of the State-Change Report being
> missed ... it is retransmitted [Robustness Variable] - 1 more
> times, at intervals chosen at random from the range (0,
> [Unsolicited Report Interval])."

> "If more changes to the same interface state entry occur
> before all the retransmissions of the State-Change Report for
> the first change have been completed, each such additional
> change triggers the immediate transmission of a new
> State-Change Report."

**Adherence:** met. A state change records a per-group
pending-change entry (record type + remaining-repeat count
seeded to `igmp.robustness` − 1) and arms a single retransmit
ticket; each fire recomputes the records from the live
pending-change map, decrements the counts, drops the exhausted
entries, and re-arms while any remain — so the repeats are
chained at successive random intervals drawn from (0,
`igmp.unsolicited_report_interval` ms] via `stack.timer` (the
Linux `igmp_ifc_timer` / `mr_ifc_count` model). A new change to
the same group overwrites that group's pending record and
re-seeds its count, so a join cancelled by a quick leave
retransmits the leave, never the stale join
(`IgmpTxHandler._send_igmp_v3_state_change` /
`_arm_state_change_retransmit` / `_fire_state_change_retransmit`).

## §5.2. Action on Reception of a Query

> "When a system receives a Query, it does not respond
> immediately.  Instead, it delays its response by a random
> amount of time, bounded by the Max Resp Time ..."

**Adherence:** met. `__phrx_igmp__membership_query`
(`packet_handler__igmp__rx.py`) draws a random delay in
[0, Max Resp Time] and schedules the current-state Report via
`stack.timer` (delay 0 = respond now).

> "1. If there is a pending response to a previous General Query
> scheduled sooner than the selected delay, no additional
> response needs to be scheduled.  2. If the received Query is a
> General Query, the interface timer is used to schedule a
> response ... Any previously pending response to a General
> Query is canceled."

**Adherence:** met for the interface (General-Query) timer. The
handler keeps a single per-interface pending-response deadline
(`_igmp_query__pending_response_at_ms` / `_handle`): a Query
whose computed response is later than the pending one is
absorbed (rule 1); an earlier one supersedes it (rule 2,
counter `igmp__membership_query__superseded`).

**Partial:** the separate per-group / per-source timers for
Group-Specific and Group-and-Source-Specific Queries (and the
combined-response source-list bookkeeping) are not maintained —
PyTCP answers every Query with the full current-state Report on
the single interface timer. This is conservative (it reports a
superset) and correct for the any-source model; the per-group
response refinement is deferred.

## §6. Description of the Router / Host Behaviour

> "the all-systems multicast address, 224.0.0.1, to which all
> IP systems ... are always members.  ... a system can never be
> in any state with respect to this address; ... reception
> state for it is never reported."

**Adherence:** met (host). `_send_igmp_v3_report` and
`_send_igmp_v3_state_change` exclude 224.0.0.1 from the records
(`IGMP__ALL_SYSTEMS` guard), and the membership API refuses to
leave it.

The router-side host-state-table maintenance (the querier's
view of which groups have members, used for forwarding) is
out-of-scope Phase-2 router work.

## §7. Interoperation With Older Versions of IGMP

> "In order to be compatible with older version routers, IGMPv3
> hosts MUST operate in version 1 and version 2 compatibility
> modes.  ... If a host receives ... an older version Query ...
> it MUST use ... the host compatibility mode ..."

**Adherence:** not implemented (deferred). PyTCP parses v1/v2
Queries (it discriminates the version by message length) and
the legacy v1/v2 Report / Leave wire forms exist
(`IgmpMessageV2Report` / `IgmpMessageV2Leave` /
`IgmpMessageV1Report`), but the older-querier-present state
machine — switching the response Report to the v1/v2 form for
the Older Version Querier Present Timeout, and sending an IGMPv2
Leave Group to 224.0.0.2 under a v2 querier — is not wired. The
host answers every querier with an IGMPv3 Report. This is the
one consciously-deferred host-side clause; it is tracked in its
own plan, `docs/refactor/igmp_version_fallback.md`.

## §8. List of Timers and Default Values

> "The Robustness Variable ... default: 2.  ... The Unsolicited
> Report Interval is the time between repetitions of a host's
> initial report of membership in a group.  Default: 1 second."

**Adherence:** met (operator-tunable). `igmp.robustness`
(default 2) and `igmp.unsolicited_report_interval` (default
1000 ms) are registered sysctls
(`packages/pytcp/pytcp/protocols/igmp/igmp__constants.py`). The
querier-side intervals (Query Interval, Query Response Interval,
Startup / Last-Member values) are router parameters the host
reads from the wire (QQIC / Max Resp Code), not host config.

## §9. Source-Specific Forwarding Rules

**Adherence:** partial. The wire codec carries source lists and
the full record-type set (MODE_IS_INCLUDE / EXCLUDE, ALLOW /
BLOCK), but the host data path joins in EXCLUDE{} mode only
(the `IP_ADD_MEMBERSHIP` "any source" case). The source-filter
socket API (`IP_ADD_SOURCE_MEMBERSHIP` / `MCAST_JOIN_SOURCE_
GROUP`) that would drive INCLUDE-mode / per-source records is a
deferred follow-on.

---

## Test coverage audit

### §4 IGMP-in-IPv4 + unknown-type drop

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__ip4_payload.py`
  An IGMP Report carried in IPv4 sets Protocol = 2 and the
  message follows the header intact.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__message__unknown.py`
  and `test__igmp__parser__integrity_checks.py` — an unknown
  type is rejected at sanity (silent drop).

**Status:** locked in.

### §4.1 / §4.1.1 / §4.1.7 Query parse + float decode

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__message__query__operation.py`
  v1/v2/v3 version discrimination, field decode, the §4.1.1 /
  §4.1.7 float-code table, the General-Query predicate.

**Status:** locked in.

### §4.2 / §4.2.14 V3 Report format + destination

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__message__v3_report__assembler.py`
  and `test__igmp__v3_group_record__assembler.py` — Report /
  record wire format + roundtrip.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__report_tx.py`
  Emitted Report goes to 224.0.0.22 (its multicast MAC),
  TTL = 1, Protocol = IGMP, type 0x22.

**Status:** locked in.

### §5.1 State-change Report + robustness retransmit

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__membership_change.py`
  Join → one CHANGE_TO_EXCLUDE_MODE record; leave → one
  CHANGE_TO_INCLUDE_MODE record; all-systems group silent.
- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__robustness_retransmit.py`
  RV=2 → one retransmit at the URI delay; RV=3 → two chained at
  successive intervals; RV=1 → none; and a leave before the join
  retransmit fires supersedes it (the retransmit carries
  CHANGE_TO_INCLUDE_MODE, never the stale CHANGE_TO_EXCLUDE_MODE).

**Status:** locked in.

### §5.2 Query response random delay + coalescing

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__query_response.py`
  Zero-delay Query → immediate Report; non-zero delay → Report
  deferred until the FakeTimer crosses the deadline;
  bad-checksum Query dropped.

**Status:** locked in (interface-timer path). The per-group /
source-specific timer refinement is the documented §5.2 partial.

### §6 All-systems group never reported

- **Integration:**
  `test__igmp__membership_change.py::...all_systems_group_change_emits_nothing`
  and `test__igmp__report_tx.py::...no_groups_no_emit`.

**Status:** locked in.

### §8 Timing / robustness sysctls

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__sysctls.py`
  Defaults, override, validator, and `igmp.max_memberships`
  enforcement.

**Status:** locked in.

### §7 Older-version querier interoperation

**Status:** n/a (not implemented; deferred). When it lands, the
natural test surface is an `IcmpTestCase`-based test driving a
v2 Query and asserting the response switches to the IGMPv2
Report form for the older-querier-present window, plus a v2
Leave Group to 224.0.0.2 on leave.

### Test coverage summary

| Aspect                                         | Coverage |
|------------------------------------------------|----------|
| §4 IGMP-in-IPv4 / unknown-type drop            | locked in |
| §4.1 Query parse + float decode                | locked in |
| §4.2 V3 Report format + 224.0.0.22 destination | locked in |
| §5.1 State-change Report + robustness retransmit | locked in |
| §5.2 Query response (interface timer)          | locked in |
| §5.2 per-group / source-specific timer         | n/a (partial; deferred) |
| §6 all-systems never reported                  | locked in |
| §8 timing / robustness sysctls                 | locked in |
| §7 older-version querier interop               | n/a (deferred) |
| §9 source-specific filtering                   | n/a (EXCLUDE{} only) |

---

## Overall assessment

| Aspect                                         | Status |
|------------------------------------------------|--------|
| §4 message formats (Query / V3 Report / record) | met   |
| §4 IPv4 carriage (proto 2, TTL 1, Router Alert) | met   |
| §5.1 state-change Report + robustness retransmit | met   |
| §5.2 random-delay Query response                | met (interface timer); per-group partial |
| §6 all-systems group exemption (host)           | met   |
| §7 older-version (v1/v2) querier interop        | not implemented (deferred) |
| §8 timing / robustness constants (sysctls)      | met   |
| §9 source-specific multicast                    | partial (EXCLUDE{} only) |
| Router / querier role                           | out of scope (Phase 2) |

PyTCP implements the IGMPv3 **host** role for the common
any-source (EXCLUDE{}) membership case: it joins/leaves groups
through the membership API, announces changes with robustness-
retransmitted state-change Reports, and answers Membership
Queries after the §5.2 random delay. The principal deferred
host-side gap is the §7 older-version querier interoperation
state machine (parse support and the legacy Report/Leave wire
forms already exist; only the version-switching logic is
unwired). Source-specific filtering (§9) and the IGMPv3
router/querier role are tracked as separate future work.
