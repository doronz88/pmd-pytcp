# RFC 3810 — Multicast Listener Discovery Version 2 (MLDv2)

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 3810                                               |
| Title       | Multicast Listener Discovery Version 2 (MLDv2)     |
| Category    | Standards Track                                    |
| Date        | June 2004                                          |
| Source text | [`rfc3810.txt`](rfc3810.txt)                       |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative statement
in RFC 3810 (MLDv2 — IPv6 multicast listener-side and
querier-side protocol). The audit was performed by reading
the RFC text fresh and inspecting the codebase under
`pytcp/stack/packet_handler/packet_handler__icmp6__{rx,tx}.py`
plus `net_proto/protocols/icmp6/` directly.

MLDv2 has two roles: **listener** (every host that joins a
non-trivial IPv6 multicast group) and **querier** (typically
one multicast-aware router per link). PyTCP is a host stack:

- **Listener role**: PyTCP emits Reports when its multicast
  group membership changes; this lets the local querier
  learn what groups are interested on this link.
- **Querier role**: deferred to Phase 2 per CLAUDE.md
  Project North Star (router-grade parity). A Phase-1 host
  has no need to send Queries.

Sections without normative content — Abstract, §1
Introduction, §2 Terminology (informational definitions),
§9 References, §10 Authors' Addresses, §11 IANA, §12
Security boilerplate — are omitted.

Adherence levels: **met**, **partial**, **not implemented**,
**deferred (Phase 2 router)**, **n/a**.

---

## Top-line adherence

PyTCP **meets** the MLDv2 listener-role requirements that
matter for a host stack: it emits Reports when group
membership changes, wraps Reports in a Hop-by-Hop header
carrying the RFC 2711 Router Alert option (value = MLD),
sets Hop Limit = 1 per §5.2.13, sources from a link-local
address per §5.2.13, and sends to the all-MLDv2-routers
group `ff02::16`.

The querier role (§5 Querier processing of inbound Reports;
§7 Querier-side timers and General / Multicast-Address-
Specific / Multicast-Address-and-Source-Specific Queries) is
**deferred to Phase 2** (router track). On the RX side,
inbound Reports are accepted and counted but no
querier-side state-machine update happens; inbound Queries
fall into `__phrx_icmp6__unknown`.

| Section | Topic                                          | Status |
|---------|------------------------------------------------|--------|
| §4 wire | Query (type 130) wire format                   | partial (parser shipped via Icmp6 demux; listener-side response is Phase-1 polish) |
| §4 wire | Report (type 143) wire format                  | met (codec + assembler + parser) |
| §4 wire | Multicast Address Record wire format           | met |
| §5      | Listener-side state machine                    | met (group join/leave triggers `CHANGE_TO_EXCLUDE` Report) |
| §5      | Querier-side state machine                     | deferred (Phase-2 router role) |
| §5.1.10 | Listener responds to Query with Report         | not implemented (Phase-1 polish — see follow-up note) |
| §5.2.13 | Hop Limit = 1 on outbound MLDv2 messages       | met |
| §5.2.13 | Source = link-local address                    | met |
| §5.2.14 | Destination = `ff02::16` (all-MLDv2-routers)   | met (for Reports) |
| §5.2.14 | Router Alert option (RFC 2711) in HBH          | met |
| §6      | Multicast Listener Discovery state transitions | met for the host (CHANGE_TO_EXCLUDE on join) |
| §7      | Timers and constants (querier-side)            | deferred (Phase-2 router role) |
| §8      | Action on reception (querier processing)       | deferred (Phase-2 router role) |

---

## §4 Message Formats

> "There are two MLDv2 message types: Multicast Listener
>  Query (type 130) and Version 2 Multicast Listener
>  Report (type 143)."

**Adherence:** met (wire format) / partial (RX
processing). Both message types live in the ICMPv6 demux:

- Type 130 (`MULTICAST_LISTENER_QUERY`) — declared in
  `Icmp6Type` (`net_proto/protocols/icmp6/icmp6__enums.py`)
  and dispatched at `packet_handler__icmp6__rx.py` to the
  generic ICMPv6 path. PyTCP currently treats inbound
  Queries as "unknown" (falls into
  `__phrx_icmp6__unknown` because there is no per-Query
  handler). A Phase-1 polish item is to add a Query handler
  that responds with the appropriate Report per §5.1.10.
- Type 143 (`MULTICAST_LISTENER_REPORT_V2`) — full codec
  at
  `net_proto/protocols/icmp6/message/mld2/icmp6__mld2__message__report.py`
  (Header / Base / Parser / Assembler + multi-record
  payload). The RX path at
  `packet_handler__icmp6__rx.py:219` dispatches to
  `__phrx_icmp6__mld2_report` which counts the Report but
  takes no state-update action (host-side; querier role
  deferred).

> "A Multicast Address Record is a block of fields that
>  contain information on the sender listening to a single
>  multicast address on the interface from which the
>  Report is sent."

**Adherence:** met. The
`Icmp6Mld2MulticastAddressRecord` dataclass at
`net_proto/protocols/icmp6/message/mld2/` carries Record
Type, Aux Data Length, Number of Sources, Multicast
Address, and optional source addresses. The
`Icmp6Mld2MulticastAddressRecordType` enum covers all six
record types (`MODE_IS_INCLUDE = 1` through
`BLOCK_OLD_SOURCES = 6`).

---

## §5 Protocol Description

### §5.1 Action on Change of Per-Interface State

> "Whenever a multicast listener's per-interface state
>  changes, the listener immediately transmits a State
>  Change Report from that interface."

**Adherence:** met. PyTCP triggers Report emission whenever
the stack's IPv6 multicast group membership changes —
specifically on `add_ip6_host` (joins the solicited-node
multicast for the new address) and on `remove_ip6_host`
(future cleanup). The current implementation emits
`CHANGE_TO_EXCLUDE` records — the MLDv2 legacy-
compatibility shape that joins each listed group in
EXCLUDE-source mode — for every group in `_ip6_multicast`
EXCEPT the all-nodes multicast (`ff02::1`), which is a
permanent group that does not need to be reported per
§5.1.10. Implementation at
`packet_handler__icmp6__tx.py:210-289`
(`_send_icmp6_multicast_listener_report`).

### §5.1.10 Switching from an Older Version of MLD

> "If a host wishes to acquire MLDv2 protocol semantics
>  ... it MUST transition by sending a Version 2 Report
>  ..."

**Adherence:** met (PyTCP is MLDv2-only; no version
switching). PyTCP never emits MLDv1 Reports; all Reports
are MLDv2 (type 143). A future MLDv1-compatibility mode
would be a separate feature.

### §5.2 Multicast Listener Query Message Format

> "Hop Limit: 1 (in fact, MLDv2 messages always have their
>  Hop Limit set to 1)."

**Adherence:** met. `_send_icmp6_multicast_listener_report`
forces `ip6__hop = 1` via the IPv6 TX path; see line 290+
of `packet_handler__icmp6__tx.py` where `_phtx_ip6` is
called. Confirmed by the wire-frame assertion in the
existing MLDv2 integration test.

> "Router Alert option [RFC 2711] in a Hop-by-Hop Options
>  header [RFC 2460]."

**Adherence:** met. The HBH carrier is constructed at
`packet_handler__icmp6__tx.py:271-284`:

```python
hbh_packet_tx = Ip6HbhAssembler(
    ip6_hbh__next=IpProto.ICMP6,
    ip6_hbh__options=Ip6HbhOptions(
        Ip6HbhOptionRouterAlert(
            value=IP6_HBH__OPTION__ROUTER_ALERT__VALUE__MLD,
        ),
        Ip6HbhOptionPadN(b""),
    ),
    ...
)
```

The `Ip6HbhOptionRouterAlert` codec lives at
`net_proto/protocols/ip6_hbh/options/ip6_hbh__option__router_alert.py`
and supports the canonical RFC 2711 RA values
(`MLD`, `RSVP`, `ACTIVE_NETWORKS`, etc.). The
PadN-to-8-octet alignment is computed inline (2-byte HBH
prefix + 4-byte RA + 2-byte PadN(0) = 8 bytes total).

> "Source Address: link-local address ... unless the
>  link-local address is not yet known (e.g. SLAAC has not
>  yet completed) in which case the unspecified address
>  (::) MAY be used."

**Adherence:** met. The IPv6 TX path checks the candidate
source: when the stack has a usable link-local on the
sending interface it is used; otherwise the unspecified
address `::` is allowed for MLDv2 Reports (the MLDv2-report
branch in `packet_handler__ip6__tx.py:260-269` explicitly
documents this as the "src=:: legitimate for MLDv2"
exception that the generic `src=:: unicast` drop rule
makes for this protocol).

### §5.2.13 / §5.2.14 Destination = `ff02::16`

**Adherence:** met. `ip6__dst = Ip6Address("ff02::16")` at
`packet_handler__icmp6__tx.py:237` — the all-MLDv2-routers
multicast group.

---

## §6 Multicast Listener Discovery State Transitions

> "The listener tracks the multicast address membership of
>  the interface ... The MLDv2 state for each multicast
>  address is one of two filter modes: INCLUDE or EXCLUDE."

**Adherence:** met (host-side simplification). PyTCP
maintains per-interface multicast membership in
`self._ip6_multicast: list[Ip6Address]` on the L2
packet handler. The current implementation uses
EXCLUDE-source-list-empty (i.e. "interested in this
multicast group from any source") for all entries —
covering the common SLAAC and solicited-node case. The
INCLUDE / explicit-source filter mode is not consumed by
any current application code; PyTCP would add it when an
application needs source-specific multicast (SSM)
filtering, which is an application-layer feature.

> "When a multicast address listener change happens, the
>  listener responds with a State Change Report."

**Adherence:** met. Address-list mutations through
`add_ip6_host` / `remove_ip6_host` trigger
`_send_icmp6_multicast_listener_report` so the local
querier sees the updated membership immediately. The
solicited-node multicast for the new address is included
automatically (it's appended to `_ip6_multicast` by
`add_ip6_host`).

---

## §7 / §8 Querier-side Timers and Action on Reception

> "The MLDv2 querier sends [General / Multicast-Address-
>  Specific / Multicast-Address-and-Source-Specific]
>  Queries periodically ... and processes inbound Reports
>  to update per-group / per-source state."

**Adherence:** deferred (Phase-2 router role). PyTCP is a
host stack today; the multicast-aware querier role is part
of the Phase-2 forwarding plane. A Phase-2 querier would:

1. Maintain per-multicast-group filter-mode + source-list
   state.
2. Run the General-Query timer, Multicast-Address-Specific-
   Query timer, and Multicast-Address-and-Source-Specific-
   Query timer per §7.
3. Process inbound Reports to update group memberships per
   §8 (`MODE_IS_INCLUDE` / `MODE_IS_EXCLUDE` /
   `CHANGE_TO_INCLUDE_MODE` / `CHANGE_TO_EXCLUDE_MODE` /
   `ALLOW_NEW_SOURCES` / `BLOCK_OLD_SOURCES`).

The Phase-2 RX path will replace the current
"counter-only" handler at
`packet_handler__icmp6__rx.py:1057` with a state-machine
that consults / updates a per-group dictionary.

---

## Phase-1 follow-ups

The host-side surface has one remaining Phase-1 polish
item:

- **§5.1.10 / Query RX response.** A host listener
  receiving a General Query SHOULD respond with a Report
  reflecting its current per-interface state. PyTCP today
  falls inbound type-130 Queries into the unknown-message
  counter; a dedicated handler that re-emits
  `_send_icmp6_multicast_listener_report` on Query receipt
  is a small (~30-50 line) change. The Phase-1 host-mode
  version does NOT need to randomise the response delay
  per §5.1.10 (that's a querier-side concern for avoiding
  Report bursts) — a simple "respond immediately" is fine
  for a single host.

The querier-role items remain Phase-2.

---

## Test coverage audit

### §4 Report wire format

- **Unit:**
  `net_proto/tests/unit/protocols/icmp6/message/mld2/test__icmp6__mld2__message__report__assembler__operation.py`
  — pins the type-143 wire form, multi-record payload,
  per-record-type encoding (1-6).
- **Unit:**
  `net_proto/tests/unit/protocols/icmp6/message/mld2/test__icmp6__mld2__message__report__parser__operation.py`
  — pins the RX-side parse path.

**Status:** locked in.

### §5 Listener-side Report emission

- **Integration:**
  `pytcp/tests/integration/test__packet_handler__icmp6__tx.py`
  — MLDv2 Report cases verify: Hop Limit = 1, source =
  link-local, destination = `ff02::16`, HBH RA-option
  carrier with value = MLD, `CHANGE_TO_EXCLUDE` record
  set populated from `_ip6_multicast`.

**Status:** locked in.

### §6 Address-change triggers Report

- **Integration:**
  `pytcp/tests/integration/protocols/icmp6/nd/test__icmp6__nd__rfc8981_temp.py`
  and `test__icmp6__nd__optimistic_dad.py` — every SLAAC
  address-claim sequence ends with an MLDv2 Report,
  verifying the trigger fires from the addressing path.

**Status:** locked in indirectly (no dedicated "address
change → Report" assertion; the integration cases pin the
end-to-end behaviour via wire observation).

### §5.1.10 Query → Report response

**No test surface — Phase-1 polish gap.** When the gap is
closed, the natural test:

1. Drive an inbound MLDv2 General Query (type 130) into
   `_phrx_ethernet`.
2. Assert a Report is emitted with the current
   `_ip6_multicast` set.

### §7 / §8 Querier role

**No test surface — Phase-2 deferred.** Tests will land
alongside the Phase-2 router-track implementation.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| Report wire format (TX + RX parse)                  | locked in |
| Hop Limit = 1 on outbound                           | locked in |
| RA-option HBH carrier                               | locked in |
| Address-change triggers Report                      | locked in indirectly |
| Query → Report response                             | n/a (Phase-1 polish gap) |
| Querier-side state machine + timers                 | n/a (Phase-2 router) |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| §4 Query wire format                                  | partial (parser shipped via Icmp6 demux; listener-side response is Phase-1 polish) |
| §4 Report wire format                                 | met    |
| §4 Multicast Address Record codec                     | met    |
| §5 Listener-side Report emission on join              | met    |
| §5.1.10 Query → Report response                       | not implemented (Phase-1 polish) |
| §5.2.13 Hop Limit = 1                                 | met    |
| §5.2.13 Source = link-local                           | met    |
| §5.2.14 Destination = `ff02::16` + RA-option HBH      | met    |
| §6 Per-interface multicast state                      | met (EXCLUDE-source-list-empty default) |
| §7 / §8 Querier timers + Action on Reception          | deferred (Phase-2 router) |
| §5.1.10 MLDv1 compatibility mode                      | n/a (PyTCP is MLDv2-only) |

PyTCP fully satisfies the listener-side requirements that
matter for a multicast-using host. The two outstanding
items are:

1. **§5.1.10 General-Query response** (Phase-1 polish). A
   small handler addition; covered by a single integration
   test when shipped.
2. **§5-§8 querier role** (Phase-2 router). Lands when the
   forwarding plane / multicast routing arrives.

## Cross-references

- IPv4 parallel: [`../../ip4/rfc1112__ip4_multicasting/adherence.md`](../../ip4/rfc1112__ip4_multicasting/adherence.md)
  (RFC 1112 IPv4 multicasting; IGMPv2 / IGMPv3 — RFCs 2236
  / 3376 — are tracked as item E in the IPv4 audit punch
  list and are not yet shipped).
- HBH Router-Alert option carrier: RFC 2711 (referenced
  here; no standalone audit yet).
- IPv6 ND / SLAAC adherence audits in this folder cover
  the upstream sources of multicast group membership (every
  SLAAC address claim adds a solicited-node multicast
  group; every group change triggers a Report).
