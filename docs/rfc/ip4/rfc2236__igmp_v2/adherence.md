# RFC 2236 — Internet Group Management Protocol, Version 2 (IGMPv2)

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 2236                                           |
| Title       | Internet Group Management Protocol, Version 2  |
| Category    | Standards Track                                |
| Date        | November 1997                                  |
| Updates     | RFC 1112                                        |
| Source text | [`rfc2236.txt`](rfc2236.txt)                   |

This document records how the PyTCP codebase relates to RFC 2236.
The audit was performed by reading the RFC text fresh and
inspecting `packages/net_proto/net_proto/protocols/igmp/` and
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__igmp__{rx,tx}.py`
directly.

**Posture.** PyTCP runs **IGMPv3** (RFC 3376) as its primary host
protocol; RFC 3376 §4 requires an IGMPv3 host to also support the
IGMPv2 message types for interoperation with older routers. PyTCP
therefore implements the IGMPv2 **wire forms** (the 8-octet Query
and the Version 2 Membership Report / Leave Group), but the
IGMPv2-specific host **behaviours** (report suppression, sending
Reports in the v2 form, the Leave Group to 224.0.0.2) form the
RFC 3376 §7 older-version-querier compatibility mode, which is
**deferred** (see the RFC 3376 record §7 and
`docs/refactor/igmp_host_membership.md` Phase 5). This record is
therefore largely a pointer to the RFC 3376 audit, calling out
only the v2-specific clauses.

---

## Top-line adherence

| Section | Topic                                                  | Status |
|---------|--------------------------------------------------------|--------|
| §2      | 8-octet message format (Type / Max Resp Time / Checksum / Group) | met (codec) |
| §2.1    | Types 0x11 / 0x16 / 0x17 / 0x12                         | met (codec) |
| §2.3    | Checksum over the whole IGMP message                   | met |
| §3      | Unsolicited Report on join                             | met via IGMPv3 (v2-form report deferred) |
| §3      | Report suppression on hearing another host's Report    | not implemented (v3 does not suppress) |
| §3      | Leave Group to 224.0.0.2 on leave                      | not implemented (deferred, §7) |
| §3      | Query / querier behaviour                              | out of scope (Phase 2 router role) |

---

## §2. Message Format

> "All IGMP messages of concern to hosts have the following format:
> [Type | Max Resp Time | Checksum | Group Address] (8 octets)."

**Adherence:** met (codec). The 8-octet form is parsed two ways:
a Membership Query (Type 0x11, 8 octets) by `IgmpMessageQuery`
(its v1/v2 branch), and the Version 2 Membership Report (0x16),
Leave Group (0x17) and Version 1 Membership Report (0x12) by the
shared `IgmpMessageGroup` (`igmp__message__group.py`), which
discriminates on the Type field and validates the group is a
multicast address.

### §2.2 Max Response Time

> "The Max Response Time field is meaningful only in Membership
> Query messages ... In all other messages, it is set to zero by
> the sender and ignored by receivers."

**Adherence:** met. `IgmpMessageGroup.__buffer__` writes the
second octet as zero for the v2 Report / Leave / v1 Report forms;
the Query path decodes Max Resp Time only on the Query message.

### §2.3 Checksum

> "the 16-bit one's complement of the one's complement sum of the
> whole IGMP message ... When receiving packets, the checksum MUST
> be verified before processing a packet."

**Adherence:** met. The IGMP parser verifies the whole-message
checksum before dispatch (`igmp__parser.py::_validate_integrity`,
shared with the RFC 3376 path); the assembler injects it.

## §3. Protocol Description — host behaviour

> "When a host joins a multicast group, it should immediately
> transmit an unsolicited Version 2 Membership Report for that
> group ... it is recommended that it be repeated once or twice
> after short delays [Unsolicited Report Interval]."

**Adherence:** met in substance via IGMPv3, with the v2 wire form
deferred. On join PyTCP emits an unsolicited IGMPv3 state-change
Report (CHANGE_TO_EXCLUDE_MODE) and retransmits it per the
Robustness Variable (RFC 3376 §5.1; see that record). Emitting
the report in the **Version 2** form instead, when an IGMPv2
querier is present, is part of the deferred §7 compatibility mode
— the v2 Report wire form (`IgmpMessageGroup`) is ready; only the
version-selection logic is unwired.

> "If a host hears another host's Report (version 1 or 2) while it
> has a timer running, it stops its timer for the specified group
> and does not send a Report, in order to suppress duplicate
> Reports."

**Adherence:** not implemented (by design under IGMPv3). IGMPv3
hosts do not suppress on hearing another member's Report (RFC
3376 removes v1/v2 report suppression); PyTCP counts a received
Report (`igmp__membership_report`) and ignores it. Report
suppression applies only in v1/v2 compatibility mode, part of the
deferred §7 work.

> "When a host leaves a multicast group, if it was the last host
> to reply to a Query ... it SHOULD send a Leave Group message to
> the all-routers multicast group (224.0.0.2)."

**Adherence:** not implemented (deferred). On leave PyTCP sends an
IGMPv3 CHANGE_TO_INCLUDE_MODE state-change Report to 224.0.0.22
(RFC 3376 §5.1) — the IGMPv3 equivalent of the v2 Leave. Emitting
an IGMPv2 **Leave Group** to 224.0.0.2 instead, under a v2
querier, is part of the deferred §7 compatibility mode (the
Leave Group wire form already exists in `IgmpMessageGroup`).

> "[Query / Querier behaviour: sending Queries, querier election,
> Group-Specific Queries on Leave, the Group Membership
> Interval]."

**Adherence:** out of scope. The querier (router) role is Phase-2
router work. PyTCP is a host (group member) only.

---

## Test coverage audit

### §2 v2 message wire forms

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__message__group.py`
  Per-type matrix for the V2 Report (0x16), Leave Group (0x17)
  and V1 Report (0x12): 8-octet length, Max-Resp-Time-zero
  framing, multicast-group sanity, from_buffer roundtrip.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__message__query__operation.py`
  The 8-octet v1/v2 Query branch (version classified by length).

**Status:** locked in (wire forms).

### §2.3 Checksum verification

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/igmp/test__igmp__parser__integrity_checks.py`
  and the integration `test__igmp__query_response.py` bad-checksum
  case.

**Status:** locked in.

### §3 join / leave reporting (via IGMPv3)

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/igmp/test__igmp__membership_change.py`
  Join / leave emit IGMPv3 state-change Reports (the v2-form
  equivalent is deferred).

**Status:** locked in for the IGMPv3 form.

### §3 v2-compatibility behaviours

**Status:** n/a (not implemented; deferred). When the §7
compatibility mode lands, the natural tests drive a v2 Query and
assert the host (a) answers in the v2 Report form for the
older-querier-present window and (b) sends a v2 Leave Group to
224.0.0.2 on leave; and that report suppression fires on hearing
another host's Report while a v2 timer runs.

### Test coverage summary

| Aspect                              | Coverage |
|-------------------------------------|----------|
| §2 v2 message wire forms            | locked in |
| §2.3 checksum                       | locked in |
| §3 join/leave reporting (IGMPv3)    | locked in |
| §3 v2-form report / Leave-to-224.0.0.2 | n/a (deferred §7) |
| §3 report suppression               | n/a (not used under IGMPv3) |
| §3 querier role                     | n/a (Phase 2 router) |

---

## Overall assessment

| Aspect                                  | Status |
|-----------------------------------------|--------|
| §2 8-octet message wire forms           | met (codec) |
| §2.3 checksum                           | met    |
| §3 join/leave reporting                 | met via IGMPv3 |
| §3 IGMPv2-form reports / Leave (224.0.0.2) | not implemented (deferred §7) |
| §3 report suppression                   | not implemented (n/a under IGMPv3) |
| §3 querier / router role                | out of scope (Phase 2) |

PyTCP supersedes IGMPv2 with IGMPv3 (RFC 3376) and implements the
IGMPv2 message wire forms required for interoperation. The
IGMPv2-specific host behaviours — answering in the v2 Report
form, the Leave Group to 224.0.0.2, and report suppression — are
the RFC 3376 §7 older-version compatibility mode, deferred as a
cohesive block (the wire forms are ready; only the version-mode
state machine is unwired). The querier role is Phase-2 router
work.
