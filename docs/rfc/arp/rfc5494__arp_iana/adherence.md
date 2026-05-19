# RFC 5494 — IANA Allocation Guidelines for ARP

| Field       | Value                                                             |
|-------------|-------------------------------------------------------------------|
| RFC number  | 5494                                                              |
| Title       | IANA Allocation Guidelines for the Address Resolution Protocol    |
| Category    | Standards Track (BCP, applies to IANA registries)                 |
| Date        | April 2009                                                        |
| Updates     | RFC 826 (registry rules only; no protocol change)                 |
| Source text | [`rfc5494.txt`](rfc5494.txt)                                      |

This document records, paragraph by paragraph, how the current
PyTCP codebase relates to each normative statement in RFC 5494.
The audit was performed by reading the RFC text fresh and
inspecting the codebase under `packages/net_proto/net_proto/protocols/arp/` and
`packages/net_proto/net_proto/lib/enums.py` directly.

RFC 5494 is administrative — it establishes the IANA
allocation policy for the three ARP wire-format fields
(`ar$hrd`, `ar$pro`, `ar$op`) and reserves a small set of
experimental code points. It does **not** modify the ARP
protocol itself. PyTCP's adherence is therefore primarily a
question of "does the implementation correctly consume the
existing IANA-assigned values, and not collide with the
reserved / experimental allocations?".

Adherence levels use the canonical descriptive language:
**met**, **not met**, **partial**, **not implemented**,
**vacuous**.

Sections without normative content for an ARP implementation
(§1 Introduction, §4 Security Considerations, §5
Acknowledgments, §6 References, Appendix A "Changes from
the Original RFCs") are summarised inline only where
relevant and otherwise omitted.

---

## §2 — IANA Considerations: `ar$hrd` (Hardware address space)

> "Requests for ar$hrd values below 256 or for a batch of
> more than one new value are made through Expert Review
> [RFC5226]."
>
> "Requests for individual new ar$hrd values that do not
> specify a value, or where the requested value is greater
> than 255, are made through First Come First Served
> [RFC5226]. The assignment will always result in a 2-octet
> value."

**Adherence:** **vacuous (consumer of registry, not
allocator)**. PyTCP does not request new `ar$hrd` values;
it consumes the already-allocated `ETHERNET = 0x0001` from
the registry (`packages/net_proto/net_proto/protocols/arp/arp__enums.py:41`).
The "Expert Review / First Come First Served" gating is an
IANA-side procedural rule with no implementation surface.

> "Note that certain protocols, such as BOOTP and DHCPv4,
> employ these values within an 8-bit field. The expert
> should determine that a need to allocate the new values
> exists and that the existing values are insufficient ...
> Similarly, the expert should assign 1-octet values for
> requests that apply to BOOTP/DHCPv4 ..."

**Adherence:** **vacuous**. PyTCP's `ArpHardwareType` is a
`ProtoEnumWord` (16-bit) and so naturally accepts both
1-octet and 2-octet values. The only allocated value PyTCP
uses is `ETHERNET = 1`, which fits both spaces.

---

## §2 — IANA Considerations: `ar$pro` (Protocol address space)

> "These numbers share the Ethertype space. The Ethertype
> space is administered as described in [RFC5342]."

**Adherence:** **met**. PyTCP's ARP header `prtype` field
is typed as `EtherType`
(`packages/net_proto/net_proto/protocols/arp/arp__header.py:82-86`), with
`EtherType.IP4 = 0x0800` consumed from the same registry
that governs the Ethernet II `type` field. The shared
registry semantic is preserved at the type-system level —
the `prtype` field uses the same Python enum that the
Ethernet II header uses, so a future protocol added to
`EtherType` would automatically be representable in ARP
without a separate registry table.

The `prtype` is hard-locked to `EtherType.IP4` via
`field(repr=False, init=False, default=EtherType.IP4)`
because PyTCP only resolves IPv4 addresses via ARP (IPv6
uses ND, which is RFC 4861, not RFC 826). This is a
single-protocol restriction, not a registry violation.

---

## §2 — IANA Considerations: `ar$op` (Opcode)

> "Requests for new ar$op values are made through IETF
> Review or IESG Approval [RFC5226]."

**Adherence:** **vacuous**. PyTCP does not request new
opcodes; it consumes the registered values
`REQUEST = 0x0001` and `REPLY = 0x0002` from the registry
(`packages/net_proto/net_proto/protocols/arp/arp__enums.py:49-50`). IETF
Review / IESG Approval is an IANA-side rule.

---

## §3 — Allocations Defined in This Document

### §3 — Experimental hardware-type allocations

> "Two new ar$hrd values are allocated for experimental
> purposes: HW_EXP1 (36) and HW_EXP2 (256). Note that
> these two new values were purposely chosen so that one
> would be below 256 and the other would be above 255 ..."

**Adherence:** **met (does not collide; rejects
experimental values on RX)**. PyTCP's `ArpHardwareType`
enum defines only `ETHERNET = 0x0001`; any incoming frame
with `ar$hrd = 36` or `ar$hrd = 256` is silently rejected
as `ArpIntegrityError`
(`packages/net_proto/net_proto/protocols/arp/arp__parser.py:84-85`). PyTCP
does not produce frames with these experimental values, so
no collision is possible on the TX side. This is the
expected behaviour for a non-experimental host.

### §3 — Experimental opcode allocations

> "Two new values for the ar$op are allocated for
> experimental purposes: OP_EXP1 (24) and OP_EXP2 (25)."

**Adherence:** **met (does not collide; rejects on RX)**.
PyTCP's `ArpOperation` enum defines only `REQUEST = 1` and
`REPLY = 2`. Inbound frames with `ar$op = 24`, `ar$op =
25`, or any other unknown opcode are caught by the sanity
check at
`packages/net_proto/net_proto/protocols/arp/arp__parser.py:110-114` —
`if self._header.oper.is_unknown` raises an
`ArpSanityError` (note: the `from_int` factory in
`ProtoEnumWord` constructs an "unknown" enum member rather
than raising, so the sanity check is the rejection path,
not the integrity check). The wire-side rejection ensures
PyTCP does not silently process experimental opcodes as
REQUEST or REPLY.

### §3 — Reserved values (`0` and `65535`)

> "In addition, for both ar$hrd and ar$op, the values 0 and
> 65535 are marked as reserved. This means that they are
> not available for allocation."

**Adherence:** **met (rejects both reserved values)**.

For `ar$hrd`:
- `ar$hrd = 0`: rejected by the integrity check at
  `arp__parser.py:84-85` because `0 != ETHERNET (1)`.
- `ar$hrd = 65535`: same path — rejected because `65535 !=
  ETHERNET`.

For `ar$op`:
- `ar$op = 0`: not in `ArpOperation`'s known-values set
  (`{REQUEST, REPLY}`), so the sanity check at
  `arp__parser.py:110-114` raises
  `ArpSanityError`.
- `ar$op = 65535`: same path — `is_unknown` is `True` so
  the sanity check rejects.

PyTCP's TX path likewise cannot emit these reserved values:
`ArpAssembler` requires `arp__oper: ArpOperation`
(typed enum), so passing a raw `0` or `65535` would fail
type construction. The hard-locked
`hrtype = ArpHardwareType.ETHERNET` field on
`ArpHeader` prevents `ar$hrd = 0` or `ar$hrd = 65535` on
emit.

---

## Test coverage audit

### §2 — `ar$hrd` consumed value (ETHERNET)

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/arp/test__arp__header__asserts.py::TestArpHeaderDefaults::test__arp__header__hrtype_default`
  — pins `ArpHeader().hrtype == ArpHardwareType.ETHERNET`.
- **Unit:**
  `..::test__arp__header__hrtype_cannot_be_overridden` —
  pins that `ArpHeader(hrtype=...)` is rejected (the field
  is `init=False`).

**Status:** **locked in**.

### §2 — `ar$pro` registry-shared semantic

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/arp/test__arp__header__asserts.py::TestArpHeaderDefaults::test__arp__header__prtype_default`
  — pins `ArpHeader().prtype == EtherType.IP4`.
- **Unit:**
  `..::test__arp__header__prlen_default` — pins
  `ArpHeader().prlen == 4` (consistent with IPv4).

**Status:** **locked in**.

### §2 — `ar$op` consumed values (REQUEST / REPLY)

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/arp/test__arp__assembler__operation.py::TestArpAssemblerPackets::test__arp__assembler__oper`
  — pins both `REQUEST` and `REPLY` round-trip on the
  wire.
- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/arp/test__arp__parser__sanity_checks.py::TestArpParserSanityChecks::test__arp__parser__sanity_error`
  — parametrised case "`oper` field value is unknown"
  raises `ArpSanityError`. This is the path that rejects
  experimental opcodes (24, 25) and reserved values (0,
  65535).

**Status:** **locked in**.

### §3 — Rejection of experimental hardware-type values

- **Unit:**
  `packages/net_proto/net_proto/tests/unit/protocols/arp/test__arp__parser__integrity_checks.py::TestArpParserIntegrityChecks::test__arp__parser__integrity_error`
  — parametrised case "hrtype != ETHERNET" raises
  `ArpIntegrityError` for any non-Ethernet hardware type
  including the experimental values (36, 256) and the
  reserved values (0, 65535). The test does not enumerate
  every hostile value individually; the integrity check
  rejects everything except `ETHERNET = 1`, so coverage is
  by-construction.

**Status:** **locked in**.

### Test coverage summary

| §  | Aspect                                              | Coverage    |
|----|-----------------------------------------------------|-------------|
| §2 | `ar$hrd` ETHERNET consumed                          | locked in   |
| §2 | `ar$pro` shares EtherType registry                  | locked in   |
| §2 | `ar$op` REQUEST / REPLY consumed                    | locked in   |
| §2 | `ar$op` unknown-value rejection (covers experimental + reserved) | locked in   |
| §3 | Experimental `ar$hrd` rejected on RX                | locked in   |
| §3 | Experimental `ar$op` rejected on RX                 | locked in   |
| §3 | Reserved `ar$hrd` (0, 65535) rejected on RX         | locked in   |
| §3 | Reserved `ar$op` (0, 65535) rejected on RX          | locked in   |
| §3 | Reserved values not emitted on TX                   | locked in (type-system + hard-locked dataclass field) |

---

## Overall assessment

| Aspect                                         | Status                                |
|------------------------------------------------|---------------------------------------|
| `ar$hrd` Expert Review / FCFS allocation       | vacuous (consumer, not allocator)     |
| `ar$pro` shares Ethertype registry             | met                                   |
| `ar$op` IETF Review allocation                 | vacuous (consumer, not allocator)     |
| Experimental `ar$hrd` (36, 256) collision-free | met                                   |
| Experimental `ar$op` (24, 25) collision-free   | met                                   |
| Reserved `ar$hrd` / `ar$op` (0, 65535) rejected on RX  | met                           |
| Reserved values cannot be emitted on TX         | met (type system + dataclass)        |

PyTCP's adherence to RFC 5494 is **complete**. The RFC is
administrative; PyTCP correctly consumes the IANA-assigned
values and rejects every reserved / experimental code point
it might encounter on the wire. The rejection happens at
the integrity-check layer (`hrtype`) or the sanity-check
layer (`oper`), and the corresponding tests pin both
behaviours. There are no compliance gaps in this RFC.
