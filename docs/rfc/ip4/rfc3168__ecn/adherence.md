# RFC 3168 — The Addition of Explicit Congestion Notification (ECN) to IP

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 3168                                                 |
| Title       | The Addition of Explicit Congestion Notification (ECN) to IP |
| Category    | Standards Track                                      |
| Date        | September 2001                                       |
| Updates     | RFC 2474, RFC 2401, RFC 793                          |
| Updated by  | RFC 4301, RFC 6040, RFC 8311                         |
| Source text | [`rfc3168.txt`](rfc3168.txt)                         |

This document records the PyTCP codebase's adherence to RFC 3168
for the **IP-layer portions** (the ECN codepoints on the IP
wire, the reassembly CE preservation rule). TCP-specific ECN
mechanics (ECE / CWR flags, ECN negotiation in SYN/SYN-ACK,
sender / receiver reactions) are out of scope here and audited
in the TCP RFC adherence records under `docs/rfc/tcp/`.

The audit was performed by reading the RFC text fresh and
inspecting `net_proto/protocols/ip4/ip4__header.py`,
`pytcp/stack/packet_handler/packet_handler__ip4__rx.py`, and
`pytcp/protocols/ip/ip_frag_table.py` directly. Non-normative
content (§1 Introduction, §2 Conventions, §3 Assumptions, §4
AQM background, §10-§22) is omitted.

---

## Top-line adherence

PyTCP **partial**: the wire codec for the 2-bit ECN field is
met; the §5.3 reassembly-preserves-CE rule is **not** met
today — reassembly currently inherits the first fragment's
ECN byte verbatim, which is conservative-enough in practice
(modern ECN-capable senders set DF=1) but is not strictly
RFC-compliant when ECN-capable fragments arrive. Documented
below as a Phase-1 sharpening.

| Section | Topic                                                | Status |
|---------|------------------------------------------------------|--------|
| §5      | ECN field structure (Not-ECT / ECT(0) / ECT(1) / CE) | met (wire codec) |
| §5      | CE codepoint MUST trigger congestion-control reaction | met (TCP side; see TCP audits) |
| §5.1    | Single CE = persistent congestion semantics          | met (transport-layer concern) |
| §5.2    | Dropped/corrupted ECN packets                        | n/a (host-layer only sees received packets) |
| §5.3    | Reassembly preserves CE across fragments             | **partial** — first-fragment ECN inherited, not OR'd |
| §6.1    | TCP-specific ECN mechanics                           | covered by TCP audits |
| §7      | Non-compliance by end nodes (sender/receiver lying)  | met (we honour CE on RX, we don't suppress on TX) |
| §8      | Non-compliance in network (CE erasure)               | n/a (router-side concern) |
| §9      | Encapsulated packets (IP-in-IP)                      | n/a (not implemented) |

---

## §5 ECN Field in IP

> "Bits 6 and 7 in the IPv4 TOS octet are designated as the ECN
> field."

**Adherence:** met. `Ip4Header.ecn: int` is the 2-bit field at
the low-order end of the TOS byte
(`net_proto/protocols/ip4/ip4__header.py:100,130`). Pack/unpack
preserve the bit positions
(`ip4__header.py:183,219`).

> "ECT(0) codepoint is '10', ECT(1) codepoint is '01', CE
> codepoint is '11', Not-ECT codepoint is '00'."

**Adherence:** met. The field is unstructured at the IP layer
— any of the four codepoints is accepted on receive and
preserved on send. The TX entry point exposes
`ip4__ecn: int = 0` as a kwarg
(`pytcp/stack/packet_handler/packet_handler__ip4__tx.py:101`)
so callers can set ECT(0) or ECT(1) on outbound packets; the
RX parser surfaces the received value as
`packet_rx.ip4.ecn`.

> "Routers treat the ECT(0) and ECT(1) codepoints as
> equivalent."

**Adherence:** n/a (PyTCP is a host stack, not a router). The
host treats the field as an opaque preserved-on-wire value.

> "Upon the receipt by an ECN-Capable transport of a single
> CE packet, the congestion control algorithms followed at the
> end-systems MUST be essentially the same as the congestion
> control response to a *single* dropped packet."

**Adherence:** met (transport-layer side). The IP layer passes
the ECN field up to TCP via `packet_rx.ip4.ecn`; TCP records
the codepoint on the per-segment metadata and feeds it into
the AccECN / classic-ECN state machine. Cross-references:
`docs/rfc/tcp/` for the TCP ECN mechanics.

## §5.3 Fragmentation

> "ECN-capable packets MAY have the DF (Don't Fragment) bit set.
> Reassembly of a fragmented packet MUST NOT lose indications
> of congestion. In other words, if any fragment of an IP
> packet to be reassembled has the CE codepoint set, then one
> of two actions MUST be taken:
> * Set the CE codepoint on the reassembled packet. However,
>   this MUST NOT occur if any of the other fragments
>   contributing to this reassembly carries the Not-ECT
>   codepoint.
> * The packet is dropped, instead of being reassembled."

**Adherence:** **partial — Phase 1 gap.** PyTCP's reassembly
rewrite at `packet_handler__ip4__rx.py:337-341` does:

```python
header = bytearray(header_bytes)  # first fragment's header
header[0] = 0x45                  # ver=4, IHL=5 (options dropped)
struct.pack_into("!H", header, 2, IP4__HEADER__LEN + len(payload))
header[6] = header[7] = header[10] = header[11] = 0  # Flags+Offset, cksum
struct.pack_into("!H", header, 10, inet_cksum(memoryview(header)))
```

The TOS byte (offset 1 of the IPv4 header) is **inherited from
the first fragment** without aggregating ECN across fragments.
This means:

- If the first fragment carries CE and all subsequent fragments
  carry ECT(0) / ECT(1) / CE → reassembled packet shows CE
  (correct).
- If the first fragment carries ECT(0) and a later fragment
  carries CE → reassembled packet shows ECT(0) and the CE
  indication is **lost** (RFC 3168 §5.3 violation).
- If the first fragment carries CE and a later fragment
  carries Not-ECT → reassembled packet shows CE. RFC 3168 says
  this MUST NOT happen ("MUST NOT occur if any of the other
  fragments ... carries the Not-ECT codepoint") — the
  alternative is to **drop** the reassembled packet, which we
  do not.

Practical impact today is low: modern ECN-capable transports
(TCP since Linux 2.4, recent macOS / Windows) set DF=1 on
ECN-capable segments to avoid in-network fragmentation
(RFC 3168 §5.3 notes this is the reason DF avoidance is
recommended on ECN-capable senders). PyTCP itself currently
emits ECT only on TCP segments with DF=1 inferred from PMTUD.
But the RFC requires correctness regardless.

**Phase-1 fix sketch:** in `packet_handler__ip4__rx.py:337`
walk every stored fragment's TOS byte, compute the aggregated
ECN per RFC 3168 §5.3 (CE if any fragment is CE *and* no
fragment is Not-ECT; drop if mixed CE + Not-ECT; otherwise
preserve), then patch byte 1 of the reassembled header
accordingly. The fragment-store retention of the per-fragment
header is already in place (`IpFragData.payload` keys fragments
by offset; the full source headers are not retained today —
only the first fragment's). A small refactor is needed to
also retain the per-fragment TOS byte; one byte per fragment
is cheap.

Marked here so the upgrade is greppable:

```python
# Phase 1: aggregate ECN per RFC 3168 §5.3 across fragments.
```

## §6.1 TCP — ECN negotiation, ECE / CWR, sender/receiver mechanics

**Adherence:** covered separately by the TCP RFC adherence
records. The IP-layer audit here only asserts that ECN bits
are passed up to TCP intact (`packet_rx.ip4.ecn` exposed on
the parser) and that outbound TCP segments can request
specific ECN codepoints via the `ip4__ecn` kwarg through to
`Ip4Assembler`.

## §7 Non-compliance by End Nodes

> "End nodes that are sending non-ECN-capable IP packets MUST
> set the ECN field to '00' (Not-ECT)."

**Adherence:** met. The default for `ip4__ecn` is 0
(`packet_handler__ip4__tx.py:101`,
`ip4__assembler.py:68`) — every outbound packet is Not-ECT
unless an ECN-aware transport explicitly sets ECT(0) or
ECT(1).

## §8 Non-compliance in the Network (CE erasure)

**Adherence:** n/a — router-side concern. PyTCP does not
forward; the RX path preserves the received ECN value into
`packet_rx.ip4.ecn` and the upper layer decides what to do.

## §9 Encapsulated Packets (IP-in-IP)

**Adherence:** not implemented. PyTCP does not implement IP-in-IP
tunnelling (RFC 2003 / RFC 4380). When tunnel support lands,
this section's ECN-tunnel rules (limited-functionality vs.
full-functionality decapsulation) become relevant.

---

## Test coverage audit

### §5 ECN field wire codec

- **Unit:**
  `net_proto/tests/unit/protocols/ip4/test__ip4__header__asserts.py`
  Boundary assert on `ecn` field (uint2: 0-3).
- **Unit:**
  `net_proto/tests/unit/protocols/ip4/test__ip4__parser__operation.py`
  Round-trip matrix exercises all 4 ECN codepoints.
- **Unit:**
  `net_proto/tests/unit/protocols/ip4/test__ip4__assembler__operation.py`
  Assembler round-trip across ECN values.

**Status:** locked in.

### §5 ECN bit propagation up to TCP

- **Integration:** TCP integration suite includes ECN-
  negotiation cases that exercise the `packet_rx.ip4.ecn`
  read path. See `docs/rfc/tcp/` for the TCP-side audits.

**Status:** locked in via TCP audits.

### §5 Default ECN=00 (Not-ECT) on send

- **Integration:**
  `pytcp/tests/integration/test__packet_handler__ip4__tx.py`
  Default cases ship with `ecn=0`. The TCP-side ECN
  negotiation tests override to ECT(0).

**Status:** locked in.

### §5.3 Reassembly preserves CE

**No test surface — Phase-1 gap.** When the fix lands, the
natural tests are:

1. Three-fragment reassembly: first carries ECT(0), middle
   carries CE, last carries ECT(0) → reassembled packet
   carries CE.
2. Mixed-Not-ECT/CE fragments → reassembled packet is dropped
   (or alternative behaviour per the §5.3 second branch).
3. All fragments same ECN → reassembled packet carries that
   ECN (regression test for the current behaviour, which is
   correct in this sub-case).

### §9 IP-in-IP tunnel ECN handling

**No test surface — not implemented.**

### Test coverage summary

| Aspect                                                | Coverage |
|-------------------------------------------------------|----------|
| §5 ECN wire codec round-trip                          | locked in |
| §5 ECN bit propagation to TCP                         | locked in via TCP audits |
| §5 Default Not-ECT on send                            | locked in |
| §5.3 Reassembly CE preservation                       | n/a (gap not closed; add test with fix) |
| §6.1 TCP-specific ECN mechanics                       | covered by TCP audits |
| §9 IP-in-IP tunnel handling                           | n/a (not implemented) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §5 ECN wire format                                  | met    |
| §5 ECN bit propagation to transport                 | met    |
| §5 Default Not-ECT on send                          | met    |
| §5.3 Reassembly preserves CE                        | **partial — Phase 1 gap** |
| §6.1 TCP-side ECN (negotiation, ECE/CWR, reactions) | met (audited in TCP records) |
| §7 End-node non-compliance protections              | met    |
| §8 Network non-compliance                           | n/a (router) |
| §9 IP-in-IP tunnel handling                         | n/a (not implemented) |

The principal Phase-1 gap is **§5.3 reassembly CE
preservation**. The fix is small (retain per-fragment TOS
byte; aggregate at reassembly time) and the test surface is
straightforward to add. Marked in the audit as the only
non-trivial RFC 3168 outstanding item.
