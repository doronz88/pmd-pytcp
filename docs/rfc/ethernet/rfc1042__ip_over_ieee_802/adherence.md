# RFC 1042 — A Standard for the Transmission of IP Datagrams over IEEE 802 Networks

| Field       | Value                                                  |
|-------------|--------------------------------------------------------|
| RFC number  | 1042                                                   |
| Title       | A Standard for the Transmission of IP Datagrams over IEEE 802 Networks |
| Category    | Internet Standard                                      |
| Date        | February 1988                                          |
| Obsoletes   | RFC 948                                                |
| Source text | [`rfc1042.txt`](rfc1042.txt)                           |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 1042. The audit was performed by reading
the RFC text fresh against the codebase under `packages/net_proto/net_proto/`
and `packages/pytcp/pytcp/` directly. Sections that contain no normative
content (Status of this Memo, Introduction,
Acknowledgments, 802.4 / 802.5 / FDDI / Token-Ring
physical-layer specifics that aren't relevant to a
TAP/TUN host substrate, References) are omitted.

---

## Top-line adherence

PyTCP implements the **inbound** RFC 1042 LLC + SNAP
parsing and dispatch path. After commits `bd0a90a8` (LLC +
SNAP protocol modules) and `61810a40` (802.3 RX dispatch
rewrite), the stack parses IEEE 802.3 frames through the
LLC and SNAP layers and routes recognised traffic to the
correct consumer:

- RFC 1042 IP-over-SNAP frames (OUI = 0x000000, PID =
  IP4 / IP6 / ARP) are dispatched to the regular Ethernet
  II per-protocol handlers — IP runs end-to-end on a
  SNAP-encapsulated wire.
- Cisco-OUI SNAP frames (OUI = 0x00000C, PID = CDP / VTP
  / DTP / PVST+ / UDLD / etc.) are logged with
  protocol-specific drop counters.
- Non-SNAP LLC traffic (STP BPDUs, Novell IPX, Global
  DSAP) is logged with DSAP-specific drop counters.

The **outbound** RFC 1042 TX path is not implemented —
PyTCP's TX path produces Ethernet II framing exclusively.
The Class I LLC service responses (XID, TEST commands) are
not implemented; PyTCP recognises the Control field values
in parsed frames but does not generate responses (matches
Linux's pragmatic behaviour where the LLC stack does not
generate XID / TEST responses without explicit consumer).

| Mechanism                                          | Status                              |
|----------------------------------------------------|-------------------------------------|
| IEEE 802.3 framing (length field at offset 12)     | met                                 |
| 802.2 LLC header (DSAP / SSAP / Control) parsing   | met (U-frame / 1-byte Control)      |
| 802.2 I-frame / S-frame (2-byte Control)           | not implemented (Type 2 connection-oriented LLC, out of scope) |
| SNAP extension (OUI / EtherType after LLC)         | met                                 |
| 802.2 Type 1 (UI) connectionless mode              | met (parse-side)                    |
| Class I service — UI command parsing               | met                                 |
| Class I service — XID / TEST response generation   | not implemented                     |
| RFC 1042 IP-over-SNAP dispatch (OUI=0, PID=IP)     | met                                 |
| Cisco-proprietary SNAP recognition + logging       | met (CDP / VTP / DTP / PVST+ / UDLD / CGMP / VLAN-Bridge) |
| Novell IPX over 802.2 recognition + logging        | met                                 |
| ARP hrtype `= 6` for IEEE 802                      | not implemented (PyTCP uses hrtype `= 1` per RFC 826; matches Linux) |
| Broadcast IP → all-ones IEEE 802 MAC               | met (same mapping as RFC 894)       |
| 16-bit physical addresses                          | not implemented (48-bit only; matches Linux) |
| Outbound 802.3 + LLC + SNAP TX                     | not implemented (TX is Ethernet II only) |
| Big-endian byte order                              | met                                 |
| 4.2bsd trailer encapsulation                       | out of scope (RFC 893 deprecated)   |

---

## §"Description" — Encapsulation Model

> "IP datagrams are sent on IEEE 802 networks
> encapsulated within the 802.2 LLC and SNAP data link
> layers, and the 802.3, 802.4, or 802.5 physical
> networks layers. The SNAP is used with an Organization
> Code indicating that the following 16 bits specify the
> EtherType code (as listed in Assigned Numbers)."

**Adherence:** met (inbound). PyTCP's
`packages/net_proto/net_proto/protocols/ethernet_802_3/` parses the 802.3
MAC framing; `packages/net_proto/net_proto/protocols/llc/` parses the LLC
header; `packages/net_proto/net_proto/protocols/snap/` parses the SNAP
extension. The runtime dispatch at
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ethernet_802_3__rx.py`
chains the three: 802.3 → LLC → (SNAP when DSAP=0xAA).
For OUI=0x000000 (RFC 1042 canonical), the PID is
interpreted as a standard EtherType and the frame is
dispatched to the matching Ethernet II per-protocol
handler (`_phrx_ip4` / `_phrx_ip6` / `_phrx_arp`).

---

## §"Description" — 802.2 Type 1 (UI) Mode Required

> "Normally, all communication is performed using 802.2
> type 1 communication. [...] However, type 1
> communication is the recommended method at this time
> and must be supported by all implementations."

**Adherence:** met (inbound). The LLC parser at
`packages/net_proto/net_proto/protocols/llc/llc__parser.py` requires the
Control field's low two bits to be `0b11` (U-frame /
Type 1) and rejects I-frame and S-frame variants
(Type 2 connection-oriented). For the canonical UI
command (Control = `0x03`), the parser accepts and
dispatches by DSAP.

---

## §"Description" — 16-bit and 48-bit Physical Addresses

> "The IEEE 802 networks may have 16-bit or 48-bit
> physical addresses."

**Adherence:** partial — 48-bit MAC only. PyTCP's
`MacAddress` value type supports only 48-bit MAC. The
16-bit variant (historically used by IEEE 802.5 Token
Ring) is not supported. Aligns with Linux's universal
48-bit MAC assumption.

---

## §"Header Format" — LLC+SNAP 8-octet Total

> "The total length of the LLC Header and the SNAP
> header is 8-octets, making the 802.2 protocol overhead
> come out on an nice boundary. The K1 value is 170
> (decimal). The K2 value is 0 (zero). The control value
> is 3 (Unnumbered Information)."

**Adherence:** met. The LLC header is 3 octets
(`packages/net_proto/net_proto/protocols/llc/llc__header.py::LLC__HEADER__LEN
= 3`) and the SNAP header is 5 octets
(`packages/net_proto/net_proto/protocols/snap/snap__header.py::SNAP__HEADER__LEN
= 5`), totalling 8. K1 = `0xAA` = `LlcSap.SNAP`
(`llc__enums.py`), K2 = `0x000000` =
`SnapOui.ENCAP_ETHERTYPE` (`snap__enums.py`), control
= `LlcControl.UI` = `0x03` (`llc__enums.py`).

---

## §"Address Mappings" — Dynamic Discovery via ARP

> "The mapping of 32-bit Internet addresses to 16-bit or
> 48-bit IEEE 802 addresses must be done via the dynamic
> discovery procedure of the Address Resolution Protocol
> (ARP)."

**Adherence:** met (covered by RFC 826 / RFC 894
adherence). PyTCP performs ARP-based dynamic resolution
for IPv4 destinations; the resolution path is
family-agnostic and applies to both Ethernet II and 802.3
RX paths. When an RFC 1042 SNAP-encapsulated ARP frame
arrives, the `__dispatch_rfc1042` helper forwards it to
`_phrx_arp` for processing — closing the IP-and-ARP
interop loop on RFC 1042 wires.

---

## §"Address Mappings" — ARP Hardware Type Code `= 6`

> "The hardware type code assigned for the IEEE 802
> networks (of all kinds) is 6 (see [7] page 16). The
> protocol type code for IP is 2048 (see [7] page 14).
> The hardware address length is 2 for 16-bit IEEE 802
> addresses, or 6 for 48-bit IEEE 802 addresses. The
> protocol address length (for IP) is 4. The operation
> code is 1 for request and 2 for reply."

**Adherence:** not implemented. PyTCP emits ARP requests
with `hrtype = 1` (`ArpHardwareType.ETHERNET` per
RFC 826) regardless of whether the underlying framing is
RFC 894 or RFC 1042. Matches Linux's pragmatic behaviour
— Linux's `arp(7)` uses `hrtype = 1` on all
Ethernet-class interfaces. The hardware-type distinction
has fallen out of practical use. Protocol type code
(`0x0800` for IP), HW-addr length (6), and proto-addr
length (4) match.

---

## §"Broadcast Address" — All-Ones IEEE 802 MAC

> "The broadcast Internet address (the address on that
> network with a host part of all binary ones) should
> be mapped to the broadcast IEEE 802 address (of all
> binary ones) (see [8] page 14)."

**Adherence:** met (same mapping as RFC 894). The
broadcast MAC `FF:FF:FF:FF:FF:FF` is shared between
RFC 894 and RFC 1042; PyTCP's mapping
(`packages/net_addr/net_addr/mac_address.py:42`) covers both.

---

## §"Trailer Formats"

> "Some versions of Unix 4.x bsd use a different
> encapsulation method [...]. Consenting systems on the
> same IEEE 802 network may use this format between
> themselves. Details of the trailer encapsulation
> method may be found in [9]. However, all hosts must be
> able to communicate using the standard (non-trailer)
> method."

**Adherence:** out of scope (deliberate non-goal — same
RFC 893 trailer deprecation as RFC 894). PyTCP does not
emit or accept trailer-encapsulated frames.

---

## §"Byte Order" — Big-Endian Transmission

> "As described in Appendix B of the Internet Protocol
> specification, the IP datagram is transmitted over IEEE
> 802 networks as a series of 8-bit bytes. This byte
> transmission order has been called 'big-endian'."

**Adherence:** met. PyTCP's struct-pack format strings
use `"!"` prefix universally (LLC, SNAP, IP4, IP6, TCP,
UDP, ARP).

---

## §"Maximum Transmission Unit" — 802.3 Max 1492 octets for IP

> "[For IEEE 802.3] This allows 1518 - 18 (MAC
> header+trailer) - 8 (LLC+SNAP header) = 1492 for the
> IP datagram (including the IP header). Note that 1492
> is not equal to 1500 which is the MTU for Ethernet
> networks."

**Adherence:** not enforced separately. PyTCP's MTU
policy follows the RFC 894 Ethernet II model
(1500-byte data field, jumbo-frame overrides via
`stack.interface_mtu`). The TX path does not emit 802.3
+ LLC + SNAP frames, so the 1492-byte bound is not
applicable to outbound traffic. Inbound SNAP frames
carrying IP are accepted up to the receiver's
`interface_mtu` ceiling.

---

## §"IEEE 802.2 Details" — Class I Service (UI / XID / TEST)

> "While not necessary for supporting IP and ARP, all
> implementations are required to support IEEE 802.2
> standard Class I service. This requires supporting
> Unnumbered Information (UI) Commands, eXchange
> IDentification (XID) Commands and Responses, and TEST
> link (TEST) Commands and Responses."

**Adherence:** partial — UI commands fully supported on
the parse side (and dispatched into the LLC/SNAP/IP
pipeline). XID and TEST commands are recognised by the
parser (their Control field values are encoded in
`LlcControl` for log purposes) but **no responses are
generated**. This matches Linux's `net/llc/` pragmatic
behaviour where XID / TEST response generation requires
an explicit registered LLC consumer; without one, the
kernel does not auto-respond. PyTCP has no XID / TEST
consumer today.

---

## Test coverage audit

### IEEE 802.3 framing

- **Unit:** `packages/net_proto/net_proto/tests/unit/protocols/ethernet_802_3/`
  — pins MAC header parse / assemble.

**Status:** locked in.

### LLC parsing + DSAP dispatch

- **Unit:** `packages/net_proto/net_proto/tests/unit/protocols/llc/test__llc__header__asserts.py`
  (4 tests) — LlcSap / LlcControl constructor validation.
- **Unit:** `packages/net_proto/net_proto/tests/unit/protocols/llc/test__llc__parser__operation.py`
  (6 tests) — STP BPDU, SNAP indicator, packet_rx slot,
  short-frame integrity, I/S-frame rejection, unknown
  DSAP accepted.

**Status:** locked in.

### SNAP parsing + OUI/PID dispatch

- **Unit:** `packages/net_proto/net_proto/tests/unit/protocols/snap/test__snap__parser__operation.py`
  (5 tests) — RFC 1042 IP-over-SNAP, Cisco CDP frame,
  packet_rx slot, short-frame integrity,
  assembler/parser round-trip.

**Status:** locked in.

### 802.3 + LLC + SNAP runtime dispatch

- **Integration:** `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__ethernet_802_3__llc_snap.py`
  (10 tests) — STP BPDU, Cisco CDP / VTP / DTP / PVST+
  / UDLD, Novell IPX over 802.2, RFC 1042 SNAP-IP4,
  RFC 1042 SNAP-ARP, Cisco-multicast-MAC filter
  precedence.

**Status:** locked in.

### Test harness coverage

- **Harness:** `packages/pytcp/pytcp/tests/lib/ethernet_802_3_testcase.py`
  — `Ethernet8023TestCase` with frame builders for STP
  BPDU, Cisco SNAP (per protocol), RFC 1042 SNAP-EtherType,
  Novell IPX over 802.2, plus `_drive_802_3_rx` helper.
- **Harness:** `packages/pytcp/pytcp/tests/lib/ethernet_testcase.py`
  — `EthernetTestCase` with Ethernet II frame builders
  (`_build_ethernet_frame` / `_build_broadcast_ethernet_frame`)
  + `_drive_ethernet_rx` helper.

### Test coverage summary

| Aspect                                              | Coverage                  |
|-----------------------------------------------------|---------------------------|
| 802.3 framing (length field at offset 12)           | locked in                 |
| LLC header parsing + DSAP dispatch                  | locked in                 |
| SNAP extension parsing + OUI/PID dispatch           | locked in                 |
| RFC 1042 IP-over-SNAP runtime dispatch              | locked in                 |
| Cisco SNAP recognition (CDP/VTP/DTP/PVST+/UDLD)     | locked in                 |
| Novell IPX over 802.2 recognition                   | locked in                 |
| Class I service — XID / TEST responses              | n/a (not implemented)     |
| ARP hrtype `= 6` for IEEE 802                       | n/a (PyTCP uses hrtype `= 1`) |
| Broadcast IP → all-ones MAC                         | locked in (shared with RFC 894) |
| Big-endian byte order                               | locked in                 |
| Outbound 802.3 + LLC + SNAP TX                      | n/a (deliberate non-goal) |

---

## Overall assessment

| Aspect                                              | Status                                       |
|-----------------------------------------------------|----------------------------------------------|
| IEEE 802.3 framing                                  | met                                          |
| 802.2 LLC header (U-frame, 1-byte Control)          | met                                          |
| 802.2 LLC I-frame / S-frame (2-byte Control)        | not implemented (Type 2, out of scope)       |
| SNAP extension parsing                              | met                                          |
| Class I service — UI command parsing                | met                                          |
| Class I service — XID / TEST response generation    | not implemented (Linux-pragmatic; matches kernel) |
| RFC 1042 IP-over-SNAP inbound dispatch              | met                                          |
| Cisco / Novell SNAP recognition + logging           | met                                          |
| ARP hrtype `= 6` for IEEE 802                       | not implemented (uses RFC 826 hrtype `= 1`)  |
| Broadcast IP → all-ones MAC                         | met                                          |
| 16-bit physical addresses                           | not implemented (48-bit only)                |
| Outbound 802.3 + LLC + SNAP TX                      | not implemented (deliberate)                 |
| Trailer encapsulation                               | out of scope (deliberate)                    |
| Big-endian byte order                               | met                                          |

**Principal gaps:**
1. **TX path stays Ethernet II only.** PyTCP does not
   emit RFC 1042 frames. Future consumers who need to
   speak STP / Cisco-management / SNAP-IP back to the
   wire would need a corresponding TX path. No current
   roadmap item.
2. **Class I XID / TEST response generation.** Linux
   skips this without an explicit consumer; PyTCP
   follows the same pragmatic stance.
3. **16-bit physical addresses.** Token Ring / FDDI
   legacy; never had practical demand on a TAP/TUN
   substrate.

The major operational outcome of this implementation: any
PyTCP instance on a switched local network will now
correctly identify and log Cisco-proprietary management
traffic (CDP, VTP, DTP, PVST+, UDLD), IEEE 802.1 STP
BPDUs, and any legacy Novell IPX still on the wire —
instead of silently dropping these frames as it did
before. Operators get per-protocol drop counters they can
read via `packet_stats_rx` for log analysis.
