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
the RFC text fresh against the codebase under `net_proto/`
and `pytcp/` directly. Sections that contain no normative
content (Status of this Memo, Introduction, Acknowledgments,
802.4 / 802.5 / FDDI / Token-Ring physical-layer specifics
that aren't relevant to a TAP/TUN host substrate,
References) are omitted.

---

## Top-line adherence

PyTCP **does not implement RFC 1042**'s LLC+SNAP
encapsulation. The `net_proto/protocols/ethernet_802_3/`
module implements the IEEE 802.3 framing layer (the
variant with a 16-bit length field at offset 12 instead
of the Ethernet II type field) but does not parse the
802.2 LLC header (DSAP/SSAP/Control) or the SNAP
extension (OUI/EtherType) on top of it. Inbound 802.3
frames carrying IP-over-LLC+SNAP would be framed
correctly at the MAC layer but then fail at the next
parser stage because the LLC+SNAP 8 bytes are passed
through verbatim as if they were the start of the IP
header.

This is a **deliberate non-goal** for PyTCP. Modern
hosts (Linux, BSD, Windows) use Ethernet II framing
(RFC 894) exclusively for IP-over-Ethernet, and RFC 1042
is only required for legacy IEEE 802.3 / 802.4 / 802.5 /
FDDI / Token-Ring networks where the wire framing
mandates LLC. PyTCP's TAP/TUN substrate is always
Ethernet II compatible.

| Mechanism                                          | Status                                |
|----------------------------------------------------|---------------------------------------|
| IEEE 802.3 framing (length field at offset 12)     | partial (framing only, no LLC/SNAP)   |
| 802.2 LLC header (DSAP / SSAP / Control)           | **not implemented**                   |
| SNAP extension (OUI / EtherType after LLC)         | **not implemented**                   |
| 802.2 Type 1 (UI) connectionless mode              | n/a (no LLC implemented)              |
| 802.2 Type 2 (connection-oriented) mode            | n/a (out of scope)                    |
| Class I service — UI / XID / TEST commands         | **not implemented**                   |
| ARP hrtype `= 6` for IEEE 802                      | **not implemented** (PyTCP uses hrtype `= 1` per RFC 826) |
| Broadcast IP → all-ones IEEE 802 MAC               | met (same mapping as RFC 894)         |
| Min packet size (28 octets IP / 24 octets ARP)     | n/a (no LLC encap)                    |
| 802.3 max packet 1518 (MTU 1492 for IP)            | n/a (no LLC encap)                    |
| Big-endian byte order                              | met                                   |
| 4.2bsd trailer encapsulation                       | out of scope (RFC 893 deprecated)     |

---

## §"Description" — Encapsulation Model

> "IP datagrams are sent on IEEE 802 networks
> encapsulated within the 802.2 LLC and SNAP data link
> layers, and the 802.3, 802.4, or 802.5 physical
> networks layers. The SNAP is used with an Organization
> Code indicating that the following 16 bits specify the
> EtherType code (as listed in Assigned Numbers)."

**Adherence:** not implemented. PyTCP's IEEE 802.3 parser
at `net_proto/protocols/ethernet_802_3/ethernet_802_3__parser.py`
reads only the 14-byte MAC header (dst, src, dlen) and
treats the remaining bytes as opaque payload. The 802.2
LLC header (DSAP=`0xAA`, SSAP=`0xAA`, Control=`0x03`)
and the 8-byte SNAP extension (3-byte OUI + 2-byte
EtherType) are not parsed; they would arrive as the first
8 bytes of `packet_rx.frame` after the MAC header is
stripped, where the next stage (IP / ARP parser) would
fail to recognize them as a valid protocol header.

---

## §"Description" — 802.2 Type 1 (UI) Mode Required

> "Normally, all communication is performed using 802.2
> type 1 communication. [...] However, type 1
> communication is the recommended method at this time
> and must be supported by all implementations."

**Adherence:** not implemented (vacuous — no LLC layer
exists to choose a type for).

---

## §"Description" — 16-bit and 48-bit Physical Addresses

> "The IEEE 802 networks may have 16-bit or 48-bit
> physical addresses."

**Adherence:** partial. PyTCP's `MacAddress` value type
at `net_addr/mac_address.py` supports only 48-bit MAC
addresses. The 16-bit variant (used historically by
IEEE 802.5 Token Ring) is not supported. This aligns
with universal modern practice — Linux, BSD, and
Windows all assume 48-bit MAC throughout.

---

## §"Header Format" — LLC+SNAP 8-octet Total

> "The total length of the LLC Header and the SNAP
> header is 8-octets, making the 802.2 protocol overhead
> come out on an nice boundary. The K1 value is 170
> (decimal). The K2 value is 0 (zero). The control value
> is 3 (Unnumbered Information)."

**Adherence:** not implemented. The constants `K1=170`
(`0xAA`), `K2=0`, control=`3`, OUI=`00:00:00` are not
encoded anywhere in PyTCP. If RFC 1042 support is ever
added, these constants belong in
`net_proto/protocols/ethernet_802_3/ethernet_802_3__constants.py`
as module-level invariants.

---

## §"Address Mappings" — Dynamic Discovery via ARP

> "The mapping of 32-bit Internet addresses to 16-bit or
> 48-bit IEEE 802 addresses must be done via the dynamic
> discovery procedure of the Address Resolution Protocol
> (ARP)."

**Adherence:** met (covered by RFC 826 / RFC 894
adherence). PyTCP performs ARP-based dynamic resolution
for IPv4 destinations in its Ethernet II / 802.3 TX
paths; the resolution path is family-agnostic so it
satisfies RFC 1042's mandate even though the LLC/SNAP
encapsulation around the ARP-resolved Ethernet frame
isn't implemented.

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
with `hrtype = 1` (`ArpHardwareType.ETHERNET` at
`net_proto/protocols/arp/arp__enums.py`), which is the
RFC 826 codepoint for "regular" Ethernet rather than the
RFC 1042 codepoint for "IEEE 802" (`= 6`). This matches
Linux's pragmatic behaviour — Linux's `arp(7)` uses
`hrtype = 1` on all Ethernet-class interfaces regardless
of whether the underlying framing is RFC 894 or RFC 1042,
because the hardware-type distinction has fallen out of
practical use. The protocol type code (`0x0800` for IP),
hardware-address length (6 for 48-bit MAC), and protocol-
address length (4 for IPv4) match RFC 1042 and are also
met.

---

## §"Broadcast Address" — All-Ones IEEE 802 MAC

> "The broadcast Internet address (the address on that
> network with a host part of all binary ones) should
> be mapped to the broadcast IEEE 802 address (of all
> binary ones) (see [8] page 14)."

**Adherence:** met (same mapping as RFC 894). The
broadcast Ethernet MAC `FF:FF:FF:FF:FF:FF` is shared
between RFC 894 and RFC 1042; PyTCP's mapping
(`net_addr/mac_address.py:42`) covers both.

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
use `"!"` prefix universally.

---

## §"Maximum Transmission Unit" — 802.3 Max 1492 octets for IP

> "[For IEEE 802.3] This allows 1518 - 18 (MAC
> header+trailer) - 8 (LLC+SNAP header) = 1492 for the
> IP datagram (including the IP header). Note that 1492
> is not equal to 1500 which is the MTU for Ethernet
> networks."

**Adherence:** not applicable. The 1492-byte MTU bound
is specific to 802.3+LLC+SNAP encapsulation, which PyTCP
does not implement. PyTCP's MTU policy follows the RFC
894 Ethernet II model (1500-byte data field, jumbo-frame
overrides via `stack.interface_mtu`).

---

## §"IEEE 802.2 Details" — Class I Service (UI / XID / TEST)

> "While not necessary for supporting IP and ARP, all
> implementations are required to support IEEE 802.2
> standard Class I service. This requires supporting
> Unnumbered Information (UI) Commands, eXchange
> IDentification (XID) Commands and Responses, and TEST
> link (TEST) Commands and Responses."

**Adherence:** not implemented (vacuous — no LLC layer).
XID and TEST commands at the LLC layer are not relevant
to a pure Ethernet II / TAP-substrate host stack.

---

## Test coverage audit

### IEEE 802.3 framing (the partial implementation that exists)

- **Unit:** `net_proto/tests/unit/protocols/ethernet_802_3/`
  — pins MAC header parse / assemble for the 802.3 framing
  layer (dst, src, dlen).

**Status:** locked in for the framing layer; nothing
above the MAC header is implemented or tested.

### LLC+SNAP encapsulation (the missing piece)

**No test surface — gap not closed.** If RFC 1042 ever
becomes a requirement (e.g. PyTCP grows a Token Ring
or FDDI driver, or interoperates with a legacy SNAP-
encapsulated peer), the natural test is one that:

1. Constructs an Ethernet 802.3 frame whose payload
   begins with the LLC+SNAP 8-byte header
   (`AA AA 03 00 00 00 08 00 ...`).
2. Drives it into the stack and asserts the IP layer
   sees the IP header at the correct offset (i.e. the
   parser strips the LLC+SNAP overhead before dispatch).

### Test coverage summary

| Aspect                                              | Coverage                  |
|-----------------------------------------------------|---------------------------|
| 802.3 framing (length field at offset 12)           | locked in (framing only)  |
| LLC header parsing                                  | n/a (not implemented)     |
| SNAP extension parsing                              | n/a (not implemented)     |
| Class I service (UI / XID / TEST)                   | n/a (not implemented)     |
| ARP hrtype `= 6` for IEEE 802                       | n/a (PyTCP uses hrtype `= 1`) |
| Broadcast IP → all-ones MAC                         | locked in (shared with RFC 894) |
| Big-endian byte order                               | locked in                 |

---

## Overall assessment

| Aspect                                              | Status                                       |
|-----------------------------------------------------|----------------------------------------------|
| IEEE 802.3 framing (length field at offset 12)      | partial (framing only)                       |
| 802.2 LLC + SNAP encapsulation                      | not implemented (deliberate non-goal)        |
| Class I service (UI / XID / TEST)                   | not implemented (deliberate non-goal)        |
| ARP hrtype `= 6` for IEEE 802                       | not implemented (uses RFC 826 hrtype `= 1`)  |
| Broadcast IP → all-ones MAC                         | met                                          |
| 16-bit physical addresses                           | not implemented (48-bit only)                |
| Trailer encapsulation                               | out of scope (deliberate)                    |
| Big-endian byte order                               | met                                          |

**Principal gap:** the entire LLC+SNAP encapsulation
layer. This is a **deliberate non-goal** for PyTCP per
the project's host-stack scope. The
`net_proto/protocols/ethernet_802_3/` framing module
exists primarily for parser-pipeline completeness — it
handles inbound 802.3 frames at the MAC layer so they
don't crash the stack, but it does not pretend to
implement the RFC 1042 LLC/SNAP stack above it. If
production users ever need RFC 1042 interop (legacy
802.3-only networks, Token Ring, FDDI), the
implementation track would be:

1. Add `Llc802__Parser` / `Llc802__Assembler` under
   `net_proto/protocols/llc_802_2/` covering DSAP /
   SSAP / Control field interpretation.
2. Add `SnapParser` / `SnapAssembler` under
   `net_proto/protocols/snap/` covering OUI / EtherType.
3. Wire 802.3 frames through LLC → SNAP → IP/ARP
   in the packet handler.
4. Optionally implement Class I LLC service (XID / TEST).

Estimated effort: 1-2 days for the parse/assemble
plumbing; another day for the runtime dispatch path
and tests. Not on the current roadmap.
