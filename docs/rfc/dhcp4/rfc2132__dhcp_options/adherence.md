# RFC 2132 — DHCP Options and BOOTP Vendor Extensions

| Field       | Value                                       |
|-------------|---------------------------------------------|
| RFC number  | 2132                                        |
| Title       | DHCP Options and BOOTP Vendor Extensions    |
| Category    | Standards Track                             |
| Date        | March 1997                                  |
| Updates     | RFC 1497, RFC 1533                          |
| Source text | [`rfc2132.txt`](rfc2132.txt)                |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 2132. The audit was performed by reading
the RFC text fresh and inspecting the codebase under
`pytcp/` and `net_proto/` directly. Sections describing
options PyTCP does not parse and never emits are grouped
under the **Options not implemented** summary table below
rather than receiving individual narrative — RFC 2132 is
an enumeration catalogue of 80+ options, and per-option
"not implemented" entries would not add information
beyond the table.

PyTCP's DHCP option catalogue lives in
`net_proto/protocols/dhcp4/options/`. The
`Dhcp4OptionType` enum at
`net_proto/protocols/dhcp4/options/dhcp4__option.py:43-54`
declares 11 codepoints; any inbound option not in this
set parses into a `Dhcp4OptionUnknown` (preserving the
wire bytes for retransmission but not interpreting the
value).

---

## §2 BOOTP Extension/DHCP Option Field Format

> "DHCP options have the same format as the BOOTP
>  'vendor extensions' ... DHCP options are tagged data
>  items that provide information to a DHCP client. ...
>  The fixed-length data items consisting of an octet,
>  in a fixed sequence, are placed in this field for
>  the option. ... The variable-length data items
>  consist of an octet specifying length followed by the
>  data."

**Adherence:** met. The TLV layout (type byte + length
byte + value bytes) is the canonical option wire shape;
PyTCP's option base class at
`net_proto/protocols/dhcp4/options/dhcp4__option.py`
uses `DHCP4__OPTION__STRUCT = "! BB"`
(`dhcp4__option.py:39-40`) for the
common type+length header. Per-option subclasses append
their typed payload.

> "Two special fixed-length options exist that do not
>  follow this rule. These are the 'pad' option (option
>  0) and the 'end' option (option 255). Both have a
>  fixed length of one octet."

**Adherence:** met. `Dhcp4OptionPad` and
`Dhcp4OptionEnd` (at
`options/dhcp4__option__pad.py` and
`options/dhcp4__option__end.py`) are single-byte options
that bypass the type+length header.

> "Options requiring more than 255 octets are split into
>  multiple options, with each having a length of at
>  most 255 octets."

**Adherence:** not implemented. RFC 3396 (Long Options)
defines the concatenation rule; PyTCP's option parser
does not concatenate split options. None of PyTCP's
implemented options approach the 255-octet ceiling, so
the gap is latent.

---

## §3.1 Pad Option (code 0)

**Adherence:** met.
`Dhcp4OptionPad` at
`options/dhcp4__option__pad.py`. Single-byte option;
the parser skips it without consuming a length byte
(`options/dhcp4__options.py` integrity walk handles the
PAD special case).

---

## §3.2 End Option (code 255)

**Adherence:** met. Same shape as Pad; the parser stops
walking on END. Emitted as the last option of every
DISCOVER and REQUEST
(`pytcp/lib/dhcp4_client.py:149`, `:204`).

---

## §3.3 Subnet Mask Option (code 1)

> "The subnet mask option specifies the client's subnet
>  mask as per RFC 950. ... The code for the subnet mask
>  option is 1, and its length is 4 octets."

**Adherence:** met. `Dhcp4OptionSubnetMask` at
`options/dhcp4__option__subnet_mask.py` parses 4-byte
mask. The client at
`pytcp/lib/dhcp4_client.py:114-119`
extracts `ack.subnet_mask` and requires it to be
non-None to proceed (returns None otherwise — a
DHCP ACK without subnet mask cannot be consumed).

> "If both the subnet mask and the router option are
>  specified in a DHCP reply, the subnet mask option
>  MUST be first."

**Adherence:** not enforced. PyTCP does not validate
option ordering between Subnet Mask and Router; both
properties are pulled out individually by `Dhcp4Options`
accessors. Behaviour is correct regardless of order.

---

## §3.5 Router Option (code 3)

> "The router option specifies a list of IP addresses
>  for routers on the client's subnet. Routers SHOULD be
>  listed in order of preference. ... The code for the
>  router option is 3. The minimum length for the router
>  option is 4 octets, and the length MUST always be a
>  multiple of 4."

**Adherence:** met. `Dhcp4OptionRouter` at
`options/dhcp4__option__router.py` parses N×4-byte
list. The client at
`pytcp/lib/dhcp4_client.py:122-123`
uses only the first router (`ack.router[0]`) as the
default gateway — the SHOULD preference order is
honoured implicitly.

---

## §3.14 Host Name Option (code 12)

> "This option specifies the name of the client. ... The
>  code for this option is 12, and its minimum length
>  is 1."

**Adherence:** met. `Dhcp4OptionHostName` at
`options/dhcp4__option__host_name.py`. The client emits
`Dhcp4OptionHostName("PyTCP")` in both DISCOVER and
REQUEST (`pytcp/lib/dhcp4_client.py:148`,
`:203`).

---

## §9.1 Requested IP Address (code 50)

> "This option is used in a client request (DHCPDISCOVER)
>  to allow the client to request that a particular IP
>  address be assigned. ... The code for this option is
>  50, and its length is 4."

**Adherence:** met (in REQUEST only). The client emits
`Dhcp4OptionReqIpAddr(yiaddr)` in REQUEST
(`pytcp/lib/dhcp4_client.py:202`),
sourced from the OFFER's `yiaddr`. PyTCP does NOT use
this option in DISCOVER — RFC 2131 §3.5 marks it MAY
for DISCOVER, so omission is compliant. The
`Dhcp4OptionReqIpAddr` codec at
`options/dhcp4__option__req_ip_addr.py` handles the
4-byte address.

---

## §9.2 IP Address Lease Time (code 51)

> "This option is used in a client request (DHCPDISCOVER
>  or DHCPREQUEST) to allow the client to request a
>  lease time for the IP address. In a server reply
>  (DHCPOFFER), a DHCP server uses this option to
>  specify the lease time it is willing to offer."

**Adherence:** wire-only. `Dhcp4OptionLeaseTime` at
`options/dhcp4__option__lease_time.py` parses 4-byte
uint32 lease time. The client does NOT emit a
lease-time hint (the option is absent from DISCOVER and
REQUEST), and it does NOT consume the lease-time from
ACK — `pytcp/lib/dhcp4_client.py:111-125`
reads only `yiaddr`, `subnet_mask`, and `router[0]`.
The lease is therefore effectively infinite from the
client's perspective.

---

## §9.4 TFTP server name (code 66)

**Adherence:** not implemented. PXE-relevant; out of
scope for PyTCP host parity.

## §9.5 Bootfile name (code 67)

**Adherence:** not implemented. Same scope.

---

## §9.6 DHCP Message Type (code 53)

> "This option is used to convey the type of the DHCP
>  message. The code for this option is 53, and its
>  length is 1. Legal values for this option are:
>  Value Message Type
>  1     DHCPDISCOVER
>  2     DHCPOFFER
>  3     DHCPREQUEST
>  4     DHCPDECLINE
>  5     DHCPACK
>  6     DHCPNAK
>  7     DHCPRELEASE
>  8     DHCPINFORM"

**Adherence:** met. `Dhcp4MessageType` at
`net_proto/protocols/dhcp4/dhcp4__enums.py:58-95`
declares all 8 codepoints (DISCOVER=1 through
INFORM=8). The `Dhcp4OptionMessageType` codec at
`options/dhcp4__option__message_type.py` carries the
single byte. The client emits DISCOVER and REQUEST
(`pytcp/lib/dhcp4_client.py:140`, `:194`)
and accepts OFFER and ACK on RX
(`pytcp/lib/dhcp4_client.py:167-172`,
`:222-227`).

DECLINE, NAK, RELEASE, INFORM message types are not
emitted by PyTCP and not handled on RX (the type filter
treats non-OFFER and non-ACK as errors).

---

## §9.7 Server Identifier (code 54)

> "DHCP clients use the contents of the 'server
>  identifier' field as the destination address for any
>  DHCP messages unicast to the DHCP server. DHCP
>  clients also indicate which of several lease offers
>  is being accepted by including this option in a
>  DHCPREQUEST message. ... The code for this option is
>  54, and its length is 4."

**Adherence:** met (for REQUEST emit). The client
includes `Dhcp4OptionServerId(srv_id)` in REQUEST
(`pytcp/lib/dhcp4_client.py:201`) sourced
from the OFFER's `srv_id` field
(`pytcp/lib/dhcp4_client.py:108`). The
"destination address for unicast" clause is vacuous —
PyTCP never unicasts (no RENEWING state).

---

## §9.8 Parameter Request List (code 55)

> "This option is used by a DHCP client to request
>  values for specified configuration parameters. ... A
>  DHCP server is not required to return the requested
>  parameters, but is encouraged to do so."

**Adherence:** met. The client emits
`Dhcp4OptionParamReqList([SUBNET_MASK, ROUTER])` in
both DISCOVER and REQUEST
(`pytcp/lib/dhcp4_client.py:142-147`,
`:195-200`). Only those two parameters are requested
because they are the only two the client consumes; a
richer client (with DNS / NTP / domain-name support)
would extend the list.

---

## §9.14 Client-identifier (code 61)

> "This option is used by DHCP clients to specify their
>  unique identifier. DHCP servers use this value to
>  index their database of address bindings. This value
>  is expected to be unique for all clients in an
>  administrative domain. ... The code for this option
>  is 61, and its minimum length is 2."

**Adherence:** partial. The client emits the option in
DISCOVER only
(`pytcp/lib/dhcp4_client.py:141`) using
the RFC 2131 legacy form
`b"\x01" + bytes(self._mac_address)` — type byte 0x01
(hardware type Ethernet) followed by the 6-byte MAC.
RFC 4361 mandates a DUID-based form for new clients;
PyTCP uses the older form. See
[`rfc4361__node_specific_client_id`](../rfc4361__node_specific_client_id/adherence.md)
for the dedicated audit.

The option is OMITTED from REQUEST
(`pytcp/lib/dhcp4_client.py:188-205`),
which violates RFC 2131 §2 ("If the client uses a
'client identifier' in one message, it MUST use that
same identifier in all subsequent messages"). The
`Dhcp4OptionClientId` codec at
`options/dhcp4__option__client_id.py` is fully
implemented; the MUST gap is in the client's
emit path, not the wire-format library.

---

## Options not implemented

The following RFC 2132 options are not in PyTCP's
catalogue (`Dhcp4OptionType` at
`options/dhcp4__option.py:43-54`). Inbound options
carrying any of these codes parse into a
`Dhcp4OptionUnknown` wrapper that preserves the wire
bytes but exposes no typed accessor.

| Code | Option name                       | RFC §  | Reason                                                |
|------|-----------------------------------|--------|-------------------------------------------------------|
| 2    | Time Offset                       | §3.4   | Timezone — out of scope (no TZ consumer)              |
| 4    | Time Server                       | §3.6   | Out of scope                                          |
| 5    | Name Server (IEN-116)             | §3.7   | Obsolete                                              |
| 6    | Domain Name Server                | §3.8   | DNS not in Phase-1 scope                              |
| 7    | Log Server                        | §3.9   | Out of scope                                          |
| 8    | Cookie Server                     | §3.10  | Out of scope                                          |
| 9    | LPR Server                        | §3.11  | Out of scope                                          |
| 10   | Impress Server                    | §3.12  | Obsolete                                              |
| 11   | Resource Location Server          | §3.13  | Obsolete                                              |
| 13   | Boot File Size                    | §3.15  | PXE — out of scope                                    |
| 14   | Merit Dump File                   | §3.16  | Obsolete                                              |
| 15   | Domain Name                       | §3.17  | DNS                                                   |
| 16   | Swap Server                       | §3.18  | Out of scope                                          |
| 17   | Root Path                         | §3.19  | NFS — out of scope                                    |
| 18   | Extensions Path                   | §3.20  | Obsolete                                              |
| 19   | IP Forwarding Enable/Disable      | §4.1   | Phase-2 router parity                                 |
| 20   | Non-Local Source Routing          | §4.2   | Out of scope                                          |
| 21   | Policy Filter                     | §4.3   | Out of scope                                          |
| 22   | Max Datagram Reassembly Size      | §4.4   | Not consumed                                          |
| 23   | Default IP TTL                    | §4.5   | Not consumed                                          |
| 24   | Path MTU Aging Timeout            | §4.6   | PMTUD — Phase-2 scope                                 |
| 25   | Path MTU Plateau Table            | §4.7   | PMTUD — Phase-2 scope                                 |
| 26   | Interface MTU                     | §5.1   | Not consumed (uses static config)                     |
| 27   | All Subnets Local                 | §5.2   | Out of scope                                          |
| 28   | Broadcast Address                 | §5.3   | Auto-derived from mask                                |
| 29   | Perform Mask Discovery            | §5.4   | ICMP-mask discovery — out of scope                    |
| 30   | Mask Supplier                     | §5.5   | Server-side                                           |
| 31   | Perform Router Discovery          | §5.6   | RFC 1256 router discovery — out of scope              |
| 32   | Router Solicitation Address       | §5.7   | Out of scope                                          |
| 33   | Static Route                      | §5.8   | Obsolete; superseded by RFC 3442 classless variant    |
| 34   | Trailer Encapsulation             | §5.9   | Obsolete                                              |
| 35   | ARP Cache Timeout                 | §5.10  | Not consumed (PyTCP uses sysctl)                      |
| 36   | Ethernet Encapsulation            | §5.11  | RFC 894 default; not negotiated                       |
| 37   | TCP Default TTL                   | §5.12  | Not consumed                                          |
| 38   | TCP Keepalive Interval            | §5.13  | Not consumed                                          |
| 39   | TCP Keepalive Garbage             | §5.14  | Not consumed                                          |
| 40   | Network Information Service Domain | §6.1  | NIS — obsolete                                        |
| 41   | NIS Servers                       | §6.2   | NIS — obsolete                                        |
| 42   | NTP Servers                       | §6.3   | NTP — out of scope                                    |
| 43   | Vendor Specific                   | §6.4   | Out of scope                                          |
| 44   | NetBIOS over TCP/IP Name Server   | §6.5   | NetBIOS — obsolete                                    |
| 45   | NetBIOS over TCP/IP Datagram Dist | §6.6   | NetBIOS — obsolete                                    |
| 46   | NetBIOS over TCP/IP Node Type     | §6.7   | NetBIOS — obsolete                                    |
| 47   | NetBIOS over TCP/IP Scope         | §6.8   | NetBIOS — obsolete                                    |
| 48   | X Window System Font Server       | §6.9   | Obsolete                                              |
| 49   | X Window System Display Manager   | §6.10  | Obsolete                                              |
| 52   | Option Overload                   | §9.3   | Not implemented — see below                           |
| 56   | Message                           | §9.9   | Server-side error string                              |
| 57   | Maximum DHCP Message Size         | §9.10  | Not emitted; see RFC 2131 §3.5 audit gap              |
| 58   | Renewal Time (T1)                 | §9.11  | Not consumed (no FSM)                                 |
| 59   | Rebinding Time (T2)               | §9.12  | Not consumed (no FSM)                                 |
| 60   | Vendor class identifier           | §9.13  | Not emitted                                           |
| 62   | NetWare/IP Domain Name            | §8.1   | NetWare — obsolete                                    |
| 63   | NetWare/IP information            | §8.2   | NetWare — obsolete                                    |
| 64   | NIS+ Domain                       | §6.13  | Obsolete                                              |
| 65   | NIS+ Servers                      | §6.14  | Obsolete                                              |
| 66   | TFTP Server Name                  | §9.4   | PXE — out of scope                                    |
| 67   | Bootfile Name                     | §9.5   | PXE — out of scope                                    |
| 68   | Mobile IP Home Agent              | §6.15  | Mobile IP — out of scope (north-star non-goal)        |
| 69   | SMTP Server                       | §6.16  | Out of scope                                          |
| 70   | POP3 Server                       | §6.17  | Out of scope                                          |
| 71   | NNTP Server                       | §6.18  | Out of scope                                          |
| 72   | WWW Server                        | §6.19  | Out of scope                                          |
| 73   | Finger Server                     | §6.20  | Out of scope                                          |
| 74   | IRC Server                        | §6.21  | Out of scope                                          |
| 75   | StreetTalk Server                 | §6.22  | Obsolete                                              |
| 76   | StreetTalk Directory Assistance   | §6.23  | Obsolete                                              |

## Option Overload (code 52)

> "This option is used to indicate that the DHCP
>  'sname' or 'file' fields are being overloaded by
>  using them to carry DHCP options. A DHCP server
>  inserts this option if the returned parameters will
>  exceed the usual space allotted for options."

**Adherence:** not implemented. PyTCP's parser walks
the `options` field starting at offset 240 and stops at
END (`net_proto/protocols/dhcp4/options/dhcp4__options.py`).
The 'sname' and 'file' fields are parsed as
ASCII-strings (`net_proto/protocols/dhcp4/dhcp4__header.py:307-308`),
not as option-extension areas. A server that overloads
these fields will have its extension options silently
dropped.

PyTCP's option block is bounded by IP4_MIN_MTU - IP4 -
UDP - DHCP4 header = 576 - 20 - 8 - 240 = 308 octets
(`net_proto/protocols/dhcp4/options/dhcp4__options.py:85`).
The two options PyTCP requests (Subnet Mask + Router)
fit comfortably; option overload is unlikely to arise
in practice.

---

## Test coverage audit

### §2 Option wire format

- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__options.py` (812 lines)
  Pins container behaviour: composition, ordering,
  serialised length, lookup properties.

**Status:** locked in.

### §3.1 / §3.2 Pad / End

- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__pad.py` (235 lines)
- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__end.py` (235 lines)

**Status:** locked in.

### §3.3 / §3.5 / §3.14 Subnet Mask / Router / Host Name

- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__subnet_mask.py` (499 lines)
- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__router.py` (542 lines)
- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__host_name.py` (436 lines)

**Status:** locked in.

### §9.1 / §9.2 Requested IP / Lease Time

- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__req_ip_addr.py` (499 lines)
- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__lease_time.py` (432 lines)

**Status:** locked in (wire format). Note: Lease Time
is parsed but unused — the client does not consume the
value (RFC 2131 §3.3 gap).

### §9.6 / §9.7 / §9.8 / §9.14 Message Type / Server ID / Param Req List / Client ID

- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__message_type.py` (461 lines)
- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__server_id.py` (499 lines)
- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__param_req_list.py` (510 lines)
- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__client_id.py` (409 lines)

**Status:** locked in.

### Unknown option fallthrough

- **Unit:**
  `net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__unknown.py` (522 lines)
  Pins that unknown codes round-trip as
  `Dhcp4OptionUnknown` preserving wire bytes.

**Status:** locked in.

### §9.3 Option Overload

**No test surface — gap not yet closed.** When the gap
is fixed, the natural test is one that:

1. Sends a DHCP frame with Option Overload = 1 (file
   field contains options) plus options in the file
   field.
2. Asserts the parser exposes the file-field options
   alongside the option-field options.

### Test coverage summary

| Aspect                                          | Coverage                          |
|-------------------------------------------------|-----------------------------------|
| Implemented option wire format (11 codecs)      | locked in (~5 200 unit lines)     |
| Unknown option fallthrough                      | locked in                         |
| Options container ordering / lookup             | locked in                         |
| Option Overload (code 52) parsing               | not implemented; no test          |
| Maximum DHCP Message Size (57) emission         | not implemented; no test          |
| RFC 3396 long-option concatenation              | not implemented; no test          |
| Lease-time consumption by client                | n/a (parsed, not consumed)        |

---

## Overall assessment

| Aspect                                       | Status                                                          |
|----------------------------------------------|-----------------------------------------------------------------|
| §2 TLV wire format                           | met                                                             |
| §3.1 / §3.2 Pad / End                        | met (and emitted)                                               |
| §3.3 Subnet Mask (1)                         | met (parsed + consumed)                                         |
| §3.5 Router (3)                              | met (parsed + first router consumed)                            |
| §3.14 Host Name (12)                         | met (emitted as "PyTCP")                                        |
| §9.1 Requested IP Address (50)               | met (emitted in REQUEST)                                        |
| §9.2 IP Address Lease Time (51)              | wire-only (parsed but unused)                                   |
| §9.3 Option Overload (52)                    | not implemented                                                 |
| §9.6 DHCP Message Type (53)                  | met (all 8 codepoints declared; DISCOVER/REQUEST emitted)       |
| §9.7 Server Identifier (54)                  | met (echoed in REQUEST)                                         |
| §9.8 Parameter Request List (55)             | met (consistent across DISCOVER/REQUEST)                        |
| §9.10 Maximum DHCP Message Size (57)         | not implemented                                                 |
| §9.11 / §9.12 T1 / T2 (58, 59)               | not consumed (no FSM)                                           |
| §9.13 Vendor class identifier (60)           | not implemented                                                 |
| §9.14 Client Identifier (61)                 | partial — emitted in DISCOVER only, missing in REQUEST          |
| RFC 3396 long-option concatenation           | not implemented                                                 |
| All other 60+ options (DNS, NTP, NIS, ...)   | not implemented (out of host-parity scope)                      |

**Principal compliance gap.** Two real issues, both
client-side rather than wire-format:

1. **Client Identifier not echoed in REQUEST**
   (RFC 2131 §2 MUST). Single-line fix at
   `pytcp/lib/dhcp4_client.py:193-205`:
   add `Dhcp4OptionClientId(b"\x01" +
   bytes(self._mac_address))` to the REQUEST options.

2. **Lease-time option parsed but unused.** The client
   reads `ack.subnet_mask` and `ack.router` from the
   ACK but ignores `ack.lease_time`. Phase-1 host
   parity with Linux dhcpcd requires plumbing
   `lease_time` into the planned RFC 2131 §4.4.5 FSM
   so T1/T2 timers can drive RENEW/REBIND. The wire
   codec is ready; the consumer is the missing piece.

Everything else in this RFC is either out of host
scope (NIS, NetBIOS, X11) or wire-format-only with the
codec implemented but no semantic consumer.
