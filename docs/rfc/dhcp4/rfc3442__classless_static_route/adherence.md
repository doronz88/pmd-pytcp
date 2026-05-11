# RFC 3442 — The Classless Static Route Option for DHCPv4

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 3442                                               |
| Title       | The Classless Static Route Option for DHCPv4       |
| Category    | Standards Track                                    |
| Date        | December 2002                                      |
| Updates     | RFC 2132                                           |
| Source text | [`rfc3442.txt`](rfc3442.txt)                       |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 3442. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `pytcp/` and `net_proto/` directly.

RFC 3442 defines option 121 (Classless Static Routes),
the modern replacement for option 33 (Static Routes,
RFC 2132 §5.8) which assumed classful routing. **PyTCP
does not implement either option** — neither code 121
nor code 33 appears in the `Dhcp4OptionType` enum at
`net_proto/protocols/dhcp4/options/dhcp4__option.py:43-54`.
The client requests only `SUBNET_MASK` and `ROUTER`
(option 3) in its Parameter Request List
(`pytcp/protocols/dhcp4/dhcp4__client.py:142-147`,
`:195-200`).

Sections without normative content (Introduction,
Definitions, Acknowledgments, References, Security
Considerations, IANA, Author's Addresses) are omitted.

---

## Classless Route Option Format (§ "Classless Route Option Format")

> "The code for this option is 121, and its minimum
>  length is 5 bytes. This option can contain one or
>  more static routes, each of which consists of a
>  destination descriptor and the IP address of the
>  router that should be used to reach that destination."

**Adherence:** not implemented. Option code 121 is
absent from PyTCP's option codec catalogue. Inbound
option 121 parses into `Dhcp4OptionUnknown` (wire bytes
preserved, no typed accessor).

---

## DHCP Client Behavior

> "DHCP clients that do not support this option MUST
>  ignore it if it is received from a DHCP server."

**Adherence:** met (vacuously). PyTCP's `Dhcp4OptionUnknown`
wrapper parses unknown codes into a typeless container;
the client never reads it. The MUST-ignore behaviour
falls out of "not implemented".

> "DHCP clients that support this option MUST install
>  the routes specified in the option, except as
>  specified in the Local Subnet Routes section."

**Adherence:** N/A (not supported).

> "DHCP clients that support this option MUST NOT
>  install the routes specified in the Static Routes
>  option (option code 33) if both a Static Routes
>  option and the Classless Static Routes option are
>  provided."

**Adherence:** N/A (neither option supported).

> "DHCP clients that support this option and that send
>  a DHCP Parameter Request List option MUST request
>  both this option and the Router option in the DHCP
>  Parameter Request List."

**Adherence:** N/A. PyTCP requests only SUBNET_MASK and
ROUTER (option 3); option 121 is not requested.

> "The Classless Static Routes option code MUST appear
>  in the parameter request list prior to both the
>  Router option code and the Static Routes option
>  code."

**Adherence:** N/A.

> "If the DHCP server returns both a Classless Static
>  Routes option and a Router option, the DHCP client
>  MUST ignore the Router option."

**Adherence:** not met (but vacuous in current code).
PyTCP's `_recv_ack` reads `ack.router[0]` unconditionally
(`pytcp/protocols/dhcp4/dhcp4__client.py:122-123`). If
a server returns both option 3 (Router) and option 121
(Classless Static Routes), PyTCP would consume the
Router option as the default gateway — this is exactly
the behaviour the MUST forbids for a compliant client.
But since PyTCP is a non-compliant client (does not
support option 121), the MUST does not apply; the
result is "PyTCP just gets the default route from
option 3, missing whatever classless routes the server
advertised."

> "Similarly, if the DHCP server returns both a
>  Classless Static Routes option and a Static Routes
>  option, the DHCP client MUST ignore the Static
>  Routes option."

**Adherence:** N/A (neither parsed).

---

## Requirements to Avoid Sizing Constraints

> "Clients implementing the Classless Static Route
>  option SHOULD send a Maximum DHCP Message Size
>  option if the DHCP client's TCP/IP stack is capable
>  of receiving larger IP datagrams."

**Adherence:** N/A (not implementing the option, so the
sizing concern doesn't apply).

> "DHCP clients requesting this option, and DHCP
>  servers sending this option, MUST implement DHCP
>  option concatenation [RFC 3396]."

**Adherence:** N/A.

---

## Test coverage audit

### Option code 121 wire format

**No test surface — gap not yet closed.** When the gap
is fixed, the natural test plan:

1. Add a `Dhcp4OptionClasslessStaticRoute` codec under
   `net_proto/protocols/dhcp4/options/`
   parsing the compact-encoding destination descriptor
   format from the RFC (width byte + significant
   octets, plus 4-byte router IP).
2. Unit-test the codec against the table of examples
   in the RFC's "Classless Route Option Format" section
   (e.g. `0` → `0.0.0.0/0`, `8.10` → `10.0.0.0/8`,
   `24.10.0.0` → `10.0.0.0/24`).
3. Integration-test: drive an ACK carrying option 121
   into the client and assert the parsed routes are
   installed into the IPv4 routing table (Phase 2 —
   routing-table API not yet in Phase 1 scope).

### Test coverage summary

| Aspect                            | Coverage                               |
|-----------------------------------|----------------------------------------|
| Option code 121 codec             | not implemented; no test               |
| Compact-encoding round-trip       | not implemented; no test               |
| Param Req List ordering           | not implemented; no test               |
| Router-option suppression on Both | not implemented; no test               |
| RFC 3396 option concatenation     | not implemented; no test               |

---

## Overall assessment

| Aspect                                                      | Status                                                 |
|-------------------------------------------------------------|--------------------------------------------------------|
| Option code 121 wire-format codec                           | not implemented                                        |
| Parameter Request List entry for option 121                 | not implemented                                        |
| Maximum DHCP Message Size (option 57) emission              | not implemented                                        |
| RFC 3396 long-option concatenation                          | not implemented                                        |
| Compact-encoding (width + significant octets) parser        | not implemented                                        |
| Local Subnet Routes (router 0.0.0.0) handling               | not implemented                                        |
| Router-option suppression when Classless Routes present     | n/a (client doesn't parse Classless Routes)            |

**Principal compliance note.** Option 121 is the
Linux-default-since-2009 way to receive a richer routing
table from DHCP than the single default route. PyTCP's
omission means a server advertising a classless route
set will be ignored — the client just installs option
3's first router as the default gateway. For Phase 1
host parity, this is a real gap because Linux dhcpcd
fetches classless routes by default. Fix sketch:

1. Add `Dhcp4OptionType.CLASSLESS_STATIC_ROUTE = 121`
   to the enum.
2. Add the codec under
   `net_proto/protocols/dhcp4/options/dhcp4__option__classless_static_route.py`
   parsing the compact-encoding format (RFC 3442
   "Destination descriptors describe..." paragraph).
3. Add option 121 to the client's Param Req List
   (BEFORE option 3, per the MUST).
4. In `_recv_ack`, prefer option 121 over option 3
   when both are present; install each parsed route
   into the routing table (Phase 1 needs a routing
   API; today PyTCP only models a single default
   gateway on the `Ip4Host` object).
5. Test the codec against the RFC's "examples" table
   and add an integration test against a server that
   sends both option 3 and option 121.

This is meaningful work because routing-table support
itself is Phase-2 territory in PyTCP (the Phase-1
`Ip4Host` model has a single gateway field). The full
RFC 3442 fix is coupled to introducing a real routing
table.
