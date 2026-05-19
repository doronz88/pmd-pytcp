# RFC 4702 — The DHCP Client FQDN Option

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 4702                                                 |
| Title       | The Dynamic Host Configuration Protocol (DHCP) Client Fully Qualified Domain Name (FQDN) Option |
| Category    | Standards Track                                      |
| Date        | October 2006                                         |
| Source text | [`rfc4702.txt`](rfc4702.txt)                         |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 4702. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/` and `packages/net_proto/net_proto/` directly.

RFC 4702 defines option 81 (Client FQDN) which a DHCP
client uses to publish its fully-qualified domain name
to the server, primarily so the server can update the
PTR (reverse) DNS record on the client's behalf.
**PyTCP does not implement option 81** — the codec is
not in `Dhcp4OptionType` at
`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option.py:43-54`,
and the client never emits or consumes the option.

PyTCP does emit a Host Name option (code 12,
`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option__host_name.py`)
with the literal value "PyTCP" at
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:148`, `:203` —
but option 12 carries an unqualified host name, not
the FQDN-format option 81 with Flags/RCODE control.

Sections without normative content (§1 Introduction,
§1.1 Terminology, §1.2 Models of Operation, §7 IANA
Considerations, §8 Security Considerations, §9
Acknowledgments, §10 References, §11 Authors'
Addresses) are omitted.

---

## §2 The Client FQDN Option — wire format

> "The code for this option is 81. Len contains the
>  number of octets that follow the Len field, and the
>  minimum value is 3 (octets)."

**Adherence:** not implemented. Option code 81 is
absent from PyTCP's codec catalogue. Inbound option 81
parses into `Dhcp4OptionUnknown`.

> "Clients MAY send the Client FQDN option, setting
>  appropriate Flags values, in both their DHCPDISCOVER
>  and DHCPREQUEST messages. If a client sends the
>  Client FQDN option in its DHCPDISCOVER message, it
>  MUST send the option in subsequent DHCPREQUEST
>  messages though the contents of the option MAY
>  change."

**Adherence:** N/A (option not emitted at all).

> "Only one Client FQDN option MAY appear in a message,
>  though it may be instantiated in a message as
>  multiple options. DHCP clients and servers
>  supporting this option MUST implement DHCP option
>  concatenation."

**Adherence:** N/A (option 81 not supported; RFC 3396
option concatenation also not implemented — see
RFC 2132 audit).

---

## §2.1 Flags Field

> "Bit 0: N flag — if set to 1, the server SHALL NOT
>  perform any DNS updates. If cleared to 0, the server
>  SHALL perform updates according to the Bit-1 (S
>  flag) and Bit-3 (O flag) values."

**Adherence:** N/A.

> "Bit 1: E flag — if set to 1, the FQDN is encoded as
>  per Section 3.1 of RFC 1035; if cleared to 0, the
>  FQDN is encoded as an ASCII string."

**Adherence:** N/A.

> "Bit 2: O flag — set by the server to indicate that
>  the FQDN it returned differs from the one sent by
>  the client."

**Adherence:** N/A.

> "Bit 3: S flag — if set to 1, the server SHOULD
>  perform the A RR update; if cleared to 0, the
>  server SHOULD NOT perform the A RR update."

**Adherence:** N/A.

---

## §3 Client Behavior

> "If a client uses the Client FQDN option, then in each
>  DHCP message it sends, the client MUST estimate
>  whether it or the server will be updating the FQDN-
>  to-IP-address mapping. ..."

**Adherence:** N/A.

> "When determining whether to perform DNS updates and
>  what kind of updates to perform, a DHCP client MUST
>  use the Client FQDN option as a hint, not as a
>  command."

**Adherence:** N/A.

> "Clients MAY use option 12 ('Host Name', RFC 2132
>  Section 3.14) to specify a hostname when the Client
>  FQDN option is supplied; clients MUST NOT use
>  options 81 and 12 to convey different information
>  about the FQDN of the client."

**Adherence:** vacuously met. PyTCP emits option 12
("PyTCP") and does not emit option 81, so the
"must-not-differ" constraint is trivially satisfied.

---

## §4 Server Behavior

**Adherence:** N/A (client only).

---

## Test coverage audit

### Option 81 codec

**No test surface — gap not yet closed.** When the gap
is fixed, the natural test plan:

1. Add a `Dhcp4OptionClientFqdn` codec parsing the
   wire format (Flags + RCODE1 + RCODE2 + FQDN bytes).
2. Unit-test ASCII-encoded FQDN round-trip and
   RFC 1035 encoded FQDN round-trip.
3. Integration-test the client sending option 81 in
   DISCOVER and re-sending in REQUEST (the MUST from
   §2).

### Test coverage summary

| Aspect                                    | Coverage                          |
|-------------------------------------------|-----------------------------------|
| Option 81 codec                           | not implemented; no test          |
| ASCII vs RFC 1035 FQDN encoding           | not implemented; no test          |
| Flags field round-trip                    | not implemented; no test          |
| Client FQDN in DISCOVER → REQUEST consistency | not implemented; no test     |
| RFC 3396 option concatenation             | not implemented; no test          |

---

## Overall assessment

| Aspect                                            | Status                                  |
|---------------------------------------------------|-----------------------------------------|
| §2 Option 81 wire format                          | not implemented                         |
| §2.1 Flags (N/E/O/S)                              | not implemented                         |
| §3 Client behaviour (DNS update negotiation)      | not implemented                         |
| §4 Server behaviour                               | n/a (client only)                       |
| RFC 3396 option concatenation                     | not implemented                         |
| Option 12 (Host Name) emission                    | met (emitted as "PyTCP" — RFC 2132 §3.14) |

**Principal compliance note.** Option 81 is the
standard DDNS-update-on-DHCP mechanism. PyTCP's
omission means no PTR / A record gets registered in
DDNS for a PyTCP-acquired DHCP lease. For Phase 1 host
parity this is a gap because Linux dhcpcd and
NetworkManager both send option 81 by default. Fix
sketch:

1. Add `Dhcp4OptionType.CLIENT_FQDN = 81` to the enum.
2. Add the codec under
   `packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option__client_fqdn.py`
   parsing the 4-byte fixed prefix (Flags, RCODE1,
   RCODE2) plus the variable-length FQDN.
3. Decide PyTCP's update policy: the conservative
   choice is "client does no updates, request server
   to update both" — set Flags to `E=1, S=1, N=0, O=0`
   so the server handles A and PTR.
4. Emit the option in DISCOVER and REQUEST
   (`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py:139-150`,
   `:193-205`). The FQDN value would need a sysctl
   (`dhcp.fqdn`, default "pytcp" or operator-set).

Out of Phase 1 host-parity scope until PyTCP gains a
DNS resolver or DDNS-update consumer; the option is
purely informational from the client's perspective.
