# RFC 4361 — Node-specific Client Identifiers for DHCPv4

| Field       | Value                                                  |
|-------------|--------------------------------------------------------|
| RFC number  | 4361                                                   |
| Title       | Node-specific Client Identifiers for DHCPv4 using DUID |
| Category    | Standards Track                                        |
| Date        | February 2006                                          |
| Updates     | RFC 2131, RFC 2132                                     |
| Source text | [`rfc4361.txt`](rfc4361.txt)                           |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 4361. The audit was performed by reading
the RFC text fresh and inspecting the codebase under
`pytcp/` and `net_proto/` directly.

RFC 4361 modernises the DHCPv4 Client Identifier (option
61) by mandating a DUID + IAID construction (matching
DHCPv6 / RFC 3315) instead of the RFC 2131 legacy
hardware-address form. **PyTCP uses the legacy
MAC-based form** (`b"\x01" + bytes(mac_address)`) at
`pytcp/lib/dhcp4_client.py:141` —
RFC 4361's MUST clauses are not implemented.

Sections without normative content (§1 Introduction, §2
Terminology, §3 Applicability, §4 Problem Statement, §5
Requirements rationale, §7 Multi-stage Network Booting
discussion, §8 Security Considerations boilerplate,
§9 IANA Considerations, §10 Acknowledgments, §11
References, §12 Author's Addresses) are omitted.

---

## §6.1 DHCPv4 Client Behavior

> "DHCPv4 clients conforming to this specification MUST
>  use stable DHCPv4 node identifiers in the
>  dhcp-client-identifier option. DHCPv4 clients MUST
>  NOT use client identifiers based solely on layer two
>  addresses that are hard-wired to the layer two device
>  (e.g., the ethernet MAC address) as suggested in
>  RFC 2131, except as allowed in section 9.2 of
>  RFC 3315."

**Adherence:** not met. PyTCP emits
`Dhcp4OptionClientId(b"\x01" + bytes(self._mac_address))`
at `pytcp/lib/dhcp4_client.py:141` —
type byte 0x01 (Ethernet hardware type) followed by the
6-byte MAC address. This is the RFC 2131 legacy form
that RFC 4361 §6.1 explicitly forbids ("MUST NOT use
client identifiers based solely on layer two
addresses").

> "DHCPv4 clients MUST send a 'client identifier' option
>  containing an Identity Association Unique Identifier,
>  as defined in section 10 of RFC 3315, and a DHCP
>  Unique Identifier, as defined in section 9 of
>  RFC 3315."

**Adherence:** not met. No DUID / IAID generation
machinery exists in PyTCP. The required wire format
(`Code 61 | Len n | Type 0xFF | IAID 4-byte | DUID
n-byte`) is not emitted.

> "To send an RFC 3315-style binding identifier in a
>  DHCPv4 'client identifier' option, the type of the
>  'client identifier' option is set to 255."

**Adherence:** not met. PyTCP uses type byte 0x01
(Ethernet hardware), not 0xFF (RFC 3315 binding
identifier).

> "Any DHCPv4 client that conforms to this specification
>  SHOULD provide a means by which an operator can learn
>  what DUID the client has chosen. Such clients SHOULD
>  also provide a means by which the operator can
>  configure the DUID."

**Adherence:** not implemented. No DUID infrastructure
exists; nothing to expose or configure.

> "DHCPv4 clients that support more than one network
>  interface SHOULD use the same DUID on every
>  interface."

**Adherence:** N/A. PyTCP is currently single-interface
(Phase 2 multi-interface is on the north-star roadmap).

> "A DHCPv4 client that generates a DUID and that has
>  stable storage MUST retain this DUID for use in
>  subsequent DHCPv4 messages, even after an operating
>  system reboot."

**Adherence:** not met. PyTCP has no DUID generation
and no stable storage for DHCP state.

---

## §6.3 DHCPv4 Server Behavior

**Adherence:** N/A. PyTCP is a DHCP client only.

---

## §6.4 Changes from RFC 2131

> "In section 4.2 of RFC 2131, the text '... If the
>  client does not provide a 'client identifier' option,
>  the server MUST use the contents of the 'chaddr'
>  field to identify the client.' is replaced by the
>  text 'The client MUST explicitly provide a client
>  identifier through the 'client identifier' option.
>  The client MUST use the same 'client identifier'
>  option for all messages.'"

**Adherence:** partial — first half met, second half
violated. PyTCP DOES provide a client-identifier option
in DISCOVER
(`pytcp/lib/dhcp4_client.py:141`), so it
is not relying on `chaddr` alone (first half met). But
the option is OMITTED from REQUEST
(`pytcp/lib/dhcp4_client.py:188-205`),
which violates the second half ("The client MUST use
the same 'client identifier' option for all messages").
This is the same MUST gap noted in RFC 2131 §2 audit.

> "In section 4.4.1 of RFC 2131, the text 'The client
>  MAY include a different unique identifier' is
>  replaced with 'The client MUST include a unique
>  identifier'."

**Adherence:** met (in DISCOVER). The client always
includes the option in DISCOVER (it is unconditional).

> "The DHCP client MUST NOT rely on the 'chaddr' field
>  to identify it."

**Adherence:** met. PyTCP sends a Client Identifier
option in DISCOVER, so the server does not need to fall
back to `chaddr`.

---

## §6.5 Changes from RFC 2132

> "The text in section 9.14, beginning with 'The client
>  identifier MAY consist of' through 'that meet this
>  requirement for uniqueness.' is replaced with 'the
>  client identifier consists of a type field whose
>  value is normally 255, followed by a four-byte IA_ID
>  field, followed by the DUID for the client as
>  defined in RFC 3315, section 9.'"

**Adherence:** not met. The PyTCP Client Identifier
wire format is the RFC 2131 legacy form, not the
RFC 4361 DUID/IAID form.

---

## Test coverage audit

### §6.1 / §6.4 / §6.5 — DUID-based Client Identifier

**No test surface — gap not yet closed.** When the gap
is fixed, the natural test plan:

1. Generate a stable DUID at first boot
   (RFC 3315 §9 — DUID-LL or DUID-LLT) and persist it
   under some sysctl or stable-storage location.
2. Assert the emitted DISCOVER/REQUEST Client
   Identifier option carries:
   - Code 61
   - Length matching `1 + 4 + len(DUID)`
   - Type byte 0xFF
   - 4-byte IAID (e.g. derived from interface index)
   - The persisted DUID bytes
3. Assert the same DUID is emitted across stack
   restarts (persistence check).

Additionally, fix the missing-CID-in-REQUEST gap
(RFC 2131 §2 MUST): add `Dhcp4OptionClientId(...)` to
the REQUEST option list at
`pytcp/lib/dhcp4_client.py:193-205`.

### Test coverage summary

| Aspect                                       | Coverage                       |
|----------------------------------------------|--------------------------------|
| RFC 2131 legacy Client Identifier emission   | locked in (test__lib__dhcp4_client.py) |
| RFC 4361 DUID-based Client Identifier        | not implemented; no test       |
| Client Identifier in REQUEST (RFC 2131 §2)   | gap; no test                   |
| DUID persistence across reboot               | not implemented; no test       |
| Same DUID across interfaces                  | n/a (single-interface)         |

---

## Overall assessment

| Aspect                                                | Status                                                |
|-------------------------------------------------------|-------------------------------------------------------|
| §6.1 Stable DUID-based Client Identifier on TX        | not met (uses RFC 2131 legacy MAC-based form)         |
| §6.1 IAID + DUID wire format (type 255)               | not met (uses type 0x01)                              |
| §6.1 Operator inspection / configuration of DUID      | not implemented                                       |
| §6.1 Same DUID across interfaces                      | n/a (single-interface)                                |
| §6.1 DUID retained across OS reboot (stable storage)  | not implemented                                       |
| §6.4 Client MUST NOT rely on chaddr for identification| met (CID always emitted in DISCOVER)                  |
| §6.4 Client MUST use same CID in all messages         | not met (CID missing in REQUEST)                      |
| §6.5 RFC 2132 §9.14 wire format change                | not met (legacy format)                               |
| §6.3 Server behaviour                                 | n/a (client only)                                     |

**Principal compliance gap.** PyTCP's DHCP client is a
PRE-RFC 4361 client. Every MUST in §6.1 is unmet
because the entire DUID/IAID infrastructure is absent.

**Fix sketch (Phase 1 plan):**

1. Add a `DhcpUniqueIdentifier` helper class under
   `pytcp/lib/` that builds a DUID-LL
   (RFC 3315 §9.2 — DUID Based on Link-layer Address)
   from the interface MAC.
2. Add a stable-storage hook (probably a sysctl
   `dhcp.duid` that defaults to "derived from MAC"
   but can be operator-overridden, mirroring Linux
   `/var/lib/dhcp/duid`).
3. Rewrite `Dhcp4OptionClientId` constructor at the
   call site
   (`pytcp/lib/dhcp4_client.py:141`,
   `:193-205`) to emit type 0xFF + 4-byte IAID + DUID
   bytes.
4. Ensure REQUEST emits the same CID (fixes the
   RFC 2131 §2 MUST gap simultaneously).

This is a single-file change in the client plus the
new helper; the wire-format codec
(`Dhcp4OptionClientId` at
`net_proto/protocols/dhcp4/options/dhcp4__option__client_id.py`)
already accepts arbitrary bytes, so no codec change is
required.
