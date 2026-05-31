# RFC 3442 — The Classless Static Route Option for DHCPv4

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 3442                                               |
| Title       | The Classless Static Route Option for DHCPv4       |
| Category    | Standards Track                                    |
| Date        | December 2002                                      |
| Updates     | RFC 2132                                            |
| Source text | [`rfc3442.txt`](rfc3442.txt)                       |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 3442. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/` and `packages/net_proto/net_proto/` directly.

RFC 3442 defines option 121 (Classless Static Routes),
the modern replacement for option 33 (Static Routes,
RFC 2132 §5.8) which assumed classful routing. **PyTCP
implements option 121 as a DHCP client** (DHCPv4 Phase 7):
the codec lives at
`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option__classless_static_route.py`,
`Dhcp4OptionType.CLASSLESS_STATIC_ROUTE = 121` is in the
enum at
`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option.py`,
and the client requests + installs the routes via the
FIB / Route API. Option 33 (Static Routes) is **not**
implemented — its absence is consistent with the RFC's
"ignore Static Routes when Classless is present" rule
(below) and with Linux defaults (dhcpcd / systemd-networkd
do not request option 33).

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

**Adherence:** met. `Dhcp4OptionClasslessStaticRoute`
holds a `list[(Ip4Network, Ip4Address)]` and
encodes / decodes the compact destination descriptor
(one mask-width octet 0–32 + `ceil(width/8)` significant
subnet octets + 4-byte router). The 5-octet minimum is
enforced: `_validate_integrity` rejects a length byte
below 5 with a typed `Dhcp4IntegrityError`, and the
dataclass requires at least one route.

> "After deriving a subnet number and subnet mask from
>  each destination descriptor, the DHCP client MUST zero
>  any bits in the subnet number where the corresponding
>  bit in the mask is zero ... the logical AND of the
>  subnet number and subnet mask."

**Adherence:** met. `decode_routes` reconstructs the
4-byte address from the significant octets and builds
`Ip4Network((address, Ip4Mask(f"/{width}")))`; the
`net_addr` network constructor ANDs the host bits
(verified by the 129.210.177.132/25 → 129.210.177.128/25
test case).

---

## Local Subnet Routes

> "A DHCP client whose underlying TCP/IP stack does not
>  provide this capability MUST ignore routes in the
>  Classless Static Routes option whose router IP address
>  is 0.0.0.0."

**Adherence:** met, by the permitted "does not provide
this capability" branch. PyTCP's host FIB does not yet
carry an output-interface index on DHCP-learned routes,
so a router-0.0.0.0 (on-link, non-connected-subnet)
route has no resolvable egress; `_install_lease_routes`
skips such routes (marked `# Phase 2:` — install as
on-link once DHCP routes carry an oif). This is the
RFC-sanctioned choice for a stack that does not provide
the multi-subnet-on-one-link capability. A future
Phase-2 build that records the oif may install them as
on-link, matching Linux.

---

## DHCP Client Behavior

> "DHCP clients that do not support this option MUST
>  ignore it if it is received from a DHCP server."

**Adherence:** met (now actively, by supporting it).

> "DHCP clients that support this option MUST install
>  the routes specified in the option, except as
>  specified in the Local Subnet Routes section."

**Adherence:** met. On the BOUND transition
`Dhcp4Client._install_lease_routes` installs each route
into the FIB via the Route API: the `0.0.0.0/0` entry
as the protocol=DHCP default (`replace_default`), each
other gatewayed entry as an explicit route
(`add_route`), router-0.0.0.0 entries excepted per Local
Subnet Routes above.

> "DHCP clients that support this option MUST NOT
>  install the routes specified in the Static Routes
>  option (option code 33) if both a Static Routes
>  option and the Classless Static Routes option are
>  provided."

**Adherence:** met (vacuously — option 33 is neither
requested nor parsed, so it is never installed).

> "DHCP clients that support this option and that send
>  a DHCP Parameter Request List option MUST request
>  both this option and the Router option in the DHCP
>  Parameter Request List."

**Adherence:** met. Every DISCOVER / REQUEST PRL the
client emits lists `CLASSLESS_STATIC_ROUTE`, `SUBNET_MASK`,
and `ROUTER` (`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py`).

> "The Classless Static Routes option code MUST appear
>  in the parameter request list prior to both the
>  Router option code and the Static Routes option
>  code."

**Adherence:** met. `CLASSLESS_STATIC_ROUTE` is the first
PRL entry, ahead of `ROUTER`; option 33 is not listed.

> "If the DHCP server returns both a Classless Static
>  Routes option and a Router option, the DHCP client
>  MUST ignore the Router option."

**Adherence:** met. When `lease.classless_static_routes`
is present `_install_lease_routes` installs the option-121
routes and never consults `lease.gateway` (the option-3
Router); the option-3 fallback runs only when option 121
is absent.

> "Similarly, if the DHCP server returns both a
>  Classless Static Routes option and a Static Routes
>  option, the DHCP client MUST ignore the Static
>  Routes option."

**Adherence:** met (vacuously — option 33 is never parsed).

---

## Requirements to Avoid Sizing Constraints

> "Clients implementing the Classless Static Route
>  option SHOULD send a Maximum DHCP Message Size
>  option if the DHCP client's TCP/IP stack is capable
>  of receiving larger IP datagrams."

**Adherence:** met. The client emits the Maximum DHCP
Message Size option (option 57, DHCPv4 Phase 8.1) in
DISCOVER / REQUEST.

> "DHCP clients requesting this option, and DHCP
>  servers sending this option, MUST implement DHCP
>  option concatenation [RFC 3396]."

**Adherence:** met (client side). `Dhcp4Options.from_buffer`
concatenates the data of every option-121 instance in
wire order before decoding
(`_concatenated_classless_static_route_data`), so a route
set split across instances on any byte boundary decodes
as one list. PyTCP is a client and never transmits
option 121, so server-side splitting on assembly is a
Phase-2 DHCP-server concern (see RFC 3396 adherence).

---

## Test coverage audit

### Option code 121 wire format

`packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__classless_static_route.py`:

- The descriptor-encoding examples table from the RFC's
  "Classless Route Option Format" section
  (`0` → `0.0.0.0/0`, `8.10` → `10.0.0.0/8`,
  `24.10.0.0` → `10.0.0.0/24`, …, `32.10.198.122.47` →
  `10.198.122.47/32`) — `test__...__descriptor_examples`.
- Assembler `__len__` / `__str__` / `__repr__` / `bytes()`
  / field matrices and `from_buffer` roundtrip.
- The RFC 3442 AND-masking rule (129.210.177.132/25 →
  129.210.177.128/25) — `test__...__masks_host_bits`.
- Integrity rejections: width > 32, descriptor truncating
  the data, below-5-octet length.

### RFC 3396 option concatenation

`packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__options.py`,
`TestDhcp4OptionsClasslessStaticRouteConcatenation`:
a route set split mid-descriptor across two instances is
joined and decoded; multiple instances collapse to one
option; an empty option-121 raises a typed integrity
error.

### Client request + install

`packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__client.py`:

- `TestDhcp4ClientParamReqListOrdering` — option 121 is
  requested and precedes Router in every PRL.
- `TestDhcp4ClientClasslessStaticRoutes` — option 121
  installed (default + explicit routes), option 3 ignored
  when 121 present, router-0.0.0.0 skipped, option-3
  fallback when 121 absent, non-default removal, RENEW
  de-duplication.

### Lease-cache persistence

`packages/pytcp/pytcp/tests/unit/protocols/dhcp4/test__dhcp4__lease_cache.py`:
the classless routes survive a write / read round-trip
(so the RFC 4436 DNAv4 fast path restores them); a lease
without them reads back as `None`.

### Test coverage summary

| Aspect                            | Coverage                               |
|-----------------------------------|----------------------------------------|
| Option code 121 codec             | covered (assembler + parser matrices)  |
| Compact-encoding examples table   | covered (RFC examples)                 |
| Host-bit AND-masking              | covered                                |
| Param Req List ordering           | covered                                |
| Router-option suppression on Both | covered                                |
| Router-0.0.0.0 (on-link) skip     | covered                                |
| RFC 3396 option concatenation     | covered (mid-descriptor split)         |
| Lease-cache round-trip            | covered                                |

---

## Overall assessment

| Aspect                                                      | Status                                                 |
|-------------------------------------------------------------|--------------------------------------------------------|
| Option code 121 wire-format codec                           | implemented                                            |
| Parameter Request List entry for option 121 (before Router) | implemented                                            |
| Maximum DHCP Message Size (option 57) emission              | implemented (Phase 8.1)                                |
| RFC 3396 long-option concatenation (client / receive)       | implemented                                            |
| Compact-encoding (width + significant octets) parser        | implemented                                            |
| Host-bit AND-masking of the subnet number                   | implemented                                            |
| Router-option (option 3) suppression when 121 present       | implemented                                            |
| Local Subnet Routes (router 0.0.0.0) handling               | ignored per the RFC-permitted "no capability" branch; Phase 2: install on-link once DHCP routes carry an oif |
| Static Routes (option 33)                                   | not implemented (never requested; ignored when 121 present, matching the RFC + Linux) |

**Compliance note.** Option 121 is the Linux-default-since-2009
way to receive a richer routing table from DHCP than the
single default route. PyTCP now requests it, decodes it
(including RFC 3396 split instances), and installs the
routes through the host-mode FIB / Route API, ignoring
option 3 when option 121 is present per the RFC MUST. The
one deliberate deviation is the Local Subnet Routes
(router-0.0.0.0) case, which RFC 3442 explicitly permits
a stack to ignore when it does not provide the
multi-subnet-on-one-link capability; PyTCP's host FIB does
not yet carry an output-interface index on DHCP-learned
routes (Phase 2).
