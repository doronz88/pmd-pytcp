# RFC 8190 — Updates to the Special-Purpose IP Address Registries

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 8190                                           |
| Title       | Updates to the Special-Purpose IP Address Registries |
| Category    | Best Current Practice (BCP 153)                |
| Date        | June 2017                                      |
| Updates     | RFC 6890                                       |
| Source text | (not bundled — see https://www.rfc-editor.org/rfc/rfc8190.html) |

This document records the PyTCP codebase's adherence to RFC
8190 (and the underlying RFC 6890 for IPv6, plus the
individual per-prefix RFCs) clause by clause. RFC 8190 is a
BCP that updates the procedural rules around the IANA
Special-Purpose Address Registries; the operational
classification requirements for hosts come from RFC 6890
("Special-Purpose IP Address Registries") and the
per-prefix RFCs it indexes (RFC 3849 / RFC 9637 for
documentation, RFC 6666 for discard, RFC 5180 for
benchmarking, etc.).

The IPv4 parallel is
[`../../ip4/rfc6890__special_purpose_ip_registries/adherence.md`](../../ip4/rfc6890__special_purpose_ip_registries/adherence.md).
PyTCP's only RFC 8190 surface is the address-classification
predicate set on `Ip6Address`.

The audit was performed by reading RFC 8190 + the live IANA
IPv6 Special-Purpose Address Registry (current as of
2026-05-22) and inspecting `packages/net_addr/net_addr/ip6_address.py`
directly.

Adherence levels: **met**, **partial**, **not implemented**,
**n/a**.

---

## Top-line adherence

PyTCP **meets** the RFC 8190 / RFC 6890 host-stack surface:
`Ip6Address.is_reserved` now mirrors the **full** IANA IPv6
Special-Purpose Address Registry — every registered prefix is
classified, either by a dedicated predicate
(`is_loopback` / `is_link_local` / `is_multicast` /
`is_private` / `is_unspecified` / `is_documentation`) or by
the `is_reserved` aggregator. The non-propagation operational
requirements are router-side (Phase-2 forwarding plane). The
"Forwardable" / "Globally Reachable" / "Reserved-by-Protocol"
metadata in the registry is operator-facing — PyTCP exposes
the bare predicates and leaves the policy decision to
consumers.

| Prefix              | Name / RFC                         | PyTCP predicate                     | Status |
|---------------------|------------------------------------|-------------------------------------|--------|
| `::/128`            | Unspecified — RFC 4291             | `is_unspecified`                    | met    |
| `::1/128`           | Loopback — RFC 4291                | `is_loopback`                       | met    |
| `::ffff:0:0/96`     | IPv4-mapped — RFC 4291 §2.5.5.2    | `is_reserved`                       | met    |
| `64:ff9b::/96`      | NAT64 well-known — RFC 6052        | `is_reserved`                       | met    |
| `64:ff9b:1::/48`    | NAT64 local-use — RFC 8215         | `is_reserved`                       | met    |
| `100::/64`          | Discard-Only — RFC 6666           | `is_reserved`                       | met    |
| `100:0:0:1::/64`    | Dummy Prefix — RFC 9780           | `is_reserved`                       | met    |
| `2001::/23`         | IETF Protocol Assignments — RFC 2928 | `is_reserved`                    | met (umbrella) |
| `2001::/32`         | TEREDO — RFC 4380                 | `is_reserved` (via 2001::/23)       | met    |
| `2001:1::1/128`     | PCP Anycast — RFC 7723           | `is_reserved` (via 2001::/23)       | met    |
| `2001:1::2/128`     | TURN Anycast — RFC 8155          | `is_reserved` (via 2001::/23)       | met    |
| `2001:1::3/128`     | DNS-SD SRP Anycast — RFC 9665     | `is_reserved` (via 2001::/23)       | met    |
| `2001:2::/48`       | Benchmarking — RFC 5180          | `is_reserved` (via 2001::/23)       | met    |
| `2001:3::/32`       | AMT — RFC 7450                   | `is_reserved` (via 2001::/23)       | met    |
| `2001:4:112::/48`   | AS112-v6 — RFC 7535             | `is_reserved` (via 2001::/23)       | met    |
| `2001:10::/28`      | Deprecated (ORCHID) — RFC 4843   | `is_reserved` (via 2001::/23)       | met    |
| `2001:20::/28`      | ORCHIDv2 — RFC 7343             | `is_reserved` (via 2001::/23)       | met    |
| `2001:30::/28`      | DET — RFC 9374                  | `is_reserved` (via 2001::/23)       | met    |
| `2001:db8::/32`     | Documentation — RFC 3849        | `is_documentation` + `is_reserved`  | met    |
| `2002::/16`         | 6to4 — RFC 3056                 | `is_reserved`                       | met    |
| `2620:4f:8000::/48` | Direct Delegation AS112 — RFC 7534 | `is_reserved`                    | met    |
| `3fff::/20`         | Documentation — RFC 9637        | `is_documentation` + `is_reserved`  | met    |
| `5f00::/16`         | SRv6 SIDs — RFC 9602            | `is_reserved`                       | met    |
| `fc00::/7`          | Unique-Local — RFC 4193         | `is_private`                        | met    |
| `fe80::/10`         | Link-Local Unicast — RFC 4291   | `is_link_local`                     | met    |
| `ff00::/8`          | Multicast — RFC 4291            | `is_multicast`                      | met    |

---

## §1 / §2 Procedural Updates (no host-stack impact)

RFC 8190 §1-§2 redefines the procedural rules for IANA
registry updates ("Allocation by IETF Document", required
fields, attribute table refresh). These are IETF-process
concerns; no host-stack code changes.

**Adherence:** n/a (procedural).

---

## §3 Updates to the Special-Purpose Address Registries

> "The 'Special-Purpose Address Registries' (...) are
>  updated to reflect the changes described above."

**Adherence:** met. The PyTCP `Ip6Address` predicates classify
the IANA IPv6 Special-Purpose Address Registry in full — every
registry entry maps to either a dedicated predicate or the
`is_reserved` aggregator (see the top-line table).

`is_reserved` is the aggregator over the "special-purpose AND
not-covered-by-another-predicate" set. The `2001::/23` IETF
Protocol Assignments umbrella (RFC 2928) subsumes every
2001:0000–2001:01ff sub-allocation (TEREDO, the PCP / TURN /
DNS-SD anycast single addresses, Benchmarking, AMT, AS112-v6,
the deprecated ORCHID block, ORCHIDv2 and the DET prefix), so
a single mask test covers all of them:

```python
@property
def is_reserved(self) -> bool:
    return (
        self.is_documentation
        or self._address & IP6__NAT64_WELL_KNOWN_PREFIX_MASK == IP6__NAT64_WELL_KNOWN_PREFIX
        or self._address & IP6__NAT64_LOCAL_PREFIX_MASK == IP6__NAT64_LOCAL_PREFIX
        or self._address & IP6__DISCARD_PREFIX_MASK == IP6__DISCARD_PREFIX
        or self._address & IP6__DUMMY_PREFIX_MASK == IP6__DUMMY_PREFIX
        or self._address & IP6__IETF_PROTOCOL_PREFIX_MASK == IP6__IETF_PROTOCOL_PREFIX
        or self._address & IP6__6TO4_PREFIX_MASK == IP6__6TO4_PREFIX
        or self._address & IP6__AS112_PREFIX_MASK == IP6__AS112_PREFIX
        or self._address & IP6__SRV6_PREFIX_MASK == IP6__SRV6_PREFIX
        or self._address & IP6__IPV4_MAPPED_PREFIX_MASK == IP6__IPV4_MAPPED_PREFIX
    )
```

(`packages/net_addr/net_addr/ip6_address.py`). Consumers that need a finer
classification call `is_documentation` directly. `is_reserved`
delegates the two documentation prefixes to `is_documentation`
so the documentation membership is defined in exactly one
place.

---

## Per-prefix audit notes

### 100::/64 (RFC 6666 Discard-Only)

> "An IPv6 prefix used for sinking traffic at the routing
>  layer, where the destination has no relevance to a host."

**Adherence:** met (`is_reserved` returns True).

### 100:0:0:1::/64 (RFC 9780 Dummy IPv6 Prefix)

> "A prefix that can be used as a non-routable placeholder
>  IPv6 destination address."

**Adherence:** met (`is_reserved` returns True). Distinct from
the discard prefix `100::/64` — the dummy prefix is the
adjacent `100:0:0:1::/64` and is matched by its own mask.

### ::ffff:0:0/96 (RFC 4291 §2.5.5.2 IPv4-mapped)

> "Used to represent IPv4 addresses inside an IPv6 socket
>  API. Such addresses MUST NOT appear on the wire."

**Adherence:** met (`is_reserved` returns True). PyTCP does
not emit IPv4-mapped addresses on the wire; an IPv4-mapped
destination on a TX path would be classified as reserved and
could be rejected by future strict-policy code.

### 64:ff9b::/96 (RFC 6052) and 64:ff9b:1::/48 (RFC 8215) NAT64

**Adherence:** met (`is_reserved` returns True). PyTCP has no
NAT64 client today, but the translation prefixes are now
classified rather than silently treated as global unicast; a
future NAT64 consumer would add a dedicated
`is_nat64_translated` predicate alongside these masks.

### 2001::/23 (RFC 2928 IETF Protocol Assignments)

**Adherence:** met (`is_reserved` returns True via the
`IP6__IETF_PROTOCOL_PREFIX` /23 mask). This umbrella covers
the 2001:0000–2001:01ff sub-allocations as one test; the
individual sub-block constants (TEREDO at `2001::/32`,
ORCHIDv2 at `2001:20::/28`, etc.) are intentionally not
duplicated, because the /23 already classifies them and PyTCP
has no consumer that needs to distinguish one sub-block from
another. The dedicated `teredo` extraction property keeps its
own `IP6__TEREDO_PREFIX` constant because it parses the
embedded server/client IPv4 pair, which is a different concern
from membership classification.

### 2001:db8::/32 (RFC 3849) and 3fff::/20 (RFC 9637) Documentation

> "Use in publicly available documentation. Filtered at
>  network boundaries to prevent leakage."

**Adherence:** met (`is_documentation` + `is_reserved` both
return True). RFC 9637 (2024) expanded the documentation
allocation with the larger `3fff::/20`; `is_documentation` now
matches either prefix, and `is_reserved` delegates to it.

### 2002::/16 (RFC 3056 6to4)

**Adherence:** met (`is_reserved` returns True). 6to4 is
deprecated for new deployment (RFC 7526) but remains a live
registry entry; PyTCP classifies it and routes via native
IPv6 only. The `sixtofour` extraction property keeps its own
`IP6__6TO4_PREFIX` constant for parsing the embedded IPv4.

### 2620:4f:8000::/48 (RFC 7534 Direct Delegation AS112) and 5f00::/16 (RFC 9602 SRv6 SIDs)

**Adherence:** met (`is_reserved` returns True). Both are
operator/router-side allocations with no host consumer in
PyTCP, but they are now classified rather than treated as
global unicast.

### fc00::/7 (RFC 4193 ULA)

**Adherence:** met (`is_private` returns True). See the
dedicated [`../rfc4193__unique_local_addresses/adherence.md`](../rfc4193__unique_local_addresses/adherence.md)
record for the full walk-through.

### fe80::/10 (RFC 4291 Link-Local), ff00::/8 (RFC 4291 Multicast)

**Adherence:** met (existing `is_link_local` /
`is_multicast` predicates). These are RFC 4291 prefixes
(referenced from RFC 6890 / the registry).

### Interaction with is_global

`is_global` remains the pure RFC 4291 `2000::/3` test and is
**not** narrowed by `is_reserved` — a benchmarking
(`2001:2::1`) or documentation (`2001:db8::1`) address is both
`is_global` and `is_reserved`. This is the documented
deliberate divergence in `ip6_address.py`: PyTCP's `is_global`
is "global unicast" in the addressing-architecture sense, not
RFC 6890 "Globally Reachable". Consumers wanting reachability
semantics combine `is_global and not is_reserved`.

---

## Test coverage audit

### is_documentation

- **Unit:**
  `packages/net_addr/net_addr/tests/unit/test__ip6_address.py::TestIp6AddressIsDocumentation`
  — 2001:db8::/32 boundary cases (match, upper edge, below,
  above, global-unrelated) plus RFC 9637 3fff::/20 cases
  (`__rfc9637_match`, `__rfc9637_boundary`, `__rfc9637_above`).

**Status:** locked in.

### is_reserved

- **Unit:**
  `packages/net_addr/net_addr/tests/unit/test__ip6_address.py::TestIp6AddressIsReserved`
  — positive cases for every recognised registry prefix:
  discard (`100::/64`), documentation (`2001:db8::/32`),
  benchmark (`2001:2::/48`), IPv4-mapped (`::ffff:0:0/96`),
  NAT64 well-known (`64:ff9b::/96`), NAT64 local-use
  (`64:ff9b:1::/48`), dummy (`100:0:0:1::/64`), IETF Protocol
  Assignments umbrella (`2001::/23`), 6to4 (`2002::/16`),
  AS112 (`2620:4f:8000::/48`), RFC 9637 documentation
  (`3fff::/20`), SRv6 SIDs (`5f00::/16`); negative cases for
  global unicast, link-local, ULA, loopback, unspecified (each
  owned by its dedicated predicate).

**Status:** locked in.

### Test coverage summary

| Predicate          | Coverage |
|--------------------|----------|
| `is_documentation` | locked in (both RFC 3849 + RFC 9637 prefixes) |
| `is_reserved`      | locked in (full IANA registry) |
| Unrelated prefixes | locked in indirectly (via existing `is_loopback` / `is_link_local` / etc. coverage) |

---

## Overall assessment

| Aspect                                                | Status |
|-------------------------------------------------------|--------|
| `is_loopback` (`::1/128`)                             | met    |
| `is_link_local` (`fe80::/10`)                         | met    |
| `is_multicast` (`ff00::/8`)                           | met    |
| `is_private` (`fc00::/7`)                             | met    |
| `is_unspecified` (`::/128`)                           | met    |
| `is_documentation` (`2001:db8::/32`, `3fff::/20`)     | met    |
| `is_reserved` aggregator (full IANA registry)         | met    |
| Procedural RFC 8190 §1-§2 rules                       | n/a (IETF process) |
| Operational non-propagation (router-side)             | n/a (no forwarding; Phase-2 concern) |
| "Forwardable" / "Globally Reachable" registry metadata | not implemented (operator-facing; no PyTCP consumer) |

PyTCP meets the host-stack surface relevant to RFC 8190 and
classifies the full IANA IPv6 Special-Purpose Address Registry.
The only un-modelled aspect is the per-entry boolean metadata
(Forwardable / Globally Reachable / Reserved-by-Protocol),
which is operator-facing policy with no current PyTCP consumer;
a strict-policy consumer would read it as
`is_global and not is_reserved`.

## Cross-references

- IPv4 parallel: [`../../ip4/rfc6890__special_purpose_ip_registries/adherence.md`](../../ip4/rfc6890__special_purpose_ip_registries/adherence.md)
- ULA (the most-used non-global special-purpose IPv6 prefix):
  [`../rfc4193__unique_local_addresses/adherence.md`](../rfc4193__unique_local_addresses/adherence.md)
- Source-selection consumers of these predicates: [`../rfc6724__default_address_selection/adherence.md`](../rfc6724__default_address_selection/adherence.md)
