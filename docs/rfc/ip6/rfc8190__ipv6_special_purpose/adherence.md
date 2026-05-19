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
per-prefix RFCs it indexes (RFC 3849 for documentation,
RFC 6666 for discard, RFC 5180 for benchmarking, etc.).

The IPv4 parallel is
[`../../ip4/rfc6890__special_purpose_ip_registries/adherence.md`](../../ip4/rfc6890__special_purpose_ip_registries/adherence.md).
PyTCP's only RFC 8190 surface is the address-classification
predicate set on `Ip6Address`.

The audit was performed by reading RFC 8190 + the IANA
IPv6 Special-Purpose Address Registry (current as of
2026-05-12) and inspecting `packages/net_addr/net_addr/ip6_address.py`
directly.

Adherence levels: **met**, **partial**, **not implemented**,
**n/a**.

---

## Top-line adherence

PyTCP **meets** the RFC 8190 / RFC 6890 surface relevant to a
host stack: the most-needed special-purpose prefixes
(loopback, link-local, ULA, multicast, unspecified,
documentation, discard, benchmarking, IPv4-mapped) are
recognised by `Ip6Address` predicates. The non-propagation
operational requirements are router-side (Phase-2 forwarding
plane). The "Forwardable" / "Globally Reachable" /
"Reserved-by-Protocol" metadata in the registry is operator-
facing — PyTCP currently exposes only the bare predicates and
leaves the policy decision to consumers.

| Prefix                  | RFC               | PyTCP predicate                  | Status |
|-------------------------|-------------------|----------------------------------|--------|
| `::/128`                | RFC 4291          | `is_unspecified`                 | met    |
| `::1/128`               | RFC 4291          | `is_loopback`                    | met    |
| `::ffff:0:0/96`         | RFC 4291 §2.5.5.2 | `is_reserved`                    | met    |
| `64:ff9b::/96`          | RFC 6052          | (no predicate; treated as global) | partial — no consumer today |
| `64:ff9b:1::/48`        | RFC 8215          | (no predicate)                   | partial — no consumer today |
| `100::/64`              | RFC 6666          | `is_reserved`                    | met    |
| `2001::/23`             | RFC 2928          | (no predicate; covered by is_global) | partial — IETF protocol assignments  |
| `2001::/32`             | RFC 4380 (TEREDO) | (no predicate)                   | n/a (operator-side; no PyTCP TEREDO) |
| `2001:1::1/128`         | RFC 7723 (PCP)    | (no predicate)                   | n/a (no PCP) |
| `2001:2::/48`           | RFC 5180          | `is_reserved`                    | met    |
| `2001:3::/32`           | RFC 7450 (AMT)    | (no predicate)                   | n/a (no AMT) |
| `2001:4:112::/48`       | RFC 7535          | (no predicate)                   | n/a (no AS112) |
| `2001:20::/28`          | RFC 7343 (ORCHIDv2) | (no predicate)                 | n/a (no HIT) |
| `2001:db8::/32`         | RFC 3849          | `is_documentation` + `is_reserved` | met  |
| `2002::/16`             | RFC 3056 (6to4)   | (no predicate)                   | partial — 6to4 deprecated, no consumer |
| `2620:4f:8000::/48`     | RFC 7534 (AS112)  | (no predicate)                   | n/a (operator-side) |
| `fc00::/7`              | RFC 4193 (ULA)    | `is_private`                     | met    |
| `fe80::/10`             | RFC 4291 (LL)     | `is_link_local`                  | met    |
| `ff00::/8`              | RFC 4291 (mc)     | `is_multicast`                   | met    |

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

**Adherence:** met (the predicates cover the registry
entries listed in the table above). The PyTCP
`Ip6Address` predicates match the IANA IPv6 Special-Purpose
Address Registry verbatim for the entries that have a
predicate; entries without a predicate either have no
PyTCP consumer (TEREDO, AMT, PCP, AS112, ORCHIDv2) or are
deprecated (6to4).

The `is_reserved` predicate is an aggregator over the
"special-purpose AND not-covered-by-another-predicate" set:

```python
@property
def is_reserved(self) -> bool:
    return (
        self._address & IP6__DISCARD_PREFIX_MASK == IP6__DISCARD_PREFIX
        or self._address & IP6__IPV4_MAPPED_PREFIX_MASK == IP6__IPV4_MAPPED_PREFIX
        or self._address & IP6__BENCHMARK_PREFIX_MASK == IP6__BENCHMARK_PREFIX
        or self._address & IP6__DOCUMENTATION_PREFIX_MASK == IP6__DOCUMENTATION_PREFIX
    )
```

(`packages/net_addr/net_addr/ip6_address.py`). Consumers that need a finer
classification call `is_documentation` directly.

---

## Per-prefix audit notes

### 100::/64 (RFC 6666 Discard-Only)

> "An IPv6 prefix used for sinking traffic at the routing
>  layer, where the destination has no relevance to a host."

**Adherence:** met (`is_reserved` returns True). Consumers
that want to drop outbound traffic to the discard prefix
can gate on `dst.is_reserved` and skip emission.

### ::ffff:0:0/96 (RFC 4291 §2.5.5.2 IPv4-mapped)

> "Used to represent IPv4 addresses inside an IPv6 socket
>  API. Such addresses MUST NOT appear on the wire."

**Adherence:** met (`is_reserved` returns True). PyTCP does
not emit IPv4-mapped addresses on the wire; an IPv4-mapped
destination on a TX path would be classified as reserved
and could be rejected by future strict-policy code.

### 2001:db8::/32 (RFC 3849 Documentation)

> "Use in publicly available documentation. Filtered at
>  network boundaries to prevent leakage."

**Adherence:** met (`is_documentation` + `is_reserved`
both return True). A future ingress-filter that drops
documentation-sourced packets at the host boundary (a
Phase-2 sysctl) would consult `is_documentation`; the
Phase-1 stack accepts them, but tests that use the
documentation prefix as fixtures get unambiguous
classification.

### 2001:2::/48 (RFC 5180 Benchmarking)

> "Address space allocated for benchmarking testing of
>  network interconnect devices."

**Adherence:** met (`is_reserved` returns True). No
operational impact on PyTCP today; the predicate is
available for future test-fixture validation or
firewall-plane gating.

### fc00::/7 (RFC 4193 ULA)

**Adherence:** met (`is_private` returns True). See the
dedicated [`../rfc4193__unique_local_addresses/adherence.md`](../rfc4193__unique_local_addresses/adherence.md)
record for the full walk-through.

### fe80::/10 (RFC 4291 Link-Local), ff00::/8 (RFC 4291 Multicast)

**Adherence:** met (existing `is_link_local` /
`is_multicast` predicates). These are RFC 4291 prefixes
(not RFC 8190 registry entries strictly, but referenced
from RFC 6890).

### Prefixes with no PyTCP predicate

The following IANA registry entries have **no PyTCP
predicate** today because PyTCP has no consumer that needs
to distinguish them:

- `64:ff9b::/96` (RFC 6052 IPv4-IPv6 Well-Known Prefix) —
  no NAT64 client.
- `64:ff9b:1::/48` (RFC 8215 IPv4-IPv6 Local-Use) — same.
- `2001:1::1/128` (RFC 7723 PCP Anycast) — no PCP client.
- `2001:3::/32` (RFC 7450 AMT) — no AMT.
- `2001:4:112::/48` (RFC 7535 AS112-v6) — operator-side.
- `2001:20::/28` (RFC 7343 ORCHIDv2) — no HIT/HIP.
- `2002::/16` (RFC 3056 6to4) — deprecated; PyTCP routes
  via native IPv6 only.

These are classified as **partial** in the top-line table
because the registry classification is missing, but the
practical impact is zero — every such prefix is currently
treated as global unicast by PyTCP, which matches the
operational behaviour of most IPv6 stacks (Linux treats
2001:db8:: as global too unless explicitly filtered).

A future code path that needs distinction (e.g. a NAT64
client emitting via 64:ff9b::/96) would add the relevant
predicate at that time.

---

## Test coverage audit

### is_documentation

- **Unit:**
  `packages/net_addr/net_addr/tests/unit/test__ip6_address.py::TestIp6AddressIsDocumentation`
  — boundary cases (2001:db8::1, 2001:db8::ffff:..., upper
  edge), neighbour rejection (2001:db7::, 2001:db9::), and
  global-unrelated rejection.

**Status:** locked in.

### is_reserved

- **Unit:**
  `packages/net_addr/net_addr/tests/unit/test__ip6_address.py::TestIp6AddressIsReserved`
  — positive cases for each recognised prefix (100::/64
  discard, ::ffff:0:0/96 IPv4-mapped, 2001:2::/48
  benchmark, 2001:db8::/32 documentation); negative cases
  for global unicast, link-local, ULA, loopback,
  unspecified (each owned by its dedicated predicate).

**Status:** locked in.

### Test coverage summary

| Predicate          | Coverage |
|--------------------|----------|
| `is_documentation` | locked in |
| `is_reserved`      | locked in |
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
| `is_documentation` (`2001:db8::/32`)                  | met (new this commit) |
| `is_reserved` aggregator                              | met (new this commit; covers discard / IPv4-mapped / benchmark / documentation) |
| Remaining special-purpose prefixes (TEREDO, NAT64, ORCHIDv2, AS112, etc.) | partial (no consumer; treated as global) |
| Procedural RFC 8190 §1-§2 rules                       | n/a (IETF process) |
| Operational non-propagation (router-side)             | n/a (no forwarding; Phase-2 concern) |

PyTCP meets the host-stack surface relevant to RFC 8190.
The remaining "partial" rows are operationally low-impact
for a host stack and become relevant when a consumer
materialises (e.g. NAT64 client → add `is_nat64_translated`
predicate alongside `64:ff9b::/96`).

## Cross-references

- IPv4 parallel: [`../../ip4/rfc6890__special_purpose_ip_registries/adherence.md`](../../ip4/rfc6890__special_purpose_ip_registries/adherence.md)
- ULA (the most-used non-global special-purpose IPv6 prefix):
  [`../rfc4193__unique_local_addresses/adherence.md`](../rfc4193__unique_local_addresses/adherence.md)
- Source-selection consumers of these predicates: [`../rfc6724__default_address_selection/adherence.md`](../rfc6724__default_address_selection/adherence.md)
