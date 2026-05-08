# RFC 6724 — Default Address Selection for IPv6

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 6724                                              |
| Title       | Default Address Selection for Internet Protocol Version 6 (IPv6) |
| Category    | Standards Track (Updates RFC 4291; Obsoletes RFC 3484) |
| Date        | September 2012                                    |
| Source text | [`rfc6724.txt`](rfc6724.txt)                      |

This adherence record is a **stub**. The audit will be
filled in using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill when the address-selection rule set gets a
focused implementation pass.

## Status: partial (MUST per RFC 8504 §6.6; key rules implemented)

PyTCP picks the source address for an outbound IPv6 packet
by matching the destination's prefix to a configured host
prefix; the `Ip6Host` model exposes per-host prefix and
gateway. This implements the common case of RFC 6724
Source Address Selection Rule 5 ("prefer matching label").
The dedicated address-class predicates in
`net_addr/ip6_address.py` (`is_link_local`,
`is_unspecified`, `is_unicast`, `is_multicast`) feed the
scope-aware Rules 1-4 implicitly via the routing path.

Not yet implemented:

- The **full destination-address selection** rule set
  (Rules D1-D8) for picking among multiple destination
  candidates returned by DNS.
- **Rule 5.5** as updated by RFC 8028 (prefer source
  address with matching first-hop router in multihomed
  networks).
- Privacy / temporary address preference (paired with
  RFC 4941; both deferred).
- Configurable address-selection policy table (RFC 6724
  §2.1) — PyTCP uses the default policy implicitly.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §6.6
  — parent classification (MUST)
- `docs/rfc/icmp6/rfc8028__first_hop_router_selection/adherence.md`
  — companion deferred record for the §5.5 update
- `docs/rfc/icmp6/rfc4941__privacy_extensions/adherence.md`
  — companion deferred record for temp-address
  preference handling
