# RFC 4191 — Default Router Preferences and More-Specific Routes

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 4191                                              |
| Title       | Default Router Preferences and More-Specific Routes |
| Category    | Standards Track (Updates RFC 2461 / RFC 2461-bis) |
| Date        | November 2005                                     |
| Source text | [`rfc4191.txt`](rfc4191.txt)                      |

This adherence record is a **stub**. The audit will be
filled in using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill when multi-router prioritization is wired into the
RA / SLAAC path.

## Status: deferred (MUST per RFC 8504 §5.9, Type C host role SHOULD)

PyTCP currently treats every Router Advertisement as a
default-preference router; the RA Preference field in
flags-byte (3-bit Prf field; RFC 4191 §2.1) is parsed by
the message dataclass but not consumed by the SLAAC code,
which collects every advertised prefix into a flat
`list[(prefix, gateway)]`. RFC 4191 §3 introduces a Type C
host role with explicit per-prefix more-specific-route
table entries; PyTCP has no such table.

This is a Phase-1 polish item. Implementation requires:

- Parsing the Route Information option (RFC 4191 §2.3),
  including the Route Lifetime, Prefix Length, Preference,
  and Prefix fields.
- A per-host route table with preference ordering.
- Source-address selection that consults the route table
  when picking among candidate routers (closely paired
  with RFC 8028 multihoming first-hop selection).

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.9
  — parent classification (MUST + Type C SHOULD)
- `docs/rfc/icmp6/rfc8028__first_hop_router_selection/adherence.md`
  — companion deferred record (multihoming)
