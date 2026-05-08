# RFC 4311 — IPv6 Host-to-Router Load Sharing

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 4311                                              |
| Title       | IPv6 Host-to-Router Load Sharing                  |
| Category    | Standards Track (Updates RFC 2461)                |
| Date        | November 2005                                     |
| Source text | [`rfc4311.txt`](rfc4311.txt)                      |

This adherence record is a **stub**. The audit will be
filled in using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill when multi-router selection is implemented.

## Status: deferred (SHOULD per RFC 8504 §5.4)

PyTCP keeps a single default gateway per IPv6 host
(`Ip6Host.gateway`); RFC 4311 §2 describes how a host with
multiple equally-preferred routers should distribute
outbound traffic across them (round-robin, hash-based, or
weighted) rather than always picking the first.

Pre-requisite for this work: a per-host route / router
list, which is the same data structure RFC 4191 / RFC 8028
need. Wire those first; load sharing layers on top.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.4
  — parent classification (SHOULD)
- `docs/rfc/icmp6/rfc4191__default_router_preferences/adherence.md`
- `docs/rfc/icmp6/rfc8028__first_hop_router_selection/adherence.md`
