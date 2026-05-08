# RFC 8028 — First-Hop Router Selection by Hosts in a Multi-Prefix Network

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 8028                                              |
| Title       | First-Hop Router Selection by Hosts in a Multi-Prefix Network |
| Category    | Standards Track (Updates RFC 4861, RFC 6724)      |
| Date        | November 2016                                     |
| Source text | [`rfc8028.txt`](rfc8028.txt)                      |

This adherence record is a **stub**. The audit will be
filled in when multihoming-aware first-hop selection
lands.

## Status: deferred (SHOULD per RFC 8504 §5.10)

In a multi-prefix multi-router network — where a host has
addresses from prefix A advertised by router R_A and from
prefix B advertised by router R_B, and both upstreams
implement BCP 38 ingress filtering — picking the wrong
first-hop router for an outbound packet causes the
upstream provider to drop the packet (the packet's source
address doesn't match the prefix BCP 38 expects to see
behind that router).

RFC 8028 mandates that hosts pair source-address selection
with first-hop router selection — when the host picks
source `A::1`, it must route through `R_A`; when it picks
`B::1`, route through `R_B`.

PyTCP holds a single default gateway per `Ip6Host`,
not a per-source-address gateway map. RFC 8028 requires
per-prefix gateway state plus a Rule 5.5 update to RFC
6724 source selection. Both pre-requisites are deferred.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.10
  — parent classification (SHOULD)
- `docs/rfc/ip6/rfc6724__default_address_selection/adherence.md`
  — companion deferred record (Rule 5.5)
- `docs/rfc/icmp6/rfc4191__default_router_preferences/adherence.md`
  — companion deferred record (per-prefix router state)
