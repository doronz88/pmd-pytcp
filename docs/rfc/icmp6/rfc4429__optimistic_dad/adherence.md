# RFC 4429 — Optimistic Duplicate Address Detection (DAD) for IPv6

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 4429                                              |
| Title       | Optimistic Duplicate Address Detection (DAD) for IPv6 |
| Category    | Standards Track                                   |
| Date        | April 2006                                        |
| Source text | [`rfc4429.txt`](rfc4429.txt)                      |

This adherence record is a **stub**. The audit will be
filled in if and when Optimistic DAD is implemented.

## Status: deferred (optional / MAY per RFC 8504 §6.3)

PyTCP performs full Duplicate Address Detection (RFC 4862
§5.4) on every newly-configured unicast address — the host
sends a Neighbor Solicitation with `src=::, dst=solicited-
node multicast` and waits a fixed timeout for a Neighbor
Advertisement before declaring the address usable.

RFC 4429 §3 reduces the address-acquisition delay by
allowing the host to *tentatively* use the address (with a
"Tentative" attribute that suppresses certain ND
behaviours) while DAD is still in progress. This is a
mobility-driven optimisation — RFC 8504 §6.3 explicitly
notes "for general purpose devices, RFC 4429 remains
optional at this time."

Not on PyTCP's critical path; tracked here for
completeness.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §6.3
  — parent classification (optional / MAY)
- `docs/rfc/icmp6/rfc4862__ipv6_slaac/adherence.md` —
  parent SLAAC record
- `docs/rfc/icmp6/rfc7527__enhanced_dad/adherence.md` —
  companion deferred record (loopback detection during DAD)
