# RFC 6437 — IPv6 Flow Label Specification

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 6437                                              |
| Title       | IPv6 Flow Label Specification                     |
| Category    | Standards Track (Updates RFC 2460)                |
| Date        | November 2011                                     |
| Source text | [`rfc6437.txt`](rfc6437.txt)                      |

This adherence record is a **stub**. The audit will be
filled in using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill when feature work touches Flow Label generation.

## Status: deferred (Phase-1 polish; SHOULD per RFC 8504 §5.1)

PyTCP's IPv6 header carries a 20-bit Flow Label field
(`net_proto/protocols/ip6/ip6__header.py`); the TX path
defaults to `flow=0` and exposes `ip6__flow` as a kwarg on
`Ip6Assembler`. RFC 6437 §3 requires that nodes set the
Flow Label "for all packets of a given flow to the same
value chosen from an approximation to a discrete uniform
distribution". PyTCP does not yet wire a uniform-random
flow-label generator at the socket / per-connection layer.

This is a Phase-1 polish item — the producing-side
generator is straightforward but needs hooking through the
TCP / UDP / Raw socket emit paths so each connection picks
a stable random value. Forwarding-side requirements
(routers MUST NOT depend solely on Flow Label values being
uniformly distributed) are out of scope until Phase 2.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.1
  — parent classification ("All nodes SHOULD support the
  setting and use of the IPv6 Flow Label")
- `docs/rfc/ip6/rfc8200__ipv6/adherence.md` §3 — IPv6
  header format including the Flow Label field
