# RFC 8106 — IPv6 Router Advertisement Options for DNS Configuration

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 8106                                              |
| Title       | IPv6 Router Advertisement Options for DNS Configuration |
| Category    | Standards Track (Obsoletes RFC 6106)              |
| Date        | March 2017                                        |
| Source text | [`rfc8106.txt`](rfc8106.txt)                      |

This adherence record is a **stub**. The audit will be
filled in if and when PyTCP grows a DNS-resolver consumer.

## Status: deferred (MUST per RFC 8504 §8.3 — but contextually N/A for the stack)

RFC 8106 defines two RA options:

- **RDNSS** (Recursive DNS Server) — IPv6 addresses of one
  or more recursive resolvers.
- **DNSSL** (DNS Search List) — domain suffixes for
  unqualified-name resolution.

PyTCP does not parse either option today. RFC 8504 §8.3
classifies the support as MUST: "Implementations MUST
include support for the DNS RA option."

The MUST is contextual: PyTCP is a network stack, not a
DNS-aware host. The DNS resolver is application-layer
(`socket.getaddrinfo` and friends in stdlib, or any
application library). When applications running atop PyTCP
need DNS, they reach the resolver via the BSD socket
facade as they would on any host. RFC 8106 is therefore
"implementable" only as far as parsing the options and
exposing them to the application layer — which is not
something PyTCP currently does for any RA option (no
generic option-pass-through API).

When PyTCP grows an explicit DNS-consumer hook (e.g.
exposing the configured RDNSS list via a `stack.dns_servers`
property), this record gets a real audit.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §8.3
  — parent classification (MUST, contextually N/A)
- `docs/rfc/icmp6/rfc4861__ipv6_nd/adherence.md` — parent
  ND record
