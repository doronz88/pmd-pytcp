# RFC 7217 — A Method for Generating Semantically Opaque Interface Identifiers with IPv6 SLAAC

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 7217                                              |
| Title       | A Method for Generating Semantically Opaque Interface Identifiers with IPv6 Stateless Address Autoconfiguration (SLAAC) |
| Category    | Standards Track                                   |
| Date        | April 2014                                        |
| Source text | [`rfc7217.txt`](rfc7217.txt)                      |

This adherence record is a **stub**. The audit will be
filled in when the IID generator is replaced.

## Status: deferred (RECOMMENDED per RFC 8504 §6.3)

PyTCP generates a SLAAC IID from the MAC address using the
modified EUI-64 mechanism (`Ip6Host.from_eui64`). The IID
is therefore stable across networks and embeds the MAC,
which leaks identity information — the privacy concern
RFC 4941 (temporary addresses) and RFC 7217 (stable but
opaque IIDs) both address from different angles.

RFC 7217 §5 generates the IID as
`F(prefix, network_id, dad_counter, secret_key)` where F
is a cryptographic hash. The result is:

- Stable across re-attaches to the *same* network.
- Different across networks (no cross-network correlation).
- No MAC leak.

RFC 8504 §6.3 says: "It is RECOMMENDED, as described in
[RFC8064], that unless there is a specific requirement for
Media Access Control (MAC) addresses to be embedded in an
Interface Identifier (IID), nodes follow the procedure in
[RFC7217] to generate SLAAC-based addresses, rather than
use [RFC4862]." The current EUI-64 generator is the
"specific requirement" exception path; for general-purpose
deployments the RFC 7217 method is preferred.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §6.3
  — parent classification (RECOMMENDED via RFC 8064)
- `docs/rfc/icmp6/rfc4862__ipv6_slaac/adherence.md` —
  parent SLAAC record
- `docs/rfc/icmp6/rfc4941__privacy_extensions/adherence.md`
  — companion deferred record (orthogonal privacy approach)
