# RFC 7527 — Enhanced Duplicate Address Detection

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 7527                                              |
| Title       | Enhanced Duplicate Address Detection              |
| Category    | Standards Track                                   |
| Date        | April 2015                                        |
| Source text | [`rfc7527.txt`](rfc7527.txt)                      |

This adherence record is a **stub**. The audit will be
filled in when DAD loopback detection is implemented.

## Status: deferred (SHOULD per RFC 8504 §6.3)

RFC 7527 §3 describes how a host running DAD can be fooled
by its own DAD Neighbor Solicitation looped back through
the network — a misconfigured switch or layer-2 loop
echoes the NS to the host, which then sees its own NS
arriving from a "different" sender and concludes the
address is duplicate, infinitely retrying SLAAC.

The §4 algorithm: track a per-DAD-attempt random "Nonce"
option in outbound NS, and on receipt of a "duplicate"
NS, compare the Nonce — if it matches, the message is the
host's own loopback and should be ignored.

PyTCP's DAD does not yet implement the Nonce check. In
practice this is a hardening item: a typical hosted
environment without layer-2 loops never triggers the
loopback case. Marked SHOULD by RFC 8504 §6.3 with the
note "where such detection is beneficial."

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §6.3
  — parent classification (SHOULD)
- `docs/rfc/icmp6/rfc4862__ipv6_slaac/adherence.md` —
  parent SLAAC / DAD record
