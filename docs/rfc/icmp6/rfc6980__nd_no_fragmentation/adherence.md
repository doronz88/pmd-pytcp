# RFC 6980 — Security Implications of IPv6 Fragmentation with IPv6 Neighbor Discovery

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 6980                                              |
| Title       | Security Implications of IPv6 Fragmentation with IPv6 Neighbor Discovery |
| Category    | Standards Track (Updates RFC 3971, RFC 4861)      |
| Date        | August 2013                                       |
| Source text | [`rfc6980.txt`](rfc6980.txt)                      |

This adherence record is a **stub**. The audit will be
filled in when the ND-no-fragmentation guard lands.

## Status: deferred (MUST per RFC 8504 §5.4)

RFC 6980 §5 mandates: "nodes MUST NOT employ IPv6
fragmentation for sending any of the following Neighbor
Discovery and SEcure Neighbor Discovery messages: Neighbor
Solicitation, Neighbor Advertisement, Router Solicitation,
Router Advertisement, Redirect, or Certification Path
Solicitation. Nodes MUST silently ignore any of these
messages on receipt if fragmented."

PyTCP's TX side does not fragment ND messages by
construction (`packet_handler__icmp6__tx.py` builds each
ND message as a single IPv6 packet sized below the link
MTU; there is no fragmentation hook on the ND emit path).
The MUST-NOT-send half is therefore implicit.

The MUST-silently-ignore half on the **receive** side is
**not** yet enforced. Today, an inbound ND message that
arrived as IPv6 fragments and was reassembled by the
fragmentation table flows transparently into the ICMPv6 RX
path and gets dispatched. RFC 6980 §5 requires the
receiver to detect that the ND message was fragmented and
drop it.

The implementation needs a flag on `PacketRx` (or the IPv6
parser) recording "this packet was reassembled from
fragments" so the ICMPv6 ND handlers can refuse it. A
single bit threaded through `__defragment_ip6_packet` →
`PacketRx.ip6_was_fragmented` → checked at each ND handler
entry-point would close the gap.

## Cross-references

- `docs/rfc/ip6/rfc8504__ipv6_node_reqs/adherence.md` §5.4
  — parent classification (MUST)
- `docs/rfc/icmp6/rfc4861__ipv6_nd/adherence.md` — parent
  ND record
