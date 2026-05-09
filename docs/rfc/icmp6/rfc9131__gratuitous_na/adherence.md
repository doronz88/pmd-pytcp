# RFC 9131 — Gratuitous Neighbor Discovery: Creating Neighbor Cache Entries on First-Hop Routers

| Field       | Value                                                                            |
|-------------|----------------------------------------------------------------------------------|
| RFC number  | 9131                                                                             |
| Title       | Gratuitous Neighbor Discovery: Creating Neighbor Cache Entries on First-Hop Routers |
| Category    | Standards Track (Updates RFC 4861)                                               |
| Date        | October 2021                                                                     |
| Source text | (RFC text not yet copied locally — fetch from https://www.rfc-editor.org/rfc/rfc9131.txt when filling in the audit) |

This adherence record is a **stub**. The audit will be
filled in when the gratuitous-NA TX path is wired up.

## Status: not implemented (host-side: SHOULD; router-side: Phase 2)

RFC 9131 introduces the IPv6 analogue of gratuitous ARP:
on link, a host or router emits an unsolicited Neighbor
Advertisement (target=self, override flag set,
destination=all-nodes-multicast) so peers can preemptively
populate their neighbour cache for it. This dramatically
reduces the time-to-first-packet after host attachment
(no need for the peer to NS-resolve before sending).

Two sides:

1. **Host-side (in scope, Phase 1):** when a SLAAC address
   completes DAD successfully, emit one or more
   gratuitous NAs analogous to the RFC 5227 §2.3 ARP
   Announcement that PyTCP already implements for IPv4.
   Linux ships this as the `IPV6_GRATUITOUS_NA` behaviour
   by default on modern kernels.

2. **Router-side (Phase 2 deferred):** a forwarding router
   uses gratuitous NAs to pre-populate its own neighbour
   cache for known-on-link hosts. PyTCP is host-only in
   Phase 1; the router-side behaviour is part of the
   eventual router-grade work.

The PyTCP DAD path currently completes silently — there is
no analogue of `_send_arp_announcement` for ND today. The
fix surface is small (one new `send_icmp6_neighbor_advertisement_gratuitous`
helper plus a hook in the DAD-success path), but DAD-
gratuitous-NA needs to compose with RFC 4862 §5.4
DAD timing so the gratuitous emits do not race a late
conflicting NS arriving at the same instant.
