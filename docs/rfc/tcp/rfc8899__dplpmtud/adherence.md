# RFC 8899 — Packetization Layer Path MTU Discovery for Datagram Transports

| Field       | Value                                                     |
|-------------|-----------------------------------------------------------|
| RFC number  | 8899                                                      |
| Title       | Packetization Layer PMTUD for Datagram Transports         |
| Category    | Standards Track                                           |
| Date        | September 2020                                            |
| Source text | [`rfc8899.txt`](rfc8899.txt)                              |

This adherence record is a stub. RFC 8899 generalises RFC
4821 PLPMTUD to datagram transports (UDP, QUIC, SCTP) and
codifies the MIN_PMTU floor / probe schedule / black-hole
detection algorithm. PyTCP does not implement active PMTUD
probing today; the per-destination MTU cache and ICMP demux
substrate added by the upcoming refactor make a future
DPLPMTUD implementation tractable as a separate feature
commit.

The audit will be filled in using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill once active PLPMTUD/DPLPMTUD probing is implemented.
