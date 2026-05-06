# RFC 8201 — Path MTU Discovery for IP version 6

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 8201                                               |
| Title       | Path MTU Discovery for IP version 6                |
| Category    | Internet Standard (STD 87)                         |
| Date        | July 2017                                          |
| Source text | [`rfc8201.txt`](rfc8201.txt)                       |

This adherence record is a stub. RFC 8201 prescribes the
IPv6 PMTUD algorithm: Packet-Too-Big handling, the 1280-byte
floor, periodic re-discovery of higher MTUs, and
per-destination MTU caching. PyTCP currently has no PMTUD
support for IPv6 (or IPv4 — see also
[rfc1191](../rfc1191__pmtud_ip4/adherence.md)). Closing the
gap is the goal of the ICMP demux + PMTUD refactor (Phases
4 + 6).

The audit will be filled in using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill once the relevant refactor phase lands.
