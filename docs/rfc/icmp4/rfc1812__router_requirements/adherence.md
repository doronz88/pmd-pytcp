# RFC 1812 — Requirements for IP Version 4 Routers

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 1812                                               |
| Title       | Requirements for IP Version 4 Routers              |
| Category    | Standards Track                                    |
| Date        | June 1995                                          |
| Source text | [`rfc1812.txt`](rfc1812.txt)                       |

This adherence record is a stub. PyTCP is a host stack, not
a router, so most of RFC 1812 does not apply directly. The
RFC is included for reference because §4.3.2 (Generation of
ICMP Messages) and §4.3.3 (Specific ICMP Messages) prescribe
the canonical forms of the ICMP error messages PyTCP both
sends (Port Unreachable in response to closed-port datagrams)
and receives (Destination Unreachable, Frag-Needed/PTB during
PMTUD).

The audit will be filled in using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill when feature/refactor work touches behaviour governed
by this RFC.
