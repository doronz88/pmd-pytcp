# RFC 4862 — IPv6 Stateless Address Autoconfiguration

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 4862                                               |
| Title       | IPv6 Stateless Address Autoconfiguration           |
| Category    | Standards Track                                    |
| Date        | September 2007                                     |
| Source text | [`rfc4862.txt`](rfc4862.txt)                       |

This adherence record is a stub. PyTCP performs Duplicate
Address Detection (the §5.4 DAD probe via Neighbor
Solicitation) for both link-local and global address
assignment, and consumes Router Advertisement prefix
information to derive global addresses. The codebase has
not been audited paragraph-by-paragraph against RFC 4862
yet.

The audit will be filled in using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill when feature/refactor work touches behaviour governed
by this RFC.
