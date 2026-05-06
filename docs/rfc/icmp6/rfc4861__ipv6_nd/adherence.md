# RFC 4861 — Neighbor Discovery for IPv6

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 4861                                               |
| Title       | Neighbor Discovery for IP version 6 (IPv6)         |
| Category    | Standards Track                                    |
| Date        | September 2007                                     |
| Source text | [`rfc4861.txt`](rfc4861.txt)                       |

This adherence record is a stub. PyTCP already implements
the four ND ICMPv6 message types (Router Solicitation,
Router Advertisement, Neighbor Solicitation, Neighbor
Advertisement) and the associated TLLA/SLLA option, but the
codebase has not been audited paragraph-by-paragraph against
RFC 4861 yet. The RFC text is included so future ND-related
work can cite specific clauses with confidence.

The audit will be filled in using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill when feature/refactor work touches behaviour governed
by this RFC.
