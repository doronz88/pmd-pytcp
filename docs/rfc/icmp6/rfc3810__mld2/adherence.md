# RFC 3810 — Multicast Listener Discovery v2 (MLDv2) for IPv6

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 3810                                               |
| Title       | Multicast Listener Discovery Version 2 (MLDv2)     |
| Category    | Standards Track                                    |
| Date        | June 2004                                          |
| Source text | [`rfc3810.txt`](rfc3810.txt)                       |

This adherence record is a stub. PyTCP emits MLDv2
membership reports during IPv6 address assignment so
upstream routers learn which solicited-node multicast
groups the host is interested in. The codebase has not
been audited paragraph-by-paragraph against RFC 3810 yet.

The audit will be filled in using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill when feature/refactor work touches behaviour governed
by this RFC.
