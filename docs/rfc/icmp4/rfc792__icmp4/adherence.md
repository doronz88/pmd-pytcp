# RFC 792 — Internet Control Message Protocol

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 792                                                |
| Title       | Internet Control Message Protocol                  |
| Category    | Internet Standard (STD 5)                          |
| Date        | September 1981                                     |
| Source text | [`rfc792.txt`](rfc792.txt)                         |

This adherence record is a stub. The PyTCP codebase has not
been audited against RFC 792 yet — the RFC text was added so
subsequent code and test work can cite specific clauses with
confidence (especially the Destination Unreachable / Time
Exceeded / Echo Request paths exercised by the ICMP demux
+ PMTUD refactor).

The audit will be filled in using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill when feature/refactor work touches behaviour governed
by this RFC.
