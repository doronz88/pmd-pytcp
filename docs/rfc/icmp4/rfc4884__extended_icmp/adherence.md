# RFC 4884 — Extended ICMP to Support Multi-Part Messages

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 4884                                               |
| Title       | Extended ICMP to Support Multi-Part Messages       |
| Category    | Standards Track                                    |
| Date        | April 2007                                         |
| Source text | [`rfc4884.txt`](rfc4884.txt)                       |

This adherence record is a stub. The PyTCP codebase has not
been audited against RFC 4884 yet, and the multi-part /
extended ICMP object format is not implemented. The RFC text
is included so the embedded-header demux added by the ICMP
refactor can co-exist gracefully with peer implementations
that emit RFC 4884 length-bearing ICMP errors (the original
datagram length is communicated out-of-band, which can shift
the embedded-payload offset compared to the legacy RFC 792
format).

The audit will be filled in using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill when feature/refactor work touches behaviour governed
by this RFC.
