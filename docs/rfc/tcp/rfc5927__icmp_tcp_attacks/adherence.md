# RFC 5927 — ICMP Attacks against TCP

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 5927                                               |
| Title       | ICMP Attacks against TCP                           |
| Category    | Informational                                      |
| Date        | July 2010                                          |
| Source text | [`rfc5927.txt`](rfc5927.txt)                       |

This adherence record is a stub. RFC 5927 catalogues
spoofed-ICMP attack vectors against TCP (blind-throughput
reduction via Frag-Needed, blind-reset via Hard Errors,
session-hijacking via PMTU shrinkage) and the recommended
mitigations (sequence-in-window check on the embedded TCP
header, Hard-Error softening for synchronized states,
PMTUD floor of 576/1280). PyTCP has not implemented these
guards yet — closing the gap is Phase 5 of the ICMP demux
+ PMTUD refactor.

The audit will be filled in using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill once Phase 5 of the refactor lands.
