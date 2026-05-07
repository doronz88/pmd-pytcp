# RFC 792 — Internet Control Message Protocol

| Field       | Value                             |
|-------------|-----------------------------------|
| RFC number  | 792                               |
| Title       | Internet Control Message Protocol |
| Category    | Internet Standard (STD 5)         |
| Date        | September 1981                    |
| Source text | [`rfc792.txt`](rfc792.txt)        |

This adherence record is currently a stub for the RFC 792 base
spec. The host-requirements layer that prescribes how PyTCP
generates and processes RFC 792 messages is audited in detail at
[`../rfc1122__host_requirements_icmp/adherence.md`](../rfc1122__host_requirements_icmp/adherence.md).

Implementation status by ICMPv4 type, as of the recent ICMP
host-requirements work:

| Type  | Name                    | Status                                         |
|-------|-------------------------|------------------------------------------------|
| 0     | Echo Reply              | met (RX + RAW socket delivery)                 |
| 3     | Destination Unreachable | met (parser + emitter; demux to TCP/UDP/PMTUD) |
| 4     | Source Quench           | deliberate non-implementation (RFC 6633)       |
| 5     | Redirect                | not implemented (parsed as Unknown)            |
| 8     | Echo Request            | met (Smurf gate at v4 echo handler)            |
| 11    | Time Exceeded           | met (parser + RFC 5927 §6 soft-error plumbing) |
| 12    | Parameter Problem       | met (parser + RFC 5927 §6 soft-error plumbing) |
| 13/14 | Timestamp / Reply       | deliberate non-implementation (RFC 6633)       |
| 15/16 | Information Req/Reply   | deliberate non-implementation (obsolete)       |
| 17/18 | Address Mask            | deliberate non-implementation (RFC 6633)       |

The audit will be expanded into a per-section walkthrough using the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill when Phase β closes the Time Exceeded / Parameter Problem
gap, since those changes touch RFC 792 normative wording on Type 11
/ Type 12 message format.
