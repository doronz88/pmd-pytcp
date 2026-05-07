# RFC 4443 — Internet Control Message Protocol (ICMPv6) for IPv6

| Field       | Value                                               |
|-------------|-----------------------------------------------------|
| RFC number  | 4443                                                |
| Title       | Internet Control Message Protocol (ICMPv6) for IPv6 |
| Category    | Internet Standard (STD 89)                          |
| Date        | March 2006                                          |
| Source text | [`rfc4443.txt`](rfc4443.txt)                        |

This adherence record is currently a stub. The host-requirements
ICMP error-generation rules apply symmetrically to v4 and v6 via
the shared `pytcp/protocols/icmp/` runtime layer; the per-clause
audit of those gates is mirrored from
[`../../icmp4/rfc1122__host_requirements_icmp/adherence.md`](../../icmp4/rfc1122__host_requirements_icmp/adherence.md)
and applies here under §2.4(e/f).

Implementation status by ICMPv6 type, as of the recent ICMP
host-requirements work:

| Type    | Name                    | Status                                   |
|---------|-------------------------|------------------------------------------|
| 1       | Destination Unreachable | met (parser + emitter; demux to TCP/UDP) |
| 2       | Packet Too Big          | met (parser + PMTUD demux)               |
| 3       | Time Exceeded           | met (parser + soft-error plumbing)       |
| 4       | Parameter Problem       | met (parser + soft-error plumbing)       |
| 128     | Echo Request            | met (replies unconditionally per §4.2)   |
| 129     | Echo Reply              | met (RX dispatch + RAW socket delivery)  |
| 133-136 | ND (RS / RA / NS / NA)  | met (RFC 4861 implementation)            |
| 137     | Redirect                | not implemented                          |
| 143     | MLDv2 Report            | met (RFC 3810 implementation)            |

§2.4(e) — "ICMPv6 error MUST NOT be originated as a result of
receiving" — the five rules (error message, redirect, multicast
destination with PTB / Param-Problem-code-2 exceptions, and the
implicit "single host" source rule) are wired through the shared
`pytcp/protocols/icmp/icmp__error_emitter.py` module via
`IcmpErrorContext.is_pmtud_response` /
`IcmpErrorContext.is_param_problem_code_2`. The UDP closed-port
emitter consumes the v6 rate limiter at
`pytcp.stack.icmp6_error_rate_limiter`, mirroring the v4 wire-up.

§2.4(f) — rate-limit requirement — met (post Phase α1.1) via the
shared `IcmpErrorRateLimiter`.

§4.2 — Echo Reply may be sent in response to multicast — the v6
echo handler delegates to
[`pytcp/protocols/icmp6/icmp6__echo_gate.py`](../../../../pytcp/protocols/icmp6/icmp6__echo_gate.py)
which currently permits unconditionally (no Smurf gate, by spec
design — multicast Echo replies are explicitly permitted).

The full per-section RFC 4443 walkthrough will be authored using
the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill when Phase β closes the Time Exceeded / Parameter Problem
gap (which touches §3.3 and §3.4).
