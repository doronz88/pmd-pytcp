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
the shared `packages/pytcp/pytcp/protocols/icmp/` runtime layer; the per-clause
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
| 4       | Parameter Problem       | met (parser + soft-error plumbing + outbound) |
| 128     | Echo Request            | met (replies unconditionally per §4.2)   |
| 129     | Echo Reply              | met (RX dispatch + RAW socket delivery)  |
| 133-136 | ND (RS / RA / NS / NA)  | met (RFC 4861 implementation)            |
| 137     | Redirect                | not implemented                          |
| 143     | MLDv2 Report            | met (RFC 3810 implementation)            |

§3.4 — Parameter Problem outbound generation — met. The IPv6
parser carries the offending field's byte offset on
`Ip6SanityError.pointer`; `PacketHandlerIp6Rx._phrx_ip6` catches
`Ip6SanityError` and (when `pointer` is set) calls
`__phrx_ip6__emit_parameter_problem`, which routes through
`try_emit_icmp_error` and emits ICMPv6 Type 4 Code 0 (erroneous
header field encountered) with the canonical pointer. Pointers
per `packages/net_proto/net_proto/protocols/ip6/ip6__header.py`:

| Sanity branch       | Pointer |
| ------------------- | :-----: |
| hop == 0            |    7    |
| src is multicast    |    8    |

The existing Code 1 (Unrecognized Next Header) emit on the
unsupported-proto path stays unchanged. Counters:
`ip6__sanity_error__respond_icmp6_param_problem` and
`ip6__sanity_error__icmp6_param_problem_suppressed`.

§2.4(e) — "ICMPv6 error MUST NOT be originated as a result of
receiving" — the five rules (error message, redirect, multicast
destination with PTB / Param-Problem-code-2 exceptions, and the
implicit "single host" source rule) are wired through the shared
`packages/pytcp/pytcp/protocols/icmp/icmp__error_emitter.py` module via
`IcmpErrorContext.is_pmtud_response` /
`IcmpErrorContext.is_param_problem_code_2`. The UDP closed-port
emitter consumes the v6 rate limiter at
`pytcp.stack.icmp6_error_rate_limiter`, mirroring the v4 wire-up.

§2.4(f) — rate-limit requirement — met (post Phase α1.1) via the
shared `IcmpErrorRateLimiter`.

§4.2 — Echo Reply may be sent in response to multicast — the v6
echo handler delegates to
[`packages/pytcp/pytcp/protocols/icmp6/icmp6__echo_gate.py`](../../../../packages/pytcp/pytcp/protocols/icmp6/icmp6__echo_gate.py)
which currently permits unconditionally (no Smurf gate, by spec
design — multicast Echo replies are explicitly permitted).

The full per-section RFC 4443 walkthrough will be authored using
the
[`rfc_adherence_audit`](../../../../.claude/skills/rfc_adherence_audit/SKILL.md)
skill when Phase β closes the Time Exceeded / Parameter Problem
gap (which touches §3.3 and §3.4).

---

## Parser validation — integrity and sanity surface

`Icmp6Parser._validate_integrity`
(`packages/net_proto/net_proto/protocols/icmp6/icmp6__parser.py`)
enforces:

- **`ICMP6__HEADER__LEN (4) <= ip6.dlen <= len(frame)`** — RFC 4443 §2.1
  common 4-byte header (Type / Code / Checksum); upper bound is
  RFC 8200 §3 IP-layer state.
- **Per-message length** — each message subclass'
  `validate_integrity` enforces its RFC-defined fixed header length
  (RFC 4443 §3-§4 for base messages, RFC 4861 §4 for ND,
  RFC 3810 §5 for MLDv2).
- **Checksum** — RFC 4443 §2.3 — one's-complement checksum over the
  full ICMPv6 message prepended with the RFC 8200 §8.1 IPv6
  pseudo-header (the parser carries the pseudo-header sum on
  `Ip6Parser.pshdr_sum`).

`Icmp6Parser._validate_sanity` delegates to each message's
`validate_sanity(ip6__hop, ip6__src, ip6__dst)`:

- **`code.is_unknown` per known message type** — Destination
  Unreachable (codes 0..6 RFC 4443 §3.1 + code 7 RFC 7610 §5);
  Packet Too Big (code 0 RFC 4443 §3.2); Time Exceeded (codes 0..1
  RFC 4443 §3.3); Parameter Problem (codes 0..2 RFC 4443 §3.4);
  Echo Request / Reply (code 0 RFC 4443 §4.1 / §4.2). Out-of-range
  values raise `Icmp6SanityError`.
- **ND messages** — RFC 4861 §6.1 / §7.1 / §8.1: Hop Limit MUST be
  255; source MUST be unicast or unspecified; target / destination
  validity per type.
- **MLDv2 Report** — RFC 3810 §5.2: Hop Limit MUST be 1; source MUST
  be link-local.
- **MLDv2 Query** — RFC 3810 §5.1.13 / §5.1.14 invariants are
  enforced at the RX listener layer (allowing operator-tunable
  tolerance via sysctl); the message-class sanity is a stub.

### Note on Unknown-type handling

Unlike ICMPv4 (where RFC 1122 §3.2.2 says "MUST silently discard"
all unknown types), RFC 4443 §2.4(b/c) splits the rule:

- (b) Unknown **informational** messages (type ≥ 128) MUST be
  silently discarded.
- (c) Unknown **error** messages (type 1..127) MUST be passed to
  the upper layer.

PyTCP's `Icmp6MessageUnknown.validate_sanity` is therefore
deliberately a no-op — the packet handler's `case _:` dispatch
arm handles unknown types via `__phrx_icmp6__unknown`, preserving
the option to deliver them to upper-layer consumers when
applicable. This is the **opposite** of the ICMPv4 design.

### Known pre-existing gap

`Icmp6ParameterProblemCode` does not yet carry **code 3** from
RFC 7112 §3 (`UNRECOGNIZED_FIRST_FRAGMENT_HAS_INCOMPLETE_HEADER_CHAIN`).
A real RFC 7112-compliant peer sending PP code=3 will be rejected
at parser sanity. Adding the enum member is a follow-up.
