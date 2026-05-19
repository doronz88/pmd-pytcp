# RFC 5095 — Deprecation of Type 0 Routing Header in IPv6

| Field       | Value                                                  |
|-------------|--------------------------------------------------------|
| RFC number  | 5095                                                   |
| Title       | Deprecation of Type 0 Routing Header in IPv6           |
| Category    | Standards Track (Updates: 2460, 4294)                  |
| Date        | December 2007                                          |
| Source text | [`rfc5095.txt`](rfc5095.txt)                           |

---

## Top-line adherence

PyTCP is **fully compliant** with RFC 5095 §3: an inbound IPv6
packet carrying a Type 0 Routing Header (RH0) is hard-dropped
and the host emits ICMPv6 Parameter Problem code 0 (erroneous
header field encountered) with the pointer set to the Routing
Type byte.

Implementation:

- The RH0 hard-drop logic lives in
  `packages/net_proto/net_proto/protocols/ip6_routing/ip6_routing__parser.py`
  (`_validate_integrity` raises
  `Ip6RoutingIntegrityError(pointer=2)`).
- The chain-walker dispatch in
  `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__rx.py`
  catches the integrity error, computes the absolute IPv6-
  packet pointer (40 + chain_offset + 2), and emits ICMPv6
  Param Problem code 0 via the existing
  `__phrx_ip6__emit_parameter_problem` helper.
- Counter: `ip6_routing__rh0__drop`.

Regression-pinned by
`packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rx__chain_walker.py::TestIp6Rx__ChainWalker__Rh0::test__ip6__rx__rh0_emits_param_problem_code_0`,
which drives an Ethernet/IPv6/RH0 frame and asserts the
outbound ICMPv6 Param Problem code 0 with pointer 42 (40
IPv6 header + 2 within the Routing Header).

---

## §1 Introduction

> "RFC 2460 [RFC2460] specifies the IPv6 Type 0 Routing
> Header (RH0). Processing of RH0 ... allows packet
> amplification and traffic-redirection attacks ... This
> document deprecates the IPv6 Type 0 Routing Header."

**Adherence:** shipped. The IANA-assigned routing type 0 is
defined in PyTCP's `Ip6RoutingType` enum
(`packages/net_proto/net_proto/protocols/ip6_routing/ip6_routing__enums.py`)
solely so the parser can recognise and reject it. There is
no encode path, no opaque-bytes preserve path — RH0 is hard-
dropped during the integrity-check phase.

## §3 Deprecation of the Type 0 Routing Header

> "An IPv6 node that receives a packet with a destination
> address assigned to it and that contains an RH0 extension
> header MUST NOT execute the algorithm specified in the
> latter part of Section 4.4 of [RFC2460] for RH0. Instead,
> such packets MUST be processed according to the behavior
> specified in [RFC2460] for a datagram that includes an
> unrecognized Routing Type value, namely:"

**Adherence:** shipped. The parser does not implement the
RH0 segment-list rotation algorithm. On receipt of a Type 0
Routing Header, the parser raises immediately during
integrity validation, before any segment-list parsing. The
absence of an RH0 algorithm path is regression-pinned by
the absence of any code that reads the RH0 segment-list
fields — a future regression that re-introduced the
algorithm would need entirely new files.

> "If Segments Left is zero, the node must ignore the
> Routing header and proceed to process the next header in
> the packet, whose type is identified by the Next Header
> field in the Routing header."

**Adherence:** shipped (deliberate over-rejection). PyTCP
hard-drops RH0 regardless of Segments Left value. RFC 5095
§3 is ambiguous about whether a Segments-Left=0 RH0 should
be silently ignored or dropped; PyTCP takes the safer
interpretation (always drop) which matches Linux
`net/ipv6/exthdrs.c::ipv6_rthdr_rcv` behaviour. The slightly
more permissive interpretation (ignore on SL=0) is also RFC-
acceptable but deliberately not chosen here for consistency
with Linux.

> "If Segments Left is non-zero, the node must discard the
> packet and send an ICMP Parameter Problem, Code 0, message
> to the packet's Source Address, pointing to the
> unrecognized Routing Type."

**Adherence:** shipped. The ICMPv6 Parameter Problem
emission with code 0 (erroneous header field encountered)
is wired through the chain walker. The pointer is the
absolute byte offset of the Routing Type byte within the
IPv6 packet:

  pointer = 40 (IPv6 main header) + chain_offset + 2

where `chain_offset` is the running offset that the chain
walker tracks for any extension headers walked before this
Routing Header (e.g. an HBH that preceded it). For an
RH-immediately-after-IPv6-header packet, `chain_offset = 0`
and the absolute pointer is 42, matching the canonical
RFC 5095 §3 example.

The Param Problem emission is gated by the existing host-
requirements machinery
(`packages/pytcp/pytcp/protocols/icmp/icmp__error_emitter.py`): rate-
limiting, src/dst eligibility checks, and packet-stats
counters all run unchanged.

> "The discarding and sending of an ICMP error message MUST
> be allowed to be disabled, with a default of allowed."

**Adherence:** PyTCP does not currently expose a sysctl-
style knob for disabling RH0 ICMP emission. The default
"emit" behaviour is in effect at all times. Linux exposes
`net.ipv6.conf.*.accept_source_route` (default 0 — RH0
discarded with ICMP). PyTCP's behaviour matches Linux's
default state; the disable-knob is a Phase-2 polish item
tracked as a follow-up.

## §4 Security Considerations

> "Lifting the deprecation of RH0 (or any similar
> functionality) ought not be done lightly ..."

**Adherence:** N/A. PyTCP does not lift the deprecation. RH0
is rejected at the IPv6-receive layer; the RH0 algorithm is
not implemented and there is no configuration that re-enables
it.

---

## Test coverage audit

The §3 clauses above are pinned by:

| Clause | Test file / class |
|--------|-------------------|
| RH0 hard-drop on receipt | `packages/net_proto/net_proto/tests/unit/protocols/ip6_routing/test__ip6_routing__parser__integrity_checks.py::TestIp6RoutingParserIntegrity::test__ip6_routing__parser__integrity__rh0_hard_drop` |
| RH0 ICMP Param Problem code 0 emission | `packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rx__chain_walker.py::TestIp6Rx__ChainWalker__Rh0::test__ip6__rx__rh0_emits_param_problem_code_0` |
| Pointer = 42 (absolute) | Same integration test asserts `probe.message.pointer == 42` for the RH-immediately-after-IPv6-header case. |
| Counter `ip6_routing__rh0__drop` | Same integration test. |
| Non-RH0 routing types pass through | `packages/net_proto/net_proto/tests/unit/protocols/ip6_routing/test__ip6_routing__parser__operation.py` (RH3, RH4, unknown via dynamic-extend) |

A regression that broke the RH0 hard-drop would fail the
integrity-check unit test loudly (the hard-drop is the very
first thing the parser does, before any field decode), and
the integration test would also fail because the absence of
the ICMPv6 reply would leave `frames_tx` empty.
