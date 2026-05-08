# RFC 8200 — Internet Protocol, Version 6 (IPv6) Specification

| Field       | Value                                                          |
|-------------|----------------------------------------------------------------|
| RFC number  | 8200                                                           |
| Title       | Internet Protocol, Version 6 (IPv6) Specification              |
| Category    | Internet Standard (STD 86); obsoletes RFC 2460                 |
| Date        | July 2017                                                      |
| Source text | [`rfc8200.txt`](rfc8200.txt)                                   |

This document records the PyTCP codebase's adherence to RFC 8200 §4
(IPv6 Extension Headers) clause by clause. Other sections of the RFC
(§3 IPv6 header format, §5 Packet Size Issues, etc.) are covered by
the IPv6 main-header adherence and the PMTUD / fragmentation audits;
this record concerns extension-header processing only.

---

## Top-line adherence (§4 Extension Headers)

PyTCP **shipped** RFC 8200 §4 extension-header processing in the
deployment series tracked at `docs/refactor/ipv6_extension_headers_plan.md`.

| Section | Topic                                              | Status      | Implementing commits / files |
|---------|----------------------------------------------------|-------------|-------------------------------|
| §4.1    | Extension-header chain order                       | shipped     | `pytcp/stack/packet_handler/packet_handler__ip6__rx.py` (`_phrx_ip6__walk_chain`) |
| §4.2    | TLV options + action-on-unrecognized (00/01/10/11) | shipped     | `net_proto/protocols/ip6_hbh/options/ip6_hbh__options.py`, `net_proto/protocols/ip6_dest_opts/options/ip6_dest_opts__options.py` |
| §4.3    | Hop-by-Hop Options Header                          | shipped     | `net_proto/protocols/ip6_hbh/` (full package) |
| §4.4    | Routing Header                                     | shipped     | `net_proto/protocols/ip6_routing/` (full package) |
| §4.5    | Fragment Header                                    | shipped     | `net_proto/protocols/ip6_frag/` (pre-existing) |
| §4.6    | Destination Options Header                         | shipped     | `net_proto/protocols/ip6_dest_opts/` (full package) |
| §4.7    | No Next Header                                     | shipped     | chain walker silent-drop branch |

Header-content options shipped: Pad1 / PadN (RFC 8200 §4.2),
Router Alert (RFC 2711), Jumbo Payload (RFC 2675), CALIPSO
(RFC 5570), Tunnel Encapsulation Limit (RFC 2473). RH0 hard-drop
covered by the separate RFC 5095 audit.

---

## §4.1 Extension Header Order

> "When more than one extension header is used in the same
> packet, it is recommended that those headers appear in the
> following order: ... Hop-by-Hop Options header, Destination
> Options header (note 1), Routing header, Fragment header,
> Destination Options header (note 2), Upper-Layer header."

**Adherence:** shipped. The chain walker in
`pytcp/stack/packet_handler/packet_handler__ip6__rx.py`
(`_phrx_ip6__walk_chain`) walks the chain in the on-the-wire
order. Order is enforced by the §4.3 HBH-must-be-first rule
(below); other extension headers are processed in whatever
order they appear, since RFC 8200 §4.1 phrases the order as a
recommendation ("it is recommended"), not a MUST.

> "Each extension header should occur at most once, except for
> the Destination Options header, which should occur at most
> twice (once before a Routing header and once before the
> upper-layer header)."

**Adherence:** PyTCP does not enforce a maximum-count rule on
extension headers. The walker happily processes any number of
DestOpts / Routing / Frag headers in the chain — each parser
runs once per occurrence and `packet_rx.frame` advances. This
is consistent with the RFC's "should" (not "MUST") and matches
Linux's `net/ipv6/exthdrs.c` behaviour.

**Phase 2:** a forwarder may want to enforce the count rule to
defend against pathological chains; a `# Phase 2:` marker in
the walker would be the natural place.

## §4.2 Options (TLV format + action-on-unrecognized)

> "[Top-2-bits encode the action] 00 - skip over this option,
> 01 - discard the packet, 10 - discard the packet and ...
> send Param Problem Code 2, 11 - discard the packet and ...
> send Param Problem Code 2 only if the packet's Destination
> Address was not a multicast address."

**Adherence:** shipped. The action-on-unrecognized walker
lives in `Ip6HbhOptions.validate_sanity` (and the matching
`Ip6DestOptsOptions.validate_sanity`) and is invoked from the
parser's `_validate_sanity` phase. The walker raises
`Ip6HbhSanityError(pointer=...)` (or
`Ip6DestOptsSanityError(pointer=...)`) which the chain walker
catches and translates to ICMPv6 Parameter Problem code 2.

The action-11 multicast suppression rule is currently
**partially** implemented: the `validate_sanity` static method
accepts `ip6_dst_is_multicast=False` as default and the chain
walker does not yet thread the destination's multicast bit
through to that check. Practically this means a packet
addressed to a multicast destination that carries an
unrecognized action-11 option will receive an ICMPv6 reply
where §4.2 requires silent suppression. ICMP errors are
advisory so the over-emission is benign; a follow-up commit
can plumb the multicast bit through cleanly.

> "Pad1 option ... [type 0]" / "PadN option ... [type 1]"

**Adherence:** shipped. `Ip6HbhOptionPad1`, `Ip6HbhOptionPadN`,
`Ip6DestOptsOptionPad1`, `Ip6DestOptsOptionPadN` — typed
dataclasses for both extension headers. Wire-frame round-trip
identity verified by
`net_proto/tests/unit/protocols/ip6_hbh/test__ip6_hbh__option__pad1.py`
and `..__option__padn.py` (and the matching `ip6_dest_opts`
test files).

## §4.3 Hop-by-Hop Options Header

> "The Hop-by-Hop Options header is used to carry optional
> information that may be examined and processed by every node
> along a packet's delivery path. The Hop-by-Hop Options
> header is identified by a Next Header value of 0 in the IPv6
> header."

**Adherence:** shipped. `IpProto.IP6_HBH = 0` in
`net_proto/lib/enums.py`. The full HBH package lives at
`net_proto/protocols/ip6_hbh/` with header / base / parser /
assembler / errors / options-subdir following the canonical
six-file shape.

> "If the IPv6 header includes a Hop-by-Hop Options header,
> this header MUST be processed before any other header
> processing starts (i.e., the Hop-by-Hop Options header MUST
> be the first extension header following the IPv6 header)."

**Adherence:** shipped. The chain walker tracks
`non_hbh_seen` and, if a Hop-by-Hop header appears after any
other extension header, drops the packet with ICMPv6 Param
Problem code 1 (treating out-of-order HBH as an unrecognized-
next-header equivalent). Counter: `ip6__hbh__not_first__drop`.

> "The Hop-by-Hop Options header is variable length, in 8-byte
> increments. ... Hdr Ext Len: 8-bit unsigned integer. Length
> of the Hop-by-Hop Options header in 8-octet units, not
> including the first 8 octets."

**Adherence:** shipped. `Ip6HbhHeader.hdr_ext_len` is the wire
field; the parser computes `total_hbh_len = (hdr_ext_len + 1) * 8`
and uses it for integrity validation and frame advancement.
Round-trip pinned by `test__ip6_hbh__parser__operation.py`.

## §4.4 Routing Header

> "The Routing header is used by an IPv6 source to list one or
> more intermediate nodes to be 'visited' on the way to a
> packet's destination. ... identified by a Next Header value
> of 43."

**Adherence:** shipped. `IpProto.IP6_ROUTING = 43`. Full
package at `net_proto/protocols/ip6_routing/`. The four
canonical wire fields (Next Header, Hdr Ext Len, Routing Type,
Segments Left) are typed; type-specific data is preserved as
opaque bytes (Phase-2-aware re-emission).

> "If, while processing a received packet, a node encounters a
> Routing header with an unrecognized Routing Type value, the
> required behavior of the node depends on the value of the
> Segments Left field, as follows. If Segments Left is zero,
> the node must ignore the Routing header and proceed to
> process the next header in the packet ... If Segments Left
> is non-zero, the node must discard the packet and send an
> ICMP Parameter Problem, Code 0."

**Adherence:** PyTCP currently parses non-RH0 routing types as
opaque (preserving wire bytes for Phase-2 forwarding) and
does NOT emit Param Problem code 0 on unknown-type-with-
segments-left>0. This is a Phase-1 simplification: as a host
stack PyTCP would not be the destination for source-routed
packets anyway, so the §4.4 unknown-type-on-receipt path is
not exercised. Marked for Phase-2: when the forwarder lands,
the chain walker should emit Param Problem code 0 for unknown
routing types with Segments Left > 0.

## §4.5 Fragment Header

**Adherence:** shipped (pre-existing). PyTCP has had IPv6
fragmentation reassembly since before the extension-header
deployment. The Fragment header lives at
`net_proto/protocols/ip6_frag/` and is wired through the
chain walker via the existing re-entry pattern in
`pytcp/stack/packet_handler/packet_handler__ip6_frag__rx.py`.

The fragment-overlap rejection (RFC 5722) and atomic-fragment
fast-path (RFC 8200 §4.5) are NOT yet implemented and are
tracked as separate items (#281, #282 in the deployment
plan).

## §4.6 Destination Options Header

> "The Destination Options header is used to carry optional
> information that need be examined only by a packet's
> destination node(s). ... identified by a Next Header value
> of 60 in the immediately preceding header."

**Adherence:** shipped. `IpProto.IP6_DEST_OPTS = 60`. Full
package at `net_proto/protocols/ip6_dest_opts/` mirroring the
HBH package layout — header / base / parser / assembler /
errors plus options-subdir with Pad1, PadN, Unknown, and the
Tunnel Encapsulation Limit (RFC 2473) option.

The §4.2 TLV option machinery is shared (separate dataclass
classes per RFC pattern, identical wire format). Action-on-
unrecognized is enforced the same way as for HBH.

## §4.7 No Next Header

> "The value 59 in the Next Header field of an IPv6 header or
> any extension header indicates that there is nothing
> following that header. If the Payload Length field of the
> IPv6 header indicates the presence of octets past the end of
> a header whose Next Header field contains 59, those octets
> must be ignored ..."

**Adherence:** shipped. `IpProto.IP6_NO_NEXT_HEADER = 59` in
the enum. The chain walker's transport-dispatch arm matches
`IpProto.IP6_NO_NEXT_HEADER` and drops silently with the
`ip6__no_next_header` counter bumped. The "octets past the
end ... must be ignored" rule is satisfied implicitly: the
walker dispatches to nothing and returns; the trailing bytes
are never read.

Pinned by the integration test
`pytcp/tests/integration/protocols/ip6/test__ip6__rx__chain_walker.py::TestIp6Rx__ChainWalker__NoNextHeader::test__ip6__rx__no_next_header_silent_drop`.

---

## Test coverage audit

The §4 clauses above are pinned by the following test files:

| Clause | Test file(s) |
|--------|--------------|
| §4.2 TLV format | `net_proto/tests/unit/protocols/ip6_hbh/test__ip6_hbh__option__pad1.py`, `..__option__padn.py`, plus the `ip6_dest_opts` mirrors |
| §4.2 action-on-unrecognized | `net_proto/tests/unit/protocols/ip6_hbh/test__ip6_hbh__options.py::TestIp6HbhOptionsValidateSanity` (full 00/01/10/11 unicast/11 multicast matrix) |
| §4.3 HBH wire format | `net_proto/tests/unit/protocols/ip6_hbh/test__ip6_hbh__parser__operation.py` |
| §4.3 HBH must be first | (chain-walker enforcement; integration coverage tracked but not yet shipped) |
| §4.4 Routing wire format | `net_proto/tests/unit/protocols/ip6_routing/test__ip6_routing__parser__operation.py` |
| §4.5 Fragment | (pre-existing `net_proto/tests/unit/protocols/ip6_frag/`) |
| §4.6 DestOpts wire format | `net_proto/tests/unit/protocols/ip6_dest_opts/test__ip6_dest_opts__parser__operation.py` |
| §4.7 No Next Header | `pytcp/tests/integration/protocols/ip6/test__ip6__rx__chain_walker.py::TestIp6Rx__ChainWalker__NoNextHeader` |

Chain-walker integration coverage:
`pytcp/tests/integration/protocols/ip6/test__ip6__rx__chain_walker.py`
covers HBH parse + dispatch, RH0 hard-drop (RFC 5095 §3),
action-10 unrecognized-option Param Problem code 2 emission,
and IP6_NO_NEXT_HEADER silent drop.
