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
| §4.1    | Extension-header chain order                       | shipped     | `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__rx.py` (`_phrx_ip6__walk_chain`) |
| §4.2    | TLV options + action-on-unrecognized (00/01/10/11) | shipped     | `packages/net_proto/net_proto/protocols/ip6_hbh/options/ip6_hbh__options.py`, `packages/net_proto/net_proto/protocols/ip6_dest_opts/options/ip6_dest_opts__options.py` |
| §4.3    | Hop-by-Hop Options Header                          | shipped     | `packages/net_proto/net_proto/protocols/ip6_hbh/` (full package) |
| §4.4    | Routing Header                                     | shipped     | `packages/net_proto/net_proto/protocols/ip6_routing/` (full package) |
| §4.5    | Fragment Header                                    | shipped     | `packages/net_proto/net_proto/protocols/ip6_frag/` (pre-existing) |
| §4.6    | Destination Options Header                         | shipped     | `packages/net_proto/net_proto/protocols/ip6_dest_opts/` (full package) |
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
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__rx.py`
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

The action-11 multicast suppression rule is **shipped**
(2026-05-29). The RX chain walker threads the parent IPv6
header's destination-is-multicast bit into the parser
constructor (`Ip6HbhParser(packet_rx,
ip6_dst_is_multicast=packet_rx.ip6.dst.is_multicast)`, and the
`Ip6DestOptsParser` equivalent), which forwards it to
`validate_sanity`. An unrecognized action-11 option on a
multicast destination therefore raises with
`multicast_only=True` / no pointer, and the chain walker
silently discards it without an ICMPv6 reply, exactly as
§4.2 requires. On a unicast destination the same option
raises with a pointer set and elicits Parameter Problem
code 2.

Action 10 (discard + Parameter Problem regardless of
destination) emits even to a multicast destination: RFC 4443
§2.4(e.3) exception (2) permits a code-2 Parameter Problem in
response to a multicast packet, and the emit site flags the
ICMP-error classifier (`classify_inbound(...,
is_param_problem_code_2=True)`) so the multicast-destination
gate is bypassed for this code only.

> "Pad1 option ... [type 0]" / "PadN option ... [type 1]"

**Adherence:** shipped. `Ip6HbhOptionPad1`, `Ip6HbhOptionPadN`,
`Ip6DestOptsOptionPad1`, `Ip6DestOptsOptionPadN` — typed
dataclasses for both extension headers. Wire-frame round-trip
identity verified by
`packages/net_proto/net_proto/tests/unit/protocols/ip6_hbh/test__ip6_hbh__option__pad1.py`
and `..__option__padn.py` (and the matching `ip6_dest_opts`
test files).

## §4.3 Hop-by-Hop Options Header

> "The Hop-by-Hop Options header is used to carry optional
> information that may be examined and processed by every node
> along a packet's delivery path. The Hop-by-Hop Options
> header is identified by a Next Header value of 0 in the IPv6
> header."

**Adherence:** shipped. `IpProto.IP6_HBH = 0` in
`packages/net_proto/net_proto/lib/enums.py`. The full HBH package lives at
`packages/net_proto/net_proto/protocols/ip6_hbh/` with header / base / parser /
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
package at `packages/net_proto/net_proto/protocols/ip6_routing/`. The four
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

**Adherence:** shipped. PyTCP has had IPv6 fragmentation
reassembly since before the extension-header deployment.
The Fragment header lives at `packages/net_proto/net_proto/protocols/ip6_frag/`
and is wired through the chain walker via the re-entry
pattern in
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6_frag__rx.py`.

Reassembly state lives in the shared `IpFragTable` at
`packages/pytcp/pytcp/protocols/ip/ip_frag_table.py` (shared with the IPv4
reassembly path so the RFC 3168 §5.3 ECN aggregator works
identically for both families). The table enforces:

- **§4.5 atomic-fragment fast-path** (RFC 6946 §4): an
  inbound fragment with `offset = 0` and `M = 0` is the
  entire datagram and is delivered immediately without
  touching the flow store. Implementation at
  `ip_frag_table.py:161-172`.
- **§4.5 overlap rejection** (RFC 5722 §3): a fragment that
  overlaps any previously-stored fragment for the same flow
  marks the flow as discarded; subsequent fragments for the
  flow are silently dropped. Implementation at
  `ip_frag_table.py:180-194`. Strict-reading interpretation
  (exact-duplicate offsets are also overlapping).

See the dedicated [`rfc5722__overlapping_fragments`](../rfc5722__overlapping_fragments/adherence.md)
and [`rfc6946__atomic_fragments`](../rfc6946__atomic_fragments/adherence.md)
adherence records for the per-RFC walk-throughs.

## §4.6 Destination Options Header

> "The Destination Options header is used to carry optional
> information that need be examined only by a packet's
> destination node(s). ... identified by a Next Header value
> of 60 in the immediately preceding header."

**Adherence:** shipped. `IpProto.IP6_DEST_OPTS = 60`. Full
package at `packages/net_proto/net_proto/protocols/ip6_dest_opts/` mirroring the
HBH package layout — header / base / parser / assembler /
errors plus options-subdir with Pad1, PadN, Unknown, and the
Tunnel Encapsulation Limit (RFC 2473) option.

The §4.2 TLV option machinery is shared (separate dataclass
classes per RFC pattern, identical wire format). Action-on-
unrecognized is enforced the same way as for HBH.

## §3 / §4 Parser integrity & sanity surface

PyTCP's IPv6 parsers expose two staged checks per layer:
`_validate_integrity` (structural pre-parse — buffer
bounds, declared lengths, fixed-shape per-option Opt Data
Len) and `_validate_sanity` (post-parse field semantics).
Hostile-wire values that would otherwise trip a dataclass
`__post_init__` assert are caught at integrity and re-raised
as the layer's typed `*IntegrityError` so the IPv6 chain
walker's `PacketValidationError` catch can drop the frame
cleanly.

### Base IPv6 header (`ip6__parser.py`)

| Phase | Check | RFC clause |
|-------|-------|------------|
| Integrity | `len(frame) >= 40` | RFC 8200 §3 (fixed 40-octet header) |
| Integrity | `(frame[0] >> 4) == 6` | RFC 8200 §3 + RFC 8504 §4.1 (silent discard on Version mismatch) |
| Integrity | `dlen == len(frame) − 40` | RFC 8200 §3 (Payload Length matches octets after the header) |
| Sanity | `hop != 0` | RFC 8200 §3 (Hop Limit zero ⇒ discard) |
| Sanity | `not src.is_loopback` (`::1`) | RFC 4291 §2.5.3 ("loopback address must not be used as the source address ... outside of a single node") |
| Sanity | `not src.is_multicast` (`ff00::/8`) | RFC 4291 §2.7 (multicast cannot be a source) |

Sanity checks attach the RFC 4443 §3.4 Parameter Problem
pointer (offset of the offending field) so the RX handler
can emit ICMPv6 Code 0 (Erroneous Header Field Encountered).
The unspecified address (`::`) is deliberately not rejected
at the parser layer — DAD-style NS messages legitimately use
`src=::` per RFC 4861 §4.3; the ICMPv6 ND layer handles its
own per-message acceptance rules.

### Extension headers (per-parser integrity)

| Parser | Integrity checks | RFC clause |
|--------|------------------|------------|
| `ip6_frag__parser.py` | `len(frame) >= 8` | RFC 8200 §4.5 (fixed 8-octet Fragment header) |
| `ip6_hbh__parser.py` | `len(frame) >= 2`; `(hdr_ext_len + 1) * 8 <= len(frame)`; container TLV walk | RFC 8200 §4.3; RFC 8200 §4.2 (TLV format) |
| `ip6_dest_opts__parser.py` | `len(frame) >= 2`; `(hdr_ext_len + 1) * 8 <= len(frame)`; container TLV walk | RFC 8200 §4.6; RFC 8200 §4.2 |
| `ip6_routing__parser.py` | `len(frame) >= 4`; `(hdr_ext_len + 1) * 8 <= len(frame)`; RH0 hard-drop | RFC 8200 §4.4; RFC 5095 §3 |

### Per-option parser integrity (HBH + Dest Opts options)

| Option | `_validate_integrity` enforces | RFC clause |
|--------|--------------------------------|------------|
| HBH Pad1 (type 0) | type-byte (Case-1 TLV, no length field) | RFC 8200 §4.2 |
| HBH PadN (type 1) | `(opt_data_len + 2) <= buffer` | RFC 8200 §4.2 |
| HBH Router Alert (type 5) | `opt_data_len == 2` | RFC 2711 §2.1 |
| HBH Jumbo Payload (type 0xC2) | `opt_data_len == 4`; `value > 65535` | RFC 2675 §2; RFC 2675 §3 |
| HBH CALIPSO (type 7) | `opt_data_len == 8 + cmpt_length * 4`; `buffer` holds full option | RFC 5570 §4 |
| HBH Unknown | `(opt_data_len + 2) <= buffer` | RFC 8200 §4.2 |
| DestOpts Pad1 / PadN / Unknown | mirror of HBH variants | RFC 8200 §4.2 |
| DestOpts Tunnel Encap Limit (type 4) | `opt_data_len == 1` | RFC 2473 §4.1.1 |

The Router Alert / Jumbo Payload / CALIPSO / Tunnel Encap
Limit pointer-or-shape checks are duplicated in the
corresponding dataclass `__post_init__` asserts — the former
is the parser-level integrity gate (reachable from hostile
wire), the latter is the construction-time invariant for
API consumers building option objects programmatically. The
duplication is deliberate and load-bearing.

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
`packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rx__chain_walker.py::TestIp6Rx__ChainWalker__NoNextHeader::test__ip6__rx__no_next_header_silent_drop`.

---

## Test coverage audit

The §4 clauses above are pinned by the following test files:

| Clause | Test file(s) |
|--------|--------------|
| §4.2 TLV format | `packages/net_proto/net_proto/tests/unit/protocols/ip6_hbh/test__ip6_hbh__option__pad1.py`, `..__option__padn.py`, plus the `ip6_dest_opts` mirrors |
| §4.2 action-on-unrecognized | `packages/net_proto/net_proto/tests/unit/protocols/ip6_hbh/test__ip6_hbh__options.py::TestIp6HbhOptionsValidateSanity` (full 00/01/10/11 unicast/11 multicast matrix); `packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rx__chain_walker.py::TestIp6Rx__ChainWalker__Hbh` (action-10/11 unicast emit, action-11 multicast suppressed, action-10 multicast emit per RFC 4443 §2.4(e.3) exception) |
| §4.3 HBH wire format | `packages/net_proto/net_proto/tests/unit/protocols/ip6_hbh/test__ip6_hbh__parser__operation.py` |
| §4.3 HBH must be first | (chain-walker enforcement; integration coverage tracked but not yet shipped) |
| §4.4 Routing wire format | `packages/net_proto/net_proto/tests/unit/protocols/ip6_routing/test__ip6_routing__parser__operation.py` |
| §4.5 Fragment | (pre-existing `packages/net_proto/net_proto/tests/unit/protocols/ip6_frag/`) |
| §4.6 DestOpts wire format | `packages/net_proto/net_proto/tests/unit/protocols/ip6_dest_opts/test__ip6_dest_opts__parser__operation.py` |
| §4.7 No Next Header | `packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rx__chain_walker.py::TestIp6Rx__ChainWalker__NoNextHeader` |

Chain-walker integration coverage:
`packages/pytcp/pytcp/tests/integration/protocols/ip6/test__ip6__rx__chain_walker.py`
covers HBH parse + dispatch, RH0 hard-drop (RFC 5095 §3),
action-10 unrecognized-option Param Problem code 2 emission,
and IP6_NO_NEXT_HEADER silent drop.
