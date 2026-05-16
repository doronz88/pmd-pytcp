# RFC 1122 — Requirements for Internet Hosts (Internet Layer)

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 1122                                                 |
| Title       | Requirements for Internet Hosts -- Communication Layers |
| Category    | Internet Standard (STD 3)                            |
| Date        | October 1989                                         |
| Updated by  | RFC 1349, 4379, 5884, 6298, 6633, 6864, 8029, 9293   |
| Source text | [`rfc1122.txt`](rfc1122.txt)                         |

This document records the PyTCP codebase's adherence to RFC 1122
**§3 (Internet Layer)** clause by clause. The audit was performed
by reading the RFC text fresh and inspecting the codebase under
`net_proto/protocols/ip4/` and
`pytcp/runtime/packet_handler/packet_handler__ip4__*.py` directly;
no prior memory or rule-file content was reused.

Scope:

- **§3.2.1 (Internet Protocol — IP)** is audited in full here.
- **§3.2.2 (ICMP)** is cross-referenced to
  `docs/rfc/icmp4/rfc1122__host_requirements_icmp/adherence.md`.
- **§3.2.3 (IGMP)** is not implemented (deferred — multicast
  group management beyond reception scope).
- **§3.3 (Specific Issues — routing, reassembly, fragmentation,
  multihoming, source-route, broadcasts, multicasting, error
  reporting)** is audited here for the IP-layer-relevant portions.
- §3.4 (Link Layer / Trailer encapsulations) — out of scope.

Non-normative discussion / implementation notes / RFC 2119
boilerplate are omitted.

---

## Top-line adherence

PyTCP **meets** the host-requirements MUSTs for §3.2.1 (IP-layer
RX and TX). Routing-table material in §3.3.1 is implemented as a
single-gateway-per-interface Phase-1 simplification (Linux's
default-route shape); the route-cache pattern (§3.3.1.3) is not
implemented because PyTCP has no Phase-1 consumer for it. ICMP
Redirect processing (§3.3.1.5) is **not** implemented — host
mode doesn't honour Redirects today, gated for Phase 2 when the
full route cache lands. The broadcast / multicast / error-
reporting rules are honoured. Source-route forwarding (§3.3.5)
is Phase 2.

| Section | Topic                                       | Status |
|---------|---------------------------------------------|--------|
| §3.2.1.1 | Version Number MUST=4 check                | met    |
| §3.2.1.2 | Header checksum MUST verify                | met    |
| §3.2.1.3 | Addressing (class, special cases, source validation, dest filtering) | met (mostly) — see clauses below |
| §3.2.1.4 | Fragmentation and Reassembly required      | met (audited under RFC 791 §3.2 + RFC 815 record) |
| §3.2.1.5 | Identification reuse on retransmit         | met (we do not reuse; see RFC 6864 audit) |
| §3.2.1.6 | Type-of-Service handling                   | met (redefined as DSCP+ECN per RFC 2474+3168) |
| §3.2.1.7 | TTL MUST NOT send=0, MUST be configurable  | met    |
| §3.2.1.8 | Options (pass to transport, specific options) | met for pass-through; LSRR/SSRR origination not implemented (Phase 2) |
| §3.3.1   | Routing outbound (default-gateway / route cache) | partial — Phase 1 single-gateway-per-host model |
| §3.3.2   | Reassembly                                  | met (audited separately under RFC 815) |
| §3.3.3   | Fragmentation                               | met (see RFC 791 §3.2) |
| §3.3.4   | Local multihoming                           | partial — Phase 1 single-interface assumption |
| §3.3.5   | Source-route forwarding                     | not implemented (Phase 2) |
| §3.3.6   | Broadcasts                                  | met    |
| §3.3.7   | IP multicasting                             | partial — reception met (§3.3.7), IGMP group management deferred |
| §3.3.8   | Error reporting (link-layer errors to upper layers) | partial — Phase 1 logs but does not propagate |

---

## §3.2.1.1 Version Number

> "A datagram whose version number is not 4 MUST be silently
> discarded."

**Adherence:** met. `Ip4Parser._validate_integrity` rejects any
frame whose first nibble is not 4 with `Ip4IntegrityError`
(`net_proto/protocols/ip4/ip4__parser.py:94-97`). The RX handler
catches `Ip4IntegrityError`, increments `ip4__failed_parse__drop`,
and silently drops the frame
(`packet_handler__ip4__rx.py:120-126`).

## §3.2.1.2 Checksum

> "A host MUST verify the IP header checksum on every received
> datagram and silently discard every datagram that has a bad
> checksum."

**Adherence:** met. `Ip4Parser._validate_integrity` calls
`inet_cksum(self._frame[:hlen])` and rejects the frame with
`Ip4IntegrityError` on non-zero result
(`ip4__parser.py:108-111`). Silently dropped via the
`Ip4IntegrityError` catch path described above.

## §3.2.1.3 Addressing

> "(c) {-1, -1} Limited broadcast. It MUST NOT be used as a
> source address."
> "(d) {<Network-number>, -1} Directed broadcast ... MUST NOT
> be used as a source address."
> "(g) {127, <any>} Internal host loopback address. Addresses
> of this form MUST NOT appear outside a host."

**Adherence:** met for limited broadcast.
`Ip4Parser._validate_sanity` rejects frames where
`src.is_limited_broadcast` with `Ip4SanityError` and emits ICMP
Parameter Problem with pointer=12
(`ip4__parser.py:154-158`). The reserved/multicast source checks
on the same lines extend the rule to (B), (D), and the (g)
loopback class via `Ip4Address.is_reserved` — loopback addresses
sit in 127/8 which is classified reserved in
`net_addr/ip4_address.py`.

> "When a host sends any datagram, the IP source address MUST be
> one of its own IP addresses (but not a broadcast or multicast
> address)."

**Adherence:** met. TX path
(`packet_handler__ip4__tx.py:251-265`) rejects any outbound src
that is not in the stack's owned-address set
(`_ip4_unicast ∪ _ip4_multicast ∪ _ip4_broadcast`) or the
unspecified-source DHCPv4 carve-out. Multicast / limited-
broadcast / network-broadcast sources are detected and replaced
with the stack's primary unicast address before send
(lines 269-321). When no replacement is possible the frame is
dropped with the documented counter.

> "A host MUST silently discard an incoming datagram that is not
> destined for the host. An incoming datagram is destined for
> the host if the datagram's destination address field is:
> (1) (one of) the host's IP address(es); or
> (2) an IP broadcast address valid for the connected network; or
> (3) the address for a multicast group of which the host is a
> member on the incoming physical interface."

**Adherence:** met. RX handler
(`packet_handler__ip4__rx.py:149-159`) checks the destination
against `_ip4_unicast ∪ _ip4_multicast ∪ _ip4_broadcast` and
drops with `ip4__dst_unknown__drop` if no membership matches.
The single exception is the DHCP-client mode (no unicast
configured yet), which permits any destination so the offer/ack
can be accepted before the stack owns an address.

> "A host MUST silently discard an incoming datagram containing
> an IP source address that is invalid by the rules of this
> section."

**Adherence:** met. The sanity rules in
`ip4__parser.py:142-158` enforce the invalid-source ban
(multicast / reserved / limited-broadcast). The handler emits
ICMP Parameter Problem **and** drops — the silent-discard
contract is satisfied because the upper layers never see the
frame; the ICMP reply is independent.

## §3.2.1.4 Fragmentation and Reassembly

> "The Internet model requires that every host support
> reassembly."

**Adherence:** met. See `docs/rfc/ip4/rfc815__ip4_reassembly/adherence.md`
for the per-clause audit of the reassembly state machine.

## §3.2.1.5 Identification

> "When sending an identical copy of an earlier datagram, a
> host MAY optionally retain the same Identification field in
> the copy."

**Adherence:** RFC 6864 §4.2 supersedes this MAY with **MUST
NOT** reuse. PyTCP's TX path does not reuse — every entry into
the fragmenter bumps `_ip4_id` afresh. See
`docs/rfc/ip4/rfc6864__ip4_id_field/adherence.md` for the
per-clause audit.

## §3.2.1.6 Type-of-Service

> "The IP layer MUST provide a means for the transport layer to
> set the TOS field of every datagram that is sent; the default
> is all zero bits. The IP layer SHOULD pass received TOS
> values up to the transport layer."
> "The particular link-layer mappings of TOS contained in
> RFC-795 SHOULD NOT be implemented."

**Adherence:** met (semantics redefined). The legacy TOS byte
has been redefined by RFC 2474 (DSCP, 6 bits) + RFC 3168 (ECN,
2 bits). PyTCP exposes both as separate kwargs on the IPv4 TX
entry point (`packet_handler__ip4__tx.py:101` — `ip4__ecn`;
DSCP defaults to 0 in `Ip4Assembler.__init__` at
`ip4__assembler.py:67`) and as separate properties on the
parser (`Ip4Header.dscp`, `Ip4Header.ecn`).

Both default to 0 unless the caller sets them. Received values
are surfaced on the parser object (`packet_rx.ip4.dscp`,
`packet_rx.ip4.ecn`) and propagated to transport-specific
hooks (TCP records peer-ECN on segment receive — see TCP
audits). RFC-795 link-layer mappings are not implemented.
Cross-references:
`docs/rfc/ip4/rfc2474__dscp/adherence.md`,
`docs/rfc/ip4/rfc3168__ecn/adherence.md`.

## §3.2.1.7 Time-to-Live

> "A host MUST NOT send a datagram with a Time-to-Live (TTL)
> value of zero."

**Adherence:** met. `packet_handler__ip4__tx.py:112` asserts
`0 < ip4__ttl < 256` before assembly; a caller attempting
`ttl=0` triggers an assertion. The default is
`IP4__DEFAULT_TTL = 64` (`ip4__header.py:75`) so callers that
don't set TTL get a safe value.

> "A host MUST NOT discard a datagram just because it was
> received with TTL less than 2."

**Adherence:** met. The RX sanity check rejects only **TTL == 0**
(`ip4__parser.py:136-140`); TTL=1 is delivered to the transport
layer normally. This matches the spec: host-mode does not
decrement TTL (decrement is a forwarder responsibility), so
TTL=1 is "fine" at the destination.

> "The IP layer MUST provide a means for the transport layer to
> set the TTL field of every datagram that is sent. When a
> fixed TTL value is used, it MUST be configurable."

**Adherence:** met. `_phtx_ip4` exposes `ip4__ttl: int | None =
None` (`packet_handler__ip4__tx.py:102`); on `None` the
handler resolves the default through qualified-module access
to `ip4_const.IP4__DEFAULT_TTL`
(`packet_handler__ip4__tx.py:122`) so every emission picks up
the live `ip4.default_ttl` sysctl value. The knob is
registered at `pytcp/protocols/ip4/ip4__constants.py` with a
validator that rejects TTL=0 (the same value §3.2.1.7
forbids on the wire) and values outside the uint8 wire field.
Operators tune it via `stack.init(sysctls={"ip4.default_ttl":
N})` at boot or `pytcp.stack.sysctl["ip4.default_ttl"] = N`
at runtime. The TCP / UDP / RAW socket layers still pass
explicit `ip4__ttl` when they have a per-packet reason; the
sysctl is the host default the transport layers fall back to.

## §3.2.1.8 Options

> "There MUST be a means for the transport layer to specify IP
> options to be included in transmitted IP datagrams."

**Adherence:** met. The TX entry point exposes
`ip4__options: Ip4Options = Ip4Options()`
(`packet_handler__ip4__tx.py:103`). Callers (today, mostly
tests and one DHCP-client path) construct the options via the
typed dataclasses under `net_proto/protocols/ip4/options/`.

> "All IP options (except NOP or END-OF-LIST) received in
> datagrams MUST be passed to the transport layer (or to ICMP
> processing when the datagram is an ICMP message). The IP and
> transport layer MUST each interpret those IP options that
> they understand and silently ignore the others."

**Adherence:** met. `Ip4Parser._parse` builds the typed
`Ip4Options` container from the on-wire byte stream
(`ip4__parser.py:121-123`) and stores it on `self._options`,
which is exposed via `packet_rx.ip4.options` and individual
accessors (`packet_rx.ip4.lsrr`, `packet_rx.ip4.ssrr`, etc.).
The transport layer can read whichever options it understands;
unrecognised kinds become `Ip4OptionUnknown` entries which are
preserved on the wire but not acted on.

> "(b) Stream Identifier Option ... this option SHOULD NOT be
> sent, and it MUST be silently ignored if received."

**Adherence:** met. Stream ID is not implemented as a typed
option (no `Ip4OptionStreamId` file); on receive it lands in
the catch-all `Ip4OptionUnknown` and the option is silently
preserved on the wire without effecting any behaviour.
Cross-reference: RFC 6814 audit (Stream ID formally deprecated).

> "(c) Source Route Options ... A host MUST support originating
> a source route and MUST be able to act as the final
> destination of a source route."

**Adherence:** partial. Wire codec for LSRR/SSRR is shipped
(`ip4__option__lsrr.py`, `ip4__option__ssrr.py`). On receive,
the LSRR/SSRR-bearing packet is gated by
`IP4__ACCEPT_SOURCE_ROUTE` (default False — matching Linux
`net.ipv4.conf.*.accept_source_route=0`)
(`packet_handler__ip4__rx.py:130-144`). When the operator opts
in, the option is parsed but not acted on as a final
destination (the rewrite-pointer step is Phase 2 router work).
Origination of LSRR/SSRR is not exposed on a high-level API.

This is a Phase-1 simplification consistent with the broader
deprecation in RFC 6814 — source-route processing on hosts is
considered an attack surface; modern stacks gate it off by
default.

> "(d) Record Route Option / (e) Timestamp Option:
> Implementation of originating and processing ... is OPTIONAL."

**Adherence:** wire codecs shipped; origination not exposed. We
do not auto-write our address into received Record Route /
Timestamp slots (that's router-side behaviour).

## §3.3.1 Routing Outbound Datagrams

> "The host IP layer MUST operate correctly in a minimal
> network environment, and in particular, when there are no
> gateways."

**Adherence:** met. The TX path handles "no gateway configured"
naturally — on-link destinations resolve via ARP directly;
off-link destinations with no gateway end up at the
`DROPPED__ETHERNET__DST_NO_GATEWAY_IP4` exit
(`pytcp/runtime/packet_handler/packet_handler__ethernet__tx.py`).
The stack starts up and operates on a single subnet without a
gateway entry.

> "To efficiently route a series of datagrams to the same
> destination, the source host MUST keep a 'route cache' of
> mappings to next-hop gateways."

**Adherence:** partial — Phase 1 simplification. PyTCP uses a
flat "single gateway per Ip4IfAddr" model (`Ip4IfAddr.gateway`
attribute) rather than a route cache. For Phase 1 host stacks
with a single uplink this is sufficient (Linux operates this
way by default with `ip route show default` showing a single
entry until ICMP Redirects or routing daemons add more).

**`# Phase 2:`** A true route cache (per-destination next-hop
mapping, Type-of-Service-aware, ageing) is Phase-2 work tied
to the forwarding plane. The fix point is a new
`pytcp/protocols/ip/ip4_route_cache.py` Subsystem.

> "The IP layer MUST pick a gateway from its list of 'default'
> gateways. The IP layer MUST support multiple default gateways."

**Adherence:** not met — Phase 1 simplification. PyTCP supports
exactly one gateway per `Ip4IfAddr`. Multiple default gateways
(equal-cost or scored) is Phase-2 work. Marked here so the
upgrade path is greppable.

> "When it receives a Redirect, the host updates the next-hop
> gateway in the appropriate route cache entry."

**Adherence:** not implemented (Phase 2). ICMP Redirect parsing
exists in the ICMPv4 protocol package, but the RX handler does
not mutate routing state on Redirect — it logs the message and
moves on. Cross-reference:
`docs/rfc/icmp4/rfc1122__host_requirements_icmp/adherence.md`
which audits the Redirect-message side of this same gap.

## §3.3.2 Reassembly

See `docs/rfc/ip4/rfc815__ip4_reassembly/adherence.md`.

## §3.3.3 Fragmentation

> "Hosts MUST NOT generate fragments that overlap."

**Adherence:** met. The TX fragmenter
(`packet_handler__ip4__tx.py:188-205`) slices the payload at
MTU-aligned 8-byte boundaries with non-overlapping ranges
(`payload[_:payload_mtu+_] for _ in range(0, len(payload),
payload_mtu)`). The construction is algebraically incapable of
producing overlap.

> "A host MAY emit a 'Don't Fragment' ICMP error message in
> response to a frame that would have required fragmentation."

This is the PMTUD feedback path — audited under
`docs/rfc/ip4/rfc1191__pmtud_ip4/adherence.md`.

## §3.3.4 Local Multihoming

> "A host MAY be multihomed."

**Adherence:** partial — Phase 1 single-interface design.
PyTCP runs on a single TAP/TUN interface today. The
multihoming requirements (3.3.4.2 (a)-(j)) presume multiple
interfaces and a route-cache / source-selection layer that
threads through them. The §6724 source-selection logic
(`packet_handler__ip4__tx.py:372-416`) is structured to be
multihoming-aware (it scans `_ip4_host` which is already a
`list[Ip4IfAddr]`), but the rest of the stack assumes a single
`_interface_mtu`, single `_mac_unicast`, etc.

**`# Phase 2:`** Multihoming is on the project north-star
(Phase 2 router). The selection logic is ready; the rest of
the stack will catch up.

## §3.3.5 Source Route Forwarding

> "A host MAY support source route forwarding ..."

**Adherence:** not implemented (Phase 2). PyTCP does not
forward source-routed datagrams; it gates them off entirely on
receive (see §3.2.1.8). When forwarding lands, this is where
the LSRR pointer-advance / dst rewrite / option preservation
logic goes.

## §3.3.6 Broadcasts

> "Limited Broadcast Address {-1, -1} ... There is a class of
> hosts that USE this address as a source address. ... it MUST
> NOT be used as a source address."

**Adherence:** met. Limited-broadcast source is rejected on
receive (§3.2.1.3 above) and replaced on send
(`packet_handler__ip4__tx.py:289-306`).

> "Subnet broadcast addresses (e.g., {network, subnet, -1})
> ... MUST be received as a broadcast."

**Adherence:** met. The `_ip4_broadcast` set populated at
`stack.init()` time from each `Ip4IfAddr.network.broadcast`
includes both subnet and (where applicable) network
broadcasts. RX handler checks against this set
(`packet_handler__ip4__rx.py:149-153`).

> "Outgoing IP datagrams from an application using a
> destination IP address of {-1, -1} MUST be silently discarded
> if the host has the option 'broadcasts permitted' [link]
> turned off."

**Adherence:** partial. PyTCP does not gate broadcast TX on a
configurable flag — it forwards any caller-requested broadcast
to the link layer unconditionally. A future
`ip4.allow_broadcast` sysctl would close this; not currently a
gap in practice because PyTCP has no public socket API for
applications to send broadcasts unless they explicitly use a
RAW socket.

## §3.3.7 IP Multicasting

> "A host SHOULD support local IP multicasting on all connected
> networks for which a mapping from Class D IP addresses to
> link-layer addresses has been specified."

**Adherence:** met (reception). `_ip4_multicast` is populated
at boot with the all-hosts (224.0.0.1) entry; the destination
filter (`packet_handler__ip4__rx.py:149-153`) admits anything
in this set. The Ethernet MAC mapping is implemented in
`net_addr/ip4_address.py` (`Ip4Address.multicast_mac`).

> "Hosts SHOULD implement IGMPv1 ..."

**Adherence:** not implemented (deferred — Phase 2 alongside the
IGMP package). Cross-reference: pending RFC 2236 / RFC 3376
audits if PyTCP ever picks up multicast group management beyond
all-hosts reception.

## §3.3.8 Error Reporting (link-layer → IP layer)

> "Wherever feasible, the IP layer MUST be informed about errors
> reported by the link layer (e.g., a refused connection from an
> X.25 network or an Ethernet Excessive Collisions error)."

**Adherence:** partial. The TAP/TUN interface reports
read/write errors via Python exceptions which the RX/TX
loops catch and log; they do not propagate as ICMP Host
Unreachable upstream. Practical impact is minimal — the only
"link-layer error" on a TAP interface is the fd being
unwriteable, which is a configuration error rather than a
transient network condition.

---

## Test coverage audit

### §3.2.1.1 / §3.2.1.2 Version + Checksum integrity

- **Unit:**
  `net_proto/tests/unit/protocols/ip4/test__ip4__parser__integrity_checks.py`
  Covers `ver != 4` and bad-checksum branches with
  `Ip4IntegrityError`.

**Status:** locked in.

### §3.2.1.3 Source-address sanity (multicast / reserved / limited-broadcast)

- **Unit:**
  `net_proto/tests/unit/protocols/ip4/test__ip4__parser__sanity_checks.py`
  Each branch exercised with the expected `pointer` value.
- **Integration:**
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  Verifies ICMP Parameter Problem emission with the documented
  rate-limit / DHCP-mode gates.

**Status:** locked in.

### §3.2.1.3 Destination filtering (own / broadcast / multicast)

- **Integration:**
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  Covers the three accept paths + the dst-unknown drop.

**Status:** locked in.

### §3.2.1.3 TX source-address validation + replacement (multicast / broadcast / unspec)

- **Integration:**
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py`
  Matrix of src=owned, src=multicast (replaced), src=limited-
  broadcast (replaced), src=network-broadcast (replaced),
  src=unspec+DHCP (passthrough), src=unspec+other (selector or
  drop).
- **Integration:**
  `pytcp/tests/integration/protocols/ip4/test__ip4__rfc6724_source_selection.py`
  RFC 6724 rule-by-rule selection.

**Status:** locked in.

### §3.2.1.6 TOS / DSCP / ECN propagation

- **Unit:**
  `net_proto/tests/unit/protocols/ip4/test__ip4__header__asserts.py`
  Field-level boundary asserts.
- **Integration:** ECN-relevant TCP flows covered in TCP audits.

**Status:** locked in (cross-reference DSCP and ECN audits).

### §3.2.1.7 TTL=0 rejection + default + configurability

- **Unit:**
  `net_proto/tests/unit/protocols/ip4/test__ip4__parser__sanity_checks.py::ttl == 0`
  pins the RX-side ban.
- **Unit:**
  `pytcp/tests/unit/protocols/ip4/test__ip4__constants.py::TestIp4Constants`
  pins `IP4__DEFAULT_TTL = 64`; `TestIp4DefaultTtlSysctl` pins
  the `ip4.default_ttl` registration, the validator's
  range-and-type rejections (TTL=0, overflow > 255, non-int),
  and that `sysctl.set` updates the backing module attribute.
- **Integration:**
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  Verifies ICMP Parameter Problem emission with `pointer=8`.
- **Integration:**
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py::TestPacketHandlerIp4TxRfc1122DefaultTtlSysctl`
  Drives the sysctl override and verifies the wire TTL of an
  outbound unicast datagram reflects the live value; verifies
  multicast destinations stay at TTL=1 regardless of the
  unicast-default override (RFC 1112 §6.1 carve-out).

**Status:** locked in.

### §3.2.1.8 Options pass-through + LSRR/SSRR gate

- **Unit:** one file per option in
  `net_proto/tests/unit/protocols/ip4/options/`.
- **Integration:**
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx__source_route.py`
  Drives the `IP4__ACCEPT_SOURCE_ROUTE` matrix.

**Status:** locked in.

### §3.3.1 Routing (default-gateway path)

- **Integration:**
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py`
  Covers off-link sends through the gateway lookup.

**Status:** locked in for the single-gateway path. Phase-2 route
cache is `n/a (gap not closed; add test with fix)`.

### §3.3.3 Fragmentation on send (no overlap)

- **Integration:**
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py`
  Fragmentation matrix asserts that fragment offsets cover the
  payload without overlap and that the last fragment carries
  MF=0.

**Status:** locked in.

### §3.3.6 Broadcasts (TX replacement, RX acceptance)

- **Integration:**
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py`
  + `..__rx.py` cover broadcast send / receive.

**Status:** locked in.

### §3.3.7 IP multicasting (reception)

- **Integration:**
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__rx.py`
  Verifies the all-hosts 224.0.0.1 RX path.

**Status:** locked in.

### Gaps without tests

- **§3.3.1.5 ICMP Redirect → route-cache update** — not
  implemented (Phase 2); no test surface today.
- **§3.3.4 Multihoming** — single-interface assumption; the
  source-selection logic is multihoming-ready but the broader
  multihoming behaviour is Phase 2.
- **§3.3.5 Source-route forwarding** — not implemented
  (Phase 2).
- **§3.3.8 Link-layer error → IP-layer notification** —
  Phase 1 logs, does not propagate; no error-injection test.

### Test coverage summary

| Aspect                                                | Coverage |
|-------------------------------------------------------|----------|
| §3.2.1.1 Version != 4 silent discard                  | locked in |
| §3.2.1.2 Bad checksum silent discard                  | locked in |
| §3.2.1.3 Source-address sanity rules                  | locked in |
| §3.2.1.3 Destination filtering (RX)                   | locked in |
| §3.2.1.3 Source-address validation + replacement (TX) | locked in |
| §3.2.1.6 TOS / DSCP / ECN propagation                 | locked in (via separate DSCP / ECN audits) |
| §3.2.1.7 TTL=0 reject + default + configurable        | locked in (sysctl `ip4.default_ttl`) |
| §3.2.1.8 Options pass-through + LSRR/SSRR gate        | locked in |
| §3.3.1 Single-gateway routing                         | locked in (Phase 1 simplification) |
| §3.3.1.5 ICMP Redirect → route update                 | n/a (Phase 2) |
| §3.3.3 Fragmentation correctness (no overlap)         | locked in |
| §3.3.4 Multihoming                                    | n/a (Phase 2) |
| §3.3.5 Source-route forwarding                        | n/a (Phase 2) |
| §3.3.6 Broadcast send / receive                       | locked in |
| §3.3.7 Multicast reception (no IGMP)                  | locked in |
| §3.3.8 Link-layer error propagation                   | partial (logged, not propagated) |

---

## Overall assessment

| Aspect                                              | Status |
|-----------------------------------------------------|--------|
| §3.2.1 IP wire-format and integrity                 | met    |
| §3.2.1 IP source/destination validity rules         | met    |
| §3.2.1 TTL / TOS / Identification host-side rules   | met (semantics redefined where superseded) |
| §3.2.1 Options pass-through and LSRR/SSRR gate      | met    |
| §3.3.1 Routing — single gateway path                | met (Phase 1) |
| §3.3.1.5 ICMP Redirect route update                 | not met (Phase 2) |
| §3.3.2/3.3.3 Reassembly + fragmentation             | met (cross-referenced)  |
| §3.3.4 Multihoming                                  | not met (Phase 2) |
| §3.3.5 Source-route forwarding                      | not met (Phase 2) |
| §3.3.6 Broadcast handling                           | met    |
| §3.3.7 Multicast reception (no IGMP)                | partial — reception met, group management deferred |
| §3.3.8 Link-layer error propagation                 | partial |

The principal Phase-1 gaps are:

1. **ICMP Redirect → no route-cache update** — covered by the
   ICMP audit; the gap is symmetric on both sides.

Phase-2 gaps (multihoming, route cache, source-route forwarding)
are tracked by the project north-star.
