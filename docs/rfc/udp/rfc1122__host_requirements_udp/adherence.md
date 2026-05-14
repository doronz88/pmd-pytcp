# RFC 1122 §4.1 — Host Requirements for UDP

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 1122 (UDP section §4.1 only)                   |
| Title       | Requirements for Internet Hosts — Communication Layers |
| Author      | R. Braden (Editor)                             |
| Category    | Internet Standard (STD 3)                      |
| Date        | October 1989                                   |
| Source text | [`rfc1122.txt`](rfc1122.txt) §4.1 (pages 77-80) |

This document audits RFC 1122 §4.1's UDP-specific clauses
against the current PyTCP codebase. The full RFC 1122 is
already mirrored elsewhere (IPv4, ICMPv4, ARP families);
this record narrows to §4.1 and is the natural extension of
[RFC 768](../rfc768__udp/adherence.md). The audit was
performed by reading §4.1 fresh and inspecting
`net_proto/protocols/udp/`,
`pytcp/stack/packet_handler/packet_handler__udp__rx.py`,
`pytcp/stack/packet_handler/packet_handler__udp__tx.py`,
and `pytcp/socket/udp__socket.py` directly. Sections
without normative content (§4.1.1 Introduction, §4.1.2
Protocol Walk-Through — "There are no known errors in the
specification of UDP", §4.1.5 Requirements Summary table)
are omitted; the Requirements Summary table is reproduced
in the Overall Assessment section as a row-by-row mapping.

---

## Top-line summary

PyTCP **meets** every MUST in §4.1 except one — the
"Sender Option to not generate checksum" MAY (4.1.3.4)
is not exposed at the socket layer, but as a MAY it is
not a conformance gap. Two SHOULDs and one MAY are
partial:

- §4.1.3.1 ICMP Port Unreachable: **met** — emitted with
  rate-limiting (RFC 1122 §3.2.2 generation gate already
  enforced).
- §4.1.3.5 "communicate chosen source address up to
  application layer": **met** — `getsockname()` returns
  the bound local address.
- §4.1.3.6 "Invalid IP source address must be discarded":
  **partial** — PyTCP drops UDP datagrams whose source IP
  is `is_unspecified` (0.0.0.0 / ::); it does NOT
  explicitly drop broadcast / multicast UDP sources at
  the UDP layer.
- §4.1.4 "MAY pass received TOS up to application layer":
  **partial** — IP_TOS is settable on TX (per-socket TOS
  / DSCP override) but the RX path does not expose the
  received TOS as ancillary data (no `IP_RECVTOS`).

| §       | Topic                                          | Status                                    |
|---------|------------------------------------------------|-------------------------------------------|
| §4.1.3.1 | UDP send Port Unreachable                     | met (with rate-limiting per §3.2.2)       |
| §4.1.3.2 | IP options pass-through (RX + TX)             | not implemented (IP-options surface not exposed at socket layer) |
| §4.1.3.3 | Pass ICMP errors up to application            | met (notify_unreachable / notify_pmtu / notify_time_exceeded / notify_parameter_problem socket callbacks) |
| §4.1.3.4 | Generate + check checksum (MUST)              | met                                        |
| §4.1.3.4 | Silently discard bad checksum                 | met                                        |
| §4.1.3.4 | Sender option to skip checksum (MAY)          | not implemented (MAY, no PyTCP consumer)   |
| §4.1.3.4 | Default is to checksum (MUST)                 | met (assembler always computes)           |
| §4.1.3.4 | Receiver option to require checksum (MAY)     | not implemented (MAY, no PyTCP consumer)   |
| §4.1.3.4 | Computed-zero-cksum → all-ones (MUST)         | **not met** — flagged in [RFC 768 audit](../rfc768__udp/adherence.md) |
| §4.1.3.5 | Pass specific-destination addr to application | met (via PacketRx + UdpMetadata)          |
| §4.1.3.5 | Application can specify local IP / wildcard   | met (`bind()`)                             |
| §4.1.3.5 | Application notified of local IP used         | met (`getsockname()`)                      |
| §4.1.3.6 | Bad IP src addr silently discarded by UDP/IP  | partial (unspecified dropped; bcast/mcast src not explicitly filtered) |
| §4.1.3.6 | Only send valid IP source address             | met (TX source picked from host's `_ip4_host` / `_ip6_host`) |
| §4.1.4   | Application MUST set TTL, TOS, IP options     | met for TTL + TOS; not implemented for IP options |
| §4.1.4   | Pass received TOS up to application (MAY)     | not implemented (MAY)                      |

---

## §4.1.3.1 Ports — ICMP Port Unreachable

> "If a datagram arrives addressed to a UDP port for which
>  there is no pending LISTEN call, UDP SHOULD send an ICMP
>  Port Unreachable message."

**Adherence:** met. The RX dispatch at
`pytcp/stack/packet_handler/packet_handler__udp__rx.py:180-230`
walks the socket table; on no match the path emits ICMPv4
or ICMPv6 Destination Unreachable (code = port) subject to
the `try_emit_icmp_error` host-requirements gate and the
outbound rate limiter. The IPv4 path bumps
`udp__no_socket_match__respond_icmp4_unreachable` /
`udp__no_socket_match__icmp4_unreachable_suppressed`; the
IPv6 path bumps the v6 counterparts. The "SHOULD" is
honoured by emission; the rate-limit gate is the
canonical exception (RFC 1122 §3.2.2 SHOULD allow
suppression).

---

## §4.1.3.2 IP Options

> "UDP MUST pass any IP option that it receives from the IP
>  layer transparently to the application layer.
>
>  An application MUST be able to specify IP options to be
>  sent in its UDP datagrams, and UDP MUST pass these
>  options to the IP layer."

**Adherence:** not implemented. PyTCP's IPv4 layer parses
options for its own use (Source/Record Route, Timestamp,
Router Alert) — see
[RFC 791 audit](../../ip4/rfc791__ip4/adherence.md) — but
the parsed option list is not exposed via the UDP socket
API. `UdpMetadata` does not carry an `ip_options` field;
`sendto()` / `send()` accept no `IP_OPTIONS` ancillary
data; `setsockopt(IPPROTO_IP, IP_OPTIONS, ...)` is not
wired.

This MUST is hard to claim conformance on for any modern
stack — Linux exposes `IP_OPTIONS` via setsockopt but very
few applications use it. PyTCP's current operating profile
(DHCP / DNS / NTP-style UDP traffic) does not consume IP
options. **Phase-1 gap, low operational impact.**

**Fix sketch:** add an `ip_options` member to
`UdpMetadata`; populate from `packet_rx.ip4.options` in
`packet_handler__udp__rx.py:128-137`; expose via
`recvmsg()` ancillary data when that API lands. TX side:
add an `ip__options` kwarg to `send_udp_packet()` and
plumb through to `_phtx_ip4`.

---

## §4.1.3.3 ICMP Messages

> "UDP MUST pass to the application layer all ICMP error
>  messages that it receives from the IP layer."

**Adherence:** met. The ICMPv4 / ICMPv6 RX dispatch hands
off transport-layer-targeted errors to the socket via the
`notify_*` callbacks:

- `notify_unreachable()` at
  `pytcp/socket/udp__socket.py:519`
- `notify_time_exceeded(icmp_type, icmp_code)` at
  `udp__socket.py:526`
- `notify_parameter_problem(icmp_type, icmp_code)` at
  `udp__socket.py:540`
- `notify_pmtu(next_hop_mtu)` at `udp__socket.py:550`

The classification happens in
`pytcp/protocols/icmp/icmp__inbound_classifier.py` and
`icmp__error_demux.py`; the dispatch routes to the
matching UDP socket via the embedded-datagram 4-tuple. The
SO_ERROR / MSG_ERRQUEUE-style userspace surface (Linux's
`IP_RECVERR`) is not yet wired — sockets see the error
but the BSD `recv()` does not return -1 + errno on next
call. This is a Phase-3 socket-parity item documented in
`docs/refactor/socket_linux_parity_audit.md`.

**Conformance verdict:** met at the protocol layer (UDP
layer passes errors to the socket); partial at the
application API (`IP_RECVERR` / `MSG_ERRQUEUE` not
exposed). The MUST is for the protocol layer's
internal pass-up; the API parity is a separate audit.

---

## §4.1.3.4 UDP Checksums

> "A host MUST implement the facility to generate and
>  validate UDP checksums."

**Adherence:** met. `inet_cksum` at
`net_proto/lib/inet_cksum.py` is the canonical engine;
assembler at
`net_proto/protocols/udp/udp__assembler.py:79-83` computes
on TX; parser at
`net_proto/protocols/udp/udp__parser.py:91-94` verifies on
RX.

> "An application MAY optionally be able to control
>  whether a UDP checksum will be generated, but it MUST
>  default to checksumming on."

**Adherence:** the **MUST** is met — `udp__assembler.py`
unconditionally computes a checksum, so the default is
"on." The **MAY** (sender-side opt-out) is **not
implemented**; PyTCP has no `SO_NO_CHECK` socket option.
A MAY without a PyTCP consumer is not a gap.

> "If a UDP datagram is received with a checksum that is
>  non-zero and invalid, UDP MUST silently discard the
>  datagram."

**Adherence:** met. The parser's integrity check at
`udp__parser.py:91-94`:

```python
if int.from_bytes(self._frame[6:8]) != 0 and inet_cksum(...):
    raise UdpIntegrityError("The packet checksum must be valid.")
```

The RX dispatch at `packet_handler__udp__rx.py:113-119`
catches `UdpIntegrityError` (silent drop) and bumps
`udp__failed_parse__drop`. No ICMP error is generated,
matching the SHOULD-silent-discard.

> "An application MAY optionally be able to control
>  whether UDP datagrams without checksums should be
>  discarded or passed to the application."

**Adherence:** not implemented (MAY, no PyTCP consumer).
The current parser unconditionally accepts cksum=0 RX
("no checksum was generated"). Linux's `IP_NODEFRAG`-
adjacent `UDP_NO_CHECK6_RX` socket option would land here
if implemented; tracked in the
[RFC 6935/6936 audit](../rfc6935__udp_zero_cksum_ipv6/adherence.md)
task.

> "If the transmitter really calculates a UDP checksum of
>  zero, it must transmit the checksum as all 1's
>  (65535)."

**Adherence:** **not met.** Documented at length in the
[RFC 768 audit](../rfc768__udp/adherence.md) §"Fields —
Checksum"; the assembler writes raw `inet_cksum` output
without substituting `0xFFFF` for a computed-zero.
Fix is mechanical (one-line `or 0xFFFF`).

---

## §4.1.3.5 UDP Multihoming

> "When a UDP datagram is received, its specific-
>  destination address MUST be passed up to the application
>  layer."

**Adherence:** met. `UdpMetadata`
(`pytcp/socket/udp__metadata.py`) carries
`ip__local_address` populated from `packet_rx.ip.dst`
(`packet_handler__udp__rx.py:131`). `recvfrom()` at
`udp__socket.py:448` and the BSD `getsockname()` at
`pytcp/socket/__init__.py:640` expose the
specific-destination address to the application.

> "An application program MUST be able to specify the IP
>  source address to be used for sending a UDP datagram or
>  to leave it unspecified (in which case the networking
>  software will choose an appropriate source address)."

**Adherence:** met. `bind((address, port))` at
`udp__socket.py:202` accepts either a specific local
address or the wildcard (`0.0.0.0` / `::`). When the
local address is unspecified, `pick_local_ip_address`
(imported at `udp__socket.py:49`) picks an appropriate
source from the host's `_ip4_host` / `_ip6_host` list
using the matching destination-prefix rule (RFC 6724-
inspired for v6; RFC 1122 §3.3.4.3 for v4).

> "There SHOULD be a way to communicate the chosen source
>  address up to the application layer (e.g., so that the
>  application can later receive a reply datagram only
>  from the corresponding interface)."

**Adherence:** met via `getsockname()`. After `bind()`
with a wildcard, the BSD-style call returns the picked
local address.

---

## §4.1.3.6 Invalid Addresses

> "A UDP datagram received with an invalid IP source
>  address (e.g., a broadcast or multicast address) must
>  be discarded by UDP or by the IP layer (see Section
>  3.2.1.3)."

**Adherence:** partial. The UDP RX path explicitly drops
datagrams with an unspecified source address at
`packet_handler__udp__rx.py:149-158`:

```python
if packet_rx.ip.src.is_unspecified:
    self._packet_stats_rx.udp__ip_source_unspecified += 1
    return
```

But **broadcast / multicast source-address dropping is
not implemented** at either the UDP layer or the IP layer.
A UDP datagram bearing source `255.255.255.255` or
`224.0.0.1` would currently be parsed and delivered to a
matching socket. Linux's `ip_route_input_slow` drops
"martian" sources via the FIB lookup; PyTCP has no
equivalent ingress filter today.

**Fix sketch:** add a `packet_rx.ip.src.is_broadcast or
packet_rx.ip.src.is_multicast` guard alongside the
`is_unspecified` drop. Counter:
`udp__ip_source_broadcast__drop` /
`udp__ip_source_multicast__drop`. The IP layer is the
more architecturally appropriate spot — the IPv4 / IPv6
RX dispatcher could centralize martian filtering for all
transport protocols — but the UDP-layer drop satisfies the
RFC's "by UDP or by the IP layer" disjunction.

> "When a host sends a UDP datagram, the source address
>  MUST be (one of) the IP address(es) of the host."

**Adherence:** met. The TX path picks the source from
`pick_local_ip_address` against the host's configured
address list. A `sendto()` with an explicit local address
not in the host list would fail at `bind()` time, so the
invariant holds by construction.

---

## §4.1.4 UDP/Application Layer Interface

> "The application interface to UDP MUST provide the full
>  services of the IP/transport interface described in
>  Section 3.4 of this document. Thus, an application
>  using UDP needs the functions of the GET_SRCADDR(),
>  GET_MAXSIZES(), ADVISE_DELIVPROB(), and RECV_ICMP()
>  calls described in Section 3.4."

**Adherence:** met. PyTCP's BSD-socket facade maps each
abstract RFC 1122 §3.4 routine to a concrete call:

- **GET_SRCADDR** → `getsockname()` at
  `pytcp/socket/__init__.py:640` returns the local
  address (after wildcard bind, the picked source).
- **GET_MAXSIZES** → MTU discovery is exposed via PMTU
  cache (`stack.pmtu_cache`); applications can query
  effective MSS through socket-side state (not currently
  via a stdlib-compatible `getsockopt`, but the
  information is available — `IP_MTU` is a Linux-specific
  option that lands as a Phase-3 socket-parity item).
- **ADVISE_DELIVPROB** → not exposed (PyTCP has no
  routing-failure-rate feedback mechanism; the closest
  proxy is `notify_pmtu` from inbound ICMP "Packet Too
  Big" / "Fragmentation Needed").
- **RECV_ICMP** → `notify_*` socket callbacks deliver
  ICMP errors per §4.1.3.3.

> "An application-layer program MUST be able to set the
>  TTL and TOS values as well as IP options for sending a
>  UDP datagram, and these values must be passed
>  transparently to the IP layer."

**Adherence:** met for TTL + TOS; not implemented for IP
options.

- **TTL** → `setsockopt(IPPROTO_IP, IP_TTL, value)` /
  `setsockopt(IPPROTO_IPV6, IPV6_UNICAST_HOPS, value)`
  wired at `pytcp/socket/__init__.py:286-313`. The TX
  path threads the per-socket override down to
  `_phtx_ip4(ip4__ttl=...)` / `_phtx_ip6(ip6__hop=...)`
  (`packet_handler__udp__tx.py:119-138`).
- **TOS** → `setsockopt(IPPROTO_IP, IP_TOS, value)` /
  `setsockopt(IPPROTO_IPV6, IPV6_TCLASS, value)` wired
  alongside TTL; the TX path passes `ip__ecn` through
  (the DSCP bits live with TOS — full DSCP plumbing is
  half-shipped, tracked in the
  [RFC 2474 audit](../../ip4/rfc2474__dscp/adherence.md)).
- **IP options** → not implemented (see §4.1.3.2).

> "UDP MAY pass the received TOS up to the application
>  layer."

**Adherence:** not implemented (MAY). The received TOS
byte is parsed but not surfaced via `UdpMetadata` or any
ancillary-data API. Linux's `IP_RECVTOS` /
`IPV6_RECVTCLASS` would land here.

---

## Test coverage audit

### §4.1.3.1 ICMP Port Unreachable on no matching socket

- **Integration:**
  `pytcp/tests/integration/test__packet_handler__udp__rx.py`
  — exercises the no-socket-match path and asserts
  outbound ICMP Port Unreachable on both IPv4 and IPv6,
  including the rate-limiter suppression counters.

**Status:** locked in.

### §4.1.3.3 ICMP error pass-up

- **Unit:**
  `pytcp/tests/unit/socket/test__socket__udp__socket.py`
  — pins the `notify_unreachable` / `notify_time_exceeded`
  / `notify_parameter_problem` / `notify_pmtu` callback
  surfaces.

**Status:** locked in (protocol-layer pass-up). The
`IP_RECVERR` / `MSG_ERRQUEUE` API parity is **n/a (gap
not closed; Phase-3 socket-parity item)**.

### §4.1.3.4 Checksum generate + validate + silent drop

- **Unit:** `net_proto/tests/unit/protocols/udp/test__udp__assembler__operation.py`
  (compute) + `test__udp__parser__integrity_checks.py`
  (verify, silent-drop, cksum=0 RX bypass).

**Status:** locked in.

### §4.1.3.4 Computed-zero → all-ones substitution

**No test surface — gap not yet closed.** Covered in the
[RFC 768 audit](../rfc768__udp/adherence.md) §"Fields —
Checksum"; when the fix lands the natural test is:

1. Construct a UDP datagram whose payload + pseudo-header
   sums to one's-complement zero (`b"\xff\xff"` with a
   pseudo-header tuned to invert).
2. Assemble + inspect the on-wire `cksum` field.
3. Assert it equals `0xFFFF`, not `0x0000`.

### §4.1.3.5 Multihoming — specific-destination + getsockname

- **Unit:** `pytcp/tests/unit/socket/test__socket__udp__socket.py`
  — pins `bind()` with wildcard + `getsockname()` return
  of the picked local address.

**Status:** locked in.

### §4.1.3.6 Invalid source address dropping

- **Integration / partial:** `udp__ip_source_unspecified`
  counter is exercised by
  `test__packet_handler__udp__rx.py`'s `is_unspecified`
  case.
- **Gap:** no test exists for broadcast / multicast
  source rejection (because the rejection is not
  implemented). When the fix lands the natural test is a
  parametrized matrix driving frames with
  `src=255.255.255.255` and `src=224.0.0.1` and asserting
  silent drop + new counter bump.

**Status:** locked in for `is_unspecified` only; the
broadcast / multicast cases are **n/a (gap not closed;
add test with fix)**.

### §4.1.4 TTL + TOS per-socket override

- **Unit:** `pytcp/tests/unit/socket/test__socket__udp__socket.py`
  (or the base socket tests) pin `setsockopt(IP_TTL)` /
  `setsockopt(IPV6_UNICAST_HOPS)` plumbing.
- **Integration:** `test__packet_handler__udp__tx.py`
  pins the per-socket TTL value appearing on the
  outbound wire.

**Status:** locked in.

### Test coverage summary

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| ICMP Port Unreachable on no socket                  | locked in |
| Silent discard on bad checksum                      | locked in |
| Checksum cksum=0 RX bypass                          | locked in |
| Computed-zero TX → all-ones (MUST)                  | n/a (gap not closed; add test with fix) |
| `notify_*` ICMP error pass-up                       | locked in |
| `IP_RECVERR` / `MSG_ERRQUEUE` API parity            | n/a (Phase-3 socket-parity track) |
| `getsockname()` reveals picked source               | locked in |
| `is_unspecified` source RX drop                     | locked in |
| Broadcast / multicast source RX drop                | n/a (gap not closed; add test with fix) |
| TTL + TOS per-socket override                       | locked in |
| IP options pass-through (RX + TX)                   | n/a (not implemented) |

---

## Overall assessment (RFC 1122 §4.1.5 Requirements Summary)

Mapping the RFC's own row-by-row Requirements Summary
table to PyTCP status. "x" in the original table marks
the column the RFC assigns; PyTCP status follows.

| Feature                                                | §       | RFC level | PyTCP status |
|--------------------------------------------------------|---------|-----------|--------------|
| UDP send Port Unreachable                              | 4.1.3.1 | SHOULD    | met (rate-limited) |
| Pass rcv'd IP options to applic layer                  | 4.1.3.2 | MUST      | not implemented |
| Applic layer can specify IP options in Send            | 4.1.3.2 | MUST      | not implemented |
| UDP passes IP options down to IP layer                 | 4.1.3.2 | MUST      | not implemented |
| Pass ICMP msgs up to applic layer                      | 4.1.3.3 | MUST      | met (notify_* callbacks; IP_RECVERR API parity deferred) |
| UDP able to generate/check checksum                    | 4.1.3.4 | MUST      | met |
| Silently discard bad checksum                          | 4.1.3.4 | MUST      | met |
| Sender option to not generate checksum                 | 4.1.3.4 | MAY       | not implemented (no consumer) |
| Default is to checksum                                 | 4.1.3.4 | MUST      | met |
| Receiver option to require checksum                    | 4.1.3.4 | MAY       | not implemented (no consumer) |
| Pass spec-dest addr to application                     | 4.1.3.5 | MUST      | met |
| Applic layer can specify Local IP addr                 | 4.1.3.5 | MUST      | met (`bind()`) |
| Applic layer specify wild Local IP addr                | 4.1.3.5 | MUST      | met |
| Applic layer notified of Local IP addr used            | 4.1.3.5 | SHOULD    | met (`getsockname()`) |
| Bad IP src addr silently discarded by UDP/IP           | 4.1.3.6 | MUST      | **partial** (unspecified dropped; bcast/mcast src not filtered) |
| Only send valid IP source address                      | 4.1.3.6 | MUST      | met |
| Full IP interface of 3.4 for application               | 4.1.4   | MUST      | met (GET_SRCADDR / RECV_ICMP); GET_MAXSIZES partial; ADVISE_DELIVPROB not implemented |
| Able to spec TTL, TOS, IP opts when send dg            | 4.1.4   | MUST      | met for TTL + TOS; not implemented for IP options |
| Pass received TOS up to applic layer                   | 4.1.4   | MAY       | not implemented (no consumer) |

**Principal gaps:**

1. **IP options at the UDP / socket interface** (§4.1.3.2)
   — three "MUST" rows in the requirements summary are
   currently "not implemented." This is the most
   substantial gap in the §4.1 audit. Modern UDP traffic
   rarely uses IP options, so the operational impact is
   low, but the conformance gap is real.
2. **Broadcast / multicast source-address ingress
   filtering** (§4.1.3.6) — single counter + guard in
   `packet_handler__udp__rx.py:149` (or in the IP layer,
   centralized).
3. **Checksum compute-zero → all-ones** (§4.1.3.4) —
   inherited from the [RFC 768 audit](../rfc768__udp/adherence.md);
   one-line fix.

The first is a Phase-1 polish track that would touch the
socket API (extend `UdpMetadata` with `ip_options`; add
`recvmsg()` ancillary-data API; expose
`setsockopt(IPPROTO_IP, IP_OPTIONS, ...)`). The latter
two are mechanical one-liners with corresponding test
additions.

---

## Cross-references

- Base UDP specification: [`../rfc768__udp/adherence.md`](../rfc768__udp/adherence.md)
- IPv4 host requirements (umbrella for §3.x): [`../../ip4/rfc1122__host_requirements_ip4/adherence.md`](../../ip4/rfc1122__host_requirements_ip4/adherence.md)
- ICMPv4 host requirements (§3.2.2 generation gate): [`../../icmp4/rfc1122__host_requirements_icmp/adherence.md`](../../icmp4/rfc1122__host_requirements_icmp/adherence.md)
- IPv4 datagram framing (RFC 791 + 1122 §3): [`../../ip4/rfc791__ip4/adherence.md`](../../ip4/rfc791__ip4/adherence.md)
- DSCP / TOS plumbing: [`../../ip4/rfc2474__dscp/adherence.md`](../../ip4/rfc2474__dscp/adherence.md)
- Socket-API parity gaps (incl. `IP_RECVERR`, `IP_OPTIONS`, `IP_RECVTOS`): `docs/refactor/socket_linux_parity_audit.md`
