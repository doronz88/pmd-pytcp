# UDP Punch List — Residual Items After Conformance Sweep

**Status:** all five UDP audits report "met" or "fully meets"
verdicts on their primary conformance clauses. This document
tracks the residual Phase-1 / Phase-3 follow-up items that
the audits called out as **not strictly conformance gaps**
but real outstanding work — typically because they land in
the BSD socket-API surface, require per-interface state, or
are MAY-level RFC items with no current PyTCP consumer.

**Branch:** `PyTCP_3_0__pre_release`.

**Audit corpus this document derives from** (all under
`docs/rfc/udp/`):

| RFC | Adherence record |
|---|---|
| RFC 768 | `rfc768__udp/adherence.md` |
| RFC 1122 §4.1 | `rfc1122__host_requirements_udp/adherence.md` |
| RFC 8085 (BCP 145) | `rfc8085__udp_usage_guidelines/adherence.md` |
| RFC 6935 / 6936 | `rfc6935__udp_zero_cksum_ipv6/adherence.md` |
| RFC 6056 (BCP 156) | `rfc6056__port_randomization/adherence.md` |

**Companion audit** in the TCP family (covers the shared
`pick_local_port` helper): `docs/rfc/tcp/rfc6056__port_randomization/adherence.md`.

**Audits and conformance fixes already shipped** (commits on
`PyTCP_3_0__pre_release`):

| Commit | Topic |
|---|---|
| `155f286b` | UDP audits: RFC 768 + RFC 1122 §4.1 |
| `e01bf17d` | UDP audit: RFC 8085 (BCP 145) |
| `cfacaf15` | UDP audit: RFC 6935/6936 |
| `6405c964` | UDP audit: RFC 6056 (BCP 156) |
| `e8baf0bf` | TCP audit: RFC 6056 (mirror) |
| `1893c640` | RFC 6056 Phase 1 — cryptographic picker + Linux-parity range |
| `cb422598` | RFC 6056 Phase 2 — Algorithm 3 for TCP `connect()` |
| `b9cd5a75` | UDP TX cksum zero → all-ones substitution (RFC 768) |
| `38d83e2e` | UDP RX accept sport=0 (RFC 768 source-port-optional) |
| `57aaa7ad` | UDP RX IPv6 cksum=0 default-discard (RFC 6935 §5) |
| `94863af4` | RFC 1122 §4.1.3.6 audit correction (filter is at IP layer) |
| _(pending)_ | RFC 1122 §3.2.1.3 directed-broadcast source filter (#2) |
| _(pending)_ | RFC 1122 §4.1.3.2 IP options pass-through (#1) — IP_OPTIONS / IP_RECVOPTS + recvmsg |
| _(pending)_ | RFC 1122 §4.1.4 received-TOS pass-through (#5) — IP_RECVTOS + IPV6_RECVTCLASS cmsg |
| _(pending)_ | RFC 1122 §3.4 GET_MAXSIZES via IP_MTU / IPV6_MTU getsockopt (#3) |
| _(pending)_ | RFC 1122 §4.1.3.3 IP_RECVERR / MSG_ERRQUEUE socket-API (#4) — closes the punch list |

---

## Item summary

| # | Item | RFC clause | Audit verdict | Effort | Priority |
|---|---|---|---|---|---|
| 1 | ~~IP options pass-through to/from application~~ **SHIPPED** | RFC 1122 §4.1.3.2 | met (IP_OPTIONS setsockopt + IP_RECVOPTS + recvmsg ancillary data) | done | — |
| 2 | ~~Directed-broadcast source filter~~ **SHIPPED** | RFC 1122 §4.1.3.6 residual | met (RX-handler `_ip4_broadcast` membership check) | done | — |
| 3 | ~~`IP_MTU` / `IPV6_MTU` getsockopt~~ **SHIPPED** | RFC 1122 §3.4 GET_MAXSIZES | met (per-socket effective PMTU via getsockopt) | done | — |
| 4 | ~~`IP_RECVERR` / `MSG_ERRQUEUE` socket-API~~ **SHIPPED** | RFC 1122 §4.1.3.3 API parity | met (per-socket error queue + Linux-shape MSG_ERRQUEUE cmsg) | done | — |
| 5 | ~~`IP_RECVTOS` / `IPV6_RECVTCLASS` ancillary~~ **SHIPPED** | RFC 1122 §4.1.4 MAY | met (recvmsg IP_TOS / IPV6_TCLASS cmsg gated by per-socket flag) | done | — |
| 6 | `UDP_NO_CHECK6_RX` / `UDP_NO_CHECK6_TX` per-port opt-in | RFC 6935 §5 alternative mode | "Phase-3 socket-parity; no consumer" | ~half-day | Deferred — no consumer |
| 7 | PLPMTUD for UDP audit + implementation | RFC 8899 | "not yet audited" | new audit + impl, ~1-2 days | Low |
| 8 | RFC 6056 Algorithm 4 / 5 | RFC 6056 §3.3.4/§3.3.5 | "not implemented (no operational need)" | ~half-day each | Skip — no conformance pressure |

---

## #1 — IP options pass-through (RFC 1122 §4.1.3.2) — **SHIPPED**

**Status:** closed. Shipped as the IP_OPTIONS / IP_RECVOPTS
setsockopt surface, `recvmsg()` ancillary-data API,
`UdpMetadata.ip4__options` plumbing, and TX wiring
through `_phtx_udp` → `_phtx_ip4(ip4__options=...)`.
Pinned by unit tests at
`packages/pytcp/pytcp/tests/unit/socket/test__socket__udp__socket.py`
(7 setsockopt + 10 recvmsg) and integration tests at
`packages/pytcp/pytcp/tests/integration/protocols/udp/test__udp__ip_options.py`
(5 end-to-end). Audit ripple landed in
`docs/rfc/udp/rfc1122__host_requirements_udp/adherence.md`
§4.1.3.2: three "not implemented" rows flipped to "met";
"Principal gap" paragraph closed out; new test-coverage
audit block added.

Item #5 (IP_RECVTOS) inherits the recvmsg cmsg
infrastructure; the half-day estimate now ~1 hour.
Item #4 (IP_RECVERR / MSG_ERRQUEUE) also inherits the
recvmsg shape, though the error-queue mechanics remain
their own work.

Original brief (kept for archaeology):

### What the RFC says

> "UDP MUST pass any IP option that it receives from the
>  IP layer transparently to the application layer.
>
>  An application MUST be able to specify IP options to be
>  sent in its UDP datagrams, and UDP MUST pass these
>  options to the IP layer."

Three MUSTs in the §4.1.5 Requirements Summary table:

- Pass rcv'd IP options to applic layer
- Applic layer can specify IP options in Send
- UDP passes IP options down to IP layer

### Why it's open

PyTCP's IPv4 layer parses IP options for its own use (LSRR/
SSRR drop, Router Alert, RR, Timestamp) but the parsed
option list isn't exposed via the UDP socket API.
`UdpMetadata` carries no `ip_options` field;
`recvmsg()` / `IP_OPTIONS` setsockopt are not wired.

### Implementation sketch

1. Extend `packages/pytcp/pytcp/socket/udp__metadata.py::UdpMetadata` with
   an `ip_options: tuple[Ip4Option, ...] | None` field.
2. Populate it in `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__rx.py`
   from `packet_rx.ip4.options` (IPv6 has no IP-options
   surface — leave `None`).
3. Add a `recvmsg()` method to `UdpSocket` that returns
   `(data, ancillary_data, flags, address)` where
   `ancillary_data` is a list of `(level, type, value)`
   tuples — including `(IPPROTO_IP, IP_OPTIONS, raw_bytes)`
   when the inbound datagram carried IP options.
4. Add `setsockopt(IPPROTO_IP, IP_OPTIONS, raw_bytes)` to
   the BSD socket facade — parses the bytes, stores them
   on the socket, plumbs through to TX path via
   `_phtx_udp(..., ip__options=...)`.
5. The IPv4 TX path needs to accept and emit the operator-
   supplied options. Touches
   `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__tx.py`.
6. Tests:
   - Unit: `setsockopt(IP_OPTIONS, bytes)` + `getsockopt`
     round-trip.
   - Integration: drive a UDP packet with IP options
     through the RX path, recvmsg returns them.
   - Integration: send a UDP packet with IP options via
     setsockopt, assert wire format includes the option
     block.

### Audit ripple

- `RFC 1122 §4.1 adherence.md`: three "not implemented"
  rows in the requirements summary flip to "met"; the
  "Principal gap" section closes out.

### Effort

~half-day to full day. Most of the work is the
`recvmsg()` ancillary-data API, which is the same
machinery that #4 (IP_RECVERR), #5 (IP_RECVTOS) would
also consume — if you ship #1, #4 and #5 become much
cheaper because the ancillary infrastructure already
exists.

---

## #2 — Directed-broadcast source filter (RFC 1122 §4.1.3.6 residual) — **SHIPPED**

**Status:** closed. Shipped as the directed-broadcast
martian-source filter at
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip4__rx.py:145-157`.
Pinned by
`packages/pytcp/pytcp/tests/integration/protocols/ip4/test__ip4__martian_source.py`
(three tests: local-subnet directed broadcast dropped,
remote-subnet directed broadcast accepted, unicast source
unaffected). Counter:
`PacketStatsRx.ip4__src_directed_broadcast__drop`.
Audit ripple landed in
`docs/rfc/udp/rfc1122__host_requirements_udp/adherence.md`
§4.1.3.6 (preamble narrative, requirements summary,
test coverage audit, overall assessment, closed-gaps
footer).

Original brief (kept for archaeology):

### What's filtered today

The IPv4 parser sanity check at
`packages/net_proto/net_proto/protocols/ip4/ip4__parser.py::_validate_sanity`
drops:

- `src.is_multicast` (224.0.0.0/4)
- `src.is_reserved` (240.0.0.0/4)
- `src.is_limited_broadcast` (255.255.255.255)

### What's NOT filtered

**Directed broadcast** — e.g. `src=10.0.1.255` for a `/24`.
This requires knowing the local subnet to recognize, which
the address library doesn't provide as a per-`Ip4Address`
property.

### Implementation sketch

Two design options:

**Option A** — IP-layer filter in `packet_handler__ip4__rx.py`,
walking the configured `_ip4_ifaddr[]` and checking
`packet_rx.ip4.src` against each `Ip4IfAddr.network.broadcast`.
Cleanest; matches Linux's `ip_route_input_slow` placement.

**Option B** — UDP-layer filter alongside `is_unspecified`.
Smaller blast radius but duplicates the work if other
transports need it.

Lean toward **A** since "martian source" is an IP-layer
concept; closes the gap for every transport in one place.

```python
# packet_handler__ip4__rx.py — after the existing
# dst-acceptance check
if any(packet_rx.ip4.src == host.network.broadcast for host in self._ip4_ifaddr):
    self._packet_stats_rx.ip4__directed_broadcast_src__drop += 1
    __debug__ and log(...)
    return
```

### Tests

Drive a UDP frame with `src=10.0.1.255` (host's own subnet
broadcast); assert the packet is dropped with the new
`ip4__directed_broadcast_src__drop` counter bumped.

### Audit ripple

- `RFC 1122 §4.1 adherence.md` §4.1.3.6: residual
  "directed-broadcast a Phase-1 follow-up" note removed.

### Effort

~1-2 hours.

---

## #3 — `IP_MTU` / `IPV6_MTU` getsockopt — **SHIPPED**

**Status:** closed. Shipped `IP_MTU=14` and `IPV6_MTU=24`
getsockopt at the base `socket` class via a new
`_effective_pmtu()` helper that reads `stack.pmtu_cache`
keyed by the connected remote address and falls back to
`stack.interface_mtu`. Unconnected sockets raise
`OSError(ENOTCONN)` (Linux `ip(7)` / `ipv6(7)`
semantics); setsockopt on these options is rejected
with `ENOPROTOOPT` since the dispatch never matches.
Pinned by 6 unit tests + 2 integration tests
(`TestUdpSocketApiIpMtuGetsockopt` exercises the
end-to-end ICMPv4 Frag-Needed → cache update →
getsockopt readback).

Skipped `IPV6_PATHMTU=61` (struct `ip6_mtuinfo`, 32-byte
packed shape) — the integer `IPV6_MTU` covers the common
case; add the struct variant when an explicit consumer
needs it.

Audit ripple in
`docs/rfc/udp/rfc1122__host_requirements_udp/adherence.md`:
§4.1.4 `GET_MAXSIZES` narrative flipped from "partial"
to "met"; requirements-summary row updated; closed-gaps
footer bumped to six.

Original brief (kept for archaeology):

### What the RFC implies

RFC 1122 §3.4 abstract API includes `GET_MAXSIZES()` to
return the effective MTU. RFC 8085 §3.2 expects applications
to "use the path MTU information provided by the IP layer"
— which requires a way to retrieve it.

### What PyTCP has

`stack.pmtu_cache` tracks per-destination PMTU; the
`notify_pmtu` socket callback delivers ICMPv6 "Packet Too
Big" updates to bound sockets. But there's no `getsockopt`
to read the current value.

### Linux comparison

```
getsockopt(sock, IPPROTO_IP, IP_MTU, &mtu, &len);
getsockopt(sock, IPPROTO_IPV6, IPV6_PATHMTU, &mtuinfo, &len);
```

### Implementation sketch

1. Add `IP_MTU = 14` and `IPV6_PATHMTU = 61` to
   `packages/pytcp/pytcp/socket/__init__.py` constants (matching Linux's
   numeric values).
2. Wire them into the `getsockopt` dispatch — return the
   current `stack.pmtu_cache` entry for the socket's
   remote address, or the interface MTU as a fallback.
3. `IPV6_PATHMTU` returns a `struct ip6_mtuinfo` (8-byte
   address + 4-byte MTU); model as a packed bytes return.

### Tests

Unit-level: mock the PMTU cache; assert
`getsockopt(IP_MTU)` returns the cached value.

### Audit ripple

- `RFC 1122 §4.1.4` row "GET_MAXSIZES partial" flips to
  "met".
- `docs/refactor/socket_linux_parity_audit.md` updates.

### Effort

~2-3 hours.

---

## #4 — `IP_RECVERR` / `MSG_ERRQUEUE` socket-API — **SHIPPED**

**Status:** closed. The largest of the punch-list items —
this commit closes the punch list. Shipped surface:

- `IP_RECVERR=11` / `IPV6_RECVERR=25` setsockopt
  (Linux-numbered, matching stdlib `socket` constants);
  enables per-socket error-queue population.
- `MSG_ERRQUEUE=0x2000` recvmsg flag; switches
  `recvmsg()` from data-queue to error-queue.
- `packages/pytcp/pytcp/socket/error_queue.py`: `ErrorQueueEntry`
  dataclass; `SoEeOrigin` IntEnum for
  `sock_extended_err.ee_origin`; `icmp4_to_errno` /
  `icmp6_to_errno` POSIX-errno mapping mirroring Linux
  `icmp_err_convert`; `pack_sock_extended_err` packs the
  cmsg payload to exact Linux wire shape
  (`struct sock_extended_err` + `sockaddr_in[6]`).
- `UdpSocket.notify_unreachable` / `notify_time_exceeded`
  / `notify_parameter_problem` / `notify_pmtu`
  signatures extended with `icmp_origin: SoEeOrigin`,
  `icmp_type: ProtoEnum | int`, `icmp_code: ProtoEnum | int`,
  `offender_ip`, `embedded_datagram`. ICMP demux callers
  in `packet_handler__icmp{4,6}__rx.py` updated to pass
  the full context.
- Per-socket error queue is a `deque(maxlen=32)` —
  FIFO drop on overflow.

Pinned by **17 new tests**:
- 8 unit tests on the queue + setsockopt + recvmsg
  shape + FIFO bound + errno mapping.
- 2 integration tests driving end-to-end ICMPv4 Port
  Unreachable through the RX demux into the error queue
  and pinning the Linux-shape cmsg unpacks correctly.

Audit ripple in
`docs/rfc/udp/rfc1122__host_requirements_udp/adherence.md`:
§4.1.3.3 narrative rewritten — Conformance verdict
flipped from "partial at the application API" to "met
at the protocol layer AND the Linux application API".
Requirements-summary row updated. Test-coverage block
extended.

**Closes the UDP punch list.** Items #1, #2, #3, #4, #5
all shipped; #6 and #7 are deferred (no consumer);
#8 declined.

Original brief (kept for archaeology):

### Background

PyTCP's UDP RX path passes ICMP errors to sockets via
the `notify_*` callbacks (`notify_unreachable`,
`notify_pmtu`, `notify_time_exceeded`,
`notify_parameter_problem`). The protocol-level pass-up
is conformant with RFC 1122 §4.1.3.3.

The BSD API gap: Linux's `IP_RECVERR` socket option
queues ICMP errors so `recvmsg(MSG_ERRQUEUE)` can dequeue
them with full per-error context (the offending datagram,
the ICMP type/code, the originating ICMP source address).
PyTCP exposes only the simpler "next recv() returns
-1 + errno" model (and even that not consistently).

### Implementation sketch

1. Per-socket error queue (`collections.deque` or similar).
2. `notify_*` callbacks enqueue a `(icmp_type, icmp_code,
   offender_address, embedded_datagram)` tuple when
   `_ip_recverr` is enabled on the socket.
3. `setsockopt(IPPROTO_IP, IP_RECVERR, value)` /
   `setsockopt(IPPROTO_IPV6, IPV6_RECVERR, value)`.
4. `recvmsg(..., flags=MSG_ERRQUEUE)` dequeues an error
   and returns the embedded datagram + cmsg with the
   error metadata.
5. The error-queue-not-empty path causes the next `recv()`
   on a connected socket to return `OSError` with the
   per-error errno (`EHOSTUNREACH`, `ENETUNREACH`, etc.).

This is the most complex Phase-3 work — `recvmsg()` with
ancillary data is non-trivial.

### Tests

Integration tests driving inbound ICMP errors that
target a UDP socket; assert the error appears in the
socket's error queue when `IP_RECVERR` is set; assert
`recvmsg(MSG_ERRQUEUE)` returns the correct cmsg shape.

### Audit ripple

- `RFC 1122 §4.1.3.3` audit text drops the "IP_RECVERR /
  MSG_ERRQUEUE API parity is a Phase-3 socket-parity
  item" caveat.
- `docs/refactor/socket_linux_parity_audit.md` major update.

### Effort

~half-day to full day. Shares ancillary-data
infrastructure with #1.

---

## #5 — `IP_RECVTOS` / `IPV6_RECVTCLASS` ancillary — **SHIPPED**

**Status:** closed. Shipped on top of the
`recvmsg`/cmsg infrastructure from #1. New constants
`IP_RECVTOS=13` and `IPV6_RECVTCLASS=66`; new socket
attrs `_ip_recvtos` / `_ipv6_recvtclass`;
`UdpMetadata.ip__tos` carries the combined DSCP+ECN
byte populated from the parsed IP header; `recvmsg`
emits `IP_TOS` cmsg as a single byte (matching Linux's
`ip(7)`) or `IPV6_TCLASS` cmsg as a 4-byte big-endian
int (matching Linux's `ipv6(7)`). Pinned by 8 unit
tests (2 setsockopt + 6 recvmsg) plus 4 integration
tests (2 IPv4 + 2 IPv6 end-to-end). Audit ripple landed
in
`docs/rfc/udp/rfc1122__host_requirements_udp/adherence.md`
§4.1.4: row flipped from "not implemented (MAY)" to
"met"; closed-gaps footer bumped to five.

Effort was ~1 hour, in line with the post-#1 estimate.

Original brief (kept for archaeology):

### What it does

When set, the received IP TOS / IPv6 Traffic Class byte
is surfaced via recvmsg ancillary data. Lets QoS-aware
applications inspect the DSCP value of incoming traffic.

### Implementation sketch

1. Extend `UdpMetadata` with `ip_tos: int` (or split
   `dscp`/`ecn`).
2. Populate from `packet_rx.ip.dscp` /
   `packet_rx.ip.ecn` (RFC 2474).
3. `setsockopt(IPPROTO_IP, IP_RECVTOS, 1)` /
   `setsockopt(IPPROTO_IPV6, IPV6_RECVTCLASS, 1)`.
4. recvmsg returns `IP_TOS` / `IPV6_TCLASS` cmsg when
   enabled.

### Tests

Unit-level: drive a UDP datagram with a known DSCP/ECN
value; assert `recvmsg` returns the correct cmsg.

### Audit ripple

- `RFC 1122 §4.1.4` row "Pass received TOS up to applic
  layer (MAY)" flips from "not implemented" to "met".

### Effort

~2-3 hours. Cheap if ancillary-data infra from #1 / #4
exists.

---

## #6 — `UDP_NO_CHECK6_RX` / `UDP_NO_CHECK6_TX`

**Status:** deferred. RFC 6935 per-port zero-checksum
opt-in. **No PyTCP consumer needs it.**

### Why deferred

PyTCP implements no tunnel protocol that would use the
RFC 6935 alternative mode (LISP, MPLS-in-UDP, Geneve, GTP,
GRE-in-UDP). The default-mode discard is fully
conformant; the opt-in is the "MAY enable" half.

### Trigger condition

Resume when:
1. PyTCP grows a tunnel-protocol consumer that needs
   zero-cksum UDP, OR
2. A user explicitly requests Linux-parity surface even
   without a consumer.

### Implementation sketch

1. Add `UDP_NO_CHECK6_RX = 102` and
   `UDP_NO_CHECK6_TX = 101` socket options (matching
   Linux's numeric values).
2. Per-socket flags `_udp_no_check6_rx` /
   `_udp_no_check6_tx`.
3. Plumb through to `UdpAssembler` (skip cksum if
   `_udp_no_check6_tx` is set on the originating socket).
4. RX side: extend the `UdpZeroCksumIp6Error` short-circuit
   in `udp__parser.py` to consult the per-port table
   (would need to plumb the socket lookup BEFORE the
   parser sanity check, which is structurally
   inconvenient — alternative: drop unconditionally and
   let an upper layer override).

### Audit ripple

- `RFC 6935/6936 adherence.md` §4 constraints 3/4/6/8 flip
  from "not implemented" to "met". Overall verdict goes
  from "fully meets every constraint that applies to a
  default-mode IPv6 UDP stack" to "fully meets every
  constraint."

### Effort

~half-day. Genuinely small but no consumer pressure.

---

## #7 — PLPMTUD for UDP (RFC 8899)

**Status:** open. Not yet audited. Would be its own track.

### What RFC 8899 specifies

Packetization Layer Path MTU Discovery — probe-based
PMTU discovery for connectionless / UDP-based protocols.
Doesn't rely on ICMP "Packet Too Big" delivery; uses
binary search via application-layer probe packets.

### Why it matters

Modern operational reality: ICMP errors are routinely
filtered by middleboxes (RFC 4890), so RFC 1191 / RFC
8201 PMTUD is unreliable. PLPMTUD is more robust.

### Scope

Substantial work — PyTCP's TCP already implements RFC
8899 (PLPMTUD is in the TCP audit corpus); UDP needs its
own track.

### Process

1. Add `docs/rfc/udp/rfc8899__plpmtud/adherence.md`
   audit first (per the rfc_adherence_audit skill).
2. Identify the implementation surface — likely a new
   subsystem under `packages/pytcp/pytcp/lib/` or
   `packages/pytcp/pytcp/protocols/udp/` for probe scheduling, per-flow
   PMTU state.
3. Expose a socket-side API for apps to opt in.

### Effort

1-2 days minimum (audit + design + implementation +
tests). This is a feature, not a polish item.

---

## #8 — RFC 6056 Algorithm 4 / 5

**Status:** declined. No conformance pressure; no real
benefit at PyTCP's scale.

See discussion in
`docs/rfc/tcp/rfc6056__port_randomization/adherence.md`
overall-assessment text. RFC 6056 §3.5 presents the five
algorithms as a menu; Algorithm 3 (which PyTCP ships) is
what Linux uses for TCP. Algorithm 4 trades memory
overhead for marginal port-reuse-frequency improvement;
Algorithm 5 is "middle ground" with weaker
unpredictability than Algorithm 3.

**Recommendation: never implement.** Re-evaluate only if
PyTCP grows a workload that exhibits Algorithm-3
port-reuse-frequency problems in practice.

---

## Implementation order recommendation

If/when this resumes:

1. **#2 directed-broadcast filter** — smallest, fastest
   win. ~1-2 hours.
2. **#1 IP options pass-through** — biggest conformance
   value; ships the ancillary-data infrastructure.
3. **#5 IP_RECVTOS** — cheap follow-on now that ancillary
   exists.
4. **#3 IP_MTU getsockopt** — medium effort, real value.
5. **#4 IP_RECVERR** — biggest single item; do last so
   the ancillary infra from #1/#5 is settled.
6. **#7 PLPMTUD** — separate track entirely; only if
   actually needed.
7. **#6 UDP_NO_CHECK6_*** — deferred until consumer.
8. **#8 RFC 6056 Algorithm 4/5** — never.

### Group commits

Group items #1, #5 into one PR (they share the
ancillary-data infrastructure). #4 in its own larger PR.
Items #2 and #3 each stand alone.

---

## Cross-references

- Per-RFC adherence records: `docs/rfc/udp/*/adherence.md`.
- Socket-API parity audit: `docs/refactor/socket_linux_parity_audit.md`.
- PMTU cache + notify_pmtu callback: `packages/pytcp/pytcp/stack/__init__.py::pmtu_cache`,
  `packages/pytcp/pytcp/socket/udp__socket.py::notify_pmtu`.
- IPv4 parser sanity checks (the §4.1.3.6 ground-truth):
  `packages/net_proto/net_proto/protocols/ip4/ip4__parser.py::_validate_sanity`.
- UDP RX dispatcher (where most items integrate):
  `packages/pytcp/pytcp/runtime/packet_handler/packet_handler__udp__rx.py::_phrx_udp`.
- Existing UdpMetadata surface (what #1 / #4 / #5 extend):
  `packages/pytcp/pytcp/socket/udp__metadata.py`.
- Linux socket-option numeric values reference:
  `/usr/include/linux/in.h` and `/usr/include/linux/in6.h`.
