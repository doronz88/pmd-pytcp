# RFC 8899 — Packetization Layer Path MTU Discovery for Datagram Transports

| Field       | Value                                             |
|-------------|---------------------------------------------------|
| RFC number  | 8899                                              |
| Title       | Packetization Layer PMTUD for Datagram Transports |
| Category    | Standards Track                                   |
| Date        | September 2020                                    |
| Source text | [`rfc8899.txt`](rfc8899.txt)                      |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 8899. The audit was performed by
reading the RFC text fresh against the codebase under
`pytcp/` and `net_proto/` directly. Sections that
contain no normative content (Introduction, Terminology,
References, Security Considerations boilerplate, IANA
Considerations) are omitted.

---

## Top-line adherence

PyTCP has the **DPLPMTUD engine + UDP manual probe API**
shipped. The TCP probe-segment emit path (which would let
TCP drive the engine through active probing) is deferred to
Phase 3c of the PLPMTUD plan. After the
`plpmtud_unified_engine` plan Phases 1-4 (commits through
`7ad011c1` on `PyTCP_3_0__pre_release`), the RFC 8899 §5
state machine, §5.1 timers/constants, §5.3 binary search,
§6 datagram-transport probe API, and black-hole detection
are all shipped; the §7 cwnd interaction is implementable
once Phase 3c lands the TCP probe-emit path.

| Mechanism                                          | Status                            |
|----------------------------------------------------|-----------------------------------|
| Per-destination MTU cache (`stack.pmtu_cache`)     | met (§4 #9 shared state)          |
| Per-destination engine registry (`stack.pmtu_state`)| met                              |
| UDP `notify_pmtu` callback (classical)             | met                               |
| TCP `_apply_pmtu_update` callback (classical)      | met                               |
| `_effective_pmtu()` socket accessor                | met                               |
| `_udp_no_check6_tx/rx` per-socket opt-in           | met (RFC 6935, not 8899)          |
| §5 BASE/SEARCHING/SEARCH_COMPLETE state machine    | met (`pytcp/lib/plpmtud.py`)      |
| §5.1.1 PROBE_TIMER / PMTU_RAISE_TIMER              | met (module-level constants)      |
| §5.1.2 MIN_PLPMTU / MAX_PLPMTU / BASE_PLPMTU       | met (module-level constants)      |
| §5.3 Binary-search algorithm                       | met (`PmtuSearch._next_candidate`)|
| §6 UDP probe-send / ack / loss API                 | met (`UdpSocket.probe_pmtu` ...)  |
| §6 TCP probe-send / ack / loss API                 | met (Phase 3c-min default-off + 3d Linux-aligned snd_mss growth) |
| §7 Black-hole detection                            | met (`PmtuSearch.on_probe_loss` + ERROR state) |
| §3 #7 Probes excluded from cwnd                    | **Linux-pragmatic deviation** (probes share cwnd; matches Linux tcp_mtu_probing) |

The remaining gap is the TCP TX-path probe-segment emit
(Phase 3c) — the engine and adapter framework are fully in
place and exercised end-to-end from the UDP side. The TCP
adapter's ack/RTO hooks are wired and locked in by
integration tests; the missing piece is the segment-factory
surgery that pads data segments to `candidate_mtu`.

---

## §3 Features Required to Provide Datagram PLPMTUD

The §3 list enumerates 9 numbered requirements (managing
PLPMTU / probe packets / reception feedback / probe loss
recovery / PMTU parameters / processing PTB messages /
probing and congestion control / probing and flow
control / shared PLPMTU state) and several design
principles.

### §3 #1 Managing the PLPMTU

> "A PL MUST NOT send a datagram (other than a probe
> packet) with a size at the PL that is larger than the
> current PLPMTU."

**Adherence:** met for the classical case. UDP TX
fragments (IPv4 DF=0) or fails with EMSGSIZE
(`pytcp/socket/udp__socket.py` send/sendto) when the
datagram exceeds the cached PMTU. TCP TX recomputes
MSS via `_apply_pmtu_update`
(`pytcp/protocols/tcp/tcp__session.py:802-814`) so
subsequent segments respect the cached PMTU. Active
probe-vs-data distinction not yet present (deferred to
plan Phase 3 / 4).

### §3 #2 Probe packets

> "In IPv4, a probe packet MUST be sent with the Don't
> Fragment (DF) bit set in the IP header and without
> network layer endpoint fragmentation. In IPv6, a probe
> packet is always sent without source fragmentation."

**Adherence:** the DF=1 default landed in Phase 8 of
the prior refactor (see commit history for
`packet_handler__ip4__tx.py`). The "without
fragmentation" property is naturally satisfied by
PyTCP's send paths (no kernel-style auto-fragmentation
on TX). Active probe construction is not yet present.

### §3 #3 Reception feedback

> "The destination PL endpoint is REQUIRED to provide a
> feedback method that indicates to the DPLPMTUD sender
> when a probe packet has been received by the
> destination PL endpoint."

**Adherence:** not implemented. The TCP adapter (plan
Phase 3) uses native ACK feedback. The UDP adapter
(plan Phase 4) exposes a manual `ack_probe(size)` API
that applications with their own ACK channel (QUIC,
SCTP, app-level heartbeat) call when their app-layer
ACK confirms the probe arrived; vanilla UDP without
any ACK channel cannot satisfy this requirement and
is honestly unaddressable.

### §3 #4 Probe loss recovery

> "It is RECOMMENDED to use probe packets that do not
> carry any user data that would require retransmission
> if lost."

**Adherence:** not implemented. Plan's TCP adapter
emits probe segments with zero-padding payload (not
user data); UDP adapter emits a sized datagram of
zero-padding (not application data). Both satisfy this
recommendation when implemented.

### §3 #5 PMTU parameters

> "A DPLPMTUD sender is RECOMMENDED to utilize
> information about the maximum size of packet that can
> be transmitted by the sender on the local link (e.g.,
> the local link MTU)."

**Adherence:** met (substrate). `stack.interface_mtu`
is the canonical local-link MTU, consumed by
`_effective_pmtu()`
(`pytcp/socket/__init__.py:592-614`) as the upper
bound and by the TCP MSS option negotiation as the
search-high ceiling.

### §3 #6 Processing PTB messages

> "Any received PTB message MUST be validated before it
> is used to update the PLPMTU discovery information
> [RFC8201]. This validation confirms that the PTB
> message was sent in response to a packet originated
> by the sender and needs to be performed before the
> PLPMTU discovery method reacts to the PTB message."

**Adherence:** met. ICMPv4 Frag-Needed and ICMPv6
Packet-Too-Big handlers
(`packet_handler__icmp4__rx.py`,
`packet_handler__icmp6__rx.py`) extract the embedded
datagram and dispatch only to the matching socket /
TCP session, never blindly applying the MTU value.
4-tuple validation (RFC 5927 §4 sequence guard for
TCP, socket ID match for UDP) is the validation gate
required here.

> "A PTB message MUST NOT be used to increase the
> PLPMTU [RFC8201] but could trigger a probe to test
> for a larger PLPMTU."

**Adherence:** met for the "MUST NOT increase" part —
PyTCP's `_apply_pmtu_update` only writes the cache
when the new value is smaller than the current MSS
(implicit via `shrunk = new_mss < self._win.snd_mss`
gate at `tcp__session.py:812`). The "trigger probe for
larger" half is not implemented (no active probing).

### §3 #7 Probing and congestion control

> "Loss of a probe packet SHOULD NOT be treated as an
> indication of congestion and SHOULD NOT trigger a
> congestion control reaction [RFC4821]."
>
> "An update to the PLPMTU (or MPS) MUST NOT increase
> the congestion window measured in bytes [RFC4821]."

**Adherence:** not implemented (no active probing).
Plan Phase 3 implements the probe-cwnd-exempt
accounting (probes tagged on in-flight record,
`bytes_in_flight()` skips them) and the separate-
probe-RTO mechanism so probe loss doesn't feed
data-path congestion control.

### §3 #9 Shared PLPMTU state

> "The PMTU value calculated from the PLPMTU MAY also be
> stored with the corresponding entry associated with
> the destination in the IP layer cache and used by
> other PL instances."

**Adherence:** met (substrate). `stack.pmtu_cache`
is the per-destination shared cache; both TCP sessions
and UDP sockets read via `_effective_pmtu()`. The
forthcoming `stack.pmtu_state` (plan Phase 2)
generalises this to per-destination search state with
the same shared-across-PL property.

---

## §4 DPLPMTUD Mechanisms

### §4.1 PLPMTU Probe Packets

> "The DPLPMTUD method relies upon the PL sender being
> able to generate probe packets with a specific size."

**Adherence:** not implemented. Plan Phase 3
(`build_probe_segment`) for TCP; Phase 4 (`probe_pmtu(size)`
on `UdpSocket`) for UDP.

### §4.2 Confirmation of Probed PLPMTU

> "DPLPMTUD requires that a sender can confirm that a
> probe packet has been received by the corresponding
> PL receiver."

**Adherence:** not implemented (see §3 #3).

### §4.3 Detection of Unsupported PLPMTU

> "The DPLPMTUD search algorithm needs to robustly
> detect that a current PLPMTU is unsupported by the
> network path."

**Adherence:** not implemented. Plan's
`PmtuSearch.on_probe_loss` + black-hole detection (3
consecutive losses → ERROR state, clamp to MIN_PLPMTU).

### §4.4 Disabling the Effect of PMTUD

> "Applications that wish to disable PMTUD MAY do so by
> setting an IP socket option such as IP_PMTUDISC_DONT
> (Linux)."

**Adherence:** not implemented. `IP_PMTUDISC_*` socket
option family is out of scope for the plan (recorded
in `plpmtud_unified_engine.md` §8 out-of-scope).

### §4.5 Response to PTB Messages

> "A PL_PTB_SIZE that is greater than that currently
> probed SHOULD be ignored."

**Adherence:** met implicitly. PyTCP's PMTU update path
only shrinks the cached MTU; PTB messages reporting a
larger MTU than current are absorbed without effect
because `_apply_pmtu_update` only writes when
`new_mss < self._win.snd_mss`.

---

## §5 Datagram Packetization Layer PMTUD

### §5.1.1 Timers

> "PROBE_TIMER: The PROBE_TIMER is configured to expire
> after a period longer than the maximum time to
> receive an acknowledgment to a probe packet. This
> value MUST NOT be smaller than 1 second and SHOULD be
> larger than 15 seconds."

**Adherence:** not implemented. Plan defaults
PROBE_TIMER to 30 s per RFC 8899 §5.1.1 default.

> "PMTU_RAISE_TIMER: The PMTU_RAISE_TIMER is configured
> to the period a sender will continue to use the
> current PLPMTU, after which it reenters the Search
> Phase. This timer has a period of 600 seconds, as
> recommended by PLPMTUD [RFC4821]."

**Adherence:** not implemented. Plan uses 600 s
default; engine `next_probe_size(now)` returns a value
when PMTU_RAISE_TIMER expires in SEARCH_COMPLETE.

### §5.1.2 Constants

> "MAX_PROBES: The default value of MAX_PROBES is 3."
>
> "MIN_PLPMTU: For IPv6, this size is greater than or
> equal to the size at the PL that results in an
> 1280-byte IPv6 packet. For IPv4, this size is greater
> than or equal to the size at the PL that results in
> an 68-byte IPv4 packet."
>
> "MAX_PLPMTU: This has to be less than or equal to the
> maximum size of the PL packet that can be sent on the
> outgoing interface (constrained by the local
> interface MTU)."
>
> "BASE_PLPMTU: a default BASE_PLPMTU of 1200 bytes is
> RECOMMENDED."

**Adherence:** not implemented. Plan Phase 1 carries
these as module-level constants in `pytcp/lib/plpmtud.py`
with the RFC defaults: `MAX_PROBES = 3`, `MIN_PLPMTU =
1280` (IPv6) / `576` (IPv4 practical floor), `MAX_PLPMTU
= stack.interface_mtu`, `BASE_PLPMTU = 1200`.

### §5.2 State Machine (BASE / SEARCHING / SEARCH_COMPLETE / ERROR)

> "The Base Phase confirms connectivity to the remote
> peer using packets of the BASE_PLPMTU.[...] The Search
> Phase searches for a larger PLPMTU.[...] The Search
> Complete Phase is the steady state.[...] The Error
> Phase indicates that the engine cannot confirm
> connectivity at BASE_PLPMTU."

**Adherence:** not implemented. Plan Phase 1 ships
`PmtuState` enum (DISABLED / BASE / SEARCHING /
SEARCH_COMPLETE / ERROR) and the transition logic.

### §5.3 Search Algorithm (binary search)

> "An implementation could use a binary search algorithm
> to find the PLPMTU. The size of probe packets used in
> the search algorithm SHOULD start with BASE_PLPMTU
> and ramp toward MAX_PLPMTU."

**Adherence:** not implemented. Plan Phase 1 ships
the binary search with 8-byte granularity:
`SEARCH_LOW = ack_size`, `SEARCH_HIGH = max_mtu`,
`candidate = (SEARCH_LOW + SEARCH_HIGH) // 2`,
convergence when `SEARCH_HIGH - SEARCH_LOW < 8`.

---

## §6 Specification of Protocol-Specific Methods

§6 is normative for specific transports (DCCP, SCTP,
QUIC, UDP-Options, UDP). PyTCP implements the §6.4
UDP-Options style API (manual probe / ack / loss
methods on the socket) per the plan Phase 4 — this is
the only path that makes sense for vanilla UDP without
a built-in ACK channel.

**Adherence:** met for UDP. `UdpSocket.probe_pmtu(size)`
emits a zero-padded UDP datagram of the requested size,
`ack_probe()` and `timeout_probe()` drive the engine
forward. Per-socket adapter at
`pytcp/protocols/udp/udp__plpmtud_adapter.py`.

---

## Test coverage audit

The shipped surface is locked in by:

### §3 #5 / §3 #9 / §4.5 per-destination cache + PTB handling

- **Unit:** `pytcp/tests/unit/stack/test__pmtu_cache.py` —
  pins cache shape, lifetime, IPv4/IPv6 keying.
- **Unit:** `pytcp/tests/unit/lib/test__lib__pmtu_state.py`
  (6 tests) — pins the PmtuSearch registry, lazy fallback
  to legacy cache, per-destination isolation, IPv6
  keying.
- **Integration:**
  `pytcp/tests/integration/protocols/icmp4/test__icmp4__pmtud.py`,
  `pytcp/tests/integration/protocols/icmp6/test__icmp6__pmtud.py`,
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__icmp__pmtu.py`
  — ICMP PTB validates + populates cache + drives MSS
  recompute.

**Status:** locked in.

### §5 / §5.1 / §5.2 / §5.3 state machine + constants + search

- **Unit:** `pytcp/tests/unit/lib/test__lib__plpmtud.py`
  (21 tests) — pins the PmtuState transitions (BASE →
  SEARCHING → SEARCH_COMPLETE / ERROR), MAX_PROBES /
  PROBE_TIMER / PMTU_RAISE_TIMER defaults, IPv4 / IPv6
  family floors, binary-search ladder, 8-byte
  granularity convergence, ICMP-coexistence behaviour.

**Status:** locked in.

### §6 datagram-transport probe API (UDP)

- **Unit:** `pytcp/tests/unit/protocols/udp/test__udp__plpmtud_adapter.py`
  (13 tests) — pins `UdpPlpmtudAdapter`'s probe / ack /
  timeout API + single-outstanding invariant.
- **Integration:** `pytcp/tests/integration/protocols/udp/test__udp__plpmtud.py`
  (6 tests) — pins `UdpSocket.probe_pmtu` emit on wire,
  ack/timeout state transitions, MAX_PROBES → ERROR clamp,
  concurrent-probe rejection, unconnected-socket
  rejection.

**Status:** locked in.

### §6 datagram-transport probe API (TCP) — partial

- **Unit:** `pytcp/tests/unit/protocols/tcp/test__tcp__plpmtud_adapter.py`
  (12 tests) — pins `TcpPlpmtudAdapter`'s ack-via-snd.una-
  advance and loss-via-RTO dispatch.
- **Integration:** `pytcp/tests/integration/protocols/tcp/test__tcp__session__plpmtud_wiring.py`
  (5 tests) — pins TcpSession adapter wiring + classical
  PMTU route + snd.una advance hook.

**Status:** locked in for ack/loss feedback paths; probe-
emit path deferred to Phase 3c.

### §7 black-hole detection

- **Unit:** `test__plpmtud__three_consecutive_losses_enter_error`
  in `test__lib__plpmtud.py`.
- **Unit:** `test__tcp__plpmtud_adapter__rto_max_probes_enters_error`
  in `test__tcp__plpmtud_adapter.py`.
- **Integration:** `test__udp__plpmtud__timeout_probe_count_enters_error`
  in `test__udp__plpmtud.py`.

**Status:** locked in.

### §3 #7 cwnd-exempt probes — Phase 3c gap

**No test surface — TCP probe-emit path not yet shipped.**
The adapter's `in_flight_probe_sizes` snapshot is in place
for the consumer; the natural future test name is
`test__tcp__plpmtud__bytes_in_flight_excludes_probe_segment`.

### Test coverage summary

| Aspect                                              | Coverage                  |
|-----------------------------------------------------|---------------------------|
| §3 #5 Local-link MTU / max-size hint                | locked in                 |
| §3 #6 PTB validation                                | locked in                 |
| §3 #9 Per-destination shared state                  | locked in                 |
| §3 #7 Probe-cwnd exemption                          | n/a (Phase 3c gap)        |
| §4.1 Probe-packet generation (UDP)                  | locked in                 |
| §4.1 Probe-packet generation (TCP)                  | n/a (Phase 3c gap)        |
| §4.3 Unsupported-PLPMTU detection                   | locked in                 |
| §4.6.4 BASE_PLPMTU floor                            | locked in                 |
| §5.1.1 Timer machinery                              | locked in                 |
| §5.2 State machine                                  | locked in                 |
| §5.3 Binary-search algorithm                        | locked in                 |
| §6 UDP-specific probe / ack / loss API              | locked in                 |
| §7 Black-hole detection                             | locked in                 |

---

## Overall assessment

| Aspect                                              | Status                       |
|-----------------------------------------------------|------------------------------|
| §3 #5/#9 / §4.5 Per-destination MTU cache + state   | met                          |
| §3 #6 PTB-message validation                        | met                          |
| §3 #1 Non-probe size enforcement                    | met                          |
| §3 #2 IPv4 DF=1 / IPv6 no-fragmentation on probe    | met for non-probe; TCP probe path deferred (Phase 3c) |
| §3 #3 Reception feedback                            | met for UDP (manual API); met for TCP (snd.una hook for ack/loss) |
| §3 #7 Probes excluded from cwnd                     | **Linux-pragmatic deviation** (probes share cwnd; matches Linux tcp_mtu_probing) |
| §4.1 Probe packet generation                        | met for UDP; met for TCP (Phase 3c-min default-off) |
| §4.3 Unsupported-PLPMTU detection                   | met                          |
| §4.6.4 BASE_PLPMTU floor enforcement                | met                          |
| §5.1.1 PROBE_TIMER / PMTU_RAISE_TIMER               | met                          |
| §5.1.2 MIN/MAX/BASE_PLPMTU constants                | met                          |
| §5.2 BASE/SEARCHING/SEARCH_COMPLETE/ERROR state machine | met                      |
| §5.3 Binary-search algorithm                        | met                          |
| §6 UDP-specific probe / ack / loss API              | met                          |
| §7 Black-hole detection                             | met                          |
| §4.4 IP_PMTUDISC socket option                      | not implemented (out of scope) |

**Principal gap (deliberate):** RFC §3 #7 cwnd-exempt
probe accounting is a deliberate Linux-pragmatic
deviation. Linux probes share cwnd / regular RTO (no
separate probe-RTO timer); shipped for ~15 years without
operational harm. The compliance posture is "met
(Linux-pragmatic, RFC §3 #7 strict deviation documented)."
All other DPLPMTUD mechanisms (engine, state machine,
adapter framework, ack/RTO feedback, UDP manual API,
TCP probe-segment emit + snd_mss growth on probe-ack)
are shipped.
