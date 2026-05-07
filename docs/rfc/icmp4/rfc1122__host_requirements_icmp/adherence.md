# RFC 1122 §3.2.2 — Host Requirements (ICMP)

| Field       | Value                                                                    |
|-------------|--------------------------------------------------------------------------|
| RFC number  | 1122                                                                     |
| Title       | Requirements for Internet Hosts -- Communication Layers                  |
| Section     | §3.2.2 (Internet Control Message Protocol -- ICMP)                       |
| Category    | Internet Standard (STD 3)                                                |
| Date        | October 1989                                                             |
| Source text | [`rfc1122.txt`](../../tcp/rfc1122__host_requirements/rfc1122.txt) §3.2.2 |

This document records, paragraph by paragraph, how the current
PyTCP codebase relates to each normative statement of RFC 1122
§3.2.2 (the ICMP host requirements). The §3.2.2 sub-sections are
audited individually. The §4 TCP sub-sections of RFC 1122 are
audited under
[`docs/rfc/tcp/rfc1122__host_requirements/`](../../tcp/rfc1122__host_requirements/adherence.md).

The audit was performed by reading the RFC text fresh and
inspecting the codebase under `pytcp/` and `net_proto/` directly.
Adherence levels use the canonical descriptive language: **met**,
**not met**, **partial**, **not implemented**, **vacuous**, or
**deliberate non-implementation** (for paragraphs whose subject was
deprecated by a later RFC and whose absence is intentional).

Sections without normative content (Introduction, headings,
Discussion / Implementation commentary) are skipped; the per-section
audit lists only the normative statements that apply to a host stack
PyTCP currently models.

---

## §3.2.2 — General ICMP rules

> "If an ICMP message of unknown type is received, it MUST be
> silently discarded."

**Adherence:** **met**. `Icmp4Parser._message_class()` resolves
unknown type bytes to `Icmp4MessageUnknown`
(`net_proto/protocols/icmp4/icmp4__parser.py:79-93`); the RX
handler routes to `__phrx_icmp4__unknown` which logs and bumps the
`icmp4__unknown` counter
(`pytcp/stack/packet_handler/packet_handler__icmp4__rx.py:111,315-324`).
No reply is emitted.

> "Every ICMP error message includes the Internet header and at
> least the first 8 data octets of the datagram that triggered the
> error; more than 8 octets MAY be sent; this header and data MUST
> be unchanged from the received datagram."

**Adherence:** **met**. The `Icmp4MessageDestinationUnreachable`
dataclass truncates `data` to
`IP4__MIN_MTU - IP4__HEADER__LEN - ICMP4__DESTINATION_UNREACHABLE__LEN`
= 548 bytes
(`net_proto/protocols/icmp4/message/icmp4__message__destination_unreachable.py:163-168`),
which is the full original IP header + at least 8 octets of payload
up to the 576-byte MIN_MTU cap mandated by RFC 1812 §4.3.2.3. The
UDP closed-port emitter passes `packet_rx.ip.packet_bytes`
verbatim, so the bytes are unchanged
(`pytcp/stack/packet_handler/packet_handler__udp__rx.py:201`).

> "In those cases where the Internet layer is required to pass an
> ICMP error message to the transport layer, the IP protocol number
> MUST be extracted from the original header and used to select the
> appropriate transport protocol entity to handle the error."

**Adherence:** **met** for Destination Unreachable. The shared
embedded-L4 demux at
`pytcp/stack/packet_handler/_icmp_error_demux.py::parse_embedded_l4`
extracts the L4 protocol from the embedded IP header and routes
UDP to `UdpSocket.notify_*` and TCP to `TcpSession.on_unreachable`
(`pytcp/stack/packet_handler/packet_handler__icmp4__rx.py:181-192`).
Time Exceeded and Parameter Problem are not yet routed because
those message types are not yet parsed (see §3.2.2.4 / §3.2.2.5
below).

> "An ICMP error message SHOULD be sent with normal (i.e., zero)
> TOS bits."

**Adherence:** **vacuous**. PyTCP does not model TOS variation on
outbound ICMP errors; the IPv4 TX path emits TOS=0 by default
(`pytcp/stack/packet_handler/packet_handler__icmp4__tx.py:108-112`,
delegating to `_phtx_ip4` without a non-zero `ip4__ecn` /
`ip4__dscp`).

> "An ICMP error message MUST NOT be sent as the result of
> receiving:
> - an ICMP error message, or
> - a datagram destined to an IP broadcast or IP multicast address, or
> - a datagram sent as a link-layer broadcast, or
> - a non-initial fragment, or
> - a datagram whose source address does not define a single host -- e.g., a zero address, a loopback address, a broadcast address, a multicast address, or a Class E address."

**Adherence:** **met** (post-α1.1). The five gates are encoded as
`IcmpErrorBlockReason` values and applied via `should_emit_icmp_error()`
+ `try_emit_icmp_error()` in
`pytcp/protocols/icmp/icmp__error_emitter.py`. The inbound classifier
at `pytcp/protocols/icmp/icmp__inbound_classifier.py::classify_inbound`
extracts the IP-layer state (limited-broadcast destination,
multicast destination, loopback/multicast/Class-E source, non-
initial fragment) into an `IcmpErrorContext`. The UDP closed-port
Port-Unreachable emitter routes through the gate at
`pytcp/stack/packet_handler/packet_handler__udp__rx.py:179-194`.
The "datagram sent as a link-layer broadcast" sub-rule is not
explicitly modeled — the closest proxy is `is_limited_broadcast` on
the IP destination, since the test harness and the production stack
both deliver L2-broadcast frames to the IP layer with the broadcast
IP destination preserved. The "ICMP error in response to ICMP
error" sub-rule is currently latent: today the only ICMP error
emitter is the UDP closed-port path, which never fires for an
inbound ICMP error (the inbound was UDP). The gate is wired and
will fire correctly when future error generators (§3.2.2.4 /
§3.2.2.5) are added.

---

## §3.2.2.1 — Destination Unreachable

> "The following additional codes are hereby defined: 6-12 ..."

**Adherence:** **met**. `Icmp4DestinationUnreachableCode` enum
covers all 16 codes (0-15)
(`net_proto/protocols/icmp4/message/icmp4__message__destination_unreachable.py:79-99`),
including the seven RFC 1122 additions (NETWORK_UNKNOWN,
HOST_UNKNOWN, SOURCE_HOST_ISOLATED, NETWORK_PROHIBITED,
HOST_PROHIBITED, NETWORK_TOS, HOST_TOS) plus the RFC 1812
extensions (COMMUNICATION_PROHIBITED, HOST_PRECEDENCE,
PRECEDENCE_CUTOFF).

> "A host SHOULD generate Destination Unreachable messages with
> code: 2 (Protocol Unreachable), when the designated transport
> protocol is not supported"

**Adherence:** **not implemented**. The IPv4 RX path drops packets
of unknown protocol with `ip4__no_proto_support__drop` but does
not emit a Protocol Unreachable
(`pytcp/stack/packet_handler/packet_handler__ip4__rx.py:160-165`).

> "A host SHOULD generate Destination Unreachable messages with
> code: 3 (Port Unreachable), when the designated transport
> protocol (e.g., UDP) is unable to demultiplex the datagram"

**Adherence:** **met**. `pytcp/stack/packet_handler/packet_handler__udp__rx.py:194-204`
emits `Icmp4DestinationUnreachableCode.PORT` when no UDP socket
matches, subject to the §3.2.2 gates above.

> "A Destination Unreachable message that is received MUST be
> reported to the transport layer."

**Adherence:** **met**.
`__phrx_icmp4__destination_unreachable` parses the embedded L4 and
routes to either `UdpSocket.notify_*` or
`TcpSession.on_unreachable`
(`pytcp/stack/packet_handler/packet_handler__icmp4__rx.py:149-192`).

> "A transport protocol that has its own mechanism for notifying
> the sender that a port is unreachable (e.g., TCP, which sends RST
> segments) MUST nevertheless accept an ICMP Port Unreachable for
> the same purpose."

**Adherence:** **met**.
`TcpSession.on_unreachable(icmp_type=3, icmp_code=3)` surfaces
`ConnError.REFUSED` to the socket layer
(`pytcp/protocols/tcp/tcp__session.py`); the
`pytcp/tests/integration/protocols/tcp/test__tcp__session__on_unreachable.py`
suite pins this behaviour.

> "A Destination Unreachable message that is received with code
> 0 (Net), 1 (Host), or 5 (Bad Source Route) may result from a
> routing transient and MUST therefore be interpreted as only a
> hint, not proof, that the specified destination is unreachable."

**Adherence:** **partial**. We accept and report these codes to
the transport layer the same way as 3 (Port). We do not
specifically distinguish "hint" vs "proof" semantics — TCP treats
all Destination Unreachable codes uniformly via
`on_unreachable(icmp_type, icmp_code)`. The "MUST NOT be used as
proof of a dead gateway" sub-rule is moot because PyTCP does not
implement gateway-deadness tracking (see §3.3.1).

---

## §3.2.2.2 — Redirect

> "A host SHOULD NOT send an ICMP Redirect message; Redirects are
> to be sent only by gateways."

**Adherence:** **met** (deliberate). PyTCP does not generate ICMPv4
Redirect messages. There is no Redirect TX path.

> "A host receiving a Redirect message MUST update its routing
> information accordingly."

**Adherence:** **not implemented**. ICMPv4 type 5 (Redirect) is not
declared in `Icmp4Type`; inbound Redirects route to
`Icmp4MessageUnknown` and are silently dropped without updating
any routing state. PyTCP's routing model is single-gateway per
host, so the missing Redirect handler does not currently violate
correctness in the deployments PyTCP targets, but the SHOULD-
support rule is not met.

> "A Redirect message SHOULD be silently discarded if the new
> gateway address it specifies is not on the same connected
> (sub-) net through which the Redirect arrived [...] or if the
> source of the Redirect is not the current first-hop gateway"

**Adherence:** **vacuous** (not implemented). Inherits the §3.2.2.2
non-implementation above.

---

## §3.2.2.3 — Source Quench

> "A host MAY send a Source Quench message [...]"
> "If a Source Quench message is received, the IP layer MUST
> report it to the transport layer."

**Adherence:** **deliberate non-implementation**. RFC 6633
deprecated Source Quench in 2012. PyTCP does not generate Source
Quench, and inbound Source Quench (ICMPv4 type 4) routes to
`Icmp4MessageUnknown` and is silently dropped — consistent with
RFC 6633 §1 ("the only acceptable behaviour is to ignore [Source
Quench] messages"). The non-implementation is intentional, not a
gap.

---

## §3.2.2.4 — Time Exceeded

> "An incoming Time Exceeded message MUST be passed to the transport
> layer."

**Adherence:** **partial** (post Phase β.1 — parser only). ICMPv4
type 11 is now declared in `Icmp4Type` and routes to
`Icmp4MessageTimeExceeded`
(`net_proto/protocols/icmp4/message/icmp4__message__time_exceeded.py`),
parsed cleanly with integrity / sanity / round-trip tests. The
remaining gap is the MUST-pass-to-transport-layer wire-up: the
`packet_handler__icmp4__rx.py` dispatch still has no
`__phrx_icmp4__time_exceeded` arm, so a successfully-parsed Time
Exceeded message is currently dropped after parsing. Phase β.2
adds the dispatch arm + `TcpSession.on_time_exceeded` /
`UdpSocket.notify_time_exceeded` plumbing, after which this clause
flips to **met**.

---

## §3.2.2.5 — Parameter Problem

> "A host SHOULD generate Parameter Problem messages."

**Adherence:** **not implemented**. PyTCP does not generate ICMPv4
Parameter Problem messages.

> "An incoming Parameter Problem message MUST be passed to the
> transport layer, and it MAY be reported to the user."

**Adherence:** **not met**. Same gap shape as §3.2.2.4: ICMPv4 type
12 is not declared in `Icmp4Type`; inbound Parameter Problem
routes to Unknown and is silently dropped. Phase β closes this
together with Time Exceeded.

---

## §3.2.2.6 — Echo Request/Reply

> "Every host MUST implement an ICMP Echo server function that
> receives Echo Requests and sends corresponding Echo Replies."

**Adherence:** **met**.
`__phrx_icmp4__echo_request`
(`pytcp/stack/packet_handler/packet_handler__icmp4__rx.py:290-323`)
emits an `Icmp4MessageEchoReply` for every accepted Echo Request.

> "An ICMP Echo Request destined to an IP broadcast or IP multicast
> address MAY be silently discarded."

**Adherence:** **met** (we exercise the MAY as a drop). The Smurf-
mitigation gate at
`pytcp/stack/packet_handler/packet_handler__icmp4__rx.py:300-310`
calls
`pytcp/protocols/icmp4/icmp4__echo_gate.py::should_emit_echo_reply`
with the destination's broadcast/multicast flags. The MUST form of
this rule appears as RFC 1812 §4.3.3.6 (router requirements);
PyTCP applies the stricter router-grade rule even though it is a
host, because the same Smurf-amplification attack vector applies.

> "The IP source address in an ICMP Echo Reply MUST be the same as
> the specific-destination address of the corresponding ICMP Echo
> Request message."

**Adherence:** **met**. The TX call uses
`ip4__src=packet_rx.ip4.dst`
(`pytcp/stack/packet_handler/packet_handler__icmp4__rx.py:317-318`),
reflecting the Echo Request destination back as the Reply source.

> "Data received in an ICMP Echo Request MUST be entirely included
> in the resulting Echo Reply."

**Adherence:** **met**. The Reply construction copies
`packet_rx.icmp4.message.data` verbatim
(`pytcp/stack/packet_handler/packet_handler__icmp4__rx.py:320-324`).

> "However, if sending the Echo Reply requires intentional
> fragmentation that is not implemented, the datagram MUST be
> truncated to maximum transmissible size and sent."

**Adherence:** **vacuous**. PyTCP's IPv4 TX path supports outbound
fragmentation (post the RFC 791 §3.1 DF-honoring change in commit
`08c6776c`), so the truncation fallback is not required.

> "An Echo Reply MUST be returned with the same Data field as
> received in the Echo Request. [...] An ICMP Echo Reply SHOULD
> echo all options received in the Echo Request."

**Adherence:** **partial**. Data is echoed verbatim; IPv4 options
are NOT echoed because the RX path does not currently parse and
forward IPv4 options through to the Echo Reply construction.

---

## §3.2.2.7 — Information Request/Reply

> Information Request/Reply (RFC 792) is obsolete per RFC 1122
> §3.2.2.7 ("A host SHOULD NOT implement these messages.").

**Adherence:** **deliberate non-implementation**. PyTCP does not
implement Information Request/Reply (ICMPv4 types 15/16). Inbound
messages route to `Icmp4MessageUnknown` and are silently dropped.

---

## §3.2.2.8 — Timestamp and Timestamp Reply

> "A host MAY implement Timestamp and Timestamp Reply."

**Adherence:** **deliberate non-implementation**. RFC 6633 §3
deprecated Timestamp messages. PyTCP does not implement types
13/14; inbound messages route to `Icmp4MessageUnknown` and are
silently dropped.

---

## §3.2.2.9 — Address Mask Request/Reply

> "A host MUST support the first, and MAY implement all three of the
> following methods for determining the address mask(s) [...]"

**Adherence:** **deliberate non-implementation** for ICMP-based
mask discovery (types 17/18). RFC 6633 §4 deprecated Address Mask
Request/Reply. PyTCP obtains its address configuration via DHCPv4
(the "first method" in the RFC 1122 list — static / boot-server
configuration) and does not implement the ICMP-based mask
discovery alternative.

---

## Test coverage audit

### §3.2.2 General gates (5 MUST NOT rules)

- **Unit:**
  `pytcp/tests/unit/protocols/icmp/test__icmp__error_emitter__gates.py::TestShouldEmitIcmpError__Block`
  — 5 parametrized cases, one per gate (`INBOUND_WAS_ICMP_ERROR`,
  `INBOUND_DST_IS_BROADCAST`, `INBOUND_DST_IS_MULTICAST`,
  `INBOUND_SRC_INVALID`, `INBOUND_NON_INITIAL_FRAGMENT`), pinning
  the verdict reason returned by `should_emit_icmp_error()`.
- **Unit:**
  `pytcp/tests/unit/protocols/icmp/test__icmp__error_emitter__try_emit.py::TestTryEmitIcmpError__GateBlock`
  — gate-block returns the gate reason, does not consume a
  rate-limiter token.
- **Unit:**
  `pytcp/tests/unit/protocols/icmp/test__icmp__inbound_classifier.py::TestClassifyInbound__Ip4SrcInvalid`,
  `TestClassifyInbound__Ip4DstClassification`,
  `TestClassifyInbound__Ip4Fragment`
  — pin the IP-layer to context-flag mapping.
- **Integration:**
  `pytcp/tests/integration/protocols/icmp4/test__icmp4__error_gates.py::TestIcmp4ErrorGates__Suppressed`
  — drives a forged UDP-to-closed-port frame with broadcast dst /
  loopback src and asserts no Port-Unreachable emerges.

**Status:** **locked in** (multiple dedicated tests).

### §3.2.2 Unknown-type silent discard

- **Locked in indirectly** by every parser-roundtrip test: any
  unrecognised type byte routes to `Icmp4MessageUnknown` and the
  `__phrx_icmp4__unknown` handler bumps the counter without
  emitting a reply.

**Status:** **locked in indirectly** (no dedicated dropped-type
test, but the surrounding parser dispatch is fully exercised).

### §3.2.2 Embedded-original-datagram unchanged

- **Integration:**
  `pytcp/tests/integration/test__packet_handler__udp__rx.py::TestPacketHandlerUdpRx_*` (golden-frame cases)
  — pin the byte-for-byte content of the emitted Port-Unreachable,
  including the embedded IP header + first 8 octets of the
  triggering UDP segment.

**Status:** **locked in**.

### §3.2.2.1 Destination Unreachable — Code 3 emission

- **Integration:**
  `pytcp/tests/integration/test__packet_handler__udp__rx.py` (the
  v4 closed-port golden) — full byte-equality on the emitted ICMPv4
  Port-Unreachable.
- **Integration:**
  `pytcp/tests/integration/protocols/icmp4/test__icmp4__error_gates.py::TestIcmp4ErrorGates__CleanUnicast`
  — pins that clean unicast still emits Port-Unreachable post-α1.1.

**Status:** **locked in**.

### §3.2.2.1 Destination Unreachable — TCP MUST accept

- **Integration:**
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__on_unreachable.py`
  — drives an ICMPv4 Port Unreachable matching a SYN_SENT and pins
  `ConnError.REFUSED`.

**Status:** **locked in**.

### §3.2.2.6 Echo server (unicast)

- **Integration:**
  `pytcp/tests/integration/protocols/icmp4/test__icmp4__echo_request_smurf.py::TestIcmp4EchoSmurf__UnicastRegression`
  — drives a unicast Echo Request and pins that the Echo Reply
  reflects the request id / data.

**Status:** **locked in**.

### §3.2.2.6 Echo Smurf-mitigation drop

- **Unit:**
  `pytcp/tests/unit/protocols/icmp4/test__icmp4__echo_gate.py::TestShouldEmitEchoReply__Block`
  — 3 cases pinning that broadcast / multicast / both destination
  flags suppress the reply at the gate level.
- **Integration:**
  `pytcp/tests/integration/protocols/icmp4/test__icmp4__echo_request_smurf.py::TestIcmp4EchoSmurf__BroadcastSuppressed`
  — drives a forged limited-broadcast Echo Request and pins that no
  reply is emitted, the suppression counter bumps, and the success
  counter stays zero.

**Status:** **locked in**.

### §3.2.2.4 / §3.2.2.5 — gaps not yet closed

**No test surface — gap not yet closed.** When Phase β closes
TIME_EXCEEDED (type 11) and PARAMETER_PROBLEM (type 12), the
natural tests are:

1. A unit test for the new `Icmp4MessageTimeExceeded` /
   `Icmp4MessageParameterProblem` parser dispatch (verifies the
   type byte routes away from `Icmp4MessageUnknown`).
2. An integration test that drives an inbound Time Exceeded carrying
   an embedded TCP segment matching an active session and asserts
   `TcpSession.on_time_exceeded` (or equivalent generalized
   `on_icmp_error`) is invoked.

### §3.2.2.2 Redirect inbound — gap not yet closed

**No test surface.** PyTCP's single-gateway routing model makes
Redirect handling architecturally optional; deferring without a
test commitment until the routing layer adds multi-gateway
support.

### Test coverage summary

| Aspect                                    | Coverage  |
|-------------------------------------------|-----------|
| §3.2.2 general gates (5 MUST NOT rules)   | locked in |
| §3.2.2 unknown-type silent discard        | indirect  |
| §3.2.2 embedded-datagram unchanged        | locked in |
| §3.2.2.1 Code 3 Port Unreachable emission | locked in |
| §3.2.2.1 TCP MUST accept Port Unreachable | locked in |
| §3.2.2.6 Echo server (unicast)            | locked in |
| §3.2.2.6 Echo Smurf-mitigation drop       | locked in |
| §3.2.2.4 Time Exceeded inbound            | n/a (gap) |
| §3.2.2.5 Parameter Problem inbound        | n/a (gap) |
| §3.2.2.2 Redirect inbound                 | n/a (gap) |

---

## Overall assessment

| Aspect                                              | Status                |
|-----------------------------------------------------|-----------------------|
| §3.2.2 unknown-type silent discard                  | met                   |
| §3.2.2 embedded-datagram unchanged                  | met                   |
| §3.2.2 ICMP-error generation gates (5 MUST NOTs)    | met                   |
| §3.2.2 TOS=0 on errors                              | vacuous               |
| §3.2.2.1 Codes 6-12 defined                         | met                   |
| §3.2.2.1 SHOULD generate Code 2 (Protocol Unreach.) | not implemented       |
| §3.2.2.1 SHOULD generate Code 3 (Port Unreach.)     | met                   |
| §3.2.2.1 MUST report to transport                   | met                   |
| §3.2.2.1 TCP MUST accept Port Unreachable           | met                   |
| §3.2.2.1 Code 0/1/5 hint-not-proof                  | partial               |
| §3.2.2.2 SHOULD NOT generate Redirect               | met (deliberate)      |
| §3.2.2.2 MUST process inbound Redirect              | not implemented       |
| §3.2.2.3 Source Quench                              | deliberate (RFC 6633) |
| §3.2.2.4 MUST pass Time Exceeded to transport       | partial (β.1 parsed)  |
| §3.2.2.5 MUST pass Param Problem to transport       | not met (Phase β)     |
| §3.2.2.5 SHOULD generate Param Problem              | not implemented       |
| §3.2.2.6 MUST implement Echo server                 | met                   |
| §3.2.2.6 MAY discard Echo to bcast/mcast            | met (Smurf drop)      |
| §3.2.2.6 src-address selection                      | met                   |
| §3.2.2.6 Data echoed verbatim                       | met                   |
| §3.2.2.6 IP options echoed                          | partial (data only)   |
| §3.2.2.7 Information Req/Reply                      | deliberate (obsolete) |
| §3.2.2.8 Timestamp                                  | deliberate (RFC 6633) |
| §3.2.2.9 Address Mask                               | deliberate (RFC 6633) |

The principal compliance gap is §3.2.2.4 / §3.2.2.5 — Time Exceeded
and Parameter Problem inbound are silently dropped because the
message types are not declared in `Icmp4Type`. Phase β closes both
in lockstep, with the demux plumbing inheriting the
`parse_embedded_l4` infrastructure already used by Destination
Unreachable. Secondary gaps are §3.2.2.1 Code 2 (Protocol
Unreachable) generation, §3.2.2.2 inbound Redirect handling
(architecturally tied to the single-gateway routing model), and
§3.2.2.6 IPv4 option echoing.
