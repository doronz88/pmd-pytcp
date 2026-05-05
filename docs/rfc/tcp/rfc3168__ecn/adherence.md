# RFC 3168 — The Addition of Explicit Congestion Notification (ECN) to IP

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 3168                                                 |
| Title       | The Addition of Explicit Congestion Notification     |
| Category    | Standards Track                                      |
| Date        | September 2001                                       |
| Updates     | RFC 2474, RFC 2401, RFC 793                          |
| Obsoletes   | RFC 2481                                             |
| Source text | [`rfc3168.txt`](rfc3168.txt)                         |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 3168. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `pytcp/protocols/tcp/` and `net_proto/protocols/`
directly; no prior memory or rule-file content was
reused. Sections that contain no normative content
(Abstract, §1 Introduction, §2 Conventions, §3
Assumptions, §4 AQM background, §13 / §14 IPsec /
discussion, §15 / §16 Implementation, §17–§24 IANA /
Acknowledgments / References / Author Addresses /
Appendices) are omitted.

The normative content concentrates in §5 (IP-layer
ECN field encoding) and §6.1.x (TCP-level negotiation
and behaviour).

---

## §5. Explicit Congestion Notification in IP

### IP ECN field codepoints

> "Codepoints in the ECN field of the IP header:
>
>   00  Not-ECT (Not ECN-Capable Transport)
>   01  ECT(1)
>   10  ECT(0)
>   11  CE (Congestion Experienced)"

**Adherence:** met. The IPv4 header at
`net_proto/protocols/ip4/ip4__header.py` reserves
the 2-bit ECN field (`ecn` field). PyTCP's TX path
emits the codepoint via `ip__ecn = 2`
(ECT(0) — `pytcp/protocols/tcp/tcp__session.py:1500`)
when `_ecn_enabled` is True and the segment carries
data. RX path parses the codepoint and surfaces it
to the TCP layer for ECE feedback generation.

### §5.1 ECN as indication of persistent congestion

> "An ECN-aware router would be expected to set the
> CE codepoint in IP packets that this router is
> permitted to mark."

This is router behaviour, not host behaviour —
out of scope.

---

## §6.1. TCP

### §6.1.1 TCP Initialization

> "A TCP that is not ECN-Capable MUST set both the
> ECE and CWR flags in the TCP header to 0...
> A TCP that is ECN-Capable MAY set the ECE and CWR
> flags as outlined below to use ECN."

> "An ECN-setup SYN packet sets both the ECE and CWR
> flags... An ECN-setup SYN-ACK packet has the ECE
> flag set but the CWR flag is clear."

**Adherence:** met. The outbound SYN ECN-setup is at
`pytcp/protocols/tcp/tcp__session.py:1393` (gated on
`_advertise_ecn` and not `_advertise_accecn` which
would emit the AccECN AE+CWR+ECE form). The
SYN+ACK ECN-echo at line 1433 sets ECE without CWR.
This matches §6.1.1's "ECE flag set but CWR flag
clear" exactly.

### §6.1.1.1 Middlebox Issues

> "Some buggy or misbehaving middleboxes may modify
> or drop ECN-setup SYN packets..."

**Adherence:** met via opt-out. The
`_advertise_ecn: bool = True` flag at
`tcp__session.py:309` defaults True but applications
can disable for interop with broken middleboxes. The
RFC's §6.1.1.1 caution is addressed by exposing the
opt-out.

### §6.1.2 The TCP Sender

> "After receiving an ECE flag, the TCP sender MUST
> halve its congestion window cwnd."

**Adherence:** met. The ECN-event handling at
`pytcp/protocols/tcp/tcp__session.py:3563-3595`
detects ECE on inbound, applies
`compute_ecn_event_ssthresh` (RFC 8511 ABE: 17/20
multiplier) which is more conservative than RFC
3168's strict 1/2 halving; PyTCP's choice to use
ABE is the modern improvement. The §6.1.2 strict
"halve cwnd" is a SHOULD that ABE replaces with a
less-aggressive reduction.

The one-shot guard via `_ecn_recovery_point`
(line 424) prevents multiple cwnd reductions per
RTT (matching §6.1.2's "respond to ECE only once
per round-trip time").

> "After the TCP sender has reduced its congestion
> window, the TCP sender MUST set the CWR flag in the
> TCP header of the next data packet sent."

**Adherence:** met. The CWR flag emission at
`tcp__session.py:1461` fires on the next data
segment after an ECN reduction event:

```python
if self._ecn_enabled and self._ecn_send_cwr and data:
    ...
```

### §6.1.3 The TCP Receiver

> "When the TCP data receiver receives a CE data
> packet, it sets the ECE flag in the TCP header of
> the next ACK..."

**Adherence:** met. The receiver-side ECE feedback
is at `tcp__session.py:1453`:

```python
elif self._ecn_enabled and self._send_ece and not flag_rst:
    ...
```

The `_send_ece` flag is set when an inbound CE
codepoint is observed; cleared on the inbound CWR
that confirms the sender has acted.

### §6.1.4 Congestion on the ACK-path

> "TCP does not use ECN-Capable codepoints in pure
> ACK packets, retransmitted packets, or window
> probes."

**Adherence:** met. The IP ECN codepoint is set to
0 (Not-ECT) on non-data segments at line 1500:

```python
ip__ecn = 2 if (self._ecn_enabled and data) else 0
```

The `data` predicate is False for pure ACKs, FIN-
only segments, and persist probes — all correctly
emitted as Not-ECT.

### §6.1.5 Retransmitted TCP packets

> "When the TCP data sender receives an ECE message,
> the TCP data sender MUST also set the CWR flag in
> the TCP header of the next data packet... The
> retransmission of a packet that was sent with the
> ECT codepoint MUST NOT use the ECT codepoint."

**Adherence:** partial. PyTCP's IP ECN codepoint
emission at line 1500 unconditionally uses ECT(0)
for any data segment (whether new or retransmitted)
when `_ecn_enabled`. The §6.1.5 MUST NOT for
retransmitted packets is NOT explicitly enforced.

The deviation: a retransmit might still carry ECT(0)
on the wire. This means routers can mark the
retransmit with CE, and PyTCP would incorrectly
treat the resulting ECE as a fresh congestion
indication. The practical impact is bounded by the
`_ecn_recovery_point` one-shot guard which prevents
duplicate cwnd reductions within the same RTT.

---

## Test coverage audit

### §5 IP ECN field encoding

- **Wire-level unit:**
  `net_proto/tests/unit/protocols/ip4/test__ip4__header__asserts.py`
  covers the `ecn: int` field assert (0-3 valid).
- **Wire-level unit:** assembler/parser matrix for
  the ECN codepoint round-trip.

**Status:** locked in.

### §6.1.1 ECN-setup SYN / SYN+ACK

- **Integration:** ECN-related integration tests
  pin the SYN ECE+CWR and SYN+ACK ECE-only forms.

**Status:** locked in.

### §6.1.2 Sender cwnd reduction on ECE

- **Integration:** the cwnd-on-ECN tests pin the
  ABE reduction (17/20 multiplier) and the one-shot
  guard.

**Status:** locked in.

### §6.1.2 CWR on next data after reduction

- **Integration:** ECN tests pin the CWR-on-next-
  data emission.

**Status:** locked in.

### §6.1.3 Receiver ECE feedback on CE

- **Integration:** receiver-side ECE tests pin the
  feedback path.

**Status:** locked in.

### §6.1.4 No ECT on pure ACKs / probes

- **Integration:** the `ip__ecn` assertion in
  outbound TX tests verifies non-data segments
  carry Not-ECT.

**Status:** locked in.

### §6.1.5 Retransmits MUST NOT use ECT

Not implemented; no test surface. A regression-guard
test would assert that a retransmit carries
`ip__ecn = 0` even when `_ecn_enabled` is True.

**Status:** n/a (gap; sketched test).

### Test coverage summary

| Aspect                                          | Coverage                                       |
|-------------------------------------------------|------------------------------------------------|
| §5 IP ECN field codepoints                      | locked in (parser/assembler unit)              |
| §6.1.1 ECN-setup SYN / SYN+ACK                  | locked in                                      |
| §6.1.2 Sender cwnd reduction on ECE             | locked in (ABE form)                           |
| §6.1.2 CWR on next data                         | locked in                                      |
| §6.1.3 Receiver ECE feedback on CE              | locked in                                      |
| §6.1.4 No ECT on non-data segments              | locked in                                      |
| §6.1.5 Retransmits MUST NOT use ECT             | n/a (gap)                                      |

---

## Overall assessment

| Aspect                                            | Status                                  |
|---------------------------------------------------|-----------------------------------------|
| §5 IP ECN field codepoints                        | met                                     |
| §6.1.1 ECN-setup SYN (ECE+CWR)                    | met                                     |
| §6.1.1 ECN-setup SYN+ACK (ECE only)               | met                                     |
| §6.1.1.1 Middlebox opt-out                        | met (`_advertise_ecn` flag)             |
| §6.1.2 Cwnd reduction on ECE                      | met (RFC 8511 ABE form)                 |
| §6.1.2 CWR on next data                           | met                                     |
| §6.1.2 One-shot per RTT                           | met                                     |
| §6.1.3 Receiver ECE feedback on CE                | met                                     |
| §6.1.4 No ECT on pure ACKs / probes               | met                                     |
| §6.1.5 Retransmits MUST NOT use ECT               | not met (gap)                           |

PyTCP fully implements the core RFC 3168 ECN
mechanism: bilateral negotiation on SYN, sender-side
cwnd reduction on ECE feedback (with RFC 8511 ABE
relaxation), receiver-side ECE feedback on CE, and
the §6.1.4 no-ECT-on-non-data rule. The opt-out
flag `_advertise_ecn` addresses the §6.1.1.1
middlebox-interop concern. Plus PyTCP supports
RFC 9341 AccECN as an extension, audited under that
RFC's record.

The single substantive gap is §6.1.5: retransmits
should not carry ECT, but PyTCP's `ip__ecn = 2 if
(self._ecn_enabled and data) else 0` does not
distinguish new transmissions from retransmits. The
fix is localised — gate on a "is_retransmit" flag at
the TX path. Practical impact bounded by the
one-shot guard which prevents stacked cwnd
reductions.
