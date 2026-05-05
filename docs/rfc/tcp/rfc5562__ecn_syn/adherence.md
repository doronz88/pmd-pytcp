# RFC 5562 — Adding ECN Capability to TCP's SYN/ACK Packets

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 5562                                                 |
| Title       | Adding ECN Capability to TCP's SYN/ACK Packets       |
| Category    | Experimental                                         |
| Date        | June 2009                                            |
| Source text | [`rfc5562.txt`](rfc5562.txt)                         |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 5562. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, §1 Introduction, §2
Conventions, §4–§9 discussion / related work /
performance / security / acknowledgments, References,
Appendices) are omitted.

---

## §3. Specification

### Allow ECT on SYN/ACK

> "We specify that a TCP node may respond to an
> initial ECN-setup SYN packet by setting ECT in the
> responding ECN-setup SYN/ACK packet, indicating to
> routers that the SYN/ACK packet is ECN-Capable.
> This allows a congested router along the path to
> mark the packet instead of dropping the packet as
> an indication of congestion."

**Adherence:** not implemented. PyTCP's outbound IP
ECN codepoint at
`pytcp/protocols/tcp/tcp__session.py:1500`:

```python
ip__ecn = 2 if (self._ecn_enabled and data) else 0
```

emits ECT(0) only on data segments. SYN+ACK has
`data` empty, so `ip__ecn = 0` (Not-ECT). PyTCP
follows the original RFC 3168 §6.1.1 rule "MUST NOT
set ECT on SYN or SYN-ACK packets" rather than the
RFC 5562 relaxation.

The omission is permitted: RFC 5562 is Experimental
("It does not specify an Internet standard of any
kind. Discussion and suggestions for improvement are
requested"). RFC 3168 §6.1.1's strict MUST NOT
remains the default safe behaviour; RFC 5562
proposes an experimental relaxation but does not
mandate it.

### §3.1 SYN/ACK dropped: retry without ECT

Not applicable — PyTCP does not emit ECT on SYN/ACK
in the first place, so the §3.1 "retry without ECT"
fallback path is unreachable.

### §3.2 SYN/ACK ECN-marked: respond with non-ECT + reduce IW

Not applicable — PyTCP does not emit ECT on SYN/ACK.

### §3.3 Management Interface

> "It is RECOMMENDED that ECN-Capable SYN/ACK
> packets... be enabled or disabled by a system-wide
> configuration..."

**Adherence:** not implemented. There is no
`_advertise_ecn_syn_ack` or similar opt-in flag; the
behaviour is simply absent.

---

## Test coverage audit

### §3 ECT on SYN/ACK

Not implemented; no test surface. The negative
behaviour (ECT not set on SYN/ACK) is implicitly
locked in by every ECN integration test that
inspects the `ip__ecn` field on the outbound SYN+ACK
and finds 0.

### §3.1 / §3.2 Marking response paths

Not applicable.

### Test coverage summary

| Aspect                                  | Coverage                          |
|-----------------------------------------|-----------------------------------|
| §3 ECT on SYN/ACK                       | n/a (not implemented; safe RFC 3168) |
| §3.1 Dropped SYN/ACK retry              | n/a                               |
| §3.2 Marked SYN/ACK response            | n/a                               |
| §3.3 Management Interface               | n/a                               |

---

## Overall assessment

| Aspect                                          | Status                                 |
|-------------------------------------------------|----------------------------------------|
| §3 ECT on SYN/ACK                               | not implemented (RFC 3168 default)     |
| §3.1 SYN/ACK dropped → retry without ECT        | n/a                                    |
| §3.2 SYN/ACK marked → non-ECT + IW=1            | n/a                                    |
| §3.3 Management interface                       | not implemented                        |

PyTCP does not implement RFC 5562. The implementation
follows RFC 3168 §6.1.1's stricter "MUST NOT set ECT
on SYN or SYN-ACK packets" rule by default. RFC 5562
is Experimental and proposes an opt-in relaxation;
PyTCP has not adopted the experiment.

Adopting RFC 5562 would be a moderate-scope project:
- Add an opt-in flag (e.g. `_advertise_ecn_syn_ack`)
- Allow `ip__ecn = 2` on outbound SYN/ACK when both
  the flag and `_ecn_enabled` (or pre-handshake
  ECN-setup) are True
- Implement §3.1 retry-without-ECT on SYN+ACK timeout
- Implement §3.2 mark-response: send non-ECT SYN/ACK
  immediately + reduce IW to 1
- Add the management interface

Estimated effort: ~5-8 commits, modest test surface
addition. The decision to skip is justified by the
RFC's Experimental status and PyTCP's research /
educational scope.
