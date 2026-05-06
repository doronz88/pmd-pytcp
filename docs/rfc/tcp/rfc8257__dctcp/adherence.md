# RFC 8257 — Data Center TCP (DCTCP)

| Field       | Value                                                    |
|-------------|----------------------------------------------------------|
| RFC number  | 8257                                                     |
| Title       | Data Center TCP (DCTCP): TCP Congestion Control for Data Centers |
| Category    | Informational                                            |
| Date        | October 2017                                             |
| Source text | [`rfc8257.txt`](rfc8257.txt)                             |

This document records, paragraph by paragraph, how
the current PyTCP codebase relates to each normative
statement in RFC 8257. Sections without normative
content (Abstract, §1 Introduction, §2 Terminology,
§3.1 narrative on switch marking, §5 Deployment, §6
Known Issues, §7 Security, §8 IANA, References) are
omitted.

---

## §3.2 Echoing Congestion Information on the Receiver

> "DCTCP introduces a new Boolean TCP state variable,
> DCTCP Congestion Encountered (DCTCP.CE)... When
> receiving packets, the CE codepoint MUST be
> processed as follows:
> 1. If CE is set and DCTCP.CE is false, set DCTCP.CE
>    to true and send an immediate ACK.
> 2. If CE is not set and DCTCP.CE is true, set
>    DCTCP.CE to false and send an immediate ACK.
> 3. Otherwise, ignore the CE codepoint."

**Adherence:** not implemented. PyTCP's RFC 3168 ECN
receiver-side path uses the simpler "set ECE flag
continuously until peer responds with CWR" semantics
per `tcp__session.py:1453-1454`. The DCTCP per-edge
state machine that toggles ECE on every CE↔non-CE
boundary is absent.

PyTCP does have AccECN (RFC 9768) which provides
fine-grained per-packet feedback through the ACE
counter — this is a different (more comprehensive)
mechanism than DCTCP's edge-triggered ACK approach.
PyTCP's AccECN can serve as a substrate for
DCTCP-style sender-side fraction estimation but
PyTCP does not actually compute the fraction.

---

## §3.3 Processing Echoed Congestion Indications on the Sender

> "DCTCP.Alpha = DCTCP.Alpha * (1 - g) + g * M, where
> M = bytes_marked / bytes_total in the most recent
> RTT."

**Adherence:** not implemented. PyTCP's sender-side
ECN response is the RFC 8511 ABE multiplier (0.85)
applied unconditionally to ECN-class congestion
events — a single-step reduction, not the
proportional fraction-based reduction DCTCP
specifies.

---

## §3.4 Handling of Congestion Window Growth

> "cwnd = cwnd * (1 - DCTCP.Alpha / 2)"

**Adherence:** not implemented.

---

## §3.5 Handling of Packet Loss

> "DCTCP MUST react to packet loss as conventional TCP
> [RFC5681]."

**Adherence:** met implicitly. PyTCP's RFC 5681 §3.1
RTO ssthresh halving and §3.2 fast-recovery paths
operate independently of any DCTCP machinery.

---

## §3.6 Handling of SYN, SYN-ACK, and RST Packets

> "DCTCP requires that SYN and SYN-ACK packets are not
> ECN capable, even though [RFC3168] permits it."

**Adherence:** met. PyTCP gates ECT marking at
`tcp__session.py:1500` on `_ecn_enabled and data` —
SYN / SYN-ACK / RST never carry ECT.

---

## §4.1 Configuration of DCTCP

> "An implementation MUST provide a configuration
> mechanism to enable / disable DCTCP and tune its
> parameters."

**Adherence:** not applicable (DCTCP not
implemented).

---

## §4.2 Computation of DCTCP.Alpha

> "DCTCP.Alpha computation requires per-RTT bytes-
> marked and bytes-total counters."

**Adherence:** not implemented.

---

## Test coverage audit

No DCTCP tests exist; the substrate (RFC 3168 ECN,
AccECN) has its own test surface.

### Test coverage summary

| Aspect                                  | Coverage  |
|-----------------------------------------|-----------|
| §3.2 DCTCP.CE state + edge ACKs         | deferred  |
| §3.3 DCTCP.Alpha estimation             | deferred  |
| §3.4 cwnd reduction by alpha/2          | deferred  |
| §3.5 RFC 5681 loss handling             | met       |
| §3.6 no ECT on SYN / SYN-ACK / RST      | locked in |
| §4.1 enable/disable configuration       | deferred  |
| §4.2 per-RTT byte counters              | deferred  |

---

## Overall assessment

| Aspect                                | Status          |
|---------------------------------------|-----------------|
| §3.2 DCTCP.CE receiver state machine  | deferred        |
| §3.3 DCTCP.Alpha sender estimation    | deferred        |
| §3.4 cwnd = cwnd * (1 - alpha/2)      | deferred        |
| §3.5 RFC 5681 loss-handling baseline  | met             |
| §3.6 no ECT on SYN/SYN-ACK/RST        | met             |
| §4.x configuration / tuning           | deferred        |

**Status: deferred by scope decision.** PyTCP targets
public-Internet TCP semantics; DCTCP is explicitly a
data-center-only protocol. RFC 8257 §1.1 itself
states that "DCTCP MUST NOT be deployed over the
public Internet without additional measures, as
detailed in §6," and §6 frames it as a controlled-
domain protocol incompatible with the standard ECN
response curve. ECN response in PyTCP is the simpler
RFC 8511 ABE multiplier (0.85 ssthresh reduction on
ECN signal) which is the appropriate response for
public-Internet deployments.

If a future PyTCP deployment scenario requires
data-center semantics, the unimplemented sub-clauses
below would be the work item. Estimated effort:
~6-8 commits.

- §3.2: per-RTT byte-marked / byte-total counters at
  the receiver and sender.
- §3.3: DCTCP.Alpha state tracking with EWMA update.
- §3.4: replacement of the ABE multiplier in the
  cwnd-response path with the `cwnd * (1 - alpha/2)`
  formula.
- §4.x: configuration knob to enable DCTCP per
  connection (probably a setsockopt level/option
  similar to TCP_CONGESTION).
