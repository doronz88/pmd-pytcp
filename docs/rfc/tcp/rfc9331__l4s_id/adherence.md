# RFC 9331 — The ECN Protocol for L4S

| Field       | Value                                                            |
|-------------|------------------------------------------------------------------|
| RFC number  | 9331                                                             |
| Title       | The Explicit Congestion Notification (ECN) Protocol for Low Latency, Low Loss, and Scalable Throughput (L4S) |
| Category    | Experimental                                                     |
| Date        | January 2023                                                     |
| Source text | [`rfc9331.txt`](rfc9331.txt)                                     |

This document records, paragraph by paragraph, how
the current PyTCP codebase relates to each normative
statement in RFC 9331. Sections without normative
content (Abstract, §1 Introduction, §1.x narrative,
§2 Roadmap, §3 Choice rationale, §6 Tunnels narrative,
§7 Experiments, §8-§9 IANA / Security, References,
Appendices) are summarized rather than enumerated.

---

## §4 Transport-Layer Behaviour (Prague L4S Requirements)

### §4.1 Codepoint Setting

> "An L4S sender MUST set ECT(1) on packets it
> identifies as L4S traffic."

**Adherence:** not implemented. PyTCP's outbound
ECT marking at `tcp__session.py:1500` is a fixed
ECT(0) (`ip__ecn = 2`) for ECN-enabled
connections. PyTCP cannot mark ECT(1) and has no
mechanism for declaring an L4S-eligible flow.

### §4.2 Prerequisite Transport Feedback

> "An L4S sender MUST receive accurate per-RTT
> feedback of CE markings (e.g. via AccECN) so it
> can perform per-mark cwnd reduction."

**Adherence:** prerequisite met (AccECN is shipped
per `rfc9768__accecn/adherence.md`), but the
sender-side scalable congestion control that
consumes that feedback is not implemented.

### §4.3 Prerequisite Congestion Response

> "An L4S sender MUST implement a Scalable
> congestion control such that the per-RTT
> reduction in cwnd is approximately proportional
> to the fraction of bytes marked CE in that RTT."

**Adherence:** not implemented. PyTCP uses RFC 8511
ABE (single-step 0.85 multiplier) for ECN response.
This is a Classic ECN response, NOT scalable —
ABE preserves more cwnd than RFC 5681 §3.1, but it
does not scale to the much-more-frequent CE
markings that L4S AQMs generate.

### §4.4 Filtering or Smoothing of ECN Feedback

**Adherence:** not implemented.

---

## §5 Network Node Behaviour (out of scope for endpoint)

> "L4S AQMs at network nodes classify packets by
> ECT(1) and apply L4S-specific marking thresholds."

**Adherence:** n/a (PyTCP is an endpoint, not a
network AQM).

---

## §5.5 Limiting Packet Bursts (sender-side
contribution)

> "L4S senders SHOULD pace bursts to maintain low
> queuing delay."

**Adherence:** not implemented. PyTCP does not
implement packet pacing; segments are emitted as
fast as cwnd / rwnd allow.

---

## §6.1 Tunnel / Encapsulation behaviour

**Adherence:** n/a (tunnels are out of scope for
PyTCP's TCP layer).

---

## §6.2 VPN Anti-Replay window

**Adherence:** n/a.

---

## Test coverage audit

No L4S tests exist; ECN/AccECN tests cover the
Classic ECN feedback path that L4S leverages.

### Test coverage summary

| Aspect                                  | Coverage  |
|-----------------------------------------|-----------|
| §4.1 ECT(1) marking on outbound         | deferred  |
| §4.2 AccECN feedback prerequisite       | met       |
| §4.3 Scalable congestion control        | deferred  |
| §4.4 ECN feedback filtering             | deferred  |
| §5.5 packet pacing                      | deferred  |

---

## Overall assessment

| Aspect                                | Status                            |
|---------------------------------------|-----------------------------------|
| §4.1 ECT(1) outbound marking          | deferred                          |
| §4.2 AccECN feedback prerequisite     | met (RFC 9768 shipped)            |
| §4.3 Scalable congestion control      | deferred                          |
| §4.4 ECN feedback filtering/smoothing | deferred                          |
| §5.5 packet pacing                    | deferred                          |

**Status: deferred by scope decision.** RFC 9331 is
Standards Track but the companion endpoint transport
(TCP Prague) is still under IETF standardization, so
the endpoint behaviour prescribed here is bleeding-
edge and would drift as the in-progress documents
evolve. PyTCP's RFC 9768 AccECN substrate is the
necessary feedback layer if a future Scalable
congestion control mode is added; the AccECN audit
at 100% is the closest PyTCP gets today.

If a future PyTCP scope decision pulls L4S in, the
unimplemented sub-clauses below would be the work
item. Estimated effort: ~10-15 commits, plus
co-evolution with whichever Scalable CC the IETF
finalises.

- §4.1: `ip__ecn` outbound marking changeable to 1
  (ECT(1)) per-connection.
- §4.3: a new scalable congestion control mode (e.g.
  TCP Prague or DCTCP variant) registered as a
  `CcMode` enum value alongside RENO and CUBIC.
- §4.4: a per-RTT CE-fraction estimator (similar to
  DCTCP.Alpha but consumed by Prague's scalable
  AIMD on cwnd directly).
- §5.5: optional packet pacing.
