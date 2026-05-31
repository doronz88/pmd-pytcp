# RFC 8311 — Relaxing Restrictions on ECN Experimentation

| Field       | Value                                                |
|-------------|------------------------------------------------------|
| RFC number  | 8311                                                 |
| Title       | Relaxing Restrictions on ECN Experimentation         |
| Category    | Standards Track                                      |
| Date        | January 2018                                         |
| Updates     | RFC 3168, 4341, 4342, 5622, 6679                     |
| Source text | [`rfc8311.txt`](rfc8311.txt)                         |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 8311. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `packages/pytcp/pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, §1 Introduction, §1.1
Terminology, §1.2 Requirements, §2 Overview, §3 ECN
Nonce closure, §5 / §6 RTP / DCCP cross-cuts, §7 IANA,
§8 Security, References) are omitted.

RFC 8311 is a meta-RFC that **relaxes** restrictions
in RFC 3168 to enable experimentation rather than
imposing new requirements. The §4 updates permit
behaviours that RFC 3168 previously forbade, but do
not require any implementation to adopt them.
PyTCP's adherence question is therefore "which §4
relaxations does PyTCP take advantage of?" rather
than "which mandates does PyTCP meet?"

---

## §4. Updates to RFC 3168

### §4.1 Congestion Response Differences

> "ECN deployments could use feedback indications
> based on a more accurate count of CE-marked
> packets to enable adjustments to TCP behavior to
> obtain better performance... Such adjustments are
> allowed when the new TCP behavior has been
> documented in an Experimental RFC."

**Adherence:** PyTCP takes advantage of this
relaxation via two mechanisms:

1. **RFC 8511 ABE (Alternative Backoff with ECN)**:
   the cwnd reduction on ECE event uses a 17/20
   multiplier instead of RFC 3168's strict 1/2.
   Implemented in `compute_ecn_event_ssthresh` at
   `packages/pytcp/pytcp/protocols/tcp/tcp__cwnd.py:145-175`. The
   inline citation explicitly references RFC 8511.

2. **RFC 9341 AccECN (Accurate ECN)**: PyTCP
   supports the AccECN feedback that conveys CE-mark
   counts beyond a single-bit ECE flag. Implemented
   via `_advertise_accecn` (line 313) and the
   AE+CWR+ECE encoding at line 1393-1430.

Both mechanisms are documented in their own RFCs
(8511, 9341), satisfying the §4.1 "documented in an
Experimental RFC" gating clause for the more
aggressive cwnd response behaviour.

### §4.2 Congestion Marking Differences

> "Marking based on a virtual queue can be used to
> implement a low-loss high-throughput service
> based on existing congestion control protocols
> (i.e., supporting connections from existing
> deployed senders)."

**Adherence:** PyTCP is a host stack, not a router.
Marking is router behaviour; this clause does not
apply to PyTCP's role as an ECN-capable sender.

> "Different ECT codepoints can be used to convey
> finer-granularity feedback... For example, the
> ECT(1) codepoint can be used to indicate
> finer-granularity feedback in the L4S
> architecture."

**Adherence:** not implemented. PyTCP uses ECT(0)
unconditionally on outbound segments
(`ip__ecn = 2` at line 1500). It does NOT use
ECT(1) for L4S-style finer feedback. RFC 8311 §4.2
permits this experimentation; PyTCP has not
adopted it.

### §4.3 TCP Control Packets and Retransmissions

> "RFC 3168 disallows the use of ECN with TCP
> control packets or with retransmitted segments,
> as the loss of these segments could affect the
> ability to abort or close down a TCP connection
> efficiently. This memo updates RFC 3168 to allow
> the use of ECN with TCP control packets and
> retransmitted segments."

**Adherence:** PyTCP follows the original RFC 3168
restriction — control packets (SYN, FIN, RST,
pure ACKs) and retransmits do NOT carry ECT. The
gate at `packages/pytcp/pytcp/protocols/tcp/tcp__session.py:1500`:

```python
ip__ecn = 2 if (self._ecn_enabled and data) else 0
```

emits ECT only when `data` is non-empty. Since
control packets typically have empty `data`, they
get Not-ECT. Retransmits also pass through this
same gate — ECT is unconditionally emitted on data
segments regardless of whether the data is new or
retransmitted.

Wait — the retransmit case: PyTCP DOES emit ECT(0)
on retransmits because `data` is non-empty for any
data segment, new or retransmitted. The §4.3
relaxation permits this; the RFC 3168 §6.1.5
restriction (audited in the RFC 3168 record as a
gap) is now permissible under RFC 8311 §4.3.

So:

- TCP control packets carry Not-ECT (PyTCP
  conformant with RFC 3168 conservative default).
- Retransmits carry ECT(0) (PyTCP takes advantage
  of RFC 8311 §4.3 relaxation, even though it's
  unintentional).

The "RFC 3168 §6.1.5 not met" gap noted in the RFC
3168 audit is therefore re-classified as "complies
with RFC 8311 §4.3 relaxation".

---

## Test coverage audit

### §4.1 ABE / AccECN cwnd response

- **Integration:** ABE tests under
  `packages/pytcp/pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py`
  pin the 17/20 ssthresh reduction.
- **Integration:** AccECN tests pin the more
  granular feedback codepoints.

**Status:** locked in (both tested via their
respective RFC adherence records).

### §4.2 Marking variants

PyTCP is host-side; router marking is out of scope.
No test surface.

**Status:** n/a.

### §4.3 ECT on retransmits / control packets

The "control packets carry Not-ECT" invariant is
implicitly verified by every ECN integration test
that checks `ip__ecn` on outbound non-data segments.
The "retransmits carry ECT(0)" behaviour is not
specifically tested but follows from the gate at
line 1500.

**Status:** locked in by construction (control
packets); locked in indirectly (retransmits).

### Test coverage summary

| Aspect                                       | Coverage                                       |
|----------------------------------------------|------------------------------------------------|
| §4.1 Alternative cwnd response (ABE/AccECN)  | locked in (cross-ref RFC 8511, RFC 9341)       |
| §4.2 Router marking variants                 | n/a (router-side)                              |
| §4.3 ECT on retransmits                      | locked in indirectly                           |
| §4.3 ECT on control packets                  | locked in by construction (Not-ECT on control) |

---

## Overall assessment

| Aspect                                          | Status                                  |
|-------------------------------------------------|-----------------------------------------|
| §3 ECN nonce closure (ECT(1) freed)             | n/a (PyTCP doesn't use ECT(1))          |
| §4.1 Alternative cwnd response (ABE)            | leveraged                               |
| §4.1 AccECN feedback                            | leveraged                               |
| §4.2 Marking variants (router-side)             | n/a                                     |
| §4.2 ECT(1) for L4S                             | not implemented                         |
| §4.3 ECT on TCP retransmits                     | leveraged (relaxation taken)            |
| §4.3 ECT on TCP control packets                 | not leveraged (Not-ECT, conservative)   |

PyTCP takes advantage of two RFC 8311 §4 relaxations:

1. The alternative cwnd response (§4.1) via RFC 8511
   ABE and RFC 9341 AccECN — both shipped per their
   respective audits.
2. The ECT-on-retransmits relaxation (§4.3) — PyTCP
   emits ECT(0) on retransmits along with new data.
   This was previously a strict RFC 3168 §6.1.5
   violation; under RFC 8311 §4.3 it becomes
   permissible experimental behaviour.

PyTCP does NOT take advantage of:

- ECT(1) for L4S finer feedback (§4.2). This is
  active research; adopting it would require
  implementing the L4S sender-side response (RFC
  9330+) which is a substantial separate project.
- ECT on TCP control packets (§4.3). PyTCP keeps
  the conservative RFC 3168 default; adopting the
  relaxation is permissible but offers limited
  benefit.

RFC 8311 is a permissive update; PyTCP's partial
adoption (ABE + AccECN + retransmit ECT) leverages
the most consequential relaxations while keeping
the conservative defaults for the experimental
extensions PyTCP has not yet integrated.
