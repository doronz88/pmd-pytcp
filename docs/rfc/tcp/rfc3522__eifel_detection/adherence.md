# RFC 3522 — The Eifel Detection Algorithm for TCP

| Field       | Value                                            |
|-------------|--------------------------------------------------|
| RFC number  | 3522                                             |
| Title       | The Eifel Detection Algorithm for TCP            |
| Category    | Experimental                                     |
| Date        | April 2003                                       |
| Source text | [`rfc3522.txt`](rfc3522.txt)                     |

This document records, paragraph by paragraph, how
the current PyTCP codebase relates to each normative
statement in RFC 3522. Sections without normative
content (Abstract, §1 Introduction, §2 narrative on
events that trigger spurious retransmits, §4
Discussion, §5 Related Work, §6 Security, §7 IANA,
References) are omitted.

---

## §3.2 The Algorithm

### Algorithm prerequisite: TCP Timestamps

> "Given that the TCP Timestamps option [RFC1323] is
> enabled for a connection, a TCP sender MAY use the
> Eifel detection algorithm as defined in this
> subsection."

**Adherence:** prerequisite met — RFC 7323 timestamps
are bilateral-negotiated and `_send_ts` /
`_ts_recent` machinery is in place. Eifel itself is
not implemented.

### Algorithm steps 1-6

> "(1) Set SpuriousRecovery = FALSE.
> (2) Set RetransmitTS = TSval of retransmit when
>     loss recovery initiated.
> (3) Wait for first acceptable ACK after retransmit.
> (4) If TSecr of acceptable ACK < RetransmitTS,
>     proceed to step 5; else DONE.
> (5) DSACK gating logic.
> (6) If timeout-based: SpuriousRecovery = SPUR_TO;
>     else: SpuriousRecovery = dupacks+1."

**Adherence:** not implemented. PyTCP's
`_retransmit_packet_timeout` snapshot-and-detect
machinery (the F-RTO simplified one-step variant
audited under RFC 5682) provides a similar function
but uses SND.UNA crossing pre-RTO SND.MAX as the
spurious-detection signal — NOT the Eifel timestamp
comparison.

The codebase does have a comment at
`pytcp/protocols/tcp/tcp__fsm__established.py:198`
that mentions RFC 3522/4015 Eifel as the *receiver*-
side beneficiary of DSACK case-2 reporting (PyTCP
emits DSACK so a peer running Eifel can detect a
spurious retransmit on its end). PyTCP itself does
not run Eifel; it only emits the DSACK so a peer can.

---

## §3.3 Corner case: timeout due to all-ACK loss

> "Step (5) DSACK gating prevents Eifel from
> misclassifying the all-ACK-loss case as spurious."

**Adherence:** n/a (Eifel not implemented).

---

## §3.4 Safe Variant Against Misbehaving Receivers

> "Step (2'): RetransmitTS stores TSval of original
> transmit; step (4'): TSecr equality with original."

**Adherence:** not implemented.

---

## Test coverage audit

No Eifel-specific tests exist. The DSACK-emission
path (which a peer running Eifel would consume) is
tested in
`pytcp/tests/integration/protocols/tcp/test__tcp__session__sack.py`
case-2 scenarios.

### Test coverage summary

| Aspect                                      | Coverage   |
|---------------------------------------------|------------|
| §3.2 step 2 RetransmitTS storage            | n/a (gap)  |
| §3.2 step 4 TSecr < RetransmitTS comparison | n/a (gap)  |
| §3.2 step 5 DSACK gating                    | n/a (gap)  |
| §3.2 step 6 SPUR_TO classification          | n/a (gap)  |
| §3.4 safe variant (TSecr equality)          | n/a (gap)  |

---

## Overall assessment

| Aspect                                 | Status                                  |
|----------------------------------------|------------------------------------------|
| §3.2 timestamp-based spurious-RTO det. | not implemented                          |
| §3.3 all-ACK-loss DSACK gating         | not implemented                          |
| §3.4 safe variant                      | not implemented                          |
| Receiver-side DSACK emission for Eifel | met (RFC 2883 §4 case-2 emission lives)  |

PyTCP does not implement Eifel detection. Spurious-
RTO detection is provided by the simplified F-RTO
variant (RFC 5682, see `rfc5682__f_rto/adherence.md`),
which uses SND.UNA crossing pre-RTO SND.MAX as the
trigger rather than the timestamp comparison.

The receiver-side DSACK emission for case-2 is met,
so a peer running Eifel can leverage PyTCP's DSACK
output to detect its own spurious retransmits.

Implementing sender-side Eifel would require:
- A `_eifel_retransmit_ts` field captured at retransmit-
  time (in `_retransmit_packet_request` and
  `_retransmit_packet_timeout`).
- A first-acceptable-ACK comparison branch in
  `_process_ack_packet` that consumes the inbound
  TSecr and decides spurious vs genuine.
- The §3.3 DSACK gate in step (5).

Estimated effort: ~4-5 commits.
