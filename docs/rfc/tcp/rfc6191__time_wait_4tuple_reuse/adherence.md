# RFC 6191 — Reducing the TIME-WAIT State Using TCP Timestamps

| Field       | Value                                          |
|-------------|------------------------------------------------|
| RFC number  | 6191                                           |
| Title       | Reducing the TIME-WAIT State Using TCP Timestamps |
| Category    | Best Current Practice (BCP 159)                |
| Date        | April 2011                                     |
| Source text | [`rfc6191.txt`](rfc6191.txt)                   |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 6191. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, Introduction narrative,
§3 Interaction with Various Timestamp Generation
Algorithms (advisory), §4 Interaction with Various ISN
Generation Algorithms (advisory), §5 Security
Considerations boilerplate, §6 Acknowledgements,
References, Appendix A scenario walk-through) are
omitted.

---

## §2. Improved Processing of Incoming Connection Requests

The RFC's §2 specifies a SHOULD-strength algorithm for
processing SYN segments received in TIME-WAIT state.
The algorithm is divided into two top-level branches
based on whether the previous incarnation used
Timestamps; each branch has 2-4 sub-cases.

### Top-level case A: previous incarnation used Timestamps

#### Sub-case A.1 — TSopt enabled in new SYN AND TSval > last seen

> "If TCP Timestamps would be enabled for the new
> incarnation of the connection, and the timestamp
> contained in the incoming SYN segment is greater
> than the last timestamp seen on the previous
> incarnation of the connection (for that direction of
> the data transfer), honor the connection request
> (creating a connection in the SYN-RECEIVED state)."

**Adherence:** met. The TIME-WAIT FSM handler at
`pytcp/protocols/tcp/tcp__fsm__time_wait.py:106-135`
implements exactly this branch:

```python
if (
    packet_rx_md
    and packet_rx_md.tcp__flag_syn
    and not packet_rx_md.tcp__flag_ack
    and not packet_rx_md.tcp__flag_rst
    and session._send_ts
    and packet_rx_md.tcp__tsval is not None
    and gt32(packet_rx_md.tcp__tsval, ts_recent_at_entry)
):
    session._reinit_for_rfc6191_reuse(packet_rx_md)
    session._change_state(FsmState.SYN_RCVD)
    session._transmit_packet(flag_syn=True, flag_ack=True)
    return
```

The check requires:
- The inbound segment is a pure SYN (not SYN+ACK, not
  RST).
- The previous incarnation had bilateral Timestamps
  (`session._send_ts`).
- The new SYN brings a TSval (`tcp__tsval is not
  None`).
- The new TSval is strictly greater than
  `_ts_recent` (modular comparison via `gt32`).

When all conditions hold, `_reinit_for_rfc6191_reuse`
(`pytcp/protocols/tcp/tcp__session.py:1866-1925+`)
resets the session to a fresh state, transitions to
SYN_RCVD, and emits the SYN+ACK. This is the canonical
RFC 6191 §2 sub-case A.1 acceptance branch.

The inline comment cites "RFC 6191 §3" but the
algorithm is in §2; §3 is "Interaction with Various
Timestamp Generation Algorithms" (advisory commentary).
This is a documentation-citation polish item, not a
behavioural defect.

#### Sub-case A.2 — TSopt enabled AND TSval == last AND seq > last_seq

> "If TCP Timestamps would be enabled for the new
> incarnation of the connection, the timestamp
> contained in the incoming SYN segment is equal to
> the last timestamp seen on the previous incarnation
> of the connection (for that direction of the data
> transfer), and the Sequence Number of the incoming
> SYN segment is greater than the last sequence number
> seen on the previous incarnation of the connection
> (for that direction of the data transfer), honor the
> connection request (creating a connection in the
> SYN-RECEIVED state)."

**Adherence:** not implemented. PyTCP's check uses
`gt32(tsval, ts_recent_at_entry)` — strict greater-
than. The boundary case `tsval == _ts_recent` falls
through to the SYN-in-TIME-WAIT challenge-ACK path
(line 161 of the FSM handler), per the inline comment
at lines 112-115:

> "The boundary case 'TSval == _ts_recent' passes PAWS
> (strict '<') but fails this gate (strict '>') and
> falls through to the RFC 1337 / RFC 9293 §3.10.7.4
> challenge-ACK path below."

Sub-case A.2 would be a small extension: if `tsval ==
_ts_recent`, also check `gt32(seq, _last_seq_seen)`.
PyTCP currently has no `_last_seq_seen` tracking on
the TIME-WAIT session, so this sub-case requires
additional state beyond what's currently kept. The
omission is conservative — PyTCP rejects connections
A.2 would accept, falling back to the safer
challenge-ACK path. Not implementing this sub-case is
permitted under §2's SHOULD; the strict reading is
"may not honor" rather than "must honor".

#### Sub-case A.3 — TSopt NOT enabled in new SYN BUT seq > last_seq

> "If TCP Timestamps would not be enabled for the new
> incarnation of the connection, but the Sequence
> Number of the incoming SYN segment is greater than
> the last sequence number seen on the previous
> incarnation of the connection (for the same
> direction of the data transfer), honor the
> incoming connection request (creating a connection
> in the SYN-RECEIVED state)."

**Adherence:** not implemented. Same reason as A.2:
no `_last_seq_seen` state on the TIME-WAIT session.
Falls back to challenge-ACK. Conservative omission
permitted under SHOULD.

#### Sub-case A.4 — Otherwise drop (default)

> "Otherwise, silently drop the incoming SYN segment,
> thus leaving the previous incarnation of the
> connection in the TIME-WAIT state."

**Adherence:** PyTCP elicits a challenge-ACK rather
than silently dropping. The challenge-ACK matches RFC
9293 §3.10.7.4 / RFC 5961 §4 for SYN-on-synchronized.
RFC 6191 §2 says "silently drop", but the RFC 9293
challenge-ACK is a stricter, more informative response
that does not violate RFC 6191's intent (the previous
incarnation stays in TIME-WAIT regardless of which
response is chosen).

### Top-level case B: previous incarnation did NOT use Timestamps

#### Sub-case B.1 — TSopt enabled in new SYN

> "If TCP Timestamps would be enabled for the new
> incarnation of the connection, honor the incoming
> connection request (creating a connection in the
> SYN-RECEIVED state)."

**Adherence:** not implemented. The RFC 6191 reuse
gate at `tcp__fsm__time_wait.py:121` requires
`session._send_ts` to be True — i.e., the PREVIOUS
incarnation had bilateral Timestamps. When the
previous incarnation did not, the gate fails even if
the new SYN brings a TSopt. This sub-case would
permit acceptance based solely on the new SYN's TSopt
presence, regardless of what the previous incarnation
did.

PyTCP's omission is conservative: an incoming SYN
without prior-TSopt context will fall back to the
challenge-ACK path. The SHOULD permits this; the
choice means PyTCP is more conservative than RFC 6191
recommends but not unsafe.

#### Sub-case B.2 — TSopt NOT enabled BUT seq > last_seq

> "If TCP Timestamps would not be enabled for the new
> incarnation of the connection, but the Sequence
> Number of the incoming SYN segment is greater than
> the last sequence number seen on the previous
> incarnation of the connection (for the same
> direction of the data transfer), honor the incoming
> connection request..."

**Adherence:** not implemented. Same `_last_seq_seen`
omission as sub-cases A.2 and A.3.

#### Sub-case B.3 — Otherwise drop

> "Otherwise, silently drop the incoming SYN segment,
> thus leaving the previous incarnation of the
> connection in the TIME-WAIT state."

**Adherence:** as in sub-case A.4, PyTCP elicits
challenge-ACK rather than silent drop.

---

## Coverage summary of §2 sub-cases

| Sub-case | Trigger                                              | PyTCP behaviour                                |
|----------|------------------------------------------------------|------------------------------------------------|
| A.1      | prev-TSopt + new-TSopt + TSval > _ts_recent          | met (accepts via `_reinit_for_rfc6191_reuse`)  |
| A.2      | prev-TSopt + new-TSopt + TSval == _ts_recent + seq > | not implemented (falls to challenge-ACK)       |
| A.3      | prev-TSopt + no-new-TSopt + seq > last_seq           | not implemented (falls to challenge-ACK)       |
| A.4      | otherwise (prev-TSopt branch)                        | challenge-ACK (vs RFC's silent drop)           |
| B.1      | prev-no-TSopt + new-TSopt                            | not implemented (falls to challenge-ACK)       |
| B.2      | prev-no-TSopt + no-new-TSopt + seq > last_seq        | not implemented (falls to challenge-ACK)       |
| B.3      | otherwise (prev-no-TSopt branch)                     | challenge-ACK (vs RFC's silent drop)           |

**Overall §2 status:** PyTCP implements the most
common sub-case (A.1 — both incarnations TSopt-
enabled, fresh TSval) and falls back conservatively
to challenge-ACK for every other case. The SHOULD
strength of §2 permits this conservative subset.

---

## Test coverage audit

### §2 sub-case A.1 — Fresh TSval acceptance

- **Integration:**
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__close__time_wait.py::TestTcpClose__TimeWaitRfc6191::test__rfc6191__fresh_tsval_syn_terminates_time_wait_and_emits_syn_ack`
  drives a session into TIME-WAIT, captures
  `_ts_recent`, then injects a SYN with TSval >
  `_ts_recent` and asserts:
  - The session terminates TIME-WAIT and transitions
    to SYN_RCVD.
  - A SYN+ACK is emitted in response.

**Status:** locked in.

### §2 sub-case A.2 — TSval == last + seq >

- **Integration (negative coverage):**
  `TestTcpClose__TimeWaitRfc6191::test__rfc6191__equal_tsval_syn_falls_back_to_challenge_ack`
  drives a SYN with TSval == `_ts_recent` and asserts
  the response is a challenge-ACK rather than
  acceptance (the conservative behaviour).

**Status:** locked in (negative coverage; positive
case not implemented).

### §2 sub-case A.3 / B.1 / B.2 — Various non-A.1 acceptance branches

- **Integration (negative coverage):**
  `TestTcpClose__TimeWaitRfc6191::test__rfc6191__syn_without_tsopt_falls_back_to_challenge_ack`
  drives a SYN without TSopt and asserts the response
  is challenge-ACK.

**Status:** the omission of these branches is locked
in by the negative test (any future addition would
break this test, prompting an update).

### Test coverage summary

| Aspect                                          | Coverage                                       |
|-------------------------------------------------|------------------------------------------------|
| §2 A.1 fresh-TSval acceptance                   | locked in                                      |
| §2 A.2 TSval-equal + seq-greater                | n/a (not implemented; negative test pinned)    |
| §2 A.3 prev-TSopt no-new-TSopt + seq            | n/a (not implemented; negative test pinned)    |
| §2 A.4 default drop                             | conservatively replaced with challenge-ACK     |
| §2 B.1 no-prev-TSopt new-TSopt                  | n/a (not implemented; negative test pinned)    |
| §2 B.2 no-prev-TSopt no-new-TSopt + seq         | n/a (not implemented)                          |
| §2 B.3 default drop                             | conservatively replaced with challenge-ACK     |

---

## Overall assessment

| Aspect                                          | Status                                          |
|-------------------------------------------------|-------------------------------------------------|
| §2 A.1 (TSval > last_TSval)                     | met                                             |
| §2 A.2 (TSval == last + seq > last_seq)         | not implemented (conservative)                  |
| §2 A.3 (no-new-TSopt + seq > last_seq)          | not implemented (conservative)                  |
| §2 A.4 (drop default)                           | replaced by challenge-ACK (stricter)            |
| §2 B.1 (no-prev-TSopt + new-TSopt)              | not implemented (conservative)                  |
| §2 B.2 (no-prev-TSopt no-new-TSopt + seq)       | not implemented (conservative)                  |
| §2 B.3 (drop default)                           | replaced by challenge-ACK (stricter)            |

PyTCP implements the most-common-case (sub-case A.1)
RFC 6191 §2 algorithm: a fresh-TSval SYN reusing a
4-tuple in TIME-WAIT is accepted via the
`_reinit_for_rfc6191_reuse` reset path. The other six
sub-cases are not implemented; an incoming SYN that
would have been accepted by sub-cases A.2 / A.3 / B.1
/ B.2 instead falls through to the RFC 9293 §3.10.7.4
challenge-ACK path. The §2 SHOULD-strength permits
this conservative subset; the practical impact is that
high-rate connection-reuse scenarios that don't match
sub-case A.1 may experience longer TIME-WAIT-induced
delays than a fully-conformant implementation would.

The two known polish items:

1. The inline comment at
   `tcp__fsm__time_wait.py:106` cites "RFC 6191 §3"
   but the algorithm is in §2.
2. The `_send_ts` gate semantically encodes "previous
   incarnation had bilateral TSopt", which is the
   correct hook for sub-case A.1; extending to B.1
   would require relaxing this gate.

Closing the gaps to fully cover all RFC 6191 §2
sub-cases would require:

- Recording `_last_seq_seen` (the FIN's seq from the
  previous incarnation) on the TIME-WAIT session for
  the seq-comparison branches.
- Distinguishing "previous-TSopt" from "previous-
  no-TSopt" at the gate so sub-case B.1 can be
  honoured.

The work is moderate in size (~3-4 commits) and would
make PyTCP fully RFC 6191 §2 conformant. It is
documented here as a known gap; whether to close it
depends on whether high-rate connection reuse becomes
a relevant use case for PyTCP deployments.
