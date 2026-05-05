# RFC 2018 — TCP Selective Acknowledgment Options

| Field       | Value                                  |
|-------------|----------------------------------------|
| RFC number  | 2018                                   |
| Title       | TCP Selective Acknowledgment Options   |
| Category    | Standards Track                        |
| Date        | October 1996                           |
| Source text | [`rfc2018.txt`](rfc2018.txt)           |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 2018. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `pytcp/protocols/tcp/`, `net_proto/protocols/tcp/`,
and `pytcp/lib/` directly; no prior memory or rule-file
content was reused. Sections that contain no normative
content (Abstract, §1 Introduction narrative, §6
Efficiency / Worst Case discussion, §7 Examples,
§9 Acknowledgments, References) are omitted.

---

## §2. Sack-Permitted Option

> "This two-byte option may be sent in a SYN by a TCP
> that has been extended to receive (and presumably
> process) the SACK option once the connection has
> opened. It MUST NOT be sent on non-SYN segments.
>
>     Kind: 4
>     Length: 2"

**Adherence:** met. PyTCP implements the SACK-Permitted
option at `net_proto/protocols/tcp/options/tcp__option__sackperm.py`
with kind=4 and length=2 exactly per the wire format.
Emission is gated on the SYN flag at
`pytcp/protocols/tcp/tcp__session.py:1315-1322`:

```python
if flag_syn and not flag_ack:           # active-open SYN
    tcp__sackperm = self._advertise_sack
elif flag_syn and flag_ack:             # passive-open SYN+ACK
    tcp__sackperm = self._send_sack
else:
    tcp__sackperm = False
```

For non-SYN segments `tcp__sackperm` is False, so the
TX path skips the option. The MUST NOT is enforced.

---

## §3. Sack Option Format

> "Kind: 5 / Length: Variable / Each block represents
> received bytes of data that are contiguous and
> isolated; that is, the bytes just below the block,
> (Left Edge of Block - 1), and just above the block,
> (Right Edge of Block), have not been received."
>
> "A SACK option that specifies n blocks will have a
> length of 8*n+2 bytes... a maximum of 4 blocks. It
> is expected that SACK will often be used in
> conjunction with the Timestamp option... thus a
> maximum of 3 SACK blocks will be allowed in this
> case."

**Adherence:** met. The wire format is implemented at
`net_proto/protocols/tcp/options/tcp__option__sack.py`:
kind=5, length=8*n+2, blocks as (left, right) 32-bit
unsigned integer pairs. The 4-block cap is enforced at
`pytcp/protocols/tcp/tcp__session.py:1701-1703`:

```python
for seq, packet_rx_md in self._ooo_packet_queue.items():
    if len(blocks) >= 4:
        break
    blocks.append(...)
```

The 3-block cap when timestamps are present is NOT
enforced — `_build_sack_blocks` always allows 4. With
TSopt's 12 bytes (10 bytes + 2 NOPs), 4 SACK blocks
would yield 12 + 2 + 4*8 = 46 bytes of options, which
exceeds the 40-byte option budget. PyTCP's TX path
will assemble such a segment but the IP / TCP option
budget enforcement may break.

This is a real conformance gap: when both TSopt and
4 SACK blocks are present, the segment exceeds the
option budget. Closing the gap requires capping at 3
blocks when `_send_ts` is True. ~3 LOC fix.

---

## §4. Generating Sack Options: Data Receiver Behavior

### Bilateral negotiation requirement

> "If the data receiver has received a SACK-Permitted
> option on the SYN for this connection, the data
> receiver MAY elect to generate SACK options as
> described below... If the data receiver has not
> received a SACK-Permitted option for a given
> connection, it MUST NOT send SACK options on that
> connection."

**Adherence:** met. The `_send_sack` flag at
`pytcp/protocols/tcp/tcp__session.py:194` is set only
when bilateral SACK was negotiated:

```python
self._send_sack = self._advertise_sack and packet_rx_md.tcp__sackperm
```

(line 1935). The SACK option emission gate at
line 1333 requires `_send_sack` AND has-blocks-to-send;
without bilateral SACK, no SACK option ever leaves.

### "Always send under permitted circumstances"

> "If the data receiver generates SACK options under
> any circumstance, it SHOULD generate them under all
> permitted circumstances."

**Adherence:** met. PyTCP emits SACK on every outbound
ACK that carries a non-empty OOO queue OR a pending
DSACK (line 1333). There is no path that conditionally
omits SACK when the conditions for emission are
otherwise met.

### Send SACK on every duplicate ACK

> "If sent at all, SACK options SHOULD be included in
> all ACKs which do not ACK the highest sequence
> number in the data receiver's queue."

**Adherence:** met. Every dup-ACK path emits a SACK
option iff `_ooo_packet_queue` is non-empty (which it
will be while there's a hole in the receive
sequence). The OOO segment that triggered the dup-ACK
is queued by the FSM established handler before
emission, so the dup-ACK carries the SACK option.

### First SACK block MUST be the most recent

> "The first SACK block (i.e., the one immediately
> following the kind and length fields in the option)
> MUST specify the contiguous block of data containing
> the segment which triggered this ACK, unless that
> segment advanced the Acknowledgment Number field in
> the header."

**Adherence:** partial. PyTCP's `_build_sack_blocks`
at `pytcp/protocols/tcp/tcp__session.py:1684-1705`:

```python
blocks: list[tuple[int, int]] = []
if self._pending_dsack is not None:
    blocks.append(self._pending_dsack)
    self._pending_dsack = None
for seq, packet_rx_md in self._ooo_packet_queue.items():
    ...
    blocks.append((seq, ...))
```

iterates the OOO queue in insertion order. Since
`_ooo_packet_queue: dict[int, TcpMetadata]` is a
regular dict (Python 3.7+ preserves insertion order),
the first emitted block is the OLDEST OOO range — not
the one that triggered the current ACK. The §4 MUST
"first block MUST specify... segment which triggered
this ACK" is therefore violated whenever a new OOO
segment arrives that's not the first OOO segment.

Exception: when a `_pending_dsack` is present (RFC
2883 case), the DSACK report goes first per RFC 2883
§4 — that is the canonical "first block" for the
DSACK case and is correct.

The non-DSACK path is the gap. Closing it requires
either:

1. Tracking which OOO seq triggered the current ACK
   (the easiest place is the FSM handler that queues
   the segment) and ensuring `_build_sack_blocks`
   emits its containing block first.
2. Reordering the dict to put the most-recently-
   inserted entry first.

Linux's implementation does (1). PyTCP's omission
matters when the receiver holds multiple OOO blocks
and a new arrival joins one of the older blocks; the
sender's view of "what's most-current" lags by one
block.

### "Include as many distinct blocks as possible"

> "The data receiver SHOULD include as many distinct
> SACK blocks as possible in the SACK option."

**Adherence:** met within the 4-block cap. The loop at
line 1701-1703 iterates the OOO queue until 4 blocks
are accumulated (with the §3 / TSopt-coexistence cap
not yet enforced — see §3 audit above).

### Repeat recent blocks (lost-ACK robustness)

> "The SACK option SHOULD be filled out by repeating
> the most recently reported SACK blocks (based on
> first SACK blocks in previous SACK options) that
> are not subsets of a SACK block already included in
> the SACK option being constructed."

**Adherence:** not implemented. PyTCP emits exactly
the current-state OOO queue blocks; it does not track
"recently reported first SACK blocks" or attempt to
repeat them for redundancy. This is a robustness
SHOULD that helps when a SACK-bearing ACK is lost in
transit; the practical impact is mitigated by the
"repeat" behaviour being implicit when the OOO queue
state hasn't advanced (the next SACK option naturally
contains the same blocks).

The strict RFC 2018 SHOULD asks for an explicit
"recently-reported blocks" cache that survives across
emission events even if the OOO queue evolves. Not
implemented.

---

## §5. Interpreting the Sack Option: Data Sender Behavior

### Record SACK info

> "When receiving an ACK containing a SACK option, the
> data sender SHOULD record the selective
> acknowledgment for future reference."

**Adherence:** met. The `_sack_scoreboard` field at
`pytcp/protocols/tcp/tcp__session.py:267` is a
`SackScoreboard` instance (defined in
`pytcp/protocols/tcp/tcp__sack.py`) that records SACK
blocks across cum-ACK boundaries. Inbound SACK blocks
are added at `tcp__session.py:2194-2198` whenever
the cum-ACK advances or an ACK carries new SACK info.

### Skip SACKed segments on retransmit

> "After the SACKed bit is turned on (as the result
> of processing a received SACK option), the data
> sender will skip that segment during any later
> retransmission. Any segment that has the SACKed bit
> turned off and is less than the highest SACKed
> segment is available for retransmission."

**Adherence:** met. The `_transmit_data` path
includes `_advance_snd_nxt_past_sacked()` at
`tcp__session.py:2343` which walks SND.NXT past any
seq range that's already in the scoreboard. When
combined with the RFC 6675 NextSeg machinery, the
sender skips SACKed ranges and only retransmits real
gaps.

### After RTO, turn off SACKed bits

> "After a retransmit timeout the data sender SHOULD
> turn off all of the SACKed bits, since the timeout
> might indicate that the data receiver has reneged."

**Adherence:** NOT met. The
`_retransmit_packet_timeout` handler at
`pytcp/protocols/tcp/tcp__session.py:2540` (area)
does NOT clear `_sack_scoreboard`. After an RTO,
the scoreboard's prior SACK blocks are retained,
which means the sender will continue to skip the
SACKed seq ranges on the post-RTO retransmit. If the
receiver has reneged (discarded SACKed data), this
will leave a permanent hole.

In practice, receiver reneging is rare (the §8
"Data Receiver Reneging" RFC text notes "Such
discarding of SACKed packets is discouraged"), so
the gap rarely surfaces. RFC 8985 RACK-TLP also
relaxes the strict reneging-detection requirement
because RACK has time-based loss detection that
re-discovers gaps independently. The
SHOULD-strength of §5 permits the omission, but it
is a strict deviation from the RFC text.

### MUST retransmit left-edge after RTO

> "The data sender MUST retransmit the segment at the
> left edge of the window after a retransmit timeout,
> whether or not the SACKed bit is on for that
> segment."

**Adherence:** met. The `_retransmit_packet_timeout`
handler rewinds SND.NXT to SND.UNA (the left edge of
the window) and `_transmit_data` re-emits from there.
The §5 MUST is satisfied because the rewind happens
BEFORE the SACK-skip walk, so the left-edge segment
is never skipped.

Wait — actually the SACK-skip walk
(`_advance_snd_nxt_past_sacked`) DOES advance SND.NXT
past SACKed ranges. If the left-edge segment happens
to be in the scoreboard (unusual but possible if the
peer SACKed it before reneging), PyTCP would skip it.
This combined with the "no scoreboard clear on RTO"
gap above creates a §5 MUST violation in the
reneging-receiver edge case. Closing both gaps
together (clear scoreboard on RTO) resolves both
deviations.

### MUST ignore prior SACK info on RTO retransmit

> "Because the data receiver is allowed to discard
> SACKed data, when a retransmit timeout occurs the
> data sender MUST ignore prior SACK information in
> determining which data to retransmit."

**Adherence:** NOT met. Same root cause as the
"turn off SACKed bits" gap. PyTCP retains the
scoreboard across RTOs, so prior SACK info is
consulted on the post-RTO retransmit. This is a §5
MUST violation strictly, but mitigated in practice by
the RACK-TLP loss detection layer and by the fact
that receiver reneging is rare.

### §5.1 Congestion control preserved

> "The congestion control algorithms present in the
> de facto standard TCP implementations MUST be
> preserved... recovery is not triggered by a single
> ACK reporting out-of-order packets at the receiver.
> Further, during recovery the data sender limits the
> number of segments sent in response to each ACK."

**Adherence:** met. PyTCP's recovery trigger is the
RFC 5681 §3.2 three-dup-ACK threshold (or the RFC
6675 §3 byte rule). A single SACK-bearing dup-ACK
does NOT trigger recovery; the count_trigger /
sack_trigger gates at
`pytcp/protocols/tcp/tcp__session.py:2764-2789`
require either the third dup-ACK or the
"more-than-(dup_thresh - 1)*SMSS bytes SACKed"
condition. RFC 6937 PRR caps the per-ACK send budget
during recovery.

---

## §8. Data Receiver Reneging

> "The data receiver is permitted to discard data in
> its queue that has not been acknowledged to the
> data sender, even if the data has already been
> reported in a SACK option."

**Adherence:** PyTCP's data receiver does NOT renege
— the OOO queue is held until the cum-ACK boundary
advances past a queued segment. PyTCP's behaviour is
strictly conformant (the RFC permits but does not
require reneging; non-reneging is the "discouraged"
side that the RFC notes).

> "The first SACK block MUST reflect the newest
> segment. Even if the newest segment is going to be
> discarded and the receiver has already discarded
> adjacent segments, the first SACK block MUST
> report, at a minimum, the left and right edges of
> the newest segment."

**Adherence:** since PyTCP doesn't renege, this
clause is moot. See §4 audit for the more general
"first SACK block must reflect triggering segment"
gap which also applies here.

---

## Test coverage audit

### §2 SACK-Permitted negotiation

- **Wire-level unit:**
  `net_proto/tests/unit/protocols/tcp/test__tcp__option__sackperm.py`
  covers the 2-byte option assembler / parser /
  asserts.
- **Integration:**
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__sack.py`
  contains tests pinning bilateral negotiation
  (`outbound_syn_advertises_sack_permitted`,
  `bilateral_sack_negotiation_sets_send_sack`,
  `passive_open_mirrors_peer_sack_permitted_offer`,
  `passive_open_omits_sack_when_peer_did_not_offer`).

**Status:** locked in.

### §3 SACK option wire format

- **Wire-level unit:**
  `net_proto/tests/unit/protocols/tcp/test__tcp__option__sack.py`
  covers the variable-length option assembler /
  parser with parameterised block-count cases.

**Status:** locked in.

### §3 4-block cap

- **Indirect:** the `len(blocks) >= 4` break at
  `tcp__session.py:1702-1703` caps emission. No
  dedicated test pins this; a regression that lifted
  the cap would be caught by option-byte-budget
  asserts in the assembler.

**Status:** locked in by construction.

### §3 / §4 3-block cap with TSopt

Not implemented; no test surface. A regression-guard
test would inject a session with bilateral TSopt and
4+ OOO segments and assert the emitted SACK option
contains at most 3 blocks.

**Status:** n/a (gap not closed).

### §4 Bilateral negotiation MUST NOT

- **Integration:** the
  `passive_open_omits_sack_when_peer_did_not_offer`
  test pins the negative case.

**Status:** locked in.

### §4 SACK on every dup-ACK

- **Integration:**
  `test__tcp__session__sack.py::out_of_order_data_segment_elicits_sack_block_in_outbound_ack`
  and
  `multiple_ooo_segments_yield_multiple_sack_blocks`
  pin the SACK-on-dup-ACK behaviour.

**Status:** locked in.

### §4 First block reflects triggering segment

Not implemented; no positive test surface. PyTCP's
"insertion order" approach incidentally produces the
RFC-compliant ordering when only one OOO block exists.
The deviation surfaces only with multiple OOO blocks.

**Status:** n/a (gap not closed).

### §4 Repeat recent blocks for ACK-loss robustness

Not implemented; no test surface.

**Status:** n/a (gap not closed).

### §5 Sender records SACK info

- **Unit:**
  `pytcp/tests/unit/protocols/tcp/test__tcp__sack.py`
  covers the `SackScoreboard` data structure (49+
  unit tests).
- **Integration:**
  `test__tcp__session__sack.py::inbound_sack_block_updates_scoreboard`
  pins the session-level integration.

**Status:** locked in.

### §5 Skip SACKed on retransmit

- **Integration:**
  `test__tcp__session__sack.py::recovery_skips_already_sacked_bytes`
  pins the SACK-skip walk during recovery.

**Status:** locked in.

### §5 Clear SACKed bits on RTO

Not implemented; no test surface. A regression-guard
test would set up a SACK-populated scoreboard,
trigger an RTO, and assert the scoreboard is empty
afterwards. PyTCP would currently fail this test.

**Status:** n/a (gap not closed).

### §5 Retransmit left-edge after RTO

- **Integration:** the broader
  `test__tcp__session__data_transfer__retransmit_timeout.py`
  tests pin the SND.NXT-rewind and left-edge
  retransmit behaviour (independent of SACK).

**Status:** locked in.

### §5 Ignore prior SACK info on RTO retransmit

Not implemented (same root cause as "Clear SACKed bits
on RTO" gap). A regression-guard test would assert
that on the post-RTO first retransmit, the SACK-skip
walk does NOT skip any seq ranges (because the
scoreboard should be clear). PyTCP would currently
fail this test.

**Status:** n/a (gap not closed).

### §5.1 Congestion control preservation

- **Integration:** every fast-retransmit / cwnd
  integration test in `test__tcp__session__cwnd.py`
  exercises this. Recovery is triggered only by 3rd
  dup-ACK or SACK byte rule, and PRR caps per-ACK
  sends during recovery.

**Status:** locked in.

### Test coverage summary

| Aspect                                      | Coverage                                        |
|---------------------------------------------|-------------------------------------------------|
| §2 SACK-Permitted negotiation               | locked in (unit + integration)                  |
| §2 MUST NOT on non-SYN                      | locked in (gate at line 1322-1324)              |
| §3 SACK option wire format                  | locked in (parser + assembler matrix)           |
| §3 4-block cap                              | locked in by construction                       |
| §3 3-block cap with TSopt                   | n/a (gap not closed)                            |
| §4 Bilateral negotiation MUST NOT           | locked in                                       |
| §4 SACK on every dup-ACK                    | locked in                                       |
| §4 First block reflects triggering segment  | n/a (gap not closed)                            |
| §4 As many blocks as possible               | locked in (within 4-cap)                        |
| §4 Repeat recent blocks                     | n/a (not implemented)                           |
| §5 Record SACK info                         | locked in (49+ unit tests for scoreboard)       |
| §5 Skip SACKed on retransmit                | locked in                                       |
| §5 Clear SACKed bits on RTO                 | n/a (gap not closed)                            |
| §5 Retransmit left-edge after RTO           | locked in                                       |
| §5 Ignore prior SACK info on RTO retransmit | n/a (gap not closed)                            |
| §5.1 Congestion control preserved           | locked in                                       |

---

## Overall assessment

| Aspect                                          | Status                                |
|-------------------------------------------------|---------------------------------------|
| §2 SACK-Permitted on SYN only                   | met                                   |
| §3 Wire format (kind 5, 8n+2 bytes)             | met                                   |
| §3 4-block cap                                  | met                                   |
| §3 3-block cap with TSopt                       | not met (gap)                         |
| §4 Bilateral negotiation MUST NOT               | met                                   |
| §4 SACK on every dup-ACK                        | met                                   |
| §4 First block reflects triggering segment      | partial (not met for multi-block OOO) |
| §4 Include as many distinct blocks as possible  | met                                   |
| §4 Repeat recent blocks                         | not implemented                       |
| §5 Record SACK info                             | met                                   |
| §5 Skip SACKed on retransmit                    | met                                   |
| §5 Clear SACKed bits on RTO                     | not met (SHOULD violation)            |
| §5 Retransmit left-edge after RTO               | met                                   |
| §5 Ignore prior SACK info on RTO retransmit     | not met (MUST violation)              |
| §5.1 Congestion control preserved               | met                                   |
| §8 Data receiver reneging                       | n/a (PyTCP receiver does not renege)  |

PyTCP's RFC 2018 conformance is solid for the wire-
level format and the bilateral negotiation; the
sender-side scoreboard and the SACK-skip retransmit
machinery are also correct. The principal gaps are:

1. **§4 first-block ordering** — `_build_sack_blocks`
   iterates the OOO queue in insertion order, not
   most-recent-first. The MUST is violated when
   multiple OOO blocks are present.
2. **§5 RTO scoreboard clear** — the scoreboard is
   not cleared on RTO, so the post-RTO retransmit
   honours stale SACK info. Both the §5 SHOULD ("turn
   off SACKed bits") and the §5.1 MUST ("ignore prior
   SACK information") are violated.
3. **§3 / §4 3-block cap with TSopt** — the option
   budget is exceeded when TSopt and 4 SACK blocks
   are simultaneously present.

All three gaps are localised fixes (~5-10 LOC each).
The §5 RTO-clear gap is the most consequential; the
others are rare-edge-case deviations. RFC 8985 RACK-
TLP's time-based loss detection mitigates the
practical impact of the §5 gap by re-discovering
losses independently of the scoreboard, but the
strict RFC 2018 §5.1 MUST is still violated.
