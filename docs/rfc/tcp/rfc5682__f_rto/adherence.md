# RFC 5682 — Forward RTO-Recovery (F-RTO)

| Field       | Value                                                             |
|-------------|-------------------------------------------------------------------|
| RFC number  | 5682                                                              |
| Title       | Forward RTO-Recovery: An Algorithm for Detecting Spurious Timeouts |
| Category    | Standards Track                                                   |
| Date        | September 2009                                                    |
| Updates     | RFC 4138                                                          |
| Source text | [`rfc5682.txt`](rfc5682.txt)                                      |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 5682. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, §1 Introduction, §1.1
Conventions, §2.2 / §3.2 Discussion narrative, §4
post-spurious actions discussion, §5 Evaluation, §6
Security, References, Appendices) are omitted.

---

## §2.1 Basic F-RTO Algorithm

### Step 1: Retransmit + initialise

> "When the retransmission timer expires, retransmit
> the first unacknowledged segment and set
> SpuriousRecovery to FALSE. If the TCP sender is
> already in RTO recovery AND 'recover' is larger
> than or equal to SND.UNA, do not enter step 2 of
> this algorithm."

**Adherence:** met (simplified). The
`_retransmit_packet_timeout` handler at
`pytcp/protocols/tcp/tcp__session.py:2619-2622`
sets:

```python
self._frto_active = True
self._frto_pre_cwnd = self._cwnd
self._frto_pre_ssthresh = self._ssthresh
self._frto_pre_snd_max = self._snd_max
```

This is the F-RTO snapshot. `_frto_active = True` is
the analog of `SpuriousRecovery = FALSE` (PyTCP uses
boolean instead of an enum). The pre-RTO cwnd /
ssthresh / SND.MAX are snapshotted for later
restoration.

PyTCP does not implement the §2.1 step 1 "if already
in RTO recovery ... do not enter step 2" gate
explicitly. The simplified one-step variant runs the
spurious-detection check on every RTO regardless of
prior state. The omitted gate's purpose is to avoid
false-spurious detection when ACKs from prior
retransmits arrive after a second RTO; the practical
risk is bounded because PyTCP's check requires
SND.UNA to cover the snapshotted SND.MAX (full
cumulative coverage of all pre-RTO data).

### Step 2: First post-RTO ACK

> "When the first acknowledgment after the RTO
> retransmission arrives at the TCP sender, store the
> highest sequence number transmitted so far in
> variable 'recover'... If the acknowledgment
> advances the window AND the Acknowledgment field
> does not cover 'recover', transmit up to two new
> segments and enter step 3."

**Adherence:** simplified. PyTCP's F-RTO is a
**one-step** variant rather than the §2.1 two-step
algorithm. Instead of waiting for two post-RTO ACKs,
PyTCP makes the spurious / genuine determination on
the FIRST post-RTO ACK at
`pytcp/protocols/tcp/tcp__session.py:3285-3296`:

```python
if self._frto_active:
    if not lt32(self._snd_una, self._frto_pre_snd_max):
        # SND.UNA has crossed pre-RTO SND.MAX
        # → spurious RTO, restore cwnd/ssthresh
        self._cwnd = self._frto_pre_cwnd
        self._ssthresh = self._frto_pre_ssthresh
        ...
    self._frto_active = False
```

Logic:

- The single post-RTO ACK is checked: does SND.UNA
  cover the pre-RTO SND.MAX?
- If yes (`!(SND.UNA < pre_SND.MAX)` → SND.UNA >= pre
  SND.MAX): all pre-RTO in-flight data was
  acknowledged → spurious RTO → restore snapshot.
- If no: data really was lost → keep the conventional
  RTO halving.
- Either way, `_frto_active` clears so subsequent
  ACKs don't re-trigger the check.

This deviates from the §2.1 two-step algorithm in
that:

1. PyTCP doesn't transmit the "up to two new
   segments" in step 2b; instead the existing
   `_transmit_data` path emits whatever cwnd / rwnd
   permit on the next tick (which may or may not be
   new data).
2. PyTCP doesn't have a SpuriousRecovery → SPUR_TO
   intermediate state; the determination is made and
   acted upon in a single pass.
3. PyTCP doesn't track the "recover" variable
   explicitly; instead `_frto_pre_snd_max` plays the
   same role.

The simplification is correct under stricter
conditions: PyTCP's check requires SND.UNA to cover
ALL of pre-RTO SND.MAX (not just advance "above
SND.UNA but not cover recover"). A peer who
selectively ACKs only the retransmit + some originals
without covering all of SND.MAX would NOT trigger
PyTCP's spurious detection — but PyTCP is also not
incorrectly classifying mixed cases as spurious. The
trade-off favours conservativeness.

### Step 3: Second post-RTO ACK

Not implemented (PyTCP's one-step variant makes the
determination on step 2). The §2.1 step 3 sub-cases
(3a duplicate ACK → cwnd to 3*MSS slow-start; 3b
window-advancing ACK → declare spurious) are
collapsed into the single boolean check at line
3286.

---

## §3 SACK-Enhanced F-RTO

### §3.1 The Algorithm

> "If the sender applies the SACK-enhanced F-RTO
> algorithm, it MUST follow the steps below..."

**Adherence:** not implemented. PyTCP uses the basic
(non-SACK-enhanced) variant even when bilateral SACK
is negotiated. The SACK-enhanced version provides
better detection in the presence of packet
reordering or duplicates, but PyTCP's simpler check
sacrifices that for code-path simplicity.

The §3 algorithm requires tracking SACK
scoreboard advancement separately from cum-ACK; the
PyTCP scoreboard exists (`_sack_scoreboard`) but is
not consulted by the F-RTO check. Closing this gap
would extend the spurious-RTO detection to cases
where the post-RTO ACK is a SACK-bearing dup-ACK
that reports the original (non-retransmitted) data
as delivered.

---

## §4 Actions after detecting spurious RTO

> "After detecting a spurious RTO, the sender may
> take various actions, including reverting cwnd /
> ssthresh, suppressing further retransmissions, and
> taking RTT samples on the delayed segments."

**Adherence:** the cwnd / ssthresh restoration is
met (see §2.1 audit). The "suppressing further
retransmissions" aspect is met implicitly — when
SND.UNA covers pre-RTO SND.MAX, there are no more
unacked bytes to retransmit. The "taking RTT
samples on delayed segments" is met by the broader
RFC 6298 + RFC 7323 RTT machinery (delayed segment
ACKs feed `update()` normally).

---

## Test coverage audit

### §2.1 step 1 — RTO snapshot

- **Integration:** F-RTO integration tests under
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__retransmit_timeout.py`
  drive an RTO and verify that
  `_frto_pre_cwnd` / `_frto_pre_ssthresh` /
  `_frto_pre_snd_max` are snapshotted before the
  conventional halving runs.

**Status:** locked in.

### §2.1 step 2 — Spurious detection on first ACK

- **Integration:** the same test file contains
  cases that drive a spurious-RTO scenario (peer's
  late-but-original ACKs arrive post-RTO covering
  pre-RTO SND.MAX) and verify the cwnd / ssthresh
  snapshot is restored.

**Status:** locked in.

### §2.1 genuine RTO (no spurious detection)

- **Integration:** cases where the post-RTO ACK is
  a partial cum-ACK (data really was lost) verify
  the conventional halving stays in effect and
  `_frto_active` clears without restoration.

**Status:** locked in.

### §3 SACK-enhanced variant

Not implemented; no test surface.

**Status:** n/a (gap).

### Test coverage summary

| Aspect                                  | Coverage                              |
|-----------------------------------------|---------------------------------------|
| §2.1 step 1 RTO snapshot                | locked in                             |
| §2.1 step 2 spurious detection          | locked in (one-step simplified form)  |
| §2.1 genuine-RTO no-restoration         | locked in                             |
| §2.1 step 3 second-ACK branch           | n/a (one-step simplified)             |
| §3 SACK-enhanced variant                | n/a (not implemented)                 |
| §4 cwnd/ssthresh restoration            | locked in                             |

---

## Overall assessment

| Aspect                                  | Status                                  |
|-----------------------------------------|-----------------------------------------|
| §2.1 step 1 RTO snapshot                | met                                     |
| §2.1 step 2 first-ACK detection         | met (one-step simplified)               |
| §2.1 step 2 transmit two new segments   | not implemented (deferred to next tick) |
| §2.1 step 3 second-ACK branch           | not implemented (collapsed into step 2) |
| §2.1 step 1 already-in-RTO-recovery gate | not implemented                        |
| §3 SACK-enhanced variant                | not implemented                         |
| §4 cwnd/ssthresh restoration            | met                                     |

PyTCP implements a simplified one-step F-RTO variant
that captures the most common spurious-RTO scenario
(all pre-RTO data was actually delivered, RTO fired
on a delay spike). The simplification trades the §2
two-step algorithm's broader detection coverage for
implementation simplicity. The §3 SACK-enhanced
variant is not implemented; cases involving packet
reordering or duplicates may not be detected as
spurious.

The most consequential gap is §3 (SACK-enhanced):
closing it would extend spurious-RTO detection to
SACK-aware partial-coverage scenarios. Estimated
effort: ~3-4 commits.
