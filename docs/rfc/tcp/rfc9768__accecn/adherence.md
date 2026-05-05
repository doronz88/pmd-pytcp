# RFC 9768 — More Accurate ECN Feedback in TCP (AccECN)

| Field       | Value                                                                  |
|-------------|------------------------------------------------------------------------|
| RFC number  | 9768                                                                   |
| Title       | More Accurate Explicit Congestion Notification (AccECN) Feedback in TCP |
| Category    | Standards Track                                                        |
| Date        | April 2026                                                             |
| Updates     | RFC 3168                                                               |
| Source text | [`rfc9768.txt`](rfc9768.txt)                                           |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 9768. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused.

> **Note on RFC numbering**: PyTCP source comments
> consistently cite "RFC 9341" for AccECN, but RFC 9341
> is actually the unrelated "Alternate-Marking Method"
> document. The correct AccECN RFC is **9768**, which is
> what this audit uses. Updating the citations in
> `pytcp/protocols/tcp/tcp__session.py`,
> `pytcp/protocols/tcp/tcp__fsm__listen.py`, and
> `pytcp/protocols/tcp/tcp__fsm__syn_sent.py` is a
> pending source-comment fix outside this audit's
> scope.

Sections without normative content (Abstract, §1
Introduction, §1.1-§1.4 narrative, §2 Protocol
Overview, §6 Summary, §7 IANA, §8 Security,
References, Appendices) are omitted.

---

## §3.1.1 Negotiation During the TCP Three-Way Handshake

### Active-open SYN flag combination

> "During the TCP three-way handshake at the start of a
> connection, to request more Accurate ECN feedback the
> TCP Client (host A) MUST set the TCP flags
> (AE,CWR,ECE) = (1,1,1) in the initial SYN segment."

**Adherence:** met. The active-open path in
`pytcp/protocols/tcp/tcp__session.py:1409-1412` sets
all three flags (`flag_ns = flag_cwr = flag_ece =
True`) when `_advertise_accecn` is True and the
segment is a SYN-only:

```python
if flag_syn and not flag_ack and self._advertise_accecn:
    flag_ns = True
    flag_cwr = True
    flag_ece = True
```

The `flag_ns` field corresponds to the AE flag (NS bit
position) per RFC 9768 §3.1.1.

### Server-side SYN/ACK encoding (Table 2 top block)

> "Then it MUST set the AE, CWR, and ECE TCP flags on
> the SYN/ACK to the combination in the top block of
> Table 2 that feeds back the IP-ECN field that arrived
> on the SYN."

| IP-ECN on SYN | AccECN SYN/ACK (AE,CWR,ECE) |
|---------------|------------------------------|
| Not-ECT (00)  | (0,1,0)                      |
| ECT(1)  (01)  | (0,1,1)                      |
| ECT(0)  (10)  | (1,0,0)                      |
| CE      (11)  | (1,1,1)                      |

**Adherence:** met. The passive-open SYN+ACK path in
`tcp__session.py:1428-1432` encodes the IP-ECN
codepoint into the three flags using the formulae:

- `flag_ns = bool(cp & 0b10)` — AE = bit1 of codepoint
- `flag_cwr = (cp & 0b10) == 0 or (cp & 0b01) != 0` —
  CWR set unless ECT(0)
- `flag_ece = bool(cp & 0b01)` — ECE = bit0

Verifying against Table 2:
- Not-ECT (cp=0b00): AE=0, CWR=(True or False)=True, ECE=0 → (0,1,0) ✓
- ECT(1)  (cp=0b01): AE=0, CWR=(True or True)=True,  ECE=1 → (0,1,1) ✓
- ECT(0)  (cp=0b10): AE=1, CWR=(False or False)=False, ECE=0 → (1,0,0) ✓
- CE      (cp=0b11): AE=1, CWR=(False or True)=True,  ECE=1 → (1,1,1) ✓

The codepoint is captured on the inbound SYN at
`tcp__fsm__listen.py:236`:
`session._accecn_synack_codepoint = packet_rx_md.ip__ecn`.

### Client-side mode entry post-SYN/ACK

> "Once a TCP Client (A) has sent the above SYN to
> declare that it supports AccECN, and once it has
> received the above SYN/ACK segment that confirms that
> the TCP Server supports AccECN, the TCP Client MUST
> set both its half-connections into AccECN mode."

**Adherence:** met. `tcp__fsm__syn_sent.py:257-258`
checks for the AccECN signature on inbound SYN+ACK:

```python
if session._advertise_accecn and (
    packet_rx_md.tcp__flag_ns or packet_rx_md.tcp__flag_cwr
):
    session._accecn_enabled = True
```

The check uses (NS or CWR) presence as the AccECN
discriminator — this distinguishes any of the four
top-block combinations from the RFC 3168 fallback
(0,0,1) which has neither NS nor CWR set.

### Server-side mode entry on SYN

> "If a TCP Server (host B) that is AccECN-enabled
> receives a SYN with the above three flags set, it
> MUST set both its half-connections into AccECN mode."

**Adherence:** met. `tcp__fsm__listen.py:228-236`
gates AccECN entry on `_advertise_accecn` AND the
arrival of the (1,1,1) signature. The session's
`_accecn_enabled` is set True before the SYN+ACK is
emitted, so the SYN+ACK encoding (above) sees the
state correctly.

---

## §3.1.2 Backward Compatibility (Table 2 second block)

> "An AccECN Client falls back to Classic ECN feedback
> if the SYN/ACK is (0,0,1), or to Not ECN if (0,0,0)."

**Adherence:** met. The active-open SYN+ACK handler
also checks `_advertise_ecn` separately at
`tcp__session.py:1413-1415`. If the peer's SYN+ACK
has neither NS nor CWR set but has ECE only, the
session falls back to RFC 3168 ECN (`_ecn_enabled =
True` set in the FSM handler).

The RFC's "Broken" combination ((1,1,1) reflected in
SYN/ACK) is not specially handled — PyTCP would
interpret it as AccECN-confirmed (CE-on-SYN) per the
codepoint encoding. This is a §3.1.2 fourth-block gap
where AccECN's SHOULD fall back to Not ECN to mitigate
the broken-server case.

**Status:** partial — the four valid AccECN
combinations and the RFC 3168 fallback work; the
broken-server (1,1,1) reflection is not detected.

---

## §3.1.3 Forward Compatibility

> "If a TCP Server that implements AccECN receives a
> SYN with the three TCP header flags (AE,CWR,ECE) set
> to any combination other than (0,0,0), (0,1,1), or
> (1,1,1) and it does not have logic specific to such a
> combination, the Server MUST negotiate the use of
> AccECN as if the three flags had been set to
> (1,1,1)."

**Adherence:** not implemented. The listener gate at
`tcp__fsm__listen.py` checks for a clean (1,1,1) match
only; other "future" combinations like (1,0,0),
(1,1,0), (0,1,0), etc. would not enter AccECN mode.

This is a forward-compatibility gap that may matter
when future TCP extensions arrive.

**Status:** gap.

---

## §3.1.5 Implications of AccECN Mode

> "Any implementation that supports AccECN MUST NOT
> switch into a different feedback mode from the one it
> first entered according to Table 2, no matter whether
> it subsequently receives valid SYNs or Acceptable
> SYN/ACKs of different types."

**Adherence:** met implicitly. PyTCP's
`_accecn_enabled` is set once during handshake and
never cleared post-ESTABLISHED.

> "MUST NOT set ECT if it is in Not ECN feedback mode."

**Adherence:** met.
`tcp__session.py:1500` gates ECT marking on
`self._ecn_enabled and data`. Without bilateral ECN,
ECT is not set.

> "A TCP Server in AccECN mode MUST NOT set ECT on any
> packet for the rest of the connection if it has
> received or sent at least one valid SYN or Acceptable
> SYN/ACK with (AE,CWR,ECE) = (0,0,0) during the
> handshake."

**Adherence:** not specifically enforced. PyTCP gates
ECT on `_ecn_enabled`; if a (0,0,0) SYN is received
when AccECN is enabled, the session would have
entered Not ECN mode (since `_advertise_accecn` would
not gate True against a (0,0,0) signature).

> "A host in AccECN mode MUST NOT set CWR to indicate
> that it has received and responded to indications of
> congestion."

**Adherence:** met. CWR setting in PyTCP's
`tcp__session.py` is gated on
`self._ecn_enabled and self._ecn_send_cwr and data`
(line 1461) for RFC 3168 ECN. The AccECN branch above
that uses CWR purely as an ACE-counter bit — it does
NOT independently set CWR for congestion-response
acknowledgement when in AccECN mode.

---

## §3.2.1 Initialization of Feedback Counters

> "When a host first enters AccECN mode, in its role as
> a Data Receiver, it initializes its counters to
> r.cep = 5, r.e0b = r.e1b = 1, and r.ceb = 0.
>
> When a host enters AccECN mode, in its role as a Data
> Sender, it initializes its counters to s.cep = 5,
> s.e0b = s.e1b = 1, and s.ceb = 0."

**Adherence:** partial. `tcp__session.py:361-374` and
the surrounding lines initialize:

```python
self._accecn_r_cep: int = 5             # OK matches RFC
self._accecn_r_ect0_b: int = 0          # SHOULD BE 1
self._accecn_r_ce_b: int = 0            # OK matches RFC (r.ceb)
self._accecn_r_ect1_b: int = 0          # SHOULD BE 1
self._accecn_s_ce_b: int = 0            # OK as initial s.ceb
```

The `r.cep` initial value 5 is correct. However, the
`r.e0b` and `r.e1b` byte counters initialize to 0 in
PyTCP — RFC 9768 §3.2.1 mandates initial value 1
specifically to be distinct from middlebox-zeroed
fields (§3.2.3.2.4 detection).

**Status:** non-conformant initial values for r.e0b /
r.e1b (off by 1).

---

## §3.2.2 The ACE Field

### ACE encoding on non-SYN segments

> "On such a packet [SYN=0], a Data Receiver MUST
> encode the 3 least significant bits of its r.cep
> counter into the ACE field that it feeds back to the
> Data Sender."

**Adherence:** met. `tcp__session.py:1441-1445`:

```python
elif self._accecn_enabled and not flag_rst:
    ace = self._accecn_r_cep & 0b111
    flag_ns = bool(ace & 0b100)
    flag_cwr = bool(ace & 0b010)
    flag_ece = bool(ace & 0b001)
```

The 3-bit field is encoded into AE (bit 2), CWR
(bit 1), ECE (bit 0). Matches the RFC's bit ordering.

### r.cep increment on inbound CE

> "The Data Receiver MUST increment the CE packet
> counter (r.cep), for every Acceptable packet that it
> receives with the CE code point in the IP-ECN field,
> including CE-marked control packets and
> retransmissions but excluding CE on SYN packets."

**Adherence:** met. The session's `_process_ack_packet`
at `tcp__session.py:3578-3585` increments `r.cep` and
the byte counters on inbound CE codepoints; the
SYN-exclusion is handled implicitly because the FSM
dispatches SYN handling before this branch.

### §3.2.2.1 ACE field on the ACK of the SYN/ACK
(handshake encoding Table 3)

> "The TCP Client uses the binary encoding in Table 3
> when writing the ACE field on the pure ACK of the
> SYN/ACK to feed back which of the 4 possible values
> of the IP-ECN field was on the SYN/ACK."

**Adherence:** not implemented. PyTCP's
`tcp__session.py:1441-1445` always encodes
`_accecn_r_cep & 0b111` into ACE on non-SYN segments
— it does NOT use the special handshake encoding from
Table 3 on the ACK of the SYN/ACK. The Client's first
post-SYN+ACK ACK would carry `(r.cep & 7)` which on
fresh sessions is `5 & 7 = 0b101` rather than the
Table-3 encoding (e.g. 0b010 for Not-ECT SYN/ACK).

**Status:** gap. The Server's Table-4 inference logic
on the inbound first ACK is also not implemented.

### §3.2.2.5 Safety Against Ambiguity (cycle handling)

**Adherence:** not implemented. PyTCP's response on
inbound AccECN counter delta in
`tcp__session.py:3623-3639` simply checks if
`tcp__accecn0_counters[1]` (s.ceb) advanced and treats
it as a single congestion event. The §3.2.2.5.2 cycle
detection (estimating how many segments could have
been acknowledged when ACE could have wrapped) is not
performed.

**Status:** gap, but the byte counters in AccECN
options largely sidestep the cycle issue when options
are present.

---

## §3.2.3 The AccECN Option

### Option Kind 172 / 174 wire format

> "When a Data Receiver sends an AccECN Option, it MUST
> set the Kind field to 172 if using Order 0, or to
> 174 if using Order 1."

**Adherence:** met for Order 0 (Kind 172). PyTCP's
`tcp__session.py:1476-1490` always emits the AccECN0
option with the byte counters. The Order-1 (Kind 174)
form is not used; this is allowed per RFC 9768 (peers
choose either ordering).

The packet handler TX code wires
`tcp__accecn0_counters` into the wire format at
length 11 (full 3-field option).

### Option content per Table 5

| Length | Order 0 fields            |
|--------|---------------------------|
| 11     | EE0B, ECEB, EE1B          |
| 8      | EE0B, ECEB                |
| 5      | EE0B                      |
| 2      | (empty)                   |

**Adherence:** met for Length 11 (full form). PyTCP
does not implement the abbreviated forms (8, 5, 2);
the full 11-byte form is always sent. This is
permissible — the abbreviated forms are an
optimization.

### §3.2.3.3 Usage of the AccECN TCP Option

> "An AccECN Data Receiver SHOULD include an AccECN
> Option on every ACK that it sends, while there are
> any new bytes to feed back."

**Adherence:** met (over-conservatively — the option
is included on every non-SYN, non-RST outbound segment
of an AccECN connection unconditionally per
`tcp__session.py:1485`).

---

## §4 Updates to RFC 3168

> "This document updates RFC 3168 with respect to
> negotiation and use of the feedback scheme for TCP."

**Adherence:** met implicitly. PyTCP's AccECN path
takes precedence over the RFC 3168 path in negotiation
(active-open SYN signature; passive listener gate;
SYN+ACK encoding); RFC 3168 is the fallback when peer
does not advertise AccECN.

---

## §5.3 Compatibility with SACK / DSACK

> "It is RECOMMENDED that the AccECN protocol be
> implemented alongside Selective Acknowledgement
> (SACK) [RFC2018]. If SACK is implemented with AccECN,
> Duplicate Selective Acknowledgement (D-SACK) [RFC2883]
> MUST also be implemented."

**Adherence:** met. PyTCP implements SACK (RFC 2018),
DSACK (RFC 2883), and AccECN; bilateral negotiation
of all three on a single connection is supported.

---

## Test coverage audit

### §3.1.1 active-open AccECN-setup SYN

- **Integration:**
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__accecn.py`
  drives an active-open with `_advertise_accecn = True`
  and verifies the outbound SYN carries (NS, CWR, ECE)
  = (1, 1, 1).

**Status:** locked in.

### §3.1.1 passive-open SYN+ACK encoding

- **Integration:** the file drives passive opens with
  the four IP-ECN codepoints (Not-ECT, ECT(0), ECT(1),
  CE) and verifies the outbound SYN+ACK carries the
  Table-2 codepoint encoding.

**Status:** locked in.

### §3.1.1 mode entry on bilateral negotiation

- **Integration:** post-handshake assertions verify
  `_accecn_enabled = True` after both peers carry
  AccECN signatures.

**Status:** locked in.

### §3.1.2 fallback to RFC 3168 / Not ECN

- **Integration:** integration tests verify peer
  responding with (0,0,1) results in
  `_ecn_enabled = True, _accecn_enabled = False`, and
  peer responding with (0,0,0) leaves both False.

**Status:** locked in (Broken-server (1,1,1)
reflection: gap).

### §3.1.3 forward compatibility

- No tests; not implemented in code.

**Status:** n/a (gap).

### §3.2.1 counter initialization

- **Unit / Integration:** post-handshake assertions
  verify `_accecn_r_cep == 5`. The off-by-one initial
  values for `_accecn_r_ect0_b` / `_accecn_r_ect1_b`
  are pinned to PyTCP's 0 (not the RFC's 1) — tests
  encode the implementation, not the spec.

**Status:** test pins implementation; spec deviation.

### §3.2.2 ACE encoding on non-SYN segments

- **Integration:** drives inbound CE-marked data,
  verifies outbound ACK ACE field reflects
  `_accecn_r_cep & 7`.

**Status:** locked in.

### §3.2.2.1 handshake encoding on ACK of SYN/ACK

- No tests; not implemented.

**Status:** n/a (gap).

### §3.2.3 AccECN option emission

- **Integration:** drives an AccECN connection,
  verifies outbound segments carry the AccECN0 option
  with the byte counters.

**Status:** locked in (Order 0 only; abbreviated forms
not exercised).

### §3.2.2.5 cycle-handling safety

- No tests; not implemented.

**Status:** n/a (gap).

### Test coverage summary

| Aspect                                           | Coverage                       |
|--------------------------------------------------|--------------------------------|
| §3.1.1 active-open SYN signature                 | locked in                      |
| §3.1.1 SYN+ACK Table-2 codepoint encoding        | locked in                      |
| §3.1.1 mode entry post-handshake                 | locked in                      |
| §3.1.2 RFC 3168 fallback                         | locked in                      |
| §3.1.2 Broken-server (1,1,1) reflection          | n/a (gap)                      |
| §3.1.3 forward compatibility                     | n/a (gap)                      |
| §3.2.1 counter initial values                    | partial (off-by-1 r.e0b/r.e1b) |
| §3.2.2 ACE encoding on non-SYN                   | locked in                      |
| §3.2.2.1 handshake encoding (Tables 3+4)         | n/a (gap)                      |
| §3.2.2.5 cycle handling                          | n/a (gap)                      |
| §3.2.3 AccECN0 option emission                   | locked in (Order 0, length 11) |
| §3.2.3 abbreviated option forms (length 8, 5, 2) | n/a                            |
| §4 Updates to RFC 3168 (negotiation precedence)  | locked in                      |
| §5 SACK + DSACK alongside AccECN                 | locked in                      |

---

## Overall assessment

| Aspect                                       | Status                                     |
|----------------------------------------------|--------------------------------------------|
| §3.1.1 negotiation (basic)                   | met                                        |
| §3.1.2 RFC 3168 fallback                     | met                                        |
| §3.1.2 Broken-server detection               | not implemented                            |
| §3.1.3 forward compatibility                 | not implemented                            |
| §3.1.5 mode-mode invariants                  | met implicitly                             |
| §3.2.1 r.cep initial value                   | met                                        |
| §3.2.1 r.e0b / r.e1b initial values          | non-conformant (uses 0 instead of 1)       |
| §3.2.2 ACE encoding on non-SYN               | met                                        |
| §3.2.2.1 handshake encoding (ACK of SYN/ACK) | not implemented                            |
| §3.2.2.3 IP-ECN mangling test                | not implemented                            |
| §3.2.2.5 cycle handling                      | not implemented                            |
| §3.2.3 AccECN0 option (Kind 172, Order 0)    | met (full length 11 only)                  |
| §3.2.3 AccECN1 option (Kind 174, Order 1)    | not implemented                            |
| §3.2.3 abbreviated lengths (8, 5, 2)         | not implemented                            |
| §4 Updates to RFC 3168                       | met                                        |
| §5.3 SACK + DSACK + AccECN coexistence       | met                                        |

PyTCP's AccECN implementation covers the negotiation
flow (active and passive open), the post-handshake ACE
encoding on non-SYN segments, and the AccECN0 option
(full 11-byte form). The core feedback loop works:
peer's CE marks reach the sender via either the ACE
field or the byte counters in the option.

Implementation gaps cluster in three areas:

1. **Edge-case handshake encoding** (§3.2.2.1
   handshake-encoded ACK of SYN/ACK; §3.1.3 forward
   compatibility): less critical, primarily affects
   IP-ECN-mangling detection.
2. **Counter initial values** (§3.2.1): off-by-one
   r.e0b / r.e1b. Easy fix.
3. **Cycle / wrap safety** (§3.2.2.5): when AccECN0
   options are stripped by middleboxes, the safety
   procedures for ACE wrap detection are not
   implemented. The pure-ACE-only mode is rare in
   practice.

The most consequential gap is the off-by-one in
§3.2.1 — easy to fix and pinned by an updated test.
The handshake-encoding (§3.2.2.1) and forward-
compatibility (§3.1.3) gaps are larger but less
exercised in practice.

The codebase's misattribution of "RFC 9341" instead of
RFC 9768 in source comments is a separate cleanup
task, not a functional gap.
