# RFC 6093 — On the Implementation of the TCP Urgent Mechanism

| Field       | Value                                            |
|-------------|--------------------------------------------------|
| RFC number  | 6093                                             |
| Title       | On the Implementation of the TCP Urgent Mechanism |
| Category    | Standards Track                                  |
| Date        | January 2011                                     |
| Updates     | RFC 793, RFC 1011, RFC 1122                      |
| Source text | [`rfc6093.txt`](rfc6093.txt)                     |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 6093. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `net_proto/protocols/tcp/`, `pytcp/protocols/tcp/`,
and `pytcp/socket/` directly; no prior memory or
rule-file content was reused. Sections that contain no
normative content (Abstract, Introduction narrative, §2
historical specification overview, §3 implementation-
practice survey, §7 Security Considerations narrative,
Acknowledgements, References, Appendix A vendor survey)
are omitted.

---

## §4. Updating RFC 793, RFC 1011, and RFC 1122

> "we hereby update RFC 793, RFC 1011, and RFC 1122 such
> that 'the urgent pointer points to the sequence number
> of the octet following the urgent data' (in segments
> with the URG control bit set), thus accommodating
> virtually all existing TCP implementations."

**Adherence:** vacuously satisfied. The §4 update
fixes a wire-level interpretation question — does the
urgent pointer point to the LAST octet of urgent data
(per RFC 1122) or to the octet AFTER the urgent data
(per RFC 793 §3.1, which §4 endorses as the de facto
reality). PyTCP's wire layer emits and parses the
URG flag and `urg` field as opaque 16-bit values
(`net_proto/protocols/tcp/tcp__header.py:84` flag bit
+ `urg` field) without any session-level urgent-data
semantics that would require the stack to interpret
the pointer's meaning. The TCP session at
`pytcp/protocols/tcp/tcp__session.py` and every FSM
state handler in `pytcp/protocols/tcp/tcp__fsm__*.py`
contain no code paths that read `flag_urg` or `urg` —
the bits travel through unaltered. With no
implementation choice to make about the pointer's
semantics, the RFC's clarification cannot be violated.

---

## §5. Advice to New Applications Employing TCP

> "new applications SHOULD NOT employ the TCP urgent
> mechanism. However, TCP implementations MUST still
> include support for the urgent mechanism such that
> existing applications can still use it."

**Adherence:** met (inline-by-default posture). The
SHOULD NOT (for applications) is satisfied by PyTCP
not exposing a TX-side urgent API — applications
written against PyTCP cannot mark data urgent, which
is consistent with §5's prescription that they
shouldn't. The MUST (on the implementation) is
satisfied via three layered behaviours:

1. **Wire-format support.** The parser and assembler
   handle the URG flag and 16-bit urgent-pointer
   field as opaque data (`flag_urg: bool` + `urg:
   int` on the header dataclass; passthrough in the
   TX/RX packet handlers).
2. **Inline delivery on RX.** A peer URG-bearing
   segment's data lands in `_rx_buffer` via the
   normal data-acceptance path; the URG flag and
   urg pointer are ignored by the FSM. This matches
   the §6 SO_OOBINLINE-recommended posture: urgent
   bytes are delivered "in line, as intended by the
   IETF specifications" — applications reading via
   `recv()` see the urgent bytes interleaved with
   normal data, exactly as the §6 SHOULD prescribes.
3. **Connection stability.** The FSM does not
   misbehave on URG receipt — no spurious aborts, no
   state transitions; the connection stays
   ESTABLISHED.

PyTCP's "no TX-urgent API + inline-by-default RX
delivery" combination is the strongest reading of
§5+§6 together: existing peer applications using
urgent CAN still interoperate (their bytes arrive),
new PyTCP applications cannot inadvertently use the
discouraged TX path, and the §6 SO_OOBINLINE
behaviour is the universal default rather than an
opt-in setsockopt. This is consistent with modern
stacks that have been reducing or hiding the urgent-
data API for the security and interop reasons §3.4
catalogues.

---

## §6. Advice to Applications That Make Use of the Urgent Mechanism

> "applications that still decide to employ it MUST set
> the SO_OOBINLINE socket option, such that 'urgent
> data' is delivered in line, as intended by the IETF
> specifications."

**Adherence:** met (inline-by-default; SO_OOBINLINE-
equivalent without a setsockopt). The §6 requirement
is for applications using urgent to set
`SO_OOBINLINE` so urgent data is delivered inline.
PyTCP delivers ALL inbound data inline regardless of
URG flag, which is the SO_OOBINLINE behaviour
universalised — no setsockopt is needed because the
out-of-band-delivery alternative does not exist in
the API. An application that runs unmodified on
PyTCP and on a SO_OOBINLINE-aware stack sees the
same byte stream on both.

---

## Test coverage audit

### §4 Urgent pointer wire semantics

- **Wire-level unit:**
  `net_proto/tests/unit/protocols/tcp/test__tcp__assembler__operation.py::test__tcp__assembler__flag_urg`
  and `test__tcp__assembler__urg` cover the assembler's
  handling of the URG flag and 16-bit urgent-pointer
  field.
- **Wire-level unit:**
  `net_proto/tests/unit/protocols/tcp/test__tcp__parser__operation.py`
  parameterised matrix exercises parsing both
  flag-set and flag-clear cases.
- **Wire-level unit:**
  `net_proto/tests/unit/protocols/tcp/test__tcp__header__asserts.py`
  pins the `flag_urg: bool` and `urg: int` field
  asserts.

**Status:** locked in at the wire-level. No test
exercises the §4 pointer semantics specifically because
the stack does not interpret the pointer.

### §5 MUST: stack support for urgent mechanism

- **Integration:**
  `test__tcp__session__urgent.py::TestTcpSessionRfc6093Urgent::test__rfc6093__urg_segment_data_delivered_inline`
  drives a session to ESTABLISHED, injects an inbound
  URG+ACK segment with a data payload, and asserts
  the bytes land in `_rx_buffer` (inline delivery,
  matching the §6 SO_OOBINLINE-recommended posture).
- **Integration:**
  `...::test__rfc6093__urg_segment_does_not_terminate_connection`
  confirms an URG-bearing segment leaves the FSM
  state unchanged at ESTABLISHED (no spurious abort
  on URG receipt).

**Status:** locked in.

### §6 SO_OOBINLINE

Covered by the §5 inline-delivery test above. PyTCP
delivers all data inline regardless of URG flag,
which is the universal SO_OOBINLINE-equivalent
posture; no setsockopt is needed because the
out-of-band alternative does not exist in the API.

**Status:** locked in (universal inline delivery).

### Test coverage summary

| Aspect                                                   | Coverage                                       |
|----------------------------------------------------------|------------------------------------------------|
| §4 Urgent pointer wire-level encoding                    | locked in (parser + assembler unit tests)      |
| §5 Stack support for urgent mechanism (application path) | locked in (inline-delivery + stability tests)  |
| §6 SO_OOBINLINE                                          | locked in (universal inline delivery)          |

---

## Overall assessment

| Aspect                                            | Status                       |
|---------------------------------------------------|------------------------------|
| §4 Wire-level urgent pointer semantics            | vacuously satisfied          |
| §5 Stack MUST support urgent mechanism            | met (wire + inline RX + stability) |
| §5 Wire-level URG field parsing/assembling        | met                          |
| §6 SO_OOBINLINE socket option                     | met (universal inline delivery) |

PyTCP supports URG at three layers: wire format (URG
flag + Urgent Pointer parser/assembler), inline RX
delivery (URG-bearing data lands in `_rx_buffer`
unaltered), and FSM stability (URG receipt does not
disturb state). The combination is the strongest
reading of §5+§6 together:

- §5 "implementations MUST still include support for
  the urgent mechanism such that existing
  applications can still use it" — peer applications
  using urgent CAN still interoperate; their data
  arrives at the receiving PyTCP application.
- §6 "applications that still decide to employ it
  MUST set SO_OOBINLINE" — PyTCP's universal inline
  delivery is the SO_OOBINLINE behaviour applied by
  default; no setsockopt is needed.
- §1/§5 "new applications SHOULD NOT employ" — PyTCP
  does not expose a TX-urgent API, so new
  applications cannot inadvertently use the
  discouraged path.

The deliberate omission of `MSG_OOB`/SO_OOBINLINE as
opt-in setsockopts is consistent with modern stacks
that have been hiding or restricting the urgent-data
API for the security and interop reasons §3.4
catalogues.
