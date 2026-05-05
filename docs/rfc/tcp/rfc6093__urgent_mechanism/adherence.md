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

**Adherence:** the SHOULD NOT (for applications) is
moot from the stack's perspective; the MUST (on the
implementation) is **NOT met**.

PyTCP supports the URG flag and urgent-pointer wire
field at the parser/assembler layer:

- `net_proto/protocols/tcp/tcp__header.py:84` —
  `flag_urg: bool` field on the header dataclass.
- `net_proto/protocols/tcp/tcp__header.py:162` and
  `:195` — assemble / parse the URG bit at offset 5
  of the flag byte.
- `net_proto/protocols/tcp/tcp__assembler.py:66, 73,
  107, 115` — assembler accepts `tcp__flag_urg` and
  `tcp__urg` keyword arguments.
- `pytcp/stack/packet_handler/packet_handler__tcp__tx.py:114, 129`
  — TX path forwards both fields through to the
  assembler.

But there is no session-level urgent-data machinery:

- No `SND.UP` / `RCV.UP` urgent-pointer state on
  `TcpSession`.
- No URG-flag handling in any FSM state handler
  (`pytcp/protocols/tcp/tcp__fsm__*.py`); a peer's URG
  flag is silently ignored.
- No `SO_OOBINLINE` socket option in the
  `SocketOption` enum (`pytcp/socket/__init__.py`),
  no `MSG_OOB` recv flag, no application path to
  send or receive urgent data.
- The `TcpSocket` class
  (`pytcp/socket/tcp__socket.py`) exposes `send` and
  `recv` only with non-urgent semantics; an application
  cannot mark a `send` as urgent or read the most
  recent urgent byte.

The RFC 6093 §5 MUST is "implementations MUST still
include support for the urgent mechanism such that
existing applications can still use it". An application
running on PyTCP cannot use the urgent mechanism at
all — there is no API path for it. The wire-level
parse/assemble support is necessary but not sufficient
to satisfy §5; the application-facing path is required
and is missing.

---

## §6. Advice to Applications That Make Use of the Urgent Mechanism

> "applications that still decide to employ it MUST set
> the SO_OOBINLINE socket option, such that 'urgent
> data' is delivered in line, as intended by the IETF
> specifications."

**Adherence:** the requirement is on applications, not
on the stack. The corresponding stack obligation is to
implement `SO_OOBINLINE`; PyTCP does not (see §5
audit). With no `SO_OOBINLINE`, no application can
satisfy the §6 MUST when running on PyTCP — but the
violation is a consequence of the §5 gap, not a
separate one.

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

Not applicable beyond the wire-level coverage above.
There is no application-level urgent-data path for
test surface to exist on. A regression-guard test for
the §5 MUST would require first implementing
`SO_OOBINLINE` and the corresponding session-level
urgent-data buffer.

If §5 is to be addressed, the natural test additions
are:

1. Outbound: `sock.send(data=b"x", flags=MSG_OOB)`
   followed by an outbound segment with URG flag set
   and `urg` pointing to the byte after the urgent
   octet.
2. Inbound: a peer segment with URG flag and
   non-zero `urg` triggers `_rcv_up` advance and the
   urgent byte being readable via
   `sock.recv(flags=MSG_OOB)` (or in-line if
   `SO_OOBINLINE` is set).

**Status:** n/a (gap not closed; tests sketched above
should accompany the fix).

### §6 SO_OOBINLINE

Not implemented; no test surface.

### Test coverage summary

| Aspect                                                   | Coverage                                       |
|----------------------------------------------------------|------------------------------------------------|
| §4 Urgent pointer wire-level encoding                    | locked in (parser + assembler unit tests)      |
| §5 Stack support for urgent mechanism (application path) | n/a (gap not closed; tests sketched)           |
| §6 SO_OOBINLINE                                          | n/a (not implemented)                          |

---

## Overall assessment

| Aspect                                            | Status                       |
|---------------------------------------------------|------------------------------|
| §4 Wire-level urgent pointer semantics            | vacuously satisfied          |
| §5 Stack MUST support urgent mechanism            | not met                      |
| §5 Wire-level URG field parsing/assembling        | met (necessary, not sufficient) |
| §6 SO_OOBINLINE socket option                     | not implemented              |

PyTCP supports URG at the wire level but does not
expose the urgent mechanism to applications. RFC 6093
§5 explicitly requires that "TCP implementations MUST
still include support for the urgent mechanism such
that existing applications can still use it"; PyTCP
fails this MUST because no application-level path
exists. The natural minimum fix is:

1. Add `_rcv_up` / `_snd_up` urgent-pointer state on
   `TcpSession`.
2. On inbound: when `flag_urg` is set, advance
   `_rcv_up` to `seq + urg` (the §4 "octet following
   urgent data" semantics) and queue the urgent
   bytes either out-of-band or in-line per the
   socket's `SO_OOBINLINE` setting.
3. On outbound (application-driven): expose
   `MSG_OOB` to `send()`; when set, emit the segment
   with `flag_urg=True` and `urg = SND.NXT - 1` (the
   §4 RFC 793 §3.9 SEND-call shape).
4. Add the `SO_OOBINLINE` socket option (level
   `SOL_SOCKET`) to control in-line vs out-of-band
   delivery. Per §6, applications using the urgent
   mechanism MUST set it; PyTCP could default it on
   to make the in-line behaviour the universal
   semantics (matching the IETF intent).

Because RFC 6093 §1 strongly recommends against new
applications using the urgent mechanism at all, and
because the application-level urgent-data API is
historically a source of cross-stack interoperability
problems and security issues (NIDS evasion via
`phrack` techniques, cited in §3.4), the §5 MUST may
reasonably be weighed against PyTCP's "research /
educational stack" scope. The conformance gap is
documented; closing it is a discretionary engineering
choice.
