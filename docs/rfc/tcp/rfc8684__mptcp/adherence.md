# RFC 8684 — TCP Extensions for Multipath Operation with Multiple Addresses (MPTCP)

| Field       | Value                                                       |
|-------------|-------------------------------------------------------------|
| RFC number  | 8684                                                        |
| Title       | TCP Extensions for Multipath Operation with Multiple Addresses |
| Category    | Standards Track                                             |
| Date        | March 2020                                                  |
| Source text | [`rfc8684.txt`](rfc8684.txt)                                |

This document records, paragraph by paragraph, how
the current PyTCP codebase relates to each normative
statement in RFC 8684. Sections without normative
content (Abstract, §1 Introduction, §1.1-1.5
narrative, §2 Operation Overview, §5 Considerations,
§6-§9 IANA / Security / References / Acknowledgments)
are summarized rather than enumerated.

---

## Top-line adherence

PyTCP has **zero MPTCP support**. A grep across
`packages/pytcp/pytcp/`, `packages/net_proto/net_proto/`, and `packages/net_addr/net_addr/` returns no
references to MPTCP, Multipath TCP, MP_CAPABLE, MP_JOIN,
DSS, ADD_ADDR, or any other RFC 8684 wire-format
identifier. No `subflow`, `MPTCP`, or `mp_*` symbols
exist.

This audit is therefore a comprehensive gap report
rather than a paragraph-by-paragraph evaluation.

---

## §3 MPTCP Protocol Specification — Overview of Gaps

### §3.1 Connection Initiation: MP_CAPABLE option (Kind=30, Subtype=0)

**Adherence:** not implemented. PyTCP's
`packages/net_proto/net_proto/protocols/tcp/options/` does not include a
`tcp__option__mp_capable.py`. SYN exchanges are
single-subflow only.

### §3.2 Starting a New Subflow: MP_JOIN option (Subtype=1)

**Adherence:** not implemented.

### §3.3 General MPTCP Operation
- MP_TCPRST (Subtype=0xF)
- DSS (Data Sequence Signal, Subtype=2) — data-level
  sequence number, ACKs, FIN
- DATA_FIN at MPTCP level

**Adherence:** not implemented.

### §3.4 Address Knowledge Exchange: ADD_ADDR / REMOVE_ADDR

**Adherence:** not implemented.

### §3.5 Fast Close: MP_FASTCLOSE

**Adherence:** not implemented.

### §3.6 Subflow Reset: MP_TCPRST

**Adherence:** not implemented.

### §3.7 Fallback: ssMP_FAIL + Infinite Mapping

**Adherence:** not implemented.

### §3.8 Error Handling

**Adherence:** not implemented.

---

## §4 Semantic Issues

> "Path-level vs connection-level retransmits, OOO
> reassembly across subflows, scheduler choice,
> congestion control coupling (LIA, OLIA, etc.)"

**Adherence:** not applicable (no multi-subflow
support).

---

## Test coverage audit

No MPTCP tests exist. The closest single-subflow tests
are the standard handshake / data-transfer integration
tests under
`packages/pytcp/pytcp/tests/integration/protocols/tcp/`.

### Test coverage summary

| Aspect                              | Coverage  |
|-------------------------------------|-----------|
| §3.1 MP_CAPABLE                     | n/a (gap) |
| §3.2 MP_JOIN                        | n/a (gap) |
| §3.3 DSS / Data Sequence Signaling  | n/a (gap) |
| §3.4 ADD_ADDR / REMOVE_ADDR         | n/a (gap) |
| §3.5 MP_FASTCLOSE                   | n/a (gap) |
| §3.6 MP_TCPRST                      | n/a (gap) |
| §3.7 Fallback / MP_FAIL             | n/a (gap) |
| §4 multi-subflow scheduler          | n/a (gap) |

---

## Overall assessment

| Aspect                  | Status          |
|-------------------------|-----------------|
| All MPTCP normative     | not implemented |

PyTCP is a single-path TCP stack. MPTCP is explicitly
out of scope for the project — the existing stack
architecture (single `TcpSession` per connection,
single 5-tuple binding) does not have the substrate
for multi-subflow operation. Implementing MPTCP would
require:

- Connection-level vs subflow-level state separation:
  one `TcpConnection` aggregating multiple
  `TcpSession` instances per subflow.
- MPTCP option parsers and assemblers for at least 7
  option subtypes: MP_CAPABLE, MP_JOIN, DSS, ADD_ADDR,
  REMOVE_ADDR, MP_FAIL, MP_FASTCLOSE.
- Data-level sequence space + reassembly across
  subflows.
- Subflow scheduler.
- MPTCP-specific congestion control coupling (LIA,
  OLIA, or BALIA per RFC 6356 / informational drafts).
- Listener-fork extension to recognize MP_CAPABLE
  SYNs and create both the master subflow and the
  parent connection.

Estimated effort: ~50+ commits, multiple weeks of
work. This is not a short adherence-fill task; it
would be a separate large project.

The existing `.claude/rules/` directory has no
MPTCP project plan. The adjacent shipped project
that is closest in spirit (multiple option
parser/assembler + bilateral negotiation +
state machine extension) is the AccECN work, which
is roughly 1/10 the size of an MPTCP implementation.
