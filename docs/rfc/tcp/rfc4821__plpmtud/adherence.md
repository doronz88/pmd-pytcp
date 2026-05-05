# RFC 4821 — Packetization Layer Path MTU Discovery (PLPMTUD)

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 4821                                               |
| Title       | Packetization Layer Path MTU Discovery             |
| Category    | Standards Track                                    |
| Date        | March 2007                                         |
| Source text | [`rfc4821.txt`](rfc4821.txt)                       |

This document records, paragraph by paragraph, how
the current PyTCP codebase relates to each normative
statement in RFC 4821.

---

## Top-line adherence

PyTCP has **zero PLPMTUD support**. A grep across
`pytcp/`, `net_proto/`, and `net_addr/` returns no
references to PLPMTUD, search-string, probe size,
search range, MIN_PROBE_RTX, or any RFC 4821
identifier.

---

## §3 Algorithm Overview — Gaps

### §3 Probing without ICMP

> "PLPMTUD MUST work without depending on ICMP
> messages. The packetization layer (TCP) probes
> directly with progressively larger segments and
> uses the loss / no-loss feedback as the signal."

**Adherence:** not implemented.

### §5 Probe segment generation

> "The TCP probe is a regular data segment with size
> equal to the current probe size; loss of the probe
> indicates the path cannot carry that size."

**Adherence:** not implemented.

### §7.5 Black hole detection

> "When repeated retransmissions of full-MSS-sized
> segments fail without any other indication, the
> sender SHOULD attempt to reduce its effective MTU
> as a black-hole detection step."

**Adherence:** not implemented. PyTCP retransmits
the same MSS-sized segments via the standard RFC
6298 RTO machinery without any size-reduction
fallback.

---

## Test coverage audit

No PLPMTUD tests exist.

### Test coverage summary

| Aspect                              | Coverage  |
|-------------------------------------|-----------|
| §3 ICMP-independent probing         | n/a (gap) |
| §5 probe segment generation         | n/a (gap) |
| §7.5 black-hole detection           | n/a (gap) |
| §8 search algorithm                 | n/a (gap) |

---

## Overall assessment

| Aspect                                | Status          |
|---------------------------------------|-----------------|
| §3 ICMP-independent path-MTU search   | not implemented |
| §5 probe segment + loss feedback      | not implemented |
| §7.5 black-hole detection             | not implemented |
| §8 binary-search probe size           | not implemented |

PyTCP relies on the local interface MTU. The
RFC 4821 vs RFC 1191 trade-off (PLPMTUD does not
trust ICMP / works through ICMP-blocking
middleboxes; classic PMTUD is simpler when ICMP
gets through) is moot for PyTCP because neither is
implemented.

Implementing PLPMTUD would require:
- A per-session probe state machine (search-low,
  search-high, current-probe-size, last-known-good).
- A probe-segment generation hook: occasionally
  send a larger-than-current-MSS segment with the
  expectation of "loss = path doesn't support this
  size; advance search-high downward".
- Black-hole detection: track consecutive RTOs of
  full-MSS segments and reduce MSS on a threshold.
- Periodic re-probe after an idle period to detect
  path-MTU increases.

Estimated effort: ~8-10 commits.
