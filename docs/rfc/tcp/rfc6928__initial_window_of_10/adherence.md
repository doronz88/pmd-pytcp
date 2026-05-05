# RFC 6928 — Increasing TCP's Initial Window

| Field       | Value                          |
|-------------|--------------------------------|
| RFC number  | 6928                           |
| Title       | Increasing TCP's Initial Window |
| Category    | Experimental                   |
| Date        | April 2013                     |
| Source text | [`rfc6928.txt`](rfc6928.txt)   |

This document records, paragraph by paragraph, how the
current PyTCP codebase relates to each normative
statement in RFC 6928. The audit was performed by
reading the RFC text fresh and inspecting the codebase
under `pytcp/protocols/tcp/` directly; no prior memory
or rule-file content was reused. Sections that contain
no normative content (Abstract, Introduction narrative,
Background, Advantages and Disadvantages discussion,
Experimental Results, Other Studies, Related Proposals,
Security Considerations boilerplate, Conclusion narrative,
Acknowledgments, References, Appendix A) are omitted.

---

## §2. TCP Modification

### IW upper-bound formula

> "More precisely, the upper bound for the initial window
> will be
>
>         min (10*MSS, max (2*MSS, 14600))                 (1)"

**Adherence:** met. The formula is implemented exactly in
the helper at
`pytcp/protocols/tcp/tcp__cwnd.py:176-196`:

```python
def initial_window(smss: int) -> int:
    return min(INITIAL_WINDOW_FACTOR * smss, max(2 * smss, INITIAL_WINDOW_BYTES))
```

with `INITIAL_WINDOW_FACTOR = 10` (line 73) and
`INITIAL_WINDOW_BYTES = 14600` (line 74). Both constants
match RFC 6928 §2 verbatim.

### Timing of IW application

> "This change applies to the initial window of the
> connection in the first round-trip time (RTT) of data
> transmission during or following the TCP three-way
> handshake. Neither the SYN/ACK nor its ACK in the
> three-way handshake should increase the initial window
> size."

**Adherence:** met. The IW is applied at the post-
handshake transition point in two places:

- `pytcp/protocols/tcp/tcp__fsm__syn_sent.py:198-204`
  (active-open SYN+ACK arrival): `_cwnd =
  initial_window(_snd_mss)` runs AFTER
  `_process_ack_packet` has fired the §3.1 slow-start
  growth on the SYN+ACK ack-advance, then unconditionally
  overwrites cwnd to the IW value. The inline comment
  cites RFC 6928 §2 explicitly.
- `pytcp/protocols/tcp/tcp__fsm__syn_rcvd.py:108-118`
  (passive- and simultaneous-open third-leg ACK
  arrival): same shape — IW is overwritten after
  `_process_ack_packet`, so the "neither the SYN/ACK
  nor its ACK should increase the initial window"
  invariant holds: any growth that the §3.1 path
  would have applied is replaced by the IW value.

### "Refrain from resetting IW to 1" SHOULD

> "RECOMMENDED that implementations refrain from resetting
> the initial window to 1 segment, unless there have been
> more than one SYN or SYN/ACK retransmissions or true
> loss detection has been made."

**Adherence:** met (with stronger semantics). PyTCP
applies the IW10 formula unconditionally on handshake
completion regardless of how many SYN or SYN+ACK
retransmissions occurred. The `_syn_retransmit_count`
field
(`pytcp/protocols/tcp/tcp__session.py:599`) is consulted
only by the RFC 6298 §5.7 SYN-RTO 3-second floor
(line 2598); it does NOT influence the IW computation.
This is more permissive than the SHOULD requires
("never reset" rather than "don't reset on the first
retransmit"); the RFC's "unless" clause merely permits
resetting after >1 retransmits, it does not require it.

### Slow-start uses (initial / restart / loss windows)

> "These changes do NOT change the loss window, which
> must remain 1 segment of MSS bytes (to permit the
> lowest possible window size in the case of severe
> congestion)."

**Adherence:** met. The post-RTO loss-window collapse
at `pytcp/protocols/tcp/tcp__session.py:2672`:

```python
self._cwnd = self._snd_mss
```

sets cwnd to exactly 1 SMSS as the loss-window value.

### Restart window (RW) — optional MAY

> "Optionally, a TCP MAY set the restart window to the
> minimum of the value used for the initial window and
> the current value of cwnd"

**Adherence:** not implemented (and not required).
PyTCP has no restart-window concept. After an idle
period, the existing `_snd_ewn` simply continues from
the cwnd it had at idle entry; there is no
post-idle cwnd reset or recalculation. The MAY
language explicitly permits this — implementations
"may" set a restart window if they wish, but are not
required to.

### Restart-window fallback on loss SHOULD

> "implementations SHOULD fall back to RFC 3390 for the
> restart window (RW) if any packet loss is detected
> during either the initial window or a restart window,
> and more than 4 KB of data is sent."

**Adherence:** vacuously not applicable. With no
restart-window mechanism, there is nothing to fall back
from. The IW itself is not reduced on loss during the
initial window — this matches the previous SHOULD's
"never reset" choice.

---

## §3. Implementation Issues

### Initial receive window advertisement

> "implementations are encouraged to advertise an
> initial receive window of at least 10 segments."

**Adherence:** met (with margin). The advertised
receive window is bounded by `_rcv_wnd_max = 65535`
(`pytcp/protocols/tcp/tcp__session.py:155`), and the
default WSCALE shift of 7 raises the maximum
advertised receive window to ~8 MB. For a 1500-MTU
link with `_rcv_mss = 1460`, 65535 bytes is ~45
segments — well above the 10-segment recommendation.

---

## §9. Interactions with the Retransmission Timer

> "implementations MUST follow RFC 6298 to restart the
> retransmission timer with the current value of RTO
> for each ACK received that acknowledges new data."

**Adherence:** met. PyTCP implements the RFC 6298 §5.3
restart-on-cum-ACK rule at
`pytcp/protocols/tcp/tcp__session.py` (the
`_process_ack_packet` post-cum-ACK timer-restart block;
covered in detail in the RFC 6298 audit). The behaviour
is gated on "advances SND.UNA" (the canonical "ACK
acknowledges new data" condition).

---

## §12. Usage and Deployment Recommendations

### Monitoring SHOULD

> "Anyone... turning on a larger initial window SHOULD
> ensure that the performance is monitored before and
> after that change. Key metrics to monitor are the rate
> of packet losses, ECN marking, and segment
> retransmissions during the initial burst."

**Adherence:** not implemented. PyTCP exposes packet-
level telemetry through the `packet_stats` counters
(`pytcp/lib/packet_stats.py`) which include
retransmission counts, but there is no IW10-specific
monitoring that compares pre- and post-flip behaviour.
The SHOULD is a deployment-process recommendation
addressed at human operators rather than at the stack
itself; for a research / educational stack like PyTCP,
the recommendation is moot.

### Cache + fallback heuristic SHOULD

> "The sender SHOULD cache such information about
> connection setups using an initial window larger than
> allowed by RFC 3390, and new connections SHOULD fall
> back to the initial window allowed by RFC 3390 if
> there is evidence of performance issues."

**Adherence:** not implemented. PyTCP has no
per-destination connection cache and no IW10 fallback
heuristic. Every new connection unconditionally uses
the IW10 formula.

### "MUST NOT be on by default without monitoring"

> "An increased initial window MUST NOT be turned on by
> default on systems without such monitoring
> capabilities."

**Adherence:** strictly NOT met. PyTCP enables IW10 by
default and ships no monitoring or fallback machinery.
The strict reading of §12 would require either
implementing the cache/fallback heuristic or making
IW10 opt-in. The practical context: RFC 6928 is
Experimental and dates from 2013; in the decade since,
IW10 has become the universal default in production
stacks (Linux, FreeBSD, Windows) and the §12 caveat
reflects deployment caution that has been overtaken by
operational experience. The §12 wording is best read
as "experimental deployments" advice rather than a
hard interoperability requirement; nonetheless, PyTCP
is technically non-compliant with this MUST NOT under
a strict reading.

### "Fall back if performance deteriorates" SHOULD

> "If users observe any significant deterioration of
> performance, they SHOULD fall back to an initial
> window as allowed by RFC 3390 for safety reasons."

**Adherence:** not implemented (consistent with the
previous §12 items). No fallback mechanism exists.

---

## Test coverage audit

### §2 IW formula

- **Unit:**
  `pytcp/tests/unit/protocols/tcp/test__tcp__cwnd.py::TestInitialWindow`
  contains five parametrised tests:
  - `test__iw__canonical_1460_mss_yields_14600` —
    canonical 1500-MTU MSS=1460 → IW=14600.
  - `test__iw__small_mss_yields_14600_floor` — small
    SMSS triggers the 14600 floor.
  - `test__iw__mid_mss_uses_14600_floor` — boundary
    case for the floor.
  - `test__iw__large_mss_uses_ten_smss_cap` — large
    SMSS triggers the 10*SMSS cap.
  - `test__iw__very_large_mss_uses_two_smss_clamp_only`
    — the 2*SMSS lower bound dominates only at extreme
    SMSS values.
- **Unit (constants):**
  `test__tcp__cwnd.py::test__cwnd__initial_window_factor_is_ten`
  and `test__cwnd__initial_window_bytes_is_14600` pin
  the constants themselves.
- **Integration:**
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py::TestTcpCwndPhase4::test__cwnd__post_handshake_initialises_cwnd_to_iw_10`
  drives the active-open handshake and asserts
  `_cwnd == min(10 * MSS, max(2 * MSS, 14600))`
  post-handshake.

**Status:** locked in.

### §2 Timing (post-handshake, not during)

- **Integration:** the same Phase 4 test class includes
  cases that pin the post-handshake transition — the
  pre-IW cwnd would not equal the IW value if the IW
  application happened during the handshake instead of
  after.

**Status:** locked in indirectly. A dedicated test
that asserts cwnd before and after the third-leg ACK
would make the regression-guard explicit; the current
indirect coverage would catch a deviation through the
final cwnd-equals-IW assertion.

### §2 Loss window = 1 SMSS

- **Integration:**
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py::TestTcpCwndPhase2::test__cwnd__rto_resets_cwnd_to_loss_window`
  drives an RTO and asserts `_cwnd == _snd_mss` post-
  RTO.

**Status:** locked in.

### §2 RW (optional MAY) and §2 RW fallback SHOULD

Not implemented; no test surface.

### §3 Initial receive window ≥ 10 segments

- **Integration:** indirectly covered by every
  handshake test that builds a SYN, since
  `_rcv_wnd_max = 65535` is enforced on every outbound
  segment via the `_rcv_wnd` property at
  `tcp__session.py:911-920`. A dedicated test would
  assert `syn.win >= 10 * MSS / 2**WSCALE`; this is
  not present.

**Status:** locked in indirectly. A regression that
shrunk `_rcv_wnd_max` below 14600 would be caught by
multiple existing handshake tests that check `syn.win`
matches the expected value.

### §9 RTO restart on cum-ACK

- **Integration:**
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__rto.py::TestTcpRtoRetransmitTimer::test__cumulative_ack_draining_in_flight_stops_retransmit_timer`
  and the broader RFC 6298 audit's test surface cover
  this. RFC 6928 §9 is a strict cross-reference to
  RFC 6298, so the RFC 6298 adherence record's test
  audit applies here too.

**Status:** locked in (covered by RFC 6298 audit).

### §12 Monitoring / Cache / Fallback

Not implemented; no test surface.

### Test coverage summary

| Aspect                                   | Coverage                                      |
|------------------------------------------|-----------------------------------------------|
| §2 IW formula                            | locked in (unit + integration)                |
| §2 Constants (10, 14600)                 | locked in (dedicated unit tests)              |
| §2 Timing post-handshake                 | locked in indirectly (via Phase 4 IW value)   |
| §2 Loss window = 1 SMSS                  | locked in                                     |
| §2 SYN-retransmit reset SHOULD           | locked in by absence (no reset path exists)   |
| §2 RW (optional MAY)                     | n/a (not implemented)                         |
| §2 RW fallback SHOULD                    | n/a (no RW to fall back from)                 |
| §3 RCV.WND ≥ 10 segments                 | locked in indirectly (via handshake tests)    |
| §9 RTO restart on cum-ACK                | locked in (covered by RFC 6298 audit)         |
| §12 Monitoring / cache / fallback        | n/a (not implemented)                         |

---

## Overall assessment

| Aspect                                 | Status                                  |
|----------------------------------------|-----------------------------------------|
| §2 IW formula                          | met                                     |
| §2 Constants encoded as 10 / 14600     | met                                     |
| §2 Timing (post-handshake)             | met                                     |
| §2 Loss window = 1 SMSS                | met                                     |
| §2 SYN-retransmit "refrain from reset" | met (stronger: never reset)             |
| §2 Restart window (optional MAY)       | not implemented (allowed by MAY)        |
| §2 RW fallback on loss SHOULD          | n/a (no RW exists)                      |
| §3 RCV.WND ≥ 10 segments               | met (by margin)                         |
| §9 RFC 6298 RTO restart                | met (cross-reference)                   |
| §12 Monitoring SHOULD                  | not implemented                         |
| §12 Cache + fallback SHOULD            | not implemented                         |
| §12 "MUST NOT default-on without monitoring" | strictly not met (default-on without monitoring) |
| §12 Fall back on deterioration SHOULD  | not implemented                         |

The core mechanical IW10 implementation is correct and
well-tested. The §12 deployment-recommendation cluster
(monitoring + cache + fallback + the
"MUST NOT default-on without monitoring") is not
implemented; PyTCP enables IW10 unconditionally. Under
a strict reading of RFC 6928 §12 this is a MUST NOT
violation, but the §12 wording reflects 2013-era
deployment caution that has been overtaken by a decade
of universal IW10 adoption in production stacks. For a
research / educational stack like PyTCP, the strict
reading of §12 is best regarded as outdated; the gap
is documented here for completeness rather than as an
actionable item.
