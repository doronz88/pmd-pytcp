# RFC 5927 — ICMP Attacks against TCP

| Field       | Value                                              |
|-------------|----------------------------------------------------|
| RFC number  | 5927                                               |
| Title       | ICMP Attacks against TCP                           |
| Category    | Informational                                      |
| Date        | July 2010                                          |
| Source text | [`rfc5927.txt`](rfc5927.txt)                       |

---

## Top-line adherence

After Phase 5 of the ICMP demux + PMTUD refactor,
PyTCP **partially implements** RFC 5927:

- §4 sequence-in-window guard is **shipped** for
  both ICMPv4 and ICMPv6 Destination Unreachable +
  PTB demuxes.
- §3 Hard-Error softening (treating Code 2 / Code 3
  as advisory in synchronized states) is partially
  implemented: Host / Net Unreachable surface the
  per-code reason without changing the FSM state;
  Port Unreachable in synchronized states is
  ignored entirely (only acted on in SYN_SENT).

What still **does not happen**:

- ICMP rate limiting (RFC 4443 §2.4(f) cross-link).
- §5 PMTUD attack mitigation: an attacker who can
  spoof a Frag-Needed at MIN_PMTU shrinks the
  victim's path MTU. PyTCP currently honors any
  Frag-Needed that passes the seq guard. Active
  PLPMTUD probing (RFC 4821 / 8899) would close
  this gap.

---

## §4 Sequence-in-Window Validation

> "ICMP error messages should be processed only if
> the embedded TCP sequence number falls within
> SND.UNA..SND.NXT — otherwise they are likely
> forged or stale and should be silently dropped."

**Adherence:** **shipped** (Phase 5).
`TcpSession.is_seq_in_window(seq)` performs wrap-aware
modular comparison against `SND.UNA..SND.NXT`. The
ICMP RX handlers (`packet_handler__icmp{4,6}__rx.py`)
extract the embedded TCP seq via the shared
`parse_embedded_l4` helper and call the predicate
before notifying the session. Failures bump
`icmp{4,6}__destination_unreachable__tcp__seq_out_of_window__drop`.

## §3 Hard-Error Softening

> "Hard ICMP errors (Code 2 = Protocol Unreachable,
> Code 3 = Port Unreachable) in synchronized states
> SHOULD be treated as advisory rather than
> aborting the connection."

**Adherence:** partially shipped (Phase 5).
`TcpSession.on_unreachable` aborts the session with
`ConnError.REFUSED` only when Port Unreachable is
received in `SYN_SENT`. Synchronized-state Port
Unreachable falls through with no effect (the
session is left intact). Host / Net Unreachable
surface `ConnError.HOST_UNREACHABLE` /
`ConnError.NET_UNREACHABLE` for the user/TCP
interface to consult, but do not transition the FSM.

## §5 PMTUD Attacks

> "An attacker can shrink a victim's path MTU by
> forging an ICMP Frag-Needed at MIN_PMTU."

**Adherence:** not mitigated. PyTCP honors any
Frag-Needed that survives the §4 seq-in-window
guard. The plan defers PLPMTUD probing (RFC 4821 /
8899) to a follow-up commit; once shipped, the
active probe will dominate the cached MTU even if
ICMP signals are forged.

---

## Test coverage audit

| Aspect                                              | Coverage |
|-----------------------------------------------------|----------|
| §4 seq-in-window guard (drop on out-of-window)      | shipped — `pytcp/tests/integration/protocols/tcp/test__tcp__session__on_unreachable.py::test__icmp4__seq_out_of_window__drops` and `test__tcp__session__on_pmtu.py::test__icmp4__frag_needed__seq_out_of_window__drops` |
| §3 Hard-Error softening (Port on SYN_SENT → REFUSED + CLOSED) | shipped — `test__tcp__session__on_unreachable.py::test__icmp4__port_unreachable__on_syn_sent__refused_and_closed` |
| §3 Host/Net Unreachable advisory surfacing         | shipped — `test__tcp__session__on_unreachable.py::test__icmp4__host_unreachable__sets_host_unreachable_error` and `test__icmp4__net_unreachable__sets_net_unreachable_error` |
| §5 PMTUD attack mitigation (PLPMTUD probing)        | n/a (gap) |

---

## Overall assessment

| Aspect                              | Status                |
|-------------------------------------|-----------------------|
| §4 sequence-in-window guard         | **shipped**           |
| §3 Hard-Error softening             | partially shipped     |
| §5 PMTUD attack mitigation          | not implemented       |

The seq-in-window guard is the load-bearing security
mitigation against off-path ICMP forgery; it is in
place and tested. The §3 softening behavior is
partially implemented — it covers SYN_SENT Port
Unreachable and synchronized-state Hard-Error
silence, but the formal "synchronized-state
Hard-Error MUST be advisory" rule is matched
de-facto by the no-op behavior in those states.
The PMTUD attack mitigation gap is closed only by
RFC 4821 / 8899 active probing.
