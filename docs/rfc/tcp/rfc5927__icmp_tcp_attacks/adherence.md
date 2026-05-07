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

After Phase 3 of the ICMP-into-TCP-FSM-dispatch
refactor, PyTCP **implements** the RFC 5927
counter-measures end-to-end:

- §4 sequence-in-window guard is **shipped** for
  both ICMPv4 and ICMPv6 Destination Unreachable +
  PTB demuxes.
- §5.2 hard-error softening is **shipped end-to-
  end**: the production ICMPv4 / ICMPv6 RX path in
  `packet_handler__icmp{4,6}__rx.py` builds an
  `IcmpMetadata` and calls `session.tcp_fsm(icmp=
  metadata)`, which routes through
  `FSM_ICMP_HANDLERS` to per-state handlers in
  `pytcp/protocols/tcp/fsm/tcp__fsm__<state>.py`.
  Per-state handlers decide hard-vs-soft on a
  per-state basis: SYN_SENT is the only state
  allowed to abort (covering all four canonical
  hard-error codes — ICMPv4 Code 2/3, ICMPv6 Code
  1/4); the shared `fsm__icmp__synchronized`
  default downgrades every hard error to soft once
  a connection is synchronized (the canonical
  counter-measure for the blind connection-reset
  attack). The legacy `TcpSession.on_*` methods
  are no longer reachable from production code; a
  Phase 4 commit deletes them.

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

## §5.2 Hard-Error Softening

> "Hard ICMP errors (Code 2 = Protocol Unreachable,
> Code 3 = Port Unreachable; ICMPv6 Code 1 = admin
> prohibited, Code 4 = Port Unreachable) in
> synchronized states SHOULD be treated as
> advisory rather than aborting the connection."

**Adherence:** shipped end-to-end (Phase 3 of the
ICMP-into-FSM refactor).

The production ICMPv4 / ICMPv6 RX path
(`packet_handler__icmp{4,6}__rx.py`) builds an
`IcmpMetadata` and calls
`session.tcp_fsm(icmp=metadata)`. The FSM dispatcher
in `pytcp/protocols/tcp/fsm/tcp__fsm.py` routes via
`FSM_ICMP_HANDLERS` to the per-state handler:

- **SYN_SENT** (`fsm__syn_sent__icmp`): the only
  state that aborts. Hard codes (v4 Code 2/3, v6
  Code 1/4) → `ConnError.REFUSED` + transition to
  `CLOSED`. Soft codes (v4 Code 0/1, v6 Code 0/3)
  surface `HOST_UNREACHABLE` / `NET_UNREACHABLE`
  and release the blocked CONNECT but leave the
  FSM in SYN_SENT.
- **All synchronized states** (SYN_RCVD,
  ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT,
  CLOSING, LAST_ACK, TIME_WAIT) share
  `fsm__icmp__synchronized`: every
  Dest-Unreachable / Time-Exceeded / Param-Problem
  is logged and discarded; PMTU still updates
  `snd_mss`.
- **LISTEN** (`fsm__listen__icmp`): pure no-op.

The legacy `TcpSession.on_*` methods remain on the
class as no-longer-reachable code; Phase 4 deletes
them. The §5.2 counter-measure is end-to-end as of
this Phase 3 commit.

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

| Aspect                                                  | Coverage                                                                                                                                                                                                                                                                                                                                                                                              |
|---------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| §4 seq-in-window guard (drop on out-of-window)          | shipped — `pytcp/tests/integration/protocols/tcp/test__tcp__session__on_unreachable.py::test__icmp4__seq_out_of_window__drops` and `test__tcp__session__on_pmtu.py::test__icmp4__frag_needed__seq_out_of_window__drops`                                                                                                                                                                                |
| §5.2 SYN_SENT hard-error abort (4 canonical codes)      | shipped — `pytcp/tests/unit/protocols/tcp/fsm/test__tcp__fsm.py::TestTcpFsmSynSentHandleIcmp::test__tcp_session__syn_sent_icmp_v4_port_unreachable_aborts` / `..__v4_protocol_unreachable_aborts` / `..__v6_admin_prohibited_aborts` / `..__v6_port_unreachable_aborts`                                                                                                                                  |
| §5.2 SYN_SENT soft-code advisory (Net / Host)           | shipped — `TestTcpFsmSynSentHandleIcmp::test__tcp_session__syn_sent_icmp_v4_host_unreachable_is_advisory` / `..__v4_net_unreachable_is_advisory`                                                                                                                                                                                                                                                       |
| §5.2 synchronized-state hard→soft downgrade             | shipped — `TestTcpFsmSynchronizedHandleIcmp::test__tcp_session__synchronized_icmp_hard_codes_are_soft` (8 states × 4 hard codes via subTest)                                                                                                                                                                                                                                                           |
| §5.2 PMTU updates `snd_mss` in any synchronized state   | shipped — `TestTcpFsmSynchronizedHandleIcmp::test__tcp_session__synchronized_icmp_pmtu_updates_snd_mss`                                                                                                                                                                                                                                                                                                |
| §5.2 LISTEN ICMP no-op                                  | shipped — `TestTcpFsmListenHandleIcmp::test__tcp_session__listen_icmp_is_no_op`                                                                                                                                                                                                                                                                                                                        |
| Legacy `on_unreachable` path (still in production)      | shipped — `test__tcp__session__on_unreachable.py::test__icmp4__port_unreachable__on_syn_sent__refused_and_closed` and `..__host_unreachable__sets_host_unreachable_error` / `..__net_unreachable__sets_net_unreachable_error` (legacy path will be unreachable after Phase 3 migration)                                                                                                                  |
| §5 PMTUD attack mitigation (PLPMTUD probing)            | n/a (gap)                                                                                                                                                                                                                                                                                                                                                                                              |

---

## Overall assessment

| Aspect                                  | Status                              |
|-----------------------------------------|-------------------------------------|
| §4 sequence-in-window guard             | **shipped**                         |
| §5.2 hard-error softening (end-to-end)  | **shipped (Phase 3)**               |
| §5 PMTUD attack mitigation              | not implemented                     |

The seq-in-window guard is the load-bearing
security mitigation against off-path ICMP forgery;
it is in place and tested. The §5.2 softening
behavior is end-to-end as of Phase 3: the
production ICMP RX path drives `tcp_fsm(icmp=...)`
into the per-state dispatcher, and only SYN_SENT
is allowed to abort. The PMTUD attack mitigation
gap is closed only by RFC 4821 / 8899 active
probing.
