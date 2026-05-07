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

After Phase 2 of the ICMP-into-TCP-FSM-dispatch
refactor, PyTCP **partially implements** RFC 5927:

- §4 sequence-in-window guard is **shipped** for
  both ICMPv4 and ICMPv6 Destination Unreachable +
  PTB demuxes.
- §5.2 hard-error softening is **shipped at the
  FSM-dispatch layer**: per-state ICMP handlers in
  `pytcp/protocols/tcp/fsm/tcp__fsm__<state>.py`
  decide hard-vs-soft on a per-state basis, and the
  shared `fsm__icmp__synchronized` default
  downgrades every hard error to soft once a
  connection is synchronized (the canonical RFC
  5927 §5.2 counter-measure). SYN_SENT is the only
  state allowed to abort, and it now covers all
  four canonical hard-error codes (ICMPv4 Code 2/3,
  ICMPv6 Code 1/4). Production wiring of the ICMP
  RX path through `tcp_fsm(icmp=...)` lands in
  Phase 3; until then the legacy `on_unreachable`
  direct-call path on `TcpSession` is still in use.

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

**Adherence:** shipped at the FSM-dispatch layer
(Phase 2 of the ICMP-into-FSM refactor).

`tcp_fsm(icmp=IcmpMetadata(...))` routes through
`FSM_ICMP_HANDLERS` (see
`pytcp/protocols/tcp/fsm/tcp__fsm.py`) to the
per-state handler:

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

The legacy `TcpSession.on_unreachable` is still
present on the session and is the path the
production ICMP RX handlers
(`packet_handler__icmp{4,6}__rx.py`) drive today.
Phase 3 of the refactor migrates those callers to
`tcp_fsm(icmp=...)` so the per-state semantics
become the actual user-observable behavior; Phase
4 deletes `on_*`. After Phase 3 the legacy
`on_unreachable` "synchronized state + Net/Host
Unreachable surfaces ConnError" branch becomes
unreachable and the §5.2 counter-measure is
end-to-end.

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
| §5.2 hard-error softening (FSM layer)   | **shipped (Phase 2)**               |
| §5.2 hard-error softening (production)  | partially shipped (awaits Phase 3)  |
| §5 PMTUD attack mitigation              | not implemented                     |

The seq-in-window guard is the load-bearing
security mitigation against off-path ICMP forgery;
it is in place and tested. The §5.2 softening
behavior is now explicit at the FSM-dispatch layer
— the `fsm__icmp__synchronized` default downgrades
every synchronized-state hard error to a no-op,
and `fsm__syn_sent__icmp` covers all four
canonical hard-error codes for the abort path.
The production ICMP RX path still calls
`TcpSession.on_*` directly; Phase 3 of the
refactor (`docs/refactor/icmp_into_tcp_fsm_plan.md`)
migrates those callers and makes the FSM path
end-to-end. The PMTUD attack mitigation gap is
closed only by RFC 4821 / 8899 active probing.
