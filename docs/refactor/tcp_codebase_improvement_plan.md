# TCP Codebase Improvement Plan

Authored 2026-05-05 after a full review of the TCP codebase
following completion of Tier 1, Tier 2, and partial Tier 3 RFC
work (RFC 9406 HyStart++ shipped; RFC 8257 DCTCP and RFC 9331 L4S
deferred by scope decision; RFC 1191 PMTUD + RFC 4821 PLPMTUD
remain pending and depend on the ICMP refactor below).

This document is the canonical plan for the structural and
maintainability improvements the codebase needs. It is
**separate from RFC-conformance work** — every recommendation
here is a refactor / decomposition / hygiene item, not a new
RFC clause.

The codebase as of commit `943698f2` (test framework TFO
state-isolation fix) is in **good correctness shape**: 8382 tests
passing, 0 skipped, lint clean, full SHOULD/MUST parity for the
modern TCP stack feature set. The issues below are organisational,
not functional.

---

## 1. Concerns identified

### Concern #1 — `tcp__session.py` is a 4000+-line god class

`pytcp/protocols/tcp/tcp__session.py` carries every aspect of a
TCP session: connection identity, send-side state, receive-side
state, timers, ~7 congestion-control snapshot/restore state
groups, ~30 socket-API knobs, plus the FSM dispatcher itself.
`__init__` is ~700 lines of state declarations. `_transmit_packet`
is ~400 lines. `_process_ack_packet` is ~500 lines.

**Severity:** High. **Effort:** Large (must be incremental).

### Concern #2 — `_transmit_packet` orchestrates 12+ concerns

A single function handles: RFC 6298 §5.7 idle-reset, RFC 5681
§4.1 RW reduction, RTT-sample tracker init, last-send timestamp
refresh, WSCALE shift, SWS gate, WSCALE / SACK-perm / Timestamps /
TFO / AccECN option emission, ECE/CWR flag composition, retransmit-
ECT-suppression, packet-handler dispatch, FIN bookkeeping,
SND.NXT / SND.MAX update, partial-segment Minshall tracking.
That's twelve concerns in one function.

**Severity:** Medium. **Effort:** Medium.

### Concern #3 — `_process_ack_packet` mixes 16 phases inline

The cum-ACK path runs (in this order): SACK ingest → RACK process
→ unacceptable-segment ack → SND.UNA advance → recover_seq decay
→ bytes_acked compute → retransmit timer manage → CC state update
(CUBIC vs Reno + HyStart override) → snd_ewn recompute → keep-
alive arm → TLP arm → F-RTO step 2/3 spurious-detection → TSecr
RTTM → Karn RTT harvest → recovery_point exit → PRR window update.
Order matters in several spots; the comments document the
dependencies but a refactor into named phases would make them
explicit.

**Severity:** Medium. **Effort:** Medium.

### Concern #4 — Module-level stack state is creeping

`pytcp/stack/__init__.py` accumulates: `tcp__fastopen_cookies`,
`tcp__fastopen_negative`, `tcp__fastopen_pending_count`, plus
secrets, cache caps, etc. The TFO test-isolation bug (commit
`943698f2`) was the canary — adding module-level state without
updating the test framework's snapshot+clear pattern silently
leaks state between tests. This will recur as the codebase
grows.

**Severity:** Medium. **Effort:** Small (one-time refactor).

### Concern #5 — ICMP→TCP error demux is missing

ICMP error messages are received at the IP layer but not
propagated to TCP sessions. RFC 1122 §4.2.3.9 is a MUST that
PyTCP currently treats as "satisfied at the fault-tolerance
minimum" via R2 abort fallback. PMTUD (RFC 1191/4821) is blocked
on this. The audit reclassifications acknowledge this is a
structural gap, not a per-RFC clause gap.

**Severity:** High. **Effort:** Medium-Large.

### Concern #6 — Heavy `setUp` in some integration tests

A few integration test files rebuild the same handshake fixture
per test method. Class-level fixtures or a shared
`_make_established_session(...)` helper would shrink test files
substantially.

**Severity:** Low. **Effort:** Small.

### Concern #7 — `_advertise_*` flag explosion

`_advertise_ts`, `_advertise_wscale`, `_advertise_sack`,
`_advertise_ecn`, `_advertise_accecn`, `_advertise_fastopen`.
Each controls whether the active-open SYN offers the
corresponding option. Works, but a `class HandshakeAdvertise`
dataclass with one place to flip defaults would be cleaner.

**Severity:** Low. **Effort:** Small.

---

## 2. Recommended refactors (ordered for sequencing)

### Refactor #1 — Extract `CongestionControlState` dataclass

**Effort:** 3–4 commits. **Risk:** Low. **Closes:** Concern #1 (partial).

Extract a `CongestionControlState` dataclass under
`pytcp/protocols/tcp/tcp__cc_state.py` carrying:

- `cwnd, ssthresh, snd_ewn` — primary CC variables
- `recovery_point, recover_seq` — RFC 6582 step 4 + RFC 6675 §5.1
- `frto_active, frto_step, frto_pre_*, frto_pre_cubic_*` — RFC 5682
- `fr_pre_cubic_*, fr_pre_cwnd, fr_pre_ssthresh, fr_cubic_snapshot_valid` — RFC 9438 §4.9.2
- `cubic_w_max, cubic_K_ms, cubic_epoch_start_ms, cubic_w_est, cubic_in_ca` — RFC 9438 §4
- `prr_delivered, prr_out, recover_fs` — RFC 6937
- `hystart_state` — RFC 9406 (already a dataclass; reference it here)

Removes ~25 fields from `TcpSession.__init__`. The snapshot+restore
patterns (`_restore_frto_snapshot`, `_fr_cubic_snapshot_valid` clear)
become methods on the dataclass. Lowest risk because each field
moves with no semantic change; tests pass throughout.

**Validation:** existing 415 TCP integration tests + RFC
adherence records' test references all unchanged.

### Refactor #2 — Split `_process_ack_packet` into phase functions

**Effort:** 2 commits. **Risk:** Low. **Closes:** Concern #3.

Split into named phase functions called in order:

1. `_phase1_ingest_sack_and_rack(packet_rx_md)` — SACK ingest +
   RACK time-based loss detection on dup-ACK path.
2. `_phase2_advance_snd_una_and_state(packet_rx_md, bytes_acked)` —
   SND.UNA advance, recover_seq decay, retransmit timer manage,
   keep-alive arm, TLP arm.
3. `_phase3_update_congestion_control(bytes_acked)` — CUBIC vs
   Reno cwnd + HyStart override + F-RTO step 2/3 spurious-detection
   + recovery exit (cwnd = ssthresh) + PRR window update.
4. `_phase4_harvest_rtt_samples(packet_rx_md)` — TSecr-driven RTTM
   + Karn sample-tracker harvest, with HyStart fold side-effects.

Each phase is one page. Mostly mechanical extraction; the order
constraints documented in the existing inline comments become
function-call ordering at the top level.

### Refactor #3 — `TcpStack` class around module-level state

**Effort:** 2 commits. **Risk:** Low. **Closes:** Concern #4.

Aggregate the module-level stack state into a `TcpStack` class:

```python
class TcpStack:
    fastopen_cookies: dict[Ip4Address | Ip6Address, bytes]
    fastopen_negative: set[Ip4Address | Ip6Address]
    fastopen_pending_count: int
    iss_secret: bytes
    fastopen_secret: bytes
    fastopen_cache_max_size: int
```

Instantiate once at stack import. Tests construct a fresh
instance per test instead of clearing module-level dicts/sets.
Eliminates the test-isolation pattern by construction. Also makes
it possible to run two PyTCP "instances" in one process
(currently impossible).

Migration is mechanical: `stack.tcp__fastopen_cookies[k]` becomes
`stack.tcp_stack.fastopen_cookies[k]` at every call site. Replace
the per-RFC-7413-§4.1.3.1 / §4.2 setUp/tearDown snapshot+clear
in `TcpSessionTestCase` with a single `stack.tcp_stack =
TcpStack()` reset.

### Refactor #4 — ICMP→TCP error demux + per-destination MTU cache

**Effort:** 4–6 commits. **Risk:** Medium. **Closes:** Concern #5
+ unblocks PMTUD work (RFC 1191 / RFC 4821 / RFC 8201).

Steps:

1. Refactor `pytcp/stack/packet_handler/packet_handler__icmp4__rx.py`
   and `packet_handler__icmp6__rx.py` to surface ICMP error
   payloads with the embedded IP+TCP header parsed out.
2. Add a TCP-error-demux: 4-tuple lookup against
   `(local_ip, local_port, remote_ip, remote_port)` extracted
   from the ICMP error payload, route to the matching
   `TcpSession`.
3. Add per-`TcpSession` callback (`session.on_icmp_error(error_type,
   next_hop_mtu)`) that dispatches based on error type:
   - ICMPv4 Type 3 Code 4 (Frag-Needed) / ICMPv6 Type 2 (PTB):
     update per-destination MTU cache, recompute MSS.
   - ICMPv4 Type 3 Codes 0-1 (Net/Host Unreachable): mark session
     for soft error.
   - ICMPv4 Type 11 (Time Exceeded): log only.
4. Add per-destination MTU cache as a stack-level structure
   (under the new `TcpStack` from Refactor #3 if done first).
5. Wire DF=1 on outbound TCP-bearing IPv4 packets.
6. Wire MSS recompute on per-destination MTU update.

This refactor is the prerequisite for RFC 1191 + RFC 4821 PMTUD
implementation. The audit records for those RFCs already
reference "cross-cut with ICMP refactor" as the blocker.

### Refactor #5 — Split `_transmit_packet` into option-builder + send pipeline

**Effort:** 3 commits. **Risk:** Medium. **Closes:** Concern #2.

Decompose into:

1. `_compute_outbound_options(seq, flags, data)` returning a
   dataclass of all option fields (mss, wscale, sackperm,
   sack_blocks, tsval, tsecr, fastopen_cookie, accecn0_counters,
   accecn1_counters).
2. `_apply_idle_reset_if_needed()` — RFC 6298 §5.7 + RFC 5681 §4.1.
3. `_handle_rtt_sample_tracker(seq, data, flag_syn, flag_fin)` —
   RFC 6298 §4 + Karn taint flag.
4. `_advance_send_state(seq, flags, data, len)` — SND.NXT / SND.MAX
   / partial-Minshall / `_last_send_time_ms` update.
5. `_compose_ecn_flags(flag_syn, flag_ack, flag_rst, data)` — RFC
   3168 §6.1.1/§6.1.2 + RFC 9768 ACE encoding + RFC 3168 §6.1.5
   retransmit-ECT-suppression.

`_transmit_packet` becomes a coordinator that calls each helper
in sequence and dispatches to the packet handler. Each helper
is one-page and independently testable.

Higher risk than #2 because the option-emission paths are
intricate (TSopt + SACK + AccECN + TFO + ECN flags interact),
but the existing test surface is dense.

---

## 3. What NOT to change

### Stay-as-is #1 — Pure-helper modules

`tcp__cwnd.py`, `tcp__cubic.py`, `tcp__rto.py`, `tcp__sack.py`,
`tcp__rack.py`, `tcp__loss_recovery.py`, `tcp__hystart.py`,
`tcp__iss.py`, `tcp__seq.py`. Each is testable in isolation; the
session integrates them. Already correctly factored.

### Stay-as-is #2 — FSM split per state per dispatch type

`tcp__fsm__<state>.py` with separate `_packet` / `_syscall` /
`_timer` dispatch functions per file. The recent refactor was
the right move and the dispatch tables in `tcp__fsm.py` make
the wiring explicit.

### Stay-as-is #3 — Adherence-record format

The per-RFC `docs/rfc/tcp/rfcXXXX__name/adherence.md` format
(RFC text + paragraph audit + test coverage table + Overall
Assessment table) works. Reviewers can navigate from clause to
implementation to test. Don't touch.

### Stay-as-is #4 — `unittest`-native tests with `parameterized_class` + `msg=`

The §7.2 self-audit script catches drift; the
`Reference: RFC X §Y` docstring trailer makes every test
traceable. Established convention; works.

### Stay-as-is #5 — 80-char copyright + module docstring + `ver 3.0.x`

Consistent across the codebase, low maintenance.

---

## 4. Net assessment

The codebase is in **good shape for an educational/research
stack with production-grade-correctness aspirations**. The RFC
conformance is genuinely strong (41 audited RFCs, modern Linux/
BSD/Windows feature parity); the issues are organisational
rather than functional.

`tcp__session.py` being 4000 lines is the main thing to chip at
over time, and it can be done incrementally without breaking
tests because the helpers are already factored.

If a week of cleanup time were available, the highest-value
sequence is:

1. **Refactor #1** (CongestionControlState extraction)
2. **Refactor #2** (`_process_ack_packet` phase split)
3. **Refactor #4** (ICMP→TCP demux) — unblocks PMTUD

Those three together meaningfully improve maintainability and
unblock the next major RFC work item, without changing one byte
of wire-level behaviour.

---

## 5. Reference points

- Last conformance commit: `943698f2` (test-framework TFO state isolation)
- Last RFC commit before that: `962667ae` (RFC 9406 HyStart++)
- Test counts: 8382 passing, 0 skipped, lint clean
- Tier 3 deferrals: RFC 8257 (DCTCP), RFC 9331 (L4S) — see audit records
- Tier 3 pending: RFC 1191 (PMTUD), RFC 4821 (PLPMTUD) — blocked on Refactor #4
