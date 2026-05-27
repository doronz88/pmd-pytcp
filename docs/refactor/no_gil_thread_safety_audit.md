# PyTCP No-GIL Thread-Safety Audit + Correction Plan

**Status:** audit performed 2026-05-27. Supersedes the
IGMP-scoped conclusion in
`socket_linux_parity_audit.md` §X1 (which claimed the
cross-thread backlog was empty — it was empty only for the
IGMP/PMTU path that triggered it).

## 0. Why this exists

PyTCP's north star includes **running on free-threaded
(no-GIL) CPython** (3.13t/3.14t). The stack is heavily
multi-threaded; today the GIL serialises bytecode so many
unguarded shared structures *happen* to be safe. Under no-GIL
that guarantee vanishes: every structure written by one
thread and read/written by another needs an explicit lock (or
a genuinely lock-free design). **GIL atomicity is not an
acceptable correctness crutch.**

The X1 audit (`socket_linux_parity_audit.md` §X1) found and
fixed F1–F4 (the IPv4 multicast / IGMP-query state and the
PMTU maps). This document is the **full** sweep — every
protocol and subsystem — so the remaining backlog is
greppable and sequenced.

### 0.1 Threads in play

| Thread | Source | Touches |
|---|---|---|
| rx-ring (per interface) | `runtime/rx_ring.py` → `PacketHandler._phrx_*` | every RX path; one per interface |
| tx-ring (per interface) | `runtime/tx_ring.py` | TX emit; drains the TX deque |
| Timer | `runtime/timer.py` | fires every registered callback (TCP RTO/persist/keepalive, IGMP/MLD response, ND DAD/RA, ARP) |
| ARP/ND aging | `lib/neighbor.py` `Subsystem` | neighbor cache expiry |
| async DAD-claim | `_claim_ip6_address_async` / IPv4 ACD | address-config mutation |
| application | sockets + control APIs (`stack.address/route/neighbor/link/membership`, `setsockopt`) | user-driven mutation |

### 0.2 Hazard classes that survive (or appear under) no-GIL

- **H1 — Python-level iteration during mutation** → hard
  `RuntimeError` (survives the GIL).
- **H2 — compound read-modify-write interleave** → lost
  update / torn invariant (GIL hides it).
- **H3 — container tear** on concurrent dict/list/set write
  → corruption (no-GIL only).
- **H4 — non-atomic `+=` on a counter** → lost increment
  (no-GIL only; benign for observability counters).

The standing invariant for new code: **lock-per-structure** —
every cross-thread `dict`/`list`/`set`/scalar gets its own
lock (or a documented lock-free design), the way
`SocketTable`/`RouteTable`/`Timer`/`NeighborCache` already do.

---

## 1. GUARDED — already no-GIL-safe (verified 2026-05-27)

These need no work; listed so the audit is complete and the
pattern is visible.

| Structure | Mechanism | File |
|---|---|---|
| `stack.sockets` (`SocketTable`) | `_lock` (accessors return snapshots) | `socket/socket_table.py` |
| `stack.packet_sockets` (`PacketSocketTable`) | `_lock` on every accessor | `socket/packet__socket_table.py:68` |
| `stack.interfaces` (`InterfaceTable`) | `_lock` | `runtime/interface_table.py` |
| `stack.ip4_fib` / `ip6_fib` (`RouteTable`) | `_lock` (lookup snapshots under lock) | `runtime/fib.py:151` |
| `Timer._heap` + `_seq` | `_lock` (RLock; callbacks fire lock-free) | `runtime/timer.py` |
| `NeighborCache._entries` (ARP/ND) | `_lock` (callbacks outside lock) | `lib/neighbor.py` |
| `DadSlotRegistry._events` / `_winners` | `_lock` | `lib/dad_slot_registry.py:100` |
| per-interface IPv4 Identification | `_lock__ip4_id` | `runtime/packet_handler/__init__.py` |
| IPv4 multicast reception state | `_lock__multicast` (F2) | `runtime/packet_handler/__init__.py` |
| IPv4 IGMP query-response state | `_lock__multicast` (F4) | `runtime/packet_handler/packet_handler__igmp__rx.py` |
| IPv4 IGMP state-change retransmit (timer thread) | `_lock__multicast` (M2) | `runtime/packet_handler/packet_handler__igmp__tx.py` |
| IPv6 MLDv2 query-response timer state | `_lock__multicast` (M1) | `runtime/packet_handler/packet_handler__icmp6__rx.py` |
| PMTU maps (`pmtu_cache`/`pmtu_state`) | `_pmtu_lock` + accessors (F3) | `stack/__init__.py` |
| `TcpStack` Fast-Open state (cookies/negative/pending) | `_lock` + accessors (T1) | `protocols/tcp/tcp__stack.py` |
| RxRing `_rx_deque` / TxRing deque | `collections.deque` append/popleft (atomic in CPython incl. free-threaded build) + `os.eventfd` wakeup | `runtime/rx_ring.py`, `runtime/tx_ring.py` |
| `Subsystem` stop signalling | `threading.Event` (thread-safe) | `runtime/subsystem.py` |
| per-socket rx queue / accept queue / error queue | `_lock__io` + `threading.Semaphore` + atomic `deque` | `socket/*.py` |
| TcpSession `_rx_buffer` / `_tx_buffer` / `_state` | `_lock__rx_buffer` / `_lock__tx_buffer` / `_lock__fsm` | `protocols/tcp/tcp__session.py` |

---

## 2. UNGUARDED — the backlog (protocol/subsystem by subsystem)

Severity = correctness impact under no-GIL (not
GIL-build behaviour, where all of these are currently benign).

### 2.1 Transport — TCP

**T1 · `TcpStack` Fast-Open state — HIGH — SHIPPED 2026-05-27**
`protocols/tcp/tcp__stack.py`. `fastopen_cookies`
(dict), `fastopen_negative` (set), `fastopen_pending_count`
(int). Written from the **RX** thread (SYN/SYN-ACK handling,
pending-count inc/dec at `fsm/tcp__fsm__listen.py` + session)
and read/written from the **TX** thread (active-open SYN
generation). No lock → cookie-cache tear (H3), lost
pending-count (H2). Stack-wide singleton.

*Fix:* added `TcpStack._lock` (`threading.Lock`, `compare=False`)
and routed every read/write through guarded accessors
(`fastopen_cookie` / `cache_fastopen_cookie` /
`is_fastopen_negative` / `mark_fastopen_negative` /
`fastopen_pending` / `incr_fastopen_pending` /
`decr_fastopen_pending`) — mirrors the PMTU `record_*`
pattern. The compound pop+insert+FIFO-evict cookie-cache
mutation is now a single critical section. All 8 production
call sites migrated; the fields remain public only for the
single-threaded test-fixture seed path. Lock discipline pinned
by `test__tcp__stack.py::TestTcpStack__Accessors` (red→green).
The check-then-increment of `fastopen_pending` across the
listen handler (read at the gate, increment after session
setup) remains a benign TOCTOU that can transiently overshoot
`fastopen_qlen` by one — out of T1 scope (field-tear/lost-update
only); a fused check-and-admit accessor is a possible later
refinement.

**T2 · `TcpSession` timer + congestion/retransmit state — HIGH (intricate)**
`protocols/tcp/tcp__session.py`. `_lock__fsm` covers FSM
*dispatch*, but:
- `_timer_deadlines` (dict) + `_service_handle` are mutated
  by `_arm_timer`/`_cancel_timer`/`_reschedule_service` —
  some call paths hold `_lock__fsm`, some (timer-thread
  `_reschedule_service`) do not (H2/H3).
- The timer thread reads `_cc` (cwnd/ssthresh/PRR),
  `_rto_state`, `_sack_scoreboard`, `_rack_tlp`,
  `_retransmit_count`/`_syn_retransmit_count`,
  `_delayed_ack_segments_pending` while the RX thread mutates
  them inside `tcp_fsm()` (H2 — torn reads of CC/RTO state).
- `_ooo_packet_queue` is guarded (all access under
  `_lock__fsm`).

Best folded into the planned TCP god-class decomposition
(`docs/refactor/` TCP-decomposition track) rather than bolted
on — the lock discipline should be designed with the session
split, not retrofitted twice.

### 2.2 Transport — UDP / RAW

**U1 · per-socket source filters — MEDIUM**
`socket/__init__.py` `_ip4_source_filters` (dict keyed by
`(ifindex, group)`). Written by the **app** thread
(`IP_*_SOURCE_MEMBERSHIP` setsockopt → `_apply_source_op`
compound RMW) and read by the **RX** thread
(`_ip4_multicast_source_admits`, the UDP + RAW data-plane
gate). Single `.get` on RX is atomic on the GIL build; under
no-GIL a dict resize during the read tears (H3), and two app
threads racing setsockopt on one socket lose an update (H2).
Not the handler-side `_ip4_multicast_filters` (that is F2,
locked) — this is the socket-side copy.

Per-socket scalar options (`_blocking`, `_ttl`, `_tos`,
`_ip_recverr`, buffer sizes, …): app-write / RX-TX-read of a
single bool/int — torn-but-benign (H4-like), LOW.

### 2.3 Network — IPv6 ND / SLAAC / DAD + IPv4 address config

**N1 · per-interface address-config state — HIGH**
`runtime/packet_handler/__init__.py`. `_ip4_ifaddr` /
`_ip6_ifaddr` (+ `_ip4/6_ifaddr_candidate`),
`_icmp6_slaac_addresses`, `_icmp6_temp_addresses`,
`_icmp6_default_routers`, `_icmp6_dad__states`, **and the
multicast membership lists `_ip4_multicast` / `_ip6_multicast`
themselves** (the M1 fix guards the MLD query *timer* state but
the membership list the Report emitter reads is still bare).
Written from the **RX** thread (RA processing — prefix/route/
address list rebuilds), the **Timer**/async **DAD-claim**
threads (SLAAC + ACD confirm), the **app** thread (Address /
Membership API), and boot. No lock → list/dict tear (H3) and
RA-vs-claim races (H2). The `DadSlotRegistry` itself is locked,
but the address *lists* it feeds are not. This is the
Address-API Phase-3 boundary; design the lock with that API.

### 2.4 Network — multicast (residuals after F2/F4)

**M1 · MLDv2 query-response state — MEDIUM — SHIPPED 2026-05-27**
`packet_handler/__init__.py:336` + `packet_handler__icmp6__rx.py`.
`_mld2_query__pending_response_at_ms` / `_mld2_query__handle`
— the IPv6 mirror of the IGMP query-response state F4 fixed
for IPv4. RX-write vs Timer-clear, no lock. F4 only covered
IPv4 IGMP; MLD was missed.

*Fix:* wrapped both entry points — `__phrx_icmp6__mld2_query`
(RX schedule/coalesce/supersede) and `_mld2_query__deferred_send`
(timer-thread clear) — in `with self._if._lock__multicast:`,
folding the IPv6 MLD query-timer state under the same
per-interface multicast RLock as the IPv4 path rather than
adding a second lock. Lock discipline pinned by
`test__mld__thread_safety.py` (red→green via the tracking-RLock
max-depth probe). NOTE residual: the MLD Report emitter
(`_send_icmp6_multicast_listener_report`) reads the IPv6
membership list `_ip6_multicast`, which is still not guarded —
that is the IPv6 half of N1 (address/membership config), tracked
there, not in M1.

**M2 · IGMP querier-present timers — LOW/MEDIUM — SHIPPED 2026-05-27**
`_igmp__v1/v2_querier_present_until_ms` are written under
`_lock__multicast` (RX, F4) but were **read** via
`_igmp_host_compatibility_mode()` (`__init__.py:2096-2098`)
from the **TX state-change retransmit timer callback**
(`packet_handler__igmp__tx.py::_fire_state_change_retransmit`,
timer thread) *without* the lock — a torn deadline read →
momentarily-wrong compat mode, plus an unguarded
read-modify-write of the `_igmp_state_change__pending` map the
RX/app path mutates under the lock.

*Fix:* wrapped the whole `_fire_state_change_retransmit` body in
`with self._if._lock__multicast:` (reentrant RLock; the nested
`_igmp_host_compatibility_mode` / `_emit_state_change` reads are
fine). Pinned by
`test__igmp__thread_safety.py::TestIgmpStateChangeRetransmitLocking`
(red→green).

### 2.5 Network — fragmentation

**F-frag · `IpFragTable` — LOW**
`protocols/ip/ip_frag_table.py` `_flows` (dict). Per-interface
instance; only that interface's single rx-ring thread writes
it (lazy sweep, no timer thread). Effectively single-threaded
per instance → safe today. Add a lock only if a sweeper
thread is ever introduced; document the single-writer
assumption.

### 2.6 ICMP

**I1 · ICMP error rate limiters — MEDIUM**
`protocols/icmp/icmp__error_emitter.py:160` `try_consume`
mutates `_tokens` / `_last_refill` (token-bucket RMW). The
limiters are **stack-wide singletons** (`stack/__init__.py`),
so in multi-interface mode every interface's rx-ring thread
hits the same limiter concurrently (H2 — token over/under-
count). No lock.

### 2.7 Observability — PacketStats

**P1 · stat counters — LARGE surface, LOW correctness**
`lib/packet_stats.py`. `PacketStatsRx`/`PacketStatsTx` (250+
`int` fields) incremented via `+=` at ~300+ sites across RX,
TX, and Timer threads; `LinkStatsCounters.rx_bytes/tx_bytes`
from the ring threads. Every `+=` is a non-atomic RMW (H4) →
lost increments under no-GIL. **Observability only — no
protocol corruption.** A lock-per-increment would be absurd
churn on the hot path; the right fix is a *strategy* decision
(per-thread counters summed on read, or accept approximate
counts, or a single stats lock taken only on snapshot). Decide
before touching.

---

## 3. Correction plan

Tests-first throughout (a failing lock-discipline or
behavioural test per fix, per the F1–F4 pattern). One concern
per commit; refresh this doc + `socket_linux_parity_audit.md`
§X1 in lockstep. Sequenced by value / independence:

1. **T1 — `TcpStack` Fast-Open lock. ✅ DONE 2026-05-27.**
   Added `threading.Lock` to `TcpStack`, guarded the three
   fastopen fields behind accessor methods (mirrors the PMTU
   `record_*` pattern). Lock-discipline test
   (`test__tcp__stack.py::TestTcpStack__Accessors`) red→green;
   8 call sites migrated. See §2.1 for detail.
2. **M1 + M2 — finish multicast. ✅ DONE 2026-05-27.** Locked
   the MLDv2 query state (wrapped `__phrx_icmp6__mld2_query` +
   `_mld2_query__deferred_send` under `_lock__multicast`,
   mirroring the IGMP F4 pattern) and closed the IGMP
   querier-timer TX-retransmit read/RMW (wrapped
   `_fire_state_change_retransmit` under `_lock__multicast`).
   Tests `test__mld__thread_safety.py` +
   `TestIgmpStateChangeRetransmitLocking` red→green. The IPv6
   membership-list read in the MLD Report emitter is the IPv6
   half of N1, not M1. See §2.4 for detail.
3. **I1 — ICMP rate-limiter lock.** Add a `threading.Lock`
   inside `IcmpErrorRateLimiter.try_consume`. Tiny.
4. **U1 — per-socket source-filter lock.** Guard
   `_ip4_source_filters` with a per-socket lock (or reuse
   `_lock__io`), both the app-write RMW and the RX-read gate.
5. **N1 — address-config lock.** Per-interface
   `_lock__addr_config` guarding the IPv4/IPv6 ifaddr +
   candidate + SLAAC/temp/router/DAD-state lists; wire it
   through the Address API and the RA/claim paths. Larger;
   design with the Phase-3 Address-API boundary.
6. **T2 — TcpSession timer/CC state.** Largest and most
   intricate; **do not bolt on** — fold the lock discipline
   into the TCP god-class decomposition so it is designed
   once. Until then, document the `_lock__fsm`-coverage gap
   inline with `# Phase: no-GIL` markers.
7. **P1 — PacketStats strategy.** Decide the counter approach
   (per-thread + sum-on-read preferred) before any code.
   Explicitly *not* a lock-per-increment.

`F-frag` and the per-socket scalar options are LOW — document
the single-writer / benign-tear assumption inline; revisit
only if a new thread touches them.

### 3.1 What "done" means

Every Part-2 item either carries a lock (or documented
lock-free design) or an inline `# Phase: no-GIL — <why
safe>` justification. At that point
`socket_linux_parity_audit.md` §X1 can legitimately claim the
no-GIL backlog is closed (it cannot today).

---

## 4. Correction to the prior record

`socket_linux_parity_audit.md` §X1 concluded "every
cross-thread structure in the stack now carries a lock." That
is **false outside the IGMP/PMTU path** — see Part 2. The §X1
conclusion should be amended to: "F1–F4 closed the IPv4
multicast / IGMP-query / PMTU cross-thread state; the full
stack-wide no-GIL backlog is tracked in
`no_gil_thread_safety_audit.md`." This document is the
authoritative no-GIL ledger going forward.
