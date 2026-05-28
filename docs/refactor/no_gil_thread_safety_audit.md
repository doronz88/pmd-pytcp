# PyTCP No-GIL Thread-Safety Audit + Correction Plan

**Status:** audit performed 2026-05-27. Supersedes the
IGMP-scoped conclusion in
`socket_linux_parity_audit.md` §X1 (which claimed the
cross-thread backlog was empty — it was empty only for the
IGMP/PMTU path that triggered it).

**Backlog progress (2026-05-27):** T1, M1, M2, I1, U1, N1, P1
all SHIPPED. **T2** (`TcpSession` timer/CC state) SHIPPED as
Phase 1 of the TCP god-class decomposition — the timer
deadline map + coalesced service handle moved onto a
`TcpTimerService` collaborator carrying its own
`threading.Lock`. **The no-GIL backlog is now fully closed.**
See §3.1.

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
| ICMP error rate-limiter token bucket | `_lock` in `try_consume` (I1) | `protocols/icmp/icmp__error_emitter.py` |
| per-socket IPv4 source-filter map | `_lock__ip4_source_filters` (U1) | `socket/__init__.py` |
| per-interface address-config + IPv6-multicast lists (ifaddr / SLAAC / temp / routers / DAD-state / `_ip6_multicast`) | `_lock__addr_config` + copy-on-write; lock-free readers (N1) | `runtime/packet_handler/__init__.py`, `stack/address.py` |
| `PacketStatsRx` / `PacketStatsTx` counters | per-thread shards (`PacketStatsShards`), summed on read; lock-free increments (P1) | `lib/packet_stats.py`, `runtime/packet_handler/__init__.py` |
| PMTU maps (`pmtu_cache`/`pmtu_state`) | `_pmtu_lock` + accessors (F3) | `stack/__init__.py` |
| `TcpStack` Fast-Open state (cookies/negative/pending) | `_lock` + accessors (T1) | `protocols/tcp/tcp__stack.py` |
| RxRing `_rx_deque` / TxRing deque | `collections.deque` append/popleft (atomic in CPython incl. free-threaded build) + `os.eventfd` wakeup | `runtime/rx_ring.py`, `runtime/tx_ring.py` |
| `Subsystem` stop signalling | `threading.Event` (thread-safe) | `runtime/subsystem.py` |
| per-socket rx queue / accept queue / error queue | `_lock__io` + `threading.Semaphore` + atomic `deque` | `socket/*.py` |
| TcpSession `_rx_buffer` / `_tx_buffer` / `_state` | `_lock__rx_buffer` / `_lock__tx_buffer` / `_lock__fsm` | `protocols/tcp/tcp__session.py` |
| TcpSession logical-timer deadline map + coalesced service handle | `TcpTimerService._lock` (Lock; `_reschedule_locked` helper assumes held) (T2) | `protocols/tcp/session/tcp__session__timers.py` |

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

**T2 · `TcpSession` timer state — HIGH — SHIPPED 2026-05-27 (TCP decomposition Phase 1)**
`protocols/tcp/tcp__session.py`. Pre-fix: `_lock__fsm` covered
FSM dispatch and (by accident, via the umbrella) deadline-map
mutations; `_kick_pump()` had to acquire `_lock__fsm` from the
caller thread just to arm a timer; the deadline-map's
load-bearing invariant ("only mutated under `_lock__fsm`") was
documented only in a single docstring, brittle to drift.

*Fix:* extracted the 9 timer helpers + `_timer_deadlines` +
`_service_handle` into a per-session `TcpTimerService`
collaborator at
`protocols/tcp/session/tcp__session__timers.py`, carrying its
own `threading.Lock` (a non-reentrant `Lock`, not an `RLock`
— public mutators take it exactly once and call a private
`_reschedule_locked` helper that assumes the lock is held).
Session keeps thin delegators (`_arm_timer` → `self._timers.
arm(...)`, etc.); `_kick_pump` no longer needs `_lock__fsm`
(the `_state` read is a single attribute load whose worst-
case torn-transition outcome is one extra pump tick that
no-ops in the next FSM dispatch's CLOSED branch — benign).
Lock ordering: `_lock__fsm` → `_lock__timer` → `stack.timer
._lock`; the timer-worker callback runs lock-free and
re-acquires `_lock__fsm` on entry to `tcp_fsm`. Pinned by
`test__tcp__session__timer_service.py::TestTcpTimerService
Locking` (tracking-lock max-depth, red→green) +
`TestTcpTimerServiceBehaviourParity` (the public delegators
preserve arm/cancel/armed/expired/cancel-all/kick-pump
semantics).

The other concerns originally listed under T2 — the timer
thread's reads of `_cc` / `_rto_state` / `_sack_scoreboard`
/ `_rack_tlp` / retransmit counters — are NOT exposed by
this fix: all of those reads happen inside `tcp_fsm(timer=
True)`, which acquires `_lock__fsm` on the timer-worker
thread before touching them, the same way the RX thread
does. Those state structures are mutated only from within
`tcp_fsm`. The umbrella `_lock__fsm` is what guards them.
Future phases of the TCP god-class decomposition may move
those reads to dedicated collaborators with finer-grained
locks; that work no longer blocks the no-GIL goal.

### 2.2 Transport — UDP / RAW

**U1 · per-socket source filters — MEDIUM — SHIPPED 2026-05-27**
`socket/__init__.py` `_ip4_source_filters` (dict keyed by
`(ifindex, group)`). Written by the **app** thread
(`IP_*_(SOURCE_)MEMBERSHIP` setsockopt → check-then-act +
`_apply_source_op` compound RMW, and the close-time
`_release_ip4_memberships`) and read by the **RX** thread
(`_ip4_multicast_source_admits`, the UDP + RAW data-plane
gate). Single `.get` on RX is atomic on the GIL build; under
no-GIL a dict resize during the read tears (H3), and two app
threads racing setsockopt on one socket lose an update (H2).
Not the handler-side `_ip4_multicast_filters` (that is F2,
locked) — this is the socket-side copy.

*Fix:* added per-socket `_lock__ip4_source_filters`
(`threading.Lock`) and wrapped all three app-side mutators
(`_ipproto_ip_membership`, `_ipproto_ip_source_membership`,
`_release_ip4_memberships` — each as one check-then-act RMW)
and the RX read gate `_ip4_multicast_source_admits` in it
(the immutable `Ip4MulticastFilter.allows` runs outside the
lock on the snapshotted reference). The UDP RX gate
`__phrx_udp__multicast_source_allowed` now delegates to that
locked accessor instead of doing its own bare `.get`, so both
the UDP and RAW data-plane gates share one guarded read path.
Lock ordering: `_lock__ip4_source_filters` is only ever taken
*before* the interface `_lock__multicast` the membership API
acquires, never after — no cycle. Pinned by
`test__igmp__thread_safety.py::TestSocketSourceFilterLocking`
(write-RMW + RX-read, red→green).

Per-socket scalar options (`_blocking`, `_ttl`, `_tos`,
`_ip_recverr`, buffer sizes, …) remain LOW (see below).

Per-socket scalar options (`_blocking`, `_ttl`, `_tos`,
`_ip_recverr`, buffer sizes, …): app-write / RX-TX-read of a
single bool/int — torn-but-benign (H4-like), LOW.

### 2.3 Network — IPv6 ND / SLAAC / DAD + IPv4 address config

**N1 · per-interface address-config state — HIGH**
`runtime/packet_handler/__init__.py`. `_ip4_ifaddr` /
`_ip6_ifaddr`, `_icmp6_slaac_addresses`,
`_icmp6_temp_addresses`, `_icmp6_default_routers`,
`_icmp6_dad__states`, **and the IPv6 multicast membership list
`_ip6_multicast`** (the M1 residual — the MLD Report emitter
reads it). Written from the **RX** thread (RA processing —
prefix/route/address list rebuilds), the **Timer**/async
**DAD-claim** threads (SLAAC + ACD confirm + sweeps), the
**app** thread (Address / Membership API), and boot. No lock →
list/dict tear (H3) and RA-vs-claim races (H2). The
`DadSlotRegistry` itself is locked, but the address *lists* it
feeds are not.

*Fix (SHIPPED 2026-05-27):* added a per-interface
`_lock__addr_config` (RLock) that serializes **writers** and
publishes a fresh list/dict object every mutation
(copy-on-write); the per-packet RX/TX **readers stay lock-free**,
loading the attribute reference once (atomic on free-threaded
CPython per PEP 703) and iterating the immutable snapshot — the
only no-GIL-safe way to iterate without crashing, since PEP 703
makes individual list/dict ops atomic but does NOT make
iterate-during-mutation safe. This finishes the atomic-rebind
pattern the Address API had already started. Every in-place
`.append`/`.remove`/`[k]=`/`.pop`/`.setdefault` on these
attributes is converted to a rebind under the lock
(`_assign/_remove_ipX_host`, `_assign/_remove_ip6_multicast`,
`_update_icmp6_{default_router,slaac_address,temp_address}`, the
`_icmp6_sweep_{temp,slaac}_addresses` cluster mutators, the
`_icmp6_regen_temp_addresses` append, the five DAD-state writes,
and the `address.py` Address-API mutators). The lock is **never
held across the DAD blocking waits** — the DAD loop locks only
at its individual mutation points. Lock ordering: taken before
`tx_ring` on the emit paths, never under `_lock__multicast`
(the MLD emitter reads `_ip6_multicast` lock-free, so the
M1→N1 cross-lock hazard is dissolved). Pinned by
`test__addr_config__thread_safety.py` (5 writers × copy-on-write
identity-change + lock-acquired, red→green).

*Out of scope (LOW, documented):* `_ip4_ifaddr_candidate` /
`_ip6_ifaddr_candidate` stay in-place — they are mutated only by
the single boot-time addressing thread (`_create_stack_*_addressing`,
which iterates a `list(...)` snapshot) and are never read on the
per-packet path, so they carry no cross-thread hazard (same
class as `F-frag`). `_ip4_multicast` is a derived `@property`
over `_ip4_multicast_filters`, already under `_lock__multicast`
(F2).

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

**I1 · ICMP error rate limiters — MEDIUM — SHIPPED 2026-05-27**
`protocols/icmp/icmp__error_emitter.py` `try_consume`
mutates `_tokens` / `_last_refill` (token-bucket RMW). The
limiters are **stack-wide singletons** (`stack/__init__.py`),
so in multi-interface mode every interface's rx-ring thread
hits the same limiter concurrently (H2 — token over/under-
count). No lock.

*Fix:* added `IcmpErrorRateLimiter._lock` (`threading.Lock`)
and wrapped the whole `try_consume` token-bucket RMW in it.
Pinned by
`test__icmp__error_emitter__rate_limiter.py::TestIcmpErrorRateLimiter__Locking`
(tracking-lock max-depth probe, red→green).

### 2.7 Observability — PacketStats

**P1 · stat counters — LARGE surface — SHIPPED 2026-05-27**
`lib/packet_stats.py`. `PacketStatsRx`/`PacketStatsTx` (308
`int` fields total) incremented via `+=` at ~316 sites across
RX, TX, and Timer threads. Every `+=` is a non-atomic RMW (H4)
→ lost increments under no-GIL. **Observability only — no
protocol corruption.** A lock-per-increment would be absurd
churn on the hot path.

*Strategy decided + shipped:* **per-thread sharded counters,
summed on read** (the Linux `percpu_counter` model — chosen
over lock-per-increment and over accept-approximate because it
is both exact and contention-free on the hot path). New
`PacketStatsShards[T]` holds one `PacketStats` shard per writing
thread via `threading.local` (the constructing thread's shard is
seeded with the injected/default instance); `current()` returns
the calling thread's shard (lock-free after first access — only
a new thread's first touch takes a brief registration lock),
`snapshot()` sums the shards field-by-field into a fresh
instance. `PacketHandler._packet_stats_rx`/`_tx` became
**properties returning `current()`**, so the ~316
`self._packet_stats_rx.field += 1` sites are unchanged and write
their thread's shard with no lock and no cross-core contention;
the public `packet_stats_rx`/`packet_stats_tx` properties return
`snapshot()` (now copy-by-value, matching the Phase-3 read-only
introspection contract). Pinned by
`test__packet_handler__stats_thread_safety.py` (distinct shard
per thread + summed snapshot + copy-by-value, red→green). The
synchronous single-thread test harness reads exact counts back
because all its increments land on the constructing thread's
seeded shard.

`LinkStatsCounters.rx_bytes`/`tx_bytes` are **left unsharded
(LOW)**: `rx_bytes` is written only by the rx-ring thread and
`tx_bytes` only by the tx-ring thread — single-writer per
counter (different slots), so no lost-update hazard; the reader
sees an atomic per-field load. Documented here rather than
guarded.

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
3. **I1 — ICMP rate-limiter lock. ✅ DONE 2026-05-27.** Added
   `IcmpErrorRateLimiter._lock` and wrapped the `try_consume`
   token-bucket RMW. Test red→green. See §2.6 for detail.
4. **U1 — per-socket source-filter lock. ✅ DONE 2026-05-27.**
   Added a dedicated `_lock__ip4_source_filters` (not
   `_lock__io` — the RX gate is called outside `_lock__io`,
   and `_lock__io` is non-reentrant) guarding both the
   app-write RMW (all three mutators) and the unified RX-read
   gate. Test red→green. See §2.2 for detail.
5. **N1 — address-config lock. ✅ DONE 2026-05-27.**
   Per-interface `_lock__addr_config` (RLock) serializing
   writers + copy-on-write publish; readers lock-free. Covers
   the IPv4/IPv6 ifaddr, SLAAC/temp/router lists, DAD-state map,
   and `_ip6_multicast`, wired through the RA/claim/sweep paths
   and the Address API. Candidates excluded (boot single-writer).
   Test red→green. See §2.3 for detail.
6. **T2 — TcpSession timer state. ✅ DONE 2026-05-27 (TCP
   decomposition Phase 1).** Extracted the 9 timer helpers
   + deadline map + coalesced service handle into
   `TcpTimerService` (`protocols/tcp/session/
   tcp__session__timers.py`) carrying its own `Lock`.
   Session keeps thin delegators; `_kick_pump` no longer
   needs `_lock__fsm`. The CC / RTO / SACK / RACK state the
   timer-worker thread touches is already guarded by
   `_lock__fsm` (timer callbacks run via `tcp_fsm(timer=True)`
   which acquires it). Test red→green. See §2.1 for detail.
7. **P1 — PacketStats strategy. ✅ DONE 2026-05-27.** Decided
   on per-thread sharded counters summed on read
   (`PacketStatsShards`, the `percpu_counter` model) over
   lock-per-increment / accept-approximate. `_packet_stats_rx`/
   `_tx` are now `current()`-shard properties (lock-free
   increments), public `packet_stats_*` return `snapshot()`.
   `LinkStatsCounters` left unsharded (single-writer per
   counter). Test red→green. See §2.7 for detail.

`F-frag` and the per-socket scalar options are LOW — document
the single-writer / benign-tear assumption inline; revisit
only if a new thread touches them.

### 3.1 What "done" means

Every Part-2 item either carries a lock (or documented
lock-free design) or an inline `# Phase: no-GIL — <why
safe>` justification.

**Status 2026-05-27:** T1, M1, M2, I1, U1, N1, P1, **and T2**
all SHIPPED. **The no-GIL backlog is fully closed.** T2 was
fixed as Phase 1 of the TCP god-class decomposition — the
deadline map + coalesced service handle moved onto a
`TcpTimerService` collaborator carrying its own lock; CC /
RTO / SACK / RACK state remain guarded by `_lock__fsm` via
the `tcp_fsm(timer=True)` callback path (no additional work
required there). `F-frag` and the per-socket scalar options
remain documented-LOW (single-writer / benign-tear).
`socket_linux_parity_audit.md` §X1 has been updated in
lockstep.

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
