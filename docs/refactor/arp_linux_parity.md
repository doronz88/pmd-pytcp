# ARP → Linux-host Parity Audit & Punch List

This document captures the ARP-related work needed to bring
PyTCP's host-stack ARP behaviour to default-Linux parity. It
records what shipped, what's still open, and the implementation
detail needed to resume each remaining item without re-deriving
it from scratch.

The classification follows the project's North Star (`CLAUDE.md`):
Phase 1 covers default-Linux **host** behaviour; Phase 2 covers
router-grade work. Items below are marked Tier 1 (blocker), Tier 2
(RFC 5227 finish), Tier 3 (Linux-specific defaults), or Tier 4
(Phase 2 / deferred per North Star).

---

## §0 Status snapshot (2026-05-09)

### ✅ Shipped

| # | Item | Commit | RFC clause |
|---|---|---|---|
| 1 | RX-vs-DAD probe-conflict-set disconnect | `cffd4841` | 5227 §2.1.1 |
| 2 | DEFEND_INTERVAL rate-limit on conflict defense | `87851caa` | 5227 §2.4(c) |
| 3 | ARP-Request rate-limit + queued-packet flush | `628e724b` | 1122 §2.3.2.1 + §2.3.2.2 |
| — | Ethernet TX `enqueue_pending` wiring tests | `c716c35f` | (test-only) |
| — | Ethernet TX → ARP cache resolution flow integration | `8b4e321e` | (test-only) |
| 5 | ANNOUNCE_NUM = 2 (second Announcement after probe) | `3d7d276d` | 5227 §2.3 |
| 6 | ANNOUNCE_WAIT (2 s post-probe quiet period) | `01841e10` | 5227 §2.1.1 |
| 7 | PROBE_WAIT (initial 0–1 s random delay) + PROBE_NUM/MIN/MAX | `5777c00a` | 5227 §2.1.1 |
| 8 | Simultaneous-probe (peer's SPA = 0, TPA = candidate) detection | `3f051584` | 5227 §2.1.1 |
| 14 | Unicast cache-refresh probe (replaces broadcast) | `30aaa98a` | 1122 §2.3.2.1 IMPL (2) |
| 15 | Wall-clock → `time.monotonic` in cache aging | `1a46f28f` | (Linux parity) |
| 16 | Configurable cache timeout (`stack.init` kwargs) | (this commit) | 1122 §2.3.2.1 SHOULD |
| — | Six RFC adherence audits (826/1027/1122/3927/5227/5494) | `03c0b678` | — |
| — | `ArpTestCase` harness + smoke / DAD / DEFEND_INTERVAL / resolution-flow integration tests | various | — |
| — | Code relocated from `pytcp/stack/` → `pytcp/protocols/arp/` | `e29e6b1e` | — |
| — | `test__arp__cache.py` import fixups (follow-up to relocation) | `24eaa44d` | — |
| — | `_ArpRxTestBase.setUp` `create=True` fix (unblock unit tests) | `f8cf5136` | — |

### 🔓 Remaining inventory

- **Tier 2 (RFC 5227 finish):** §2 (#9), §3 (#10) below.
- **Tier 3 (Linux defaults):** §4–§6, §10 below (#14, #15, #16 shipped).
- **Tier 4 (deferred):** §11 below.

---

## §1 — Tier 2 #8: simultaneous-probe detection (RFC 5227 §2.1.1)

### What's missing

> "In addition, if during this period the host receives any ARP
> Probe where the packet's 'target IP address' is the address
> being probed for, and the packet's 'sender hardware address'
> is not the hardware address of any of the host's interfaces,
> then the host SHOULD similarly treat this as an address
> conflict and signal an error to the configuring agent as
> above."

This is the case where ANOTHER host is probing the SAME address
at the same time as us. The peer's frame has:
- `arp.spa = 0.0.0.0` (probe — peer's "I want this address")
- `arp.tpa = our candidate IP`
- `arp.sha != our MAC` (real foreign peer, not loopback)

PyTCP's existing probe-conflict detection branches at
`packet_handler__arp__rx.py:202,292,320` only fire when
`arp.spa in self._ip4_host_candidate` — that condition is FALSE
when SPA = 0. So the simultaneous-probe case is silently missed.

### Where to add the branch

`pytcp/stack/packet_handler/packet_handler__arp__rx.py` —
inside `__phrx_arp__request`, after the existing loop-drop and
conflict-defend checks but before the gratuitous-Request
branch. Pseudocode:

```python
# RFC 5227 §2.1.1: another host is probing the same candidate
# (their SPA = 0, TPA = our candidate, SHA != our MAC).
if (
    packet_rx.arp.spa.is_unspecified
    and packet_rx.arp.tpa in {c.address for c in self._ip4_host_candidate}
    and packet_rx.arp.sha != self._mac_unicast
):
    self._packet_stats_rx.arp__op_request__simultaneous_probe += 1
    __debug__ and log(
        "arp",
        f"{packet_rx.tracker} - <WARN>Simultaneous-probe conflict "
        f"detected for candidate {packet_rx.arp.tpa} from peer "
        f"{packet_rx.arp.sha}</>",
    )
    self._arp_probe__unicast_conflict.add(packet_rx.arp.tpa)
    return
```

### Stats counter

Add `arp__op_request__simultaneous_probe: int = 0` to
`pytcp/lib/packet_stats.py::PacketStatsRx`. Field count goes
from current N → N+1.

### Tests-first

**Unit** — extend
`pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__arp__rx.py::TestPacketHandlerArpRxRequest`
with `test__stack__packet_handler__arp__rx__simultaneous_probe_conflict`:

```python
def test__stack__packet_handler__arp__rx__simultaneous_probe_conflict(self):
    """
    Ensure a peer's ARP Probe (SPA=0, TPA=our candidate, foreign
    SHA) registers as a probe-conflict on the per-instance set.

    Reference: RFC 5227 §2.1.1 (simultaneous-probe conflict).
    """
    frame = _arp_frame(
        oper=ArpOperation.REQUEST,
        sha=HOST_A__MAC,
        spa=IP4__UNSPEC,
        tha=MAC__UNSPEC,
        tpa=STACK__IP4_ADDRESS__CANDIDATE,
    )
    packet_rx = _make_packet_rx(frame, ethernet_dst=MAC__BROADCAST)
    self._handler._phrx_arp(packet_rx)

    self.assertIn(
        STACK__IP4_ADDRESS__CANDIDATE,
        self._handler._arp_probe__unicast_conflict,
        msg="...",
    )
    self.assertEqual(
        self._handler._packet_stats_rx.arp__op_request__simultaneous_probe,
        1,
        msg="...",
    )
```

**Integration** — extend
`pytcp/tests/integration/protocols/arp/test__arp__dad.py::TestArpDad`
with `test__arp__dad__simultaneous_probe_aborts_claim`. Inject
the simultaneous-probe at idx 1 (during the first inter-probe
sleep) using the existing `_drive_dad(on_sleep=...)` harness.

### Effort

Small (~50 lines source + 30 lines tests). One commit.

### Reference

`docs/rfc/arp/rfc5227__ipv4_acd/adherence.md` §2.1.1 calls out
this gap explicitly under "Simultaneous-probe (SPA = 0)
detection — not implemented."

---

## §2 — Tier 2 #9: abandon-after-second-conflict (RFC 5227 §2.4(b) MUST)

### What's missing

> "However, if this is not the first conflicting ARP packet the
> host has seen, and the time recorded for the previous
> conflicting ARP packet is recent, within DEFEND_INTERVAL
> seconds, then the host MUST immediately cease using this
> address and signal an error to the configuring agent as
> described above."

Today PyTCP's `_maybe_send_arp_defense`
(`packet_handler__arp__rx.py:90-103`) rate-limits the defense
but never abandons. The MUST: on the **second** conflict within
DEFEND_INTERVAL of the previous, give up the address.

Plus the §2.4-final SHOULD:

> "Before abandoning an address due to a conflict, hosts SHOULD
> actively attempt to reset any existing connections using that
> address."

### Required state

Add to `PacketHandlerL2`:

```python
self._arp_defend__last_conflict_at: dict[Ip4Address, float] = {}
```

Distinct from the existing `_arp_defend__last_emitted` (which
tracks last DEFENSE; this tracks last CONFLICT — they're
different timestamps because rate-limiting suppresses defenses).

### Logic split

Replace `_maybe_send_arp_defense` with `_handle_arp_conflict`
that does:

```python
def _handle_arp_conflict(self, *, ip4_unicast):
    now = time.monotonic()
    last = self._arp_defend__last_conflict_at.get(ip4_unicast)
    self._arp_defend__last_conflict_at[ip4_unicast] = now

    if last is not None and now - last < ARP__DEFEND_INTERVAL:
        # Second conflict within window — RFC 5227 §2.4(b) MUST abandon.
        self._abandon_ipv4_address(ip4_unicast=ip4_unicast)
        return

    # First conflict (or stale window) — defend, gated by
    # the per-IP last-defended timestamp (existing logic).
    last_defense = self._arp_defend__last_emitted.get(ip4_unicast)
    if last_defense is None or now - last_defense >= ARP__DEFEND_INTERVAL:
        self._arp_defend__last_emitted[ip4_unicast] = now
        self._send_gratuitous_arp(ip4_unicast=ip4_unicast)
```

### Abandon path

```python
def _abandon_ipv4_address(self, *, ip4_unicast):
    """
    Tear down all sessions bound to the address, remove from
    '_ip4_host', log, signal the configuring agent.
    """
    # 1. ABORT any TcpSessions bound to this address.
    from pytcp.lib.tx_status import TxStatus
    from pytcp.protocols.tcp.tcp__session import SysCall
    for socket_id, sock in list(stack.sockets.items()):
        if socket_id.local_ip == ip4_unicast:
            session = getattr(sock, "_tcp_session", None)
            if session is not None:
                session.tcp_fsm(syscall=SysCall.ABORT)

    # 2. Remove from _ip4_host.
    self._ip4_host = [h for h in self._ip4_host if h.address != ip4_unicast]

    # 3. Log + stat.
    log("arp", f"<CRIT>Abandoned IPv4 address {ip4_unicast} after second conflict</>")
    # Optional: PacketStatsRx.arp__op_*__conflict__abandon += 1

    # 4. Configuring-agent signal: if _ip4_host is now empty,
    #    set _ip4_support = False (mirrors the DAD-failure path
    #    at the bottom of _create_stack_ip4_addressing).
    if not self._ip4_host:
        self._ip4_support = False
```

### Tests-first

**Unit** in
`test__stack__packet_handler__arp__rx.py::TestPacketHandlerArpRxDefendInterval`
(extend the existing class):

- `test__abandon_after_second_conflict_within_window` — drive
  2 conflicts at t=1000 and t=1005; assert address removed
  from `_ip4_host` and the stub's `aborted_session_ids` (or
  similar spy) records the ABORT.
- `test__no_abandon_after_second_conflict_outside_window` —
  drive 2 conflicts at t=1000 and t=1011 (10.5 s apart, past
  DEFEND_INTERVAL); assert address still in `_ip4_host` and
  defense fires both times.

**Integration** in
`test__arp__defend_interval.py::TestArpDefendInterval`:

- `test__second_conflict_within_window_abandons` — drive 2
  conflicts at the wire level; assert no second defensive
  ARP, address removed from `_ip4_host`.

### Effort

Substantial. Touches:
- `pytcp/stack/packet_handler/packet_handler__arp__rx.py` (~30 lines)
- `pytcp/stack/packet_handler/__init__.py` (~30 lines for `_abandon_ipv4_address` + state field)
- `pytcp/lib/packet_stats.py` (new counter)
- TCP session ABORT plumbing — verify the API exists and works from this caller (`tcp_session.tcp_fsm(syscall=SysCall.ABORT)` is the canonical call per `pytcp/protocols/tcp/tcp__session.py`).

### Reference

`docs/rfc/arp/rfc5227__ipv4_acd/adherence.md` §2.4 / §2.4(b).

---

## §3 — Tier 2 #10: MAX_CONFLICTS / RATE_LIMIT_INTERVAL

### What's missing

> "A host implementing this specification MUST take precautions
> to limit the rate at which it probes for new candidate
> addresses: if the host experiences MAX_CONFLICTS or more
> address conflicts on a given interface, then the host MUST
> limit the rate at which it probes for new addresses on this
> interface to no more than one attempted new address per
> RATE_LIMIT_INTERVAL."

### Why dormant today

PyTCP's static-config + DHCP-only model has no automatic
candidate-rotation path. A claim either succeeds or fails;
PyTCP doesn't pick a different IP and try again. So
"rate-limit the retry" has nothing to rate-limit.

This MUST becomes live the moment any of:
- RFC 3927 link-local autoconfig is implemented (auto-pick
  another 169.254.x.x on conflict)
- DHCP DECLINE handling triggers asking for another lease
- Multi-candidate static config with fallback

### Action today

**None — defer until a candidate-rotation path lands.** When
that work happens, the implementing item will need to:

1. Track per-interface conflict count.
2. When count >= MAX_CONFLICTS (10), gate new candidate
   probes by RATE_LIMIT_INTERVAL (60 s).

Constants to add (pre-emptively, optional):
- `ARP__MAX_CONFLICTS = 10`
- `ARP__RATE_LIMIT_INTERVAL = 60`

### Reference

`docs/rfc/arp/rfc5227__ipv4_acd/adherence.md` §2.1.1
"MAX_CONFLICTS / RATE_LIMIT_INTERVAL — not implemented (dormant
in static-config model)."

---

## §4 — Tier 3 #11: NUD state machine

### What's missing

Linux's `net/core/neighbour.c` implements the RFC 4861 §7.3.2
state machine plus FAILED:

```
        NUD_NONE
            ↓ (find_entry on miss)
       NUD_INCOMPLETE
            ↓ (ARP Reply received)         ↓ (PROBE_NUM probes, no Reply)
        NUD_REACHABLE                      NUD_FAILED
            ↓ (REACHABLE_TIME elapsed)
         NUD_STALE
            ↓ (TX uses entry)
          NUD_DELAY
            ↓ (DELAY_FIRST_PROBE_TIME elapsed, no upper-layer confirm)
          NUD_PROBE
            ↓ (probe Reply)         ↓ (no Reply after MAX_UNICAST_SOLICIT)
        NUD_REACHABLE                NUD_FAILED
```

Today PyTCP has binary present/absent. The
`_PendingResolution` table from #3 is essentially `INCOMPLETE`
already; the cache's `CacheEntry` is essentially a degenerate
`REACHABLE` (no aging-related state). The FSM grows from
adding STALE/DELAY/PROBE/FAILED states and the transitions
between them.

### Implementation rough plan

1. **New file** `pytcp/protocols/arp/arp__nud.py` housing:
   - `NudState` enum (INCOMPLETE/REACHABLE/STALE/DELAY/PROBE/FAILED)
   - `NeighborEntry` dataclass replacing `CacheEntry` — carries
     state, `state_changed_at: float` (monotonic), `probe_count: int`
   - State transition helpers

2. **Refactor `ArpCache`** (`pytcp/protocols/arp/arp__cache.py`):
   - Replace `_arp_cache: dict[Ip4Address, CacheEntry]` with
     `_neighbours: dict[Ip4Address, NeighborEntry]`
   - `find_entry` returns MAC immediately for REACHABLE; queues
     packet for INCOMPLETE; for STALE → transition to DELAY
     and return MAC; for DELAY → return MAC; for PROBE → return
     MAC; for FAILED → return None
   - `add_entry` (on RX of Reply) → REACHABLE
   - `_subsystem_loop` runs the timer-driven transitions
     (REACHABLE → STALE after REACHABLE_TIME; DELAY → PROBE
     after DELAY_FIRST_PROBE_TIME; PROBE → FAILED after
     MAX_UNICAST_SOLICIT × RETRANS_TIMER)

3. **Reachability confirmation hook** (#12 below): public
   method `confirm_reachability(ip4_address)` that the TCP
   layer calls on in-window ACK. Moves the entry directly
   from STALE/DELAY/PROBE → REACHABLE without sending a probe.

4. **Bounded cache + GC** (#13 below): three thresholds
   triggering eviction (LRU? oldest-first?) when cache size
   crosses each.

5. **Generic `NeighborCache[A: Ip4Address | Ip6Address]`**:
   if the work is going to grow into ND too, extract a generic
   base. ARP and ND would both inherit. Linux's
   `net/core/neighbour.c` is the canonical model.

### Constants to add

Linux defaults (RFC 4861 §10):
- `ARP__NUD__REACHABLE_TIME = 30000`  ms (30 s base, randomised
  to 50–150% per Linux)
- `ARP__NUD__DELAY_FIRST_PROBE_TIME = 5000`  ms (5 s)
- `ARP__NUD__RETRANS_TIMER = 1000`  ms (1 s)
- `ARP__NUD__MAX_UNICAST_SOLICIT = 3`
- `ARP__NUD__MAX_MULTICAST_SOLICIT = 3`
- `ARP__GC_THRESH1 = 128`
- `ARP__GC_THRESH2 = 512`
- `ARP__GC_THRESH3 = 1024`

### Tests-first

This is the largest single piece of remaining work. Plan: one
PR per state with its own failing tests (incremental tests-
first):

1. `INCOMPLETE` state (folds in #3's `_PendingResolution`).
2. `REACHABLE` state (current `CacheEntry` semantics).
3. `STALE` transition on REACHABLE_TIME elapse.
4. `DELAY` transition on first TX from STALE.
5. `PROBE` transition + unicast probe emission.
6. `FAILED` transition after MAX_UNICAST_SOLICIT.
7. Reachability confirmation hook (#12).
8. Bounded-cache eviction (#13).

### Effort

1–2 weeks. Foundational architectural work.

### Reference

`docs/refactor/arp_linux_parity.md` (this file) §4
(this section) is the canonical plan.

---

## §5 — Tier 3 #12: reachability confirmation hook

Folds into #11. The TCP layer feeds back "I just received an
in-window ACK from this IP" so the neighbour entry can be
moved STALE → REACHABLE without sending a probe.

### Implementation

- `ArpCache.confirm_reachability(ip4_address)` public API
- TCP session calls it from the in-window-ACK code path
  (`pytcp/protocols/tcp/tcp__session.py`'s ACK processor)

### Effort

Small (~20 lines + tests) **once #11 lands**.

---

## §6 — Tier 3 #13: bounded cache + GC

Folds into #11. Linux uses three thresholds:
- `gc_thresh1 = 128` — below this, never GC
- `gc_thresh2 = 512` — above this, GC after stale_time
- `gc_thresh3 = 1024` — hard cap; never exceed

### Implementation

- Cache size check in `add_entry`.
- Eviction: prefer FAILED entries first, then oldest STALE,
  then oldest by last_used.

### Effort

Small (~50 lines + tests) **once #11 lands**.

---

## §7 — Tier 3 #14: unicast cache-refresh probe

Currently `_subsystem_loop` calls
`stack.packet_handler.send_arp_request(arp__tpa=...)` which
sends a BROADCAST Request. Linux uses unicast for refresh
(RFC 1122 §2.3.2.1 IMPLEMENTATION (2)).

### Implementation

- New TX helper `_send_arp_unicast_probe(ip4_address, mac_address)`
  — sends Request with `ethernet__dst = mac_address` instead
  of broadcast.
- Refresh path in `_subsystem_loop` uses the unicast helper
  with the cached MAC.

### Effort

Small (~30 lines + tests). Standalone — doesn't require #11.

---

## §8 — Tier 3 #15: wall-clock → time.monotonic in cache aging

`arp__cache.py::_subsystem_loop` uses `int(time.time())`. NTP
jumps could mass-expire entries.

### Fix

Switch to `time.monotonic()`. `find_entry` and
`_maybe_send_arp_defense` are already monotonic (per the recent
refactor); only the loop's aging arithmetic is left.

### Effort

Tiny (~5 lines + 1 test). Standalone — doesn't require #11.

---

## §9 — Tier 3 #16: configurable cache timeout

Today the ARP cache timeouts (`ARP__CACHE__ENTRY_MAX_AGE`,
`ARP__CACHE__ENTRY_REFRESH_TIME`) are compile-time constants in
`pytcp/protocols/arp/arp__constants.py`.

### Possible approaches

1. **Sysctl-style mutable module attributes** — the constants
   become writable globals; tests already patch them this way.
   Lowest-friction.
2. **`stack.init(arp_cache_max_age=...)` kwarg** — surface the
   timeout in the stack-init API. Highest visibility for users.
3. **Per-interface configuration** — when multi-interface
   support lands (Phase 2).

### Effort

Small (~30 lines + tests).

---

## §10 — Tier 3 #17: Linux sysctl knobs

Default Linux exposes:
- `arp_accept` (0/1) — accept ARP for IPs not on local subnets
- `arp_announce` (0/1/2) — restrict source IP in outbound ARP
- `arp_ignore` (0..8) — controls when to reply to ARP requests
- `arp_filter` (0/1) — multi-interface ARP behaviour

PyTCP today encodes the conservative defaults (effectively
`arp_announce=1`, `arp_ignore=1`, `arp_filter=0`,
`arp_accept=0`) hardcoded in
`packet_handler__arp__rx.py::__update_arp_cache` and the
Request-handling logic.

### Effort

Each knob: small (~30 lines + tests). All four together: ~150
lines + comprehensive matrix tests. Mostly mechanical.

---

## §11 — Tier 4: Phase 2 deferred

These are explicitly out of scope per the project North Star.
**Do not implement** without revisiting the project Phase
classification.

- **RFC 1027 Proxy ARP** — router-grade. Audit at
  `docs/rfc/arp/rfc1027__proxy_arp/adherence.md`.
- **RFC 3927 IPv4 link-local autoconfiguration** — out of
  default Linux scope (only enabled via NetworkManager /
  `avahi-autoipd`). Audit at
  `docs/rfc/arp/rfc3927__ipv4_lla/adherence.md`.
- **§2.6.2 / §2.7 LLA forwarding gate** — silent risk only.
  Audit at `docs/rfc/arp/rfc3927__ipv4_lla/adherence.md`
  §2.6.2.

---

## §12 — Key file inventory

```
pytcp/protocols/arp/
├── arp__cache.py        # ArpCache subsystem; CacheEntry, _PendingResolution
└── arp__constants.py    # ARP__CACHE/DEFEND/REQUEST/PROBE/ANNOUNCE constants

pytcp/stack/packet_handler/
├── __init__.py                          # PacketHandlerL2._create_stack_ip4_addressing (DAD flow)
├── packet_handler__arp__rx.py           # __phrx_arp__request, __phrx_arp__reply, _maybe_send_arp_defense
└── packet_handler__arp__tx.py           # _phtx_arp + helpers (_send_arp_probe, _send_arp_announcement, etc.)

net_proto/protocols/arp/
├── arp__assembler.py
├── arp__base.py
├── arp__enums.py        # ArpHardwareType, ArpOperation
├── arp__errors.py       # ArpIntegrityError, ArpSanityError
├── arp__header.py       # ArpHeader dataclass
└── arp__parser.py

pytcp/tests/lib/arp_testcase.py          # ArpTestCase harness

pytcp/tests/integration/protocols/arp/
├── test__arp__dad.py                    # DAD-flow integration
├── test__arp__defend_interval.py        # Conflict-defense rate-limit
├── test__arp__harness_smoke.py          # ArpTestCase smoke tests
├── test__arp__resolution_flow.py        # Outbound IPv4 → ARP miss → Reply → flush
├── test__arp__rx.py                     # Migrated RX wire-format matrix
└── test__arp__tx.py                     # Migrated TX wire-format matrix

pytcp/tests/unit/protocols/arp/
├── test__arp__cache.py                  # ArpCache unit tests (rate-limit, queue, aging)
└── test__arp__constants.py              # Constants pinned to RFC values

pytcp/tests/unit/stack/packet_handler/
├── test__stack__packet_handler__arp__rx.py
└── test__stack__packet_handler__arp__tx.py

docs/rfc/arp/
├── rfc826__arp/                         # Foundational ARP audit
├── rfc1027__proxy_arp/                  # Phase 2 deferred
├── rfc1122__host_requirements_arp/      # §2.3.2 host requirements audit
├── rfc3927__ipv4_lla/                   # Phase 2 deferred
├── rfc5227__ipv4_acd/                   # Probe / announce / defend audit
└── rfc5494__arp_iana/                   # IANA registry audit
```

### Constants currently in `pytcp/protocols/arp/arp__constants.py`

| Constant | Value | RFC clause |
|---|---|---|
| `ARP__CACHE__ENTRY_MAX_AGE` | 3600 (s) | host-side aging |
| `ARP__CACHE__ENTRY_REFRESH_TIME` | 300 (s) | host-side refresh window |
| `ARP__DEFEND_INTERVAL` | 10 (s) | RFC 5227 §1.1 |
| `ARP__REQUEST_RATE_LIMIT` | 1 (s) | RFC 1122 §2.3.2.1 |
| `ARP__PROBE_WAIT` | 1 (s) | RFC 5227 §1.1 |
| `ARP__PROBE_NUM` | 3 | RFC 5227 §1.1 |
| `ARP__PROBE_MIN` | 1 (s) | RFC 5227 §1.1 |
| `ARP__PROBE_MAX` | 2 (s) | RFC 5227 §1.1 |
| `ARP__ANNOUNCE_WAIT` | 2 (s) | RFC 5227 §1.1 |
| `ARP__ANNOUNCE_NUM` | 2 | RFC 5227 §1.1 |
| `ARP__ANNOUNCE_INTERVAL` | 2 (s) | RFC 5227 §1.1 |

### `_create_stack_ip4_addressing` sleep order

The `ArpTestCase._dad_sleep_durations` list captures these in
order; tests reference them by index:

| Index | Constant | Purpose |
|---|---|---|
| 0 | PROBE_WAIT | Initial 0–1 s random delay (RFC §2.1.1) |
| 1–3 | PROBE_MIN..PROBE_MAX | Three inter-probe sleeps |
| 4 | ANNOUNCE_WAIT | Post-probe quiet period (RFC §2.1.1) |
| 5 | ANNOUNCE_INTERVAL | Between Announcement 1 and 2 (RFC §2.3) |

### `ArpTestCase._drive_dad` API

```python
def _drive_dad(
    self,
    *,
    on_sleep: Callable[[int], None] | None = None,
    num_sleep_callbacks: int = 3,
) -> None:
    """
    'on_sleep' fires with sleep index 0, 1, 2, ... up to
    'num_sleep_callbacks' total. Tests targeting post-probe
    sleeps (indexes 4, 5) pass higher counts.
    """
```

### Branch

`PyTCP_3_0__pre_release`

---

## §13 — Resume prompt

Paste this verbatim after `/compact` to resume the work in any
fresh session:

```
I'm resuming the PyTCP ARP→Linux-host parity work. Read
'docs/refactor/arp_linux_parity.md' first — it's the canonical
plan with §0 status snapshot, §1–§3 Tier 2 RFC 5227 finish items,
§4–§10 Tier 3 Linux-specific defaults, and §12 file/constants
inventory. Then read these in order before any code:

  1. CLAUDE.md (Project North Star, Phase 1 vs Phase 2 split)
  2. .claude/rules/feature_implementation.md (tests-first MUST,
     §7.2 audit before commit, commit discipline)
  3. .claude/rules/unit_tests.md (test authoring conventions,
     §7.2 audit script)
  4. .claude/rules/coding_style.md (source authoring)
  5. The current state of pytcp/protocols/arp/ + the
     packet_handler__arp__{rx,tx}.py files — these are the
     ARP runtime today.

After reading, confirm you understand:

  - Tier 1 (#1, #2, #3) shipped (commits cffd4841, 87851caa,
    628e724b). Tier 2 RFC 5227 items #5/#6/#7 also shipped
    (commits 3d7d276d, 01841e10, 5777c00a).
  - Tier 2 remaining: #8 simultaneous-probe detection (small),
    #9 abandon-after-second-conflict (substantial — needs
    TcpSession ABORT plumbing), #10 MAX_CONFLICTS (dormant in
    static-config model).
  - Tier 3 (NUD FSM + extensions) is the big architectural
    piece. The _PendingResolution table from #3 is the seed
    for NUD's INCOMPLETE state.
  - Tier 4 (RFC 1027 / RFC 3927) is deliberately deferred per
    the North Star.

Suggested resume order:

  1. #8 simultaneous-probe — small standalone commit closing
     the last RFC 5227 §2.1.1 detection gap.
  2. #15 wall-clock → monotonic in cache aging — tiny standalone.
  3. #14 unicast cache-refresh probe — small standalone.
  4. Then either:
     (a) #11 NUD state machine — 1–2 weeks of architectural
         work; absorbs #12, #13, and lays foundation for ND.
     (b) Keep picking off small standalone items from Tier 3
         until ready to commit to the bigger refactor.

Defer #9 abandon-after-second-conflict UNTIL the NUD work
starts — its FAILED state is the natural home for the abandon
path.

Branch: PyTCP_3_0__pre_release.

Before any code, run 'git log --oneline -20' to confirm the
session-end state matches the §0 snapshot in this document.
Tests-first per CLAUDE.md MUST. Run 'make lint && make test'
before each commit; the §7.2 audit on docstrings is a blocker,
not a polish item.

Do NOT push without explicit user request. Commit after each
item; user pushes when ready. Then ask the user which item to
start with (default to #8 if they say "go" or "next").
```
