# PyTCP NUD state machine — design + per-phase plan

This document captures the design and the per-phase
migration plan for PyTCP's Neighbour Unreachability Detection
(NUD) state machine — the FSM that replaces the current
binary present/absent ARP and ND cache models with the
INCOMPLETE / REACHABLE / STALE / DELAY / PROBE / FAILED
states Linux's `net/core/neighbour.c` implements.

The FSM is generic over address type from day one. Both the
IPv4 ARP cache (`pytcp/protocols/arp/arp__cache.py`) and the
IPv6 ND cache (currently at `pytcp/stack/nd_cache.py`,
unrelocated) become thin adapters over a single
`NeighborCache[A]` at `pytcp/lib/neighbor.py` — matching
Linux's factoring and avoiding the duplication that would
result from putting the FSM under either protocol's package.

This document mirrors the shape of `sysctl_framework.md`:
motivation, design, per-phase migration plan, anti-patterns,
resume prompt. The line items #11 (NUD FSM), #12
(reachability hook), #13 (bounded GC) and #9
(abandon-after-conflict) from the ARP punch list at
`docs/refactor/arp_linux_parity.md` all converge here — #11
is the architectural piece that absorbs #12 and #13 and
unlocks #9's FAILED-state plumbing.

---

## §0 Why

Linux's neighbour cache is the canonical model. Every
mainstream Unix descended from BSD has eventually moved its
ARP cache toward the same six-state FSM (with minor
naming variations) because the binary present/absent model
fails three operational requirements:

1. **Failure detection.** Without a FAILED state, a host
   that loses link-layer connectivity to a peer never
   notices — the cache entry just ages out at MAX_AGE.
   Upper-layer retransmits absorb the latency cost
   instead.
2. **Refresh without traffic disruption.** Without
   STALE / DELAY / PROBE, an entry approaching expiry
   either gets refreshed proactively (wastes link
   bandwidth on idle entries) or expires mid-flight
   (causes a cache-miss stall on active flows). The
   four-state refresh path Linux uses lets entries
   silently transition through STALE while the host has
   no traffic for them, then refresh ON DEMAND when a
   new TX arrives.
3. **Upper-layer feedback.** TCP's in-window ACKs are
   strong evidence the neighbour is reachable — much
   stronger than a probe Reply. Without a hook, this
   evidence is wasted; the cache fires a probe anyway.
   Linux exposes `NEIGH_UPDATE_F_USE` for this.

PyTCP's `_PendingResolution` table (commit `628e724b`) is
already a degenerate INCOMPLETE state; the existing
`CacheEntry` is a degenerate REACHABLE; the unicast
cache-refresh probe (commit `30aaa98a`) is half of the
PROBE state. The work is making these explicit, generalising
the data structure, and adding STALE / DELAY / FAILED.

---

## §1 The state machine

The six states + their transitions, drawn from RFC 4861
§7.3.2 (originally specified for IPv6 ND but adopted
verbatim by Linux for ARP too):

```
                         find_entry on miss
        NUD_NONE  ──────────────────────────►  NUD_INCOMPLETE
                                                    │
                          ARP / NS Reply received   │
            ┌───────────────────────────────────────┘
            │             after PROBE_NUM unicast probes, no Reply
            ▼                                       ▼
       NUD_REACHABLE                            NUD_FAILED
            │                                       ▲
            │ REACHABLE_TIME elapsed                │
            ▼                                       │
        NUD_STALE                                   │
            │                                       │
            │ TX uses entry                         │
            ▼                                       │
        NUD_DELAY                                   │
            │                                       │
            │ DELAY_FIRST_PROBE_TIME elapsed,       │
            │ no upper-layer reachability confirm   │
            ▼                                       │
        NUD_PROBE                                   │
            │                                       │
            │ probe Reply         no Reply after    │
            ▼                       MAX_UNICAST_SOLICIT
       NUD_REACHABLE  ◄──────────────────────────────┘
```

Confirmation hook (#12) provides a side-door directly to
`NUD_REACHABLE` from any of `STALE / DELAY / PROBE` — the
TCP layer calls it on in-window ACK so we skip the unicast
probe entirely.

State-by-state semantics:

| State | Meaning | Reads | Writes (state) | Wire output |
|---|---|---|---|---|
| `NUD_NONE` | absent | n/a | (created on TX miss) | n/a |
| `NUD_INCOMPLETE` | resolving | enqueue packet, hold | INCOMPLETE → REACHABLE on Reply; → FAILED after PROBE_NUM | broadcast Request (ARP) / multicast NS (ND) |
| `NUD_REACHABLE` | confirmed reachable | return MAC immediately | → STALE after REACHABLE_TIME; (#12) confirmation re-arms timer | none |
| `NUD_STALE` | aging | return MAC; transition to DELAY on first TX | STALE → DELAY on TX; → REACHABLE on (#12) confirm; → REACHABLE on solicited Reply | none |
| `NUD_DELAY` | grace period before probe | return MAC | DELAY → PROBE after DELAY_FIRST_PROBE_TIME; → REACHABLE on (#12) confirm | none |
| `NUD_PROBE` | actively probing | return MAC | PROBE → REACHABLE on Reply; → FAILED after MAX_UNICAST_SOLICIT | unicast Request (ARP) / unicast NS (ND) |
| `NUD_FAILED` | abandoned | return None | (eviction-eligible) | none |

`NUD_PERMANENT` is a 7th state (effectively REACHABLE that
never ages out) for static entries — PyTCP already supports
this via `CacheEntry.permanent`; it carries forward.

---

## §2 `NeighborEntry` dataclass

Replaces the existing `CacheEntry` with state + timing
fields:

```python
@dataclass(slots=True)
class NeighborEntry[A: Ip4Address | Ip6Address]:
    address: A
    mac_address: MacAddress | None      # None while INCOMPLETE
    state: NudState
    state_changed_at: float              # time.monotonic at last transition
    probe_count: int                     # PROBE-state retry counter
    permanent: bool = False
    queued_packet: EthernetAssembler | None = None  # INCOMPLETE only
    last_used_at: float = 0.0            # for LRU eviction (#13)
```

`NudState` is a `ProtoEnumByte` (per the codebase enum
convention) with the six members + `PERMANENT`.

The `slots=True` + non-frozen dataclass deliberately differs
from the protocol-header pattern (which uses
`frozen=True, kw_only=True, slots=True`). Neighbour entries
mutate frequently — frozen would force `object.__setattr__`
on every transition. `slots=True` keeps memory bounded;
non-frozen makes transitions readable.

---

## §3 Generic `NeighborCache[A]` at `pytcp/lib/neighbor.py`

```python
class NeighborCache[A: Ip4Address | Ip6Address](Subsystem):
    _entries: dict[A, NeighborEntry[A]]
    _solicit_callback: Callable[[A, MacAddress | None], None]
    # MacAddress arg is None for INCOMPLETE (broadcast/multicast),
    # set to the cached MAC for PROBE (unicast).

    def find_entry(self, address: A) -> MacAddress | None: ...
    def add_entry(self, address: A, mac_address: MacAddress) -> None: ...
    def confirm_reachability(self, address: A) -> None: ...   # #12
    def enqueue_pending(self, address: A, packet: EthernetAssembler) -> None: ...
    @override
    def _subsystem_loop(self) -> None: ...
    # Garbage collection (#13)
    def _gc_pass(self) -> None: ...
```

The `_solicit_callback` is the protocol-specific TX
hook. ARP supplies `lambda addr, mac: stack.packet_handler.
send_arp_request(arp__tpa=addr) if mac is None else
send_arp_unicast_request(arp__tpa=addr, ethernet__dst=mac)`.
ND supplies the equivalent ICMPv6 NS solicit.

The cache is generic over address type via PEP 695 syntax
(`class NeighborCache[A: Ip4Address | Ip6Address]`). Both
adapters (ArpCache, NdCache) inherit and supply the
type-specific bits via constructor kwargs.

`_subsystem_loop` runs the timer-driven transitions:

- `REACHABLE → STALE` after `REACHABLE_TIME` elapsed.
- `DELAY → PROBE` after `DELAY_FIRST_PROBE_TIME`, fires
  unicast solicit.
- `PROBE` retries every `RETRANS_TIMER` until probe_count
  reaches `MAX_UNICAST_SOLICIT`, then `→ FAILED`.
- `FAILED` entries become eviction candidates (#13's GC
  prefers them).
- `INCOMPLETE` retries every `RETRANS_TIMER` until
  probe_count reaches `MAX_MULTICAST_SOLICIT`, then `→ FAILED`.

---

## §4 ArpCache adapter

`pytcp/protocols/arp/arp__cache.py` becomes:

```python
class ArpCache(NeighborCache[Ip4Address]):
    @override
    def __init__(self) -> None:
        super().__init__(
            solicit_callback=self._solicit_arp,
        )

    def _solicit_arp(
        self,
        address: Ip4Address,
        cached_mac: MacAddress | None,
    ) -> None:
        if cached_mac is None:
            stack.packet_handler.send_arp_request(arp__tpa=address)
        else:
            stack.packet_handler.send_arp_unicast_request(
                arp__tpa=address,
                ethernet__dst=cached_mac,
            )
```

Existing public surface (`add_entry`, `find_entry`,
`enqueue_pending`) is inherited from `NeighborCache`; the
ArpCache subclass just supplies the IPv4-specific solicit
hook. The unicast cache-refresh probe behaviour (#14,
shipped in commit `30aaa98a`) is preserved as the
`PROBE`-state solicit path; the broadcast Request is
preserved as the `INCOMPLETE`-state solicit path.

---

## §5 NdCache adapter

`pytcp/stack/nd_cache.py` migrates to
`pytcp/protocols/icmp6/nd__cache.py` (matching the ARP
relocation done in commit `e29e6b1e`) and becomes:

```python
class NdCache(NeighborCache[Ip6Address]):
    @override
    def __init__(self) -> None:
        super().__init__(
            solicit_callback=self._solicit_ns,
        )

    def _solicit_ns(
        self,
        address: Ip6Address,
        cached_mac: MacAddress | None,
    ) -> None:
        # Unicast NS for PROBE (cached_mac known); multicast NS
        # for INCOMPLETE (cached_mac None — solicited-node
        # multicast group as dst).
        ...
```

The migration also relocates the existing ND constants
(currently at `pytcp/stack/__init__.py:103-107`) to a
sibling `pytcp/protocols/icmp6/icmp6__nd__constants.py`
following the per-protocol layout convention.

---

## §6 Reachability confirmation hook (#12)

Public method on `NeighborCache`:

```python
def confirm_reachability(self, address: A) -> None:
    """
    Side-door from STALE / DELAY / PROBE → REACHABLE on
    upper-layer evidence (in-window TCP ACK). Skips the
    unicast probe.
    """
    entry = self._entries.get(address)
    if entry is None or entry.state == NudState.INCOMPLETE:
        return  # nothing to confirm
    entry.state = NudState.REACHABLE
    entry.state_changed_at = time.monotonic()
    entry.probe_count = 0
```

TCP integration: `pytcp/protocols/tcp/tcp__session.py` calls
the hook from the in-window-ACK code path. The address is
the peer's IPv4 or IPv6 — routes to ArpCache or NdCache by
type dispatch (or by separate hooks). Effort: ~20 lines +
tests once `NeighborCache.confirm_reachability` exists.

---

## §7 Bounded cache + GC (#13)

Three Linux-style thresholds, registered as sysctls per the
framework:

| Sysctl key | Default | Meaning |
|---|---|---|
| `neighbor.gc_thresh1` | 128 | Below this size, never GC. |
| `neighbor.gc_thresh2` | 512 | Above this, GC after stale_time. |
| `neighbor.gc_thresh3` | 1024 | Hard cap; eviction MUST run. |

GC pass priority order (within `_gc_pass`):

1. `FAILED` entries (oldest first).
2. `STALE` entries past `gc_stale_time`.
3. `REACHABLE` entries by `last_used_at` (LRU).

Permanent entries are never evicted. Entries with
`queued_packet` (INCOMPLETE with held packet) are skipped to
avoid losing the queued TX.

---

## §8 Abandon-after-second-conflict (#9)

RFC 5227 §2.4(b) MUST: on the SECOND conflict within
DEFEND_INTERVAL, the host MUST abandon the address. The
"abandon" path needs a place to live; the natural home is
the `FAILED` state of the address-owning interface's
NeighborEntry — but actually, address-defense is a
PacketHandler concern, not a NeighborCache concern. The link
to NUD is procedural rather than structural:

- The PacketHandler tracks `_arp_defend__last_conflict_at:
  dict[Ip4Address, float]` (separate from
  `_arp_defend__last_emitted` from #2).
- On the second conflict within DEFEND_INTERVAL, the
  abandon path:
  1. ABORTs every TcpSession bound to the address (RFC 5227
     §2.4-final SHOULD — "actively attempt to reset any
     existing connections"). This is the substantial bit
     that gates #9 on having NUD's FAILED concept available
     as the "this address is dead" semantic.
  2. Removes the address from `self._ip4_host`.
  3. Logs an operator-visible warning.

The TcpSession ABORT plumbing benefits from the FAILED
state because it provides a clean termination semantic for
sessions whose neighbour cache entry is unreachable — the
session's RTO path can check NUD state and short-circuit
retries on FAILED.

---

## §9 Sysctl integration for NUD timing constants

Per the framework at `docs/refactor/sysctl_framework.md`,
NUD timing constants are policy knobs, not invariants. They
register at module load time on `pytcp/lib/neighbor.py`'s
sibling `neighbor__constants.py`:

| Sysctl key | Default | Linux equivalent |
|---|---|---|
| `neighbor.reachable_time` | 30 (seconds) | `net.ipv4.neigh.default.base_reachable_time` (Linux uses ms) |
| `neighbor.delay_first_probe_time` | 5 | `net.ipv4.neigh.default.delay_first_probe_time` |
| `neighbor.retrans_timer` | 1 | `net.ipv4.neigh.default.retrans_timer_ms` (Linux ms) |
| `neighbor.max_unicast_solicit` | 3 | `net.ipv4.neigh.default.ucast_solicit` |
| `neighbor.max_multicast_solicit` | 3 | `net.ipv4.neigh.default.mcast_solicit` |
| `neighbor.gc_thresh1` | 128 | `net.ipv4.neigh.default.gc_thresh1` |
| `neighbor.gc_thresh2` | 512 | `net.ipv4.neigh.default.gc_thresh2` |
| `neighbor.gc_thresh3` | 1024 | `net.ipv4.neigh.default.gc_thresh3` |

PyTCP uses **seconds** rather than Linux's ms for all
timing keys — consistent with the existing ARP timing
sysctls (`arp.cache.max_age` is seconds, etc.). Operators
multiply Linux defaults by 1000 in their head.

These are GENERIC NUD constants (they apply to both ARP and
ND). Per-family overrides
(`arp.nud.reachable_time` / `nd.nud.reachable_time`) can be
added later when there is a real consumer asking for the
per-family namespace; defer until then.

`neighbor.reachable_time` becomes the new `MAX_AGE` —
`arp.cache.max_age` and the equivalent ND sysctl get
deprecated and aliased onto `neighbor.reachable_time` during
the migration.

---

## §10 Migration phases

Per-phase, each landing as one or more focused commits.
Phases are mechanically reversible: each ends in a green
test suite, lint clean, and shippable state.

### Phase 1 — `NeighborCache[A]` module + unit tests ✅ shipped (this commit)

`pytcp/lib/neighbor.py` plus unit tests at
`pytcp/tests/unit/lib/test__lib__neighbor.py`. The cache is
fully functional but no protocol consumes it yet — ArpCache
and NdCache continue to use their existing implementations.

Tests-first matrix:
- `INCOMPLETE` state: enqueue + multicast solicit + Reply
  → REACHABLE.
- `REACHABLE → STALE` after `REACHABLE_TIME`.
- `STALE → DELAY` on first TX.
- `DELAY → PROBE` after `DELAY_FIRST_PROBE_TIME`, unicast
  solicit fires.
- `PROBE → REACHABLE` on Reply; `→ FAILED` after
  `MAX_UNICAST_SOLICIT`.
- `confirm_reachability` skips probe path
  (STALE/DELAY/PROBE → REACHABLE).
- Permanent entries skip every transition.

Sysctl registrations land in this commit too —
`neighbor.reachable_time` etc. are registered with the
framework before any consumer exists.

### Phase 2 — ArpCache adapter ✅ shipped (this commit)

Refactor `ArpCache` to inherit from `NeighborCache[Ip4Address]`.
The existing ArpCache tests get updated to expect NUD-state
semantics; the existing
`test__arp_cache__loop_refreshes_near_expiry_used_entry`
becomes a `STALE → DELAY → PROBE` walk.

The `arp.cache.max_age` and `arp.cache.refresh_time` sysctls
become deprecated aliases for `neighbor.reachable_time` and
the analogous `gc_stale_time`; existing call sites continue
to work.

### Phase 3 — NdCache adapter + ND cache relocation

Relocate `pytcp/stack/nd_cache.py` →
`pytcp/protocols/icmp6/nd__cache.py` (matching commit
`e29e6b1e`'s ARP relocation). Refactor as
`NdCache(NeighborCache[Ip6Address])`. ND constants migrate
out of `pytcp/stack/__init__.py` to a sibling
`icmp6__nd__constants.py`.

### Phase 4 — Reachability confirmation hook (#12)

`NeighborCache.confirm_reachability` is already in Phase 1.
This phase wires the TCP integration: in
`tcp__session.py`'s ACK processor, on an in-window ACK,
call the hook for the peer's IPv4 / IPv6 address. Effort
~20 lines + tests.

### Phase 5 — Bounded cache + GC (#13)

`_gc_pass` implementation, three sysctl gc_thresh entries,
eviction priority order. Effort ~50 lines + tests.

### Phase 6 — Abandon-after-second-conflict (#9)

RFC 5227 §2.4(b) MUST plumbing on PacketHandler. TcpSession
ABORT path. The most operator-visible change — produces a
warning-level log on abandon. Effort ~100 lines + tests.

---

## §11 Anti-patterns

- **Skipping the generic step.** "Just put NUD under
  `pytcp/protocols/arp/`" is what the original §4 of
  `arp_linux_parity.md` proposed; we rejected it because
  ND adoption later forces either duplication or a
  refactor. The Phase 1 generic module is load-bearing.
- **Mixing wire concerns into `NeighborCache`.** The cache
  knows nothing about ARP wire format or ICMPv6 ND wire
  format — those live in the per-protocol packages. The
  cache only knows "solicit this address; here's a hint
  if I have a cached MAC." Adapters supply the wire.
- **Reaching across protocol boundaries from
  `confirm_reachability`.** TCP calls the hook; the cache
  doesn't reach into TCP. Direction is one-way upper-layer
  → cache.
- **Coupling FAILED-state semantics to per-protocol
  abandon paths.** FAILED is a generic "neighbour
  unreachable" signal; what an upper-layer DOES with that
  signal (RFC 5227 §2.4(b) abandon, ICMP no-route,
  PMTU-discovery probe failure) is the upper layer's
  responsibility.
- **Using wall-clock time anywhere in the FSM.** Every
  timer comparison uses `time.monotonic()`; we already
  hit this with #15 in commit `1a46f28f`. Don't regress.
- **Sysctl per-family before per-default.** `neighbor.*`
  is the generic namespace; `arp.nud.*` /
  `nd.nud.*` per-family overrides come later if and only
  if a real consumer needs to differentiate. Don't
  pre-emptively bifurcate.

---

## §12 Resume prompt

```
I'm continuing the PyTCP NUD state machine refactor. Read
'docs/refactor/nud_state_machine.md' first — it's the
canonical design + per-phase plan. Then read these in order
before any code:

  1. CLAUDE.md (Project North Star)
  2. .claude/rules/feature_implementation.md (tests-first MUST)
  3. .claude/rules/unit_tests.md (test conventions)
  4. .claude/rules/coding_style.md (source authoring;
     §6.1 sysctl pattern applies to NUD timing constants)
  5. .claude/skills/sysctl_knob/SKILL.md (NUD timing
     constants register through this workflow)
  6. The current state of pytcp/lib/neighbor.py if it
     exists, plus pytcp/protocols/arp/arp__cache.py and
     pytcp/stack/nd_cache.py.

After reading, confirm:

  - Phase 1 (NeighborCache[A] module + unit tests):
    {shipped|pending — at commit X}.
  - Phase 2 (ArpCache adapter): {shipped|pending}.
  - Phase 3 (NdCache adapter + relocation): {shipped|pending}.
  - Phase 4 (reachability hook from TCP): {shipped|pending}.
  - Phase 5 (bounded cache + GC): {shipped|pending}.
  - Phase 6 (#9 abandon-after-conflict): {shipped|pending}.

Tests-first per CLAUDE.md MUST. §7.2 audit before commit.
Branch: PyTCP_3_0__pre_release. No push without ask.

Suggested per-session split: one phase per session given
context budget. Phase 1 alone is 80–120k tokens of work
(FSM design + module + tests + commit). Plan to stop at
the end of each phase, write a status update at §0 of this
doc, and resume fresh in the next session.
```

---

## §13 Cross-references

- ARP punch list: `docs/refactor/arp_linux_parity.md` §4
  (one-paragraph pointer to this doc; full plan removed).
- Sysctl framework:
  `docs/refactor/sysctl_framework.md` §1 classification +
  §8 per-package migration order — NUD timing constants
  follow Phase 3 of that plan (per-package sweep) and
  register in `neighbor__constants.py`.
- Per-RFC adherence: RFC 4861 §7.3.2 (the FSM spec); RFC
  1122 §2.3.2.1 (the ARP-side host requirements);
  RFC 5227 §2.4(b) (the abandon-after-conflict MUST that
  Phase 6 closes).
- Linux source: `net/core/neighbour.c` (the FSM
  implementation); `net/ipv4/arp.c` (ARP-specific solicit
  hooks); `net/ipv6/ndisc.c` (ND-specific solicit hooks).
