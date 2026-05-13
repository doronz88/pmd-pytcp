# Link API — Phase-3 Link-Control Surface Plan

| Field             | Value                                                                                                                                                                                                                                                  |
|-------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Status            | **Shipped** 2026-05-12 — Phases 0-5 complete; commits 41f7fd58 (decisions), cdc11324 (Phase 0), 3ceb4432 (Phase 1), efa64c8c (Phase 2), 5bb2cf2f (Phase 3), d4aed533 (Phase 4) on PyTCP_3_0__pre_release                                                |
| Plan author       | RFC 3927 follow-up (2026-05-12)                                                                                                                                                                                                                        |
| Source motivation | RFC 3927 Phase 5 closure raised the question: should `stack/__init__.py`'s `packet_handler._mac_unicast` read be promoted to a public surface? Per CLAUDE.md the Link API is the canonical Phase-3 home for that read (and friends).                   |
| Target branch     | `PyTCP_3_0__pre_release`                                                                                                                                                                                                                               |
| Touch points      | new `pytcp/lib/link_api.py`, `pytcp/stack/__init__.py` (slot + wiring), `pytcp/stack/packet_handler/__init__.py` (back-end methods if mutation lands), `pytcp/lib/packet_stats.py` (`LinkStatsCounters` dataclass — Phase 3), test harness snapshot     |
| Linux analogue    | `ip link show` / `ip link set` / RTNETLINK `RTM_NEWLINK` / `RTM_GETLINK` / `RTM_SETLINK`                                                                                                                                                               |

This document is the implementation plan for shipping the
**Phase-3 Link API** — one of the seven sanctioned consumer
surfaces from CLAUDE.md's Project North Star:

| PyTCP API | Plane | Linux equivalent |
|-----------|-------|------------------|
| Link API (interface up/down/MTU/MAC) | Link control | `ip link` / RTNETLINK `RTM_NEWLINK` |

The track is structurally similar to the existing
`Ip4AddressApi` work: a new `pytcp/lib/link_api.py` exposing
read + (eventually) write surfaces; backed by `PacketHandler`
state today; future Phase-3 swap replaces the internals with a
real IPC channel without touching consumers.

---

## 1. Goal

Ship a sanctioned `pytcp.stack.link` consumer surface that
covers the canonical Linux `ip link` properties — MAC, MTU,
interface layer, name, running state, flags, basic stats —
plus a minimal Phase-1 mutation surface (set_mtu, up/down)
where consumer demand justifies it.

After this track lands, consumers (DHCP, link-local, future
operator CLI, future introspection tools) read link state via
`stack.link.*` and never reach `packet_handler.*` for
interface-level facts. The Phase-3 line that the Address API
drew for the address plane is mirrored on the link plane.

---

## 2. Current state — what exists today

### Read sites scattered across the codebase

| Property                    | Today's home                                                | Read by                                                       |
|-----------------------------|-------------------------------------------------------------|---------------------------------------------------------------|
| MAC address                 | `packet_handler._mac_unicast`                                | DHCP / link-local construction (in `stack.init`)              |
| MTU                         | `packet_handler._interface_mtu` + `stack.interface_mtu`     | TX path (fragmentation), MSS calc, ICMP PMTUD                  |
| Interface layer (L2 vs L3)  | `packet_handler._interface_layer`                            | Ethernet TX path, every protocol that needs L2 decision        |
| Interface name              | Function-arg in `initialize_interface__tap()`; not stored   | One-off at boot                                                |
| Running state               | `stack.stack_initialized` + per-Subsystem `_event__stop_subsystem` | `stack.stop()` reads; otherwise implicit                |
| Flags (BROADCAST etc.)      | Implicit in `interface_layer` (L2 = broadcast/multicast)    | Nowhere — implicit                                             |
| rx/tx stats                 | `packet_handler.packet_stats_rx` / `.packet_stats_tx`        | Tests; no public API                                          |

### Existing Phase-3 surfaces (precedent)

- `pytcp/lib/address_api.py::Ip4AddressApi` — read + write
  for the address plane. Mirror this structurally.
- `pytcp/lib/sysctl.py` — sysctl registry.
- `pytcp.socket` — BSD socket factory.

### Linux `ip link show` reference

```
$ ip link show eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP \
       mode DEFAULT group default qlen 1000
    link/ether 02:00:00:00:00:07 brd ff:ff:ff:ff:ff:ff
    RX:  bytes packets errors dropped overrun mcast
        12345  100     0      0       0       0
    TX:  bytes packets errors dropped carrier collsns
        67890  150     0      0       0       0
```

Maps cleanly onto the property table in §3 below.

---

## 3. Phased plan

The track ships as **six commits** totalling ~1-2 days. Each
phase is independently testable; Phase 0 is the minimum
viable API and can ship out of order from the rest.

### Phase 0 — Minimum read-only surface (1 commit; ~30 min)

The MAC + MTU + interface-layer trio. Closes the immediate
`packet_handler._mac_unicast` reach-through and establishes
the namespace.

**Properties:**

```python
class LinkApi:
    """
    Phase-1 link-layer control surface — Linux 'ip link' /
    RTNETLINK 'RTM_NEWLINK' equivalent. Read-only at start;
    mutation lands in Phase 4 when a consumer materialises.
    """

    @property
    def mac_address(self) -> MacAddress | None:
        """L2 MAC; None in L3/TUN mode (no Ethernet)."""

    @property
    def mtu(self) -> int:
        """Interface MTU in bytes."""

    @property
    def interface_layer(self) -> InterfaceLayer:
        """L2 (TAP) or L3 (TUN)."""
```

**Wire-up:**

- New file `pytcp/lib/link_api.py` (~60 lines).
- `pytcp/stack/__init__.py` grows `link: LinkApi` module-
  level slot; constructed in `init` / `mock__init` after
  `packet_handler` is built.
- DHCP construction (in `stack.init`) reads `stack.link.mac_address`
  instead of `packet_handler._mac_unicast`.
- Link-local construction (in `stack.init`) likewise.
- Test harness `_STACK__PATCHED_ATTRS` adds `link`.

**Tests-first:**

- `pytcp/tests/unit/lib/test__lib__link_api.py`:
  - `mac_address` returns the bound packet handler's MAC.
  - `mac_address` returns None when bound to an L3 handler
    (no `_mac_unicast`).
  - `mtu` returns the bound handler's MTU.
  - `interface_layer` returns L2 or L3 as appropriate.

**Adherence refresh:** none yet — the Link API isn't tied to
a specific RFC. Add a cross-reference in the IPv4 audit
punch-list to note the new namespace.

### Phase 1 — Interface name (1 commit; ~30 min)

Linux `ip link show` always shows the device name (eth0,
tap7). PyTCP knows the name at boot
(`initialize_interface__tap("tap7")`) but throws it away.

**Implementation:**

- `initialize_interface__tap/tun()` returns the name in the
  result dict (or stash it on a module global).
- `stack.init()` records the name on the packet_handler (new
  attribute `_interface_name: str | None = None`).
- `LinkApi.name` property reads it.

**Tests-first:**

- `LinkApi.name` returns the bound interface's name (e.g.
  "tap7").
- `LinkApi.name` is None when no name was recorded (mock harness).

### Phase 2 — Running state + flags (1 commit; ~45 min)

Mirrors Linux's `IFF_UP` / `IFF_RUNNING` / `BROADCAST` /
`MULTICAST` / `LOOPBACK` flags.

**Properties:**

```python
@property
def is_running(self) -> bool:
    """True when stack.start() has run and stack.stop() has not.
    Linux IFF_UP + IFF_RUNNING equivalent."""

@property
def flags(self) -> frozenset[LinkFlag]:
    """Set of LinkFlag enum values: BROADCAST, MULTICAST,
    LOOPBACK, POINTOPOINT. Derived from interface_layer."""
```

New `LinkFlag` enum in `pytcp/lib/link_api.py`. Values
mirror Linux's `IFF_*` selection.

**Implementation:**

- `is_running` checks `stack.stack_initialized` AND any
  subsystem-stop event state.
- `flags` derives from `interface_layer` (L2 → BROADCAST,
  MULTICAST; L3 → POINTOPOINT).

**Tests-first:**

- `is_running` is False before `stack.start()`; True after;
  False after `stack.stop()`.
- `flags` for L2 includes BROADCAST + MULTICAST.
- `flags` for L3 includes POINTOPOINT.

### Phase 3 — Stats introspection (1 commit; ~1.5 hours)

Mirrors Linux's `RX/TX bytes packets errors dropped` block
in `ip -s link show`.

**Properties + new dataclasses:**

```python
# pytcp/lib/link_api.py
@dataclass(frozen=True, kw_only=True, slots=True)
class LinkStats:
    rx_bytes: int
    rx_packets: int
    rx_errors: int
    rx_dropped: int
    rx_multicast: int
    tx_bytes: int
    tx_packets: int
    tx_errors: int
    tx_dropped: int
    tx_multicast: int

@property
def stats(self) -> LinkStats:
    """Copy-by-value snapshot of cumulative interface stats.
    Linux equivalent: 'ip -s link show' RX/TX block. See
    docstring body for the bucket → PyTCP counter mapping
    (e.g. rx_errors = sum of *__integrity_error__drop +
    *__failed_parse__drop)."""

# pytcp/lib/packet_stats.py (new sibling dataclass)
@dataclass(slots=True)
class LinkStatsCounters:
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_multicast: int = 0
    tx_multicast: int = 0
```

**Implementation (per §6.4):**

- Add `LinkStatsCounters` to `pytcp/lib/packet_stats.py`.
- Add `_link_stats: LinkStatsCounters` slot to
  `PacketHandler`. Existing `_packet_stats_rx` /
  `_packet_stats_tx` are untouched.
- Increment `_link_stats.rx_bytes` at `_phrx_ethernet` start;
  `_link_stats.tx_bytes` at `_send_out_packet`; multicast in
  the multicast-receive / multicast-egress paths.
- `LinkApi.stats` aggregates two sources:
  - `rx_packets` / `rx_errors` / `rx_dropped` / `tx_*`
    counters: sum existing `_packet_stats_rx` /
    `_packet_stats_tx` fields per the documented bucket
    mapping.
  - `rx_bytes` / `tx_bytes` / `rx_multicast` /
    `tx_multicast`: read directly from `_link_stats`.
- Returns a fresh `LinkStats` (frozen, slotted) per call —
  copy-by-value per Phase-3 "introspection is read-only".
- Extend `_STACK__PATCHED_ATTRS` (or whichever harness slot
  manages packet-handler state) to snapshot/restore
  `_link_stats` per test.

**Bucket → counter mapping** (documented verbatim in
`LinkStats` docstring so future drops know their home):

- `rx_packets` ← `ethernet__pre_parse` (L2) or
  `ip4__pre_parse + ip6__pre_parse` (L3)
- `tx_packets` ← `ethernet__tx` (L2) or
  `ip4__tx + ip6__tx` (L3)
- `rx_errors` ← sum of all `*__integrity_error__drop` +
  `*__failed_parse__drop`
- `tx_errors` ← TX-path structural failures
- `rx_dropped` ← sum of `*__sanity_error__drop` +
  `*__no_proto_support__drop` + `*__no_socket_match__drop`
  + `*__not_for_us__drop` + `icmp*__rate_limited__drop`
- `tx_dropped` ← `ip4__allow_broadcast__drop` +
  `ip6__src_scope_mismatch__drop` +
  `ip4__link_local_scope_mismatch__drop`

**Tests-first:**

- Empty fixture → `LinkStats` all zeros.
- Populated `_packet_stats_rx.ethernet__pre_parse=5` →
  `rx_packets == 5`.
- Populated `_link_stats.rx_bytes=1500` → `rx_bytes == 1500`.
- `_packet_stats_rx.ip4__integrity_error__drop=2` +
  `_packet_stats_rx.tcp__integrity_error__drop=3` →
  `rx_errors == 5`.
- The returned `LinkStats` is frozen / slotted (mutation
  raises `FrozenInstanceError`).

**Integration test impact:** zero. Existing `exact=True`
assertions on `packet_stats_*` are untouched because no
fields were added to those dataclasses.

### Phase 4 — Mutation: set_mtu + set_mac_address (1 commit; ~2.5 hours)

The minimal mutation surface that has plausible consumers.
`up()` / `down()` are NOT in this phase (deferred per §6.3
to the Phase-2 multi-interface track).

**Methods:**

```python
def set_mtu(self, *, mtu: int) -> None:
    """Set the interface MTU. Linux 'ip link set mtu N'.
    Propagates to packet_handler._interface_mtu and
    interface_mtu module global. Rejects values < 68 (RFC
    791 §3.2) or > 65535. NOTE: values below 1280 break
    IPv6 (RFC 8200 §5); the docstring warns the operator."""

def set_mac_address(self, *, mac_address: MacAddress) -> None:
    """Set the interface MAC. Linux 'ip link set address'.
    Requires the stack stopped first (stack.start() not run
    yet, or stack.stop() already run); raises otherwise.
    Validates the MAC (not multicast, not zero). Updates
    packet_handler._mac_unicast. Schedules gratuitous
    announce for every owned host (RFC 5227 §3 / RFC 4861
    §7.2.6) at the next stack.start()."""
```

**Implementation:**

- `set_mtu` writes through to `packet_handler._interface_mtu`,
  `stack.interface_mtu`, and the TxRing's MTU if it has
  one. Validates against RFC 791 §3.2 minimum (68 octets).
- `set_mac_address`:
  1. Reject if `stack.stack_initialized` is True (linux-faithful
     "down first").
  2. Validate MAC (not multicast bit; not zero).
  3. Update `packet_handler._mac_unicast`.
  4. Mark every `_ip4_host` and `_ip6_host` for re-announce
     at next start.

**Tests-first:**

- `set_mtu(1400)` updates `packet_handler._interface_mtu`
  and `stack.interface_mtu`.
- `set_mtu(67)` rejects (below RFC 791 §3.2 minimum).
- `set_mtu(70000)` rejects (above uint16).
- `set_mac_address` with stack running rejects with a clear
  error message.
- `set_mac_address` with stack stopped updates the MAC and
  schedules re-announce.
- `set_mac_address` validation: multicast bit rejection;
  zero-MAC rejection.
- Integration test: after `set_mac_address` + `stack.start()`,
  the wire shows gratuitous ARP for every owned IPv4 host
  and unsolicited NA for every owned IPv6 host.

### Phase 5 — Adherence refresh + docs (1 commit; ~30 min)

- Update `docs/refactor/ip4_audit_punchlist.md` to
  cross-reference the new Link API.
- Update CLAUDE.md's north-star table to mark Link API as
  shipped (currently listed as a future surface).
- Add a small RFC-adherence-style record at
  `docs/api/link_api.md` documenting the surface (no specific
  RFC; this is operator-facing API).
- Memory entry — add a `reference_link_api.md` pointer if
  the surface is worth recalling in future sessions.

---

## 4. Sysctl knobs to add

None expected. Link properties are interface-instance state,
not policy knobs. If a future consumer needs a tunable
"default MTU at boot" or similar, it'd land via the existing
`INTERFACE__TAP__MTU` sysctl (which already exists).

---

## 5. New / touched files inventory

### New source files

| File                              | Phase | Purpose                                                |
|-----------------------------------|-------|--------------------------------------------------------|
| `pytcp/lib/link_api.py`           | 0     | `LinkApi` class + `LinkFlag` enum + `LinkStats` dataclass |

### Touched source files

| File                                              | Phases | Why                                                              |
|---------------------------------------------------|--------|------------------------------------------------------------------|
| `pytcp/stack/__init__.py`                         | 0-4    | `link: LinkApi` slot, `init`/`mock__init` wiring, callers migrate |
| `pytcp/stack/packet_handler/__init__.py`          | 1, 4   | `_interface_name` attribute (Phase 1), MTU mutation (Phase 4)     |
| `pytcp/lib/packet_stats.py`                       | 3      | (read-only access — no schema change)                             |
| `pytcp/tests/lib/network_testcase.py`             | 0      | `_STACK__PATCHED_ATTRS` adds `link`                              |

### New test files

| File                                                   | Phase  | Cases (target)                                                          |
|--------------------------------------------------------|--------|-------------------------------------------------------------------------|
| `pytcp/tests/unit/lib/test__lib__link_api.py`           | 0      | `mac_address` / `mtu` / `interface_layer` reads                          |
| (same file, extended)                                   | 1      | `name` read                                                              |
| (same file, extended)                                   | 2      | `is_running` / `flags` reads + `LinkFlag` enum                            |
| (same file, extended)                                   | 3      | `stats` returns `LinkStats`; aggregation correctness                     |
| (same file, extended)                                   | 4      | `set_mtu` validation + propagation; `up`/`down` delegation                |

---

## 6. Open design decisions

### 6.1 Read shape — properties vs methods

Plan uses **properties** for read access (`link.mac_address`,
`link.mtu`). Alternative: methods (`link.get_mac_address()`).

Linux RTNETLINK is method-shaped (`RTM_GETLINK`). PyTCP's
existing `Ip4AddressApi.list_ip4_hosts()` is method-shaped.

**Decision (confirmed 2026-05-12):** **all reads are
properties, including `stats`.** Pythonic default; matches
`HeaderProperties` mixins and value-type field access
across the codebase; `stats` allocation cost (aggregating
~100 counters into a frozen dataclass) is microseconds, not
a syscall — calling it a property is honest enough. Future
Phase-3 IPC swap-out, if it ever lands, becomes a single
sweep across the surface; pre-emptively making `stats` a
method today doesn't help.

### 6.2 `set_mtu` validation policy

- Lower bound: **68 octets** (RFC 791 §3.2 — minimum
  reassembled IP datagram size for IPv4).
- Upper bound: **65535** (uint16 wire limit).
- Alternative: enforce a higher minimum (e.g. 576 octets per
  RFC 1122 §3.3.3) — but 68 is the spec floor.

**Decision (confirmed 2026-05-12):** **68 octets floor**.
Matches Linux's `ETH_MIN_MTU` device-level enforcement.
Accepts the IPv6-silently-breaks-below-1280 footgun as
operator responsibility (Linux ships the same footgun;
Linux releases it via per-interface IPv6 disable which
PyTCP doesn't have yet, so the docstring warns the
operator).

### 6.3 `up()` / `down()` overlap with `stack.start()` / `stack.stop()`

Phase-3 north-star says stack lifecycle is its own surface.
`LinkApi.up/down` delegate; they don't duplicate logic.

Alternative: drop `up/down` from LinkApi entirely; operators
call `stack.start/stop`. Cleaner but loses the Linux-parity
`ip link set up/down` ergonomics.

**Decision (confirmed 2026-05-12):** **defer `up()`/`down()`
to the Phase-2 multi-interface track.** Phase-1 has no
consumer demand (tests + examples call `stack.start/stop`
directly and won't migrate); Phase-2 needs per-interface
lifecycle with real semantics; shipping delegating wrappers
today locks in semantics that will need to be torn out then.
Phase 4 scope reduces to `set_mtu` + `set_mac_address` only.

### 6.4 Stats aggregation — which counters map to which buckets?

`PacketStats*` has 100+ fine-grained counters. `LinkStats`
needs 8 canonical buckets. The mapping is a judgement call:

- `rx_bytes` / `tx_bytes` — sum of frame lengths (need a new
  byte counter).
- `rx_packets` ≈ `ethernet__pre_parse` (L2) or
  `ip4__pre_parse + ip6__pre_parse` (L3).
- `rx_errors` ≈ sum of `*__integrity_error__drop` + similar.
- `rx_dropped` ≈ sum of `*__no_proto_support__drop` + similar.
- TX symmetric.

**Decision (confirmed 2026-05-12):** **separate
`LinkStatsCounters` dataclass on `PacketHandler`**.
Adding `rx_bytes`/`tx_bytes`/`rx_multicast`/`tx_multicast`
directly to `PacketStatsRx`/`PacketStatsTx` would break
every integration test using the strict `exact=True`
assertion (the rule from `integration_testing.md §8`).
Instead, Phase 3 adds a new sibling dataclass:

```python
# pytcp/lib/packet_stats.py (new sibling dataclass)
@dataclass(slots=True)
class LinkStatsCounters:
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_multicast: int = 0
    tx_multicast: int = 0
```

`PacketHandler` grows a `_link_stats: LinkStatsCounters`
slot alongside the existing `_packet_stats_rx` /
`_packet_stats_tx`. Integration tests' `exact=True`
assertions on `packet_stats_*` are completely untouched.

`LinkApi.stats` combines both sources:
- `rx_packets` / `rx_errors` / `rx_dropped` etc. —
  aggregate from existing `_packet_stats_rx` fields (no new
  per-protocol counters needed).
- `rx_bytes` / `rx_multicast` etc. — read directly from
  `_link_stats`.

The aggregation mapping is documented verbatim in the
`LinkStats` docstring so future contributors know which
bucket a new drop counter belongs to.

Harness `setUp` clears `link_stats` per-test (snapshot/restore
extension to the existing `_STACK__PATCHED_ATTRS` pattern).
Phase 3 effort bumps from ~45 min to ~1.5 h to cover the
schema add + harness reset.

### 6.5 Multi-interface forward-compat

PyTCP is single-interface in Phase 1. The Link API today
exposes "the" interface. Phase-2 (router-grade) needs per-
interface state.

The Linux Link API is multi-interface (each call takes
ifindex / name). The PyTCP equivalent would be
`stack.link[interface_name]` or `stack.link.get(name)`.

**Decision (confirmed 2026-05-12):** **Phase 1 API is
`stack.link.mac_address` (no interface arg).** When
multi-interface lands, the API becomes
`stack.link["tap7"].mac_address` — the single-arg
subscript is the natural Linux-parity upgrade path. Phase-2
multi-interface is a major refactor anyway (route table,
FIB, forwarding plane); one more shape change at
`stack.link` is rounding error compared to the rest. No
Phase-2 commitment in this track; Phase-1 stays clean.

### 6.6 Mutation in Phase 1 — set_mtu only?

`set_mac_address` is genuinely Phase 2 / hotplug territory.
`set_mtu` has plausible Phase-1 consumers (PMTU work,
operator config). Plan ships `set_mtu` in Phase 4 of this
track; defers `set_mac_address`.

**Decision (confirmed 2026-05-12):** **ship
`set_mac_address` in Phase 4 with Linux-faithful "stack
stopped first" semantics.**

`set_mac_address(mac_address=...)` requires the stack to be
stopped (`stack.start()` not yet called, or `stack.stop()`
already run). Rationale: Linux requires `ip link set down`
before `ip link set address`; the equivalent here is "stack
not running." This restriction lifts when multi-interface
lands and per-interface lifecycle becomes meaningful.

Implementation in Phase 4 covers:

1. MAC validation (reject multicast bit set; reject all-zero).
2. Update `packet_handler._mac_unicast`.
3. Update RX MAC filter (the unicast filter changes; solicited
   -node multicast is derived from IPv6 address and is
   unaffected).
4. Schedule gratuitous announce for every owned host:
   - RFC 5227 §3 gratuitous ARP for each `_ip4_host`.
   - RFC 4861 §7.2.6 unsolicited Neighbor Advertisement for
     each `_ip6_host`.
   Reuse `Ip4AddressApi.send_gratuitous_arp` from the RFC
   3927 track.
5. Tests: validation matrix + RX-filter assertion + wire-
   level integration test for the announce sequence + "stack
   not stopped" rejection.

Phase 4 effort revises from ~30 min (set_mtu only) to
~2.5 h (set_mtu + set_mac_address + stop-first guard
+ announce wire-level tests).

`up()`/`down()` are NOT in Phase 4 — deferred per §6.3.

---

## 7. Test strategy

### 7.1 Unit layer

`pytcp/tests/unit/lib/test__lib__link_api.py`:

- Hand-rolled `_FakePacketHandler` exposes only the attrs
  `LinkApi` reads (`_mac_unicast`, `_interface_mtu`,
  `_interface_layer`, `_interface_name`, `packet_stats_*`).
- Each property has 2-3 cases: happy path + edge (L3 returns
  None for MAC; missing name returns None; etc.).
- `set_mtu` validation matrix: under-min, at-min, normal,
  at-max, over-max.

### 7.2 §7.2 docstring audit

Every new test method follows the canonical shape (Ensure...
opener + trailing Reference: line). For Link API tests with
no RFC clause, use `Reference: PyTCP test infrastructure
(Phase-3 Link API surface).`

### 7.3 Integration touch points

Minimal — the Link API is read-mostly and unit-testable
without the harness. The two migration call sites (DHCP +
link-local construction in `stack.init`) are exercised by
existing harness fixtures.

---

## 8. Effort estimate

| Phase | Description                                             | Effort  | Cumulative | Commit     |
|-------|---------------------------------------------------------|---------|------------|------------|
| 0     | Read-only MAC + MTU + interface_layer                   | ~30 min | ~30 min    | `cdc11324` |
| 1     | Interface name plumbing                                 | ~30 min | ~1 h       | `3ceb4432` |
| 2     | Running state + flags enum                              | ~45 min | ~1.75 h    | `efa64c8c` |
| 3     | Stats introspection (incl. LinkStatsCounters dataclass) | ~1.5 h  | ~3.25 h    | `5bb2cf2f` |
| 4     | set_mtu + set_mac_address (stack-stopped-first)         | ~2.5 h  | ~5.75 h    | `d4aed533` |
| 5     | Adherence + docs                                        | ~30 min | ~6.25 h    | (this)     |

**Total: ~6 h** (~a working day). Phases shipped in
numeric order, each as a focused commit. `up()`/`down()`
deferred to the Phase-2 multi-interface track per §6.3.

---

## 9. Commit discipline

Each phase = one focused commit. Commit message template:

```
Link API: <phase title> (Phase N)

<paragraph: what landed, why>

Tests-first: <pin>.

Reference: <PyTCP plan doc + linux equivalent>.

Lint clean. <N> passing.
```

`make lint` + `make test` + §7.2 audit gate every commit.

---

## 10. Closing the audit loop

After Phase 5:

- `docs/refactor/link_api.md` (this doc) marks every phase
  shipped.
- `docs/refactor/ip4_audit_punchlist.md` cross-references the
  new namespace.
- CLAUDE.md's north-star table flips Link API from "future"
  to "shipped (read + minimal mutation)".
- Memory entry `reference_link_api.md` summarises the
  surface so future sessions don't have to re-derive it.

---

## 11. References

### Phase-3 north-star (CLAUDE.md)

| Surface           | Plane                 | Linux                  | PyTCP state after this track                                    |
|-------------------|-----------------------|------------------------|-----------------------------------------------------------------|
| Link API          | Link control          | `ip link` / RTNETLINK  | **shipped** (read + set_mtu + set_mac_address; up/down Phase-2) |
| Address API       | Network-layer control | `ip addr` / RTNETLINK  | shipped (RFC 3927 track)                                        |
| Route API         | Routing control       | `ip route` / RTNETLINK | not yet                                                         |
| Neighbor API      | Neighbor control      | `ip neighbor`          | not yet                                                         |
| Introspection API | State observation     | `/proc/net/*`          | not yet (stats peek via Link API §3)                            |

### PyTCP internal references

- `docs/refactor/rfc3927_link_local_autoconfig.md` —
  structural template for the phased-track pattern.
- `pytcp/lib/address_api.py` — the sibling Phase-3 surface
  this track mirrors structurally.
- `pytcp/stack/__init__.py` — the kernel assembly point
  that constructs / wires both APIs.

### Linux references

- `man 8 ip-link` — read + mutation surface.
- `linux/include/uapi/linux/if_link.h` — `IFF_*` flag
  enumeration.
- `linux/net/core/rtnetlink.c::rtnl_fill_ifinfo` — RTNETLINK
  message builder for `RTM_GETLINK`.

---

## 12. Linux comparison + Phase-3 alignment

### 12.1 Linux equivalents per phase

| PyTCP after Phase N       | Linux equivalent                          |
|---------------------------|-------------------------------------------|
| Phase 0 `mac_address`     | `ip link show eth0 \| grep link/ether`    |
| Phase 0 `mtu`             | `ip link show eth0 \| grep mtu`           |
| Phase 0 `interface_layer` | `ip link show eth0 \| grep link/`         |
| Phase 1 `name`            | `ip link show` first column               |
| Phase 2 `is_running`      | `ip link show eth0 \| grep state`         |
| Phase 2 `flags`           | `ip link show eth0 \| grep <FLAGS>`       |
| Phase 3 `stats`           | `ip -s link show eth0`                    |
| Phase 4 `set_mtu`         | `ip link set eth0 mtu N`                  |
| Phase 4 `set_mac_address` | `ip link set eth0 address aa:bb:..`       |
| Phase-2 (deferred) `up`/`down` | `ip link set eth0 up`/`down`         |

### 12.2 Phase-3 alignment

Per CLAUDE.md Phase-3 design implications:

- **Every read goes through the sanctioned API** — DHCP and
  link-local no longer touch `packet_handler._mac_unicast`
  directly.
- **No reach-through from "userspace"** — the `stack.link`
  singleton is the only public surface.
- **State introspection is read-only and copy-by-value** —
  `stats` returns a frozen dataclass; `flags` returns a
  frozenset.
- **Mutations go through the API for their plane** — MTU
  mutation lives on Link API, not directly on packet_handler.
- **Stack lifecycle is its own surface** — `up()` / `down()`
  delegate to `stack.start()` / `stack.stop()` rather than
  duplicating.

### 12.3 What this track does NOT do

- **Multi-interface support** — out of scope (Phase 2 router
  track). The single-interface assumption is preserved.
- **MAC address mutation** — deferred (no consumer demand;
  hotplug is Phase 2).
- **Per-protocol filters / qdisc / queueing** — Linux exposes
  these via `ip link`; PyTCP has no queueing model today.
- **Hardware offload flags** — explicitly out of scope per
  CLAUDE.md ("Hardware offloads ... out of scope regardless
  of phase").
