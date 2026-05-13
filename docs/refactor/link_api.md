# Link API — Phase-3 Link-Control Surface Plan

| Field           | Value                                                                |
|-----------------|----------------------------------------------------------------------|
| Status          | Plan — implementation not yet started                                |
| Plan author     | RFC 3927 follow-up (2026-05-12)                                      |
| Source motivation | RFC 3927 Phase 5 closure raised the question: should `stack/__init__.py`'s `packet_handler._mac_unicast` read be promoted to a public surface? Per CLAUDE.md the Link API is the canonical Phase-3 home for that read (and friends). |
| Target branch   | `PyTCP_3_0__pre_release`                                             |
| Touch points    | new `pytcp/lib/link_api.py`, `pytcp/stack/__init__.py` (slot + wiring), `pytcp/stack/packet_handler/__init__.py` (back-end methods if mutation lands), test harness snapshot |
| Linux analogue  | `ip link show` / `ip link set` / RTNETLINK `RTM_NEWLINK` / `RTM_GETLINK` / `RTM_SETLINK` |

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

### Phase 3 — Stats introspection (1 commit; ~45 min)

Mirrors Linux's `RX/TX bytes packets errors dropped` block
in `ip -s link show`.

**Properties:**

```python
@dataclass(frozen=True, kw_only=True, slots=True)
class LinkStats:
    rx_bytes: int
    rx_packets: int
    rx_errors: int
    rx_dropped: int
    tx_bytes: int
    tx_packets: int
    tx_errors: int
    tx_dropped: int

@property
def stats(self) -> LinkStats:
    """Copy-by-value snapshot of cumulative interface stats.
    Linux equivalent: 'ip -s link show' RX/TX block."""
```

**Implementation:**

- Map the existing `PacketStatsRx` / `PacketStatsTx` fields
  to the `LinkStats` shape. The mapping aggregates protocol-
  specific counters into the four canonical buckets.
- Each `stats` access returns a fresh frozen dataclass —
  copy-by-value per Phase-3 "introspection is read-only".

**Open design decision:** which counters map to which
buckets? Some protocol-specific drops (e.g.
`ip4__src_not_owned__drop`) clearly map to `rx_errors`; some
(e.g. `ip4__no_proto_support__drop`) are ambiguous. Phase 3
proposes a draft mapping in the commit; review may revise.

**Tests-first:**

- Empty `PacketStats*` → `LinkStats` with all zeros.
- Populated `PacketStatsRx.ethernet__pre_parse=5` → `rx_packets >= 5`.
- The returned `LinkStats` is frozen / slotted (mutation
  raises).

### Phase 4 — Mutation: set_mtu + up/down (1 commit; ~2 hours)

The minimal mutation surface that has plausible consumers.

**Methods:**

```python
def set_mtu(self, *, mtu: int) -> None:
    """Set the interface MTU. Linux 'ip link set mtu N'.
    Propagates to packet_handler._interface_mtu and
    interface_mtu module global. Rejects values < 68 (RFC
    791 §3.2) or > 65535."""

def up(self) -> None:
    """Mark the interface up. Equivalent to 'stack.start()'
    when the stack is initialized but not running. No-op
    when already up."""

def down(self) -> None:
    """Mark the interface down. Equivalent to 'stack.stop()'.
    Stops all subsystems. The stack can be brought back up
    via 'up()'."""

def set_mac_address(self, *, mac_address: MacAddress) -> None:
    """Phase-2 hotplug (deferred). Linux 'ip link set address'."""
```

**Open design decision:** `up()` / `down()` overlap with
`stack.start()` / `stack.stop()`. Per Phase-3 north-star:

> Stack lifecycle is its own API surface. `stack.init()` /
> `stack.start()` / `stack.stop()` are the boundary; treat
> them like `clone(2)` / `exit(2)` rather than ordinary
> function calls.

So `LinkApi.up/down` should delegate to `stack.start/stop`
— not duplicate logic. The Linux equivalent is `ip link set
up` which calls into the kernel's interface-up path; same
shape.

**Implementation:**

- `set_mtu` writes through to `packet_handler._interface_mtu`,
  `stack.interface_mtu`, and the TxRing's MTU if it has
  one. Validates against RFC 791 §3.2 minimum (68 octets).
- `up()` calls `stack.start()`; `down()` calls `stack.stop()`.
- `set_mac_address` deferred to Phase 5 (or Phase-2 of the
  multi-interface track).

**Tests-first:**

- `set_mtu(1400)` updates `packet_handler._interface_mtu`
  and `stack.interface_mtu`.
- `set_mtu(67)` rejects (below RFC 791 §3.2 minimum).
- `set_mtu(70000)` rejects (above uint16).
- `up()` / `down()` delegate to `stack.start/stop` (mock
  the stack functions and verify call).

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

**Decision:** properties for single-value reads (mac, mtu,
name, is_running, interface_layer); methods for richer
operations (stats — which returns a dataclass; future
queries that take filter args).

### 6.2 `set_mtu` validation policy

- Lower bound: **68 octets** (RFC 791 §3.2 — minimum
  reassembled IP datagram size for IPv4).
- Upper bound: **65535** (uint16 wire limit).
- Alternative: enforce a higher minimum (e.g. 576 octets per
  RFC 1122 §3.3.3) — but 68 is the spec floor.

### 6.3 `up()` / `down()` overlap with `stack.start()` / `stack.stop()`

Phase-3 north-star says stack lifecycle is its own surface.
`LinkApi.up/down` delegate; they don't duplicate logic.

Alternative: drop `up/down` from LinkApi entirely; operators
call `stack.start/stop`. Cleaner but loses the Linux-parity
`ip link set up/down` ergonomics.

**Decision:** ship delegating wrappers. Cheap, mirrors Linux.

### 6.4 Stats aggregation — which counters map to which buckets?

`PacketStats*` has 100+ fine-grained counters. `LinkStats`
needs 8 canonical buckets. The mapping is a judgement call:

- `rx_bytes` / `tx_bytes` — sum of frame lengths (need a new
  byte counter — Phase 3 may add `rx_bytes`/`tx_bytes` to
  PacketStats).
- `rx_packets` ≈ `ethernet__pre_parse` (L2) or
  `ip4__pre_parse + ip6__pre_parse` (L3).
- `rx_errors` ≈ sum of `*__integrity_error__drop` + similar.
- `rx_dropped` ≈ sum of `*__no_proto_support__drop` + similar.
- TX symmetric.

**Decision:** ship a defensible draft mapping in Phase 3;
review may revise.

### 6.5 Multi-interface forward-compat

PyTCP is single-interface in Phase 1. The Link API today
exposes "the" interface. Phase-2 (router-grade) needs per-
interface state.

The Linux Link API is multi-interface (each call takes
ifindex / name). The PyTCP equivalent would be
`stack.link[interface_name]` or `stack.link.get(name)`.

**Decision:** Phase 1 API is `stack.link.mac_address` (no
interface arg). When multi-interface lands, the API becomes
`stack.link["tap7"].mac_address` — the single-arg
subscript is the natural Linux-parity upgrade path. No
Phase-2 commitment in this track.

### 6.6 Mutation in Phase 1 — set_mtu only?

`set_mac_address` is genuinely Phase 2 / hotplug territory.
`set_mtu` has plausible Phase-1 consumers (PMTU work,
operator config). Plan ships `set_mtu` in Phase 4 of this
track; defers `set_mac_address`.

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

| Phase | Description                                | Effort   | Cumulative |
|-------|--------------------------------------------|----------|------------|
| 0     | Read-only MAC + MTU + interface_layer      | ~30 min  | ~30 min    |
| 1     | Interface name plumbing                    | ~30 min  | ~1 h       |
| 2     | Running state + flags enum                 | ~45 min  | ~1.75 h    |
| 3     | Stats introspection                        | ~45 min  | ~2.5 h     |
| 4     | set_mtu + up/down mutation                 | ~2 h     | ~4.5 h     |
| 5     | Adherence + docs                           | ~30 min  | ~5 h       |

**Total: ~5 h** (~half a working day). Phases ship in
numeric order, each as a focused commit.

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

| Surface | Plane | Linux | PyTCP state after this track |
|---|---|---|---|
| Link API | Link control | `ip link` / RTNETLINK | **shipped** (read + set_mtu + up/down) |
| Address API | Network-layer control | `ip addr` / RTNETLINK | shipped (RFC 3927 track) |
| Route API | Routing control | `ip route` / RTNETLINK | not yet |
| Neighbor API | Neighbor control | `ip neighbor` | not yet |
| Introspection API | State observation | `/proc/net/*` | not yet (stats peek via Link API §3) |

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

| PyTCP after Phase N | Linux equivalent                            |
|---------------------|---------------------------------------------|
| Phase 0 `mac_address` | `ip link show eth0 | grep link/ether`     |
| Phase 0 `mtu`         | `ip link show eth0 | grep mtu`            |
| Phase 0 `interface_layer` | `ip link show eth0 | grep link/`      |
| Phase 1 `name`        | `ip link show` first column                |
| Phase 2 `is_running`  | `ip link show eth0 | grep state`           |
| Phase 2 `flags`       | `ip link show eth0 | grep <FLAGS>`         |
| Phase 3 `stats`       | `ip -s link show eth0`                     |
| Phase 4 `set_mtu`     | `ip link set eth0 mtu N`                  |
| Phase 4 `up`/`down`   | `ip link set eth0 up`/`down`              |

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
