# PyTCP Packet Handler Rewrite Plan

A phased, tests-first rewrite of the `packages/pytcp/pytcp/runtime/packet_handler/`
subsystem. The goal is to retire the 20-mixin, single-interface
god-class in favor of a per-`Interface` composed handler model that
admits multi-interface operation and ships the seven sanctioned
Phase-3 API surfaces inline as their underlying state lands.

**Status: SUPERSEDED / DELIVERED on `PyTCP_3_0_6`.** The rewrite shipped
by a different (more incremental) route than this monolithic plan
assumed. Delivered: the per-`ifindex` `InterfaceTable` + per-interface
rings/caches, six of the seven Phase-3 API surfaces as dedicated
modules (link / address / route / neighbor / sysctl / socket).
**Reconciled 2026-05-30:** introspection did NOT ship as a dedicated
`pytcp.stack.introspection` module — it landed only as scattered
read-only copy-by-value accessors on the stack module (e.g.
`local_ip4_hosts()`). Also delivered: the egress seam, the
RFC 1812 `forward_or_deliver` seam (host-mode stub), singleton retirement
+ Neighbor API (`e5dc77f5`), and the mixin→composition collapse + RX
dispatch registry (`6a7f13d8`..`3abdcf5c`, tracked in
`packet_handler_composition.md`). Phase-2 router/forwarding logic behind
the `forward_or_deliver` seam remains a deliberate future-phase stub.
This document is retained as the architectural anchor / archaeology;
the per-phase plan below predates the as-shipped sequencing.

This document was the architectural anchor for the rewrite.

---

## Phase-3 boundary contract

The CLAUDE.md "Project North Star" §Phase 3 names seven sanctioned
API surfaces that consumers — tests, examples, CLI tools, eventually
external applications — talk to PyTCP through. Everything else is
internal. This rewrite ships each surface at the phase where its
underlying state naturally lands, not as a single end-of-rewrite
facade.

| API surface             | Module                          | Linux equivalent                  | Lands in phase |
|-------------------------|---------------------------------|-----------------------------------|----------------|
| BSD `socket()`          | `pytcp.socket`                  | `socket(2)`                       | Already exists; reach-throughs cleaned on touch |
| Sysctl registry         | `pytcp.stack.sysctl`            | `/proc/sys/net/`                  | Already exists; cadences added in Phase 5       |
| Link API                | `pytcp.stack.link`              | `ip link` / `RTM_NEWLINK`         | Phase 3                                         |
| Introspection API       | read-only accessors on `pytcp.stack` (e.g. `local_ip4_hosts()`) — NO dedicated `pytcp.stack.introspection` module shipped | `/proc/net/*`, `ss`               | Phase 4                                         |
| Address API             | `pytcp.stack.address`           | `ip addr` / `RTM_NEWADDR`         | Phase 8                                         |
| Neighbor API            | `pytcp.stack.neighbor`          | `ip neighbor` / `RTM_NEWNEIGH`    | Phase 8                                         |
| Route API               | `pytcp.stack.route`             | `ip route` / `RTM_NEWROUTE`       | Phase 9                                         |

Three rules govern every API module:

1. **Value-typed only.** Methods take and return strings, ints,
   `Ip4Address`/`Ip6Address`, `Ip4Network`/`Ip6Network`, and
   immutable dataclasses. Never `Interface` / `TcpSession` /
   `NeighborCache` references. Sockets identified by integer IDs;
   interfaces identified by string names.
2. **Read-only introspection is copy-by-value.** Snapshot accessors
   return immutable data the caller cannot mutate to affect stack
   state. Linux equivalent: reading `/proc/net/*` is text — readable,
   never writable by reading.
3. **Mutation goes through the right plane.** Address changes go
   through `pytcp.stack.address`, never `packet_handler._ip6_ifaddr.append(...)`.
   Route changes through `pytcp.stack.route`, never `Ip4IfAddr.gateway = ...`.
   Each plane's API is the boundary; the underlying attribute is
   implementation detail.

Reach-throughs in tests / examples / internal callers (the DHCP4
client mutates `Ip4IfAddr.gateway` directly today, for example) are
**Phase-3 violations cleaned on touch**, per the
`feature_implementation.md` modernisation-on-touch rule. The
phase that touches a violating call site fixes it in the same
commit; no separate sweep.

---

## Read-out of current state

- `packages/pytcp/pytcp/runtime/packet_handler/__init__.py` is 2040 lines: an
  abstract `PacketHandler(Subsystem)` (state-rich) + concrete
  `PacketHandlerL2` and `PacketHandlerL3` that diamond-inherit 20
  `PacketHandler<Proto><Dir>(ABC)` mixins. Mixin cross-calls are
  MRO-resolved; each mixin uses a `TYPE_CHECKING` block to declare
  the cross-call surface it needs. There is no enforcement.
- `packages/pytcp/pytcp/stack/__init__.py` declares **module-level singletons** for
  `timer`, `rx_ring`, `tx_ring`, `arp_cache`, `nd_cache`,
  `packet_handler`, plus shared dicts `sockets`, `pmtu_cache`, and
  the two `Icmp*ErrorRateLimiter` instances. There is no
  first-class `Interface` object — the *interface* is implicit in
  the singletons.
- L2 RX entry is `PacketHandlerL2._subsystem_loop`: dequeue, branch
  on EtherType vs LLC length, dispatch to `_phrx_ethernet_802_3` or
  `_phrx_ethernet`. EtherType demux is a `match`/`case` inside
  `_phrx_ethernet`. L3 entry has the same shape but with a TUN
  protocol-family prefix.
- IPv6 RX (`_phrx_ip6`) does the destination-is-mine check at the
  top and walks the EH chain. There is no forwarding seam —
  non-mine destinations are dropped. This is the single most
  important Phase-2 surface to break open.
- Periodic housekeeping (RFC 8981 §3.4 sweep + §18c.2 regen, RFC 4862
  §5.5.3 stable sweep) lives in
  `PacketHandlerL2._maybe_run_periodic_tasks`, called from inside
  `_subsystem_loop` after every RX dequeue. The `Timer` subsystem
  exists and is used by TCP, but periodic ND tasks bypass it and
  live on the RX hot path.
- `NeighborCache[A]` is generic over address type
  (`packages/pytcp/pytcp/lib/neighbor.py`). Today there are two singletons:
  `arp_cache` (IPv4) and `nd_cache` (IPv6). They are not keyed by
  interface.
- `TcpTestCase` (`packages/pytcp/pytcp/tests/lib/tcp_testcase.py`)
  builds on `NetworkTestCase`. It mocks `TxRing` to capture frames,
  mocks `ArpCache`/`NdCache` with a static lookup table, constructs
  a real `PacketHandlerL2` with the test stack addressing, calls
  `stack.mock__init` to wire the mocks into the module-level
  singletons, and drives RX via
  `_drive_rx(frame=...)` calling `self._packet_handler._phrx_ethernet(PacketRx(frame))`.
  TX assertions parse captured frames into a `TcpProbe`. This is
  the canonical pattern the new harness mirrors.
- Existing `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__*__rx.py`
  / `__tx.py` files (~17 files) are the legacy harness — they
  extend `NetworkTestCase` directly.

Current Phase-3 violations to inventory in Phase 0 (non-exhaustive):
- `packages/pytcp/pytcp/lib/dhcp4_client.py` mutates `Ip4IfAddr.gateway` directly
- Several examples import from `pytcp.runtime.packet_handler.*`
- `TcpTestCase` reaches into `_packet_handler._ip6_ifaddr` for
  fixture setup
- `NetworkTestCase` reads / writes module-level singletons directly

---

## Phase 0 — RFC adherence audit refresh + reach-through inventory

**Goal.** Make the RFC ground truth current and inventory current
Phase-3 boundary violations before code changes.

**Dependencies.** None.

**Deliverables.**
- Audit refresh, using the `rfc_adherence_audit` skill, for any RFC
  whose mechanism is touched by the rewrite. Concretely: RFC 826
  (ARP), 5227 (ARP ACD), 4861 (ND), 4862 (SLAAC), 7217 (stable
  IID), 8981 (temp addr), 4429 (Optimistic DAD), 7527 (Enhanced
  DAD), 9131 (gratuitous NA), 4191/4311/8028 (default-router
  selection), 6724 (source selection), 8200 (IPv6), 791 (IPv4),
  4443 (ICMPv6), 1812 (router requirements — Phase-2 stub).
- New audit folders to create where they do not exist today:
  `docs/rfc/ip4/rfc1812__router_requirements/` (Phase-2 prep,
  mostly gap inventory), `docs/rfc/ip4/rfc791__ipv4/` if absent,
  audit of `docs/rfc/ip6/rfc8200__ipv6/` for forwarding-relevant
  clauses.
- **`docs/refactor/packet_handler_phase3_violations.md`** — new
  document. Greppable inventory of every current reach-through
  from "userspace" (tests / examples / internal callers acting as
  consumers) into stack internals. Each entry: file:line, what
  internal state is touched, which Phase-3 API will replace it.
  Becomes the per-phase cleanup checklist.
- This document committed at end of Phase 0.

**Tests.** None — audit phase.

**Reversibility.** Pure-doc; revert audit commits.

**Effort.** M (each audit ~30-60 min; 6-10 audits + violations doc).

---

## Phase 1 — New `PacketHandlerTestCase` (replaces `NetworkTestCase`)

**Goal.** Land a packet-handler-specific test base that supports
multi-interface operation from day one and that we write *all*
future packet-handler tests against — including the Phase 2 spec
backfill and every later-phase rewrite assertion.
`PacketHandlerTestCase` extends `unittest.TestCase` directly;
`NetworkTestCase` becomes a thin compat alias during the migration
and is deleted in Phase 10.

**Dependencies.** Phase 0.

**Deliverables.**
- `packages/pytcp/pytcp/tests/lib/packet_handler_testcase.py` — new file. Class
  `PacketHandlerTestCase(TestCase)`. Layout mirrors
  `TcpTestCase`:
  - `setUp` snapshots and clears the same module-global state
    `TcpTestCase` does (`stack.sockets`, `stack.pmtu_cache`,
    `stack.icmp{4,6}_error_rate_limiter`, the
    `_STACK__PATCHED_ATTRS` set), plus the new `stack.interfaces`
    dict landed in Phase 8 (a no-op until then).
  - `_add_interface(*, name, layer, mac=None, mtu=1500, ip4=...,
    ip6=..., gateway4=..., gateway6=...)` builder. Returns a typed
    `TestInterface` handle whose `tx_frames: list[bytes]` attribute
    records emitted frames, replacing today's flat
    `self._frames_tx`. The builder uses the future `pytcp.stack.link`
    + `pytcp.stack.address` APIs (added in Phase 3 and Phase 8
    respectively) — during Phase 1 / 2 it calls a thin shim that
    forwards to today's `mock__init` until the APIs land.
  - `_drive_rx(*, interface, frame)` — inject a raw frame at the
    appropriate entry point for the interface's layer
    (`_phrx_ethernet` / `_phrx_ethernet_802_3` for L2, `_phrx_ip6`
    / `_phrx_ip4` for L3 after stripping the TUN PI prefix).
    During Phase 1 `interface` defaults to the single test
    interface.
  - `_drive_tx(*, interface, call)` — invoke a TX entry by passing
    a small wrapper that captures the assembler call.
  - `_advance(*, ms)` — drives the `FakeTimer`
    (`packages/pytcp/pytcp/tests/lib/fake_timer.py`).
- Typed `EthernetProbe`, `Ip4Probe`, `Ip6Probe`, `ArpProbe`,
  `Icmp4Probe`, `Icmp6Probe` — frozen dataclasses analogous to
  `TcpProbe`, in the same file. Populated by re-parsing captured
  wire bytes through the real `*Parser`. Parsers are the spec
  source of truth, so a probe asserts what the wire actually says.
- Stack-state isolation helpers — `_snapshot_stack_state()` /
  `_restore_stack_state()` factored out of `setUp`/`tearDown` so
  derived test classes can re-snapshot mid-test.
- `packages/pytcp/pytcp/tests/lib/__init__.py` re-exports the new symbols.
- `packages/pytcp/pytcp/tests/lib/network_testcase.py` becomes a thin compat
  alias: `NetworkTestCase = PacketHandlerTestCase`. Existing
  tests that subclass `NetworkTestCase` continue to work
  unmodified through the rewrite; they migrate to
  `PacketHandlerTestCase` in Phase 10.
- *No production code changes* in this phase.

**Tests.** One harness smoke test per layer:
- `packages/pytcp/pytcp/tests/integration/protocols/_harness/test__harness__l2_smoke.py`
  — drive a known ARP request frame through a single L2 test
  interface, assert one ARP reply frame is captured.
- `packages/pytcp/pytcp/tests/integration/protocols/_harness/test__harness__l3_smoke.py`
  — same with an ICMPv6 Echo Request through a single L3 test
  interface.
- `packages/pytcp/pytcp/tests/integration/protocols/_harness/test__harness__multi_interface.py`
  — build *two* interfaces, drive a frame into one, assert no TX
  appears on the other. Locks in the contract Phase 8 will
  satisfy in production.

**Modernisation-on-touch.** None (all-new files).

**Reversibility.** Pure-test additions; revert test-lib commits.

**Effort.** L. Probe dataclasses + multi-interface plumbing are
the bulk.

---

## Phase 2 — Spec-driven coverage backfill

**Goal.** Use the new harness to write tests that pin RFC behavior
for every protocol's RX and TX path, *before* any structural change
touches that code. Tests are written against the spec, not against
the current code. Disagreements surface RFC-vs-current divergences
we want to know about *now* rather than during the rewrite.

**Dependencies.** Phase 1.

**Deliverables.** New tests under
`packages/pytcp/pytcp/tests/integration/protocols/<proto>/` (matching the
documented cross-cutting test path):
- `arp/test__arp__request_response.py`,
  `arp/test__arp__acd_conflict.py` (RFC 5227),
  `arp/test__arp__probe_announce.py`
- `ethernet/test__ethernet__demux.py`,
  `ethernet/test__ethernet__dst_filter.py`
- `ip4/test__ip4__deliver_or_drop.py`,
  `ip4/test__ip4__source_route.py`,
  `ip4/test__ip4__ttl_zero.py`,
  `ip4/test__ip4__fragment_reassembly.py`,
  `ip4/test__ip4__fragmentation.py`
- `ip6/test__ip6__deliver_or_drop.py`,
  `ip6/test__ip6__hbh_chain.py`,
  `ip6/test__ip6__rh0_drop.py`,
  `ip6/test__ip6__hop_limit.py`,
  `ip6/test__ip6__fragment_reassembly.py`
- `icmp6/test__icmp6__nd_ns_na.py`,
  `icmp6/test__icmp6__ra_pi.py`,
  `icmp6/test__icmp6__ra_default_router_list.py`,
  `icmp6/test__icmp6__error_emission_rate_limit.py`
- `icmp4/test__icmp4__echo.py`,
  `icmp4/test__icmp4__redirect_ignored.py` (host MUST ignore per
  RFC 1122 §3.2.2.2 absent forwarding),
  `icmp4/test__icmp4__error_emission_rate_limit.py`
- `udp/test__udp__deliver_or_port_unreachable.py`,
  `tcp/test__tcp__demux.py` (TCP FSM detail stays under
  `TcpTestCase`; this only pins demux)
- For each test class, the docstring carries the
  `Reference: RFC X §Y (clause).` line per `unit_testing.md` §7.

**Run discipline.** Every test runs against the *current*
god-class. Failures here are signals — they surface latent RFC
gaps and should either be fixed now (preferred, in-phase) or
marked `expectedFailure` with a `# Phase 2 backfill: RFC X gap,
fix in #<followup>` comment. No silent xfail.

**Modernisation-on-touch.** None (all-new test files; new code
already uses modern forms).

**Reversibility.** Pure-test additions.

**Effort.** XL. Largest phase by code volume. Worth it: gives the
rewrite a known-good behavioral baseline.

---

## Phase 3 — `Interface` abstraction + Link API

**Goal.** Define a first-class `Interface` object that owns
per-interface state. Ship the **Link API** (`pytcp.stack.link`) as
the consumer-facing surface backed by the `Interface` object. Keep
the production stack at a single instance for now — this phase
ships *the abstraction*, not multi-interface activation.

**Dependencies.** Phase 2.

**Deliverables.**
- `packages/pytcp/pytcp/stack/interface.py` — new file. Class `Interface`:
  - Identity: `name`, `layer: InterfaceLayer`, `mtu`, `mac`
    (only when `layer is L2`).
  - Owned subsystems: `rx_ring: RxRing`, `tx_ring: TxRing` —
    per-Interface attributes, not module-level singletons.
  - Per-AF config containers (in `packages/pytcp/pytcp/stack/interface_ip4.py`
    and `packages/pytcp/pytcp/stack/interface_ip6.py`): `Ip4DeviceConfig` and
    `Ip6DeviceConfig` (host/multicast/broadcast lists, frag-ID
    counters, DAD/ACD state, RA-learned default-router list,
    SLAAC table, temp-addr table, RA-parameter mirror, RFC 7217
    secret key).
  - Per-AF L2-bound caches: `arp_cache`, `nd_cache` (still
    singletons under the hood in this phase; Phase 4/8 lifts the
    singleton constraint).
- **`packages/pytcp/pytcp/stack/link/__init__.py` — Link API.** Public functions:
  - `add(*, name: str, layer: InterfaceLayer, mtu: int, mac: MacAddress | None) -> None`
  - `remove(*, name: str) -> None`
  - `up(*, name: str) -> None`, `down(*, name: str) -> None`
  - `set_mtu(*, name: str, mtu: int) -> None`
  - `set_mac(*, name: str, mac: MacAddress) -> None`
  - `list() -> tuple[LinkInfo, ...]` — returns immutable
    `LinkInfo` dataclasses (name, layer, mtu, mac, oper_state).
  - All take/return value types only. No `Interface` references
    leak across the boundary.
- `packages/pytcp/pytcp/stack/__init__.py` — `init()` constructs an `Interface`
  via `pytcp.stack.link.add(...)` and stores it in a new
  `stack.interfaces: dict[str, Interface]` (single-entry initially)
  plus a `stack.default_interface: Interface` shortcut. Legacy
  module-level `timer`, `rx_ring`, `tx_ring`, `arp_cache`,
  `nd_cache`, `packet_handler` names stay as aliases resolving to
  `default_interface.<x>`. Rename without breaking.
- `packages/pytcp/pytcp/runtime/packet_handler/__init__.py` — `PacketHandler.__init__`
  takes an `interface: Interface` parameter; per-interface state
  (MAC, host lists, multicast lists, frag counters, ND tables)
  moves off `self` and behind `self._interface.<x>` properties.
  Mixin `TYPE_CHECKING` blocks update to type-check against
  `_interface`.

**Phase-3 reach-through cleanup (on-touch).**
- Tests that construct interfaces via `mock__init(...)` direct args
  migrate to `pytcp.stack.link.add(...)` in the same commit.
- `Makefile` `make run` target documented as calling the Link API
  (one example tweak; no behavioural change).

**Tests.** Re-run Phase 2 + the legacy
`packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__*` suite; both must
pass identically. New:
- `packages/pytcp/pytcp/tests/integration/api/link/test__link__add_remove.py` —
  add and remove an interface via the Link API, assert it
  appears/disappears in `list()`.
- `packages/pytcp/pytcp/tests/integration/api/link/test__link__mtu_mac.py` —
  set MTU and MAC via the Link API, assert observable on the
  underlying packet flow.
- `packages/pytcp/pytcp/tests/integration/api/link/test__link__no_internal_refs.py`
  — assert `list()` returns immutable dataclasses, mutating them
  does not affect stack state.
- `packages/pytcp/pytcp/tests/integration/protocols/_interface/test__interface__lifecycle.py`
  — construct/start/stop an `Interface` in isolation; assert no
  leakage into module globals.

**Modernisation-on-touch.** Every mixin file's `TYPE_CHECKING` block
gets touched in this phase — fix any obsolete typing forms in the
same commit (`Optional`, `Union`, `List`, etc.). Expect 10-15%
LOC overhead.

**Reversibility.** Hardest phase to revert because it moves
attribute ownership. Keep legacy module-level aliases live; revert
by deleting `interface.py` and removing parameter wiring.

**Effort.** XL. Touches every mixin; ships a new public API.

---

## Phase 4 — Per-protocol state objects + Introspection API

**Goal.** Pull each protocol's state cluster out of the giant
`PacketHandlerL2.__init__` into a typed state class. Ship the
**Introspection API** (`pytcp.stack.introspection`) as the
read-only consumer surface backed by `snapshot()` methods on the
state objects.

**Dependencies.** Phase 3.

**Per-interface vs global state split** (matches Linux):
- **Per-Interface:** MAC unicast, MAC multicast list, IPv4/IPv6
  host lists, multicast group memberships, MTU, fragmentation ID
  counters, RFC 8981 temp-addr table, RA-learned default-router
  list (per-interface so RA from interface A does not poison
  interface B), DAD state, ARP ACD state. Mirrors `struct
  in_device` / `struct inet6_dev`.
- **Global:** PMTU cache, TCP stack singleton, ICMP error rate
  limiters (one per AF — Linux keeps these per-net-namespace,
  PyTCP is single-namespace), RFC 7217 secret key (single
  per-process is RFC-permitted; defer per-interface to Phase 2 of
  stack work).
- **Globally-keyed-but-conceptually-per-interface:**
  `NeighborCache` entries keyed on `(ifindex, address)` per
  Linux's `struct neighbour`. Achieved by giving each `Interface`
  its own `ArpCache` and `NdCache` instance (lands in Phase 8).

**Deliverables.** New state-object modules:
- `packages/pytcp/pytcp/stack/state/ip4_device.py` — `Ip4DeviceState` with a
  `snapshot() -> Ip4DeviceSnapshot` returning an immutable
  dataclass.
- `packages/pytcp/pytcp/stack/state/ip6_device.py` — `Ip6DeviceState` + snapshot.
- `packages/pytcp/pytcp/stack/state/icmp6_nd.py` — `Icmp6NdState` (DAD per-address
  dicts, RA prefix list, RA event semaphore, default-router list,
  SLAAC table, temp-addr table, RA parameter mirror, last-sweep
  timestamp) + snapshot.
- `packages/pytcp/pytcp/stack/state/arp_acd.py` — `ArpAcdState` (probe-conflict
  set, defend-last-emitted dict, last-conflict-at dict) + snapshot.
- `packages/pytcp/pytcp/stack/state/ip_reassembler.py` — wrap `IpFragTable` per
  AF + snapshot.
- `packages/pytcp/pytcp/runtime/packet_handler/__init__.py` — `PacketHandler`
  shrinks dramatically; methods that today read
  `self._icmp6_default_routers` go through
  `self._interface.icmp6_nd.default_routers`.
- **`packages/pytcp/pytcp/stack/introspection/__init__.py` — Introspection API.**
  Public functions:
  - `interfaces() -> tuple[InterfaceSnapshot, ...]`
  - `ip4_addresses(*, ifname: str) -> tuple[Ip4HostSnapshot, ...]`
  - `ip6_addresses(*, ifname: str) -> tuple[Ip6HostSnapshot, ...]`
  - `nd_default_routers(*, ifname: str) -> tuple[NdRouterSnapshot, ...]`
  - `slaac_addresses(*, ifname: str) -> tuple[SlaacSnapshot, ...]`
  - `temp_addresses(*, ifname: str) -> tuple[TempAddrSnapshot, ...]`
  - `arp_neighbors(*, ifname: str) -> tuple[NeighborSnapshot, ...]`
  - `nd_neighbors(*, ifname: str) -> tuple[NeighborSnapshot, ...]`
  - `interface_counters(*, ifname: str) -> InterfaceCountersSnapshot`
  - `socket_list() -> tuple[SocketSnapshot, ...]`
  - `routes() -> tuple[RouteSnapshot, ...]` (lands as stub
    returning `()` until Phase 9; documented contract is stable).
  - All return frozen dataclasses. Mutating the returned values
    does not affect stack state. Calling code is encouraged to
    re-snapshot rather than cache.

**Phase-3 reach-through cleanup (on-touch).**
- Test fixtures that read `_packet_handler._ip6_ifaddr`,
  `_icmp6_default_routers`, etc. for assertions migrate to
  `pytcp.stack.introspection.*` calls in the same commit.
- DHCP4 client reads of stack state migrate (writes deferred to
  Phase 8 when the Address API lands).

**Tests.** Phase 2 + 3 + legacy must pass. New:
- `packages/pytcp/pytcp/tests/integration/api/introspection/test__introspection__copy_by_value.py`
  — assert mutating returned snapshots does not affect subsequent
  snapshot() calls.
- `packages/pytcp/pytcp/tests/integration/api/introspection/test__introspection__per_interface_isolation.py`
  — build two interfaces, mutate ND state on one, assert the
  other's introspection snapshot is unchanged.
- `packages/pytcp/pytcp/tests/integration/protocols/_interface/test__interface__state_isolation.py`
  — same invariant at the state-object level.

**Modernisation-on-touch.** Every state-extraction commit touches
the corresponding mixin file — modernise typing in the same
commit.

**Reversibility.** Each state-object extraction independently
revertible.

**Effort.** L (state extraction) + M (Introspection API + tests).

---

## Phase 5 — Periodic housekeeping → `Timer` + sysctl cadences

**Goal.** Get RFC 8981 sweep, RFC 4862 stable sweep, ARP defend
timers off the L2 RX hot path and onto the existing `Timer`
subsystem. Cadences become sysctl knobs via the existing
`sysctl_knob` skill.

**Dependencies.** Phase 4 (state objects own the data the timers
act on).

**Deliverables.**
- `packages/pytcp/pytcp/runtime/packet_handler/__init__.py` — delete
  `_maybe_run_periodic_tasks`. `_subsystem_loop` is back to
  "dequeue and dispatch."
- `packages/pytcp/pytcp/stack/state/icmp6_nd.py` —
  `Icmp6NdState.register_timers(timer, interface)` registers
  `_icmp6_sweep_temp_addresses`, `_icmp6_regen_temp_addresses`,
  `_icmp6_sweep_slaac_addresses` with `timer.register_method(...)`
  keyed on `interface.name` so multi-interface registration is
  naturally distinct.
- `packages/pytcp/pytcp/stack/state/arp_acd.py` — same pattern for ARP defend
  timers.
- `packages/pytcp/pytcp/stack/__init__.py::init()` — after constructing each
  `Interface`, call its state objects' `register_timers(timer,
  interface)` methods.
- New sysctl knobs via the `sysctl_knob` skill:
  - `net.ipv6.icmp6.temp_addr_sweep_interval_s`
  - `net.ipv6.icmp6.slaac_sweep_interval_s`
  - `net.ipv4.arp.defend_interval_s`
  Existing constants in `nd__constants.py` / `arp__constants.py`
  migrate to the sysctl registry per the skill's per-package
  migration sweep guidance.

**Phase-3 reach-through cleanup (on-touch).** None — periodic
cadence values were already constants, not consumer-facing.

**Tests.** All prior phases + legacy pass. New:
- `packages/pytcp/pytcp/tests/integration/protocols/_interface/test__timer__nd_sweep_register.py`
  — assert `Timer` has the expected registered methods after
  `Interface` construction.
- `packages/pytcp/pytcp/tests/integration/protocols/_interface/test__timer__nd_sweep_fires.py`
  — drive `FakeTimer` past the configured sweep interval, assert
  an expired temp-addr is removed.
- `packages/pytcp/pytcp/tests/integration/protocols/_interface/test__timer__sysctl_overrides_cadence.py`
  — set the sysctl to a different value, assert the next sweep
  fires at the new cadence.

**Modernisation-on-touch.** Touches `nd__constants.py` and
`arp__constants.py` — modernise any obsolete typing in the same
commit.

**Reversibility.** Pure relocation; revert by re-instating
`_maybe_run_periodic_tasks`.

**Effort.** M.

---

## Phase 6 — Composition over mixin inheritance

**Goal.** Each `PacketHandler<Proto><Dir>` mixin becomes a
standalone `<Proto><Dir>Handler` class. Cross-protocol calls
become explicit `self.ip6.process(pkt)` instead of MRO-resolved
`self._phrx_ip6(pkt)`. One protocol at a time, lowest-coupling
first.

**Dependencies.** Phases 3-5.

**Handler ownership.** **Per-Interface instances**, not module-
level singletons-with-context. Mirrors Linux `struct net_device`
carrying `nd_*` ops as instance methods; lets each handler hold a
back-reference to its `Interface` without a hot-path lookup;
makes per-interface dispatch tables (Phase 7) trivial.

**Deliverables.** New handler module per protocol:
- `packages/pytcp/pytcp/stack/protocols/ethernet_handler.py` — `EthernetHandler`
  with `process_rx(pkt)` and `emit_tx(*, src, dst, payload)`.
  Holds back-reference to owning `Interface`.
- `packages/pytcp/pytcp/stack/protocols/{ethernet_802_3_handler,arp_handler,
  ip4_handler,ip6_handler,ip6_frag_handler,icmp4_handler,
  icmp6_handler,tcp_handler,udp_handler}.py` — analogous.
- A new `packages/pytcp/pytcp/runtime/packet_handler/__init__.py` that is **glue
  only** — instantiates the handlers, wires their cross-references,
  exposes a single `dispatch_rx(packet_rx)` entry the RX ring
  calls. Target ≤200 lines (final shape achieved after Phase 7).
- Migration order: ARP first (least cross-protocol coupling), then
  UDP, ICMPv4, ICMPv6, IPv4, IPv6, IPv6-frag, TCP, Ethernet,
  Ethernet-802.3. Each migration is a separate commit pair (test
  + impl).
- Old mixin files deleted as their handlers ship.
- Each handler module docstring carries the Phase-3 marker:
  `# Phase 3: stack-internal; not reachable across the consumer API boundary.`

**Phase-3 reach-through cleanup (on-touch).** The handler-
extraction commits touch every mixin's call sites. Any test that
reaches into mixin internals (`_phrx_ip6`, etc.) for assertions
migrates to drive_rx + probe pattern in the same commit.

**Tests.** All prior phases + legacy stay green throughout. Each
per-protocol migration adds a
`packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__<proto>__handler_composition.py`
that asserts the handler can be instantiated standalone (i.e.
without the god-class) and that its RX/TX entries behave
identically to the pre-migration mixin path. Tests-first commit
ships **before** the mixin is deleted.

**Modernisation-on-touch.** Each new handler file uses modern
forms by construction; per-mixin migration commit fixes obsolete
forms in the touched call sites.

**Reversibility.** Per-protocol — each migration is an
independent commit set. Revert one without affecting the others.

**Effort.** XL. Biggest behavioral-equivalence work.

---

## Phase 7 — Registration-table dispatch

**Goal.** Replace `match`/`case` EtherType dispatch in
`_phrx_ethernet` and `match`/`case` IpProto dispatch in
`_phrx_ip6.__walk_chain` with registry tables. Per-Interface
registries so an L3 interface does not register the Ethernet
handler.

**Dependencies.** Phase 6.

**Deliverables.**
- `packages/pytcp/pytcp/stack/dispatch.py` — new file. `EthertypeRegistry`,
  `IpProtoRegistry`, `Ip6ExtensionHeaderRegistry` — typed dict
  classes mapping a wire codepoint to a callable
  `(packet_rx) -> None`.
- `packages/pytcp/pytcp/stack/interface.py` —
  `Interface.register_default_handlers()` builds the registries
  based on `self.layer` and per-AF support flags. L2 interface
  registers ARP/IP4/IP6 in the EtherType registry; L3 interface
  registers only IP4/IP6 in a TUN-PI registry.
- `packages/pytcp/pytcp/stack/protocols/ethernet_handler.py::process_rx` —
  replaces the `match`/`case` with
  `self._interface.ethertype_registry.dispatch(packet_rx.ethernet.type, packet_rx)`.
- `packages/pytcp/pytcp/stack/protocols/ip6_handler.py::_walk_chain` — same
  conversion for the EH chain.

**Phase-3 reach-through cleanup (on-touch).** None — dispatch is
stack-internal.

**Tests.** All prior phases + legacy stay green. New:
- `packages/pytcp/pytcp/tests/integration/protocols/_interface/test__registry__l2_l3_difference.py`
  — assert an L3 `Interface`'s EtherType registry is empty (no
  ARP); unknown EtherType on L2 still produces the existing
  `ethernet__no_proto_support__drop` stat bump.
- `packages/pytcp/pytcp/tests/integration/protocols/_interface/test__registry__custom_handler.py`
  — register a fake handler in the test, drive a frame, assert
  the fake handler ran. Pins that the registry is the *only*
  dispatch path; future protocol additions cannot regress to
  `if/elif`.

**Modernisation-on-touch.** Touches every handler module — fix
any residual obsolete forms.

**Reversibility.** Per dispatch table.

**Effort.** M.

---

## Phase 8 — Multi-interface activation + Address API + Neighbor API

**Goal.** Lift the singleton constraint. The stack runs N
interfaces, each with its own RX/TX ring threads, its own handler
set, its own caches. Ship the **Address API** (`pytcp.stack.address`)
and **Neighbor API** (`pytcp.stack.neighbor`) as the consumer
surfaces backed by per-Interface state.

**Dependencies.** Phases 3-7.

**Deliverables.**
- `packages/pytcp/pytcp/stack/__init__.py` — `init()` is renamed to
  `add_interface(*, name, layer, mtu, mac=None, ...)`; called
  once per interface. The old single-shot `init(...)` becomes a
  thin wrapper that calls `add_interface` once and sets the
  `default_interface` shortcut.
- `packages/pytcp/pytcp/stack/__init__.py` — `start()` / `stop()` iterate
  `stack.interfaces.values()`. Legacy module-level aliases
  (`rx_ring`, `tx_ring`, `arp_cache`, `nd_cache`,
  `packet_handler`) are removed; remaining call sites route
  through `stack.interfaces[name].<x>` or
  `stack.default_interface.<x>`.
- The socket layer's outbound TX (today goes to `stack.tx_ring`)
  is updated to choose interface via FIB lookup (Phase 9 wires
  this; here the choice is "default interface").
- `stack.sockets` stays a global dict, keyed by `SocketId`
  (which carries the local IP); inbound RX delivery uses that
  key.
- `NeighborCache` becomes per-Interface — each Interface
  constructs its own `ArpCache`/`NdCache`. Module-level
  `arp_cache` / `nd_cache` aliases deleted.
- **`packages/pytcp/pytcp/stack/address/__init__.py` — Address API.** Public
  functions:
  - `add_ip4(*, ifname: str, host: Ip4IfAddr) -> None`
  - `remove_ip4(*, ifname: str, address: Ip4Address) -> None`
  - `add_ip6(*, ifname: str, host: Ip6IfAddr) -> None`
  - `remove_ip6(*, ifname: str, address: Ip6Address) -> None`
  - `flush(*, ifname: str, family: AddressFamily) -> None`
  - `list_ip4(*, ifname: str) -> tuple[Ip4HostSnapshot, ...]`
  - `list_ip6(*, ifname: str) -> tuple[Ip6HostSnapshot, ...]`
- **`packages/pytcp/pytcp/stack/neighbor/__init__.py` — Neighbor API.** Public
  functions:
  - `add_static_arp(*, ifname: str, ip: Ip4Address, mac: MacAddress) -> None`
  - `add_static_nd(*, ifname: str, ip: Ip6Address, mac: MacAddress) -> None`
  - `remove(*, ifname: str, ip: Ip4Address | Ip6Address) -> None`
  - `flush(*, ifname: str, family: AddressFamily) -> None`
  - `list_arp(*, ifname: str) -> tuple[NeighborSnapshot, ...]`
  - `list_nd(*, ifname: str) -> tuple[NeighborSnapshot, ...]`

**Phase-3 reach-through cleanup (on-touch).**
- DHCP4 client's `Ip4IfAddr.gateway = ...` mutation migrates to
  `pytcp.stack.address.add_ip4(...)` + `pytcp.stack.route.add(...)`
  (the route part is a forward reference to Phase 9's Route API,
  which is already specified). Cleaned in this commit using a
  thin shim if Phase 9 has not landed yet.
- `stack.mock__init` callers in tests migrate to per-API calls.
- Examples that touch `_ip6_ifaddr`, `_ip4_ifaddr`, etc. directly
  migrate to the Address API.

**Tests.** All prior phases + legacy stay green. New:
- `packages/pytcp/pytcp/tests/integration/protocols/_interface/test__multi_interface__rx_isolation.py`
  — two interfaces, frame into A, assert no TX on B and B's
  stats are zero.
- `packages/pytcp/pytcp/tests/integration/protocols/_interface/test__multi_interface__arp_caches_are_separate.py`
  — populate ARP cache on A, assert lookup on B misses.
- `packages/pytcp/pytcp/tests/integration/protocols/_interface/test__multi_interface__nd_dad_concurrent.py`
  — DAD claims on A and B for the same address run independently.
- `packages/pytcp/pytcp/tests/integration/api/address/test__address__add_remove_ip4.py`,
  `test__address__add_remove_ip6.py`,
  `test__address__flush.py`,
  `test__address__list_immutable.py`.
- `packages/pytcp/pytcp/tests/integration/api/neighbor/test__neighbor__add_static_arp.py`,
  `test__neighbor__add_static_nd.py`,
  `test__neighbor__flush.py`,
  `test__neighbor__list_immutable.py`.

**Modernisation-on-touch.** Touches `stack/__init__.py`, every
test that called `mock__init` directly, every example. Substantial
modernisation in the same commits.

**Reversibility.** Hardest of any phase to revert because the
singleton aliases are deleted. Mitigate by keeping
`stack.default_interface` shortcut indefinitely so the common
single-interface case stays terse.

**Effort.** XL.

---

## Phase 9 — FIB + `forward_or_deliver` seam + Route API

**Goal.** Stand up a FIB and a `forward_or_deliver()` seam in the
IP RX paths so Phase-2 forwarding work is mechanical. Ship the
**Route API** (`pytcp.stack.route`) as the consumer surface backed
by the FIB. Hardcoded routes initially; the *extension surface* is
what matters.

**Dependencies.** Phase 8.

**Routing layer placement.** New subsystem `packages/pytcp/pytcp/stack/routing/`.
Linux equivalent: `net/ipv4/fib_*.c` and `net/ipv6/route.c`. The
FIB is a stack-level singleton (mirrors Linux's per-net-namespace
`struct net.ipv4.fib_main`); per-interface "connected" routes are
auto-installed when an Interface gains an address.

**Forwarding seam.** Goes into `Ip6Handler.process_rx` and
`Ip4Handler.process_rx` immediately after the parser succeeds and
**before** the destination-is-mine check. Contract: parse → FIB
lookup → if egress is "this stack as host" deliver upstream as
today; otherwise call `forward_or_deliver` which in Phase 1 just
returns "drop" (and bumps a Phase-2-tracking counter). Forward
path cannot run before parse; forward-or-deliver must run before
upper-layer demux because demux implies delivery. For IPv6, this
happens between IP parse and EH chain walk for delivered-locally
packets; the EH walk for forwarded packets is a Phase-2 concern
marked `# Phase 2: forwarding path`.

**Deliverables.**
- `packages/pytcp/pytcp/stack/routing/__init__.py` — package marker.
- `packages/pytcp/pytcp/stack/routing/fib.py` — `Fib` class, single global
  `stack.fib: Fib`. Methods `lookup(dst) -> FibResult` (with
  `result.egress_interface`, `result.next_hop`, `result.is_local`,
  `result.is_blackhole`).
- `packages/pytcp/pytcp/stack/routing/fib_entry.py` — `FibEntry` dataclass
  (prefix, next-hop, egress interface, metric, source:
  connected/static/RA-learned).
- `packages/pytcp/pytcp/stack/interface.py` — when an `Interface` gains a host
  address (via the Address API from Phase 8), install a connected
  route into `stack.fib`. When an RA arrives carrying a default
  router, install a default route via that interface (Phase 1
  hosts only consume RAs; this is the hook Phase 2 grows).
- `packages/pytcp/pytcp/stack/protocols/ip6_handler.py::process_rx` — insert FIB
  lookup + `forward_or_deliver` seam.
- `packages/pytcp/pytcp/stack/protocols/ip4_handler.py::process_rx` — same.
- `packages/pytcp/pytcp/stack/protocols/ip6_handler.py::forward_or_deliver` —
  Phase-1 stub: log + increment `ip6__forward_drop` stat. Marked
  `# Phase 2: full forwarding implementation here`.
- `packages/pytcp/pytcp/stack/protocols/icmp4_handler.py` and
  `icmp6_handler.py` — stub `_emit_redirect()` (RFC 1812 §5.2.7.2),
  wired-but-unreachable in Phase 1. Marked `# Phase 2`.
- TX path egress-selection: `Ip6Handler.emit_tx` and
  `Ip4Handler.emit_tx` consult
  `stack.fib.lookup(dst).egress_interface` to choose which
  Interface's `tx_ring` to enqueue on.
- **`packages/pytcp/pytcp/stack/route/__init__.py` — Route API.** Public
  functions:
  - `add(*, prefix: Ip4Network | Ip6Network, gateway: Ip4Address | Ip6Address | None = None, ifname: str | None = None, metric: int = 0) -> None`
  - `remove(*, prefix: Ip4Network | Ip6Network, gateway: Ip4Address | Ip6Address | None = None) -> None`
  - `list(*, family: AddressFamily | None = None) -> tuple[RouteSnapshot, ...]`
  - `lookup(*, dst: Ip4Address | Ip6Address) -> RouteSnapshot | None`
  - `default_route(*, family: AddressFamily) -> RouteSnapshot | None`
- The Phase 4 introspection stub for `routes()` becomes real: it
  delegates to `route.list()`.

**Phase-3 reach-through cleanup (on-touch).**
- DHCP4 client's gateway-install path (started in Phase 8)
  completes — `pytcp.stack.route.add(prefix=Ip4Network("0.0.0.0/0"),
  gateway=...)`.
- `Ip4IfAddr.gateway` attribute and `Ip6IfAddr.gateway` attribute are
  marked `# Phase 3: implementation detail of the address store;
  not the consumer-facing route`. They stay for now (still used
  internally by route insertion), but consumer code never reads
  or writes them after this phase.

**Tests.** All prior phases + legacy stay green. New:
- `packages/pytcp/pytcp/tests/integration/protocols/_interface/test__fib__lookup_local.py`
  — packet for our own address resolves to `is_local=True`.
- `packages/pytcp/pytcp/tests/integration/protocols/_interface/test__fib__lookup_off_link.py`
  — packet for off-link destination resolves to default route via
  the right interface.
- `packages/pytcp/pytcp/tests/integration/protocols/_interface/test__fib__forward_drops.py`
  — Phase-1 stub: a transit packet gets dropped + the counter
  bumps. Phase 2 will flip this test green by implementing the
  forward path.
- `packages/pytcp/pytcp/tests/integration/protocols/_interface/test__multi_interface__egress_selection.py`
  — two interfaces, two FIB entries, packet to dest A egresses
  interface A, packet to dest B egresses interface B.
- `packages/pytcp/pytcp/tests/integration/api/route/test__route__add_remove.py`,
  `test__route__list_immutable.py`,
  `test__route__lookup.py`,
  `test__route__connected_auto_install.py`.

**Modernisation-on-touch.** Touches IP-RX paths and the DHCP4
client — modernise typing in the same commits.

**Reversibility.** FIB module and Route API are independent;
remove `forward_or_deliver` calls and delete the modules to
revert.

**Effort.** L (FIB + seam) + M (Route API + tests).

---

## Phase 10 — Cleanup

**Goal.** Retire the legacy harness once the new harness equals
coverage; delete dead code; remove the `NetworkTestCase` compat
alias; the new `packages/pytcp/pytcp/runtime/packet_handler/__init__.py` is ≤200
lines of glue. Final reach-through residue cleanup.

**Dependencies.** All prior phases.

**Deliverables.**
- Delete `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__*__rx.py`
  / `__tx.py` (17 files) — only after coverage diff confirms the
  new harness's tests cover every behavior the old tests pinned.
  Delete the `NetworkTestCase` compat alias in
  `packages/pytcp/pytcp/tests/lib/network_testcase.py`.
- Delete every `packet_handler__*__rx.py` / `__tx.py` mixin file
  (20 files).
- `packages/pytcp/pytcp/runtime/packet_handler/__init__.py` reduced to
  `PacketHandler` glue + dispatch entry. Verify ≤200 lines.
- Verify `packages/pytcp/pytcp/stack/__init__.py` no longer carries module-level
  subsystem singletons; only the multi-interface dict + cross-
  interface globals (TCP stack, PMTU cache, ICMP rate limiters)
  remain.
- Final pass on the
  `docs/refactor/packet_handler_phase3_violations.md` inventory:
  every entry must be marked `done`. Any remaining entries are
  pulled into a Phase-11 follow-up doc.

**Tests.** Full suite green. The §7.2 docstring audit passes for
every test file changed.

**Modernisation-on-touch.** Final sweep — any obsolete forms in
the deleted-and-replaced files are gone by definition.

**Reversibility.** Cleanup-only; revert is git-revert.

**Effort.** S.

---

## Design decisions to confirm before Phase 0

| # | Decision | Recommendation | Rationale |
|---|----------|----------------|-----------|
| 1 | Top-level `Interface` class? | **Yes**, in `packages/pytcp/pytcp/stack/interface.py`, owns rings + per-AF device-config sub-objects. | Mirrors Linux `struct net_device`; without it multi-interface is structurally impossible. |
| 2 | Per-interface vs global state split | **Per-interface**: addresses, multicast, MTU, DAD, ARP ACD, RA-learned routers, SLAAC tables, frag-ID counters. **Global**: TCP stack, PMTU cache, ICMP rate limiters, FIB. | Matches Linux's `in_device`/`inet6_dev` vs `net.ipv4.fib_main` boundary. |
| 3 | Handler ownership | **Per-Interface instances** of each `<Proto><Dir>Handler`, with back-reference to owning Interface. | Per-interface dispatch tables (Phase 7) become trivial; cross-handler calls do not need an interface parameter. |
| 4 | Dispatch/registration | **Per-Interface registries** populated by the Interface based on layer + AF support. | An L3 interface does not register the Ethernet handler; per-interface `# disable IPv6` becomes a one-line change. |
| 5 | Routing layer placement | New subsystem `packages/pytcp/pytcp/stack/routing/` with global `Fib`; `Interface` installs connected routes on address gain. | Mirrors Linux `net/route.c` boundary; keeps FIB out of `packages/pytcp/pytcp/stack/__init__.py`. |
| 6 | Forwarding seam | `forward_or_deliver` called from `IpXHandler.process_rx` immediately after parse and **before** the destination-is-mine check, with Phase-1 stub that always drops transit traffic. | Cannot run before parse; must run before upper-layer demux because demux implies delivery. |
| 7 | Test harness migration | **Replace** `NetworkTestCase` with `PacketHandlerTestCase`; legacy harness becomes a thin alias deleted in Phase 10. | Cleanest end state; migration cost bounded by Phase 2 backfill. |
| 8 | Phase-3 API delivery model | **Inline** — each phase ships its API alongside the structural work; no end-of-rewrite facade. Five new modules: `pytcp.stack.{link,address,route,neighbor,introspection}`. | Each plane has a distinct surface per CLAUDE.md; a single facade would foreclose the seven-API model. |
| 9 | Reach-through cleanup cadence | **On-touch**, per `feature_implementation.md` modernisation-on-touch rule. Phase 0 inventories; each later phase fixes the violations its commits touch. | No separate sweep commit; the fix lands with the feature that touched the file. |

## Linux-as-tiebreaker citations

For each ambiguous interface-model decision, the Linux equivalent is
named for the audit trail:
- Per-interface object: `struct net_device` in
  `include/linux/netdevice.h`.
- Per-AF per-interface state: `struct in_device`
  (`include/linux/inetdevice.h`) for IPv4, `struct inet6_dev`
  (`include/net/if_inet6.h`) for IPv6.
- Neighbour cache keyed on `(ifindex, addr)`: `struct neighbour`
  in `include/net/neighbour.h`.
- ARP defend / probe state: `struct arp_neigh_priv` in
  `net/ipv4/arp.c`.
- Per-interface ND parameter overrides: `struct nd_default_router`
  and `idev->cnf` in `net/ipv6/ndisc.c`.
- FIB: `struct fib_table` per AF per net-namespace in
  `net/ipv4/fib_*.c` and `net/ipv6/route.c`.
- RFC 7217 stable secret: `idev->stable_secret` (per-interface in
  Linux; PyTCP defers per-interface and keeps per-process for
  Phase 1).
- ICMP error rate limit: `net/ipv4/icmp.c` `icmp_xrlim_allow`
  (Linux's is per-route via `inetpeer`; PyTCP's per-AF singleton
  is a deliberate Phase-1 simplification).
- Netlink RTM_* family for the management plane: `net/core/rtnetlink.c`
  is the closest analog to the `pytcp.stack.{link,address,route,neighbor}`
  API split.

## Risks & open questions

1. **Cross-interface fragmentation.** Linux keys reassembly per-net-
   namespace, *not* per-interface. **Recommendation:** keep the
   fragment table global (cross-interface), against the per-interface
   rule of thumb. Needs explicit confirmation.
2. **Socket bind-to-device.** When multi-interface lands, the BSD
   socket layer needs an `SO_BINDTODEVICE` analogue or `socket_id`
   needs an interface dimension. Today `SocketId` keys on local IP;
   that *implicitly* selects an interface but only when the IP is
   unique. **Defer to follow-up; mark with `# Phase 2 (multi-interface
   socket binding)`.** Outbound path uses FIB lookup's egress-
   interface choice in Phase 9.
3. **Netdev event model.** Linux has `notifier_chain` for events
   like NETDEV_UP/DOWN/CHANGEADDR. PyTCP currently has none.
   **Recommendation:** out-of-scope for this rewrite; add TODO in
   `packages/pytcp/pytcp/stack/interface.py`. Becomes a follow-up alongside
   long-term Phase-3 daemon-mode IPC work.
4. **Phase-2 forwarding interaction with HBH/RH.** Forwarders must
   process HBH but must *not* consume the segment-1 destination of
   a Routing header. Phase 9 stub does not need to handle this,
   but the seam must be placed *before* the chain walker so Phase 2
   can split walk-as-destination from walk-as-forwarder. Confirmed
   in Phase 9 deliverables.
5. **ICMP error emission from the forwarder.** Phase 2 needs ICMP
   errors emitted with the original packet's IP source as the
   destination, not with the host's address as the source. Current
   `try_emit_icmp_error` is host-shaped. **Recommendation:** flag
   with `# Phase 2 (forwarder error emission)` in
   `packages/pytcp/pytcp/protocols/icmp/icmp__error_emitter.py`.
6. **`stack.mock__init` after Phase 8.** Current single-singleton
   `mock__init` does not generalise to N interfaces. The new
   harness uses per-API calls (`pytcp.stack.link.add(...)`,
   `pytcp.stack.address.add_ip4(...)`) instead. `mock__init` may
   be retained as a single-interface convenience wrapper or
   deleted — decide in Phase 8.
7. **DHCPv6 client.** Future Phase-1 protocol. The new handler-
   composition model (Phase 6) and per-interface registries
   (Phase 7) make this clean: one new `Dhcp6ClientHandler` per
   Interface that registers in the UDP demux. Worth confirming
   this is the intended landing site.
8. **MLD/IGMP querier role.** Phase-2 router work. Interface object
   should reserve a slot for "is querier" but not implement it.
   Same for `Ip6Handler`'s "are we a router" flag — defaults to
   False, gates redirect generation, reserved for Phase 2.
9. **Daemon-mode IPC transport.** The five Phase-3 API modules
   are pure in-process Python today. Future daemon-mode work
   (separate process, AF_UNIX + SCM_RIGHTS for fd passing,
   request/response RPC for management plane) replaces the
   *implementation* of those modules without changing the
   surface. Out of scope for this rewrite; the API shape is
   what makes that future work mechanical.
10. **Examples migration.** The `examples/` directory will need
    a sweep to migrate any internal-state reach-throughs to the
    five new APIs. Captured per-example in Phase 0's violations
    inventory; cleaned on-touch as each phase exercises the
    relevant API.

## Critical files for implementation

- `/root/PyTCP/packages/pytcp/pytcp/runtime/packet_handler/__init__.py` — the
  2040-line god-class being decomposed; the plan's gravity well.
- `/root/PyTCP/packages/pytcp/pytcp/stack/__init__.py` — module-level singletons
  that become per-Interface; the multi-interface activation
  surface.
- `/root/PyTCP/packages/pytcp/pytcp/tests/lib/tcp_testcase.py` — reference
  design for the new `PacketHandlerTestCase`; the proven
  snapshot-and-restore pattern to mirror.
- `/root/PyTCP/packages/pytcp/pytcp/lib/neighbor.py` — `NeighborCache[A]` already
  generic; per-Interface keying lives here in Phase 4/8.
- `/root/PyTCP/packages/pytcp/pytcp/runtime/packet_handler/packet_handler__ip6__rx.py`
  — IPv6 RX path where the `forward_or_deliver` seam lands in
  Phase 9; the most spec-loaded file outside the god-class.
- `/root/PyTCP/packages/pytcp/pytcp/lib/dhcp4_client.py` — canonical Phase-3
  reach-through (mutates `Ip4IfAddr.gateway` directly); migrates
  through Phase 8 (Address API) + Phase 9 (Route API).
