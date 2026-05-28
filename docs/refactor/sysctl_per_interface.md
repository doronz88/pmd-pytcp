# PyTCP sysctl — per-interface namespace migration

**Status:** Phase 0 SHIPPED 2026-05-28 (registry scaffold +
24 tests + helper module). Phase 1 (ARP, 4 knobs) SHIPPED
2026-05-28. Phase 2 (Neighbor cache, 6 knobs) SHIPPED
2026-05-28. Phase 3 (ICMPv6 / ND, 22 knobs) SHIPPED
2026-05-28. Phase 4 (IPv4 conf-plane, 2 knobs) SHIPPED
2026-05-28. Phase 5 (close-out) remains. Successor to
`docs/refactor/sysctl_migration_remaining.md` (the flat-namespace
migration that closed earlier the same day with three commits —
`d0a25807` TCP, `812f02d8` ICMP rate-limiter, `7b281322` stack-wide).
This document scopes the next layer: promoting the conf-plane and
neighbor-plane sysctls from a single global value to per-interface
slots, matching Linux's `net.<family>.{conf,neigh}.<iface>.<knob>`
shape.

## 0. TL;DR

- Multi-interface runtime is **already shipped** (commit `e5dc77f5`,
  2026-05-23). Every interface owns its own `PacketHandlerL2`,
  `ArpCache`, `NdCache`, `LinkApi(ifindex)`, etc.
- Sysctl registry is **still flat** — one global `arp.ignore` value
  applies to every interface's RX handler. Operator who wants
  `arp_ignore=1` on `tap7` but `arp_ignore=2` on `tap8` has no way
  to express that today.
- This plan promotes **34 of 85** registered knobs to a per-interface
  namespace; the remaining 51 stay global by design (TCP, ICMP rate
  limiter, IGMP host parameters, ephemeral port range, fragment
  flow timeouts, RFC 5227 ARP-probe timing, etc.).
- The work splits cleanly into **five phases**. Each is one atomic
  commit per the framework's no-half-migrated rule. Estimated
  scope: ~10 commits total counting the per-namespace splits.

## 1. Why now

The flat-namespace migration (TCP + ICMP rate-limiter + stack-wide)
closed earlier the same day. Three motivating factors flip this
from a Phase-2 placeholder to a near-term workable task:

1. **The runtime is multi-interface.** The Phase-2 marker wording
   in `arp__constants.py` / `nd__constants.py` ("Phase 2: per-
   interface — mode 1 has no observable effect on single-interface
   PyTCP today") is now factually stale. PyTCP supports multiple
   interfaces; the sysctl namespace has not followed.
2. **The audit found mismatches.** `docs/refactor/sysctl_migration_remaining.md`'s
   sister audit (the post-migration cross-check) flagged the
   per-interface vs global gap as the largest remaining departure
   from Linux semantics — 34 knobs deep.
3. **Operator value is real.** A multi-homed host running with
   one trusted LAN interface and one untrusted public interface
   wants `accept_redirects=0` on public and `accept_redirects=1`
   on the trusted side, or `arp_ignore=2` on public and
   `arp_ignore=1` on trusted. Today PyTCP forces both to one
   global value.

## 2. Current state

### 2.1 Runtime

Per-interface state lives where you'd expect:

- `pytcp.stack.interfaces: dict[int, PacketHandlerL2 | PacketHandlerL3]`
  — the interface registry keyed by `ifindex`.
- Each `PacketHandler` carries its own `_arp_cache` (an
  `Ip4Address`-bound `NeighborCache` adapter), `_nd_cache`, `_tx_ring`,
  `_rx_ring`, `_interface_name`, `_mac_unicast`, `_ip4_ifaddr` list,
  `_ip6_ifaddr` list, etc.
- The Link / Address / Route / Neighbor / Membership APIs already
  expose a `.interface(ifindex)` view that scopes operations to one
  device, modeled on Linux's `ip link ... dev <ifX>`.

### 2.2 Sysctl registry

`pytcp.stack.sysctl` is flat:

- One dotted key → one `_Knob` entry → one `(module_name, attr)`
  backing pair → one Python value.
- Validators are per-knob; cross-knob constraints are per-knob-pair.
- Consumer reads via qualified module access (`arp__constants.ARP__IGNORE`)
  see the single global value regardless of which interface's RX
  handler invoked the read.

### 2.3 The gap

```
runtime side:                          sysctl side:
                                       
  stack.interfaces[1]   tap7             arp__constants.ARP__IGNORE = 1
   ├── _arp_cache                                ▲
   ├── _packet_handler                           │
   │     reads ARP__IGNORE  ───────────┐         │
   │                                    │  ALL READS LAND ON THE SAME ATTR
  stack.interfaces[2]   tap8           │         │
   ├── _arp_cache                       │         │
   ├── _packet_handler                  │         │
   │     reads ARP__IGNORE  ───────────┘
```

## 3. Per-interface candidate inventory

Linux's `Documentation/networking/ip-sysctl.rst` is the source of
truth. A knob is a per-interface candidate iff Linux exposes it
under `net.<family>.conf.<iface>.X` or `net.<family>.neigh.<iface>.X`.

### 3.1 ARP (4 of 12 knobs migrate)

| PyTCP key | Linux | Per-interface? |
|---|---|---|
| `arp.accept` | `net.ipv4.conf.<iface>.arp_accept` | ✅ migrate |
| `arp.ignore` | `net.ipv4.conf.<iface>.arp_ignore` | ✅ migrate |
| `arp.announce` | `net.ipv4.conf.<iface>.arp_announce` | ✅ migrate |
| `arp.filter` | `net.ipv4.conf.<iface>.arp_filter` | ✅ migrate |
| `arp.defend_interval` | RFC 5227 (no Linux per-iface form) | ⬜ stay global |
| `arp.probe_wait` | RFC 5227 timing | ⬜ stay global |
| `arp.probe_num` | RFC 5227 timing | ⬜ stay global |
| `arp.probe_min` | RFC 5227 timing | ⬜ stay global |
| `arp.probe_max` | RFC 5227 timing | ⬜ stay global |
| `arp.announce_num` | RFC 5227 timing | ⬜ stay global |
| `arp.announce_interval` | RFC 5227 timing | ⬜ stay global |
| `arp.announce_wait` | RFC 5227 timing | ⬜ stay global |

RFC 5227 ARP-probe / announce timing is MAC-layer behavior that
doesn't vary by interface; Linux keeps these hardcoded.

### 3.2 Neighbor cache (6 of 10 knobs migrate)

| PyTCP key | Linux | Per-interface? |
|---|---|---|
| `neighbor.reachable_time` | `net.ipv4.neigh.<iface>.base_reachable_time_ms` | ✅ migrate |
| `neighbor.retrans_timer` | `net.ipv4.neigh.<iface>.retrans_time_ms` | ✅ migrate |
| `neighbor.delay_first_probe_time` | `net.ipv4.neigh.<iface>.delay_first_probe_time` | ✅ migrate |
| `neighbor.max_unicast_solicit` | `net.ipv4.neigh.<iface>.ucast_solicit` | ✅ migrate |
| `neighbor.max_multicast_solicit` | `net.ipv4.neigh.<iface>.mcast_solicit` | ✅ migrate |
| `neighbor.unres_qlen` | `net.ipv4.neigh.<iface>.unres_qlen` | ✅ migrate |
| `neighbor.gc_thresh1` | `net.ipv4.neigh.default.gc_thresh1` (table-wide) | ⬜ stay global |
| `neighbor.gc_thresh2` | `net.ipv4.neigh.default.gc_thresh2` (table-wide) | ⬜ stay global |
| `neighbor.gc_thresh3` | `net.ipv4.neigh.default.gc_thresh3` (table-wide) | ⬜ stay global |
| `neighbor.gc_stale_time` | `net.ipv4.neigh.default.gc_stale_time` (table-wide) | ⬜ stay global |

GC thresholds + stale-time are table-wide on Linux (the per-iface
slot doesn't apply). PyTCP's neighbor cache is also per-process
table-wide; keep these in the flat namespace.

### 3.3 ICMPv6 / ND (22 of 22 knobs migrate)

Every `icmp6.*` key today maps to `net.ipv6.conf.<iface>.X` on
Linux. Full list — all migrate:

```
icmp6.accept_dad
icmp6.accept_ra_defrtr
icmp6.accept_ra_min_hop_limit
icmp6.accept_ra_pinfo
icmp6.accept_redirects
icmp6.dad_transmits
icmp6.enhanced_dad
icmp6.gratuitous_na_count
icmp6.idgen_retries
icmp6.max_desync_factor_s
icmp6.max_rtr_solicitation_delay_ms
icmp6.max_rtr_solicitations
icmp6.optimistic_dad
icmp6.regen_advance_s
icmp6.retrans_timer_ms
icmp6.rtr_solicitation_interval_ms
icmp6.rtr_solicitation_max_rt_ms
icmp6.temp_addr_sweep_interval_s
icmp6.temp_preferred_lifetime_s
icmp6.temp_valid_lifetime_s
icmp6.use_rfc7217
icmp6.use_tempaddr
```

A handful (`gratuitous_na_count`, `regen_advance_s`,
`temp_addr_sweep_interval_s`, `rtr_solicitation_interval_ms`,
`rtr_solicitation_max_rt_ms`, `max_rtr_solicitation_delay_ms`)
don't have direct Linux per-interface sysctls — Linux hardcodes
them. PyTCP exposes them as tunables for testing; the namespace
extension should still be per-interface for consistency with the
rest of the ND knobs, even when Linux has nothing equivalent.

### 3.4 IPv4 conf-plane (2 of 4 ip4 knobs migrate)

| PyTCP key | Linux | Per-interface? |
|---|---|---|
| `ip4.accept_source_route` | `net.ipv4.conf.<iface>.accept_source_route` | ✅ migrate |
| `ip4.allow_broadcast` | `net.ipv4.conf.<iface>.bc_forwarding` (broadcast forwarding) | ✅ migrate |
| `ip4.default_ttl` | `net.ipv4.ip_default_ttl` (global) | ⬜ stay global |
| `ip4.frag.flow_timeout_s` | `net.ipv4.ipfrag_time` (global) | ⬜ stay global |

`ip4.default_ttl` is Linux-global despite living in the `ipv4`
namespace. Frag flow timeout is process-wide reassembly.

### 3.5 IPv6 conf-plane (0 of 4 ip6 knobs migrate)

| PyTCP key | Linux | Per-interface? |
|---|---|---|
| `ip6.flow_label_generation` | `net.ipv6.auto_flowlabels` / `flowlabel_consistency` (global) | ⬜ stay global |
| `ip6.ext_hdr_max_options` | RFC 8504 §5.3 (PyTCP-only) | ⬜ stay global |
| `ip6.ext_hdr_max_pad_bytes` | RFC 8504 §5.3 (PyTCP-only) | ⬜ stay global |
| `ip6.ext_hdr_max_unknown_options` | RFC 8504 §5.3 (PyTCP-only) | ⬜ stay global |

Linux exposes these globally; PyTCP follows. Extension-header
resource caps would be reasonable to expose per-interface in a
future revision, but Linux's lead is to keep them global.

### 3.6 Knobs that stay global (51 total)

For greppability, the namespaces that DO NOT migrate:

- **`tcp.*`** (10) — TCP-stack-wide on Linux (`net.ipv4.tcp_*`),
  no per-iface form. Stays flat.
- **`icmp.error.*`** (2) — Global error rate limiter (Linux
  `net.ipv4.icmp_ratelimit` / `icmp_msgs_burst`). Stays flat.
- **`icmp4.echo_ignore_broadcasts`** (1) — Linux's
  `net.ipv4.icmp_echo_ignore_broadcasts` is global. Stays flat.
- **`igmp.*`** (5) — Linux's IGMP knobs are global +
  per-iface mix; PyTCP's are global only. The
  `igmp.version` / `igmp.query_interval` could become
  per-interface later when there's a real Linux-parity ask.
- **`dhcp.*`** (16) — DHCPv4 client knobs; PyTCP-specific
  application-layer tunables with no Linux kernel parallel.
  The client is already per-interface (one `Dhcp4Client` per
  L2 interface); making the sysctls per-interface is a
  reasonable follow-up but out of scope here.
- **`ip4_link_local.*`** (3) — RFC 3927 autoconfig client;
  PyTCP-specific. Same shape as DHCP — per-interface client
  exists, sysctls are global.
- **`net.ephemeral_port_range.{low,high}`** (2) — Process-wide.
- **`ip{4,6}.frag.flow_timeout_s`** (2), **`ip4.default_ttl`**,
  **`ip6.*`** (4) — Linux-global.
- **`arp.{defend_interval, probe_*, announce_*}`** (8) — RFC 5227
  MAC-layer timing, Linux-global.
- **`neighbor.{gc_thresh{1,2,3}, gc_stale_time}`** (4) — Table-wide.

Total: **34 per-interface candidates, 51 stay flat.**

## 4. Design

### 4.1 Key syntax

Linux mirrors interface NAMES, not ifindex:

```
net.ipv4.conf.eth0.arp_ignore
net.ipv6.conf.tap7.accept_redirects
net.ipv4.neigh.tap7.retrans_time_ms
```

PyTCP's `LinkApi` already surfaces interface names
(`stack.link.interface(ifindex).name`). Operator tools and
documentation already cite the interface name. So the PyTCP
key shape mirrors Linux directly:

```
arp.<ifname>.ignore                      # per-interface override
neighbor.<ifname>.retrans_timer
icmp6.<ifname>.accept_redirects
ip4.<ifname>.accept_source_route
```

**Rejected alternative:** `arp.ignore@<ifindex>` (PyTCP-native
ifindex addressing). Reasons:

- ifindex is an internal handle; humans use names.
- Linux mirroring keeps every existing `description=` field's
  citation parallel to the real key.
- Tests, docs, and operator tools all use names today.

### 4.2 The `default` pseudo-interface

Linux exposes two pseudo-interfaces in addition to the real
device names:

- **`default`** — a template for newly-attached interfaces.
  Setting `net.ipv6.conf.default.use_tempaddr = 2` does NOT
  affect any existing interface, but every interface created
  after the write inherits the value.
- **`all`** — write-fan-out. Setting `net.ipv4.conf.all.accept_redirects = 0`
  applies to every existing interface AND becomes the new default
  for future ones. Read behavior varies per-knob (some OR-across,
  some max-across, some return-default) — messy and per-knob.

**Decision:** ship `default` in this migration; defer `all` to
a follow-up if operator demand surfaces.

- `default` is genuinely useful for daemon-shaped startup
  (operator writes the template once, every subsequently-attached
  interface inherits it).
- `all` write-fan-out is convenient but the per-knob read
  semantics are messy. Operators can script "set on every
  interface" via the `stack.interfaces.keys()` introspection
  surface in the meantime.

### 4.3 Resolution chain

When a runtime consumer reads `arp.ignore` for interface
`tap7`, the registry resolves in this order:

1. `arp.tap7.ignore` (per-interface explicit override)
2. `arp.default.ignore` (template, applied when the interface
   slot is empty)
3. **Registered default** baked into the `register(...)` call
   (applied when neither slot has been set).

The `default` slot is initialized to the registered default at
boot; per-interface slots are NOT pre-populated. An interface
attached at runtime reads through `default` until an operator
sets its slot explicitly.

### 4.4 Registry shape changes

The `_Knob` dataclass grows an `interface_scope: bool` flag.
Per-interface knobs register once with the flag set:

```python
register(
    key="arp.ignore",                # base key, no <ifname>
    module_name=__name__,
    attr="ARP__IGNORE",
    default=ARP__IGNORE,
    interface_scope=True,            # NEW
    validator=...,
    description="Linux 'net.ipv4.conf.<iface>.arp_ignore'.",
)
```

Operator-side reads and writes use the full key:

```python
sysctl["arp.tap7.ignore"] = 2
sysctl["arp.default.ignore"] = 2     # template for new interfaces
sysctl.get("arp.tap7.ignore")
sysctl.get("arp.default.ignore")
```

The base key `arp.ignore` (no interface segment) is **rejected
by the registry** for interface-scope knobs — operators must
specify `tap7` or `default`.

### 4.5 Storage shape changes

The flat module-level attribute (`arp__constants.ARP__IGNORE = 1`)
is REPLACED by a per-interface map:

```python
# arp__constants.py
ARP__IGNORE: dict[str, int] = {"default": 1}
```

Key: interface name (`"tap7"`) or `"default"`. Reads via
qualified module access lookup with fallback:

```python
def _arp_ignore_for(ifname: str) -> int:
    return arp__constants.ARP__IGNORE.get(
        ifname,
        arp__constants.ARP__IGNORE["default"],
    )
```

The sysctl registry's `set()` updates the dict in place; `get()`
returns the dict value at the supplied interface name. The
registered `default=` carries the initial template value.

**Helper module** — `pytcp.stack.sysctl_iface` exports a small
set of helpers consumers call instead of doing the dict-lookup
inline:

```python
from pytcp.stack import sysctl_iface

# inside a packet handler that knows its own _interface_name:
value = sysctl_iface.get_for_iface("arp.ignore", self._interface_name)
```

The helper centralizes the fallback chain and stays grep-able.

### 4.6 Consumer-side reads

Today (flat):

```python
if arp__constants.ARP__IGNORE == 2 and not on_local_subnet:
    return  # drop
```

After (per-interface):

```python
arp_ignore = sysctl_iface.get_for_iface("arp.ignore", self._interface_name)
if arp_ignore == 2 and not on_local_subnet:
    return  # drop
```

Every consumer of a per-interface knob updates in lockstep with
the registry shape change. Since every consumer is per-interface
runtime code (packet handlers, neighbor caches), the
`self._interface_name` argument is always in scope.

### 4.7 Test fixture impact

`NetworkTestCase` already snapshots `stack.__dict__`. The
per-interface storage lives on the constants modules, so
snapshot/restore should already cover the dict — verify in
phase 1.

Tests that currently mutate `stack.IP4__ACCEPT_SOURCE_ROUTE = True`
directly need to flip to one of:

- `with sysctl.override("ip4.tap7.accept_source_route", True): ...`
- Setting `IP4__ACCEPT_SOURCE_ROUTE["tap7"] = True` directly
  (preserves the test-side direct-attribute idiom)

The harness `_STACK__PATCHED_ATTRS` snapshot still covers the
storage attribute (which is now a dict; the dict identity is
restored, NOT a deep snapshot — verify per-test cleanup hygiene).

## 5. Phased rollout

Each phase is one atomic commit per the framework's no-half-
migrated rule. Push only when the user asks.

### Phase 0 — registry scaffolding (SHIPPED 2026-05-28)

Extended `pytcp.stack.sysctl` for interface-scope knobs:

- Added `interface_scope: bool = False` to `_Knob`.
- Added `_resolve_with_iface(key)` parser: if the registered
  knob is `interface_scope=True`, the operator-supplied key
  must be `<namespace...>.<ifname>.<field>` (the ifname is
  the second-to-last segment, matching Linux); bare base key
  is rejected with a self-explanatory `KeyError`.
- `set()` / `get()` dispatch on `(knob, ifname)` from the
  resolver; per-iface writes land in `storage[<ifname>]`;
  per-iface reads fall back through the chain
  `storage[<ifname>]` → `storage["default"]`.
- `reset_to_defaults()` replaces the per-interface dict with
  a fresh `{"default": <registered>}`.
- `snapshot()` returns the full per-interface dict for
  interface-scope knobs (operator debug-dump surface).
- New helper module `pytcp.stack.sysctl_iface` with
  `get_for_iface(base_key, ifname)` and
  `set_for_iface(base_key, ifname, value)` — the runtime read
  / write path for per-interface consumers; both reject flat
  keys with a helpful `KeyError`.
- New test file `tests/unit/stack/test__stack__sysctl_iface.py`
  — 24 tests pinning every aspect of the new shape:
  registration flag, per-iface set / get / fallback / unknown
  ifname, bare-base rejection, validator run-through, reset
  semantics, helper surface, override round-trip, list_keys
  bounded-by-base, snapshot dict surface.

No production code reads the new API yet. Pure scaffold
commit; the per-package migrations in Phases 1–4 will flip
each `*__constants.py` policy attribute from scalar to
`dict[str, T]` with `{"default": <scalar>}` initial state
and register with `interface_scope=True`.

Decisions taken in this commit body for the §8 open questions:

- **Q1 (write for absent ifname):** accepted. Pre-attach
  config persists in `storage[<ifname>]` until reset;
  matches Linux `sysctl -w net.ipv4.conf.fake0.arp_ignore=2`.
- **Q2 (detach):** the slot persists across detach (matches
  Linux). Will be re-validated in Phase 1 when the first
  consumer (ARP) lands.
- **Q3 (introspection helpers):** `sysctl.snapshot()` already
  surfaces the per-interface dict for interface-scope knobs,
  so the dedicated `sysctl_iface.snapshot()` /
  `sysctl_iface.list_keys()` helpers were not added — defer
  to Phase 5 close-out if operator demand emerges.
- **Q4 (`all` pseudo-interface):** deferred per the plan.
  Only `default` is wired; `all` write-fan-out can land
  later as an additive helper without touching the registry
  shape.

Commit: `<filled-in-by-commit>` on `PyTCP_3_0_6`. 24 new
tests, 11828 total green.

### Phase 1 — ARP (SHIPPED 2026-05-28)

Migrated the 4 ARP conf-plane knobs:

- `arp.accept`, `arp.ignore`, `arp.announce`, `arp.filter`
- Storage: `arp__constants.ARP__{ACCEPT,IGNORE,ANNOUNCE,FILTER}`
  flipped from `int` to `dict[str, int]` with
  `{"default": <value>}` initial state; registrations carry
  `interface_scope=True`.
- Consumers (4 sites): `packet_handler__arp__rx.py` (`ARP__ACCEPT`
  one site, `ARP__IGNORE` two sites) and
  `packet_handler__arp__tx.py` (`ARP__ANNOUNCE` one site)
  flipped to
  `sysctl_iface.get_for_iface("arp.<field>", self._if._interface_name)`.
- Helper widened: `sysctl_iface.get_for_iface(base, ifname:
  str | None)` accepts `None` (test fixtures with no
  `interface_name` plumbed through) and resolves directly
  to the `"default"` slot.
- Stale "Phase 2: per-interface" comment stripped from
  `ARP__FILTER`'s docstring; description rewritten to
  reflect actual multi-interface behaviour.
- New test file
  `tests/integration/protocols/arp/test__arp__sysctl_per_interface.py`
  (5 tests, two-interface fixture): kill-switch scoped to
  one iface, off-subnet accept scoped to one iface,
  `default`-slot template applies to every iface without an
  override, bare-base-key rejection, pre-attach config
  persists across the live-process lifetime and is cleared
  by `reset_to_defaults`.
- Existing test files updated in lockstep:
  - `tests/unit/protocols/arp/test__arp__constants.py` — the
    `ARP__ANNOUNCE` / `ARP__FILTER` default-value checks
    became `ARP__X["default"]`; every
    `sysctl_module.set("arp.<field>", v)` /
    `.override("arp.<field>", v)` became
    `"arp.default.<field>"`.
  - `tests/unit/runtime/packet_handler/test__runtime__packet_handler__arp__{rx,tx}.py`
    — `_StubInterface` carries `_interface_name`; every
    bare-base-key override became `arp.default.<field>`.

Commit: `<filled-in-by-commit>` on `PyTCP_3_0_6`. 5 new
tests + 31 unit tests modernised, 11833 total green.

### Phase 2 — Neighbor cache (SHIPPED 2026-05-28)

Migrated 6 of 10 `neighbor.*` knobs (the per-interface
subset). The four table-wide GC knobs (`gc_thresh{1,2,3}` +
`gc_stale_time`) stay flat — Linux runs neighbour-table GC
over the unified table.

- Storage: 6 dict promotions in `lib/neighbor__constants.py`
  (`NEIGHBOR__REACHABLE_TIME`,
  `NEIGHBOR__DELAY_FIRST_PROBE_TIME`,
  `NEIGHBOR__RETRANS_TIMER`,
  `NEIGHBOR__MAX_UNICAST_SOLICIT`,
  `NEIGHBOR__MAX_MULTICAST_SOLICIT`,
  `NEIGHBOR__UNRES_QLEN`) → `dict[str, int]` with
  `{"default": <value>}` initial state. The four GC knobs
  remain plain `int`.
- Plumbing: `NeighborCache` base gains a class-level
  `_iface_name: str | None = None` attribute. `stack/lifecycle.py`
  sets `arp_cache._iface_name = interface_name` /
  `nd_cache._iface_name = interface_name` right after the
  `_owner` binding (both L2 and L3 paths).
- Consumers (6 sites in `lib/neighbor.py`): the FSM loop
  resolves all five timing knobs once per iteration through
  `sysctl_iface.get_for_iface("neighbor.<field>", iface)`;
  the `_enqueue_pending` consumer reads the queue cap the
  same way.
- New behavioural pin
  `tests/unit/lib/test__lib__neighbor__sysctl_per_interface.py`
  (4 tests, two-cache fixture binding `_iface_name` to
  `"tap_a"` / `"tap_b"`): per-iface `unres_qlen` constrains
  one cache's queue while the other inherits the default,
  per-iface `reachable_time` flips one cache's
  REACHABLE → STALE transition without affecting the other,
  bare-base-key rejection, GC thresholds stay flat
  (per-iface form on a flat key rejected).
- Existing tests updated in lockstep:
  - `tests/unit/lib/test__lib__neighbor.py` —
    `"neighbor.reachable_time"` / `"neighbor.unres_qlen"`
    overrides became `"neighbor.default.X"`; default-value
    check reads `NEIGHBOR__REACHABLE_TIME["default"]`.
  - `tests/unit/stack/test__stack__init.py` — two
    `assertGreater(NEIGHBOR__X, 0)` checks updated to
    `NEIGHBOR__X["default"]`.
  - `tests/unit/protocols/arp/test__arp__cache.py`,
    `tests/unit/protocols/icmp6/nd/test__nd__cache.py` —
    bare-base override → `"neighbor.default.reachable_time"`.

Commit: `<filled-in-by-commit>` on `PyTCP_3_0_6`. 4 new
tests, 11838 total green.

### Phase 3 — ICMPv6 / ND (SHIPPED 2026-05-28)

The biggest single phase. All 22 `icmp6.*` knobs migrated
together per the no-half-migrated rule.

- Storage: 22 dict promotions in
  `protocols/icmp6/nd/nd__constants.py` (every
  registered `ICMP6__X` scalar → `dict[str, T]` with
  `{"default": <value>}` initial state; the
  `ICMP6__SLAAC__TWO_HOUR_RULE_S` constant remains scalar
  — it's a protocol invariant, not a knob).
- Each migrated `register(...)` call now carries
  `interface_scope=True`; the registered `default=` is the
  scalar template that seeds the `"default"` slot.
- Consumer-side updates (28 production-code sites):
  - `packet_handler__icmp6__rx.py` (3 sites: `accept_ra_pinfo`,
    `accept_ra_defrtr`, `accept_redirects`).
  - `packet_handler__icmp6__tx.py` (1 site:
    `gratuitous_na_count`).
  - `packet_handler__ip6__tx.py` (1 site: `use_tempaddr`
    inside the §6724 rule-7 source-address selector).
  - `runtime/packet_handler/__init__.py` (25 sites across
    SLAAC mint / temp-addr regen / RA min-hop-limit / RS
    backoff / RFC 7217 IID gen / DAD initial-delay /
    enhanced DAD / accept_dad / use_rfc7217 /
    optimistic_dad / idgen_retries / temp_addr_sweep).
  - All consumer reads go through
    `sysctl_iface.get_for_iface("icmp6.<field>",
    self._interface_name)` (PacketHandler) or
    `sysctl_iface.get_for_iface("icmp6.<field>",
    self._if._interface_name)` (sub-handlers).
- New behavioural pin
  `tests/integration/protocols/icmp6/nd/test__icmp6__nd__sysctl_per_interface.py`
  (4 tests): registry-meta check that all 22 knobs are
  `interface_scope=True`, bare-base-key rejection, default-
  slot template applies to unnamed iface, per-iface override
  scoped to one iface only. Red before Phase 3 (bare key
  registered as flat); green after.
- Bulk-modernised 20 existing ICMPv6/ND integration tests
  and 1 unit test (131 override-key replacements:
  `sysctl_module.override("icmp6.<field>", v)` →
  `"icmp6.default.<field>"`); 5 direct attribute reads in
  `test__icmp6__nd__rfc8981_temp.py` updated to
  `nd__constants.ICMP6__X["default"]`; the
  `test__addr_config__thread_safety.py` outlier (`sysctl.override`
  variant) updated manually; 3 unit-test stubs gained
  `_interface_name: str | None = None`.

Commit: `<filled-in-by-commit>` on `PyTCP_3_0_6`. 4 new
tests, 11842 total green.

### Phase 4 — IPv4 conf-plane (SHIPPED 2026-05-28)

Migrated the 2 ip4 conf-plane knobs:

- `ip4.accept_source_route` and `ip4.allow_broadcast` —
  storage promotion from scalar to `dict[str, T]` with
  `{"default": <value>}` initial state.
- `IP4__ACCEPT_SOURCE_ROUTE` lives on `stack/__init__.py`;
  `IP4__ALLOW_BROADCAST` lives on
  `protocols/ip4/ip4__constants.py`. Both registrations
  carry `interface_scope=True`.
- Consumers (2 sites): `packet_handler__ip4__rx.py` (the
  LSRR/SSRR drop gate) and `packet_handler__ip4__tx.py`
  (the broadcast-emission gate) both flip to
  `sysctl_iface.get_for_iface("ip4.<field>",
  self._if._interface_name)`.
- New behavioural pin
  `tests/integration/protocols/ip4/test__ip4__sysctl_per_interface.py`
  (6 tests): each knob's interface_scope flag, bare-base-key
  rejection, per-iface override scoped, broadcast per-iface
  override, default-slot template update.
- Existing tests modernised in lockstep: bare-base
  `sysctl_module.override` calls → `ip4.default.<field>`;
  direct attribute reads `stack.IP4__ACCEPT_SOURCE_ROUTE`
  → `stack.IP4__ACCEPT_SOURCE_ROUTE["default"]`; direct
  attribute writes in `test__ip4__source_route.py` and
  `test__icmp4__echo_options.py` switched to either
  `sysctl_module.override` (auto-restore on exit) or a
  snapshot/restore pattern in `setUp`/`tearDown`; the
  `test__ip4__constants.py` default-value check now reads
  `IP4__ALLOW_BROADCAST["default"]`; the ip4 rx and ip4 tx
  unit-test stub interfaces gained
  `_interface_name: str | None = None`.

Commit: `<filled-in-by-commit>` on `PyTCP_3_0_6`. 6 new
tests, 11848 total green.

### Phase 5 — close-out (1 commit)

- Strip the now-stale "Phase 2: per-interface" comments from
  `arp__constants.py`, `neighbor__constants.py`,
  `nd__constants.py`, `stack/__init__.py`.
- Update `description=` fields to drop the `<iface>`
  placeholder (it's no longer aspirational — it's real).
- Bump the `docs/refactor/sysctl_migration_remaining.md`
  closure note to record the per-interface follow-up.

## 6. Phasing rationale

- **Phase 0 first** because every later phase depends on the
  registry scaffolding.
- **ARP before Neighbor before ICMPv6 / ND** in order of size
  — earliest phases set the migration pattern; bigger phases
  follow once the pattern is proven.
- **IPv4 conf-plane last among migrations** because the two
  knobs are independent of the rest and can ship as a small
  catch-up phase.
- **One namespace per commit**, never partial — the half-
  migrated package state is exactly what the no-half-migrated
  rule exists to prevent.

## 7. Test plan

Per phase:

1. **Registry-level test** in
   `tests/unit/stack/test__stack__sysctl_iface.py` — pins the
   per-interface set/get/reset path for a representative knob
   from the phase's namespace.
2. **Behavioural test** in
   `tests/integration/<namespace>/test__<namespace>__sysctl_per_interface.py`
   — drives a packet handler with two interfaces installed,
   sets a per-interface override on one, asserts the runtime
   observes the override on that interface and the default on
   the other.
3. **Pre-fix red, post-fix green** per the tests-first rule.
4. **§7.2 docstring audit** clean on every touched test file.
5. **`make lint` clean.**
6. **Full test suite green** per-package (per the OOM-history
   memory; avoid the single-process `make test` run).

## 8. Open questions

These need a decision in the commit body of each affected phase,
not pre-decided in this doc:

1. **What happens when an operator writes `<ifname>` for an
   interface that doesn't exist?** Two options: (a) the write
   succeeds and the slot persists until an interface with that
   name attaches, then auto-applies (Linux's behavior); (b) the
   write raises `KeyError` because the interface name doesn't
   exist. Recommendation: **(a)** — matches Linux + supports
   pre-attach configuration.
2. **What happens when an interface DETACHES?** The per-
   interface slot persists in the dict so a re-attach reuses
   the prior value, OR the slot is auto-purged on detach.
   Recommendation: **persist** — matches Linux + makes
   re-attach predictable.
3. **Do we expose `sysctl_iface.snapshot()` / `list_keys()` per
   interface?** Useful for operator-tool introspection.
   Recommendation: **yes**, lands in Phase 0.
4. **`all` pseudo-interface — deferred or omitted?** Per §4.2,
   ship `default` only; revisit `all` when operator demand
   surfaces. Document the decision in Phase 0's commit body.

## 9. Definition of done

The per-interface migration is closed when:

1. Phases 0-5 all shipped on `PyTCP_3_0_6`.
2. `make lint` clean.
3. Full test suite green (~11800+ tests pre-migration; +50
   to +100 new tests across the five phases).
4. `docs/refactor/sysctl_migration_remaining.md` updated with
   a closure note pointing at this doc as the follow-up.
5. This document amended to reflect "DONE" status, OR marked
   DELETED with the closure recorded in a memory entry.
6. `MEMORY.md` index updated with the per-interface closure
   pointer.
7. The "Phase 2: per-interface" stale comments are stripped
   from `arp__constants.py`, `nd__constants.py`,
   `neighbor__constants.py` per Phase 5.

## 10. Cross-references

- `docs/refactor/sysctl_framework.md` — the registry's core
  design + the policy-vs-invariant classification rule.
- `docs/refactor/sysctl_migration_remaining.md` — the flat-
  namespace migration that closed earlier the same day; this
  doc is the per-interface follow-up.
- `.claude/skills/sysctl_knob/SKILL.md` — per-knob workflow;
  needs an addendum after Phase 0 lands documenting the
  interface-scope registration shape.
- `.claude/rules/pytcp.md` §2 — policy vs invariant
  heuristic; the qualified-module-access pattern at §2.1
  will evolve to qualified-helper-access for per-interface
  knobs.
- `.claude/rules/source_files.md` §7 — naming convention.
- Linux source of truth: kernel `Documentation/networking/ip-sysctl.rst`,
  `man 7 arp`, `man 7 icmp`, `man 7 tcp`.

## 11. Restart prompt for a fresh session

After the current session is compacted, drop the following
prompt to resume work on this plan:

> Resume the PyTCP sysctl per-interface migration.
>
> READ FIRST (authoritative):
> - `docs/refactor/sysctl_per_interface.md` — this plan.
> - `docs/refactor/sysctl_framework.md` — upstream registry
>   design.
> - `docs/refactor/sysctl_migration_remaining.md` — the flat-
>   namespace predecessor (closed 2026-05-28).
> - `.claude/skills/sysctl_knob/SKILL.md` — per-knob workflow.
> - `.claude/rules/pytcp.md` §2 — policy-vs-invariant +
>   qualified-module-access patterns.
> - `.claude/rules/feature_implementation.md` — tests-first;
>   one commit per concern; modernise-on-touch.
>
> GIT: branch `PyTCP_3_0_6`. Working tree clean. ~11800+ tests
> green pre-migration; lint clean.
>
> CONTEXT (carries from previous session):
> - Multi-interface runtime IS shipped (commit `e5dc77f5`,
>   2026-05-23). Per-interface `PacketHandler`, `ArpCache`,
>   `NdCache`, `LinkApi(ifindex)` are all in place.
> - Sysctl registry is still flat (one global value per key);
>   34 of 85 knobs need per-interface promotion. See §3 of
>   the plan for the full candidate inventory.
> - Phase 0 (registry scaffolding) is the prerequisite for
>   every later phase.
>
> DO: start with Phase 0. Per the sysctl_knob skill —
> classify the registry-shape extension, write failing tests
> in `tests/unit/stack/test__stack__sysctl_iface.py` covering
> the new `interface_scope=True` `_Knob` shape + the
> `<namespace>.<ifname>.<field>` key parsing + the
> `default` slot fallback + the `sysctl_iface.get_for_iface()`
> helper. Then implement until green. No production-code
> consumer changes in Phase 0 — pure scaffold. Commit message:
> "feat(stack): scaffold interface-scope sysctl registry
> (Phase 0 of per-interface migration)" with the trailer
> `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`.
>
> Push only on explicit "push it". After Phase 0 lands, ask
> whether to continue with Phase 1 (ARP) or stop.

