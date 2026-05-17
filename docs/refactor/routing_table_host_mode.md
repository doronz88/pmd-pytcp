# Routing Table — Host-Mode FIB Plan

| Field             | Value |
|-------------------|-------|
| Status            | **Pending** — plan only; no code written |
| Plan author       | Routing-table refactor request (2026-05-17) |
| Source motivation | The Ethernet TX next-hop decision is the single-gateway-per-`IfAddr` Phase-1 shortcut flagged in CLAUDE.md ("Per-destination routing state must be representable"). The memory-tracked `IfAddr.gateway` removal blocks on a real FIB. This track lands the host-mode routing table and the Phase-3 Route API. |
| Target branch     | `PyTCP_3_0__pre_release` (cut from current `PyTCP_3_0_5`) |
| Touch points      | new `pytcp/runtime/fib.py`, new `pytcp/stack/route.py`, `pytcp/runtime/packet_handler/packet_handler__ethernet__tx.py` (next-hop rewrite), `pytcp/stack/__init__.py` (singleton + slot), `pytcp/stack/lifecycle.py` (boot route install + wiring), `pytcp/protocols/dhcp4/dhcp4__client.py` (default route via API), `pytcp/runtime/packet_handler/__init__.py` (RA/SLAAC default route via API), `net_addr/ip_ifaddr.py` + `ip4_ifaddr.py` + `ip6_ifaddr.py` + `errors.py` (gateway removal), `pytcp/tests/lib/network_testcase.py` (snapshot + topology) |
| Linux analogue    | `ip route` / RTNETLINK `RTM_NEWROUTE` / `RTM_DELROUTE` / `RTM_GETROUTE`; `/proc/net/route`; `net/ipv4/fib_*`, `net/ipv6/route.c` |

This document is the implementation plan for the **host-mode
routing table** and the **Phase-3 Route API** — one of the
seven sanctioned consumer surfaces from CLAUDE.md's Project
North Star:

| PyTCP API | Plane | Linux equivalent |
|-----------|-------|------------------|
| Route API (add / remove / list routes, gateways) | Routing control | `ip route` / RTNETLINK `RTM_NEWROUTE` |

The track is structurally a sibling of the shipped
`Ip4AddressApi` work: a runtime-private data structure
(`pytcp/runtime/fib.py`, the FIB) wrapped by a
`pytcp/stack/route.py` consumer surface; backed today by an
in-process table, with the Phase-3 swap to a real IPC channel
deferred but unblocked.

The scope here is **host-mode only**. Phase 2 (router-grade
forwarding) and Phase 3 (kernel/userspace IPC) are explicitly
out of scope, but every Phase-1 data-model decision is taken
so it does not foreclose them. Forward-compat hooks are marked
`# Phase 2:` / `# Phase 3:` so the upgrade path is greppable.

---

## 1. Goal

Replace the single-gateway-per-`IfAddr` next-hop shortcut with
a real per-address-family routing table (FIB) doing
longest-prefix-match destination lookup, and expose
mutation/introspection through a sanctioned
`pytcp.stack.route` surface.

After this track lands:

- The Ethernet TX path resolves next-hop via
  `fib.lookup(dst)` — a destination-keyed decision, not a
  source-address scan.
- A host can carry **multiple routes**: connected (direct)
  routes derived from assigned addresses, a default route,
  and operator/protocol-installed **static routes to
  non-default prefixes** (a real Linux-host capability PyTCP
  lacks today).
- `Ip4IfAddr.gateway` / `Ip6IfAddr.gateway` and the
  `_validate_gateway` machinery are **removed** from
  `net_addr`; the default route lives in the FIB. This closes
  the memory-tracked `IfAddr` gateway-removal item.
- DHCPv4, IPv6 RA/SLAAC, and boot config install the default
  route through `stack.route`, never via a direct attribute
  write.
- The FIB lookup is callable, unchanged, from a future
  forwarding plane (Phase 2) and the table is keyed so policy
  routing / multi-interface (Phase 2) and an IPC boundary
  (Phase 3) slot in without a redesign.

Explicit non-goals (Phase 2+, tracked but not done here):
forwarding/transit path, ICMP Redirect processing, RFC 4191
RA Route Information option consumption, policy routing
(`ip rule` / multiple tables), per-route MTU folding the PMTU
cache, `rp_filter`, ECMP/multipath.

---

## 2. Current state — what exists today

### The next-hop decision is inline, duplicated, source-keyed

`pytcp/runtime/packet_handler/packet_handler__ethernet__tx.py`
makes the entire routing decision inside `_phtx_ethernet`,
once for IPv6 (lines 109-190) and once for IPv4 (lines
193-306). There is **no routing-table abstraction anywhere**
in the codebase (Explore confirmed: zero `fib` / `route table`
/ `RTM_` structures; the IPv6 RA Route Information option is
parsed but never consumed).

IPv6 decision (`packet_handler__ethernet__tx.py:130-190`):

```python
for ip6_host in self._ip6_ifaddr:
    if ip6_host.address == ip6_src and ip6_dst not in ip6_host.network:
        if ip6_host.gateway is None:
            return TxStatus.DROPPED__ETHERNET__DST_NO_GATEWAY_IP6
        if mac := stack.nd_cache.find_entry(ip6_address=ip6_host.gateway):
            ...                                  # off-link → gateway
        ...
if mac := stack.nd_cache.find_entry(ip6_address=ip6_dst):
    ...                                          # on-link → dst direct
```

IPv4 is the same shape with ARP, plus the multicast /
limited-broadcast / network-broadcast special-cases
(`:200-239`).

Three structural problems for the routing-table target:

1. **Source-keyed, not destination-keyed.** The on-link/
   off-link test is `ip{4,6}_dst not in <src-owning ifaddr>.network`.
   Real routing is a destination longest-prefix match that
   *yields* the source. The source is already chosen upstream
   (RFC 6724 for v6, `ip4_source_selection` for v4) before
   the packet reaches Ethernet TX, so Phase 1 keeps the
   source-first ordering but must stop deriving on-link-ness
   from the source's subnet.

2. **Single gateway, attached to the address.**
   `IfAddr.gateway` (`net_addr/ip_ifaddr.py:60,135-150`,
   abstract `_validate_gateway` at `:111-116`) stores exactly
   one default-router IP per interface address. No non-default
   static route is representable.

3. **`net_addr` value-type purity violation.** `IfAddr` is
   otherwise an immutable value type; the mutable
   `gateway`/`_validate_gateway` carve-out exists only because
   there is nowhere else to put the default router. The
   memory-tracked removal blocks on this plan.

### Where the gateway is set at runtime (consumers to rewire)

| Site | What it does today |
|---|---|
| `pytcp/stack/lifecycle.py:164,168` | `Ip4IfAddr(addr, gateway=_stack.IP4_GATEWAY)` / `Ip6IfAddr(...)` at boot |
| `pytcp/protocols/dhcp4/dhcp4__client.py:603-605, 837-839, 1268-1270` | `ip4_host.gateway = ack.router[0]` on lease ACK / RENEW / INIT-REBOOT |
| `pytcp/runtime/packet_handler/__init__.py:656,661,754,774,892,916,1191-1192` | `ip6_host.gateway = router_address` from RA on SLAAC stable + RFC 8981 temp + RFC 7217 regen |

### Existing Phase-3 surfaces (precedent to mirror)

- `pytcp/stack/address.py` (`Ip4AddressApi`) — the canonical
  template: runtime state owned by `PacketHandler`, wrapped by
  a `pytcp/stack/*.py` API; copy-by-value introspection
  (`list_ip4_ifaddrs() -> tuple[...]`, `:228-238`); mutations
  documented as the RTNETLINK seam (`:121-138`).
- `pytcp/stack/link.py` (`LinkApi`) — sibling read+mutate
  surface, snapshot/restore in the test harness.
- `pytcp/stack/sysctl.py` — dict-like policy registry.
- `pytcp/stack/lifecycle.py` `init()` / `mock__init()` — where
  singletons are constructed and wired; the test harness
  snapshots `stack.__dict__`.

### Linux `ip route` reference (the parity target)

A Linux route is `{dst-prefix, oif, gateway?, prefsrc?,
metric, scope, protocol, table}`. Lookup: longest-prefix
match; ties broken by lowest metric. A "connected" route
(scope link, no gateway) is auto-created when an address is
assigned to an interface; `default` is `0.0.0.0/0` / `::/0`
via a gateway. Host mode uses table `main` (id 254) only.
On-link = a matched route with no gateway. Off-link = matched
route with a gateway; the gateway is then itself resolved
against the table (Phase 1: gateway is required to be
directly reachable via a connected route — no recursive
multi-hop next-hop, which matches the Linux host case).

---

## 3. Phased plan

Each phase is one tests-first commit (or a tests commit + a
fix commit where the change is large), mechanically
reversible, `make validate` clean. Phases are ordered so the
risky cross-cutting `net_addr` change lands **after** the FIB
is proven, behind a dual-write shim.

### Phase 0 — `Route` + `RouteTable` data structure (1 commit; ~2 h)

Pure data structure and lookup, fully unit-tested, **not yet
wired** — zero behaviour change.

New `pytcp/runtime/fib.py`:

```python
@dataclass(frozen=True, kw_only=True, slots=True)
class Route[A: (Ip4Address, Ip6Address), N: (Ip4Network, Ip6Network)]:
    destination: N                 # prefix this route covers
    gateway: A | None = None       # None ⇒ on-link / connected
    prefsrc: A | None = None       # preferred source (Phase 1: advisory)
    metric: int = 0                # lower wins on equal prefix
    scope: RouteScope = RouteScope.GLOBAL   # GLOBAL / LINK / HOST
    protocol: RouteProtocol = RouteProtocol.STATIC  # KERNEL/DHCP/RA/STATIC/BOOT
    # Phase 2: oif (output interface) — single implicit iface in host mode.
    # Phase 2: table id — only `main` (254) exists in host mode.

class RouteTable[A, N]:
    def add(self, route: Route[A, N]) -> None: ...
    def remove(self, *, destination: N, gateway: A | None = None) -> int: ...
    def lookup(self, destination: A, /,
               connected: Iterable[N]) -> Route[A, N] | None: ...
    def snapshot(self) -> tuple[Route[A, N], ...]: ...   # copy-by-value
```

Lookup semantics (RFC 1122 §3.3.1 next-hop selection; Linux
`fib_lookup` as tiebreaker):

1. Build candidate set = explicitly-added routes **plus**
   connected routes derived on-the-fly from the supplied
   `connected` networks (a connected route is
   `Route(destination=net, gateway=None, scope=LINK)`).
   Deriving connected routes at lookup time (rather than
   syncing them on address add/remove) means **zero
   sync surface** between the Address API and the FIB and no
   stale-route race — connected routes are a *view* of
   assigned addresses, never stored.
2. Filter to routes whose `destination` contains the lookup
   address.
3. Pick the longest prefix. Tie → lowest `metric`. Tie →
   connected (scope LINK, no gateway) over a gateway'd route
   (more specific scope wins — Linux behaviour).
4. Return the winning `Route`, or `None` (no route to host).

`RouteScope` / `RouteProtocol` are `IntEnum` per the enum
rule; values mirror Linux `rtnetlink.h` `RT_SCOPE_*` /
`RTPROT_*` so `ip route show` parity and Phase-3 IPC are
free.

**Tests-first** (`pytcp/tests/unit/runtime/test__runtime__fib.py`):
longest-prefix wins over default; metric tiebreak; connected
beats gateway'd at equal prefix; no-route returns `None`;
default route (`0.0.0.0/0` / `::/0`) matches anything;
snapshot is copy-by-value (mutating the result does not touch
the table); IPv6 link-local gateway accepted; remove by
`(destination, gateway)` returns count. Reference lines:
`RFC 1122 §3.3.1 (next-hop selection algorithm).`

### Phase 1 — Wire FIB singleton + introspection-only Route API + dual-write (1 commit; ~1.5 h)

- `pytcp/stack/__init__.py`: add `ip4_fib` / `ip6_fib`
  singleton slots (`RouteTable[...]`) and a `route:
  RouteApi` Phase-3 slot.
- `pytcp/stack/route.py` (`RouteApi`) — **read-only this
  phase**, mirroring `Ip4AddressApi`'s introspection shape:
  `list_ip4_routes() -> tuple[Route, ...]`,
  `list_ip6_routes() -> tuple[Route, ...]` (copy-by-value
  snapshot — Phase-3 "introspection is read-only" constraint).
- `pytcp/stack/lifecycle.py` `init()`: construct the two
  FIBs; when `IP4_GATEWAY` / `IP6_GATEWAY` is set, install a
  **default route** (`0.0.0.0/0` / `::/0` via gateway,
  `protocol=BOOT`) into the FIB **in addition to** the
  existing `Ip{4,6}IfAddr(gateway=...)` write (dual-write).
  Nothing reads the FIB yet, so this is inert.
- `mock__init()`: accept/construct mock FIBs.
- `pytcp/tests/lib/network_testcase.py`: snapshot/restore
  `ip4_fib` / `ip6_fib` / `route` in `setUp`/`tearDown`
  (mandatory per pytcp.md §6.1 — module-level stack state).
  Pre-install the fixture default routes
  (`STACK__IP4_GATEWAY`, `STACK__IP6_GATEWAY`) so the harness
  topology is unchanged.

**Tests-first**: `RouteApi.list_*` returns a copy-by-value
snapshot; boot config with a gateway produces exactly one
default route; without a gateway produces none; harness
snapshot/restore isolates the FIB across tests. Reference:
`PyTCP test infrastructure (no RFC clause).` for the harness
plumbing test; `RFC 1122 §3.3.1` for the default-route test.

### Phase 2 — Rewrite Ethernet TX next-hop to consult the FIB (1 tests commit + 1 fix commit; ~3 h)

Replace the source-keyed ifaddr scan in
`packet_handler__ethernet__tx.py` with, for each family:

```python
route = stack.ip{4,6}_fib.lookup(
    ip{4,6}_dst,
    connected=[h.network for h in self._ip{4,6}_ifaddr],
)
if route is None:
    return TxStatus.DROPPED__ETHERNET__DST_NO_ROUTE_IP{4,6}
next_hop = route.gateway or ip{4,6}_dst         # on-link ⇒ gateway is None
if mac := stack.{arp,nd}_cache.find_entry(...=next_hop):
    ...send...
else:
    stack.{arp,nd}_cache.enqueue_pending(...=next_hop, ...)
    return TxStatus.DROPPED__ETHERNET__DST_..._CACHE_MISS
```

The multicast / limited-broadcast / network-broadcast
special-cases stay (they are link-scope, not routed in host
mode; Linux models them as implicit `224.0.0.0/4` etc. routes
— note `# Phase 2:` for representing them as routes later).
`IfAddr.gateway` still exists but is now read by **nothing**
(dual-write keeps it populated; it is dead-but-present until
Phase 4).

Intentional, Linux-correct behaviour change to document and
test: today, if `dst` is on-link for ifaddr B but the chosen
source is ifaddr A's address, the code treats `dst` as
off-link (`dst not in A.network`) and sends to A's gateway.
The FIB matches B's connected route and sends `dst` directly
— this is what Linux does (`fib_lookup` is destination-keyed;
RFC 1122 §3.3.4.1 multihoming). Add an integration test that
pins the new behaviour and cite the deviation inline.

New/renamed stat counters: `ethernet__dst_unspec__ip{4,6}_lookup__route_hit__on_link__{arp,nd}_cache_hit__send`,
`...__route_hit__gateway__..._cache_hit__send`,
`...__no_route__drop`, mirroring the existing naming scheme.
Update `pytcp/lib/packet_stats.py` and every
`_assert_packet_stats_tx(exact=True, ...)` call in the
integration suite (the strict default means every renamed
counter must be re-pinned).

**Tests-first**: integration tests via `NetworkTestCase` —
on-link dst → ARP/ND dst directly; off-link dst → default
route gateway; no route → drop with the new counter; the
multihoming behaviour-change test above; parity with the
pre-rewrite frame output for the unchanged-topology cases.
References: `RFC 1122 §3.3.1 (next-hop selection).`,
`RFC 1122 §3.3.4.1 (multihoming source/route coupling).`,
`RFC 4861 §5.2 (IPv6 next-hop determination).`,
`RFC 5942 §4 (IPv6 on-link determination).`

### Phase 3 — Route API mutation surface + rewire consumers (1 commit; ~2.5 h)

- `RouteApi` gains mutation methods, documented as the
  RTNETLINK seam exactly like `Ip4AddressApi`:
  `add_ip{4,6}_route(*, route)`,
  `remove_ip{4,6}_route(*, destination, gateway=None)`,
  `replace_default_ip{4,6}(*, gateway, protocol)` (atomic-ish
  swap mirroring `Ip4AddressApi.replace_ifaddr`'s
  add-before-remove ordering).
- Rewire the three runtime consumers from
  `IfAddr.gateway = X` to
  `stack.route.replace_default_ip{4,6}(gateway=X,
  protocol=...)`:
  - `pytcp/stack/lifecycle.py` boot config (drop the
    dual-write; install only the FIB route).
  - `pytcp/protocols/dhcp4/dhcp4__client.py` (3 sites;
    `protocol=DHCP`).
  - `pytcp/runtime/packet_handler/__init__.py` RA/SLAAC
    (6 sites; `protocol=RA`; the link-local gateway from RA
    is a valid FIB gateway — scope handling unchanged).
- `IfAddr.gateway` setter still exists but is now written by
  nothing.

**Tests-first**: `add`/`remove`/`replace_default` mutate the
snapshot; DHCPv4 lease ACK installs a `protocol=DHCP` default
route (integration, via the DHCP client harness path); RA
installs a `protocol=RA` default route with a link-local
gateway; `replace_default` is atomic (old gone, new present;
no transient no-route window for the common path).
References: `RFC 9293 §3.9` fallback for the API-plumbing
units; `RFC 2131 §4.4.1` (DHCP router option) for the DHCP
test; `RFC 4861 §6.3.4` (default router from RA) for the RA
test.

### Phase 4 — Remove `IfAddr.gateway` from `net_addr` (1 commit; ~2 h)

The memory-tracked `IfAddr` gateway removal, now unblocked:

- Delete `_gateway` slot, `gateway` property + setter,
  abstract `_validate_gateway`
  (`net_addr/ip_ifaddr.py:55,60,110-116,134-150`).
- Delete the concrete `_validate_gateway` in
  `ip4_ifaddr.py` / `ip6_ifaddr.py` and the
  `Ip4IfAddrGatewayError` / `Ip6IfAddrGatewayError` classes
  in `net_addr/errors.py`; drop the `gateway=` ctor kwarg.
- `lifecycle.py:164,168`: `Ip4IfAddr(_stack.IP4_ADDRESS)` /
  `Ip6IfAddr(...)` — no `gateway=`.
- Delete or migrate every gateway-validation test under
  `net_addr/tests/unit/` (the RFC 3021 /31 edge etc. — per
  the `ifaddr_gateway_removal` memory, these are *moot*, not
  ported; the routing semantics they tested now live in the
  FIB unit tests).
- `net_addr.md`-governed value-type doc note: `IfAddr` is now
  a pure value type with no mutable carve-out (delete the
  "known wart" carve-out language).

**Tests-first**: the *failing* direction here is the deletion
exposing any remaining reader — a repo-wide grep gate
(`git grep -n '\.gateway' net_addr pytcp` returns only FIB /
Route API hits) plus `make validate` green proves no
consumer survives. The net_addr value-type test matrix gets
the gateway cases removed; no new assertions (removal, not
behaviour change). Reference:
`PyTCP test infrastructure (no RFC clause).`

### Phase 5 — Static non-default routes (1 commit; ~1.5 h)

The genuinely new host capability: `stack.route.add_ip4_route`
with a non-default `destination` and a gateway (a Linux host
routinely has `ip route add 10.2.0.0/16 via 10.0.1.254`).
Phase 0's lookup already supports this; this phase adds the
integration coverage and the operator-facing path.

- Confirm `RouteApi.add_ip{4,6}_route` accepts non-default
  prefixes (no code change expected if Phase 3 was general).
- Integration test: host with default route via R1 **and** a
  static `10.9.0.0/16` via R2 — packet to `10.9.1.1` resolves
  R2's MAC, packet to `8.8.8.8` resolves R1's MAC, packet to
  an on-link host resolves directly. Pins longest-prefix +
  the connected/static/default precedence end-to-end.

**Tests-first**: the three-destination integration scenario
above. Reference: `RFC 1122 §3.3.1 (longest-prefix next-hop
selection).`

### Phase 6 — Adherence + docs + close the audit loop (1 commit; ~1 h)

- Refresh/author the relevant per-RFC adherence records via
  the `rfc_adherence_audit` skill — RFC 1122 §3.3 (routing),
  RFC 4861 §5.2/§6.3 (IPv6 next-hop / default router), RFC
  5942 (on-link model) — including the parallel test-coverage
  audit (per the `rfc_adherence_includes_test_audit` rule).
  Land in the same commit as no further code change (per the
  `audit_in_lockstep_with_code` rule the audit should track
  Phases 2-5; if any phase substantially shifts adherence,
  refresh in *that* phase's commit and treat Phase 6 as the
  final reconciliation).
- CLAUDE.md North Star table: Route API → "Phase-1 shipped".
- Update the `ifaddr_gateway_removal` and add a
  `routing_table_host_mode` memory pointer.
- Verify all `# Phase 2:` / `# Phase 3:` markers are present
  and greppable (forwarding-plane call site, `oif` field,
  table id, multicast-as-route, PMTU-as-route-metric).

---

## 4. Sysctl knobs to add

**None in Phase 1.** Host-mode routing (connected derivation
+ default + static) needs no policy knob. Candidates flagged
for Phase 2, *not* registered now (registering a sysctl is a
forever API per pytcp.md §2 — defer until there is a real
consumer): `net.ipv4.conf.all.rp_filter` (reverse-path
filter — forwarding), `net.ipv{4,6}.route.gc_*` (route cache
GC — only meaningful with a route *cache*, which host mode
does not have), per-route `mtu` (folds the PMTU cache —
Phase 2). Note them in §12, do not call the `sysctl_knob`
skill this track.

---

## 5. New / touched files inventory

### New source files

| File | Phase | Purpose |
|---|---|---|
| `pytcp/runtime/fib.py` | 0 | `Route`, `RouteScope`, `RouteProtocol`, `RouteTable`, lookup |
| `pytcp/stack/route.py` | 1/3 | `RouteApi` — Phase-3 consumer surface (read in P1, mutate in P3) |

### Touched source files

| File | Phases | Why |
|---|---|---|
| `pytcp/stack/__init__.py` | 1 | `ip4_fib` / `ip6_fib` / `route` slots |
| `pytcp/stack/lifecycle.py` | 1,3,4 | construct FIBs; boot default route; drop `gateway=` |
| `pytcp/runtime/packet_handler/packet_handler__ethernet__tx.py` | 2 | next-hop rewrite to `fib.lookup` |
| `pytcp/lib/packet_stats.py` | 2 | renamed/new route stat counters |
| `pytcp/protocols/dhcp4/dhcp4__client.py` | 3 | default route via `RouteApi` (3 sites) |
| `pytcp/runtime/packet_handler/__init__.py` | 3 | RA/SLAAC default route via `RouteApi` (6 sites) |
| `net_addr/ip_ifaddr.py` | 4 | delete `gateway` / `_validate_gateway` |
| `net_addr/ip4_ifaddr.py`, `ip6_ifaddr.py` | 4 | delete concrete `_validate_gateway`, ctor kwarg |
| `net_addr/errors.py` | 4 | delete `Ip{4,6}IfAddrGatewayError` |
| `pytcp/tests/lib/network_testcase.py` | 1,2 | FIB snapshot/restore; fixture default routes; counter re-pin |

### New test files

| File | Phase | Cases (target) |
|---|---|---|
| `pytcp/tests/unit/runtime/test__runtime__fib.py` | 0 | lookup matrix, prefix/metric/scope tiebreaks, snapshot |
| `pytcp/tests/unit/stack/test__stack__route.py` | 1,3 | RouteApi read snapshot, mutation, replace-default atomicity |
| `pytcp/tests/integration/protocols/ip4/test__ip4__routing.py` | 2,5 | on-link/off-link/no-route, multihoming change, static route |
| `pytcp/tests/integration/protocols/ip6/test__ip6__routing.py` | 2,5 | IPv6 equivalents incl. link-local gateway |
| `pytcp/tests/integration/protocols/dhcp4/...` (extend) | 3 | DHCP ACK installs `protocol=DHCP` default route |
| `pytcp/tests/integration/protocols/icmp6/nd/...` (extend) | 3 | RA installs `protocol=RA` default route |

---

## 6. Open design decisions

### 6.1 Connected routes — derived at lookup vs stored

**Decision: derived at lookup.** `RouteTable.lookup` takes the
current `connected` networks as an argument and synthesizes
the connected routes per-call. Stored routes = explicit
(default + static) only. Rationale: a connected route is
definitionally a view of an assigned address; storing it
creates a sync obligation between the Address API and the FIB
(add/remove address ⇒ add/remove connected route) with a
stale-route race window. Deriving is O(#ifaddr) per TX which
is negligible (host has ≤ a handful). Phase 2 (per-interface)
keeps this — connected routes derive from that interface's
addresses.

### 6.2 Phase-1 ordering — source-first kept, route consulted for next-hop only

**Decision: keep source-first.** RFC 6724 / `ip4_source_selection`
still run upstream and choose the source before Ethernet TX.
The FIB is consulted only for the next-hop / on-link decision
on an already-sourced packet. Rationale: flipping to
route-first source selection (`route.prefsrc`) is a large,
separable change that risks the source-selection RFC
conformance suite; it is a Phase-2 improvement, not a
prerequisite. `Route.prefsrc` is stored from Phase 0 so the
flip is unblocked. The one observable consequence — the
multihoming case in Phase 2 — is the Linux-correct behaviour
and is tested + cited as a deliberate fix.

### 6.3 FIB location — `runtime/` not `net_addr/`

**Decision: `pytcp/runtime/fib.py`.** The FIB is mutable stack
state with a lifecycle, not a value type — it belongs in
`runtime/` next to the neighbor caches, not in `net_addr/`
(net_addr.md §1 forbids stateful code there). It consumes
`net_addr` value types (`Ip4Network` etc.) the way the
neighbor caches do.

### 6.4 Gateway removal sequencing — dual-write then rip-out

**Decision: Phase 1 dual-writes, Phase 4 removes.** The
`net_addr` gateway deletion touches `net_addr`, DHCP4,
RA/SLAAC, lifecycle, and the entire gateway test corpus. Doing
it atomically with the TX rewrite makes one un-bisectable
mega-commit. Dual-writing the gateway into both `IfAddr` and
the FIB (Phase 1), switching the reader to the FIB (Phase 2),
rewiring the writers to the Route API (Phase 3), then deleting
the now-dead `IfAddr.gateway` (Phase 4) keeps every commit
green and reversible.

### 6.5 Recursive next-hop resolution

**Decision: one level, Phase 1.** If a matched route has a
gateway, the gateway is resolved directly against ARP/ND (it
must be reachable via a connected route — the normal host
case). PyTCP does **not** recurse (gateway-of-gateway). Linux
hosts effectively never need this. Multi-hop / recursive
next-hop is a Phase-2 router concern; `lookup` returning the
`Route` (not a flattened MAC) leaves the recursion point
open.

### 6.6 `RouteApi` shape — `add(route=Route(...))` vs flat kwargs

**Decision: pass a `Route` object.** `add_ip4_route(*,
route: Route[...])` not `add_ip4_route(*, destination=...,
gateway=..., metric=...)`. Rationale: matches the
`Ip4AddressApi.add_ifaddr(*, ip4_ifaddr=Ip4IfAddr(...))`
precedent, keeps the API stable as `Route` gains Phase-2
fields, and the `Route` dataclass already validates via
`__post_init__`. `replace_default_ip4(*, gateway, protocol)`
stays flat — it is a convenience over the common case.

---

## 7. Test strategy

### 7.1 Unit layer

`test__runtime__fib.py` (Phase 0) is the canonical pin for
lookup semantics — parameterized matrix over (routes,
connected nets, lookup addr) → expected `Route | None`, plus
dedicated `TestCase`s for snapshot copy-by-value and
remove-by-key count. `test__stack__route.py` pins the API
contract (copy-by-value reads, mutation, `replace_default`
atomicity).

### 7.2 §7.2 docstring audit

Run the mandatory audit script (unit_testing.md §7.2 /
integration_testing.md §9.1) against every test file each
phase touches, before staging. Reference-line picks: RFC 1122
§3.3.1 (next-hop), §3.3.4.1 (multihoming); RFC 4861 §5.2,
§6.3.4; RFC 5942 §4; RFC 2131 §4.4.1 (DHCP router option);
plumbing tests use the `PyTCP test infrastructure (no RFC
clause).` fallback.

### 7.3 Integration touch points

`NetworkTestCase` topology already has `STACK / HOST_A
(on-link, resolved) / HOST_B (on-link, unresolved) / HOST_C
(off-link via ROUTER) / ROUTER`. The default route to
`STACK__IP{4,6}_GATEWAY` is pre-installed in the harness FIB
(Phase 1) so every existing integration test sees identical
behaviour. The Phase-2 rewrite must hold the entire existing
integration suite green except the deliberately-changed
multihoming counter assertions. Phase 5 adds a second
fixture router for the static-route scenario.

---

## 8. Effort estimate

| Phase | Description | Effort | Cumulative | Commit |
|---|---|---|---|---|
| 0 | `Route` + `RouteTable` + lookup, unit-tested | ~2 h | 2 h | 1 |
| 1 | FIB singleton + read-only RouteApi + dual-write + harness | ~1.5 h | 3.5 h | 1 |
| 2 | Ethernet TX next-hop rewrite + counters | ~3 h | 6.5 h | 1-2 |
| 3 | RouteApi mutation + rewire DHCP/RA/boot | ~2.5 h | 9 h | 1 |
| 4 | Remove `IfAddr.gateway` from net_addr | ~2 h | 11 h | 1 |
| 5 | Static non-default routes + integration | ~1.5 h | 12.5 h | 1 |
| 6 | Adherence + docs + memory + audit close | ~1 h | 13.5 h | 1 |

≈ 13-14 h total over 7-8 commits. Phase 2 may split into a
tests commit and a fix commit if the counter re-pinning is
large.

## 9. Commit discipline

Per feature_implementation.md §4: one concern per commit;
tests-first commit precedes (or is bundled atomically with)
the implementation; commit body cites the governing RFC
clause and what flipped green; `make lint` + `make test` +
§7.2 audit clean before each commit; modernise legacy
typing/Python forms on touch in the same commit; never
`--no-verify`. Body template:

```
<phase>: <one-line summary>

<what changed, what the new tests pin that wasn't pinned before>

Reference: RFC 1122 §3.3.1 (next-hop selection).
Linux tiebreaker: net/ipv4/fib_trie.c::fib_table_lookup.

<N> passing, 0 skipped.
```

## 10. Closing the audit loop

After Phase 6: per-RFC adherence records refreshed (with the
parallel test-coverage audit); CLAUDE.md North Star Route-API
row → Phase-1 shipped; `ifaddr_gateway_removal` memory updated
to "shipped, see routing_table_host_mode.md"; new
`routing_table_host_mode` memory pointer added; this doc's
Status field updated with the commit hashes.

## 11. References

### Phase-3 north-star (CLAUDE.md)

| Surface | Plane | Linux | PyTCP state after this track |
|---|---|---|---|
| Route API | Routing control | `ip route` / `RTM_NEWROUTE` | Phase-1 host FIB + read/mutate API shipped; forwarding-plane consumption Phase-2 |

### PyTCP internal references

- `pytcp/stack/address.py` — `Ip4AddressApi`, the precedent
  template (copy-by-value reads, RTNETLINK-seam docstrings).
- `pytcp/stack/link.py` — sibling Phase-3 surface.
- `pytcp/runtime/packet_handler/packet_handler__ethernet__tx.py`
  — the rewrite site.
- `net_addr/ip_ifaddr.py` — `IfAddr.gateway` (to be removed).
- `pytcp/tests/lib/network_testcase.py` — harness topology +
  snapshot/restore.
- `.claude/rules/pytcp.md` §6.1 (stack-state snapshot rule),
  §2 (sysctl classification), `net_addr.md` §1 (no stateful
  code), `enums.md` (RouteScope/RouteProtocol IntEnum).

### Linux references

- `ip route`, `ip rule`; RTNETLINK `RTM_{NEW,DEL,GET}ROUTE`
  (`man 7 rtnetlink`).
- `net/ipv4/fib_trie.c::fib_table_lookup`,
  `net/ipv4/route.c::ip_route_output_slow`,
  `net/ipv6/route.c::ip6_route_output` — lookup tiebreaker.
- `/proc/net/route`, `/proc/net/ipv6_route` — introspection
  parity target.
- RFC 1122 §3.3 (host routing); RFC 4861 §5.2, §6.3
  (IPv6 next-hop / default-router); RFC 5942 (IPv6 subnet
  model / on-link); RFC 4191 (RA route information — Phase 2).

## 12. Phase-2 / Phase-3 forward-compat

### 12.1 Router-grade (Phase 2) hooks left in place

- `fib.lookup(dst)` is destination-keyed and returns a
  `Route` — a future forwarding plane calls the identical
  entry point for transit packets. Marked `# Phase 2:
  forwarding plane calls fib.lookup` at the TX call site.
- `Route.oif` and a table-id are reserved (commented) from
  Phase 0 so per-interface routing and policy routing
  (`ip rule` / multiple tables) slot in without a dataclass
  break.
- One-level next-hop resolution leaves the recursion point
  open for router-grade recursive/multipath next-hop (§6.5).
- Connected-route derivation is per-interface-ready (§6.1).
- RFC 4191 RA Route Information option (parsed-but-unconsumed
  today) consumption is a Phase-2 add: it installs
  `protocol=RA`, non-default routes through the *same*
  `RouteApi.add` — no new surface.

### 12.2 Kernel/userspace (Phase 3) alignment

- `RouteApi` is the sole mutation/introspection seam; the
  FIB is runtime-private. Internals swap from in-process
  table to an IPC/RTNETLINK channel with zero consumer
  change — the `Ip4AddressApi` Phase-3 contract, replicated.
- Reads are copy-by-value snapshots (`tuple[Route, ...]`),
  never live references — `/proc/net/route` semantics.
- `RouteScope` / `RouteProtocol` numeric values mirror
  Linux `rtnetlink.h` so the eventual RTNETLINK encoding is
  a direct map.

### 12.3 What this track does NOT do

Forwarding/transit path; ICMP Redirect generation **or**
processing; RFC 4191 route-info consumption; policy routing /
multiple tables / `ip rule`; `rp_filter`; ECMP/multipath;
per-route MTU (PMTU-cache fold); route cache + GC. All are
Phase-2+ and are explicitly representable on top of the
Phase-1 data model without redesign.
