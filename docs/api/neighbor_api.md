# Neighbor API — Neighbor-control surface

| Field           | Value                                                                          |
|-----------------|--------------------------------------------------------------------------------|
| Status          | **not yet** — design only                                                      |
| Module path     | (TBD; expected `pytcp.lib.neighbor_api`, exposed as `pytcp.stack.neighbor`)    |
| Linux analogue  | `ip neighbor add` / `ip neighbor del` / `ip neighbor show` / RTNETLINK `RTM_NEWNEIGH` |
| Refactor plan   | (TBD; will land when a consumer needs neighbor-cache control)                 |

## Purpose

The Neighbor API will be PyTCP's neighbor-control consumer
surface — the canonical way to add / remove / list ARP +
ND cache entries and to flush stale state. Mirrors
Linux's `ip neighbor` family.

Not yet shipped because PyTCP's existing ARP / ND caches
(`pytcp.protocols.arp.arp__cache.ArpCache` and
`pytcp.protocols.icmp6.nd.nd__cache.NdCache`) already work
without operator intervention: entries auto-populate on
RX, age out per `neighbor.*` sysctls (the canonical RFC
4861 NUD framework), and dead entries get probed and
flushed automatically.

The API surface becomes load-bearing when:

- An operator CLI wants to inspect / debug cache state.
- A consumer needs to install **permanent / static**
  entries (Linux's `ip neighbor add ... nud permanent`).
- A test fixture needs to seed cache entries without
  exercising the RX path.

## Current state — internal caches

| Cache             | Source                                                                  |
|-------------------|-------------------------------------------------------------------------|
| ARP (IPv4)        | `pytcp.protocols.arp.arp__cache.ArpCache`                                |
| ND (IPv6)         | `pytcp.protocols.icmp6.nd.nd__cache.NdCache`                             |
| NUD framework     | `pytcp.lib.neighbor` (shared base class + `neighbor.*` sysctls)         |

Both are `Subsystem` subclasses (background aging /
probing); consumers normally don't touch them directly.
Test fixtures in `pytcp.tests.lib.network_testcase` reach
into them through autospec mocks (`mock__arp_cache`,
`mock__nd_cache`) — that reach-through is the Phase-1
test affordance.

## Anticipated surface (when shipped)

```python
# Read — Linux 'ip neighbor show' / '/proc/net/arp'.
stack.neighbor.list_ip4_entries()       # → tuple[ArpCacheEntry, ...]
stack.neighbor.list_ip6_entries()       # → tuple[NdCacheEntry, ...]
stack.neighbor.find_ip4(address)        # → MacAddress | None
stack.neighbor.find_ip6(address)        # → MacAddress | None

# Mutation — operator-facing.
stack.neighbor.add_permanent(
    address=Ip4Address("10.0.0.5"),
    mac_address=MacAddress("02:..."),
)
stack.neighbor.remove(address=Ip4Address("10.0.0.5"))
stack.neighbor.flush()                                  # whole-cache flush
stack.neighbor.flush(address=Ip4Address("10.0.0.5"))    # single-entry
```

Permanent entries (Linux `nud permanent`) bypass the NUD
aging timers — useful for closed-network deployments
where ARP traffic should be suppressed.

## Phase-3 alignment

The Neighbor API will be the seam through which test
fixtures stop reaching into the cache internals. The
plan: every `mock__arp_cache` / `mock__nd_cache` patch
site in the integration harness gets replaced by
`stack.neighbor` interaction, with the cache instances
remaining internal.

## Deferred / out of scope

- **NUD probe-only mode** — Linux's `nud none` /
  `nud reachable` administrative override is niche.
- **Per-interface scoping** — Phase-2 multi-interface
  concern.

## Plan / history

- No refactor plan yet — will be drafted when an
  operator CLI or "permanent entry" consumer
  materialises.
- Phase-1 sanctioned introspection has a partial
  workaround via the Introspection API (see
  `introspection_api.md`).

## Cross-API dependencies (anticipated)

- **Link API**: per-interface scoping when multi-interface
  lands.
- **Sysctl**: NUD aging parameters (`neighbor.reachable_time`,
  `neighbor.retrans_timer`, etc.) are already sysctl-
  tunable in Phase-1.
- **Address API**: when an address is removed (`ip addr
  del`), its solicited-node multicast filter is dropped
  — Linux purges related ND cache entries; PyTCP defers
  that cleanup.
