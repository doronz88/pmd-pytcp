# Introspection API — State observation surface

| Field           | Value                                                                                                |
|-----------------|------------------------------------------------------------------------------------------------------|
| Status          | partial — interface counters via Link API; route table / neighbor cache / socket list deferred       |
| Module paths    | `pytcp.stack.link.stats` (shipped); `pytcp.stack.{route,neighbor}` (TBD); `pytcp.stack.sockets` (raw dict today) |
| Linux analogue  | `/proc/net/route`, `/proc/net/arp`, `ss`, `/proc/net/dev`, `ip -s link show`                        |

## Purpose

The Introspection API is PyTCP's read-only state-observation
surface — the canonical way for monitoring tools, operator
CLIs, and debugging consumers to inspect stack state
without mutating it. Mirrors Linux's `/proc/net/*` files
and the `ss` (`socket statistics`) tool.

Per CLAUDE.md Phase-3 design implications: **state
introspection is read-only and copy-by-value**. Accessors
return immutable snapshots, never live references that
the caller could mutate. The Linux equivalent is
`/proc/net/*` text — readable, never writable by reading.

## Current state (Phase 1 — partial)

Three categories of introspection:

| Category              | Status                                                         |
|-----------------------|----------------------------------------------------------------|
| Per-interface counters| **shipped** — `pytcp.stack.link.stats` returns a frozen `LinkStats` snapshot |
| Route table           | not yet (Route API not yet shipped)                            |
| Neighbor cache        | not yet (Neighbor API not yet shipped)                         |
| Socket list           | partial — `pytcp.stack.sockets` is a live dict (Phase-3 violation; will be wrapped) |

### Shipped: `LinkApi.stats`

`pytcp.stack.link.stats` returns a `LinkStats` frozen
dataclass with eight buckets — Linux's `ip -s link show`
RX/TX block equivalent.

```python
from pytcp.stack import link

s = link.stats
# rx_packets / rx_bytes / rx_errors / rx_dropped
# tx_packets / tx_bytes / tx_errors / tx_dropped
```

Full documentation at [`link_api.md`](link_api.md) §LinkStats.

### Partial: socket list

`pytcp.stack.sockets` is a `dict[SocketId, socket]`
populated by every `bind()` / connect path. Today it is
a live dict — consumers can iterate it, but mutating it
would corrupt stack state. The intended Phase-3
introspection wrap:

```python
# Anticipated when introspection-API consolidation lands.
stack.introspect.list_sockets()    # → tuple[SocketSnapshot, ...]
```

where `SocketSnapshot` is a frozen dataclass exposing
`local_address`, `remote_address`, `local_port`,
`remote_port`, `state`, `family`, `type`, `proto`,
counters — Linux's `ss -tan` columns.

## Anticipated full surface (when complete)

The Introspection API is likely to consolidate into a
single namespace once the Route / Neighbor APIs land:

```python
# Per-interface
stack.link.stats                        # shipped
stack.link.name                         # shipped

# Per-route (Route API)
stack.route.list_ip4_routes()           # not yet
stack.route.list_ip6_routes()           # not yet

# Per-neighbor (Neighbor API)
stack.neighbor.list_ip4_entries()       # not yet
stack.neighbor.list_ip6_entries()       # not yet

# Per-socket (consolidated)
stack.introspect.list_sockets()         # not yet (today: stack.sockets raw dict)

# Process-wide
stack.introspect.is_running             # → bool (today: stack.link.is_running)
stack.introspect.startup_time           # → float | None
```

Each accessor returns a frozen, copy-by-value snapshot.

## Phase-3 alignment

The introspection contract per CLAUDE.md is verbatim:

> State introspection is read-only and copy-by-value.
> Route-table / neighbor-cache / socket-list / packet-
> counter accessors return immutable snapshots, never
> live references the caller could mutate. The Linux
> equivalent is `/proc/net/*` text — readable, never
> writable by reading.

`LinkApi.stats` already meets this; the socket dict
violates it (live reference). The other two surfaces
(route / neighbor) don't exist yet so the violation
doesn't apply.

## Deferred / out of scope

- **`ss`-style filtering** (Linux `ss -tan dst :22`) — not
  a Phase-1 concern; raw-list iteration covers the use
  cases.
- **Per-CPU counters** — Linux exposes per-CPU counters
  for hot paths; PyTCP is single-threaded per-subsystem
  so this doesn't apply.
- **Netlink-style event subscriptions** — Linux's
  `RTM_NEWLINK / DELLINK` events. The Address API's
  `subscribe_conflicts` is the closest existing
  equivalent; a generic "watch any stack event"
  subscription is Phase-2+.

## Plan / history

- No standalone refactor plan — the Introspection surface
  grows incrementally as the Link / Route / Neighbor APIs
  ship.
- Link API stats: shipped 2026-05-12; see
  [`link_api.md`](link_api.md) §LinkStats.
- Socket-list consolidation: tracked under the socket
  parity audit (`docs/refactor/socket_linux_parity_audit.md`).

## Cross-API dependencies

- **Link API**: provides per-interface counters today.
- **Route API**: will provide FIB introspection when
  shipped.
- **Neighbor API**: will provide ARP / ND cache
  introspection when shipped.
- **Socket factory**: socket-list introspection wraps
  `pytcp.stack.sockets` once consolidated.
