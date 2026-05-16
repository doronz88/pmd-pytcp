# Route API — Routing-control surface

| Field           | Value                                                                              |
|-----------------|------------------------------------------------------------------------------------|
| Status          | **not yet** — design only                                                          |
| Module path     | (TBD; expected `pytcp.lib.route_api`, exposed as `pytcp.stack.route`)              |
| Linux analogue  | `ip route add` / `ip route del` / `ip route show` / RTNETLINK `RTM_NEWROUTE`       |
| Refactor plan   | (TBD; will land when forwarding-plane work begins per the Phase-2 north-star)      |

## Purpose

The Route API will be PyTCP's routing-control consumer
surface — the canonical way to add / remove / list routes
and gateways, mirroring Linux's `ip route` family. Not yet
shipped because PyTCP today has no real route table: the
single-interface stack uses per-host `Ip4IfAddr.gateway` /
`Ip6IfAddr.gateway` for the default-route lookup, and there
is no FIB.

Per CLAUDE.md Project North Star Phase 2: **router-grade
parity** requires a real forwarding plane (FIB, IP
forwarding, ICMP Redirect generation, PMTU advertising on
transit, RFC 1812 requirements, IGMP/MLD querier role).
The Route API is the consumer-facing slice of that work.

## Current state (Phase-1 simplifications)

PyTCP's routing today is implicit:

- Outbound packets choose a gateway via the
  per-`Ip4IfAddr` / `Ip6IfAddr` `.gateway` attribute.
- "Are we on-link?" is decided by network-mask
  comparison against the bound host networks.
- No FIB; no LPM lookup; no policy routing; no metric.

When the Phase-2 forwarding plane lands, these
simplifications get replaced by a real route table —
and the Route API becomes the consumer surface for it.

## Anticipated surface (when shipped)

The shape will mirror the existing Address / Link APIs:

```python
# Read
stack.route.list_ip4_routes()       # → tuple[Ip4Route, ...]
stack.route.list_ip6_routes()       # → tuple[Ip6Route, ...]
stack.route.lookup_ip4(dst)         # → Ip4Route | None     (FIB-equivalent)
stack.route.lookup_ip6(dst)         # → Ip6Route | None

# Mutation — operator-facing
stack.route.add(route=Ip4Route(...))
stack.route.remove(destination=Ip4Network(...))
stack.route.set_default_gateway(version=IpVersion.IP4, gateway=Ip4Address(...))
```

The `Ip4Route` / `Ip6Route` value types are not designed
yet; they will live in `net_addr/` alongside `Ip4IfAddr` /
`Ip6IfAddr`.

## Linux equivalents the API needs to cover

- `ip route show` — list table.
- `ip route get <dst>` — single-destination FIB lookup.
- `ip route add <net> via <gw> dev <iface>` — install.
- `ip route del` — remove.
- `ip route flush` — wipe (per-table or whole).
- `ip route show table <name>` — multi-table support
  (deferred to a later Phase-2 sub-track).

## Deferred / out of scope

Per CLAUDE.md non-goals: **no userspace routing protocols**
(BGP, OSPF, RIP). Those belong outside the stack. The
Route API is for the static / kernel-managed route table
that operator tools and the RX-side forwarding decision
consume.

Other deferred items (Phase-2):

- ICMP Redirect emission (RFC 1812 §4.3.3.2 / RFC 1122
  §3.3.1.5) — the forwarder generates Redirects when an
  RX route lookup discovers the same-subnet next hop.
- RX route-cache update on received Redirect.
- Source-route forwarding (LSRR/SSRR pointer advance) —
  RFC 1122 §3.3.5.
- Multi-table / policy routing.

## Plan / history

- No refactor plan yet — will be drafted when the
  forwarding-plane track begins.
- Tracked under the Phase-2 north-star bucket in
  `docs/refactor/ip4_audit_punchlist.md`.

## Cross-API dependencies (anticipated)

- **Address API**: route → host binding is "which Ip4IfAddr
  is the source-address candidate for this route?" —
  Phase-1 source-selection logic ports over.
- **Link API**: routes carry an `oif` (outgoing
  interface); multi-interface Phase-2 makes this a real
  pointer to a per-interface Link API instance.
- **Sysctl**: `net.ipv4.conf.*.forwarding` — the master
  enable for the FIB-as-forwarder mode. Not registered
  today.
