# Address API unification — `Ip4AddressApi` → family-agnostic `AddressApi`

Status: **planned** (no code yet). Branch: `PyTCP_3_0_6`.

## 1. Goal

Collapse the IPv4-only `Ip4AddressApi` into a single, **family-agnostic**
`AddressApi` that manages both IPv4 and IPv6 host addresses through one
surface — the Linux `ip addr` / `RTM_NEWADDR` model. This closes the
multi-interface track's "IPv6 Address API" gap (today IPv6 hosts have
**no** control-plane API at all — they are mutated only through
`packet_handler._assign_ip6_host` internals).

This is the **Address** row of the CLAUDE.md Phase-3 North Star:

> | Address API (assign / remove **IPv4 / IPv6** host per interface) | Network-layer control | `ip addr` / `RTM_NEWADDR` |

One row, both families, mapped to `ip addr` — which is itself
family-agnostic.

## 2. Why now

Phase 4.4c/4.5 (the userspace ACD migration) stripped `Ip4AddressApi`
down to its pure `add` / `remove` / `replace` / `list` surface, deleting
the IPv4-only ACD methods (`probe` / `announce` / `claim_with_acd` /
`send_gratuitous_arp`) and the conflict-subscription machinery. Those
methods were **ARP/IPv4-specific** (RFC 5227) and could never have lived
on a family-agnostic surface — IPv6 uses ND/DAD, not ARP ACD. With them
gone, what remains is exactly the family-shaped `RTM_NEWADDR` primitive
set, so unification is now a clean rename + a v6 dispatch arm rather than
a surgical separation. **The ACD removal was the prerequisite.**

## 3. Linux model (the parity target)

In rtnetlink the address family is a **field**, not a verb. There is one
`RTM_NEWADDR` (with `ifa_family` = `AF_INET` / `AF_INET6`), one
`RTM_DELADDR`, one `RTM_GETADDR`. `ip addr add 10.0.0.5/24 dev eth0` and
`ip addr add 2001:db8::5/64 dev eth0` are the **same command/verb** — the
family is inferred from the prefix. `ip -4` / `ip -6` are display
filters.

So the faithful API has **single verbs**, family inferred from the
argument's value type (`isinstance` on `Ip4IfAddr` vs `Ip6IfAddr`,
`Ip4Address` vs `Ip6Address`) — exactly how `iproute2` parses the CLI.

## 4. Target API shape

```python
class AddressApi:
    # device selector — 'ip addr ... dev <ifX>'
    def interface(self, ifindex: int, /) -> "AddressApi": ...

    # 'ip addr add' / RTM_NEWADDR
    def add(self, *, ifaddr: Ip4IfAddr | Ip6IfAddr) -> None: ...

    # 'ip addr del' / RTM_DELADDR — keyed by address (matches RTM_DELADDR)
    def remove(
        self,
        *,
        address: Ip4Address | Ip6Address,
        abort_bound_sessions: bool = True,
    ) -> None: ...

    # 'ip addr replace' — add-then-remove ordering, both families
    def replace(
        self,
        *,
        old_address: Ip4Address | Ip6Address,
        new_ifaddr: Ip4IfAddr | Ip6IfAddr,
        abort_bound_sessions: bool = True,
    ) -> None: ...

    # 'ip addr show' — read-only copy-by-value snapshot, family-filterable
    def list_ifaddrs(
        self,
        *,
        family: AddressFamily | None = None,
    ) -> tuple[Ip4IfAddr | Ip6IfAddr, ...]: ...
```

Each verb dispatches on the address/ifaddr value type. `family=None` on
`list_ifaddrs` returns both families (IPv4 first, then IPv6); a specific
`family` filters. The `stack.address` attribute name is unchanged; only
the class is renamed `Ip4AddressApi` → `AddressApi`.

### Naming decisions

- **`add` / `remove` / `replace` / `list_ifaddrs`** (drop the `_ifaddr`
  verb suffix and the `ip4_` arg prefix). Matches `ip addr
  add/del/replace/show`. `list_ifaddrs` (not bare `list`, which shadows
  the builtin; not `show`, to keep the PyTCP `list_*` convention from
  NeighborApi/RouteApi).
- Kwargs: `ifaddr=`, `address=`, `old_address=` / `new_ifaddr=`,
  `family=`. No family in the verb name.

## 5. IPv6-specific behaviour the verbs MUST handle

IPv4 and IPv6 host installs are **not** symmetric. The dispatch arms
differ in three ways the doc pins so the implementation doesn't silently
drop a side-effect:

1. **Solicited-node multicast join/leave.** Installing an IPv6 host joins
   its solicited-node multicast group (and, on L2, the derived multicast
   MAC + an MLD report); removing it leaves the group. IPv4 has no such
   step. The v6 arm routes through the existing
   `PacketHandler._assign_ip6_host` / `_remove_ip6_host` (which already
   call `_assign_ip6_multicast` / `_remove_ip6_multicast`, themselves
   per-layer-overridden so L3/TUN skips the MAC side). The IPv4 arm keeps
   the current direct `_ip4_ifaddr` rebind.

2. **Thread-safe mutation (atomic rebind).** The IPv4 arm rebinds
   `_ip4_ifaddr = [*old, new]` so the TX worker (reading the list during
   source-address selection on another thread) always sees the old or new
   list whole. The current `_assign_ip6_host` uses in-place
   `.append()` / `.remove()` — **not** atomic-rebind. Decision: the v6 arm
   must adopt the same atomic-rebind discipline. Either refactor
   `_assign_ip6_host` / `_remove_ip6_host` to rebind, or have the API do
   the rebind and call a SNM-join helper. (Pre-existing latent v6 race;
   fix it here rather than inherit it.)

3. **DAD is NOT in the API.** Linux's kernel `RTM_NEWADDR` for v6 triggers
   kernel DAD; PyTCP's DAD lives in `PacketHandler._claim_ip6_address_async`
   (RFC 4862/7527, optimistic DAD, RFC 7217/8981 regenerate-on-failure),
   driven by the SLAAC/boot path. `AddressApi.add` is the **install-now**
   primitive (mirrors today's `_assign_ip6_host`); it does **not** run
   DAD. This is deliberate and consistent with the ACD decision: protocol
   conflict-detection (ARP ACD, ND DAD) is a per-protocol concern, not an
   address-plane verb. The SLAAC path keeps calling
   `_claim_ip6_address_async` directly, then installs via the API (or via
   the internal assign — see §7 decision). A future explicit "DAD-then-add"
   convenience can layer on top but is out of scope here.

4. **`abort_bound_sessions` generalisation.** The internal
   `_abort_bound_tcp_sessions(ip4_address: Ip4Address)` helper must widen
   to `Ip4Address | Ip6Address` (it already matches on
   `socket_id.local_address`, which is family-agnostic). No logic change,
   just the type.

## 6. Internal-vs-API boundary (a deliberate non-change)

`AddressApi` is the boundary for **external** consumers (DHCP client,
link-local client, operator tooling). The packet handler's own SLAAC /
boot / RA paths that call `_assign_ip6_host` / `_remove_ip6_host`
**intra-handler** are not "userspace reach-through" and need not route
through the API — a handler calling its own method is fine. The API
wraps those methods for the external boundary. (If we later want the API
as the single mutation point even internally, that's a separate
consolidation; not required for unification.)

## 7. Implementation plan (tests-first, one focused commit or a small series)

1. **Rename + widen, IPv4 behaviour unchanged.** `Ip4AddressApi` →
   `AddressApi`; `add_ifaddr`→`add`, `remove_ifaddr`→`remove`,
   `replace_ifaddr`→`replace`, `list_ip4_ifaddrs`→`list_ifaddrs(family=)`.
   Verbs still IPv4-only internally but signatures accept the unions.
   Widen `_abort_bound_tcp_sessions` to `Ip4Address | Ip6Address`.
   Update every consumer + the `stack.address` annotation + lifecycle
   wiring in the same commit (no back-compat shim — no installed base).
   Tests: rename the address-API unit tests; assert IPv4 behaviour
   unchanged.
2. **Add the IPv6 dispatch arm.** `add`/`remove`/`replace`/`list_ifaddrs`
   handle `Ip6IfAddr` / `Ip6Address` — SNM join/leave via the
   (rebind-fixed) `_assign_ip6_host` / `_remove_ip6_host`, family filter
   on `list_ifaddrs`, v6 session abort. Tests: a parallel IPv6 matrix +
   mixed-family `list_ifaddrs(family=None)`.
3. **Route the IPv6 boot/SLAAC install through the API where it is the
   external boundary** (decision point in §6 — likely leave intra-handler
   calls as-is). Confirm DHCP / link-local consumers compile against the
   renamed verbs.

Each step: `make lint` + full `make test` + §7.2 docstring audit;
refresh the address-API references in the RFC adherence docs if any cite
the old verb names.

## 8. Consumer migration (verb renames, same commit as step 1)

- `protocols/dhcp4/dhcp4__client.py` — `add_ifaddr` / `remove_ifaddr` /
  `replace_ifaddr` → `add` / `remove` / `replace`; the `address_api`
  param type `Ip4AddressApi | None` → `AddressApi | None`.
- `protocols/ip4/link_local/link_local__client.py` — `add_ifaddr` /
  `remove_ifaddr` → `add` / `remove`; param type.
- `stack/lifecycle.py` — `Ip4AddressApi(...)` construction (init +
  mock__init), the `address_view` selector.
- `stack/__init__.py` — `address: Ip4AddressApi` annotation + import.
- `stack/route.py` — docstring reference to `Ip4AddressApi.replace_ifaddr`.

## 9. Out of scope — tracked follow-up: normalize Route + Neighbor

The same single-verb / family-agnostic principle applies to the other
control APIs, which currently diverge from the netlink model:

- **`RouteApi`** uses **fully family-split verbs** (`add_ip4_route` /
  `add_ip6_route`, `replace_default_ip4` / `replace_default_ip6`,
  `list_ip4_routes` / `list_ip6_routes`) — Linux is one `RTM_NEWROUTE`
  verb + `rtm_family`. **Not aligned.**
- **`NeighborApi`** is a **hybrid** — `remove(ip: Ip4 | Ip6)` and
  `flush(family=)` are family-agnostic, but `add_static_arp` /
  `add_static_nd` and `list_arp` / `list_nd` are split. Linux is one
  `RTM_NEWNEIGH` + `ndm_family`. **Partially aligned.**

**Follow-up item (after this unification lands):** normalize `RouteApi`
and `NeighborApi` to the single-verb / family-agnostic shape
(`add(route)` / `delete(route)` / `replace_default(gateway)` /
`list_routes(family=None)`; `add(ip, mac)` / `delete(ip)` /
`flush(...)` / `list_neighbors(family=None)`), so all three control
planes are uniformly Linux-shaped. This is a separate, larger pass (every
caller + the route/neighbor consumers + their tests) and is deliberately
deferred — `AddressApi` sets the correct precedent first.

## 10. Test plan

- Rename `tests/unit/stack/test__stack__address.py` test classes to the
  new verbs; keep the `_abort_bound_tcp_sessions` and `remove`-aborts
  coverage.
- Add an IPv6 matrix: `add(Ip6IfAddr)` joins SNM (+ MAC multicast on L2),
  `remove(Ip6Address)` leaves it, `list_ifaddrs(family=AF_INET6)` filters,
  `list_ifaddrs()` returns both families.
- Assert the v6 `add`/`remove` use atomic-rebind (the list object identity
  changes) — the thread-safety fix from §5.2.
- Integration: confirm DHCPv4 BOUND install and RFC 3927 link-local
  install still drive the renamed verbs (existing client tests, updated
  for the rename).
