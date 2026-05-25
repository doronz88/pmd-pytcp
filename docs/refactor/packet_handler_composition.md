# Packet Handler — Mixin → Composition Collapse

A focused, tests-first plan to retire the 20-mixin diamond-inheritance
model in `packages/pytcp/pytcp/runtime/packet_handler/` in favour of
explicit composition. This document **supersedes Phases 6 and 7** of the
older `packet_handler_rewrite_plan.md` for the *current* codebase — the
seven Phase-3 API surfaces (link / address / route / neighbor /
introspection / sysctl / socket), the per-`ifindex` `InterfaceTable`,
the per-interface rings + caches, the egress seam, and the RFC 1812
`forward_or_deliver` seam have **already shipped** by a different route,
so the surrounding scaffolding the old plan assumed is in place. What
remains is the structural collapse itself.

No code lands in `__init__.py` until Sebastian signs off on the design
decisions in §7.

---

## 1. What we are fixing

`packages/pytcp/pytcp/runtime/packet_handler/__init__.py` is **2137
lines**:

- An abstract `PacketHandler(Subsystem, ABC)` carrying *all* per-interface
  state (rings, neighbor caches, ifaddr/multicast lists, IPv4 ID counter +
  lock, frag tables, the full ICMPv6 ND state cluster — default-router
  list, SLAAC table, temp-addr table, DAD state map, RA-parameter mirror,
  RFC 7217 secret), the addressing-acquisition threads, the subsystem
  lifecycle hooks, the TX marshalling funnel, and the `get_icmp6_*`
  introspection accessors.
- A concrete `PacketHandlerL2(PacketHandler, …20 mixins…)` (TAP) and
  `PacketHandlerL3(PacketHandler, …14 mixins…)` (TUN).
- 20 `PacketHandler<Proto><Dir>(ABC)` mixin files. **Each one** re-declares
  the cross-mixin attributes and method signatures it depends on inside an
  `if TYPE_CHECKING:` block — e.g. `packet_handler__ethernet__rx.py`
  declares `_packet_stats_rx`, `_mac_unicast`, `_ifindex`, `_ip4_support`,
  and stub `_phrx_arp` / `_phrx_ip6` / `_phrx_ip4` signatures.

The smell is the **`TYPE_CHECKING` declaration block**: it is an
*unenforced* contract. mypy type-checks each mixin against the shadow
attributes the mixin *claims* its eventual `self` will have; nothing
proves the diamond actually supplies them, nothing flags a mixin that
reads an attribute it forgot to declare, and a reader cannot tell from a
`self._phrx_ip6(...)` call site which of the 20 bases provides the method.
The 2137-line file and the 20-deep MRO are the symptoms; the unprovable
shared-`self` is the disease.

## 2. Hard constraints (must survive the refactor)

1. **The handler IS the interface object.** `stack.interfaces[ifindex]`
   maps to a `PacketHandlerL2 | PacketHandlerL3`; `stack.egress_packet_handler(dst)`
   returns one; `InterfaceTable.add(handler)` stamps `handler._ifindex`.
   The four sibling control APIs and `TcpSession` reach into the handler:
   - **TX entry:** `send_tcp_packet`, `send_udp_packet`, `send_ip4_packet`,
     `send_ip6_packet`, `send_icmp4_packet`, `send_icmp6_packet`,
     `send_arp_request`, `send_arp_unicast_request`, the ND `send_icmp6_*`
     family, `send_link_frame`.
   - **State / introspection reach-ins:** `_ip4_ifaddr`, `_ip6_ifaddr`,
     `_arp_cache`, `_nd_cache`, `_interface_layer`, `_interface_name`,
     `_interface_mtu`, `_mac_unicast`, `_assign_ip*` / `_remove_ip*`,
     `_packet_stats_rx` / `_packet_stats_tx`, `_link_stats`, the
     `get_icmp6_*` accessors.

   This surface must remain on `PacketHandlerL2` / `PacketHandlerL3`
   verbatim. The collapse is internal; consumers see no change.
2. **RX entry points stay callable on the handler.** The subsystem loop
   and the legacy `NetworkTestCase` harness drive `_phrx_ethernet`,
   `_phrx_ethernet_802_3`, `_phrx_ip4`, `_phrx_ip6` directly.
3. **Subsystem lifecycle** (`start` / `stop` / `_start` /
   `_subsystem_loop`) stays on the handler — it extends `Subsystem`.
4. **TX single-writer marshalling.** Every `_phtx_*` call funnels through
   `_marshal_tx` → `_tx_ring.dispatch(run)` so per-interface TX state is
   written by one thread. The one funnel must remain.
5. **mypy strict, no overrides.** Replacement references must fully check;
   the win is that they check *for real* instead of against a shadow decl.
6. **11315 tests green throughout**, per-protocol revertible. The 22
   `tests/unit/runtime/packet_handler/*` files (each with a
   `_StubHandler(Mixin)` subclass) and the 10
   `tests/integration/packet_handler/test__packet_handler__*` files are the
   behavioural net.

## 3. Recommended design — "Interface as context"

Keep **all state and lifecycle on the handler**; turn each **mixin into a
standalone sub-handler class** that holds a typed back-reference to the
interface and reaches its shared state through that reference. This is how
Linux models it: the per-protocol ops hang off `struct net_device` and
reach back into it (`nd_*`, `ndo_*`), rather than each op owning a copy of
the device state.

### 3.1 Shape

```python
# packet_handler__ethernet__rx.py  (after)
class EthernetRxHandler:
    """Inbound Ethernet II demux + AF_PACKET tap for one interface."""

    def __init__(self, *, interface: PacketHandler) -> None:
        self._if = interface

    def process(self, packet_rx: PacketRx, /) -> None:
        self._if._packet_stats_rx.ethernet__pre_parse += 1
        ...
        # cross-call into the next layer, via the interface hub:
        self._if._phrx_ip6(packet_rx)
```

- The `if TYPE_CHECKING:` declaration block is **deleted**. Where the mixin
  body said `self._packet_stats_rx`, it now says `self._if._packet_stats_rx`
  — a real typed attribute access mypy verifies against `PacketHandler`'s
  declared attributes. A forgotten/renamed attribute is now a hard mypy
  error, not a silently-stale shadow.
- `PacketHandler.__init__` constructs the sub-handlers it needs (L2: all
  ten protocols × both directions; L3: the seven non-link protocols) and
  stores them: `self._ethernet_rx = EthernetRxHandler(interface=self)`, etc.
- **The handler keeps the public method names as thin delegators**, so
  every external + cross-call site is unchanged:
  ```python
  def _phrx_ethernet(self, packet_rx: PacketRx, /) -> None:
      self._ethernet_rx.process(packet_rx)

  def send_tcp_packet(self, *, ...) -> TxStatus:
      return self._tcp_tx.send(...)
  ```
  Cross-protocol calls inside a sub-handler hop through the interface hub
  (`self._if._phrx_ip6(...)` → the 1-line delegator → `self._ip6_rx.process(...)`).
  Behaviourally identical to today's MRO resolution, but the indirection is
  now an explicit, greppable method on a named object.

### 3.2 What changes, what stays

| | Before | After |
|---|---|---|
| `PacketHandlerL2` bases | `PacketHandler` + 20 mixins | `PacketHandler` only |
| `PacketHandlerL3` bases | `PacketHandler` + 14 mixins | `PacketHandler` only |
| Mixin file | `class …(ABC)` + `TYPE_CHECKING` decl block | `class …Handler` + `__init__(interface=)`, no shadow block |
| Cross-call `self._phrx_ip6(p)` | MRO-resolved | `self._if._phrx_ip6(p)` → handler delegator |
| Shared state `self._ip6_ifaddr` | implicit on shared `self` | `self._if._ip6_ifaddr` (typed) |
| Per-interface state + lifecycle | on `PacketHandler` | unchanged on `PacketHandler` |
| External surface (`send_*`, `_phrx_*`, state attrs) | on the handler | unchanged (thin delegators) |

### 3.3 End state

- 20 mixin files → 20 sub-handler files (≈ same per-file size; the body is
  the same logic with `self._if.` prefixes and no `TYPE_CHECKING` block).
- `__init__.py` loses the 20/14-deep inheritance lists and gains a
  sub-handler construction block + thin delegators. It still owns the base
  state, the ND-state methods, the addressing threads, and the lifecycle —
  realistically **~1300–1500 lines**. This plan does **not** claim the
  ≤200-line target from the old doc: that target assumed state was *also*
  relocated into per-AF device-state objects (old-plan Phase 4), which is a
  **separate** concern deliberately left out of scope here (see §6).
- The diamond is gone; the unprovable shadow contract is gone; each
  sub-handler is a real, independently-constructable, fully-typed class.

## 4. Alternatives considered (and why not)

- **Separate `InterfaceContext` state object.** Move all shared state off
  the handler into a `ctx` both the handler and sub-handlers reference.
  Cleaner state/behaviour split, shrinks the handler more — but every state
  access in the base, *and* every sibling-API reach-in
  (`handler._ip4_ifaddr` in address/neighbor/link APIs, `TcpSession`) would
  have to move to `handler._ctx.ip4_ifaddr` or be re-exposed as handler
  properties. Much larger blast radius, not cleanly per-protocol. **Defer**
  — it can layer on top of the recommended design later if wanted, decoupled
  from the mixin collapse.
- **Direct sub-handler↔sub-handler references** (no hub delegators).
  Slightly "purer" composition, but needs a wiring pass and edits at every
  cross-call site, and the external surface still needs handler delegators
  anyway. The hub-delegator approach is strictly less churn for the same
  behaviour. **Not chosen.**
- **Registration-dispatch table folded into each step.** Replacing the
  `match`/`case` demuxes with per-interface `{codepoint: handler.process}`
  registries (old-plan Phase 7) is a real win — it is where "an L3 interface
  doesn't register the Ethernet handler" becomes a one-liner — but folding
  it in per-protocol couples two changes. **Do it as the final sub-phase**
  (§5, step 11), after every mixin is a sub-handler, as one focused,
  separately-revertible commit.

## 5. Phased migration (per-protocol, tests-first, one commit pair each)

Order: leaves first (fewest things depend on them), the demux hub and the
EH-chain walker last, so cross-call delegators accrete gradually and each
step is small and revertible. Cross-call counts (RX/TX decls) drove the
order:

| Step | Protocol | Coupling (rx/tx) | Notes |
|---|---|---|---|
| 1 | ARP | 3 / 5 | L2-only, near-leaf — first to prove the pattern |
| 2 | Ethernet-802.3 | 4 / 1 | L2-only |
| 3 | UDP | 4 / 4 | calls ip4/ip6 tx + icmp error emit |
| 4 | TCP | 2 / 4 | |
| 5 | ICMPv4 | 2 / 3 | |
| 6 | ICMPv6 | 4 / 10 | heavy TX (ND emit family) |
| 7 | IPv6-frag | 2 / 2 | |
| 8 | IPv4 | 5 / 3 | |
| 9 | IPv6 | 10 / 4 | heaviest RX (EH chain walker) |
| 10 | Ethernet II | 4 / 2 | the top demux hub — last |
| 11 | — | — | registration-dispatch table (replace `match`/`case` demuxes) |
| 12 | — | — | final sweep: confirm `__init__.py` carries no mixin inheritance, audit line count, delete dead `TYPE_CHECKING` import residue |

**Each protocol step (1–10):**
1. **Tests-first.** Adjust that protocol's `tests/unit/runtime/packet_handler/test__…__<proto>__<dir>.py`: its `_StubHandler(Mixin)` subclass becomes a real `<Proto><Dir>Handler(interface=<stub interface>)` construction. The stub interface is a small `create_autospec(PacketHandler, spec_set=True)` (or a minimal real handler) carrying just the attributes the sub-handler reads. Watch the test fail (import/attribute error) before the impl lands.
2. **Impl.** Convert the mixin file to a sub-handler class; delete its `TYPE_CHECKING` block; prefix shared-state reads with `self._if.`; instantiate it in `PacketHandler.__init__`; add the thin delegator(s) on the handler; remove the mixin from the `PacketHandlerL2`/`L3` base list.
3. **Gate.** `make lint` (mypy strict, 472 files) clean, full `make test` (~80 s) green, §7.2 docstring audit clean on touched test files.
4. **Commit** the pair (push only when asked).

**Step 11 (registration table):** new `dispatch.py` with typed
`EthertypeRegistry` / `IpProtoRegistry` / `Ip6ExtHdrRegistry`; the handler
builds the registry for its layer at construction; the Ethernet demux, the
L3 TUN-PI demux in `_subsystem_loop`, and the IPv6 EH-chain `match` consult
the registry. Tests: an L3 interface's EtherType registry is empty (no
ARP); a registered fake handler is the only dispatch path.

**Behavioural-equivalence net:** every step keeps the full 22 unit +
10 legacy integration + all protocol integration suites green. No new
behaviour is introduced; the only assertions added are
"sub-handler constructs standalone and its RX/TX entry behaves identically".

## 6. Explicitly out of scope

- **State relocation into per-AF device-state objects** (old-plan Phase 4:
  `Ip4DeviceState` / `Ip6DeviceState` / `Icmp6NdState`). The handler stays
  the state bag here. Relocating state is a *separate* refactor that can
  layer on later; bundling it would balloon the blast radius and break the
  per-protocol revertibility.
- **Moving periodic ND housekeeping off the RX hot path onto `Timer`**
  (old-plan Phase 5). `_maybe_run_periodic_tasks` stays where it is.
- **Multi-interface *activation*.** The infrastructure (per-ifindex table,
  per-interface rings/caches) already exists; lighting up N live interfaces
  is its own track.

## 7. Decisions (confirmed by Sebastian 2026-05-24)

| # | Decision | Resolution |
|---|----------|------------|
| 1 | Shared-state carrier | **CONFIRMED — Interface-as-context** (§3): state stays on the handler; sub-handlers hold a typed `_if` back-ref. Not a separate `InterfaceContext`. |
| 2 | Cross-handler dispatch | **CONFIRMED — Hub delegators** (§3.1): cross-calls hop through the handler's thin `_phrx_*`/`send_*` methods. Not direct sub-handler refs. |
| 3 | Registration table | **CONFIRMED — Final sub-phase** (step 11), one focused commit — not folded into each protocol step. |
| 4 | Scope | **CONFIRMED — Mixin collapse only**; state relocation, Timer migration, multi-iface activation **out** (§6). |
| 5 | `__init__.py` size target | **CONFIRMED — No ≤200-line claim.** Realistic ~1300–1500 lines once the diamond + shadow blocks are gone; further shrink is the out-of-scope state-relocation work. |
| 6 | Migration order | **CONFIRMED — Leaves → hub** (§5): ARP, 802.3, UDP, TCP, ICMPv4, ICMPv6, IPv6-frag, IPv4, IPv6, Ethernet II, then registry. |

**Rationale captured at sign-off:** the separate-`InterfaceContext` /
state-relocation end state (decisions 1 & 4) is not foreclosed — it is a
*sequential follow-on*, not an alternative. Untangling the diamond and
relocating all state in one motion is two hard refactors superimposed
(no per-protocol revert points, blast radius across every sibling API +
`TcpSession`). Interface-as-context collapse first yields a clean,
fully-typed base from which a later state-extraction pass is mechanical
and optional. Collapse-only is a genuine stable resting point: removing
the diamond + the unprovable `TYPE_CHECKING` shadow blocks is the change
that makes the file comprehensible and the sub-handlers independently
testable; the residual size is legitimate interface state on the
interface object (Linux `struct net_device` parity).

## 8. Paired follow-on — legacy-harness retirement

After the collapse lands, the second multi-interface-track item is the
test-harness cleanup (old-plan Phases 1 + 10, now much smaller because the
APIs it assumed already exist):

- Introduce `packages/pytcp/pytcp/tests/lib/packet_handler_testcase.py`
  (`PacketHandlerTestCase`) — a packet-handler-focused base that constructs
  interfaces through the existing link/address APIs and drives RX via the
  handler's `_phrx_*` entry points, mirroring `TcpTestCase`.
- Migrate the 10 `tests/integration/packet_handler/test__packet_handler__*`
  files (and the relevant `tests/unit/runtime/packet_handler/*` `_StubHandler`
  files) onto it; delete the `NetworkTestCase` compat alias.

This is its own plan; it is **not** designed in detail here. It follows the
collapse because the new construction shape (sub-handlers over the
interface) is what the new harness wraps.

---

## References

- `docs/refactor/packet_handler_rewrite_plan.md` — the original 10-phase
  anchor. Its Phase-3-API / interface / FIB phases shipped by a different
  route; its Phases 6–7 are superseded by this document for the current
  codebase; its Phase 1 + 10 inform §8.
- Linux model: per-protocol ops hanging off `struct net_device`
  (`include/linux/netdevice.h`); the per-proto handler reaching back into
  the device is the `ndo_*` pattern this design mirrors.
