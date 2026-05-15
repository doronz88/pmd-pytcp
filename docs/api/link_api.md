# Link API — Link-control surface

| Field           | Value                                                                                                    |
|-----------------|----------------------------------------------------------------------------------------------------------|
| Status          | shipped 2026-05-12 (Phases 0-5)                                                                          |
| Module path     | `pytcp.stack.link` (exposed as `pytcp.stack.link`)                                                     |
| Linux analogue  | `ip link show` / `ip link set` / RTNETLINK `RTM_NEWLINK` / `RTM_GETLINK` / `RTM_SETLINK`                 |
| Refactor plan   | `docs/refactor/link_api.md` (6-phase plan + §6 design decisions)                                          |
| Memory pointer  | `reference_link_api.md`                                                                                  |

## Purpose

The Link API is PyTCP's link-control consumer surface —
the canonical way for consumer code to read interface
state (MAC, MTU, name, running flag, flags, stats) and to
mutate the link-level configuration (set_mtu,
set_mac_address). Mirrors Linux's `ip link show` / `ip
link set` ergonomics with subset semantics scoped to a
single-interface stack.

Replaced the historical `packet_handler._mac_unicast` /
`._interface_mtu` reach-through that DHCPv4 and RFC 3927
link-local construction used at boot. Phase-3 alignment:
every consumer-visible link-level fact goes through this
API.

## Read surface

```python
from pytcp.stack import link

link.mac_address       # MacAddress | None       (None on L3 / TUN — no Ethernet)
link.mtu               # int                     (interface MTU in bytes)
link.name              # str | None              ("tap7", "tun7"; None when not plumbed)
link.interface_layer   # InterfaceLayer          (.L2 = TAP, .L3 = TUN)
link.is_running        # bool                    (True after start(), False after stop())
link.flags             # frozenset[LinkFlag]     (derived from interface_layer)
link.stats             # LinkStats               (frozen 8-bucket snapshot)
```

### `LinkFlag` enum

Mirrors the meaningful subset of Linux's `IFF_*`:

| Flag         | Set when                                                |
|--------------|---------------------------------------------------------|
| `BROADCAST`  | L2 (TAP) — Ethernet supports broadcast                   |
| `MULTICAST`  | L2 (TAP) — Ethernet supports multicast                   |
| `LOOPBACK`   | future loopback adapter (no consumer today)              |
| `POINTOPOINT`| L3 (TUN) — no L2 broadcast domain                        |

```python
{LinkFlag.BROADCAST, LinkFlag.MULTICAST}  # L2 (TAP)
{LinkFlag.POINTOPOINT}                    # L3 (TUN)
```

### `LinkStats` dataclass

Frozen 8-bucket snapshot — Linux's `struct
rtnl_link_stats64` first-eight equivalent surfaced by
`ip -s link show`.

| Field        | Mapped from                                                                       |
|--------------|-----------------------------------------------------------------------------------|
| `rx_packets` | L2: `ethernet__pre_parse` + `ethernet_802_3__pre_parse`; L3: `ip4__pre_parse + ip6__pre_parse` |
| `rx_bytes`   | `LinkStatsCounters.rx_bytes` (bumped by `RxRing` per `os.read`)                    |
| `rx_errors`  | sum of all `PacketStatsRx.*__failed_parse__drop` fields                             |
| `rx_dropped` | sum of `PacketStatsRx.*__drop` fields EXCEPT `*__failed_parse__drop`                |
| `tx_packets` | L2: `ethernet__pre_assemble + ethernet_802_3__pre_assemble`; L3: `ip4__pre_assemble + ip6__pre_assemble` |
| `tx_bytes`   | `LinkStatsCounters.tx_bytes` (bumped by `TxRing` per `enqueue`)                    |
| `tx_errors`  | sum of `PacketStatsTx.tx_ring__*__drop` fields (kernel-level TX failures)           |
| `tx_dropped` | sum of `PacketStatsTx.*__drop` fields EXCEPT `tx_ring__*__drop`                     |

The aggregation logic walks dataclass fields by name
pattern via `_sum_drops()`, so new `*__drop` counters
added by future protocol work automatically land in the
right bucket.

`LinkStatsCounters` is a sibling dataclass at
`pytcp.lib.packet_stats.LinkStatsCounters` — NOT new
fields on `PacketStatsRx` / `PacketStatsTx`. This keeps
the strict `exact=True` integration-test regression net
working on the existing per-protocol stats objects.

## Mutation surface

```python
link.set_mtu(mtu=1400)                                  # propagates to packet_handler + stack + rings
link.set_mac_address(mac_address=MacAddress("02:..."))  # requires stack stopped
```

### `set_mtu(*, mtu: int) -> None`

- Validates `LINK_API__MTU__MIN` (68; RFC 791 §3.2 floor)
  ≤ mtu ≤ `LINK_API__MTU__MAX` (65535; uint16 wire limit).
- Propagates to `packet_handler._interface_mtu`,
  `stack.interface_mtu`, and the TX/RX ring `_mtu`
  fields (ring writes wrapped in `try/except
  AttributeError` to tolerate mock fixtures and
  `autospec(spec_set=True)` proxies).
- Raises `ValueError` on out-of-range.

**Note:** values below 1280 break IPv6 (RFC 8200 §5).
PyTCP does not enforce the higher floor today because
there is no per-interface IPv6 enable/disable knob to
release the constraint when an operator wants an
IPv4-only low-MTU link. The operator owns the
consequences.

### `set_mac_address(*, mac_address: MacAddress) -> None`

- **Precondition:** the stack must be stopped
  (`stack.start()` not run yet, or `stack.stop()` already
  run; i.e. `not stack.stack_running`). Mirrors Linux's
  `ip link set down` precondition for `ip link set
  address`. Raises `RuntimeError` if the stack is
  running.
- Rejects L3 (TUN) handlers — no Ethernet layer; raises
  `RuntimeError`.
- Validates via `MacAddress.is_unicast` (handles both
  the IEEE 802 multicast bit and the all-zero case in
  one call). Raises `ValueError` on a non-unicast MAC.
- Updates `packet_handler._mac_unicast`.

**Stale peer ARP / ND caches.** After
`set_mac_address`, peers retain entries for the old MAC
until they age out naturally. Consumers that need
immediate refresh should call
`stack.address.send_gratuitous_arp(address=...)` for
every owned IPv4 host after the next `stack.start()`.
Automatic announce scheduling is deferred.

## Module-level state added in Phase 2

The `stack_running: bool` flag on `pytcp.stack` is the
running-flag backing for `is_running`. Maintained by
`stack.start()` (sets True) / `stack.stop()` (sets
False) / `mock__init()` (resets to False per-test).

The flag is included in `_STACK__PATCHED_ATTRS` in the
`NetworkTestCase` harness so it snapshots / restores per
test — per the existing memory rule
`feedback_stack_module_state_test_isolation`.

## Examples

### Read interface state

```python
from pytcp.stack import link

print(f"interface: {link.name or '(no name)'}")
print(f"  mac: {link.mac_address or '(none)'}")
print(f"  mtu: {link.mtu}")
print(f"  layer: {link.interface_layer.name}")
print(f"  running: {link.is_running}")
print(f"  flags: {[f.name for f in link.flags]}")
```

### Dashboard-style stats

```python
from pytcp.stack import link

s = link.stats
print(f"RX: {s.rx_packets} pkts, {s.rx_bytes} bytes, "
      f"{s.rx_errors} errors, {s.rx_dropped} dropped")
print(f"TX: {s.tx_packets} pkts, {s.tx_bytes} bytes, "
      f"{s.tx_errors} errors, {s.tx_dropped} dropped")
```

### Change MTU at runtime

```python
from pytcp.stack import link

link.set_mtu(mtu=9000)   # jumbo frames
```

### Change MAC (stack must be stopped first)

```python
from net_addr import MacAddress
from pytcp import stack

stack.stop()
stack.link.set_mac_address(mac_address=MacAddress("02:aa:bb:cc:dd:ee"))
stack.start()
# Optionally re-announce owned hosts:
for host in stack.address.list_ip4_hosts():
    stack.address.send_gratuitous_arp(address=host.address)
```

## Deferred / out of scope

Per the plan §6.3 and §6.6:

- **`up()` / `down()` methods** — deferred to the Phase-2
  multi-interface track. Phase-1 has no consumer demand
  (tests and examples call `stack.start/stop` directly);
  Phase-2 needs real per-interface lifecycle with
  different semantics.
- **Multi-interface API shape** — Phase-1 is
  `stack.link.X`; Phase-2 will become
  `stack.link["tap7"].X`. Breaking change at the seam;
  mechanical migration of all call sites.
- **`rx_multicast` / `tx_multicast` counters in
  `LinkStats`** — Linux's `struct rtnl_link_stats64`
  includes them; PyTCP defers until a consumer needs them.
- **Automatic gratuitous-announce on `set_mac_address`**
  — requires persistent re-announce state across
  stop/start. Deferred until a real consumer needs it.
- **Hardware-offload / multi-queue / qdisc flags** —
  out of scope per CLAUDE.md Project North Star
  non-goals.

## Plan / history

- Plan doc: `docs/refactor/link_api.md` (~600 lines with
  all six §6 design decisions documented).
- Commits (all on `PyTCP_3_0__pre_release`): `41f7fd58`
  (§6 decisions), `cdc11324` (Phase 0), `3ceb4432`
  (Phase 1), `efa64c8c` (Phase 2), `5bb2cf2f` (Phase 3),
  `d4aed533` (Phase 4).
- Memory entry: `reference_link_api.md`.

## Cross-API dependencies

- **Address API**: consumers calling
  `stack.address.send_gratuitous_arp(...)` after a
  `set_mac_address` to refresh peer caches.
- **Sysctl**: no current overlap; `LINK_API__MTU__MIN/MAX`
  are protocol invariants (RFC 791 §3.2 / uint16),
  not sysctls.
