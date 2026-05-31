# Address API — Network-layer-control surface

| Field           | Value                                                                          |
|-----------------|--------------------------------------------------------------------------------|
| Status          | shipped (RFC 3927 track)                                                       |
| Module path     | `pytcp.stack.address` (exposed as `pytcp.stack.address`)                     |
| Linux analogue  | `ip addr add` / `ip addr del` / RTNETLINK `RTM_NEWADDR` / `RTM_DELADDR`        |
| Refactor plan   | `docs/refactor/rfc3927_link_local_autoconfig.md` (Phase 0.5 API extraction)   |

## Purpose

The Address API is PyTCP's network-layer-control consumer
surface — the canonical way to add / remove IPv4 host
addresses on the stack, run RFC 5227 Address Conflict
Detection (ACD), and subscribe to post-claim conflict
events. Mirrors Linux's `ip addr` ergonomics + the
`n-acd` / `sd_ipv4ll_start` library's ACD primitives.

Phase-1 implementation is `Ip4AddressApi` — IPv4 only.
A future `Ip6AddressApi` (or unified `AddressApi`) will
land when an IPv6-specific address-control consumer
materialises.

Per CLAUDE.md Phase-3: **the surface IS the Phase-3
seam**. The DHCPv4 client (`packages/pytcp/pytcp/protocols/dhcp4/`)
and the RFC 3927 link-local autoconfig client
(`packages/pytcp/pytcp/protocols/ip4/link_local/`) consume the API
without reaching into `packet_handler._ip4_ifaddr`.

## Address-list management

```python
from pytcp.stack import address
from net_addr import Ip4IfAddr

# Install — Linux 'ip addr add 10.0.0.5/24 dev eth0'.
address.add_ifaddr(ip4_ifaddr=Ip4IfAddr("10.0.0.5/24"))

# List — Linux 'ip addr show' / '/proc/net/route' equivalent.
hosts = address.list_ip4_ifaddrs()         # tuple[Ip4IfAddr, ...]; copy-by-value snapshot

# Remove — Linux 'ip addr del'.
address.remove_ifaddr(ip4_address=Ip4Address("10.0.0.5"))

# Replace — atomic-ish swap (new added before old removed).
address.replace_ifaddr(
    old_address=Ip4Address("10.0.0.5"),
    new_ifaddr=Ip4IfAddr("10.0.0.6/24"),
)
```

### TCP-session ABORT policy on remove / replace

`remove_ifaddr` and `replace_ifaddr` accept
`abort_bound_sessions: bool = True` (the default). When
True, every TCP session bound to the removed local
address is issued `SysCall.ABORT` (RFC 9293 §3.10.7.4 —
emits RST and tears the session down).

This is a deliberate **deviation from Linux**, which
silently leaves bound sessions to rot. PyTCP follows RFC
5227 §2.4-final SHOULD ("immediately discontinue use").
Pass `abort_bound_sessions=False` for diagnostics or
where the caller has its own teardown discipline.

## RFC 5227 Address Conflict Detection

The ACD surface is the bulk of the API and is shared
between DHCPv4 (DAD during DISCOVER → ARP-Probe sequence)
and RFC 3927 link-local (per-candidate Probe + Announce).

### Probe → Announce → Install (composite)

```python
result = address.claim_with_acd(ip4_ifaddr=Ip4IfAddr("169.254.5.7/16"))
if result.success:
    # Probe was clean, announce burst fired, host is installed.
    print(f"Claimed {result.address}")
else:
    print(f"Conflict on {result.address}; sender MAC = {result.conflict_sender_mac}")
```

`claim_with_acd` is the canonical entry point: blocks for
the canonical PROBE_WAIT + PROBE_NUM probes + ANNOUNCE_WAIT
+ (ANNOUNCE_NUM-1)*ANNOUNCE_INTERVAL window (~5-9 s with
default `arp.*` sysctls). On clean probe the host is
installed; on conflict the host is NOT installed and the
conflicting peer MAC is reported.

### Individual primitives

```python
# Probe only — RFC 5227 §2.1.1 ARP Probe sequence.
result = address.probe(address=Ip4Address("10.0.0.5"))
# → ProbeResult(success=bool, address=Ip4Address, conflict_sender_mac=MacAddress | None)

# Announce only — RFC 5227 §2.3 gratuitous-ARP burst.
address.announce(address=Ip4Address("10.0.0.5"))

# Single-shot gratuitous ARP — RFC 5227 §2.4(b) defense.
address.send_gratuitous_arp(address=Ip4Address("10.0.0.5"))
```

L2 (TAP) only — ACD is an Ethernet/ARP operation. Calling
these on an L3 (TUN) stack raises `AttributeError` at
runtime.

### Conflict subscription

```python
def on_conflict(event: ConflictEvent) -> None:
    print(f"Conflict on {event.address} from {event.sender_mac} @ {event.timestamp}")

handle = address.subscribe_conflicts(
    address=Ip4Address("10.0.0.5"),
    on_conflict=on_conflict,
)
# ...later:
address.unsubscribe_conflicts(handle=handle)
```

The callback fires from the ARP RX thread; long work
should be deferred to the consumer's own thread. The
RFC 3927 link-local client uses this to implement §2.5
defend / abandon.

### TCP-session ABORT primitive

```python
# Used by RFC 3927 §2.5(a) link-local abandon paths and any
# future DHCPDECLINE-on-conflict consumer that needs to
# reset bound sessions before yielding the address.
address.abort_bound_tcp_sessions(address=Ip4Address("10.0.0.5"))
```

## Result types

```python
@dataclass(frozen=True, kw_only=True, slots=True)
class ProbeResult:
    success: bool
    address: Ip4Address
    conflict_sender_mac: MacAddress | None = None

@dataclass(frozen=True, kw_only=True, slots=True)
class ClaimResult:
    success: bool
    address: Ip4Address
    conflict_sender_mac: MacAddress | None = None

@dataclass(frozen=True, kw_only=True, slots=True)
class ConflictEvent:
    address: Ip4Address
    sender_mac: MacAddress
    timestamp: float

@dataclass(frozen=True, kw_only=True, slots=True)
class SubscriptionHandle:
    address: Ip4Address
    callback_id: int
```

All result types are frozen + slotted — copy-by-value per
the Phase-3 "introspection is read-only" constraint.

## Examples in the repo

- `packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py` — DHCP DAD via
  `address.probe(address=...)`; gratuitous announce via
  `address.announce(address=...)` at BOUND.
- `packages/pytcp/pytcp/protocols/ip4/link_local/link_local__client.py`
  — RFC 3927 §2.1.1 probe + §2.4 announce + §2.5 defend /
  abandon via the conflict-subscription surface.
- `packages/pytcp/pytcp/stack/__init__.py::init` — constructs the
  singleton `address: Ip4AddressApi` after
  `packet_handler` is built.

## Deferred / out of scope

- **IPv6 address control** — a unified `AddressApi` or
  parallel `Ip6AddressApi` is planned but not yet
  consumer-driven. SLAAC currently mutates
  `packet_handler._ip6_ifaddr` directly via the ND track's
  internal helpers; promoting that to a sanctioned API
  surface is a follow-up.
- **`ip addr show eth0` per-interface filter** — Phase-1
  is single-interface, so `list_ip4_ifaddrs()` returns the
  whole list. Multi-interface Phase-2 will need either
  per-interface API instances (`stack.address["tap7"]`)
  or an ifname-filtered list.
- **DHCPDECLINE on conflict** — partially supported via
  `abort_bound_tcp_sessions`; full DHCPDECLINE message
  emission is in the DHCPv4 client's deferred Phase-9
  backlog.

## Plan / history

- Refactor plan: `docs/refactor/rfc3927_link_local_autoconfig.md`
  (Phase 0.5 extracted the ACD API from inline DHCP /
  link-local code).
- Source: `packages/pytcp/pytcp/stack/address.py`.
- Adherence: `docs/rfc/ip4/rfc3927__ip4_link_local/adherence.md`.
- Per-RFC: `docs/rfc/ip4/rfc5227__address_conflict_detection/`
  (when authored).

## Cross-API dependencies

- **Link API**: `set_mac_address` consumers may call
  `address.send_gratuitous_arp(...)` after start() to
  refresh peer caches.
- **Sysctl**: ACD timing parameters (`arp.probe.*`,
  `arp.announce.*`) are sysctl-tunable.
