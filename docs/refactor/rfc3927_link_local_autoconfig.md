# RFC 3927 — IPv4 Link-Local Autoconfig Plan

| Field           | Value                                                                |
|-----------------|----------------------------------------------------------------------|
| Status          | Plan — implementation not yet started                                |
| Plan author     | Audit pass (2026-05-12)                                              |
| Source audit    | `docs/rfc/ip4/rfc3927__ip4_link_local/adherence.md`                  |
| Target branch   | `PyTCP_3_0__pre_release`                                             |
| Touch points    | new `pytcp/protocols/ip4/link_local/`, `pytcp/stack/address.py` (new ACD API surface), DHCP client (migrates to new API), `packet_handler__ip4__tx.py`, `packet_handler__ethernet__tx.py`, sysctl framework, RFC 3927 / 5227 / 2131 adherence records |
| Coupled records | RFC 1122 §3.3.4 (multihoming — out of scope), RFC 2131 (DHCP client — coordination + migration to new API), RFC 5227 (ACD — extracted into sanctioned API), RFC 6724 (IPv4 source selection — already in place) |
| Design option   | **Option B** — extract a Phase-3-clean ACD API on `Ip4AddressApi`; both DHCP and link-local consume it. Cleans up DHCP's existing `_arp_dad_probe_address` reach-through as a side effect. See §12.2 for the alignment rationale. |

This document is the implementation plan for closing the
RFC 3927 IPv4 Link-Local Autoconfiguration gap surfaced by the
2026-05-11 IPv4 audit pass. The plan is structured as a series
of independently-shippable phases so each commit is mechanically
reversible and the test surface grows in lockstep with the
implementation. The track is item D of the IPv4 audit punch
list (`docs/refactor/ip4_audit_punchlist.md`); the underlying
gap inventory is the RFC 3927 adherence record.

---

## 1. Goal

Implement RFC 3927 IPv4 Link-Local Address autoconfiguration as
a host-stack-parity feature: when DHCPv4 fails to acquire a
lease within a configurable window, the stack autoconfigures a
169.254/16 address using the §2.1 pseudo-random selection +
§2.2 ARP-probe + §2.4 ARP-announce protocol, defends the
address against conflicts per §2.5, and coexists with the DHCP
client per §2.11.

After this track lands, a PyTCP host on a DHCP-less link
behaves like Linux `avahi-autoipd` / `dhcpcd --link-local`:

- Falls back to 169.254/16 after a configurable DHCP-fail
  window (default off until operator opts in, mirroring Linux
  `net.ipv4.conf.<iface>.enable_ip4ll`).
- Picks a MAC-seeded candidate so reboots are idempotent
  (per §2.1 SHOULD).
- Runs the canonical RFC 5227 ARP-probe (3 probes, 1–2s
  spacing, 2s announce-wait) — reuses the existing
  `_arp_dad_probe_address` plumbing.
- Announces with 2 gratuitous ARPs after a clean probe.
- Defends or reconfigures on conflict per §2.5(a) / §2.5(b)
  decision rules.
- Gates `src.is_link_local != dst.is_link_local` mixes on TX
  per §2.6.
- Refuses to send link-local destinations through the default
  gateway per §2.8.
- Lets the DHCPv4 client keep trying in parallel; on a
  successful DHCP bind the link-local address is withdrawn
  per §2.11.

---

## 2. Current state — what the audit found

The 2026-05-11 RFC 3927 audit
(`docs/rfc/ip4/rfc3927__ip4_link_local/adherence.md`) lists:

### What's already in place — load-bearing for this track

- **`Ip4Address.is_link_local`** predicate covers 169.254/16
  (`net_addr/ip4_address.py`).
- **IP4 scope ordering** in `pytcp/lib/ip4_source_selection.py`
  recognises `IP4__SCOPE__LINK_LOCAL = 0x2`; RFC 6724 rule-2
  picks a link-local source when the destination is
  link-local.
- **ARP DAD machinery** (RFC 5227 §2.1.1 Probe / §2.3
  Announce) is implemented as `_arp_dad_probe_address` /
  `_arp_dad_announce_address` on the packet handler and
  reused by the DHCPv4 client + static-host claim path
  (`pytcp/runtime/packet_handler/__init__.py:1776-1828`).
- **`DadSlotRegistry`** (`pytcp/lib/dad_slot_registry.py`)
  provides the per-candidate conflict-signal slot the probe
  loop polls.
- **`Ip4AddressApi`** (`pytcp/stack/address.py`) exposes
  `add_host` / `remove_host` / `replace_host` as the
  kernel/userspace boundary for address installs — the
  Phase-3-clean surface link-local autoconfig writes to.
- **`Subsystem` base class** (`pytcp/runtime/subsystem.py`) and
  the `Dhcp4Client` reference implementation
  (`pytcp/protocols/dhcp4/dhcp4__client.py`) — the structural
  template for the new `Ip4LinkLocal` subsystem.

### Unmet (the gap this plan closes)

- **§1.9** — no DHCP-failure → link-local fallback trigger.
- **§2.1** — no pseudo-random address generator seeded from
  the MAC.
- **§2.2** — Probe machinery exists but no consumer for
  link-local.
- **§2.4** — Announce machinery exists but no consumer for
  link-local.
- **§2.5** — no defend-or-reconfigure decision tree; the ARP
  RX path can call a per-flow conflict signal but no
  link-local-specific handler is wired.
- **§2.6** — TX-side `src.is_link_local != dst.is_link_local`
  gate is absent. The adherence record marks this as a gap;
  practical impact today is zero (no caller path generates
  a 169.254 source) but it must land before the autoconfig
  subsystem so the gate is in place when the new consumer
  arrives.
- **§2.8** — TX path does not short-circuit link-local
  destinations away from the default gateway. Same
  zero-practical-impact / land-before-consumer logic.
- **§2.11** — no DHCPv4-client coordination hook.

Phase-2 / out-of-scope:

- **§3 Multi-interface** — PyTCP is single-interface
  (Phase 1). Multi-interface considerations are deferred to
  the Phase-2 multihoming track.
- **§4 Healing of Network Partitions** — informational; no
  PyTCP code surface.

---

## 3. Phased plan

The track ships as seven commits totalling ~3 calendar days.
Each phase is independently testable; phase 0 and phase 0.5
are standalone preparatory steps and can ship out of order
relative to each other but both must land before phase 1.

Phase 0.5 is the **Option B** work — extracting an
`Ip4AddressApi.claim_with_acd` / `subscribe_conflicts`
surface that turns the existing
`_arp_dad_probe_address` / `_arp_dad_announce_address`
reach-throughs into private implementation detail. Both DHCP
and the eventual link-local client consume the new API. This
draws a clean Phase-3 line that today is fuzzy (see §12.2 for
the architectural argument).

### Phase 0 — §2.6 TX-side scope-mismatch gate (1 commit; ~1.5 hours)

Standalone closure of the RFC 3927 §2.6 source/destination
scope-mismatch rule the adherence record flagged as a gap.
Lands before the autoconfig subsystem so the gate is in
place when link-local autoconfig populates `_ip4_host` with
a 169.254/16 entry. Zero practical impact today (no caller
generates a 169.254 source), which is why it shipped as a
gap in the IPv4 audit pass — closing it is a low-risk prep
step.

§2.8 (link-local-not-to-router) is examined alongside §2.6
and found to be **subsumed** — see §0.2 below.

**0.1 §2.6 source/destination scope-mismatch gate**

In `_phtx_ip4` after destination validation, reject any
combination where `src.is_link_local != dst.is_link_local`:

```python
# RFC 3927 §2.6: a host MUST NOT send a packet with a
# link-local source to a non-link-local destination, and a
# link-local destination MUST NOT be sent with a non-
# link-local source. The two halves of the rule are
# symmetric — link-local addressing is local-only.
if ip4__src.is_link_local != ip4__dst.is_link_local:
    self._packet_stats_tx.ip4__link_local_scope_mismatch__drop += 1
    return TxStatus.DROPPED__IP4__LINK_LOCAL_SCOPE_MISMATCH
```

Exception: the unspecified-source DHCP path (`src=0.0.0.0`)
short-circuits before this check, mirroring the existing
broadcast-gate carve-out from the `ip4.allow_broadcast`
commit.

**0.2 §2.8 subsumed by §2.6 — no separate gate**

Closer reading shows §2.8 cannot fire independently of §2.6
in PyTCP's host-stack model:

- If src is global and dst is link-local, §2.6 drops at the
  IPv4 layer.
- If src is unspecified (DHCP path) and dst is link-local,
  there's no such caller in PyTCP today and any future one
  would be the DHCP-fallback case which uses
  `dst=255.255.255.255`, not 169.254.
- If both src and dst are link-local (after autoconfig
  ships), the host has an `Ip4IfAddr("169.254.x.y/16")`
  configured. The Ethernet TX path's gateway branch
  triggers only when `ip4_dst not in ip4_host.network`;
  with the 169.254/16 host installed, any 169.254 dst IS
  in the network, so the gateway path is naturally
  skipped.

An explicit §2.8 short-circuit in `_phtx_ethernet` would be
dead code. The adherence record's §2.8 status flips from
"met vacuously" to "met (subsumed by §2.6)" with the
rationale documented inline.

**Wire-up:**

- New `TxStatus.DROPPED__IP4__LINK_LOCAL_SCOPE_MISMATCH`.
- New `PacketStatsTx.ip4__link_local_scope_mismatch__drop`
  counter.
- Roster test update (`test__lib__tx_status.py`,
  `test__lib__packet_stats.py` field_count).

**Tests-first:**

- Integration: `TestPacketHandlerIp4TxRfc3927ScopeGate`
  covering:
  - link-local source + global destination → dropped
  - global source + link-local destination → dropped
  - link-local source + link-local destination → allowed
    (passes the gate; downstream Ethernet TX handles the
    on-link resolution)
  - global source + global destination → unaffected
  - DHCP path (src=0.0.0.0) unaffected by gate

**Adherence refresh:** flip §2.6 from "gap" to "met"; flip
§2.8 from "met vacuously" to "met (subsumed by §2.6)" with
the rationale documented inline.

### Phase 0.5 — Extract the sanctioned ACD API (1 commit; ~1 day)

Refactor that draws the Phase-3 line. The RFC 5227 Address
Conflict Detection machinery currently lives as
`_arp_dad_probe_address` / `_arp_dad_announce_address` /
`_send_gratuitous_arp` on `PacketHandler`, called via reach-
through by both the DHCPv4 client (`Dhcp4Client`) and the
static-host claim path in `_create_stack_ip4_addressing`.
This phase wraps that machinery behind two new
`Ip4AddressApi` methods, migrates every existing consumer to
the public surface, and leaves the underlying helpers as
private detail.

The Linux analogues are `sd_ipv4ll` / `n-acd` — separate
libraries that NetworkManager / systemd-networkd consume. The
PyTCP equivalent is the in-process API on `Ip4AddressApi`.

**0.5.1 New API: `claim_with_acd`**

```python
# pytcp/stack/address.py
@dataclass(frozen=True, kw_only=True, slots=True)
class ClaimResult:
    """
    Outcome of a 'claim_with_acd' call. 'success=True' means
    the address was probed without conflict, announced, and
    installed via 'add_host'; the conflict fields are None.
    'success=False' means a conflicting ARP was observed
    during the probe window; the address is NOT installed and
    the conflict source is reported for diagnostic / retry
    logic.
    """

    success: bool
    address: Ip4Address
    conflict_sender_ip: Ip4Address | None = None
    conflict_sender_mac: MacAddress | None = None


class Ip4AddressApi:
    def claim_with_acd(self, *, ip4_host: Ip4IfAddr) -> ClaimResult:
        """
        Synchronously claim an IPv4 host: run the RFC 5227
        §2.1.1 ARP Probe sequence; if no conflict is observed,
        run the §2.3 ARP Announce sequence and install via
        'add_host'. Returns 'ClaimResult.success=True' on
        successful claim, 'success=False' with conflict
        source on conflict.

        Blocks for ~5-9 seconds — PROBE_WAIT + PROBE_NUM
        probes + ANNOUNCE_WAIT. Callers run on a dedicated
        thread (typically a 'Subsystem' subclass).
        """
```

**0.5.2 New API: `subscribe_conflicts`**

```python
# pytcp/stack/address.py
@dataclass(frozen=True, kw_only=True, slots=True)
class ConflictEvent:
    """
    Post-claim ARP conflict on a previously-installed
    address. Reported to every 'subscribe_conflicts' callback
    registered for that address.
    """

    address: Ip4Address
    sender_ip: Ip4Address
    sender_mac: MacAddress
    timestamp: float


@dataclass(frozen=True, kw_only=True, slots=True)
class SubscriptionHandle:
    """Returned by 'subscribe_conflicts'; pass to 'unsubscribe_conflicts'."""

    address: Ip4Address
    callback_id: int


class Ip4AddressApi:
    def subscribe_conflicts(
        self,
        *,
        address: Ip4Address,
        on_conflict: Callable[[ConflictEvent], None],
    ) -> SubscriptionHandle:
        """
        Register a callback for post-claim ARP conflicts on
        'address'. Fired from the ARP RX thread when a
        matching conflict is detected. Callbacks run on the
        caller's responsibility — long work should defer to
        the subsystem's own thread.
        """

    def unsubscribe_conflicts(
        self,
        *,
        handle: SubscriptionHandle,
    ) -> None: ...
```

**0.5.3 New API: `send_gratuitous_arp`**

```python
class Ip4AddressApi:
    def send_gratuitous_arp(self, *, address: Ip4Address) -> None:
        """
        Broadcast a single gratuitous ARP for 'address'.
        Public-API form of '_send_gratuitous_arp' on the
        packet handler. Used by RFC 3927 §2.5(b) defensive-
        ARP path and any future caller (RFC 5227 §2.4 conflict
        defense, RFC 8327 NUD-style updates, etc.).
        """
```

**0.5.4 Implementation: move the helpers behind the API**

The existing `_arp_dad_probe_address` /
`_arp_dad_announce_address` / `_send_gratuitous_arp` methods
on `PacketHandler` stay in place — but they become **private
implementation detail** called only by the API impl. The
`DadSlotRegistry` access pattern moves into the API as well:
callers no longer see `_ip4_arp_dad__registry`.

The conflict-routing path:

1. ARP RX detects a conflict (already implemented).
2. ARP RX consults the API's per-address subscription
   registry.
3. Matching subscribers' callbacks fire.

The subscription registry is a small `dict[Ip4Address,
list[Callback]]` owned by `Ip4AddressApi`. Concurrent
modification is fine — ARP RX appends, API consumers register
/ unregister on subsystem threads, the callback fan-out
copies the list under a lock.

**0.5.5 Migrate DHCP client**

DHCPv4's reach-through wasn't in the client itself — the client
holds `arp_dad_verifier` / `arp_dad_announcer` callbacks; the
reach-through lived at the WIRING point in
`pytcp/stack/__init__.py`, which bound the callbacks directly
to `packet_handler._arp_dad_probe_address` /
`_arp_dad_announce_address`. Phase 0.5 changes the wiring to
route through the API:

```python
# pytcp/stack/__init__.py
dhcp4_client = Dhcp4Client(
    mac_address=packet_handler._mac_unicast,
    arp_dad_verifier=lambda addr: address.probe(address=addr).success,
    arp_dad_announcer=lambda addr: address.announce(address=addr),
    address_api=address,
)
```

DHCP client code is untouched — it's already abstracted via the
callback interface. The Phase-3 line is drawn correctly: DHCP
no longer reaches into packet_handler internals (even
indirectly through the wiring), and the callbacks resolve via
the sanctioned `Ip4AddressApi` surface.

A future cleanup may collapse the verifier/announcer callbacks
into a single `address_api`-direct reference, but that's a
DHCP-internal refactor and out of scope for Phase 0.5's
reach-through closure.

**0.5.6 Migrate static-host claim path**

`pytcp/runtime/packet_handler/__init__.py::_create_stack_ip4_addressing`
currently has:

```python
for ip4_host in list(self._ip4_host_candidate):
    verified = self._arp_dad_probe_address(ip4_host.address)
    self._ip4_host_candidate.remove(ip4_host)
    if verified:
        stack.address.add_host(ip4_host=ip4_host)
        self._arp_dad_announce_address(ip4_host.address)
```

Becomes:

```python
for ip4_host in list(self._ip4_host_candidate):
    result = stack.address.claim_with_acd(ip4_host=ip4_host)
    self._ip4_host_candidate.remove(ip4_host)
    if result.success:
        # claim_with_acd already installed + announced
        log_success
```

**0.5.7 TCP-session abort on conflict (§2.5 SHOULD prep)**

The §2.5 abandon path needs to reset TCP sessions on the
abandoned address. Add the helper to `Ip4AddressApi`:

```python
class Ip4AddressApi:
    def abort_bound_tcp_sessions(self, *, address: Ip4Address) -> None:
        """
        Abort every active TCP session bound to the local
        address. Used by §2.5 abandon paths (link-local
        conflict reconfigure, DHCPDECLINE on lease conflict,
        operator-driven address remove). Mirrors the Linux
        'fib_validate_source' / 'inet_release' abort path.
        """
```

The DHCPv4 Phase 4 plan mentions this helper too; this phase
lands it so link-local Phase 3 can use it without coupling
to the DHCP track's ordering.

**Wire-up:**

- `Ip4AddressApi` grows the three new methods +
  `abort_bound_tcp_sessions`.
- `DadSlotRegistry` ownership migrates from `PacketHandler`
  to `Ip4AddressApi` (or remains on `PacketHandler` as a
  private detail; either works — the public surface is what
  matters).
- `packet_handler__arp__rx.py` calls the API's
  conflict-fan-out instead of touching a public registry.
- New PacketStats counters: `ip4__acd_claimed`,
  `ip4__acd_conflict_during_probe`, `ip4__acd_defended`,
  `ip4__acd_unsubscribed`.

**Tests-first:**

- Unit: `pytcp/tests/unit/lib/test__lib__address_api.py`
  extends with:
  - `TestIp4AddressApiClaimWithAcd` — clean claim succeeds,
    conflicting claim returns `success=False` with
    `conflict_sender_*` populated, address is NOT installed
    on failure.
  - `TestIp4AddressApiSubscribeConflicts` — callback fires
    on matching conflict, doesn't fire on non-matching,
    unsubscribe stops further fires.
  - `TestIp4AddressApiSendGratuitousArp` — single ARP
    Announcement emitted with `sender=address`,
    `target=address`.
  - `TestIp4AddressApiAbortBoundTcpSessions` — every TCP
    session whose local IP matches gets aborted; others
    untouched.
- Integration: existing DHCP integration tests stay green
  after the migration (they exercise `claim_with_acd`
  indirectly through DHCP's claim path).
- Integration: existing static-host integration tests stay
  green.
- §7.2 audit on every touched test file.

**Adherence refresh:**

- **RFC 5227 adherence record** — refresh the test-coverage
  section to point at the new API surface; flip the
  "implementation surface" paragraph to mention
  `Ip4AddressApi.claim_with_acd`.
- **RFC 2131 (DHCPv4) adherence record** — flip the
  Phase-3-cleanup note on the `_arp_dad_probe_address`
  reach-through from "deferred" to "closed in commit
  <hash>".

### Phase 1 — Subsystem skeleton + address selection (1 commit; ~4 hours)

The first half of the autoconfig state machine. Lands the new
`Ip4LinkLocal(Subsystem)` skeleton with a single state
(`INIT`) that picks a candidate but does not yet probe — the
probe wiring lands in Phase 2.

**1.1 New package `pytcp/protocols/ip4/link_local/`**

PEP 420 namespace package — no `__init__.py`. Files:

```
pytcp/protocols/ip4/link_local/
  link_local__client.py     # Subsystem + FSM driver
  link_local__constants.py  # sysctl registrations
  link_local__rng.py        # MAC-seeded address selector
```

**1.2 `Ip4LinkLocalState` enum**

```python
class Ip4LinkLocalState(Enum):
    """RFC 3927 link-local-autoconfig FSM state."""
    INIT = "INIT"           # No candidate selected; pick next
    CLAIMING = "CLAIMING"   # claim_with_acd() in flight (probe + announce + install)
    BOUND = "BOUND"         # Address installed; subscribed to conflict events
    HALTED = "HALTED"       # Disabled (e.g. DHCP succeeded, operator disabled)
```

The FSM is simpler than the raw RFC 3927 state diagram
because `claim_with_acd` collapses §2.2 (Probe) + §2.4
(Announce) into a single synchronous step. The internal
probe-vs-announce distinction is implementation detail of
the ACD API — link-local doesn't need to see it.

**1.3 `Ip4LinkLocal(Subsystem)` skeleton**

```python
class Ip4LinkLocal(Subsystem):
    """RFC 3927 IPv4 Link-Local autoconfig FSM."""

    def __init__(self, *, mac_address: MacAddress, ...) -> None:
        super().__init__(name="IPv4 Link-Local Autoconfig")
        self._mac = mac_address
        self._state: Ip4LinkLocalState = Ip4LinkLocalState.INIT
        self._candidate: Ip4IfAddr | None = None
        self._conflict_count: int = 0
        self._defend_history: list[float] = []
        self._cached_candidate: Ip4Address | None = None  # Phase 1.5

    @override
    def _subsystem_loop(self) -> None:
        match self._state:
            case Ip4LinkLocalState.INIT:
                self._do_init()
            case Ip4LinkLocalState.CLAIMING:
                self._do_claiming()
            case Ip4LinkLocalState.BOUND:
                self._do_bound()
            case Ip4LinkLocalState.HALTED:
                pass
```

**1.4 MAC-seeded address generator (§2.1)**

`pytcp/protocols/ip4/link_local/link_local__rng.py`:

```python
import struct
from net_addr import Ip4Address, MacAddress

# RFC 3927 §2.1: select from 169.254.1.0 to 169.254.254.255
# inclusive. First 256 (169.254.0.0/24) and last 256
# (169.254.255.0/24) are reserved.
_MIN_VALUE = int(Ip4Address("169.254.1.0"))
_MAX_VALUE = int(Ip4Address("169.254.254.255"))
_RANGE_SIZE = _MAX_VALUE - _MIN_VALUE + 1  # 65024


def candidate_from_mac(mac: MacAddress, *, attempt: int = 0) -> Ip4Address:
    """
    Generate a candidate 169.254/16 address from the MAC.

    The MAC's 48 bits + attempt counter feed a small Linear
    Congruential Generator seeded so different hosts diverge
    (per RFC 3927 §2.1 "different hosts do not generate the
    same sequence of numbers"). The 'attempt' counter rolls
    the seed forward on each retry so a conflict-driven
    regeneration picks a different candidate.
    """

    seed = struct.unpack("!Q", b"\x00\x00" + bytes(mac))[0]
    # LCG with Numerical-Recipes constants.
    value = (seed * 1103515245 + 12345 + attempt) & 0x7FFFFFFF
    return Ip4Address(_MIN_VALUE + (value % _RANGE_SIZE))
```

Determinism rationale: per RFC 3927 §2.1 SHOULD the same host
SHOULD pick the same address across reboots when no persistent
storage is used. Seeding from the MAC achieves this. The
`attempt` counter rolls the sequence forward on each conflict;
the §9 `MAX_CONFLICTS = 10` cap below the §9 `RATE_LIMIT_INTERVAL`
ceiling triggers the rate-limit phase.

**Phase 1 commit note:** the in-flight Phase 1 commit
trims the §1.5 cached-candidate persistence and §1.6 stack
integration to the minimum: the
`pytcp/protocols/ip4/link_local/` package ships with
`link_local__rng.py` (the MAC-seeded RNG) +
`link_local__constants.py` (file scaffolding only —
sysctls land in subsequent phases) +
`link_local__client.py` (the `Ip4LinkLocal` Subsystem
with INIT-state candidate selection). The stack-side
`stack.link_local: Ip4LinkLocal | None = None` slot is
declared with `mock__init` initialisation, the
test-harness snapshot/restore set is extended in lockstep
per `pytcp.md` §6.1, but no caller instantiates the
subsystem yet — Phase 4 wires the DHCP-fallback trigger
that actually starts it.

**1.5 Cached candidate (§2.1 MAY)**

RFC 3927 §2.1 last paragraph: hosts SHOULD prefer the
previously-claimed address on reboot if persistent storage is
available. Mirror the DHCP plan's `lease_cache_path` sysctl
pattern with a Phase-1.5 sub-knob:

```python
# pytcp/protocols/ip4/link_local/link_local__constants.py
IP4_LINK_LOCAL__CACHE_PATH = ""  # empty → no persistent cache

register(
    key="ip4_link_local.cache_path",
    module_name=__name__,
    attr="IP4_LINK_LOCAL__CACHE_PATH",
    default=IP4_LINK_LOCAL__CACHE_PATH,
    validator=_is_optional_str("ip4_link_local.cache_path"),
    description="Path to per-MAC link-local candidate cache; empty disables caching.",
)
```

When set, the subsystem reads / writes a small TOML file
keyed by MAC address. Phase-1.5 commits this as a sub-phase
of Phase 1 if implementation time permits; otherwise it lands
in Phase 5 cleanup.

**1.6 Stack integration**

`pytcp/stack/__init__.py` gains a `link_local` slot:

```python
link_local: Ip4LinkLocal | None = None

def init(..., ip4_link_local: bool = False, ...) -> None:
    ...
    if ip4_link_local:
        link_local = Ip4LinkLocal(mac_address=STACK__MAC_ADDRESS, ...)
        link_local.start()
```

The `ip4_link_local` kwarg gates the subsystem at boot — the
default is **off** so existing tests / consumers see no
behaviour change. Operators opt in.

Test harness snapshot/restore in `NetworkTestCase.setUp` adds
`stack.link_local` to the snapshot set so per-test mutations
do not leak.

**Tests-first:**

- Unit: `pytcp/tests/unit/protocols/ip4/link_local/test__link_local__rng.py`
  - same MAC → same candidate (idempotency)
  - different MAC → different candidate
  - `attempt` rolls the sequence forward
  - generated address is always in [169.254.1.0,
    169.254.254.255]
  - reserved first-/last-/256 blocks never appear
- Unit: `test__ip4_link_local__constants.py` covers the
  sysctl registrations.
- Integration: `test__ip4_link_local__client__init_to_probing.py`
  drives `_do_init()` once and verifies the state advances
  to `PROBING` with a non-None `_candidate` whose address is
  link-local.

### Phase 2 — `_do_claiming` via the ACD API (1 commit; ~3 hours)

The second half of the autoconfig state machine. With the
Phase 0.5 ACD API in place, `_do_claiming` is a one-call step:
ask the API to claim the candidate, handle the result, advance
or retry.

**2.1 `_do_claiming()`**

```python
def _do_claiming(self) -> None:
    """
    RFC 3927 §2.2 + §2.4 claim. Delegates probe + announce +
    install to 'stack.address.claim_with_acd'. On success,
    subscribes for post-claim conflicts and transitions to
    BOUND. On conflict, retries with a fresh candidate up to
    MAX_CONFLICTS; after that, sleeps RATE_LIMIT_INTERVAL.
    """

    assert self._candidate is not None
    result = stack.address.claim_with_acd(ip4_host=self._candidate)
    if result.success:
        self._subscription = stack.address.subscribe_conflicts(
            address=self._candidate.address,
            on_conflict=self._on_bound_conflict,
        )
        self._state = Ip4LinkLocalState.BOUND
        self._packet_stats.ip4_link_local__claimed += 1
    else:
        self._on_claim_conflict(result)
```

**2.2 `_on_claim_conflict()` — retry-or-rate-limit**

```python
def _on_claim_conflict(self, result: ClaimResult, /) -> None:
    """
    RFC 3927 §2.2 retry path. Bumps the conflict counter and
    either picks a fresh candidate immediately or enters the
    RATE_LIMIT_INTERVAL cool-down once MAX_CONFLICTS is hit.
    """

    self._conflict_count += 1
    self._packet_stats.ip4_link_local__conflict_during_probe += 1

    if self._conflict_count < ip4ll_const.IP4_LINK_LOCAL__MAX_CONFLICTS:
        self._candidate = None  # _do_init picks a fresh one
        self._state = Ip4LinkLocalState.INIT
    else:
        # RFC 3927 §9: rate-limit further attempts.
        time.sleep(ip4ll_const.IP4_LINK_LOCAL__RATE_LIMIT_INTERVAL)
        self._conflict_count = 0
        self._candidate = None
        self._state = Ip4LinkLocalState.INIT
```

Spec-pinned constants (registered as sysctls in Phase 1):

```python
# pytcp/protocols/ip4/link_local/link_local__constants.py
IP4_LINK_LOCAL__MAX_CONFLICTS = 10        # §9
IP4_LINK_LOCAL__RATE_LIMIT_INTERVAL = 60  # §9 (seconds)
```

**2.3 `_do_bound()`**

Idle. Each iteration sleeps via the base class. Conflict
handling is callback-driven via the subscription registered
in `_do_claiming`; the BOUND state is otherwise inert.

**Tests-first:**

- Integration: `test__ip4_link_local__client__happy_path.py`
  drives INIT → CLAIMING → BOUND when no conflicting ARP
  arrives. Asserts the address is installed via the API
  (`stack.address.list_ip4_hosts()` contains the candidate)
  and the wire shows 3 probes + 2 announcements (the
  test exercises the API's full behaviour, not the
  internals).
- Integration:
  `test__ip4_link_local__client__conflict_regenerates.py`
  injects a conflicting ARP during the probe window via the
  ACD-API test scaffolding, verifies the candidate
  regenerates with `attempt=1`.
- Integration: `test__ip4_link_local__client__rate_limit_pause.py`
  drives 10 consecutive conflicts, asserts the FakeTimer
  advances by `RATE_LIMIT_INTERVAL` before the next probe.
- Stat-counter: `ip4_link_local__claimed`,
  `ip4_link_local__conflict_during_probe` increment per
  expected branch.

The whole phase is **much smaller** than the original plan
because the Probe + Announce mechanics are hidden inside the
API. The link-local client is left with the policy: which
candidate, when to retry, when to rate-limit.

### Phase 3 — Conflict detection / defense (§2.5) (1 commit; ~3 hours)

The §2.5(a) / §2.5(b) decision tree for handling ARP
conflicts on an address that is already in `BOUND` state.
With the Phase 0.5 API in place, conflict events arrive via
the `subscribe_conflicts` callback registered in `_do_claiming`.
No ARP RX patching needed — the API's fan-out machinery
already routes the event.

**3.1 `_on_bound_conflict()` — RFC 3927 §2.5 decision**

```python
def _on_bound_conflict(self, event: ConflictEvent, /) -> None:
    """
    Subscription callback fired by 'Ip4AddressApi' on any
    post-claim ARP conflict matching our BOUND address.
    Implements the RFC 3927 §2.5 decision: if this is the
    first conflict in DEFEND_INTERVAL, fire one defensive
    gratuitous ARP and stay BOUND (§2.5(b)). Otherwise
    (second conflict within DEFEND_INTERVAL) abandon and
    reconfigure (§2.5(a)).
    """

    now = event.timestamp
    recent = [t for t in self._defend_history if now - t < ARP__DEFEND_INTERVAL]

    if not recent:
        # §2.5(b): defend with one gratuitous ARP.
        self._defend_history.append(now)
        stack.address.send_gratuitous_arp(address=event.address)
        self._packet_stats.ip4_link_local__defended += 1
        return

    # §2.5(a): abandon. RFC 3927 §2.5 paragraph 7 SHOULD —
    # reset any TCP sessions bound to the abandoned address.
    stack.address.abort_bound_tcp_sessions(address=event.address)
    stack.address.unsubscribe_conflicts(handle=self._subscription)
    stack.address.remove_host(ip4_host=self._candidate)
    self._subscription = None
    self._candidate = None
    self._defend_history.clear()
    self._conflict_count += 1
    self._state = Ip4LinkLocalState.INIT
    self._packet_stats.ip4_link_local__reconfigured += 1
```

Every cross-subsystem call here is a sanctioned-surface call
on `Ip4AddressApi`. The link-local client never touches
`packet_handler` directly.

**3.2 `DEFEND_INTERVAL` reuses `ARP__DEFEND_INTERVAL`**

Per §9 `DEFEND_INTERVAL = 10` matches RFC 5227's defend
interval. PyTCP already has `ARP__DEFEND_INTERVAL = 10` in
`pytcp/protocols/arp/arp__constants.py` registered as the
`arp.defend_interval` sysctl. The link-local subsystem reads
the same constant via qualified-module access — no new
sysctl needed.

**Tests-first:**

- Integration:
  `test__ip4_link_local__client__defend_on_first_conflict.py`
  — inject conflict via the ACD API's test-scaffolding
  conflict-event injector, assert defensive gratuitous ARP
  fires (one frame on wire), state stays `BOUND`.
- Integration:
  `test__ip4_link_local__client__reconfigure_on_second_conflict.py`
  — two conflicts within `DEFEND_INTERVAL`, assert
  reconfigure: state cycles back to `INIT`, address
  removed from `stack.address.list_ip4_hosts()`,
  subscription cancelled.
- Integration: TCP-session reset on abandon. Sets up a
  bound TCP socket on the link-local address, drives the
  abandon path, asserts the session sees the reset.

### Phase 4 — DHCPv4 client coordination (§2.11 / §1.9) (1 commit; ~3 hours)

The fallback trigger that makes link-local actually do
something. RFC 3927 §2.11 is explicit: DHCP behaviour MUST
NOT change. Link-local autoconfig is a parallel subsystem
that watches DHCP state and:

- Activates after the configurable fallback timer fires.
- Deactivates when DHCP successfully binds.

**4.1 New sysctl `ip4_link_local.dhcp_fallback_timeout_ms`**

```python
# Default 0 — disabled; operator opts in.
# Linux dhclient's link-local fallback fires after 60s of
# failed DISCOVER (dhclient script's 'TIMEOUT' branch).
IP4_LINK_LOCAL__DHCP_FALLBACK_TIMEOUT_MS = 0
```

When `> 0`, the link-local subsystem polls `stack.dhcp4_client.state`
and:

- Enters `INIT` (kicks off autoconfig) if DHCP has been in
  `INIT` / `SELECTING` / `REQUESTING` continuously for
  `dhcp_fallback_timeout_ms`.
- Enters `HALTED` (and removes the link-local address) when
  DHCP transitions to `BOUND`.

**4.2 No DHCP-side modifications**

Per RFC 3927 §2.11, the DHCPv4 client is unchanged. The
coupling is read-only: link-local watches DHCP state; DHCP
never reads link-local state.

This satisfies the "RFC 3927 forbids modifying DHCP" rule
the audit record calls out.

**4.3 Address-API conflict prevention**

When DHCP succeeds while link-local has a 169.254/16 host
installed, the DHCP-success handler in the lifecycle calls
`stack.address.replace_host(...)`. This must remove the
link-local host before installing the DHCP-acquired host.
The existing `replace_host` API (mentioned in the DHCP plan
doc §4.5) handles this with no further coupling — both
subsystems are clients of the same address API.

**Tests-first:**

- Integration:
  `test__ip4_link_local__client__dhcp_fallback_trigger.py`
  drives DHCP into a continuous-DISCOVER state, advances
  the FakeTimer past the fallback window, asserts
  link-local enters `INIT`.
- Integration:
  `test__ip4_link_local__client__dhcp_success_halts.py`
  — link-local in `BOUND`, DHCP succeeds → link-local
  state goes `HALTED` and `stack.address.list_ip4_hosts`
  no longer contains the link-local host.

### Phase 5 — Adherence refresh + audit-doc updates (1 commit; ~2 hours)

Flip every "not implemented" / "gap" status in the RFC 3927
adherence record to its post-implementation state. Update
the IPv4 audit punch-list to mark item D complete. Update
the DHCPv4 adherence record's §2.11-coupling section to
cross-reference the new behaviour.

**5.1 RFC 3927 adherence record (`docs/rfc/ip4/rfc3927__ip4_link_local/adherence.md`)**

| Section | Old status | New status |
|---------|------------|------------|
| §1.9    | not implemented (Phase 2) | met (DHCP fallback timer) |
| §2.1    | not implemented           | met (`link_local__rng.candidate_from_mac`) |
| §2.2    | not implemented           | met (`_do_probing` → `_arp_dad_probe_address`) |
| §2.4    | not implemented           | met (`_do_announcing` → `_arp_dad_announce_address`) |
| §2.5    | not implemented           | met (`_on_bound_conflict` defend / reconfigure) |
| §2.6    | gap                       | met (TX scope-mismatch gate from Phase 0) |
| §2.7    | n/a (host)                | n/a (host) — unchanged |
| §2.8    | met vacuously             | met explicitly (link-local destination short-circuit from Phase 0) |
| §2.11   | n/a (no autoconfig)       | met (DHCP-watcher fallback / replace pattern) |

Test-coverage audit section adds an entry per test file
under `pytcp/tests/integration/protocols/ip4_link_local/`.

**5.2 IPv4 audit punch-list refresh**

Move item D from "Phase-1 features" to a "Shipped" section,
list the commits. Item E (multicast / IGMP) and item F (IPv6
parity sweep) move up the recommended-sequencing list.

**5.3 DHCPv4 adherence cross-references**

The RFC 2131 record's §2.11-coupling paragraph (currently
"link-local is not implemented; this is a future
consideration") flips to "link-local autoconfig is now a
separate `Ip4LinkLocal` subsystem; DHCP behaviour is
unchanged per RFC 3927 §2.11; the two clients coordinate
through the address API."

### Phase 6 — Optional: cached-candidate persistence (1 commit; ~3 hours)

If Phase 1.5's TOML cache lands as part of Phase 1 this
phase is folded in. Otherwise it ships separately as a
small follow-up:

- TOML file at `IP4_LINK_LOCAL__CACHE_PATH` mapping MAC
  → previously-claimed address.
- On `INIT`, if cache hit and no recent conflict on that
  address, use it as the first candidate (skipping the RNG
  seed → first candidate).
- Update cache on successful `BOUND` transition.
- Cache invalidation on `_on_bound_conflict` reconfigure.

Tests: unit-level for cache read/write; integration for
cache-hit-respects-recent-conflict semantics.

---

## 4. Sysctl knobs to add

All registered in `pytcp/protocols/ip4/link_local/link_local__constants.py`
with the canonical pattern from `arp__constants.py`. Phase
where each lands in parentheses.

| Key                                     | Type / range  | Default | Description                                                     | Phase |
|-----------------------------------------|---------------|---------|-----------------------------------------------------------------|-------|
| `ip4_link_local.max_conflicts`          | int > 0       | 10      | RFC 3927 §9 MAX_CONFLICTS                                       | 2     |
| `ip4_link_local.rate_limit_interval_s`  | int > 0       | 60      | RFC 3927 §9 RATE_LIMIT_INTERVAL (seconds)                       | 2     |
| `ip4_link_local.dhcp_fallback_timeout_ms` | int ≥ 0     | 0       | DHCP-fail window before link-local kicks in; 0 = disabled       | 4     |
| `ip4_link_local.cache_path`             | str (path)    | `""`    | TOML cache for the per-MAC candidate; empty = no cache          | 1.5/6 |

No new finalize_validator constraints — knobs are independent.

---

## 5. New / touched files inventory

### New source files

| File                                                                 | Purpose |
|----------------------------------------------------------------------|---------|
| `pytcp/protocols/ip4/link_local/link_local__client.py`           | `Ip4LinkLocal(Subsystem)` FSM driver |
| `pytcp/protocols/ip4/link_local/link_local__constants.py`        | sysctl registrations + RFC 3927 §9 constants |
| `pytcp/protocols/ip4/link_local/link_local__rng.py`              | MAC-seeded address selector |

### Touched source files

| File                                                                 | Why |
|----------------------------------------------------------------------|-----|
| `pytcp/stack/address.py`                                           | Phase 0.5 — add `claim_with_acd` / `subscribe_conflicts` / `unsubscribe_conflicts` / `send_gratuitous_arp` / `abort_bound_tcp_sessions` |
| `pytcp/runtime/packet_handler/__init__.py`                             | Phase 0.5 — `_arp_dad_probe_address` / `_arp_dad_announce_address` / `_send_gratuitous_arp` become private (called from the API impl); static-host claim path migrates to `claim_with_acd` |
| `pytcp/runtime/packet_handler/packet_handler__arp__rx.py`              | Phase 0.5 — conflict-detection RX path routes events to the API's subscription registry instead of writing the `DadSlotRegistry` directly |
| `pytcp/protocols/dhcp4/dhcp4__client.py`                             | Phase 0.5 — migrate `_arp_dad_probe_address` / `_arp_dad_announce_address` call sites to `stack.address.claim_with_acd` |
| `pytcp/stack/__init__.py`                                            | new `link_local` singleton, init kwarg, import `link_local__constants` to populate the sysctl registry, snapshot/restore in `mock__init` |
| `pytcp/runtime/packet_handler/packet_handler__ip4__tx.py`              | Phase-0 §2.6 scope-mismatch gate |
| `pytcp/runtime/packet_handler/packet_handler__ethernet__tx.py`         | Phase-0 §2.8 link-local destination → bypass gateway lookup |
| `pytcp/lib/tx_status.py`                                             | new `DROPPED__IP4__LINK_LOCAL_SCOPE_MISMATCH` variant |
| `pytcp/lib/packet_stats.py`                                          | new counters: `ip4__link_local_scope_mismatch__drop`, `ip4__acd_claimed`, `ip4__acd_conflict_during_probe`, `ip4__acd_defended`, `ip4_link_local__claimed`, `ip4_link_local__defended`, `ip4_link_local__reconfigured`, `ip4_link_local__conflict_during_probe` |
| `pytcp/tests/lib/network_testcase.py`                                | snapshot `stack.link_local` + the ACD subscription registry in `setUp`; restore in `tearDown` |

### New test files

| File                                                                                                | Layer       | Cases (target) |
|-----------------------------------------------------------------------------------------------------|-------------|-----------------|
| `pytcp/tests/unit/lib/test__lib__address_api.py` (extend)                                           | unit        | Phase 0.5 — `claim_with_acd` clean / conflict / address-not-installed-on-failure; `subscribe_conflicts` fan-out / unsubscribe; `send_gratuitous_arp` wire-emission; `abort_bound_tcp_sessions` per-address scoping |
| `pytcp/tests/unit/protocols/ip4/link_local/test__link_local__rng.py`                            | unit        | MAC determinism, attempt counter, range bounds, reserved blocks |
| `pytcp/tests/unit/protocols/ip4/link_local/test__ip4_link_local__constants.py`                      | unit        | sysctl registration, validators, defaults |
| `pytcp/tests/integration/protocols/ip4_link_local/test__ip4_link_local__client__init_to_claiming.py` | integration | INIT → CLAIMING transition |
| `pytcp/tests/integration/protocols/ip4_link_local/test__ip4_link_local__client__happy_path.py`      | integration | full INIT → BOUND with no conflict |
| `pytcp/tests/integration/protocols/ip4_link_local/test__ip4_link_local__client__conflict_regenerates.py` | integration | conflict-during-probe → regenerate |
| `pytcp/tests/integration/protocols/ip4_link_local/test__ip4_link_local__client__rate_limit_pause.py` | integration | 10-conflict cool-down |
| `pytcp/tests/integration/protocols/ip4_link_local/test__ip4_link_local__client__defend_on_first_conflict.py` | integration | §2.5(b) defend |
| `pytcp/tests/integration/protocols/ip4_link_local/test__ip4_link_local__client__reconfigure_on_second_conflict.py` | integration | §2.5(a) abandon |
| `pytcp/tests/integration/protocols/ip4_link_local/test__ip4_link_local__client__dhcp_fallback_trigger.py` | integration | DHCP-fail → link-local INIT |
| `pytcp/tests/integration/protocols/ip4_link_local/test__ip4_link_local__client__dhcp_success_halts.py` | integration | DHCP-bind → link-local HALTED + remove |
| `pytcp/tests/integration/protocols/<proto>/test__<proto>__ip4__tx.py` (extend)                                 | integration | Phase-0 `TestPacketHandlerIp4TxRfc3927ScopeGate` (4 cases) |
| `pytcp/tests/integration/protocols/<proto>/test__<proto>__ethernet__tx.py` (extend)                            | integration | Phase-0 `Test*Rfc3927DstLinkLocalBypassGateway` |

### Touched test files

| File                                                  | Why |
|-------------------------------------------------------|-----|
| `pytcp/tests/unit/lib/test__lib__tx_status.py`        | `_EXPECTED_MEMBERS` tuple grows by 1 |
| `pytcp/tests/unit/lib/test__lib__packet_stats.py`     | field_count for `PacketStatsTx` and `PacketStatsRx` updated |

---

## 6. Open design decisions

The plan is firm on most points but the items below are
worth flagging for review before Phase 1 lands.

**Closed in plan v2 (Option B):** the original v1 plan
listed two questions that Option B's API-extraction phase
resolves:

- *`_arp_dad_probe_address` reuse vs fork* — closed. The
  helper becomes private detail of `Ip4AddressApi.claim_with_acd`;
  link-local consumes only the public API.
- *TCP-session abort helper placement* — closed. The
  helper lands on `Ip4AddressApi.abort_bound_tcp_sessions`
  in Phase 0.5 and both DHCPDECLINE and §2.5(a) abandon
  consume it.

Six questions remain open below.

### 6.1 RNG choice — LCG vs `random.Random` seeded

The plan specifies a manual LCG (Numerical-Recipes constants)
for determinism and zero state-machine surprise. Alternative:
`random.Random(seed)`. The argument for the manual LCG is:

- Deterministic across Python versions (stdlib `random` is
  guaranteed deterministic per-seed, but the algorithm is
  Mersenne Twister, which is overkill for 64K addresses).
- 4-line implementation — no module-level state to
  snapshot/restore in tests.

Either is defensible. Default to the manual LCG; revisit in
review if there's a strong argument for `random.Random`.

### 6.2 Fallback trigger — DHCP state vs DHCP timer

Phase 4 watches `stack.dhcp4_client.state`. Alternative:
expose a callback from DHCP that fires when DISCOVER has
been retried N times.

State-polling is simpler and matches the §2.11 "no DHCP
modifications" rule. The DHCP client never knows link-local
exists. State-polling cost is one read per
`Subsystem._subsystem_loop` tick (~10 Hz default) — trivial.

### 6.3 §2.6 placement — `_phtx_ip4` or both ip4 and source-selection

The plan places the §2.6 gate in `_phtx_ip4` only. The
source-selection path (RFC 6724 rule 2) already prefers
matching scopes, so a CALLER picking the wrong source
shouldn't happen via the normal path. The gate guards the
caller-supplied-src path only.

Alternative: add a complementary check in the source
selector itself. Defer — the existing RFC 6724 rule 2 sort
key already encodes the scope-match preference.

### 6.4 Multi-interface — out of scope

RFC 3927 §3 considers multi-interface scenarios. PyTCP is
single-interface (Phase 1). The plan does not address §3.x.
The future Phase-2 multi-interface track will revisit; the
link-local subsystem's `Ip4LinkLocal.__init__` takes the
MAC + interface implicitly (single interface), so the
per-interface refactor lands later.

### 6.5 What to do when MAX_CONFLICTS hits

RFC 3927 §9 specifies RATE_LIMIT_INTERVAL = 60s between
attempts after MAX_CONFLICTS = 10. Plan: pause for 60s,
reset `conflict_count`, retry from RNG. Alternative: stop
trying forever after 10 conflicts (operator opt-in to
retry).

The 60s-rate-limit-then-retry is the RFC default and matches
Linux. Going further (stop forever) would be a Linux-deviation
and surfaces no clear consumer demand.

### 6.6 Sysctl namespace — `ip4_link_local.` vs `ip4ll.`

Linux uses `IPV4LL` in many references but no actual
sysctl with that prefix. Plan uses `ip4_link_local.` for
clarity (long-form mirrors `arp.` /
`neighbor.` / `icmp6.` patterns). Defensible either way.

---

## 7. Test strategy

### 7.1 Unit layer

`pytcp/tests/unit/protocols/ip4/link_local/`:

- **`test__ip4_link_local__rng.py`** — every property of the
  MAC-seeded RNG: determinism, range bounds, reserved-block
  exclusion, attempt-counter independence, distribution
  spot-check across 1000 MACs (no obvious clustering).
- **`test__ip4_link_local__constants.py`** — sysctl
  registration, validator rejection branches, defaults
  match the RFC §9 values.

### 7.2 Integration layer

Builds on `NetworkTestCase` with a dedicated
`Ip4LinkLocalTestCase` subclass that:

- Sets `stack.link_local` to a fresh `Ip4LinkLocal`
  instance in `setUp`.
- Snapshots / restores `stack.link_local` and the
  `ip4_link_local.*` sysctls in `setUp` / `tearDown`.
- Provides `_drive_probe_conflict` and
  `_drive_dhcp_state_change` helpers that mirror the
  ND-test-case `_drive_rx` / `_advance` pattern.

The integration tests cover every state-transition edge:

| Transition                            | Test file |
|---------------------------------------|-----------|
| INIT → CLAIMING                       | `__init_to_claiming.py` |
| CLAIMING → BOUND                      | `__happy_path.py` |
| CLAIMING → INIT (conflict, retry)     | `__conflict_regenerates.py` |
| CLAIMING → INIT (MAX_CONFLICTS hit)   | `__rate_limit_pause.py` |
| BOUND → BOUND (§2.5(b) defend)        | `__defend_on_first_conflict.py` |
| BOUND → INIT (§2.5(a) reconfigure)    | `__reconfigure_on_second_conflict.py` |
| any → HALTED (DHCP success)           | `__dhcp_success_halts.py` |
| HALTED → INIT (DHCP loss + fallback)  | `__dhcp_loss_reactivates.py` |

### 7.3 §7.2 docstring audit

Every new and modified test file runs through the §7.2 audit
before its respective commit:

- `Ensure ...` opener on every test method.
- Trailing `Reference: RFC 3927 §X.Y (...)` line per cited
  clause.
- No inline RFC citations in the description.

Touched test files (`test__lib__tx_status.py`,
`test__lib__packet_stats.py`,
`test__packet_handler__ip4__tx.py`,
`test__packet_handler__ethernet__tx.py`,
`test__packet_handler__arp__rx.py`) inherit the §7.2
violation-cleanup-on-touch obligation.

---

## 8. Effort estimate

| Phase | Description                                                | Effort   | Cumulative |
|-------|------------------------------------------------------------|----------|------------|
| 0     | §2.6 TX scope-mismatch gate (§2.8 subsumed)                | ~1.5 h   | ~1.5 h     |
| 0.5   | Extract ACD API + migrate DHCP / static-host call sites    | ~8 h     | ~9.5 h     |
| 1     | Subsystem skeleton + address selection                     | ~4 h     | ~13.5 h    |
| 2     | `_do_claiming` via the ACD API                             | ~3 h     | ~16.5 h    |
| 3     | Conflict detection / defense                               | ~3 h     | ~19.5 h    |
| 4     | DHCPv4 client coordination                                 | ~3 h     | ~22.5 h    |
| 5     | Adherence refresh + audit-doc updates                      | ~2 h     | ~24.5 h    |
| 6     | Cached-candidate persistence (optional)                    | ~3 h     | ~27.5 h    |

**Total: ~3 calendar days** for phases 0–5; +half a day for
phase 6 if it ships separately. The +1 day over the v1 plan
estimate is Phase 0.5; it buys Phase-3-clean boundaries for
both link-local AND DHCP, which is the whole point of going
with Option B.

Within the budget: Phase 0.5 dominates because the migration
touches the existing DHCP test surface and the static-host
claim path. Phases 1-5 are all smaller than v1 because the
hard ACD plumbing is now an API call, not bespoke code.

---

## 9. Commit discipline

Each phase ships as **one focused commit**. Commit messages
follow the established PyTCP template:

```
IPv4 link-local: <one-line summary>

<paragraph: what changed, why, which RFC clause(s)>

Tests-first: <list of failing-test-then-flip-green pins>.

Reference: RFC 3927 §X.Y (clause).
[Reference: RFC 5227 §..., RFC 2131 §..., etc.]

Lint clean. <N> passing, <M> skipped.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

`make lint` + `make test` + §7.2 audit gate every commit.

Phases ship in numeric order **except**: Phase 0 is the
standalone scope-gate fix and can ship before Phase 1 if
the test surface for the gate is ready first. Phase 6
(persistence) ships last and is optional.

---

## 10. Closing the audit loop

Phase 5's adherence-record refresh is mandatory — the
`rfc_adherence_audit` skill rules (and CLAUDE.md "RFC
adherence audits update in lockstep with code") mean the
audit record MUST be refreshed in the same commit that
flips the implementation status. The plan reserves Phase 5
specifically for this so the audit-refresh work doesn't
slip.

After Phase 5:

- `docs/rfc/ip4/rfc3927__ip4_link_local/adherence.md` shows
  every §-section moved to "met" (or "n/a" with rationale).
- `docs/rfc/ip4/rfc5227__ip4_acd/adherence.md` (or the
  equivalent record — created if not present) reflects the
  new public-API surface; the existing implementation
  paragraph now references `Ip4AddressApi.claim_with_acd`
  instead of `_arp_dad_probe_address`.
- `docs/rfc/dhcp4/rfc2131__dhcp/adherence.md` Phase-3-cleanup
  note on the ACD reach-through flips to "closed in commit
  <Phase 0.5 hash>".
- `docs/refactor/ip4_audit_punchlist.md` lists item D under
  the session-shipped commits.
- The `auto memory` reference entry for the IPv4 punch list
  is refreshed to point at the new state.

---

## 11. References

### RFCs

- **RFC 3927** — Dynamic Configuration of IPv4 Link-Local
  Addresses (this track's spec).
- **RFC 5227** — IPv4 Address Conflict Detection (ARP Probe
  / Announce machinery; reused).
- **RFC 6724** — Default Address Selection for IPv6 — the
  IPv4 source-selection adapter PyTCP uses borrows the same
  rule structure; link-local scope is already plumbed.
- **RFC 2131** — DHCPv4 (coordination per §2.11).
- **RFC 4436** — DNAv4 (informational; touches §2.11
  fast-reattach but out of scope for this track).

### PyTCP internal references

- `docs/rfc/ip4/rfc3927__ip4_link_local/adherence.md` — gap
  inventory feeding this plan.
- `docs/refactor/dhcp4_client_full_parity.md` — structural
  template for the new subsystem (address API, Phase-3 seam,
  lifecycle pattern).
- `docs/refactor/sysctl_framework.md` — sysctl registration
  framework.
- `docs/refactor/ip4_audit_punchlist.md` — track D placement
  in the broader IPv4 audit roadmap.
- `pytcp/protocols/dhcp4/dhcp4__client.py` — reference
  implementation of the `Subsystem`-based FSM pattern.
- `pytcp/runtime/packet_handler/__init__.py::_arp_dad_probe_address`
  / `_arp_dad_announce_address` — the RFC 5227 probe /
  announce machinery; Phase 0.5 hides these behind
  `Ip4AddressApi.claim_with_acd`.
- `pytcp/stack/address.py` — Phase-3-clean address-control
  surface; gains the ACD API in Phase 0.5.

### External library references (Linux Phase-3 analogues)

- `n-acd` (`https://github.com/nettools/n-acd`) — standalone
  RFC 5227 ACD library used by NetworkManager. Its API
  surface (probe / announce / defend, callback-based
  conflict events) is the closest analogue to what Phase
  0.5 extracts.
- `sd_ipv4ll` (`src/libsystemd-network/sd-ipv4ll.c` in
  systemd) — systemd-networkd's link-local autoconfig
  library. Embeds both the ACD protocol and the RFC 3927
  FSM into one library; PyTCP separates them (ACD on
  `Ip4AddressApi`, link-local FSM in `Ip4LinkLocal`) for
  reuse with DHCP.

---

## 12. Linux comparison + Phase-3 alignment

### 12.1 Linux equivalents

| PyTCP                                          | Linux                                                                  |
|------------------------------------------------|------------------------------------------------------------------------|
| `Ip4AddressApi.claim_with_acd`                 | `n-acd` library API (`n_acd_probe`); `sd_ipv4ll_start`                 |
| `Ip4AddressApi.subscribe_conflicts`            | `n-acd` event callbacks; systemd's `sd_ipv4ll_set_callback`            |
| `Ip4AddressApi.send_gratuitous_arp`            | `arp_notify` triggered gratuitous ARP in `net/ipv4/arp.c`              |
| `Ip4AddressApi.abort_bound_tcp_sessions`       | `fib_validate_source` / `inet_release` abort path on address removal   |
| `Ip4LinkLocal` subsystem                       | `avahi-autoipd` (separate daemon) / `dhcpcd --ipv4ll` (in-process)     |
| `ip4_link_local.dhcp_fallback_timeout_ms`      | `dhcpcd` config `ipv4ll` + timeout; systemd-networkd `LinkLocalAddressing=fallback` |
| MAC-seeded RNG                                 | `avahi-autoipd` uses MD5-of-MAC; `sd_ipv4ll` uses SipHash24; PyTCP's manual LCG is the Linux-equivalent-class choice for embedded targets |

PyTCP's design is a single in-process subsystem rather than
Linux's separate-daemon model (avahi-autoipd). The
single-process approach fits PyTCP's stack-as-library shape
and is the same model dhcpcd / systemd-networkd /
NetworkManager use — they all run DHCP and IPv4LL FSMs in
one process, coordinating via shared in-process state.

The split between the ACD API (kernel-side, on
`Ip4AddressApi`) and the autoconfig FSM (userspace-side, in
`Ip4LinkLocal`) **mirrors the Linux library layout**: `n-acd`
provides the protocol primitive; the consumer
(NetworkManager / sd_ipv4ll) layers the policy / state
machine on top. PyTCP's library equivalent is the
`Ip4AddressApi.claim_with_acd` + `subscribe_conflicts`
surface from Phase 0.5.

### 12.2 Phase-3 alignment

Per CLAUDE.md Phase-3 design implications:

- **Address mutations go through the API** —
  `Ip4LinkLocal` (and DHCP after the Phase 0.5 migration)
  calls only `stack.address.*` methods. No subsystem
  reaches into `packet_handler._ip4_host` /
  `_arp_dad_probe_address` / `_send_gratuitous_arp` after
  Phase 0.5.
- **Sysctls are the operator-facing dial** — every tunable
  in the plan is a registered knob with a description and
  validator. ACD-engine timing knobs live in `arp.*` (shared);
  link-local policy knobs live in `ip4_link_local.*`.
- **No reach-through from user code** — the `link_local`
  singleton is an implementation detail; operators control
  it via boot kwarg + sysctls.
- **State introspection is read-only** —
  `Ip4LinkLocal.state` / `.bound_address` are read-only
  properties.
- **Cross-subsystem coupling goes through the API surface**
  — link-local watches DHCP via `stack.dhcp4_client.state`
  (one-way read); link-local aborts TCP via
  `stack.address.abort_bound_tcp_sessions` (sanctioned
  helper); DHCP-on-success removes link-local addresses
  via `stack.address.remove_host` (sanctioned helper).

### 12.3 The Phase-3 line this plan draws

Before this track:

| Surface                                  | DHCP touches it? | Phase-3 status         |
|------------------------------------------|------------------|------------------------|
| `_arp_dad_probe_address`                 | yes              | reach-through (gap)    |
| `_arp_dad_announce_address`              | yes              | reach-through (gap)    |
| `_send_gratuitous_arp`                   | no (yet)         | reach-through (latent) |
| `_ip4_arp_dad__registry`                 | no (yet)         | public attribute (gap) |
| (no `abort_bound_tcp_sessions` API)      | n/a              | missing helper         |

After Phase 0.5:

| Surface                                  | Status                                                         |
|------------------------------------------|----------------------------------------------------------------|
| `_arp_dad_probe_address` (etc.)          | private; called only from `Ip4AddressApi` impl                 |
| `_ip4_arp_dad__registry`                 | private to the API impl                                        |
| `Ip4AddressApi.claim_with_acd`           | sanctioned ✅ — DHCP + link-local + static-host consume it     |
| `Ip4AddressApi.subscribe_conflicts`      | sanctioned ✅ — link-local consumes it; future VRRP etc. ditto |
| `Ip4AddressApi.send_gratuitous_arp`      | sanctioned ✅ — used by §2.5(b) defense                        |
| `Ip4AddressApi.abort_bound_tcp_sessions` | sanctioned ✅ — used by §2.5(a) abandon + future DHCPDECLINE   |

The pattern generalises to IPv6 (a future `Ip6AddressApi.claim_with_dad`
mirroring this shape for ND DAD), to VRRP / CARP, and to the
eventual Phase-3 operator-facing `ip addr add` tool. The
boundary drawn here is the canonical "address-control plane"
surface for the Phase-3 north star.
