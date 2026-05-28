# DHCPv4 Client — Full RFC Parity Refactor Plan

| Field           | Value                                                |
|-----------------|------------------------------------------------------|
| Status          | Phases 0–8 SHIPPED; Phase 9 deferred (each item dependency-blocked on a consumer PyTCP does not have today — see below) |
| Plan author     | Audit pass (2026-05-11)                              |
| Source audit    | `docs/rfc/dhcp4/rfcXXXX__*/adherence.md` (11 records)|
| Target branch   | `PyTCP_3_0__pre_release`                             |
| Touch points    | `packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py`, `packages/net_proto/net_proto/protocols/dhcp4/`, new lib helpers, sysctl framework, test harness |

This document is the implementation plan for taking
PyTCP's minimal one-shot DHCPv4 client to full Linux
host parity. It is derived from the 11 RFC adherence
records under `docs/rfc/dhcp4/`, which catalogue every
MUST / SHOULD / MAY clause and where PyTCP stands
today. The plan converts that gap inventory into a
phased implementation roadmap.

The audits land in commit `74cc7a43` (3 522 lines of
analysis across 11 RFCs).

---

## 1. Goal

Bring `packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py` (229 lines, linear
DISCOVER → OFFER → REQUEST → ACK) into compliance with
the dominant client-relevant DHCPv4 RFCs (2131, 2132,
4361, 3442, 4436, 6842) and partial compliance with the
extension RFCs (4702, 3203, 8910) where a consumer
exists.

After this refactor, a PyTCP DHCP client should behave
like Linux dhcpcd at the wire level:

- Full FSM (INIT / SELECTING / REQUESTING / INIT-REBOOT
  / BOUND / RENEWING / REBINDING).
- Retransmission with exponential backoff.
- Lease lifecycle with T1/T2/expiry timers running off
  the RX subsystem thread.
- DUID/IAID Client Identifier per RFC 4361.
- DHCPDECLINE on ARP conflict; DHCPNAK handling;
  DHCPRELEASE on shutdown.
- INIT-REBOOT path with cached prior lease.
- Optional DNAv4 fast-reattach (RFC 4436).
- Classless Static Routes (RFC 3442) — coupled to a
  routing-table API.

---

## 2. Current state — what the audit found

### Implemented (working)

- Wire format: full BOOTP header dataclass, 11 option
  codecs, integrity-validated parser, kw-only
  assembler (~8 900 unit-test lines).
- Linear DISCOVER → REQUEST happy path.
- BROADCAST flag, magic cookie, Param Req List
  (`SUBNET_MASK + ROUTER`), Host Name "PyTCP".
- Boot-time ARP DAD against the leased address via
  RFC 5227 (`_create_stack_ip4_addressing`).

### Unmet MUSTs

1. **RFC 2131 §2 / §4.3.6** — Client Identifier
   present in DISCOVER but **missing in REQUEST**
   ("MUST use same identifier in all subsequent
   messages").
2. **RFC 2131 §4.1** — Retransmission with exponential
   backoff (single recv timeout, no retries).
3. **RFC 2131 §3.1 step 5** — DHCPDECLINE on detected
   ARP conflict (currently: silent drop of candidate).
4. **RFC 2131 §3.1 / §3.2** — DHCPNAK handler
   (currently: silent treat-as-error).
5. **RFC 2131 §4.4.1** — xid validation on inbound
   OFFER/ACK (currently: any xid accepted).
6. **RFC 6842 §3** — Client MUST validate echoed CID
   on inbound (currently: never read).
7. **RFC 4361 §6.1** — Stable DUID + IAID Client
   Identifier (currently: RFC 2131 legacy
   `b"\x01" + MAC`).
8. **RFC 4361 §6.4** — Client MUST send same CID in
   all messages (same gap as #1).

### Unmet SHOULDs

- RFC 2131 §4.4.1 — Random 1–10 s initial delay
  before DISCOVER.
- RFC 2131 §3.5 — Maximum DHCP Message Size option
  emission.
- RFC 2131 §3.1 step 1 — Lease time hint in DISCOVER.
- RFC 4361 §6.1 — Operator-visible DUID via sysctl /
  inspection.
- RFC 4702 — Client FQDN option emission.
- RFC 3442 — Classless Static Routes option in PRL.

### Not implemented (whole features)

- Full FSM (no states beyond linear function).
- T1 / T2 / lease expiry timers.
- INIT-REBOOT (no cached prior lease).
- RENEWING / REBINDING (no post-BOUND maintenance).
- DHCPRELEASE on shutdown.
- DHCPDECLINE on conflict.
- DHCPINFORM.
- DNAv4 fast reattach (RFC 4436).
- Classless Static Routes (RFC 3442).
- Client FQDN (RFC 4702).
- FORCERENEW (RFC 3203 — gated on RFC 3118 auth).
- Captive-Portal option (RFC 8910).
- RFC 3396 long-option concatenation. *(Client/receive
  side SHIPPED 2026-05-25 — see Phase 8.3.)*

---

## 3. Phased plan

Each phase is sized to be one or a small number of
commits. Phases are ordered so each one's tests can
run without the next.

### Phase 0 — Quick wins (1 commit; ~1 hour)

Five tiny fixes, each gated by a single-file change in
`packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py` plus minimal additions to
the options accessor.

**0.1 Client Identifier in REQUEST** (RFC 2131 §2 MUST)

```python
# packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py — _send_request, ~line 195
Dhcp4OptionClientId(b"\x01" + bytes(self._mac_address)),
```

Mirror the DISCOVER emission. Single line.

**0.2 xid validation on inbound** (RFC 2131 §4.4.1 MUST)

```python
# In _recv_offer and _recv_ack
if dhcp4_packet_rx.xid != xid:
    return None  # silently discard
```

**0.3 CID echo validation** (RFC 6842 §3 MUST)

Add `client_id` accessor to `Dhcp4Options`
(`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__options.py`)
mirroring `server_id` / `subnet_mask` etc.

Then in `_recv_offer` / `_recv_ack`:

```python
echoed = packet.client_id
expected = b"\x01" + bytes(self._mac_address)
if echoed is not None and echoed != expected:
    return None
```

**0.4 NAK handler** (RFC 2131 §3.1 / §3.2)

Currently `_recv_ack` treats any non-ACK as "wrong
message type → return None". Distinguish NAK as a
specific restart signal:

```python
if packet.message_type == Dhcp4MessageType.NAK:
    # Restart from DISCOVER (caller re-enters fetch())
    return _NakReceived
```

Caller path: if `_recv_ack` returns the NAK sentinel,
re-invoke `fetch()` once (full restart). Bounded retry
to avoid loops.

**0.5 Lease time consumed**

Currently the ACK's `lease_time` option is parsed but
unused. Plumb it into the returned object:

```python
@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp4Lease:
    ip4_host: Ip4IfAddr
    lease_time__sec: int         # 0xffffffff = infinity
    server_id: Ip4Address
    acquired_at_monotonic: float
```

`Dhcp4Client.fetch()` returns `Dhcp4Lease | None`
instead of `Ip4IfAddr | None`. Update the one call site
in `packages/pytcp/pytcp/runtime/packet_handler/__init__.py` to read
`lease.ip4_host`.

**Tests** (extend `packages/pytcp/pytcp/tests/unit/lib/test__lib__dhcp4_client.py`):

- CID present in REQUEST.
- Wrong-xid OFFER silently dropped.
- Mismatched CID echo silently dropped.
- NAK triggers the restart sentinel.
- `Dhcp4Lease.lease_time__sec` matches the ACK's
  option 51 value.

**Adherence record refresh:** update RFC 2131, 6842
records to mark §2 / §4.4.1 / §3 as met.

### Phase 1 — Retransmission backoff (1 commit; ~3 hours)

Replace the single-recv timeout with the canonical
RFC 2131 §4.1 backoff:

```python
import random

def _recv_with_backoff(self, expected_type, *, send_again):
    delay_ms = 4000  # RFC 2131 §4.1 — first retransmit at 4s
    for attempt in range(5):  # 4s, 8s, 16s, 32s, 64s
        jitter_ms = random.uniform(-1000, 1000)
        timeout_s = max(0.001, (delay_ms + jitter_ms) / 1000.0)
        try:
            packet = Dhcp4Parser(self._socket.recv__mv(timeout=timeout_s))
            if packet.message_type == expected_type:
                return packet
        except TimeoutError:
            pass
        send_again()  # retransmit the prior TX
        delay_ms = min(delay_ms * 2, 64000)
    return None  # gave up after 5 attempts (~124 s total)
```

The `secs` field of the DHCP header gets populated
with the actual elapsed-since-first-message time per
RFC 1542 §3.2.

**New sysctls:**

| Key                         | Default | RFC clause            |
|-----------------------------|---------|-----------------------|
| `dhcp.retrans_initial_ms`   | 4000    | RFC 2131 §4.1         |
| `dhcp.retrans_max_ms`       | 64000   | RFC 2131 §4.1         |
| `dhcp.retrans_max_attempts` | 5       | "give adequate prob." |
| `dhcp.retrans_jitter_ms`    | 1000    | "±1 s" per RFC        |

Workflow: invoke the `sysctl_knob` skill once per
constant.

**Tests:**

- Server silence → 5 attempts at the right intervals.
- First successful recv before backoff finishes →
  early return.
- Jitter falls in [-1s, +1s] over 100 iterations.
- `secs` field advances across retransmissions.

### Phase 2 — Initial random delay + DHCPDECLINE (1 commit; ~3 hours)

**2.1 Initial random delay** (RFC 2131 §4.4.1)

```python
# In fetch(), before sending DISCOVER:
initial_delay__sec = random.uniform(1.0, 10.0)
__debug__ and log("dhcp4", f"Initial delay: {initial_delay__sec:.2f}s")
time.sleep(initial_delay__sec)
```

Behind a sysctl `dhcp.init_delay_max_ms` (default
10000; set to 0 to disable for tests).

**2.2 DHCPDECLINE on ARP conflict** (RFC 2131 §3.1 step 5 MUST)

Currently `_create_stack_ip4_addressing` runs ARP DAD
on the leased IP and silently drops the candidate on
conflict. The MUST is:

> "the client MUST send a DHCPDECLINE message to the
>  server and restarts the configuration process"

Plumb the ARP DAD result back into the DHCP client:

```python
# In Dhcp4Client:
def fetch(self) -> Dhcp4Lease | None:
    for _ in range(MAX_RESTART_ATTEMPTS):
        lease = self._discover_and_request()
        if lease is None:
            return None
        if self._verify_via_arp(lease.ip4_host):
            return lease
        self._send_decline(lease)
        time.sleep(10.0)  # RFC 2131 §3.1 step 5 SHOULD ≥ 10s
    return None
```

Requires:
- `_verify_via_arp(host)` returning bool — runs
  `_send_arp_probe` + waits for conflict signal via
  the existing `_ip4_arp_dad__registry` (from
  commit `be1043b6`).
- `_send_decline(lease)` emits DHCPDECLINE per
  RFC 2131 §3.1 (broadcast, no ciaddr, server-id +
  requested-ip identifying the rejected offer).

The existing `_create_stack_ip4_addressing` becomes:

```python
if lease := Dhcp4Client(mac_address=self._mac_unicast).fetch():
    # ARP DAD already passed (Dhcp4Client did it)
    self._ip4_ifaddr_candidate.append(lease.ip4_host)
```

The current top-level RFC 5227 DAD loop at
`__init__.py:1864-1903` stays for static-host case but
no longer runs on DHCP-leased addresses (those are
DAD-verified inside `Dhcp4Client.fetch()`).

**Tests:**

- ARP conflict during post-ACK probe → DECLINE
  emitted with correct server-id and requested-ip.
- DECLINE → ≥10s wait → restart from DISCOVER.
- No conflict → lease applied as before.

### Phase 3 — DUID / IAID Client Identifier (RFC 4361) (1 commit; ~4 hours)

**3.1 New helper** `packages/pytcp/pytcp/lib/dhcp_uid.py`:

```python
class DhcpUniqueIdentifier:
    """
    RFC 3315 §9 DUID + RFC 3315 §10 IAID for DHCPv4 / DHCPv6 client.
    Type 3 (DUID-LL — link-layer): 2-byte type + 2-byte hwtype + MAC.
    """

    @classmethod
    def from_mac(cls, mac: MacAddress, /) -> bytes:
        return b"\x00\x03" + b"\x00\x01" + bytes(mac)

    @classmethod
    def iaid_for_interface(cls, *, interface_idx: int = 0) -> bytes:
        return interface_idx.to_bytes(4, "big")
```

**3.2 Persistence** — sysctl `dhcp.duid` (default empty
string = auto-derive from MAC). When non-empty, the
operator-supplied hex string overrides. Stable across
process restarts via the existing sysctl registry.

**3.3 Client emission**:

```python
# In _send_discover and _send_request:
duid = DhcpUniqueIdentifier.from_mac(self._mac_address)  # or from sysctl
iaid = DhcpUniqueIdentifier.iaid_for_interface()
cid_bytes = b"\xff" + iaid + duid
Dhcp4OptionClientId(cid_bytes)
```

**3.4 Echo validation** (extension of Phase 0.3):

```python
expected = b"\xff" + iaid + duid
if echoed != expected:
    return None
```

**Tests:**

- DUID-LL wire format matches RFC 3315 §9.2.
- Same DUID across DISCOVER and REQUEST.
- Same DUID across two `fetch()` invocations
  (persistence via sysctl).
- Operator-overridden DUID via
  `sysctl_module.override("dhcp.duid", "00:03:00:01:...")`.

**Adherence record refresh:** RFC 4361 record marked
mostly met (operator-configurable storage via sysctl
satisfies §6.1 SHOULD).

### Phase 4 — Subsystem + lease lifecycle (3-4 commits; ~2 days)

The major architectural change. Convert
`Dhcp4Client` from a one-shot function into a
long-running `Subsystem` with the RFC 2131 §4.4 state
diagram.

**4.1 `Dhcp4Lifecycle(Subsystem)` skeleton**

New file `packages/pytcp/pytcp/lib/dhcp4_lifecycle.py`:

```python
class Dhcp4State(Enum):
    INIT = "INIT"
    INIT_REBOOT = "INIT-REBOOT"
    SELECTING = "SELECTING"
    REQUESTING = "REQUESTING"
    REBOOTING = "REBOOTING"
    BOUND = "BOUND"
    RENEWING = "RENEWING"
    REBINDING = "REBINDING"


class Dhcp4Lifecycle(Subsystem):
    """RFC 2131 §4.4 DHCPv4 client FSM."""

    def __init__(self, *, mac_address: MacAddress, ...) -> None:
        super().__init__(name="DHCP4 Lifecycle")
        self._state: Dhcp4State = Dhcp4State.INIT
        self._lease: Dhcp4Lease | None = None
        self._lease_acquired_at: float = 0.0
        # ... timers, sockets, ...

    @override
    def _subsystem_loop(self) -> None:
        now = time.monotonic()
        match self._state:
            case Dhcp4State.INIT:
                self._do_init()
            case Dhcp4State.SELECTING:
                self._do_selecting()
            case Dhcp4State.REQUESTING:
                self._do_requesting()
            case Dhcp4State.BOUND:
                self._do_bound(now)
            case Dhcp4State.RENEWING:
                self._do_renewing(now)
            case Dhcp4State.REBINDING:
                self._do_rebinding(now)
```

The subsystem loop runs in its own thread (per the
`Subsystem` base class). State transitions happen
inside `_do_*` methods, each making at most one
RX/TX exchange before yielding via the base class's
sleep.

**4.2 T1 / T2 / lease expiry timers**

Each `_do_bound(now)` iteration checks:

- `now ≥ acquired_at + T1` → transition to RENEWING.
- `now ≥ acquired_at + T2` → transition to REBINDING
  (from either BOUND or RENEWING).
- `now ≥ acquired_at + lease_time` → transition to
  INIT (lease expired) and HALT NETWORK
  (RFC 2131 §4.4.5 MUST).

Default T1 = 0.5 × lease, T2 = 0.875 × lease (RFC 2131
§4.4.5).

**4.3 RENEWING / REBINDING**

RENEWING: unicast REQUEST to server-id, `ciaddr=`
current IP, no server-id option, no requested-ip
option. Backoff per RFC 2131 §4.4.5 ("one-half of the
remaining time until T2, down to a minimum of 60s").

REBINDING: broadcast REQUEST, `ciaddr=` current IP,
no server-id, no requested-ip. Backoff per RFC 2131
§4.4.5 ("one-half of the remaining lease time").

**4.4 DHCPRELEASE on shutdown**

```python
@override
def _stop(self) -> None:
    if self._state == Dhcp4State.BOUND and self._lease is not None:
        self._send_release(self._lease)
    super()._stop()
```

**4.5 Stack integration via the address API (Phase-3 seam)**

The `Dhcp4Lifecycle` subsystem must NOT mutate
`packet_handler._ip4_ifaddr` directly — that would be a
Phase-3 boundary violation (per `CLAUDE.md` Phase-3
design implications: "Configuration mutations go
through the API for their plane. Address changes go
through the address API, not
`packet_handler._ip6_ifaddr.append(...)`").

Introduce a minimal Phase-1 address-API stub that the
DHCP client is the first consumer of:

```python
# packages/pytcp/pytcp/stack/address.py — NEW
class Ip4AddressApi:
    """
    Phase-1 IPv4 address-control surface. Mirrors Linux
    RTNETLINK RTM_NEWADDR / RTM_DELADDR semantics
    (`net/ipv4/devinet.c`). The Phase-3 north-star wraps
    this around a real RTNETLINK-equivalent message
    bus; the Phase-1 implementation directly mutates
    PacketHandler state.

    Consumer code (DHCP client, future operator-config
    surfaces) imports this — never reaches into
    `packet_handler._ip4_ifaddr` directly.
    """

    def add_ifaddr(
        self,
        *,
        ip4_host: Ip4IfAddr,
        origin: Ip4IfAddrSource = Ip4IfAddrSource.DHCP,
    ) -> None: ...

    def remove_ifaddr(
        self,
        *,
        ip4_address: Ip4Address,
        abort_bound_sessions: bool = True,
    ) -> None:
        """
        Remove the address. Linux silently rots TCP sessions
        on a removed IP; PyTCP defaults to ACTIVE abort via
        the existing `_abandon_ipv4_address` hook (RFC 5227
        §2.4 final SHOULD). Pass `abort_bound_sessions=False`
        only for diagnostics.
        """

    def replace_ifaddr(
        self,
        *,
        old_address: Ip4Address,
        new_ifaddr: Ip4IfAddr,
        new_origin: Ip4IfAddrSource = Ip4IfAddrSource.DHCP,
    ) -> None:
        """
        Atomic swap. Install `new` BEFORE removing `old` so
        the brief overlap parallels Linux's RTM_DELADDR →
        RTM_NEWADDR ordering. Bound sessions on `old` abort
        once `new` is bound (RFC 5227 §2.4 final SHOULD).
        """

    def list_ip4_ifaddrs(self) -> tuple[Ip4IfAddr, ...]:
        """Read-only copy-by-value snapshot — Linux
        equivalent is `/proc/net/route` + `ip addr show`."""
```

`stack.init()` / `stack.start()` get two singletons
when `ip4_dhcp=True`:

- `stack.address: Ip4AddressApi` (operator-config +
  DHCP client share this)
- `stack.dhcp4_lifecycle: Dhcp4Lifecycle` (consumes
  `stack.address.*` methods)

`_create_stack_ip4_addressing` becomes
`dhcp4_lifecycle.start_and_wait_for_bind(timeout=N)`.

Phase-1 implementation of `Ip4AddressApi` is a thin
wrapper around `packet_handler._ip4_ifaddr.append(...)`
/ `_abandon_ipv4_address(...)`. Phase-3 swap replaces
the wrapper internals with RTNETLINK-equivalent
message bus routing; **consumer code does not change**.

### Phase 4.5 — Async address-change handling (Linux RTNETLINK parity)

When the lifecycle FSM transitions in a way that
changes the assigned IP — RENEW returning ACK with a
different `yiaddr`, NAK during RENEW/REBIND forcing
re-DISCOVER and a new address, or lease expiry forcing
INIT — the change must propagate to the rest of the
stack atomically.

**Linux model recap** (`net/ipv4/devinet.c`,
`dhcpcd`):

- Userspace daemon installs/removes IPs via
  RTM_NEWADDR / RTM_DELADDR.
- Kernel silently lets TCP sessions on a removed IP
  rot — RTO accumulates, applications see ETIMEDOUT.
- Routes added by the daemon via separate
  RTM_NEWROUTE are NOT auto-cleaned; daemon tracks
  and reaps them on lease loss.
- On RENEW with same IP → daemon does NOT call any
  RTM_*; pure internal bookkeeping.

**PyTCP behavior** (per the address API defined in 4.5
above):

| Transition                                  | Address-API call                       | TCP-session impact                  |
|---------------------------------------------|----------------------------------------|-------------------------------------|
| `INIT → BOUND` (first lease)                | `add_ifaddr(host, DHCP)`                 | none                                |
| `BOUND → BOUND` (RENEW ACK, same IP)        | none (internal lease bookkeeping)      | none                                |
| `BOUND → REBINDING → BOUND` (different IP)  | `replace_ifaddr(old, new, DHCP)`         | sessions on `old` abort             |
| `RENEW/REBIND NAK → INIT → BOUND` (different IP) | `replace_ifaddr(old, new, DHCP)`    | sessions on `old` abort             |
| `lease expiry, no new ACK`                  | `remove_ifaddr(addr)` + halt IPv4        | sessions on `addr` abort            |
| `stack.stop()` (graceful)                   | `send_release()` + `remove_ifaddr(addr)` | sessions abort with RST before RELEASE |

**Deliberate deviation from Linux: active TCP-session
abort.**

Linux's kernel doesn't actively reset TCP sessions on
address removal — they rot silently until application-
level timeouts fire. PyTCP is a single-process stack
with the existing `_abandon_ipv4_address` hook
(`packet_handler__arp__rx.py:131`) that already
implements RFC 5227 §2.4 final SHOULD ("hosts SHOULD
actively attempt to reset any existing connections
using that address"). Reusing it on every
`remove_ifaddr` / `replace_ifaddr` is cleaner than
Linux's behaviour.

This is a deliberate improvement; the RFC 2131
adherence record should mark it under "deviation
noted (cleaner than Linux)" rather than as a gap.
Document the choice with an inline comment at the
`abort_bound_sessions` parameter in
`Ip4AddressApi.remove_ifaddr`.

**Route-table cleanup deferred to Phase 7.**

Phase 4 only handles the single-gateway case via
`Ip4IfAddr.gateway`, which is auto-cleared when the
host is removed. Routes from DHCP option 3 (single
default gateway) ride along with the host.

Phase 7 (RFC 3442 Classless Static Routes) introduces
N independent routes per lease — those must be
explicitly tracked by the lifecycle and reaped via a
parallel `Ip4RouteApi` on lease loss. Mirrors
dhcpcd's per-lease route-tracking list.

**Tests for 4.5:**

- Same-IP RENEW ACK → `_ip4_ifaddr` unchanged, no
  abort.
- Different-IP after NAK → `_ip4_ifaddr` swap atomic
  (assert both never co-exist outside the
  `replace_ifaddr` window).
- TCP session bound to the old IP after swap → asserted
  aborted (RST emitted, session removed from
  `stack.sockets`).
- Lease expiry → `_ip4_ifaddr` empty + IPv4 disabled +
  abort happened.
- `stack.stop()` while BOUND → DHCPRELEASE on wire,
  THEN `remove_ifaddr` + abort.

**Tests for §4.4 (extended):** new integration
harness `packages/pytcp/pytcp/tests/lib/dhcp4_testcase.py`:

- Boot path: stub server replies → BOUND.
- T1 fires → RENEWING → unicast REQUEST → BOUND
  (same IP, no `replace_ifaddr` call).
- T2 fires (no RENEWING ACK) → REBINDING.
- Lease expires (no REBINDING ACK) → INIT + halt.
- Stack stop → DHCPRELEASE + `remove_ifaddr`.

**Adherence record refresh:** RFC 2131 §4.4 marked
met; §4.4.5 lease-expiry behaviour pinned. Add a
note about the Linux deviation.

### Phase 5 — INIT-REBOOT + cached lease (1-2 commits; ~6 hours)

**5.1 Cached lease persistence**

New sysctl `dhcp.lease_cache_path` (default
`/var/lib/packages/pytcp/pytcp/dhcp4_lease` or in-memory if empty).
On successful BOUND, the lifecycle serialises the
lease (IP, mask, gateway, server-id, lease-time,
acquired-at) to the cache file. On boot, the cache
file is read; if present and lease still has time
remaining, the lifecycle starts in INIT-REBOOT
instead of INIT.

**5.2 INIT-REBOOT state**

```python
def _do_init_reboot(self) -> None:
    # Broadcast REQUEST with requested-ip = cached IP,
    # no server-id, ciaddr = 0.
    self._send_request_init_reboot(cached_lease=self._cached_lease)
    self._state = Dhcp4State.REBOOTING

def _do_rebooting(self, now: float) -> None:
    # Same as REQUESTING but on timeout, fall back to INIT
    # (RFC 2131 §4.4.2 "If the client receives neither a
    # DHCPACK nor a DHCPNAK message after 60 seconds /
    # 4 tries, the client MAY choose to use the previously
    # allocated network address").
```

**Tests:**

- Boot with valid cache file → INIT-REBOOT path
  exercised → BOUND on ACK.
- Cache file present, NAK on REQUEST → fall back to
  INIT → DISCOVER → BOUND.
- Cache file present, lease expired → fall back to
  INIT without sending REBOOT REQUEST.

### Phase 6 — DNAv4 (RFC 4436) (1 commit; ~4 hours)

Built on top of Phase 5 (cached lease prerequisite).

```python
def _do_init_reboot(self) -> None:
    if nd_const.DHCP4__DNAV4 and self._cached_lease.gateway_mac is not None:
        # RFC 4436 — unicast ARP probe to prior gateway
        if self._dnav4_probe(self._cached_lease):
            # Reachable — short-circuit DHCP entirely
            self._apply_lease(self._cached_lease)
            self._state = Dhcp4State.BOUND
            return
    # Fall through to standard INIT-REBOOT (REQUEST)
    self._send_request_init_reboot(...)
```

`_dnav4_probe` sends a unicast ARP Request to the
cached gateway MAC for the cached gateway IP, waits
1 second (RFC 4436 §4.1), and returns True if a reply
arrives.

Requires ARP cache to support unicast probe emission
(currently only broadcast — single function addition
to `packages/pytcp/pytcp/protocols/arp/arp__cache.py`).

**New sysctl:** `dhcp.dnav4` (default 1; set 0 to
disable).

**Tests:**

- Cached lease + ARP reply received → BOUND without
  DHCP traffic.
- Cached lease + ARP timeout → INIT-REBOOT path
  (REQUEST broadcast).

### Phase 7 — Classless Static Routes (RFC 3442) — SHIPPED

Shipped 2026-05-25 (option-121 codec + RFC 3396
concatenation + client request/install). The host-mode
FIB / Route API (prerequisite below) landed first
(`docs/refactor/routing_table_host_mode.md`), removing
the single-gateway `Ip4IfAddr` limitation. Full
adherence record:
`docs/rfc/dhcp4/rfc3442__classless_static_route/adherence.md`.
The one deviation: router-0.0.0.0 (Local Subnet Routes)
entries are ignored per the RFC-permitted "stack does
not provide this capability" branch (Phase 2: install
on-link once DHCP-learned routes carry an output-interface
index in the FIB).

**Prerequisite (now satisfied):** A routing-table API.
Currently PyTCP's `Ip4IfAddr` carries a single gateway
field; a real routing table is needed for multiple
routes.

**7.1 Wire codec** — `Dhcp4OptionClasslessStaticRoute`
at `packages/net_proto/net_proto/protocols/dhcp4/options/`. Compact
encoding per RFC 3442 ("Destination descriptors
describe..."): width byte + significant octets + 4-byte
router.

**7.2 Option type added:**

```python
class Dhcp4OptionType(ProtoOptionType):
    ...
    CLASSLESS_STATIC_ROUTE = 121
```

**7.3 Param Request List:**

```python
Dhcp4OptionParamReqList([
    Dhcp4OptionType.CLASSLESS_STATIC_ROUTE,  # MUST be first
    Dhcp4OptionType.SUBNET_MASK,
    Dhcp4OptionType.ROUTER,
])
```

**7.4 Consumer side** — when 121 is present, install
each route into the routing table and IGNORE option 3
(RFC 3442 MUST). Phase-2-level work because the
routing table itself doesn't exist as a Phase-1 API.

**Tests:**

- Codec round-trip on the RFC's "examples" table.
- PRL ordering MUST satisfied.
- Both 121 and 3 in ACK → 121 installed, 3 ignored.

### Phase 8 — Polish options (1-2 commits; ~3 hours)

**8.1 Maximum DHCP Message Size (option 57)**

Always emit in DISCOVER and REQUEST when client can
accept larger messages — set to interface MTU
(default 1500).

**8.2 Lease time hint in DISCOVER (option 51)**

```python
Dhcp4OptionLeaseTime(lease_time__sec=86400)  # 1 day suggestion
```

Sysctl `dhcp.requested_lease_time__sec` (default
86400).

**8.3 RFC 3396 long-option concatenation** — SHIPPED
(2026-05-25, client/receive side, for the option-121
concatenation-requiring option). `Dhcp4Options.from_buffer`
joins the data of all same-code option-121 instances
before decoding. Server-side splitting on assembly
(option 121 TX, RFC 4702 FQDN TX) is a Phase-2
DHCP-server concern.

Update parser to concatenate split options before
typed-codec invocation. Required by RFC 3442 and
RFC 4702.

**8.4 Option Overload (option 52)** — SHIPPED

Parse `sname` / `file` overload — when option 52 is
present with value 1, 2, or 3, parse those fields as
additional options.

Shipped in `Dhcp4Parser._apply_option_overload` at
`packages/net_proto/net_proto/protocols/dhcp4/dhcp4__parser.py:115-176`.
The option dataclass is at
`packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option__overload.py`
with `includes_file` / `includes_sname` accessors.
Hostile-wire safety: each overloaded sub-block is preflighted
through `Dhcp4Options.validate_integrity(offset=0)` so a
truncated / over-length option inside the overlay raises a
typed `Dhcp4IntegrityError` before `from_buffer` dispatches
(commit `4c84b682`). Tests:
`packages/net_proto/net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__overload.py`
(10 tests, codec round-trip + integrity) and
`test__dhcp4__parser__option_overload.py` (6 tests,
parser-side merge happy + hostile paths).

### Phase 9 — Deferred RFCs

The following RFCs are documented as "not implemented"
in the audit but deferred from the implementation
plan because each requires an external consumer:

- **RFC 4702 (Client FQDN)** — requires DDNS update
  consumer. Skip until PyTCP grows a DNS resolver
  with DDNS support.
- **RFC 3203 (FORCERENEW)** — gated on RFC 3118 DHCP
  Authentication. Rarely deployed; defer
  indefinitely.
- **RFC 8910 (Captive Portal)** — requires HTTP
  user-agent. Defer until PyTCP grows one.

---

## 4. Sysctl knobs to add

| Key                              | Default                  | Phase  | RFC clause             |
|----------------------------------|--------------------------|--------|------------------------|
| `dhcp.retrans_initial_ms`        | 4000                     | 1      | RFC 2131 §4.1          |
| `dhcp.retrans_max_ms`            | 64000                    | 1      | RFC 2131 §4.1          |
| `dhcp.retrans_max_attempts`      | 5                        | 1      | RFC 2131 §4.1          |
| `dhcp.retrans_jitter_ms`         | 1000                     | 1      | RFC 2131 §4.1          |
| `dhcp.init_delay_max_ms`         | 10000                    | 2      | RFC 2131 §4.4.1        |
| `dhcp.decline_wait_ms`           | 10000                    | 2      | RFC 2131 §3.1 step 5   |
| `dhcp.duid`                      | "" (auto-derive from MAC)| 3      | RFC 4361 §6.1          |
| `dhcp.iaid_base`                 | 0                        | 3      | RFC 4361 §6.1          |
| `dhcp.t1_fraction`               | 0.5                      | 4      | RFC 2131 §4.4.5        |
| `dhcp.t2_fraction`               | 0.875                    | 4      | RFC 2131 §4.4.5        |
| `dhcp.requested_lease_time__sec` | 86400                    | 8      | RFC 2131 §3.5          |
| `dhcp.lease_cache_path`          | ""  (in-memory; no persistence) | 5 | (PyTCP-internal)  |
| `dhcp.dnav4`                     | 1                        | 6      | RFC 4436               |
| `dhcp.classless_static_routes`   | 1                        | 7      | RFC 3442               |

Each knob is added via the `sysctl_knob` skill — one
invocation per knob, classify as policy.

---

## 5. New / touched files inventory

### New source files

- `packages/pytcp/pytcp/stack/address.py` (Phase 4) —
  `Ip4AddressApi` (and `Ip6AddressApi` skeleton for
  symmetry); the Phase-3 north-star address-control
  surface. DHCP client is the first consumer; future
  operator-config code (manual `ip addr add`-like
  surfaces) layers on top.
- `packages/pytcp/pytcp/lib/route_api.py` (Phase 7 prereq) —
  `Ip4RouteApi` mirroring `RTM_NEWROUTE` /
  `RTM_DELROUTE`. Phase 4 uses
  `Ip4AddressApi`-implicit single-gateway only; Phase 7
  introduces N-route tracking.
- `packages/pytcp/pytcp/lib/dhcp4_lifecycle.py` (Phase 4) —
  `Dhcp4Lifecycle(Subsystem)` FSM. Consumes
  `stack.address` exclusively; never touches
  `_ip4_ifaddr` directly.
- `packages/pytcp/pytcp/lib/dhcp_uid.py` (Phase 3) — DUID/IAID helper.
- `packages/pytcp/pytcp/lib/dhcp4_lease_cache.py` (Phase 5) —
  serialised lease cache.
- `packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option__classless_static_route.py`
  (Phase 7).
- `packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option__client_fqdn.py`
  (Phase 9, deferred).
- `packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option__max_msg_size.py`
  (Phase 8).
- `packages/pytcp/pytcp/lib/dhcp4_constants.py` — sysctl-backed
  policy constants (per `pytcp.md` §2).

### Touched source files

- `packages/pytcp/pytcp/protocols/dhcp4/dhcp4__client.py` (Phases 0, 1, 2, 3,
  8) — every phase.
- `packages/pytcp/pytcp/runtime/packet_handler/__init__.py` (Phase 4,
  5) — replace `_create_stack_ip4_addressing` DHCP
  block with `dhcp4_lifecycle` integration; harness
  snapshot/restore.
- `packages/pytcp/pytcp/stack/__init__.py` (Phase 4) — add
  `stack.address: Ip4AddressApi` and
  `stack.dhcp4_lifecycle: Dhcp4Lifecycle` singletons;
  update `stack.init()`, `stack.start()`,
  `stack.stop()` plus the test-harness snapshot
  contract (`integration_testing.md` §5.4 — any new
  module-level state requires snapshot/restore in
  `NetworkTestCase` setUp/tearDown).
- `packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__option.py`
  (Phase 7) — extend `Dhcp4OptionType` enum.
- `packages/net_proto/net_proto/protocols/dhcp4/options/dhcp4__options.py`
  (Phase 0.3, 7, 8) — new accessors: `client_id`,
  `classless_static_routes`, etc.
- `packages/pytcp/pytcp/protocols/arp/arp__cache.py` (Phase 6) —
  unicast ARP Request emission for DNAv4 probe.
- `packages/pytcp/pytcp/stack/sysctl.py` registry — populated via the
  `sysctl_knob` skill per Phase.

### New test files

- `packages/pytcp/pytcp/tests/integration/protocols/dhcp4/test__dhcp4__fsm.py`
  (Phase 4) — full FSM state-by-state.
- `packages/pytcp/pytcp/tests/integration/protocols/dhcp4/test__dhcp4__retransmission.py`
  (Phase 1).
- `packages/pytcp/pytcp/tests/integration/protocols/dhcp4/test__dhcp4__decline.py`
  (Phase 2).
- `packages/pytcp/pytcp/tests/integration/protocols/dhcp4/test__dhcp4__init_reboot.py`
  (Phase 5).
- `packages/pytcp/pytcp/tests/integration/protocols/dhcp4/test__dhcp4__dnav4.py`
  (Phase 6).
- `packages/pytcp/pytcp/tests/integration/protocols/dhcp4/test__dhcp4__classless_routes.py`
  (Phase 7).
- `packages/pytcp/pytcp/tests/unit/lib/test__lib__dhcp_uid.py` (Phase 3).
- `packages/pytcp/pytcp/tests/unit/lib/test__lib__dhcp4_lease_cache.py`
  (Phase 5).
- `packages/pytcp/pytcp/tests/lib/dhcp4_testcase.py` (Phase 4) — new
  integration test harness extending `NetworkTestCase`
  with stub server + FakeTimer + lease helpers.

### Touched test files

- `packages/pytcp/pytcp/tests/unit/lib/test__lib__dhcp4_client.py`
  (Phases 0, 1, 2, 3) — extend with new contract tests.
- `packages/pytcp/pytcp/tests/lib/network_testcase.py` (Phase 4) —
  snapshot/restore `stack.dhcp4_lifecycle` per the
  `integration_testing.md` §5.4 contract.

---

## 6. Open design decisions

These are the questions a fresh session should
re-confirm with the user before implementing the
relevant phase.

1. **Lease cache storage format.** JSON in
   `/var/lib/packages/pytcp/pytcp/dhcp4_lease`? Or a small sysctl-
   serialised blob? Phase 5.
2. **DUID flavour.** RFC 3315 lists DUID-LL, DUID-LLT,
   DUID-UUID. Plan defaults to DUID-LL (link-layer);
   user should confirm if DUID-LLT (with timestamp,
   for greater uniqueness across MAC reuse) is
   preferred. Phase 3.
3. **Stack-level DHCP enable.** Currently `ip4_dhcp`
   is a single boolean on `PacketHandlerL2.__init__`.
   Phase 4 introduces a lifecycle thread that must
   stop on `stack.stop()` — should the boolean become
   a richer config (e.g. retry-forever vs give-up-
   after-N)? Phase 4.
4. **Multi-interface.** The current plan assumes
   one DHCP client per stack. Multi-interface
   (Phase 2 north-star territory) would need one
   `Dhcp4Lifecycle` per interface. Plan currently
   ignores this; revisit when multi-interface lands.
5. **Address API scope in Phase 4.** Phase 4 builds
   the minimal `Ip4AddressApi` (add/remove/replace/
   list) needed by the DHCP client. Should it also
   include the operator-facing surface
   (`set_subnet_mask`, `set_origin`, ...) so the
   Phase-3 cutover is mechanical, or keep it
   DHCP-only for Phase 4 and broaden later? User
   decision.
6. **Routing-table API scope.** Phase 4 uses the
   single-gateway `Ip4IfAddr.gateway` field (option 3).
   Phase 7 (RFC 3442) requires N independent routes
   per lease — necessitates an `Ip4RouteApi` mirroring
   `RTM_NEWROUTE` / `RTM_DELROUTE`. Should `Ip4RouteApi`
   be designed in Phase 4 as a stub even though
   single-gateway is sufficient, or deferred until
   Phase 7? Recommendation: stub now, populate in
   Phase 7 (mirrors how `Ip4AddressApi` is being
   designed).
7. **Boot blocking semantics.** Today
   `_create_stack_ip4_addressing` is synchronous —
   the boot path waits for DHCP completion. After
   Phase 4 the lifecycle runs asynchronously; should
   the boot path block until BOUND
   (`start_and_wait_for_bind(timeout=N)`), time out
   after N seconds and proceed without IPv4, or
   return immediately and let other subsystems race
   the lifecycle? User decision; recommend
   `wait_for_bind` with `dhcp.boot_wait_ms` sysctl
   default 30 000 ms — matches Linux dhcpcd's
   default `oneshot` 30-s timeout.
8. **TCP-session abort policy on lease change.**
   The plan defaults `Ip4AddressApi.remove_ifaddr`'s
   `abort_bound_sessions=True` (active abort, cleaner
   than Linux). Should this be configurable via a
   sysctl `dhcp.abort_sessions_on_lease_change`
   (default 1) so operators can choose Linux-parity
   silent-rot behaviour? Recommendation: yes — the
   sysctl is cheap insurance.

---

## 7. Test strategy

The wire-format library already has ~8 900 unit-test
lines. The plan does not add to that; instead, every
phase adds **integration tests** under
`packages/pytcp/pytcp/tests/integration/protocols/dhcp4/` exercising
the client end-to-end via the new
`Dhcp4TestCase` harness (Phase 4 prerequisite).

`Dhcp4TestCase` (new harness):
- Extends `NetworkTestCase`.
- Stubs the DHCP server: receives outbound DHCP
  frames via the mocked TxRing, parses them, builds
  a canned reply, drives the reply back through
  `_drive_rx`.
- Exposes `_drive_dhcp_exchange(...)` similar to
  `_drive_dad` on `ArpTestCase`.
- Snapshots / restores `stack.dhcp4_lifecycle` per
  `integration_testing.md` §5.4.

Phase-by-phase test count estimate:

| Phase   | New unit tests | New integration tests |
|---------|----------------|-----------------------|
| 0       | ~12            | 0                     |
| 1       | ~4             | ~3                    |
| 2       | ~2             | ~3                    |
| 3       | ~8             | ~3                    |
| 4       | ~5             | ~15                   |
| 5       | ~4             | ~5                    |
| 6       | ~2             | ~4                    |
| 7       | ~6             | ~3                    |
| 8       | ~6             | ~2                    |

Total: ~50 unit + ~38 integration = ~88 new tests.

The §7.2 docstring audit must pass on every new test
file (per `unit_testing.md` §7.2).

---

## 8. Effort estimate

Cumulative scope from Phase 0 → Phase 8 (Phase 9
deferred):

| Phase | Description                          | Effort     |
|-------|--------------------------------------|------------|
| 0     | Five quick wins                      | ~1 hour    |
| 1     | Retransmission backoff               | ~3 hours   |
| 2     | Initial delay + DHCPDECLINE          | ~3 hours   |
| 3     | DUID / IAID Client Identifier        | ~4 hours   |
| 4     | Subsystem + lease lifecycle FSM      | ~2 days    |
| 5     | INIT-REBOOT + cached lease           | ~6 hours   |
| 6     | DNAv4                                | ~4 hours   |
| 7     | Classless Static Routes (gated)      | ~6 hours   |
| 8     | Polish (option 57, 51, RFC 3396, 52) | ~3 hours   |

Total **excluding** Phase 7 (which is blocked on
routing-table API): ~3-4 days of focused work,
spread across ~10-12 commits.

---

## 9. Commit discipline

Per `feature_implementation.md` §4:

- One concern per commit.
- Tests + impl together when atomic.
- Refresh the relevant adherence record in the SAME
  commit as the code change (per the
  `feedback_audit_in_lockstep_with_code` memory).
- `make lint` clean + `make test` clean per commit.
- §7.2 docstring audit clean on every new test file.

Phase boundaries are natural commit boundaries. Some
phases (1, 4) will produce multiple commits; mark
each commit with the phase number in the subject
line for traceability.

---

## 10. Closing the audit loop

Each phase that closes a MUST gap should:

1. Update `docs/rfc/dhcp4/rfcXXXX__*/adherence.md` to
   move the relevant requirement from "not met" to
   "met".
2. Update the overall-assessment table at the
   bottom.
3. Update the principal-compliance-gap closing
   paragraph.

The 11 audit records are the canonical source of
"what's done"; this plan is the canonical source of
"how to get there." Both should converge: after the
final phase commit, every audit record's "principal
compliance gap" paragraph should be either
"all relevant requirements met" or list only the
deferred Phase-9 RFCs.

---

## 11. References

| Document                                                                             | Role                                  |
|--------------------------------------------------------------------------------------|---------------------------------------|
| `docs/rfc/dhcp4/rfc2131__dhcp/adherence.md`                                          | Authoritative gap inventory (core)    |
| `docs/rfc/dhcp4/rfc2132__dhcp_options/adherence.md`                                  | Option-catalogue gap inventory        |
| `docs/rfc/dhcp4/rfc4361__node_specific_client_id/adherence.md`                       | DUID/IAID gap                         |
| `docs/rfc/dhcp4/rfc6842__client_id_echo/adherence.md`                                | CID echo validation gap               |
| `docs/rfc/dhcp4/rfc3442__classless_static_route/adherence.md`                        | Classless routes gap                  |
| `docs/rfc/dhcp4/rfc4436__dnav4/adherence.md`                                         | DNAv4 gap                             |
| `.claude/rules/feature_implementation.md`                                            | Tests-first workflow                  |
| `.claude/rules/pytcp.md`                                                             | Subsystem / sysctl conventions        |
| `.claude/rules/unit_testing.md` + `.claude/rules/integration_testing.md`             | Test conventions + §7.2 audit         |
| `.claude/skills/sysctl_knob/SKILL.md`                                                | New sysctl workflow                   |
| `.claude/skills/rfc_adherence_audit/SKILL.md`                                        | Adherence-record refresh workflow     |
| Linux `net/ipv4/devinet.c`                                                           | RTNETLINK reference for `RTM_NEWADDR` / `RTM_DELADDR` |
| Linux `dhcpcd` source                                                                | Reference DHCPv4 client implementation |

---

## 12. Linux comparison + Phase-3 alignment

This section is the explicit architectural map
between PyTCP's design and Linux's DHCP architecture.
The Phase-3 north-star ("kernel/userspace boundary
with Linux-mirrored APIs") is binding — design
decisions made now must not foreclose the Phase-3
cutover.

### 12.1 Architecture comparison

| Concern                  | Linux                                                                                    | PyTCP Phase 1 (this plan)                                       | PyTCP Phase 3 (north-star)                                  |
|--------------------------|------------------------------------------------------------------------------------------|-----------------------------------------------------------------|-------------------------------------------------------------|
| DHCP code lives in       | Userspace daemon (`dhcpcd`, `dhclient`, `systemd-networkd`)                              | Same Python process as the TCP/IP stack                         | Logically userspace (DHCP becomes a consumer of the kernel-equivalent address API) |
| Address mutation         | `RTM_NEWADDR` / `RTM_DELADDR` over `AF_NETLINK NETLINK_ROUTE`                            | `stack.address.add_ifaddr(...)` / `.remove_ifaddr(...)`             | Same surface; internals route via in-process RTNETLINK-equivalent message bus |
| Route mutation           | `RTM_NEWROUTE` / `RTM_DELROUTE` over `AF_NETLINK`                                        | `Ip4IfAddr.gateway` field auto-managed with host (single-gateway only) | `stack.route.add_*` / `.remove_*` (Phase 7 introduces)      |
| TCP-session on removed IP| Kernel silently lets RTO accumulate; no proactive RST                                    | Active abort via `_abandon_ipv4_address` (RFC 5227 §2.4 final SHOULD) | Same — Linux-deviation deliberate                          |
| Lease persistence        | `/var/lib/dhcp/dhcpcd.lease` (per-interface)                                             | `dhcp.lease_cache_path` sysctl (Phase 5)                        | Same                                                        |
| DUID storage             | `/var/lib/dhcp/dhcpcd.duid`                                                              | `dhcp.duid` sysctl (Phase 3)                                    | Same                                                        |
| Renewal threading        | Single-thread event loop (`libevent`)                                                    | Dedicated `Subsystem` thread for `Dhcp4Lifecycle`               | Same                                                        |
| RX dispatch              | Raw socket on port 68 owned by daemon                                                    | BSD-socket-style `socket(AF_INET4, SOCK_DGRAM)` bound on 68     | Same — already a Phase-3 surface                            |

### 12.2 The "Phase-3-clean" design rule

Every consumer-facing decision in this plan follows
one rule: **the DHCP client must reach into the stack
only through APIs that are valid in Phase 3** (the
seven sanctioned surfaces in `CLAUDE.md`: socket,
sysctl, link, address, route, neighbor,
introspection).

Concretely:

- `Dhcp4Lifecycle` imports `stack.address`,
  `stack.route` (Phase 7), `stack.sockets` (already
  Phase-3-clean), `sysctl_module`.
- `Dhcp4Lifecycle` does NOT import
  `packet_handler._ip4_ifaddr`, `_arp_defend__*`,
  `_abandon_ipv4_address`, or any other
  packet-handler private state. **If it needs
  something, that thing becomes part of the
  address / route / introspection API instead.**
- Phase-1 implementation of those APIs is a thin
  wrapper around current packet-handler state;
  Phase 3 swaps the wrapper internals for the real
  message bus without changing the DHCP client.

The address API is essentially the smallest
Phase-3 surface PyTCP can ship today. Building it
in Phase 4 — driven by the DHCP client as the first
consumer — is the cheapest way to validate the
Phase-3 design without committing to a full
RTNETLINK-equivalent message bus.

### 12.3 Deliberate Linux deviations (documented)

Two places where PyTCP improves on Linux. Both are
documented in adherence records so future readers
know these are choices, not gaps:

1. **Active TCP-session abort on address removal.**
   PyTCP defaults to actively aborting (sending RST,
   freeing the session, removing from
   `stack.sockets`) when an IP is removed from the
   stack. Linux silently lets the session rot until
   RTO times out. The PyTCP behaviour matches
   RFC 5227 §2.4 final SHOULD and is cleaner in a
   single-process stack. Sysctl
   `dhcp.abort_sessions_on_lease_change=0` is
   available to opt into Linux-parity rot.

2. **Optional DUID storage in sysctl rather than
   filesystem.** Linux stores DUID under
   `/var/lib/dhcp/`; PyTCP defaults to the sysctl
   registry (in-memory, derived from MAC each boot
   unless operator overrides via
   `sysctl_module.override("dhcp.duid", "...")`).
   The Linux-style filesystem path is reachable by
   pointing `dhcp.duid_storage_path` at a real file
   (Phase 3 follow-up); the Phase-1 default
   ("derive each boot from MAC") matches dhcpcd's
   `--allowinterfaces` minimal mode.

### 12.4 What this plan deliberately does NOT include

The following are explicitly out of scope for the
DHCPv4 refactor, even though they touch the same
machinery:

- **DHCPv6 client.** Different RFC (RFC 8415,
  formerly 3315), different message format, different
  state machine. Future `docs/refactor/dhcp6_client_*.md`.
- **DHCP server / relay agent.** PyTCP is a host
  stack; server/relay are Phase 2 router territory.
- **RFC 3118 DHCP Authentication.** Rare in
  practice; gates FORCERENEW (RFC 3203) which is
  also Phase 9 deferred.
- **Multi-interface DHCP.** One `Dhcp4Lifecycle` per
  stack today; multi-interface requires
  per-interface lifecycles and the address API
  growing an `interface=` parameter. Phase 2
  north-star territory.
