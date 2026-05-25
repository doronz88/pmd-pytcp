# Raw Link Socket (`AF_PACKET`) Plan

| Field  | Value |
|--------|-------|
| Status | **COMPLETE on `PyTCP_3_0_6`.** Phases 0-3 (`AF_PACKET` socket) and the full userspace ACD migration (4.1-4.5) shipped & pushed — including 4.5, deleting the in-RX conflict detector (`0d0aef0b`). End state matches Linux `sd-ipv4acd`: all IPv4 ACD runs over per-address `Ip4Acd` `AF_PACKET` sockets; the ARP RX path does no conflict detection. See §10.1 for the per-step commit ledger. Created 2026-05-23; closed 2026-05-24. |
| Branch | `PyTCP_3_0_6` |
| Motivation | Linux-faithful client-side ACD (DHCPv4 / RFC 3927 link-local), and a general L2 send/capture substrate. Unblocks the paused *IPv6 Address API / ACD-off-the-Address-API* refactor — see `packet_handler_rewrite_plan.md` Phase 8 and the ACD discussion below. |

---

## 1. Goal

Add an `AF_PACKET` **raw link socket** to `pytcp.socket` so consumers
can send and receive **raw Ethernet frames** (including ARP, which is
below IP and therefore unreachable through the existing raw **IP**
socket). This is the PyTCP equivalent of Linux
`socket(AF_PACKET, SOCK_RAW, htons(ETH_P_...))` (`net/packet/af_packet.c`).

The immediate consumer is **client-side ACD**: today the ARP-probe /
announce mechanism is a stack primitive exposed (wrongly, vs Linux) on
`Ip4AddressApi`. With a raw link socket the DHCPv4 client and the
RFC 3927 link-local client can emit their own ARP probes — exactly as
Linux `dhclient` / `systemd-networkd` do over `AF_PACKET` — so ACD
*mechanism* and *policy* both live in the client and the Address API
collapses to the clean `add/del/list/flush` Linux surface.

Secondary consumers: tcpdump-style capture, custom L2 protocols,
test harnesses that want to assert on raw egress frames without
parsing through the IP layer.

## 2. Why the existing `RawSocket` is not enough

`pytcp.socket.RawSocket` is a raw **IP** socket — Linux
`socket(AF_INET, SOCK_RAW, proto)` / `IPPROTO_RAW`:

- Family is `AddressFamily.INET4 / INET6` only; there is no `AF_PACKET`
  (`socket/__init__.py:302`).
- It is keyed by `IpProto`; its `send` / `sendto` inject at the IP
  layer via `egress_packet_handler(...).send_ip{4,6}_packet(...)`
  (`raw__socket.py:265-322`). The stack still builds the IP context
  and does the Ethernet / ARP framing *below* it.

Consequence: an ARP probe (an L2 / ARP-ethertype frame) cannot be sent
through it. ACD therefore cannot move into the client without an
`AF_PACKET`-style door. This plan adds that door.

## 3. Linux reference (the parity target)

- **Create.** `socket(AF_PACKET, SOCK_RAW, htons(protocol))`.
  - `SOCK_RAW` — the buffer is the **complete** Ethernet frame
    (dst/src MAC + ethertype + payload); the sender supplies the whole
    header.
  - `SOCK_DGRAM` — "cooked": the link header is stripped on RX and
    built by the kernel on TX from the `sockaddr_ll`.
  - `protocol` — an **ethertype** in network order (`ETH_P_ARP`,
    `ETH_P_IP`, …) or `ETH_P_ALL` (every frame). It is a capture /
    delivery filter, not an `IpProto`.
- **Address — `struct sockaddr_ll`** (`linux/if_packet.h`):
  `sll_family` (AF_PACKET), `sll_protocol` (ethertype), `sll_ifindex`
  (bind scope), `sll_hatype`, `sll_pkttype`
  (`PACKET_HOST`/`BROADCAST`/`MULTICAST`/`OTHERHOST`/`OUTGOING`),
  `sll_halen`, `sll_addr` (the MAC).
- **bind(sockaddr_ll)** scopes the socket to one `sll_ifindex` and an
  ethertype filter. Unbound = every interface.
- **RX.** Every ingress frame matching `(ifindex?, ethertype)` is
  queued to the socket, regardless of whether the stack also consumes
  it (a packet socket is a tap, parallel to normal delivery).
- **TX.** `sendto(frame, sockaddr_ll)` writes the frame out
  `sll_ifindex`. `SOCK_RAW` writes verbatim; `SOCK_DGRAM` prepends the
  header from `sll_addr` / `sll_protocol`.

## 4. Current state — the seams this touches

| Seam | File | What changes |
|------|------|--------------|
| Socket factory `__new__` dispatch | `socket/__init__.py:670` | new `case (AddressFamily.PACKET, SocketType.RAW, ...)` → `PacketSocket` |
| `AddressFamily` / `SocketType` enums | `socket/__init__.py:297,318` | add `PACKET = 17` (Linux value); `protocol` arg becomes an ethertype for the PACKET family |
| Socket identity / registry | `socket/socket_id.py`, `socket/socket_table.py`, `stack.sockets` | `SocketId` is IP-shaped (`local/remote address+port`). Packet sockets key on `(ifindex, ethertype)` → a **separate registry** (`stack.packet_sockets`) is cleaner than overloading the IP-keyed table |
| Ingress tap | `packet_handler__ethernet__rx.py:63` (`_phrx_ethernet`) | fan every parsed frame to matching packet sockets **before** the EtherType→IP demux; must not slow the hot path when no packet socket is bound |
| Egress | `runtime/tx_ring.py` (`enqueue`/`dispatch`) | a path that puts an **already-built** Ethernet frame on the ring, skipping the IP / assembler layers |
| Lifecycle | `stack/__init__.py`, `stack/lifecycle.py` | `packet_sockets` registry built per `init()` / `mock__init()`; close-on-stop |

## 5. Phased plan

Each phase is tests-first (one failing test → impl), `make lint` +
`make test` clean, one focused commit (or a tests+impl pair).

- **Phase 0 — enums + factory dispatch (skeleton).** Add
  `AddressFamily.PACKET`, the `sockaddr_ll`-equivalent address value
  type (a small frozen dataclass: `ifindex`, `ethertype`, `pkttype`,
  `mac`), and the factory `__new__` branch returning a `PacketSocket`
  stub. No RX/TX behaviour. Unit-test the dispatch + bad-combo
  `EPROTONOSUPPORT` / `ValueError`.
- **Phase 1 — RX tap + recv.** A `PacketSocket` registry keyed by
  `(ifindex, ethertype)` with `ETH_P_ALL` wildcard; the
  `_phrx_ethernet` tap fans matching frames into per-socket queues
  with `pkttype` metadata; `recvfrom()` returns `(frame, sockaddr_ll)`.
  Integration test: drive an RX frame, assert a bound packet socket
  receives it AND normal IP delivery still happens (tap is parallel).
- **Phase 2 — TX (`SOCK_RAW`).** `sendto(frame, addr)` enqueues a
  verbatim Ethernet frame onto the egress interface's `TxRing`.
  Integration test: send → assert the exact bytes hit the ring.
- **Phase 3 — bind / ifindex scoping + ethertype filter.**
  `bind(sockaddr_ll)`; unbound = all interfaces; protocol filter;
  `pkttype` classification (HOST/BROADCAST/MULTICAST/OUTGOING).
- **Phase 4 — consumer payoff (the ACD move).** Rewire the DHCPv4
  `arp_dad_verifier` / `arp_dad_announcer` and the RFC 3927
  link-local client to run ACD over a `PacketSocket` (ethertype ARP)
  instead of `Ip4AddressApi.probe` / `.announce` /
  `claim_with_acd`. Then strip the ACD surface off `Ip4AddressApi`
  (coordinates with the paused Address-API refactor).
- **Phase 5 — `SOCK_DGRAM` cooked variant (optional), docs, RFC
  adherence.** Cooked header build/strip; capture example;
  introspection.

## 6. Open design decisions

- **Separate `packet_sockets` registry vs generalising `SocketId`.**
  `SocketId` (IP 4-tuple) does not fit `(ifindex, ethertype)`. A
  dedicated registry + `PacketSocketId` keeps the IP fast-path
  delivery untouched. **Lean: separate registry.**
- **Hot-path cost of the ingress tap.** When no packet socket is
  bound, the tap must be a single cheap "is the registry empty?"
  check. Guard with a module-level "any packet sockets?" flag.
- **`SOCK_RAW` first, `SOCK_DGRAM` later.** Full-frame send/recv is
  what ACD needs; the cooked variant is a convenience.
- **Phase-3 boundary.** The factory `__new__` stays dumb (family/type/
  protocol match + allocate); all behaviour on `PacketSocket`.
- **Frame copy semantics.** RX hands the socket a copy (or a
  `memoryview` into a buffer that outlives delivery) — packet sockets
  must not alias the RX ring buffer.
- **L2 vs L3 interfaces.** Packet sockets are Ethernet (L2) only; a
  TUN (L3) interface has no link header — bind to an L3 ifindex
  raises (mirrors the ARP/ND L2-only caveat).

## 7. Non-goals (out of scope)

- BPF / cBPF / eBPF socket filters (`SO_ATTACH_FILTER`).
- `PACKET_RX_RING` / `PACKET_TX_RING` mmap'd ring buffers
  (`PACKET_MMAP`).
- VLAN tag offload, `PACKET_AUXDATA`, timestamping.
- `AF_PACKET` fanout groups (`PACKET_FANOUT`).
These are Linux extensions with no PyTCP consumer; revisit per the
north-star "real consumer" test.

## 8. Relationship to the paused work

This plan is the prerequisite that makes the *ACD-off-the-Address-API*
step of `packet_handler_rewrite_plan.md` Phase 8 fully Linux-faithful.
Sequencing once this lands: (1) packet socket → (2) move ACD into the
clients over it → (3) strip ACD off `Ip4AddressApi` → (4) the unified
`stack.address` add/del/list/flush surface (the originally-paused IPv6
Address API slice rides on (4)).

## 9. References

- Linux `man 7 packet`; `linux/if_packet.h` (`sockaddr_ll`,
  `PACKET_*`); `net/packet/af_packet.c`.
- PyTCP socket layer: `socket/__init__.py` (factory, enums),
  `socket/raw__socket.py` (raw-IP sibling), `socket/socket_id.py`,
  `socket/socket_table.py`.
- RX/TX seams: `runtime/packet_handler/packet_handler__ethernet__rx.py`,
  `runtime/tx_ring.py`, `runtime/rx_ring.py`.
- Consumers to rewire (Phase 4): `protocols/dhcp4/dhcp4__client.py`,
  `protocols/ip4/link_local/link_local__client.py`, `stack/address.py`.
- Rules: `.claude/rules/pytcp.md` (socket facade §5, factory §5.1),
  `enums.md` (stdlib-parity bare-alias pattern for `AF_PACKET` /
  `ETH_P_*` / `PACKET_*`).

---

## 10. Phase 4 execution status + the full-"B" ACD migration

### 10.1 What shipped (pushed, green — 11355 tests)

| Sub-phase | Commit | Summary |
|-----------|--------|---------|
| 4.1 | `21dd1c79` | `Ip4Acd` engine (`protocols/ip4/acd/ip4_acd.py`): `probe` + `announce` over the AF_PACKET socket; conflict detect by reading ARP off the socket. The Linux `sd-ipv4acd` model. |
| 4.1 | `981ba5fa` | `Ip4Acd` ongoing-defense lifecycle: `claim` (probe+announce, holds the socket), `poll_conflict` (§2.4 drain → peer MAC), `defend` (gratuitous ARP), `release`. |
| 4.2 | `a9cdd077` | DHCPv4 `arp_dad_verifier`/`announcer` repointed from `Ip4AddressApi.probe/announce` to `Ip4Acd.probe/announce` (lifecycle glue only). |
| 4.3 | `5ae0839a` | RFC 3927 link-local fully off the Address-API ACD surface: `_do_claiming` → `Ip4Acd.claim` + `add_ifaddr`; BOUND tick polls `Ip4Acd.poll_conflict` → §2.5 `defend`/abandon. |
| 4.4a | `315ab58a` | Static-host `_create_stack_ip4_addressing` → per-candidate `Ip4Acd.probe`+`announce`, NO ongoing defender (bare `ip addr add`). |
| 4.4b | `2bd44154` | DHCPv4 client takes `acd: Ip4Acd` directly; INIT `probe`→DECLINE-on-conflict, BOUND `start_defense`+`poll_conflict`→DHCPDECLINE+re-acquire. New engine primitive `Ip4Acd.start_defense` (announce+hold, no re-probe). |
| 4.4c | `8985e261` | **Deleted** the in-RX ARP conflict detector (`_handle_arp_conflict`/`_abandon_ipv4_address`/`_arp_defend__*`/RX conflict branches) + probe-time DAD (`_arp_dad_*`/`_ip4_arp_dad__registry`/`_send_arp_probe`/`_send_arp_announcement`/`_send_gratuitous_arp`) + the orphaned `Ip4AddressApi.probe`/`announce`/`claim_with_acd`/`send_gratuitous_arp` wrappers + 7 dead RX stat counters. Fixes the latent double-defense. `DadSlotRegistry` kept (IPv6 ND). |
| 4.5 | `0d0aef0b` | Stripped `Ip4AddressApi` to the pure `ip addr` surface (`add_ifaddr`/`remove_ifaddr`/`replace_ifaddr`/`list_ip4_ifaddrs` + `interface`); removed the dead conflict-subscription machinery + public `abort_bound_tcp_sessions`. |

**COMPLETE.** The full Linux `sd-ipv4acd` end state: all IPv4 ACD is a userspace function over per-address `Ip4Acd` AF_PACKET sockets; the stack ARP RX path does no conflict detection. Sections 10.2-10.5 below are the historical plan (kept for archaeology); every step landed. Suite green at 11302 tests.

### 10.2 The architecture the code actually has (discovered reading it)

- **Ongoing §2.4 defense for ALL installed IPv4 addresses** (static, DHCP, *and* link-local) lives in the ARP RX path: `packet_handler__arp__rx._handle_arp_conflict` (+ `_abandon_ipv4_address`, the `_arp_defend__last_conflict_at` / `_arp_defend__last_emitted` dicts), triggered from the two `spa in self._ip4_unicast and sha != _mac` branches (arp__rx lines ~262/269 and ~422). It is **not dead code** — it is the only defender for static/DHCP addresses.
- **`DadSlotRegistry`** (`lib/dad_slot_registry.py`) is **shared with IPv6 ND DAD** (`_icmp6_nd_dad__registry`, used by `packet_handler__icmp6__rx` + `_perform_ip6_nd_dad`). The class **stays**; only the IPv4 `_ip4_arp_dad__registry` usage is removable.
- **Static-host claim** (`packet_handler.__init__._create_stack_ip4_addressing`) still calls `stack.address.claim_with_acd` → `Ip4AddressApi.probe/announce` → `handler._arp_dad_probe_address` / `_arp_dad_announce_address`. A remaining consumer of the old path.
- **Latent double-defense bug (introduced by 4.3):** a link-local address is installed in `_ip4_ifaddr`, so a conflicting ARP for it is now handled **twice** — by the RX `_handle_arp_conflict` AND by link-local's own `Ip4Acd.poll_conflict`. They can race (RX `_abandon` yanks the address while link-local still thinks it is BOUND). Only resolved by deleting the RX detector (§10.3 step 3). No clean interim fix exists because the RX path legitimately still defends static/DHCP until they migrate.

### 10.3 Full-"B" plan (the chosen, Linux-faithful end state)

Per-address `Ip4Acd` everywhere (the Linux model: each managed address has its own acd doing probe+announce+ongoing-defense on its own socket; the kernel does no IPv4 ACD).

1. **4.4a — static-host → `Ip4Acd`.** Rewire `_create_stack_ip4_addressing`: `Ip4Acd(mac, ifindex).probe()` → on clean, `announce()` + install (`self._ip4_ifaddr = [*..., host]`). **Static gets probe+announce only, NO ongoing defender** — matches a bare Linux `ip addr add` (ongoing defense is a managing-daemon job; static config is the bare assignment). Add `from pytcp.protocols.ip4.acd.ip4_acd import Ip4Acd` (verified no import cycle).
2. **4.4b — DHCP ongoing defense.** Restructure the DHCPv4 `Subsystem` so the BOUND state holds an `Ip4Acd.claim` on the lease address and polls `poll_conflict` each tick; abandon → DHCPDECLINE + FSM restart. (networkd-equivalent; the SHOULD per RFC 5227 §2.4 / RFC 2131.)
3. **4.4c — delete the RX conflict detector + probe-time DAD machinery.** Remove `_handle_arp_conflict`, `_abandon_ipv4_address`, `_arp_defend__last_conflict_at` / `_arp_defend__last_emitted`, the two RX conflict-trigger branches; `_arp_dad_probe_address`, `_arp_dad_announce_address`, `_ip4_arp_dad__registry`, the IPv4 `try_signal_conflict` branches (arp__rx ~287/311/439/471), `_send_arp_probe`, `_send_arp_announcement`. **This is the step that fixes the double-defense.** Keep `_send_gratuitous_arp` only if still referenced (it is by `_handle_arp_conflict` → goes away with it; check `Ip4AddressApi.send_gratuitous_arp` first). Keep `DadSlotRegistry` (IPv6).
4. **4.5 — strip `Ip4AddressApi`.** Remove `probe` / `announce` / `claim_with_acd` / `send_gratuitous_arp` / `subscribe_conflicts` / `unsubscribe_conflicts` / `_fire_conflict_event` / `ProbeResult` / `ClaimResult` / `ConflictEvent` / `SubscriptionHandle` / `_OnConflict` / `_Subscriptions`. Keep `add_ifaddr` / `remove_ifaddr` (aborts bound sessions) / `replace_ifaddr` / `list_ip4_ifaddrs`. Check whether `abort_bound_tcp_sessions` has any remaining caller (link-local now relies on `remove_ifaddr`'s default abort; `_abandon_ipv4_address` inlines its own) — if none, remove it too. Result: the Address API is the pure `RTM_NEWADDR` / `ip addr` surface.

### 10.4 The blocker that makes this multi-commit: ACD real-timing vs patched-sleep tests

`Ip4Acd` runs **real** RFC 5227 timing (`time.monotonic` / `time.sleep` / `random.uniform`, ~5-9 s per probe). The DAD-adjacent integration tests were built around the **old patched-sleep** loop (`ArpTestCase._drive_dad` patches `link_local__client.time.sleep`, not `ip4_acd`'s). So the moment a path under test routes through `Ip4Acd`, the test runs real-time and **hangs** (confirmed: 4.4a made `test__arp__dad` time out). Every DAD-adjacent test must be reworked to (a) collapse the `arp.*` timers to ~0 via `patch.object(arp__constants, ...)` + `patch("...ip4_acd.random.uniform", return_value=0.0)`, and (b) inject conflicts onto the **ACD socket** (the RX tap `_phrx_ethernet` delivers ARP to it) rather than asserting on the `DadSlotRegistry`.

**Test-rework inventory (must accompany the code deletions):**
- `tests/integration/protocols/arp/test__arp__dad.py` — rewire to ACD timing/injection (the hang).
- `tests/integration/protocols/arp/test__arp__defend_interval.py` — §2.4 defense now lives in `Ip4Acd`/consumers, not the RX path.
- `tests/unit/runtime/packet_handler/test__runtime__packet_handler__arp__rx.py` — drop the conflict-branch assertions.
- `tests/unit/runtime/packet_handler/test__runtime__packet_handler__init.py` — `_create_stack_ip4_addressing` no longer calls `claim_with_acd`.
- `tests/unit/stack/test__stack__address.py` — drop the stripped-method tests.
- DHCP client tests — the BOUND-defense restructure (4.4b).
- RFC adherence: refresh `docs/rfc/arp/rfc5227__*/adherence.md` (and any RFC 3927 record) — ACD now lives in `Ip4Acd` + the per-consumer clients, the RX path no longer does conflict detection.

### 10.5 Sequencing constraint

`Ip4AddressApi.probe` (4.5 target) **calls** `handler._arp_dad_probe_address` (4.4c target), and `_create_stack_ip4_addressing` (4.4a) **calls** `claim_with_acd` (4.5 target). So the order is fixed: **4.4a → 4.4b → 4.4c → 4.5** (migrate every caller before deleting the callee). Each is a focused commit with its test rework + `make lint` + full-suite green + the §7.2 docstring audit.
