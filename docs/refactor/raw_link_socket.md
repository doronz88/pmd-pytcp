# Raw Link Socket (`AF_PACKET`) Plan

| Field  | Value |
|--------|-------|
| Status | **Planned** — not started. Created 2026-05-23. |
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
