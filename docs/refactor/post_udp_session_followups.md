# Post-UDP Session Follow-ups

Snapshot of open work as of 2026-05-14, after the UDP
punch-list close-out. Pushed on
`origin/PyTCP_3_0__pre_release` through commit `d4c9da33`.

## What this session shipped

| Commit | Topic |
|---|---|
| `b804f565` | IP4 RX directed-broadcast martian filter (UDP punch #2) |
| `3d56eed9` | UDP IP options pass-through via setsockopt + recvmsg (UDP punch #1) |
| `ec411f65` | UDP IP_RECVTOS / IPV6_RECVTCLASS recvmsg cmsg (UDP punch #5) |
| `83cf7214` | UdpTestCase harness + end-to-end socket-API integration tests |
| `c554ec50` | UDP IP_MTU / IPV6_MTU getsockopt (UDP punch #3) |
| `7a737d63` | UDP IP_RECVERR / MSG_ERRQUEUE socket-API (UDP punch #4) |
| `2dd484c6` | Enum-discipline rule + first wave of bare-int conversions |
| `0f405f04` | `IFF_TUN/TAP/NO_PI` → `TunTapFlag(IntFlag)` |
| `d4c9da33` | `Ip4TestCase` + `Ip6TestCase` harnesses + migration of 5 tests |

UDP §4.1.5 requirements-summary table: every MUST + the
TOS-passthrough MAY now met. Audit doc at
`docs/rfc/udp/rfc1122__host_requirements_udp/adherence.md`
reads "Principal gap: none."

10691 tests passing, 4 skipped. `make lint` clean.

## Direct follow-on items

### 1. TCP-side IP_RECVERR / MSG_ERRQUEUE

**Source:** flagged in commit `7a737d63` body. The UDP-side
error queue + cmsg infrastructure landed; TCP needs the
parallel surface. TCP's `notify_*` callbacks already exist
and dispatch to the FSM, but there's no equivalent
'recvmsg(MSG_ERRQUEUE)' surface on `TcpSocket`.

**Scope:**
- Extend `TcpSocket` with the same `_error_queue` /
  `_ip_recverr` / `_ipv6_recverr` flags / `recvmsg(MSG_ERRQUEUE)`
  method that `UdpSocket` has.
- Update the ICMP demux callers in
  `packet_handler__icmp{4,6}__rx.py` for the TCP branch
  (currently `int(message.code)` for TCP — replace with
  enum, pass through `icmp_origin` / `embedded_datagram` /
  `offender_ip` like the UDP path).
- The error-queue plumbing (`pytcp.socket.error_queue`
  module — `ErrorQueueEntry`, `SoEeOrigin`, `icmp4_to_errno`
  / `icmp6_to_errno`, `pack_sock_extended_err`) is shared
  and ready to consume.
- Decide: does TCP's recvmsg(MSG_ERRQUEUE) behavior need
  to interact with FSM state? Linux's TCP IP_RECVERR
  queues per-socket regardless of FSM — the application
  gets the error context independent of whether the
  session has been reset/closed yet.

**Effort:** ~half-day (smaller than the UDP version
because the error_queue module exists).

### 2. UDP #6 — `UDP_NO_CHECK6_RX/TX` per-port opt-in

**Status:** deferred — no PyTCP consumer needs the
RFC 6935 zero-cksum-IPv6 alternative mode (no tunnel
protocol). Resume when a real consumer needs it.

**Source:** `docs/refactor/udp_remaining_items.md` #6.

### 3. UDP #7 — PLPMTUD for UDP (RFC 8899)

**Status:** deferred. Own audit + design track. RFC 8899
is substantial — would need
`docs/rfc/udp/rfc8899__plpmtud/adherence.md` first.

**Source:** `docs/refactor/udp_remaining_items.md` #7.

### 4. On-touch enum migrations

The enum-discipline rule (`.claude/rules/enums.md` §5)
mandates that bare-int-as-enum patterns be fixed on
touch. The first wave (~36 constants) is shipped; legacy
code may still contain candidates the survey missed.
When touching files in `pytcp/`, `net_proto/`, or
`net_addr/`, check for the `FOO: int = N` pattern.

## Broader project tracks (not introduced this session)

These are existing tracks visible from project memory —
listed here for completeness but not opened during this
session:

| Track | Doc | Status |
|---|---|---|
| Socket Linux parity audit | `docs/refactor/socket_linux_parity_audit.md` | 26 originally-flagged deficiencies; UDP work this session closed ~half |
| RFC 6724 source selection for ND | `docs/refactor/rfc6724_source_selection.md` | §12c/§18d remaining (last ND gap) |
| IPv4 audit punch list | `docs/refactor/ip4_audit_punchlist.md` | Post-2026-05-11 inventory; RFC 3927 autoconfig, sysctl knobs, IPv6 audit parity |
| Phase 2 (router-grade parity) | `CLAUDE.md` north star | Future |
| Phase 3 (kernel/userspace boundary) | `CLAUDE.md` north star | Future |
| Link API | `docs/refactor/link_api.md` | Shipped 2026-05-12; `up`/`down` deferred to Phase 2 |

## Per-protocol harness inventory (full as of this session)

```
NetworkTestCase
├── IcmpTestCase           — FakeTimer + ICMP probes + rate-limiter snapshots
│   └── NdTestCase         — ND IS an ICMPv6 family
├── ArpTestCase            — ARP DAD + monotonic-clock patching
├── TcpSessionTestCase     — TCP segment factory + FSM-aware assertions
├── UdpTestCase            — UDP socket + recvmsg helpers (new)
├── Ip4TestCase            — IPv4 frame builders + Ip4Probe (new)
└── Ip6TestCase            — IPv6 frame builders + Ip6Probe (new)
```

When adding a new socket-touching harness later (e.g. a
`RawTestCase` if Raw sockets grow integration coverage),
consider extracting `_SocketsAwareNetworkTestCase` —
`IcmpTestCase`, `TcpSessionTestCase`, and `UdpTestCase`
all redundantly snapshot `stack.sockets`. Marked with
greppable `Phase 3: extract _SocketsAware base when the
fourth socket-touching harness lands.` comment in
`UdpTestCase`.

## Suggested next step

**Item 1 (TCP IP_RECVERR)** is the most natural pickup —
inherits the UDP-side infrastructure, smallest scope,
closes a real follow-up flagged in the UDP commit
message.

The deferred items (#6, #7) and the broader project
tracks are independent — pick based on priority.
