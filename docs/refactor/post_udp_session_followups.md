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

### 1. TCP-side IP_RECVERR / MSG_ERRQUEUE — SHIPPED 2026-05-14

The TCP socket-API error-queue surface landed:

- `TcpSocket._error_queue` / `_error_queue_ready` /
  `notify_unreachable` / `notify_time_exceeded` /
  `notify_parameter_problem` / `notify_pmtu` / `recvmsg`
  / `_recvmsg_errqueue` mirror the UDP shape, sharing
  the `build_icmp_error_entry` helper extracted to
  `pytcp/socket/error_queue.py`.
- ICMPv4 / ICMPv6 demux TCP dispatchers
  (`packet_handler__icmp{4,6}__rx.py`) now call
  `socket.notify_*` alongside the existing
  `session.tcp_fsm(IcmpMetadata(...))` event, with
  enum-typed `icmp_type` / `icmp_code` (Icmp4Type /
  Icmp6Type / Icmp{4,6}DestinationUnreachableCode /
  Icmp{4,6}TimeExceededCode / Icmp{4,6}ParameterProblemCode)
  + `SoEeOrigin.ICMP{,6}` + offender + embedded.
- 13 new integration tests in
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__ip_recverr.py`
  cover get/set round-trip, ICMPv4 dest-unreachable /
  frag-needed / time-exceeded / parameter-problem,
  ICMPv6 dest-unreachable / packet-too-big, gating,
  FIFO bound, FSM-independence.
- RFC 1122 §4.2.3.9 adherence record refreshed to
  reflect the new full-propagation surface.

10700 tests passing, 4 skipped. `make lint` clean.

### 2. UDP #6 — `UDP_NO_CHECK6_RX/TX` per-port opt-in — SHIPPED 2026-05-14

The RFC 6935 §5 alternative-mode per-port opt-in
landed despite the original "defer until consumer"
recommendation:

- `pytcp/socket/__init__.py`: `SOL_UDP=17`,
  `UdpOption(IntEnum)` with `UDP_NO_CHECK6_TX=101` /
  `UDP_NO_CHECK6_RX=102` + bare aliases (Linux
  numbering for stdlib parity).
- `UdpSocket._udp_no_check6_tx` / `_udp_no_check6_rx`
  flags + `_sol_udp_setsockopt` / `_sol_udp_getsockopt`
  dispatchers.
- `UdpAssembler(udp__no_cksum=False)` kwarg makes
  `assemble()` and `Udp.__buffer__` emit literal
  `0x0000` (bypassing the RFC 768 zero-to-all-ones
  substitution).
- `_phtx_udp(udp__no_cksum=...)` and
  `send_udp_packet(udp__no_cksum=...)` thread the flag
  from socket through to assembler.
- `UdpParser(accept_zero_cksum_ip6=False)` kwarg
  bypasses the `UdpZeroCksumIp6Error` raise on retry.
- `PacketHandlerUdpRx.__phrx_udp__retry_zero_cksum_ip6`
  peeks the raw dport (bytes 2-3 of the UDP header,
  parser raised pre-`_parse`), enumerates matching
  socket IDs via `UdpMetadata.socket_ids`, and retries
  the parse with the bypass when an opted-in socket
  is found.
- 6 new integration tests in
  `pytcp/tests/integration/protocols/udp/test__udp__no_check6.py`
  cover: get/set round-trip for TX and RX; TX opt-in
  emits cksum=0x0000 literal; TX default emits
  computed non-zero cksum; RX opt-in delivers cksum=0
  IPv6 to socket; RX default drops + counter bump.
- RFC 6935 / 6936 adherence record refreshed: §5
  per-port opt-in flipped from "partial / not
  implemented" to "met"; RFC 6936 §4 constraints
  3/4/6/7 all flipped from "not implemented" to "met".

10706 tests passing, 4 skipped. `make lint` clean.

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
