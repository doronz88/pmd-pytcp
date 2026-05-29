# Socket parity — follow-up plan

**Authored:** 2026-05-29 on `PyTCP_3_0_6` (HEAD `5311a1b1`).
Successor pointer to `docs/refactor/socket_linux_parity_audit.md`
after the 2026-05-28..29 sweep closed the bounded items. This
doc tracks the **substantial refactor scope** and the
**deferred-with-rationale tail** so a fresh session can
pick the next track without re-discovering state.

---

## 1. What's done (post 2026-05-29 sweep)

Bounded items shipped this sweep (commit hashes on
`PyTCP_3_0_6`):

| Gap | Commit | Summary |
|-----|--------|---------|
| M5 TCP_INFO | `20c01eb6` | 240-byte Linux 5.5 struct layout packed from `TcpSession`; `getsockopt(IPPROTO_TCP, TCP_INFO)` returns bytes. |
| M6 TCP_USER_TIMEOUT + M7 TCP_MAXSEG | `9829332d` | Per-session R2-budget override + SYN MSS-option clamp; both propagated via `connect()` / `listen()`. |
| H3 IPV6_V6ONLY (Phases 1-3c) | `6edab2be` / `72479a5f` / `3389d546` / `abe5281d` / `91319a3d` | Full dual-stack: `Ip6Address` mapped helpers, setsockopt storage, bind cross-family conflict, RX listener-table extension, accept presentation surfacing. |
| H6 TCP IP_TTL / IPV6_UNICAST_HOPS | `15349458` | `TcpSession._transmit_packet` reads `_effective_ip_ttl()`; threaded through `send_tcp_packet` → `_phtx_tcp` → `_phtx_ip4`/`_phtx_ip6`. |
| H4 IPv6 IPV6_JOIN_GROUP | `b4ddb185` | `IPV6_JOIN_GROUP=20` / `IPV6_LEAVE_GROUP=21`; per-socket membership tracking; existing `_assign_ip6_multicast` auto-emits MLDv2 Report. |
| M3 MSG_OOB / SO_OOBINLINE | `d75d5d90` | Linux constants exposed; SO_OOBINLINE guard documents the RFC 6093 §6 universal-inline design. Doc-realignment commit, not a feature gap. |
| H5 SO_BROADCAST EACCES gate | `5311a1b1` | UDP `send`/`sendto` to `255.255.255.255` requires SO_BROADCAST=1; DHCPv4 client `_open_client_socket` now sets the flag. |
| H2 SO_REUSEPORT | `af536889` / `c41aa96b` / `c76fa4f5` / `fe619b78` | 4-phase track (2026-05-29). `SocketTable` cohort storage + transparent round-robin `get`; SolSocketOption optname 15 setsockopt/getsockopt; `is_address_in_use` group-rule gate; TCP/UDP cohort RX-demux integration pins. Round-robin demux (Phase-1 simplification of Linux's 4-tuple hash; retransmit-safe). See §2.1. |
| M2 sendmsg / recvmsg | `7527caa3` (sendmsg) + earlier IP_RECVERR work (recvmsg) | `recvmsg` (+ MSG_ERRQUEUE cmsg) landed with the error-queue work; `sendmsg` shipped 2026-05-29 across base stub + UDP / TCP / RAW (+ `RawSocket.recvmsg`). Scatter-gather concatenation reusing send/sendto; `ancdata` validated-then-ignored Phase-1; TCP rejects an address with EISCONN. See §2.2. |
| M8 MSG_ERRQUEUE / IP_RECVERR | earlier IP_RECVERR work | Per-socket error queue + `recvmsg(MSG_ERRQUEUE)` → IP_RECVERR / IPV6_RECVERR cmsg. See §2.2. |
| H8 SO_LINGER | (this commit) | `SO_LINGER=13` + struct-linger setsockopt/getsockopt; `TcpSocket.close` 3-way branch (graceful FIN / lingering wait on `TcpSession._event__closed` / zero-linger abortive RST). UDP/RAW store as no-op. See §2.2. |

11960+ tests passing.

---

## 2. Substantial refactors — genuinely actionable

Each below is multi-day work and a deliberate scope-expansion
decision past v3.0.6 host-stack closure. Pick one when you want
to push the parity surface further.

### 2.1 H2 SO_REUSEPORT — SHIPPED 2026-05-29

**Status.** Done across four commits (`af536889`, `c41aa96b`,
`c76fa4f5`, `fe619b78`). The on-the-ground surgery was smaller
than the estimate below: `SocketTable` already existed as a
lock-guarded wrapper, so the risky "introduce a wrapper behind
the dict API" migration was already done and the ~30 mocked-dict
test fixtures needed zero churn (the dict-compat shims were
preserved). Storage became `dict[SocketId, list[socket]]` (a
cohort per id), `get` round-robins multi-member cohorts
transparently (so the RX handlers were unchanged), and
`is_address_in_use` enforces Linux's all-or-nothing group rule.
The plan-as-written below is retained for historical context.

**Goal.** Allow multiple sockets to bind the same `(local_ip,
local_port)` 4-tuple with `setsockopt(SO_REUSEPORT, 1)` and
demux inbound connections across the cohort (Linux's classic
multi-worker server pattern).

**Surgery surface.**
1. `stack.sockets: dict[SocketId, socket]` — refactor to
   multi-listener-aware structure. Two viable shapes:
   - `dict[SocketId, list[socket]]` (list per key; demux via
     round-robin or hash). Smaller diff but every reader needs
     to be updated.
   - Wrapper class `SocketTable` exposing `get(key)` /
     `iter_listeners(key)` / `add(socket)` / `remove(socket)`
     with internal multi-listener semantics. Cleaner API,
     bigger initial diff.
2. `is_address_in_use` — gate the cross-cohort conflict on the
   binding socket's `_so_reuseport` flag (same shape as the H3
   Phase 3a `dual_stack` parameter).
3. Inbound demux — TCP RX (`packet_handler__tcp__rx.py` listener-
   match loop) and UDP RX both need to select one listener from
   the cohort. Linux uses a 4-tuple hash. PyTCP can start with
   round-robin (simplest) and document the choice; the
   eBPF-driven custom-hash surface is out of scope.
4. `accept()` semantics — each cohort listener has its own
   accept queue (Linux behaviour). The connection lands on the
   listener that won the demux at SYN time.

**Risk.** The refactor touches every reader of `stack.sockets`.
The biggest landmines are the test fixtures that mock the dict
directly — there are dozens. Plan: introduce the new structure
behind the existing dict API first, migrate callers in batches,
then flip the storage shape.

**Tests-first.**
- Two AF_INET TCP sockets bind same port with REUSEPORT → both
  succeed.
- Without REUSEPORT, second bind raises EADDRINUSE.
- Inbound SYN dispatches to one listener; the other is
  untouched.
- 4-way cohort accepts 4 connections, each landing on a
  different listener (round-robin pin).
- UDP version of the same scenarios.

**Effort estimate.** 2-3 days for the storage refactor + tests;
the migration sweep is mechanical but slow.

### 2.2 H8 + M2 + M8 bundle — control-message layer — SHIPPED 2026-05-29

> **DONE 2026-05-29 — the whole bundle is shipped.** A code survey
> found `recvmsg` (M2 recv-side) and `MSG_ERRQUEUE` → `IP_RECVERR`
> cmsg (M8) were already implemented on `UdpSocket` / `TcpSocket`
> with tests, and the cmsg form is already the stdlib
> `list[(level, type, data)]` tuple (no byte-level CMSG codec
> needed). The remaining work — `sendmsg` (send-side of M2) + the
> base/Raw msg-surface, and `SO_LINGER` (H8) — shipped in two
> commits: `7527caa3` (sendmsg + recvmsg/sendmsg surface across
> base/UDP/TCP/RAW) and the SO_LINGER commit (option plumbing +
> `TcpSocket.close` 3-way branch + `TcpSession._event__closed`). The
> detailed plan is `docs/refactor/socket_sendmsg_so_linger.md`. The
> prose below is the original (stale) framing, retained for context.

H8 (SO_LINGER), M2 (sendmsg/recvmsg), M8 (MSG_ERRQUEUE) are
coupled because all three require an extended setsockopt /
recv signature shape that PyTCP doesn't have today. Ship as one
focused work block.

**Goal.** Expose Linux's `sendmsg(2)` / `recvmsg(2)` surface with
control-message (cmsg) support, layer the existing
per-socket error queue under `recvmsg(MSG_ERRQUEUE)`, and
unlock SO_LINGER via the bytes-encoded setsockopt path the
cmsg API already needs.

**Surgery surface.**
1. **cmsg encoder/decoder** — new module
   `packages/pytcp/pytcp/socket/cmsg.py` with:
   - `pack_cmsg(level, type_, data) -> bytes` (Linux
     `CMSG_DATA` / `CMSG_FIRSTHDR` shape).
   - `iter_cmsg(buffer) -> Iterator[tuple[int, int, bytes]]`
     for the recv path.
   - Type registry for the supported cmsg types: IP_RECVERR /
     IPV6_RECVERR (M8), IP_TOS / IPV6_TCLASS (M4 cmsg side —
     bonus, since DSCP already stored).
2. **`sendmsg(buffers, ancdata, flags, address)` /
   `recvmsg(bufsize, ancbufsize, flags)` methods** on socket
   base + per-flavour overrides on TcpSocket / UdpSocket /
   RawSocket. Signatures match stdlib `socket.sendmsg` /
   `recvmsg` for drop-in compat.
3. **MSG_ERRQUEUE wiring** — `recvmsg(MSG_ERRQUEUE)` pops from
   the existing `_error_queue` (already in tree from the
   IP_RECVERR work) and packs each entry as a cmsg
   `(level=IPPROTO_IP, type=IP_RECVERR, data=sock_extended_err
   + offending IP header)`. The `pack_sock_extended_err` helper
   already exists in `pytcp/socket/error_queue.py`.
4. **SO_LINGER setsockopt** — extend `_sol_socket_setsockopt`
   to accept `bytes` for SO_LINGER (`struct linger { int
   l_onoff; int l_linger; }`). The `setsockopt(level, optname,
   value: int | bytes)` signature already accepts bytes since
   the H4 IGMP work; this just adds the SO_LINGER case + close-
   path drain behaviour.

**Risk.** `sendmsg` / `recvmsg` are new methods, so the risk is
mostly in scope creep — every Linux cmsg type is a temptation.
Discipline: ship MSG_ERRQUEUE + the IP_RECVERR cmsg first;
defer IP_PKTINFO / IP_TOS-cmsg-side / IPV6_PKTINFO to a
follow-up.

**Tests-first.**
- `sendmsg(buffers, [])` round-trips bytes (no cmsg) on UDP +
  TCP.
- `recvmsg(bufsize, ancbufsize)` returns `(data, ancdata, flags,
  address)` shape matching stdlib.
- `recvmsg(MSG_ERRQUEUE)` after an inbound ICMP returns the
  IP_RECVERR cmsg with the canonical Linux byte layout.
- SO_LINGER `setsockopt(SOL_SOCKET, SO_LINGER, struct.pack("ii",
  1, 30))` round-trips via getsockopt.
- `close()` on a SO_LINGER socket blocks until either the FIN
  ACKs or the linger timeout elapses.

**Effort estimate.** 3-4 days for the full bundle; the cmsg
codec is the longest pole.

---

## 3. Forever-deferred-with-rationale

These rows are documented as won't-ship in the audit doc; not
worth re-opening unless North Star changes.

| Gap | Rationale |
|-----|-----------|
| L1 dup() / dup2() | PyTCP's per-socket eventfd + python-level rx queue + accept queue don't fit BSD `dup` (which shares the same kernel file table entry). The semantic mismatch is fundamental, not a "we just need to implement it" gap. |
| L2 socketpair() | Mostly Unix-domain; CLAUDE.md North Star explicitly out-of-scope. |
| L3 hostname in bind/connect | Apps should call `getaddrinfo` (C4 re-export already in tree) and pass a numeric IP. Auto-resolve in bind/connect is SHOULD-not-MUST per POSIX; no real consumer. |
| DHCPv4 Phase 9 (RFC 4702 / 3203 / 8910) | Each blocked on a consumer PyTCP doesn't have (DDNS / DHCP-Auth / HTTP-UA). See `docs/refactor/dhcp4_client_full_parity.md`. |

---

## 4. Hygiene punts

| Gap | Note |
|-----|------|
| X3 listen() implicit bind tightening | `listen()` on an unbound socket should return EINVAL per POSIX; PyTCP picks an ephemeral port instead. Tightening would break `examples/` apps that don't bind first. Land as a `breaking-change` commit only if other Phase-3 boundary work touches the area. |

---

## 5. Cross-references

- `docs/refactor/socket_linux_parity_audit.md` — the canonical
  audit; §100 status table is up-to-date through 2026-05-29.
- `docs/rfc/tcp/rfc6093__urgent_mechanism/adherence.md` — the
  RFC 6093 §6 universal-inline design that M3 reconciled.
- `docs/refactor/no_gil_thread_safety_audit.md` — X1 closure;
  any new socket-side cross-thread state in the H2 / cmsg work
  needs a lock-per-structure or COW pattern per the standing
  invariant.

---

## 6. Resume prompt (paste verbatim in a fresh session)

```
Read docs/refactor/socket_parity_followup.md end to end — it's the
follow-up plan for the remaining socket-layer Linux parity work on
PyTCP_3_0_6 at HEAD 5311a1b1. Then read CLAUDE.md (Project North Star)
and the relevant rule files in .claude/rules/ (feature_implementation.md,
pytcp.md, sysctl_knob skill if applicable).

Context: the 2026-05-28..29 sweep closed every bounded item in
docs/refactor/socket_linux_parity_audit.md — M5 TCP_INFO,
M6 TCP_USER_TIMEOUT, M7 TCP_MAXSEG, H3 IPV6_V6ONLY (5-phase track),
H4 IPv6 IPV6_JOIN_GROUP, H6 TCP IP_TTL propagation, M3 doc-
realignment + SO_OOBINLINE guard, H5 SO_BROADCAST EACCES gate.
11927 tests passing. Audit doc §100 status table is up-to-date.

What remains is two substantial multi-day refactors (§2 of the
followup plan):

  A) H2 SO_REUSEPORT — stack.sockets refactor from dict[SocketId,
     socket] to multi-listener-aware structure + inbound demux
     across the REUSEPORT cohort. ~2-3 days.

  B) H8 + M2 + M8 bundle — control-message (cmsg) decoder/encoder
     layer + sendmsg/recvmsg methods + MSG_ERRQUEUE wiring + the
     SO_LINGER bytes-encoded setsockopt path that the cmsg API
     unlocks. ~3-4 days.

Plus deferred-with-rationale (§3) and one hygiene punt (§4) —
neither is worth opening as standalone work.

Follow the standing discipline: tests-first (a failing test that
pins the requirement before any fix), one logical unit per commit,
make lint + full make test + the §7.2 docstring audit clean before
each commit, modernise legacy typing/Python forms on touch, RFC-
ground every behavioural claim, commit trailer "Co-Authored-By:
Claude Opus 4.7 (1M context) <noreply@anthropic.com>", push only
when I explicitly say so. Refresh socket_linux_parity_audit.md in
the same commit as the code when a row's status changes.

I want to start: <pick A (H2 SO_REUSEPORT), B (H8/M2/M8 bundle),
or state a different task>.
```
