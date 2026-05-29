# Socket parity — M4 DSCP marking (scope)

**Authored:** 2026-05-29 on `PyTCP_3_0_6` (HEAD `f570a385`, after the
Track B sendmsg / SO_LINGER work). Scopes the last open item in the
socket Linux-parity audit: the **DSCP portion of M4
`IP_TOS` / `IPV6_TCLASS`**. The ECN portion shipped in `89da6654`;
this completes the byte.

## 0. Current state — what's already there

The TOS/Traffic-Class byte splits as `DSCP (high 6 bits) | ECN (low 2)`
(RFC 2474 §3). PyTCP already:

- **Stores the full byte.** `setsockopt(IP_TOS / IPV6_TCLASS, v)` saves
  all 8 bits in `_ip_tos` / `_ipv6_tclass` (`socket/__init__.py`);
  `getsockopt` returns it. Round-trip tests exist.
- **Threads only the ECN portion to the wire.** `_effective_ip_ecn()`
  returns the low 2 bits, passed as `ip__ecn` → `ip4__ecn` / `ip6__ecn`
  through the TX plumbing into the assemblers.
- **The wire layer is fully ready.** `Ip4Assembler` /
  `Ip6Assembler` already accept `ip4__dscp` / `ip6__dscp` (the
  headers carry a `dscp` field, packed at the right bit offset). They
  default `dscp=0`, which is why the high 6 bits are currently dropped.
- **Surfaces DSCP on RX.** `recvmsg` returns the full TOS/TClass byte
  as the `IP_TOS` / `IPV6_TCLASS` cmsg.

So the gap is **purely the TX plumbing + a socket accessor** — no
net_proto change. The work is a parallel `ip__dscp` kwarg flow
mirroring the existing `ip__ecn` flow, plus an `_effective_ip_dscp()`
accessor, wired from the UDP / TCP / RAW send paths.

### 0.1 Finding — fragmentation currently drops BOTH DSCP and ECN

While tracing the plumbing, the fragmentation paths were found to drop
the DSCP **and** the already-shipped ECN:

- **IPv4** (`packet_handler__ip4__tx.py:267`): `Ip4FragAssembler(...)`
  is built without `ip4_frag__dscp` **or** `ip4_frag__ecn`, so both
  default to 0 on every fragment even when the unfragmented header
  carried them.
- **IPv6** (`packet_handler__ip6_frag__tx.py:162`): the per-fragment
  re-entry `self._if._phtx_ip6(ip6__src=…, ip6__dst=…,
  ip6__payload=ip6_frag_tx)` passes neither `ip6__dscp` nor
  `ip6__ecn`, so the outer IPv6 header on each fragment is zeroed.

Both assemblers / handlers expose the source value
(`ip4_packet_tx.dscp` / `.ecn`, `ip6_packet_tx.dscp` / `.ecn`), so the
fix is a one-line propagation at each site. This is a latent ECN
correctness bug independent of DSCP; the DSCP work fixes both at the
same lines. **Phase B below isolates it so the ECN-preservation fix is
bisectable.**

## 1. Linux grounding

- Linux applies the `IP_TOS` / `IPV6_TCLASS` **DSCP** bits to every
  socket-originated packet — UDP, TCP, and raw
  (`net/ipv4/ip_sockglue.c` `IP_TOS`; `ip_queue_xmit` / `udp_sendmsg`
  copy `inet->tos` into the IPv4 header; `net/ipv6/...` for TClass).
- The **ECN** low-2-bits: for UDP / RAW the socket value is used as-is;
  for TCP the stack overrides them with RFC 3168 ECT/CE per the ECN
  state machine (PyTCP already does exactly this — TCP `ip__ecn` is
  `2 if ecn.enabled and data and not retransmit else 0`,
  `tcp__session__tx.py:245`, **not** from the socket option). DSCP is
  orthogonal and applies to TCP too.
- Fragments inherit the original datagram's DSCP/ECN (the per-fragment
  IP header is a copy of the original's TOS/TClass byte). This is what
  §0.1 fixes.

Conformance precedence: RFC 2474 §3 (DS field layout) is unambiguous —
DSCP is the high 6 bits, marked on transmit per the socket option.
Linux is the tiebreaker for the "applies to all socket-originated
traffic, ECN-bits-overridden-for-TCP" behaviour.

## 2. Edit surface

### 2.1 net_proto
None. `Ip4Assembler` / `Ip6Assembler` / `Ip4FragAssembler` already take
the `*__dscp` kwarg; the headers pack it.

### 2.2 Socket layer (`packages/pytcp/pytcp/socket/`)
- **`__init__.py`** — add `_effective_ip_dscp()` mirroring
  `_effective_ip_ecn()`: high 6 bits of the family's TOS/TClass —
  `(self._ipv6_tclass >> 2) & 0x3F` for INET6 else
  `(self._ip_tos >> 2) & 0x3F`.
- **`udp__socket.py`** — `send` (`:472`) and `sendto` (`:544`): add
  `ip__dscp=self._effective_ip_dscp()` alongside the existing
  `ip__ecn=`.
- **`raw__socket.py`** — `send` (IPv6 `:267` / IPv4 `:276`) and
  `sendto` (IPv6 `:315` / IPv4 `:324`): add
  `ip6__dscp=` / `ip4__dscp=self._effective_ip_dscp()`.
- **TCP** — add `ip__dscp=session._socket._effective_ip_dscp()` at the
  three `send_tcp_packet` call sites that carry socket traffic:
  `session/tcp__session__tx.py:246` (data/ACK),
  `session/tcp__session.py:1412`, `fsm/tcp__fsm__syn_sent.py:207`
  (active-open SYN). Verify no fourth socket-originated site; the
  stack-generated RST path in `packet_handler__tcp__rx.py` stays
  `dscp=0` (no socket).

### 2.3 Runtime TX plumbing — thread `ip__dscp` (default 0)
Each protocol has **two hops**: the composition facade in
`runtime/packet_handler/__init__.py` (delegator) and the per-protocol
sub-handler in `packet_handler__<proto>__tx.py`. Add an `ip__dscp` /
`ip4__dscp` / `ip6__dscp` parameter (default 0) at each, mirroring the
existing `ip__ecn` exactly:

| Protocol | Facade (`__init__.py`) | Sub-handler |
|---|---|---|
| UDP | `_phtx_udp`, `send_udp_packet` | `packet_handler__udp__tx.py` `_phtx_udp` (map `ip__dscp`→`ip4__dscp`/`ip6__dscp`), `send_udp_packet` |
| TCP | `_phtx_tcp`, `send_tcp_packet` | `packet_handler__tcp__tx.py` `_phtx_tcp`, `send_tcp_packet` |
| IPv4 | `_phtx_ip4`, `send_ip4_packet` | `packet_handler__ip4__tx.py` `_phtx_ip4` (→ `Ip4Assembler(ip4__dscp=)`), `send_ip4_packet` |
| IPv6 | `_phtx_ip6`, `send_ip6_packet` | `packet_handler__ip6__tx.py` `_phtx_ip6` (→ `Ip6Assembler(ip6__dscp=)`), `send_ip6_packet` |

Default 0 everywhere → all stack-generated traffic (ICMP, ND, DHCP,
ARP has no IP layer) is byte-for-byte unchanged.

### 2.4 Fragmentation (the §0.1 fix)
- `packet_handler__ip4__tx.py:267` — add
  `ip4_frag__dscp=ip4_packet_tx.dscp, ip4_frag__ecn=ip4_packet_tx.ecn`.
- `packet_handler__ip6_frag__tx.py:162` — add
  `ip6__dscp=ip6_packet_tx.dscp, ip6__ecn=ip6_packet_tx.ecn` to the
  per-fragment `_phtx_ip6` re-entry.

## 3. Tests (tests-first)

### Unit
- `test__socket__*` (the `socket/__init__.py` accessor): `_effective_
  ip_dscp()` extracts the high 6 bits for INET4 (`_ip_tos`) and INET6
  (`_ipv6_tclass`); ECN bits don't leak into the DSCP value. (The
  setsockopt/getsockopt full-byte round-trip is already covered.)

### Integration (mandatory — wire-format change, per
`feature_implementation.md` §2.1)
- **UDP** v4 + v6: `setsockopt(IP_TOS / IPV6_TCLASS, dscp<<2 | ecn)`,
  `sendto` → parse the TX frame, assert the outbound header's `dscp`
  == set value and `ecn` == set value. (Extend
  `test__udp__socket_api.py` or a new `test__udp__ip_dscp.py`.)
- **TCP** v4 + v6: `setsockopt(IP_TOS, dscp<<2)`, drive handshake,
  assert the SYN and a data segment carry `dscp` on the IP header
  (ECN stays RFC-3168-driven, not the socket value). New
  `test__tcp__session__ip_dscp.py`.
- **RAW** v4 + v6: dscp appears on the emitted IP header.
- **Fragmentation preserves DSCP + ECN** (pins §0.1): send an
  oversized UDP datagram (or raw packet) with a non-zero DSCP and ECN
  set, assert **every** emitted fragment carries both. One v4 and one
  v6 case.

## 4. Conformance bookkeeping (same-commit)
- Flip the **M4 DSCP** row in `socket_linux_parity_audit.md` §100 (and
  the Phase-2 M4 row) from `partial` to shipped.
- Update `socket_parity_followup.md` — DSCP was the last actionable
  socket item; note the track closed.
- RFC adherence: the IPv4 / IPv6 records' TOS / Traffic-Class field
  sections (`docs/rfc/ip4/...`, `docs/rfc/ip6/...`) and any RFC 2474 /
  RFC 3168 DS-field note — verify whether a record exists and add the
  "DSCP marked from the socket IP_TOS / IPV6_TCLASS option" line +
  test references. (No RFC 2474 record exists in `docs/rfc/` today;
  the DS-field layout is documented in the ip4/ip6 header records.)

## 5. Commit plan
- **Phase A — DSCP marking.** Socket `_effective_ip_dscp()` +
  `ip__dscp` plumbing through UDP / TCP / RAW + the TX handler chain;
  unit + non-fragmented integration tests; ledger flip. One coherent
  unit.
- **Phase B — fragmentation DSCP/ECN preservation.** The two §0.1
  one-line fixes + the frag-preserves-DSCP/ECN integration tests.
  Isolated so the latent ECN-drop fix is bisectable and its own test
  pins it.

Both: `make lint` + full `make test` + §7.2 docstring audit clean
before each commit; commit trailer
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`;
push only on explicit request.

## 6. Effort / risk
- **Effort:** ~½–1 day. The plumbing is mechanical (mirror `ip__ecn`);
  the integration tests are the bulk.
- **Risk:** low. Additive kwarg with `0` defaults → no behavioural
  change for any non-socket or DSCP-unset path. The one genuine
  behavioural change is the fragmentation fix (Phase B), which is a
  strict correctness improvement (fragments stop zeroing DSCP/ECN),
  isolated and test-pinned.

## 7. Out of scope
- Per-send DSCP via `sendmsg` ancillary data (`IP_TOS` cmsg on send) —
  that is the `# Phase 2:` per-send-cmsg follow-up already marked in
  `udp__socket.py` / `tcp__socket.py`; this work is the per-socket
  `setsockopt` DSCP only.
- Changing TCP's ECN behaviour — RFC 3168 ECT/CE marking stays
  stack-driven; only DSCP is added for TCP.
- DSCP-based egress queueing / policy (no qdisc in PyTCP).
