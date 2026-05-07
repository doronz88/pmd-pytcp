# Refactor #4 — Generalise ICMP error demux + per-destination MTU cache + PMTUD

Authored 2026-05-06 after the state/ + fsm/ subpackage reorg
landed (commits `45aea7c0`..`c5ac6c78`). This plan is the
canonical implementation guide for the only remaining structural
refactor on the roadmap, and the gateway to the four pending
PMTUD RFCs (1191, 8201, 4821, 8899).

The scope here was corrected from the original
`docs/refactor/tcp_codebase_improvement_plan.md` Concern #5 in
commit `5d8f8daa`. **This is NOT an "ICMP→TCP" refactor** — the
codebase already has working ICMP→UDP demux for Destination-
Unreachable. What's missing is enumerated explicitly below.

---

## 1. Current state inventory

### 1.1 What works today

| ICMP error path                                  | UDP                             | TCP             |
|--------------------------------------------------|---------------------------------|-----------------|
| ICMPv4 Type 3 (Dest-Unreachable, all codes)      | **Wired** (`notify_unreachable`) | Missing         |
| ICMPv4 Type 3 Code 4 (Frag-Needed) — PMTUD       | Missing (`# TODO` line 152)     | Missing         |
| ICMPv6 Type 1 (Dest-Unreachable)                 | **Wired** (`notify_unreachable`) | Missing (TODO line 185-187) |
| ICMPv6 Type 2 (Packet-Too-Big) — PMTUD           | Missing                         | Missing         |
| ICMPv4 Type 11 / ICMPv6 Type 3 (Time Exceeded)   | Not wired (log only)            | Not wired       |

The UDP Dest-Unreachable demux paths in
`pytcp/stack/packet_handler/packet_handler__icmp4__rx.py`
(`__phrx_icmp4__destination_unreachable`, lines 147-203) and
`packet_handler__icmp6__rx.py` (`__phrx_icmp6__destination_unreachable`,
lines 142-198) parse the embedded IP+UDP header out of the ICMP
error payload, build a `UdpMetadata`, look up the matching socket,
and call `socket.notify_unreachable()`.

### 1.2 What this plan delivers

0. **ICMP integration-test harness** mirroring `TcpSessionTestCase`
   so this refactor and the future ICMP protocol refactor have a
   fluent, low-friction integration-test surface instead of the
   coarse parametrized golden-bytes matrix.
1. **Shared embedded-header parser** so the same parsing code drives
   all four error handlers (v4/v6 × Dest-Unreachable / Frag-Needed
   / Packet-Too-Big).
2. **TCP demux** for Dest-Unreachable on both v4 and v6.
3. **PMTUD demux** (Frag-Needed for v4, Packet-Too-Big for v6) for
   both UDP and TCP.
4. **Per-destination MTU cache** at the IP/stack layer (NOT on
   `TcpStack` — UDP consults it too).
5. **DF=1 on outbound IPv4** for both TCP and UDP.
6. **TCP MSS recompute** on per-destination MTU update.
7. **RFC 5927 hardening** (TCP only): validate the embedded TCP
   sequence falls in `SND.UNA..SND.NXT` before acting on an
   ICMP error, so an attacker can't forge ICMP errors for
   arbitrary 4-tuples.

### 1.3 What this plan does NOT deliver

- Full RFC 4821 / 8899 PLPMTUD probing (requires this refactor +
  active probing logic; defer to a separate feature commit).
- `Time Exceeded` handling (informational, log-only is fine).
- Any non-error ICMP demux (Echo Request/Reply already handled).

---

## 2. Architecture decisions

### 2.1 Where does `pmtu_cache` live?

**Decision: stack module level (`pytcp/stack/__init__.py`), NOT
under `TcpStack`.**

Reason: UDP needs it too. UDP datagrams over an IPv4 path with
`MTU < interface_mtu` need the cached MTU to fragment-or-fail
at send time. Wrapping it under `TcpStack` (which is currently
TCP-specific TFO state) would force UDP to reach into a
TCP-named container.

Implementation: a stand-alone module-level dict
`pmtu_cache: dict[Ip4Address | Ip6Address, int] = {}`. If we
later refactor to a unified `IpStack` aggregator (analogous to
`TcpStack`), it can live there. For now, flat module-level
matches the convention of `arp_probe_unicast_conflict`.

Test isolation: extend `TcpSessionTestCase.setUp/tearDown` to
snapshot+clear+restore `stack.pmtu_cache` (per the
`feedback_stack_module_state_test_isolation.md` rule).

### 2.2 Where does the embedded-header parser live?

**Decision: a new module
`pytcp/stack/packet_handler/_icmp_error_demux.py`.**

Provides:
- `parse_embedded_l4(frame: bytes, ip_version: IpVersion) -> EmbeddedL4 | None`
  — returns `(IpProto, four_tuple)` or `None` on malformed input.
- `EmbeddedL4` is a small frozen dataclass: `proto: IpProto`,
  `local_ip`, `local_port`, `remote_ip`, `remote_port`, plus for
  TCP: `embedded_seq: int` (the seq of the segment that triggered
  the error, used for RFC 5927 validation).

This is consumed by both ICMPv4 and ICMPv6 RX handlers, so
neither one re-implements the parser. Replaces the inline
parsing currently duplicated at `packet_handler__icmp4__rx.py:163-181`
and the v6 counterpart.

### 2.3 Where do TCP / UDP error callbacks live?

**Decision:**
- `UdpSocket.notify_pmtu(next_hop_mtu: int)` — analogous to the
  existing `notify_unreachable()`.
- `TcpSession.on_unreachable(icmp_type: int, icmp_code: int)` —
  routes by code: Net/Host Unreachable → soft error;
  Port Unreachable on SYN_SENT → abort.
- `TcpSession.on_pmtu(next_hop_mtu: int)` — update local
  per-destination MTU view, recompute MSS, possibly retransmit
  the offending segment smaller.

The TCP callbacks bridge `pmtu_cache` (stack-level read) +
`SendSeqState`/`WindowState` (per-session writes) so they
necessarily stay on `TcpSession`. The UDP callback is a
straightforward socket-level method.

### 2.4 RFC 5927 hardening boundary

**Decision: validation lives in the ICMP RX handler, not in
`TcpSession.on_*`.**

The `parse_embedded_l4` helper extracts `embedded_seq`. The RX
handler does the 4-tuple session lookup and then asks the
session whether the seq is acceptable:
`tcp_session.is_seq_in_window(embedded_seq) -> bool`. If False,
the ICMP error is silently dropped (and a counter is bumped on
`packet_stats_rx`).

This keeps the session callback simple (only fires on validated
errors) and concentrates the security-sensitive check in one
place.

### 2.5 DF=1 on outbound

**Decision: set in the IPv4 packet handler at the L4-protocol
gate.**

`pytcp/stack/packet_handler/packet_handler__ip4__tx.py` already
constructs the outbound IPv4 header. Add a parameter
`df: bool = False` to the existing `_phtx_ip4` (or whatever the
exact callable is — confirm via `grep`) and set it from:
- TCP: always `True` (PMTUD requires DF for routers to return
  Frag-Needed instead of silently fragmenting).
- UDP: `True` for IP_PMTUDISC_DO equivalent (default), `False`
  for explicit "let routers fragment" mode (rare).

IPv6 has no DF — fragmentation is end-to-end-only by design. The
hop-limit-exceeded / packet-too-big paths handle it.

---

## 3. Phased implementation

Each phase is one commit. Suite must be green at every phase
boundary. Order is bottom-up so the testing harness and demux
infrastructure exist before the protocol callbacks reach for them.

> Note on existing exact-bytes-match integration tests: Phase 8
> (DF=1 default in `_phtx_ip4`) will toggle the IPv4 flags byte
> on every existing outbound v4 frame in the
> `_expected__frames_tx` golden buffers across
> `test__packet_handler__udp__rx.py`,
> `test__packet_handler__tcp__rx.py`,
> `test__packet_handler__udp__tx.py`,
> `test__packet_handler__icmp4__rx.py`, etc. Phase 8's commit
> body must enumerate the golden-byte updates explicitly. That
> churn is mechanical but high-volume — anticipate it.

### Phase 0 — ICMP integration-test harness (1 commit)

Mirrors `TcpSessionTestCase` so subsequent ICMP-related work
(this refactor + the future ICMP protocol refactor) writes
fluent integration tests instead of golden-byte parametrized
matrices.

- New file `pytcp/tests/lib/icmp_testcase.py`:
  - `Icmp4Probe` frozen dataclass — decoded snapshot of one
    outbound IPv4/ICMPv4 frame: `ip_src`, `ip_dst`, `ip_df`,
    `ip_mf`, `ip_offset`, `icmp_type`, `icmp_code`, `icmp_id`,
    `icmp_seq`, `icmp_mtu` (Frag-Needed only),
    `embedded_proto`, `embedded_l4` (`EmbeddedL4` re-exported
    from Phase 1's helper), `data` (raw embedded bytes).
  - `Icmp6Probe` — IPv6/ICMPv6 counterpart, plus ND fields
    (`nd_target`, `nd_options`).
  - `IcmpTestCase(NetworkTestCase)` extending the shared
    snapshot+clear+restore harness with the same isolation
    hooks as `TcpSessionTestCase` (`stack.sockets`,
    `stack.tcp_stack`, `stack.interface_mtu`, plus
    `stack.pmtu_cache` once Phase 3 lands — wire the snapshot
    in Phase 0 with a no-op fallback if the attribute doesn't
    exist yet, so Phase 3 lands without harness churn).
  - Helpers: `_drive_rx`, `_advance`, `_parse_tx_icmp4`,
    `_parse_tx_icmp6`, `_assert_icmp4_message`,
    `_assert_icmp6_message`, `_assert_no_tx`.
- Migration: reshape the existing parametrized
  `pytcp/tests/integration/test__packet_handler__icmp4__rx.py`
  and `test__packet_handler__icmp6__rx.py` (and the `tx`
  counterparts) into per-scenario files under
  `pytcp/tests/integration/protocols/icmp4/` and
  `protocols/icmp6/` using `IcmpTestCase`. Keep one fluent
  test per existing parametrized case so coverage parity is
  obvious in the diff. Delete the old monolithic files only
  after the new tests pass.
- No production-code changes.

### Phase 1 — Embedded-header parser helper (1 commit)

- New file `pytcp/stack/packet_handler/_icmp_error_demux.py`
  with `EmbeddedL4` dataclass + `parse_embedded_l4` function.
- New unit tests `pytcp/tests/unit/stack/packet_handler/test___icmp_error_demux.py`
  covering: IPv4+UDP, IPv4+TCP, IPv6+UDP, IPv6+TCP; rejection
  paths (truncated, unknown proto, malformed); both Dest-Unreachable
  and Frag-Needed/PTB embedding shapes.
- No call-site changes yet. Production code is untouched.

### Phase 2 — Refactor existing UDP Dest-Unreachable demux to use the helper (1 commit)

- `packet_handler__icmp4__rx.py:__phrx_icmp4__destination_unreachable`:
  replace the inline parser at lines 163-181 with a call to
  `parse_embedded_l4`. UDP-only path stays as-is otherwise.
- `packet_handler__icmp6__rx.py:__phrx_icmp6__destination_unreachable`:
  same.
- No behaviour change. Existing UDP integration tests still pass.

### Phase 3 — Add `pmtu_cache` module-level state (1 commit)

- Add `pytcp/stack/__init__.py` line near other module-level
  state: `pmtu_cache: "dict[Ip4Address | Ip6Address, int]" = {}`.
- Extend `pytcp/tests/lib/tcp_session_testcase.py` `setUp` /
  `tearDown` with snapshot+clear+restore of `stack.pmtu_cache`
  (mandatory per the project rule).
- New unit test
  `pytcp/tests/unit/stack/test__pmtu_cache.py` pinning that the
  module-level dict exists and is empty by default.
- No production logic reads it yet — this is just the substrate.

### Phase 4 — UDP PMTUD callback (1 commit)

- Add `UdpSocket.notify_pmtu(next_hop_mtu)` method that updates
  `stack.pmtu_cache[remote_ip] = next_hop_mtu` and exposes the
  cached MTU to subsequent `sendto` calls (caller can choose
  fragment-or-fail semantics).
- Wire ICMPv4 Type 3 Code 4 into the existing `__phrx_icmp4__destination_unreachable`
  branch (the Frag-Needed code carries the next-hop MTU in the
  ICMP `unused`/`mtu` field). Same for ICMPv6 Type 2 in
  `__phrx_icmp6__packet_too_big` (new method).
- New ICMPv6 dispatch: extend the type-match in
  `__phrx_icmp6` to route Type 2 to a new
  `__phrx_icmp6__packet_too_big` handler.
- Integration tests in `pytcp/tests/integration/stack/test__udp__pmtud.py`
  pinning that an ICMP Frag-Needed/PTB with a `UdpSocket`
  matching 4-tuple lands in the cache and `notify_pmtu` fires.

### Phase 5 — TCP demux (Dest-Unreachable, both v4 + v6) (1 commit)

- Add `TcpSession.on_unreachable(icmp_type, icmp_code)` that
  routes:
  - ICMPv4 Type 3 Code 1 (Host Unreachable): mark
    `_connection_error = ConnError.HOST_UNREACHABLE` (new
    enum), release `_event__connect`, transition to CLOSED if
    SYN_SENT.
  - ICMPv4 Type 3 Code 0 (Net Unreachable): same with
    `NET_UNREACHABLE`.
  - ICMPv4 Type 3 Code 3 (Port Unreachable) on SYN_SENT: abort
    with `CONNECTION_REFUSED` (existing enum value).
  - ICMPv6 Type 1 Code 0 (No route to destination): same as Net
    Unreachable.
  - ICMPv6 Type 1 Code 3 (Address Unreachable): same as Host.
  - ICMPv6 Type 1 Code 4 (Port Unreachable): same as IPv4 code 3.
- Add `TcpSession.is_seq_in_window(seq)` for RFC 5927 guard.
- Extend `__phrx_icmp4__destination_unreachable` and `__phrx_icmp6__destination_unreachable`
  to dispatch based on `EmbeddedL4.proto`: UDP → existing
  `notify_unreachable`; TCP → 4-tuple lookup against
  `stack.sockets`, RFC 5927 seq guard, `tcp_session.on_unreachable(...)`.
- Closes the TODO at `packet_handler__icmp6__rx.py:185-187`.
- New unit + integration tests covering the routing matrix.

### Phase 6 — TCP PMTUD callback (1 commit)

- Add `TcpSession.on_pmtu(next_hop_mtu)` that:
  1. Updates `stack.pmtu_cache[remote_ip] = next_hop_mtu`.
  2. Recomputes `self._win.snd_mss = next_hop_mtu - ip_tcp_overhead`
     (clamped to RFC 9293 §3.7.5 / RFC 2675 §5 ceilings).
  3. If a segment with seq+len exceeding the new MSS is
     in-flight, walks back `SND.NXT` to retransmit smaller.
- Wire ICMPv4 Type 3 Code 4 + ICMPv6 Type 2 into TCP demux
  alongside the UDP path from phase 4.
- Integration tests in
  `pytcp/tests/integration/protocols/tcp/test__tcp__session__pmtud.py`
  driving the full path: outbound segment, ICMP Frag-Needed /
  PTB inbound, MSS recompute, smaller retransmit on the wire.

### Phase 8 — DF=1 on outbound IPv4 (1 commit)

- Audit `pytcp/stack/packet_handler/packet_handler__ip4__tx.py`
  to find the IPv4 TX entry point (likely `_phtx_ip4` or
  `send_ip4_packet`).
- Add `df: bool = True` parameter (default True per modern
  PMTUD-on-by-default behaviour).
- Wire callers: TCP-bearing path always passes `df=True`; UDP
  path passes the socket's IP_MTU_DISCOVER setting.
- Update existing integration tests that observe outbound IPv4
  flag bits.

### Phase 9 — Per-RFC adherence audit updates (1 commit)

- Update `docs/rfc/ip4/rfc1191__pmtud_ip4/adherence.md`
  reflecting shipped status.
- Update RFC 8201 (IPv6 PMTUD) audit (create if not present).
- Update RFC 5927 audit reflecting the seq-in-window guard.
- Note in the adherence records that RFC 4821 / 8899 PLPMTUD
  probing remains future work but the substrate (pmtu_cache +
  ICMP demux) is in place.

---

## 4. RFC compliance audit

Every commit cites one or more clauses in its commit message
and (for the test commits) in test docstring `Reference:` lines.

| RFC | Clause | Used by |
|---|---|---|
| RFC 792 | Type 3 (Destination Unreachable) | Phase 5 |
| RFC 1122 | §4.2.3.9 (TCP MUST react to ICMP) | Phase 5 |
| RFC 1191 | §3 (Frag-Needed handling + MTU plateau) | Phase 6 |
| RFC 4443 | Type 1 (Destination Unreachable v6) | Phase 5 |
| RFC 4443 | Type 2 (Packet Too Big v6) | Phase 6 |
| RFC 4821 | §1 (PLPMTUD substrate, deferred) | Phase 8 audit |
| RFC 5927 | §2 (TCP ICMP attack mitigations) | Phase 5 |
| RFC 5927 | §4 (seq-in-window validation) | Phase 5 |
| RFC 8201 | §4 (IPv6 PMTUD MTU update rule) | Phase 6 |
| RFC 8899 | §1 (DPLPMTUD substrate, deferred) | Phase 8 audit |
| RFC 9293 | §3.7.5 (MSS option update on path-MTU change) | Phase 6 |

---

## 5. Test surface

### 5.1 New unit tests

| File | Coverage |
|---|---|
| `pytcp/tests/unit/stack/packet_handler/test___icmp_error_demux.py` | `parse_embedded_l4` happy path + every rejection branch |
| `pytcp/tests/unit/stack/test__pmtu_cache.py` | Module-level dict exists + isolation hook works |
| `pytcp/tests/unit/socket/test__udp__socket__pmtu.py` | `UdpSocket.notify_pmtu` updates the cache |
| `pytcp/tests/unit/protocols/tcp/test__tcp__session__icmp__dest_unreachable.py` | `on_unreachable` per-code routing |
| `pytcp/tests/unit/protocols/tcp/test__tcp__session__icmp__pmtu.py` | `on_pmtu` MSS recompute + retransmit walkback |
| `pytcp/tests/unit/protocols/tcp/test__tcp__session__is_seq_in_window.py` | RFC 5927 seq guard predicate |

### 5.2 New integration tests

All built on top of the new `IcmpTestCase` harness from Phase 0.

| File | Coverage |
|---|---|
| `pytcp/tests/integration/protocols/icmp4/test__icmp4__error_demux.py` | ICMPv4 Type 3 + Type 11 RX paths into UDP/TCP demux |
| `pytcp/tests/integration/protocols/icmp4/test__icmp4__pmtud.py` | ICMPv4 Type 3 Code 4 → `pmtu_cache` update + UDP/TCP callbacks |
| `pytcp/tests/integration/protocols/icmp6/test__icmp6__error_demux.py` | ICMPv6 Type 1 + Type 2 + Type 3 RX paths |
| `pytcp/tests/integration/protocols/icmp6/test__icmp6__pmtud.py` | ICMPv6 Type 2 (Packet Too Big) → `pmtu_cache` update + UDP/TCP callbacks |
| `pytcp/tests/integration/protocols/tcp/test__tcp__session__pmtud.py` | End-to-end PMTUD signal for TCP — outbound segment, ICMP Frag-Needed inbound, MSS recompute, smaller retransmit observable on the mock TAP |
| `pytcp/tests/integration/protocols/tcp/test__tcp__session__icmp__dest_unreachable.py` | End-to-end SYN_SENT ICMP-Port-Unreachable → ConnectionRefused abort |

### 5.3 Existing tests that may need updates

- `pytcp/tests/integration/test__packet_handler__icmp4__rx.py`
  and `test__packet_handler__icmp6__rx.py` — Phase 0 migrates
  these into per-scenario files under
  `pytcp/tests/integration/protocols/icmp4/` and
  `protocols/icmp6/` using `IcmpTestCase`. Coverage parity
  is the migration acceptance gate.
- `pytcp/tests/unit/stack/packet_handler/test__stack__packet_handler__icmp4__rx.py`
  — already exercises the existing UDP Dest-Unreachable demux
  unit-level; Phase 2's refactor must keep this green.
- Every integration test that exact-bytes-matches outbound v4
  frames in `_expected__frames_tx` — Phase 8 changes the
  default DF bit, so the IPv4 flags byte (offset 6 in the v4
  header) flips from `0x00` to `0x40` on every emitted v4
  frame. Affects (at minimum):
  `test__packet_handler__udp__rx.py`,
  `test__packet_handler__udp__tx.py`,
  `test__packet_handler__tcp__rx.py`,
  `test__packet_handler__icmp4__rx.py`. Mechanical
  golden-byte updates only; enumerate in Phase 8 commit body.

---

## 6. Risks and tradeoffs

### 6.1 RFC 5927 attack surface

ICMP errors are forgeable — an off-path attacker who knows or
guesses a 4-tuple can craft an ICMP error to trigger
`on_unreachable` and abort a session. The seq-in-window guard
narrows the attack window to the size of the receive window,
which is reasonable for typical workloads but does not fully
close it. PyTCP's stance: implement the guard, document the
residual risk in the audit, and rely on rate-limiting (TODO,
future) to mitigate flooding.

### 6.2 PMTUD deadlock — the "PMTUD black hole"

Some middleboxes silently drop ICMP Frag-Needed responses,
leaving the sender stuck retransmitting MSS-sized segments
that get dropped at the bottleneck. RFC 4821 PLPMTUD addresses
this via active probing — out of scope for this refactor but
the per-destination MTU cache substrate makes a future PLPMTUD
implementation a tractable feature commit.

### 6.3 Stale MTU cache entries

`pmtu_cache` entries never expire in this refactor. RFC 1191
recommends periodic re-discovery of higher MTUs (the "plateau
table" approach). Documented as future work; the cache is
process-lifetime-only so server restarts purge it naturally.

### 6.4 IPv6 jumbograms

RFC 2675 §5 + RFC 9293 §3.7.5 cap MSS option at 65535 even on
jumbo paths. The MSS-recompute path in Phase 6 must respect
this ceiling — already handled by the existing
`tcp__sport=min(self._rcv_mss, 0xFFFF)` clamp in
`_phase1_compose_ecn_flags` but worth verifying.

---

## 7. Effort + risk

| Phase | Commits | Risk | Notes |
|---|---|---|---|
| 0 — ICMP harness + migration                   | 1 | Low         | Pure test-side; coverage parity gate |
| 1 — Embedded-header parser helper              | 1 | Low         | Pure new code |
| 2 — Refactor existing UDP demux onto helper    | 1 | Low         | No behaviour change |
| 3 — `pmtu_cache` substrate                     | 1 | Low         | Module-level dict + harness snapshot hook |
| 4 — UDP PMTUD callback                         | 1 | Medium      | New ICMP type-2 handler |
| 5 — TCP demux (Dest-Unreachable v4 + v6)       | 1 | Medium      | RFC 5927 guard, FSM transitions |
| 6 — TCP PMTUD                                  | 1 | Medium-High | MSS recompute + retransmit walkback |
| 8 — DF=1 outbound IPv4                         | 1 | Medium      | Wire-format default change; golden-byte updates across existing exact-bytes tests |
| 9 — Audits                                     | 1 | Low         | Documentation |
| **Total**                                      | **9** | **Medium overall** | |

Phase numbers skip 7 deliberately — Phase 7 was used in an
earlier draft and dropped during the Phase-0 insertion. The
sequencing rationale (test-harness first, demux second,
substrate third, callbacks last, wire-default change after
all behaviour pinned) is what matters; the labels are stable
references for commit messages.

Realistic estimate: 9 commits, roughly half a day of focused
work each. Phase 0 is mostly mechanical migration of existing
ICMP integration cases and pays for itself across the rest of
the refactor and the future ICMP protocol refactor. Phase 6
remains the highest-risk slice because of the retransmit-
walkback subtlety.

---

## 8. Reference points

- Last commit before this refactor: `c5ac6c78` (FSM subpackage move)
- Original concern + corrected scope: see
  `docs/refactor/tcp_codebase_improvement_plan.md` Concern #5
  (corrected in commit `5d8f8daa`).
- ICMP RX handlers to be touched:
  - `pytcp/stack/packet_handler/packet_handler__icmp4__rx.py`
  - `pytcp/stack/packet_handler/packet_handler__icmp6__rx.py`
- Test framework isolation: extend
  `pytcp/tests/lib/tcp_session_testcase.py` per
  `feedback_stack_module_state_test_isolation.md`.
- Test counts at this plan's authoring: 8482 passing, 0 skipped,
  lint clean, branch `PyTCP_3_0__pre_release`.
