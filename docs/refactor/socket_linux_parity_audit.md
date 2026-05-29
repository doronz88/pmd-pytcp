# Socket-Layer Linux Parity Audit

> **STATUS UPDATE (post-`89da6654`, refreshed 2026-05-28):** Phase 1
> is fully shipped (8 commits since audit creation `ccae024c`).
> Phase 2 server-compat options are mostly shipped. **H4 IPv4
> IP_ADD_MEMBERSHIP shipped 2026-05-26 via the IGMP track** (commits
> `f837d017` initial + `8aa1a257`/`0e5fff39`/`a4b95781`/`5ed73306`/
> `e9abe066` R3-R6 refinements + `c98e409c`/`9cc7dfdc` §9 source
> filters + `752d2bfd` finalizer); the H4 IPv6 half (IPV6_JOIN_GROUP)
> remains deferred. **H2 SO_REUSEPORT shipped 2026-05-29** (4-phase
> track `af536889`/`c41aa96b`/`c76fa4f5`/`fe619b78`). **The former
> deferred bundle — M2 sendmsg/recvmsg, M8 MSG_ERRQUEUE, H8
> SO_LINGER — is now fully shipped** (M8 + recvmsg landed with the
> IP_RECVERR work; `sendmsg` + `SO_LINGER` shipped 2026-05-29). See
> §100 "Shipping status" for the full ledger.



**Goal:** PyTCP's `pytcp.socket` module should be a drop-in
substitute for CPython's stdlib `socket` module, such that
applications written against the Linux/BSD socket API can be
re-imported against PyTCP and continue to work without
source modifications. Improvements that don't break
compatibility are welcome — but compatibility is the
primary constraint.

**Reference frame:** POSIX-2017 socket API + Linux-specific
extensions where they're widely depended on (SO_REUSEPORT,
TCP_NODELAY, IPV6_V6ONLY, getaddrinfo, etc.).

**Scope:** This audit catalogues *what's missing*. The
fixes themselves are deferred — each gap below has a
proposed implementation sketch but no commit. Use this
document as the punch list to drive future socket-layer
work; address gaps in priority order.

**Status snapshot (at HEAD `762e52ec`):** PyTCP exposes a
working facade with `TcpSocket`, `UdpSocket`, `RawSocket`,
factored through a `socket()` factory. Major mechanisms
shipped: TCP RFC 9293 FSM with full congestion control,
SACK, RACK/TLP, TFO, AccECN, keep-alive; UDP datagram path
with optional `connect()`; RAW IP socket with explicit
protocol. The FSM, addressing, and per-protocol-family code
paths are sound. The deficiencies below are **API-surface
and integration**, not protocol implementation.

---

## Top-line classification

| Tier | Definition | Item count |
|---|---|---|
| **CRITICAL** | Blocks app compatibility outright. Apps using these patterns will fail to start or behave incorrectly under PyTCP regardless of what they're trying to do. | 6 |
| **HIGH** | Limits major application categories (servers needing port reuse, multicast receivers, dual-stack listeners). App is functional but misconfigured by default. | 8 |
| **MEDIUM** | Limits advanced or specialized application categories. Many apps work without these; some break in subtle ways. | 8 |
| **LOW** | Polish / introspection / esoteric APIs. Workarounds exist. | 4 |

**Gap count: 26.** The CRITICAL bucket is the priority —
those gaps make PyTCP unable to host any standard event-
loop framework (asyncio, trio, twisted) or any application
that uses `select` / `poll` / non-blocking IO.

---

## CRITICAL — blocks app compatibility (6)

### C1. No `fileno()` / file-descriptor model

**Linux:** `sock.fileno()` returns an integer file descriptor
that the OS kernel manages. `select`, `poll`, `epoll`,
`selectors`, async event loops all consume `fileno()`.

**PyTCP:** Sockets are pure Python objects. `fileno()` is
not implemented. There is no file descriptor at all — no
kernel object, no readable/writable bit a kernel-aware
poller could observe.

**Implication:** No standard event loop can drive PyTCP
sockets. `asyncio.StreamReader/Writer`, `selectors.DefaultSelector`,
`select.select`, `select.poll`, `select.epoll` — all need
fileno(). Apps using any of them — which is virtually every
async / concurrent app — won't even import successfully.

**Sketch:** Two options. (a) Use `os.eventfd()` per socket
to expose a real fd that signals readability when bytes
land in the rx buffer; the socket's `fileno()` returns the
eventfd. The TX buffer needs an analogous writable signal.
(b) Use a `socketpair()` of OS pipes per socket and write a
sentinel byte when state transitions. Both work; eventfd is
simpler. Either way the FSM and UDP rx queue need a callback
to set the readable bit. Significant infrastructure but
unblocks everything else.

**Severity rationale:** Without this, no other gap matters —
apps simply can't dispatch on PyTCP sockets.

### C2. No `setblocking(False)` / non-blocking mode

**Linux:** `sock.setblocking(False)` (or `fcntl(F_SETFL, O_NONBLOCK)`)
makes `recv` / `send` / `accept` raise `BlockingIOError`
(errno EAGAIN/EWOULDBLOCK) when they would block.

**PyTCP:** Every operation blocks. There is no non-blocking
mode. The per-call `timeout=` kwarg on `recv` / `accept`
provides a related-but-different model.

**Implication:** Async frameworks expect non-blocking mode +
fd polling. Without setblocking(False), even with a working
fileno(), you'd block in recv waiting for the buffer.

**Sketch:** Add `_blocking: bool = True` flag, expose
`setblocking(flag)` / `getblocking()`. Wire each blocking
call to check the flag and raise `BlockingIOError(EAGAIN)`
if it would block (rx buffer empty, accept queue empty,
tx buffer full).

### C3. No `select` / `poll` / `epoll` / `selectors` integration

**Linux:** Apps drive sockets through `selectors.DefaultSelector()`
or directly with `select.select(rlist, wlist, xlist)`. The
kernel atomically reports which fds are ready.

**PyTCP:** Even with C1+C2 unblocked, the connection from
"socket has data" to "selector returns ready" doesn't exist.
PyTCP's stack runs in its own thread and would need to drive
the eventfd / pipe whenever an FSM/UDP-queue state change
makes a socket ready.

**Sketch:** Pair with C1's eventfd. Every place that today
calls `_event__rx_buffer.release()` (semaphore wakeup) also
writes to the eventfd. Tx-side: when tx buffer drains below
high-water mark, signal writable. accept-side: when accept
queue gains an entry, signal readable.

### C4. No `getaddrinfo()` / `gethostbyname()` / address
resolution

**Linux:** `socket.getaddrinfo("example.com", 80)` resolves
hostnames to a list of `(family, type, proto, canonname,
sockaddr)` tuples. Apps construct addresses by calling
`getaddrinfo` first.

**PyTCP:** `bind` / `connect` / `sendto` accept literal
IP-string addresses only. Apps that pass `("hostname", port)`
will fail with `gaierror` or unparseable-address errors.

**Implication:** Any app that takes a hostname argument
(virtually all client apps) breaks.

**Sketch:** Re-export `socket.getaddrinfo` from CPython's
stdlib socket module — DNS resolution is application-layer
and lives outside the stack. The PyTCP socket module's
`getaddrinfo` would just be `import socket as _stdlib;
getaddrinfo = _stdlib.getaddrinfo`. Same for
`gethostbyname`, `getnameinfo`, `getfqdn`. App code calls
PyTCP's `getaddrinfo` and gets stdlib resolution; the
resulting IP string then flows into PyTCP's `bind`/`connect`.

### C5. `recv(bufsize)` ignores `bufsize`

**Linux:** `recv(4096)` returns at most 4096 bytes. Apps
loop on this for streaming.

**PyTCP:** The `bufsize` parameter is accepted but
explicitly TODO / ignored in `tcp__socket.py` and
`udp__socket.py`. Returns whatever happens to be buffered.

**Implication:** Apps that depend on chunked-read semantics
(HTTP body parsers, framing protocols, length-prefixed
formats) will see oversized returns and may misalign
parser state.

**Sketch:** Implement `bufsize` as a slice of the rx buffer
in TCP (`bytes(self._rx_buffer[:bufsize]); del
self._rx_buffer[:bufsize]`). For UDP, truncate the popped
datagram to bufsize and discard remainder (POSIX semantics).

### C6. No errno-mapped `OSError`

**Linux:** Connection refused → `ConnectionRefusedError`
(subclass of `OSError`, `errno=ECONNREFUSED`). Address in
use → `OSError(errno=EADDRINUSE)`. Apps branch on
`e.errno` against the `errno` module constants.

**PyTCP:** Most exceptions are bare `OSError("message
text")` with no errno. Some specific ones do set errno
(EPROTONOSUPPORT, EDESTADDRREQ — confirmed in the audit) but
the coverage is sparse.

**Implication:** Apps that do `except OSError as e: if
e.errno == errno.EAGAIN: ...` see `e.errno is None` and
fall through.

**Sketch:** Sweep through every `raise OSError(...)` in
the socket layer and ensure the errno argument is set to
the matching POSIX value: ECONNREFUSED, ETIMEDOUT,
EADDRINUSE, EADDRNOTAVAIL, EHOSTUNREACH, ENETUNREACH,
EAGAIN, EINPROGRESS, EALREADY, EISCONN, ENOTCONN, EPIPE,
EBADF. Most are 1-2 line edits.

---

## HIGH — limits major application categories (8)

### H1. No `SO_REUSEADDR`

**Linux:** Allows binding a socket to an address-port that
is in TIME_WAIT, or that another socket on the same box has
already bound to (in some configurations). Required for
restartable servers.

**PyTCP:** No `setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)`. A
server that crashes and restarts within `2*MSL` (60-240s
TIME_WAIT) will fail to rebind to its port.

**Sketch:** Wire as a flag on `TcpSocket`/`UdpSocket`. On
TCP, the FSM bind-validation should consult the flag before
rejecting on existing TIME_WAIT entries. On UDP, the bind
gate would allow the bind even if the (addr, port) tuple is
in `stack.sockets`.

### H2. `SO_REUSEPORT` — SHIPPED 2026-05-29 (Phases 1–4)

**Linux:** Multiple sockets on the same (addr, port) for
load balancing across worker threads/processes. Linux's
SO_REUSEPORT hashes incoming connections to one of the
listening sockets (`net/core/sock_reuseport.c`); every
socket in the group must opt into the flag.

**PyTCP:** Shipped. `SocketTable` (`pytcp/socket/socket_table.py`)
now stores a *cohort* — `dict[SocketId, list[socket]]` — per
id; only listening ids (remote unspecified, port 0) ever hold
more than one member, so established-connection lookups stay
size-1. `SocketTable.get` round-robins delivery across a
multi-member cohort under the table lock (no new lock,
no-GIL-safe), so the TCP / UDP RX handlers load-balance
transparently with no RX-path change. `SO_REUSEPORT`
(SolSocketOption optname 15) round-trips via
setsockopt/getsockopt; `is_address_in_use` permits an overlap
only when the binding socket **and** every overlapping open
socket carry the flag (Linux's all-or-nothing group rule).

**Phase-1 simplification:** the demux is round-robin, not
Linux's 4-tuple hash. Round-robin is retransmit-safe because a
listener-fork child registers its full 5-tuple before any
duplicate SYN arrives, so the exact-match path (not the cohort)
wins on retransmits. eBPF / custom REUSEPORT hash selection and
REUSEPORT × dual-stack mixed-`v6only` cohorts are out of scope
(documented in `docs/refactor/socket_parity_followup.md`).

**Tests:** `SocketTable` cohort/round-robin/register/unregister
unit tests; `is_address_in_use` + TcpSocket/UdpSocket bind-gate
unit tests; TCP + UDP cohort RX-demux integration tests
(`test__tcp__session__reuseport_cohort.py`,
`test__udp__reuseport_cohort.py`) covering one-per-listener
distribution, cursor wrap, and retransmit stability.

### H3. `IPV6_V6ONLY` — SHIPPED 2026-05-28 (Phases 1, 2, 3a, 3b, 3c)

**Linux:** Default for Python is `IPV6_V6ONLY=1` (IPv6
sockets accept only IPv6 peers). Setting it to 0 makes the
socket accept IPv4-mapped peers (`::ffff:1.2.3.4`) — dual-
stack mode.

**PyTCP:** Dual-stack support shipped across four phases.

  * **Phase 1 (`6edab2be`):** `Ip6Address.is_ipv4_mapped`
    predicate + `Ip6Address.from_ipv4_mapped(ip4)`
    classmethod — the value-type prerequisites consumers
    can already use (Linux `IN6_IS_ADDR_V4MAPPED` parallel).
  * **Phase 2 (`72479a5f`):** `IPV6_V6ONLY` setsockopt
    storage + getsockopt — operator-facing knob with
    Python-default `V6ONLY = 1`. No behaviour change yet.
  * **Phase 3a (`3389d546`):** Bind-time cross-family
    conflict detection — `is_address_in_use` understands
    that an AF_INET6 V6ONLY=0 listener bound to `::`
    reserves both IPv4 and IPv6 namespaces on its port.
    `TcpSocket.bind` / `UdpSocket.bind` pass `dual_stack=...`.
  * **Phase 3b:** TCP RX listener-table extension —
    `TcpMetadata.listening_socket_ids` on an IPv4 envelope
    now appends an AF_INET6 wildcard pattern as the third
    candidate so an IPv6 V6ONLY=0 listener bound to `::`
    can accept the inbound IPv4 SYN. The dispatch loop in
    `packet_handler__tcp__rx.py` filters cross-family
    matches against the listener's `_ipv6_v6only` flag — a
    V6ONLY=1 listener that happened to bind `::` is skipped
    so the IPv4 inbound falls through to the no-listener
    drop path.

  * **Phase 3c:** Application-facing IPv4-mapped IPv6 surfacing.
    Accepted children of an AF_INET6 V6ONLY=0 listener receiving an
    IPv4 SYN now carry a `_dual_stack` presentation flag set by
    the listener-fork. The app-facing accessors — `family` /
    `local_ip_address` / `remote_ip_address` / `getsockname()` /
    `getpeername()` / the `accept()` return tuple — wrap the wire
    IPv4 addresses into the canonical `::ffff:0:0/96` form via
    `Ip6Address.from_ipv4_mapped(ip4)` (the Phase 1 classmethod).
    The wire attributes (`_address_family` = AF_INET4 /
    `_local_ip_address` / `_remote_ip_address` / `socket_id`)
    stay AF_INET4 so the RX-path active-socket lookup keeps
    matching inbound IPv4 packets. Linux-parity end-to-end on the
    common dual-stack use case.

### H4. Multicast group membership — IPv4 SHIPPED, IPv6 deferred

**Linux:** UDP multicast receivers MUST call
`setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, struct ip_mreq)`
to instruct the kernel to listen on the multicast address.

**IPv4 — SHIPPED 2026-05-26** via the IGMP track. Initial
landing at commit `f837d017`
(`feat(igmp): add IP_ADD/DROP_MEMBERSHIP socket options`); the
post-review refinements R3-R6 (membership refcount + close
release + EADDRINUSE/EADDRNOTAVAIL parity + ENOBUFS cap +
`ip_mreqn` accepted form, commits `8aa1a257` /
`0e5fff39` / `a4b95781` / `5ed73306` / `e9abe066`)
hardened the surface. The RFC 3376 §9 source-filter
controls (`IP_ADD/DROP_SOURCE_MEMBERSHIP`,
`IP_BLOCK/UNBLOCK_SOURCE`) shipped under the same track
(`c98e409c` + `9cc7dfdc`). The socket finalizer
(`752d2bfd`) releases leaked memberships on GC. See
`project_igmp_shipped` memory entry for the full
inventory.

**IPv6 — deferred.** No app-driven `IPV6_JOIN_GROUP` /
`IPV6_LEAVE_GROUP` setsockopt yet — the IPv6 multicast
machinery exists (`_ip6_multicast` list on the packet
handler, MLDv2 listener replies to queries) but is
SLAAC-driven only (auto-join solicited-node multicast on
address assignment); applications cannot drive a
user-requested join. Lift the IPv4 IGMP socket-options
pattern (`socket/__init__.py` lines ~638-720) to a
parallel IPv6 surface + emit an MLDv2 Report on join,
MLDv2 Done on leave. The MLDv2 report-emitter side is
already in tree (`packet_handler__icmp6__tx.py`); this
gap is purely the app-facing setsockopt + per-socket
membership table.

### H5. No `SO_BROADCAST`

**Linux:** UDP sockets sending to a broadcast address must
have `SO_BROADCAST=1` enabled, otherwise sendto raises
`EACCES`.

**PyTCP:** Sendto to a broadcast address may or may not
work depending on stack-internal address-class checks; the
SO_BROADCAST gate is missing. Apps that call
`setsockopt(SOL_SOCKET, SO_BROADCAST, 1)` get an error.

**Sketch:** Add the option as a flag on `UdpSocket`. Have
the IPv4 broadcast emit path consult the flag before
allowing the send.

### H6. No `IP_TTL` / `IPV6_UNICAST_HOPS`

**Linux:** Apps set per-socket TTL (IPv4) or Hop Limit
(IPv6) — important for traceroute, multicast
limited-scope, NAT detection.

**PyTCP:** No setsockopt. Outbound packets use the stack-
default TTL/Hop. Apps can't override per-socket.

**Sketch:** Per-socket override stored on the
TCP/UDP/RAW socket; thread it down to the IPv4/IPv6 emit
path.

### H7. No `SO_SNDBUF` / `SO_RCVBUF`

**Linux:** Apps tune send and receive buffer sizes for
high-bandwidth-delay-product paths. Linux often does
auto-tuning by default but apps can override.

**PyTCP:** Internal TX/RX buffers use stack defaults. No
setsockopt knobs.

**Sketch:** Wire as options that adjust per-session
buffer caps. For TCP this also affects window-scale
advertisement (RCV.WND derives from rx buffer space).

### H8. No `SO_LINGER`

**Linux:** Controls behavior of `close()` on a TCP socket
with unsent data — block until drained, drop immediately,
or send RST.

**PyTCP:** `close()` always does graceful FIN close.
`abort()` does RST. No SO_LINGER option to bind one of
these to `close()` behaviour.

**Sketch:** Map `SO_LINGER {l_onoff, l_linger}` to a flag +
timeout on the TcpSocket; have `close()` consult the flag
to choose between graceful close, blocking-with-timeout, or
RST.

---

## MEDIUM — limits advanced application categories (8)

### M1. No `SO_RCVTIMEO` / `SO_SNDTIMEO`

**Linux:** Persistent timeout on all blocking ops. Apps
prefer this over per-call `timeout=`.

**PyTCP:** Per-call `timeout=` parameter exists; no
setsockopt-driven persistent timeout.

**Sketch:** Add a `_rcv_timeout` / `_snd_timeout` field;
each blocking op uses it as the default if no per-call
timeout passed.

### M2. No `sendmsg` / `recvmsg`

**Linux:** Scatter-gather IO + ancillary data (control
messages: IP_PKTINFO, IP_RECVERR, IPV6_HOPLIMIT receive,
SCM_RIGHTS for fd passing on Unix sockets).

**PyTCP:** Only `send`/`recv` and `sendto`/`recvfrom`. No
`sendmsg`/`recvmsg`.

**Sketch:** Substantial — would need a control-message
decoder/encoder layer. Many apps don't use this; stubbing
to raise `NotImplementedError` may be fine for
compatibility-on-most-apps.

### M3. No MSG_OOB (TCP urgent data)

**Linux:** TCP urgent / out-of-band data via `MSG_OOB` flag
on send/recv.

**PyTCP:** TCP FSM has URG-flag handling per RFC 9293, but
the socket facade doesn't expose MSG_OOB.

**Sketch:** Add MSG_OOB flag handling to TcpSocket.send /
recv; route to/from the existing FSM URG path.

### M4. No `IP_TOS` / `IPV6_TCLASS`

**Linux:** Per-socket DSCP+ECN bits (the 8-bit Traffic
Class field). Used for QoS marking.

**PyTCP:** TCP FSM has ECN echo wired (RFC 3168 / 9768);
the IPv6 emit path exposes `ip6__ecn` kwarg. No socket-
layer setsockopt to drive it from the application.

**Sketch:** Map IP_TOS / IPV6_TCLASS to a per-socket
DSCP+ECN override; thread to the emit path.

### M5. `TCP_INFO` — SHIPPED 2026-05-28

**Linux:** `getsockopt(IPPROTO_TCP, TCP_INFO, struct
tcp_info)` returns ~50 fields of connection statistics —
RTT, RTO, cwnd, ssthresh, retransmits, etc.

**PyTCP:** SHIPPED. `getsockopt(IPPROTO_TCP, TCP_INFO)`
returns the canonical 240-byte Linux 5.5 struct layout
packed from the underlying `TcpSession`. State byte maps
PyTCP `FsmState` → Linux `enum tcp_states` via
`_FSM_TO_TCP_INFO_STATE`; populated fields include
`tcpi_snd_mss` / `tcpi_rcv_mss` from `WindowState`,
`tcpi_snd_cwnd` / `tcpi_snd_ssthresh` from `CcState`
(BYTES → SEGMENTS conversion per Linux units),
`tcpi_rtt` / `tcpi_rttvar` from `RtoState` (ms → μs),
`tcpi_options` flags from negotiated TS / SACK / WSCALE /
ECN state, `tcpi_snd_wscale` / `tcpi_rcv_wscale` bit-
packed nibbles, `tcpi_pmtu` from the PLPMTUD engine's
current MTU. The pre-existing `TcpSocket.status()` →
`TcpStatus` dataclass surface remains; TCP_INFO is the
Linux-shaped wire surface bolted on top so applications
written against the stdlib socket pattern see the bytes
they expect. Counters PyTCP doesn't track per-session
(pacing rate, busy time, bytes-acked counters, segs-out
/-in) zero-fill with inline rationale. See
`pytcp/socket/tcp__info.py` for the packer.

### M6. `TCP_USER_TIMEOUT` — SHIPPED 2026-05-28

**Linux:** Per-connection abort-after-no-ACK timeout
(replaces the RFC 1122 default ~100 s).

**PyTCP:** SHIPPED. `setsockopt(IPPROTO_TCP,
TCP_USER_TIMEOUT, ms)` stores a per-socket
`_tcp_user_timeout`; `connect()` / `listen()` propagate
it onto `TcpSession._user_timeout_ms`. The R2 abort
site in `session/tcp__session__retransmit.py` consults
the override and computes
`budget = max(1, _user_timeout_ms // current_rto_ms)` so
the abort fires after the user's wall-time budget elapses
under the current RTO. PyTCP's count-based machinery
approximates Linux's time-based
`tcp_time_stamp - tp->retrans_stamp` check; an exact
time-based implementation would need an additional
`first_unacked_at_ms` tracker the cum-ACK path would
have to maintain — documented inline as out-of-scope for
the M6 surgery.

### M7. `TCP_MAXSEG` — SHIPPED 2026-05-28

**Linux:** Clamp / read the negotiated MSS. Some apps need
to verify the path MSS.

**PyTCP:** SHIPPED. `setsockopt(IPPROTO_TCP, TCP_MAXSEG,
mss)` stores a per-socket `_tcp_maxseg`; `connect()` /
`listen()` propagate it onto
`TcpSession._maxseg_override`. The SYN-options assembly in
`session/tcp__session__tx.py` clamps the emitted MSS
option to `min(rcv_mss, 0xFFFF, _maxseg_override)` when
the override is positive — so the peer learns no
advertised MSS larger than the application wants.
`getsockopt(IPPROTO_TCP, TCP_MAXSEG)` returns the live
`session._win.snd_mss` post-connect (matching Linux's
"current effective MSS") or the stored override
pre-connect. Validator rejects values below
Linux `TCP_MIN_MSS = 88`.

### M8. No `MSG_ERRQUEUE` / IP_RECVERR

**Linux:** Routes ICMP errors to a separate per-socket
error queue, retrieved by `recvmsg(MSG_ERRQUEUE)`. Apps
opt-in via `IP_RECVERR=1`.

**PyTCP:** ICMP errors hooked into UDP socket via
`notify_*` methods (Unreachable, TimeExceeded,
ParameterProblem, PMTU); `notify_unreachable` raises on
the next normal recv. Linux's MSG_ERRQUEUE delivery model
is not implemented.

**Sketch:** Add per-socket error queue; on
`setsockopt(IP_RECVERR=1)`, route notify_* into the queue
instead of inlining.

---

## LOW — polish / niche (4)

### L1. No `dup()` / `dup2()` / `fileno()` semantics

Apps that fork and pass sockets via fd inheritance won't
work (dependent on C1).

### L2. No `socketpair()`

Niche; mostly Unix-domain. Workarounds via two TCP sockets
on loopback.

### L3. No hostname accepting in `bind` / `connect`

Apps that pass `("localhost", port)` directly without
`getaddrinfo` will fail. Unblocked once C4 lands —
applications get into the habit of resolving first.

### L4. No `INADDR_ANY` symbolic constants

Linux apps use `socket.INADDR_ANY` (= 0). Easy fix: just
expose the constant in `pytcp.socket`.

---

## Cross-cutting issues

### X1. Stack thread separation — AUDIT (2026-05-27)

PyTCP's stack runs across several threads — the rx-ring
thread (PacketHandler RX methods), the tx-ring thread, the
Timer subsystem thread, the ARP/ND cache aging threads — and
application code calls into sockets / control APIs from its
own thread(s). This section records the explicit cross-thread
shared-state audit owed since the original write-up.

**Threat model.** PyTCP ships and tests on standard CPython,
so the GIL holds: every individual bytecode op (a `d[k]=v`
key set, a `d.get(k)`, a `d.pop(k)`, a `deque.append`/
`popleft`, a scalar field assignment) is atomic w.r.t. other
Python threads, and a single C-level call such as
`list(some_dict)` cannot be interleaved by another Python
thread. Three hazard classes survive the GIL: **(H1)** a
*Python-level* `for`/comprehension iterating a shared
dict/set/list on one thread while another thread changes its
size → hard `RuntimeError: ... changed size during iteration`;
**(H2)** a compound check-then-act / read-modify-write spanning
multiple bytecodes interleaved by another writer → lost update
or stale read (no crash); **(H3)** a multi-statement invariant
(container + derived counter) observed torn by a reader. A
fourth class — raw container corruption / tearing on any
unguarded write — appears on free-threaded CPython
(3.13t/3.14t). **Running on no-GIL CPython is a PyTCP north-star
goal**, so this fourth class is in scope: GIL atomicity is NOT
an acceptable correctness crutch, and every cross-thread
dict / list / set / scalar ultimately needs its own lock (the
lock-per-structure pattern the SocketTable / RouteTable / Timer
heap / NeighborCache already follow). The findings below are
therefore tiered two ways: severity **on today's GIL build**
(what can crash or misbehave now) and **on a no-GIL build**
(what must be locked to reach the north star). "Benign under
the GIL" means "not a 3.0.6-on-CPython bug" — it does **not**
mean "done"; each such item is on the no-GIL backlog.

**Already correctly guarded** (these predate and survive the
audit — each has genuine multi-writer, iterate-while-mutate,
or torn-invariant exposure and carries its own lock):

| Structure | Lock | File |
|---|---|---|
| `stack.sockets` (SocketTable) | `_lock` — accessors return snapshots | `socket/socket_table.py` |
| `stack.ip4_fib` / `ip6_fib` (RouteTable) | `_lock` (lookup snapshots under lock) | `runtime/fib.py` |
| `Timer._heap` + `_seq` | `_lock` (RLock; released before callback) | `runtime/timer.py` |
| `NeighborCache._entries` (ARP/ND) | `_lock` (callbacks fire outside lock) | `lib/neighbor.py` |
| Per-interface IPv4 Identification | `_lock__ip4_id` | `runtime/packet_handler/__init__.py` |
| Per-socket rx/tx buffers, accept signal | `_lock__io` / `_lock__rx_buffer` / `_lock__tx_buffer` / `_lock__fsm` + semaphores + eventfd | `socket/*.py`, `protocols/tcp/tcp__session.py` |

**Findings — unguarded cross-thread state:**

- **F1 (H1, real, low-probability crash — the one defect worth
  fixing).** `_igmp_group_query__pending` (per-group GSSQ
  response records) is iterated on the **rx-ring thread** in
  `_igmp_cancel_pending_timers` (`for pending in …pending.
  values(): …; .clear()`, `packet_handler__igmp__rx.py:374/376`)
  while the **timer thread** can `pop(group)` the same dict from
  `_igmp_group_query__deferred_send` (`:305`). If a
  Group-(and-Source-)Specific Query response timer fires in the
  exact instant a querier compatibility-mode change cancels the
  pending set, the RX iteration raises `RuntimeError:
  dictionary changed size during iteration` and kills the RX
  subsystem loop. Window is narrow and both sides are internal
  threads (no app involvement), but it is a genuine GIL-present
  crash. **Fix:** snapshot before iterating —
  `for pending in list(self._if._igmp_group_query__pending.
  values()):` (the codebase already uses exactly this
  snapshot-then-iterate idiom at `igmp__tx.py:310`
  `groups = list(self._igmp_state_change__pending)` and at
  `igmp__tx.py:143/163` `dict.fromkeys(self._if._ip4_multicast)`).

- **F2 (H2, moderate, no crash).** The IPv4 multicast reception
  state — `_ip4_multicast_filters` and `_ip4_multicast_refs` —
  is written only by the **app thread** (membership join/leave,
  `IP_*_SOURCE_MEMBERSHIP` setsockopt) and read by the **rx-ring
  thread** *only through atomic snapshots*: the `_ip4_multicast`
  property is `list(self._ip4_multicast_filters)` (one C-level
  call, GIL-atomic) and every RX/TX/IGMP consumer iterates that
  snapshot or `dict.fromkeys(...)` of it, never the live dict.
  RX delivery is therefore safe under the GIL. The residual is
  **app-vs-app**: two application threads doing concurrent
  join/leave/setsockopt on the same interface race on the
  compound `_mc_recompute` read-merge-assign and the
  `_mc_ref_acquire`/`_mc_ref_release` refcount RMW, which can lose
  an update or strand a refcount. Linux serialises these under the
  socket/`mc_list` lock; PyTCP had no such lock.
  **FIXED (2026-05-27):** a per-interface reentrant
  `_lock__multicast` now guards every read and write of
  `_ip4_multicast_filters` / `_ip4_multicast_refs` (the mutators
  `_mc_ref_acquire` / `_mc_ref_release` / `_mc_set_socket_filter` /
  `_mc_clear_socket_filter` / `_mc_recompute` /
  `_assign_ip4_multicast` / `_remove_ip4_multicast`, and the
  readers `_ip4_multicast` / `_mc_is_joined` /
  `_ip4_multicast_filter_for` plus the IGMP-TX current-state
  reads). Reentrant because the mutators nest. Pinned by the
  lock-discipline test in
  `test__igmp__thread_safety.py`.

- **F3 (H2/benign under GIL; real under no-GIL).** `stack.pmtu_cache`
  / `stack.pmtu_state` were bare dicts written from the rx-ring
  thread (ICMPv4 Frag-Needed, ICMPv6 Packet-Too-Big) and from
  app/tx paths (UDP, TCP), read via `.get(dst)` in `current_pmtu`.
  Every access is an independent single-key set or get — no
  iteration, no multi-key invariant — so all are GIL-atomic
  (worst case a reader sees a slightly stale per-destination
  MTU). On a free-threaded build, an unguarded dict write racing
  another access tears the map. **FIXED (2026-05-27):** a shared
  module `stack._pmtu_lock` now guards every access; the maps
  stay plain dicts (so the test-harness snapshot/clear/restore
  idioms keep working) but all reads/writes go through
  `current_pmtu` / `record_classical_pmtu` / `record_pmtu_engine`,
  each holding the lock. The four ICMP/UDP/TCP write sites were
  migrated to the accessors. Pinned by `test__pmtu_cache.py`
  (`TestPmtuCacheLocking`).

- **F4 (H2/benign under GIL; real under no-GIL).** The IGMP
  query-response state — the General-Query scalars
  `_igmp_query__pending_response_at_ms` / `_igmp_query__handle`,
  the `_igmp_query__suppressed_groups` set, and the
  `_igmp_group_query__pending` per-group map — is written by the
  rx-ring thread (query arrival, `__phrx_igmp__membership_query` /
  `__phrx_igmp__report`) and the timer thread (deferred send,
  `_igmp_query__deferred_send` / `_igmp_group_query__deferred_send`).
  On the GIL build scalar/dict ops are atomic (worst case a
  logical race — a response double-scheduled or a just-fired
  schedule cleared); on a no-GIL build the unguarded set/dict
  writes tear. **FIXED (2026-05-27):** the four query-state
  thread-entry methods (the two `__phrx_igmp__*` RX handlers and
  the two timer-fired deferred-send callbacks) now run under the
  per-interface `_lock__multicast` (reentrant, so the
  transitively-called schedulers, `_igmp_cancel_pending_timers`,
  and the report emitters that re-acquire it nest cleanly). This
  also completes the no-GIL hardening of the `_igmp_group_query__
  pending` map that F1 only crash-fixed: its mutations and the
  cancel-loop snapshot now hold the lock. Pinned by
  `test__igmp__thread_safety.py::TestIgmpQueryResponseStateLocking`.

**Conclusion.** The structures with real multi-writer /
iterate-while-mutate / torn-invariant exposure are all already
lock-guarded; the locking design (snapshot-under-lock for
tables, snapshot-before-iterate for the multicast/IGMP derived
views, callbacks-outside-lock for the timer and neighbor cache)
is sound and is the template for the rest.

- **On today's GIL build:** exactly **one** genuine defect was
  found — **F1**, a one-line snapshot fix (shipped). F2 was a
  latent app-vs-app serialisation gap (matches a Linux lock PyTCP
  lacked); F3/F4 did not crash or corrupt.
- **For the no-GIL north star:** F2, F3, and F4 were all real
  correctness bugs and are **all now fixed** — the per-interface
  `_lock__multicast` (F2; it also guards the IGMP query-response
  state for F4) and the shared module `_pmtu_lock` (F3), see the
  findings above. **Scope caveat (corrected 2026-05-27):** F1–F4
  closed only the **IPv4 multicast / IGMP-query / PMTU**
  cross-thread state this IGMP-triggered audit reached. A later
  full stack-wide sweep found the no-GIL backlog was **NOT**
  empty. All of `TcpStack` Fast-Open state (T1), MLDv2 query-
  response timer state (M1), IGMP state-change retransmit-timer
  compat-mode read/RMW (M2), ICMP error rate-limiter token bucket
  (I1), per-socket IPv4 source-filter map (U1), per-interface
  address-config + IPv6-multicast lists (N1, copy-on-write +
  write lock), `PacketStats` counters (P1, per-thread shards
  summed on read), **and `TcpSession` timer state (T2, the
  deadline map + coalesced service handle moved onto
  `TcpTimerService` with its own `Lock` as Phase 1 of the TCP
  god-class decomposition)** SHIPPED 2026-05-27. **The no-GIL
  backlog is fully closed.** The authoritative no-GIL ledger +
  correction plan is **`no_gil_thread_safety_audit.md`**. The
  lock-per-structure pattern (SocketTable, RouteTable, Timer
  heap, NeighborCache, per-interface IPv4-ID, the multicast/IGMP
  state, the PMTU maps, the per-socket buffers, the TCP timer
  service) — augmented by copy-on-write (N1) and per-thread
  shards (P1) where the access shape demands them — is the
  standing invariant for any new cross-thread state.

### X2. `accept()` returns blocking sockets

Linux: child socket inherits parent's blocking flag (or
since Linux 2.6.27, flags can be passed to `accept4()`).
PyTCP child sockets returned from `accept()` should
inherit `_blocking` from the parent — verify when C2
lands.

### X3. `listen()` should not implicitly bind

The audit notes "implicitly binds if not bound yet" for
`listen()`. This deviates from POSIX: `listen()` on an
unbound socket returns EINVAL on Linux. Apps that forget
to bind get a confusing error on Linux but a working
ephemeral-port server on PyTCP. Should be tightened to
match Linux semantics for compatibility.

---

## Recommended sequencing

The CRITICAL bucket is interlocked: C1 (fileno) is the
foundation; C2 (setblocking), C3 (selector integration), and
C5 (bufsize) layer on top. Without C1, the rest of the work
is mostly ineffective for async frameworks.

Phase 1 (unblocks event loops):

  1. C1 fileno() + eventfd backing.
  2. C2 setblocking() / getblocking().
  3. C5 bufsize honor in recv.
  4. C3 selector integration + readability/writability
     signaling.
  5. C6 errno-mapped OSError sweep.
  6. C4 getaddrinfo / gethostbyname re-export.

Phase 2 (server compatibility):

  7. H1 SO_REUSEADDR.
  8. H7 SO_SNDBUF / SO_RCVBUF.
  9. H8 SO_LINGER.
  10. H6 IP_TTL / IPV6_UNICAST_HOPS.
  11. H3 IPV6_V6ONLY (and dual-stack via IPv4-mapped).
  12. M1 SO_RCVTIMEO / SO_SNDTIMEO.

Phase 3 (multicast + advanced):

  13. H4 IP_ADD_MEMBERSHIP / IPV6_JOIN_GROUP.
  14. H5 SO_BROADCAST.
  15. H2 SO_REUSEPORT.
  16. M4 IP_TOS / IPV6_TCLASS.
  17. M5 TCP_INFO.

Phase 4 (specialised):

  18. M2 sendmsg / recvmsg.
  19. M3 MSG_OOB.
  20. M6 TCP_USER_TIMEOUT.
  21. M7 TCP_MAXSEG.
  22. M8 MSG_ERRQUEUE.

Phase 5 (polish):

  23-26. L1-L4, plus the X1-X3 cross-cutting items.

The Phase-1 set is the gate — that's what unlocks
"applications written for Linux can be re-imported and
run unchanged" for any non-trivial app.

---

## Suggested next step

Phase 1 is a 4-6 commit work block. The largest piece is
C1+C3 (fileno + selector integration); the rest are
small. Recommend starting with C1 / C2 / C5 as a single
commit chain, then C6 (errno sweep) as a separate
mechanical pass, then C3 (the integration that actually
unblocks asyncio).

Phase 2 gaps are independently shippable — each is a
single setsockopt option wired to existing handler state.

---

## Out of scope (deliberate non-goals per CLAUDE.md North Star)

These are POSIX socket API features that PyTCP will *not*
implement, regardless of compatibility cost:

- `AF_UNIX` Unix-domain sockets — outside the TCP/IP stack
  scope.
- `socketpair()` for Unix domain — same.
- `SCM_RIGHTS` fd-passing — Unix-domain control message,
  not relevant.
- `TCP_MD5SIG` — crypto extension; PyTCP doesn't implement
  per-segment MD5 signatures.
- `IPSEC_*` socket options — IPsec is a North Star
  non-goal.

Apps that depend on these will not work atop PyTCP and
that's intentional.

---

## §100 Shipping status (post-`89da6654`)

### Phase 1 — shipped in full (6/6)

| Gap | Commit    | Summary                                                       |
|-----|-----------|---------------------------------------------------------------|
| C1  | `eb084949`| `fileno()` backed by per-socket `os.eventfd`; RX-side signal/drain wired across UDP, RAW, TCP-data, TCP-accept-queue, EOF/abort/timeout/keep-alive paths. |
| C2  | `31983483`| `setblocking(flag)` / `getblocking()` on the abstract base; non-blocking RX/accept paths raise `BlockingIOError(errno.EAGAIN)`; accepted children inherit the listener's flag. |
| C5  | `7dfe3723`| `recv(bufsize)` honor — UDP/RAW truncate the popped datagram per POSIX SOCK_DGRAM/SOCK_RAW; TCP already forwarded bufsize as byte_count, regression test added. |
| C3  | `b8559d7c`| `selectors.DefaultSelector` integration tests; eventfd is always writable (matches PyTCP's unbounded tx buffer until SO_SNDBUF lands). |
| C6  | `c27182e6`| Errno-mapped `OSError` sweep — `e.errno` set to ECONNREFUSED/ETIMEDOUT/EADDRINUSE/EADDRNOTAVAIL/EAGAIN/EPIPE/EDESTADDRREQ/ENOPROTOOPT/EINVAL across Tcp/Udp/Raw. |
| C4  | `74af6e82`| `getaddrinfo` / `gethostbyname` / `gethostbyname_ex` / `gethostname` / `getnameinfo` / `getfqdn` re-exported from CPython stdlib; INADDR_* constants exposed (L4 bonus). |

### Phase 2 — shipped (5/8) + deferred (3/8)

| Gap | Status | Commit / Rationale |
|-----|--------|---------------------|
| H1 SO_REUSEADDR     | shipped | `705a4617` — bypasses "address already in use" gate when set. |
| H7 SO_SNDBUF/RCVBUF | shipped (storage) | `705a4617` — round-trip via setsockopt; full tx/rx buffer cap enforcement deferred to a focused commit (RCVBUF would also need to drive RCV.WND advertisement). |
| H6 IP_TTL / IPV6_UNICAST_HOPS | shipped | `89da6654` — UDP/RAW threaded. TCP propagation completed 2026-05-28: `TcpSession._transmit_packet` reads `session._socket._effective_ip_ttl()` and passes `ip__ttl` through `send_tcp_packet` → `_phtx_tcp` → `_phtx_ip4`/`_phtx_ip6`. 5 integration tests pin the SYN + data-segment paths for both IPv4 and IPv6. |
| M1 SO_RCVTIMEO/SO_SNDTIMEO | shipped (RCVTIMEO) | `705a4617` — RCVTIMEO supplies recv-default timeout; SNDTIMEO storage-only (UDP/RAW sends today don't block on tx buffer space). |
| M4 IP_TOS / IPV6_TCLASS | shipped (ECN portion) | `89da6654` — full 8-bit DSCP+ECN stored; ECN low-2-bits threaded into outbound packets; full DSCP marking deferred (needs `ip__dscp` kwarg through packet handlers). |
| **H3 IPV6_V6ONLY**  | shipped | Five-phase delivery: Phase 1 (`Ip6Address.is_ipv4_mapped` + `from_ipv4_mapped`) + Phase 2 (`IPV6_V6ONLY` setsockopt) + Phase 3a (bind cross-family conflict) + Phase 3b (IPv4 SYN finds AF_INET6 V6ONLY=0 listener via `listening_socket_ids` extension + RX-loop V6ONLY filter) + Phase 3c (accepted children carry `_dual_stack` presentation flag; family / addresses / getsockname / getpeername / accept return wrap to IPv4-mapped IPv6). |
| **H2 SO_REUSEPORT** | **shipped** | `af536889` (Phase 1 — `SocketTable` cohort storage `dict[SocketId, list[socket]]` + register/unregister + transparent round-robin `get` + writer migration) + `c41aa96b` (Phase 2 — SolSocketOption optname 15 + setsockopt/getsockopt) + `c76fa4f5` (Phase 3 — `is_address_in_use` reuseport group-rule gate) + Phase 4 (TCP/UDP cohort RX-demux integration tests). Demux is round-robin (deliberate Phase-1 simplification of Linux's 4-tuple hash; retransmit-safe via the exact-match-first path). |
| **H8 SO_LINGER**    | **shipped** | 2026-05-29 — `SolSocketOption.SO_LINGER = 13` + bare alias; bytes-valued `setsockopt(SOL_SOCKET, SO_LINGER, struct.pack("@ii", l_onoff, l_linger))` decoded via base `_so_linger_set` (EINVAL on wrong length), `getsockopt` returns the packed `struct linger`. The close-path branch lives in `TcpSocket.close`: `{l_onoff=1, l_linger=0}` → abortive RST via `TcpSession.abort()` (RFC 9293 §3.10.7.4); `{l_onoff=1, l_linger>0}` → graceful FIN then block on the new `TcpSession._event__closed` until CLOSED or the deadline elapses (RX/timer threads advance the FSM in a live stack); linger-off / unset → unchanged graceful close. UDP / RAW store the option as a no-op (Linux parity — linger is meaningless for a connectionless socket). 3 unit + 4 integration tests. |

### Phase 3 — multicast / advanced — all deferred (5/5)

| Gap | Status | Rationale |
|-----|--------|-----------|
| **H4 IPv4 IP_ADD_MEMBERSHIP** | shipped | `f837d017` initial + R3-R6 refinements (`8aa1a257`/`0e5fff39`/`a4b95781`/`5ed73306`/`e9abe066`) + `c98e409c`/`9cc7dfdc` §9 source filters + `752d2bfd` finalizer. Full IGMP host stack (RFC 3376 §7 v1/v2 fallback + §9 SSM). |
| **H4 IPv6 IPV6_JOIN_GROUP** | shipped (any-source join) 2026-05-28 | `IPV6_JOIN_GROUP` (= 20) and `IPV6_LEAVE_GROUP` (= 21) wired through `_ipproto_ipv6_membership(mreq)`; ifindex=0 picks the first IPv6-capable interface; EADDRINUSE on duplicate join, EADDRNOTAVAIL on stale leave, EINVAL on non-multicast or truncated mreq. The existing handler `_assign_ip6_multicast` emits the MLDv2 Report automatically. 8 integration tests. Per-socket source-filter parity (IPV6_ADD/DROP_SOURCE_MEMBERSHIP) is a follow-up that lifts the IPv4 source-filter machinery to IPv6. |
| **H5 SO_BROADCAST** | shipped 2026-05-28 | Storage shipped `705a4617`; EACCES gate added 2026-05-28 across `UdpSocket.send` and `UdpSocket.sendto` when the destination is the IPv4 limited broadcast `255.255.255.255` and `_so_broadcast` is False. Stack-internal audit identified one consumer (DHCPv4 client `_open_client_socket`) which now sets the flag explicitly at construction so the lease acquisition path stays clean. 4 integration tests (with-flag, without-flag, unicast not gated, connected-send broadcast). |
| **H2 SO_REUSEPORT** | (see Phase 2)    |  |
| **M4 IP_TOS / IPV6_TCLASS** (DSCP portion) | shipped 2026-05-29 | DSCP (high 6 bits) now marked on every socket-originated packet. New `socket._effective_ip_dscp()` (mirror of `_effective_ip_ecn`); an `ip__dscp` / `ip4__dscp` / `ip6__dscp` kwarg (default 0) threads through the TX handler chain (facade + per-proto sub-handler) into the IPv4 / IPv6 assemblers (which already carried a `dscp` field). Wired from UDP `send`/`sendto`, RAW `send`/`sendto`, and the TCP transmit path (SYN/data/ACK/FIN + keepalive + SYN-SENT reject RST). TCP ECN stays RFC-3168 stack-driven; DSCP is orthogonal. UDP/TCP wire integration tests v4+v6; RAW + accessor unit tests. (Fragmentation DSCP/ECN preservation is a follow-up — see `socket_dscp_marking.md` §0.1 / Phase B.) |
| **M5 TCP_INFO**     | shipped  | 240-byte Linux 5.5 layout packed by `pytcp/socket/tcp__info.py::pack_tcp_info` from `TcpSession`; surfaced via `getsockopt(IPPROTO_TCP, TCP_INFO)`. 9 integration tests. |

### Phase 4 — specialised — all deferred (5/5)

| Gap | Rationale |
|-----|-----------|
| **M2 sendmsg / recvmsg**  | **shipped.** `recvmsg` landed with the IP_RECVERR / cmsg work (UDP/TCP, `MSG_ERRQUEUE` + IP_OPTIONS / IP_TOS / IPV6_TCLASS cmsgs); `sendmsg` shipped 2026-05-29 across the base stub + `UdpSocket` / `TcpSocket` / `RawSocket` (+ `RawSocket.recvmsg`). No byte-level CMSG codec is needed — stdlib `recvmsg`/`sendmsg` exchange ancillary data as parsed `(level, type, data)` tuples, which PyTCP already uses. `sendmsg` concatenates the scatter-gather `buffers` into one payload and reuses the existing `send` / `sendto` paths; `ancdata` is structurally validated then ignored Phase-1 (Linux silently ignores unhandled cmsgs; per-send IP_TOS / IP_TTL / IP_PKTINFO honouring is a marked `# Phase 2:` follow-up). TCP `sendmsg` rejects a non-None `address` with `EISCONN`. 11 unit + 1 integration test. |
| **M3 MSG_OOB / SO_OOBINLINE** | shipped (design-aligned 2026-05-28). PyTCP's RFC 6093 adherence record (`docs/rfc/tcp/rfc6093__urgent_mechanism/adherence.md` §6) documents the universal-inline design choice: PyTCP delivers ALL inbound data inline regardless of the URG flag — the `SO_OOBINLINE=1` posture RFC 6093 §6 recommends. This commit reconciles the audit-side wording (which previously described M3 as "FSM URG handling exists but isn't surfaced"; that framing was misleading) and adds the Linux constants applications look for: `MSG_OOB = 1` on `MsgFlag`, `SO_OOBINLINE = 10` on `SolSocketOption`. `setsockopt(SOL_SOCKET, SO_OOBINLINE, 1)` is accepted as a no-op (confirms the universal-inline posture); `setsockopt(..., 0)` raises `OSError(EINVAL)` with a message naming RFC 6093 §6 since opting INTO out-of-band delivery is not supported. `getsockopt(SOL_SOCKET, SO_OOBINLINE)` always returns 1. 5 tests. |
| **M6 TCP_USER_TIMEOUT**   | shipped — `TcpSession._user_timeout_ms` propagated from `TcpSocket._tcp_user_timeout`; R2-abort site computes `max(1, _user_timeout_ms // current_rto_ms)` as the approximated count budget. 5 unit + 2 integration tests. |
| **M7 TCP_MAXSEG**         | shipped — `TcpSession._maxseg_override` propagated from `TcpSocket._tcp_maxseg`; SYN-options assembly in `session/tcp__session__tx.py` clamps to `min(rcv_mss, 0xFFFF, _maxseg_override)`. Validator rejects below Linux `TCP_MIN_MSS=88`. 6 unit + 3 integration tests. |
| **M8 MSG_ERRQUEUE / IP_RECVERR** | **shipped.** Per-socket error queue (`pytcp/socket/error_queue.py`) + `notify_*` paths refactored to enqueue rather than inline-raise; `recvmsg(MSG_ERRQUEUE)` on UDP / TCP dequeues an `IP_RECVERR` / `IPV6_RECVERR` cmsg via `pack_sock_extended_err`. Integration tests: `test__tcp__session__ip_recverr.py`, `test__udp__socket_api.py`, `test__udp__ip_options.py`. |

### Phase 5 — polish (1/4 shipped + 3 deferred)

| Gap | Status | Rationale |
|-----|--------|-----------|
| **L1 dup() / dup2()**     | deferred | Depends on the per-socket eventfd's OS semantics — `os.dup(eventfd)` shares the kernel object, but we'd also need to share the Python-level rx queue / accept queue, which doesn't fit the BSD `dup` model cleanly. |
| **L2 socketpair()**       | deferred (out-of-scope) | Mostly Unix-domain; outside North-Star. |
| **L3 hostname in bind/connect** | deferred | Apps should call `getaddrinfo` first and pass a numeric IP; the C4 re-export already unblocks this idiom. Auto-resolve in bind/connect is a SHOULD, not a MUST. |
| **L4 INADDR_* constants** | shipped | `74af6e82` exposes INADDR_ANY / INADDR_BROADCAST / INADDR_LOOPBACK / INADDR_NONE. |

### Cross-cutting (X1-X3)

| Item | Status | Note |
|------|--------|------|
| **X1 stack-thread safety audit** | performed + closed (2026-05-27); **no-GIL backlog fully closed (2026-05-27)** | See §X1. All findings fixed. **F1**: rx-thread iteration of `_igmp_group_query__pending` racing the timer-thread `pop` (snapshot fix). **F2**: app-vs-app multicast-membership RMW (per-interface `_lock__multicast`). **F3**: `pmtu_cache`/`pmtu_state` (shared module `_pmtu_lock` + guarded accessors). **F4**: IGMP query-response state — scalars + suppressed set + per-group pending map (folded under `_lock__multicast`). **Full stack-wide no-GIL backlog (tracked in `no_gil_thread_safety_audit.md`) fully closed: T1 TCP-TFO + M1 MLDv2-query + M2 IGMP-retransmit + I1 ICMP-rate-limiter + U1 per-socket-source-filter + N1 address-config-COW + P1 PacketStats-per-thread-shards + T2 TcpSession-timer-service (TCP decomposition Phase 1) — all SHIPPED 2026-05-27.** Lock-per-structure (or copy-on-write / per-thread shards) is the standing invariant. **Post-close reviews** of new cross-thread state land in `no_gil_thread_safety_audit.md` §5: the socket Track B additions (2026-05-29) — `TcpSession._event__closed` (self-synchronizing `threading.Event`) and `TcpSocket._so_linger` (app-thread-only single-reference) — were reviewed and need no new lock. |
| **X2 accept() inheritance**       | shipped | `31983483` — accepted children inherit the listener's `_blocking` flag both at the listener-fork pivot and at `accept()` pop time. |
| **X3 listen() implicit bind**     | unchanged | `listen()` on an unbound socket still picks an ephemeral port instead of returning EINVAL; tightening would break existing PyTCP examples that don't bind first. Punt to a hygiene commit. |

### Suggested resume points

If resuming this work, prioritise (rough order):

  1. ~~**M5 TCP_INFO**~~ — SHIPPED 2026-05-28.
  2. ~~**M6 TCP_USER_TIMEOUT + M7 TCP_MAXSEG**~~ — SHIPPED 2026-05-28.
  3. ~~**H3 IPV6_V6ONLY + IPv4-mapped IPv6**~~ — SHIPPED 2026-05-28. (Originally: high-value (most
     servers expect dual-stack); substantial refactor in
     `net_addr.Ip6Address` + dual-stack listener pivot.
  4. ~~**H4 IPv6 IPV6_JOIN_GROUP**~~ — SHIPPED 2026-05-28 (any-source
     join). Per-socket source filters (IPV6_ADD/DROP_SOURCE_MEMBERSHIP)
     remain — lift the IPv4 source-filter machinery if a real consumer
     needs it.
  5. **H2 SO_REUSEPORT** — `stack.sockets` multi-listener refactor.
  6. **M2 sendmsg/recvmsg + M8 MSG_ERRQUEUE** — control-message
     layer; one focused work block.

---

## §101 Stack-ring audit findings (post-`bb2a13fa`)

A separate audit of the RX / TX ring path landed in two waves. The
**first wave** added focused MTU / shutdown / observability fixes
(`3ae9087e`, `fabbe61a`, `502d4143`, `2dc796c8`) and the
benchmark + profiling harness (`fe43a785`, `c6882e5c`). The **second
wave** rewrote the ring data plane after a real-wire hping3 flood
exposed the `queue.Queue` `Lock + Condition` pair as the bottleneck
under producer/consumer load: drains converted to inner-loop drains
(`f0ad0076`, `d3fbccfb`), `queue.Queue` replaced by `collections.deque`
+ `os.eventfd` on both sides (`f207f2dd`, `0625e2ed`), defensive
`os.read` OSError handling shipped (`e1d77217`), and the ring drop
counters were folded into the shared `PacketStats` dataclasses so the
unified-stats snapshot covers them in one pass (`bb2a13fa`).

### Real-wire delivered throughput

Measured against `hping3 --flood --icmp -d 1472 <stack-ip>` on a TAP
interface, kernel TX `txqueuelen=1000`, single CPU, `PYTHONOPTIMIZE=1`:

| Stage | Echo-reply pps | TX qsize | TX queue-full drops |
|---|---|---|---|
| Pre-refactor (`queue.Queue`, outer-only drain) | ~3,800 | pegged at 1000 | thousands per 5s |
| Post-TX inner-drain | ~6,800 | 0 ↔ 1000 oscillation | hundreds per 5s |
| Post-deque + eventfd (TX) | ~6,900 | 0 — 13 | zero |
| Post-deque + eventfd (RX, current) | **~6,965** | 0 — 13 | zero |

The 78% throughput improvement (`3,800 → 6,965 pps`) and the
collapse of TX queue-full drops to zero validate the refactor.
The remaining ceiling at ~7k pps is **consumer-side and GIL-bound**
(packet handler at 99-119% CPU), not ring-side.

### Shipped — ring-side punch list (closed)

| # | Item | Commit | Notes |
|---|---|---|---|
| 1 | RX read buffer scales with MTU | `3ae9087e` | Jumbo / jumbogram support, no fixed 1518 ceiling. |
| 2 | RX selector closed on stop | `fabbe61a` | No epoll fd leak across `stack.stop()` cycles. |
| 3 | Shutdown order: timer → TX ring | `2dc796c8` | Timer-driven RTO/persist/keep-alive callbacks cannot enqueue to a stopped TX ring. |
| 4 | Drop counters (queue-full + os-error) | `502d4143` | Both rings, both error classes. |
| 5 | RX inner-drain (drain all per wake-up) | `f0ad0076` | +1.9% on synthetic bench, prevents loss-on-burst once consumer speeds up. |
| 6 | TX inner-drain (drain all per wake-up) | `d3fbccfb` | First wave that closed the real-wire TX qsize oscillation. |
| 7 | TX `queue.Queue` → deque + eventfd | `f207f2dd` | Replaces `Lock + Condition` per-op cost with deque atomics + single eventfd signal. Module-level `_TX_PROTO_DISPATCH: dict[type, ...]` for O(1) protocol resolution; `isinstance` fallback only for `MagicMock(spec=...)` fixtures. |
| 8 | RX `queue.Queue` → deque + eventfd | `0625e2ed` | Same shape as TX. Fast path: deque non-empty; slow path: `select` on the eventfd. |
| 9 | RX defensive OSError on `os.read` | `e1d77217` | Drains the eventfd notification even if the kernel read fails (ENXIO on shutdown race), increments `rx_ring__os_error__drop`. |
| 10 | Ring counters wired into `PacketStats` | `bb2a13fa` | `tx_ring__queue_full__drop`, `tx_ring__os_error__drop`, `rx_ring__queue_full__drop`, `rx_ring__os_error__drop` are now fields on the shared dataclasses; `examples/stack.py` snapshots via generic `dataclasses.fields(stats)` iteration so any new counter shows up without curated lists. |

Tests: every item above has unit-test coverage (`test__stack__rx_ring.py`,
`test__stack__tx_ring.py`, `test__lib__packet_stats.py`,
`test__stack__init.py`). The dispatch fast-path now also has structural
+ behavioural tests pinning the `type()`-keyed dict (the `MagicMock`-
based tests would not have caught a regression where a key was replaced
with a string or removed). Stack-level integration tests pin the
shared-`PacketStats` invariant — same instance threaded into both
rings + the packet handler.

### Acceptable as-is (post-refactor data)

| Item | Status | Rationale |
|---|---|---|
| TUN protocol-family hint dispatch | Acceptable | Only refactor if VLAN-tagged TAP / TUN_PI variants land. The fast-path dict already covers Ethernet II, 802.3, IPv4, IPv6, IPv4-frag — that is the production set. |
| Cosmetic `_stop` symmetry between rings | Acceptable | RX has a selector to close, TX uses `select.select` directly. Asymmetric but correct; no leak in either direction. |
| Kernel TAP `txqueuelen` ceiling | Out of ring scope | A separate flood-test data point: `ip -s link show tap7` showed 96.3% kernel-side TX drops at one stage. The fix is `ip link set tap7 txqueuelen 10000` on the host, not stack code. Document on the benchmark page if the GIL ceiling lifts. |

### Real bottleneck — consumer-side dispatch

The post-refactor flood data points the next throughput frontier
firmly **outside** the rings: `packet_handler` thread per-packet
work (parse → dispatch → emit). Suggested investigations:

1. Profile under a real-wire flood (`PYTCP_STATS_INTERVAL=1
   PYTHONOPTIMIZE=1 make benchmark` + `cProfile`) — find which
   protocol handler dominates.
2. The 884 `__debug__ and log(...)` call sites add ~50% overhead
   when not stripped. Always run benchmarks with `-O` /
   `PYTHONOPTIMIZE=1` (`make benchmark` does this; `make run`
   does not).
3. The ICMP echo-reply path round-trips through ARP cache lookup
   + Ethernet-header rewrite — verify the ARP cache hit is fast.
4. Free-threaded CPython 3.13t / 3.14t lifts the GIL ceiling.
   The deque + eventfd patterns shipped here are already
   GIL-free-friendly — no `Lock` contention to migrate. A simple
   `python3.14t make benchmark` smoke test would quantify.
5. AF_PACKET TPACKET_V3 mmap rings are the kernel-bypass path
   for sub-µs RX; explicitly **out of scope** per the project
   North Star (kernel-bypass rejected by Phase 1 + Phase 2
   constraints).

These are tracked here so future audits know the rings are not the
current bottleneck and the next investment is in the consumer
thread or the interpreter — not the ring data plane.

---

## §99 Resume prompt (paste verbatim after `/compact`)

```
I'm resuming PyTCP socket-layer Linux-parity work from a
context-compacted state. Phase 1 is fully shipped (`eb084949`
through `74af6e82`) and Phase 2 is partially shipped (commits
`705a4617`, `89da6654`); the remaining deferred items are listed
in the audit doc's §100 "Shipping status" ledger.

Read these in order before any code:

  1. docs/refactor/socket_linux_parity_audit.md — read §100
     "Shipping status" first to see what's done and what's
     deferred-with-rationale, then the original tier-by-tier
     classification for context.
  2. CLAUDE.md (Project North Star: Linux-stack parity;
     deliberate-skip categories)
  3. .claude/rules/feature_implementation.md (commit
     discipline; tests-first; Linux-as-tiebreaker rule)
  4. .claude/rules/unit_testing.md (test-authoring rule;
     §7.2 self-audit script blocks every commit)
  5. `.claude/rules/source_files.md` / `net_proto.md` / `pytcp.md` (source-authoring rule)
  6. The current packages/pytcp/pytcp/socket/ tree

After reading, confirm you understand:

  - Phase 1 (CRITICAL) is fully shipped. Phase 2 (HIGH) is
    mostly shipped except H3 IPV6_V6ONLY, H2 SO_REUSEPORT,
    H8 SO_LINGER (substantial refactors deferred per §100).
  - Suggested resume order (per §100 "Suggested resume
    points"): M5 TCP_INFO → M6 TCP_USER_TIMEOUT + M7
    TCP_MAXSEG → H3 IPV6_V6ONLY → H4 IPv6 IPV6_JOIN_GROUP
    (IPv4 half SHIPPED via IGMP track) → H2 SO_REUSEPORT
    → M2 sendmsg/recvmsg + M8 MSG_ERRQUEUE.
  - Out-of-scope per North Star: AF_UNIX, TCP_MD5SIG,
    IPsec socket options, SCM_RIGHTS, socketpair (Unix
    domain). Don't add these even if asked.

Branch: PyTCP_3_0_6

Then ask the user which item to start with (default to
M5 TCP_INFO if they say "go" or "next"). Tests-first per
CLAUDE.md MUST.

Do NOT push without explicit user request. Commit after
each item; user pushes when ready.
```
