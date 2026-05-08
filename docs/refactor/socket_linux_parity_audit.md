# Socket-Layer Linux Parity Audit

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

### H2. No `SO_REUSEPORT`

**Linux:** Multiple sockets on the same (addr, port) for
load balancing across worker threads/processes. Linux's
SO_REUSEPORT hashes incoming connections to one of the
listening sockets.

**PyTCP:** Single socket per (addr, port) tuple by
construction (`stack.sockets` is a flat dict).

**Sketch:** Convert `stack.sockets` to a multi-listener
structure for ports that opted into REUSEPORT. Inbound
connection demux picks one listener (round-robin or hash).
This is a larger refactor.

### H3. No `IPV6_V6ONLY`

**Linux:** Default for Python is `IPV6_V6ONLY=1` (IPv6
sockets accept only IPv6 peers). Setting it to 0 makes the
socket accept IPv4-mapped peers (`::ffff:1.2.3.4`) — dual-
stack mode.

**PyTCP:** No dual-stack at all. AF_INET6 sockets only
accept IPv6 peers. Apps that bind one socket to `[::]:80`
expecting to serve both IPv4 and IPv6 clients (very common)
get only IPv6.

**Sketch:** Two pieces. (a) Implement IPv4-mapped IPv6
addresses (`::ffff:0:0/96`) in `Ip6Address`. (b) When an
AF_INET6 socket has V6ONLY=0, register both IPv4 and IPv6
listeners under the hood and translate inbound IPv4
connections into IPv4-mapped peer addresses on accept().

### H4. No multicast group membership (IP_ADD_MEMBERSHIP / IPV6_JOIN_GROUP)

**Linux:** UDP multicast receivers MUST call
`setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, struct ip_mreq)`
to instruct the kernel to listen on the multicast address.

**PyTCP:** No setsockopt for these. Multicast receivers
can't subscribe to groups via the normal socket API. (The
stack does manage MLDv2 reports for some multicast
addresses, but applications have no API to drive
membership.)

**Sketch:** Map IP_ADD_MEMBERSHIP / IPV6_JOIN_GROUP to
`stack.packet_handler._ip4/6_multicast` mutation + (for v6)
trigger an outbound MLDv2 Report. Conversely
IP_DROP_MEMBERSHIP / IPV6_LEAVE_GROUP removes from the list
+ MLDv2 LEAVE.

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

### M5. No `TCP_INFO`

**Linux:** `getsockopt(IPPROTO_TCP, TCP_INFO, struct
tcp_info)` returns ~50 fields of connection statistics —
RTT, RTO, cwnd, ssthresh, retransmits, etc.

**PyTCP:** A `status()` method returns a `TcpStatus`
dataclass with similar info, but it's not the standard
`TCP_INFO` getsockopt API.

**Sketch:** Wrap `status()` output into a serialized
`tcp_info`-shaped struct; expose via `getsockopt(IPPROTO_TCP,
TCP_INFO)` in addition to the current `status()` method.

### M6. No `TCP_USER_TIMEOUT`

**Linux:** Per-connection abort-after-no-ACK timeout
(replaces the RFC 1122 default ~100 s).

**PyTCP:** Stack-default RFC 6298 timeout applies; no
per-socket override.

**Sketch:** Per-session override on `TcpSession._rto_state`
that the R2 abort path consults.

### M7. No `TCP_MAXSEG`

**Linux:** Clamp / read the negotiated MSS. Some apps need
to verify the path MSS.

**PyTCP:** MSS visible via `status().snd_mss` (read-only);
no setsockopt to clamp.

**Sketch:** Per-session MSS clamp consulted during
SYN-options assembly.

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

### X1. Stack thread separation

PyTCP's stack runs in its own thread; sockets are accessed
from application threads. Thread-safety of the socket-layer
data structures (rx buffers, accept queues) needs an
explicit audit. Symptoms of a missing audit would be rare
race conditions under concurrent recv + ICMP error
delivery, or accept + concurrent close.

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

## §99 Resume prompt (paste verbatim after `/compact`)

```
I'm resuming PyTCP socket-layer Linux-parity work from a
context-compacted state. The full audit lives at
`docs/refactor/socket_linux_parity_audit.md` (committed at
`ccae024c`); it catalogues 26 deficiencies in pytcp.socket
classified CRITICAL / HIGH / MEDIUM / LOW against the
POSIX-2017 + Linux extensions baseline.

Read these in order before any code:

  1. docs/refactor/socket_linux_parity_audit.md (the full
     deficiency report — sections by tier, plus the
     "Recommended sequencing" §99 phase plan)
  2. CLAUDE.md (Project North Star: applications written
     for Linux should re-import against pytcp.socket and
     work unchanged; deliberate-skip categories)
  3. .claude/rules/feature_implementation.md (commit
     discipline; tests-first; Linux-as-tiebreaker rule)
  4. .claude/rules/unit_tests.md (test-authoring rule;
     §7.2 self-audit script blocks every commit)
  5. .claude/rules/coding_style.md (source-authoring rule)
  6. The current pytcp/socket/ tree to see what's there:
     - pytcp/socket/__init__.py (factory + enums + base)
     - pytcp/socket/tcp__socket.py
     - pytcp/socket/udp__socket.py
     - pytcp/socket/raw__socket.py
     - pytcp/socket/socket_id.py

After reading, confirm you understand:

  - The CRITICAL bucket is interlocked: C1 (fileno + eventfd
    backing) is the foundation; C2 (setblocking), C3
    (selector integration), C5 (bufsize) layer on top.
    Without C1, the other CRITICAL items are mostly
    ineffective for async frameworks (asyncio / trio /
    twisted).
  - Phase 1 (the work block to start with) is C1 → C2 →
    C5 → C3 → C6 (errno sweep) → C4 (getaddrinfo re-
    export from CPython stdlib). Each commit lands tests-
    first; the §7.2 audit blocks every commit.
  - Out-of-scope per North Star: AF_UNIX, TCP_MD5SIG,
    IPsec socket options. Don't add these even if asked.

Branch: PyTCP_3_0__pre_release

Then ask the user which Phase-1 commit to start with. If
they say "go" or "next", start with C1 (fileno() +
eventfd backing). Tests-first per CLAUDE.md MUST.

Do NOT push without explicit user request. Commit after
each phase; user pushes when ready.
```
