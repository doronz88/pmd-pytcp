# Kernel / Userspace Process Separation Plan

| Field      | Value                                                                 |
|------------|-----------------------------------------------------------------------|
| Status     | **ACTIVE — Phases 0, 1 & 2 complete; Phase 3 UDP datagram plane complete (out-of-process UDP echo passing); Phase-3 raw/AF_PACKET families + recvmsg cmsg ancillary remain.** Created 2026-05-31 on `PyTCP_3_0_7`. |
| Branch     | `PyTCP_3_0_7`                                                          |
| Motivation | Cut a real process boundary so the stack runs as a daemon and client processes use it from other processes — the North Star Phase-3 kernel/userspace boundary. Independent of the router/forwarding track. |

---

## 1. Context

PyTCP is a **feature-complete host stack** today (TCP/UDP/raw/AF_PACKET
sockets, the seven control APIs, IGMP/MLD, DHCPv4/v6, ND, PMTUD). Its
North Star Phase 3 is the kernel/userspace boundary: "PyTCP becomes a
self-contained 'kernel' exposing a small Linux-mirrored set of
user-facing APIs. Consumers interact with PyTCP only through these
surfaces, the way a Linux process talks to its kernel."

Today every consumer — examples, tests, future tools — must `import
pytcp`, call `stack.init()` / `add_interface()` / `stack.start()`, and
open sockets **in the same process as the stack**. That co-residence of
a socket example with the "kernel" is the awkwardness this track fixes.
It is a **host-stack** improvement, **independent of forwarding** —
nothing here depends on the router plane, in either direction.

**The stack is unusually ready for the cut** (verified):

- **Daemon shape exists.** `stack.init()` already supports a
  zero-interface resting state, and `examples/stack.py` is already a
  standalone Click runner (`make run`) that boots and idles.
- **Sockets are already OS-selectable.** Every socket backs `fileno()`
  with a real `os.eventfd` (`socket/__init__.py`), signalled readable by
  the RX threads (`_signal_readable` / `_drain_readable`);
  `select` / `poll` / `epoll` / `selectors` already work on a PyTCP
  socket in-process. The RX/TX rings already use eventfd + `selectors`.
  The hard "socket readiness as a real fd" problem is solved.
- **Control APIs already return copy-by-value snapshots** — already an
  RPC-shaped surface (route / neighbor / link / address / membership /
  sysctl + introspection).
- **No existing cross-process IPC** (no `socketpair` / `SCM_RIGHTS` /
  `AF_UNIX`) — greenfield, no legacy IPC to reconcile.

**Primary pain to solve (confirmed with the user):** socket/data
examples. So the data-plane boundary (the hard half) is in scope, not
just control-plane.

## 2. Package-placement decision (settled 2026-05-31)

The IPC layer lives **inside `pytcp`**, not as a fourth PyPI dist:

- `pytcp/ipc/` — the wire-protocol codec, the AF_UNIX transport, the
  server `Subsystem`, the per-socket bridge pump.
- `pytcp/client/` — the client ABI mirror (socket-class shims + control
  API mirror).

Rationale: the **server half is irreducibly coupled to the stack** (it
imports the real socket objects, the seven control APIs, the
`Subsystem` base, the eventfd `fileno()`) — it cannot live in a package
`pytcp` depends on without a cycle. A `net_ipc` peer of
`net_addr` / `net_proto` (which are deliberately bottom-of-the-graph,
stack-independent) does not fit. Only the **codec** could be standalone,
and a truly slim stack-free client would also need the socket-ABI enums
factored out of `pytcp.socket` first — a bigger refactor than this
additive plan. A 4th lockstep dist also adds real release overhead
(publish.yml OIDC job, PyPI Environment, version pinning, editable-
install ordering).

**Extraction-ready constraint:** the **codec core** of `pytcp/ipc/` (the
framing, the request/response envelope, the op-tag enums, the typed arg
encode/decode) MUST be authored using only `net_addr` + `net_proto` +
stdlib, reaching into **no** pytcp stack internals
(`socket` / `protocols` / `runtime` / `stack`). The **server
`Subsystem`** and the **bridge pump** necessarily import the stack and
stay pytcp-resident. If a stack-free client consumer ever appears,
lifting the codec core into a standalone `PyTCP-net_ipc` dist (a peer
above `net_proto`) is then a mechanical extraction rather than a
rewrite.

## 3. Architecture

The design keeps the existing in-process stack **completely unchanged**
and wraps it with an IPC frontend. Two roles:

- **Stack daemon** = a normal in-process PyTCP stack + an IPC server. It
  owns the TAP/TUN fd, runs all protocol threads, the FIB, caches, and
  the real `pytcp.socket` objects. It listens on an **AF_UNIX stream
  socket** (e.g. `$XDG_RUNTIME_DIR/pytcp.sock`).
- **Client library** = a thin shim (`pytcp.client`) that mirrors the
  socket API surface + the control APIs (same method names, signatures,
  and return types as the in-process classes) and marshals each call to
  the daemon. A client is a separate OS process.

**Purely additive.** The protocol stack, the four socket classes, and
the seven control APIs are not modified — they are the daemon-side
*implementation*. The existing ~12k in-process tests and the
integration harness keep working untouched.

### 3.1 The two channels

**1. Control channel (the "syscall" / netlink RPC).** One AF_UNIX
stream connection per client process. A small length-prefixed binary
wire protocol (authored net_proto-style with `struct` codecs — zero
deps) carries request/response for every control op: the socket
syscalls (`socket` / `bind` / `listen` / `accept` / `connect` /
`setsockopt` / `getsockopt` / `close` / `shutdown` / `getsockname` /
`getpeername`) **and** the six control APIs + introspection
(`route.*`, `neighbor.*`, `link.*`, `address.*`, `membership.*`,
`sysctl[*]`). Low-frequency, coarse — the netlink half.

**2. Per-socket data channel (the high-throughput half).** When a
client opens (or accepts) a socket, the daemon creates a
`socket.socketpair(AF_UNIX, …)` and **passes one end to the client via
`SCM_RIGHTS`** over the control channel. The client's socket fd **is**
that real kernel socketpair end — so `select` / `poll` / `epoll` /
`asyncio` work natively on the client with zero PyTCP-specific
machinery.

- **TCP** → `SOCK_STREAM` socketpair: client `os.read` / `os.write` the
  fd; the daemon runs a bridge pump that shuttles bytes between the
  socketpair and the internal `TcpSession` rx/tx buffers, selecting on
  the internal socket's existing `fileno()` eventfd for readiness.
- **UDP / raw / AF_PACKET** → `SOCK_DGRAM` socketpair: each datagram
  framed `{sockaddr, cmsg-blob, payload}` so message boundaries +
  `recvfrom` / `recvmsg` address / ancillary data survive.

**Why fd-passing (not pure RPC for data):** each client socket gets its
own native selectable fd (the whole point for the user's socket
examples), and the socketpair's kernel buffer **is** the socket buffer
— backpressure falls out for free (client stops reading → daemon bridge
stops draining the internal socket → TCP rwnd closes; and symmetrically
on TX). No custom shared-memory ring; the kernel moves the bytes.

### 3.2 How it maps to the North Star

The control-channel `socket()` request **is** the user/kernel
transition the North Star names (the `socket.__new__` dispatch, now
across a real process boundary). Client disconnect = process death =
the daemon closes that client's sockets, exactly like a kernel reaping
fds on `exit(2)`.

## 4. Phasing (each phase tests-first, one logical unit per commit)

### Phase 0 — IPC transport + wire-protocol scaffolding
New `pytcp/ipc/` package: the length-prefixed framing codec (frame
read/write over a stream socket; request/response envelope; op-tag
enum), the AF_UNIX **server** (a `Subsystem` that listens, accepts
client connections, owns the per-client dispatch loop) and the
**client connector**. End-to-end deliverable: client connects, sends a
`PING`, daemon replies `PONG`. Tests-first: net_proto-style unit tests
on the framing codec + envelope; an integration test that runs the
server in a daemon thread + a client over a real AF_UNIX socket.

### Phase 1 — Control-plane RPC (the netlink half)
Marshal the six control APIs + introspection over the control channel
(no fd passing, pure request/response): `route.*`, `neighbor.*`,
`link.*`, `address.*`, `membership.*`, `sysctl[*]`. A
`pytcp.client.stack` surface mirroring the same method signatures,
returning the same frozen snapshots (re-decoded client-side).
Deliverable: an out-of-process config tool can add a route / read the
neighbor cache against a running daemon. Tests-first: client RPC →
daemon mutates real stack state → client introspection reflects it.

### Phase 2 — TCP socket syscall RPC + data-channel fd passing
The syscall half for stream sockets: `socket` / `bind` / `connect` /
`setsockopt` / `getsockopt` / `close` / `shutdown` over the control
channel; per-socket `SOCK_STREAM` socketpair handed back via
`SCM_RIGHTS`; the daemon-side **bridge pump** (a selector loop reusing
the internal socket's existing eventfd `fileno()`) shuttling bytes both
ways. Client `TcpSocket` shim whose `fileno()` is the socketpair fd and
whose `send` / `recv` are `os.write` / `os.read`. Deliverable: an
out-of-process TCP client connects + echoes through the daemon.
Tests-first: daemon-thread + client integration driving the TAP wire on
one side and the client socket on the other.

### Phase 3 — Datagram sockets (UDP / raw / AF_PACKET)
`SOCK_DGRAM` socketpair + the `{sockaddr, cmsg, payload}` framing so
`sendto` / `recvfrom` / `sendmsg` / `recvmsg` and ancillary data
(IP_TTL, IP_RECVERR error queue, etc.) round-trip. `listen`-less;
bind/connect via control RPC. Tests-first: out-of-process UDP echo + a
`recvmsg` cmsg case.

### Phase 4 — `accept()` fd passing (passive open)
`accept()` is a control RPC; on a completed passive open the daemon
spawns a fresh socketpair + bridge for the child internal socket
(already created by the TCP FSM) and returns the new fd via
`SCM_RIGHTS` in the accept response — the client gets a real fd for the
accepted connection. Tests-first: out-of-process listening server
accepts an inbound SYN driven on the TAP wire.

### Phase 5 — Examples migration (the user-visible payoff)
Reshape `examples/` so socket examples are **clients** against a
running daemon, not in-process stack bootstrappers. `make run` becomes
"start the daemon"; the TCP/UDP echo client/server examples connect via
`pytcp.client`. Keep one in-process example for the embedded use-case.
Deliverable: a socket example that no longer imports/boots the stack.

### Phase 6 — Daemon lifecycle + ergonomics
A daemon entry point (`python -m pytcp.daemon` / a `pytcpd` console
script), socket-path config + `$XDG_RUNTIME_DIR` default, clean
client-disconnect teardown (reap the client's sockets), startup
readiness signalling, and a `mock__`-style test affordance so the
daemon can be stood up in a harness. Doc + README refresh.

## 5. Files (by area — new code is additive, stack internals untouched)

- **New `pytcp/ipc/`:** wire-protocol framing + op codecs (net_proto-
  style `struct` codecs), the AF_UNIX server `Subsystem`, the client
  connector, the per-socket bridge pump. `net_addr` + stdlib only; no
  reach into stack internals (extraction-ready per §2).
- **New `pytcp/client/`:** `socket` API mirror (the four socket-class
  shims) + `stack` control-API mirror, marshalling to the daemon. Same
  method signatures as the in-process surfaces.
- **New daemon entry point:** `pytcp/daemon/__main__.py` (or reuse/
  extend `examples/stack.py`'s runner) wiring `stack.init/start` + the
  IPC server `Subsystem`.
- **Unchanged:** `pytcp/socket/*`, `pytcp/protocols/*`,
  `pytcp/runtime/*`, `pytcp/stack/{route,link,address,neighbor,
  membership,sysctl}.py` — daemon-side implementation, not modified.
  (If a tiny hook is needed to let the bridge observe an internal
  socket's readiness, prefer reusing the existing `fileno()` eventfd
  over adding surface.)
- **Examples:** `examples/*` socket cases reshaped to clients (Phase 5).

## 6. Verification

- **Codec layer:** net_proto-style unit tests (round-trip every op
  request/response frame; boundary / oversize / short-frame integrity).
- **IPC integration:** a harness that runs the daemon in a **thread**
  behind a real AF_UNIX socket + a client in the test thread —
  exercises the genuine `socketpair` / `SCM_RIGHTS` / framing path
  without subprocess flakiness, while still driving the TAP wire via the
  existing `TcpTestCase` / `NetworkTestCase` mocks on the daemon side.
  One end-to-end **subprocess** smoke test (real two-process) per socket
  family as the honest cross-process pin.
- **Regression:** the existing ~12k in-process tests stay green
  untouched (the IPC layer is additive; the in-process `import
  pytcp.socket` path is unchanged).
- **Per commit:** `make lint` clean; §7.2 docstring audit clean on
  touched test files; full `make test` (whole-suite, single process)
  green.
- **End-to-end payoff pin:** the Phase-5 migrated socket example runs as
  a separate process against a `make run` daemon.
- **No push** unless explicitly asked. Commit trailer:
  `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## 7. Key design decisions (and why)

- **Additive IPC frontend, zero stack rewrite.** The daemon is a normal
  in-process stack; the client is an ABI mirror. Keeps 12k tests green,
  keeps the integration harness in-process, de-risks the whole project.
- **IPC inside `pytcp`, not a 4th dist** (§2), but `pytcp/ipc/`
  authored extraction-ready (net_addr + stdlib only, no stack reach-in).
- **fd-passing (`SCM_RIGHTS` socketpair) for the data path**, not
  per-byte RPC — native selectable fds + free backpressure (socketpair
  buffer = socket buffer). The kernel moves the data bytes; only control
  ops are marshalled.
- **Reuse the existing eventfd `fileno()`** as the daemon-side bridge
  readiness signal — no new wakeup primitive.
- **AF_UNIX local only** (Linux, single host) — matches the "kernel on
  this machine" model; network-transparent RPC is out of scope.

## 8. Out of scope (documented, not built)

- **Shared-memory zero-copy rings.** The AF_UNIX socketpair copy is the
  Phase-1 data path; a zero-copy ring is a later perf track if profiling
  demands it.
- **Network-transparent / remote clients.** AF_UNIX, same host only.
- **Non-Linux** (`SCM_RIGHTS` / `eventfd` are Linux; the stack already
  targets Linux).
- **The forwarding plane / router work** — a separate track, orthogonal
  to this boundary cut and not a dependency in either direction.
- **Capability / permission model** on the daemon socket (filesystem
  permissions on the AF_UNIX path only for now).

## 9. Commit ledger

_(updated as phases land)_

### Phase 0 — IPC transport + wire-protocol scaffolding (complete)

The `pytcp/ipc/` package + an out-of-process PING → PONG round-trip.

- `cee3fa2e` — length-prefixed stream framing codec
  (`ipc__frame.py` + `ipc__errors.py`: `IpcError` / `IpcFrameError`).
  12 unit tests over a real socketpair.
- `d5f681c2` — control-channel message envelope + op-tag enums
  (`ipc__enums.py`: `IpcMessageKind` / `IpcOp`; `ipc__message.py`:
  `IpcMessage`). `op` decodes as a tolerant raw int (ENOSYS-style),
  `kind` is strict. 10 unit tests.
- `ce2a3f84` — AF_UNIX server `Subsystem` + client connector
  (`ipc__server.py`: `IpcServer` thread-per-client; `ipc__client.py`:
  `IpcClient` synchronous request/response; `IpcConnectionError`).
  6 integration tests over a real AF_UNIX socket + live server thread.

Design notes that landed:
- The envelope `op` field is a raw 16-bit opcode, not an `IpcOp`
  member; an unknown op is answered with `RESPONSE_ERROR` at dispatch
  rather than dropping the connection (forward/backward op-vocabulary
  compat). `kind` stays strict (a fixed 3-value framing concept).
- The server is thread-per-client (matches "owns the per-client
  dispatch loop"); `_stop()` uses `shutdown(SHUT_RDWR)` to interrupt a
  dispatch thread blocked in `recv_frame` (a bare `close()` can leave
  the syscall pending on Linux).
- The client carries a 5 s response timeout so a hung daemon surfaces
  loudly instead of wedging a caller (and the suite).

### Phase 1 — Control-plane RPC (the netlink half) — in progress

Marshal the six control APIs + introspection over the control channel.

- `80a1e2d1` — control-plane tagged value codec (`ipc__values.py`):
  net_addr types / enums / snapshots / containers <-> JSON-native tagged
  forms. 12 unit tests.
- `b584b296` — control-RPC machinery + the **sysctl** mirror end-to-end.
  `ipc__rpc.py` (CONTROL_CALL body codec + `control_call` client helper),
  `ipc__control.py` (daemon dispatcher with per-API method allowlist),
  the `-> IpcMessage` handler-contract change in `ipc__server.py`,
  `IpcRemoteError`, and the new `pytcp/client/` package
  (`connect()` -> `ClientStack.sysctl`). 4 unit + 6 integration tests.

Design notes:
- Control bodies are **JSON** documents (the low-frequency netlink half),
  not the binary struct framing the data plane uses. Typed values cross
  via the tagged value codec.
- One `CONTROL_CALL` op routes on `(api, method)` in the body rather than
  one op per method — the op space stays tiny.
- A per-API **method allowlist** in `ipc__control.py` gates which
  wire-supplied names may be invoked; the dispatcher never reflects an
  arbitrary attribute off a stack object.
- Remote failures surface client-side as a single `IpcRemoteError`
  (carrying the remote type name + message) — Phase-1 simplification; the
  original exception type is reported, not reconstructed.

- `dcecd15d` — the five remaining mirrors (`route` / `link` / `address`
  / `neighbor` / `membership`), Phase 1 complete. Shared proxy bases
  (`client__base.py`: `_ClientApiProxy` + `_DeviceScopedProxy` for the
  `interface(ifindex)` chaining), the per-API proxies, `ClientStack`
  wiring, the dispatcher resolver/allowlist + property-read support, and
  the `IpcControlTestCase` harness. 13 integration tests.

Notes that landed with the mirrors:
- `LinkApi`'s read **properties** marshal as zero-arg RPC reads; the
  dispatcher reads a property value vs. calls a method via a `callable()`
  check.
- Two in-process-only surfaces are **omitted by design** (they can't
  cross a process boundary): `address.add`'s `dad_conflict_callback`, and
  `membership.set_socket_filter` / `clear_socket_filter` (token-keyed
  `Ip4MulticastFilter` socket plumbing).
- The `neighbor` integration fixture swaps **real** ARP/ND caches onto
  the boot interface — `NetworkTestCase` mocks them for RX/TX, but the
  neighbor control API needs a real entry store.
- The harness silences the `stack` log channel **per class** in
  `setUpClass` so the server's cleanup-time stop log (an `addCleanup`
  that runs after `NetworkTestCase.tearDown` restores its snapshot) does
  not leak.

### Phase 2 — TCP socket syscall RPC + data-channel fd passing (complete)

The two novel data-plane primitives:

- `3b305c38` — SCM_RIGHTS fd-passing (`ipc__fdpass.py`):
  `send_frame_with_fd` / `recv_frame_with_fd`. The fd rides the 4-byte
  length prefix's `sendmsg`; the receiver `recvmsg`s the prefix to
  capture it, then reads the payload via the now-public `recv_exactly`.
  Received fds are closed on any framing error so they don't leak.
  5 unit tests (real socketpair + pipe; the received fd is a working
  duplicate).
- `bc8ca718` — the per-socket data bridge (`ipc__socket_bridge.py`):
  `SocketBridge`, two blocking pump threads (RX stack→client, TX
  client→stack) over a `BridgedSocket` Protocol (`recv(bufsize,
  timeout)` / `send` / `shutdown`). Half-close (`recv` of b"") →
  `shutdown(SHUT_WR)` on the far side; backpressure implicit (socketpair
  buffer = socket buffer). Uses a short-timeout blocking `recv` rather
  than a selector on the eventfd `fileno()` — same underlying readiness,
  simpler, with a poll for prompt stop. 5 unit tests (socketpair stub).

The socket-syscall RPC + client socket + echo (2b-ii):

- `82eda4dc` — value codec gains `bytes` (base64-tagged): a setsockopt
  value / getsockopt return can be raw bytes. 2 unit tests.
- `20623a6a` — `IpcOp.SOCKET_CALL` + the socket-syscall body codec
  (`ipc__socket_rpc.py`): a `SocketRequest` (method + per-client handle +
  typed kwargs), `{value}` OK / `{error,message}` error bodies. The
  socket-plane analogue of `ipc__rpc`. 3 unit tests.
- `32e21744` — `recv_frame_with_fd` tolerates a zero-fd frame (returns
  `(payload, None)`): the socket-creation path's fd-less RESPONSE_ERROR
  must not raise. 1 new unit test.
- `3f9cec1f` — the value codec crosses the socket-option enum family
  (IpProto / SolLevel / SocketOption / SolSocketOption / IpOption /
  IpV6Option / MsgFlag) faithfully as members, **not** ints: an
  IPPROTO_\* level is an `IpProto` ProtoEnum whose member ≠ its integer,
  so the daemon's `==` option dispatch only matches a member. 1 unit test.
- `1b348462` — the daemon per-client socket session
  (`ipc__socket_session.py`): each connection owns a `SocketSession`
  handle table of real `TcpSocket`s, each paired with a `SocketBridge`.
  `socket()` creates a socketpair + daemon socket and hands the client
  end back via `send_frame_with_fd`; the bridge starts on `connect`
  (the stack socket has no session to read before then). bind / connect /
  setsockopt / getsockopt / shutdown / close / getsockname / getpeername
  are handle-keyed RPC. `close_all` reaps every open socket abortively on
  disconnect (kernel-reaps-on-exit). Wired into `IpcServer._serve_client`
  via `_serve_socket_call`; `IpcClient.request_with_fd` is the fd-bearing
  client primitive. 6 integration tests.
- `f27ecf92` — `ClientTcpSocket` + `ClientStack.socket()`: data path is
  the passed socketpair end (real selectable fd; `send`/`recv` are
  ordinary socket I/O); control methods marshal over `SOCKET_CALL`.
  `ipc__socket_rpc` gains the `socket_call` / `open_socket` client
  helpers. 4 integration tests.
- `695d3653` — end-to-end out-of-process TCP echo (`TcpTestCase` +
  IpcServer): client connects to a TAP-wire peer and exchanges data both
  directions over its real fd. The blocking `connect()` runs on a
  background thread while the main thread drives the SYN-ACK (different
  threads → no deadlock). 2 integration tests; stable across repeated
  runs.

Design notes that landed:
- `listen` / `accept` are deliberately **out of scope** here — passive
  open + the accept fd-pass are Phase 4.
- The bridge starts at `connect`, not at `socket()` creation: the stack
  socket's `recv` asserts a live session, so an RX pump started before
  connect would crash. The fd is still passed at `socket()` time; only
  the pump start defers.
- Socket-option **family / type** cross as typed enum members (the
  daemon dispatches the factory on them); option **level / optname**
  also cross as members (not ints) because of the ProtoEnum `==` rule
  above. setsockopt **value** crosses as int or bytes.
- Per-client session is single-threaded (one dispatch loop reads
  requests sequentially), so the handle table needs no lock; the bridge
  pumps run on their own threads and touch only `recv` / `send`, the
  same concurrency the in-process stack already handles.

### Phase 4 preview — `accept()` fd passing

The session table + `_serve_socket_call` fd-pass path generalise to
`accept()`: on a completed passive open the daemon spawns a fresh
socketpair + bridge for the child internal socket and returns the new fd
via `SCM_RIGHTS` in the accept response. `listen` / `accept` were left
off the SOCKET_CALL allowlist for exactly this reason.

### Phase 3 — Datagram sockets — UDP plane complete

The datagram data plane uses a SOCK_DGRAM socketpair (boundary-
preserving — one PyTCP datagram per AF_UNIX datagram), each datagram
framed with its peer address so the address survives the boundary.

- `e2c00891` — datagram data-channel frame codec (`ipc__dgram_frame`):
  `tag(1) [port(2) ip(4|16)] payload`, tag 0 = no address (connected
  send), 4 = IPv4, 6 = IPv6. net_proto + stdlib only. 6 unit tests.
- `98d286eb` — the datagram bridge (`ipc__dgram_bridge`): `DatagramBridge`
  RX pump frames each `recvfrom` with its sender address; TX pump decodes
  the framed address and replays it as `sendto` (or `send` for a
  connected socket). A SOCK_DGRAM socketpair has no peer-close EOF
  (closed far end just times out), so teardown is `stop`-driven from the
  control-channel disconnect; a stack-refused datagram is dropped
  (UDP best-effort). 3 unit tests.
- `c6140539` — daemon DGRAM session support: the `socket` call carries
  the socket `type`; `_DaemonSocket` is generalised over a
  TcpSocket+SocketBridge or UdpSocket+DatagramBridge; the DGRAM bridge
  starts at creation (a datagram socket can receive before connect); UDP
  close is a plain unregister; `shutdown` is rejected on a datagram
  handle. The value codec crosses `SocketType` as a member. 2 integration
  + 1 unit test.
- `88cbf623` — `ClientUdpSocket` + `ClientStack.socket()` type dispatch
  (STREAM -> `ClientTcpSocket`, DGRAM -> `ClientUdpSocket`). `sendto` /
  `recvfrom` frame/unframe the peer address over the SOCK_DGRAM fd.
  End-to-end out-of-process UDP echo (UdpTestCase + IpcServer): a peer
  datagram is delivered to the client with its sender address (RX), and a
  client `sendto` reaches the wire addressed to the peer (TX). UDP has no
  handshake, so both directions run inline; stable across repeated runs.
  2 integration tests.

**Remaining in Phase 3 (datagram families + ancillary):**

1. **`recvmsg` cmsg ancillary.** The frame format carries only
   `{address, payload}` today; extend it to `{address, cmsg, payload}` so
   the RX pump can `recvmsg` (capturing IP_TOS / IPV6_TCLASS / IP_OPTIONS
   and the IP_RECVERR error-queue cmsgs) and the client `recvmsg` can
   read them. The daemon UdpSocket already produces these cmsgs
   (`udp__socket._recvmsg` / `_recvmsg_errqueue`); only the data-channel
   framing + a client `recvmsg` are missing.
2. **Raw sockets (`RawSocket`).** IP-level datagram socket — its own
   `_open_raw` + a raw client shim. Address shape differs (no port).
3. **AF_PACKET (`PacketSocket`).** Link-level frames — `SockAddrLl`
   addressing; its own session + client shim.

### Phases 4-6 — later

`accept()` fd passing (passive open), examples migration, daemon
lifecycle — see §4.
