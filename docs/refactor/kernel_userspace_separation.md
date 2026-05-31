# Kernel / Userspace Process Separation Plan

| Field      | Value                                                                 |
|------------|-----------------------------------------------------------------------|
| Status     | **ACTIVE — Phase 0 complete; Phase 1 next.** Created 2026-05-31 on `PyTCP_3_0_7`. |
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

### Phase 1 — Control-plane RPC (the netlink half) — next

Marshal the six control APIs + introspection over the control channel.
