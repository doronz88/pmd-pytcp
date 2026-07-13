# Pure-asyncio runtime

Goal: remove every thread and every `threading` primitive from the stack.
The whole stack — packet pipeline, timers, protocol FSMs, socket API, IPC —
runs on ONE asyncio event loop. Consumers (pymobiledevice3) are asyncio-native;
today they bridge the blocking socket API with `asyncio.to_thread` + daemon
rx-pump threads. After this refactor they `await` the stack directly.

This is a breaking API change → version 0.1.0.

## Core invariant

All stack state is mutated on the event loop. Therefore:

- Every `threading.Lock` / `RLock` that guards in-memory state is DELETED
  (single-threaded loop ⇒ no data races; callbacks never preempt each other).
- `threading.Event` → `asyncio.Event`; `event.wait(timeout)` →
  `await wait_event(event, timeout)` (helper in `pmd_pytcp/_compat.py`,
  implemented with `asyncio.wait_for`; returns bool like the threading API).
- `threading.Semaphore` → `asyncio.Semaphore`. Producers (packet pipeline,
  FSM) call `.release()` synchronously from loop context — valid. Consumers
  `await acquire_semaphore(sem, timeout)` (compat helper, bool return).
- The rx→parse→FSM→tx pipeline STAYS synchronous code, invoked from loop
  callbacks/tasks. Only *waiting points* become `async def`.

Python floor stays 3.9: no `asyncio.timeout()`, no `TaskGroup`; use
`asyncio.wait_for`. On 3.9 asyncio primitives bind the *current* loop at
construction — stack objects containing primitives must be constructed with
the target loop current (inside async code, or under `asyncio.run`). Document
this in README.

## Runtime components

### Subsystem (runtime/subsystem.py)
Thread → `asyncio.Task`.
- `_subsystem_loop()` becomes `async def`.
- `start()` requires a running loop; creates the task.
- `stop()` stays sync: sets stop event + `task.cancel()`.
- new `async def wait_stopped()` awaits task completion (used by lifecycle).
- The base loop wrapper awaits `_subsystem_loop()` repeatedly until the stop
  event is set, and swallows `CancelledError` on shutdown.

### Timer (runtime/timer.py)
Full rewrite over `loop.call_later`. No heap, no lock, no task.
- Public surface unchanged: `call_later(delay_ms, cb, *args, **kw) -> TimerHandle`,
  `call_periodic(period_ms, ...) -> TimerHandle`, `cancel(handle)`, `now_ms`,
  `start()`, `stop()`.
- `TimerHandle` wraps the underlying `asyncio.TimerHandle`; periodic entries
  re-arm from the fire wrapper (deadline += period, no drift: schedule by
  absolute `loop.time()` deadlines via `call_at`).
- Callbacks stay plain sync callables, run on the loop, exceptions logged
  (same policy as today).
- `stop()` cancels every outstanding handle (keep a live-handle set).
- `now_ms` stays `time.monotonic_ns() // 1_000_000`.

### RxRing (runtime/rx_ring.py)
select-thread + deque + eventfd → readiness callback with direct dispatch.
- `start()`: set fd non-blocking; `loop.add_reader(fd, self._on_readable)`.
  On the socket-I/O path (Windows/`PYTCP_FORCE_SOCK_IO`, where the fd is a
  registered socket and proactor loops lack `add_reader`), spawn a task that
  `await loop.sock_recv(sock, n)` in a loop instead.
- `_on_readable()`: burst-drain — `io_backend.read()` until `BlockingIOError`
  or a per-callback frame budget (reuse the existing drain-burst idea; budget
  = `queue_max_size` is fine), parse `PacketRx`, and deliver each frame
  synchronously via `self._deliver(packet_rx)` — a callback the PacketHandler
  installs at `start()` time. No rx deque, no eventfd, no `dequeue()`.
- Keep drop counters: `os_error_drop_count` (OSError on read) unchanged;
  `queue_full_drop_count` remains as API but only counts frames dropped when
  no deliver callback is installed.
- `stop()`: `remove_reader`/cancel task; close nothing we don't own (fd is
  the host's).

### TxRing (runtime/tx_ring.py)
select-thread + eventfd + `_TxRequest` marshaling → loop-driven drain.
- `enqueue(frame)` / `enqueue_raw_frame(frame)` stay SYNC (append to deque,
  schedule `_drain` via `loop.call_soon` if not already scheduled/armed).
- `_drain()`: pop + `io_backend.writev` until empty or `BlockingIOError`;
  on EAGAIN arm `loop.add_writer(fd, self._drain)` (disarm when empty).
  On the socket-I/O path use a writer task + `loop.sock_sendall`.
- DELETE `_TxRequest`, `dispatch()`, `dispatch_async()` — single loop means
  single writer by construction. The PacketHandler funnels
  (`packet_handler/__init__.py` `_dispatch_tx` wrappers around
  `tx_ring.dispatch{,_async}`) just call `run()` inline.
- Frame-too-big / unknown-type / OSError handling and stats unchanged.

### PacketHandler (runtime/packet_handler/)
- No longer consumes an rx queue: `start()` installs `self._phrx_*` entry as
  the RxRing deliver callback. The Subsystem rx-dequeue loop is gone (it may
  remain a Subsystem only if something still needs a periodic task; otherwise
  drop the inheritance).
- `_lock__ip4_id`, `_lock__multicast`, `_lock__addr_config`: DELETE.
- Address-acquire threads (`_acquire_ip6_addresses` / `_acquire_ip4_addresses`)
  and DAD probe threads → `asyncio.Task`s tracked on the handler; `stop()`
  cancels them.
- `_ip_configuration_in_progress` / `_icmp6_ra__event` semaphores → asyncio
  primitives per the mapping above; their waiters become async.

### Neighbor caches (lib/neighbor.py, arp/nd caches)
- Keep Subsystem (task) base; maintenance cadence via
  `await wait_event(stop_event, SUBSYSTEM_SLEEP_TIME__SEC)` or plain
  `asyncio.sleep`. `_lock` deleted.

### DAD slot registry (lib/dad_slot_registry.py)
- Lock deleted; per-candidate `threading.Event` → `asyncio.Event`.

## Protocols

### TCP session + FSM (protocols/tcp/)
- FSM/session locks deleted. `_event__connect` (Semaphore released by the
  syn_sent/syn_rcvd FSM arms) → `asyncio.Semaphore`; `connect()` awaits it.
- Session timers keep using the Timer API (surface unchanged).
- App-visible waits (established, rx data ready, close, tx window space)
  → asyncio primitives.

### DHCP4 / DHCP6 clients, link-local, ICMP error emitter
- FSM loops stay Subsystem tasks; `Event.wait` → `await wait_event(...)`.
- `start_and_wait_for_bind(timeout_s)` → `async def`.
- ICMP error-emitter rate-limiter lock deleted.

## Socket API (socket/)

Breaking change — blocking calls become coroutines:
- `async def`: `connect`, `accept`, `recv`, `recvfrom`, `recvmsg`, `send`,
  `sendto`, `sendmsg` (anything that can wait). Explicit `timeout=` params
  are preserved (implemented with `asyncio.wait_for`; on timeout raise the
  same exceptions as today).
- Stay sync: `bind`, `listen`, `close`, `shutdown`, `setsockopt`/`getsockopt`,
  properties. (TCP `close` triggers FSM sync-side effects only.)
- `SO_RCVTIMEO`-style default timeouts keep working (wrap in wait_for).
- All internal semaphores/events → asyncio equivalents.

## IPC + daemon

- `IpcServer` → `asyncio.start_unix_server`; per-client threads → per-client
  tasks (stream reader/writer with the same framing).
- Dgram/Packet/Socket bridges: rx/tx pump threads → tasks using loop sock
  APIs; `_event__stop` → task cancellation.
- `ipc__client` (out-of-process consumer side) → asyncio streams API.
- `daemon.run_daemon()` → `async def`, driven by `asyncio.run` in `__main__`;
  signal handling via `loop.add_signal_handler`.

## Stack lifecycle (stack/lifecycle.py)

- `init()` stays sync (construction only) — but Timer/handler construct
  asyncio primitives, so `init()` must run with the target loop current.
- `start()` / `stop()` become `async def`. DHCP boot wait awaited. Teardown
  order preserved; each subsystem `stop()` then `await wait_stopped()`.
- `add_interface` / `remove_interface` stay sync; on a running stack they
  require a running loop (task spawn/cancel is sync-safe from loop context).
- `mock__init` unchanged in shape.

## io_backend (lib/io_backend.py)

- eventfd emulation DELETED once rings stop using it (no remaining users).
- Keep `read` / `writev` / `register_interface_fd` / `needs_socket_io`.
- Add: `set_nonblocking(fd)`, `sock_for_fd(fd) -> socket | None` (for the
  rings' async socket path).

## Tests

- Pure-parsing/unit tests (majority): untouched.
- Tests that call blocking APIs or start subsystems → convert to
  `unittest.IsolatedAsyncioTestCase` (works under tests_runner.py and pytest).
- Thread-safety tests (test__*__thread_safety.py, stats races, MLD/IGMP
  concurrency): the guarantee they verify no longer exists; replace with a
  loop-reentrancy equivalent where meaningful, otherwise delete.
- `nd_testcase.py` and integration harnesses: drive the loop with
  IsolatedAsyncioTestCase; FakeTimer keeps its surface.

## Consumers (pymobiledevice3, separate repo)

- `userspace_tunnel.py`: drop `asyncio.to_thread` wrappers, rx-pump daemon
  threads, teardown threads; `await` sockets directly. Stack start/stop
  awaited. UDP transport reader becomes a task. requirements floor bumps to
  `pmd-pytcp>=0.1.0`.

## Non-goals

- No API-compat shim for the old blocking socket API (the point is clearer
  usage; consumers migrate).
- No trio/anyio abstraction — asyncio only.
