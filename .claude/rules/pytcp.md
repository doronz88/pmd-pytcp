# PyTCP — Stack Runtime Rule

This rule codifies how the `pytcp/` package's runtime
services are authored: the `Subsystem` base class, packet
handlers, the BSD-socket facade, the sysctl registry, and
stack-wide configuration. It complements
[`source_files.md`](source_files.md) (general file mechanics)
and [`net_proto.md`](net_proto.md)
(per-protocol packet authoring under `net_proto/`).

The Project North Star's Phase 3 (kernel/userspace boundary —
see `CLAUDE.md`) makes the architectural seams in this file
load-bearing: every consumer-facing API of the stack goes
through one of the surfaces below, never through a direct
attribute on a running instance.

---

## 1. Module-level constants in `pytcp/`

Naming follows the general convention from
[`source_files.md`](source_files.md) §7 — `ALL_CAPS` with
double-underscore segments encoding hierarchy:
`STACK__MAC_ADDRESS`, `ARP_CACHE__ENTRY_MAX_AGE__SEC`,
`SUBSYSTEM_SLEEP_TIME__SEC`.

Struct format strings, when needed by stack code, are also
defined as module constants — never inlined — per
[`net_proto.md`](net_proto.md) §11.

## 2. Runtime-tunable constants (sysctls)

Every module-level constant in `pytcp/` falls into one of
two buckets; the classification matters because it
determines whether the constant is **mutable at runtime
through the public API** or not.

| Bucket             | Mutable at runtime? | Examples                                                                                       |
|--------------------|:-------------------:|------------------------------------------------------------------------------------------------|
| **Policy**         | yes (sysctl)        | cache aging timeouts, rate-limits, retry counts, defaults the operator can sensibly override   |
| **Protocol invariant** | no              | header struct sizes, RFC-pinned wire values, IANA codepoints, enum codepoints, struct pack codes |

**Heuristic:** if Linux exposes the equivalent under
`/proc/sys/net/`, it is policy; if Linux uses `#define` or
an inline `const` in a kernel header, it is invariant. When
ambiguous, default to **invariant** — every sysctl is a
forever-load-bearing API the moment users start tuning it,
and a wrong "make this mutable" decision is much harder to
walk back than a wrong "keep this static" decision.

### 2.1 Policy constants — qualified-module-access pattern

Policy constants are registered with the central registry at
`pytcp/lib/sysctl.py` so the operator can mutate them at
runtime via `pytcp.stack.sysctl["arp.cache.max_age"] = 60`
and at boot via `stack.init(arp_cache_max_age=60)`. The
underlying ALL_CAPS module attribute remains the canonical
storage; the registry is an index mapping the dotted-name
canonical key (`arp.cache.max_age`) to the module attribute
the runtime reads.

Code that reads a policy constant uses **qualified module
access** so each read re-resolves the current value:

```python
# Good — library code reading a sysctl-backed policy constant
from pytcp.protocols.arp import arp__constants

now = time.monotonic()
if now - entry.create_time > arp__constants.ARP__CACHE__ENTRY_MAX_AGE:
    ...
```

**NOT:**

```python
# Forbidden — captures the value at import time and locks it
from pytcp.protocols.arp.arp__constants import ARP__CACHE__ENTRY_MAX_AGE

if now - entry.create_time > ARP__CACHE__ENTRY_MAX_AGE:  # stale on mutation
    ...
```

**Protocol invariants** stay as `from X import Y`-style local
bindings. They never need to re-resolve because they never
change.

### 2.2 Module-top imports for constants modules

The qualified-module import goes at module top, not inside
the function reading the constant:

```python
# Good — at module top
from pytcp.lib import neighbor__constants as nbr_const

# inside a method
if entry.probe_count >= nbr_const.NEIGHBOR__MAX_MULTICAST_SOLICIT:
    ...
```

**Never:**

```python
# Forbidden — function-local import
def _subsystem_loop(self) -> None:
    from pytcp.lib import neighbor__constants as nbr_const  # NO
    ...
```

Function-local imports re-execute the import machinery on
every call AND defer the `*_constants.py` module's
`register(...)` side-effects until the first invocation —
which means the sysctl registry is empty at boot and operator
overrides racing the first read hit `KeyError`. The
qualified-access pattern in §2.1 gives you live
re-resolution; the import location does not affect that.

### 2.3 Adding a new policy knob

Invoke the
[`sysctl_knob`](../skills/sysctl_knob/SKILL.md) skill. It
codifies the workflow: classify, register, optional explicit
`stack.init()` kwarg, validator, tests-first, audit-doc
Reference, §7.2 docstring audit, commit. The framework's
full design (registry shape, naming, validation, migration
phases) lives at `docs/refactor/sysctl_framework.md`.

### 2.4 Migration of static constants to sysctl-backed

Proceeds **per-package, not per-constant** (see
`sysctl_framework.md` §8). When you touch a package's
`*__constants.py` for any feature reason, classify and
migrate the whole file's policy constants in the same
commit. Half-migrated packages are the failure mode the
framework exists to prevent; piecemeal sweeps drift
indefinitely. A `# Phase 2: per-interface` comment marks
knobs that will become per-interface namespaces when
multi-interface support lands.

## 3. The `Subsystem` base class

Every background service in `pytcp/` extends `Subsystem`
from `pytcp/lib/subsystem.py`.

- Implement `_subsystem_loop()` (abstract) with the
  per-iteration work. The base class wraps it in a loop
  guarded by `self._event__stop_subsystem`.
- Threading attributes are prefixed `_event__`, `_thread__`,
  `_lock__` to keep intent grep-able.
- Start/stop are the only public lifecycle methods;
  additional subsystem-specific startup work goes in
  `_start()` (called from `start()` after the thread is
  spawned).
- Loop cadence: `SUBSYSTEM_SLEEP_TIME__SEC = 0.1` is the
  canonical poll interval; override only if the protocol
  demands it.

Subsystem subclasses include the `ArpCache` / `NdCache`
neighbor caches (`pytcp/lib/neighbor.py` + adapters), the
`TxRing`, and any future timer-driven service.

## 4. Packet handlers

RX / TX handlers live under `pytcp/stack/packet_handler/`,
named `packet_handler__<proto>__<rx|tx>.py`.

- Each file contributes methods to the `PacketHandler` class
  via explicit composition (mixins). Keep each file focused
  on one direction of one protocol.
- The `PacketHandler` lifecycle is owned by
  `stack.init(...)` — consumers do not instantiate handlers
  directly. Test fixtures use the
  `pytcp.tests.lib.network_testcase` harness which wires the
  handler with mocked `TxRing` / `ArpCache` / `NdCache`. See
  [`integration_testing.md`](integration_testing.md) §4.
- Stat counters live on `PacketHandler.packet_stats_rx` /
  `.packet_stats_tx` (dataclasses with one `int` per
  counter). Every RX/TX path branch bumps a specific
  counter; integration tests assert on the counter snapshot
  via `_assert_packet_stats_rx/_tx(exact=True, ...)`.

## 5. The BSD socket facade

`pytcp/socket/__init__.py` exposes an abstract `socket`
class with a `__new__` factory that returns `TcpSocket`,
`UdpSocket`, or `RawSocket` based on the `type_` argument.
Mirror BSD socket semantics — method names (`bind`,
`listen`, `accept`, `connect`, `send`, `recv`, `close`)
match the stdlib `socket` module.

TCP's FSM is implemented in
`pytcp/protocols/tcp/tcp__session.py` using `FsmState` and
`SysCall` enums. Keep state transitions inside the session
object; the socket class is a thin BSD-API shim over it.

### 5.1 Phase 3 — socket factory as user/kernel transition

Per the CLAUDE.md Phase-3 design implications, the socket
factory's `__new__` dispatch is the user/kernel transition.
Keep it dumb — argument validation, family/type/proto
match, allocate the per-flavour socket object. Putting
protocol logic in the factory pulls Phase-3 work into the
wrong layer.

## 6. Stack configuration

Stack-wide constants (IP / MAC addresses, ARP / ND cache
timers, MTU, port ranges, logger channels) live in
`pytcp/stack/__init__.py`. Add new tunables there,
following the §1 naming convention (`STACK__MAC_ADDRESS`,
`ARP_CACHE__ENTRY_MAX_AGE__SEC`, etc.).

### 6.1 `stack.init()` / `stack.shutdown()` boundary

`stack.init()` and `stack.shutdown()` are the canonical
stack-lifecycle entry points. Per the CLAUDE.md Phase-3
design implications:

- Treat them like `clone(2)` / `exit(2)` rather than
  ordinary function calls.
- Adding a new stack-wide singleton means extending that
  boundary, not piggy-backing on import-time module state.
- **Adding module-level state to `pytcp/stack/__init__.py`
  REQUIRES the same commit to update
  `NetworkTestCase`/`IcmpTestCase`/`TcpSessionTestCase`
  `setUp`/`tearDown`** to snapshot and restore the new
  attribute. Otherwise tests pass alone and fail in suite
  (or vice versa). See
  [`integration_testing.md`](integration_testing.md) §5.4
  for the canonical snapshot/restore pattern.

The `stack.mock__init(...)` affordance is the test path —
integration harnesses use it to install mocked singletons
without exercising the real init.

## 7. Anti-patterns

Stack-runtime anti-patterns. General source-file
anti-patterns live in [`source_files.md`](source_files.md)
§10; protocol-authoring anti-patterns live in
[`net_proto.md`](net_proto.md) §17.

- **Creating a subsystem without extending `Subsystem`** —
  ad-hoc threading in `pytcp/` is a red flag. Background
  work goes through the `Subsystem` lifecycle.
- **Direct attribute assignment to read a sysctl-backed
  value.** Use qualified module access
  (`nbr_const.NEIGHBOR__MAX_MULTICAST_SOLICIT`) so each read
  re-resolves; never
  `from pytcp.lib.neighbor__constants import NEIGHBOR__MAX_MULTICAST_SOLICIT`
  which captures import-time and locks it.
- **Function-local `from pytcp.lib import foo__constants`**
  in a hot-loop method. Module-top only; see §2.2.
- **Putting protocol logic in `socket.__new__`.** The
  factory dispatches; the protocol class implements. Keep
  the seam clean for Phase 3.
- **Instantiating `PacketHandler` from a test** instead of
  using `NetworkTestCase` / `IcmpTestCase`. The harness
  wires the mocks consistently; ad-hoc construction breaks
  the test-isolation contract.
- **Adding module-level state to `pytcp/stack/__init__.py`
  without updating the test harness in the same commit.**
  See §6.1 above and
  [`integration_testing.md`](integration_testing.md) §5.4.
- **Per-test `stack.init()` calls** in test bodies. The
  harness installs mocked singletons via
  `stack.mock__init(...)` — bypassing that breaks snapshot/
  restore.
- **Configuration mutations as direct attribute writes.**
  Per the Phase-3 design implications, address / route /
  neighbor / sysctl changes go through their respective
  APIs, never as `_ip6_host.append(...)` or
  `Ip4Host.gateway = ...` or
  `stack.foo = ...`. The API is the boundary; the
  attribute is implementation.

## 8. Cross-references

- [`source_files.md`](source_files.md) — general source-file
  mechanics (file skeleton, copyright block, module
  docstring, imports, naming, formatting).
- [`net_proto.md`](net_proto.md) —
  per-protocol six-file pattern under `net_proto/`.
- [`python_features.md`](python_features.md) — Python
  3.10–3.14 features and forbidden pre-3.10 fallbacks.
- [`typing.md`](typing.md) — annotation discipline,
  generics, `Self` / `@override`, the protected-hook
  pattern, `cast` and `# type: ignore` policy.
- [`integration_testing.md`](integration_testing.md) — the
  test harness hierarchy that mocks the runtime services
  described here.
- [`feature_implementation.md`](feature_implementation.md) —
  workflow including the snapshot/restore-the-harness-on-touch
  rule.
- [`sysctl_knob`](../skills/sysctl_knob/SKILL.md) skill —
  workflow for adding a new policy knob.
- `docs/refactor/sysctl_framework.md` — the full sysctl
  framework design.
