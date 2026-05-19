# PyTCP sysctl framework — design + per-package migration plan

This document captures the framework PyTCP uses to expose
runtime-tunable stack policy (timeouts, rate-limits, retry
counts, defaults) the way Linux exposes the
`net.ipv4.*` / `net.ipv6.*` / `net.core.*` sysctl namespace.
It records the design, the classification rule, the migration
order, and the resume prompt for picking the work back up.

The framework is the chosen replacement for the ad-hoc
`stack.init()` kwargs introduced in commit `a25603cb` (the #16
"configurable cache timeout" work). That commit's kwargs are
the user-facing API; the registry behind them is the runtime
single-source-of-truth.

---

## §0 Why

Linux's `net.*` sysctl namespace is the canonical operability
surface for a network stack: every tunable knob is a string
key the operator can read or write at any time, with the
kernel reading the live value on the next code path that
references it. PyTCP today scatters its tunables across
module-level constants, "configurable" only by editing source
or — post-#16 — through a handful of `stack.init()` kwargs
whose mechanism happens to make the underlying constants
live-mutable but whose API doesn't expose that.

Adopting Linux's structure gives PyTCP:

- Operability parity — `stack.sysctl["arp.cache.max_age"] = 60`
  works on a running stack without restart.
- Discoverability — one registry lists every tunable knob.
- A clean separation between **policy** (sysctls) and
  **protocol invariants** (static constants), matching the
  `#define` vs `sysctl_*` split in `net/`.
- A natural extension point for Phase 2 per-interface
  namespaces (`net.ipv4.neigh.<iface>.*`).

---

## §1 Classification rule (policy vs invariant)

Every constant in the codebase falls into one of two buckets.
The classification is the highest-leverage decision in the
framework — get it wrong and you either lock in mutability
the protocol can't tolerate or freeze a knob the operator
needs to tune.

| Bucket             | Goes through registry? | Examples                                                                                       |
|--------------------|:----------------------:|------------------------------------------------------------------------------------------------|
| **Policy**         | yes                    | cache aging timeouts, rate-limits, retry counts, defaults the operator can sensibly override   |
| **Protocol invariant** | no                 | header struct sizes, RFC-pinned wire values (`TCP__MIN_MSS = 536`), enum codepoints, IANA values |

Heuristic: if Linux exposes the equivalent under
`/proc/sys/net/` it is policy; if Linux uses a `#define` or
hard-codes the value in a header, it is an invariant. When
the analogue is ambiguous, default to **invariant** — every
sysctl is a forever-load-bearing API the moment users start
tuning it, and a wrong "make this mutable" decision is much
harder to walk back than a wrong "keep this static" decision.

Examples of correct calls:

| PyTCP constant                          | Bucket    | Linux analog                             |
|-----------------------------------------|-----------|------------------------------------------|
| `ARP__CACHE__ENTRY_MAX_AGE`             | policy    | `net.ipv4.neigh.default.base_reachable_time` |
| `ARP__CACHE__ENTRY_REFRESH_TIME`        | policy    | `net.ipv4.neigh.default.gc_stale_time`   |
| `ARP__REQUEST_RATE_LIMIT`               | invariant | RFC 1122 §2.3.2.1 pins 1 s recommended   |
| `ARP__DEFEND_INTERVAL`                  | policy    | RFC 5227 §1.1 "MAY tune"                 |
| `ARP__PROBE_NUM`, `ARP__PROBE_WAIT`     | policy    | RFC 5227 §1.1 "MAY tune"                 |
| `TCP__HEADER__LEN`                      | invariant | wire-format constant                     |
| `IP4__DEFAULT_TTL`                      | policy    | `net.ipv4.ip_default_ttl`                |
| `IP4__FRAG_FLOW_TIMEOUT`                | policy    | `net.ipv4.ipfrag_time`                   |
| `EPHEMERAL_PORT_RANGE`                  | policy    | `net.ipv4.ip_local_port_range`           |
| `UDP__HEADER__STRUCT`                   | invariant | wire-format pack code                    |

When in doubt, search Linux source for the equivalent. If
`net/ipv4/sysctl_net_ipv4.c` exposes it via `proc_handler`,
it is policy; if it lives in a header file as `#define` or
inline `const`, it is invariant.

---

## §2 Registry shape

Single file: `packages/pytcp/pytcp/stack/sysctl.py`. Exposes:

```python
# Public API
def get(key: str) -> Any: ...
def set(key: str, value: Any) -> None: ...
def list_keys() -> list[str]: ...

# Optional dict-like sugar
sysctl: _SysctlRegistry  # supports sysctl["arp.cache.max_age"] = 60

# Internal registration (called from each *__constants.py)
def _register(
    *,
    key: str,                   # dotted: "arp.cache.max_age"
    default: Any,
    validator: Callable[[Any], None] | None = None,
    description: str = "",
) -> None: ...
```

Each policy constant in `<package>/<proto>__constants.py`
registers itself with the registry at import time. The
constant's MODULE-LEVEL name remains intact (existing call
sites that do `arp__constants.X` continue to work) — the
registry merely tracks the name → live-value mapping for the
public API. Mutation through `sysctl.set("arp.cache.max_age",
60)` writes both the registry entry and the module attribute,
so qualified-access reads (`arp__constants.ARP__CACHE__ENTRY_MAX_AGE`)
see the new value on the next read.

The registry is a dict-of-namedtuples internally:

```python
@dataclass(slots=True)
class _Knob:
    key: str                # dotted name, canonical
    module: ModuleType      # the *__constants.py the value lives on
    attr: str               # the ALL_CAPS module attribute name
    default: Any            # restored on stack.stop()
    validator: Callable[[Any], None] | None
    description: str
```

`set` writes through to `setattr(_Knob.module, _Knob.attr,
value)` after the validator passes. `get` reads via
`getattr`. This keeps the module attribute as the
single-source-of-truth and the registry as an index over them.

---

## §3 Naming convention

Dotted snake-case canonical, kwargs derived by replacing `.`
with `_`:

| Sysctl key                  | Module attribute (existing)         | `stack.init` kwarg          |
|-----------------------------|-------------------------------------|------------------------------|
| `arp.cache.max_age`         | `ARP__CACHE__ENTRY_MAX_AGE`         | `arp_cache_max_age`          |
| `arp.cache.refresh_time`    | `ARP__CACHE__ENTRY_REFRESH_TIME`    | `arp_cache_refresh_time`     |
| `arp.defend_interval`       | `ARP__DEFEND_INTERVAL`              | `arp_defend_interval`        |
| `arp.accept`                | `ARP__ACCEPT` (new)                 | `arp_accept`                 |
| `ip4.default_ttl`           | `IP4__DEFAULT_TTL`                  | `ip4_default_ttl`            |
| `ip4.frag_time`             | `IP4__FRAG_FLOW_TIMEOUT`            | `ip4_frag_time`              |

Mirror Linux's hierarchy where applicable
(`net.ipv4.neigh.default.base_reachable_time` → drop the
non-PyTCP-relevant `net.ipv4.` prefix, drop the
`neigh.default.` namespace until per-interface lands → arrive
at `arp.cache.max_age`). When PyTCP has no Linux analogue,
pick a sensible dotted name that mirrors the package layout
(`<package>.<subject>.<field>`).

---

## §4 `stack.init()` kwarg integration

`stack.init(arp_cache_max_age=60, ...)` continues to be the
boot-time configuration surface. Internally it routes each
kwarg through `pytcp.stack.sysctl.set("arp.cache.max_age", 60)`
— same validator path as the runtime mutation. Default `None`
on the kwarg means "leave the registry default in place."

The `init()` function should NOT enumerate every knob — that
would couple `init()`'s signature to the registry's
membership. Instead, accept a single `sysctls: dict[str, Any]
| None = None` bag kwarg after the explicit named kwargs and
route each entry through the registry. Names must match a
registered key or the registry raises `KeyError("unknown
sysctl: '<name>'")`. The bag form is keyed by the canonical
dotted name (`"arp.defend_interval"`) — there is no
`underscore_form → dotted.form` auto-conversion to avoid
ambiguity when a key has mid-segment underscores
(`arp.cache.max_age` vs hypothetical `arp.cache_max.age`
would both derive `arp_cache_max_age`).

```python
def init(
    *,
    fd: int,
    layer: InterfaceLayer,
    # ... existing structural kwargs ...
    arp_cache_max_age: int | None = None,    # explicit for type safety + autocomplete
    arp_cache_refresh_time: int | None = None,
    # ... future explicit kwargs as they're added ...
    sysctls: dict[str, Any] | None = None,    # bag for less-common knobs (dotted-name keys)
) -> None: ...
```

The "promote a knob to an explicit kwarg" decision is
ergonomic: if the knob is one most users will tune
(documented in the README, mentioned in tutorials), make it
explicit. Otherwise leave it accessible only through
`sysctls={"<dotted.key>": value}` at boot or via
`stack.sysctl["<dotted.key>"] = value` at runtime.

---

## §5 Validation

Per-knob validators run at write time, on both `init()`
kwargs and `set()` calls. The validator is a callable that
raises `ValueError` on rejection:

```python
def _is_positive_int(name: str) -> Callable[[int], None]:
    def validator(value: int) -> None:
        if not isinstance(value, int) or value <= 0:
            raise ValueError(
                f"sysctl '{name}' must be a positive int; got {value!r}"
            )
    return validator

_register(
    key="arp.cache.max_age",
    default=ARP__CACHE__ENTRY_MAX_AGE,
    validator=_is_positive_int("arp.cache.max_age"),
    description="ARP cache entry lifetime, seconds.",
)
```

For knobs whose validity depends on another knob (e.g.
`arp.cache.refresh_time < arp.cache.max_age`), use a
`finalize_validators()` pass that runs at the end of `init()`
after every kwarg has been applied. Each cross-knob
constraint is its own validator function listed in a
module-level list.

**Rule:** validators MUST raise `ValueError`; the registry
re-raises with the offending key prepended. Don't return
`bool` and have the registry interpret — explicit raise
keeps the rejection message informative.

---

## §6 Discovery + introspection

```python
pytcp.stack.sysctl.list_keys()         # ['arp.cache.max_age', ...]
pytcp.stack.sysctl.describe(key)       # → str description
pytcp.stack.sysctl.snapshot()          # → dict[str, Any] of current values
pytcp.stack.sysctl.reset_to_defaults() # restore registered defaults
```

`reset_to_defaults()` is what `stack.stop()` calls (and what
`TcpSessionTestCase.tearDown` calls for test isolation). It
walks the registry and restores each `_Knob.default` via
`setattr`, leaving no per-test mutation leaked into the next
test's defaults.

---

## §7 Test patterns

Tests that mutate a knob can use either:

```python
# Direct registry write (runtime-mutation style)
pytcp.stack.sysctl.set("arp.cache.max_age", 60)
try:
    ...
finally:
    pytcp.stack.sysctl.set("arp.cache.max_age", default)
```

or:

```python
# Patch the underlying module attribute (existing style; still works)
with patch("pytcp.protocols.arp.arp__constants.ARP__CACHE__ENTRY_MAX_AGE", 60):
    ...
```

Both work because the registry writes through to the module
attribute. The `patch()` form is preferred for unit tests
because it auto-restores on context exit; the direct `set()`
form is preferred for integration tests where you want to
observe the live runtime behaviour against a tuned knob.

A test-only context manager is convenient:

```python
from pytcp.stack.sysctl import override

with override("arp.cache.max_age", 60):
    self._cache._subsystem_loop()
```

`override` is a `contextmanager` that calls `set()` on enter
and restores the prior value on exit. Tests that already
`patch()` don't need it; tests that want a one-line override
do.

---

## §8 Migration order

Per-package, not per-constant. When you touch a package's
constants for any feature reason, classify and migrate the
WHOLE `*__constants.py` file's policy knobs in the same
commit. This avoids both the multi-week wholesale sweep and
the slow drift of pure-lazy migration.

### Phase 0 — Build registry ✅ shipped `8eb94ccb`

Write `packages/pytcp/pytcp/stack/sysctl.py` with:
- `_register`, `get`, `set`, `list_keys`, `describe`,
  `snapshot`, `reset_to_defaults`, `override` (cm).
- `_SysctlRegistry` class (the dict-like sugar; binds
  `pytcp.stack.sysctl` for the public API).
- A `_finalize_validators` pass that runs the cross-knob
  constraint list at end of `init()`.

Unit tests at `packages/pytcp/pytcp/tests/unit/lib/test__lib__sysctl.py`:
- `register` then `get` returns the default.
- `set` updates both the module attr and the registry.
- `set` with a failing validator raises `ValueError` with
  the offending key in the message.
- `list_keys` enumerates registered knobs.
- `reset_to_defaults` restores the registered defaults.
- `override` context manager round-trips.
- Cross-knob validator raises with both knob names in
  message.

No source migration in this commit. Pure infrastructure.

### Phase 1 — Migrate `arp__constants.py` policy knobs (#16 retrofit + #17 prep) ✅ shipped (this commit)

Walk every constant in `packages/pytcp/pytcp/protocols/arp/arp__constants.py`,
classify each, register the policy ones with the registry.
Update `stack.init()` to forward kwargs through the registry
instead of writing to the module attribute directly. Existing
unit tests that patch `pytcp.protocols.arp.arp__constants.X`
remain valid (the registry writes through to the same
attribute).

Knobs to register:

| Key                          | Default | Validator             |
|------------------------------|---------|-----------------------|
| `arp.cache.max_age`          | 3600    | positive int          |
| `arp.cache.refresh_time`     | 300     | positive int; < max_age |
| `arp.defend_interval`        | 10      | positive int          |
| `arp.probe_wait`             | 1       | positive int          |
| `arp.probe_num`              | 3       | positive int          |
| `arp.probe_min`              | 1       | positive int; < probe_max |
| `arp.probe_max`              | 2       | positive int          |
| `arp.announce_num`           | 2       | positive int          |
| `arp.announce_interval`      | 2       | positive int          |
| `arp.announce_wait`          | 2       | positive int          |

`ARP__REQUEST_RATE_LIMIT` stays as a static constant —
RFC 1122 §2.3.2.1 pins it at 1 s "recommended", but PyTCP's
rate-limit mechanism currently encodes the recommendation as
a hard floor and varying it would complicate the
in-progress-resolution gate without adding operational
benefit. Re-classify when there's a real consumer for a
runtime override.

### Phase 2 — Ship #17 (`arp_accept` / `arp_ignore` modes 0–2) ✅ shipped (this commit)

`arp_announce` and `arp_filter` are deferred until PyTCP grows
real multi-subnet / multi-interface support — registering them
as no-ops would violate this plan's §9 "no API surface without
a consumer" anti-pattern. They land in the per-package sweep
that introduces multi-interface (Phase 4 territory).

`arp_ignore` modes 3-8 (Linux cluster / anycast variants) are
explicitly rejected by the validator with the message "modes
3-8 deferred to Phase 2 cluster / anycast support" until a real
consumer surfaces.

Original Phase 2 description (kept for archaeology):

Each Linux ARP-policy knob becomes a registry entry. The RX
handler reads them via the registry on each frame (i.e. via
qualified access on `arp__constants` after they're registered
there). Tests already exist in template form per the resume
doc's §10 Tier 3 #17.

### Phase 3+ — Per-package sweeps as features arrive

When the next feature touches:

- `packages/pytcp/pytcp/protocols/icmp4/` constants → migrate ICMP4 package.
- `packages/pytcp/pytcp/protocols/icmp6/` constants → migrate ICMP6 package.
- `packages/pytcp/pytcp/protocols/ip4/` constants → migrate IP4 package
  (default TTL, fragment timeouts, MTU, send-redirects,
  forwarding flag).
- `packages/pytcp/pytcp/protocols/ip6/` constants → migrate IP6 package
  (hop limit, MTU, frag timeouts).
- `packages/pytcp/pytcp/protocols/tcp/tcp__constants.py` → migrate TCP
  package (RTO bounds, retry counts, MSS minimums,
  delayed-ACK timer, keep-alive intervals, CC defaults).
- `packages/pytcp/pytcp/protocols/udp/` → minimal (mostly invariants;
  port-range overlaps with stack-level knobs).
- `packages/pytcp/pytcp/stack/__init__.py` constants → migrate stack-wide
  policy (ND cache timers, ephemeral port range, fragment
  timeouts).

The order is driven by feature work, not a forced schedule.
Each package's migration is a single commit; no half-migrated
package state.

### Phase 4 — Tier 4 deferred (Phase-2 stack feature)

Per-interface namespace: `arp.cache.max_age` → multi-key
`arp.cache.<iface>.max_age` after multi-interface support
lands. Until then, all sysctls are global. Mark with
`# Phase 2: per-interface` comment in the registry registration.

---

## §9 Anti-patterns

- **Reaching into `arp__constants` from `init()` directly.**
  Always go through `pytcp.stack.sysctl.set(...)`. The direct
  `setattr(arp__constants, "X", value)` form bypasses the
  validator — same bug class as bypassing
  `__post_init__`-style validation.
- **Promoting an invariant to a sysctl.** If the value is
  RFC-pinned and PyTCP has no operational reason to deviate,
  it stays a static constant. Ad-hoc "make it tunable so
  tests can patch it" is a smell — tests can patch the
  module attribute directly without registering a public
  knob.
- **Forgetting `reset_to_defaults()` in `stack.stop()`.**
  Tests that mutate sysctls in `setUp` and don't restore in
  `tearDown` leak per-test state into the next test's
  defaults. `stop()` calling `reset_to_defaults()` is the
  belt-and-braces guard.
- **Validators that return `bool` instead of raising.** The
  registry can't distinguish "validation passed" from
  "validator forgot to return True." Always raise `ValueError`.
- **Adding a knob without an audit-doc Reference.** Every
  policy knob should map to either a Linux sysctl or an RFC
  clause that justifies its existence; if neither, the knob
  shouldn't be public.
- **Hierarchical `__getitem__` parsing.** Don't get cute
  with `sysctl["arp"]["cache"]["max_age"]` — flat dotted
  keys keep the parser trivial and match Linux's `proc_dostring`
  form.

---

## §10 Resume prompt

```
I'm continuing the PyTCP sysctl framework migration. Read
'docs/refactor/sysctl_framework.md' first — it's the canonical
plan with §0 motivation, §1 classification rule, §2-§7 design,
§8 migration order. Then read these in order before any code:

  1. CLAUDE.md (Project North Star)
  2. .claude/rules/feature_implementation.md (tests-first MUST,
     §7.2 audit)
  3. .claude/rules/unit_testing.md (test conventions)
  4. `.claude/rules/source_files.md` / `net_proto.md` / `pytcp.md` §6.1 (sysctl pattern)
  5. .claude/skills/sysctl_knob/SKILL.md (workflow for adding
     a knob)
  6. The current state of packages/pytcp/pytcp/stack/sysctl.py if it exists,
     plus packages/pytcp/pytcp/protocols/arp/arp__constants.py.

After reading, confirm:

  - Phase 0 (build registry): {shipped|pending — at commit X}.
  - Phase 1 (ARP package migration + #16 retrofit):
    {shipped|pending}.
  - Phase 2 (#17 sysctls on registry): {shipped|pending}.
  - Phase 3+ (per-package): track in git log; ask user which
    package's feature is next before migrating its constants.

Tests-first per CLAUDE.md MUST. §7.2 audit before commit.
Branch: PyTCP_3_0__pre_release. No push without ask.
```

---

## §11 Cross-references

- Skill: `.claude/skills/sysctl_knob/SKILL.md` (workflow for
  adding a single knob — when this plan's phases require it).
- Rule: `.claude/rules/source_files.md` / `net_proto.md` / `pytcp.md` §6.1 (the
  classification rule + qualified-access pattern, as a
  reading reference for any new code).
- Per-RFC adherence: knob's audit-doc Reference cites the
  Linux sysctl analog or the RFC clause that motivates the
  default.
- ARP punch list: `docs/refactor/arp_linux_parity.md` §10
  (#17) drives Phase 2 of this plan.
