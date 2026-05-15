# Sysctl Registry — Protocol-policy control plane

| Field           | Value                                                        |
|-----------------|--------------------------------------------------------------|
| Status          | shipped                                                      |
| Module path     | `pytcp.stack.sysctl` (exposed as `pytcp.stack.sysctl`)         |
| Linux analogue  | `/proc/sys/net/` namespace; `sysctl net.ipv4.X`              |
| Refactor doc    | `docs/refactor/sysctl_framework.md`                          |
| Workflow skill  | `.claude/skills/sysctl_knob/SKILL.md` (adding a new knob)   |

## Purpose

The Sysctl Registry exposes PyTCP's runtime-tunable
protocol-policy constants as a Linux-equivalent `net.*`
namespace. Operators read / write live values via dotted
keys (`arp.cache.max_age`, `tcp.cubic.alpha`,
`ip4_link_local.max_conflicts`, …); protocol code reads
the values via qualified module access so each read
re-resolves the current value.

Per CLAUDE.md "Phase-3 design implications": **every
user-observable knob lands on either the sysctl registry
or one of the dedicated control APIs**, never as a direct
attribute on a `PacketHandler` / `TcpStack` / cache
instance.

## What is and is not a sysctl

| Bucket                 | Mutable at runtime? | Examples                                                 |
|------------------------|:-------------------:|----------------------------------------------------------|
| **Policy**             | yes (sysctl)        | cache aging timeouts, rate limits, retry counts, defaults |
| **Protocol invariant** | no                  | header struct sizes, RFC-pinned wire values, enum codepoints |

Heuristic: if Linux exposes the equivalent under
`/proc/sys/net/`, it is policy. If Linux uses a `#define`
or `const`, it is invariant. When ambiguous, default to
invariant.

The full classification + migration framework lives at
`docs/refactor/sysctl_framework.md`. Adding a new sysctl
follows the workflow at
`.claude/skills/sysctl_knob/SKILL.md`.

## Public surface

```python
import pytcp.stack.sysctl as sysctl
# Or equivalently:
from pytcp.stack import sysctl
```

### Read / write

```python
sysctl.get("arp.cache.max_age")           # → int (seconds)
sysctl.set("arp.cache.max_age", 60)       # idempotent set

# Dictionary-style sugar (the canonical operator UX):
pytcp.stack.sysctl["arp.cache.max_age"]
pytcp.stack.sysctl["arp.cache.max_age"] = 60
```

### Bulk operations

```python
sysctl.list_keys()                        # → list[str], all registered keys
sysctl.describe("arp.cache.max_age")      # → human-readable description
sysctl.snapshot()                         # → dict[str, Any] of current values
sysctl.reset_to_defaults()                # restore every knob to its registration default
```

### Context-managed override (test fixtures)

```python
with sysctl.override("icmp6.use_tempaddr", 2):
    result = self._packet_handler._select_ip6_source(...)
# Original value restored on exit; raises if the key is unknown.
```

### Boot-time bulk apply (in `stack.init`)

```python
stack.init(
    fd=fd, layer=InterfaceLayer.L2, mac_address=mac,
    sysctls={
        "arp.cache.max_age": 60,
        "tcp.cubic.alpha": 1.0,
        "ip4_link_local.max_conflicts": 5,
    },
)
```

The bag-form `sysctls=` kwarg applies every override before
subsystems are constructed, so the new values are visible
on the first read.

## Validators

Each knob optionally carries a per-knob validator (called
on every `set()`) and the registry supports cross-knob
"finalize" validators (called once after a `sysctls={...}`
bag application). Validators raise `ValueError` on bad
input; the registry preserves the prior value.

Common shipped validators in `pytcp.stack.sysctl`:

- `is_positive_int(name)` — int > 0.
- `is_non_negative_int(name)` — int >= 0.
- `is_float_in_range(name, low=, high=)` — bounded float.

Custom validators are just `Callable[[Any], None]` that
raise `ValueError`.

## Reading a sysctl from protocol code

Qualified module access is the canonical pattern — each
read re-resolves the live value:

```python
# Good — re-resolves on every call
from pytcp.protocols.arp import arp__constants

now = time.monotonic()
if now - entry.create_time > arp__constants.ARP__CACHE__ENTRY_MAX_AGE:
    ...

# Forbidden — captures at import time, locks the value
from pytcp.protocols.arp.arp__constants import ARP__CACHE__ENTRY_MAX_AGE

if now - entry.create_time > ARP__CACHE__ENTRY_MAX_AGE:  # stale on mutation
    ...
```

See `.claude/rules/pytcp.md` §2 for the full pattern.

## Registering a new knob

Use the `sysctl_knob` skill workflow. Concretely, the
protocol's `*__constants.py` module calls `sysctl.register`
at import time:

```python
# pytcp/protocols/arp/arp__constants.py
from pytcp.lib import sysctl

ARP__CACHE__ENTRY_MAX_AGE: int = 60

sysctl.register(
    key="arp.cache.max_age",
    module_name=__name__,
    attr="ARP__CACHE__ENTRY_MAX_AGE",
    default=60,
    validator=sysctl.is_positive_int("arp.cache.max_age"),
    description="Maximum age of an ARP cache entry in seconds.",
)
```

## Namespacing convention

Dotted keys mirror Linux's `net.<family>.<area>.<knob>`
shape:

| Prefix                | Owner                                                              |
|-----------------------|--------------------------------------------------------------------|
| `arp.*`               | `pytcp.protocols.arp.arp__constants`                               |
| `neighbor.*`          | `pytcp.lib.neighbor__constants`                                    |
| `nd.*`                | `pytcp.protocols.icmp6.nd.nd__constants`                           |
| `ip4.*`               | `pytcp.protocols.ip4.ip4__constants`                               |
| `ip4_link_local.*`    | `pytcp.protocols.ip4_link_local.ip4_link_local__constants`         |
| `tcp.*`               | `pytcp.protocols.tcp.tcp__constants`                               |
| `icmp4.*` / `icmp6.*` | `pytcp.protocols.icmp[46].icmp[46]__constants`                     |
| `udp.*`               | `pytcp.protocols.udp.udp__constants`                               |

`sysctl.list_keys()` returns the full live inventory.

## Deferred / out of scope

- **Per-interface namespaces** (Phase-2). Linux supports
  `net.ipv4.conf.<ifname>.X`; PyTCP is single-interface
  in Phase-1 so per-interface overrides don't exist yet.
  When multi-interface lands, the natural seam is
  `arp.cache.tap7.max_age` etc.
- **`net.*` parity sweep**. PyTCP currently has ~80
  registered knobs; Linux has thousands. The plan is to
  add knobs on-demand when a real consumer (or a real
  RFC SHOULD/MAY clause) needs runtime tuning.
- **Persistence**. Sysctl values reset to registration
  defaults on process restart. There is no
  `/etc/sysctl.conf` equivalent; operators bake defaults
  into their `stack.init(sysctls={...})` call.

## Plan / history

- Framework design: `docs/refactor/sysctl_framework.md`.
- Per-knob workflow: `.claude/skills/sysctl_knob/SKILL.md`.
- Source: `pytcp/stack/sysctl.py`.
