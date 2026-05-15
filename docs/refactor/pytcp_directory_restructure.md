# PyTCP Directory Restructure — `stack/` Split + `runtime/` Extraction

| Field             | Value                                                                                                                                                                |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Status            | **PROPOSAL** — drafted 2026-05-14; not yet started                                                                                                                   |
| Plan author       | Session-internal audit follow-up                                                                                                                                     |
| Source motivation | `pytcp/stack/__init__.py` is 751 lines and conflates Phase-3 public APIs with internal RX/TX rings, packet-handler dispatch, and timer machinery                     |
| Target branch     | `PyTCP_3_0__pre_release`                                                                                                                                             |
| Touch points      | ~30 production-source moves + ~25 unit-test file relocations + ~136 test-file import updates + ~77 doc/rule references + `CLAUDE.md` + 8 `.claude/rules/*.md` mentions of current paths |
| Risk              | **Medium** — wide blast radius (~208 import sites total) but each step is mechanical; tests act as the regression net                                                |
| Phases            | 0 (decisions) → 1 (extract `runtime/`) → 2 (split `stack/__init__.py`) → 3 (relocate Phase-3 APIs) → 4 (`lib/` cleanup) → 5 (docs + rules) → 6 (close-out)            |

This document is the implementation plan for a one-shot
directory restructure of the `pytcp/` package. The intent is
to make the Phase-3 design implications from CLAUDE.md
structurally visible: `pytcp.stack.*` becomes the namespace
for kernel-equivalent control-plane APIs **only**, and the
implementation guts (packet-handler dispatch, RX/TX rings,
timer subsystem) move to a new `pytcp/runtime/` sibling that
is visually private.

The user-observable public surface — `stack.init/start/stop`,
`stack.sysctl`, `stack.link`, `stack.address`, and the future
Phase-3 surfaces — keeps the same import paths it has today.
Only internal modules get new paths.

---

## 1. Goal

After this track lands, the `pytcp/` tree reads as three
visually distinct concerns:

| Directory              | Visibility | Contents                                                                                       |
|------------------------|------------|------------------------------------------------------------------------------------------------|
| `pytcp/stack/`         | **public** | Phase-3 control-plane APIs only — one file per API; no implementation guts                     |
| `pytcp/socket/`        | **public** | BSD socket factory (data plane) — unchanged                                                    |
| `pytcp/protocols/`     | private    | Per-protocol runtime (FSMs, caches, parsers) — unchanged                                       |
| `pytcp/runtime/`       | **private**| NEW — packet-handler dispatch, RX/TX rings, timer subsystem, `Subsystem` base, singleton wiring|
| `pytcp/lib/`           | private    | Generic helpers — everything that isn't a public API and isn't runtime machinery               |

Anything a Phase-3 consumer imports (`stack.init`, `stack.X.*`,
`socket.socket(...)`) keeps working with the **same import
path** it has today. Anything that's reach-through to
internals will visibly require a `pytcp.runtime.*` or
`pytcp.protocols.*` import — making the Phase-3 leak greppable.

## 2. Non-goals

- **No API changes.** `stack.init(...)` keeps the same kwargs;
  `stack.sysctl["k"] = v` keeps working; `pytcp.socket.socket(...)`
  is untouched. This is a directory move, not a redesign.
- **No new APIs.** `stack.route` / `stack.neighbor` /
  `stack.introspection` files are introduced as `__init__`-free
  placeholders only if their landing track is already
  in-flight; otherwise they wait for their own track.
- **No legacy-file deletions.** The 8 legacy flat-directory
  tests under `pytcp/tests/integration/protocols/<proto>/test__<proto>__*.py`
  stay in place. Their fate is a separate policy call (see
  `docs/refactor/socket_linux_parity_audit.md` Phase 3).
- **No new tests written.** Existing test coverage stays.
  Unit tests for moved modules **do** relocate (see §5.4)
  because `unit_testing.md §3` ties test paths to source
  paths — that's a `git mv`, not new test authoring.
  Integration tests under
  `pytcp/tests/integration/protocols/<proto>/` are
  unaffected.
- **No CLAUDE.md re-architecting.** The North-Star Phase-3 table
  already names `pytcp.stack.sysctl` etc.; this plan honours
  it. The only edits to `CLAUDE.md` are path strings (e.g.
  `pytcp/stack/__init__.py` → `pytcp/stack/lifecycle.py`).

## 3. Current state

### 3.1 `pytcp/` layout today

```
pytcp/
├── __init__.py              (38 lines — minimal re-exports)
├── lib/                     (21 modules — generic helpers + Phase-3 APIs + Subsystem base)
│   ├── address_api.py       ← Phase-3 API
│   ├── link_api.py          ← Phase-3 API
│   ├── sysctl.py            ← Phase-3 API
│   ├── subsystem.py         ← runtime base
│   ├── ... (18 others — packet_stats, logger, ip helpers, neighbor caches, etc.)
├── protocols/               (per-protocol runtime; unchanged in this plan)
├── socket/                  (BSD facade; unchanged in this plan)
├── stack/
│   ├── __init__.py          (751 lines — init/start/stop, sysctl wiring,
│   │                         singleton imports, re-exports, fixture topology)
│   ├── packet_handler/      (21 mixin files: per-protocol RX/TX)
│   │   ├── __init__.py
│   │   ├── _icmp_error_demux.py
│   │   └── packet_handler__<proto>__<rx|tx>.py × 20
│   ├── rx_ring.py
│   ├── tx_ring.py
│   └── timer.py
└── template.py
```

### 3.2 Import-site inventory

| Pattern grep'd from import lines              | Total | Source | Tests | Docs / Rules |
|-----------------------------------------------|-------|--------|-------|--------------|
| `from pytcp.stack`                            |    42 |      8 |    34 | —            |
| `from pytcp.lib`                              |   166 |     64 |   102 | —            |
| `pytcp.stack.packet_handler` (incl. nested) *(pre-Phase-1)*    |    59 |      — |     — | —            |
| `pytcp.stack.{tx_ring,rx_ring,timer}` *(pre-Phase-1)*          |    47 |      — |     — | —            |
| `pytcp.lib.subsystem` *(pre-Phase-1)*                          |    34 |      — |     — | —            |
| `pytcp.lib.sysctl` *(pre-Phase-3)*                             |    12 |      — |     — | —            |
| `pytcp.lib.address_api` *(pre-Phase-3)*                        |    18 |      — |     — | —            |
| `pytcp.lib.link_api` *(pre-Phase-3)*                           |     2 |      — |     — | —            |
| **Doc references to `pytcp.{stack,lib}.X`**   |    69 |      — |     — | 69 in `docs/` |
| **Rule references to `pytcp.{stack,lib}.X`**  |     8 |      — |     — |  8 in `.claude/rules/` |

Each row is a `grep -r` count, so a single file with three
matching lines counts as three. The total churn (Python
imports + docs + rules) is ~285 line-level edits.

### 3.3 Why `stack/__init__.py` is 751 lines

`stack/__init__.py` today owns six concerns interleaved:

1. **Stack-wide constants / fixture topology** (MAC, IP hosts,
   gateways, MTU, multicast groups, logger channel set).
2. **Singleton attribute declarations** (`tx_ring`, `arp_cache`,
   `nd_cache`, `tcp_stack`, `pmtu_cache`, …).
3. **`init(...)` function** — builds singletons from kwargs.
4. **`start()` / `stop()`** — spawn / wind down threads.
5. **`mock__init(...)`** — test affordance for the harness.
6. **Re-exports** of `stack.sysctl`, `stack.link`, `stack.address`.

Of these, only (3)/(4)/(5) and the re-exports in (6) are
publicly visible API. (1) is fixture topology that doesn't
need to be in the public namespace. (2) is implementation
detail. This plan extracts each concern into a dedicated file.

## 4. Target structure

```
pytcp/
├── __init__.py
├── stack/                       PUBLIC NAMESPACE (Phase-3 control plane)
│   ├── __init__.py              ~50 lines — re-exports + lifecycle facade only
│   ├── lifecycle.py             init() / start() / stop() / mock__init()
│   ├── sysctl.py                was lib/sysctl.py
│   ├── link.py                  was lib/link_api.py
│   ├── address.py               was lib/address_api.py
│   ├── (route.py)               placeholder — Phase-3 future surface
│   ├── (neighbor.py)            placeholder — Phase-3 future surface
│   └── (introspection.py)       placeholder — Phase-3 future surface
├── socket/                      PUBLIC NAMESPACE (data plane) — unchanged
├── protocols/                   private — unchanged
├── runtime/                     NEW PRIVATE NAMESPACE
│   ├── __init__.py
│   ├── singletons.py            extracted from stack/__init__.py: singleton
│   │                            attribute declarations + the fixture-topology
│   │                            constants (STACK__MAC_ADDRESS, STACK__IP*_HOST,
│   │                            etc.)
│   ├── packet_handler/          was stack/packet_handler/ (verbatim move)
│   │   ├── __init__.py
│   │   ├── _icmp_error_demux.py
│   │   └── packet_handler__<proto>__<rx|tx>.py × 20
│   ├── rx_ring.py               was stack/rx_ring.py
│   ├── tx_ring.py               was stack/tx_ring.py
│   ├── timer.py                 was stack/timer.py
│   └── subsystem.py             was lib/subsystem.py
└── lib/                         private — slimmed
    ├── dad_slot_registry.py
    ├── dhcp_uid.py
    ├── interface_layer.py
    ├── ip4_source_selection.py
    ├── ip6_ext_hdr_limits.py
    ├── ip6_flow_label.py
    ├── ip6_policy_table.py
    ├── ip6_source_selection.py
    ├── ip_helper.py
    ├── ip_scope.py
    ├── logger.py
    ├── name_enum.py
    ├── neighbor.py
    ├── neighbor__constants.py
    ├── packet_stats.py
    ├── plpmtud.py
    └── tx_status.py
```

`lib/` shrinks from 21 modules to 17 (sysctl + subsystem + link_api
+ address_api moved out).

## 5. File-by-file move map

### 5.1 Public API moves (stay under `stack.*` namespace; new file paths)

| Old                          | New                          | Public symbol path        |
|------------------------------|------------------------------|---------------------------|
| `pytcp/lib/sysctl.py`        | `pytcp/stack/sysctl.py`      | `pytcp.stack.sysctl`      |
| `pytcp/lib/link_api.py`      | `pytcp/stack/link.py`        | `pytcp.stack.link`        |
| `pytcp/lib/address_api.py`   | `pytcp/stack/address.py`     | `pytcp.stack.address`     |

Public symbol path stays identical — `pytcp.stack.sysctl` is
already the name `lib/sysctl.py` is imported under in source
code, but lots of sites currently say
`from pytcp.lib import sysctl as sysctl_module`. After the
move that legacy form is still allowed (the module exists at
both `pytcp.stack.sysctl` and the legacy path can be deleted),
but **all sites migrate to the new path in the same commit**.

### 5.2 Runtime moves (private — new namespace `pytcp.runtime.*`)

| Old                                | New                                | Notes                                                  |
|------------------------------------|------------------------------------|--------------------------------------------------------|
| `pytcp/stack/packet_handler/`      | `pytcp/runtime/packet_handler/`    | 22 files in directory; bulk `git mv` of the folder    |
| `pytcp/stack/rx_ring.py`           | `pytcp/runtime/rx_ring.py`         |                                                        |
| `pytcp/stack/tx_ring.py`           | `pytcp/runtime/tx_ring.py`         |                                                        |
| `pytcp/stack/timer.py`             | `pytcp/runtime/timer.py`           |                                                        |
| `pytcp/lib/subsystem.py`           | `pytcp/runtime/subsystem.py`       | `Subsystem` is a runtime base, not a generic helper    |

### 5.3 `stack/__init__.py` split

**Revised approach** — singletons stay in `pytcp/stack/`. The
test harness writes `stack.X = Y` directly (verified in
`pytcp/tests/lib/{icmp,udp,tcp_session}_testcase.py`); moving
singletons to a sibling module would break those writes
because `import pytcp.stack as stack; stack.X = Y` writes to
the `pytcp.stack` module, not to whatever module hosts the
declaration. Re-import-time visibility would only get the
*initial* value across, not subsequent mutations.

Split (752 lines → 2 files):

| Concern                                                | Lines (est) | New home                       |
|--------------------------------------------------------|-------------|--------------------------------|
| Constants (secrets, MTU, address defaults, `LOG__*`, port range, `IP*__SUPPORT`, etc.) | ~150 | stays in `pytcp/stack/__init__.py` |
| `TunTapFlag` enum + `IFF_*` bare-alias exports + `TUNSETIFF` constant | ~30 | stays in `pytcp/stack/__init__.py` |
| Singleton attribute declarations (`tx_ring: TxRing`, `arp_cache: ArpCache`, `nd_cache: NdCache`, `tcp_stack: TcpStack`, `pmtu_cache: dict[...]`, `sockets: dict[...]`, `icmp{4,6}_error_rate_limiter`, `packet_handler`, `timer`, `address: Ip4AddressApi`, `link: LinkApi`, `dhcp4_client`, `link_local`, `stack_initialized: bool`, `stack_running: bool`, `interface_mtu`) + `current_pmtu()` helper | ~90 | stays in `pytcp/stack/__init__.py` |
| `initialize_interface__tap()` / `initialize_interface__tun()` (TUN/TAP fd setup helpers) | ~60 | stays in `pytcp/stack/__init__.py` |
| `init(...)`, `start()`, `stop()`, `mock__init(...)` lifecycle functions | ~360 | **new** `pytcp/stack/lifecycle.py` |
| Re-exports — `from pytcp.stack.lifecycle import init, start, stop, mock__init` | ~5 | added to `pytcp/stack/__init__.py` |

The lifecycle functions in `lifecycle.py` read and write the
singletons via `import pytcp.stack as stack; stack.X = Y` —
the same pattern the test harness uses, so a single canonical
"writeable" module for stack state (the `pytcp.stack`
namespace). `runtime/` does NOT get a `singletons.py`.

Result: `pytcp/stack/__init__.py` shrinks from ~752 lines to
~415 lines (45% reduction); the gnarly 360-line lifecycle code
moves to a dedicated file. The Phase-3 north-star table stays
honoured — `pytcp.stack.*` is still the public namespace; the
internal split is between `__init__.py` (state) and
`lifecycle.py` (lifecycle methods).

### 5.4 Test layout — unit tests relocate; integration tests stay

#### 5.4.1 Unit-test relocations (path convention from `unit_testing.md §3`)

The test-file naming convention pins `<pkg>/<subpkg>/<source>.py`
to `<pkg>/tests/unit/<subpkg>/test__<subdir>__<source>.py`. When
source moves, the corresponding unit-test file moves too:

**Tests for moved `lib/` → `stack/` modules (3 files):**

| Old test path                                          | New test path                                   |
|--------------------------------------------------------|-------------------------------------------------|
| `pytcp/tests/unit/lib/test__lib__sysctl.py`            | `pytcp/tests/unit/stack/test__stack__sysctl.py` |
| `pytcp/tests/unit/lib/test__lib__link_api.py`          | `pytcp/tests/unit/stack/test__stack__link.py`   |
| `pytcp/tests/unit/lib/test__lib__address_api.py`       | `pytcp/tests/unit/stack/test__stack__address.py`|

Note: the source rename `link_api.py` → `link.py` collapses
the redundant `_api` suffix. Test name follows suit:
`test__lib__link_api.py` → `test__stack__link.py` (not
`test__stack__link_api.py`).

**Tests for moved `lib/subsystem.py` → `runtime/subsystem.py` (1 file):**

| Old test path                                       | New test path                                          |
|-----------------------------------------------------|--------------------------------------------------------|
| `pytcp/tests/unit/lib/test__lib__subsystem.py`      | `pytcp/tests/unit/runtime/test__runtime__subsystem.py` |

**Tests for moved `stack/` → `runtime/` modules (3 files):**

| Old test path                                  | New test path                                          |
|------------------------------------------------|--------------------------------------------------------|
| `pytcp/tests/unit/stack/test__stack__rx_ring.py` | `pytcp/tests/unit/runtime/test__runtime__rx_ring.py` |
| `pytcp/tests/unit/stack/test__stack__tx_ring.py` | `pytcp/tests/unit/runtime/test__runtime__tx_ring.py` |
| `pytcp/tests/unit/stack/test__stack__timer.py`   | `pytcp/tests/unit/runtime/test__runtime__timer.py`   |

**Tests for moved `stack/packet_handler/` → `runtime/packet_handler/` (17 files):**

`pytcp/tests/unit/stack/packet_handler/` → `pytcp/tests/unit/runtime/packet_handler/`

Files within the directory rename from `test__stack__packet_handler__*` to
`test__runtime__packet_handler__*` (15 files). Two outliers don't carry the
`__stack__` prefix today and rename in style only:

| Old test path (relative to `stack/packet_handler/`)            | New test path (relative to `runtime/packet_handler/`)            |
|----------------------------------------------------------------|------------------------------------------------------------------|
| `test___icmp_error_demux.py`                                   | `test___icmp_error_demux.py` *(unchanged name; dir moves)*       |
| `test__packet_handler__ip6_frag__tx__rfc6980.py`               | `test__packet_handler__ip6_frag__tx__rfc6980.py` *(unchanged)*  |
| `test__stack__packet_handler__init.py`                         | `test__runtime__packet_handler__init.py`                         |
| `test__stack__packet_handler__<proto>__<rx\|tx>.py` × 15       | `test__runtime__packet_handler__<proto>__<rx\|tx>.py`            |

**Test for `stack/__init__.py` split (1 file → 2 files):**

| Old test path                                  | New test paths                                              |
|------------------------------------------------|-------------------------------------------------------------|
| `pytcp/tests/unit/stack/test__stack__init.py`  | `pytcp/tests/unit/stack/test__stack__init.py` *(slim re-export tests)* |
|                                                | `pytcp/tests/unit/stack/test__stack__lifecycle.py` *(init/start/stop/mock__init tests)* |
|                                                | `pytcp/tests/unit/runtime/test__runtime__singletons.py` *(if any singleton-attr-only tests exist)* |

The split mirrors the `stack/__init__.py` split in §5.3. Most
of `test__stack__init.py`'s coverage today exercises `init()` /
`start()` / `stop()` — that bulk moves to
`test__stack__lifecycle.py`. The remaining slim `test__stack__init.py`
asserts the public re-export surface (which names appear on
`pytcp.stack`).

**Unit-test file relocation total: ~25 files** (3 + 1 + 3 + 17 + 1 split).

#### 5.4.2 Integration tests — no file relocations

Integration tests under
`pytcp/tests/integration/protocols/<proto>/` (and the legacy
flat `pytcp/tests/integration/protocols/<proto>/test__<proto>__*.py`)
test wire-level behaviour, not source-file paths. They stay
where they are; only their `from pytcp.X import Y` lines
update.

#### 5.4.3 Import-line updates inside every affected test file

| Old import                                  | New import                                          |
|---------------------------------------------|-----------------------------------------------------|
| `from pytcp import stack`                   | `from pytcp import stack` *(unchanged)*             |
| `from pytcp.runtime.packet_handler import ...`| `from pytcp.runtime.packet_handler import ...`      |
| `from pytcp.runtime.tx_ring import TxRing`    | `from pytcp.runtime.tx_ring import TxRing`          |
| `from pytcp.runtime.rx_ring import RxRing`    | `from pytcp.runtime.rx_ring import RxRing`          |
| `from pytcp.runtime.timer import Timer`       | `from pytcp.runtime.timer import Timer`             |
| `from pytcp.runtime.subsystem import Subsystem` | `from pytcp.runtime.subsystem import Subsystem`     |
| `from pytcp.lib import sysctl as sysctl_module` | `from pytcp.stack import sysctl as sysctl_module` |
| `from pytcp.stack.link import ...`        | `from pytcp.stack.link import ...`                  |
| `from pytcp.stack.address import ...`     | `from pytcp.stack.address import ...`               |

Counts (from §3.2) translate to ~136 test-file import-line
edits, on top of the ~25 test-file relocations from §5.4.1.

#### 5.4.4 Each relocated test file's module docstring path

Every relocated test file's module docstring (per
`source_files.md §4`) has a path string that must update:

```python
# Old: pytcp/tests/unit/lib/test__lib__sysctl.py
# New: pytcp/tests/unit/stack/test__stack__sysctl.py
```

~25 module-docstring path lines to edit alongside the
`git mv`.

### 5.5 Production-source import updates (~72 files)

Same renames as §5.4. The unit_testing.md / integration_testing.md
rule files reference `pytcp.lib.X` / `pytcp.stack.X` paths in
examples — see §8.

## 6. Phase plan

Six phases, each ending with `make lint && make test` clean.
Phase boundaries are commit boundaries; each phase commit
must independently land green.

### Phase 0 — Decisions + plan freeze (no code)

1. Land this plan doc (no code changes).
2. Open an issue or note in CLAUDE.md if any of the
   following decisions remain open:
   - Is `pytcp.runtime` the right name vs `pytcp._runtime` /
     `pytcp.kernel`? Recommendation: `runtime/` (no leading
     underscore — namespace privacy is documented in this
     plan + CLAUDE.md, not encoded in the path).
   - Do we ship Phase-3 placeholder files (`stack/route.py`
     etc.) now, or wait for each track? Recommendation:
     wait. The N-1 placeholder files would just be empty
     modules.
   - Does `runtime/singletons.py` keep the historical
     `STACK__MAC_ADDRESS` naming, or do those become
     plain `MAC_ADDRESS` once they're no longer under
     `pytcp.stack.*`? Recommendation: keep the
     `STACK__*` prefix — it's the convention the test
     harness imports.

### Phase 1 — Extract `runtime/` (mechanical bulk moves)

**Goal:** Create `pytcp/runtime/` with packet_handler / RX
ring / TX ring / timer / subsystem. All public APIs still
work at their current import paths.

Steps (one commit):

1. `git mv pytcp/stack/packet_handler pytcp/runtime/packet_handler`
2. `git mv pytcp/runtime/rx_ring.py pytcp/runtime/rx_ring.py`
3. `git mv pytcp/runtime/tx_ring.py pytcp/runtime/tx_ring.py`
4. `git mv pytcp/runtime/timer.py pytcp/runtime/timer.py`
5. `git mv pytcp/runtime/subsystem.py pytcp/runtime/subsystem.py`
6. Create `pytcp/runtime/__init__.py` (project-standard
   skeleton from `source_files.md` §2.1).
7. **Relocate unit tests for moved modules** (§5.4.1):
   - `git mv pytcp/tests/unit/lib/test__lib__subsystem.py pytcp/tests/unit/runtime/test__runtime__subsystem.py`
   - `git mv pytcp/tests/unit/stack/test__stack__rx_ring.py pytcp/tests/unit/runtime/test__runtime__rx_ring.py`
   - `git mv pytcp/tests/unit/stack/test__stack__tx_ring.py pytcp/tests/unit/runtime/test__runtime__tx_ring.py`
   - `git mv pytcp/tests/unit/stack/test__stack__timer.py pytcp/tests/unit/runtime/test__runtime__timer.py`
   - `git mv pytcp/tests/unit/stack/packet_handler pytcp/tests/unit/runtime/packet_handler` (whole dir, 17 files)
   - Inside the relocated `packet_handler/` dir, rename
     each file from `test__stack__packet_handler__*.py` to
     `test__runtime__packet_handler__*.py` (15 files; two
     outliers keep their existing names).
8. Bulk-rewrite imports across the codebase (both source and
   tests):
   ```bash
   pytcp.runtime.packet_handler   → pytcp.runtime.packet_handler
   pytcp.runtime.rx_ring          → pytcp.runtime.rx_ring
   pytcp.runtime.tx_ring          → pytcp.runtime.tx_ring
   pytcp.runtime.timer            → pytcp.runtime.timer
   pytcp.runtime.subsystem          → pytcp.runtime.subsystem
   ```
   Expected churn: ~140 import lines (59 + 47 + 34 = 140).
9. Update each moved file's module docstring path (per
   source_files.md §4) — both production source AND the
   relocated test files. ~30 docstring lines.
10. `make lint && make test` — must be green.

Estimated diff size: ~30 source files renamed + ~21 unit-test
files renamed + ~140 import lines + ~50 docstring-path lines
= ~241 edits, ~51 file renames.

**Commit message:**

```
pytcp.runtime: extract internal RX/TX/timer/packet-handler/subsystem

Moves stack/packet_handler/, stack/{rx,tx}_ring, stack/timer, and
lib/subsystem under a new pytcp/runtime/ namespace. These are
implementation guts — no Phase-3 consumer should import them. The
move is mechanical: file paths change, content unchanged; ~140
import-line updates across source + tests follow.

stack/__init__.py is unchanged in this commit; the lifecycle /
sysctl / link / address API extraction happens in subsequent
phases.

make lint clean; make test 10955 passing, 4 skipped, 0 failures.
```

### Phase 2 — Split `stack/__init__.py` into lifecycle + singletons

**Goal:** Move the singleton attribute declarations + fixture
topology constants out of `stack/__init__.py` into
`pytcp/runtime/singletons.py`. Move `init/start/stop/mock__init`
into `pytcp/stack/lifecycle.py`. Shrink
`pytcp/stack/__init__.py` to a pure re-export module.

Steps (one commit):

1. Create `pytcp/stack/lifecycle.py` containing `init()`,
   `start()`, `stop()`, `mock__init()` — copied verbatim from
   the current `stack/__init__.py`. The functions still use
   the `global timer, tx_ring, ...` pattern, but rewritten as
   `import pytcp.stack as _stack; _stack.timer = Timer(...)`
   because the symbols now live in a sibling module.
2. Update `pytcp/stack/__init__.py`:
   - Delete the four lifecycle functions (~360 lines).
   - Add `from pytcp.stack.lifecycle import init, start, stop, mock__init`
     at the bottom of the file so `pytcp.stack.init` /
     `.start` / `.stop` / `.mock__init` keep working.
   - Constants, singleton declarations, `current_pmtu()`,
     TunTapFlag, IFF_* aliases, and the
     `initialize_interface__{tap,tun}()` helpers stay.
3. **Split the existing `test__stack__init.py`** (§5.4.1):
   - Lifecycle tests (`init/start/stop/mock__init`) → new
     `pytcp/tests/unit/stack/test__stack__lifecycle.py`.
   - Re-export surface assertions + constant tests stay in
     the slimmed-down `test__stack__init.py`.
4. `make lint && make test` — must be green.

Risk: `lifecycle.py` mutates `pytcp.stack`'s module-level
state via attribute assignment on the imported `_stack`
module. Python supports this — module attribute assignment
is identical regardless of which file does the assignment,
as long as both files share the same `pytcp.stack` module
object. The test harness uses the same pattern, so this is
the canonical idiom.

### Phase 3 — Relocate Phase-3 public APIs

**Goal:** Move `lib/sysctl.py`, `lib/link_api.py`,
`lib/address_api.py` to `pytcp/stack/sysctl.py`,
`pytcp/stack/link.py`, `pytcp/stack/address.py` respectively.
Update every import site.

Steps (one commit):

1. `git mv pytcp/stack/sysctl.py pytcp/stack/sysctl.py`
2. `git mv pytcp/stack/link.py pytcp/stack/link.py`
3. `git mv pytcp/stack/address.py pytcp/stack/address.py`
4. **Relocate unit tests for these modules** (§5.4.1):
   - `git mv pytcp/tests/unit/lib/test__lib__sysctl.py pytcp/tests/unit/stack/test__stack__sysctl.py`
   - `git mv pytcp/tests/unit/lib/test__lib__link_api.py pytcp/tests/unit/stack/test__stack__link.py`
   - `git mv pytcp/tests/unit/lib/test__lib__address_api.py pytcp/tests/unit/stack/test__stack__address.py`
5. Bulk-rewrite imports (source + tests):
   ```
   pytcp.stack.sysctl       → pytcp.stack.sysctl
   pytcp.stack.link     → pytcp.stack.link
   pytcp.stack.address  → pytcp.stack.address
   ```
   Expected churn: ~32 import lines (12 + 2 + 18).
6. Update class names if the file rename suggests
   (`LinkApi` stays — class name unchanged; only the module
   path changes).
7. Update each moved source AND test file's module docstring
   path. ~6 docstring lines.
8. `make lint && make test` — must be green.

After this phase, every `pytcp.stack.X` import path is a
genuine Phase-3 public API and nothing else.

### Phase 4 — `lib/` cleanup audit

**Goal:** Confirm the remaining files in `pytcp/lib/` are
genuine generic helpers, not stragglers that should have moved
to `runtime/` or `stack/`.

Steps (one commit, or zero if the audit finds nothing):

1. Re-grep `from pytcp.lib import ...` and confirm every
   remaining `lib/` file is consumed by ≥2 distinct
   subpackages without becoming Phase-3-visible.
2. Specific files to re-validate:
   - `lib/packet_stats.py` — used by tests + every handler.
     **Keep in `lib/`** (it's a dataclass shared across
     handlers; not Phase-3, not runtime).
   - `lib/logger.py` — used everywhere. **Keep in `lib/`**.
   - `lib/neighbor.py` + `lib/neighbor__constants.py` —
     used by ArpCache + NdCache. Currently sysctl-backed
     constants. **Keep in `lib/`** (not user-visible).
   - `lib/plpmtud.py` — used by TCP + UDP + ICMP modules.
     **Keep in `lib/`**.
   - `lib/ip_helper.py`, `lib/ip_scope.py`,
     `lib/ip{4,6}_source_selection.py`,
     `lib/ip6_policy_table.py`, `lib/ip6_flow_label.py`,
     `lib/ip6_ext_hdr_limits.py` — IP helper functions.
     **Keep in `lib/`** (cross-protocol helpers).
   - `lib/dad_slot_registry.py` — DAD ND helper. **Keep in
     `lib/`** (ARP and ND both consume).
   - `lib/dhcp_uid.py` — DHCP4 helper. **Keep in `lib/`**.
   - `lib/interface_layer.py` — `InterfaceLayer` enum. The
     enum has Phase-3 visibility (via `stack.link.layer`).
     Recommendation: **keep in `lib/`** for now; consider
     exporting through `stack/link.py` if a future
     consumer needs it directly. Don't move in this plan.
   - `lib/name_enum.py` — used by `socket/__init__.py` for
     `AddressFamily` / `SocketType`. **Keep in `lib/`**.
   - `lib/tx_status.py` — `TxStatus` enum used by every
     TX path. **Keep in `lib/`**.
3. If anything looks misclassified during this audit,
   move it. Expected: zero or one moves.
4. `make lint && make test`.

### Phase 5 — Documentation + rules updates

**Goal:** Sweep `CLAUDE.md`, `.claude/rules/*.md`, and
`docs/**/*.md` for stale path references.

Steps (one commit):

1. `CLAUDE.md` — update the file paths in the
   Packet-flow ASCII diagram + the "Stack-wide configuration
   constants" pointer + the Phase-3 API table cell that says
   `pytcp.stack.sysctl registry`.
2. `.claude/rules/pytcp.md` — every reference to
   `pytcp/stack/sysctl.py` → `pytcp/stack/sysctl.py`,
   `pytcp/runtime/subsystem.py` → `pytcp/runtime/subsystem.py`,
   `pytcp/runtime/packet_handler/` →
   `pytcp/runtime/packet_handler/`, etc. ~8 line-level
   edits.
3. `.claude/rules/unit_testing.md` and
   `.claude/rules/integration_testing.md` — same path
   updates in their cross-reference tables and §11 example
   code blocks.
4. `docs/refactor/*.md` — re-grep all 19 plan docs for
   stale paths. Most reference `pytcp.stack.sysctl` /
   `pytcp.runtime.packet_handler` in their "Touch points"
   tables; ~69 line-level edits.
5. `docs/rfc/**/*.md` adherence audits — same path updates
   where they cite implementation files. Sampling suggests
   <10 files affected.
6. `make lint` (no Python change but lint pass still runs).
7. Verify no broken links by skimming the rule files.

### Phase 6 — Close-out

1. Update the auto-memory `MEMORY.md` index (add a
   `project_directory_restructure.md` entry).
2. Open a status-line note: pytcp dir restructure complete;
   subsequent feature plans land under the new paths.
3. Mark this plan's Status field as **Shipped**.

## 7. Import-update execution strategy

The bulk of the work is the same find-and-replace
applied 200+ times. Three execution options:

### Option A — One scripted rewrite per phase

```bash
python3 << 'EOF'
import re
from pathlib import Path

REWRITES = [
    (r'\bpytcp\.stack\.packet_handler\b', 'pytcp.runtime.packet_handler'),
    (r'\bpytcp\.stack\.rx_ring\b',        'pytcp.runtime.rx_ring'),
    (r'\bpytcp\.stack\.tx_ring\b',        'pytcp.runtime.tx_ring'),
    (r'\bpytcp\.stack\.timer\b',          'pytcp.runtime.timer'),
    (r'\bpytcp\.lib\.subsystem\b',        'pytcp.runtime.subsystem'),
]

for py in Path('.').rglob('*.py'):
    if '__pycache__' in py.parts or 'venv' in py.parts:
        continue
    text = py.read_text()
    new = text
    for pattern, replacement in REWRITES:
        new = re.sub(pattern, replacement, new)
    if new != text:
        py.write_text(new)
        print(f'rewrote {py}')
EOF
```

Run, then `make lint && make test`. If anything fails, the
diff is small enough to investigate by hand.

### Option B — Per-file Edit calls

Slower but visible in the conversation; better for review.
Pick this only if the scripted rewrite produces too many
false positives.

### Option C — Hybrid

Phase 1 scripted (mechanical packet_handler / rx_ring /
tx_ring / timer / subsystem renames). Phase 2 hand-edited
(the `stack/__init__.py` split has structural changes, not
just import rewrites). Phase 3 scripted (sysctl / link /
address renames).

**Recommendation: Option C.** Phases 1 + 3 are pure
find-and-replace; Phase 2 is a content split that warrants
careful editing.

## 8. Validation gates

Each phase must pass before commit:

1. **`make lint`** — codespell + isort + black + flake8 +
   mypy strict + pylint. Mypy strict is the load-bearing
   gate: any missed import update surfaces as
   `[import-not-found]` immediately.
2. **`make test`** — full suite (currently 10959 examples,
   4 pre-existing skips). Any test failure rolls back
   the phase.
3. **§7.2 docstring audit** — n/a for this plan (no new
   test files; existing tests are unchanged in content).
4. **Smoke run** — `make tap7 && make run` for ~30 seconds
   to confirm the stack actually starts after each phase
   (the rings and packet-handler are exercised at boot).
   This is a manual check; the test suite mocks them.

## 9. Risks and mitigations

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Missed import rewrite in a corner file (examples/, scripts/) | Medium | Re-grep after each phase; mypy strict catches `[import-not-found]` at lint time. |
| `pytcp.stack.X` attribute access pattern breaks because `stack/__init__.py` no longer exposes the name directly (only via `from pytcp.runtime.singletons import *`) | Medium-High | Phase 2's `__all__` list must enumerate every legacy name the harness's `stack.__dict__.copy()` snapshot pattern relied on. Validation: full integration suite covers this. |
| `from pytcp.lib import sysctl as sysctl_module` left dangling — the legacy `pytcp.stack.sysctl` path no longer exists | Low | Mypy strict catches; Phase 3's import-rewrite covers. |
| `examples/` or `tests_runner.py` external scripts break | Low | Both are in-tree; mypy strict + `make test` covers. |
| External-consumer codebase (if any) breaks | n/a | PyTCP has no external consumers today; the only "consumer" is the in-tree test suite + `examples/`. |
| Phase 2's `stack/__init__.py` split miscategorises a constant or singleton | Medium | The 751-line file is straightforward by inspection; risk is mechanical, not architectural. Use Phase 2's audit checklist. |
| docs/refactor/ plan files reference stale paths after the move | Medium | Phase 5 sweeps them. |
| The renamed module is imported as `from pytcp.runtime.packet_handler import _icmp_error_demux` in tests; `_`-prefixed names imported across module boundaries was flagged forbidden by `.claude/rules/source_files.md §5.1` | Low | This is pre-existing; the underscore-import rule was tightened earlier. Audit the four offenders in `_icmp_error_demux.py` consumers (likely zero — it's `_`-prefixed for a reason). |

## 10. Rollback procedure

Each phase commits independently. To roll back:

- **Phase 1**: `git revert <phase-1-sha>` — reverses the
  bulk move. Subsequent phases that depend on Phase 1
  paths would need rebasing.
- **Phase 2**: `git revert <phase-2-sha>` — restores the
  751-line `stack/__init__.py`.
- **Phase 3**: `git revert <phase-3-sha>` — reverses the
  sysctl / link / address moves.
- **Phase 4/5/6**: revert-safe; no architectural changes.

`make test` validates that each revert lands clean.

## 11. Sequencing decision

**Recommended order: Phase 1 → 2 → 3** (the order this
plan documents). Rationale:

- Phase 1 (extract `runtime/`) is the safest mechanical
  step. No `__init__.py` semantics change; just paths.
- Phase 2 splits the 751-line file; depends on Phase 1
  because `lifecycle.py` and `singletons.py` need
  `from pytcp.runtime.packet_handler import ...`.
- Phase 3 relocates public APIs; trivially depends on
  Phase 2 because `stack/__init__.py` re-exports
  `from . import sysctl, link, address`.

Alternate order **Phase 3 → 1 → 2** is also valid (move
APIs first, then implementation). The recommended order
is preferred because it lands the highest-blast-radius
change (Phase 1, ~140 import-line edits) first, when
the codebase is still in a known-good state.

## 12. Out-of-scope follow-ups

- **Legacy flat-directory test deletion** — eight
  `pytcp/tests/integration/protocols/<proto>/test__<proto>__*.py`
  files are still siblings of `protocols/`. See
  earlier audit; not addressed by this plan.
- **Phase-3 future surfaces** (`stack/route.py`,
  `stack/neighbor.py`, `stack/introspection.py`) —
  each gets its own track per CLAUDE.md North Star.
- **`pytcp/lib/` second-pass audit** — Phase 4 here is
  a quick triage. A deeper "is this really a helper or
  is it cross-cutting infrastructure" audit may surface
  candidates for further moves; defer to a follow-up
  plan if any.

## 13. Estimated effort

| Phase | Engineering effort | Review effort | Risk |
|-------|--------------------|---------------|------|
| 0 (this plan)                              | ~2 h    | ~30 min | n/a |
| 1 (runtime extract + 21 test relocations)  | ~3 h    | ~1 h    | Low-Medium |
| 2 (stack split + test split)               | ~4 h    | ~1 h    | Medium |
| 3 (API relocate + 3 test relocations)      | ~1.5 h  | ~30 min | Low |
| 4 (lib audit)                              | ~1 h    | ~15 min | Very low |
| 5 (docs/rules)                             | ~2 h    | ~30 min | Low |
| 6 (close-out)                              | ~30 min | ~5 min  | None |
| **Total**                                  | **~14 h** | **~3.5 h** | **Medium** |

Could land in one focused day if no surprises surface, two
days if the Phase 2 split runs into singleton-snapshot
edge cases the test harness hadn't surfaced yet. The added
test-file relocations are bulk `git mv` operations — the
risk addition over the original estimate is small, but
~25 file moves do widen the review diff.

## 14. Cross-references

- `CLAUDE.md` — Project North Star (the seven Phase-3
  consumer surfaces this plan honours).
- `.claude/rules/pytcp.md` — the canonical rule for
  `pytcp/` authoring; describes `Subsystem`,
  packet-handler mixin composition, BSD socket facade,
  sysctl registry, stack configuration. Phase 5 updates
  the path strings.
- `.claude/rules/source_files.md` §2.1 — file skeleton
  every new `runtime/` / `stack/` file follows.
- `docs/refactor/link_api.md` — Phase-3 shipped track
  this restructure makes structurally visible
  (`stack/link.py`).
- `docs/refactor/sysctl_framework.md` — sysctl design,
  affected by Phase 3's `lib/sysctl.py` →
  `stack/sysctl.py` move.
- `docs/refactor/packet_handler_rewrite_plan.md` —
  separate plan touching the same code; deconflict if
  in-flight.
