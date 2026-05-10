# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PyTCP is a pure Python TCP/IP stack (Python 3.14+) built on TAP/TUN interfaces. It implements Ethernet through TCP/UDP with zero runtime dependencies (stdlib only). The project is structured as three independent packages: `net_addr`, `net_proto`, and `pytcp`.

## Project North Star

PyTCP's goal is to be a pure-Python TCP/IP stack that is **feature-equivalent to the Linux kernel network stack**, in two phases:

- **Phase 1 (current):** host-stack parity. Default-configured Linux host coverage — every protocol mechanism a Linux host runs by default.
- **Phase 2 (future):** router-grade parity. Full forwarding plane: FIB, IP forwarding, ICMP Redirect generation, PMTU advertising on transit, RFC 1812 router requirements, IGMP/MLD querier role.

Design decisions made in Phase 1 must not foreclose Phase 2. Concretely:

- **Don't bake "we are the destination" assumptions** into parser / dispatch code paths that will later need to make a forwarding decision. Keep RX-path delivery and forward-or-deliver routing as separable steps even if the forward branch is currently a stub.
- **Parse extension headers / options as full typed objects, not opaque blobs**, even when the host has no semantic use for them — Phase 2 needs to forward them faithfully (RH preservation, HBH walking, etc.).
- **Per-destination routing state must be representable** in the eventual data model. Single-gateway shortcuts are tolerated as Phase 1 simplifications; they should be marked with a `# Phase 2: ...` comment so the upgrade path is greppable.
- **Hop-Limit / TTL handling, ICMP error rate-limiting, embedded-data preservation** — already wired host-side, designed once with forwarding in mind.

Conformance precedence:

1. **RFC text first.** When the governing RFC is unambiguous, PyTCP follows it. Deliberate deviation requires an inline comment citing the rationale.
2. **Linux behavior as tiebreaker.** When the RFC is silent, ambiguous, or offers a SHOULD/MAY menu, PyTCP picks the Linux choice. Cite the Linux source file or sysctl in the commit body so the decision is greppable.
3. **Linux-specific extensions are in scope** when there is a real PyTCP consumer (e.g. CIPSO/CALIPSO, IP_RECVERR-style socket APIs, sysctl knobs that gate behavior).

Explicit non-goals (out of scope regardless of phase):

- Hardware offloads, XDP / AF_XDP, kernel-bypass paths
- Netfilter / eBPF / nftables hooks
- Crypto extensions (AH, ESP, IPsec, MACsec)
- Mobility extensions (MIPv6, NEMO, RH2 mobility processing)
- Userspace routing protocols (BGP, OSPF, RIP — these belong outside the stack)

Feature triage uses this north star: a gap that exists in PyTCP but not in Linux as host (Phase 1) or router (Phase 2) is on-list. Phase-2 items are tracked but deferrable; Phase-1 items are not.

## Commands

```bash
# Setup
make venv                 # create virtual environment (Python 3.14+)
source venv/bin/activate

# Development
make lint                 # codespell + isort + black + flake8 + mypy + pylint
make test                 # run all three test suites via unittest
make validate             # lint + test together

# Run the stack (requires TAP interface and sudo for bridge/tap/tun setup)
make tap7                 # create tap7 interface (sudo)
make bridge               # set up bridge (sudo)
make run                  # run stack on tap7

# Clean
make clean                # remove venv, caches, build artifacts
```

### Running a single test

```bash
# unittest is the test framework — run a specific test file directly
PYTHONPATH=. python -m unittest net_proto/tests/unit/protocols/arp/test__arp__assembler__operation.py

# Or run an entire suite via the find-glob the Makefile uses
PYTHONPATH=. python -m unittest $(find net_proto/tests/unit -name 'test__*.py')
```

## Architecture

### Package boundaries

| Package | Role |
|---|---|
| `net_addr/` | Standalone address library: `Ip4Address`, `Ip6Address`, `MacAddress`, etc. No dependency on the other packages. |
| `net_proto/` | Protocol packet library: parse/assemble/validate. Depends on `net_addr` only. |
| `pytcp/` | Running stack: threads, sockets, ARP/ND caches, RX/TX rings. Depends on both. |

### Packet flow

```
TAP/TUN fd
  └─> RxRing  ──> PacketHandler (per protocol, RX side)
                     └─> Socket queues / ARP cache / ND cache / fragment store
  <── TxRing  <── PacketHandler (per protocol, TX side)
                     <── Socket send / ARP probe / ICMPv6 ND / DHCP
```

RX and TX handlers live in `pytcp/stack/packet_handler/packet_handler__<proto>__<rx|tx>.py`. There are ~19 handler files covering Ethernet, ARP, IPv4, IPv6, IPv6-frag, ICMPv4, ICMPv6, TCP, UDP, and 802.3.

The stack is threaded; every subsystem extends `pytcp/lib/subsystem.py` (`Subsystem` base class) and implements `_subsystem_loop()`. Startup / shutdown use `threading.Event`.

The socket API (`pytcp/socket/`) mimics BSD sockets: `TcpSocket`, `UdpSocket`, `RawSocket` are returned by a factory `__new__` on the abstract `socket` class. TCP's FSM is a separate runtime under `pytcp/protocols/tcp/`, decomposed into `tcp__session.py` (the `TcpSession` class), `tcp__enums.py`, `tcp__constants.py`, `tcp__fsm.py` (the dispatch table), and one `tcp__fsm__<state>.py` free-function module per FSM state. `pytcp/socket/tcp__socket.py` is the BSD-facade shim that delegates to `TcpSession`.

Stack-wide configuration constants (IP/MAC addresses, ARP/ND cache timers, MTU, port ranges, logger channels) live in `pytcp/stack/__init__.py`.

### Per-RFC adherence

Per-RFC adherence audits live at `docs/rfc/<family>/rfcXXXX__<name>/adherence.md` across TCP, IP6, ICMP6, ICMP4, ARP families. Use the [`rfc_adherence_audit`](.claude/skills/rfc_adherence_audit/SKILL.md) skill to add or refresh an entry.

## Canonical Rules

PyTCP has six canonical rule files in `.claude/rules/`. They are auto-loaded into the session context — read the relevant one before any non-trivial change. CLAUDE.md does not duplicate their content; when something feels missing here, it lives in one of the rules below.

| Rule | What it covers | Read when |
|---|---|---|
| [`feature_implementation.md`](.claude/rules/feature_implementation.md) | tests-first workflow, spec grounding, commit discipline, phase reporting | Every code change |
| [`python_features.md`](.claude/rules/python_features.md) | Python 3.10–3.14 language features (PEP 604 / 585 / 695 / 696 / 698 / 649); forbidden pre-3.10 fallbacks | Any new file or refactor |
| [`typing.md`](.claude/rules/typing.md) | mypy strict, annotations, generics, `Self` / `@override`, `Protocol` / `TypedDict`, `cast` and `# type: ignore` policy | Any annotation |
| [`coding_style.md`](.claude/rules/coding_style.md) | PyTCP source-file conventions (file skeleton, copyright block, six-file protocol layout, dataclass shape, parser / assembler / error patterns, `Subsystem` runtime) | Any new source file |
| [`unit_testing.md`](.claude/rules/unit_testing.md) | unit tests (framework, mocking discipline §6a, isolation §10a, modern Python features §10b, the §7.2 docstring audit) | Any new unit test |
| [`integration_testing.md`](.claude/rules/integration_testing.md) | integration tests (harness hierarchy, drive_rx / probe / fluent-assert pattern, stat-counter assertions) | Any new integration test |

### Pre-commit checklist (MANDATORY)

1. `make lint` clean (codespell + isort + black + flake8 + mypy strict + pylint).
2. `make test` clean.
3. **§7.2 docstring audit** clean on any test file you wrote or modified (see [`unit_testing.md`](.claude/rules/unit_testing.md) §7.2).
4. **Modernise legacy typing / Python forms on touch** — fix them in the same commit, not as a separate sweep. Forbidden forms catalogued in [`python_features.md`](.claude/rules/python_features.md) §22 and [`typing.md`](.claude/rules/typing.md) §23.

### Tests-first (MUST)

Every behavioural change opens with one or more **failing tests** that pin the spec requirement, then the implementation flips them green. See [`feature_implementation.md`](.claude/rules/feature_implementation.md) §2 for the full procedure.

### Skills

- [`rfc_adherence_audit`](.claude/skills/rfc_adherence_audit/SKILL.md) — add or refresh a per-RFC adherence record.
- [`sysctl_knob`](.claude/skills/sysctl_knob/SKILL.md) — add a runtime-tunable sysctl-backed constant.
