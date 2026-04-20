# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PyTCP is a pure Python TCP/IP stack (Python 3.12+) built on TAP/TUN interfaces. It implements Ethernet through TCP/UDP with zero runtime dependencies (stdlib only). The project is structured as three independent packages: `net_addr`, `net_proto`, and `pytcp`.

## Commands

```bash
# Setup
make venv                 # create virtual environment (Python 3.12+)
source venv/bin/activate

# Development
make lint                 # codespell + isort + black + flake8 + mypy + pylint
make test                 # run all three test suites via testslide
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
# testslide is the test framework - run a specific test file directly
python -m testslide net_proto/tests/unit/protocols/arp/test__arp__assembler__operation.py

# Or run an entire suite
python -m testslide net_proto/tests/unit/
```

### Linting tools and config

- **black** / **isort**: line length 120, black profile
- **flake8**: ignores E203, E266, E701, E704, W503, E731, E741
- **mypy**: strict mode (`disallow_untyped_defs`, `disallow_any_unimported`, `check_untyped_defs`, etc.)
- **codespell**: custom ignore list in Makefile (`ect,ether,nd,tha,assertIn,sourc`)

## Architecture

### Package Boundaries

| Package | Role |
|---|---|
| `net_addr/` | Standalone address library: `Ip4Address`, `Ip6Address`, `MacAddress`, etc. No dependency on the other packages. |
| `net_proto/` | Protocol packet library: parse/assemble/validate. Depends on `net_addr` only. |
| `pytcp/` | Running stack: threads, sockets, ARP/ND caches, RX/TX rings. Depends on both. |

### `net_proto` Protocol Structure

Each protocol under `net_proto/protocols/<proto>/` follows a fixed layout:

- `*__header.py` — header dataclass + constants
- `*__parser.py` — parse bytes into header, raising `*IntegrityError` or `*SanityError`
- `*__assembler.py` — build bytes from header + payload
- `*__base.py` — shared logic between parser and assembler
- `enums.py` — protocol-specific enums
- `errors.py` — exception classes
- `tests/unit/` — testslide test files mirroring the source layout

Validation happens at two explicit levels: **integrity** (structural/format) and **sanity** (logical consistency). These produce separate exception types per protocol.

### `pytcp` Stack Runtime

The stack is threaded; every subsystem extends `pytcp/lib/subsystem.py` (`Subsystem` base class) and implements `_subsystem_loop()`. Startup/shutdown use `threading.Event`.

Packet flow:

```
TAP/TUN fd
  └─> RxRing  ──> PacketHandler (per protocol, RX side)
                     └─> Socket queues / ARP cache / ND cache / fragment store
  <── TxRing  <── PacketHandler (per protocol, TX side)
                     <── Socket send / ARP probe / ICMPv6 ND / DHCP
```

RX and TX handlers live in `pytcp/stack/packet_handler/packet_handler__<proto>__<rx|tx>.py`. There are ~19 handler files covering Ethernet, ARP, IPv4, IPv6, IPv6-frag, ICMPv4, ICMPv6, TCP, UDP, and 802.3.

The socket API (`pytcp/socket/`) mimics BSD sockets: `TcpSocket`, `UdpSocket`, `RawSocket` are returned by a factory `__new__` on the abstract `socket` class. TCP includes a full FSM in `tcp__session.py`.

### Protocol Stacking with Generics

Assembler classes use Python 3.12 generic syntax for type-safe stacking:

```python
class EthernetAssembler[P: (ArpAssembler | Ip4Assembler | Ip6Assembler)]:
    ...
```

This enforces which payloads are legal at compile time via mypy.

### Configuration

Stack-wide constants (IP/MAC addresses, ARP/ND cache timers, MTU, port ranges, logger channels) live in `pytcp/stack/__init__.py` lines 76–138.

## Conventions

- **File naming**: double-underscore separators — `tcp__socket.py`, `packet_handler__arp__rx.py`, `test__arp__assembler__operation.py`.
- **Type hints**: full strict mypy compliance required on all new code.
- **No comments on obvious code**: docstrings and inline comments only when the *why* is non-obvious.
- **Zero external runtime deps**: the stack itself uses stdlib only; `aenum` and `click` are only for `net_addr` CLI helpers.
- **Memory**: prefer `memoryview`/buffer protocol for packet data; assemblers expose `__buffer__()`.

## Coding Style Rules

### File Structure

Every file follows this exact order:
1. `#!/usr/bin/env python3` shebang
2. 80-char `#`-bordered copyright/license block
3. Module docstring with: description, file path, and `ver 3.0.x`
4. Imports
5. Module-level constants
6. Class definition(s)

### Imports

- Order: stdlib → `dataclasses`/`typing` → local packages (`net_addr`, `net_proto`, `pytcp`)
- Multi-import from same module uses parentheses, never backslash continuation
- Circular-import avoidance uses `TYPE_CHECKING` guard
- No `__all__` except in package `__init__.py` files

```python
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from net_proto.protocols.tcp.tcp__base import Tcp
```

### Module-Level Constants

- ALL_CAPS with double-underscore delimiters: `TCP__HEADER__LEN`, `IP6__MIN_MTU`
- Double underscores encode hierarchy: `PROTOCOL__CATEGORY__NAME`
- Inline comment only when value needs RFC citation or non-obvious explanation

### Dataclasses

- Always configured `@dataclass(frozen=True, kw_only=True, slots=True)`
- Fields with non-trivial configuration use `field(repr=False, init=False, default=...)`
- `__post_init__` is always decorated `@override` and contains only `assert` validation
- Frozen dataclass mutation (rare) uses `object.__setattr__(self, name, value)`

### Class Hierarchy Pattern (per protocol)

```
*Header (dataclass)                   ← frozen data, struct pack/unpack
*HeaderProperties (ABC)               ← @property accessors into _header
*OptionsProperties (ABC)              ← @property accessors into _options
*Base (Tcp, ProtoBase...)             ← declares _header/_options/_payload
*Parser(Tcp, ProtoParser)             ← integrity → parse → sanity pipeline
*Assembler(Tcp[P], ProtoAssembler)    ← kw-only ctor, assemble() method
```

### Naming Conventions

| Target | Pattern | Example |
|---|---|---|
| Module constants | `PROTO__FIELD` | `TCP__HEADER__LEN` |
| Assembler params | `proto__field` | `tcp__sport` |
| Private attributes | `_name` | `_header`, `_frame` |
| Private methods | `_name` | `_validate_integrity` |
| Test classes | `Test<Feature>__<Variant>` | `TestTcpParser__Ip4` |
| Test methods | `test__proto__component` | `test__tcp__parser` |
| Files | `proto__component.py` | `tcp__header.py` |

No trailing underscores. No dunder names except standard Python protocols.

### Type Annotations

- Use Python 3.10+ syntax everywhere: `Type1 | Type2`, not `Union[Type1, Type2]`
- Use lowercase generics: `list[Buffer]`, `dict[str, Any]`
- Use `Self` from `typing` for self-referential classmethods
- Decorate every override with `@override`
- Mark positional-only parameters with `/`:
  ```python
  def assemble(self, buffers: list[Buffer], /) -> None:
  ```
- All assembler constructor parameters are keyword-only (after bare `*`)

### Validation

**In dataclass headers** (`__post_init__`):
```python
assert is_uint16(self.sport), f"The 'sport' field must be a 16-bit unsigned integer. Got: {self.sport}"
```

**In parsers** — three mandatory phases:
```python
def __init__(self, packet_rx: PacketRx) -> None:
    self._frame = packet_rx.frame
    self._validate_integrity()
    self._parse()
    self._validate_sanity()
```

- `_validate_integrity()`: structural/format checks → raises `*IntegrityError`
- `_parse()`: extracts fields from buffer
- `_validate_sanity()`: logical consistency → raises `*SanityError`

Walrus operator in validation conditionals:
```python
if (value := self._header.sport) == 0:
    raise TcpSanityError(f"The 'sport' field must be greater than 0. Got: {value}")
```

### Error Classes

```python
class TcpIntegrityError(PacketIntegrityError):
    """Exception raised when TCP packet integrity check fails."""

    def __init__(self, message: str, /) -> None:
        super().__init__("[TCP] " + message)
```

- Always subclass the appropriate base error
- Constructor prepends `[PROTO] ` to every message

### Docstrings

- Triple quotes always, even for one-liners
- Module: description + blank line + file path + blank line + `ver x.y.z`
- Class: brief noun phrase (e.g. `"The TCP packet header."`)
- Method: imperative phrase (e.g. `"Get the TCP header 'sport' field."`, `"Ensure integrity of..."`)
- Property pattern: `"Get the <protocol> header '<field>' field."`
- All classes and all methods have docstrings — no exceptions

### Properties

- Exposed via a dedicated `*HeaderProperties(ABC)` mixin class
- One property per field; name and return type match the underlying field exactly
- The mixin is listed in the base class's inheritance but not in Parser/Assembler directly

### Assembler Pattern

- All constructor parameters keyword-only, prefixed `proto__field`, defaulting to zero/empty
- `assemble(self, buffers: list[Buffer], /) -> None` appends components in-place
- Validates constraints with `assert` before constructing the header object

### Enums

- Inherit from `ProtoEnumWord` or `ProtoEnumByte`
- Implement `__str__` using `match`/`case` for human-readable names
- Include a `from_proto()` factory classmethod

### Tests

- Framework: `testslide.TestCase` (not `unittest.TestCase`)
- Parameterized tests use `@parameterized_class(testcases)` with a module-level `testcases: list[dict[str, Any]]`
- Each test case dict keys: `_description`, `_args`, `_kwargs`, `_mocked_values`, `_results`
- `setUp` populates `self._args` and `self._kwargs` for constructor tests
- Test method docstrings start with `"Ensure ..."` and describe the behavioral guarantee

### Inline Comments

- Write zero comments on self-evident code
- RFC packet format diagrams are the one systematic exception (ASCII art in header files)
- Inline `# RFC XXXX` or `# reason` only when the value or choice is non-obvious

### Formatting

- Line length: 120 chars max (black/isort configured at 120)
- Multi-line: parentheses, 4-space indent continuation, trailing comma on last element
- f-strings preferred; use `!r` for values in assertion messages
- Bit-field packing: one flag per line with `|` aligned
