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
