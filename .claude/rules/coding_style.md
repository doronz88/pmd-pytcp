# PyTCP — Source Code Authoring Rule

This rule codifies how non-test Python source files are written in
PyTCP. It is distilled from the current state of `net_addr/`,
`net_proto/`, and `pytcp/` (excluding `tests/`). Every new or
rewritten source file MUST follow it.

The rule covers: toolchain, file skeleton, imports, module constants,
dataclasses, the per-protocol class hierarchy
(`*Header` / `*HeaderProperties` / `*Base` / `*Parser` / `*Assembler` /
`*Errors`), options-bearing protocols, enums, the `Subsystem` runtime,
the socket API, naming, type annotations, validation idioms,
docstrings, inline comments, formatting, and the recurring buffer /
struct conventions.

Test files are governed by a separate rule:
[`.claude/rules/unit_tests.md`](unit_tests.md). Follow that rule for
anything under `tests/`.

---

## 1. Language, toolchain, dependencies

- Target **Python 3.14+**. The project ships on 3.14 and uses the
  modern features available through that version:
  - 3.10+ union syntax (`A | B`) — never `Optional[X]` / `Union[A, B]`.
  - 3.10+ `match` / `case`.
  - 3.10+ `int.bit_count()` for popcount — never a string-format scan.
  - 3.11+ `typing.Self` for self-returning classmethods.
  - 3.12+ PEP 695 generic-class syntax (`class Foo[T]: ...`) and
    `type X = ...` aliases — preferred over `TypeVar` / `TypeAlias`.
  - 3.12+ `typing.override` on every method that overrides a parent.
  - 3.13+ PEP 696 type-parameter defaults (`class Foo[T = int]: ...`).
  - 3.14+ PEP 649 lazy annotation evaluation — annotations are stored
    as `__annotate__` closures and only evaluated on access. A plain
    `foo: Ip4Address` in a signature no longer requires
    `from __future__ import annotations` provided the name is in
    runtime scope.
- The stack itself has **zero runtime dependencies outside the
  standard library**. The only permitted non-stdlib imports in
  non-test source are:
  - `aenum` — used by `net_proto/lib/proto_enum.py` to dynamically
    extend enums with unknown values.
  - `click` — used by `net_addr` CLI helpers only.
  If you need anything else at runtime, stop and justify it before
  adding it.
- Linting is authoritative: `make lint` (codespell + isort + black +
  flake8 + mypy + pylint) must pass. Line length is **120**. `mypy`
  runs in strict mode.
- Prefer `memoryview` / the buffer protocol for packet data. Never
  copy bytes you can slice.

## 2. File skeleton

A `.py` file is either a **library module** (imported only) or a
**script** (has an `if __name__ == "__main__":` block and is invoked
as `./foo.py`). The shebang and executable bit go on scripts only —
per standard Python convention, library modules carry neither.

Known scripts in this repo: `tests_runner.py` and every file in
`examples/`. Everything under `net_addr/`, `net_proto/`, or `pytcp/`
is a library module.

### Library module layout (no shebang)

1. Lines 1–22: the 80-character-wide GPL copyright block (see §3).
2. Blank lines 23 and 24.
3. Lines 25–31: module docstring (see §4).
4. Blank line 32 (single blank after the docstring — black 26's rule).
5. Imports (see §5).
6. Blank line.
7. Module-level constants (see §6), including any RFC ASCII diagrams.
8. Blank line.
9. Class / function definitions.

No shebang. No executable bit (`chmod a-x`).

### Script layout (shebang + exec bit)

1. Shebang on line 1: `#!/usr/bin/env python3`
2. Blank line 2.
3. Lines 3–24: the GPL copyright block.
4. Blank lines 25 and 26.
5. Lines 27–33: module docstring.
6. Blank line 34 (single blank after the docstring).
7. Imports.
8. Blank line.
9. Module-level constants.
10. Blank line.
11. Function / class definitions, ending with an
    `if __name__ == "__main__":` entry block.

The file must be marked executable (`chmod +x`).

### Common rules

No code, comments, or `__all__` between the docstring and the first
import. `__all__` lives **only in package `__init__.py` files**
(see `net_proto/__init__.py`); source modules never declare it.

## 3. Copyright / license block (MANDATORY, verbatim)

The 80-character-wide GPL block below is identical in every file
(opening/closing lines are 80 `#` characters). Do not shorten,
widen, or edit the wording. In library modules it starts on line 1;
in scripts it starts on line 3 (after shebang + blank line).

```
################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################
```

When copying, verify the width with `awk 'NR==3 {print length($0)}'`
on a known-good file (should print `80`).

## 4. Module docstring

Immediately after the license block (two blank lines), every module
has a triple-quoted docstring in this exact shape:

```python
"""
<one-sentence description of what this module contains>.

<path relative to repo root, forward slashes>

ver 3.0.x
"""
```

- Opening and closing `"""` each on their own line.
- First line is one sentence, period-terminated, starting with either
  `This module contains the ...` (for modules) or
  `This package contains ...` (for `__init__.py` files).
- The relative path uses `/` separators and matches the file's real
  location (e.g. `net_proto/protocols/udp/udp__header.py`).
- The version string tracks the package version and is bumped in
  lockstep with `pyproject.toml`. Use the current value (e.g.
  `ver 3.0.4`); do not leave `3.0.x` literal.

## 5. Imports

Order (each group separated by one blank line):

1. `from __future__ import annotations` (only when a module uses
   `if TYPE_CHECKING:` imports inside annotations — those names
   aren't in runtime scope, and PEP 649 would otherwise try to
   resolve them lazily and fail. If the module's annotations all
   use names that are actually imported at runtime, omit the
   future-import entirely — PEP 649 gives you lazy evaluation for
   free on 3.14+).
2. Standard library: plain `import …` lines first, then `from …
   import …` lines.
3. `aenum` / `click` (on the rare occasions they are allowed).
4. Local packages in dependency order: `net_addr` → `net_proto` →
   `pytcp`.

Rules:

- **Only absolute imports.** Never `from ..lib import foo`.
- Multi-import from one module uses parentheses, one name per line,
  trailing comma:
  ```python
  from net_proto.lib.int_checks import (
      is_4_byte_alligned,
      is_uint6,
      is_uint16,
      is_uint32,
  )
  ```
  Never backslash-continued.
- Circular-import avoidance uses `TYPE_CHECKING`:
  ```python
  from typing import TYPE_CHECKING

  if TYPE_CHECKING:
      from net_proto.protocols.tcp.tcp__base import Tcp
  ```
- Note the spelling `is_4_byte_alligned` (double-l) — it is
  deliberate and consistent across the codebase. Match it; do not
  "correct" it ad hoc.

## 6. Module-level constants

- Naming: ALL-CAPS, double-underscore segments encoding a hierarchy:
  `PROTO[__SUBJECT]__FIELD`. Examples:
  - `UDP__HEADER__LEN`
  - `UDP__HEADER__STRUCT`
  - `TCP__OPTIONS__MAX_LEN`
  - `TCP__OPTION__MSS__LEN`
  - `IP6__MIN_MTU`
- Struct format strings are always constants, never inlined:
  `UDP__HEADER__STRUCT = "! HH HH"`. Keep the leading `"! "` so byte
  order is explicit.
- Place the RFC ASCII packet diagram directly above the constants it
  documents, as a block of `# ...` comments. Use the `+-+-+` format
  from the relevant RFC verbatim (see `udp__header.py:45-51` and
  `tcp__header.py` for TCP's 32-bit-wide box diagram). Close the
  block with a blank line, then the constants.
- Inline `# ...` comment on a constant only when the value cites an
  RFC or carries non-obvious meaning:
  ```python
  TCP__MIN_MSS = 536  # Minimum recommended MSS (RFC 879).
  ```

## 7. Dataclasses

All protocol headers and option payloads are `@dataclass` with the
same three flags, in this order:

```python
@dataclass(frozen=True, kw_only=True, slots=True)
class UdpHeader(ProtoStruct):
    """
    The UDP packet header.
    """

    sport: int
    dport: int
    plen: int
    cksum: int
```

Field rules:

- Declare every field with a type annotation. No bare defaults — if
  the field is optional, mark it so in the type.
- Fields that are not user-settable use
  `field(repr=False, init=False, default=<const>)`. Example from
  `arp__header.py`:
  ```python
  hrtype: ArpHardwareType = field(
      repr=False,
      init=False,
      default=ArpHardwareType.ETHERNET,
  )
  ```
- A frozen dataclass that needs to compute a field in `__post_init__`
  mutates itself with `object.__setattr__(self, "name", value)`. This
  is rare — most computed fields belong on the base class as
  properties instead.

`__post_init__` rules:

- Always decorated `@override`.
- Triple-quoted docstring beginning with `Ensure integrity of ...`.
- Body contains **only `assert` statements**, one per invariant, one
  per line, with a full descriptive failure message interpolating the
  offending value via `!r`:
  ```python
  assert is_uint16(self.sport), (
      f"The 'sport' field must be a 16-bit unsigned integer. "
      f"Got: {self.sport!r}"
  )
  ```
  Short messages may stay on one line (see `udp__header.py:74`); wrap
  when the assert line would exceed 120 chars.
- No control flow, no method calls beyond `is_uintN` / `is_N_byte_alligned`
  / `isinstance`. Heavier validation belongs in the parser's
  `_validate_integrity` / `_validate_sanity`.

## 8. Per-protocol file layout

Every protocol at `net_proto/protocols/<proto>/` contains the same
file set, double-underscore-separated:

| File                        | Role                                                  |
| --------------------------- | ----------------------------------------------------- |
| `<proto>__header.py`        | Frozen `<Proto>Header` dataclass + `*HeaderProperties` mixin + module constants + RFC diagram. |
| `<proto>__base.py`          | `<Proto>(Proto, <Proto>HeaderProperties, ...)` with common dunders (`__len__`, `__str__`, `__repr__`, `__buffer__`) and `header` / `payload` properties. |
| `<proto>__parser.py`        | `<Proto>Parser(<Proto>, ProtoParser)` with the three-phase pipeline. |
| `<proto>__assembler.py`     | `<Proto>Assembler(<Proto>, ProtoAssembler)` with kw-only ctor and `assemble()`. |
| `<proto>__errors.py`        | `<Proto>IntegrityError`, `<Proto>SanityError` subclasses. |
| `<proto>__enums.py`         | Protocol-specific enums (optional; only if the protocol has them). |
| `options/<proto>__option.py`, `options/<proto>__option__<name>.py`, `options/<proto>__options.py` | TLV option support (optional; only for TCP, IPv4 options, IPv6 HBH/DO, etc.). |

Reference (canonical minimum): `net_proto/protocols/udp/` (no
options, no enums — the simplest possible protocol).
Reference (full): `net_proto/protocols/tcp/` (options container, per-option files, enums).

The `net_addr/` package does **not** follow this layout — it is a
pure value-type library (address classes, masks, hosts). It still
obeys §1–§7, §11–§14, §17–§21, but ignores §8–§10 (no parser /
assembler / errors triad). If you add code there, mirror existing
modules like `net_addr/address.py`.

## 9. `*Header` + `*HeaderProperties` (`<proto>__header.py`)

Every header file defines two classes in this order:

### 9.1 `<Proto>Header(ProtoStruct)` — the frozen dataclass

- Inherits from `ProtoStruct` (defined in
  `net_proto/lib/proto_struct.py`).
- Fields listed in wire order (matches the ASCII diagram above).
- Implements, always with `@override`:
  - `__post_init__` — see §7.
  - `__len__` → returns the `<PROTO>__HEADER__LEN` constant (not
    `struct.calcsize`).
  - `__buffer__(self, _: int) -> memoryview` — packs fields via
    `struct.pack_into` into a `bytearray(len(self))` and returns
    `memoryview(buffer)`. For checksummed protocols, pack `0` in the
    checksum slot here; the real checksum is injected later by the
    base class's `__buffer__` or by the assembler's `assemble()`.
  - `from_buffer(cls, buffer: Buffer, /) -> Self` as a `@classmethod`
    — unpacks via `struct.unpack` using the module-level struct
    constant and returns `cls(**fields)`.

### 9.2 `<Proto>HeaderProperties(ABC)` — the properties mixin

- Inherits from `abc.ABC`.
- Declares `_header: <Proto>Header` as a class-level annotation
  (no value) so subclasses / mypy see the expected attribute.
- Exposes **one `@property` per header field**, in the same order as
  the dataclass fields. Return type matches the field's type exactly.
  Each property body is a single `return self._header.<field>`.
- Property docstring is exactly `Get the <PROTO> header '<field>'
  field.` (multi-line triple-quoted form — see §17).

> Do not skip the mixin "because it's redundant." It is the public
> read surface for parsers and assemblers, and mypy strict + the
> `*Base` MRO rely on it.

## 10. `*Base` (`<proto>__base.py`)

- Class signature: `class <Proto>(Proto, <Proto>HeaderProperties[, <Proto>OptionsProperties]):`.
- Declares shared instance attributes as class-level annotations:
  ```python
  _header: UdpHeader
  _payload: Buffer
  ```
- For protocols carried in IP, declare
  `pshdr_sum: int = 0` at class level (it is later overwritten on
  each instance by the RX / TX path before checksum calculation).
- Implements the `Proto` abstract methods with `@override`:
  - `__len__` → `len(self._header) + len(self._payload)` (plus
    options length where applicable).
  - `__str__` → short human-readable log line (`"UDP {sport} > {dport}, len {plen} (...)"`).
    Format is protocol-specific but always single-line for the log.
  - `__repr__` → `f"{type(self).__name__}(header={self._header!r}, payload={self._payload!r})"`
    (add `options=` for protocols with options).
  - `__buffer__(self, _: int) -> memoryview` → concatenates
    `bytearray(self._header)` + options + payload and injects the
    checksum at the canonical offset via
    `buffer[a:b] = inet_cksum(...).to_bytes(2)`.
- Defines `header` and `payload` `@property` accessors returning
  `self._header` / `self._payload`. For options-bearing protocols,
  add `options` too.

## 11. `*Parser` (`<proto>__parser.py`) — the three-phase pipeline

```python
class UdpParser(Udp, ProtoParser):
    """
    The UDP packet parser.
    """

    _payload: Buffer

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the UDP packet parser.
        """

        self._frame = packet_rx.frame
        self._ip__payload_len = packet_rx.ip.payload_len
        self._ip__pshdr_sum = packet_rx.ip.pshdr_sum

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.udp = self
        packet_rx.frame = packet_rx.frame[len(self._header) :]
```

Required elements, in this order:

1. Capture the input frame and any parent-layer inputs as private
   attributes. Parent-layer values are named with the parent protocol
   prefix: `self._ip__payload_len`, `self._ip__pshdr_sum`. The
   double-underscore communicates "this came from the IP layer."
2. Call, in order, `self._validate_integrity()`, `self._parse()`,
   `self._validate_sanity()`. Never reorder, never skip, never merge.
3. Install the parser onto `packet_rx` at the canonical attribute:
   `packet_rx.<proto> = self` (e.g. `packet_rx.udp`, `packet_rx.tcp`).
4. Advance `packet_rx.frame` past the consumed bytes so the next
   layer sees only its payload:
   `packet_rx.frame = packet_rx.frame[len(self._header) :]`
   (TCP and protocols with variable-length headers use
   `self._header.hlen` instead of `len(self._header)`).

Each phase method is `@override`-decorated, with a triple-quoted
docstring:

- `_validate_integrity()` — purely structural checks on `self._frame`
  and the parent-layer scalars. Raise `<Proto>IntegrityError(msg)` on
  any violation. Do not read parsed fields (they don't exist yet).
  Prefer `f"... Got: {VAR=}, {OTHER=}"` (f-string `=` debug form) for
  multi-value error messages:
  ```python
  raise UdpIntegrityError(
      "The condition 'UDP__HEADER__LEN <= self._ip__payload_len <= "
      f"len(self._frame)' must be met. Got: {UDP__HEADER__LEN=}, "
      f"{self._ip__payload_len=}, {len(self._frame)=}",
  )
  ```
- `_parse()` — builds `self._header = <Proto>Header.from_buffer(self._frame)`
  and sets `self._payload = self._frame[len(self._header) : self._header.plen]`
  (or protocol equivalent). No validation here.
- `_validate_sanity()` — logical checks against already-parsed fields.
  Use the walrus operator to bind the offending value for the error
  message:
  ```python
  if (value := self.sport) == 0:
      raise UdpSanityError(
          f"The 'sport' field must be greater than 0. Got: {value}",
      )
  ```

## 12. `*Assembler` (`<proto>__assembler.py`)

```python
class UdpAssembler(Udp, ProtoAssembler):
    """
    The UDP packet assembler.
    """

    _payload: bytes

    def __init__(
        self,
        *,
        udp__sport: int = 0,
        udp__dport: int = 0,
        udp__payload: Buffer = bytes(),
        echo_tracker: Tracker | None = None,
    ) -> None:
        """
        Initialize the UDP packet assembler.
        """

        self._tracker: Tracker = Tracker(prefix="TX", echo_tracker=echo_tracker)

        self._payload = udp__payload

        self._header = UdpHeader(
            sport=udp__sport,
            dport=udp__dport,
            plen=UDP__HEADER__LEN + len(self._payload),
            cksum=0,
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the UDP packet into list of buffers.
        """

        header = bytearray(self._header)
        header[6:8] = inet_cksum(header, self._payload, init=self.pshdr_sum).to_bytes(2)

        buffers.append(header)
        buffers.append(self._payload)
```

Rules:

- All constructor parameters are **keyword-only** (bare `*` before
  them) and prefixed `<proto>__field` matching the header field name.
  Exceptions: cross-cutting parameters like `echo_tracker` keep their
  plain name.
- Every parameter has a sensible default: `0` for integers, `False`
  for flags, `bytes()` for payloads, `None` for optional objects.
- First line of the body creates the `Tracker` with `prefix="TX"` and
  the caller's `echo_tracker`. Assemblers are always TX-side.
- Any constructor validation beyond what the header dataclass enforces
  goes here as `assert ...` statements (e.g. TCP options length
  bounds). Keep messages in the same style as header asserts.
- `assemble(self, buffers: list[Buffer], /) -> None` is positional-
  only on `buffers` and mutates it in place. Append in wire order:
  header, then options (if any), then payload. Inject the checksum
  **into the header bytearray before append**, never into an already-
  appended buffer.
- For protocols that support type-parameterized stacking, use PEP 695
  generic syntax:
  ```python
  class EthernetAssembler[P: (ArpAssembler | Ip4Assembler | Ip6Assembler)]:
      ...
  ```
  The payload constraint enforces legal stacks via mypy.

## 13. Error classes (`<proto>__errors.py`)

```python
from net_proto.lib.errors import PacketIntegrityError, PacketSanityError


class TcpIntegrityError(PacketIntegrityError):
    """
    Exception raised when TCP packet integrity check fails.
    """

    def __init__(self, message: str, /) -> None:
        super().__init__("[TCP] " + message)


class TcpSanityError(PacketSanityError):
    """
    Exception raised when TCP packet sanity check fails.
    """

    def __init__(self, message: str, /) -> None:
        super().__init__("[TCP] " + message)
```

- One file per protocol, containing exactly two classes:
  `<Proto>IntegrityError` and `<Proto>SanityError`.
- Base classes from `net_proto/lib/errors.py`:
  `PacketIntegrityError` prepends `"[INTEGRITY ERROR]"` (no trailing
  space); `PacketSanityError` prepends `"[SANITY ERROR]"` (no
  trailing space). Do not duplicate those prefixes — your subclass
  adds only `"[<PROTO>] "` (with one trailing space).
- Constructor signature: `def __init__(self, message: str, /) -> None:`
  — `message` is positional-only.
- The combined rendered form is therefore
  `"[INTEGRITY ERROR][TCP] the original message"`. Tests assert on
  this exact string; do not change the format without updating all
  test fixtures.

## 14. Options (TLV-bearing protocols)

Only a subset of protocols (TCP, IPv4, IPv6 HBH/DO) carry options.
When they do, layout under `<proto>/options/`:

- `<proto>__option.py` — base `<Proto>Option` class (parsing /
  assembling skeleton, `kind` / `len` fields, abstract methods).
- `<proto>__option__<name>.py` — one file per option (e.g.
  `tcp__option__mss.py`, `tcp__option__sack.py`). Each file defines:
  - Module constants (`<PROTO>__OPTION__<NAME>__LEN`,
    `<PROTO>__OPTION__<NAME>__STRUCT`).
  - A frozen dataclass `<Proto>Option<Name>` with its own
    `__post_init__` asserts, `__len__`, `__str__`, `__repr__`,
    `__buffer__`, `from_buffer` — same shape as headers.
  - For variable-length options (e.g. SACK), the `__post_init__` may
    compute `len` via `object.__setattr__`.
- `<proto>__options.py` — the container class
  `<Proto>Options(ProtoOptions)`. Exposes:
  - `__len__` — total bytes including padding to alignment.
  - `__bytes__` / `__buffer__` — serialized option block.
  - A `<Proto>OptionsProperties(ABC)` mixin with convenience lookups
    (`options.mss`, `options.wscale`, …) returning `None` when the
    option is not present.
  - Integrity validation of the option set as a whole (alignment,
    duplicates, mandatory presence).

The base class inherits from both `<Proto>HeaderProperties` **and**
`<Proto>OptionsProperties`; the parser and assembler route options
through the container.

## 15. Enums

- Inherit from `ProtoEnumByte` (8-bit) or `ProtoEnumWord` (16-bit),
  from `net_proto/lib/proto_enum.py`. Do not subclass stdlib `Enum`
  directly for protocol fields.
- Members listed in the order they appear in the relevant RFC / wire
  enumeration.
- Implement `__str__` with a `match`/`case` statement mapping each
  known member to a human-readable short name; fall back to a
  formatted hex value for unknown (dynamically extended) members:
  ```python
  @override
  def __str__(self) -> str:
      """
      Get the value as a string.
      """

      match self:
          case EtherType.ARP:
              name = "ARP"
          case EtherType.IP4:
              name = "IPv4"
          case EtherType.IP6:
              name = "IPv6"
          case EtherType.RAW:
              name = "Raw"

      return f"0x{self.value:0>4x}" if self.is_unknown else name
  ```
  No `if/elif` chains for this dispatch.
- Provide a `from_proto(proto: Proto) -> <Enum>` `@staticmethod`
  whenever the enum has to be derived from a concrete protocol
  object. Use early returns and `isinstance` checks; end with
  `assert False, f"Unknown protocol: {type(proto)}"` for the
  unreachable fallback.
- Unknown values at runtime are injected via
  `aenum.extend_enum(...)` inside `ProtoEnumByte` /
  `ProtoEnumWord`'s `_missing_` hook — do not re-implement it per
  enum.

## 16. `pytcp` stack runtime

### 16.1 `Subsystem`

- Every background service in `pytcp/` extends `Subsystem` from
  `pytcp/lib/subsystem.py`.
- Implement `_subsystem_loop()` (abstract) with the per-iteration
  work. The base class wraps it in a loop guarded by
  `self._event__stop_subsystem`.
- Threading attributes are prefixed `_event__`, `_thread__`,
  `_lock__` to keep intent grep-able.
- Start/stop are the only public lifecycle methods; additional
  subsystem-specific startup work goes in `_start()` (called from
  `start()` after the thread is spawned).
- Loop cadence: `SUBSYSTEM_SLEEP_TIME__SEC = 0.1` is the canonical
  poll interval; override only if the protocol demands it.

### 16.2 Packet handlers

- RX / TX handlers live under `pytcp/stack/packet_handler/`, named
  `packet_handler__<proto>__<rx|tx>.py`.
- Each file contributes methods to the `PacketHandler` class via
  explicit composition (mixins). Keep each file focused on one
  direction of one protocol.

### 16.3 Sockets

- `pytcp/socket/__init__.py` exposes an abstract `socket` class with
  a `__new__` factory that returns `TcpSocket`, `UdpSocket`, or
  `RawSocket` based on the `type_` argument. Mirror BSD socket
  semantics — method names (`bind`, `listen`, `accept`, `connect`,
  `send`, `recv`, `close`) match the stdlib `socket` module.
- TCP's FSM is implemented in `pytcp/socket/tcp__session.py` using
  `FsmState` and `SysCall` enums. Keep state transitions inside the
  session object; the socket class is a thin BSD-API shim over it.

### 16.4 Stack configuration

- Stack-wide constants (IP / MAC addresses, ARP / ND cache timers,
  MTU, port ranges, logger channels) live in `pytcp/stack/__init__.py`.
  Add new tunables there, following the §6 naming convention
  (`STACK__MAC_ADDRESS`, `ARP_CACHE__ENTRY_MAX_AGE__SEC`, etc.).

## 17. Docstrings

- **Every module, every class, every method** has a docstring.
  Functions at module scope too (rare; most code is method-bound).
- Always triple-quoted `"""…"""`, even for one-liners.
- Format for classes and methods is the multi-line form — opening
  `"""` on its own line, a single sentence on the next, closing
  `"""` on its own line:
  ```python
  def __len__(self) -> int:
      """
      Get the UDP header length.
      """

      return UDP__HEADER__LEN
  ```
  The blank line between the closing `"""` and the first statement
  is mandatory.
- Phrasing:
  - **Classes**: a noun phrase ending in a period.
    `"""The UDP packet header."""`, `"""The UDP protocol base."""`.
  - **Methods**: imperative phrase ending in a period.
    `"""Get the UDP header length."""`, `"""Initialize the UDP
    packet parser."""`, `"""Assemble the UDP packet into list of
    buffers."""`.
  - **`__post_init__` / `_validate_*`**: start with `Ensure …`.
  - **Property accessors on `*HeaderProperties`**: exactly
    `Get the <PROTO> header '<field>' field.` — don't paraphrase.
  - **`header` / `payload` / `options` properties on the base**:
    `Get the <PROTO> packet '_<field>' attribute.`
- Module docstrings follow §4 exactly (description + path + `ver`).

## 18. Properties

- Every header field → one `@property` on `<Proto>HeaderProperties`.
- Every container field → one `@property` on `<Proto>OptionsProperties`
  (for options-bearing protocols).
- On `<Proto>` base, expose the underlying `_header`, `_payload`,
  `_options` via `header`, `payload`, `options` properties.
- No setters. These types are read-only at the public surface;
  mutation happens only through the parser / assembler constructors.
- Return type annotation matches the underlying field. Never widen
  (`int` → `int | None`) or narrow (`Buffer` → `bytes`) silently.

## 19. Type annotations

- Use 3.10+ pipe unions: `Tracker | None`, never `Optional[Tracker]`
  or `Union[Tracker, None]`.
- Use lowercase builtin generics: `list[Buffer]`, `dict[str, Any]`,
  `tuple[int, int]`. Never `List[...]`, `Dict[...]`.
- Use `typing.Self` for self-returning classmethods:
  `def from_buffer(cls, buffer: Buffer, /) -> Self:`.
- Decorate every override with `@override` (from `typing`). mypy
  strict will flag missing overrides.
- Positional-only `/` is used for any parameter that accepts a
  buffer, byte string, or container being mutated in place:
  ```python
  def assemble(self, buffers: list[Buffer], /) -> None: ...
  def from_buffer(cls, buffer: Buffer, /) -> Self: ...
  def __init__(self, message: str, /) -> None: ...
  ```
- Keyword-only `*` is mandatory on assembler constructors (§12) and
  on any factory where the call site benefits from named arguments.
- `Buffer` is a module-level type alias (`type Buffer = bytes |
  bytearray | memoryview`, `net_proto/lib/buffer.py`). Use it instead
  of re-spelling the union.
- PEP 695 class generics (`class Foo[T]: ...`) are preferred over
  `TypeVar` for new code.

## 20. Validation helpers (`net_proto/lib/int_checks.py`)

- `is_uint6`, `is_uint8`, `is_uint16`, `is_uint32`, `is_uint64` —
  use these in header `__post_init__` asserts and parser sanity
  checks. Do **not** inline the bound comparison.
- `is_4_byte_alligned(n)`, `is_8_byte_alligned(n)` — alignment
  predicates. Note the intentional misspelling `alligned`; match it
  everywhere (including tests, error messages, and constant names).
- The `UINT_N__MIN` / `UINT_N__MAX` constants from the same module
  are the canonical bounds — reference them in tests rather than
  hard-coding `65535`.

## 21. Error messages and assertion style

- Prefer `!r` in assert / error interpolation for values:
  `f"Got: {self.sport!r}"`. Plain `{value}` is acceptable in sanity
  checks where the field is an integer and `!r` adds noise.
- For multi-value integrity errors, use the f-string `=` debug form:
  `f"Got: {UDP__HEADER__LEN=}, {plen=}, {self._ip__payload_len=}"`.
- Message template: `"The '<field>' field must be <constraint>. Got: <value>"`
  or `"The condition '<expression>' must be met. Got: <values>"`.
  Keep phrasing identical across protocols so the tests' string
  matching stays robust.
- Never hand-roll the `[INTEGRITY ERROR]` / `[SANITY ERROR]` prefix
  in message text. Raise the protocol-specific exception class and
  let the base class prepend the tag (§13).

## 22. Buffer / struct conventions

- Header `__buffer__` builds a `bytearray(len(self))`, packs via
  `struct.pack_into(<PROTO>__HEADER__STRUCT, buf, 0, *fields)`, and
  returns `memoryview(buf)`. Pack the checksum slot as `0`; the real
  checksum is computed later.
- Base `__buffer__` concatenates header + options + payload into a
  single `bytearray`, then overwrites the checksum slice
  (`buffer[a:b] = inet_cksum(...).to_bytes(2)`) before returning a
  `memoryview`. Keep the offset literals (`6:8` for UDP, `16:18` for
  TCP, etc.) as plain integers — they match the RFC diagram above
  the constants.
- Assembler `assemble(buffers, /)` appends `bytearray` (header), then
  any options buffer, then the payload. Downstream code relies on
  positional indexing of `buffers`; never reorder or collapse.
- Always return `memoryview` from `__buffer__`, never raw `bytes` —
  callers expect zero-copy semantics.

## 23. Naming summary

| Target                          | Pattern                        | Example                                   |
| ------------------------------- | ------------------------------ | ----------------------------------------- |
| Module-level constant           | `PROTO__SUBJECT__FIELD`        | `TCP__OPTION__MSS__LEN`                   |
| Module filename                 | `proto__component.py`          | `tcp__parser.py`, `tcp__option__mss.py`   |
| Class                           | `<Proto><Component>`           | `TcpHeader`, `TcpParser`, `TcpAssembler`  |
| Properties mixin                | `<Proto><Component>Properties` | `TcpHeaderProperties`                     |
| Error class                     | `<Proto>(Integrity\|Sanity)Error` | `TcpIntegrityError`                    |
| Assembler ctor kwarg            | `proto__field`                 | `tcp__sport`, `udp__payload`              |
| Private instance attribute      | `_name`                        | `_header`, `_payload`, `_frame`           |
| Parent-layer input on a parser  | `_parent__field`               | `_ip__payload_len`, `_ip__pshdr_sum`      |
| Private method                  | `_name`                        | `_validate_integrity`, `_parse`           |
| Threading attribute             | `_event__name`, `_thread__name`, `_lock__name` | `_event__stop_subsystem`  |
| Packet handler file             | `packet_handler__proto__dir.py` | `packet_handler__tcp__rx.py`             |

No trailing underscores on public names. Dunder names are limited to
standard Python protocols (`__init__`, `__len__`, `__str__`,
`__repr__`, `__buffer__`, `__post_init__`, `__eq__`, `__hash__`,
`__bytes__`).

## 24. Formatting

- **120-char** hard line limit (black / isort configured at 120).
- Opening paren on the same line as the callable / class; arguments
  indented 4 spaces; closing paren on its own line at the original
  indent level. Trailing comma on the last element of any multi-line
  call, tuple, list, or dict.
- Prefer f-strings; never `%` formatting or `.format()`.
- Bit-field packing uses one operand per line, operator at the
  start of the continuation line, aligned:
  ```python
  self.hlen << 10
  | self.flag_ns << 8
  | self.flag_cwr << 7
  | self.flag_ece << 6
  ...
  ```
  This pattern appears in every header that packs flag bits (TCP,
  IPv4, IPv6). Match it.
- Walrus `:=` inside `if`/`while` conditions is idiomatic for
  "check a value and capture it for the error message" (§11).

## 25. Inline comments

- Default to **zero inline comments**. Names are the primary
  documentation; docstrings cover intent; the type system covers
  structure.
- Exceptions — write a comment only when it earns its keep:
  1. **RFC packet diagrams** above module constants (§6).
  2. **RFC citations** on constants whose value needs a source
     (`# Minimum recommended MSS (RFC 879).`).
  3. **Non-obvious workarounds**, especially when bypassing a normal
     constraint (e.g. `# Hack to bypass the 'frozen=True' dataclass
     decorator`).
- Never write comments that describe *what* the next line does. If
  the code needs that comment, rename the variable or extract the
  method instead.
- Never reference tickets, PRs, commit hashes, or "added for <caller>"
  in inline comments — that belongs in the commit message and rots
  in source.

## 26. Cross-cutting idioms worth matching

These patterns recur across the codebase. When you touch related
code, conform to them rather than introducing a novel variant.

1. **Parent-layer prefix on parser attributes.** Anything pulled
   from `packet_rx.<parent>` is stored as
   `self._<parent>__<field>`: `self._ip__payload_len`,
   `self._ip__pshdr_sum`. Lets the reader trace the data flow
   without re-reading the parent parser.
2. **Struct format constants.** Every `struct.pack_into` /
   `struct.unpack` references a module-level string constant named
   `<PROTO>__…__STRUCT`. Never inline the format string.
3. **Checksum-zeroed pack, checksum-injected concat.** The header's
   `__buffer__` packs the checksum slot as `0`. The base class /
   assembler overwrites the slice after the full packet is assembled.
   Do not try to compute the checksum inside the header.
4. **Walrus in sanity checks.** `if (value := self.<field>) ...` is
   the canonical form — captures the value for the error message
   without re-evaluating it. Use it in every sanity check.
5. **Tracker direction.** Parsers receive the `Tracker` from the
   packet (`prefix="RX"`); assemblers construct it with
   `prefix="TX"`. The prefix is asserted at construction — matching
   it is not optional.
6. **`pshdr_sum` on `Udp`, `Tcp`, `Icmp*`.** Declared as a class-
   level attribute with a `0` default. The RX / TX path overwrites
   per-instance. Do not turn it into a property.
7. **Private attribute declaration at class level.** Instance
   attributes that parsers / assemblers set in `__init__` are also
   declared at class scope with annotations (`_payload: Buffer`) so
   mypy strict and IDE tooling see them without walking `__init__`.
8. **No `__all__` in modules.** Only in package `__init__.py`. If you
   want to signal "this is the public surface," export it from the
   package `__init__.py`.

## 27. Reference implementations

When in doubt, mirror the structure of:

- `net_proto/protocols/udp/udp__header.py` — minimal header class,
  the `*HeaderProperties` mixin, RFC diagram style.
- `net_proto/protocols/udp/udp__base.py` — the simplest `*Base`
  shape (dunders + `header` / `payload` properties).
- `net_proto/protocols/udp/udp__parser.py` — canonical three-phase
  pipeline, parent-layer prefix idiom, walrus sanity checks.
- `net_proto/protocols/udp/udp__assembler.py` — kw-only ctor,
  `TX` tracker, checksum injection in `assemble()`.
- `net_proto/protocols/udp/udp__errors.py` — the two-class template
  for protocol errors (identical shape: `[UDP] ` prefix in both).
- `net_proto/protocols/tcp/` — full pattern including options
  container, per-option files, enums, PEP 695 generics on the
  assembler.
- `net_proto/lib/proto.py` — `Proto` ABC with the default dunder
  set every protocol inherits.
- `net_proto/lib/errors.py` — the canonical
  `PacketIntegrityError` / `PacketSanityError` chain and how the
  tag prefixes compose.
- `net_proto/lib/enums.py` + `net_proto/lib/proto_enum.py` —
  `ProtoEnumByte` / `ProtoEnumWord` pattern, match/case `__str__`,
  `from_proto` factory.
- `pytcp/lib/subsystem.py` — `Subsystem` base and the
  `_event__stop_subsystem` / `_thread__subsystem` pattern.
- `pytcp/socket/__init__.py` + `pytcp/socket/tcp__session.py` —
  the BSD-socket facade and the TCP FSM.

These files are the canonical examples. Any deviation from this
rule should be justified by something that appears in one of them —
not by a novel pattern introduced in a new file.

## 28. Anti-patterns to avoid

- Writing a new header without the matching `<Proto>HeaderProperties`
  mixin, or skipping a property because "callers can just read
  `header.<field>` directly."
- Merging integrity and sanity checks into a single method, or
  interleaving parsing into the validation pass.
- Assembling the checksum inside the header's `__buffer__` instead
  of letting the base class / assembler inject it after full
  concatenation.
- Hand-rolling the `[INTEGRITY ERROR]` / `[SANITY ERROR]` prefix in
  a message string instead of raising the canonical exception class.
- Inlining `struct` format strings instead of defining a module
  constant.
- Using `%` formatting, `.format()`, or string concatenation with
  `+` for user-visible messages. Always f-strings.
- `typing.Optional`, `typing.Union`, `typing.List`, `typing.Dict` —
  use `X | None`, `X | Y`, `list[X]`, `dict[X, Y]`.
- Forgetting `@override` on a method that implements an abstract
  parent. mypy strict will fail; catching it locally is cheaper than
  a CI round-trip.
- Relative imports (`from ..lib import foo`). Always absolute.
- `__all__` in a non-`__init__.py` source module.
- Trailing underscore on a public name (`type_` is fine as a
  keyword-collision workaround in `socket.__new__`; no other uses).
- Comments that narrate the code (`# Set sport to 0`) instead of
  explaining a non-obvious *why*.
- New runtime dependencies outside the stdlib (plus the two allowed
  above).
- Silently tightening or widening a type annotation on a property
  relative to the underlying field.
- Creating a subsystem without extending `Subsystem` — ad-hoc
  threading in `pytcp/` is a red flag.

## 29. Workflow when adding a new protocol

1. Create `net_proto/protocols/<proto>/` with the six-file skeleton
   (§8). Copy a lean reference (`udp/`) and rename.
2. Fill the RFC diagram + constants in `<proto>__header.py`.
3. Fill the dataclass + `*HeaderProperties`. Get
   `python -m compileall net_proto/protocols/<proto>` clean.
4. Fill `<proto>__base.py` (dunders, `header` / `payload` properties).
5. Fill `<proto>__errors.py`.
6. Fill `<proto>__parser.py` — integrity, parse, sanity in that order.
7. Fill `<proto>__assembler.py` — kw-only ctor, `assemble()`.
8. Wire the protocol into the dispatch tables
   (`net_proto/lib/enums.py`'s `from_proto`, the relevant packet
   handler in `pytcp/stack/packet_handler/`).
9. Write tests per [`.claude/rules/unit_tests.md`](unit_tests.md).
   Do **not** skip the header-asserts / parser-integrity /
   parser-sanity / parser-operation / assembler-operation matrix.
10. Run `make lint && make test`. Both must pass with zero output
    regressions before commit.
