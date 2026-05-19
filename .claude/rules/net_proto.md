# PyTCP — `net_proto/` Authoring Rule

This rule codifies the architecture of every protocol family
under `net_proto/protocols/<proto>/`: the per-protocol
six-file pattern (`*Header` / `*HeaderProperties` / `*Base` /
`*Parser` / `*Assembler` / `*Errors`), options-bearing
protocols, enums, dataclass shape, validation helpers, error
message templates, and the buffer / struct conventions every
header packs and unpacks against.

It complements [`source_files.md`](source_files.md) (general
file mechanics applied to every subpackage) and the two
sibling subpackage rules — [`net_addr.md`](net_addr.md) for
the value-type library `packages/net_addr/net_addr/` and
[`pytcp.md`](pytcp.md) for the runtime services in `pytcp/`.

The `packages/net_addr/net_addr/` package does **not** follow the six-file
protocol layout — it is a pure value-type library. See
[`net_addr.md`](net_addr.md) for its authoring rules.

---

## 1. Per-protocol file layout

Every protocol at `net_proto/protocols/<proto>/` contains the
same file set, double-underscore-separated:

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
Reference (full): `net_proto/protocols/tcp/` (options
container, per-option files, enums).

## 2. Dataclasses

All protocol headers and option payloads are `@dataclass`
with the same three flags, in this order:

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

- Declare every field with a type annotation. No bare
  defaults — if the field is optional, mark it so in the
  type.
- Fields that are not user-settable use
  `field(repr=False, init=False, default=<const>)`. Example
  from `arp__header.py`:
  ```python
  hrtype: ArpHardwareType = field(
      repr=False,
      init=False,
      default=ArpHardwareType.ETHERNET,
  )
  ```
- A frozen dataclass that needs to compute a field in
  `__post_init__` mutates itself with
  `object.__setattr__(self, "name", value)`. This is rare —
  most computed fields belong on the base class as
  properties instead.

`__post_init__` rules:

- Always decorated `@override`.
- Triple-quoted docstring beginning with `Ensure integrity of ...`.
- Body contains **only `assert` statements**, one per
  invariant, one per line, with a full descriptive failure
  message interpolating the offending value via `!r`:
  ```python
  assert is_uint16(self.sport), (
      f"The 'sport' field must be a 16-bit unsigned integer. "
      f"Got: {self.sport!r}"
  )
  ```
  Short messages may stay on one line; wrap when the
  assert line would exceed 120 chars.
- No control flow, no method calls beyond `is_uintN` /
  `is_N_byte_alligned` / `isinstance`. Heavier validation
  belongs in the parser's `_validate_integrity` /
  `_validate_sanity`.

## 3. Module-level constants and RFC diagrams

Constant naming follows the general convention from
[`source_files.md`](source_files.md) §7 — ALL-CAPS with
double-underscore segments encoding hierarchy:

- `UDP__HEADER__LEN`
- `UDP__HEADER__STRUCT`
- `TCP__OPTIONS__MAX_LEN`
- `TCP__OPTION__MSS__LEN`
- `IP6__MIN_MTU`

Struct format strings are always constants, never inlined:
`UDP__HEADER__STRUCT = "! HH HH"`. Keep the leading `"! "`
so byte order is explicit.

Place the RFC ASCII packet diagram directly above the
constants it documents, as a block of `# ...` comments. Use
the `+-+-+` format from the relevant RFC verbatim (see
`udp__header.py` and `tcp__header.py` for examples). Close
the block with a blank line, then the constants.

Inline `# ...` comment on a constant only when the value
cites an RFC or carries non-obvious meaning:

```python
TCP__MIN_MSS = 536  # Minimum recommended MSS (RFC 879).
```

## 4. `*Header` + `*HeaderProperties` (`<proto>__header.py`)

Every header file defines two classes in this order:

### 4.1 `<Proto>Header(ProtoStruct)` — the frozen dataclass

- Inherits from `ProtoStruct` (defined in
  `net_proto/lib/proto_struct.py`).
- Fields listed in wire order (matches the ASCII diagram
  above).
- Implements, always with `@override`:
  - `__post_init__` — see §2.
  - `__len__` → returns the `<PROTO>__HEADER__LEN` constant
    (not `struct.calcsize`).
  - `__buffer__(self, _: int) -> memoryview` — packs fields
    via `struct.pack_into` into a `bytearray(len(self))` and
    returns `memoryview(buffer)`. For checksummed protocols,
    pack `0` in the checksum slot here; the real checksum is
    injected later by the base class's `__buffer__` or by
    the assembler's `assemble()`.
  - `from_buffer(cls, buffer: Buffer, /) -> Self` as a
    `@classmethod` — unpacks via `struct.unpack` using the
    module-level struct constant and returns
    `cls(**fields)`.

### 4.2 `<Proto>HeaderProperties(ABC)` — the properties mixin

- Inherits from `abc.ABC`.
- Declares `_header: <Proto>Header` as a class-level
  annotation (no value) so subclasses / mypy see the
  expected attribute.
- Exposes **one `@property` per header field**, in the same
  order as the dataclass fields. Return type matches the
  field's type exactly. Each property body is a single
  `return self._header.<field>`.
- Property docstring is exactly `Get the <PROTO> header
  '<field>' field.` (multi-line triple-quoted form per
  [`source_files.md`](source_files.md) §6).

> Do not skip the mixin "because it's redundant." It is the
> public read surface for parsers and assemblers, and mypy
> strict + the `*Base` MRO rely on it.

## 5. `*Base` (`<proto>__base.py`)

- Class signature: `class <Proto>(Proto, <Proto>HeaderProperties[, <Proto>OptionsProperties]):`.
- Declares shared instance attributes as class-level
  annotations:
  ```python
  _header: UdpHeader
  _payload: Buffer
  ```
- For protocols carried in IP, declare `pshdr_sum: int = 0`
  at class level (it is later overwritten on each instance
  by the RX / TX path before checksum calculation).
- Implements the `Proto` abstract methods with `@override`:
  - `__len__` → `len(self._header) + len(self._payload)`
    (plus options length where applicable).
  - `__str__` → short human-readable log line (`"UDP {sport}
    > {dport}, len {plen} (...)"`). Format is
    protocol-specific but always single-line for the log.
  - `__repr__` → `f"{type(self).__name__}(header={self._header!r},
    payload={self._payload!r})"` (add `options=` for
    protocols with options).
  - `__buffer__(self, _: int) -> memoryview` → concatenates
    `bytearray(self._header)` + options + payload and
    injects the checksum at the canonical offset via
    `buffer[a:b] = inet_cksum(...).to_bytes(2)`.
- Defines `header` and `payload` `@property` accessors
  returning `self._header` / `self._payload`. For
  options-bearing protocols, add `options` too.

## 6. Properties

- Every header field → one `@property` on
  `<Proto>HeaderProperties`.
- Every container field → one `@property` on
  `<Proto>OptionsProperties` (for options-bearing protocols).
- On `<Proto>` base, expose the underlying `_header`,
  `_payload`, `_options` via `header`, `payload`, `options`
  properties.
- No setters. These types are read-only at the public
  surface; mutation happens only through the parser /
  assembler constructors.
  **Exception**: the Ethernet II and 802.3 header property
  mixins expose `dst` and `src` setters that bypass
  `frozen=True` via `object.__setattr__`. The TX packet
  handlers rewrite these two fields at send time after route
  lookup (see
  `pytcp/runtime/packet_handler/packet_handler__ethernet__tx.py`),
  so the setters are load-bearing and must remain. Every
  such setter must carry the inline comment `# Hack to
  bypass the 'frozen=True' dataclass decorator.` so the
  deviation is greppable. No other protocol may add setters.
- Return type annotation matches the underlying field. Never
  widen (`int` → `int | None`) or narrow (`Buffer` →
  `bytes`) silently.

## 7. `*Parser` (`<proto>__parser.py`) — the three-phase pipeline

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

1. Capture the input frame and any parent-layer inputs as
   private attributes. Parent-layer values are named with
   the parent protocol prefix: `self._ip__payload_len`,
   `self._ip__pshdr_sum`. The double-underscore communicates
   "this came from the IP layer."
2. Call, in order, `self._validate_integrity()`,
   `self._parse()`, `self._validate_sanity()`. Never
   reorder, never skip, never merge.
3. Install the parser onto `packet_rx` at the canonical
   attribute: `packet_rx.<proto> = self` (e.g.
   `packet_rx.udp`, `packet_rx.tcp`).
4. Advance `packet_rx.frame` past the consumed bytes so the
   next layer sees only its payload:
   `packet_rx.frame = packet_rx.frame[len(self._header) :]`
   (TCP and protocols with variable-length headers use
   `self._header.hlen` instead of `len(self._header)`).

Each phase method is `@override`-decorated, with a
triple-quoted docstring:

- `_validate_integrity()` — purely structural checks on
  `self._frame` and the parent-layer scalars. Raise
  `<Proto>IntegrityError(msg)` on any violation. Do not read
  parsed fields (they don't exist yet). Prefer `f"... Got:
  {VAR=}, {OTHER=}"` (f-string `=` debug form) for
  multi-value error messages:
  ```python
  raise UdpIntegrityError(
      "The condition 'UDP__HEADER__LEN <= self._ip__payload_len <= "
      f"len(self._frame)' must be met. Got: {UDP__HEADER__LEN=}, "
      f"{self._ip__payload_len=}, {len(self._frame)=}",
  )
  ```
- `_parse()` — builds `self._header = <Proto>Header.from_buffer(self._frame)`
  and sets `self._payload = self._frame[len(self._header) :
  self._header.plen]` (or protocol equivalent). No
  validation here.

  **Exception — wrapping `from_buffer` errors**: when a
  protocol's `from_buffer` classmethod enforces wire-level
  invariants with `assert` (e.g. DHCPv4 asserts `hrtype ==
  ETHERNET` and `magic_cookie == DHCP4__HEADER__MAGIC_COOKIE`)
  or performs operations that can raise Python-level
  exceptions that are actually integrity violations (e.g.
  `bytes.decode("ascii")` raising `UnicodeDecodeError` on
  non-ASCII fields), `_parse()` wraps the call and re-raises
  the offender as `<Proto>IntegrityError`:

  ```python
  try:
      self._header = Dhcp4Header.from_buffer(self._frame)
  except (AssertionError, UnicodeDecodeError) as error:
      raise Dhcp4IntegrityError(str(error)) from error
  ```

  The `from ... error` clause preserves the traceback chain.
  The try/except list enumerates every exception type the
  underlying `from_buffer` can raise — extending the list is
  allowed, catching bare `Exception` is not. Only apply this
  pattern when `from_buffer` genuinely can raise on integrity
  violations; do not wrap `from_buffer` calls defensively.
- `_validate_sanity()` — logical checks against
  already-parsed fields. Use the walrus operator to bind the
  offending value for the error message:
  ```python
  if (value := self.sport) == 0:
      raise UdpSanityError(
          f"The 'sport' field must be greater than 0. Got: {value}",
      )
  ```

## 8. `*Assembler` (`<proto>__assembler.py`)

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

- All constructor parameters are **keyword-only** (bare `*`
  before them) and prefixed `<proto>__field` matching the
  header field name. Exceptions: cross-cutting parameters
  like `echo_tracker` keep their plain name.
- Every parameter has a sensible default: `0` for integers,
  `False` for flags, `bytes()` for payloads, `None` for
  optional objects.
- First line of the body creates the `Tracker` with
  `prefix="TX"` and the caller's `echo_tracker`. Assemblers
  are always TX-side.
- Any constructor validation beyond what the header
  dataclass enforces goes here as `assert ...` statements
  (e.g. TCP options length bounds). Keep messages in the
  same style as header asserts.
- `assemble(self, buffers: list[Buffer], /) -> None` is
  positional-only on `buffers` and mutates it in place.
  Append in wire order: header, then options (if any), then
  payload. Inject the checksum **into the header bytearray
  before append**, never into an already-appended buffer.
- For protocols that support type-parameterized stacking,
  use PEP 695 generic syntax:
  ```python
  class EthernetAssembler[P: (ArpAssembler | Ip4Assembler | Ip6Assembler)]:
      ...
  ```
  The payload constraint enforces legal stacks via mypy.

## 9. Error classes (`<proto>__errors.py`)

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
  `PacketIntegrityError` prepends `"[INTEGRITY ERROR]"` (no
  trailing space); `PacketSanityError` prepends `"[SANITY
  ERROR]"` (no trailing space). Do not duplicate those
  prefixes — your subclass adds only `"[<PROTO>] "` (with
  one trailing space).
- Constructor signature: `def __init__(self, message: str, /) -> None:`
  — `message` is positional-only.
- The combined rendered form is therefore
  `"[INTEGRITY ERROR][TCP] the original message"`. Tests
  assert on this exact string; do not change the format
  without updating all test fixtures.

## 10. Options (TLV-bearing protocols)

Only a subset of protocols (TCP, IPv4, IPv6 HBH/DO) carry
options. When they do, layout under `<proto>/options/`:

- `<proto>__option.py` — base `<Proto>Option` class (parsing
  / assembling skeleton, `kind` / `len` fields, abstract
  methods).
- `<proto>__option__<name>.py` — one file per option (e.g.
  `tcp__option__mss.py`, `tcp__option__sack.py`). Each file
  defines:
  - Module constants (`<PROTO>__OPTION__<NAME>__LEN`,
    `<PROTO>__OPTION__<NAME>__STRUCT`).
  - A frozen dataclass `<Proto>Option<Name>` with its own
    `__post_init__` asserts, `__len__`, `__str__`,
    `__repr__`, `__buffer__`, `from_buffer` — same shape as
    headers.
  - For variable-length options (e.g. SACK), the
    `__post_init__` may compute `len` via
    `object.__setattr__`.
- `<proto>__options.py` — the container class
  `<Proto>Options(ProtoOptions)`. Exposes:
  - `__len__` — total bytes including padding to alignment.
  - `__bytes__` / `__buffer__` — serialized option block.
  - A `<Proto>OptionsProperties(ABC)` mixin with convenience
    lookups (`options.mss`, `options.wscale`, …) returning
    `None` when the option is not present.
  - Integrity validation of the option set as a whole
    (alignment, duplicates, mandatory presence).

The base class inherits from both `<Proto>HeaderProperties`
**and** `<Proto>OptionsProperties`; the parser and assembler
route options through the container.

## 11. Enums

- Inherit from `ProtoEnumByte` (8-bit) or `ProtoEnumWord`
  (16-bit), from `net_proto/lib/proto_enum.py`. Do not
  subclass stdlib `Enum` directly for protocol fields.
- Members listed in the order they appear in the relevant
  RFC / wire enumeration.
- Implement `__str__` with a `match`/`case` statement
  mapping each known member to a human-readable short name;
  fall back to a formatted hex value for unknown
  (dynamically extended) members:
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
  No `if/elif` chains for this dispatch — see
  [`python_features.md`](python_features.md) §4.
- Provide a `from_proto(proto: Proto) -> <Enum>`
  `@staticmethod` whenever the enum has to be derived from a
  concrete protocol object. Use early returns and
  `isinstance` checks; end with `assert False, f"Unknown
  protocol: {type(proto)}"` for the unreachable fallback.
- Unknown values at runtime are injected via
  `aenum.extend_enum(...)` inside `ProtoEnumByte` /
  `ProtoEnumWord`'s `_missing_` hook — do not re-implement
  it per enum.

## 12. Validation helpers (`net_proto/lib/int_checks.py`)

- `is_uint6`, `is_uint8`, `is_uint16`, `is_uint32`,
  `is_uint64` — use these in header `__post_init__` asserts
  and parser sanity checks. Do **not** inline the bound
  comparison.
- `is_4_byte_alligned(n)`, `is_8_byte_alligned(n)` —
  alignment predicates. Note the intentional misspelling
  `alligned`; match it everywhere (including tests, error
  messages, and constant names).
- The `UINT_N__MIN` / `UINT_N__MAX` constants from the same
  module are the canonical bounds — reference them in tests
  rather than hard-coding `65535`.

## 13. Error message templates

f-string mechanics (`!r`, `=` debug form, no `%` /
`.format()`) live in
[`python_features.md`](python_features.md) §20.
Protocol-specific message-template conventions:

- Message template:
  `"The '<field>' field must be <constraint>. Got: <value>"`
  or `"The condition '<expression>' must be met. Got: <values>"`.
  Keep phrasing identical across protocols so the tests'
  string matching stays robust across the codebase.
- Never hand-roll the `[INTEGRITY ERROR]` / `[SANITY ERROR]`
  prefix in message text. Raise the protocol-specific
  exception class and let the base class prepend the tag
  (§9).
- In sanity checks, plain `{value}` is acceptable where the
  field is an integer and `!r` adds noise; in integrity
  checks the multi-value `{name=}` debug form is canonical.

## 14. Buffer / struct conventions

- Header `__buffer__` builds a `bytearray(len(self))`, packs
  via `struct.pack_into(<PROTO>__HEADER__STRUCT, buf, 0,
  *fields)`, and returns `memoryview(buf)`. Pack the
  checksum slot as `0`; the real checksum is computed later.
- Base `__buffer__` concatenates header + options + payload
  into a single `bytearray`, then overwrites the checksum
  slice (`buffer[a:b] = inet_cksum(...).to_bytes(2)`) before
  returning a `memoryview`. Keep the offset literals (`6:8`
  for UDP, `16:18` for TCP, etc.) as plain integers — they
  match the RFC diagram above the constants.
- Assembler `assemble(buffers, /)` appends `bytearray`
  (header), then any options buffer, then the payload.
  Downstream code relies on positional indexing of
  `buffers`; never reorder or collapse.
- Always return `memoryview` from `__buffer__`, never raw
  `bytes` — callers expect zero-copy semantics.

## 15. Cross-cutting idioms

These patterns recur across the codebase. When you touch
related code, conform to them rather than introducing a
novel variant.

1. **Parent-layer prefix on parser attributes.** Anything
   pulled from `packet_rx.<parent>` is stored as
   `self._<parent>__<field>`: `self._ip__payload_len`,
   `self._ip__pshdr_sum`. Lets the reader trace the data
   flow without re-reading the parent parser.
2. **Struct format constants.** Every `struct.pack_into` /
   `struct.unpack` references a module-level string constant
   named `<PROTO>__…__STRUCT`. Never inline the format
   string.
3. **Checksum-zeroed pack, checksum-injected concat.** The
   header's `__buffer__` packs the checksum slot as `0`. The
   base class / assembler overwrites the slice after the
   full packet is assembled. Do not try to compute the
   checksum inside the header.
4. **Walrus in sanity checks.** `if (value := self.<field>)
   ...` is the canonical form — captures the value for the
   error message without re-evaluating it. Use it in every
   sanity check.
5. **Tracker direction.** Parsers receive the `Tracker` from
   the packet (`prefix="RX"`); assemblers construct it with
   `prefix="TX"`. The prefix is asserted at construction —
   matching it is not optional.
6. **`pshdr_sum` on `Udp`, `Tcp`, `Icmp*`.** Declared as a
   class-level attribute with a `0` default. The RX / TX
   path overwrites per-instance. Do not turn it into a
   property.
7. **Private attribute declaration at class level.**
   Instance attributes that parsers / assemblers set in
   `__init__` are also declared at class scope with
   annotations (`_payload: Buffer`) so mypy strict and IDE
   tooling see them without walking `__init__`.

## 16. Reference implementations

When in doubt, mirror the structure of:

- `net_proto/protocols/udp/udp__header.py` — minimal header
  class, the `*HeaderProperties` mixin, RFC diagram style.
- `net_proto/protocols/udp/udp__base.py` — the simplest
  `*Base` shape (dunders + `header` / `payload` properties).
- `net_proto/protocols/udp/udp__parser.py` — canonical
  three-phase pipeline, parent-layer prefix idiom, walrus
  sanity checks.
- `net_proto/protocols/udp/udp__assembler.py` — kw-only
  ctor, `TX` tracker, checksum injection in `assemble()`.
- `net_proto/protocols/udp/udp__errors.py` — the two-class
  template for protocol errors (identical shape: `[UDP] `
  prefix in both).
- `net_proto/protocols/tcp/` — full pattern including
  options container, per-option files, enums, PEP 695
  generics on the assembler.
- `net_proto/lib/proto.py` — `Proto` ABC with the default
  dunder set every protocol inherits.
- `net_proto/lib/errors.py` — the canonical
  `PacketIntegrityError` / `PacketSanityError` chain and how
  the tag prefixes compose.
- `net_proto/lib/enums.py` + `net_proto/lib/proto_enum.py`
  — `ProtoEnumByte` / `ProtoEnumWord` pattern, match/case
  `__str__`, `from_proto` factory.

These files are the canonical examples. Any deviation from
this rule should be justified by something that appears in
one of them — not by a novel pattern introduced in a new
file.

## 17. Anti-patterns

Protocol-architecture anti-patterns. General source-file
anti-patterns live in [`source_files.md`](source_files.md)
§10; stack-runtime anti-patterns live in
[`pytcp.md`](pytcp.md) §7. Language /
typing anti-patterns live in
[`python_features.md`](python_features.md) §22 and
[`typing.md`](typing.md) §23.

- **Writing a new header without the matching
  `<Proto>HeaderProperties` mixin**, or skipping a property
  because "callers can just read `header.<field>` directly."
  The mixin is the public read surface.
- **Merging integrity and sanity checks into a single
  method**, or interleaving parsing into the validation
  pass. The three-phase pipeline order is mandatory.
- **Assembling the checksum inside the header's
  `__buffer__`** instead of letting the base class /
  assembler inject it after full concatenation.
- **Hand-rolling the `[INTEGRITY ERROR]` / `[SANITY ERROR]`
  prefix** in a message string instead of raising the
  canonical exception class.
- **Inlining `struct` format strings** instead of defining a
  module constant.
- **Silently tightening or widening a type annotation on a
  property** relative to the underlying field.
- **Skipping the RFC ASCII packet diagram** above the
  constants block. The diagram is documentation that the
  RFC matches; it's not optional.

## 18. Workflow when adding a new protocol

1. Create `net_proto/protocols/<proto>/` with the six-file
   skeleton (§1). Copy a lean reference (`udp/`) and rename.
2. Fill the RFC diagram + constants in `<proto>__header.py`.
3. Fill the dataclass + `*HeaderProperties`. Get
   `python -m compileall net_proto/protocols/<proto>` clean.
4. Fill `<proto>__base.py` (dunders, `header` / `payload`
   properties).
5. Fill `<proto>__errors.py`.
6. Fill `<proto>__parser.py` — integrity, parse, sanity in
   that order.
7. Fill `<proto>__assembler.py` — kw-only ctor,
   `assemble()`.
8. Wire the protocol into the dispatch tables
   (`net_proto/lib/enums.py`'s `from_proto`, the relevant
   packet handler in `pytcp/runtime/packet_handler/`).
9. Write tests per
   [`unit_testing.md`](unit_testing.md). Do **not** skip
   the header-asserts / parser-integrity / parser-sanity /
   parser-operation / assembler-operation matrix. Add
   integration tests per
   [`integration_testing.md`](integration_testing.md) when
   the protocol has runtime behaviour (FSM, cache, timer).
10. Run `make lint && make test`. Both must pass with zero
    output regressions before commit.

## 19. Cross-references

- [`source_files.md`](source_files.md) — general source-file
  mechanics (file skeleton, copyright block, imports,
  naming, formatting).
- [`pytcp.md`](pytcp.md) — `pytcp/` runtime
  services (`Subsystem`, packet handlers, sockets, sysctls).
- [`python_features.md`](python_features.md) — modern Python
  features (PEP 604 / 585 / 695 / 696 / 698 / 649) consumed
  by the protocol patterns here; forbidden pre-3.10
  fallbacks.
- [`typing.md`](typing.md) — annotation discipline,
  generics, `Self` / `@override`, the protected-hook pattern
  for non-Liskov methods.
- [`unit_testing.md`](unit_testing.md) — the required test
  matrix per protocol (header asserts / parser integrity /
  parser sanity / parser operation / assembler operation).
- [`integration_testing.md`](integration_testing.md) — the
  harness hierarchy for runtime-behaviour testing.
- [`feature_implementation.md`](feature_implementation.md) —
  tests-first workflow + commit discipline.
- [`rfc_adherence_audit`](../skills/rfc_adherence_audit/SKILL.md)
  skill — author or refresh a per-RFC adherence record when
  shipping a new mechanism.
