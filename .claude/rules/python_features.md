# PyTCP — Python Language-Feature Rule

This rule codifies which Python language features every new
or rewritten PyTCP module **MUST** use, and which obsolete
or pre-3.10 equivalents are **forbidden**. PyTCP targets
**Python 3.14+**; every feature listed below is unconditionally
available at runtime — there is no installed base on older
interpreters, so no compatibility shims are tolerated.

The rule is normative. If a line of code in this repository
could be rewritten using a newer-Python form listed below, it
is wrong as written and a reviewer is entitled to bounce the
PR. The narrow exception is third-party code or a verbatim
RFC quote where the original wording matters for archaeology;
neither applies to PyTCP source.

The companion rules [`typing.md`](typing.md) (type
annotations, generics, `Self`, `@override`, mypy strict),
[`unit_testing.md`](unit_testing.md), and
[`integration_testing.md`](integration_testing.md) sit
alongside this one. Where they overlap, this rule provides
the canonical pin for the language-feature choice (PEP /
version / forbidden equivalent) and they reference back.

---

## 1. Target version and toolchain

- **Target: Python 3.14+.** `pyproject.toml` declares
  `requires-python = ">=3.14"`. mypy strict is the canonical
  type-check gate (`make lint`).
- **Zero installed base.** PyTCP ships as one repo on one
  interpreter version. There are **no** "but we need to
  support 3.X" exceptions — the project upgrades the floor in
  lockstep with CPython releases.
- **No `__future__` imports** except the narrow `from __future__
  import annotations` case described in §17 (and even that is
  audited together with `TYPE_CHECKING` guards).
- **Linting authority.** `make lint` (codespell + isort + black
  + flake8 + mypy + pylint) is canonical. mypy strict catches
  most violations of this rule mechanically; pylint catches the
  rest. CI must be green.

## 2. Quick reference

The features below are listed in PEP order. The "Status" column
states the PyTCP enforcement level:

- **MUST** — use this form in all new code; rewrite legacy uses
  on touch.
- **MUST NOT** — using the obsolete form is a blocker.
- **N/A** — feature exists but PyTCP has no consumer for it
  (kept here so future code knows the modern form when it
  arrives).

| § | PEP | Feature | Version | Status |
|---|---|---|---|---|
| §3 | 604 | `X \| Y` union syntax | 3.10 | MUST |
| §4 | 634-636 | `match` / `case` | 3.10 | MUST (where it fits) |
| §5 | — | `int.bit_count()` | 3.10 | MUST for popcount |
| §6 | — | `str.removeprefix` / `removesuffix` | 3.9 | MUST |
| §7 | 585 | Lowercase builtin generics | 3.9 | MUST |
| §8 | — | `dict \| dict` merge | 3.9 | MUST |
| §9 | 673 | `typing.Self` | 3.11 | MUST |
| §10 | 654 | Exception groups + `except*` | 3.11 | MUST (where it fits) |
| §11 | 680 | `tomllib` | 3.11 | MUST (no `toml` / `tomli`) |
| §12 | 655 | `Required` / `NotRequired` | 3.11 | MUST |
| §13 | 675 | `LiteralString` | 3.11 | N/A (no consumer) |
| §14 | 695 | Generic-class / function / `type` syntax | 3.12 | MUST |
| §15 | 698 | `typing.override` | 3.12 | MUST |
| §16 | 696 | Type-parameter defaults | 3.13 | MUST |
| §17 | 649 | Lazy annotation evaluation | 3.14 | MUST (audit `__future__`) |
| §18 | 750 | t-strings (template strings) | 3.14 | MUST (when escaping) |
| §19 | — | Walrus `:=` in conditionals | 3.8 | MUST (sanity checks) |
| §20 | — | f-strings + `=` debug form | 3.8 | MUST (no `%` / `.format()`) |
| §21 | — | Positional-only `/` / keyword-only `*` | 3.8 | MUST |

---

## 3. PEP 604 — `X | Y` union syntax (3.10)

```python
# Good
def find_entry(self, *, ip4_address: Ip4Address) -> MacAddress | None: ...

type Buffer = bytes | bytearray | memoryview

flush_callback: FlushCallback[P] | None
```

**MUST NOT.** Never write `Optional[X]`, `Union[X, Y]`, or
import `typing.Optional` / `typing.Union`:

```python
# Forbidden — pre-3.10 typing equivalents
from typing import Optional, Union
def find_entry(...) -> Optional[MacAddress]: ...
flush_callback: Union[FlushCallback[P], None]
```

The `typing.Optional` / `typing.Union` symbols are deprecated
runtime aliases; mypy strict accepts both forms but they double
the cognitive cost of every signature and rot when a third
union member is added.

## 4. PEP 634-636 — Structural pattern matching (3.10)

Use `match` / `case` for any dispatch over a closed set of
codepoints, enum members, or structured tuples. The canonical
PyTCP examples are protocol-enum `__str__` and protocol-from-
proto factories:

```python
# Good — enums.py
@override
def __str__(self) -> str:
    match self:
        case EtherType.ARP:
            return "ARP"
        case EtherType.IP4:
            return "IPv4"
        case EtherType.IP6:
            return "IPv6"
        case EtherType.RAW:
            return "Raw"
    return f"0x{self.value:0>4x}"
```

```python
# Good — InterfaceLayer dispatch
match self._interface_layer:
    case InterfaceLayer.L2:
        return self._phtx_ethernet(...)
    case InterfaceLayer.L3:
        self.__send_out_packet(ip6_packet_tx)
        return TxStatus.PASSED__IP6__TO_TX_RING
```

**MUST NOT.** Don't write equivalent `if`/`elif`/`else`
chains when the dispatch is over an enum or a small closed
set:

```python
# Forbidden
if self is EtherType.ARP:
    return "ARP"
elif self is EtherType.IP4:
    return "IPv4"
elif self is EtherType.IP6:
    return "IPv6"
elif self is EtherType.RAW:
    return "Raw"
else:
    return f"0x{self.value:0>4x}"
```

`match` is preferred because mypy exhaustiveness-checks it
(every enum member must have a case or fall through a
documented default), and the structure scans as a dispatch
table rather than a sequence of opaque conditionals.

`if/elif` is fine for arbitrary boolean conditions — `match`
is mandatory only when the discriminant is an enum, isinstance
chain, or destructurable shape.

## 5. `int.bit_count()` (3.10)

```python
# Good — RFC 6724 §2.2 CommonPrefixLen
def common_prefix_len(a: Ip6Address, b: Ip6Address, /) -> int:
    xor = int(a) ^ int(b)
    if xor == 0:
        return 128
    return 128 - xor.bit_length()
```

```python
# Good — popcount of a flags byte
weight = flags.bit_count()
```

**MUST NOT.** Never compute population count via string
formatting:

```python
# Forbidden
weight = bin(flags).count("1")
weight = sum(int(c) for c in f"{flags:b}")
```

The string-format-scan idiom existed because pre-3.10 Python
had no popcount primitive; PyTCP's floor is 3.14 so the
primitive is always available.

## 6. `str.removeprefix` / `str.removesuffix` (3.9)

```python
# Good
clean = path.removeprefix("pytcp/")
trimmed = name.removesuffix(".py")
```

**MUST NOT.** Don't manually slice based on a precomputed
length:

```python
# Forbidden
if path.startswith("pytcp/"):
    clean = path[len("pytcp/"):]
if name.endswith(".py"):
    trimmed = name[:-3]
```

The manual-slice idiom hides the prefix/suffix intent behind
arithmetic and breaks silently when someone edits the literal
without updating the slice.

## 7. PEP 585 — Lowercase builtin generics (3.9)

Use the lowercase builtins as generic types directly:

```python
# Good
def assemble(self, buffers: list[Buffer], /) -> None: ...

_entries: dict[A, NeighborEntry[A, P]]
options: tuple[Icmp6NdOption, ...]
flags: set[NudState]
```

**MUST NOT.** Never import `List`, `Dict`, `Tuple`, `Set`,
`FrozenSet`, `Type` from `typing`:

```python
# Forbidden
from typing import List, Dict, Tuple, Set, FrozenSet, Type
def assemble(self, buffers: List[Buffer], /) -> None: ...
```

`typing.Type[X]` should be `type[X]`.

## 8. `dict | dict` merge (3.9)

```python
# Good
merged = base_options | overrides
config = defaults | user_supplied
```

**MUST NOT.** Don't use `{**a, **b}` or `dict(a, **b)` for the
same effect:

```python
# Forbidden
merged = {**base_options, **overrides}
merged = dict(base_options, **overrides)
```

For in-place update, `dict.update(other)` is still correct —
the `|=` operator is the in-place variant and is also accepted.

## 9. PEP 673 — `typing.Self` (3.11)

```python
# Good
from typing import Self

class Ip6Header(ProtoStruct):
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        fields = struct.unpack(IP6__HEADER__STRUCT, buffer)
        return cls(**dict(zip(_FIELD_NAMES, fields)))
```

```python
# Good — fluent setters returning the same subclass
class Ip6Host:
    def with_gateway(self, gateway: Ip6Address) -> Self:
        return type(self)(self._network, self._address, gateway=gateway)
```

**MUST NOT.** Don't use `TypeVar` bound to the class as a
workaround:

```python
# Forbidden
T = TypeVar("T", bound="Ip6Header")
class Ip6Header(ProtoStruct):
    @classmethod
    def from_buffer(cls: type[T], buffer: Buffer, /) -> T: ...
```

`Self` resolves to "the actual subclass at call time" without
the manual TypeVar dance.

## 10. PEP 654 — Exception groups + `except*` (3.11)

```python
# Good — gathering multiple concurrent DAD failures
try:
    await asyncio.gather(*claims, return_exceptions=False)
except* DadConflictError as eg:
    for exc in eg.exceptions:
        log("nud", f"DAD conflict for {exc.address}")
except* DadTimeoutError as eg:
    for exc in eg.exceptions:
        log("nud", f"DAD timeout for {exc.address}")
```

PyTCP is largely threaded rather than asyncio-based, so the
consumer surface for `except*` is small today. The rule is
still **MUST** when a path genuinely needs to surface multiple
concurrent failures — don't flatten an `ExceptionGroup` into a
single representative exception.

## 11. PEP 680 — `tomllib` (3.11)

```python
# Good — reading pyproject.toml
import tomllib
with open("pyproject.toml", "rb") as fh:
    config = tomllib.load(fh)
```

**MUST NOT.** Never add `toml`, `tomli`, or `tomli_w` to
dependencies for read paths. PyTCP has zero runtime
dependencies; `tomllib` is stdlib.

`tomllib` is read-only. For TOML writing (rare; PyTCP does not
need it today) `tomli_w` would be a justified test-only
dependency, never a runtime one.

## 12. PEP 655 — `Required` / `NotRequired` (3.11)

```python
# Good — sysctl-spec TypedDict with optional validator
from typing import NotRequired, Required, TypedDict

class SysctlSpec(TypedDict):
    key: Required[str]
    attr: Required[str]
    default: Required[object]
    validator: NotRequired[Callable[[object], None]]
    description: NotRequired[str]
```

**MUST NOT.** Don't split into two `TypedDict` classes with
`total=False`:

```python
# Forbidden
class _SysctlBase(TypedDict, total=False):
    validator: Callable[[object], None]
    description: str

class SysctlSpec(_SysctlBase):
    key: str
    attr: str
    default: object
```

The `Required` / `NotRequired` markers express per-field
optionality without splitting the schema.

## 13. PEP 675 — `LiteralString` (3.11)

PyTCP currently has no consumer (we don't build SQL or shell
commands from user input). Listed here so the modern form is
the default when someone adds one.

```python
# Good — when adding the feature later
from typing import LiteralString

def log_template(channel: LiteralString, /) -> None:
    log_subsystem.fire(channel)
```

## 14. PEP 695 — Generic-class / function / `type` syntax (3.12)

**Generic classes:**

```python
# Good
class NeighborCache[A: Ip4Address | Ip6Address, P = object](Subsystem):
    _entries: dict[A, NeighborEntry[A, P]]

@dataclass(frozen=True, kw_only=True, slots=True)
class NeighborEntry[A: Ip4Address | Ip6Address, P = object]:
    address: A
    queued_packet: P | None = field(default=None)
```

**Generic functions:**

```python
# Good
def first[T](iterable: Iterable[T]) -> T | None:
    for item in iterable:
        return item
    return None
```

**Type aliases:**

```python
# Good
type Buffer = bytes | bytearray | memoryview
type SolicitCallback[A: Ip4Address | Ip6Address] = Callable[[A, MacAddress | None], None]
type FlushCallback[P] = Callable[[P, MacAddress], None]
```

**MUST NOT.** Never use the pre-PEP-695 forms:

```python
# Forbidden
from typing import Generic, TypeVar, TypeAlias

A = TypeVar("A", bound="Ip4Address | Ip6Address")
P = TypeVar("P")

class NeighborCache(Generic[A, P], Subsystem):
    ...

Buffer: TypeAlias = "bytes | bytearray | memoryview"
SolicitCallback: TypeAlias = Callable[[A, "MacAddress | None"], None]
```

`TypeVar`, `Generic`, `TypeAlias` survive in `typing` only for
backwards compat. PyTCP does not have an installed base, so
they are forbidden in new code and on-touch in legacy code.

## 15. PEP 698 — `typing.override` (3.12)

Every method that overrides a parent method **MUST** carry
`@override`:

```python
# Good
from typing import override

class UdpHeader(ProtoStruct):
    @override
    def __post_init__(self) -> None:
        assert is_uint16(self.sport), ...

    @override
    def __len__(self) -> int:
        return UDP__HEADER__LEN

    @override
    def __buffer__(self, _: int) -> memoryview: ...
```

mypy strict flags missing overrides, but the decorator also
serves as inline documentation that "this is part of the
parent's contract." It's not optional.

**Edge case — protected-hook pattern, not override.** When a
subclass adds a new public method that *delegates* to a parent
protected method with a different signature, the subclass
method is **not** an override and `@override` would be wrong:

```python
# Good — protected-hook pattern
class NeighborCache:
    def _find_entry(self, address: A) -> MacAddress | None: ...

class ArpCache(NeighborCache[Ip4Address, EthernetAssembler]):
    # New public method; signature differs (kw-only ip4_address=).
    # NOT an override — no @override decorator.
    def find_entry(self, *, ip4_address: Ip4Address) -> MacAddress | None:
        return self._find_entry(ip4_address)
```

See [`typing.md`](typing.md) §11.1 for the full pattern.

## 16. PEP 696 — Type-parameter defaults (3.13)

```python
# Good — default keeps single-parameter call sites working
class NeighborCache[A: Ip4Address | Ip6Address, P = object](Subsystem):
    ...

# Consumers may bind both or rely on the default:
cache_no_payload: NeighborCache[Ip4Address] = NeighborCache(...)
cache_typed: NeighborCache[Ip4Address, EthernetAssembler] = ArpCache()
```

Use a default whenever a generic parameter is "new since the
last version" and you want existing single-parameter call
sites to keep working without an explicit `, object` everywhere.

## 17. PEP 649 — Lazy annotation evaluation (3.14)

Plain annotations are evaluated lazily as `__annotate__`
closures and are only resolved on access (via
`typing.get_type_hints` or similar). This means **runtime
imports of typed names don't need to happen before the
annotated module loads** — there is no longer a forward-
reference problem for names visible at runtime.

Consequence:

```python
# Good — runtime imports, no TYPE_CHECKING guard, no future-import
from net_addr import Ip4Address, MacAddress
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler

class ArpCache(NeighborCache[Ip4Address, EthernetAssembler]):
    def find_entry(self, *, ip4_address: Ip4Address) -> MacAddress | None: ...
    def _flush_packet(self, packet: EthernetAssembler, mac_address: MacAddress) -> None: ...
```

**MUST NOT** — the trio of future-import + `TYPE_CHECKING`
guard + string-quoted annotations, when the names involved
are runtime-safe to import:

```python
# Forbidden — unnecessary indirection on 3.14+
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from net_addr import Ip4Address, MacAddress
    from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler

class ArpCache(NeighborCache["Ip4Address", "EthernetAssembler"]):
    def find_entry(self, *, ip4_address: "Ip4Address") -> "MacAddress | None": ...
```

The trio is only justified when there is a **genuine circular
import** (module A imports from module B at annotation time
and module B imports from A at runtime). If you can move the
import to module top without a `ImportError` at startup, the
guard is unnecessary and **MUST** be removed.

When removing a `TYPE_CHECKING` guard, **audit the trio
together**:

1. Drop `from __future__ import annotations`.
2. Drop the `if TYPE_CHECKING:` block.
3. Move the imports to the module top.
4. **Unquote every annotation**, including PEP 695 bounds
   (`class Foo[T: Bar]:` not `class Foo[T: "Bar"]:`) and
   `type X = ...` aliases (`type X = Foo | Bar` not
   `type X = "Foo | Bar"`).

Half-converted files (some annotations quoted, some not) are
the worst state — they hide which annotations actually need
lazy evaluation.

## 18. PEP 750 — Template strings (3.14)

t-strings are the safe-by-default escaping replacement for
manual `f"...".replace(...)`-based escaping. PyTCP has no
SQL / HTML / shell-injection surface today, so this is mostly
**N/A**. The rule kicks in when someone adds a code path that
substitutes untrusted values into a structured string format —
use a `t"..."` with the appropriate processor rather than
inlining the substitution.

## 19. Walrus operator (3.8)

The walrus operator is mandatory for capture-while-testing in
sanity-check conditionals and cache-lookup patterns:

```python
# Good — captures value for the error message in one line
if (value := self._header.sport) == 0:
    raise UdpSanityError(
        f"The 'sport' field must be greater than 0. Got: {value}",
    )

# Good — find_entry pattern from packet_handler__ethernet__tx
if mac_address := stack.nd_cache.find_entry(ip6_address=ip6_dst):
    ethernet_packet_tx.dst = mac_address
    self.__send_out_packet(ethernet_packet_tx)
    return TxStatus.PASSED__ETHERNET__TO_TX_RING
```

**MUST NOT.** Don't pre-bind the value in the line above:

```python
# Forbidden — verbose
value = self._header.sport
if value == 0:
    raise UdpSanityError(...)

mac_address = stack.nd_cache.find_entry(ip6_address=ip6_dst)
if mac_address:
    ...
```

The pre-bind form is acceptable when the value is used in
*multiple* statements after the test; the walrus form is
canonical when the value is needed only inside the conditional.

## 20. f-strings (3.6, debug form 3.8)

```python
# Good
log("ip6", f"{tracker} - Resolved destination IPv6 {ip6_dst} to MAC {mac}")
raise UdpIntegrityError(
    f"The condition 'UDP__HEADER__LEN <= self._ip__payload_len <= "
    f"len(self._frame)' must be met. Got: {UDP__HEADER__LEN=}, "
    f"{self._ip__payload_len=}, {len(self._frame)=}",
)
assert is_uint16(self.sport), f"The 'sport' field must be a 16-bit unsigned integer. Got: {self.sport!r}"
```

The `{x=}` debug form is mandatory for multi-value error
messages — it emits `x=value` automatically so adding /
removing diagnostic values from a message is one identifier
edit, not a manual string-concat update.

The `!r` conversion is the canonical form for values in
assertion messages.

**MUST NOT.** Never use `%`-formatting or `.format()`:

```python
# Forbidden
log("ip6", "%s - Resolved destination IPv6 %s to MAC %s" % (tracker, ip6_dst, mac))
log("ip6", "{0} - Resolved destination IPv6 {1} to MAC {2}".format(tracker, ip6_dst, mac))
```

Don't concatenate with `+` for user-visible messages:

```python
# Forbidden
raise UdpIntegrityError("Got: " + repr(self.sport))
```

## 21. Positional-only `/` and keyword-only `*` (3.8)

Buffer/byte-string arguments and mutated containers are
positional-only:

```python
# Good
def assemble(self, buffers: list[Buffer], /) -> None: ...
def from_buffer(cls, buffer: Buffer, /) -> Self: ...
def __init__(self, message: str, /) -> None: ...  # protocol error subclasses
```

Assembler constructors and factories are keyword-only:

```python
# Good
def __init__(
    self,
    *,
    udp__sport: int = 0,
    udp__dport: int = 0,
    udp__payload: Buffer = bytes(),
    echo_tracker: Tracker | None = None,
) -> None: ...

def add_entry(self, *, ip4_address: Ip4Address, mac_address: MacAddress) -> None: ...
```

**MUST NOT.** Never write a constructor whose call sites
depend on positional argument order:

```python
# Forbidden
def __init__(
    self,
    udp__sport: int = 0,
    udp__dport: int = 0,
    udp__payload: Buffer = bytes(),
) -> None: ...
```

Positional construction is brittle to field re-ordering and
hides intent at the call site.

---

## 22. Forbidden patterns roundup

A single-section index of the canonical anti-patterns this
rule forbids. If you find any of these in source on a touch,
fix them in the same commit:

| Anti-pattern | Replace with | Section |
|---|---|---|
| `Optional[X]` | `X \| None` | §3 |
| `Union[X, Y]` | `X \| Y` | §3 |
| `List[X]` | `list[X]` | §7 |
| `Dict[K, V]` | `dict[K, V]` | §7 |
| `Tuple[A, B]` | `tuple[A, B]` | §7 |
| `Set[X]` | `set[X]` | §7 |
| `FrozenSet[X]` | `frozenset[X]` | §7 |
| `Type[X]` | `type[X]` | §7 |
| `if/elif` over enum | `match`/`case` | §4 |
| `bin(x).count("1")` | `x.bit_count()` | §5 |
| Manual prefix-strip slicing | `str.removeprefix` | §6 |
| `{**a, **b}` | `a \| b` | §8 |
| `TypeVar(..., bound="Cls")` | `typing.Self` | §9 |
| `from typing import Generic` | PEP 695 `class C[T]:` | §14 |
| `from typing import TypeAlias` | PEP 695 `type X = ...` | §14 |
| Missing `@override` | `@override` from `typing` | §15 |
| `from __future__ import annotations` (no real cycle) | drop it + unquote | §17 |
| `TYPE_CHECKING` guard (no real cycle) | runtime import | §17 |
| String-quoted annotation (no real cycle) | unquote | §17 |
| `%`-formatting / `.format()` | f-string | §20 |
| Positional dataclass / assembler ctor | keyword-only `*` | §21 |
| `typing.Optional[X] \| None` (double-optional) | `X \| None` | §3 |
| `cast(X, value)` to launder type | tighten the surrounding types | §14 |
| `# type: ignore[override]` to hide Liskov mismatch | refactor to protected-hook pattern | §15, [`typing.md`](typing.md) §11.1 |

---

## 23. When the rule does not apply

- **Vendored / third-party code.** If PyTCP ever vendors an
  external library, that code is fenced off from these rules
  (it lives in its own subdirectory and is not "PyTCP source"
  for the purposes of this rule).
- **Verbatim RFC quotes** in ASCII diagrams or comment blocks.
  These are documentation, not code; the wording is preserved
  for archaeology.
- **Generated code** (none today). If a future code-generation
  step lands, the rule applies to the generator's source, not
  the generated output.

There is no other exception. "I prefer the old form" or "the
team always wrote it this way" is not a justification; the
project floor is 3.14 and the modern form is the canonical
form.

---

## 24. Audit checklist

Before opening a PR, run `make lint` (mandatory). If `make
lint` is clean, the mechanical rules in this file are
satisfied. The non-mechanical ones (e.g. "use match/case
where it fits") rely on reviewer judgement; a reviewer is
entitled to bounce a PR that uses `if/elif` on an enum or a
string-quoted annotation that has no circular-import
justification.

When refactoring legacy code that pre-dates this rule:

1. Read the surrounding module to understand whether a
   `TYPE_CHECKING` guard has a real reason (audit the trio
   together per §17).
2. Don't reflow whitespace or rename identifiers in the same
   commit as a typing modernisation — keep the diff focused so
   the reviewer can verify the rewrite is mechanical.
3. Delete `from __future__ import annotations`,
   `from typing import (Optional, Union, List, ...)`, and
   similar legacy imports as part of the modernisation —
   leaving the import behind "in case it's needed" is
   exactly the rot this rule exists to prevent.

---

## 25. Cross-references

- [`typing.md`](typing.md) — annotation discipline,
  generics, `Self`, `@override`, mypy strict, and the
  forbidden-`# type: ignore`-pattern catalogue. Where this
  file references a typing feature, that file documents
  how to apply it.
- [`unit_testing.md`](unit_testing.md) and
  [`integration_testing.md`](integration_testing.md) for
  test-file authoring conventions. Test files follow the
  same language-feature rules; the `parameterized_class`
  dev dependency is a test-only exception to the
  zero-runtime-deps policy.
- [`feature_implementation.md`](feature_implementation.md)
  for the tests-first workflow, the modernise-on-touch
  rule, and the docstring audit.
- [`source_files.md`](source_files.md) — general PyTCP
  source-file conventions (file skeleton, imports, naming,
  formatting).
- [`net_proto.md`](net_proto.md) —
  PyTCP protocol patterns that consume these features
  (six-file layout, dataclass shape, parser three-phase
  pipeline, assembler PEP 695 generic stacking).
- [`pytcp.md`](pytcp.md) — `Subsystem`,
  packet handlers, sysctls.
- CPython "What's New" pages — authoritative source for
  per-version feature inventories:
  [3.10](https://docs.python.org/3/whatsnew/3.10.html),
  [3.11](https://docs.python.org/3/whatsnew/3.11.html),
  [3.12](https://docs.python.org/3/whatsnew/3.12.html),
  [3.13](https://docs.python.org/3/whatsnew/3.13.html),
  [3.14](https://docs.python.org/3/whatsnew/3.14.html).
