# PyTCP — `net_addr/` Authoring Rule

This rule codifies the conventions for the `net_addr/`
subpackage — PyTCP's pure value-type library for network
addresses, networks, hosts, and masks. The library has no
dependency on `net_proto/` or `pytcp/`; it sits at the
bottom of the dependency graph and is consumed by the other
two subpackages.

The general source-file mechanics (file skeleton, copyright
block, module docstring, imports, naming, formatting) live
in [`source_files.md`](source_files.md) and apply to
`net_addr/` exactly as they apply elsewhere. This rule
adds the `net_addr/`-specific architectural conventions on
top: the ABC hierarchy, value-type construction, equality /
hashing, and the deliberate `click` exception to the
zero-runtime-deps mandate.

The two sibling subpackage rules — protocol authoring under
`net_proto/` and the runtime services under `pytcp/` — live
in [`net_proto.md`](net_proto.md) and
[`pytcp.md`](pytcp.md) respectively.

---

## 1. Package scope

`net_addr/` is a **pure value-type library**. It contains:

- Address classes: `Ip4Address`, `Ip6Address`, `MacAddress`.
- Network classes: `Ip4Network`, `Ip6Network`.
- Host classes: `Ip4Host`, `Ip6Host` (address + network +
  optional gateway / origin / expiration metadata).
- Mask classes: `Ip4Mask`, `Ip6Mask`.
- Enumerations: `IpVersion`, `Ip4HostOrigin`,
  `Ip6HostOrigin`.
- ABC base classes: `Base`, `Address`, `IpAddress`,
  `IpNetwork`, `IpHost`, `IpMask`, `IpHostOrigin`.
- `click_types.py` — `click`-typed wrappers for CLI argument
  parsing.
- Error classes — format / sanity / assertion errors for
  every value type.

It does **not** contain:

- Anything stateful (timers, caches, threads, sockets).
- Protocol parsers, assemblers, or wire-format packing.
- Anything that imports from `net_proto/` or `pytcp/`.

If you find yourself writing stateful code in `net_addr/`,
stop — that work belongs in `pytcp/` (per
[`pytcp.md`](pytcp.md)). If you find yourself writing wire
parsing, stop — that's `net_proto/` (per
[`net_proto.md`](net_proto.md)).

## 2. Runtime dependencies

`net_addr/` is the **only** PyTCP subpackage that may import
`click` at runtime. `click` is used by `net_addr/click_types.py`
to expose Click-compatible argument types for CLI consumers
(`ClickTypeIp4Address`, `ClickTypeIp6Host`, etc.). The CLI
helpers are opt-in — importing `net_addr.Ip4Address` does
not pull in `click`; only consumers that need the Click
types import from `net_addr.click_types`.

Everything else in `net_addr/` is stdlib-only:
`socket.inet_aton` / `inet_ntoa`, `re`, `time` for host
expiration, `typing` for `Self` / generics. No other
runtime dependencies.

## 3. Class hierarchy

`net_addr/` is organised as an ABC hierarchy. Every concrete
type inherits from a deliberate chain of abstract bases so
the value-type contract is enforced uniformly:

```
Base                                (net_addr/base.py)
├── Address                         (net_addr/address.py — abstract)
│   ├── IpAddress                   (net_addr/ip_address.py — abstract)
│   │   ├── Ip4Address              (net_addr/ip4_address.py)
│   │   └── Ip6Address              (net_addr/ip6_address.py)
│   └── MacAddress                  (net_addr/mac_address.py)
├── IpNetwork[A, M]                 (net_addr/ip_network.py — abstract, generic)
│   ├── Ip4Network                  (net_addr/ip4_network.py)
│   └── Ip6Network                  (net_addr/ip6_network.py)
├── IpHost[A, N, O]                 (net_addr/ip_host.py — abstract, generic)
│   ├── Ip4Host                     (net_addr/ip4_host.py)
│   └── Ip6Host                     (net_addr/ip6_host.py)
└── IpMask                          (net_addr/ip_mask.py — abstract)
    ├── Ip4Mask                     (net_addr/ip4_mask.py)
    └── Ip6Mask                     (net_addr/ip6_mask.py)
```

When adding a new value-type concept:

1. Identify where it sits in the hierarchy. If it's a
   v4/v6-parallel pair, both branches need a sibling class.
2. Lift shared behaviour into the ABC and the
   `IpNetwork[A, M]` / `IpHost[A, N, O]` PEP 695 generics.
   See [`typing.md`](typing.md) §9 for generic syntax.
3. The concrete subclass overrides type-version-specific
   methods (`__init__` accepting v4-shaped vs v6-shaped
   inputs, `__str__` formatting, etc.) and binds `_version`
   to the right `IpVersion` member.

## 4. Value-type implementation conventions

`net_addr/` classes are value types but they are **not
@dataclass**. The codebase predates the @dataclass-everywhere
pattern that `net_proto/` adopted, and the value-type
contract requires explicit control over `__init__`'s
multi-form input parsing (str / bytes / int / Self / None)
that `@dataclass` does not offer ergonomically.

The canonical shape:

```python
class Ip4Address(IpAddress):
    """
    IPv4 address support class.
    """

    __slots__ = ()                       # see §4.1
    _version: IpVersion = IpVersion.IP4  # class-level binding

    def __init__(                        # see §4.2
        self,
        address: Self | str | bytes | bytearray | memoryview | int | None = None,
        /,
    ) -> None:
        """
        Initialize the IPv4 address object.
        """

        if address is None:
            self._address = 0
            return

        if isinstance(address, Ip4Address):
            self._address = int(address)
            return
        ...
        raise Ip4AddressFormatError(address)
```

### 4.1 `__slots__` is mandatory

Every concrete class declares `__slots__`. The base
`Address` class declares `__slots__ = ("_address",)` and
descendants declare additional slots for their own fields:

```python
class IpHost[A, N, O](Address, ABC):
    __slots__ = ("_network", "_gateway", "_origin", "_expiration_time")
    _network: N
    _gateway: A | None
    _origin: O
    _expiration_time: int
```

Reasons:

- Memory efficiency — addresses are created in tens of
  thousands during heavy parsing; per-instance `__dict__` is
  wasted space.
- Type discipline — `__slots__` plus the class-level
  annotation tells mypy strict exactly which attributes
  exist; setting an undeclared attribute raises at runtime.
- Immutability proxy — `__slots__` doesn't make the
  instance frozen, but combined with no public mutators
  (§4.3) the effect is equivalent.

Empty `__slots__ = ()` on a concrete subclass is correct
when the subclass adds no new attributes beyond the base
chain; the empty declaration tells the slot machinery the
class is still slotted.

### 4.2 Multi-form `__init__` with positional-only signature

Every value-type `__init__` accepts the canonical set of
input forms in priority order and raises `<Type>FormatError`
when none match:

```python
def __init__(
    self,
    address: Self | str | bytes | bytearray | memoryview | int | None = None,
    /,
) -> None:
    if address is None:
        self._address = 0          # the unspecified address
        return
    if isinstance(address, Self):
        self._address = int(address)
        return
    if isinstance(address, int):
        if 0 <= address <= MASK:
            self._address = address
            return
    if isinstance(address, (memoryview, bytes, bytearray)):
        if len(address) == LEN:
            self._address = int.from_bytes(address)
            return
    if isinstance(address, str):
        if re.search(REGEX, address):
            ...
    raise FormatError(address)
```

- **Positional-only** (`/` after `address`). Construction is
  via `Ip4Address("10.0.0.1")`, never `Ip4Address(address="10.0.0.1")`.
- **`None` → unspecified.** The default value is `None`,
  which constructs the address with value 0. This is the
  PyTCP convention for "the unspecified / zero address"
  (e.g. `Ip4Address()` == `Ip4Address("0.0.0.0")`).
- **`Self` → copy.** `Ip4Address(other_ip4_address)` returns
  a new instance with the same value.
- **Try every input form before raising.** The format-error
  raise is the falls-through-everything default; never an
  `else` branch.
- **Construction errors raise `<Type>FormatError`**, not
  `ValueError` or `TypeError`. The error class subclasses
  `<Type>Error` which subclasses `Exception`. Constructors
  do not catch and silently default to zero.

### 4.3 No public mutators

Once constructed, a value-type instance is immutable from
the public API surface. Properties are read-only; there are
no `setX` / `set_x` methods.

The internal `_field` attributes can technically be assigned
to (since `__slots__` doesn't freeze) but the class contract
forbids it. The two valid mutation patterns:

- **Construct a fresh instance** with the new value:
  `host.address = new_address` is forbidden; instead
  `Ip4Host(other, gateway=new_gateway)` (the copy
  constructor form — see §4.2) produces a new host with
  the override.
- **Class-side state on `Ip4Host`** (the `gateway`,
  `origin`, `expiration_time` extras) is the historical
  exception: these were carved out as mutable for the
  packet-handler RX path before the value-type contract
  was tightened. Treat them as a known wart, not a
  template.

### 4.4 Equality and hashing

Every concrete value type overrides `__eq__` and `__hash__`
through the ABC chain. The canonical pattern lives on
`Address`:

```python
@override
def __eq__(self, other: object, /) -> bool:
    return other is self or (
        isinstance(other, type(self)) and self._address == other._address
    )

@override
def __hash__(self) -> int:
    return hash((type(self), self._address))
```

Rules:

- **Type-identity comparison.** `isinstance(other, type(self))`
  — not `isinstance(other, Address)`. An `Ip4Address` with
  value 0 is NOT equal to a `MacAddress` with value 0,
  even though both are `Address` subclasses with `_address
  == 0`. The hash includes `type(self)` for the same reason.
- **Identity fast path.** The leading `other is self` check
  avoids the isinstance / equality work for the common
  same-object case (very frequent in cache lookups).
- **Symmetric.** No need to delegate to `other.__eq__` —
  the type-equality requirement makes equality symmetric by
  construction.
- **Never compare across versions.** `Ip4Address("0.0.0.0")
  != Ip6Address("::")` even though both are
  "the unspecified address."

### 4.5 `__str__` and `__repr__`

`__str__` returns the canonical wire-format string
(e.g. `"10.0.0.1"`, `"2001:db8::1"`, `"02:00:00:00:00:07"`).
Use `socket.inet_ntoa` / `socket.inet_ntop` where possible;
they're the canonical Linux-equivalent formatters.

`__repr__` is the constructor-callable form:
`Ip4Address("10.0.0.1")`. mypy strict + IDE tooling rely on
this format for the dataclass-style introspection that
log lines depend on.

### 4.6 `__buffer__` and `__int__`

Every `Address` subclass implements:

- `__int__(self) -> int` — return the raw integer value.
  Already implemented on `Address` as
  `return self._address`; subclasses do not need to
  override.
- `__buffer__(self, _: int) -> memoryview` — return the
  wire-bytes representation as a `memoryview`. Each
  subclass implements this with its specific byte width.

The `__buffer__` protocol (PEP 688) means `bytes(addr)`,
`memoryview(addr)`, and `struct.pack_into("4s", buf, 0, addr)`
all work without an explicit conversion. Consumers in
`net_proto/` packs addresses into headers via this
protocol; do not add a separate `to_bytes()` method.

### 4.7 `typing.Self` for self-returning methods

Use `typing.Self` (PEP 673) for any method that returns
"an instance of the same concrete class" — including the
unspecified-address factory:

```python
@property
def unspecified(self) -> Self:
    """
    Get the unspecified network address.
    """

    return type(self)()
```

`Ip4Address.unspecified` returns an `Ip4Address`;
`Ip6Address.unspecified` returns an `Ip6Address`. Without
`Self`, the return type would have to be `Address` (the
declared base), losing the subtype information.

See [`typing.md`](typing.md) §10 for the full `Self` rules.

## 5. Network / host / mask classes

The address pattern from §4 generalises to networks, hosts,
and masks. The differences:

- `IpNetwork[A, M]` is generic over address type and mask
  type. PEP 695 generic syntax — see
  [`typing.md`](typing.md) §9.
- `Ip4Network` / `Ip6Network` accept additional input
  forms: `(Ip4Address, Ip4Mask)`, `(Ip4Address, Ip4Network)`,
  and the canonical string form `"10.0.0.0/24"`.
- `IpHost[A, N, O]` is generic over address, network, and
  host-origin enum.
- Host classes have the known carve-out for mutable
  `gateway` / `origin` / `expiration_time` fields (§4.3) —
  these are kw-only constructor arguments and accessed via
  read-only properties on the public surface but settable
  via the internal `_gateway` slot from the packet handler.
  Each setter on a host MUST carry the
  `# Hack to bypass the value-type immutability contract.`
  inline comment so the deviation is greppable.

## 6. Click CLI helpers (`click_types.py`)

`net_addr.click_types` exposes `click.ParamType` subclasses
that consume the value-type constructors above. Each Click
type:

- Subclasses `click.ParamType`.
- Names follow the `ClickType<ValueType>` pattern —
  `ClickTypeIp4Address`, `ClickTypeIp6Host`,
  `ClickTypeMacAddress`.
- Implements `convert(value, param, ctx)` to call the
  underlying value-type constructor and translate format
  errors into `click.BadParameter`.
- Is exported from `net_addr.__init__` alongside the value
  types for symmetric import sites.

Consumers (CLI tools under `examples/` or future bin/
scripts) use the Click types via `@click.option`
decorators. The `click` runtime dependency is justified by
this surface alone — every other PyTCP subpackage uses
stdlib only.

## 7. Error classes

Each value type has its own error hierarchy in
`net_addr/errors.py`:

```
Exception
├── Ip4AddressError
│   ├── Ip4AddressFormatError       (constructor input rejected)
│   └── Ip4AddressSanityError       (post-construction invariant violated)
├── Ip6AddressError
│   ...
└── MacAddressError
    ...
```

- Constructor input validation raises `*FormatError`.
- Cross-field invariants (e.g. host gateway not in network)
  raise `*SanityError`.
- The base `<Type>Error` is unused as a direct raise — it's
  the catch-all for consumers that want to handle "any
  problem with this value type."
- Error messages quote the offending input verbatim:
  `raise Ip4AddressFormatError(value)` — the `__init__` of
  the error class formats the message with `repr(value)` so
  the wire input is preserved in the traceback.

## 8. Module structure inside `net_addr/`

Each value type lives in its own module:

| File | Contents |
|---|---|
| `base.py` | `Base` ABC — root of the value-type hierarchy |
| `address.py` | `Address` ABC — abstract address contract |
| `ip_address.py` | `IpAddress` ABC — abstract IP-address contract |
| `ip4_address.py` | `Ip4Address` concrete class |
| `ip6_address.py` | `Ip6Address` concrete class |
| `mac_address.py` | `MacAddress` concrete class |
| `ip_network.py` | `IpNetwork[A, M]` generic ABC |
| `ip4_network.py` | `Ip4Network` concrete class |
| `ip6_network.py` | `Ip6Network` concrete class |
| `ip_host.py` | `IpHost[A, N, O]` generic ABC |
| `ip4_host.py` | `Ip4Host` concrete class |
| `ip6_host.py` | `Ip6Host` concrete class |
| `ip_mask.py` | `IpMask` ABC |
| `ip4_mask.py` | `Ip4Mask` concrete class |
| `ip6_mask.py` | `Ip6Mask` concrete class |
| `ip_host_origin.py` | `IpHostOrigin` enum base |
| `ip4_host_origin.py` | `Ip4HostOrigin` enum |
| `ip6_host_origin.py` | `Ip6HostOrigin` enum |
| `ip_version.py` | `IpVersion` enum (`IP4` / `IP6`) |
| `errors.py` | Error class hierarchy for every value type |
| `click_types.py` | Click `ParamType` subclasses |
| `__init__.py` | Re-export every public symbol via `__all__` |

The package `__init__.py` is the **only** place in PyTCP
that declares `__all__` (per
[`source_files.md`](source_files.md) §2.3). It re-exports
every concrete class plus the Click types plus the error
classes, so consumers write `from net_addr import
Ip4Address` instead of reaching into the per-type module.

## 9. Anti-patterns

`net_addr/`-specific anti-patterns. General source-file
anti-patterns live in [`source_files.md`](source_files.md)
§10; language / typing anti-patterns live in
[`python_features.md`](python_features.md) §22 and
[`typing.md`](typing.md) §23.

- **Using `@dataclass(frozen=True, slots=True)`** for a new
  value type. `net_addr/` uses explicit `__slots__` plus
  explicit `__init__` for the multi-form input parsing.
  Match the existing pattern — do not introduce a
  dataclass branch.
- **Single-input `__init__` signature.** Every value-type
  constructor must accept `None` (unspecified), `Self`
  (copy), `int` (raw value), `bytes` / `bytearray` /
  `memoryview` (wire form), and `str` (canonical formatter
  output). Drop one, and the type stops being
  interchangeable across PyTCP's data path.
- **Keyword arguments on a value-type `__init__`** (except
  for `Ip4Host` / `Ip6Host`'s `gateway` / `origin` /
  `expiration_time` carve-outs in §4.3). The single
  positional-only `address: Self | str | bytes | ... | None`
  is the contract.
- **Raising `ValueError` / `TypeError`** on constructor
  failure. Use `<Type>FormatError` — see §7.
- **Importing `net_proto` or `pytcp`** from `net_addr/`.
  `net_addr/` is the bottom of the dependency graph; the
  reverse direction is the only legal flow.
- **Adding a setter (`set_address(value)` or
  `address.setter`)** to make a value mutable. Construct a
  fresh instance instead.
- **Putting stateful behaviour in `net_addr/`** — timers,
  caches, threads, sockets. That's `pytcp/`. If a helper
  has any state that outlives a single value, it belongs
  somewhere else.
- **Reaching into `net_addr/_*.py` modules** from consumers.
  Import the public symbol from `net_addr` (the package),
  never from a private submodule path. The package
  `__init__.py` is the boundary.
- **Comparing addresses across versions.**
  `Ip4Address("0.0.0.0") != Ip6Address("::")` is the
  intentional contract — never patch `__eq__` to make
  them equal. If you need a v4-mapped v6 comparison, do
  the explicit mapping via
  `Ip6Address("::ffff:0.0.0.0")` first.

## 10. Reference implementations

When in doubt, mirror the structure of:

- `net_addr/ip4_address.py` — minimal `IpAddress` subclass.
  Multi-form `__init__`, `__str__` via `socket.inet_ntoa`,
  `is_*` predicates.
- `net_addr/ip6_address.py` — heavier subclass with the
  full IPv6 scope / multicast / solicited-node predicate
  family. Same value-type shape as v4.
- `net_addr/mac_address.py` — non-IP address type. Shows
  how the pattern generalises beyond IPv4 / IPv6.
- `net_addr/ip4_host.py` — host class with the known
  carve-out for mutable gateway / origin / expiration_time
  via `__slots__` + setters.
- `net_addr/click_types.py` — every Click `ParamType`
  subclass.
- `net_addr/errors.py` — the canonical error-class
  hierarchy.

These files are the canonical examples. Any deviation from
this rule should be justified by something that appears in
one of them — not by a novel pattern introduced in a new
file.

## 11. Cross-references

- [`source_files.md`](source_files.md) — general source-file
  conventions (file skeleton, copyright block, imports,
  naming, formatting). Apply identically to `net_addr/`.
- [`net_proto.md`](net_proto.md) — the per-protocol six-file
  pattern for `net_proto/protocols/<proto>/`. Consumes
  `net_addr/` value types in header dataclasses.
- [`pytcp.md`](pytcp.md) — the runtime services in `pytcp/`.
  Consumes `net_addr/` value types for stack configuration
  and runtime address bookkeeping.
- [`python_features.md`](python_features.md) — modern
  Python features (PEP 604 / 585 / 695) used by `net_addr/`.
- [`typing.md`](typing.md) — annotation discipline; `Self`,
  PEP 695 generics on `IpNetwork[A, M]` / `IpHost[A, N, O]`,
  ABC + `@override` patterns.
- [`unit_testing.md`](unit_testing.md) §3 — the
  `net_addr/tests/unit/` test layout and the value-type
  parameterised-matrix pattern.
- [`integration_testing.md`](integration_testing.md) —
  integration tests rarely exercise `net_addr/` directly
  (value types are stateless), but the test harness still
  imports `Ip4Address` / `Ip6Address` / `MacAddress`
  fixtures from `net_addr/`.
- [`feature_implementation.md`](feature_implementation.md)
  — tests-first workflow.
