# PyTCP — `packages/net_addr/net_addr/` Authoring Rule

This rule codifies the conventions for the `packages/net_addr/net_addr/`
subpackage — PyTCP's pure value-type library for network
addresses, networks, interface addresses, and masks. The library has no
dependency on `packages/net_proto/net_proto/` or `packages/pytcp/pytcp/`; it sits at the
bottom of the dependency graph and is consumed by the other
two subpackages.

The general source-file mechanics (file skeleton, copyright
block, module docstring, imports, naming, formatting) live
in [`source_files.md`](source_files.md) and apply to
`packages/net_addr/net_addr/` exactly as they apply elsewhere. This rule
adds the `packages/net_addr/net_addr/`-specific architectural conventions on
top: the ABC hierarchy, value-type construction, equality /
hashing, and the deliberate `click` exception to the
zero-runtime-deps mandate.

The two sibling subpackage rules — protocol authoring under
`packages/net_proto/net_proto/` and the runtime services under `packages/pytcp/pytcp/` — live
in [`net_proto.md`](net_proto.md) and
[`pytcp.md`](pytcp.md) respectively.

---

## 1. Package scope

`packages/net_addr/net_addr/` is a **pure value-type library**. It contains:

- Address classes: `Ip4Address`, `Ip6Address`, `MacAddress`.
- Network classes: `Ip4Network`, `Ip6Network`.
- Interface-address classes: `Ip4IfAddr`, `Ip6IfAddr` (a pure
  address + network pair — no mutable metadata). The default
  gateway is not interface-address state — it lives in the
  routing table (FIB) reached through the Route API; see
  `docs/refactor/routing_table_host_mode.md`.
- Mask classes: `Ip4Mask`, `Ip6Mask`.
- Wildcard classes: `Ip4Wildcard`, `Ip6Wildcard` (arbitrary,
  possibly non-contiguous ACL / firewall match masks).
- Enumerations: `IpVersion`.
- ABC base classes: `Base`, `Ip`, `Address`, `IpAddress`,
  `IpNetwork`, `IfAddr`, `IpMask`, `IpWildcard`.
- `click_types.py` — `click`-typed wrappers for CLI argument
  parsing.
- Error classes — format / sanity errors for every value
  type.

It does **not** contain:

- Anything stateful (timers, caches, threads, sockets).
- Protocol parsers, assemblers, or wire-format packing.
- Anything that imports from `packages/net_proto/net_proto/` or `packages/pytcp/pytcp/`.

If you find yourself writing stateful code in `packages/net_addr/net_addr/`,
stop — that work belongs in `packages/pytcp/pytcp/` (per
[`pytcp.md`](pytcp.md)). If you find yourself writing wire
parsing, stop — that's `packages/net_proto/net_proto/` (per
[`net_proto.md`](net_proto.md)).

## 2. Runtime dependencies

`packages/net_addr/net_addr/` is the **only** PyTCP subpackage that may import
`click` at runtime. `click` is used by `packages/net_addr/net_addr/click_types.py`
to expose Click-compatible argument types for CLI consumers
(`ClickTypeIp4Address`, `ClickTypeIp6IfAddr`, etc.). The CLI
helpers are opt-in — importing `net_addr.Ip4Address` does
not pull in `click`; only consumers that need the Click
types import from `net_addr.click_types`.

Everything else in `packages/net_addr/net_addr/` is stdlib-only:
`socket` (`inet_pton` / `inet_ntop` / `inet_ntoa`), `re`,
`hashlib` / `secrets` (RFC 7217 / RFC 8981 IPv6 IID
generation in `ip6_ifaddr.py`), `typing` for `Self` /
generics. No other runtime dependencies.

## 3. Class hierarchy

`packages/net_addr/net_addr/` is organised as an ABC hierarchy. Every concrete
type inherits from a deliberate chain of abstract bases so
the value-type contract is enforced uniformly. There are two
roots: `Base` (the value-type contract — `__str__` /
`__repr__` / `__eq__` / `__hash__`) and `Ip` (a small mixin
providing IP-version introspection — `version` / `is_ip4` /
`is_ip6`), mixed into every IP-versioned family but **not**
into `MacAddress` (a MAC has no IP version):

```
Base                            (net_addr/base.py — value-type contract ABC)
Ip                              (net_addr/ip.py — IP-version mixin ABC: version / is_ip4 / is_ip6)

Address(Base)                   (net_addr/address.py — abstract)
├── IpAddress(Address, Ip)      (net_addr/ip_address.py — abstract)
│   ├── Ip4Address              (net_addr/ip4_address.py)
│   └── Ip6Address              (net_addr/ip6_address.py)
└── MacAddress                  (net_addr/mac_address.py — no Ip mixin)

IpNetwork[A, M](Base, Ip)       (net_addr/ip_network.py — abstract, generic)
├── Ip4Network                  (net_addr/ip4_network.py)
└── Ip6Network                  (net_addr/ip6_network.py)

IfAddr[A, N](Base, Ip)          (net_addr/ip_ifaddr.py — abstract, generic)
├── Ip4IfAddr                   (net_addr/ip4_ifaddr.py)
└── Ip6IfAddr                   (net_addr/ip6_ifaddr.py)

IpMask(Base, Ip)                (net_addr/ip_mask.py — abstract)
├── Ip4Mask                     (net_addr/ip4_mask.py)
└── Ip6Mask                     (net_addr/ip6_mask.py)

IpWildcard(Base, Ip)            (net_addr/ip_wildcard.py — abstract)
├── Ip4Wildcard                 (net_addr/ip4_wildcard.py)
└── Ip6Wildcard                 (net_addr/ip6_wildcard.py)
```

When adding a new value-type concept:

1. Identify where it sits in the hierarchy. If it's a
   v4/v6-parallel pair, both branches need a sibling class.
2. Lift shared behaviour into the ABC and the
   `IpNetwork[A, M]` / `IfAddr[A, N]` PEP 695 generics.
   See [`typing.md`](typing.md) §9 for generic syntax.
3. The concrete subclass overrides type-version-specific
   methods (`__init__` accepting v4-shaped vs v6-shaped
   inputs, `__str__` formatting, etc.) and binds `_version`
   to the right `IpVersion` member.

## 4. Value-type implementation conventions

`packages/net_addr/net_addr/` classes are value types but they are **not
@dataclass**. The codebase predates the @dataclass-everywhere
pattern that `packages/net_proto/net_proto/` adopted, and the value-type
contract requires explicit control over `__init__`'s
multi-form input parsing (str / bytes / int / Self / None)
that `@dataclass` does not offer ergonomically.

The canonical shape:

```python
@final                                   # see §4.4 — seals the leaf
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
class IfAddr[A: (Ip6Address, Ip4Address), N: (Ip6Network, Ip4Network)](Base, Ip, ABC):
    __slots__ = ("_address", "_network")
    _address: A
    _network: N
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
  `ifaddr.address = new_address` is forbidden; instead
  `Ip4IfAddr((new_address, mask))` (or the copy-constructor
  form — see §4.2) produces a new interface address.
- **No carve-outs remain.** `IfAddr` is a pure
  `(address, network)` value pair with no mutable state.
  The historical `origin` / `expiration_time` / `gateway`
  extras are **gone** — address provenance / lifetime is
  owned by the runtime that holds the address, and the
  default gateway moved to the FIB / Route API
  (`docs/refactor/routing_table_host_mode.md`). Do not
  re-introduce a mutable field on a value type; construct a
  fresh instance instead.

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
- **Symmetric — enforced by `@final`, not assumed.**
  `isinstance(other, type(self))` + a `type(self)`-keyed hash
  is symmetric and hash-consistent *only* for leaf classes: a
  subclass instance compares unequal to a base instance in
  one direction and equal in the other (Python's reflected-
  `__eq__` subclass priority), and the two hashes diverge.
  Every concrete value type is therefore decorated `@final`
  (`Ip4Address`, `Ip6Address`, `MacAddress`, `Ip4Network`,
  `Ip6Network`, `Ip4Mask`, `Ip6Mask`, `Ip4Wildcard`,
  `Ip6Wildcard`, `Ip4IfAddr`, `Ip6IfAddr`) so mypy strict
  rejects any subclass that would reintroduce the asymmetry.
  The ABCs (`Address`, `IpAddress`, `IpNetwork`, `IfAddr`,
  `IpMask`, `IpWildcard`) stay subclassable — only the leaves
  are sealed. `@final` is a type-checker contract (it sets a
  runtime-introspectable `__final__`, which the
  `test__abstract_stubs.py` leaf-finality test pins); do not
  rely on it for runtime enforcement.
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
`packages/net_proto/net_proto/` packs addresses into headers via this
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

## 5. Network / interface-address / mask classes

The address pattern from §4 generalises to networks,
interface addresses, and masks. The differences:

- `IpNetwork[A, M]` is generic over address type and mask
  type. PEP 695 generic syntax — see
  [`typing.md`](typing.md) §9.
- `Ip4Network` / `Ip6Network` accept additional input
  forms: `(Ip4Address, Ip4Mask)`, `(Ip4Address, Ip4Network)`,
  and the canonical string form `"10.0.0.0/24"`.
- `IfAddr[A, N]` is generic over address type and network
  type (PEP 695). `Ip4IfAddr` / `Ip6IfAddr` accept a `Self`,
  an `(address, network)` or `(address, mask)` tuple, or the
  canonical `"addr/prefix"` string; the tuple form with an
  explicit network runs an `address in network` sanity check,
  while the mask / string forms derive the network by masking
  and so are contained by construction.
- Interface-address classes are fully immutable value types —
  no mutable fields, no setters (§4.3). `Ip6IfAddr` carries
  classmethod IID generators (`from_eui64`, `from_rfc7217`,
  `from_rfc8981_temp`) that each return a fresh instance.
- `IpWildcard[]` (`Ip4Wildcard` / `Ip6Wildcard`) is the
  ACL / firewall match mask — an arbitrary, possibly
  non-contiguous per-bit "don't care" mask, distinct from the
  contiguous `IpMask` netmask. `IpNetwork.hostmask` returns
  the wildcard that is the inverted netmask (the contiguous
  special case). `__or__` / `__ror__` apply it to an address.

## 6. Click CLI helpers (`click_types.py`)

`net_addr.click_types` exposes `click.ParamType` subclasses
that consume the value-type constructors above. Each Click
type:

- Subclasses `click.ParamType`.
- Names follow the `ClickType<ValueType>` pattern —
  `ClickTypeIp4Address`, `ClickTypeIp6IfAddr`,
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
`packages/net_addr/net_addr/errors.py`:

```
NetAddrError
├── IpAddressError                       (concept umbrella: any version, any axis)
│   ├── IpAddressFormatError             (axis base: any version, Format)
│   ├── IpAddressSanityError             (axis base: any version, Sanity)
│   ├── Ip4AddressError                  (per-type umbrella: any axis)
│   └── Ip6AddressError
│       ├── Ip6AddressFormatError  →  (Ip6AddressError, IpAddressFormatError)
│       └── Ip6AddressSanityError  →  (Ip6AddressError, IpAddressSanityError)
├── IpNetworkError / IfAddrError           (same concept/axis/per-type/leaf shape, both Format and Sanity axes)
├── IpMaskError / IpWildcardError           (same shape but Format axis ONLY — a mask / wildcard can only fail
│                                            at construction, so there is no *MaskSanityError / *WildcardSanityError)
└── MacAddressError                      (single concrete type → no version split)
    ├── MacAddressFormatError
    └── MacAddressSanityError
```

- Constructor input validation raises `*FormatError`.
- Cross-field invariants (e.g. an interface address not contained
  by its own network) raise `*SanityError`.
- **Every concrete leaf has three catchable supersets**: its
  version-agnostic axis base (`IpAddressFormatError` — any
  version, that axis), its per-type umbrella (`Ip4AddressError`
  — that concrete type, both axes; the MAC-parallel grouping),
  and its concept umbrella (`IpAddressError` — any version, any
  axis). A leaf reaches both the per-type and the axis lineage
  by **multiple inheritance among `NetAddrError` subclasses**
  (`class Ip6AddressFormatError(Ip6AddressError,
  IpAddressFormatError)`). The umbrellas carry no `__init__`,
  so they are transparent in the MRO and the message-formatting
  `__init__` resolves unchanged. This MI is the sanctioned
  two-axis expression and is **distinct from** the §7.1
  prohibition on MI **with a builtin** (`class X(NetAddrError,
  ValueError)`), which remains forbidden.
- The base `<Type>Error` is unused as a direct raise — it's
  the catch-all for consumers that want to handle "any
  problem with this value type."
- Error messages quote the offending input verbatim:
  `raise Ip4AddressFormatError(value)` — the `__init__` of
  the error class formats the message with `repr(value)` so
  the wire input is preserved in the traceback.

### 7.1 `packages/net_addr/net_addr/` raises ONLY `NetAddrError` subclasses (MUST)

Every `raise` statement reachable at runtime in `packages/net_addr/net_addr/`
**MUST** raise a subclass of `NetAddrError`. A bare builtin
exception (`ValueError`, `TypeError`, `IndexError`,
`RuntimeError`, `KeyError`, `OverflowError`, …) is
**forbidden** — a consumer that does `except NetAddrError:`
around any net_addr call must catch *every* failure the
library can produce. This is normative; a reviewer is
entitled to bounce a PR that adds a bare-builtin `raise`
under `packages/net_addr/net_addr/`.

PyTCP does **not** chase stdlib-`ipaddress` exception
parity. There is **no** multiple-inheritance-with-a-builtin
pattern (`class X(NetAddrError, ValueError)`): the goal is a
single clean `NetAddrError` tree, not protocol mirroring. A
caller that wants the old behaviour catches `NetAddrError`.

If no existing `NetAddrError` subclass fits the failure, a
**new one MUST be created** in `packages/net_addr/net_addr/errors.py` and
exported from `packages/net_addr/net_addr/__init__.py` `__all__` — never
reach for a builtin because "there is no matching error
yet." Reuse before inventing: most failures map onto the
existing two-axis vocabulary.

### 7.2 Format vs Sanity — the two-axis mapping (MUST)

Every `packages/net_addr/net_addr/` failure is one of exactly two kinds, and
each maps onto the existing per-type hierarchy:

| Failure kind | Error family | Examples |
|---|---|---|
| **Construction** — a value cannot be built from the given input | `<Type>FormatError` | bad address / mask / network / ifaddr literal |
| **Everything else** — a precondition, invariant, invalid operation argument, unsupported `__format__` code, out-of-range index, or a generator that cannot satisfy its contract | `<Type>SanityError` | `multicast_mac` on a non-multicast address; bad `subnets` / `supernet` / `address_exclude` argument; `IpNetwork.__getitem__` out of range; unknown `__format__` code; RFC 8981 retry exhaustion |

Per-type Sanity classes exist for every family
(`Ip4/Ip6AddressSanityError`, `Ip4/Ip6NetworkSanityError`,
`Ip4/Ip6IfAddrSanityError`, `MacAddressSanityError`); the
`IpAddressSanityError` / `IpNetworkSanityError` bases are
used directly only by version-agnostic code (e.g. the
`IpNetwork.summarize` staticmethod, which has no concrete
version in hand). Construction stays on the existing
`*FormatError` classes — do not reclassify constructor
input rejection as Sanity.

Consequence accepted by this project: `__format__` no
longer raises `ValueError` and `IpNetwork.__getitem__` no
longer raises `IndexError`. `IpNetwork.__iter__` is defined
explicitly so iteration does not depend on the
`__getitem__`/`IndexError` sequence protocol; the parity
loss is intentional.

### 7.3 No bare `assert` for user-reachable preconditions; `NotImplementedError` exemption

- A user-reachable precondition check (e.g.
  `Ip6Address.solicited_node_multicast` requiring a
  unicast/unspecified address) **MUST** raise the relevant
  `*SanityError`, not `assert` (which raises the builtin
  `AssertionError` and is stripped under `python -O`).
  `assert` remains acceptable only for genuinely
  unreachable internal invariants and for the mypy-narrowing
  idiom.
- `raise NotImplementedError` inside an `@abstractmethod`
  body is the **one exemption** to §7.1 — it is the
  idiomatic abstract-stub marker, the ABC machinery makes
  the path unreachable, and it is not a `NetAddrError`. Do
  not "fix" these to a net_addr error.

### 7.4 Catching is symmetric with raising

Because §7.1 guarantees net_addr never raises a bare builtin,
a `try` around a net_addr call **MUST NOT** catch bare
builtins (`except ValueError`) to mop up sub-constructor
failures — catch the precise `NetAddrError` subclass. A
lingering `except ValueError` next to `except Ip6MaskFormatError`
is the asymmetry this rule exists to remove; delete the
builtin arm once the raising side is `NetAddrError`-only.

## 8. Module structure inside `packages/net_addr/net_addr/`

Each value type lives in its own module:

| File | Contents |
|---|---|
| `base.py` | `Base` ABC — value-type contract root (`__str__` / `__repr__` / `__eq__` / `__hash__`) |
| `ip.py` | `Ip` ABC — IP-version mixin (`version` / `is_ip4` / `is_ip6`) |
| `address.py` | `Address` ABC — abstract address contract |
| `ip_address.py` | `IpAddress` ABC — abstract IP-address contract |
| `ip4_address.py` | `Ip4Address` concrete class |
| `ip6_address.py` | `Ip6Address` concrete class |
| `mac_address.py` | `MacAddress` concrete class |
| `ip_network.py` | `IpNetwork[A, M]` generic ABC |
| `ip4_network.py` | `Ip4Network` concrete class |
| `ip6_network.py` | `Ip6Network` concrete class |
| `ip_ifaddr.py` | `IfAddr[A, N]` generic ABC |
| `ip4_ifaddr.py` | `Ip4IfAddr` concrete class |
| `ip6_ifaddr.py` | `Ip6IfAddr` concrete class |
| `ip_mask.py` | `IpMask` ABC |
| `ip4_mask.py` | `Ip4Mask` concrete class |
| `ip6_mask.py` | `Ip6Mask` concrete class |
| `ip_wildcard.py` | `IpWildcard` ABC |
| `ip4_wildcard.py` | `Ip4Wildcard` concrete class |
| `ip6_wildcard.py` | `Ip6Wildcard` concrete class |
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

`packages/net_addr/net_addr/`-specific anti-patterns. General source-file
anti-patterns live in [`source_files.md`](source_files.md)
§10; language / typing anti-patterns live in
[`python_features.md`](python_features.md) §22 and
[`typing.md`](typing.md) §23.

- **Using `@dataclass(frozen=True, slots=True)`** for a new
  value type. `packages/net_addr/net_addr/` uses explicit `__slots__` plus
  explicit `__init__` for the multi-form input parsing.
  Match the existing pattern — do not introduce a
  dataclass branch.
- **A concrete value type without `@final`.** Every concrete
  leaf (address / network / mask / wildcard / interface
  address) MUST be `@final` — the `isinstance`-based
  `__eq__` / `__hash__` contract (§4.4) is symmetric only
  for leaves. The ABCs stay open; the leaves are sealed.
  Adding a new concrete type means adding `@final` and a
  case to the `test__abstract_stubs.py` leaf-finality test
  in the same commit.
- **Single-input `__init__` signature.** Every value-type
  constructor must accept `None` (unspecified), `Self`
  (copy), `int` (raw value), `bytes` / `bytearray` /
  `memoryview` (wire form), and `str` (canonical formatter
  output). Drop one, and the type stops being
  interchangeable across PyTCP's data path.
- **Keyword arguments on a value-type `__init__`** (the sole
  sanctioned exception is the keyword-only `strict` flag on
  `Ip4Network` / `Ip6Network`, declared on the `IpNetwork`
  base — see §5 and the inline rationale in `ip_network.py`).
  Otherwise the single positional-only
  `address: Self | str | bytes | ... | None` is the contract;
  there is no `origin` / `expiration_time` / `gateway`
  carve-out (those were removed when `IfAddr` became a pure
  value type).
- **Raising a bare builtin exception anywhere in
  `packages/net_addr/net_addr/`** — `ValueError`, `TypeError`, `IndexError`,
  `RuntimeError`, `KeyError`, etc. Raise a `NetAddrError`
  subclass (creating one if none fits), multiply-inheriting
  the builtin only where a Python protocol requires it
  (§7.1–§7.2). The `@abstractmethod` `NotImplementedError`
  stub is the sole exemption (§7.3).
- **`assert` for a user-reachable precondition.** Raise the
  relevant `*SanityError` instead; `assert` is stripped
  under `python -O` and raises the builtin `AssertionError`
  (§7.3).
- **`except ValueError` (or any bare builtin) around a
  net_addr call** to catch sub-constructor failures. Catch
  the precise `NetAddrError` subclass — the raising side
  never produces a bare builtin (§7.4).
- **Importing `net_proto` or `pytcp`** from `packages/net_addr/net_addr/`.
  `packages/net_addr/net_addr/` is the bottom of the dependency graph; the
  reverse direction is the only legal flow.
- **Adding a setter (`set_address(value)` or
  `address.setter`)** to make a value mutable. Construct a
  fresh instance instead.
- **Putting stateful behaviour in `packages/net_addr/net_addr/`** — timers,
  caches, threads, sockets. That's `packages/pytcp/pytcp/`. If a helper
  has any state that outlives a single value, it belongs
  somewhere else.
- **Reaching into `packages/net_addr/net_addr/_*.py` modules** from consumers.
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

- `packages/net_addr/net_addr/ip4_address.py` — minimal `IpAddress` subclass.
  Multi-form `__init__`, `__str__` via `socket.inet_ntoa`,
  `is_*` predicates.
- `packages/net_addr/net_addr/ip6_address.py` — heavier subclass with the
  full IPv6 scope / multicast / solicited-node predicate
  family. Same value-type shape as v4.
- `packages/net_addr/net_addr/mac_address.py` — non-IP address type. Shows
  how the pattern generalises beyond IPv4 / IPv6.
- `packages/net_addr/net_addr/ip4_ifaddr.py` — interface-address class: an
  immutable `(address, network)` value pair with multi-form
  construction (`Self` / tuple / mask-tuple / string) and the
  tuple-form `address in network` sanity check. No mutable
  fields.
- `packages/net_addr/net_addr/ip6_ifaddr.py` — adds the RFC 4291 EUI-64,
  RFC 7217 stable-opaque, and RFC 8981 temporary IID
  classmethod generators (each returns a fresh instance).
- `packages/net_addr/net_addr/ip4_wildcard.py` — the ACL / firewall match-mask
  value type (arbitrary non-contiguous bits), sibling to the
  contiguous `Ip4Mask`.
- `packages/net_addr/net_addr/click_types.py` — every Click `ParamType`
  subclass.
- `packages/net_addr/net_addr/errors.py` — the canonical error-class
  hierarchy.

These files are the canonical examples. Any deviation from
this rule should be justified by something that appears in
one of them — not by a novel pattern introduced in a new
file.

## 11. Cross-references

- [`source_files.md`](source_files.md) — general source-file
  conventions (file skeleton, copyright block, imports,
  naming, formatting). Apply identically to `packages/net_addr/net_addr/`.
- [`net_proto.md`](net_proto.md) — the per-protocol six-file
  pattern for `packages/net_proto/net_proto/protocols/<proto>/`. Consumes
  `packages/net_addr/net_addr/` value types in header dataclasses.
- [`pytcp.md`](pytcp.md) — the runtime services in `packages/pytcp/pytcp/`.
  Consumes `packages/net_addr/net_addr/` value types for stack configuration
  and runtime address bookkeeping.
- [`python_features.md`](python_features.md) — modern
  Python features (PEP 604 / 585 / 695) used by `packages/net_addr/net_addr/`.
- [`typing.md`](typing.md) — annotation discipline; `Self`,
  PEP 695 generics on `IpNetwork[A, M]` / `IfAddr[A, N]`,
  ABC + `@override` patterns.
- [`unit_testing.md`](unit_testing.md) §3 — the
  `packages/net_addr/net_addr/tests/unit/` test layout and the value-type
  parameterised-matrix pattern.
- [`integration_testing.md`](integration_testing.md) —
  integration tests rarely exercise `packages/net_addr/net_addr/` directly
  (value types are stateless), but the test harness still
  imports `Ip4Address` / `Ip6Address` / `MacAddress`
  fixtures from `packages/net_addr/net_addr/`.
- [`feature_implementation.md`](feature_implementation.md)
  — tests-first workflow.
