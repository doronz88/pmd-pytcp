# PyTCP — Enum-Discipline Rule

This rule codifies how PyTCP represents **enumerated
values** — protocol codepoints, socket-option numbers,
flag bits, well-known kinds, message types, etc. The
short version: a value that is one of a closed (or
extensible) set of categorical alternatives lives as a
member of an `Enum` / `IntEnum` / `ProtoEnum` subclass.
Bare module-level `int` constants representing
enumerated values are **forbidden** — except where they
exist to mirror Python's standard library `socket`
module surface, in which case they are bare module-level
**aliases for `IntEnum` members**, never standalone
integers.

The rule is normative. `make lint` (mypy strict)
catches a large class of violations mechanically when
parameter / return / dataclass-field types use the
proper enum class. A reviewer is entitled to bounce a
PR that introduces a bare `FOO: int = N` constant
representing an enumerated value.

The companion rules
[`python_features.md`](python_features.md),
[`typing.md`](typing.md), [`source_files.md`](source_files.md),
[`net_proto.md`](net_proto.md) and
[`pytcp.md`](pytcp.md) sit alongside this one — they
reference back when their own surface needs an
enumerated value.

---

## 1. The two questions

When you have a constant `N`, ask:

1. **Is `N` one of a set?** Could it be replaced by some
   other value `M` that represents a different choice in
   the same domain (different ICMP type, different socket
   option, different flag bit, different shutdown mode)?
2. **Is the set named?** Does the domain have a name —
   `Icmp4Type`, `IpOption`, `MsgFlag`, `SoEeOrigin`, etc.?

If both answers are yes, `N` is an enum member, not a
bare int. The enum is the canonical home; the int is the
implementation detail.

If `N` is a sentinel value (e.g. `MAX_BACKOFF_MS`,
`UDP__HEADER__LEN`, `INADDR_BROADCAST` mask), it's a
scalar — leave it as a bare int.

## 2. The two acceptable forms

### 2.1 Internal enumerated value — enum-only, no bare alias

Used for PyTCP-internal categorical values that have no
Python stdlib equivalent.

```python
# Good
from enum import IntEnum

class SoEeOrigin(IntEnum):
    """sock_extended_err.ee_origin values (linux/errqueue.h)."""
    NONE = 0
    LOCAL = 1
    ICMP = 2
    ICMP6 = 3
    TXSTATUS = 4
    ZEROCOPY = 5
    TXTIME = 6
```

Call-site access:

```python
# Good
entry = ErrorQueueEntry(origin=SoEeOrigin.ICMP, ...)
if entry.origin is SoEeOrigin.ICMP6:
    ...
```

**Forbidden — bare module-level aliases** for the enum
members, since they double the namespace surface without
matching any external (Linux / stdlib) convention:

```python
# Forbidden
SO_EE_ORIGIN_ICMP = SoEeOrigin.ICMP   # No stdlib counterpart — drop the alias.
SO_EE_ORIGIN_ICMP6 = SoEeOrigin.ICMP6
```

### 2.2 Stdlib-parity public API — IntEnum + bare module-level aliases

Used for constants that Python's stdlib `socket` module
exposes as bare module-level names. PyTCP MUST expose
the same bare names with the same integer values so a
program written for stdlib `socket` runs **unchanged**
against PyTCP.

```python
# Good
class IpOption(IntEnum):
    """IPPROTO_IP-level setsockopt optname values (Linux
    numbers from <netinet/ip.h>; matches stdlib socket.IP_*)."""
    IP_TOS = 1
    IP_TTL = 2
    IP_OPTIONS = 4
    IP_RECVOPTS = 6
    IP_RECVERR = 11
    # ...

# Bare module-level aliases — match Python stdlib socket
# module surface so 'from pytcp.socket import IP_RECVERR'
# works exactly like 'from socket import IP_RECVERR'.
IP_TOS = IpOption.IP_TOS
IP_TTL = IpOption.IP_TTL
IP_OPTIONS = IpOption.IP_OPTIONS
IP_RECVOPTS = IpOption.IP_RECVOPTS
IP_RECVERR = IpOption.IP_RECVERR
```

The aliases are **`IntEnum` members**, not standalone
integers — `IP_RECVERR is IpOption.IP_RECVERR` evaluates
True, `int(IP_RECVERR) == 11`. Pythonic equality
(`==`) still works against bare ints
(`IP_RECVERR == 11 is True`).

**Forbidden — standalone bare int aliases:**

```python
# Forbidden
IP_TOS: int = 1
IP_TTL: int = 2
IP_OPTIONS: int = 4
IP_RECVERR: int = 11
```

These are forbidden because they fail the §1 test —
they enumerate a domain with no backing enum. Future
code can't type a parameter as `IpOption` and have mypy
catch a wrong-domain int sneaking in (`SO_REUSEADDR=2`
would silently match `IP_TTL=2` if both are bare ints).

### 2.3 Protocol wire enum — already a ProtoEnum, no bare alias

Used for protocol wire codepoints under `packages/net_proto/net_proto/`.
`ProtoEnum` is the existing PyTCP base (subclasses the
stdlib `enum.Enum` with `from_int` / `from_bytes` machinery
and a native `_missing_` hook for unknown wire codepoints).
Members are accessed via enum-member syntax; no bare
module-level aliases.

```python
# Good
from net_proto import Icmp4Type, IpProto

match packet_rx.icmp4.message.type:
    case Icmp4Type.DESTINATION_UNREACHABLE: ...
    case Icmp4Type.TIME_EXCEEDED: ...

if proto is IpProto.UDP: ...
```

The full inventory:
[`net_proto.md`](net_proto.md) §11.

## 3. Stdlib socket parity — the load-bearing constraint

PyTCP's `pytcp.socket` module is a drop-in replacement
for Python stdlib `socket`. A program written like:

```python
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVERR, 1)
data, ancdata, flags, addr = sock.recvmsg(4096, 256, socket.MSG_ERRQUEUE)
```

MUST run **unchanged** against PyTCP by simply
substituting `import socket` with `from pytcp import
socket`. This means:

- Every constant `socket.X` that the program references
  MUST exist as `pytcp.socket.X` with the **same integer
  value** as Linux.
- The constant MAY be backed by an `IntEnum` member —
  `IntEnum` is a subclass of `int`, so `sock.setsockopt(
  IPPROTO_IP, IpOption.IP_RECVERR, 1)` and
  `sock.setsockopt(IPPROTO_IP, 11, 1)` produce identical
  behavior.
- A consumer doing `flags & socket.MSG_ERRQUEUE` works
  because `MsgFlag.MSG_ERRQUEUE & 0x2000 == 0x2000` via
  `IntEnum`'s int inheritance.

The audit when adding a new public-API constant:

1. **Does Python stdlib `socket` expose this constant
   with this exact name on Linux?** Check via
   `python3 -c "import socket; print(socket.X)"`.
2. **If yes** — define the IntEnum group it belongs to
   (creating it if needed), add the member, re-export
   as a bare module-level name (§2.2).
3. **If no** — the constant is PyTCP-internal. Add it
   as an enum member without a bare alias (§2.1).

## 4. Forbidden patterns roundup

| Anti-pattern | Replace with | § |
|---|---|---|
| `FOO: int = N` at module scope, where FOO is one of a set | IntEnum class + bare alias (§2.2) or enum member only (§2.1) | §2 |
| `FOO = SomeEnum.X` at module scope, no stdlib counterpart | Drop the alias; use `SomeEnum.X` directly | §2.1 |
| `if value == 2:` where 2 is `SoEeOrigin.ICMP` | `if value is SoEeOrigin.ICMP:` (or `==` for non-Enum / IntEnum mixes) | §2 |
| Function parameter `: int` that accepts one of a set | `: SomeEnum` for type-safety; `: SomeEnum \| int` if both forms must be accepted | §2 |
| `int(SomeEnum.X)` cast at call site to "convert" to int | Drop the cast — IntEnum is-int already; the receiver's `: int` annotation accepts it | §2.2 |
| Different IntEnum members sharing the same value within one enum class | Move shared values into separate enum classes; never alias (Python silently aliases IntEnum members with same value, hiding intent) | §2 |

## 5. Migration policy

This rule applies retroactively to existing code that
fails it. Touch-time rule:

- When you touch a file that contains a bare
  `FOO: int = N` matching §1's "enumerated value" test,
  fix it in the same commit. Don't file a follow-up
  "convert bare ints" task; fix on touch.
- The §10b "modernise on touch" pattern from
  [`feature_implementation.md`](feature_implementation.md)
  §4 applies here too.

When the conversion is non-trivial (the enum class
doesn't exist yet, the new class crosses module
boundaries), pause and ask before committing — the
conversion is small enough to fit in the same commit
in most cases.

## 6. When the constant IS just a scalar

The rule applies to **enumerated** values. Pure scalars
remain bare ints — naming an enum for them adds
noise without type-safety value:

- **Lengths / sizes**: `UDP__HEADER__LEN = 8`,
  `ERROR_QUEUE__MAX_LEN = 32`, `IP4__OPTIONS__MAX_LEN = 40`.
- **Timeouts in seconds / ms**:
  `ARP_CACHE__ENTRY_MAX_AGE = 60`,
  `SUBSYSTEM_SLEEP_TIME__SEC = 0.1`.
- **Counts / retry limits**: `STACK__MAX_RETRIES = 3`.
- **Sentinel address ints exposed by stdlib socket**:
  `INADDR_ANY = 0`, `INADDR_BROADCAST = 0xFFFFFFFF`
  (these are values an `Ip4Address` could take, not
  values out of a closed set of named alternatives —
  they happen to be exposed by stdlib socket as bare
  ints for historical reasons).

**Heuristic test for §1:**

- If swapping `N` for `M` would change the meaning to a
  named alternative (`IP_TTL → IP_TOS`), it's an enum.
- If swapping `N` for `M` would just change a quantity
  (`60 → 90` seconds), it's a scalar.

## 7. Examples from the existing PyTCP codebase

### 7.1 Existing enums that follow this rule

| Enum class | Module | Style |
|---|---|---|
| `Icmp4Type`, `Icmp6Type` | `packages/net_proto/net_proto/protocols/icmp{4,6}/message/icmp{4,6}__message.py` | `ProtoEnum`; member access only |
| `IpProto` | `packages/net_proto/net_proto/lib/enums.py` | `ProtoEnum`; member access only |
| `EtherType` | `packages/net_proto/net_proto/protocols/ethernet/ethernet__enums.py` | `ProtoEnum`; member access only |
| `ArpHardwareType`, `ArpOperation` | `packages/net_proto/net_proto/protocols/arp/arp__enums.py` | `ProtoEnum`; member access only |
| `IpVersion` | `packages/net_addr/net_addr/ip_version.py` | `IntEnum`; member access only |
| `AddressFamily`, `SocketType` | `packages/pytcp/pytcp/socket/__init__.py` | `NameEnum`; member access only (stdlib parity is the `AF_INET = AddressFamily.INET4` family) |
| `SocketOption` (TCP_*) | `packages/pytcp/pytcp/socket/__init__.py` | IntEnum + bare aliases (§2.2 — stdlib parity) |
| `SolSocketOption` (SO_*) | `packages/pytcp/pytcp/socket/__init__.py` | IntEnum + bare aliases (§2.2 — stdlib parity) |
| `IpOption` (IP_*) | `packages/pytcp/pytcp/socket/__init__.py` | IntEnum + bare aliases (§2.2 — stdlib parity) |
| `IpV6Option` (IPV6_*) | `packages/pytcp/pytcp/socket/__init__.py` | IntEnum + bare aliases (§2.2 — stdlib parity) |
| `MsgFlag` (MSG_*) | `packages/pytcp/pytcp/socket/__init__.py` | IntEnum + bare aliases (§2.2 — stdlib parity) |
| `SoEeOrigin` | `packages/pytcp/pytcp/socket/error_queue.py` | IntEnum, member access only (§2.1 — not in stdlib socket) |

### 7.2 Existing bare ints that are scalars (correctly NOT enums)

| Constant | Module | Why scalar |
|---|---|---|
| `UDP__HEADER__LEN = 8` | `packages/net_proto/net_proto/protocols/udp/udp__header.py` | byte length |
| `ARP_CACHE__ENTRY_MAX_AGE__SEC = 60` | `packages/pytcp/pytcp/protocols/arp/arp__constants.py` | timeout |
| `ERROR_QUEUE__MAX_LEN = 32` | `packages/pytcp/pytcp/socket/error_queue.py` | capacity |
| `INADDR_ANY = 0` | `packages/pytcp/pytcp/socket/__init__.py` | sentinel address (stdlib-mirrored) |
| `IPPROTO_IP = 0` | `packages/pytcp/pytcp/socket/__init__.py` | default-protocol sentinel (stdlib-mirrored; conceptually NOT an `IpProto` value because IANA next-header 0 is HOPOPT) |
| `SOL_SOCKET = 1` | `packages/pytcp/pytcp/socket/__init__.py` | setsockopt level sentinel; only one value in this "domain" today, so no enum |

`IPPROTO_IP` and `SOL_SOCKET` are borderline — they're
each effectively single-value "domains" today
(`SOL_SOCKET` is the only socket-level level value;
`IPPROTO_IP` is the only "default protocol" sentinel).
If/when PyTCP adds a second value in either domain
(e.g. `SOL_PACKET`), promote to an enum on touch.

## 8. The mypy strict story

Once a parameter, dataclass field, or return type is
annotated with the enum class, mypy strict catches
wrong-domain integers passed in:

```python
# Good — strict typing
def notify_unreachable(
    self,
    *,
    icmp_origin: SoEeOrigin = SoEeOrigin.NONE,
    icmp_type: ProtoEnum | int = 0,
    ...
) -> None: ...

# Caller — type-checked
sock.notify_unreachable(
    icmp_origin=SoEeOrigin.ICMP,
    icmp_type=Icmp4Type.DESTINATION_UNREACHABLE,
    icmp_code=Icmp4DestinationUnreachableCode.PORT,
    ...
)
```

A caller that passes `icmp_origin=2` (bare int) still
compiles because `int` is a structural superset, but
mypy strict can catch the case where the parameter is
typed as the enum and a non-`SoEeOrigin` int sneaks in.

The `ProtoEnum | int` union on `icmp_type` / `icmp_code`
is the **migration pattern**: accept both the enum and
the int form, so RX-path callers reading the value
back from a parsed cmsg (where it's already an int)
don't need to round-trip through the enum.

## 9. Cross-references

- [`python_features.md`](python_features.md) — Python
  3.10–3.14 language features; `match`/`case` over enums
  is mandatory (§4) and uses the patterns this rule
  pins.
- [`typing.md`](typing.md) — mypy strict; this rule's
  enforcement gate runs through it.
- [`net_proto.md`](net_proto.md) §11 — the
  `ProtoEnumByte` / `ProtoEnumWord` family used by every
  protocol wire enum.
- [`source_files.md`](source_files.md) §7 — general
  naming convention (`ALL_CAPS` for constants applies
  to the bare aliases in §2.2).
- [`pytcp.md`](pytcp.md) — `packages/pytcp/pytcp/socket/` is where the
  bulk of the stdlib-parity bare-alias surface lives.
- Linux numeric reference: `/usr/include/linux/in.h`,
  `/usr/include/linux/in6.h`, `/usr/include/linux/errqueue.h`,
  `/usr/include/sys/socket.h`. Cross-check stdlib via
  `python3 -c "import socket; print(socket.IP_RECVERR)"`.
