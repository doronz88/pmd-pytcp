# PyTCP-net_addr

An alternative to Python's standard-library `ipaddress` module —
originally built for the [PyTCP](https://github.com/ccie18643/PyTCP)
TCP/IP stack, fully usable on its own.

```python
from net_addr import Ip6Address, Ip4Network, MacAddress

Ip6Address("2001:db8::1").is_global                 # True
Ip4Network("10.0.0.0/24")[10]                       # Ip4Address("10.0.0.10")
MacAddress("02:00:00:00:00:07").is_multicast        # False
Ip4Address("10.0.0.1") in Ip4Network("10.0.0.0/8")  # True
```

## Why

A correct, immutable, strict-parsing address library with no runtime
dependencies and a single clean exception tree — suitable for protocol
stacks, network tooling, and anywhere `ipaddress` is too loose or does
not give you hashable / orderable / MAC / wildcard / interface-address
value types.

## Features

- **Value types** — `Ip4Address`, `Ip6Address`, `MacAddress`,
  `Ip4Network` / `Ip6Network`, `Ip4Mask` / `Ip6Mask`,
  `Ip4Wildcard` / `Ip6Wildcard` (ACL / firewall, non-contiguous),
  `Ip4IfAddr` / `Ip6IfAddr`.
- **Immutable & efficient** — `__slots__`, hashable, totally
  ordered, `@final` leaves; equality never crosses address families.
- **Multi-form constructors** — string, integer,
  `bytes` / `bytearray` / `memoryview`, copy, or unspecified, via one
  positional argument.
- **Strict parsing** — POSIX `inet_pton` only; legacy octal / hex /
  short-form leniencies and hybrid MAC separators are rejected.
- **RFC-accurate classification** — global / private / link-local /
  loopback / multicast / documentation / reserved; RFC 4007 IPv6
  zone identifiers; IPv4-mapped, 6to4 and Teredo extraction.
- **CIDR arithmetic** — `subnets()`, `supernet()`,
  `address_exclude()`, `hosts()`, RFC 4632 `summarize()`,
  containment and overlap.
- **IPv6 interface-identifier generators** — EUI-64, RFC 7217
  stable-privacy, RFC 8981 temporary; solicited-node multicast and
  multicast-MAC mapping.
- **Rich formatting** — expanded form, MAC hyphen / Cisco notations,
  zero-padded radix, reverse-DNS PTR names.
- **One exception tree** — every failure is a `NetAddrError`
  subclass; never a bare builtin.
- **Fully typed** — ships `py.typed` (PEP 561); strict-mypy clean.

## Installation

```bash
pip install PyTCP-net_addr
```

Stdlib-only. The optional Click argument types are an extra:

```bash
pip install "PyTCP-net_addr[cli]"   # adds click; exposes the net_addr ClickType* params
```

## Requirements

Python **3.14+** (the library uses PEP 695 generics and modern
typing).

## License

GPL-3.0-or-later. Part of the PyTCP project by Sebastian Majewski.
