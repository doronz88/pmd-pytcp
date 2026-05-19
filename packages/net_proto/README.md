# PyTCP-net_proto

The network-protocol packet **parse / assemble / validate** layer of
the [PyTCP](https://github.com/ccie18643/PyTCP) TCP/IP stack —
extracted as its own distribution and usable on its own.

```python
from net_proto import IpProto
from net_proto.protocols.udp.udp__parser import UdpParser
```

## Why

Strict, RFC-grounded, fully-typed wire-format codecs for the
common Internet protocols, with a single clean validation-error
tree and no runtime dependencies beyond the address library it is
built on.

## Coverage

Ethernet II / 802.3 (LLC/SNAP), ARP, IPv4 (+ options), IPv6
(+ Hop-by-Hop / Destination-Options / Routing / Fragment
extension headers), ICMPv4, ICMPv6 (incl. ND, MLDv2), TCP
(+ options), UDP, DHCPv4 — each as a parser / assembler pair with
header dataclasses, integrity + sanity validation, and typed
protocol enums.

## Install

```bash
pip install PyTCP-net_proto
```

Depends only on `PyTCP-net_addr` (the address value-type library)
and `aenum`. Fully typed (ships `py.typed`, PEP 561).

## Requirements

Python **3.14+**.

## License

GPL-3.0-or-later. Part of the PyTCP project by Sebastian Majewski.
