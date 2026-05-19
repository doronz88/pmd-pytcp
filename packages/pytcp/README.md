# PyTCP

Pure-Python, zero-dependency TCP/IP stack — Ethernet through
RFC 9293 TCP — running in user space on a TAP/TUN interface, with
a Berkeley-sockets API.

```python
from pytcp import socket, stack
```

## What it is

A full, RFC-grounded TCP/IP stack implemented entirely in Python:
Ethernet II / 802.3, ARP, IPv4 / IPv6 (with extension headers),
ICMPv4 / ICMPv6 (incl. Neighbor Discovery, MLDv2), UDP, and a
RFC 9293 TCP with a real FSM, congestion control, and a
BSD-sockets facade. It runs on a TAP/TUN interface in user space —
no kernel module, no privileged data path.

## Architecture

The stack is split into three independently-published,
strictly-layered distributions:

| Distribution | Import | Role |
|---|---|---|
| [`PyTCP-net_addr`](https://pypi.org/project/PyTCP-net_addr/) | `net_addr` | Address value types (IPv4/IPv6/MAC, networks, masks). |
| [`PyTCP-net_proto`](https://pypi.org/project/PyTCP-net_proto/) | `net_proto` | Protocol packet parse / assemble / validate. |
| **`PyTCP`** | `pytcp` | The running stack: threads, sockets, ARP/ND caches, RX/TX rings. |

Installing `PyTCP` pulls the other two automatically (lockstep
version pin).

## Install

```bash
pip install PyTCP
```

Brings in `PyTCP-net_proto` and `PyTCP-net_addr` (and `aenum`).
Fully typed (ships `py.typed`, PEP 561).

## Requirements

Python **3.14+**, Linux (TAP/TUN), POSIX. Running the stack
needs a TAP/TUN interface (root for interface/bridge setup).

## License

GPL-3.0-or-later. PyTCP by Sebastian Majewski.
