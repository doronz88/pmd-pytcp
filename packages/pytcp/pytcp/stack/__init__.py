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


"""
This package contains the stack components and global structures.

pytcp/stack/__init__.py

ver 3.0.6
"""

from __future__ import annotations

import fcntl
import os
import secrets
import struct
import sys
from enum import IntFlag
from typing import TYPE_CHECKING, Any

from net_addr import MacAddress
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.logger import log
from pytcp.protocols.arp.arp__cache import ArpCache
from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4Client
from pytcp.protocols.icmp6.nd.nd__cache import NdCache
from pytcp.protocols.icmp.icmp__error_emitter import IcmpErrorRateLimiter
from pytcp.protocols.tcp.tcp__stack import TcpStack
from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3
from pytcp.runtime.rx_ring import RxRing
from pytcp.runtime.timer import Timer
from pytcp.runtime.tx_ring import TxRing
from pytcp.socket.socket_table import SocketTable
from pytcp.stack.address import Ip4AddressApi
from pytcp.stack.link import LinkApi
from pytcp.stack.route import RouteApi

if TYPE_CHECKING:
    from net_addr import Ip4Address, Ip4Network, Ip6Address, Ip6Network
    from pytcp.lib.plpmtud import PmtuSearch
    from pytcp.protocols.ip4.link_local.link_local__client import Ip4LinkLocal
    from pytcp.runtime.fib import RouteTable


assert sys.version_info >= (
    3,
    12,
), "PyTCP stack requires Python version 3.12 or higher to run."


# TUN/TAP ioctl request number (Linux <linux/if_tun.h>);
# single value, no enum domain.
TUNSETIFF = 0x400454CA


class TunTapFlag(IntFlag):
    """
    TUN/TAP interface flags passed in the 'ifr_flags' field of
    the 'TUNSETIFF' ioctl. Linux numbers from
    '<linux/if_tun.h>'. 'IFF_TUN' and 'IFF_TAP' are mutually
    exclusive (interface type); 'IFF_NO_PI' is a separate
    modifier flag, OR'd in to suppress the 4-byte packet-info
    header on RX/TX.
    """

    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000


# Bare module-level aliases — IFF_* are commonly referenced
# directly (mirroring how C code uses '#define IFF_TUN'), and
# the test fixture imports them as 'stack.IFF_TUN'.
IFF_TUN = TunTapFlag.IFF_TUN
IFF_TAP = TunTapFlag.IFF_TAP
IFF_NO_PI = TunTapFlag.IFF_NO_PI

# PyTCP code metadata.
PYTCP_VERSION = "ver 3.0.6"
GITHUB_REPO = "https://github.com/ccie18643/PyTCP"

# RFC 6528 §3 Initial Sequence Number secret. Generated once at
# module import via 'secrets.token_bytes(16)' so each PyTCP stack
# process has a fresh 128-bit keying value for the TCP ISN hash.
# 'pytcp.protocols.tcp.tcp__iss.compute_iss' reads this when TcpSession picks
# its initial sequence number; the secret never leaves the process
# and is regenerated on restart, so attackers who learn one ISN
# cannot infer ISNs for any other 4-tuple or for any future
# stack-process lifetime.
TCP__ISS_SECRET: bytes = secrets.token_bytes(16)

# RFC 6437 §3 IPv6 Flow Label generation secret. Generated
# once at module import via 'secrets.token_bytes(16)' so each
# PyTCP stack process picks a fresh 128-bit keying value for
# the per-(src, dst) flow-label hash. 'pytcp.protocols.ip6.ip6__flow_label.compute_ip6_flow_label'
# reads this when the IPv6 TX path needs a flow label (and
# the caller did not supply one explicitly). Same allocation
# pattern as 'TCP__ISS_SECRET' / 'TCP__FASTOPEN_SECRET'; the
# secret never leaves the process.
IP6__FLOW_SECRET: bytes = secrets.token_bytes(16)

# RFC 7413 TCP Fast Open server-side cookie generation
# secret. Same allocation pattern as 'TCP__ISS_SECRET':
# generated at module import time via 'secrets.token_bytes(16)'
# so each PyTCP stack process has a fresh 128-bit keying
# value for the TFO cookie HMAC. Implementations MAY rotate
# the secret to invalidate outstanding cookies; PyTCP keeps
# it stable for the process lifetime.
TCP__FASTOPEN_SECRET: bytes = secrets.token_bytes(16)

# RFC 6056 §3.3.3 Algorithm 3 port-selection secret. Used
# by 'pytcp.socket.socket__bind_helpers.pick_local_port_for' to compute
# a per-(local_ip, remote_ip, remote_port) BLAKE2s-keyed
# offset into 'EPHEMERAL_PORT_RANGE' so the source port
# for a TCP connect() is unpredictable to an off-path
# attacker AND independent of the source ports chosen for
# connections to other destinations (the §3.3.3
# per-destination subspace property). Same allocation
# pattern as 'TCP__ISS_SECRET' / 'TCP__FASTOPEN_SECRET' /
# 'IP6__FLOW_SECRET': 128 bits at module import, never
# persisted, regenerated on process restart.
TCP__PORT_SECRET: bytes = secrets.token_bytes(16)

# Mutable TCP-stack-level state (TFO cookie cache + negative
# cache + pending-request counter). Aggregated under one
# 'TcpStack' instance so test fixtures snapshot+restore one
# object instead of three separate fields, and a future new
# field is automatically covered by the existing reset path.
tcp_stack: TcpStack = TcpStack()

# RFC 7413 §3.1 cookie cache size cap. Bounds the per-process
# memory footprint of the TFO cookie cache for long-running
# clients that connect to many distinct servers. The default
# 1024 matches Linux's 'tcp_fastopen_blackhole_timeout_sec'
# era choice for cache size; entries are evicted in FIFO
# order (oldest first) when an insert would push the cache
# past the cap. Adjustable per process via direct assignment;
# tests patch this to small values to exercise the eviction
# path deterministically.
TCP__FASTOPEN_CACHE_MAX_SIZE: int = 1024

# Interface configuration.
INTERFACE__TAP__MTU = 1500
INTERFACE__TUN__MTU = 1500

# Addresses configuration.
MAC_ADDRESS: str = "02:00:00:{x}{x}:{x}{x}:{x}{x}"
IP4_ADDRESS = None
IP4_GATEWAY = None
IP6_ADDRESS = None
IP6_GATEWAY = None

# Protocol support configuration.
IP6__SUPPORT = True
IP4__SUPPORT = True

# Whether the stack accepts inbound IPv4 packets carrying LSRR or
# SSRR source-route options (RFC 791 §3.1, types 131 / 137).
# Default False matches Linux's 'net.ipv4.conf.*.accept_source_route'
# default since the early 2000s — source-routed packets are dropped
# at the IPv4 RX gate. Operators that genuinely need source-route
# acceptance set this to True.
IP4__ACCEPT_SOURCE_ROUTE = False

# ARP runtime configuration constants live alongside the ARP
# protocol code at 'pytcp/protocols/arp/arp__constants.py'.
# Importers should refer to that module directly rather than
# reaching through 'pytcp.stack'.

# ICMPv6 ND cache aging timers moved to the generic NUD
# framework at 'pytcp/lib/neighbor__constants.py' alongside
# their IPv4 ARP counterparts. The 'NdCache' is now a thin
# adapter on 'NeighborCache[Ip6Address]' that reads
# 'neighbor.reachable_time' / 'neighbor.retrans_timer' / etc.
# Operators tune these via 'pytcp.stack.sysctl["neighbor.X"]'
# or the 'sysctls={"neighbor.X": ...}' bag kwarg on
# 'stack.init()'.

# IPv4 and IPv6 fragmnt flow expiration time, determines for how many seconds
# IP fragment flow is considered valid. Fragemnt flows are being cleaned up prior
# of handling every fragmented packet.
IP4__FRAG_FLOW_TIMEOUT = 5
IP6__FRAG_FLOW_TIMEOUT = 5

# Native support for UDP Echo (used for packet flow unit testing only
# and should always be disabled).
UDP__ECHO_NATIVE = False

# RFC 6056 §3.2 ephemeral port range. Matches the Linux
# default ('net.ipv4.ip_local_port_range = 32768 60999')
# so PyTCP picks from a 28,232-port pool — well above the
# 16,384-port floor RFC 6056 §3.2 mentions for the IANA
# dynamic range, and large enough to give the §3.1
# obfuscation SHOULD meaningful guessing-space against an
# off-path attacker. Step=1 (every port is a candidate);
# the historical step=2 even-only restriction is gone.
EPHEMERAL_PORT_RANGE = range(32768, 61000)

# Logger configuration - LOG__CHANNEL sets which subsystems of stack log to the
# console, LOG__DEBUG adds info about class/method caller.
# Following subsystems are supported:
# stack, timer, rx-ring, tx-ring, arp-c, nd-c, ether, arp, ip4, ip6, icmp4,
# icmp6, udp, tcp, socket, tcp-ss, service.
LOG__CHANNEL = {
    "stack",
    # "timer",
    "rx-ring",
    "tx-ring",
    "arp-c",
    "nd-c",
    "ether",
    "arp",
    "ip4",
    "ip6",
    "icmp4",
    "icmp6",
    "udp",
    "tcp",
    "socket",
    "tcp-ss",
    "dhcp4",
    "service",
    "client",
}
LOG__DEBUG = False
LOG__OUTPUT = sys.stderr

# Stack subsystems.
timer: Timer
rx_ring: RxRing
tx_ring: TxRing
arp_cache: ArpCache
nd_cache: NdCache
packet_handler: PacketHandlerL2 | PacketHandlerL3
# Phase 2 of the multi-interface migration: the per-ifindex
# interface registry. Linux keys interfaces (and their ARP / ND
# caches, addresses, MTU) per ifindex; PyTCP's 'PacketHandler'
# instance IS the per-interface object, so the registry maps
# 'ifindex -> handler'. Today the stack is single-interface, so
# the registry holds exactly one entry at 'STACK__DEFAULT_IFINDEX'
# and 'packet_handler' above is that sole interface. Rebuilt fresh
# by 'init()' / 'mock__init()' (same reconstruct-per-test
# lifecycle as 'packet_handler' / 'route', so it needs no
# snapshot/restore). Phase 6 makes 'packet_handler' a shim over
# this registry once N>1 interfaces are supported.
STACK__DEFAULT_IFINDEX: int = 1
interfaces: dict[int, PacketHandlerL2 | PacketHandlerL3] = {}
# Phase 4 commit A — IPv4 address-control API, the kernel/userspace
# boundary surface consumed by the DHCPv4 client and (eventually)
# operator-config CLI tools. Mirrors Linux RTNETLINK 'RTM_NEWADDR'
# / 'RTM_DELADDR' semantics. Set in 'init()' / 'mock__init()' after
# 'packet_handler' is constructed.
address: Ip4AddressApi
# Link API Phase 0 — link-control surface (MAC, MTU, interface
# layer; mutation lands in Phase 4). Mirrors Linux 'ip link' /
# RTNETLINK 'RTM_GETLINK' / 'RTM_NEWLINK'. Constructed by 'init()'
# / 'mock__init()' alongside 'address'. Replaces the
# 'packet_handler._mac_unicast' reach-through used by DHCP and
# RFC 3927 link-local construction. See
# 'docs/refactor/link_api.md' for the full plan.
link: LinkApi
# Host-mode routing table (FIB) — Phase 1 of
# 'docs/refactor/routing_table_host_mode.md'. One per address
# family. Reconstructed fresh by 'init()' / 'mock__init()'
# (same lifecycle as 'timer' / 'address' / 'link'), so they do
# not leak across the test suite and need no snapshot/restore.
# Phase 1 is inert: the FIBs are populated by the boot
# dual-write but nothing reads them yet — the Ethernet-TX
# next-hop rewrite that consumes 'lookup()' lands in Phase 2.
ip4_fib: RouteTable[Ip4Address, Ip4Network]
ip6_fib: RouteTable[Ip6Address, Ip6Network]
# Route API Phase 1 — read-only routing-control surface over
# the two FIBs. Mirrors Linux 'ip route show' / RTNETLINK
# 'RTM_GETROUTE'. Mutation lands in Phase 3. Constructed by
# 'init()' / 'mock__init()' alongside 'address' / 'link'. See
# 'docs/refactor/routing_table_host_mode.md' for the full plan.
route: RouteApi
# Phase 4 commit B — DHCPv4 client subsystem. Constructed by
# 'init()' iff 'ip4_dhcp=True' on an L2 interface; spawned as a
# background thread by 'start()'; joined by 'stop()'. None on L3
# (TUN, no MAC) or when DHCP is disabled.
dhcp4_client: Dhcp4Client | None = None
# RFC 3927 §2 IPv4 Link-Local autoconfig client subsystem. Phase
# 1 lands the slot only — the subsystem is not yet instantiated
# by 'init()'. The DHCP-fallback wiring lands in Phase 4 of the
# RFC 3927 track (docs/refactor/rfc3927_link_local_autoconfig.md).
link_local: "Ip4LinkLocal | None" = None

# Stack shared data.
stack_initialized: bool = False
# Link API Phase 2 — admin-up / running flag. True once
# 'start()' has spawned every subsystem thread; False after
# 'stop()' has signalled them to wind down. Linux's
# IFF_UP + IFF_RUNNING equivalent (PyTCP collapses the two
# because per-subsystem-up granularity has no consumer
# today). Snapshotted/restored by 'NetworkTestCase' per
# test so the flag does not leak across the integration
# suite.
stack_running: bool = False
interface_mtu: int
sockets: SocketTable = SocketTable()
# RFC 1191 §3 / RFC 8201 §4 per-destination Path-MTU cache. Keyed
# by remote IP (v4 or v6); value is the most recently learned next-
# hop MTU. Populated by ICMP Frag-Needed / Packet-Too-Big handlers
# in Phases 4-6 of the ICMP demux + PMTUD refactor; consulted by
# UDP and TCP TX paths for fragment-or-fail / MSS-recompute
# decisions. Process-lifetime only — entries do not expire.
# Legacy scalar view; new consumers should call 'current_pmtu(dst)'
# below which prefers 'pmtu_state' when present.
pmtu_cache: dict[Ip4Address | Ip6Address, int] = {}

# RFC 4821 / RFC 8899 per-destination PLPMTUD engine state. Each
# entry is a PmtuSearch instance whose state machine
# (BASE / SEARCHING / SEARCH_COMPLETE / ERROR) the per-transport
# adapter drives. Phase 2 of the PLPMTUD plan
# (docs/refactor/plpmtud_unified_engine.md) introduces this dict
# alongside the legacy 'pmtu_cache' above; subsequent phases wire
# the TCP and UDP adapters that mutate it via PmtuSearch's public
# API ('on_probe_ack' / 'on_probe_loss' / 'on_classical_pmtu' /
# 'next_probe_size' / 'confirm_current').
pmtu_state: dict[Ip4Address | Ip6Address, PmtuSearch[Ip4Address] | PmtuSearch[Ip6Address]] = {}


def current_pmtu(dst: Ip4Address | Ip6Address, /) -> int | None:
    """
    Return the current PLPMTU for 'dst', preferring the active
    PLPMTUD engine state ('pmtu_state') over the legacy
    classical-PMTUD scalar cache ('pmtu_cache'). Returns None
    when no signal has been observed for the destination — the
    caller should fall back to 'stack.interface_mtu'.
    """

    engine = pmtu_state.get(dst)
    if engine is not None:
        return engine.current_mtu
    return pmtu_cache.get(dst)


# RFC 1812 §4.3.2.8 / RFC 4443 §2.4(f) outbound ICMP error rate
# limiters. One per L3 version so a flood of v4 errors cannot
# starve legitimate v6 error generation (and vice versa). Consumed
# by every ICMP error generator via try_emit_icmp_error().
icmp4_error_rate_limiter: IcmpErrorRateLimiter = IcmpErrorRateLimiter()
icmp6_error_rate_limiter: IcmpErrorRateLimiter = IcmpErrorRateLimiter()


def initialize_interface__tap(interface_name: str, *, mac_address: MacAddress | None = None) -> dict[str, Any]:
    """
    Initialize the TAP interface.
    """

    log("stack", f"Initializing TAP interface: {interface_name}")

    if mac_address is None:
        mac_address = MacAddress(MAC_ADDRESS.format(x=interface_name[3:5]))

    log("stack", f"Assigning MAC address: {mac_address}")

    try:
        fd = os.open("/dev/net/tun", os.O_RDWR)

    except FileNotFoundError:
        log("stack", "<CRIT>Unable to access '/dev/net/tun' device</>")
        sys.exit(-1)

    fcntl.ioctl(
        fd,
        TUNSETIFF,
        struct.pack("16sH", interface_name.encode(), IFF_TAP | IFF_NO_PI),
    )

    return {
        "fd": fd,
        "layer": InterfaceLayer.L2,
        "mtu": INTERFACE__TAP__MTU,
        "mac_address": mac_address,
        "interface_name": interface_name,
    }


def initialize_interface__tun(interface_name: str) -> dict[str, Any]:
    """
    Initialize the TUN interface.
    """

    log("stack", f"Initializing TUN interface: {interface_name}")

    try:
        fd = os.open("/dev/net/tun", os.O_RDWR)

    except FileNotFoundError:
        log("stack", "<CRIT>Unable to access '/dev/net/tun' device</>")
        sys.exit(-1)

    fcntl.ioctl(
        fd,
        TUNSETIFF,
        struct.pack("16sH", interface_name.encode(), IFF_TUN),
    )

    return {
        "fd": fd,
        "layer": InterfaceLayer.L3,
        "mtu": INTERFACE__TUN__MTU,
        "interface_name": interface_name,
    }


# Lifecycle entry points live in pytcp/stack/lifecycle.py per
# Phase 2 of docs/refactor/pytcp_directory_restructure.md; re-
# exported here so 'pytcp.stack.{init,start,stop,mock__init}'
# import paths stay stable.
from pytcp.stack.lifecycle import init, mock__init, start, stop  # noqa: E402, F401

# Public API surface of the stack package (source_files.md §2.3:
# __all__ lives only in package __init__.py). Required so mypy's
# strict no_implicit_reexport recognises the lifecycle / handler
# re-exports and the logging / sysctl config names as the
# package's intentional public surface.
__all__ = [
    "LOG__CHANNEL",
    "LOG__DEBUG",
    "LOG__OUTPUT",
    "PacketHandlerL2",
    "PacketHandlerL3",
    "TCP__ISS_SECRET",
    "init",
    "mock__init",
    "rx_ring",
    "start",
    "stop",
    "sysctl",
]
