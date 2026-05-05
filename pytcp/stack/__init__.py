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

ver 3.0.3
"""

from __future__ import annotations

import fcntl
import os
import secrets
import struct
import sys
from typing import TYPE_CHECKING, Any

from net_addr import Ip4Host, Ip6Host, MacAddress
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.logger import log
from pytcp.socket.socket_id import SocketId
from pytcp.stack.arp_cache import ArpCache
from pytcp.stack.nd_cache import NdCache
from pytcp.stack.packet_handler import PacketHandlerL2, PacketHandlerL3
from pytcp.stack.rx_ring import RxRing
from pytcp.stack.timer import Timer
from pytcp.stack.tx_ring import TxRing

if TYPE_CHECKING:
    from net_addr import Ip4Address, Ip6Address
    from pytcp.socket import socket


assert sys.version_info >= (
    3,
    12,
), "PyTCP stack requires Python version 3.12 or higher to run."


# Constants for TUN/TAP interface.
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

# PyTCP code metadata.
PYTCP_VERSION = "ver 3.0.4"
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

# RFC 7413 TCP Fast Open server-side cookie generation
# secret. Same allocation pattern as 'TCP__ISS_SECRET':
# generated at module import time via 'secrets.token_bytes(16)'
# so each PyTCP stack process has a fresh 128-bit keying
# value for the TFO cookie HMAC. Implementations MAY rotate
# the secret to invalidate outstanding cookies; PyTCP keeps
# it stable for the process lifetime.
TCP__FASTOPEN_SECRET: bytes = secrets.token_bytes(16)

# RFC 7413 §3.1 / §4.1.3 Fast Open client-side cookie cache.
# Maps peer IP address to the most-recently-seen cookie issued
# by that peer in a SYN+ACK. A subsequent active-open SYN to
# the same peer replays the cached cookie + (optionally) data
# to skip the data RTT. The cache is per-process and stable
# for the process lifetime; restarts purge it (matching the
# secret rotation behaviour). Wire-format compatibility: the
# cookie byte-strings are 4..16 bytes per RFC 7413 §2.
tcp__fastopen_cookies: "dict[Ip4Address | Ip6Address, bytes]" = {}

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

# RFC 7413 §4.1.3.1 negative-response cache: peers we have
# seen TFO fail with (handshake completed via 3WHS rather
# than the TFO fast path, indicating a middlebox or peer
# that drops TFO-bearing SYNs). Subsequent active-open
# attempts to a peer in this set bypass the TFO option
# entirely so a known-bad path is not exercised on every
# new connection. The cache is per-process and stable for
# the process lifetime; restarts purge it.
tcp__fastopen_negative: "set[Ip4Address | Ip6Address]" = set()

# RFC 7413 §4.2 PendingFastOpenRequests: count of TFO-
# accepted active connections in SYN-RCVD state on the
# server side. When the count meets or exceeds the
# 'fastopen_qlen' limit configured on a listening socket,
# the listen handler refuses TFO acceptance for the
# incoming SYN (returns the empty-cookie cookie response
# so the client falls back to 3WHS) until the in-flight
# TFO connections drain to ESTABLISHED or CLOSED.
tcp__fastopen_pending_count: int = 0

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

# ARP cache configuration.
ARP__CACHE__ENTRY_MAX_AGE = 3600
ARP__CACHE__ENTRY_REFRESH_TIME = 300

# ICMPv6 ND cache configuration.
ICMP6__ND__CACHE__ENTRY_MAX_AGE = 3600
ICMP6__ND__CACHE__ENTRY_REFRESH_TIME = 300

# IPv4 and IPv6 fragmnt flow expiration time, determines for how many seconds
# IP fragment flow is considered valid. Fragemnt flows are being cleaned up prior
# of handling every fragmented packet.
IP4__FRAG_FLOW_TIMEOUT = 5
IP6__FRAG_FLOW_TIMEOUT = 5

# Native support for UDP Echo (used for packet flow unit testing only
# and should always be disabled).
UDP__ECHO_NATIVE = False

# Ephemeral port range, used for picking local ports for outbound connections.
EPHEMERAL_PORT_RANGE = range(32168, 60700, 2)

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

# Stack shared data.
stack_initialized: bool = False
interface_mtu: int
sockets: dict[SocketId, socket] = {}
arp_probe_unicast_conflict: set[Ip4Address] = set()


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
    }


def mock__init(
    *,
    mock__timer: Timer | None = None,
    mock__tx_ring: TxRing | None = None,
    mock__rx_ring: RxRing | None = None,
    mock__arp_cache: ArpCache | None = None,
    mock__nd_cache: NdCache | None = None,
    mock__packet_handler: PacketHandlerL2 | None = None,
) -> None:
    """
    Initialize stack components for unit testing.
    """

    global timer, rx_ring, tx_ring, arp_cache, nd_cache, packet_handler

    if mock__timer is not None:
        timer = mock__timer

    if mock__tx_ring is not None:
        tx_ring = mock__tx_ring

    if mock__rx_ring is not None:
        rx_ring = mock__rx_ring

    if mock__arp_cache is not None:
        arp_cache = mock__arp_cache

    if mock__nd_cache is not None:
        nd_cache = mock__nd_cache

    if mock__packet_handler is not None:
        packet_handler = mock__packet_handler


def init(
    *,
    fd: int,
    layer: InterfaceLayer,
    mtu: int = 1500,
    mac_address: MacAddress | None = None,
    ip4_support: bool = True,
    ip4_host: Ip4Host | None = (None if IP4_ADDRESS is None else Ip4Host(IP4_ADDRESS, gateway=IP4_GATEWAY)),
    ip4_dhcp: bool = True if IP4_ADDRESS is None else False,
    ip6_support: bool = True,
    ip6_host: Ip6Host | None = (None if IP6_ADDRESS is None else Ip6Host(IP6_ADDRESS, gateway=IP6_GATEWAY)),
    ip6_gua_autoconfig: bool = True if IP6_ADDRESS is None else False,
    ip6_lla_autoconfig: bool = True,
) -> None:
    """
    Initialize stack components.
    """

    global timer, rx_ring, tx_ring, arp_cache, nd_cache, packet_handler
    global interface_mtu, stack_initialized

    timer = Timer()
    tx_ring = TxRing(
        fd=fd,
        mtu=mtu,
    )
    rx_ring = RxRing(
        fd=fd,
        mtu=mtu,
    )
    nd_cache = NdCache()

    match layer:
        case InterfaceLayer.L2:
            assert mac_address is not None, "MAC address must be provided for Layer 2 (TAP) interface."
            arp_cache = ArpCache()
            packet_handler = PacketHandlerL2(
                mac_address=mac_address,
                interface_mtu=mtu,
                ip4_support=ip4_support,
                ip4_host=ip4_host,
                ip4_dhcp=ip4_dhcp,
                ip6_support=ip6_support,
                ip6_host=ip6_host,
                ip6_gua_autoconfig=ip6_gua_autoconfig,
                ip6_lla_autoconfig=ip6_lla_autoconfig,
            )
        case InterfaceLayer.L3:
            assert mac_address is None, "MAC address must NOT be provided for Layer 3 (TUN) interface."
            packet_handler = PacketHandlerL3(
                interface_mtu=mtu,
                ip4_support=ip4_support,
                ip4_host=ip4_host,
                ip6_support=ip6_support,
                ip6_host=ip6_host,
            )

    interface_mtu = mtu
    stack_initialized = True


def start() -> None:
    """
    Start stack components.
    """

    assert stack_initialized, "Stack not initialized. Call 'stack.init()' first."

    timer.start()
    if hasattr(packet_handler, "arp_cache"):
        arp_cache.start()
    nd_cache.start()
    tx_ring.start()
    rx_ring.start()
    packet_handler.start()


def stop() -> None:
    """
    Stop stack components.
    """

    assert stack_initialized, "Stack not initialized. Call 'stack.init()' first."

    packet_handler.stop()
    rx_ring.stop()
    tx_ring.stop()
    if hasattr(packet_handler, "arp_cache"):
        arp_cache.stop()
    nd_cache.stop()
    timer.stop()
