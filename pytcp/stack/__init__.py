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
from pytcp.lib.address_api import Ip4AddressApi
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.link_api import LinkApi
from pytcp.lib.logger import log
from pytcp.protocols.arp.arp__cache import ArpCache
from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4Client
from pytcp.protocols.icmp6.nd.nd__cache import NdCache
from pytcp.protocols.icmp.icmp__error_emitter import IcmpErrorRateLimiter
from pytcp.protocols.tcp.tcp__stack import TcpStack
from pytcp.socket.socket_id import SocketId
from pytcp.stack.packet_handler import PacketHandlerL2, PacketHandlerL3
from pytcp.stack.rx_ring import RxRing
from pytcp.stack.timer import Timer
from pytcp.stack.tx_ring import TxRing

if TYPE_CHECKING:
    from net_addr import Ip4Address, Ip6Address
    from pytcp.protocols.ip4_link_local.ip4_link_local__client import Ip4LinkLocal
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

# RFC 6437 §3 IPv6 Flow Label generation secret. Generated
# once at module import via 'secrets.token_bytes(16)' so each
# PyTCP stack process picks a fresh 128-bit keying value for
# the per-(src, dst) flow-label hash. 'pytcp.lib.ip6_flow_label.compute_ip6_flow_label'
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
sockets: dict[SocketId, socket] = {}
# RFC 1191 §3 / RFC 8201 §4 per-destination Path-MTU cache. Keyed
# by remote IP (v4 or v6); value is the most recently learned next-
# hop MTU. Populated by ICMP Frag-Needed / Packet-Too-Big handlers
# in Phases 4-6 of the ICMP demux + PMTUD refactor; consulted by
# UDP and TCP TX paths for fragment-or-fail / MSS-recompute
# decisions. Process-lifetime only — entries do not expire.
pmtu_cache: dict[Ip4Address | Ip6Address, int] = {}

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


def mock__init(
    *,
    mock__timer: Timer | None = None,
    mock__tx_ring: TxRing | None = None,
    mock__rx_ring: RxRing | None = None,
    mock__arp_cache: ArpCache | None = None,
    mock__nd_cache: NdCache | None = None,
    mock__packet_handler: PacketHandlerL2 | None = None,
    mock__address: Ip4AddressApi | None = None,
    mock__link: LinkApi | None = None,
    mock__dhcp4_client: Dhcp4Client | None = None,
) -> None:
    """
    Initialize stack components for unit testing.
    """

    global timer, rx_ring, tx_ring, arp_cache, nd_cache, packet_handler
    global address, link, dhcp4_client, link_local, stack_running

    # Reset the Link API running flag per test so it does not
    # leak from a prior test that called 'stack.start()'. The
    # unit test corpus does not normally call start/stop, so
    # the default 'False' is the right reset value.
    stack_running = False

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

    # Phase 4 commit A — the Address API. If the test harness
    # passes a packet_handler, also build a default Address API
    # over it (tests that need to mock the API itself can pass
    # 'mock__address' explicitly).
    if mock__address is not None:
        address = mock__address
    elif mock__packet_handler is not None:
        address = Ip4AddressApi(packet_handler=mock__packet_handler)

    # Link API Phase 0 — same pattern as 'address'. Tests get a
    # default 'LinkApi' bound to the mocked packet handler so
    # consumer code reading 'stack.link.mac_address' works in
    # isolation without bespoke harness wiring.
    if mock__link is not None:
        link = mock__link
    elif mock__packet_handler is not None:
        link = LinkApi(packet_handler=mock__packet_handler)

    # Phase 4 commit B — DHCPv4 lifecycle. Default to None unless
    # the harness explicitly opts in; existing tests (NetworkTestCase
    # et al.) don't exercise the lifecycle and don't need a fake.
    dhcp4_client = mock__dhcp4_client

    # RFC 3927 Phase 1 — link-local autoconfig client slot. Default
    # None for unit tests; the link-local subsystem is exercised
    # through its own unit tests, not through the integration
    # harness in Phase 1.
    link_local = None


def init(
    *,
    fd: int,
    layer: InterfaceLayer,
    mtu: int = 1500,
    mac_address: MacAddress | None = None,
    interface_name: str | None = None,
    ip4_support: bool = True,
    ip4_host: Ip4Host | None = (None if IP4_ADDRESS is None else Ip4Host(IP4_ADDRESS, gateway=IP4_GATEWAY)),
    ip4_dhcp: bool = True if IP4_ADDRESS is None else False,
    ip4_link_local: bool = False,
    ip6_support: bool = True,
    ip6_host: Ip6Host | None = (None if IP6_ADDRESS is None else Ip6Host(IP6_ADDRESS, gateway=IP6_GATEWAY)),
    ip6_gua_autoconfig: bool = True if IP6_ADDRESS is None else False,
    ip6_lla_autoconfig: bool = True,
    sysctls: dict[str, Any] | None = None,
) -> None:
    """
    Initialize stack components.
    """

    global timer, rx_ring, tx_ring, arp_cache, nd_cache, packet_handler
    global interface_mtu, stack_initialized

    # Apply any operator overrides for the registered sysctl
    # knobs before subsystems are constructed. The bag-form
    # 'sysctls={"arp.X": ..., "neighbor.X": ...}' is keyed by
    # the dotted-name canonical key. Per-knob validators run on
    # each set(); cross-knob constraints
    # ('finalize_validators') run after the bag is fully
    # applied. Importing 'arp__constants' / 'neighbor__constants'
    # triggers their module-level 'register' calls so the
    # registry is populated before we set anything.
    from pytcp.lib import neighbor__constants  # noqa: F401  pylint: disable=unused-import
    from pytcp.lib import sysctl as sysctl_module
    from pytcp.protocols.arp import arp__constants  # noqa: F401  pylint: disable=unused-import
    from pytcp.protocols.icmp6.nd import nd__constants  # noqa: F401  pylint: disable=unused-import
    from pytcp.protocols.ip4 import ip4__constants  # noqa: F401  pylint: disable=unused-import
    from pytcp.protocols.ip4_link_local import (  # noqa: F401  pylint: disable=unused-import
        ip4_link_local__constants,
    )
    from pytcp.protocols.ip6 import ip6__constants  # noqa: F401  pylint: disable=unused-import

    if sysctls is not None:
        for key, value in sysctls.items():
            sysctl_module.set(key, value)
    sysctl_module.finalize_validators()

    timer = Timer()

    # Construct stats objects up front so the rings and the packet
    # handler share the same instances — ring drop counters and
    # per-protocol counters end up on a single dataclass for
    # unified-stats consumers.
    from pytcp.lib.packet_stats import LinkStatsCounters, PacketStatsRx, PacketStatsTx

    _packet_stats_rx = PacketStatsRx()
    _packet_stats_tx = PacketStatsTx()
    # Link API Phase 3 — link-level aggregate counters (rx_bytes /
    # tx_bytes). Shared instance bumped by RxRing on every
    # successful 'os.read' and by TxRing on every successful
    # 'enqueue'. Read by 'LinkApi.stats' for the
    # 'rx_bytes' / 'tx_bytes' buckets.
    _link_stats = LinkStatsCounters()

    tx_ring = TxRing(
        fd=fd,
        mtu=mtu,
        packet_stats=_packet_stats_tx,
        link_stats=_link_stats,
    )
    rx_ring = RxRing(
        fd=fd,
        mtu=mtu,
        packet_stats=_packet_stats_rx,
        link_stats=_link_stats,
    )
    nd_cache = NdCache()

    match layer:
        case InterfaceLayer.L2:
            assert mac_address is not None, "MAC address must be provided for Layer 2 (TAP) interface."
            arp_cache = ArpCache()
            packet_handler = PacketHandlerL2(
                mac_address=mac_address,
                interface_mtu=mtu,
                interface_name=interface_name,
                ip4_support=ip4_support,
                ip4_host=ip4_host,
                ip4_dhcp=ip4_dhcp,
                ip6_support=ip6_support,
                ip6_host=ip6_host,
                ip6_gua_autoconfig=ip6_gua_autoconfig,
                ip6_lla_autoconfig=ip6_lla_autoconfig,
                packet_stats_rx=_packet_stats_rx,
                packet_stats_tx=_packet_stats_tx,
                link_stats=_link_stats,
            )
        case InterfaceLayer.L3:
            assert mac_address is None, "MAC address must NOT be provided for Layer 3 (TUN) interface."
            packet_handler = PacketHandlerL3(
                interface_mtu=mtu,
                interface_name=interface_name,
                ip4_support=ip4_support,
                ip4_host=ip4_host,
                ip6_support=ip6_support,
                ip6_host=ip6_host,
                packet_stats_rx=_packet_stats_rx,
                packet_stats_tx=_packet_stats_tx,
                link_stats=_link_stats,
            )

    # Phase 4 commit A — IPv4 address-control API. Bound to the
    # newly-constructed 'packet_handler' so DHCP / operator-config
    # consumers never need to import the packet handler directly.
    global address, link
    address = Ip4AddressApi(packet_handler=packet_handler)

    # Link API Phase 0 — link-control surface. Bound to the same
    # packet handler so DHCP / link-local construction (and any
    # future operator-config consumer) reads link-level facts via
    # 'stack.link.*' instead of reaching into
    # 'packet_handler._mac_unicast' / '._interface_mtu' /
    # '._interface_layer'. See 'docs/refactor/link_api.md'.
    link = LinkApi(packet_handler=packet_handler)

    # Phase 4 commit B — DHCPv4 client subsystem. Construct only on
    # L2 (DHCP needs link-layer broadcast and a MAC address; L3/TUN
    # cannot do DHCP). Wired with the address API's RFC 5227 §2.1.1
    # probe and §2.3 announce surfaces as callbacks; the lifecycle
    # never reaches into 'packet_handler' internals directly — the
    # API is the Phase-3-clean kernel/userspace boundary surface.
    global dhcp4_client, link_local
    if ip4_dhcp and layer is InterfaceLayer.L2:
        # MAC is read via the Link API surface so DHCP construction
        # has no reach-through into packet handler internals. The
        # 'mac is not None' assertion narrows
        # 'MacAddress | None' → 'MacAddress' for mypy; on L2 the
        # MAC is always populated.
        dhcp_mac = link.mac_address
        assert dhcp_mac is not None, "L2 stack must expose a unicast MAC via stack.link.mac_address."
        # Adapters that match the callback shape DHCP expects while
        # routing through the sanctioned address-API methods. The
        # 'address' singleton is bound to 'packet_handler' above so
        # the call chain ends up at the same RFC 5227 helpers, but
        # via the public API surface rather than a reach-through.
        _address_api = address
        dhcp4_client = Dhcp4Client(
            mac_address=dhcp_mac,
            arp_dad_verifier=lambda addr: _address_api.probe(address=addr).success,
            arp_dad_announcer=lambda addr: _address_api.announce(address=addr),
            address_api=address,
        )
    else:
        dhcp4_client = None

    # RFC 3927 IPv4 Link-Local autoconfig client subsystem.
    # Constructed only on L2 (link-local depends on Ethernet/ARP);
    # operator opts in via 'ip4_link_local=True'. The 'is_dhcp_bound'
    # closure reads 'dhcp4_client.state' via the public 'state'
    # property so the link-local subsystem can implement RFC 3927
    # §1.9 / §2.11 coordination without reaching into DHCP
    # internals. When no DHCP client exists the closure returns
    # False and the link-local fallback timer kicks immediately.
    if ip4_link_local and layer is InterfaceLayer.L2:
        # MAC is read via the Link API surface, same pattern as
        # the DHCP block above.
        ll_mac = link.mac_address
        assert ll_mac is not None, "L2 stack must expose a unicast MAC via stack.link.mac_address."
        # Capture the global into a local to avoid the closure
        # binding to the symbol at definition time (we want it to
        # read the live module-level 'dhcp4_client' on every call).
        from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4State

        def _is_dhcp_bound() -> bool:
            return dhcp4_client is not None and dhcp4_client.state is Dhcp4State.BOUND

        from pytcp.protocols.ip4_link_local.ip4_link_local__client import Ip4LinkLocal as _Ip4LinkLocal

        link_local = _Ip4LinkLocal(
            mac_address=ll_mac,
            address_api=address,
            is_dhcp_bound=_is_dhcp_bound,
        )
    else:
        link_local = None

    interface_mtu = mtu
    stack_initialized = True


def start() -> None:
    """
    Start stack components.
    """

    assert stack_initialized, "Stack not initialized. Call 'stack.init()' first."

    global stack_running
    stack_running = True

    timer.start()
    if hasattr(packet_handler, "arp_cache"):
        arp_cache.start()
    nd_cache.start()
    tx_ring.start()
    rx_ring.start()
    packet_handler.start()

    # RFC 3927 link-local autoconfig subsystem. Start BEFORE the
    # DHCP wait so the two FSMs run in parallel — the link-local
    # subsystem's '_reconcile_with_dhcp' polls DHCP state and
    # naturally waits until 'dhcp_fallback_timeout_ms' has elapsed
    # of continuous DHCP-unbound time before claiming.
    if link_local is not None:
        link_local.start()

    # Phase 4 commit B — DHCPv4 lifecycle. Start AFTER the packet
    # handler so the TX/RX/socket plumbing is live; block up to
    # 'dhcp.boot_wait_ms' for the FSM to reach BOUND. On timeout
    # the lifecycle keeps trying in the background; boot proceeds
    # without IPv4 for now.
    if dhcp4_client is not None:
        from pytcp.protocols.dhcp4 import dhcp4__constants

        boot_wait_s = dhcp4__constants.DHCP4__BOOT_WAIT_MS / 1000.0
        bound = dhcp4_client.start_and_wait_for_bind(timeout_s=boot_wait_s)
        if bound:
            __debug__ and log("stack", "DHCPv4 lifecycle reached BOUND during boot")
        else:
            __debug__ and log(
                "stack",
                f"<WARN>DHCPv4 lifecycle did not reach BOUND within "
                f"{boot_wait_s:.1f}s; proceeding without IPv4 (lifecycle "
                f"continues in background)</>",
            )


def stop() -> None:
    """
    Stop stack components.
    """

    assert stack_initialized, "Stack not initialized. Call 'stack.init()' first."

    global stack_running
    stack_running = False

    # Teardown order:
    #   0. dhcp4_client    — stop the DHCPv4 lifecycle FIRST so any
    #                        in-flight RENEW/REBIND/RELEASE work
    #                        completes against still-live sockets.
    #   1. packet_handler  — stop application-side TX producers.
    #   2. timer           — stop periodic callbacks (TCP RTO,
    #                        persist, keep-alive, delayed-ACK) so
    #                        they cannot enqueue to a stopped tx_ring.
    #   3. rx_ring         — stop kernel reads.
    #   4. tx_ring         — drain anything still queued + stop.
    #   5. arp_cache / nd_cache — stop cache-refresh threads.
    if dhcp4_client is not None:
        dhcp4_client.stop()
    if link_local is not None:
        link_local.stop()
    packet_handler.stop()
    timer.stop()
    rx_ring.stop()
    tx_ring.stop()
    if hasattr(packet_handler, "arp_cache"):
        arp_cache.stop()
    nd_cache.stop()

    # Restore every registered sysctl to its compile-time default
    # so a follow-up 'stack.init()' (typical in long-running test
    # harnesses) starts from a clean baseline rather than
    # inheriting overrides from the prior run.
    from pytcp.lib import sysctl as sysctl_module

    sysctl_module.reset_to_defaults()
