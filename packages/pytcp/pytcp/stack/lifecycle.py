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
Stack lifecycle module — owns the init / start / stop /
mock__init entry points. Extracted from
'pytcp/stack/__init__.py' (Phase 2 of the directory restructure
at 'docs/refactor/pytcp_directory_restructure.md') so the
sibling 'pytcp/stack/__init__.py' shrinks to constants +
singleton declarations + interface helpers.

The lifecycle functions read and write the module-level
singletons that still live on 'pytcp.stack' via
'import pytcp.stack as _stack; _stack.X = Y'. Same pattern
the test harness uses for snapshot/restore.

pytcp/stack/lifecycle.py

ver 3.0.6
"""

from __future__ import annotations

from typing import Any

from net_addr import (
    Ip4Address,
    Ip4IfAddr,
    Ip4Network,
    Ip6Address,
    Ip6IfAddr,
    Ip6Network,
    MacAddress,
)
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.logger import log
from pytcp.lib.packet_stats import LinkStatsCounters, PacketStatsRx, PacketStatsTx
from pytcp.protocols.arp.arp__cache import ArpCache
from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4Client
from pytcp.protocols.icmp6.nd.nd__cache import NdCache
from pytcp.runtime.fib import RouteTable
from pytcp.runtime.interface_table import InterfaceTable
from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3
from pytcp.runtime.rx_ring import RxRing
from pytcp.runtime.timer import Timer
from pytcp.runtime.tx_ring import TxRing
from pytcp.stack.address import Ip4AddressApi
from pytcp.stack.link import LinkApi
from pytcp.stack.route import RouteApi, install_boot_default_routes


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
    mock__route: RouteApi | None = None,
    mock__dhcp4_client: Dhcp4Client | None = None,
) -> None:
    """
    Initialize stack components for unit testing.
    """

    import pytcp.stack as _stack

    # Reset the Link API running flag per test so it does not
    # leak from a prior test that called 'stack.start()'. The
    # unit test corpus does not normally call start/stop, so
    # the default 'False' is the right reset value.
    _stack.stack_running = False

    if mock__timer is not None:
        _stack.timer = mock__timer

    if mock__tx_ring is not None:
        _stack.tx_ring = mock__tx_ring

    if mock__rx_ring is not None:
        _stack.rx_ring = mock__rx_ring

    if mock__arp_cache is not None:
        _stack.arp_cache = mock__arp_cache

    if mock__nd_cache is not None:
        _stack.nd_cache = mock__nd_cache

    if mock__packet_handler is not None:
        _stack.packet_handler = mock__packet_handler
        # Inject the RX / TX rings into the handler the same way the
        # real 'init()' does, so a test exercising the loop /
        # send-out paths through 'mock__init' dequeues from / enqueues
        # onto the handler's own rings rather than the global shims.
        # Harness tests that drive RX via '_phrx_ethernet' directly
        # don't pass 'mock__rx_ring' and leave that None; the TX
        # harness passes 'mock__tx_ring' and asserts on its recorded
        # frames.
        if mock__rx_ring is not None:
            mock__packet_handler._rx_ring = mock__rx_ring
        if mock__tx_ring is not None:
            mock__packet_handler._tx_ring = mock__tx_ring
        # Bind the per-interface neighbor caches to the handler the
        # same way 'init()' does (both directions), so the RX/TX
        # cache lookups go through 'self._{arp,nd}_cache' and the
        # caches' solicit / flush callbacks route back through the
        # owning handler rather than the global shims.
        if mock__arp_cache is not None:
            mock__packet_handler._arp_cache = mock__arp_cache
            mock__arp_cache._owner = mock__packet_handler
        if mock__nd_cache is not None:
            mock__packet_handler._nd_cache = mock__nd_cache
            mock__nd_cache._owner = mock__packet_handler
        # Register the handler in the per-ifindex interface registry
        # keyed by its own '_ifindex' (default 1 for the harness's
        # sole interface). Only when a handler is passed — a
        # timer-only 'mock__init' (e.g. IcmpTestCase's second call)
        # must NOT wipe the registry the first call populated. Rebuild
        # the table fresh (same reconstruct-per-test lifecycle as the
        # FIBs below) and place the handler at its own ifindex.
        _interfaces = InterfaceTable(first_ifindex=_stack.STACK__DEFAULT_IFINDEX)
        _interfaces[mock__packet_handler._ifindex] = mock__packet_handler
        _stack.interfaces = _interfaces

    # Phase 4 commit A — the Address API. If the test harness
    # passes a packet_handler, also build a default Address API
    # over it (tests that need to mock the API itself can pass
    # 'mock__address' explicitly).
    if mock__address is not None:
        _stack.address = mock__address
    elif mock__packet_handler is not None:
        _stack.address = Ip4AddressApi(packet_handler=mock__packet_handler)

    # Link API Phase 0 — same pattern as 'address'. Tests get a
    # default 'LinkApi' bound to the mocked packet handler so
    # consumer code reading 'stack.link.mac_address' works in
    # isolation without bespoke harness wiring.
    if mock__link is not None:
        _stack.link = mock__link
    elif mock__packet_handler is not None:
        _stack.link = LinkApi(packet_handler=mock__packet_handler)

    # Host-mode routing table — Phase 1. Rebuild the two FIBs
    # fresh every 'mock__init' (i.e. every harness 'setUp') so
    # route state cannot leak across the suite; same reconstruct-
    # per-test lifecycle as 'timer' / 'address' / 'link', which
    # is why the FIBs need no snapshot/restore entry. The
    # integration harness installs the fixture default routes
    # after this call; unit tests get clean empty FIBs.
    ip4_fib: RouteTable[Ip4Address, Ip4Network] = RouteTable()
    ip6_fib: RouteTable[Ip6Address, Ip6Network] = RouteTable()
    _stack.ip4_fib = ip4_fib
    _stack.ip6_fib = ip6_fib
    if mock__route is not None:
        _stack.route = mock__route
    else:
        _stack.route = RouteApi(ip4_fib=ip4_fib, ip6_fib=ip6_fib)

    # Inject the routing-control API into the current handler the
    # same way 'init()' does, so the RX RA path drives the default
    # route through 'self._route_api'. 'mock__init' rebuilds
    # 'stack.route' on EVERY call (e.g. 'IcmpTestCase' calls it a
    # second time, timer-only), so re-inject into whatever handler
    # is currently bound — not just the one passed this call —
    # otherwise the handler keeps a stale RouteApi wrapping the
    # previous FIBs.
    _current_handler = getattr(_stack, "packet_handler", None)
    if _current_handler is not None:
        _current_handler._route_api = _stack.route

    # Phase 4 commit B — DHCPv4 lifecycle. Default to None unless
    # the harness explicitly opts in; existing tests (NetworkTestCase
    # et al.) don't exercise the lifecycle and don't need a fake.
    _stack.dhcp4_client = mock__dhcp4_client

    # RFC 3927 Phase 1 — link-local autoconfig client slot. Default
    # None for unit tests; the link-local subsystem is exercised
    # through its own unit tests, not through the integration
    # harness in Phase 1.
    _stack.link_local = None


def add_interface(
    *,
    fd: int,
    layer: InterfaceLayer,
    mtu: int = 1500,
    mac_address: MacAddress | None = None,
    interface_name: str | None = None,
    ip4_support: bool = True,
    ip4_host: Ip4IfAddr | None = None,
    ip4_dhcp: bool = False,
    ip6_support: bool = True,
    ip6_host: Ip6IfAddr | None = None,
    ip6_gua_autoconfig: bool = False,
    ip6_lla_autoconfig: bool = True,
) -> int:
    """
    Construct one network interface — its fd-bound RX / TX rings,
    its per-ifindex neighbor cache(s) and its packet handler —
    register it in 'stack.interfaces' under a freshly allocated
    ifindex, and return that ifindex.

    The handler instance IS the interface: it owns the injected
    rings and the ARP / ND caches (Linux keys neighbors per
    ifindex). The first interface added takes 'STACK__DEFAULT_IFINDEX'
    and also populates the N=1 back-compat singletons
    'stack.packet_handler' / 'rx_ring' / 'tx_ring' / 'arp_cache' /
    'nd_cache' (retired in a later phase); subsequent interfaces get
    the next free index and leave those shims on the boot interface.

    'init()' calls this once for the boot interface; the runtime
    multi-interface path calls it again once N>1 is enabled.
    """

    import pytcp.stack as _stack

    # Per-interface stats — each interface's rings + handler share
    # one set, so ring drop counters and per-protocol counters land
    # on a single dataclass per interface for unified-stats consumers.
    packet_stats_rx = PacketStatsRx()
    packet_stats_tx = PacketStatsTx()
    link_stats = LinkStatsCounters()

    tx_ring = TxRing(fd=fd, mtu=mtu, packet_stats=packet_stats_tx, link_stats=link_stats)
    rx_ring = RxRing(fd=fd, mtu=mtu, packet_stats=packet_stats_rx, link_stats=link_stats)
    nd_cache = NdCache()
    arp_cache: ArpCache | None = None

    packet_handler: PacketHandlerL2 | PacketHandlerL3
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
                rx_ring=rx_ring,
                tx_ring=tx_ring,
                packet_stats_rx=packet_stats_rx,
                packet_stats_tx=packet_stats_tx,
                link_stats=link_stats,
            )
            # Bind the per-interface neighbor caches to this handler
            # and the reverse owner back-reference so the caches'
            # solicit / flush callbacks route through this interface.
            # ARP is L2-only; ND is used by both layers.
            packet_handler._arp_cache = arp_cache
            packet_handler._nd_cache = nd_cache
            arp_cache._owner = packet_handler
            nd_cache._owner = packet_handler
        case InterfaceLayer.L3:
            assert mac_address is None, "MAC address must NOT be provided for Layer 3 (TUN) interface."
            packet_handler = PacketHandlerL3(
                interface_mtu=mtu,
                interface_name=interface_name,
                ip4_support=ip4_support,
                ip4_host=ip4_host,
                ip6_support=ip6_support,
                ip6_host=ip6_host,
                rx_ring=rx_ring,
                tx_ring=tx_ring,
                packet_stats_rx=packet_stats_rx,
                packet_stats_tx=packet_stats_tx,
                link_stats=link_stats,
            )
            # L3 (TUN) has no ARP; bind only the ND cache + its owner.
            packet_handler._nd_cache = nd_cache
            nd_cache._owner = packet_handler

    is_first = not _stack.interfaces
    # The table allocates the next ifindex (first_ifindex when empty,
    # else max+1) and stamps it onto the handler, atomically under its
    # lock so concurrent runtime adds cannot collide on an index.
    ifindex = _stack.interfaces.add(packet_handler)

    # Route state is global (shared across interfaces). Inject the
    # Route API if it already exists (a runtime add_interface call);
    # for the boot interface 'init()' builds the FIB after this
    # returns and injects the Route API itself.
    route = getattr(_stack, "route", None)
    if route is not None:
        packet_handler._route_api = route

    # First interface populates the N=1 back-compat singletons.
    if is_first:
        _stack.packet_handler = packet_handler
        _stack.rx_ring = rx_ring
        _stack.tx_ring = tx_ring
        _stack.nd_cache = nd_cache
        if arp_cache is not None:
            _stack.arp_cache = arp_cache

    # Daemon runtime path (RTM_NEWLINK): when the stack is already
    # running, bring the new interface's subsystem threads up on the
    # spot. At boot the stack is not yet running, so the pending
    # 'stack.start()' starts every registered interface instead.
    if _stack.stack_running:
        _start_interface(packet_handler)

    return ifindex


def remove_interface(ifindex: int, /) -> PacketHandlerL2 | PacketHandlerL3 | None:
    """
    Remove the interface registered under 'ifindex' — the RTNETLINK
    'RTM_DELLINK' equivalent. Deregisters it from 'stack.interfaces'
    and, when the stack is running, stops its subsystem threads (handler
    + rings + neighbor caches). Returns the removed handler, or None
    when no interface is registered under 'ifindex'.

    Phase 6 part 5 deliberately stops at thread-teardown + deregister:
    the 'RTM_DELLINK' cascade for addresses on the removed interface —
    evicting the peer neighbor caches and aborting TCP sessions bound to
    those addresses — is deferred to its own slice.

    NOTE: removing the interface that the N=1 back-compat singletons
    ('stack.packet_handler' / 'rx_ring' / 'tx_ring' / 'arp_cache' /
    'nd_cache') point at does NOT yet clear those shims — they are
    retired in Phase 6 part 6. Runtime removal targets non-shim
    interfaces until then.
    """

    import pytcp.stack as _stack

    iface = _stack.interfaces.pop(ifindex)
    if iface is None:
        return None
    if _stack.stack_running:
        _stop_interface(iface)
    return iface


def init(
    *,
    fd: int,
    layer: InterfaceLayer,
    mtu: int = 1500,
    mac_address: MacAddress | None = None,
    interface_name: str | None = None,
    ip4_support: bool = True,
    ip4_host: Ip4IfAddr | None = None,
    ip4_dhcp: bool | None = None,
    ip4_link_local: bool = False,
    ip6_support: bool = True,
    ip6_host: Ip6IfAddr | None = None,
    ip6_gua_autoconfig: bool | None = None,
    ip6_lla_autoconfig: bool = True,
    sysctls: dict[str, Any] | None = None,
) -> None:
    """
    Initialize stack components.
    """

    import pytcp.stack as _stack

    # Resolve None-valued kwargs against the stack-level
    # config constants. The legacy form used these constants
    # as default-expression values, which evaluated at module
    # import — meaning a test changing 'stack.IP4_ADDRESS'
    # would not affect a later 'init()' call. Move the
    # resolution into the body so each invocation sees the
    # current values.
    if ip4_host is None and _stack.IP4_ADDRESS is not None:
        ip4_host = Ip4IfAddr(_stack.IP4_ADDRESS)
    if ip4_dhcp is None:
        ip4_dhcp = _stack.IP4_ADDRESS is None
    if ip6_host is None and _stack.IP6_ADDRESS is not None:
        ip6_host = Ip6IfAddr(_stack.IP6_ADDRESS)
    if ip6_gua_autoconfig is None:
        ip6_gua_autoconfig = _stack.IP6_ADDRESS is None

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
    from pytcp.protocols.arp import arp__constants  # noqa: F401  pylint: disable=unused-import
    from pytcp.protocols.icmp6.nd import nd__constants  # noqa: F401  pylint: disable=unused-import
    from pytcp.protocols.ip4 import ip4__constants  # noqa: F401  pylint: disable=unused-import
    from pytcp.protocols.ip4.link_local import (  # noqa: F401  pylint: disable=unused-import
        link_local__constants,
    )
    from pytcp.protocols.ip6 import ip6__constants  # noqa: F401  pylint: disable=unused-import
    from pytcp.stack import sysctl as sysctl_module

    if sysctls is not None:
        for key, value in sysctls.items():
            sysctl_module.set(key, value)
    sysctl_module.finalize_validators()

    _stack.timer = Timer()

    # Build the boot interface — its rings, neighbor caches and
    # packet handler — and register it in 'stack.interfaces'.
    # 'add_interface' also populates the N=1 back-compat singletons
    # ('stack.packet_handler' / 'rx_ring' / 'tx_ring' / 'arp_cache' /
    # 'nd_cache') from this first interface; the global APIs (address /
    # link / route) and the DHCP / link-local subsystems below bind to
    # that boot handler. The reset to a fresh empty table makes a
    # re-'init()' (common in long-running test harnesses) start from
    # zero interfaces.
    _stack.interfaces = InterfaceTable(first_ifindex=_stack.STACK__DEFAULT_IFINDEX)
    add_interface(
        fd=fd,
        layer=layer,
        mtu=mtu,
        mac_address=mac_address,
        interface_name=interface_name,
        ip4_support=ip4_support,
        ip4_host=ip4_host,
        ip4_dhcp=ip4_dhcp,
        ip6_support=ip6_support,
        ip6_host=ip6_host,
        ip6_gua_autoconfig=ip6_gua_autoconfig,
        ip6_lla_autoconfig=ip6_lla_autoconfig,
    )

    # IPv4 address-control API + link-control surface — built as the
    # UNBOUND, device-independent "userspace tools" (the 'ip addr' /
    # 'ip link' model), NOT pinned to the boot interface. A bare op on
    # the unbound tool resolves the SOLE registered interface
    # (transitional N=1 crutch in '_resolve_handler'), so DHCP /
    # link-local / operator-config consumers reading 'stack.address.*' /
    # 'stack.link.*' work unchanged at N=1; '.interface(ifindex)' selects
    # a device once N>1. This is the daemon-shaped target: no privileged
    # boot interface bound into the control APIs. See
    # 'docs/refactor/link_api.md' and the Phase-6 plan.
    _stack.address = Ip4AddressApi()
    _stack.link = LinkApi()

    # Host-mode routing table — Phase 3 of
    # 'docs/refactor/routing_table_host_mode.md'. Build the two
    # FIBs and install the static boot-config gateway as the
    # 'protocol=BOOT' default route. The Phase-1 dual-write is
    # gone: 'Ip{4,6}IfAddr.gateway' is no longer written (the
    # ctor calls above dropped 'gateway='), so the FIB is the
    # single source of truth for the next hop. DHCP / RA /
    # autoconfig install their learned gateway at runtime via
    # 'RouteApi.replace_default_ip{4,6}'.
    ip4_fib: RouteTable[Ip4Address, Ip4Network] = RouteTable()
    ip6_fib: RouteTable[Ip6Address, Ip6Network] = RouteTable()
    install_boot_default_routes(
        ip4_fib=ip4_fib,
        ip6_fib=ip6_fib,
        ip4_gateway=_stack.IP4_GATEWAY,
        ip6_gateway=_stack.IP6_GATEWAY,
    )
    _stack.ip4_fib = ip4_fib
    _stack.ip6_fib = ip6_fib
    _stack.route = RouteApi(ip4_fib=ip4_fib, ip6_fib=ip6_fib)

    # Inject the routing-control API into the handler so the RX RA
    # path drives the default route through 'self._route_api'
    # instead of reaching 'stack.route'. Route state is global
    # (shared across interfaces); the injection just makes the
    # dependency explicit.
    _stack.packet_handler._route_api = _stack.route

    # Phase 4 commit B — DHCPv4 client subsystem. Construct only on
    # L2 (DHCP needs link-layer broadcast and a MAC address; L3/TUN
    # cannot do DHCP). Wired with the address API's RFC 5227 §2.1.1
    # probe and §2.3 announce surfaces as callbacks; the lifecycle
    # never reaches into 'packet_handler' internals directly — the
    # API is the Phase-3-clean kernel/userspace boundary surface.
    if ip4_dhcp and layer is InterfaceLayer.L2:
        # MAC is read via the Link API surface so DHCP construction
        # has no reach-through into packet handler internals. The
        # 'mac is not None' assertion narrows
        # 'MacAddress | None' → 'MacAddress' for mypy; on L2 the
        # MAC is always populated.
        dhcp_mac = _stack.link.mac_address
        assert dhcp_mac is not None, "L2 stack must expose a unicast MAC via stack.link.mac_address."
        # Adapters that match the callback shape DHCP expects while
        # routing through the sanctioned address-API methods. The
        # 'address' singleton is bound to 'packet_handler' above so
        # the call chain ends up at the same RFC 5227 helpers, but
        # via the public API surface rather than a reach-through.
        _address_api = _stack.address
        _stack.dhcp4_client = Dhcp4Client(
            mac_address=dhcp_mac,
            arp_dad_verifier=lambda addr: _address_api.probe(address=addr).success,
            arp_dad_announcer=lambda addr: _address_api.announce(address=addr),
            address_api=_stack.address,
            route_api=_stack.route,
        )
    else:
        _stack.dhcp4_client = None

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
        ll_mac = _stack.link.mac_address
        assert ll_mac is not None, "L2 stack must expose a unicast MAC via stack.link.mac_address."
        from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4State

        def _is_dhcp_bound() -> bool:
            return _stack.dhcp4_client is not None and _stack.dhcp4_client.state is Dhcp4State.BOUND

        from pytcp.protocols.ip4.link_local.link_local__client import Ip4LinkLocal as _Ip4LinkLocal

        _stack.link_local = _Ip4LinkLocal(
            mac_address=ll_mac,
            address_api=_stack.address,
            is_dhcp_bound=_is_dhcp_bound,
        )
    else:
        _stack.link_local = None

    _stack.interface_mtu = mtu
    _stack.stack_initialized = True


def _start_interface(iface: PacketHandlerL2 | PacketHandlerL3, /) -> None:
    """
    Start one interface's own subsystem threads — its neighbor
    cache(s), TX / RX rings and packet handler (the handler owns its
    injected '_rx_ring' / '_tx_ring' / '_arp_cache' / '_nd_cache').
    Shared by 'stack.start()' (boot, every registered interface) and
    'add_interface' (runtime add to an already-running stack).
    """

    if iface._arp_cache is not None:
        iface._arp_cache.start()
    assert iface._nd_cache is not None
    iface._nd_cache.start()
    assert iface._tx_ring is not None and iface._rx_ring is not None
    iface._tx_ring.start()
    iface._rx_ring.start()
    iface.start()


def _stop_interface(iface: PacketHandlerL2 | PacketHandlerL3, /) -> None:
    """
    Stop one interface's own subsystem threads — handler first (stop
    TX producers), then its rings, then its neighbor cache(s); the
    reverse of '_start_interface'. Used by 'remove_interface' to tear
    down a single interface on a running stack. ('stack.stop()' keeps
    its own global ordering — all handlers, then the shared timer, then
    all rings/caches — so it does not call this per-interface helper.)
    """

    iface.stop()
    assert iface._rx_ring is not None and iface._tx_ring is not None
    iface._rx_ring.stop()
    iface._tx_ring.stop()
    if iface._arp_cache is not None:
        iface._arp_cache.stop()
    assert iface._nd_cache is not None
    iface._nd_cache.stop()


def start() -> None:
    """
    Start stack components.
    """

    import pytcp.stack as _stack

    assert _stack.stack_initialized, "Stack not initialized. Call 'stack.init()' first."

    _stack.stack_running = True

    _stack.timer.start()
    # Per-interface subsystems: start each registered interface's own
    # caches, rings and handler. At N=1 this is the single boot
    # interface; the loop is the N>1 path.
    for iface in _stack.interfaces.values():
        _start_interface(iface)

    # RFC 3927 link-local autoconfig subsystem. Start BEFORE the
    # DHCP wait so the two FSMs run in parallel — the link-local
    # subsystem's '_reconcile_with_dhcp' polls DHCP state and
    # naturally waits until 'dhcp_fallback_timeout_ms' has elapsed
    # of continuous DHCP-unbound time before claiming.
    if _stack.link_local is not None:
        _stack.link_local.start()

    # Phase 4 commit B — DHCPv4 lifecycle. Start AFTER the packet
    # handler so the TX/RX/socket plumbing is live; block up to
    # 'dhcp.boot_wait_ms' for the FSM to reach BOUND. On timeout
    # the lifecycle keeps trying in the background; boot proceeds
    # without IPv4 for now.
    if _stack.dhcp4_client is not None:
        from pytcp.protocols.dhcp4 import dhcp4__constants

        boot_wait_s = dhcp4__constants.DHCP4__BOOT_WAIT_MS / 1000.0
        bound = _stack.dhcp4_client.start_and_wait_for_bind(timeout_s=boot_wait_s)
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

    import pytcp.stack as _stack

    assert _stack.stack_initialized, "Stack not initialized. Call 'stack.init()' first."

    _stack.stack_running = False

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
    if _stack.dhcp4_client is not None:
        _stack.dhcp4_client.stop()
    if _stack.link_local is not None:
        _stack.link_local.stop()
    # Per-interface handlers first (stop application-side TX
    # producers), then the shared timer (so periodic callbacks cannot
    # enqueue onto a stopped ring), then each interface's rings +
    # caches. At N=1 this is the single boot interface.
    for iface in _stack.interfaces.values():
        iface.stop()
    _stack.timer.stop()
    for iface in _stack.interfaces.values():
        assert iface._rx_ring is not None and iface._tx_ring is not None
        iface._rx_ring.stop()
        iface._tx_ring.stop()
        if iface._arp_cache is not None:
            iface._arp_cache.stop()
        assert iface._nd_cache is not None
        iface._nd_cache.stop()

    # Restore every registered sysctl to its compile-time default
    # so a follow-up 'stack.init()' (typical in long-running test
    # harnesses) starts from a clean baseline rather than
    # inheriting overrides from the prior run.
    from pytcp.stack import sysctl as sysctl_module

    sysctl_module.reset_to_defaults()
