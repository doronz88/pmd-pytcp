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

ver 3.0.5
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
from pytcp.protocols.arp.arp__cache import ArpCache
from pytcp.protocols.dhcp4.dhcp4__client import Dhcp4Client
from pytcp.protocols.icmp6.nd.nd__cache import NdCache
from pytcp.runtime.fib import RouteTable
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

    # Phase 4 commit B — DHCPv4 lifecycle. Default to None unless
    # the harness explicitly opts in; existing tests (NetworkTestCase
    # et al.) don't exercise the lifecycle and don't need a fake.
    _stack.dhcp4_client = mock__dhcp4_client

    # RFC 3927 Phase 1 — link-local autoconfig client slot. Default
    # None for unit tests; the link-local subsystem is exercised
    # through its own unit tests, not through the integration
    # harness in Phase 1.
    _stack.link_local = None


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

    _stack.tx_ring = TxRing(
        fd=fd,
        mtu=mtu,
        packet_stats=_packet_stats_tx,
        link_stats=_link_stats,
    )
    _stack.rx_ring = RxRing(
        fd=fd,
        mtu=mtu,
        packet_stats=_packet_stats_rx,
        link_stats=_link_stats,
    )
    _stack.nd_cache = NdCache()

    match layer:
        case InterfaceLayer.L2:
            assert mac_address is not None, "MAC address must be provided for Layer 2 (TAP) interface."
            _stack.arp_cache = ArpCache()
            _stack.packet_handler = PacketHandlerL2(
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
            _stack.packet_handler = PacketHandlerL3(
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
    _stack.address = Ip4AddressApi(packet_handler=_stack.packet_handler)

    # Link API Phase 0 — link-control surface. Bound to the same
    # packet handler so DHCP / link-local construction (and any
    # future operator-config consumer) reads link-level facts via
    # 'stack.link.*' instead of reaching into
    # 'packet_handler._mac_unicast' / '._interface_mtu' /
    # '._interface_layer'. See 'docs/refactor/link_api.md'.
    _stack.link = LinkApi(packet_handler=_stack.packet_handler)

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


def start() -> None:
    """
    Start stack components.
    """

    import pytcp.stack as _stack

    assert _stack.stack_initialized, "Stack not initialized. Call 'stack.init()' first."

    _stack.stack_running = True

    _stack.timer.start()
    if hasattr(_stack.packet_handler, "arp_cache"):
        _stack.arp_cache.start()
    _stack.nd_cache.start()
    _stack.tx_ring.start()
    _stack.rx_ring.start()
    _stack.packet_handler.start()

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
    _stack.packet_handler.stop()
    _stack.timer.stop()
    _stack.rx_ring.stop()
    _stack.tx_ring.stop()
    if hasattr(_stack.packet_handler, "arp_cache"):
        _stack.arp_cache.stop()
    _stack.nd_cache.stop()

    # Restore every registered sysctl to its compile-time default
    # so a follow-up 'stack.init()' (typical in long-running test
    # harnesses) starts from a clean baseline rather than
    # inheriting overrides from the prior run.
    from pytcp.stack import sysctl as sysctl_module

    sysctl_module.reset_to_defaults()
