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
This package contains packet handler class for inbound and outbound packets.

pytcp/runtime/packet_handler/__init__.py

ver 3.0.6
"""

from __future__ import annotations

import random
import secrets
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import TYPE_CHECKING, override

from net_addr import (
    Ip4Address,
    Ip4IfAddr,
    Ip6Address,
    Ip6IfAddr,
    Ip6Mask,
    Ip6Network,
    MacAddress,
)
from net_proto import ETHERNET_802_3__PACKET__MAX_LEN, EtherType, Icmp6NdRoutePreference
from pytcp import stack
from pytcp.lib.dad_slot_registry import DadSlotRegistry
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.logger import log
from pytcp.lib.packet_stats import LinkStatsCounters, PacketStatsRx, PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.icmp6.nd import nd__constants
from pytcp.protocols.icmp6.nd.nd__router_state import (
    Icmp6DadState,
    Icmp6DefaultRouter,
    Icmp6RaParameters,
    Icmp6SlaacAddress,
    Icmp6SlaacAddressState,
    Icmp6TempAddress,
)
from pytcp.protocols.ip4.acd.ip4_acd import Ip4Acd
from pytcp.protocols.ip.ip_frag_table import IpFragTable
from pytcp.runtime.fib import RouteProtocol
from pytcp.runtime.rx_ring import RxRing
from pytcp.runtime.subsystem import Subsystem
from pytcp.runtime.timer import TimerHandle
from pytcp.runtime.tx_ring import TxRing

from .packet_handler__arp__rx import PacketHandlerArpRx
from .packet_handler__arp__tx import PacketHandlerArpTx
from .packet_handler__ethernet_802_3__rx import PacketHandlerEthernet8023Rx
from .packet_handler__ethernet_802_3__tx import PacketHandlerEthernet8023Tx
from .packet_handler__ethernet__rx import PacketHandlerEthernetRx
from .packet_handler__ethernet__tx import PacketHandlerEthernetTx
from .packet_handler__icmp4__rx import PacketHandlerIcmp4Rx
from .packet_handler__icmp4__tx import PacketHandlerIcmp4Tx
from .packet_handler__icmp6__rx import PacketHandlerIcmp6Rx
from .packet_handler__icmp6__tx import PacketHandlerIcmp6Tx
from .packet_handler__ip4__rx import PacketHandlerIp4Rx
from .packet_handler__ip4__tx import PacketHandlerIp4Tx
from .packet_handler__ip6__rx import PacketHandlerIp6Rx
from .packet_handler__ip6__tx import PacketHandlerIp6Tx
from .packet_handler__ip6_frag__rx import PacketHandlerIp6FragRx
from .packet_handler__ip6_frag__tx import PacketHandlerIp6FragTx
from .packet_handler__tcp__rx import PacketHandlerTcpRx
from .packet_handler__tcp__tx import PacketHandlerTcpTx
from .packet_handler__udp__rx import PacketHandlerUdpRx
from .packet_handler__udp__tx import PacketHandlerUdpTx

if TYPE_CHECKING:
    from threading import Semaphore

    from pytcp.protocols.arp.arp__cache import ArpCache
    from pytcp.protocols.icmp6.nd.nd__cache import NdCache
    from pytcp.stack.route import RouteApi


class PacketHandler(Subsystem, ABC):
    """
    Base class for packet handlers.
    """

    _subsystem_name = "Packet Handler"

    _event__stop_subsystem: threading.Event

    _packet_stats_rx: PacketStatsRx
    _packet_stats_tx: PacketStatsTx
    _link_stats: LinkStatsCounters
    # Per-interface RX ring. Injected at construction by
    # 'stack.init()' (the ring is fd-bound, hence per-interface).
    # The subsystem loop dequeues from this — never from the
    # global 'stack.rx_ring' shim. 'None' only for standalone
    # unit-test handlers that never run the subsystem loop. The
    # class-level 'None' default (rather than an annotation alone)
    # keeps the attribute visible to 'create_autospec' so test
    # fixtures can install a mock ring on a spec'd handler.
    _rx_ring: RxRing | None = None
    # Per-interface TX ring (fd-bound). Injected at construction;
    # the TX-mixin send-out paths enqueue onto this — never onto
    # the global 'stack.tx_ring' shim. 'None' only for standalone
    # unit-test handlers that never enqueue.
    _tx_ring: TxRing | None = None
    # Per-interface neighbor caches (Linux keys ARP / ND per
    # ifindex). Injected after construction by 'stack.init()'.
    # ARP is L2-only, so '_arp_cache' stays None on an L3 (TUN)
    # handler; '_nd_cache' is used by both layers. 'None' for
    # standalone unit-test handlers that never resolve a neighbor.
    _arp_cache: ArpCache | None = None
    _nd_cache: NdCache | None = None
    # Routing-control API (the host-mode FIB mutation surface).
    # Global state shared across interfaces, but injected as an
    # explicit dependency rather than reached via 'stack.route'.
    # The RX RA path drives the default route through this. 'None'
    # until injected (early-RX / test contexts without a Route API).
    _route_api: RouteApi | None = None
    # Per-interface index (Linux ifindex). The handler IS the
    # interface object; 'stack.interfaces' maps this index to the
    # handler. Class-level default 1 (the sole interface today /
    # standalone unit-test handlers); 'stack.init()' assigns the
    # real index per registered interface.
    _ifindex: int = 1
    _interface_mtu: int
    _interface_name: str | None
    _ip6_support: bool
    _ip4_support: bool
    _ip6_ifaddr_candidate: list[Ip6IfAddr]
    _ip4_ifaddr_candidate: list[Ip4IfAddr]
    _ip6_ifaddr: list[Ip6IfAddr]
    _ip4_ifaddr: list[Ip4IfAddr]
    _ip6_multicast: list[Ip6Address]
    _ip4_multicast: list[Ip4Address]
    # IPv4 Identification counter + the lock guarding its masked
    # read-modify-write. Per-interface (the counter is interface
    # state); the tiny lock makes '_next_ip4_id' atomic under the
    # current app-thread TX model and stays cheap (uncontended)
    # once Phase 4 makes TX single-writer. IPv6 has no counterpart:
    # its Fragment Identification is a fresh random per datagram
    # (a loop-local in '_phtx_ip6_frag'), not stored on the handler.
    _ip4_id: int
    _lock__ip4_id: threading.Lock
    _ip6_frag_table: IpFragTable
    _ip4_frag_table: IpFragTable
    _ip_configuration_in_progress: Semaphore
    _mac_unicast: MacAddress
    _icmp6_default_routers: list[Icmp6DefaultRouter]
    _icmp6_slaac_addresses: list[Icmp6SlaacAddress]
    _icmp6_temp_addresses: list[Icmp6TempAddress]
    _icmp6_slaac__secret_key: bytes
    _icmp6_ra_parameters: Icmp6RaParameters
    _icmp6_dad__states: dict[Ip6Address, Icmp6DadState]
    _ip6_addressing_complete: bool

    @override
    def __init__(
        self,
        *,
        interface_mtu: int,
        ip6_support: bool,
        ip4_support: bool,
        interface_name: str | None = None,
        ip6_host: Ip6IfAddr | None = None,
        ip4_host: Ip4IfAddr | None = None,
        rx_ring: RxRing | None = None,
        tx_ring: TxRing | None = None,
        packet_stats_rx: PacketStatsRx | None = None,
        packet_stats_tx: PacketStatsTx | None = None,
        link_stats: LinkStatsCounters | None = None,
    ) -> None:
        """
        Class constructor.
        """

        super().__init__()

        # Per-interface RX / TX rings (fd-bound). Injected by
        # 'stack.init()'; standalone unit-test handlers leave them
        # None and never run '_subsystem_loop' / enqueue.
        self._rx_ring = rx_ring
        self._tx_ring = tx_ring

        # Per-interface neighbor caches. Injected after construction
        # by 'stack.init()' (the cache <-> handler relationship is
        # bidirectional, so they cannot both be ctor args). Default
        # None so standalone unit-test handlers have the attributes
        # present without a cache wired.
        self._arp_cache = None
        self._nd_cache = None

        # Initialize data stores for packet statistics. When the
        # caller supplies pre-constructed stats objects (the
        # 'stack.init()' path does this so the rings can share
        # them), reuse — otherwise default to fresh instances for
        # standalone unit-test callers.
        self._packet_stats_rx = packet_stats_rx if packet_stats_rx is not None else PacketStatsRx()
        self._packet_stats_tx = packet_stats_tx if packet_stats_tx is not None else PacketStatsTx()
        # Link-level aggregate counters (bytes / multicast) bumped
        # by the rings at frame receive / send time. Sharing the
        # same instance across PacketHandler + RxRing + TxRing
        # mirrors the 'packet_stats_*' pattern; consumers read via
        # 'stack.link.stats'.
        self._link_stats = link_stats if link_stats is not None else LinkStatsCounters()

        # Initialize the interface mtu.
        self._interface_mtu = interface_mtu

        # Record the interface name as plumbed through by
        # 'stack.init()' (None when the harness skips this).
        # Read by the Link API's 'name' property; not used by
        # the packet-handling paths.
        self._interface_name = interface_name

        # Initialize support for IPv6 and IPv4 protocols.
        self._ip6_support = ip6_support
        self._ip4_support = ip4_support

        # Used to assign IP addresses to the stack.
        self._ip6_ifaddr_candidate = []
        self._ip4_ifaddr_candidate = []

        # Used to keep track of IPv6 and IPv4 unicast addresses.
        self._ip6_ifaddr = []
        self._ip4_ifaddr = []

        # Used to keep track of IPv6 and IPv4 multicast addresses.
        self._ip6_multicast = []
        self._ip4_multicast = []

        # IPv4 Identification counter (last value) + its lock. The
        # IPv6 Fragment Identification is generated fresh per
        # datagram as a loop-local in '_phtx_ip6_frag', so there is
        # no IPv6 counter to store here.
        self._ip4_id: int = 0
        self._lock__ip4_id = threading.Lock()

        # Used to defragment IPv4 and IPv6 packets.
        self._ip4_frag_table = IpFragTable(timeout=stack.IP4__FRAG_FLOW_TIMEOUT)
        self._ip6_frag_table = IpFragTable(timeout=stack.IP6__FRAG_FLOW_TIMEOUT)

        # Used for IPv4 and IPv6 address configuration.
        self._ip_configuration_in_progress: Semaphore = threading.Semaphore(0)

        # RFC 4429 §3.1 Optimistic DAD per-address state map.
        # Populated by the DAD-claim path; consulted by the NA
        # emit path to clear the Override flag on outbound NAs
        # whose source is in OPTIMISTIC state per §3.3.
        self._icmp6_dad__states: dict[Ip6Address, Icmp6DadState] = {}

        # Flips True at the end of '_create_stack_ip6_addressing'.
        # Gates runtime stable-SLAAC claim in the RX path: a
        # PI for a new prefix that arrives DURING the boot
        # window updates the SLAAC tracking table only (the
        # boot loop owns the claim ordering); a PI that
        # arrives AFTER the boot window also spawns a fresh
        # '_claim_ip6_address_async' worker.
        self._ip6_addressing_complete: bool = False

        # Assign IP addresses statically.
        if ip6_host is not None:
            self._ip6_ifaddr_candidate.append(ip6_host)

        if ip4_host is not None:
            self._ip4_ifaddr_candidate.append(ip4_host)

    def _marshal_tx(self, run: Callable[[], TxStatus], /) -> TxStatus:
        """
        Marshal a '_phtx_*' pipeline call onto this interface's TX
        worker thread (ring-handoff single-writer) and return its
        'TxStatus'. Every stack-originated or stack-generated TX
        operation — socket sends, RX-thread replies, timer-thread
        retransmits, neighbor solicitations / advertisements —
        funnels through here so the per-interface TX state
        ('_ip4_id', stat counters, the ifaddr lists read during
        assembly) is written by one thread only. 'TxRing.dispatch'
        runs the call inline when there is no live worker (unit-test
        / boot path) or when the caller is already the worker (a
        re-entrant solicitation emitted mid-pipeline), so wrapping
        every entry point is safe even when they nest.
        """

        assert self._tx_ring is not None, "PacketHandler must have an injected TX ring to send."
        return self._tx_ring.dispatch(run)

    def _marshal_tx_async(self, run: Callable[[], TxStatus], /) -> None:
        """
        Fire-and-forget variant of '_marshal_tx' (Phase 4b async
        send): hand a '_phtx_*' call to this interface's TX worker
        and return immediately without waiting for the 'TxStatus'.
        The UDP / raw socket send paths use this so the application
        thread is not blocked on the worker; the datagram is
        "accepted into the stack" the moment it is queued, matching
        Linux's queued-on-send UDP semantics. Delivery failures
        (no route, ARP timeout, ICMP error) surface asynchronously,
        not through the send() return value.
        """

        assert self._tx_ring is not None, "PacketHandler must have an injected TX ring to send."
        self._tx_ring.dispatch_async(run)

    @property
    def _ip6_unicast(self) -> list[Ip6Address]:
        """
        Get the list of stack's IPv6 unicast addresses.
        """

        return [ip6_host.address for ip6_host in self._ip6_ifaddr]

    @property
    def _ip4_unicast(self) -> list[Ip4Address]:
        """
        Get the list of stack's IPv4 unicast addresses.
        """

        return [ip4_host.address for ip4_host in self._ip4_ifaddr]

    @property
    def _ip4_broadcast(self) -> list[Ip4Address]:
        """
        Get the list of stack's IPv4 broadcast addresses.
        """

        ip4_broadcast = [ip4_host.network.broadcast for ip4_host in self._ip4_ifaddr]
        ip4_broadcast.append(Ip4Address(0xFFFFFFFF))

        return ip4_broadcast

    @override
    def _start(self) -> None:
        """
        Perform additional actions after starting the subsystem thread.
        """

        self._acquire_ip4_addresses()
        self._acquire_ip6_addresses()

        self._log_stack_address_info()

    def _thread__packet_handler__acquire_ip6_addresses(self) -> None:
        """
        Thread to acquire the IPv6 addresses.
        """

        __debug__ and log("stack", "Started the IPv6 address acquire thread")

        self._create_stack_ip6_addressing()

        self._ip_configuration_in_progress.release()

        __debug__ and log("stack", "Finished the IPv6 address acquire thread")

    def _thread__packet_handler__acquire_ip4_addresses(self) -> None:
        """
        Thread to acquire the IPv4 addresses.
        """

        __debug__ and log("stack", "Started the IPv4 address acquire thread")

        self._create_stack_ip4_addressing()

        self._ip_configuration_in_progress.release()

        __debug__ and log("stack", "Finished the IPv4 address acquire thread")

    @abstractmethod
    def _create_stack_ip6_addressing(self) -> None:
        """
        Create lists of IPv6 unicast and multicast addresses stack
        should listen on.
        """

        raise NotImplementedError

    @abstractmethod
    def _create_stack_ip4_addressing(self) -> None:
        """
        Create lists of IPv4 unicast, multicast and broadcast addresses stack
        should listen on.
        """

        raise NotImplementedError

    def _acquire_ip6_addresses(self) -> None:
        """
        Start thread to acquire the IPv6 addresses.
        """

        __debug__ and log("stack", "Starting the IPv6 address acquire thread")

        threading.Thread(
            target=self._thread__packet_handler__acquire_ip6_addresses,
            daemon=True,
        ).start()

    def _acquire_ip4_addresses(self) -> None:
        """
        Start thread to acquire the IPv4 addresses.
        """

        __debug__ and log("stack", "Starting the IPv4 address acquire thread")

        threading.Thread(
            target=self._thread__packet_handler__acquire_ip4_addresses,
            daemon=True,
        ).start()

    def _assign_ip6_host(self, /, ip6_host: Ip6IfAddr) -> None:
        """
        Assign IPv6 host unicast  address to the list stack listens on.
        """

        self._ip6_ifaddr.append(ip6_host)

        __debug__ and log("stack", f"Assigned IPv6 unicast address {ip6_host}")

        self._assign_ip6_multicast(ip6_host.address.solicited_node_multicast)

    def _remove_ip6_host(self, /, ip6_host: Ip6IfAddr) -> None:
        """
        Remove IPv6 host unicast address from the list stack listens on.
        """

        self._ip6_ifaddr.remove(ip6_host)

        __debug__ and log("stack", f"Removed IPv6 unicast address {ip6_host}")

        self._remove_ip6_multicast(ip6_host.address.solicited_node_multicast)

    @abstractmethod
    def _claim_ip6_address_async(
        self,
        *,
        ip6_host: Ip6IfAddr,
        regenerate: Callable[[], Ip6IfAddr] | None = None,
    ) -> threading.Thread:
        """
        Claim 'ip6_host' on a daemon worker thread (DAD on L2,
        direct assign on L3). Returns the worker so callers
        that need to wait can '.join()'.

        When 'regenerate' is supplied, on DAD failure the
        worker calls it up to 'icmp6.idgen_retries' times to
        get a fresh candidate (RFC 7217 §6 / RFC 8981 §3.3.3).
        Each retry runs a full DAD cycle; the worker installs
        the first candidate that passes.
        """

        raise NotImplementedError

    @abstractmethod
    def _assign_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Assign IPv6 multicast address to the list stack listens on.
        """

        raise NotImplementedError

    @abstractmethod
    def _remove_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Remove IPv6 multicast address from the list stack listens on.
        """

        raise NotImplementedError

    def _assign_ip4_host(self, /, ip4_host: Ip4IfAddr) -> None:
        """
        Assign IPv6 host unicast  address to the list stack listens on.
        """

        self._ip4_ifaddr.append(ip4_host)

        __debug__ and log("stack", f"Assigned IPv4 unicast address {ip4_host}")

    def _remove_ip4_host(self, /, ip4_host: Ip4IfAddr) -> None:
        """
        Remove IPv4 host unicast address from the list stack listens on.
        """

        self._ip4_ifaddr.remove(ip4_host)

        __debug__ and log("stack", f"Removed IPv4 unicast address {ip4_host}")

    def _log_stack_address_info(self) -> None:
        """
        Log all the addresses stack will listen on
        """

        for _ in (self._ip6_support, self._ip4_support):
            self._ip_configuration_in_progress.acquire(timeout=15)

        if __debug__:
            if self._ip6_support:
                log(
                    "stack",
                    "<INFO>Stack listening on unicast IPv6 addresses: "
                    f"{', '.join([str(ip6_unicast) for ip6_unicast in self.ip6_unicast])}</>",
                )
                log(
                    "stack",
                    "<INFO>Stack listening on multicast IPv6 addresses: "
                    f"{', '.join([str(ip6_multicast) for ip6_multicast in set(self._ip6_multicast)])}</>",
                )

            if self._ip4_support:
                log(
                    "stack",
                    "<INFO>Stack listening on unicast IPv4 addresses: "
                    f"{', '.join([str(ip4_unicast) for ip4_unicast in self._ip4_unicast])}</>",
                )
                log(
                    "stack",
                    "<INFO>Stack listening on multicast IPv4 addresses: "
                    f"{', '.join([str(ip4_multicast) for ip4_multicast in self._ip4_multicast])}</>",
                )
                log(
                    "stack",
                    "<INFO>Stack listening on broadcast IPv4 addresses: "
                    f"{', '.join([str(ip4_broadcast) for ip4_broadcast in self._ip4_broadcast])}</>",
                )

    ###
    # Public interface.
    ###

    @property
    def packet_stats_rx(self) -> PacketStatsRx:
        """
        Get the packet statistics for received packets.
        """

        return self._packet_stats_rx

    @property
    def packet_stats_tx(self) -> PacketStatsTx:
        """
        Get the packet statistics for transmitted packets.
        """

        return self._packet_stats_tx

    @property
    def ip6_host(self) -> list[Ip6IfAddr]:
        """
        Get the list of stack's IPv4 host addresses.
        """

        return self._ip6_ifaddr

    @property
    def ip6_unicast(self) -> list[Ip6Address]:
        """
        Get the list of stack's IPv6 unicast addresses.
        """

        return self._ip6_unicast

    @property
    def ip4_host(self) -> list[Ip4IfAddr]:
        """
        Get the list of stack's IPv4 host addresses.
        """

        return self._ip4_ifaddr

    @property
    def ip4_unicast(self) -> list[Ip4Address]:
        """
        Get the list of stack's IPv4 unicast addresses.
        """

        return self._ip4_unicast

    @property
    def ip4_broadcast(self) -> list[Ip4Address]:
        """
        Get the list of stack's IPv4 broadcast addresses.
        """

        return self._ip4_broadcast

    def _update_icmp6_default_router(
        self,
        *,
        address: Ip6Address,
        router_lifetime: int,
        prf: Icmp6NdRoutePreference = Icmp6NdRoutePreference.MEDIUM,
    ) -> None:
        """
        Apply an inbound RA's Router Lifetime to the default-
        router list per RFC 4861 §6.3.4. A non-zero lifetime
        installs / refreshes the entry; a zero lifetime removes
        it. The RFC 4191 Default Router Preference is captured
        on the entry; RFC 4191 §2.2 mandates that a RESERVED
        (binary 10) advertisement be normalised to MEDIUM at the
        receiver. Bumps 'update_router' or 'remove_router'
        counters only when the list actually changes.
        """

        existing = next(
            (r for r in self._icmp6_default_routers if r.address == address),
            None,
        )

        # Phase 3 of docs/refactor/routing_table_host_mode.md:
        # the RA's router lifetime drives the host-mode FIB
        # default route. This is the single chokepoint where RA
        # router info is consumed — the per-IfAddr
        # 'ip6_host.gateway = ...' writes the SLAAC / RFC 8981 /
        # RFC 7217 paths used are gone (the FIB owns the next
        # hop). The injected '_route_api' may be None in reduced
        # test contexts that drive this without a Route API bound.
        route_api = self._route_api

        if router_lifetime > 0:
            normalised_prf = Icmp6NdRoutePreference.MEDIUM if prf is Icmp6NdRoutePreference.RESERVED else prf
            self._icmp6_default_routers = [r for r in self._icmp6_default_routers if r.address != address]
            self._icmp6_default_routers.append(
                Icmp6DefaultRouter(
                    address=address,
                    lifetime=router_lifetime,
                    expires_at=time.monotonic() + router_lifetime,
                    prf=normalised_prf,
                ),
            )
            self._packet_stats_rx.icmp6__nd_router_advertisement__update_router += 1
            if route_api is not None:
                route_api.replace_default_ip6(gateway=address, protocol=RouteProtocol.RA)
            return

        if existing is not None:
            self._icmp6_default_routers = [r for r in self._icmp6_default_routers if r.address != address]
            self._packet_stats_rx.icmp6__nd_router_advertisement__remove_router += 1
            if route_api is not None:
                route_api.remove_default_ip6()

    def get_icmp6_default_routers(self) -> list[Icmp6DefaultRouter]:
        """
        Get the list of currently-active default-router entries
        per RFC 4861 §6.3.4 sorted by RFC 4191 preference
        (HIGH > MEDIUM > LOW) so a TX-side consumer that picks
        the first valid entry naturally selects the most-
        preferred router. Lazy-aged: entries whose 'expires_at'
        deadline has passed are filtered out at access time
        instead of removed by a background sweep.
        """

        now = time.monotonic()
        prf_rank = {
            Icmp6NdRoutePreference.HIGH: 0,
            Icmp6NdRoutePreference.MEDIUM: 1,
            Icmp6NdRoutePreference.LOW: 2,
        }
        active = [r for r in self._icmp6_default_routers if r.expires_at > now]
        # 'RESERVED' was normalised to MEDIUM at install time; the
        # rank dict has no entry for it, so a defensive fallback
        # places any stray RESERVED at MEDIUM rank.
        active.sort(key=lambda r: prf_rank.get(r.prf, prf_rank[Icmp6NdRoutePreference.MEDIUM]))
        return active

    def _update_icmp6_slaac_address(
        self,
        *,
        prefix: Ip6Network,
        valid_lifetime: int,
        preferred_lifetime: int,
        router_address: Ip6Address,
    ) -> None:
        """
        Apply an inbound Prefix-Information option to the SLAAC
        address table per RFC 4862 §5.5.3. A non-zero
        'valid_lifetime' installs / refreshes the entry; zero
        'valid_lifetime' removes a matching entry (the §5.5.3
        (e)(6)(a) "advertised lifetime overwrites address valid
        lifetime" rule collapses to removal at value 0). The
        2-hour rule (e)(6)(b)/(c) clamps refresh on existing
        entries: an unauthenticated router cannot shorten an
        address's remaining lifetime below 2 hours unless the
        existing remaining is already ≤ 2 hours. Bumps
        'pi__update_address' / 'pi__remove_address' /
        'pi__2hour_rule_ignored__drop' counters per the path
        actually taken.
        """

        existing = next(
            (a for a in self._icmp6_slaac_addresses if a.prefix == prefix),
            None,
        )

        if valid_lifetime == 0:
            if existing is not None:
                self._icmp6_slaac_addresses = [a for a in self._icmp6_slaac_addresses if a.prefix != prefix]
                self._packet_stats_rx.icmp6__nd_router_advertisement__pi__remove_address += 1
            return

        now = time.monotonic()

        # RFC 4862 §5.5.3 (e)(6) 2-hour rule. Only applies on
        # refresh (existing is not None); first-install bypasses
        # the safeguard entirely. PyTCP has no SEND support so
        # case (b) is unconditional.
        new_valid_lifetime = valid_lifetime
        if existing is not None:
            remaining = existing.valid_until - now
            two_hour_s = nd__constants.ICMP6__SLAAC__TWO_HOUR_RULE_S
            if valid_lifetime > two_hour_s or valid_lifetime > remaining:
                new_valid_lifetime = valid_lifetime
            elif remaining <= two_hour_s:
                self._packet_stats_rx.icmp6__nd_router_advertisement__pi__2hour_rule_ignored__drop += 1
                return
            else:
                new_valid_lifetime = two_hour_s

        address = self._derive_ip6_host(ip6_network=prefix).address

        self._icmp6_slaac_addresses = [a for a in self._icmp6_slaac_addresses if a.prefix != prefix]
        self._icmp6_slaac_addresses.append(
            Icmp6SlaacAddress(
                address=address,
                prefix=prefix,
                preferred_until=now + preferred_lifetime,
                valid_until=now + new_valid_lifetime,
                router_address=router_address,
            ),
        )
        self._packet_stats_rx.icmp6__nd_router_advertisement__pi__update_address += 1

        # Runtime stable-address claim: a brand-new prefix
        # admitted AFTER boot-time addressing completed needs
        # a DAD claim — boot loop only handles prefixes that
        # arrived during the boot window. The
        # '_ip6_addressing_complete' flag gates this so the
        # boot loop's own claim path doesn't double up. On
        # refresh ('existing is not None') no claim is needed
        # — the stable address is already in '_ip6_ifaddr'.
        if existing is None and self._ip6_addressing_complete:
            ip6_host = Ip6IfAddr((address, Ip6Mask("/64")))
            self._claim_ip6_address_async(
                ip6_host=ip6_host,
                regenerate=self._make_rfc7217_regenerator(ip6_network=prefix),
            )

    def get_icmp6_slaac_addresses(self) -> list[Icmp6SlaacAddress]:
        """
        Get the list of currently-active SLAAC address entries
        per RFC 4862 §5.5.3. Lazy-aged: entries whose
        'valid_until' deadline has passed are filtered out at
        access time instead of removed by a background sweep.
        """

        now = time.monotonic()
        return [a for a in self._icmp6_slaac_addresses if a.valid_until > now]

    def _update_icmp6_temp_address(
        self,
        *,
        prefix: Ip6Network,
        valid_lifetime: int,
        preferred_lifetime: int,
        router_address: Ip6Address,
    ) -> None:
        """
        Apply an inbound Prefix-Information option to the
        RFC 8981 §3 temporary-address table. No-op when
        'icmp6.use_tempaddr=0'. Otherwise:

        - 'valid_lifetime=0' removes any existing entry for
          the prefix (RFC 4862 §5.5.3 (e)(4) interaction
          applied to the temp table).
        - Existing entry: refresh the 'preferred_until' /
          'valid_until' deadlines but preserve the address
          (regeneration is §18c, not §18b).
        - New entry: generate a random IID via
          'Ip6IfAddr.from_rfc8981_temp', spawn an async DAD
          claim via '_claim_ip6_address_async', and append
          to '_icmp6_temp_addresses'.

        Lifetimes are clamped to TEMP_VALID_LIFETIME /
        TEMP_PREFERRED_LIFETIME (RFC 8981 §3.4 / §3.8). The
        preferred deadline is further offset by a random
        DESYNC_FACTOR to prevent fleet-wide synchronised
        regeneration; the §18c regeneration subsystem will
        consume the offset to schedule rotation.
        """

        if nd__constants.ICMP6__USE_TEMPADDR == 0:
            return

        existing = next(
            (t for t in self._icmp6_temp_addresses if t.prefix == prefix),
            None,
        )

        if valid_lifetime == 0:
            if existing is not None:
                self._icmp6_temp_addresses = [t for t in self._icmp6_temp_addresses if t.prefix != prefix]
            return

        # RFC 8981 §3.4 lifetime clamps. The preferred lifetime
        # is reduced by a random DESYNC_FACTOR offset so a fleet
        # of hosts created together don't all rotate at the same
        # instant.
        now = time.monotonic()
        desync = random.uniform(0, nd__constants.ICMP6__MAX_DESYNC_FACTOR_S)
        clamped_valid = min(valid_lifetime, nd__constants.ICMP6__TEMP_VALID_LIFETIME_S)
        clamped_preferred_base = min(preferred_lifetime, nd__constants.ICMP6__TEMP_PREFERRED_LIFETIME_S)
        clamped_preferred = max(0.0, clamped_preferred_base - desync)

        if existing is not None:
            # Refresh deadlines, preserve address. Drop the old
            # entry and append a new one with the same address.
            refreshed = Icmp6TempAddress(
                address=existing.address,
                prefix=prefix,
                preferred_until=now + clamped_preferred,
                valid_until=now + clamped_valid,
                created_at=existing.created_at,
                router_address=router_address,
            )
            self._icmp6_temp_addresses = [t for t in self._icmp6_temp_addresses if t.prefix != prefix]
            self._icmp6_temp_addresses.append(refreshed)
            return

        # New entry — generate random IID, spawn DAD claim.
        try:
            temp_host = Ip6IfAddr.from_rfc8981_temp(ip6_network=prefix)
        except RuntimeError:
            # Reserved-IID retry exhaustion (broken random
            # source). Skip the temp address; the stable SLAAC
            # entry still carries the prefix.
            return

        self._icmp6_temp_addresses.append(
            Icmp6TempAddress(
                address=temp_host.address,
                prefix=prefix,
                preferred_until=now + clamped_preferred,
                valid_until=now + clamped_valid,
                created_at=now,
                router_address=router_address,
            ),
        )

        # RFC 8981 §3.3.3 — on DAD failure, retry with a fresh
        # random IID up to 'icmp6.idgen_retries' times. Each
        # call to 'from_rfc8981_temp' yields a different IID
        # (no 'dad_counter' is needed; the random generator is
        # stateless).
        def _regenerate() -> Ip6IfAddr:
            return Ip6IfAddr.from_rfc8981_temp(ip6_network=prefix)

        # Spawn async DAD claim. The worker will assign the
        # address into '_ip6_ifaddr' on success or fall through
        # to the failure path on collision (where retries
        # exhaust before the temp-table entry is left
        # orphaned).
        self._claim_ip6_address_async(ip6_host=temp_host, regenerate=_regenerate)

    def get_icmp6_temp_addresses(self) -> list[Icmp6TempAddress]:
        """
        Get the list of currently-active RFC 8981 temporary
        addresses. Lazy-aged: entries whose 'valid_until'
        deadline has passed are filtered out at access time
        instead of removed by a background sweep.
        """

        now = time.monotonic()
        return [t for t in self._icmp6_temp_addresses if t.valid_until > now]

    def _icmp6_sweep_temp_addresses(self) -> None:
        """
        Remove temporary addresses whose 'valid_until'
        deadline has passed from BOTH '_icmp6_temp_addresses'
        AND '_ip6_ifaddr'. The lazy accessor
        ('get_icmp6_temp_addresses') already filters out
        expired entries at read time, but '_ip6_ifaddr' is the
        hot list that the RX dispatch and TX source-address
        selection both walk directly — leaving expired
        entries there would mean the host kept receiving on
        and sourcing from addresses whose valid lifetime has
        elapsed.

        Invoked periodically from the subsystem loop, rate-
        limited by 'icmp6.temp_addr_sweep_interval_s'.

        Reference: RFC 8981 §3.4 (expired temp address must
                                  not be used for new traffic).
        """

        now = time.monotonic()
        expired = [t for t in self._icmp6_temp_addresses if t.valid_until <= now]
        if not expired:
            return

        for entry in expired:
            __debug__ and log(
                "stack",
                f"<INFO>RFC 8981 sweep: temp address {entry.address} "
                f"(prefix {entry.prefix}) past valid_until — removing</>",
            )
            # Drop from '_ip6_ifaddr'. The address may already
            # be absent (e.g. if a manual operator action
            # removed it). The solicited-node multicast may
            # already be absent too (manual cleanup, never
            # joined). Both are tolerated — best-effort.
            for ip6_host in list(self._ip6_ifaddr):
                if ip6_host.address == entry.address:
                    self._ip6_ifaddr.remove(ip6_host)
                    snm = ip6_host.address.solicited_node_multicast
                    if snm in self._ip6_multicast:
                        self._remove_ip6_multicast(snm)
                    break

        # Drop from the temp-address table.
        self._icmp6_temp_addresses = [t for t in self._icmp6_temp_addresses if t.valid_until > now]

    def _icmp6_regen_temp_addresses(self) -> None:
        """
        For each prefix represented in '_icmp6_temp_addresses',
        check whether the newest entry is approaching its
        REGEN_ADVANCE threshold (preferred_until - REGEN_ADVANCE
        <= now). If so, mint a fresh random IID for the same
        prefix and append it to the table — both the old and
        new entries coexist during the rotation-overlap window
        per RFC 8981 §3.4. Skip prefixes where a sibling entry
        is already past the regen threshold (the regen has
        already happened).

        No-op when 'icmp6.use_tempaddr=0'.

        Reference: RFC 8981 §3.4 (regenerate REGEN_ADVANCE
                                  before preferred lifetime
                                  expires).
        """

        if nd__constants.ICMP6__USE_TEMPADDR == 0:
            return
        if not self._icmp6_temp_addresses:
            return

        now = time.monotonic()
        regen_advance_s = nd__constants.ICMP6__REGEN_ADVANCE_S

        # Group entries by prefix; for each prefix, find the
        # newest 'preferred_until'. If that newest entry is at
        # or past its regen-advance threshold, regenerate.
        prefixes_seen: set[Ip6Network] = set()
        for entry in list(self._icmp6_temp_addresses):
            prefix = entry.prefix
            if prefix in prefixes_seen:
                continue
            prefixes_seen.add(prefix)

            siblings = [t for t in self._icmp6_temp_addresses if t.prefix == prefix]
            newest = max(siblings, key=lambda t: t.preferred_until)

            # If the newest is far from the regen threshold,
            # nothing to do for this prefix.
            if newest.preferred_until - regen_advance_s > now:
                continue

            # Mint a fresh random IID for the same prefix.
            try:
                temp_host = Ip6IfAddr.from_rfc8981_temp(ip6_network=prefix)
            except RuntimeError:
                continue

            # Append a NEW entry alongside (not replacing) the
            # existing one. Lifetimes derived from the same
            # TEMP_*_LIFETIME ceilings as §18b.
            desync = random.uniform(0, nd__constants.ICMP6__MAX_DESYNC_FACTOR_S)
            clamped_valid = nd__constants.ICMP6__TEMP_VALID_LIFETIME_S
            clamped_preferred = max(0.0, nd__constants.ICMP6__TEMP_PREFERRED_LIFETIME_S - desync)

            self._icmp6_temp_addresses.append(
                Icmp6TempAddress(
                    address=temp_host.address,
                    prefix=prefix,
                    preferred_until=now + clamped_preferred,
                    valid_until=now + clamped_valid,
                    created_at=now,
                    router_address=newest.router_address,
                ),
            )

            # RFC 8981 §3.3.3 regen via §20.3 retry: each retry
            # mints a fresh random IID.
            def _regenerate(p: Ip6Network = prefix) -> Ip6IfAddr:
                return Ip6IfAddr.from_rfc8981_temp(ip6_network=p)

            __debug__ and log(
                "stack",
                f"<INFO>RFC 8981 regen: minting new temp address {temp_host} "
                f"for prefix {prefix} (existing {newest.address} approaching "
                "preferred-lifetime expiry)</>",
            )
            self._claim_ip6_address_async(ip6_host=temp_host, regenerate=_regenerate)

    def _icmp6_sweep_slaac_addresses(self) -> None:
        """
        Remove stable SLAAC entries past 'valid_until' from
        BOTH '_icmp6_slaac_addresses' AND '_ip6_ifaddr'. The
        lazy accessor 'get_icmp6_slaac_addresses()' already
        filters expired entries at read time, but '_ip6_ifaddr'
        is the hot list TX and RX walk directly — the stable
        address must be pruned there too once its valid
        lifetime has elapsed.

        Invoked periodically from '_maybe_run_periodic_tasks'
        alongside the §18c.1 temp-address sweep.

        Reference: RFC 4862 §5.5.3 (e)(7) (expired stable
                                           address must not
                                           be used).
        """

        now = time.monotonic()
        expired = [a for a in self._icmp6_slaac_addresses if a.valid_until <= now]
        if not expired:
            return

        for entry in expired:
            __debug__ and log(
                "stack",
                f"<INFO>SLAAC sweep: stable address {entry.address} "
                f"(prefix {entry.prefix}) past valid_until — removing</>",
            )
            for ip6_host in list(self._ip6_ifaddr):
                if ip6_host.address == entry.address:
                    self._ip6_ifaddr.remove(ip6_host)
                    snm = ip6_host.address.solicited_node_multicast
                    if snm in self._ip6_multicast:
                        self._remove_ip6_multicast(snm)
                    break

        self._icmp6_slaac_addresses = [a for a in self._icmp6_slaac_addresses if a.valid_until > now]

    def get_icmp6_default_router_for_destination(
        self,
        *,
        destination: Ip6Address,
    ) -> Icmp6DefaultRouter | None:
        """
        Pick a default router for outbound traffic to
        'destination' using deterministic per-destination
        distribution across the highest-preference equivalence
        class per RFC 4311 §3 host-to-router load sharing.

        The same destination always selects the same router so
        TCP flows aren't reordered, but distinct destinations
        spread across all highest-preference routers (preserving
        the §14 RFC 4191 preference rule — a LOW router never
        gets traffic when a HIGH router is available). The
        index is computed as
        'int(destination) % len(highest_preference_set)'.

        Returns None when no default routers are tracked.

        Reference: RFC 4311 §3 (per-destination load sharing).
        Reference: RFC 4191 §2.1 (preference precedence).
        """

        active_routers = self.get_icmp6_default_routers()
        if not active_routers:
            return None

        # 'get_icmp6_default_routers()' returns the active list
        # sorted by §14 preference (HIGH > MEDIUM > LOW). The
        # highest-preference equivalence class is the prefix of
        # entries sharing the head's prf value.
        head_prf = active_routers[0].prf
        candidates = [r for r in active_routers if r.prf == head_prf]

        index = int(destination) % len(candidates)
        return candidates[index]

    def get_icmp6_default_router_for_source(
        self,
        *,
        source: Ip6Address,
    ) -> Icmp6DefaultRouter | None:
        """
        Pick the default router whose RA-advertised prefix
        covers 'source', falling back to the highest-preference
        default router when no source-matching entry exists per
        RFC 8028 §3 first-hop selection in multi-prefix
        networks. Returns None when no default routers are
        tracked.

        The host MUST emit a packet whose source is in ISP A's
        prefix via ISP A's router (not via a randomly-picked
        default), otherwise the upstream anti-spoofing filter
        drops it.

        Reference: RFC 8028 §3 (first-hop selection by source).
        """

        active_routers = self.get_icmp6_default_routers()
        if not active_routers:
            return None

        # Find the SLAAC entry whose address equals 'source';
        # its 'router_address' names the announcing router.
        slaac_entry = next(
            (a for a in self._icmp6_slaac_addresses if a.address == source),
            None,
        )
        if slaac_entry is not None:
            for router in active_routers:
                if router.address == slaac_entry.router_address:
                    return router

        # No SLAAC binding — fall back to the highest-preference
        # router (the accessor returns the list pre-sorted).
        return active_routers[0]

    def get_icmp6_dad_state(self, *, address: Ip6Address) -> Icmp6DadState | None:
        """
        Get the per-address Duplicate Address Detection state
        (RFC 4862 §5.4 + RFC 4429 §3.1). Returns None when no
        DAD activity has been recorded for 'address' — either
        the host never started DAD on it or DAD failed and the
        entry was cleaned up. The NA emit path consults this
        accessor to clear the Override flag for OPTIMISTIC
        sources per RFC 4429 §3.3.
        """

        return self._icmp6_dad__states.get(address)

    def get_icmp6_slaac_address_state(
        self,
        *,
        prefix: Ip6Network,
    ) -> Icmp6SlaacAddressState | None:
        """
        Get the lifecycle state of the SLAAC address derived
        from the given prefix per RFC 4862 §5.5.4. Returns
        None when no entry exists or when the entry has been
        REMOVED (valid_until passed).
        """

        now = time.monotonic()
        entry = next(
            (a for a in self._icmp6_slaac_addresses if a.prefix == prefix),
            None,
        )
        if entry is None:
            return None
        return entry.state(now)

    def _update_icmp6_ra_parameters(
        self,
        *,
        cur_hop_limit: int,
        reachable_time_ms: int,
        retrans_timer_ms: int,
    ) -> None:
        """
        Apply the three RA-header host-parameter fields to
        '_icmp6_ra_parameters' per RFC 4861 §6.3.4. Each field
        with value 0 is "unspecified by this router" per §4.2
        and MUST NOT overwrite the existing host value. The
        Cur-Hop-Limit advertisement is additionally floored by
        'icmp6.accept_ra_min_hop_limit' (Linux parity).
        """

        prior = self._icmp6_ra_parameters
        new_hop = prior.cur_hop_limit
        new_reach = prior.reachable_time_ms
        new_retrans = prior.retrans_timer_ms

        if cur_hop_limit > 0:
            if cur_hop_limit >= nd__constants.ICMP6__ACCEPT_RA_MIN_HOP_LIMIT:
                new_hop = cur_hop_limit
                self._packet_stats_rx.icmp6__nd_router_advertisement__cur_hop_limit__update += 1
            else:
                self._packet_stats_rx.icmp6__nd_router_advertisement__cur_hop_limit__floor__drop += 1

        if reachable_time_ms > 0:
            new_reach = reachable_time_ms
            self._packet_stats_rx.icmp6__nd_router_advertisement__reachable_time__update += 1
            # RFC 4861 §6.3.4 wires the captured value through
            # to this interface's IPv6 NUD cache as a per-cache
            # override; ARP is unaffected. Guarded for the early-RX
            # path where the ND cache has not yet been injected
            # (test fixtures, mock__init).
            if self._nd_cache is not None:
                self._nd_cache.set_reachable_time_override_ms(reachable_time_ms)

        if retrans_timer_ms > 0:
            new_retrans = retrans_timer_ms
            self._packet_stats_rx.icmp6__nd_router_advertisement__retrans_timer__update += 1

        self._icmp6_ra_parameters = Icmp6RaParameters(
            cur_hop_limit=new_hop,
            reachable_time_ms=new_reach,
            retrans_timer_ms=new_retrans,
        )

    def get_icmp6_ra_parameters(self) -> Icmp6RaParameters:
        """
        Get the most recent RA-header parameter snapshot per
        RFC 4861 §6.3.4. Each field is None until the host has
        observed at least one RA carrying a non-zero (and floor-
        passing) advertisement of that field.
        """

        return self._icmp6_ra_parameters

    def _derive_ip6_host(self, *, ip6_network: Ip6Network) -> Ip6IfAddr:
        """
        Derive the host's IPv6 address for 'ip6_network' using
        either RFC 7217 stable opaque IIDs (default; modern
        Linux equivalent of 'addr_gen_mode = 2') or legacy
        EUI-64. Selection is gated by the 'icmp6.use_rfc7217'
        sysctl.

        Reference: RFC 7217 §5 (algorithm specification).
        Reference: RFC 4291 §2.5.1 (legacy EUI-64 fallback).
        """

        if nd__constants.ICMP6__USE_RFC7217:
            return Ip6IfAddr.from_rfc7217(
                ip6_network=ip6_network,
                mac_address=self._mac_unicast,
                secret_key=self._icmp6_slaac__secret_key,
            )
        return Ip6IfAddr.from_eui64(
            mac_address=self._mac_unicast,
            ip6_network=ip6_network,
        )

    def _make_rfc7217_regenerator(
        self,
        *,
        ip6_network: Ip6Network,
    ) -> Callable[[], Ip6IfAddr] | None:
        """
        Build a DAD-failure regenerator for an RFC 7217 stable
        opaque IID address (RFC 7217 §6 retry on collision).
        Each invocation re-derives with an incremented
        'dad_counter'. Returns None when EUI-64 derivation is
        active ('icmp6.use_rfc7217 = 0') because EUI-64 is
        deterministic from the MAC and re-derivation would
        produce the same address.
        """

        if not nd__constants.ICMP6__USE_RFC7217:
            return None

        counter = [0]

        def _regenerate() -> Ip6IfAddr:
            counter[0] += 1
            return Ip6IfAddr.from_rfc7217(
                ip6_network=ip6_network,
                mac_address=self._mac_unicast,
                secret_key=self._icmp6_slaac__secret_key,
                dad_counter=counter[0],
            )

        return _regenerate

    def _effective_ip6_hop_limit(self) -> int:
        """
        Get the effective default Hop Limit for outbound IPv6
        traffic per RFC 4861 §6.3.4: the most recent RA-
        advertised Cur-Hop-Limit if observed, otherwise the
        protocol default (RFC 8200 §3 — 64). Callers that
        protocol-mandate a specific value (e.g. ND with 255,
        MLD with 1) bypass this helper.
        """

        from net_proto import IP6__DEFAULT_HOP_LIMIT

        return self._icmp6_ra_parameters.cur_hop_limit or IP6__DEFAULT_HOP_LIMIT


class PacketHandlerL2(
    PacketHandler,
    PacketHandlerArpRx,
    PacketHandlerArpTx,
    PacketHandlerEthernetRx,
    PacketHandlerEthernetTx,
    PacketHandlerEthernet8023Rx,
    PacketHandlerEthernet8023Tx,
    PacketHandlerIcmp6Rx,
    PacketHandlerIcmp6Tx,
    PacketHandlerIcmp4Rx,
    PacketHandlerIcmp4Tx,
    PacketHandlerIp4Rx,
    PacketHandlerIp4Tx,
    PacketHandlerIp6Rx,
    PacketHandlerIp6Tx,
    PacketHandlerIp6FragRx,
    PacketHandlerIp6FragTx,
    PacketHandlerTcpRx,
    PacketHandlerTcpTx,
    PacketHandlerUdpRx,
    PacketHandlerUdpTx,
):
    """
    Pick up and respond to incoming packets on Layer 2 (TAP) interface.
    """

    _interface_layer = InterfaceLayer.L2

    _ip4_dhcp: bool
    _ip6_lla_autoconfig: bool
    _ip6_gua_autoconfig: bool
    _mac_unicast: MacAddress
    _mac_multicast: list[MacAddress]
    _mac_broadcast: MacAddress
    _icmp6_nd_dad__registry: DadSlotRegistry[Ip6Address]
    _icmp6_ra__prefixes: list[tuple[Ip6Network, Ip6Address]]
    _icmp6_ra__event: Semaphore
    _mld2_query__pending_response_at_ms: int | None
    _mld2_query__handle: TimerHandle | None

    @override
    def __init__(
        self,
        *,
        mac_address: MacAddress,
        interface_mtu: int,
        interface_name: str | None = None,
        ip4_support: bool = True,
        ip4_host: Ip4IfAddr | None = None,
        ip4_dhcp: bool = True,
        ip6_support: bool = True,
        ip6_host: Ip6IfAddr | None = None,
        ip6_lla_autoconfig: bool = True,
        ip6_gua_autoconfig: bool = True,
        rx_ring: RxRing | None = None,
        tx_ring: TxRing | None = None,
        packet_stats_rx: PacketStatsRx | None = None,
        packet_stats_tx: PacketStatsTx | None = None,
        link_stats: LinkStatsCounters | None = None,
    ) -> None:
        """
        Class constructor.
        """

        super().__init__(
            interface_mtu=interface_mtu,
            interface_name=interface_name,
            ip6_support=ip6_support,
            ip4_support=ip4_support,
            ip6_host=ip6_host,
            ip4_host=ip4_host,
            rx_ring=rx_ring,
            tx_ring=tx_ring,
            packet_stats_rx=packet_stats_rx,
            packet_stats_tx=packet_stats_tx,
            link_stats=link_stats,
        )

        self._ip4_dhcp = ip4_dhcp
        self._ip6_lla_autoconfig = ip6_lla_autoconfig
        self._ip6_gua_autoconfig = ip6_gua_autoconfig

        # MAC and IPv6 Multicast lists hold duplicate entries by design. This
        # is to accommodate IPv6 Solicited Node Multicast mechanism where
        # multiple IPv6 unicast addresses can be tied to the same SNM address
        # (and the same multicast MAC). This is important when removing one of
        # the unicast addresses, so the other ones keep it's SNM entry in the
        # multicast list. Its the simplest solution and imho perfectly valid
        # one in this case.
        self._mac_unicast = mac_address
        self._mac_multicast = []
        self._mac_broadcast = MacAddress(0xFFFFFFFFFFFF)

        # Used for the ICMPv6 ND DAD process. Per-address state
        # (events, peer TLLA capture, RFC 7527 Enhanced DAD
        # nonce trackers) lives in 'DadSlotRegistry[Ip6Address]'
        # so multiple addresses can DAD concurrently. The RX
        # path signals the right slot by inbound NS / NA
        # 'target_address'; an entry's presence means a worker
        # is in DAD for that address. The registry's internal
        # lock makes worker install / nonce-add / tear-down
        # atomic against the RX 'try_signal_conflict' call.
        self._icmp6_nd_dad__registry: DadSlotRegistry[Ip6Address] = DadSlotRegistry()

        # RFC 7217 §5 secret_key — generated once per process
        # at handler init. PyTCP doesn't persist this to disk;
        # an OS-style "stable_secret" file is out of scope. The
        # 128-bit minimum is per RFC 7217 §5.
        self._icmp6_slaac__secret_key = secrets.token_bytes(16)

        # Used for the ICMPv6 ND RA address auto configuration.
        self._icmp6_ra__prefixes: list[tuple[Ip6Network, Ip6Address]] = []
        self._icmp6_ra__event: Semaphore = threading.Semaphore(0)

        # RFC 3810 §5.1.10 deferred-Report state. Tracks the
        # absolute 'stack.timer.now_ms' at which the next
        # scheduled MLDv2 Report will fire on Query receipt;
        # None means no Report is pending. Coalesces multiple
        # inbound Queries: a Query whose computed response
        # time is later than the existing pending entry is
        # absorbed without rescheduling.
        self._mld2_query__pending_response_at_ms: int | None = None
        self._mld2_query__handle: TimerHandle | None = None

        # RFC 4861 §6.3.4 default-router list — entries learned
        # from inbound RAs, indexed implicitly by RA source link-
        # local. Lazy-aged: 'get_icmp6_default_routers()' filters
        # out entries whose 'expires_at' is in the past instead of
        # a background sweep, mirroring how Linux's
        # 'rt6_check_expired' is invoked on demand.
        self._icmp6_default_routers: list[Icmp6DefaultRouter] = []

        # RFC 4862 §5.5.3 SLAAC address table — per-address
        # preferred / valid lifetime state harvested from RA
        # Prefix-Information options, plus the per-address
        # lifecycle state (PREFERRED / DEPRECATED) computed
        # lazily from the deadlines per §5.5.4. Same lazy-ageing
        # pattern as the default-router list above.
        self._icmp6_slaac_addresses: list[Icmp6SlaacAddress] = []

        # RFC 8981 SLAAC temporary-address table — populated
        # alongside '_icmp6_slaac_addresses' when
        # 'icmp6.use_tempaddr' is non-zero. Each entry mints a
        # random-IID address via 'Ip6IfAddr.from_rfc8981_temp' and
        # claims it via the §20.1 async DAD worker. Lifetimes
        # are clamped to TEMP_*_LIFETIME at creation. Lazy-aged
        # like '_icmp6_slaac_addresses'.
        self._icmp6_temp_addresses: list[Icmp6TempAddress] = []

        # RFC 8981 §3.4 sweep timestamp — '_subsystem_loop'
        # rate-limits sweep invocations via this monotonic
        # timestamp. Initialised to 0.0 so the first iteration
        # of the loop runs the sweep immediately (which is
        # cheap on an empty table).
        self._last_temp_addr_sweep_at: float = 0.0

        # RFC 4861 §6.3.4 RA-header parameter mirror —
        # Cur-Hop-Limit, Reachable Time, Retrans Timer values
        # observed from the most recent RA carrying a non-zero
        # advertisement of each field. Phase 2: TX / NUD / DAD
        # consumers will fall back to these when set, otherwise
        # to operator-configured sysctl defaults.
        self._icmp6_ra_parameters: Icmp6RaParameters = Icmp6RaParameters(
            cur_hop_limit=None,
            reachable_time_ms=None,
            retrans_timer_ms=None,
        )

    @override
    def _subsystem_loop(self) -> None:
        """
        Pick up incoming packets from RX Ring and processes them.
        Also runs periodic housekeeping (RFC 8981 temp-address
        sweep) rate-limited by 'icmp6.temp_addr_sweep_interval_s'.
        """

        assert self._rx_ring is not None, "Started PacketHandler must have an injected RX ring."

        if (packet_rx := self._rx_ring.dequeue()) is not None:
            if int.from_bytes(packet_rx.frame[12:14]) <= ETHERNET_802_3__PACKET__MAX_LEN:
                self._phrx_ethernet_802_3(packet_rx)
            else:
                self._phrx_ethernet(packet_rx)

        self._maybe_run_periodic_tasks()

    def _maybe_run_periodic_tasks(self) -> None:
        """
        Run periodic housekeeping tasks at most once per
        'icmp6.temp_addr_sweep_interval_s' seconds. Both the
        RFC 8981 §3.4 cleanup sweep (§18c.1) and the
        regen-before-expiry mint (§18c.2) run here.
        """

        now = time.monotonic()
        interval = nd__constants.ICMP6__TEMP_ADDR_SWEEP_INTERVAL_S
        if now - self._last_temp_addr_sweep_at < interval:
            return
        self._last_temp_addr_sweep_at = now
        # Regen first so freshly-minted entries don't get
        # sweep-removed by an unlikely valid_until=now race
        # in the same tick (the cleanup sweep filters strictly
        # on valid_until <= now).
        self._icmp6_regen_temp_addresses()
        self._icmp6_sweep_temp_addresses()
        # Stable-SLAAC sweep — symmetric to the temp sweep,
        # for §12a.runtime lifecycle close-out.
        self._icmp6_sweep_slaac_addresses()

    def _send_icmp6_nd_router_solicitations_with_backoff(self) -> None:
        """
        Send up to 'icmp6.max_rtr_solicitations' Router
        Solicitations spaced by RFC 7559 §2 truncated binary
        exponential backoff with ±10% randomisation. Each
        inter-message wait is at least
        'icmp6.rtr_solicitation_interval_ms', doubles each
        round, and is capped at 'icmp6.rtr_solicitation_max_rt_ms'.
        Returns early on the first RA receipt (the RX handler
        releases '_icmp6_ra__event'). 'max_rtr_solicitations = 0'
        is the kill switch — no RS is emitted.
        """

        max_attempts = nd__constants.ICMP6__MAX_RTR_SOLICITATIONS
        if max_attempts <= 0:
            return

        rt_ms = nd__constants.ICMP6__RTR_SOLICITATION_INTERVAL_MS
        mrt_ms = nd__constants.ICMP6__RTR_SOLICITATION_MAX_RT_MS

        for _ in range(max_attempts):
            self._send_icmp6_nd_router_solicitation()
            wait_s = (rt_ms + random.uniform(-0.1, 0.1) * rt_ms) / 1000.0
            if self._icmp6_ra__event.acquire(timeout=wait_s):
                return
            rt_ms = min(2 * rt_ms, mrt_ms)

    def _perform_ip6_nd_dad(self, *, ip6_unicast_candidate: Ip6Address) -> bool:
        """
        Perform IPv6 ND Duplicate Address Detection, return True if passed.

        Per RFC 4862 §5.1 the host emits 'icmp6.dad_transmits'
        probes spaced by 'icmp6.retrans_timer_ms' milliseconds
        before declaring the address verified. A conflict event
        released at any point during the loop short-circuits
        further probing — the host MUST NOT continue once a
        duplicate has been signaled. 'dad_transmits = 0'
        disables DAD entirely (Linux parity).

        Per-address DAD state lives in '_icmp6_nd_dad__registry'
        ('DadSlotRegistry[Ip6Address]') keyed by the candidate
        address, so multiple addresses can DAD concurrently in
        separate worker threads. Each call installs its own
        slot on entry and tears it down on exit — the RX path
        looks up the slot by inbound NS / NA 'target_address'
        and signals the right Event. The candidate's lifecycle
        state is also recorded in '_icmp6_dad__states':
        TENTATIVE while probes are in flight, VALID on success,
        removed on conflict. The Optimistic-DAD helper
        '_claim_ip6_address_optimistic' overrides the TENTATIVE
        entry with OPTIMISTIC before invoking us so the NA emit
        path sees the relaxed Override-flag rule per RFC 4429
        §3.3.
        """

        __debug__ and log(
            "stack",
            f"ICMPv6 ND DAD - Starting process for {ip6_unicast_candidate}",
        )

        # 'icmp6.accept_dad=0' short-circuits DAD entirely:
        # candidate goes straight to VALID with no probes
        # emitted, no initial delay taken, and no per-address
        # DAD-state slot. Linux 'accept_dad=0' parity.
        if nd__constants.ICMP6__ACCEPT_DAD == 0:
            self._icmp6_dad__states[ip6_unicast_candidate] = Icmp6DadState.VALID
            return True

        # Per-address DAD slot. Populated BEFORE the first probe
        # TX so the RX dispatch can find this candidate's slot
        # when peer NS / NA arrives. The registry's internal
        # lock guarantees the RX path cannot observe a partial
        # install.
        dad_event = self._icmp6_nd_dad__registry.install(ip6_unicast_candidate)
        # Default to TENTATIVE; the Optimistic-DAD wrapper
        # promotes this to OPTIMISTIC before invoking us.
        self._icmp6_dad__states.setdefault(ip6_unicast_candidate, Icmp6DadState.TENTATIVE)

        # RFC 4862 §5.4.2 — random initial delay before the
        # first DAD probe to alleviate fleet-wide
        # synchronisation when many hosts boot at the same
        # instant. Ceiling is 'icmp6.max_rtr_solicitation_delay_ms'
        # (default 1000 ms = RFC 4861 §10). Setting the sysctl
        # to 0 disables.
        max_initial_delay_ms = nd__constants.ICMP6__MAX_RTR_SOLICITATION_DELAY_MS
        if max_initial_delay_ms > 0:
            time.sleep(random.uniform(0, max_initial_delay_ms / 1000.0))

        # The optimistic wrapper has already joined the
        # solicited-node multicast group via '_assign_ip6_host';
        # in the strict path the multicast must be joined here
        # so DAD probes can be received back from peers.
        solicited_node = ip6_unicast_candidate.solicited_node_multicast
        joined_for_dad = solicited_node not in self._ip6_multicast
        if joined_for_dad:
            self._assign_ip6_multicast(ip6_multicast=solicited_node)

        # RFC 4861 §6.3.4: an RA-advertised Retrans Timer
        # supersedes the operator-configured sysctl default. The
        # mirror is captured by §13a; consumer wiring is §13b.
        effective_retrans_timer_ms = self._icmp6_ra_parameters.retrans_timer_ms or nd__constants.ICMP6__RETRANS_TIMER_MS
        retrans_timer_s = effective_retrans_timer_ms / 1000.0
        conflict = False
        for _probe_index in range(nd__constants.ICMP6__DAD_TRANSMITS):
            # RFC 7527 §4.1: every NS(DAD) carries a fresh
            # random nonce when Enhanced DAD is enabled. The
            # nonce is registered with the slot under the
            # registry's lock so the RX nonce-membership read
            # in 'registry.try_signal_conflict' cannot observe
            # a partially-mutated set.
            nonce: bytes | None = None
            if nd__constants.ICMP6__ENHANCED_DAD:
                nonce = secrets.token_bytes(6)
                self._icmp6_nd_dad__registry.register_nonce(ip6_unicast_candidate, nonce)
            self._send_icmp6_nd_dad_message(
                ip6_unicast_candidate=ip6_unicast_candidate,
                nonce=nonce,
            )
            if dad_event.wait(timeout=retrans_timer_s):
                conflict = True
                break

        if conflict:
            # The RX path captured the peer's TLLA into the
            # slot under the registry's lock; we read it back
            # the same way.
            conflict_tlla = self._icmp6_nd_dad__registry.peer_info(ip6_unicast_candidate)
            __debug__ and log(
                "stack",
                "<WARN>ICMPv6 ND DAD - Duplicate IPv6 address detected, "
                f"{ip6_unicast_candidate} advertised by "
                f"{conflict_tlla}</>",
            )
            # Conflict — drop the per-address state entry; the
            # caller is responsible for reverting any pre-claim
            # (Optimistic-DAD wrapper removes the address from
            # '_ip6_ifaddr'; the strict path never assigned it).
            self._icmp6_dad__states.pop(ip6_unicast_candidate, None)
        else:
            __debug__ and log(
                "stack",
                "ICMPv6 ND DAD - No duplicate address detected for " f"{ip6_unicast_candidate}",
            )
            # Promote the per-address state to VALID before the
            # gratuitous NA goes out so the NA emit path's
            # OPTIMISTIC-source Override-flag suppression no
            # longer applies (RFC 9131 §3 announcement carries
            # Override=1 by design, RFC 4429 §3.3 step 5).
            self._icmp6_dad__states[ip6_unicast_candidate] = Icmp6DadState.VALID
            # RFC 9131 §3 — gratuitous Neighbor Advertisement(s)
            # on host attachment so peers preemptively populate
            # their neighbour cache for our newly-claimed
            # address. Operator-tunable count via
            # 'icmp6.gratuitous_na_count' (default 1; 0 disables).
            self.send_icmp6_neighbor_advertisement_gratuitous(ip6_unicast=ip6_unicast_candidate)

        # Tear down the per-address DAD slot. Order: clear the
        # slot AFTER the state-transition above so the RX
        # dispatch cannot signal a slot that's about to be
        # popped. The registry tear-down runs under its
        # internal lock so an in-flight RX
        # 'try_signal_conflict' call cannot observe a
        # half-popped slot.
        self._icmp6_nd_dad__registry.teardown(ip6_unicast_candidate)
        if joined_for_dad:
            self._remove_ip6_multicast(ip6_unicast_candidate.solicited_node_multicast)
        return not conflict

    def _claim_ip6_address_optimistic(self, *, ip6_host: Ip6IfAddr) -> bool:
        """
        Claim 'ip6_host' using RFC 4429 §3 Optimistic DAD: the
        address is installed into '_ip6_ifaddr' as OPTIMISTIC
        before the DAD probes are emitted, then the DAD probe
        loop runs as in the strict path. On success the state
        is promoted to VALID; on collision the address is
        removed and the per-address state cleared.

        Returns True on DAD success, False on collision.
        """

        self._icmp6_dad__states[ip6_host.address] = Icmp6DadState.OPTIMISTIC
        self._assign_ip6_host(ip6_host=ip6_host)
        if self._perform_ip6_nd_dad(ip6_unicast_candidate=ip6_host.address):
            return True
        # Collision: roll back the optimistic assignment. The
        # per-address state was already cleared inside
        # '_perform_ip6_nd_dad'.
        self._remove_ip6_host(ip6_host=ip6_host)
        return False

    @override
    def _claim_ip6_address_async(
        self,
        *,
        ip6_host: Ip6IfAddr,
        regenerate: Callable[[], Ip6IfAddr] | None = None,
    ) -> threading.Thread:
        """
        Spawn a daemon worker thread that runs the DAD claim for
        'ip6_host' (synchronous '_perform_ip6_nd_dad' or
        '_claim_ip6_address_optimistic' depending on
        'icmp6.optimistic_dad'). Returns the worker thread so
        callers that need to wait for completion can '.join()'
        it; callers that fire-and-forget simply discard the
        returned handle.

        Multiple addresses can be claimed concurrently — each
        worker owns its own slot in '_icmp6_nd_dad__registry'
        and the RX dispatch keys on inbound NS / NA
        'target_address' to signal the right slot. This is what
        unblocks RFC 8981 temp-address regen (§18b/c) and
        runtime PI-arrival claims, neither of which can block
        the RX subsystem thread.

        When 'regenerate' is supplied (RFC 7217 §6 / RFC 8981
        §3.3.3), on DAD failure the worker calls it up to
        'icmp6.idgen_retries' times to mint a fresh candidate
        for the same prefix. The first candidate that DAD
        passes is installed; if all retries fail the
        accept_dad=2 fail-hard hook (§20.4) fires.
        """

        def _attempt_claim(candidate: Ip6IfAddr) -> bool:
            if nd__constants.ICMP6__OPTIMISTIC_DAD == 1:
                return self._claim_ip6_address_optimistic(ip6_host=candidate)
            ok = self._perform_ip6_nd_dad(ip6_unicast_candidate=candidate.address)
            if ok:
                self._assign_ip6_host(ip6_host=candidate)
            return ok

        def _worker() -> None:
            max_retries = nd__constants.ICMP6__IDGEN_RETRIES if regenerate is not None else 0
            current = ip6_host
            for attempt in range(max_retries + 1):
                ok = _attempt_claim(current)
                if ok:
                    __debug__ and log("stack", f"Successfully claimed IPv6 address {current}")
                    return
                if attempt < max_retries:
                    # RFC 7217 §6 / RFC 8981 §3.3.3 — re-derive
                    # the IID and retry. The closure owns the
                    # 'dad_counter' / random-IID logic.
                    assert regenerate is not None
                    __debug__ and log(
                        "stack",
                        f"<WARN>DAD failure on {current}; regenerating " f"(attempt {attempt + 1}/{max_retries})</>",
                    )
                    current = regenerate()

            __debug__ and log(
                "stack",
                f"<WARN>Unable to claim IPv6 address {current}; gave up " f"after {max_retries} retries</>",
            )
            # 'icmp6.accept_dad=2' fail-hard: any DAD failure
            # (after retries are exhausted) disables IPv6 on
            # the interface entirely. Linux 'accept_dad=2'
            # parity.
            if nd__constants.ICMP6__ACCEPT_DAD == 2:
                __debug__ and log(
                    "stack",
                    f"<CRIT>icmp6.accept_dad=2 — DAD failure on {current} " "disables IPv6 on this interface</>",
                )
                self._ip6_support = False

        thread = threading.Thread(
            target=_worker,
            daemon=True,
            name=f"DAD-{ip6_host.address}",
        )
        thread.start()
        return thread

    @override
    def _create_stack_ip6_addressing(self) -> None:
        """
        Create lists of IPv6 unicast and multicast addresses stack
        should listen on.

        Each address claim spawns a daemon DAD worker thread via
        '_claim_ip6_address_async'. With 'icmp6.optimistic_dad=0'
        the boot path '.join()'s every worker (preserving today's
        "address available only after DAD passes" semantic but
        permitting parallel DAD across candidates); with =1 the
        boot path fires-and-forgets so the workers transition
        OPTIMISTIC → VALID after boot has returned.

        For auto-configured addresses (link-local autoconfig,
        RA-driven SLAAC) the boot path passes an RFC 7217
        regenerator so DAD failures retry up to
        'icmp6.idgen_retries' times with an incremented
        'dad_counter' before giving up. Statically-configured
        candidates pass no regenerator — the operator picked
        the exact address; we cannot substitute a different
        one.
        """

        def _claim_ip6_address(
            ip6_host: Ip6IfAddr,
            *,
            regenerate: Callable[[], Ip6IfAddr] | None = None,
        ) -> None:
            thread = self._claim_ip6_address_async(ip6_host=ip6_host, regenerate=regenerate)
            if nd__constants.ICMP6__OPTIMISTIC_DAD == 0:
                thread.join()

        # Assign IPv6 All Nodes multicast address.
        self._assign_ip6_multicast(Ip6Address("ff02::1"))

        # Configure Link Local address(es) staticaly.
        for ip6_host in list(self._ip6_ifaddr_candidate):
            if ip6_host.address.is_link_local:
                self._ip6_ifaddr_candidate.remove(ip6_host)
                _claim_ip6_address(ip6_host)

        # Configure Link Local address automatically.
        if self._ip6_lla_autoconfig:
            lla_network = Ip6Network("fe80::/64")
            ip6_host = self._derive_ip6_host(ip6_network=lla_network)
            _claim_ip6_address(
                ip6_host,
                regenerate=self._make_rfc7217_regenerator(ip6_network=lla_network),
            )

        # If we don't have any link local address then disable
        # IPv6 protocol operations.
        if not self._ip6_ifaddr:
            __debug__ and log(
                "stack",
                "<WARN>Unable to assign any IPv6 link local address, " "disabling IPv6 protocol</>",
            )
            self._ip6_support = False
            return

        # Check if there are any statically configures GUA addresses.
        for ip6_host in list(self._ip6_ifaddr_candidate):
            self._ip6_ifaddr_candidate.remove(ip6_host)
            _claim_ip6_address(ip6_host)

        # Send out IPv6 Router Solicitation messages with
        # RFC 7559 §2 exponential backoff and wait for an RA
        # so SLAAC can pick up the advertised prefix.
        if self._ip6_gua_autoconfig:
            self._send_icmp6_nd_router_solicitations_with_backoff()
            # The RA source (tuple's 2nd element) no longer feeds
            # a per-IfAddr gateway: the default route was already
            # installed in the FIB by '_update_icmp6_default_router'
            # when the boot-window RA was received. Phase 4 may
            # simplify '_icmp6_ra__prefixes' to a prefix list.
            for prefix, _ in list(self._icmp6_ra__prefixes):
                __debug__ and log(
                    "stack",
                    f"Attempting IPv6 address auto configuration for RA " f"prefix {prefix}",
                )
                ip6_address = self._derive_ip6_host(ip6_network=prefix)
                _claim_ip6_address(
                    ip6_address,
                    regenerate=self._make_rfc7217_regenerator(ip6_network=prefix),
                )

        # Open the runtime-claim gate. From here on, any PI
        # arriving at the RX path for a brand-new prefix
        # (existing SLAAC entry is None) triggers an
        # immediate '_claim_ip6_address_async' for the
        # stable address. Boot-window PIs only updated the
        # tracking table and relied on the loop above for
        # their claim ordering.
        self._ip6_addressing_complete = True

    @override
    def _create_stack_ip4_addressing(self) -> None:
        """
        Create lists of IPv4 unicast, multicast and broadcast addresses stack
        should listen on.

        Handles statically configured candidates only. As of Phase 4
        commit B, the DHCPv4 path is owned by 'stack.dhcp4_client'
        (a 'Subsystem' that 'stack.start()' brings up after the
        packet handler) — the lifecycle calls
        'stack.address.add(...)' on its BOUND transition; this
        method is not the integration point for that.
        """

        # Probe each candidate sequentially over its own 'Ip4Acd'
        # engine (the Linux 'sd-ipv4acd' model — RFC 5227 §2.1.1
        # Probe then §2.3 Announce on a clean probe). A statically
        # configured host gets probe + announce only, with NO
        # ongoing defender: this mirrors a bare Linux 'ip addr add',
        # where §2.4 ongoing defense is a managing-daemon job (DHCP
        # client / link-local autoconfig), not part of static
        # assignment. The engine opens its own AF_PACKET socket and
        # reads ARP off it for conflicts, so the stack's ARP RX path
        # is uninvolved.
        for ip4_host in list(self._ip4_ifaddr_candidate):
            self._ip4_ifaddr_candidate.remove(ip4_host)
            acd = Ip4Acd(mac_address=self._mac_unicast, ifindex=self._ifindex)
            if acd.probe(address=ip4_host.address).success:
                acd.announce(address=ip4_host.address)
                self._assign_ip4_host(ip4_host=ip4_host)
                __debug__ and log(
                    "stack",
                    f"Successfully claimed IPv4 address {ip4_host.address}",
                )
            else:
                __debug__ and log(
                    "stack",
                    f"<WARN>Unable to claim IPv4 address {ip4_host.address}</>",
                )

        # If we have no statically configured IPv4 host AND DHCP is
        # not running, disable IPv4 outright. When DHCP IS running,
        # 'stack.start()' blocks on
        # 'dhcp4_client.start_and_wait_for_bind(...)' AFTER this
        # method returns, so '_ip4_ifaddr' may still populate via the
        # Address API before any IPv4 application traffic flows.
        if not self._ip4_ifaddr and not self._ip4_dhcp:
            __debug__ and log(
                "stack",
                "<WARN>No statically configured IPv4 address and DHCP " "disabled; disabling IPv4 protocol</>",
            )
            self._ip4_support = False

    @override
    def _assign_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Assign IPv6 multicast address to the list stack listens on.
        """

        self._ip6_multicast.append(ip6_multicast)

        __debug__ and log("stack", f"Assigned IPv6 multicast {ip6_multicast}")

        self._assign_mac_multicast(ip6_multicast.multicast_mac)

        self._send_icmp6_multicast_listener_report()

    @override
    def _remove_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Remove IPv6 multicast address from the list stack listens on.
        """

        self._ip6_multicast.remove(ip6_multicast)

        __debug__ and log("stack", f"Removed IPv6 multicast {ip6_multicast}")

        self._remove_mac_multicast(ip6_multicast.multicast_mac)

    def _assign_mac_multicast(self, /, mac_multicast: MacAddress) -> None:
        """
        Assign MAC multicast address to the list stack listens on.
        """

        self._mac_multicast.append(mac_multicast)

        __debug__ and log("stack", f"Assigned MAC multicast {mac_multicast}")

    def _remove_mac_multicast(self, /, mac_multicast: MacAddress) -> None:
        """
        Remove MAC multicast address from the list stack listens on.
        """

        self._mac_multicast.remove(mac_multicast)

        __debug__ and log("stack", f"Removed MAC multicast {mac_multicast}")

    @override
    def _log_stack_address_info(self) -> None:
        """
        Log all the addresses stack will listen on
        """

        for _ in (self._ip6_support, self._ip4_support):
            self._ip_configuration_in_progress.acquire(timeout=15)

        if __debug__:
            log(
                "stack",
                "<INFO>Stack listening on unicast MAC address: " f"{self._mac_unicast}</>",
            )
            log(
                "stack",
                "<INFO>Stack listening on multicast MAC addresses: "
                f"{', '.join([str(mac_multicast) for mac_multicast in set(self._mac_multicast)])}</>",
            )
            log(
                "stack",
                "<INFO>Stack listening on broadcast MAC address: " f"{self._mac_broadcast}</>",
            )

        self._ip_configuration_in_progress.release(2)
        super()._log_stack_address_info()


class PacketHandlerL3(
    PacketHandler,
    PacketHandlerIcmp6Rx,
    PacketHandlerIcmp6Tx,
    PacketHandlerIcmp4Rx,
    PacketHandlerIcmp4Tx,
    PacketHandlerIp4Rx,
    PacketHandlerIp4Tx,
    PacketHandlerIp6Rx,
    PacketHandlerIp6Tx,
    PacketHandlerIp6FragRx,
    PacketHandlerIp6FragTx,
    PacketHandlerTcpRx,
    PacketHandlerTcpTx,
    PacketHandlerUdpRx,
    PacketHandlerUdpTx,
):
    """
    Pick up and respond to incoming packets on Layer 3 (TUN) interface.
    """

    _interface_layer = InterfaceLayer.L3

    @override
    def _subsystem_loop(self) -> None:
        """
        Pick up incoming packets from RX Ring and processes them.
        """

        assert self._rx_ring is not None, "Started PacketHandler must have an injected RX ring."

        if (packet_rx := self._rx_ring.dequeue()) is not None:
            match EtherType.from_bytes(packet_rx.frame[2:4]):
                case EtherType.IP6:
                    if self._ip6_support:
                        packet_rx.frame = packet_rx.frame[4:]
                        self._phrx_ip6(packet_rx)
                case EtherType.IP4:
                    if self._ip4_support:
                        packet_rx.frame = packet_rx.frame[4:]
                        self._phrx_ip4(packet_rx)
                case _:
                    __debug__ and log(
                        "stack",
                        f"<WARN>Unknown EtherType 0x{packet_rx.frame[2:4].hex()} " "received, dropping packet</>",
                    )

    @override
    def _claim_ip6_address_async(
        self,
        *,
        ip6_host: Ip6IfAddr,
        regenerate: Callable[[], Ip6IfAddr] | None = None,
    ) -> threading.Thread:
        """
        L3 has no DAD — claims complete synchronously via
        '_assign_ip6_host'. The 'regenerate' callback is
        accepted for signature parity with L2 but never
        invoked (no DAD failure to retry). The returned
        Thread is a no-op helper that has already finished,
        so callers '.join()'ing it return immediately.
        """

        del regenerate  # unused on L3 — no DAD, no retry
        self._assign_ip6_host(ip6_host=ip6_host)
        thread = threading.Thread(target=lambda: None, daemon=True, name=f"DAD-{ip6_host.address}")
        thread.start()
        return thread

    @override
    def _create_stack_ip6_addressing(self) -> None:
        """
        Create lists of IPv6 unicast and multicast addresses stack
        should listen on.
        """

        self._assign_ip6_multicast(Ip6Address("ff02::1"))

        for ip6_host in list(self._ip6_ifaddr_candidate):
            self._ip6_ifaddr_candidate.remove(ip6_host)
            self._assign_ip6_host(ip6_host=ip6_host)

        if not self._ip6_ifaddr:
            __debug__ and log(
                "stack",
                "<WARN>Unable to assign any IPv6 address, disabling IPv6 " "protocol</>",
            )
            self._ip6_support = False

    @override
    def _create_stack_ip4_addressing(self) -> None:
        """
        Create lists of IPv4 unicast, multicast and broadcast addresses stack
        should listen on.
        """

        for ip4_host in list(self._ip4_ifaddr_candidate):
            self._ip4_ifaddr_candidate.remove(ip4_host)
            self._assign_ip4_host(ip4_host=ip4_host)

        if not self._ip4_ifaddr:
            __debug__ and log(
                "stack",
                "<WARN>Unable to assign any IPv4 address, disabling IPv4 " "protocol</>",
            )
            self._ip4_support = False

    @override
    def _assign_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Assign IPv6 multicast address to the list stack listens on.
        """

        self._ip6_multicast.append(ip6_multicast)

        __debug__ and log("stack", f"Assigned IPv6 multicast {ip6_multicast}")

        self._send_icmp6_multicast_listener_report()

    @override
    def _remove_ip6_multicast(self, /, ip6_multicast: Ip6Address) -> None:
        """
        Remove IPv6 multicast address from the list stack listens on.
        """

        self._ip6_multicast.remove(ip6_multicast)

        __debug__ and log("stack", f"Removed IPv6 multicast {ip6_multicast}")
