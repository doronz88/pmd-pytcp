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
This module contains the Phase-3 routing-control API
('RouteApi') — the kernel/userspace boundary surface for the
host-mode routing table. Phase 1 ships the read-only
introspection surface only ('list_ip4_routes' /
'list_ip6_routes'); mutation lands in Phase 3. The Linux
equivalents are 'ip route show' / '/proc/net/route' and
RTNETLINK 'RTM_GETROUTE'.

pytcp/stack/route.py

ver 3.0.5
"""

from net_addr import Ip4Address, Ip4Network, Ip6Address, Ip6Network
from pytcp.lib.logger import log
from pytcp.runtime.fib import Route, RouteProtocol, RouteTable

# The IPv4 / IPv6 default-route destinations (Linux 'default'
# in 'ip route'). Protocol-invariant — these are the
# all-addresses prefixes, not a tunable.
DEFAULT_IP4_NETWORK: Ip4Network = Ip4Network("0.0.0.0/0")
DEFAULT_IP6_NETWORK: Ip6Network = Ip6Network("::/0")


def install_boot_default_routes(
    *,
    ip4_fib: RouteTable[Ip4Address, Ip4Network],
    ip6_fib: RouteTable[Ip6Address, Ip6Network],
    ip4_gateway: Ip4Address | None,
    ip6_gateway: Ip6Address | None,
) -> None:
    """
    Install the static boot-config gateway (if any) as a
    'protocol=BOOT' default route in the FIB. This is the only
    boot-time default-route source; 'Ip{4,6}IfAddr.gateway' is
    no longer written (Phase 3 of
    'docs/refactor/routing_table_host_mode.md' dropped the
    Phase-1 dual-write — the FIB is now the single source of
    truth for the next hop). The DHCP / RA / autoconfig paths
    do NOT go through here; they learn the gateway at runtime
    and install it via 'RouteApi.replace_default_ip{4,6}'. A
    'None' gateway installs no default route (the DHCP /
    autoconfig case).
    """

    if ip4_gateway is not None:
        ip4_fib.add(
            route=Route(
                destination=DEFAULT_IP4_NETWORK,
                gateway=ip4_gateway,
                protocol=RouteProtocol.BOOT,
            )
        )
        __debug__ and log("stack", f"<lg>Route API</>: boot IPv4 default via {ip4_gateway}")

    if ip6_gateway is not None:
        ip6_fib.add(
            route=Route(
                destination=DEFAULT_IP6_NETWORK,
                gateway=ip6_gateway,
                protocol=RouteProtocol.BOOT,
            )
        )
        __debug__ and log("stack", f"<lg>Route API</>: boot IPv6 default via {ip6_gateway}")


class RouteApi:
    """
    Phase-3 routing-control surface — mirrors Linux RTNETLINK
    'RTM_GETROUTE' / 'ip route show' semantics.

    Phase-1 implementation: read-only introspection over the two
    per-address-family FIBs. Mutation ('add' / 'remove' /
    'replace_default') lands in Phase 3 of
    'docs/refactor/routing_table_host_mode.md'.

    Consumer code reads the route table ONLY through this
    surface; it never reaches into 'stack.ip4_fib' /
    'stack.ip6_fib' directly. This is the architectural seam the
    Phase-3 north-star turns into a real IPC channel — the
    wrapper internals swap from a direct in-process table to an
    RTNETLINK-equivalent message bus without any consumer change.
    """

    def __init__(
        self,
        *,
        ip4_fib: RouteTable[Ip4Address, Ip4Network],
        ip6_fib: RouteTable[Ip6Address, Ip6Network],
    ) -> None:
        """
        Bind the API to the stack's IPv4 / IPv6 FIBs. The FIBs
        own the route storage; the API is the only sanctioned
        consumer surface over them.
        """

        self._ip4_fib = ip4_fib
        self._ip6_fib = ip6_fib

    def list_ip4_routes(self) -> tuple[Route[Ip4Address, Ip4Network], ...]:
        """
        Return a read-only copy-by-value snapshot of the IPv4
        routing table — Linux 'ip -4 route show' /
        '/proc/net/route' equivalent. The returned tuple is
        immutable; the caller cannot mutate stack state through
        it (Phase-3 north-star "introspection is read-only"
        constraint).
        """

        return self._ip4_fib.snapshot()

    def list_ip6_routes(self) -> tuple[Route[Ip6Address, Ip6Network], ...]:
        """
        Return a read-only copy-by-value snapshot of the IPv6
        routing table — Linux 'ip -6 route show' /
        '/proc/net/ipv6_route' equivalent. Same immutability
        contract as 'list_ip4_routes'.
        """

        return self._ip6_fib.snapshot()

    def add_ip4_route(self, *, route: Route[Ip4Address, Ip4Network]) -> None:
        """
        Install an explicit IPv4 route — Linux 'RTM_NEWROUTE' /
        'ip -4 route add' equivalent. Does not de-duplicate; the
        caller owns replace semantics (see 'replace_default_ip4').
        """

        self._ip4_fib.add(route=route)

    def add_ip6_route(self, *, route: Route[Ip6Address, Ip6Network]) -> None:
        """
        Install an explicit IPv6 route — Linux 'RTM_NEWROUTE' /
        'ip -6 route add' equivalent.
        """

        self._ip6_fib.add(route=route)

    def remove_ip4_route(
        self,
        *,
        destination: Ip4Network,
        gateway: Ip4Address | None = None,
    ) -> int:
        """
        Remove every IPv4 route to 'destination' (optionally
        gateway-qualified) — Linux 'RTM_DELROUTE' / 'ip -4 route
        del' equivalent. Returns the number of routes removed.
        """

        return self._ip4_fib.remove(destination=destination, gateway=gateway)

    def remove_ip6_route(
        self,
        *,
        destination: Ip6Network,
        gateway: Ip6Address | None = None,
    ) -> int:
        """
        Remove every IPv6 route to 'destination' (optionally
        gateway-qualified) — Linux 'RTM_DELROUTE' / 'ip -6 route
        del' equivalent. Returns the number of routes removed.
        """

        return self._ip6_fib.remove(destination=destination, gateway=gateway)

    def replace_default_ip4(self, *, gateway: Ip4Address, protocol: RouteProtocol) -> None:
        """
        Atomically replace the IPv4 default route: remove any
        existing 0.0.0.0/0 route, then install a single new one
        via 'gateway' with the given 'protocol'. Linux 'ip route
        replace default via ...' equivalent.

        Remove-then-add (not the add-before-remove ordering of
        'Ip4AddressApi.replace_ifaddr'): two same-prefix default
        routes would create a lookup tiebreak ambiguity, whereas
        two interface addresses do not. The call is synchronous
        from the control-plane caller's view, so the transient
        no-default window is not observable to a concurrent
        lookup in practice.
        """

        self._ip4_fib.remove(destination=DEFAULT_IP4_NETWORK)
        self._ip4_fib.add(
            route=Route(
                destination=DEFAULT_IP4_NETWORK,
                gateway=gateway,
                protocol=protocol,
            )
        )
        __debug__ and log("stack", f"<lg>Route API</>: IPv4 default via {gateway} ({protocol!r})")

    def replace_default_ip6(self, *, gateway: Ip6Address, protocol: RouteProtocol) -> None:
        """
        Atomically replace the IPv6 default route: remove any
        existing ::/0 route, then install a single new one via
        'gateway' (typically the RA source link-local address)
        with the given 'protocol'. See 'replace_default_ip4' for
        the remove-then-add rationale.
        """

        self._ip6_fib.remove(destination=DEFAULT_IP6_NETWORK)
        self._ip6_fib.add(
            route=Route(
                destination=DEFAULT_IP6_NETWORK,
                gateway=gateway,
                protocol=protocol,
            )
        )
        __debug__ and log("stack", f"<lg>Route API</>: IPv6 default via {gateway} ({protocol!r})")
