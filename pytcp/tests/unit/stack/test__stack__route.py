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
This module contains tests for the read-only Route API and the
Phase-1 boot default-route dual-write helper.

pytcp/tests/unit/stack/test__stack__route.py

ver 3.0.5
"""

from typing import override
from unittest import TestCase

from net_addr import Ip4Address, Ip4IfAddr, Ip4Network, Ip6Address, Ip6IfAddr, Ip6Network
from pytcp.runtime.fib import Route, RouteProtocol, RouteTable
from pytcp.stack.route import RouteApi, install_boot_default_routes


class TestRouteApiRead(TestCase):
    """
    The read-only Route API introspection tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a RouteApi over fresh empty IPv4 / IPv6 FIBs.
        """

        self._ip4_fib: RouteTable[Ip4Address, Ip4Network] = RouteTable()
        self._ip6_fib: RouteTable[Ip6Address, Ip6Network] = RouteTable()
        self._route_api = RouteApi(ip4_fib=self._ip4_fib, ip6_fib=self._ip6_fib)

    def test__stack__route__list_reflects_fib_contents(self) -> None:
        """
        Ensure 'list_ip4_routes' / 'list_ip6_routes' return the
        current FIB contents.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        r4 = Route(destination=Ip4Network("0.0.0.0/0"), gateway=Ip4Address("10.0.1.1"))
        r6 = Route(destination=Ip6Network("::/0"), gateway=Ip6Address("fe80::1"))
        self._ip4_fib.add(route=r4)
        self._ip6_fib.add(route=r6)

        self.assertEqual(
            self._route_api.list_ip4_routes(),
            (r4,),
            msg="list_ip4_routes must reflect the IPv4 FIB contents.",
        )
        self.assertEqual(
            self._route_api.list_ip6_routes(),
            (r6,),
            msg="list_ip6_routes must reflect the IPv6 FIB contents.",
        )

    def test__stack__route__list_is_copy_by_value(self) -> None:
        """
        Ensure the returned snapshot is an immutable tuple that
        does not observe a later FIB mutation (Phase-3 read-only
        introspection constraint).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        snap_before = self._route_api.list_ip4_routes()
        self._ip4_fib.add(route=Route(destination=Ip4Network("0.0.0.0/0")))

        self.assertIsInstance(
            snap_before,
            tuple,
            msg="list_ip4_routes must return an immutable tuple.",
        )
        self.assertEqual(
            snap_before,
            (),
            msg="A snapshot taken before a later add must not observe the add.",
        )
        self.assertEqual(
            len(self._route_api.list_ip4_routes()),
            1,
            msg="A fresh snapshot must observe every added route.",
        )

    def test__stack__route__empty_fibs_yield_empty_tuples(self) -> None:
        """
        Ensure both list methods yield an empty tuple when the
        backing FIB is empty.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._route_api.list_ip4_routes(),
            (),
            msg="list_ip4_routes on an empty FIB must be ().",
        )
        self.assertEqual(
            self._route_api.list_ip6_routes(),
            (),
            msg="list_ip6_routes on an empty FIB must be ().",
        )


class TestInstallBootDefaultRoutes(TestCase):
    """
    The Phase-1 boot default-route dual-write helper tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build fresh empty IPv4 / IPv6 FIBs for each case.
        """

        self._ip4_fib: RouteTable[Ip4Address, Ip4Network] = RouteTable()
        self._ip6_fib: RouteTable[Ip6Address, Ip6Network] = RouteTable()

    def test__stack__route__boot_ipv4_gateway_installs_default(self) -> None:
        """
        Ensure a boot IPv4 host carrying a gateway installs
        exactly one 0.0.0.0/0 BOOT-protocol default route.

        Reference: RFC 1122 §3.3.1 (default route / next-hop selection).
        """

        ip4_host = Ip4IfAddr("10.0.1.7/24")
        ip4_host.gateway = Ip4Address("10.0.1.1")

        install_boot_default_routes(
            ip4_fib=self._ip4_fib,
            ip6_fib=self._ip6_fib,
            ip4_host=ip4_host,
            ip6_host=None,
        )

        self.assertEqual(
            self._ip4_fib.snapshot(),
            (
                Route(
                    destination=Ip4Network("0.0.0.0/0"),
                    gateway=Ip4Address("10.0.1.1"),
                    protocol=RouteProtocol.BOOT,
                ),
            ),
            msg="A boot IPv4 gateway must install one BOOT default route.",
        )
        self.assertEqual(
            self._ip6_fib.snapshot(),
            (),
            msg="No IPv6 host must leave the IPv6 FIB empty.",
        )

    def test__stack__route__boot_ipv6_gateway_installs_default(self) -> None:
        """
        Ensure a boot IPv6 host carrying a (link-local) gateway
        installs exactly one ::/0 BOOT-protocol default route.

        Reference: RFC 1122 §3.3.1 (default route / next-hop selection).
        """

        ip6_host = Ip6IfAddr("2001:db8:0:1::7/64")
        ip6_host.gateway = Ip6Address("fe80::1")

        install_boot_default_routes(
            ip4_fib=self._ip4_fib,
            ip6_fib=self._ip6_fib,
            ip4_host=None,
            ip6_host=ip6_host,
        )

        self.assertEqual(
            self._ip6_fib.snapshot(),
            (
                Route(
                    destination=Ip6Network("::/0"),
                    gateway=Ip6Address("fe80::1"),
                    protocol=RouteProtocol.BOOT,
                ),
            ),
            msg="A boot IPv6 gateway must install one BOOT default route.",
        )

    def test__stack__route__no_host_installs_nothing(self) -> None:
        """
        Ensure that with no hosts the dual-write installs no
        routes (the DHCP / autoconfig path — gateway is learned
        and installed later, in Phase 3).

        Reference: RFC 1122 §3.3.1 (default route / next-hop selection).
        """

        install_boot_default_routes(
            ip4_fib=self._ip4_fib,
            ip6_fib=self._ip6_fib,
            ip4_host=None,
            ip6_host=None,
        )

        self.assertEqual(
            (self._ip4_fib.snapshot(), self._ip6_fib.snapshot()),
            ((), ()),
            msg="No hosts must install no default routes.",
        )

    def test__stack__route__host_without_gateway_installs_nothing(self) -> None:
        """
        Ensure a host with no gateway installs no default route.

        Reference: RFC 1122 §3.3.1 (default route / next-hop selection).
        """

        install_boot_default_routes(
            ip4_fib=self._ip4_fib,
            ip6_fib=self._ip6_fib,
            ip4_host=Ip4IfAddr("10.0.1.7/24"),
            ip6_host=Ip6IfAddr("2001:db8:0:1::7/64"),
        )

        self.assertEqual(
            (self._ip4_fib.snapshot(), self._ip6_fib.snapshot()),
            ((), ()),
            msg="A gateway-less host must install no default route.",
        )

    def test__stack__route__dual_stack_installs_both(self) -> None:
        """
        Ensure a dual-stack boot host installs one IPv4 and one
        IPv6 BOOT default route.

        Reference: RFC 1122 §3.3.1 (default route / next-hop selection).
        """

        ip4_host = Ip4IfAddr("10.0.1.7/24")
        ip4_host.gateway = Ip4Address("10.0.1.1")
        ip6_host = Ip6IfAddr("2001:db8:0:1::7/64")
        ip6_host.gateway = Ip6Address("fe80::1")

        install_boot_default_routes(
            ip4_fib=self._ip4_fib,
            ip6_fib=self._ip6_fib,
            ip4_host=ip4_host,
            ip6_host=ip6_host,
        )

        self.assertEqual(
            len(self._ip4_fib.snapshot()),
            1,
            msg="Dual-stack boot must install one IPv4 default route.",
        )
        self.assertEqual(
            len(self._ip6_fib.snapshot()),
            1,
            msg="Dual-stack boot must install one IPv6 default route.",
        )
