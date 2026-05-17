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
This module contains the host-mode routing-table integration
tests. Phase 1 pins the harness wiring + FIB per-test isolation;
Phases 2 / 5 add the next-hop and static-route scenarios.

pytcp/tests/integration/protocols/ip4/test__ip4__routing.py

ver 3.0.5
"""

from net_addr import Ip4Network, Ip6Network
from pytcp import stack
from pytcp.runtime.fib import Route, RouteProtocol
from pytcp.tests.lib.network_testcase import (
    STACK__IP4_GATEWAY,
    STACK__IP6_GATEWAY,
    NetworkTestCase,
)

_FIXTURE_IP4_DEFAULT = Route(
    destination=Ip4Network("0.0.0.0/0"),
    gateway=STACK__IP4_GATEWAY,
    protocol=RouteProtocol.BOOT,
)
_FIXTURE_IP6_DEFAULT = Route(
    destination=Ip6Network("::/0"),
    gateway=STACK__IP6_GATEWAY,
    protocol=RouteProtocol.BOOT,
)


class TestIp4RoutingHarnessWiring(NetworkTestCase):
    """
    The host-mode FIB harness-wiring and isolation tests.
    """

    def test__ip4__routing__harness_installs_fixture_default_routes(self) -> None:
        """
        Ensure the integration harness exposes the read-only
        Route API and that it reports exactly the fixture
        default routes the topology pre-installs.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            stack.route.list_ip4_routes(),
            (_FIXTURE_IP4_DEFAULT,),
            msg="Harness must pre-install exactly the IPv4 fixture default route.",
        )
        self.assertEqual(
            stack.route.list_ip6_routes(),
            (_FIXTURE_IP6_DEFAULT,),
            msg="Harness must pre-install exactly the IPv6 fixture default route.",
        )

    def test__ip4__routing__fib_is_isolated_across_tests_a(self) -> None:
        """
        Ensure every test starts with a freshly-rebuilt FIB
        holding only the fixture default route, then mutates it;
        the mutation must not leak into the sibling test.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            stack.ip4_fib.snapshot(),
            (_FIXTURE_IP4_DEFAULT,),
            msg="FIB must start each test with only the fixture default route.",
        )

        stack.ip4_fib.add(
            route=Route(
                destination=Ip4Network("10.9.0.0/16"),
                gateway=STACK__IP4_GATEWAY,
                protocol=RouteProtocol.STATIC,
            )
        )

        self.assertEqual(
            len(stack.ip4_fib.snapshot()),
            2,
            msg="The in-test mutation must be visible within this test.",
        )

    def test__ip4__routing__fib_is_isolated_across_tests_b(self) -> None:
        """
        Ensure the sibling test's FIB mutation did not leak into
        this test — proving 'mock__init' rebuilds the FIBs fresh
        per test.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            stack.ip4_fib.snapshot(),
            (_FIXTURE_IP4_DEFAULT,),
            msg="Sibling test's static route must not leak into this test's FIB.",
        )
