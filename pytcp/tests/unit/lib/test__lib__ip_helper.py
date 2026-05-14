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
This module contains tests for the IP helper functions.

pytcp/tests/unit/lib/test__lib__ip_helper.py

ver 3.0.4
"""

from types import SimpleNamespace
from typing import Any
from unittest import TestCase
from unittest.mock import patch

from parameterized import parameterized_class  # type: ignore

from net_addr import (
    Ip4Address,
    Ip4Network,
    Ip6Address,
    Ip6Network,
    IpVersion,
)
from pytcp.lib.ip_helper import (
    ip_version,
    is_address_in_use,
    pick_local_ip4_address,
    pick_local_ip6_address,
    pick_local_ip_address,
    pick_local_port,
    str_to_ip,
)
from pytcp.socket import AddressFamily, SocketType


@parameterized_class(
    [
        {
            "_description": "Well-formed IPv6 address.",
            "_ip_address": "2001:db8::1",
            "_results": {
                "ip_version": IpVersion.IP6,
                "str_to_ip": Ip6Address("2001:db8::1"),
            },
        },
        {
            "_description": "Well-formed IPv4 address.",
            "_ip_address": "10.0.0.1",
            "_results": {
                "ip_version": IpVersion.IP4,
                "str_to_ip": Ip4Address("10.0.0.1"),
            },
        },
        {
            "_description": "IPv6 loopback.",
            "_ip_address": "::1",
            "_results": {
                "ip_version": IpVersion.IP6,
                "str_to_ip": Ip6Address("::1"),
            },
        },
        {
            "_description": "IPv4 zero address.",
            "_ip_address": "0.0.0.0",
            "_results": {
                "ip_version": IpVersion.IP4,
                "str_to_ip": Ip4Address("0.0.0.0"),
            },
        },
        {
            "_description": "Garbage string that parses as neither.",
            "_ip_address": "not-an-ip",
            "_results": {
                "ip_version": None,
                "str_to_ip": None,
            },
        },
        {
            "_description": "Empty string.",
            "_ip_address": "",
            "_results": {
                "ip_version": None,
                "str_to_ip": None,
            },
        },
    ]
)
class TestIpVersionAndStrToIp(TestCase):
    """
    The 'ip_version()' and 'str_to_ip()' happy/fallback path tests.
    """

    _description: str
    _ip_address: str
    _results: dict[str, Any]

    def test__ip_helper__ip_version(self) -> None:
        """
        Ensure 'ip_version()' returns the correct 'IpVersion' member for
        valid strings and 'None' for anything that parses as neither an
        IPv6 nor an IPv4 address. Exercises the double try/except
        fallback chain.
        """

        self.assertEqual(
            ip_version(ip_address=self._ip_address),
            self._results["ip_version"],
            msg=f"Unexpected ip_version() result for case: {self._description}",
        )

    def test__ip_helper__str_to_ip(self) -> None:
        """
        Ensure 'str_to_ip()' returns the matching 'Ip6Address' /
        'Ip4Address' value for valid strings and 'None' for unparsable
        input. Mirrors the dispatch logic of 'ip_version()' but returns
        the address object itself.
        """

        self.assertEqual(
            str_to_ip(self._ip_address),
            self._results["str_to_ip"],
            msg=f"Unexpected str_to_ip() result for case: {self._description}",
        )


class TestStrToIpPositionalOnly(TestCase):
    """
    The 'str_to_ip()' signature tests.
    """

    def test__ip_helper__str_to_ip__positional_only(self) -> None:
        """
        Ensure 'str_to_ip' accepts its 'ip_address' argument positionally
        only (it appears before the '/' in the signature). Passing it as
        a keyword must raise 'TypeError'.
        """

        with self.assertRaises(TypeError):
            str_to_ip(ip_address="10.0.0.1")  # type: ignore[call-arg]


class TestPickLocalIp6Address(TestCase):
    """
    The 'pick_local_ip6_address()' tests.
    """

    def test__ip_helper__pick_local_ip6__remote_in_local_network(self) -> None:
        """
        Ensure the helper returns the local host's own address when the
        remote address falls inside one of the configured local IPv6
        networks. This is the first (and preferred) branch of the
        selector.
        """

        local_host = SimpleNamespace(
            address=Ip6Address("2001:db8::100"),
            network=Ip6Network("2001:db8::/64"),
            gateway=None,
        )
        fake_handler = SimpleNamespace(ip6_host=[local_host])

        with patch("pytcp.lib.ip_helper.stack.packet_handler", fake_handler):
            result = pick_local_ip6_address(remote_ip6_address=Ip6Address("2001:db8::5"))

        self.assertEqual(
            result,
            Ip6Address("2001:db8::100"),
            msg="pick_local_ip6_address() must return the matching local address for an in-network remote.",
        )

    def test__ip_helper__pick_local_ip6__remote_external_uses_gateway_host(self) -> None:
        """
        Ensure the helper falls back to the address of the first host
        that has a gateway configured when the remote is outside every
        local network.
        """

        no_gw = SimpleNamespace(
            address=Ip6Address("fd00::1"),
            network=Ip6Network("fd00::/8"),
            gateway=None,
        )
        with_gw = SimpleNamespace(
            address=Ip6Address("2001:db8::100"),
            network=Ip6Network("2001:db8::/64"),
            gateway=Ip6Address("2001:db8::1"),
        )
        fake_handler = SimpleNamespace(ip6_host=[no_gw, with_gw])

        with patch("pytcp.lib.ip_helper.stack.packet_handler", fake_handler):
            result = pick_local_ip6_address(remote_ip6_address=Ip6Address("2606:4700::1"))

        self.assertEqual(
            result,
            Ip6Address("2001:db8::100"),
            msg="pick_local_ip6_address() must return the first gateway-bearing host for an external remote.",
        )

    def test__ip_helper__pick_local_ip6__no_match_returns_unspecified(self) -> None:
        """
        Ensure the helper returns the unspecified '::' address when the
        remote does not match any local network and no host has a
        gateway configured.
        """

        orphan = SimpleNamespace(
            address=Ip6Address("2001:db8::100"),
            network=Ip6Network("2001:db8::/64"),
            gateway=None,
        )
        fake_handler = SimpleNamespace(ip6_host=[orphan])

        with patch("pytcp.lib.ip_helper.stack.packet_handler", fake_handler):
            result = pick_local_ip6_address(remote_ip6_address=Ip6Address("2606:4700::1"))

        self.assertEqual(
            result,
            Ip6Address(),
            msg="pick_local_ip6_address() must fall back to the unspecified '::' address.",
        )


class TestPickLocalIp4Address(TestCase):
    """
    The 'pick_local_ip4_address()' tests.
    """

    def test__ip_helper__pick_local_ip4__remote_in_local_network(self) -> None:
        """
        Ensure the helper returns the matching local host address when
        the remote is inside one of the configured IPv4 networks.
        """

        local_host = SimpleNamespace(
            address=Ip4Address("10.0.0.100"),
            network=Ip4Network("10.0.0.0/24"),
            gateway=None,
        )
        fake_handler = SimpleNamespace(ip4_host=[local_host])

        with patch("pytcp.lib.ip_helper.stack.packet_handler", fake_handler):
            result = pick_local_ip4_address(remote_ip4_address=Ip4Address("10.0.0.5"))

        self.assertEqual(
            result,
            Ip4Address("10.0.0.100"),
            msg="pick_local_ip4_address() must return the matching local address for an in-network remote.",
        )

    def test__ip_helper__pick_local_ip4__remote_external_uses_gateway_host(self) -> None:
        """
        Ensure the helper falls back to the address of the first host
        that has a gateway configured when the remote is outside every
        local network.
        """

        no_gw = SimpleNamespace(
            address=Ip4Address("172.16.0.1"),
            network=Ip4Network("172.16.0.0/16"),
            gateway=None,
        )
        with_gw = SimpleNamespace(
            address=Ip4Address("10.0.0.100"),
            network=Ip4Network("10.0.0.0/24"),
            gateway=Ip4Address("10.0.0.1"),
        )
        fake_handler = SimpleNamespace(ip4_host=[no_gw, with_gw])

        with patch("pytcp.lib.ip_helper.stack.packet_handler", fake_handler):
            result = pick_local_ip4_address(remote_ip4_address=Ip4Address("8.8.8.8"))

        self.assertEqual(
            result,
            Ip4Address("10.0.0.100"),
            msg="pick_local_ip4_address() must return the first gateway-bearing host for an external remote.",
        )

    def test__ip_helper__pick_local_ip4__no_match_returns_unspecified(self) -> None:
        """
        Ensure the helper returns the unspecified '0.0.0.0' address when
        the remote does not match any local network and no host has a
        gateway configured.
        """

        orphan = SimpleNamespace(
            address=Ip4Address("10.0.0.100"),
            network=Ip4Network("10.0.0.0/24"),
            gateway=None,
        )
        fake_handler = SimpleNamespace(ip4_host=[orphan])

        with patch("pytcp.lib.ip_helper.stack.packet_handler", fake_handler):
            result = pick_local_ip4_address(remote_ip4_address=Ip4Address("8.8.8.8"))

        self.assertEqual(
            result,
            Ip4Address(),
            msg="pick_local_ip4_address() must fall back to the unspecified '0.0.0.0' address.",
        )


class TestPickLocalIpAddressDispatch(TestCase):
    """
    The 'pick_local_ip_address()' generic-dispatch tests.
    """

    def test__ip_helper__pick_local_ip__dispatches_to_ip6(self) -> None:
        """
        Ensure the generic helper forwards to the IPv6 helper and
        propagates its return value when the remote is an IPv6 address.
        The generic signature is type-parametrized, so the return type
        must match the input type.
        """

        expected = Ip6Address("2001:db8::cafe")
        remote = Ip6Address("2001:db8::1")

        with (
            patch("pytcp.lib.ip_helper.pick_local_ip6_address", return_value=expected) as mock_ip6,
            patch("pytcp.lib.ip_helper.pick_local_ip4_address") as mock_ip4,
        ):
            result = pick_local_ip_address(remote_ip_address=remote)

        mock_ip6.assert_called_once_with(remote_ip6_address=remote)
        mock_ip4.assert_not_called()
        self.assertEqual(
            result,
            expected,
            msg="pick_local_ip_address() must return the IPv6 helper's result for IPv6 input.",
        )

    def test__ip_helper__pick_local_ip__dispatches_to_ip4(self) -> None:
        """
        Ensure the generic helper forwards to the IPv4 helper and
        propagates its return value when the remote is an IPv4 address.
        """

        expected = Ip4Address("10.0.0.100")
        remote = Ip4Address("8.8.8.8")

        with (
            patch("pytcp.lib.ip_helper.pick_local_ip4_address", return_value=expected) as mock_ip4,
            patch("pytcp.lib.ip_helper.pick_local_ip6_address") as mock_ip6,
        ):
            result = pick_local_ip_address(remote_ip_address=remote)

        mock_ip4.assert_called_once_with(remote_ip4_address=remote)
        mock_ip6.assert_not_called()
        self.assertEqual(
            result,
            expected,
            msg="pick_local_ip_address() must return the IPv4 helper's result for IPv4 input.",
        )


class TestPickLocalPort(TestCase):
    """
    The 'pick_local_port()' ephemeral-port-allocator tests.
    """

    def test__ip_helper__pick_local_port__returns_value_from_range(self) -> None:
        """
        Ensure the helper returns a port drawn from
        'stack.EPHEMERAL_PORT_RANGE' when no socket has claimed anything
        yet.
        """

        with (
            patch("pytcp.lib.ip_helper.stack.EPHEMERAL_PORT_RANGE", range(10000, 10004, 2)),
            patch("pytcp.lib.ip_helper.stack.sockets", {}),
        ):
            port = pick_local_port()

        self.assertIn(
            port,
            {10000, 10002},
            msg="pick_local_port() must return a value from the configured ephemeral port range.",
        )

    def test__ip_helper__pick_local_port__skips_ports_already_in_use(self) -> None:
        """
        Ensure ports currently used by any open socket are excluded from
        the pool. If every port-but-one is taken, the helper must pick
        that last remaining port.
        """

        sockets = {
            "s1": SimpleNamespace(local_port=10000),
            "s2": SimpleNamespace(local_port=10002),
        }

        with (
            patch("pytcp.lib.ip_helper.stack.EPHEMERAL_PORT_RANGE", range(10000, 10006, 2)),
            patch("pytcp.lib.ip_helper.stack.sockets", sockets),
        ):
            port = pick_local_port()

        self.assertEqual(
            port,
            10004,
            msg="pick_local_port() must pick the single remaining free port when all others are in use.",
        )

    def test__ip_helper__pick_local_port__uses_secrets_choice_for_entropy(self) -> None:
        """
        Ensure the picker delegates the final selection to
        'secrets.choice', a CSPRNG-backed primitive, rather than
        relying on Python set-pop hash ordering. The
        'secrets.choice' call MUST receive the unused-ports
        collection (anything in EPHEMERAL_PORT_RANGE that no
        existing socket has claimed) so an attacker observing
        one selection learns nothing useful about future ones.

        Reference: RFC 6056 §3.1 (obfuscate the ephemeral port
        selection; needs cryptographic-quality randomness).
        """

        sockets = {"s1": SimpleNamespace(local_port=10002)}

        with (
            patch("pytcp.lib.ip_helper.stack.EPHEMERAL_PORT_RANGE", range(10000, 10006)),
            patch("pytcp.lib.ip_helper.stack.sockets", sockets),
            patch("pytcp.lib.ip_helper.secrets.choice", return_value=10005) as mock_choice,
        ):
            port = pick_local_port()

        self.assertEqual(
            port,
            10005,
            msg="pick_local_port() must return the value secrets.choice yields.",
        )
        mock_choice.assert_called_once()
        (passed_pool,), _kwargs = mock_choice.call_args
        self.assertEqual(
            sorted(passed_pool),
            [10000, 10001, 10003, 10004, 10005],
            msg=(
                "secrets.choice must be invoked with every port from "
                "EPHEMERAL_PORT_RANGE that no existing socket has claimed."
            ),
        )

    def test__ip_helper__pick_local_port__raises_when_exhausted(self) -> None:
        """
        Ensure 'pick_local_port()' raises 'OSError' with the canonical
        '[Errno 98] Address already in use' message when every port in
        the ephemeral range is claimed.
        """

        sockets = {f"s{p}": SimpleNamespace(local_port=p) for p in range(10000, 10006, 2)}

        with (
            patch("pytcp.lib.ip_helper.stack.EPHEMERAL_PORT_RANGE", range(10000, 10006, 2)),
            patch("pytcp.lib.ip_helper.stack.sockets", sockets),
        ):
            with self.assertRaises(OSError) as context:
                pick_local_port()

        self.assertIn(
            "[Errno 98] Address already in use",
            str(context.exception),
            msg="pick_local_port() must raise with the canonical Errno 98 message when exhausted.",
        )


class TestIsAddressInUse(TestCase):
    """
    The 'is_address_in_use()' tests.
    """

    def _make_socket(
        self,
        *,
        family: AddressFamily,
        type: SocketType,
        local_ip_address: Ip4Address | Ip6Address,
        local_port: int,
    ) -> SimpleNamespace:
        """
        Build a namespace stub whose attribute surface matches the small
        slice of the socket API that 'is_address_in_use' inspects.
        """

        return SimpleNamespace(
            family=family,
            type=type,
            local_ip_address=local_ip_address,
            local_port=local_port,
        )

    def test__ip_helper__is_address_in_use__exact_match_returns_true(self) -> None:
        """
        Ensure an open socket bound to exactly the same
        (family, type, IP, port) tuple flags the address as in use.
        """

        opened = self._make_socket(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
        )

        with patch("pytcp.lib.ip_helper.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertTrue(
            result,
            msg="is_address_in_use() must return True when an identical socket is already open.",
        )

    def test__ip_helper__is_address_in_use__open_on_unspecified_blocks_specific(self) -> None:
        """
        Ensure a socket bound to the unspecified address (e.g. 0.0.0.0)
        blocks subsequent binds on any specific address using the same
        port/family/type — the BSD 'bound to ANY' semantics.
        """

        opened = self._make_socket(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            local_ip_address=Ip4Address(),
            local_port=8080,
        )

        with patch("pytcp.lib.ip_helper.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertTrue(
            result,
            msg="A socket bound to 0.0.0.0 must block a specific-IP bind on the same port.",
        )

    def test__ip_helper__is_address_in_use__new_unspecified_blocks_specific(self) -> None:
        """
        Ensure a new bind request on the unspecified address is blocked
        by any existing socket bound to a specific IP on the same port,
        family, and socket type.
        """

        opened = self._make_socket(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
        )

        with patch("pytcp.lib.ip_helper.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address(),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertTrue(
            result,
            msg="A specific-IP bind must block a subsequent 0.0.0.0 bind on the same port.",
        )

    def test__ip_helper__is_address_in_use__different_port_returns_false(self) -> None:
        """
        Ensure a different port is considered free even when the family,
        type, and local IP match an existing socket.
        """

        opened = self._make_socket(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
        )

        with patch("pytcp.lib.ip_helper.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=9090,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertFalse(
            result,
            msg="is_address_in_use() must return False for a different port.",
        )

    def test__ip_helper__is_address_in_use__different_family_returns_false(self) -> None:
        """
        Ensure sockets in a different address family are ignored so an
        IPv4 bind is not blocked by an IPv6 listener on the same port.
        """

        opened = self._make_socket(
            family=AddressFamily.INET6,
            type=SocketType.STREAM,
            local_ip_address=Ip6Address("::"),
            local_port=8080,
        )

        with patch("pytcp.lib.ip_helper.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertFalse(
            result,
            msg="is_address_in_use() must ignore sockets from a different address family.",
        )

    def test__ip_helper__is_address_in_use__different_type_returns_false(self) -> None:
        """
        Ensure sockets of a different type (STREAM vs DGRAM) are ignored
        so a TCP bind is not blocked by a UDP listener on the same port.
        """

        opened = self._make_socket(
            family=AddressFamily.INET4,
            type=SocketType.DGRAM,
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
        )

        with patch("pytcp.lib.ip_helper.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertFalse(
            result,
            msg="is_address_in_use() must ignore sockets of a different socket type.",
        )

    def test__ip_helper__is_address_in_use__different_ip_returns_false(self) -> None:
        """
        Ensure a different specific local IP on the same port/family/type
        is considered free — BSD sockets allow multiple binds at the
        same port as long as the specific addresses differ.
        """

        opened = self._make_socket(
            family=AddressFamily.INET4,
            type=SocketType.STREAM,
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
        )

        with patch("pytcp.lib.ip_helper.stack.sockets", {"s1": opened}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.2"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertFalse(
            result,
            msg="is_address_in_use() must return False for a different specific local IP on the same port.",
        )

    def test__ip_helper__is_address_in_use__empty_sockets_returns_false(self) -> None:
        """
        Ensure a completely empty socket table always resolves to free.
        """

        with patch("pytcp.lib.ip_helper.stack.sockets", {}):
            result = is_address_in_use(
                local_ip_address=Ip4Address("10.0.0.1"),
                local_port=8080,
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
            )

        self.assertFalse(
            result,
            msg="is_address_in_use() must return False when no sockets are open.",
        )
