#!/usr/bin/env python3

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
This module contains tests for the NetAddr package IPv4 host support class.

net_addr/tests/unit/test__ip4_host.py

ver 3.0.4
"""


import time
from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore

from net_addr import (
    Ip4Address,
    Ip4Host,
    Ip4HostFormatError,
    Ip4HostGatewayError,
    Ip4HostOrigin,
    Ip4HostSanityError,
    Ip4Mask,
    Ip4Network,
    IpVersion,
)

IP4_ADDRESS_EXPIRATION_TIME = int(time.time() + 3600)


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (str)",
            "_args": [
                "192.168.1.100/24",
            ],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.1"),
                "origin": Ip4HostOrigin.DHCP,
                "expiration_time": IP4_ADDRESS_EXPIRATION_TIME,
            },
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4Host('192.168.1.100/24')",
                "__hash__": hash("Ip4Host('192.168.1.100/24')"),
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
                "gateway": Ip4Address("192.168.1.1"),
                "origin": Ip4HostOrigin.DHCP,
                "expiration_time": IP4_ADDRESS_EXPIRATION_TIME,
            },
        },
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (Ip4Host)",
            "_args": [
                Ip4Host("192.168.1.100/24"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4Host('192.168.1.100/24')",
                "__hash__": hash("Ip4Host('192.168.1.100/24')"),
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
                "gateway": None,
                "origin": Ip4HostOrigin.UNKNOWN,
                "expiration_time": 0,
            },
        },
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (Ip4Address, Ip4Mask)",
            "_args": [
                (Ip4Address("192.168.1.100"), Ip4Mask("255.255.255.0")),
            ],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.1"),
                "origin": Ip4HostOrigin.STATIC,
            },
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4Host('192.168.1.100/24')",
                "__hash__": hash("Ip4Host('192.168.1.100/24')"),
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
                "gateway": Ip4Address("192.168.1.1"),
                "origin": Ip4HostOrigin.STATIC,
                "expiration_time": 0,
            },
        },
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (Ip4Address, Ip4Network)",
            "_args": [
                (Ip4Address("192.168.1.100"), Ip4Network("192.168.1.0/24")),
            ],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.1"),
                "origin": Ip4HostOrigin.STATIC,
            },
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4Host('192.168.1.100/24')",
                "__hash__": hash("Ip4Host('192.168.1.100/24')"),
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
                "gateway": Ip4Address("192.168.1.1"),
                "origin": Ip4HostOrigin.STATIC,
                "expiration_time": 0,
            },
        },
        {
            "_description": "Test the IPv4 host: 10.0.0.1/8 (Ip4Address, None)",
            "_args": [
                (Ip4Address("10.0.0.1"), None),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "10.0.0.1/8",
                "__repr__": "Ip4Host('10.0.0.1/8')",
                "__hash__": hash("Ip4Host('10.0.0.1/8')"),
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("10.0.0.1"),
                "network": Ip4Network("10.0.0.0/8"),
                "gateway": None,
                "origin": Ip4HostOrigin.UNKNOWN,
                "expiration_time": 0,
            },
        },
    ]
)
class TestNetAddrIp4Host(TestCase):
    """
    The NetAddr IPv4 Host tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv4 host object with testcase arguments.
        """

        self._ip4_host = Ip4Host(*self._args, **self._kwargs)

    def test__net_addr__ip4_host__str(self) -> None:
        """
        Ensure the IPv4 host '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._ip4_host),
            self._results["__str__"],
        )

    def test__net_addr__ip4_host__repr(self) -> None:
        """
        Ensure the IPv4 host '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._ip4_host),
            self._results["__repr__"],
        )

    def test__net_addr__ip4_host__eq(self) -> None:
        """
        Ensure the IPv4 host '__eq__()' method returns a correct value.
        """

        self.assertTrue(
            self._ip4_host == self._ip4_host,
        )

        self.assertTrue(
            self._ip4_host == Ip4Host(str(self._ip4_host)),
        )

        self.assertFalse(
            self._ip4_host == "not an IPv4 host",
        )

    def test__net_addr__ip4_host__hash(self) -> None:
        """
        Ensure the IPv4 host '__hash__()' method returns a correct value.
        """

        self.assertEqual(
            hash(self._ip4_host),
            self._results["__hash__"],
        )

    def test__net_addr__ip4_host__version(self) -> None:
        """
        Ensure the IPv4 host 'version' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_host.version,
            self._results["version"],
        )

    def test__net_addr__ip4_host__is_ip4(self) -> None:
        """
        Ensure the IPv4 host 'is_ip4' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_host.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip4_host__is_ip6(self) -> None:
        """
        Ensure the IPv4 host 'is_ip6' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_host.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip4_host__address(self) -> None:
        """
        Ensure the IPv4 host 'address' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_host.address,
            self._results["address"],
        )

    def test__net_addr__ip4_host__network(self) -> None:
        """
        Ensure the IPv4 host 'network' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_host.network,
            self._results["network"],
        )

    def test__net_addr__ip4_host__gateway(self) -> None:
        """
        Ensure the IPv4 host 'gateway' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_host.gateway,
            self._results["gateway"],
        )

    def test__net_addr__ip4_host__origin(self) -> None:
        """
        Ensure the IPv4 host 'origin' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_host.origin,
            self._results["origin"],
        )

    def test__net_addr__ip4_host__expiration_time(self) -> None:
        """
        Ensure the IPv4 host 'expiration_time' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_host.expiration_time,
            self._results["expiration_time"],
        )


@parameterized_class(
    [
        {
            "_description": "Test Ip4HostSanityError: address not in network.",
            "_args": [
                (Ip4Address("192.168.1.100"), Ip4Network("192.168.2.0/24")),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4HostSanityError,
                "error_message": (
                    "The IPv4 address doesn't belong to the provided network: "
                    "(Ip4Address('192.168.1.100'), Ip4Network('192.168.2.0/24'))"
                ),
            },
        },
        {
            "_description": "Test Ip4HostFormatError: invalid input type.",
            "_args": [
                12345,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4HostFormatError,
                "error_message": "The IPv4 host format is invalid: 12345",
            },
        },
        {
            "_description": "Test Ip4HostFormatError: invalid string format.",
            "_args": [
                "not-a-host",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4HostFormatError,
                "error_message": "The IPv4 host format is invalid: 'not-a-host'",
            },
        },
        {
            "_description": "Test Ip4HostGatewayError: gateway not in network.",
            "_args": [
                "192.168.1.100/24",
            ],
            "_kwargs": {
                "gateway": Ip4Address("10.0.0.1"),
            },
            "_results": {
                "error": Ip4HostGatewayError,
                "error_message": "The IPv4 host gateway is invalid: Ip4Address('10.0.0.1')",
            },
        },
        {
            "_description": "Test Ip4HostGatewayError: gateway equals network address.",
            "_args": [
                "192.168.1.100/24",
            ],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.0"),
            },
            "_results": {
                "error": Ip4HostGatewayError,
                "error_message": "The IPv4 host gateway is invalid: Ip4Address('192.168.1.0')",
            },
        },
        {
            "_description": "Test Ip4HostGatewayError: gateway equals broadcast address.",
            "_args": [
                "192.168.1.100/24",
            ],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.255"),
            },
            "_results": {
                "error": Ip4HostGatewayError,
                "error_message": "The IPv4 host gateway is invalid: Ip4Address('192.168.1.255')",
            },
        },
        {
            "_description": "Test Ip4HostGatewayError: gateway equals host address.",
            "_args": [
                "192.168.1.100/24",
            ],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.100"),
            },
            "_results": {
                "error": Ip4HostGatewayError,
                "error_message": "The IPv4 host gateway is invalid: Ip4Address('192.168.1.100')",
            },
        },
    ]
)
class TestNetAddrIp4HostErrors(TestCase):
    """
    The NetAddr IPv4 host error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip4_host__errors(self) -> None:
        """
        Ensure the IPv4 host raises an error on invalid input.
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip4Host(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
        )


@parameterized_class(
    [
        {
            "_description": "AssertionError: DHCP origin requires expiration_time.",
            "_args": ["192.168.1.100/24"],
            "_kwargs": {
                "origin": Ip4HostOrigin.DHCP,
            },
        },
        {
            "_description": "AssertionError: non-DHCP origin with expiration_time set.",
            "_args": ["192.168.1.100/24"],
            "_kwargs": {
                "origin": Ip4HostOrigin.STATIC,
                "expiration_time": 9999999999,
            },
        },
        {
            "_description": "AssertionError: copying Ip4Host with gateway set.",
            "_args": [Ip4Host("192.168.1.100/24")],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.1"),
            },
        },
        {
            "_description": "AssertionError: copying Ip4Host with origin set.",
            "_args": [Ip4Host("192.168.1.100/24")],
            "_kwargs": {
                "origin": Ip4HostOrigin.STATIC,
            },
        },
        {
            "_description": "AssertionError: copying Ip4Host with expiration_time set.",
            "_args": [Ip4Host("192.168.1.100/24")],
            "_kwargs": {
                "expiration_time": 9999999999,
            },
        },
    ]
)
class TestNetAddrIp4HostAssertionErrors(TestCase):
    """
    The NetAddr IPv4 host assertion error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]

    def test__net_addr__ip4_host__assertion_errors(self) -> None:
        """
        Ensure the IPv4 host raises AssertionError on constraint violations.
        """

        with self.assertRaises(AssertionError):
            Ip4Host(*self._args, **self._kwargs)


class TestNetAddrIp4HostSetters(TestCase):
    """
    The NetAddr IPv4 host property setter tests.
    """

    def setUp(self) -> None:
        """
        Initialize a base IPv4 host for setter tests.
        """

        self._ip4_host = Ip4Host("192.168.1.100/24", origin=Ip4HostOrigin.STATIC)

    def test__net_addr__ip4_host__origin_setter(self) -> None:
        """
        Ensure the IPv4 host 'origin' setter stores the new value.
        """

        self._ip4_host.origin = Ip4HostOrigin.UNKNOWN
        self.assertEqual(self._ip4_host.origin, Ip4HostOrigin.UNKNOWN)

    def test__net_addr__ip4_host__expiration_time_setter(self) -> None:
        """
        Ensure the IPv4 host 'expiration_time' setter stores the new value.
        """

        self._ip4_host.expiration_time = 9999999999
        self.assertEqual(self._ip4_host.expiration_time, 9999999999)

    def test__net_addr__ip4_host__gateway_setter(self) -> None:
        """
        Ensure the IPv4 host 'gateway' setter stores a valid gateway.
        """

        self._ip4_host.gateway = Ip4Address("192.168.1.254")
        self.assertEqual(self._ip4_host.gateway, Ip4Address("192.168.1.254"))

    def test__net_addr__ip4_host__gateway_setter__clear(self) -> None:
        """
        Ensure the IPv4 host 'gateway' setter accepts None to clear the gateway.
        """

        self._ip4_host.gateway = Ip4Address("192.168.1.1")
        self._ip4_host.gateway = None
        self.assertIsNone(self._ip4_host.gateway)

    def test__net_addr__ip4_host__gateway_setter__error(self) -> None:
        """
        Ensure the IPv4 host 'gateway' setter raises Ip4HostGatewayError on invalid gateway.
        """

        with self.assertRaises(Ip4HostGatewayError):
            self._ip4_host.gateway = Ip4Address("10.0.0.1")
