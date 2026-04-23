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
This module contains tests for the NetAddr package IPv4 network support class.

net_addr/tests/unit/test__ip4_network.py

ver 3.0.4
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore

from net_addr import (
    Ip4Address,
    Ip4Host,
    Ip4Mask,
    Ip4Network,
    Ip4NetworkFormatError,
    Ip6Address,
    Ip6Host,
    Ip6Network,
    IpVersion,
)


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 network: 0.0.0.0/0 (None)",
            "_args": [
                None,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.0/0",
                "__repr__": "Ip4Network('0.0.0.0/0')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address(),
                "mask": Ip4Mask(),
                "last": Ip4Address("255.255.255.255"),
                "broadcast": Ip4Address("255.255.255.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 0.0.0.0/0 (str)",
            "_args": [
                "0.0.0.0/0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.0/0",
                "__repr__": "Ip4Network('0.0.0.0/0')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address(),
                "mask": Ip4Mask(),
                "last": Ip4Address("255.255.255.255"),
                "broadcast": Ip4Address("255.255.255.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 192.168.1.0/24 (str CIDR)",
            "_args": [
                "192.168.1.100/24",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.0/24",
                "__repr__": "Ip4Network('192.168.1.0/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.0"),
                "mask": Ip4Mask("255.255.255.0"),
                "last": Ip4Address("192.168.1.255"),
                "broadcast": Ip4Address("192.168.1.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 192.168.1.0/24 (str address mask)",
            "_args": [
                "192.168.1.100 255.255.255.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.0/24",
                "__repr__": "Ip4Network('192.168.1.0/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.0"),
                "mask": Ip4Mask("255.255.255.0"),
                "last": Ip4Address("192.168.1.255"),
                "broadcast": Ip4Address("192.168.1.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 192.168.1.0/24 (Ip4Address, Ip4Mask)",
            "_args": [
                (Ip4Address("192.168.1.100"), Ip4Mask("255.255.255.0")),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.0/24",
                "__repr__": "Ip4Network('192.168.1.0/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.0"),
                "mask": Ip4Mask("255.255.255.0"),
                "last": Ip4Address("192.168.1.255"),
                "broadcast": Ip4Address("192.168.1.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 192.168.1.0/24 (Ip4Network)",
            "_args": [
                Ip4Network("192.168.1.100/24"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.0/24",
                "__repr__": "Ip4Network('192.168.1.0/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.0"),
                "mask": Ip4Mask("255.255.255.0"),
                "last": Ip4Address("192.168.1.255"),
                "broadcast": Ip4Address("192.168.1.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 10.0.0.0/8 (str)",
            "_args": [
                "10.20.30.40/8",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "10.0.0.0/8",
                "__repr__": "Ip4Network('10.0.0.0/8')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("10.0.0.0"),
                "mask": Ip4Mask("255.0.0.0"),
                "last": Ip4Address("10.255.255.255"),
                "broadcast": Ip4Address("10.255.255.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 172.16.16.0/20 (str)",
            "_args": [
                "172.16.21.40/20",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "172.16.16.0/20",
                "__repr__": "Ip4Network('172.16.16.0/20')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("172.16.16.0"),
                "mask": Ip4Mask("255.255.240.0"),
                "last": Ip4Address("172.16.31.255"),
                "broadcast": Ip4Address("172.16.31.255"),
            },
        },
        {
            "_description": "Test the IPv4 network: 172.16.10.70/31 (str)",
            "_args": [
                "172.16.10.70/31",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "172.16.10.70/31",
                "__repr__": "Ip4Network('172.16.10.70/31')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("172.16.10.70"),
                "mask": Ip4Mask("255.255.255.254"),
                "last": Ip4Address("172.16.10.71"),
                "broadcast": Ip4Address("172.16.10.71"),
            },
        },
        {
            "_description": "Test the IPv4 network: 127.0.0.1/32 (str)",
            "_args": [
                "127.0.0.1/32",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "127.0.0.1/32",
                "__repr__": "Ip4Network('127.0.0.1/32')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("127.0.0.1"),
                "mask": Ip4Mask("255.255.255.255"),
                "last": Ip4Address("127.0.0.1"),
                "broadcast": Ip4Address("127.0.0.1"),
            },
        },
    ]
)
class TestNetAddrIp4Network(TestCase):
    """
    The NetAddr IPv4 Network tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv4 network object with testcase arguments.
        """

        self._ip4_network = Ip4Network(*self._args, **self._kwargs)

    def test__net_addr__ip4_network__str(self) -> None:
        """
        Ensure the IPv4 network '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._ip4_network),
            self._results["__str__"],
        )

    def test__net_addr__ip4_network__repr(self) -> None:
        """
        Ensure the IPv4 network '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._ip4_network),
            self._results["__repr__"],
        )

    def test__net_addr__ip4_network__eq(self) -> None:
        """
        Ensure the IPv4 network '__eq__()' method returns a correct value.
        """

        self.assertTrue(
            self._ip4_network == self._ip4_network,
            msg="An Ip4Network instance must compare equal to itself.",
        )

        self.assertTrue(
            self._ip4_network == Ip4Network(str(self._ip4_network)),
            msg="Ip4Network must compare equal to one reconstructed from its string representation.",
        )

        if int(self._ip4_network.mask) != 0:
            self.assertFalse(
                self._ip4_network
                == Ip4Network(
                    (
                        Ip4Address((int(self._ip4_network.address) - 1) & 0xFF_FF_FF_FF),
                        self._ip4_network.mask,
                    ),
                ),
                msg="Ip4Network instances with different network addresses must not compare equal.",
            )

        self.assertFalse(
            self._ip4_network
            == Ip4Network(
                (
                    self._ip4_network.address,
                    Ip4Mask(f"/{(len(self._ip4_network.mask) + 1) % 33}"),
                ),
            ),
            msg="Ip4Network instances with different masks must not compare equal.",
        )

        self.assertFalse(
            self._ip4_network == "not an IPv4 network",
            msg="Ip4Network must not compare equal to a foreign string value.",
        )

    def test__net_addr__ip4_network__version(self) -> None:
        """
        Ensure the IPv4 network 'version' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_network.version,
            self._results["version"],
        )

    def test__net_addr__ip4_network__is_ip4(self) -> None:
        """
        Ensure the IPv4 network 'is_ip4' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_network.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip4_network__is_ip6(self) -> None:
        """
        Ensure the IPv4 network 'is_ip6' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_network.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip4_network__address(self) -> None:
        """
        Ensure the IPv4 network 'address' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_network.address,
            self._results["address"],
        )

    def test__net_addr__ip4_network__mask(self) -> None:
        """
        Ensure the IPv4 network 'mask' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_network.mask,
            self._results["mask"],
        )

    def test__net_addr__ip4_network__last(self) -> None:
        """
        Ensure the IPv4 network 'last' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_network.last,
            self._results["last"],
        )

    def test__net_addr__ip4_network__broadcast(self) -> None:
        """
        Ensure the IPv4 network 'broadcast' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_network.broadcast,
            self._results["broadcast"],
        )


@parameterized_class(
    [
        {
            "_description": "Ip4Address inside network",
            "_network": "192.168.1.0/24",
            "_object": Ip4Address("192.168.1.100"),
            "_result": True,
        },
        {
            "_description": "Ip4Address equals network address",
            "_network": "192.168.1.0/24",
            "_object": Ip4Address("192.168.1.0"),
            "_result": True,
        },
        {
            "_description": "Ip4Address equals broadcast address",
            "_network": "192.168.1.0/24",
            "_object": Ip4Address("192.168.1.255"),
            "_result": True,
        },
        {
            "_description": "Ip4Address outside network",
            "_network": "192.168.1.0/24",
            "_object": Ip4Address("192.168.2.1"),
            "_result": False,
        },
        {
            "_description": "Ip4Host inside network",
            "_network": "192.168.1.0/24",
            "_object": Ip4Host("192.168.1.50/24"),
            "_result": True,
        },
        {
            "_description": "Ip4Host outside network",
            "_network": "192.168.1.0/24",
            "_object": Ip4Host("192.168.2.50/24"),
            "_result": False,
        },
        {
            "_description": "Unsupported type returns False",
            "_network": "192.168.1.0/24",
            "_object": "192.168.1.1",
            "_result": False,
        },
        {
            "_description": "Ip6Address cross-version returns False",
            "_network": "192.168.1.0/24",
            "_object": Ip6Address("2001:db8::1"),
            "_result": False,
        },
        {
            "_description": "Ip6Host cross-version returns False",
            "_network": "192.168.1.0/24",
            "_object": Ip6Host("2001:db8::1/64"),
            "_result": False,
        },
        {
            "_description": "Integer type returns False",
            "_network": "192.168.1.0/24",
            "_object": 0xC0A80101,
            "_result": False,
        },
        {
            "_description": "None returns False",
            "_network": "192.168.1.0/24",
            "_object": None,
            "_result": False,
        },
    ]
)
class TestNetAddrIp4NetworkContains(TestCase):
    """
    The NetAddr IPv4 network '__contains__()' tests.
    """

    _description: str
    _network: str
    _object: Any
    _result: bool

    def test__net_addr__ip4_network__contains(self) -> None:
        """
        Ensure the IPv4 network '__contains__()' method returns a correct value.
        """

        self.assertEqual(
            self._object in Ip4Network(self._network),
            self._result,
            msg=f"'__contains__()' returned wrong value for case: {self._description}.",
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 network format: '192.168.1.0//24'",
            "_args": [
                "192.168.1.0//24",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": "The IPv4 network format is invalid: '192.168.1.0//24'",
            },
        },
        {
            "_description": "Test the IPv4 network format: '192.168.1./24'",
            "_args": [
                "192.168.1./24",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": "The IPv4 network format is invalid: '192.168.1./24'",
            },
        },
        {
            "_description": "Test the IPv4 network format: '192.168.1.0/33'",
            "_args": [
                "192.168.1.0/33",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": "The IPv4 network format is invalid: '192.168.1.0/33'",
            },
        },
        {
            "_description": "Test the IPv4 network format: '192.168.1.0 128.255.255.255' (non-contiguous mask)",
            "_args": [
                "192.168.1.0 128.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": "The IPv4 network format is invalid: '192.168.1.0 128.255.255.255'",
            },
        },
        {
            "_description": "Test the IPv4 network format: '192.168.1.0' (missing mask)",
            "_args": [
                "192.168.1.0",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": "The IPv4 network format is invalid: '192.168.1.0'",
            },
        },
        {
            "_description": "Test the IPv4 network format: '256.168.1.0/24' (invalid address)",
            "_args": [
                "256.168.1.0/24",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": "The IPv4 network format is invalid: '256.168.1.0/24'",
            },
        },
        {
            "_description": "Test the IPv4 network format: 12345 (invalid type)",
            "_args": [
                12345,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4NetworkFormatError,
                "error_message": "The IPv4 network format is invalid: 12345",
            },
        },
    ]
)
class TestNetAddrIp4NetworkErrors(TestCase):
    """
    The NetAddr IPv4 network error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip4_network__errors(self) -> None:
        """
        Ensure the IPv4 network raises an error on invalid input.
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip4Network(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Expected error message does not match for case: {self._description}.",
        )


class TestNetAddrIp4NetworkEquality(TestCase):
    """
    The NetAddr IPv4 network equality and inequality tests not tied to
    a parameterized matrix.
    """

    def test__net_addr__ip4_network__eq__cross_version(self) -> None:
        """
        Ensure an IPv4 network never compares equal to an IPv6 network
        even when their string representations overlap.
        """

        self.assertNotEqual(
            Ip4Network("192.168.1.0/24"),
            Ip6Network("2001:db8::/24"),
            msg="Ip4Network must not compare equal to an Ip6Network.",
        )

    def test__net_addr__ip4_network__eq__foreign_types(self) -> None:
        """
        Ensure the IPv4 network is never equal to a value of a foreign
        type, including its own component pieces.
        """

        network = Ip4Network("192.168.1.0/24")

        self.assertFalse(
            network == "192.168.1.0/24",
            msg="Ip4Network must not compare equal to its string representation.",
        )
        self.assertFalse(
            network == network.address,
            msg="Ip4Network must not compare equal to its Ip4Address component.",
        )
        self.assertFalse(
            network == network.mask,
            msg="Ip4Network must not compare equal to its Ip4Mask component.",
        )
        self.assertFalse(
            network == Ip4Host("192.168.1.1/24"),
            msg="Ip4Network must not compare equal to an Ip4Host.",
        )
        self.assertFalse(
            network == 0xC0A80100,
            msg="Ip4Network must not compare equal to an integer.",
        )
        self.assertFalse(
            network == None,  # noqa: E711
            msg="Ip4Network must not compare equal to None.",
        )

    def test__net_addr__ip4_network__ne(self) -> None:
        """
        Ensure the IPv4 network '__ne__()' method returns a correct value.
        """

        network = Ip4Network("192.168.1.0/24")
        self.assertTrue(
            network != Ip4Network("192.168.2.0/24"),
            msg="Ip4Network instances with different network addresses must be unequal.",
        )
        self.assertTrue(
            network != Ip4Network("192.168.1.0/25"),
            msg="Ip4Network instances with different masks must be unequal.",
        )
        self.assertFalse(
            network != Ip4Network("192.168.1.0/24"),
            msg="Ip4Network instances with matching address and mask must not be unequal.",
        )
        self.assertTrue(
            network != "192.168.1.0/24",
            msg="Ip4Network must be unequal to its string representation.",
        )


class TestNetAddrIp4NetworkHashConsistency(TestCase):
    """
    The NetAddr IPv4 network hash consistency tests.
    """

    def test__net_addr__ip4_network__hash__distinct_instances(self) -> None:
        """
        Ensure two independently constructed equal networks hash identically.
        """

        a = Ip4Network("192.168.1.100/24")
        b = Ip4Network((Ip4Address("192.168.1.200"), Ip4Mask("/24")))
        c = Ip4Network("192.168.1.0 255.255.255.0")

        self.assertEqual(
            a,
            b,
            msg="Ip4Network built from CIDR string and (address, mask) tuple must compare equal.",
        )
        self.assertEqual(
            a,
            c,
            msg="Ip4Network built from CIDR string and 'address mask' string must compare equal.",
        )
        self.assertEqual(
            hash(a),
            hash(b),
            msg="Equal Ip4Network values must hash to the same value across constructor forms.",
        )
        self.assertEqual(
            hash(a),
            hash(c),
            msg="Equal Ip4Network values must hash to the same value across string forms.",
        )

    def test__net_addr__ip4_network__usable_in_set(self) -> None:
        """
        Ensure equal IPv4 networks collapse into a single element when
        used in a set.
        """

        a = Ip4Network("192.168.1.0/24")
        b = Ip4Network((Ip4Address("192.168.1.100"), Ip4Mask("/24")))
        c = Ip4Network("192.168.2.0/24")

        self.assertEqual(
            len({a, b}),
            1,
            msg="Two equal Ip4Network values must collapse into one set element.",
        )
        self.assertEqual(
            len({a, b, c}),
            2,
            msg="Distinct Ip4Network values must occupy distinct set elements.",
        )
        self.assertIn(
            a,
            {b},
            msg="Set membership lookup must treat equal Ip4Network values as the same key.",
        )

    def test__net_addr__ip4_network__usable_in_dict(self) -> None:
        """
        Ensure equal IPv4 networks refer to the same dict entry regardless
        of which constructor form was used to build the key.
        """

        a = Ip4Network("192.168.1.0/24")
        b = Ip4Network((Ip4Address("192.168.1.100"), Ip4Mask("/24")))

        mapping = {a: "value"}

        self.assertEqual(
            mapping[b],
            "value",
            msg="Ip4Network must behave consistently as a dict key across input forms.",
        )


class TestNetAddrIp4NetworkRoundtrip(TestCase):
    """
    The NetAddr IPv4 network string roundtrip tests.
    """

    def test__net_addr__ip4_network__roundtrip__str(self) -> None:
        """
        Ensure 'Ip4Network(str(x))' yields a network equal to 'x'.
        """

        for spec in (
            "0.0.0.0/0",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.1.0/24",
            "192.168.1.100/31",
            "255.255.255.255/32",
        ):
            with self.subTest(spec=spec):
                network = Ip4Network(spec)
                self.assertEqual(
                    Ip4Network(str(network)),
                    network,
                    msg=f"Roundtrip through str() must preserve network {spec!r}.",
                )

    def test__net_addr__ip4_network__roundtrip__copy(self) -> None:
        """
        Ensure constructing an Ip4Network from another Ip4Network yields
        an equal network with the same hash.
        """

        source = Ip4Network("192.168.1.100/24")
        clone = Ip4Network(source)

        self.assertEqual(
            clone,
            source,
            msg="Copy-constructed Ip4Network must compare equal to the source.",
        )
        self.assertEqual(
            hash(clone),
            hash(source),
            msg="Copy-constructed Ip4Network must share the source's hash.",
        )
        self.assertEqual(
            clone.address,
            source.address,
            msg="Copy-constructed Ip4Network must preserve the network address.",
        )
        self.assertEqual(
            clone.mask,
            source.mask,
            msg="Copy-constructed Ip4Network must preserve the mask.",
        )
