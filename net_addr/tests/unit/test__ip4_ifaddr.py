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

net_addr/tests/unit/test__ip4_ifaddr.py

ver 3.0.5
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore

from net_addr import (
    Ip4Address,
    Ip4IfAddr,
    Ip4IfAddrFormatError,
    Ip4IfAddrGatewayError,
    Ip4IfAddrSanityError,
    Ip4Mask,
    Ip4Network,
    Ip6IfAddr,
    IpVersion,
)


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (str)",
            "_args": [
                "192.168.1.100/24",
            ],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.1"),
            },
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4IfAddr('192.168.1.100/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
                "gateway": Ip4Address("192.168.1.1"),
            },
        },
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (Ip4IfAddr)",
            "_args": [
                Ip4IfAddr("192.168.1.100/24"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4IfAddr('192.168.1.100/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
                "gateway": None,
            },
        },
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (Ip4Address, Ip4Mask)",
            "_args": [
                (Ip4Address("192.168.1.100"), Ip4Mask("255.255.255.0")),
            ],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.1"),
            },
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4IfAddr('192.168.1.100/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
                "gateway": Ip4Address("192.168.1.1"),
            },
        },
        {
            "_description": "Test the IPv4 host: 192.168.1.100/24 (Ip4Address, Ip4Network)",
            "_args": [
                (Ip4Address("192.168.1.100"), Ip4Network("192.168.1.0/24")),
            ],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.1"),
            },
            "_results": {
                "__str__": "192.168.1.100/24",
                "__repr__": "Ip4IfAddr('192.168.1.100/24')",
                "version": IpVersion.IP4,
                "is_ip6": False,
                "is_ip4": True,
                "address": Ip4Address("192.168.1.100"),
                "network": Ip4Network("192.168.1.0/24"),
                "gateway": Ip4Address("192.168.1.1"),
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

        self._ip4_ifaddr = Ip4IfAddr(*self._args, **self._kwargs)

    def test__net_addr__ip4_host__str(self) -> None:
        """
        Ensure the IPv4 host '__str__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            str(self._ip4_ifaddr),
            self._results["__str__"],
        )

    def test__net_addr__ip4_host__repr(self) -> None:
        """
        Ensure the IPv4 host '__repr__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            repr(self._ip4_ifaddr),
            self._results["__repr__"],
        )

    def test__net_addr__ip4_host__eq(self) -> None:
        """
        Ensure the IPv4 host '__eq__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._ip4_ifaddr == self._ip4_ifaddr,
            msg="An Ip4IfAddr instance must compare equal to itself.",
        )

        self.assertTrue(
            self._ip4_ifaddr == Ip4IfAddr(str(self._ip4_ifaddr)),
            msg="Ip4IfAddr must compare equal to one reconstructed from its string representation.",
        )

        self.assertFalse(
            self._ip4_ifaddr == "not an IPv4 host",
            msg="Ip4IfAddr must not compare equal to a foreign string value.",
        )

        self.assertFalse(
            self._ip4_ifaddr == None,  # noqa: E711
            msg="Ip4IfAddr must not compare equal to None.",
        )

        self.assertFalse(
            self._ip4_ifaddr
            == Ip4IfAddr(
                (
                    Ip4Address((int(self._ip4_ifaddr.address) ^ 0x01) & 0xFF_FF_FF_FF),
                    self._ip4_ifaddr.network,
                ),
            ),
            msg="Ip4IfAddr instances with different addresses must not compare equal.",
        )

        self.assertFalse(
            self._ip4_ifaddr
            == Ip4IfAddr(
                (
                    self._ip4_ifaddr.address,
                    Ip4Mask(f"/{(len(self._ip4_ifaddr.network.mask) + 1) % 33}"),
                ),
            ),
            msg="Ip4IfAddr instances with different networks must not compare equal.",
        )

    def test__net_addr__ip4_host__version(self) -> None:
        """
        Ensure the IPv4 host 'version' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_ifaddr.version,
            self._results["version"],
        )

    def test__net_addr__ip4_host__is_ip4(self) -> None:
        """
        Ensure the IPv4 host 'is_ip4' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_ifaddr.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip4_host__is_ip6(self) -> None:
        """
        Ensure the IPv4 host 'is_ip6' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_ifaddr.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip4_host__address(self) -> None:
        """
        Ensure the IPv4 host 'address' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_ifaddr.address,
            self._results["address"],
        )

    def test__net_addr__ip4_host__network(self) -> None:
        """
        Ensure the IPv4 host 'network' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_ifaddr.network,
            self._results["network"],
        )

    def test__net_addr__ip4_host__gateway(self) -> None:
        """
        Ensure the IPv4 host 'gateway' property returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ip4_ifaddr.gateway,
            self._results["gateway"],
        )


class TestNetAddrIp4HostSemantics(TestCase):
    """
    The NetAddr IPv4 host semantic tests not tied to a parameterized matrix.
    """

    def test__net_addr__ip4_host__eq__ignores_metadata(self) -> None:
        """
        Ensure '__eq__()' compares only address and network, ignoring
        the gateway.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        plain = Ip4IfAddr("192.168.1.100/24")
        decorated = Ip4IfAddr(
            "192.168.1.100/24",
            gateway=Ip4Address("192.168.1.1"),
        )

        self.assertEqual(
            plain,
            decorated,
            msg="Ip4IfAddr equality must ignore the gateway.",
        )
        self.assertEqual(
            hash(plain),
            hash(decorated),
            msg="Equal Ip4IfAddr values must hash to the same value regardless of gateway.",
        )

    def test__net_addr__ip4_host__eq__cross_version(self) -> None:
        """
        Ensure '__eq__()' returns False when compared to an Ip6IfAddr.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertNotEqual(
            Ip4IfAddr("192.168.1.100/24"),
            Ip6IfAddr("2001:db8::c0a8:164/64"),
            msg="Ip4IfAddr must not compare equal to an Ip6IfAddr.",
        )

    def test__net_addr__ip4_host__eq__foreign_types(self) -> None:
        """
        Ensure the IPv4 host is never equal to a value of a foreign type,
        including its own component pieces.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        host = Ip4IfAddr("192.168.1.100/24")

        self.assertFalse(
            host == "192.168.1.100/24",
            msg="Ip4IfAddr must not compare equal to its string representation.",
        )
        self.assertFalse(
            host == host.address,
            msg="Ip4IfAddr must not compare equal to its Ip4Address component.",
        )
        self.assertFalse(
            host == host.network,
            msg="Ip4IfAddr must not compare equal to its Ip4Network component.",
        )
        self.assertFalse(
            host == 0,
            msg="Ip4IfAddr must not compare equal to an integer.",
        )

    def test__net_addr__ip4_host__ne(self) -> None:
        """
        Ensure the IPv4 host '__ne__()' method returns a correct value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        host = Ip4IfAddr("192.168.1.100/24")
        self.assertTrue(
            host != Ip4IfAddr("192.168.1.101/24"),
            msg="Ip4IfAddr instances with different addresses must be unequal.",
        )
        self.assertFalse(
            host != Ip4IfAddr("192.168.1.100/24"),
            msg="Ip4IfAddr instances with the same address and network must not be unequal.",
        )
        self.assertTrue(
            host != "192.168.1.100/24",
            msg="Ip4IfAddr must be unequal to its string representation.",
        )

    def test__net_addr__ip4_host__hash__distinct_instances(self) -> None:
        """
        Ensure two independently constructed equal hosts hash identically.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4IfAddr("192.168.1.100/24")
        b = Ip4IfAddr((Ip4Address("192.168.1.100"), Ip4Mask("/24")))
        self.assertEqual(
            a,
            b,
            msg="Ip4IfAddr built from string and from (address, mask) tuple must compare equal.",
        )
        self.assertEqual(
            hash(a),
            hash(b),
            msg="Equal Ip4IfAddr values must hash to the same value across constructor forms.",
        )

    def test__net_addr__ip4_host__usable_in_set(self) -> None:
        """
        Ensure equal IPv4 hosts collapse into a single element when used
        in a set.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4IfAddr("192.168.1.100/24")
        b = Ip4IfAddr((Ip4Address("192.168.1.100"), Ip4Mask("/24")))
        c = Ip4IfAddr("192.168.1.101/24")

        self.assertEqual(
            len({a, b}),
            1,
            msg="Two equal Ip4IfAddr values must collapse into one set element.",
        )
        self.assertEqual(
            len({a, b, c}),
            2,
            msg="Distinct Ip4IfAddr values must occupy distinct set elements.",
        )
        self.assertIn(
            a,
            {b},
            msg="Set membership lookup must treat equal Ip4IfAddr values as the same key.",
        )

    def test__net_addr__ip4_host__usable_in_dict(self) -> None:
        """
        Ensure equal IPv4 hosts refer to the same dict entry regardless
        of which constructor form was used to build the key.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4IfAddr("192.168.1.100/24")
        b = Ip4IfAddr((Ip4Address("192.168.1.100"), Ip4Mask("/24")))

        mapping = {a: "value"}

        self.assertEqual(
            mapping[b],
            "value",
            msg="Ip4IfAddr must behave consistently as a dict key across input forms.",
        )

    def test__net_addr__ip4_host__roundtrip__str(self) -> None:
        """
        Ensure 'Ip4IfAddr(str(x))' yields a host equal to 'x' (metadata-free).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for spec in ("0.0.0.0/0", "10.0.0.1/8", "192.168.1.100/24", "255.255.255.254/31"):
            with self.subTest(spec=spec):
                host = Ip4IfAddr(spec)
                self.assertEqual(
                    Ip4IfAddr(str(host)),
                    host,
                    msg=f"Roundtrip through str() must preserve host {spec!r}.",
                )

    def test__net_addr__ip4_host__copy_preserves_fields(self) -> None:
        """
        Ensure copying an Ip4IfAddr preserves address, network, and gateway.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        source = Ip4IfAddr(
            "192.168.1.100/24",
            gateway=Ip4Address("192.168.1.1"),
        )
        clone = Ip4IfAddr(source)

        self.assertEqual(
            clone.address,
            source.address,
            msg="Copying an Ip4IfAddr must preserve its address.",
        )
        self.assertEqual(
            clone.network,
            source.network,
            msg="Copying an Ip4IfAddr must preserve its network.",
        )
        self.assertEqual(
            clone.gateway,
            source.gateway,
            msg="Copying an Ip4IfAddr must preserve its gateway.",
        )


@parameterized_class(
    [
        {
            "_description": "Test Ip4IfAddrSanityError: address not in network.",
            "_args": [
                (Ip4Address("192.168.1.100"), Ip4Network("192.168.2.0/24")),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4IfAddrSanityError,
                "error_message": (
                    "The IPv4 address doesn't belong to the provided network: "
                    "(Ip4Address('192.168.1.100'), Ip4Network('192.168.2.0/24'))"
                ),
            },
        },
        {
            "_description": "Test Ip4IfAddrFormatError: invalid input type.",
            "_args": [
                12345,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4IfAddrFormatError,
                "error_message": "The IPv4 interface address format is invalid: 12345",
            },
        },
        {
            "_description": "Test Ip4IfAddrFormatError: invalid string format.",
            "_args": [
                "not-a-host",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4IfAddrFormatError,
                "error_message": "The IPv4 interface address format is invalid: 'not-a-host'",
            },
        },
        {
            "_description": "Test Ip4IfAddrFormatError: string with extra slash.",
            "_args": [
                "192.168.1.0/24/extra",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4IfAddrFormatError,
                "error_message": "The IPv4 interface address format is invalid: '192.168.1.0/24/extra'",
            },
        },
        {
            "_description": "Test Ip4IfAddrFormatError: None input.",
            "_args": [
                None,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4IfAddrFormatError,
                "error_message": "The IPv4 interface address format is invalid: None",
            },
        },
        {
            "_description": "Test Ip4IfAddrFormatError: maskless (Ip4Address, None) tuple is rejected.",
            "_args": [
                (Ip4Address("10.0.0.1"), None),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4IfAddrFormatError,
                "error_message": "The IPv4 interface address format is invalid: (Ip4Address('10.0.0.1'), None)",
            },
        },
        {
            "_description": "Test Ip4IfAddrFormatError: string with out-of-range mask.",
            "_args": [
                "10.0.0.1/99",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4IfAddrFormatError,
                "error_message": "The IPv4 interface address format is invalid: '10.0.0.1/99'",
            },
        },
        {
            "_description": "Test Ip4IfAddrGatewayError: gateway not in network.",
            "_args": [
                "192.168.1.100/24",
            ],
            "_kwargs": {
                "gateway": Ip4Address("10.0.0.1"),
            },
            "_results": {
                "error": Ip4IfAddrGatewayError,
                "error_message": "The IPv4 interface address gateway is invalid: Ip4Address('10.0.0.1')",
            },
        },
        {
            "_description": "Test Ip4IfAddrGatewayError: gateway equals network address.",
            "_args": [
                "192.168.1.100/24",
            ],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.0"),
            },
            "_results": {
                "error": Ip4IfAddrGatewayError,
                "error_message": "The IPv4 interface address gateway is invalid: Ip4Address('192.168.1.0')",
            },
        },
        {
            "_description": "Test Ip4IfAddrGatewayError: gateway equals broadcast address.",
            "_args": [
                "192.168.1.100/24",
            ],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.255"),
            },
            "_results": {
                "error": Ip4IfAddrGatewayError,
                "error_message": "The IPv4 interface address gateway is invalid: Ip4Address('192.168.1.255')",
            },
        },
        {
            "_description": "Test Ip4IfAddrGatewayError: gateway equals host address.",
            "_args": [
                "192.168.1.100/24",
            ],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.100"),
            },
            "_results": {
                "error": Ip4IfAddrGatewayError,
                "error_message": "The IPv4 interface address gateway is invalid: Ip4Address('192.168.1.100')",
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

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip4IfAddr(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Expected error message does not match for case: {self._description}.",
        )


@parameterized_class(
    [
        {
            "_description": "AssertionError: copying Ip4IfAddr with gateway set.",
            "_args": [Ip4IfAddr("192.168.1.100/24")],
            "_kwargs": {
                "gateway": Ip4Address("192.168.1.1"),
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

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(
            AssertionError,
            msg=f"Expected AssertionError for case: {self._description}.",
        ):
            Ip4IfAddr(*self._args, **self._kwargs)


class TestNetAddrIp4HostSetters(TestCase):
    """
    The NetAddr IPv4 host property setter tests.
    """

    def setUp(self) -> None:
        """
        Initialize a base IPv4 host for setter tests.
        """

        self._ip4_ifaddr = Ip4IfAddr("192.168.1.100/24")

    def test__net_addr__ip4_host__gateway_setter(self) -> None:
        """
        Ensure the IPv4 host 'gateway' setter stores a valid gateway.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._ip4_ifaddr.gateway = Ip4Address("192.168.1.254")
        self.assertEqual(
            self._ip4_ifaddr.gateway,
            Ip4Address("192.168.1.254"),
            msg="The 'gateway' setter must store a valid in-network address.",
        )

    def test__net_addr__ip4_host__gateway_setter__clear(self) -> None:
        """
        Ensure the IPv4 host 'gateway' setter accepts None to clear the gateway.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._ip4_ifaddr.gateway = Ip4Address("192.168.1.1")
        self._ip4_ifaddr.gateway = None
        self.assertIsNone(
            self._ip4_ifaddr.gateway,
            msg="Assigning None to 'gateway' must clear the stored gateway.",
        )

    def test__net_addr__ip4_host__gateway_setter__error__outside_network(self) -> None:
        """
        Ensure the 'gateway' setter rejects an address outside the host network.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(
            Ip4IfAddrGatewayError,
            msg="The 'gateway' setter must reject an address outside the host's network.",
        ):
            self._ip4_ifaddr.gateway = Ip4Address("10.0.0.1")

    def test__net_addr__ip4_host__gateway_setter__error__network_address(self) -> None:
        """
        Ensure the 'gateway' setter rejects the network address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(
            Ip4IfAddrGatewayError,
            msg="The 'gateway' setter must reject the network address.",
        ):
            self._ip4_ifaddr.gateway = Ip4Address("192.168.1.0")

    def test__net_addr__ip4_host__gateway_setter__error__broadcast_address(self) -> None:
        """
        Ensure the 'gateway' setter rejects the broadcast address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(
            Ip4IfAddrGatewayError,
            msg="The 'gateway' setter must reject the broadcast address.",
        ):
            self._ip4_ifaddr.gateway = Ip4Address("192.168.1.255")

    def test__net_addr__ip4_host__gateway_setter__error__host_address(self) -> None:
        """
        Ensure the 'gateway' setter rejects the host's own address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(
            Ip4IfAddrGatewayError,
            msg="The 'gateway' setter must reject the host's own address.",
        ):
            self._ip4_ifaddr.gateway = Ip4Address("192.168.1.100")


class TestNetAddrIp4IfAddrFormat(TestCase):
    """
    The NetAddr IPv4 interface-address __format__ tests.
    """

    def test__net_addr__ip4_ifaddr__format(self) -> None:
        """
        Ensure __format__ renders the host address in the
        pl / nm / hm notations; default and 'pl' equal str();
        an unknown spec raises ValueError.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        a = Ip4IfAddr("192.0.2.5/24")
        for spec, expected in [
            ("", "192.0.2.5/24"),
            ("pl", "192.0.2.5/24"),
            ("nm", "192.0.2.5/255.255.255.0"),
            ("hm", "192.0.2.5/0.0.0.255"),
        ]:
            with self.subTest(spec=spec):
                self.assertEqual(format(a, spec), expected, msg=f"format({spec!r}) must be {expected!r}.")

        self.assertEqual(f"{a}", "192.0.2.5/24", msg="Default format must equal str().")
        with self.assertRaises(ValueError, msg="An unknown format spec must raise ValueError."):
            format(a, "zz")
