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
This module contains tests for the NetAddr package MAC address support class.

net_addr/tests/unit/test__mac_address.py

ver 3.0.4
"""


from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore

from net_addr import MacAddress, MacAddressFormatError


@parameterized_class(
    [
        {
            "_description": "Test the MAC address: 00:00:00:00:00:00 (str)",
            "_args": [
                "00:00:00:00:00:00",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "00:00:00:00:00:00",
                "__repr__": "MacAddress('00:00:00:00:00:00')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00",
                "__int__": 0,
                "__hash__": hash(MacAddress("00:00:00:00:00:00")),
                "is_unspecified": True,
                "is_unicast": False,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 00:00:00:00:00:00 (None)",
            "_args": [
                None,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "00:00:00:00:00:00",
                "__repr__": "MacAddress('00:00:00:00:00:00')",
                "__bytes__": b"\x00\x00\x00\x00\x00\x00",
                "__int__": 0,
                "__hash__": hash(MacAddress("00:00:00:00:00:00")),
                "is_unspecified": True,
                "is_unicast": False,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (str)",
            "_args": [
                "02:03:04:aa:bb:cc",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "__hash__": hash(MacAddress("02:03:04:aa:bb:cc")),
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (str uppercase)",
            "_args": [
                "02:03:04:AA:BB:CC",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "__hash__": hash(MacAddress("02:03:04:aa:bb:cc")),
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (bytes)",
            "_args": [
                b"\x02\x03\x04\xaa\xbb\xcc",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "__hash__": hash(MacAddress("02:03:04:aa:bb:cc")),
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (bytearray)",
            "_args": [
                bytearray(b"\x02\x03\x04\xaa\xbb\xcc"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "__hash__": hash(MacAddress("02:03:04:aa:bb:cc")),
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (memoryview)",
            "_args": [
                memoryview(b"\x02\x03\x04\xaa\xbb\xcc"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "__hash__": hash(MacAddress("02:03:04:aa:bb:cc")),
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (MacAddress)",
            "_args": [
                MacAddress("02:03:04:aa:bb:cc"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "__hash__": hash(MacAddress("02:03:04:aa:bb:cc")),
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 02:03:04:aa:bb:cc (int)",
            "_args": [
                2211986455500,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "02:03:04:aa:bb:cc",
                "__repr__": "MacAddress('02:03:04:aa:bb:cc')",
                "__bytes__": b"\x02\x03\x04\xaa\xbb\xcc",
                "__int__": 2211986455500,
                "__hash__": hash(MacAddress("02:03:04:aa:bb:cc")),
                "is_unspecified": False,
                "is_unicast": True,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 01:00:5e:01:02:03 (str)",
            "_args": [
                "01:00:5e:01:02:03",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "01:00:5e:01:02:03",
                "__repr__": "MacAddress('01:00:5e:01:02:03')",
                "__bytes__": b"\x01\x00\x5e\x01\x02\x03",
                "__int__": 1101088752131,
                "__hash__": hash(MacAddress("01:00:5e:01:02:03")),
                "is_unspecified": False,
                "is_unicast": False,
                "is_multicast": True,
                "is_multicast_ip4": True,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 33:33:00:01:02:03 (str)",
            "_args": [
                "33:33:00:01:02:03",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "33:33:00:01:02:03",
                "__repr__": "MacAddress('33:33:00:01:02:03')",
                "__bytes__": b"\x33\x33\x00\x01\x02\x03",
                "__int__": 56294136414723,
                "__hash__": hash(MacAddress("33:33:00:01:02:03")),
                "is_unspecified": False,
                "is_unicast": False,
                "is_multicast": True,
                "is_multicast_ip4": False,
                "is_multicast_ip6": True,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: 33:33:ff:01:02:03 (str)",
            "_args": [
                "33:33:ff:01:02:03",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "33:33:ff:01:02:03",
                "__repr__": "MacAddress('33:33:ff:01:02:03')",
                "__bytes__": b"\x33\x33\xff\x01\x02\x03",
                "__int__": 56298414604803,
                "__hash__": hash(MacAddress("33:33:ff:01:02:03")),
                "is_unspecified": False,
                "is_unicast": False,
                "is_multicast": True,
                "is_multicast_ip4": False,
                "is_multicast_ip6": True,
                "is_multicast_ip6_solicited_node": True,
                "is_broadcast": False,
            },
        },
        {
            "_description": "Test the MAC address: ff:ff:ff:ff:ff:ff (str)",
            "_args": [
                "ff:ff:ff:ff:ff:ff",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "ff:ff:ff:ff:ff:ff",
                "__repr__": "MacAddress('ff:ff:ff:ff:ff:ff')",
                "__bytes__": b"\xff\xff\xff\xff\xff\xff",
                "__int__": 281474976710655,
                "__hash__": hash(MacAddress("ff:ff:ff:ff:ff:ff")),
                "is_unspecified": False,
                "is_unicast": False,
                "is_multicast": False,
                "is_multicast_ip4": False,
                "is_multicast_ip6": False,
                "is_multicast_ip6_solicited_node": False,
                "is_broadcast": True,
            },
        },
    ]
)
class TestNetAddrMacAddress(TestCase):
    """
    The NetAddr MAC address tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the MAC address object with testcase arguments.
        """

        self._mac_address = MacAddress(*self._args, **self._kwargs)

    def test__net_addr__mac_address__str(self) -> None:
        """
        Ensure the MAC address '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._mac_address),
            self._results["__str__"],
        )

    def test__net_addr__mac_address__repr(self) -> None:
        """
        Ensure the MAC address '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._mac_address),
            self._results["__repr__"],
        )

    def test__net_addr__mac_address__bytes(self) -> None:
        """
        Ensure the MAC address '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._mac_address),
            self._results["__bytes__"],
        )

    def test__net_addr__mac_address__int(self) -> None:
        """
        Ensure the MAC address '__int__()' method returns a correct value.
        """

        self.assertEqual(
            int(self._mac_address),
            self._results["__int__"],
        )

    def test__net_addr__mac_address__eq(self) -> None:
        """
        Ensure the MAC address '__eq__()' method returns a correct value.
        """

        self.assertTrue(
            self._mac_address == self._mac_address,
            msg="MacAddress must compare equal to itself.",
        )

        self.assertFalse(
            self._mac_address == MacAddress((int(self._mac_address) + 1) & 0xFFFF_FFFF_FFFF),
            msg="MacAddress values with different integer payloads must compare unequal.",
        )

        self.assertFalse(
            self._mac_address == "not a MAC address",
            msg="MacAddress must not compare equal to an arbitrary string.",
        )

    def test__net_addr__mac_address__hash(self) -> None:
        """
        Ensure the MAC address '__hash__()' method returns a correct value.
        """

        self.assertEqual(
            hash(self._mac_address),
            self._results["__hash__"],
        )

    def test__net_addr__mac_address__is_unspecified(self) -> None:
        """
        Ensure the MAC address 'is_unspecified()' property returns a correct
        value.
        """

        self.assertEqual(
            self._mac_address.is_unspecified,
            self._results["is_unspecified"],
        )

    def test__net_addr__mac_address__is_unicast(self) -> None:
        """
        Ensure the MAC address 'is_unicast' property returns a correct
        value.
        """

        self.assertEqual(
            self._mac_address.is_unicast,
            self._results["is_unicast"],
        )

    def test__net_addr__mac_address__is_multicast(self) -> None:
        """
        Ensure the MAC address 'is_multicast' property returns a correct
        value.
        """

        self.assertEqual(
            self._mac_address.is_multicast,
            self._results["is_multicast"],
        )

    def test__net_addr__mac_address__is_multicast_ip4(self) -> None:
        """
        Ensure the MAC address 'is_multicast_ip4' property returns a correct
        value.
        """

        self.assertEqual(
            self._mac_address.is_multicast__ip4,
            self._results["is_multicast_ip4"],
        )

    def test__net_addr__mac_address__is_multicast_ip6(self) -> None:
        """
        Ensure the MAC address 'is_multicast_ip6' property returns a correct
        value.
        """

        self.assertEqual(
            self._mac_address.is_multicast__ip6,
            self._results["is_multicast_ip6"],
        )

    def test__net_addr__mac_address__is_multicast_ip6_solicited_node(
        self,
    ) -> None:
        """
        Ensure the MAC address 'is_multicast__ip6__solicited_node' property
        returns a correct value.
        """

        self.assertEqual(
            self._mac_address.is_multicast__ip6__solicited_node,
            self._results["is_multicast_ip6_solicited_node"],
        )

    def test__net_addr__mac_address__is_broadcast(self) -> None:
        """
        Ensure the MAC address 'is_broadcast' property returns a correct
        value.
        """

        self.assertEqual(
            self._mac_address.is_broadcast,
            self._results["is_broadcast"],
        )

    def test__net_addr__mac_address__unspecified(self) -> None:
        """
        Ensure the MAC address 'unspecified' property yields the all-zero
        MAC address regardless of the source instance.
        """

        self.assertEqual(
            self._mac_address.unspecified,
            MacAddress(),
            msg="MacAddress.unspecified must always equal the all-zero MAC address.",
        )
        self.assertTrue(
            self._mac_address.unspecified.is_unspecified,
            msg="MacAddress.unspecified must report 'is_unspecified' as True.",
        )


@parameterized_class(
    [
        {
            "_description": "Test the MAC address format: '01:23:45:ab:cd'",
            "_args": [
                "01:23:45:ab:cd",
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": ("The MAC address format is invalid: '01:23:45:ab:cd'"),
            },
        },
        {
            "_description": "Test the MAC address format: '01:23:45:ab:cd:ef:01'",
            "_args": [
                "01:23:45:ab:cd:ef:01",
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": ("The MAC address format is invalid: '01:23:45:ab:cd:ef:01'"),
            },
        },
        {
            "_description": "Test the MAC address format: '01:23:45:ab:cd:eg'",
            "_args": [
                "01:23:45:ab:cd:eg",
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": ("The MAC address format is invalid: '01:23:45:ab:cd:eg'"),
            },
        },
        {
            "_description": "Test the MAC address format: b'\x01\x23\x45\xab\xcd'",
            "_args": [
                b"\x01\x23\x45\xab\xcd",
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": (r"The MAC address format is invalid: b'\x01#E\xab\xcd'"),
            },
        },
        {
            "_description": "Test the MAC address format: b'\x01\x23\x45\xab\xcd\xef\x01'",
            "_args": [
                b"\x01\x23\x45\xab\xcd\xef\x01",
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": (r"The MAC address format is invalid: b'\x01#E\xab\xcd\xef\x01'"),
            },
        },
        {
            "_description": "Test the MAC address format: -1",
            "_args": [
                -1,
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": "The MAC address format is invalid: -1",
            },
        },
        {
            "_description": "Test the MAC address format: 281474976710656",
            "_args": [
                281474976710656,
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": "The MAC address format is invalid: 281474976710656",
            },
        },
        {
            "_description": "Test the MAC address format: {}",
            "_args": [
                {},
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": "The MAC address format is invalid: {}",
            },
        },
        {
            "_description": "Test the MAC address format: 1.1",
            "_args": [
                1.1,
            ],
            "_kwargs": {},
            "_results": {
                "error": MacAddressFormatError,
                "error_message": "The MAC address format is invalid: 1.1",
            },
        },
    ]
)
class TestNetAddrMacAddressErrors(TestCase):
    """
    The NetAddr MAC address error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__mac_address__errors(self) -> None:
        """
        Ensure the MAC address raises an error on invalid input.
        """

        with self.assertRaises(self._results["error"]) as error:
            MacAddress(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Expected error message does not match for case: {self._description}.",
        )


class TestNetAddrMacAddressEquality(TestCase):
    """
    The NetAddr MAC address equality and inequality tests not tied to a
    parameterized matrix.
    """

    def test__net_addr__mac_address__eq__foreign_types(self) -> None:
        """
        Ensure the MAC address is never equal to a value of a foreign type,
        even when the underlying integer or byte payload would match.
        """

        mac = MacAddress("02:03:04:aa:bb:cc")

        self.assertFalse(
            mac == "02:03:04:aa:bb:cc",
            msg="MacAddress must not compare equal to its string representation.",
        )
        self.assertFalse(
            mac == int(mac),
            msg="MacAddress must not compare equal to its integer payload.",
        )
        self.assertFalse(
            mac == bytes(mac),
            msg="MacAddress must not compare equal to its bytes payload.",
        )
        self.assertFalse(
            mac == None,  # noqa: E711
            msg="MacAddress must not compare equal to None.",
        )

    def test__net_addr__mac_address__ne(self) -> None:
        """
        Ensure the MAC address '__ne__()' method returns a correct value.
        """

        mac = MacAddress("02:03:04:aa:bb:cc")
        self.assertTrue(
            mac != MacAddress("02:03:04:aa:bb:cd"),
            msg="MacAddress instances with different payloads must be unequal.",
        )
        self.assertFalse(
            mac != MacAddress("02:03:04:aa:bb:cc"),
            msg="MacAddress instances with matching payloads must not be unequal.",
        )
        self.assertTrue(
            mac != "02:03:04:aa:bb:cc",
            msg="MacAddress must be unequal to its string representation.",
        )


class TestNetAddrMacAddressHashConsistency(TestCase):
    """
    The NetAddr MAC address hash consistency tests.
    """

    def test__net_addr__mac_address__hash__distinct_instances(self) -> None:
        """
        Ensure independently constructed equal MAC addresses hash identically
        regardless of the input form.
        """

        a = MacAddress("02:03:04:aa:bb:cc")
        b = MacAddress(b"\x02\x03\x04\xaa\xbb\xcc")
        c = MacAddress(2211986455500)
        d = MacAddress("02-03-04-AA-BB-CC")

        for other, label in ((b, "bytes"), (c, "int"), (d, "dash-separated string")):
            with self.subTest(source=label):
                self.assertEqual(
                    a,
                    other,
                    msg=f"MacAddress built from {label} must compare equal to CIDR-style constructor.",
                )
                self.assertEqual(
                    hash(a),
                    hash(other),
                    msg=f"Equal MacAddress values must hash identically across constructor forms ({label}).",
                )

    def test__net_addr__mac_address__usable_in_set(self) -> None:
        """
        Ensure equal MAC addresses collapse into a single element when used
        in a set.
        """

        a = MacAddress("02:03:04:aa:bb:cc")
        b = MacAddress(2211986455500)
        c = MacAddress("02:03:04:aa:bb:cd")

        self.assertEqual(
            len({a, b}),
            1,
            msg="Two equal MacAddress values must collapse into one set element.",
        )
        self.assertEqual(
            len({a, b, c}),
            2,
            msg="Distinct MacAddress values must occupy distinct set elements.",
        )
        self.assertIn(
            a,
            {b},
            msg="Set membership lookup must treat equal MacAddress values as the same key.",
        )

    def test__net_addr__mac_address__usable_in_dict(self) -> None:
        """
        Ensure equal MAC addresses refer to the same dict entry regardless
        of which constructor form built the key.
        """

        a = MacAddress("02:03:04:aa:bb:cc")
        b = MacAddress(b"\x02\x03\x04\xaa\xbb\xcc")

        mapping = {a: "value"}

        self.assertEqual(
            mapping[b],
            "value",
            msg="MacAddress must behave consistently as a dict key across input forms.",
        )


class TestNetAddrMacAddressRoundtrip(TestCase):
    """
    The NetAddr MAC address roundtrip tests.
    """

    def test__net_addr__mac_address__roundtrip__str(self) -> None:
        """
        Ensure 'MacAddress(str(x))' yields a MAC address equal to 'x'.
        """

        for spec in (
            "00:00:00:00:00:00",
            "02:03:04:aa:bb:cc",
            "01:00:5e:01:02:03",
            "33:33:ff:01:02:03",
            "ff:ff:ff:ff:ff:ff",
        ):
            with self.subTest(spec=spec):
                mac = MacAddress(spec)
                self.assertEqual(
                    MacAddress(str(mac)),
                    mac,
                    msg=f"Roundtrip through str() must preserve MAC address {spec!r}.",
                )

    def test__net_addr__mac_address__roundtrip__int(self) -> None:
        """
        Ensure 'MacAddress(int(x))' yields a MAC address equal to 'x'.
        """

        for spec in (
            "00:00:00:00:00:00",
            "02:03:04:aa:bb:cc",
            "ff:ff:ff:ff:ff:ff",
        ):
            with self.subTest(spec=spec):
                mac = MacAddress(spec)
                self.assertEqual(
                    MacAddress(int(mac)),
                    mac,
                    msg=f"Roundtrip through int() must preserve MAC address {spec!r}.",
                )

    def test__net_addr__mac_address__roundtrip__bytes(self) -> None:
        """
        Ensure 'MacAddress(bytes(x))' yields a MAC address equal to 'x'.
        """

        for spec in (
            "00:00:00:00:00:00",
            "02:03:04:aa:bb:cc",
            "ff:ff:ff:ff:ff:ff",
        ):
            with self.subTest(spec=spec):
                mac = MacAddress(spec)
                self.assertEqual(
                    MacAddress(bytes(mac)),
                    mac,
                    msg=f"Roundtrip through bytes() must preserve MAC address {spec!r}.",
                )

    def test__net_addr__mac_address__roundtrip__copy(self) -> None:
        """
        Ensure constructing a MacAddress from another MacAddress yields an
        equal instance with the same hash.
        """

        source = MacAddress("02:03:04:aa:bb:cc")
        clone = MacAddress(source)

        self.assertEqual(
            clone,
            source,
            msg="Copy-constructed MacAddress must compare equal to the source.",
        )
        self.assertEqual(
            hash(clone),
            hash(source),
            msg="Copy-constructed MacAddress must share the source's hash.",
        )
        self.assertEqual(
            int(clone),
            int(source),
            msg="Copy-constructed MacAddress must preserve the integer payload.",
        )
