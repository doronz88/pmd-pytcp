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
Module contains tests for the DHCPv4 Router option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__router.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_addr.ip4_address import Ip4Address
from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionRouter,
    Dhcp4OptionType,
)


class TestDhcp4OptionRouterAsserts(TestCase):
    """
    The DHCPv4 Router option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the DHCPv4 Router option constructor.
        """

        self._args: list[Any] = [[Ip4Address("192.0.2.1")]]
        self._kwargs: dict[str, Any] = {}

    def test__dhcp4__option__router__routers__not_list(self) -> None:
        """
        Ensure the DHCPv4 Router option constructor raises an exception when the
        provided 'routers' argument is not a list.
        """

        self._args[0] = value = Ip4Address("192.0.2.1")

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionRouter(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'routers' field must be a list. Got: {type(value)!r}",
        )

    def test__dhcp4__option__router__routers__element_not_Ip4Address(
        self,
    ) -> None:
        """
        Ensure the DHCPv4 Router option constructor raises an exception when the
        provided 'routers' list contains a non-Ip4Address element.
        """

        value: list[Any]

        self._args[0] = value = [Ip4Address(), "not an Ip4Address"]

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionRouter(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            "The 'routers' field must be a list of Ip4Address elements. "
            f"Got: {[type(item) for item in value]!r}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Router option (empty list).",
            "_args": [[]],
            "_kwargs": {},
            "_results": {
                "__len__": 2,
                "__str__": "router []",
                "__repr__": "Dhcp4OptionRouter(routers=[])",
                "__bytes__": b"\x03\x00",
                "routers": [],
            },
        },
        {
            "_description": "The DHCPv4 Router option (one router).",
            "_args": [[Ip4Address("192.0.2.1")]],
            "_kwargs": {},
            "_results": {
                "__len__": 6,  # 2 + 1*4
                "__str__": "router ['192.0.2.1']",
                "__repr__": "Dhcp4OptionRouter(routers=[Ip4Address('192.0.2.1')])",
                "__bytes__": b"\x03\x04\xc0\x00\x02\x01",
                "routers": [Ip4Address("192.0.2.1")],
            },
        },
        {
            "_description": "The DHCPv4 Router option (two routers).",
            "_args": [[Ip4Address("192.0.2.1"), Ip4Address("198.51.100.5")]],
            "_kwargs": {},
            "_results": {
                "__len__": 10,  # 2 + 2*4
                "__str__": "router ['192.0.2.1', '198.51.100.5']",
                "__repr__": (
                    "Dhcp4OptionRouter(routers=[Ip4Address('192.0.2.1'), Ip4Address('198.51.100.5')])"
                ),
                "__bytes__": b"\x03\x08\xc0\x00\x02\x01\xc6\x33\x64\x05",
                "routers": [
                    Ip4Address("192.0.2.1"),
                    Ip4Address("198.51.100.5"),
                ],
            },
        },
        {
            "_description": "The DHCPv4 Router option (TEST-NET-3 router).",
            "_args": [[Ip4Address("203.0.113.10")]],
            "_kwargs": {},
            "_results": {
                "__len__": 6,
                "__str__": "router ['203.0.113.10']",
                "__repr__": "Dhcp4OptionRouter(routers=[Ip4Address('203.0.113.10')])",
                "__bytes__": b"\x03\x04\xcb\x00\x71\x0a",
                "routers": [Ip4Address("203.0.113.10")],
            },
        },
    ]
)
class TestDhcp4OptionRouterAssembler(TestCase):
    """
    The DHCPv4 Router option assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Router option object with testcase arguments.
        """

        self._option = Dhcp4OptionRouter(*self._args, **self._kwargs)

    def test__dhcp4__option__router__len(self) -> None:
        """
        Ensure the DHCPv4 Router option '__len__()' method returns a correct value.
        """

        self.assertEqual(len(self._option), self._results["__len__"])

    def test__dhcp4__option__router__str(self) -> None:
        """
        Ensure the DHCPv4 Router option '__str__()' method returns a correct value.
        """

        self.assertEqual(str(self._option), self._results["__str__"])

    def test__dhcp4__option__router__repr(self) -> None:
        """
        Ensure the DHCPv4 Router option '__repr__()' method returns a correct value.
        """

        self.assertEqual(repr(self._option), self._results["__repr__"])

    def test__dhcp4__option__router__bytes(self) -> None:
        """
        Ensure the DHCPv4 Router option '__bytes__()' method returns a correct value.
        """

        self.assertEqual(bytes(self._option), self._results["__bytes__"])

    def test__dhcp4__option__router__field(self) -> None:
        """
        Ensure the DHCPv4 Router option 'routers' field contains a correct value.
        """

        self.assertEqual(self._option.routers, self._results["routers"])


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Router option (empty list).",
            "_args": [b"\x03\x00" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionRouter(routers=[]),
            },
        },
        {
            "_description": "The DHCPv4 Router option (one router).",
            "_args": [b"\x03\x04\xc0\x00\x02\x01" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionRouter(routers=[Ip4Address("192.0.2.1")]),
            },
        },
        {
            "_description": "The DHCPv4 Router option (two routers).",
            "_args": [b"\x03\x08\xc0\x00\x02\x01\xc6\x33\x64\x05" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionRouter(
                    routers=[
                        Ip4Address("192.0.2.1"),
                        Ip4Address("198.51.100.5"),
                    ]
                ),
            },
        },
        {
            "_description": "The DHCPv4 Router option minimum length assert.",
            "_args": [b"\x03"],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the DHCPv4 Router option must be 2 "
                    "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Router option incorrect 'type' field assert.",
            "_args": [b"\xfe\x04\xc0\x00\x02\x01"],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The DHCPv4 Router option type must be {Dhcp4OptionType.ROUTER!r}. "
                    f"Got: {Dhcp4OptionType.from_int(254)!r}"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Router option length integrity check (multiple of 4).",
            "_args": [b"\x03\x03\x01\x02\x03"],
            "_kwargs": {},
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Router option length value (less header) "
                    "must be a multiple of 4. Got: 3"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Router option length integrity check (II).",
            "_args": [b"\x03\x04"],
            "_kwargs": {},
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Router option length value must "
                    "be less than or equal to the length of provided bytes (2). Got: 6"
                ),
            },
        },
    ]
)
class TestDhcp4OptionRouterParser(TestCase):
    """
    The DHCPv4 Router option parser tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__dhcp4__option__router__from_bytes(self) -> None:
        """
        Ensure the DHCPv4 Router option parser creates the proper option
        object or throws assertion error.
        """

        if "option" in self._results:
            option = Dhcp4OptionRouter.from_bytes(*self._args, **self._kwargs)

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Dhcp4OptionRouter.from_bytes(*self._args, **self._kwargs)

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
