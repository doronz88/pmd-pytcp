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
Module contains tests for the DHCPv4 Server Identifier option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__srv_id.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_addr.ip4_address import Ip4Address
from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionSrvId,
    Dhcp4OptionType,
)


class TestDhcp4OptionSrvIdAsserts(TestCase):
    """
    The DHCPv4 Server Identifier option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the DHCPv4 Server Identifier option constructor.
        """

        self._args: list[Any] = [Ip4Address("192.0.2.1")]
        self._kwargs: dict[str, Any] = {}

    def test__dhcp4__option__srv_id__srv_id__not_Ip4Address(self) -> None:
        """
        Ensure the DHCPv4 Server Identifier option constructor raises an exception when the
        provided 'srv_id' argument is not an Ip4Address.
        """

        self._args[0] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionSrvId(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'srv_id' field must be an Ip4Address. Got: {type(value)!r}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Server Identifier option (TEST-NET-1).",
            "_args": [Ip4Address("192.0.2.1")],
            "_kwargs": {},
            "_results": {
                "__len__": 6,
                "__str__": "server_identifier 192.0.2.1",
                "__repr__": "Dhcp4OptionSrvId(srv_id=Ip4Address('192.0.2.1'))",
                "__bytes__": b"\x36\x04\xc0\x00\x02\x01",
                "srv_id": Ip4Address("192.0.2.1"),
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option (low address).",
            "_args": [Ip4Address("1.2.3.4")],
            "_kwargs": {},
            "_results": {
                "__len__": 6,
                "__str__": "server_identifier 1.2.3.4",
                "__repr__": "Dhcp4OptionSrvId(srv_id=Ip4Address('1.2.3.4'))",
                "__bytes__": b"\x36\x04\x01\x02\x03\x04",
                "srv_id": Ip4Address("1.2.3.4"),
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option (TEST-NET-3).",
            "_args": [Ip4Address("203.0.113.10")],
            "_kwargs": {},
            "_results": {
                "__len__": 6,
                "__str__": "server_identifier 203.0.113.10",
                "__repr__": "Dhcp4OptionSrvId(srv_id=Ip4Address('203.0.113.10'))",
                "__bytes__": b"\x36\x04\xcb\x00\x71\x0a",
                "srv_id": Ip4Address("203.0.113.10"),
            },
        },
    ]
)
class TestDhcp4OptionSrvIdAssembler(TestCase):
    """
    The DHCPv4 Server Identifier option assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Server Identifier option object with testcase arguments.
        """

        self._option = Dhcp4OptionSrvId(*self._args, **self._kwargs)

    def test__dhcp4__option__srv_id__len(self) -> None:
        """
        Ensure the DHCPv4 Server Identifier option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(len(self._option), self._results["__len__"])

    def test__dhcp4__option__srv_id__str(self) -> None:
        """
        Ensure the DHCPv4 Server Identifier option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(str(self._option), self._results["__str__"])

    def test__dhcp4__option__srv_id__repr(self) -> None:
        """
        Ensure the DHCPv4 Server Identifier option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(repr(self._option), self._results["__repr__"])

    def test__dhcp4__option__srv_id__bytes(self) -> None:
        """
        Ensure the DHCPv4 Server Identifier option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(bytes(self._option), self._results["__bytes__"])

    def test__dhcp4__option__srv_id__field(self) -> None:
        """
        Ensure the DHCPv4 Server Identifier option 'srv_id' field contains a correct
        value.
        """

        self.assertEqual(self._option.srv_id, self._results["srv_id"])


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Server Identifier option (TEST-NET-1).",
            "_args": [b"\x36\x04\xc0\x00\x02\x01" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionSrvId(srv_id=Ip4Address("192.0.2.1")),
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option (low address).",
            "_args": [b"\x36\x04\x01\x02\x03\x04" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionSrvId(srv_id=Ip4Address("1.2.3.4")),
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option (TEST-NET-3).",
            "_args": [b"\x36\x04\xcb\x00\x71\x0a" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionSrvId(srv_id=Ip4Address("203.0.113.10")),
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option minimum length assert.",
            "_args": [b"\x36"],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the DHCPv4 Subnet Mask option must be 2 "
                    "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option incorrect 'type' field assert.",
            "_args": [b"\xfe\x04\xc0\x00\x02\x01"],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The DHCPv4 Server Identifier option type must be {Dhcp4OptionType.SRV_ID!r}. "
                    f"Got: {Dhcp4OptionType.from_int(254)!r}"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option length integrity check (I).",
            "_args": [
                b"\x36\x03\xc0\x00\x02"
            ],  # claims 3 -> total 5 (should be 6)
            "_kwargs": {},
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Server Identifier option length value must be "
                    "6 bytes. Got: 5"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Server Identifier option length integrity check (II).",
            "_args": [
                b"\x36\x04"
            ],  # claims 4 -> total 6, but provided only 2 bytes
            "_kwargs": {},
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Server Identifier option length value must "
                    "be less than or equal to the length of provided bytes (2). Got: 6"
                ),
            },
        },
    ]
)
class TestDhcp4OptionSrvIdParser(TestCase):
    """
    The DHCPv4 Server Identifier option parser tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__dhcp4__option__srv_id__from_bytes(self) -> None:
        """
        Ensure the DHCPv4 Server Identifier option parser creates the proper option
        object or throws assertion error.
        """

        if "option" in self._results:
            option = Dhcp4OptionSrvId.from_bytes(*self._args, **self._kwargs)

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Dhcp4OptionSrvId.from_bytes(*self._args, **self._kwargs)

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
