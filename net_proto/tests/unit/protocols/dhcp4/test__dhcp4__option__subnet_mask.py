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
Module contains tests for the DHCPv4 Subnet Mask option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__subnet_mask.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_addr.ip4_mask import Ip4Mask
from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionSubnetMask,
    Dhcp4OptionType,
)


class TestDhcp4OptionSubnetMaskAsserts(TestCase):
    """
    The DHCPv4 Subnet Mask option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the DHCPv4 Subnet Mask option constructor.
        """

        self._args: list[Any] = [Ip4Mask("255.255.255.0")]
        self._kwargs: dict[str, Any] = {}

    def test__dhcp4__option__subnet_mask__subnet_mask__not_Ip4Mask(
        self,
    ) -> None:
        """
        Ensure the DHCPv4 Subnet Mask option constructor raises an exception when the
        provided 'subnet_mask' argument is not an Ip4Mask.
        """

        self._args[0] = value = "255.255.255.0"  # not an Ip4Mask instance

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionSubnetMask(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'subnet_mask' field must be an Ip4Mask. Got: {type(value)!r}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Subnet Mask option (/24).",
            "_args": [Ip4Mask("255.255.255.0")],
            "_kwargs": {},
            "_results": {
                "__len__": 6,
                "__str__": "subnet_mask /24",
                "__repr__": "Dhcp4OptionSubnetMask(subnet_mask=Ip4Mask('/24'))",
                "__bytes__": b"\x01\x04\xff\xff\xff\x00",
                "subnet_mask": Ip4Mask("255.255.255.0"),
            },
        },
        {
            "_description": "The DHCPv4 Subnet Mask option (/16).",
            "_args": [Ip4Mask("255.255.0.0")],
            "_kwargs": {},
            "_results": {
                "__len__": 6,
                "__str__": "subnet_mask /16",
                "__repr__": "Dhcp4OptionSubnetMask(subnet_mask=Ip4Mask('/16'))",
                "__bytes__": b"\x01\x04\xff\xff\x00\x00",
                "subnet_mask": Ip4Mask("255.255.0.0"),
            },
        },
        {
            "_description": "The DHCPv4 Subnet Mask option (/8).",
            "_args": [Ip4Mask("255.0.0.0")],
            "_kwargs": {},
            "_results": {
                "__len__": 6,
                "__str__": "subnet_mask /8",
                "__repr__": "Dhcp4OptionSubnetMask(subnet_mask=Ip4Mask('/8'))",
                "__bytes__": b"\x01\x04\xff\x00\x00\x00",
                "subnet_mask": Ip4Mask("255.0.0.0"),
            },
        },
    ]
)
class TestDhcp4OptionSubnetMaskAssembler(TestCase):
    """
    The DHCPv4 Subnet Mask option assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Subnet Mask option object with testcase arguments.
        """

        self._option = Dhcp4OptionSubnetMask(*self._args, **self._kwargs)

    def test__dhcp4__option__subnet_mask__len(self) -> None:
        """
        Ensure the DHCPv4 Subnet Mask option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(len(self._option), self._results["__len__"])

    def test__dhcp4__option__subnet_mask__str(self) -> None:
        """
        Ensure the DHCPv4 Subnet Mask option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(str(self._option), self._results["__str__"])

    def test__dhcp4__option__subnet_mask__repr(self) -> None:
        """
        Ensure the DHCPv4 Subnet Mask option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(repr(self._option), self._results["__repr__"])

    def test__dhcp4__option__subnet_mask__bytes(self) -> None:
        """
        Ensure the DHCPv4 Subnet Mask option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(bytes(self._option), self._results["__bytes__"])

    def test__dhcp4__option__subnet_mask__field(self) -> None:
        """
        Ensure the DHCPv4 Subnet Mask option 'subnet_mask' field contains a correct
        value.
        """

        self.assertEqual(self._option.subnet_mask, self._results["subnet_mask"])


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Subnet Mask option (/24).",
            "_args": [b"\x01\x04\xff\xff\xff\x00" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionSubnetMask(
                    subnet_mask=Ip4Mask("255.255.255.0")
                ),
            },
        },
        {
            "_description": "The DHCPv4 Subnet Mask option (/16).",
            "_args": [b"\x01\x04\xff\xff\x00\x00" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionSubnetMask(
                    subnet_mask=Ip4Mask("255.255.0.0")
                ),
            },
        },
        {
            "_description": "The DHCPv4 Subnet Mask option (/8).",
            "_args": [b"\x01\x04\xff\x00\x00\x00" + b"ZH0PA"],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionSubnetMask(
                    subnet_mask=Ip4Mask("255.0.0.0")
                ),
            },
        },
        {
            "_description": "The DHCPv4 Subnet Mask option minimum length assert.",
            "_args": [b"\x01"],
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
            "_description": "The DHCPv4 Subnet Mask option incorrect 'type' field assert.",
            "_args": [b"\xfe\x04\xff\xff\xff\x00"],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The DHCPv4 Subnet Mask option type must be {Dhcp4OptionType.SUBNET_MASK!r}. "
                    f"Got: {Dhcp4OptionType.from_int(254)!r}"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Subnet Mask option length integrity check (I).",
            "_args": [
                b"\x01\x03\xff\xff\xff"
            ],  # claims 3 -> total 5 (should be 6)
            "_kwargs": {},
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Subnet Mask option length value must be "
                    "6 bytes. Got: 5"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Subnet Mask option length integrity check (II).",
            "_args": [
                b"\x01\x04"
            ],  # claims 4 -> total 6, but provided only 2 bytes
            "_kwargs": {},
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Subnet Mask option length value must "
                    "be less than or equal to the length of provided bytes (2). Got: 6"
                ),
            },
        },
    ]
)
class TestDhcp4OptionSubnetMaskParser(TestCase):
    """
    The DHCPv4 Subnet Mask option parser tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__dhcp4__option__subnet_mask__from_bytes(self) -> None:
        """
        Ensure the DHCPv4 Subnet Mask option parser creates the proper option
        object or throws assertion error.
        """

        if "option" in self._results:
            option = Dhcp4OptionSubnetMask.from_bytes(
                *self._args, **self._kwargs
            )

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Dhcp4OptionSubnetMask.from_bytes(*self._args, **self._kwargs)

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
