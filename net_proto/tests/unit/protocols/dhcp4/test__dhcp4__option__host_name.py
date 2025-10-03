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
Module contains tests for the DHCPv4 Host Name option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__host_name.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionHostName,
    Dhcp4OptionType,
)


class TestDhcp4OptionHostNameAsserts(TestCase):
    """
    The DHCPv4 Host Name option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the DHCPv4 Host Name option constructor.
        """

        self._args: list[Any] = [
            "host",
        ]
        self._kwargs: dict[str, Any] = {}

    def test__dhcp4__option__host_name__host_name__not_str(self) -> None:
        """
        Ensure the DHCPv4 Host Name option constructor raises an exception when the
        provided 'host_name' argument is not a str.
        """

        self._args[0] = value = 123

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionHostName(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'host_name' field must be a str. Got: {type(value)!r}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Host Name option (single char).",
            "_args": [
                "a",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 3,
                "__str__": "host_name a",
                "__repr__": "Dhcp4OptionHostName(host_name='a')",
                "__bytes__": b"\x0c\x01\x61",
                "host_name": "a",
            },
        },
        {
            "_description": "The DHCPv4 Host Name option (short).",
            "_args": [
                "host",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 6,
                "__str__": "host_name host",
                "__repr__": "Dhcp4OptionHostName(host_name='host')",
                "__bytes__": b"\x0c\x04\x68\x6f\x73\x74",
                "host_name": "host",
            },
        },
        {
            "_description": "The DHCPv4 Host Name option (alnum-hyphen).",
            "_args": [
                "tom-tit-tot-01",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 16,
                "__str__": "host_name tom-tit-tot-01",
                "__repr__": "Dhcp4OptionHostName(host_name='tom-tit-tot-01')",
                "__bytes__": b"\x0c\x0e\x74\x6f\x6d\x2d\x74\x69\x74\x2d\x74\x6f\x74\x2d\x30\x31",
                "host_name": "tom-tit-tot-01",
            },
        },
        {
            "_description": "The DHCPv4 Host Name option (empty).",
            "_args": [
                "",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 2,
                "__str__": "host_name ",
                "__repr__": "Dhcp4OptionHostName(host_name='')",
                "__bytes__": b"\x0c\x00",
                "host_name": "",
            },
        },
    ]
)
class TestDhcp4OptionHostNameAssembler(TestCase):
    """
    The DHCPv4 Host Name option assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Host Name option object with testcase arguments.
        """

        self._option = Dhcp4OptionHostName(*self._args, **self._kwargs)

    def test__dhcp4__option__host_name__len(self) -> None:
        """
        Ensure the DHCPv4 Host Name option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
        )

    def test__dhcp4__option__host_name__str(self) -> None:
        """
        Ensure the DHCPv4 Host Name option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
        )

    def test__dhcp4__option__host_name__repr(self) -> None:
        """
        Ensure the DHCPv4 Host Name option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
        )

    def test__dhcp4__option__host_name__bytes(self) -> None:
        """
        Ensure the DHCPv4 Host Name option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
        )

    def test__dhcp4__option__host_name__host_name(self) -> None:
        """
        Ensure the DHCPv4 Host Name option 'host_name' field contains a correct
        value.
        """

        self.assertEqual(
            self._option.host_name,
            self._results["host_name"],
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Host Name option (single char).",
            "_args": [
                b"\x0c\x01\x61" + b"ZH0PA",
            ],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionHostName(host_name="a"),
            },
        },
        {
            "_description": "The DHCPv4 Host Name option (short).",
            "_args": [
                b"\x0c\x04\x68\x6f\x73\x74" + b"ZH0PA",
            ],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionHostName(host_name="host"),
            },
        },
        {
            "_description": "The DHCPv4 Host Name option (alnum-hyphen).",
            "_args": [
                b"\x0c\x0e\x74\x6f\x6d\x2d\x74\x69\x74\x2d\x74\x6f\x74\x2d\x30\x31" + b"ZH0PA",
            ],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionHostName(host_name="tom-tit-tot-01"),
            },
        },
        {
            "_description": "The DHCPv4 Host Name option (empty).",
            "_args": [
                b"\x0c\x00" + b"ZH0PA",
            ],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionHostName(host_name=""),
            },
        },
        {
            "_description": "The DHCPv4 Host Name option minimum length assert.",
            "_args": [
                b"\x0c",
            ],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": ("The minimum length of the DHCPv4 Host Name option must be 2 " "bytes. Got: 1"),
            },
        },
        {
            "_description": "The DHCPv4 Host Name option incorrect 'type' field assert.",
            "_args": [
                b"\xfe\x01a",
            ],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The DHCPv4 Host Name option type must be {Dhcp4OptionType.HOST_NAME!r}. "
                    f"Got: {Dhcp4OptionType.from_int(254)!r}"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Host Name option length integrity check (II).",
            "_args": [
                b"\x0c\x01",
            ],
            "_kwargs": {},
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Host Name option length value must "
                    "be less than or equal to the length of provided bytes (2). Got: 3"
                ),
            },
        },
    ]
)
class TestDhcp4OptionHostNameParser(TestCase):
    """
    The DHCPv4 Host Name option parser tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__dhcp4__option__host_name__from_buffer(self) -> None:
        """
        Ensure the DHCPv4 Host Name option parser creates the proper option
        object or throws assertion error.
        """

        if "option" in self._results:
            option = Dhcp4OptionHostName.from_buffer(*self._args, **self._kwargs)

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Dhcp4OptionHostName.from_buffer(*self._args, **self._kwargs)

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
