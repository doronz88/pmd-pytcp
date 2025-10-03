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
Module contains tests for the DHCPv4 Client Identifier option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__client_id.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionClientId,
    Dhcp4OptionType,
)


class TestDhcp4OptionClientIdAsserts(TestCase):
    """
    The DHCPv4 Client Identifier option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the DHCPv4 Client Identifier option constructor.
        """

        self._args: list[Any] = [
            b"\xaa\xbb\xcc\xdd\xee\xff",
        ]
        self._kwargs: dict[str, Any] = {}

    def test__dhcp4__option__client_id__client_id__not_bytes(self) -> None:
        """
        Ensure the DHCPv4 Client Identifier option constructor raises an exception when the
        provided 'client_id' argument is not bytes.
        """

        self._args[0] = value = "not bytes"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionClientId(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'client_id' field must be bytes. Got: {type(value)!r}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Client Identifier option (empty).",
            "_args": [
                b"",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 2,
                "__str__": "client_id ",
                "__repr__": "Dhcp4OptionClientId(client_id=b'')",
                "__bytes__": b"\x3d\x00",
                "client_id": b"",
            },
        },
        {
            "_description": "The DHCPv4 Client Identifier option (6-byte ID).",
            "_args": [
                b"\xaa\xbb\xcc\xdd\xee\xff",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 8,
                "__str__": "client_id aa:bb:cc:dd:ee:ff",
                "__repr__": "Dhcp4OptionClientId(client_id=b'\\xaa\\xbb\\xcc\\xdd\\xee\\xff')",
                "__bytes__": b"\x3d\x06\xaa\xbb\xcc\xdd\xee\xff",
                "client_id": b"\xaa\xbb\xcc\xdd\xee\xff",
            },
        },
        {
            "_description": "The DHCPv4 Client Identifier option (htype + MAC, 7 bytes).",
            "_args": [
                b"\x01\xde\xad\xbe\xef\x00\x01",
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 9,
                "__str__": "client_id 01:de:ad:be:ef:00:01",
                "__repr__": "Dhcp4OptionClientId(client_id=b'\\x01\\xde\\xad\\xbe\\xef\\x00\\x01')",
                "__bytes__": b"\x3d\x07\x01\xde\xad\xbe\xef\x00\x01",
                "client_id": b"\x01\xde\xad\xbe\xef\x00\x01",
            },
        },
    ]
)
class TestDhcp4OptionClientIdAssembler(TestCase):
    """
    The DHCPv4 Client Identifier option assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Client Identifier option object with testcase arguments.
        """

        self._option = Dhcp4OptionClientId(*self._args, **self._kwargs)

    def test__dhcp4__option__client_id__len(self) -> None:
        """
        Ensure the DHCPv4 Client Identifier option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
        )

    def test__dhcp4__option__client_id__str(self) -> None:
        """
        Ensure the DHCPv4 Client Identifier option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
        )

    def test__dhcp4__option__client_id__repr(self) -> None:
        """
        Ensure the DHCPv4 Client Identifier option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
        )

    def test__dhcp4__option__client_id__bytes(self) -> None:
        """
        Ensure the DHCPv4 Client Identifier option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
        )

    def test__dhcp4__option__client_id__field(self) -> None:
        """
        Ensure the DHCPv4 Client Identifier option 'client_id' field contains a correct
        value.
        """

        self.assertEqual(
            self._option.client_id,
            self._results["client_id"],
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Client Identifier option (empty).",
            "_args": [
                b"\x3d\x00" + b"ZH0PA",
            ],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionClientId(client_id=b""),
            },
        },
        {
            "_description": "The DHCPv4 Client Identifier option (6-byte ID).",
            "_args": [
                b"\x3d\x06\xaa\xbb\xcc\xdd\xee\xff" + b"ZH0PA",
            ],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionClientId(client_id=b"\xaa\xbb\xcc\xdd\xee\xff"),
            },
        },
        {
            "_description": "The DHCPv4 Client Identifier option (htype + MAC, 7 bytes).",
            "_args": [
                b"\x3d\x07\x01\xde\xad\xbe\xef\x00\x01" + b"ZH0PA",
            ],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionClientId(client_id=b"\x01\xde\xad\xbe\xef\x00\x01"),
            },
        },
        {
            "_description": "The DHCPv4 Client Identifier option minimum length assert.",
            "_args": [
                b"\x3d",
            ],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the DHCPv4 Client Identifier option must be 2 " "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Client Identifier option incorrect 'type' field assert.",
            "_args": [
                b"\xfe\x01\x00",
            ],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The DHCPv4 Client Identifier option type must be {Dhcp4OptionType.CLIENT_ID!r}. "
                    f"Got: {Dhcp4OptionType.from_int(254)!r}"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Client Identifier option length integrity check (II).",
            "_args": [
                b"\x3d\x02",
            ],
            "_kwargs": {},
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Client Identifier option length value must "
                    "be less than or equal to the length of provided bytes (2). Got: 4"
                ),
            },
        },
    ]
)
class TestDhcp4OptionClientIdParser(TestCase):
    """
    The DHCPv4 Client Identifier option parser tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__dhcp4__option__client_id__from_buffer(self) -> None:
        """
        Ensure the DHCPv4 Client Identifier option parser creates the proper option
        object or throws assertion error.
        """

        if "option" in self._results:
            option = Dhcp4OptionClientId.from_buffer(*self._args, **self._kwargs)

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Dhcp4OptionClientId.from_buffer(*self._args, **self._kwargs)

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
