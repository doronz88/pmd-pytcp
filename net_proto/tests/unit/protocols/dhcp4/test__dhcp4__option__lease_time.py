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
Module contains tests for the DHCPv4 IP Address Lease Time option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__lease_time.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionLeaseTime,
    Dhcp4OptionType,
)
from net_proto.lib.int_checks import UINT_32__MAX


class TestDhcp4OptionLeaseTimeAsserts(TestCase):
    """
    The DHCPv4 IP Address Lease Time option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the DHCPv4 IP Address Lease Time option constructor.
        """

        self._args: list[Any] = [60]
        self._kwargs: dict[str, Any] = {}

    def test__dhcp4__option__lease_time__lease_time__not_int(self) -> None:
        """
        Ensure the DHCPv4 IP Address Lease Time option constructor raises an exception when the
        provided 'lease_time' argument is not an int.
        """

        self._args[0] = value = UINT_32__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionLeaseTime(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'lease_time' field must be a 32-bit unsigned integer. Got: {value}",
        )

    def test__dhcp4__option__lease_time__lease_time__out_of_range(self) -> None:
        """
        Ensure the DHCPv4 IP Address Lease Time option constructor raises an exception when the
        provided 'lease_time' argument is outside the valid range (0..4294967295).
        """

        self._args[0] = value = 0x1_0000_0000

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionLeaseTime(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'lease_time' field must be a 32-bit unsigned integer. Got: {value}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 IP Address Lease Time option (zero).",
            "_args": [0],
            "_kwargs": {},
            "_results": {
                "__len__": 6,
                "__str__": "lease_time 0",
                "__repr__": "Dhcp4OptionLeaseTime(lease_time=0)",
                "__bytes__": b"\x33\x04\x00\x00\x00\x00",
                "lease_time": 0,
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option (one minute).",
            "_args": [60],
            "_kwargs": {},
            "_results": {
                "__len__": 6,
                "__str__": "lease_time 60",
                "__repr__": "Dhcp4OptionLeaseTime(lease_time=60)",
                "__bytes__": b"\x33\x04\x00\x00\x00\x3c",
                "lease_time": 60,
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option (one day).",
            "_args": [86400],
            "_kwargs": {},
            "_results": {
                "__len__": 6,
                "__str__": "lease_time 86400",
                "__repr__": "Dhcp4OptionLeaseTime(lease_time=86400)",
                "__bytes__": b"\x33\x04\x00\x01Q\x80",
                "lease_time": 86400,
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option (max uint32).",
            "_args": [4294967295],
            "_kwargs": {},
            "_results": {
                "__len__": 6,
                "__str__": "lease_time 4294967295",
                "__repr__": "Dhcp4OptionLeaseTime(lease_time=4294967295)",
                "__bytes__": b"\x33\x04\xff\xff\xff\xff",
                "lease_time": 4294967295,
            },
        },
    ]
)
class TestDhcp4OptionLeaseTimeAssembler(TestCase):
    """
    The DHCPv4 IP Address Lease Time option assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the DHCPv4 IP Address Lease Time option object with testcase arguments.
        """

        self._option = Dhcp4OptionLeaseTime(*self._args, **self._kwargs)

    def test__dhcp4__option__lease_time__len(self) -> None:
        """
        Ensure the DHCPv4 IP Address Lease Time option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(len(self._option), self._results["__len__"])

    def test__dhcp4__option__lease_time__str(self) -> None:
        """
        Ensure the DHCPv4 IP Address Lease Time option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(str(self._option), self._results["__str__"])

    def test__dhcp4__option__lease_time__repr(self) -> None:
        """
        Ensure the DHCPv4 IP Address Lease Time option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(repr(self._option), self._results["__repr__"])

    def test__dhcp4__option__lease_time__bytes(self) -> None:
        """
        Ensure the DHCPv4 IP Address Lease Time option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(bytes(self._option), self._results["__bytes__"])

    def test__dhcp4__option__lease_time__field(self) -> None:
        """
        Ensure the DHCPv4 IP Address Lease Time option 'lease_time' field contains a correct
        value.
        """

        self.assertEqual(self._option.lease_time, self._results["lease_time"])


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 IP Address Lease Time option (zero).",
            "_args": [memoryview(b"\x33\x04\x00\x00\x00\x00" + b"ZH0PA")],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionLeaseTime(lease_time=0),
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option (one minute).",
            "_args": [memoryview(b"\x33\x04\x00\x00\x00\x3c" + b"ZH0PA")],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionLeaseTime(lease_time=60),
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option (one day).",
            "_args": [memoryview(b"\x33\x04\x00\x01\x51\x80" + b"ZH0PA")],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionLeaseTime(lease_time=86400),
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option (max uint32).",
            "_args": [memoryview(b"\x33\x04\xff\xff\xff\xff" + b"ZH0PA")],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionLeaseTime(lease_time=4294967295),
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option minimum length assert.",
            "_args": [memoryview(b"\x33")],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the DHCPv4 IP Address Lease Time option must be 2 "
                    "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option incorrect 'type' field assert.",
            "_args": [memoryview(b"\xfe\x04\x00\x00\x00\x3c")],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The DHCPv4 IP Address Lease Time option type must be {Dhcp4OptionType.LEASE_TIME!r}. "
                    f"Got: {Dhcp4OptionType.from_int(254)!r}"
                ),
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option length integrity check (I).",
            "_args": [memoryview(b"\x33\x03\x00\x00\x3c")],
            "_kwargs": {},
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 IP Address Lease Time option length value must be "
                    "6 bytes. Got: 5"
                ),
            },
        },
        {
            "_description": "The DHCPv4 IP Address Lease Time option length integrity check (II).",
            "_args": [memoryview(b"\x33\x04")],
            "_kwargs": {},
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 IP Address Lease Time option length value must "
                    "be less than or equal to the length of provided bytes (2). Got: 6"
                ),
            },
        },
    ]
)
class TestDhcp4OptionLeaseTimeParser(TestCase):
    """
    The DHCPv4 IP Address Lease Time option parser tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__dhcp4__option__lease_time__from_bytes(self) -> None:
        """
        Ensure the DHCPv4 IP Address Lease Time option parser creates the proper option
        object or throws assertion error.
        """

        if "option" in self._results:
            option = Dhcp4OptionLeaseTime.from_bytes(
                *self._args, **self._kwargs
            )

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Dhcp4OptionLeaseTime.from_bytes(*self._args, **self._kwargs)

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
