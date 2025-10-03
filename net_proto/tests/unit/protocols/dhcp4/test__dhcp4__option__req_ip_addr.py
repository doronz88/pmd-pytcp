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
Module contains tests for the DHCPv4 Requested Ip Address option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__req_ip_addr.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_addr.ip4_address import Ip4Address
from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionReqIpAddr,
    Dhcp4OptionType,
)


class TestDhcp4OptionReqIpAddrAsserts(TestCase):
    """
    The DHCPv4 Requested Ip Address option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the DHCPv4 Requested Ip Address option constructor.
        """

        self._args: list[Any] = [
            Ip4Address("192.0.2.1"),
        ]
        self._kwargs: dict[str, Any] = {}

    def test__dhcp4__option__req_ip_addr__req_ip_addr__not_Ip4Address(
        self,
    ) -> None:
        """
        Ensure the DHCPv4 Requested Ip Address option constructor raises an exception when the
        provided 'req_ip_addr' argument is not an Ip4Address.
        """

        self._args[0] = value = "not an Ip4Address"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionReqIpAddr(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'req_ip_addr' field must be an Ip4Address. Got: {type(value)!r}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Requested Ip Address option (TEST-NET-1).",
            "_args": [
                Ip4Address("192.0.2.1"),
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 6,
                "__str__": "req_ip_addr 192.0.2.1",
                "__repr__": "Dhcp4OptionReqIpAddr(req_ip_addr=Ip4Address('192.0.2.1'))",
                "__bytes__": b"\x32\x04\xc0\x00\x02\x01",
                "req_ip_addr": Ip4Address("192.0.2.1"),
            },
        },
        {
            "_description": "The DHCPv4 Requested Ip Address option (low address).",
            "_args": [
                Ip4Address("1.2.3.4"),
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 6,
                "__str__": "req_ip_addr 1.2.3.4",
                "__repr__": "Dhcp4OptionReqIpAddr(req_ip_addr=Ip4Address('1.2.3.4'))",
                "__bytes__": b"\x32\x04\x01\x02\x03\x04",
                "req_ip_addr": Ip4Address("1.2.3.4"),
            },
        },
        {
            "_description": "The DHCPv4 Requested Ip Address option (TEST-NET-3).",
            "_args": [
                Ip4Address("203.0.113.10"),
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 6,
                "__str__": "req_ip_addr 203.0.113.10",
                "__repr__": "Dhcp4OptionReqIpAddr(req_ip_addr=Ip4Address('203.0.113.10'))",
                "__bytes__": b"\x32\x04\xcb\x00\x71\x0a",
                "req_ip_addr": Ip4Address("203.0.113.10"),
            },
        },
    ]
)
class TestDhcp4OptionReqIpAddrAssembler(TestCase):
    """
    The DHCPv4 Requested Ip Address option assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Requested Ip Address option object with testcase arguments.
        """

        self._option = Dhcp4OptionReqIpAddr(*self._args, **self._kwargs)

    def test__dhcp4__option__req_ip_addr__len(self) -> None:
        """
        Ensure the DHCPv4 Requested Ip Address option '__len__()' method returns a correct
        value.
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
        )

    def test__dhcp4__option__req_ip_addr__str(self) -> None:
        """
        Ensure the DHCPv4 Requested Ip Address option '__str__()' method returns a correct
        value.
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
        )

    def test__dhcp4__option__req_ip_addr__repr(self) -> None:
        """
        Ensure the DHCPv4 Requested Ip Address option '__repr__()' method returns a correct
        value.
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
        )

    def test__dhcp4__option__req_ip_addr__bytes(self) -> None:
        """
        Ensure the DHCPv4 Requested Ip Address option '__bytes__()' method returns a correct
        value.
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
        )

    def test__dhcp4__option__req_ip_addr__field(self) -> None:
        """
        Ensure the DHCPv4 Requested Ip Address option 'req_ip_addr' field contains a correct
        value.
        """

        self.assertEqual(
            self._option.req_ip_addr,
            self._results["req_ip_addr"],
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Requested Ip Address option (TEST-NET-1).",
            "_args": [
                b"\x32\x04\xc0\x00\x02\x01" + b"ZH0PA",
            ],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionReqIpAddr(req_ip_addr=Ip4Address("192.0.2.1")),
            },
        },
        {
            "_description": "The DHCPv4 Requested Ip Address option (low address).",
            "_args": [
                b"\x32\x04\x01\x02\x03\x04" + b"ZH0PA",
            ],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionReqIpAddr(req_ip_addr=Ip4Address("1.2.3.4")),
            },
        },
        {
            "_description": "The DHCPv4 Requested Ip Address option (TEST-NET-3).",
            "_args": [
                b"\x32\x04\xcb\x00\x71\x0a" + b"ZH0PA",
            ],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionReqIpAddr(req_ip_addr=Ip4Address("203.0.113.10")),
            },
        },
        {
            "_description": "The DHCPv4 Requested Ip Address option minimum length assert.",
            "_args": [
                b"\x32",
            ],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the DHCPv4 Requested Ip Address option must be 2 " "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Requested Ip Address option incorrect 'type' field assert.",
            "_args": [
                b"\xfe\x04\xc0\x00\x02\x01",
            ],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The DHCPv4 Requested Ip Address option type must be {Dhcp4OptionType.REQ_IP_ADDR!r}. "
                    f"Got: {Dhcp4OptionType.from_int(254)!r}"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Requested Ip Address option length integrity check (I).",
            "_args": [
                b"\x32\x03\xc0\x00\x02",
            ],
            "_kwargs": {},
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Requested Ip Address option length value must be "
                    "6 bytes. Got: 5"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Requested Ip Address option length integrity check (II).",
            "_args": [
                b"\x32\x04",
            ],
            "_kwargs": {},
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Requested Ip Address option length value must "
                    "be less than or equal to the length of provided bytes (2). Got: 6"
                ),
            },
        },
    ]
)
class TestDhcp4OptionReqIpAddrParser(TestCase):
    """
    The DHCPv4 Requested Ip Address option parser tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__dhcp4__option__req_ip_addr__from_buffer(self) -> None:
        """
        Ensure the DHCPv4 Requested Ip Address option parser creates the proper option
        object or throws assertion error.
        """

        if "option" in self._results:
            option = Dhcp4OptionReqIpAddr.from_buffer(*self._args, **self._kwargs)

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Dhcp4OptionReqIpAddr.from_buffer(*self._args, **self._kwargs)

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
