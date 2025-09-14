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
Module contains tests for the DHCPv4 Parameter Request List option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__param_req_list.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionParamReqList,
    Dhcp4OptionType,
)


class TestDhcp4OptionParamReqListAsserts(TestCase):
    """
    The DHCPv4 Parameter Request List option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the DHCPv4 Parameter Request List option
        constructor.
        """

        self._args: list[Any] = [[Dhcp4OptionType.HOST_NAME]]
        self._kwargs: dict[str, Any] = {}

    def test__dhcp4__option__param_req_list__param_req_list__not_list(
        self,
    ) -> None:
        """
        Ensure the DHCPv4 Parameter Request List option constructor raises an
        exception when the provided 'param_req_list' argument is not a list.
        """

        self._args[0] = value = "not a list"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionParamReqList(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'param_req_list' field must be a list. Got: {type(value)!r}",
        )

    def test__dhcp4__option__param_req_list__param_req_list__contains_wrong_types(
        self,
    ) -> None:
        """
        Ensure the DHCPv4 Parameter Request List option constructor raises an
        exception when the provided 'param_req_list' argument contains elements
        of the wrong types.
        """

        value: list[Any]

        self._args[0] = value = [
            Dhcp4OptionType.HOST_NAME,
            "not an option type",
        ]

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionParamReqList(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'param_req_list' field must be a list of Dhcp4OptionType elements. "
            f"Got: {[type(item) for item in value]!r}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Parameter Request List option (empty).",
            "_args": [[]],
            "_kwargs": {},
            "_results": {
                "__len__": 2,
                "__str__": "param_req_list []",
                "__repr__": "Dhcp4OptionParamReqList(param_req_list=[])",
                "__bytes__": b"\x37\x00",
                "param_req_list": [],
            },
        },
        {
            "_description": "The DHCPv4 Parameter Request List option (one element).",
            "_args": [[Dhcp4OptionType.HOST_NAME]],
            "_kwargs": {},
            "_results": {
                "__len__": 3,
                "__str__": "param_req_list ['HOST_NAME']",
                "__repr__": (
                    "Dhcp4OptionParamReqList(param_req_list=[<Dhcp4OptionType.HOST_NAME: 12>])"
                ),
                "__bytes__": b"\x37\x01\x0c",
                "param_req_list": [Dhcp4OptionType.HOST_NAME],
            },
        },
        {
            "_description": "The DHCPv4 Parameter Request List option (two elements).",
            "_args": [
                [Dhcp4OptionType.HOST_NAME, Dhcp4OptionType.MESSAGE_TYPE]
            ],
            "_kwargs": {},
            "_results": {
                "__len__": 4,
                "__str__": "param_req_list ['HOST_NAME', 'MESSAGE_TYPE']",
                "__repr__": (
                    "Dhcp4OptionParamReqList(param_req_list=[<Dhcp4OptionType.HOST_NAME: 12>, "
                    "<Dhcp4OptionType.MESSAGE_TYPE: 53>])"
                ),
                "__bytes__": b"\x37\x02\x0c\x35",
                "param_req_list": [
                    Dhcp4OptionType.HOST_NAME,
                    Dhcp4OptionType.MESSAGE_TYPE,
                ],
            },
        },
    ]
)
class TestDhcp4OptionParamReqListAssembler(TestCase):
    """
    The DHCPv4 Parameter Request List option assembler tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Parameter Request List option object with testcase
        arguments.
        """

        self._option = Dhcp4OptionParamReqList(*self._args, **self._kwargs)

    def test__dhcp4__option__param_req_list__len(self) -> None:
        """
        Ensure the DHCPv4 Parameter Request List option '__len__()' method returns
        a correct value.
        """

        self.assertEqual(len(self._option), self._results["__len__"])

    def test__dhcp4__option__param_req_list__str(self) -> None:
        """
        Ensure the DHCPv4 Parameter Request List option '__str__()' method returns
        a correct value.
        """

        self.assertEqual(str(self._option), self._results["__str__"])

    def test__dhcp4__option__param_req_list__repr(self) -> None:
        """
        Ensure the DHCPv4 Parameter Request List option '__repr__()' method
        returns a correct value.
        """

        self.assertEqual(repr(self._option), self._results["__repr__"])

    def test__dhcp4__option__param_req_list__bytes(self) -> None:
        """
        Ensure the DHCPv4 Parameter Request List option '__bytes__()' method
        returns a correct value.
        """

        self.assertEqual(bytes(self._option), self._results["__bytes__"])

    def test__dhcp4__option__param_req_list__field(self) -> None:
        """
        Ensure the DHCPv4 Parameter Request List option 'param_req_list' field
        contains a correct value.
        """

        self.assertEqual(
            self._option.param_req_list, self._results["param_req_list"]
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Parameter Request List option (empty).",
            "_args": [
                b"\x37\x00" + b"ZH0PA",
            ],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionParamReqList(param_req_list=[]),
            },
        },
        {
            "_description": "The DHCPv4 Parameter Request List option (one element).",
            "_args": [
                b"\x37\x01\x0c" + b"ZH0PA",
            ],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionParamReqList(
                    param_req_list=[Dhcp4OptionType.HOST_NAME]
                ),
            },
        },
        {
            "_description": "The DHCPv4 Parameter Request List option (two elements).",
            "_args": [
                b"\x37\x02\x0c\x35" + b"ZH0PA",
            ],
            "_kwargs": {},
            "_results": {
                "option": Dhcp4OptionParamReqList(
                    param_req_list=[
                        Dhcp4OptionType.HOST_NAME,
                        Dhcp4OptionType.MESSAGE_TYPE,
                    ]
                ),
            },
        },
        {
            "_description": "The DHCPv4 Parameter Request List option minimum length assert.",
            "_args": [
                b"\x37",
            ],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    "The minimum length of the DHCPv4 Parameter Request List option must be 2 "
                    "bytes. Got: 1"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Parameter Request List option incorrect 'type' field assert.",
            "_args": [
                b"\xfe\x00",
            ],
            "_kwargs": {},
            "_results": {
                "error": AssertionError,
                "error_message": (
                    f"The DHCPv4 Parameter Request List option type must be {Dhcp4OptionType.PARAM_REQ_LIST!r}. "
                    f"Got: {Dhcp4OptionType.from_int(254)!r}"
                ),
            },
        },
        {
            "_description": "The DHCPv4 Parameter Request List option length integrity check (II).",
            "_args": [
                b"\x37\x02",
            ],
            "_kwargs": {},
            "_results": {
                "error": Dhcp4IntegrityError,
                "error_message": (
                    "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Parameter Request List option length value must "
                    "be less than or equal to the length of provided bytes (2). Got: 4"
                ),
            },
        },
    ]
)
class TestDhcp4OptionParamReqListParser(TestCase):
    """
    The DHCPv4 Parameter Request List option parser tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__dhcp4__option__param_req_list__from_buffer(self) -> None:
        """
        Ensure the DHCPv4 Parameter Request List option parser creates the proper
        option object or throws assertion error.
        """

        if "option" in self._results:
            option = Dhcp4OptionParamReqList.from_buffer(
                *self._args, **self._kwargs
            )

            self.assertEqual(
                option,
                self._results["option"],
            )

        if "error" in self._results:
            with self.assertRaises(self._results["error"]) as error:
                Dhcp4OptionParamReqList.from_buffer(*self._args, **self._kwargs)

            self.assertEqual(
                str(error.exception),
                self._results["error_message"],
            )
