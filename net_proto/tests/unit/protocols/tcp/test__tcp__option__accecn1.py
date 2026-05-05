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
Module contains tests for the TCP AccECN1 (kind=174) option code.

net_proto/tests/unit/protocols/tcp/test__tcp__option__accecn1.py

ver 3.0.4
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore

from net_proto import (
    TCP__OPTION__ACCECN1__LEN,
    UINT_24__MAX,
    UINT_24__MIN,
    TcpOptionAccecn1,
    TcpOptionType,
)


class TestTcpOptionAccecn1Asserts(TestCase):
    """
    The TCP AccECN1 option constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Build a valid default kwargs dict for the TCP AccECN1 option
        constructor so each test can override one field and trigger its
        assert.
        """

        self._kwargs: dict[str, Any] = {
            "ee0b": 0,
            "eceb": 0,
            "ee1b": 0,
        }

    def test__tcp__option__accecn1__default_accepted(self) -> None:
        """
        Ensure the default kwargs dict itself is accepted; this guards
        the negative tests from silent regressions that would make the
        baseline invalid.
        """

        option = TcpOptionAccecn1(**self._kwargs)

        self.assertEqual(
            len(option),
            TCP__OPTION__ACCECN1__LEN,
            msg="Default-constructed option must serialize to the 11-byte AccECN1 option.",
        )

    def test__tcp__option__accecn1__ee0b__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'ee0b' value below
        UINT_24__MIN.
        """

        self._kwargs["ee0b"] = value = UINT_24__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn1(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ee0b' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ee0b' under UINT_24__MIN.",
        )

    def test__tcp__option__accecn1__ee0b__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'ee0b' value above
        UINT_24__MAX.
        """

        self._kwargs["ee0b"] = value = UINT_24__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn1(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ee0b' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ee0b' over UINT_24__MAX.",
        )

    def test__tcp__option__accecn1__eceb__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'eceb' value below
        UINT_24__MIN.
        """

        self._kwargs["eceb"] = value = UINT_24__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn1(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'eceb' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'eceb' under UINT_24__MIN.",
        )

    def test__tcp__option__accecn1__eceb__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'eceb' value above
        UINT_24__MAX.
        """

        self._kwargs["eceb"] = value = UINT_24__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn1(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'eceb' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'eceb' over UINT_24__MAX.",
        )

    def test__tcp__option__accecn1__ee1b__under_min(self) -> None:
        """
        Ensure the constructor rejects a 'ee1b' value below
        UINT_24__MIN.
        """

        self._kwargs["ee1b"] = value = UINT_24__MIN - 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn1(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ee1b' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ee1b' under UINT_24__MIN.",
        )

    def test__tcp__option__accecn1__ee1b__over_max(self) -> None:
        """
        Ensure the constructor rejects a 'ee1b' value above
        UINT_24__MAX.
        """

        self._kwargs["ee1b"] = value = UINT_24__MAX + 1

        with self.assertRaises(AssertionError) as error:
            TcpOptionAccecn1(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'ee1b' field must be a 24-bit unsigned integer. Got: {value!r}",
            msg="Unexpected assertion message for 'ee1b' over UINT_24__MAX.",
        )


@parameterized_class(
    [
        {
            "_description": "TCP AccECN1 with all-zero counters (minimum values).",
            "_kwargs": {
                "ee0b": 0,
                "eceb": 0,
                "ee1b": 0,
            },
            "_results": {
                "__str__": "accecn1 ect1=0/ce=0/ect0=0",
                "__repr__": "TcpOptionAccecn1(ee0b=0, eceb=0, ee1b=0)",
                # TCP AccECN1 wire frame (11 bytes):
                #   Byte 0     : 0xae     -> type=TcpOptionType.ACCECN1 (174)
                #   Byte 1     : 0x0b     -> len=TCP__OPTION__ACCECN1__LEN (11)
                #   Bytes 2-4  : 0x000000 -> ee1b=0   (r.ECT(1)) - first slot in AccECN1
                #   Bytes 5-7  : 0x000000 -> eceb=0   (r.CE)
                #   Bytes 8-10 : 0x000000 -> ee0b=0   (r.ECT(0)) - third slot in AccECN1
                "__bytes__": b"\xae\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            },
        },
        {
            "_description": "TCP AccECN1 with all-max counters (UINT_24 ceiling).",
            "_kwargs": {
                "ee0b": 16777215,
                "eceb": 16777215,
                "ee1b": 16777215,
            },
            "_results": {
                "__str__": "accecn1 ect1=16777215/ce=16777215/ect0=16777215",
                "__repr__": "TcpOptionAccecn1(ee0b=16777215, eceb=16777215, ee1b=16777215)",
                # TCP AccECN1 wire frame (11 bytes):
                #   Byte 0     : 0xae     -> type=TcpOptionType.ACCECN1 (174)
                #   Byte 1     : 0x0b     -> len=11
                #   Bytes 2-4  : 0xffffff -> ee1b=UINT_24__MAX
                #   Bytes 5-7  : 0xffffff -> eceb=UINT_24__MAX
                #   Bytes 8-10 : 0xffffff -> ee0b=UINT_24__MAX
                "__bytes__": b"\xae\x0b\xff\xff\xff\xff\xff\xff\xff\xff\xff",
            },
        },
        {
            "_description": "TCP AccECN1 with distinct counter values - exercises wire reordering.",
            "_kwargs": {
                "ee0b": 0x123456,
                "eceb": 0x789ABC,
                "ee1b": 0xDEF012,
            },
            "_results": {
                "__str__": "accecn1 ect1=14610450/ce=7903932/ect0=1193046",
                "__repr__": "TcpOptionAccecn1(ee0b=1193046, eceb=7903932, ee1b=14610450)",
                # TCP AccECN1 wire frame (11 bytes):
                #   Byte 0     : 0xae     -> type=TcpOptionType.ACCECN1 (174)
                #   Byte 1     : 0x0b     -> len=11
                #   Bytes 2-4  : 0xdef012 -> ee1b=0xdef012 (r.ECT(1)) - first slot
                #   Bytes 5-7  : 0x789abc -> eceb=0x789abc (r.CE)
                #   Bytes 8-10 : 0x123456 -> ee0b=0x123456 (r.ECT(0)) - third slot
                "__bytes__": b"\xae\x0b\xde\xf0\x12\x78\x9a\xbc\x12\x34\x56",
            },
        },
    ]
)
class TestTcpOptionAccecn1Assembler(TestCase):
    """
    The TCP AccECN1 option assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build the TCP AccECN1 option from the parametrized kwargs.
        """

        self._option = TcpOptionAccecn1(**self._kwargs)

    def test__tcp__option__accecn1__len(self) -> None:
        """
        Ensure '__len__()' returns TCP__OPTION__ACCECN1__LEN (11 bytes).
        """

        self.assertEqual(
            len(self._option),
            TCP__OPTION__ACCECN1__LEN,
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__tcp__option__accecn1__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__tcp__option__accecn1__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__tcp__option__accecn1__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire frame.
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__tcp__option__accecn1__type(self) -> None:
        """
        Ensure the 'type' field is TcpOptionType.ACCECN1.
        """

        self.assertEqual(
            self._option.type,
            TcpOptionType.ACCECN1,
            msg=f"Unexpected 'type' field for case: {self._description}",
        )

    def test__tcp__option__accecn1__length(self) -> None:
        """
        Ensure the 'len' field equals TCP__OPTION__ACCECN1__LEN.
        """

        self.assertEqual(
            self._option.len,
            TCP__OPTION__ACCECN1__LEN,
            msg=f"Unexpected 'len' field for case: {self._description}",
        )

    def test__tcp__option__accecn1__ee0b(self) -> None:
        """
        Ensure the 'ee0b' field exposes the provided value.
        """

        self.assertEqual(
            self._option.ee0b,
            self._kwargs["ee0b"],
            msg=f"Unexpected 'ee0b' field for case: {self._description}",
        )

    def test__tcp__option__accecn1__eceb(self) -> None:
        """
        Ensure the 'eceb' field exposes the provided value.
        """

        self.assertEqual(
            self._option.eceb,
            self._kwargs["eceb"],
            msg=f"Unexpected 'eceb' field for case: {self._description}",
        )

    def test__tcp__option__accecn1__ee1b(self) -> None:
        """
        Ensure the 'ee1b' field exposes the provided value.
        """

        self.assertEqual(
            self._option.ee1b,
            self._kwargs["ee1b"],
            msg=f"Unexpected 'ee1b' field for case: {self._description}",
        )

    def test__tcp__option__accecn1__from_buffer_round_trip(self) -> None:
        """
        Ensure 'from_buffer()' reconstructs an equal option from
        the wire bytes produced by '__bytes__()'.
        """

        decoded = TcpOptionAccecn1.from_buffer(self._results["__bytes__"])

        self.assertEqual(
            decoded,
            self._option,
            msg=f"Round-trip decode disagrees with assembled value for case: {self._description}",
        )
