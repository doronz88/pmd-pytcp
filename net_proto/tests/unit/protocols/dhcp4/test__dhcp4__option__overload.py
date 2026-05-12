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
Module contains tests for the DHCPv4 Option Overload option
(RFC 2132 §9.3) wire-format codec.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__overload.py

ver 3.0.4
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore

from net_proto import Dhcp4IntegrityError, Dhcp4OptionOverload, Dhcp4OptionType


class TestDhcp4OptionOverloadAsserts(TestCase):
    """
    The DHCPv4 Option Overload option constructor argument assert tests.
    """

    def test__dhcp4__option__overload__rejects_zero(self) -> None:
        """
        Ensure the constructor raises when 'value' is 0 — the
        defined values are exactly 1/2/3.

        Reference: RFC 2132 §9.3 (value must be 1, 2, or 3).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionOverload(0)

        self.assertIn(
            "must be 1, 2, or 3",
            str(error.exception),
            msg="value=0 must trigger the enum assertion.",
        )

    def test__dhcp4__option__overload__rejects_four(self) -> None:
        """
        Ensure the constructor raises when 'value' is 4 (out of
        the defined 1/2/3 set).

        Reference: RFC 2132 §9.3 (value must be 1, 2, or 3).
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionOverload(4)

        self.assertIn(
            "must be 1, 2, or 3",
            str(error.exception),
            msg="value=4 must trigger the enum assertion.",
        )


@parameterized_class(
    [
        {
            "_description": "Overload value 1 — 'file' field carries options.",
            "_args": [1],
            "_results": {
                "__len__": 3,
                "__str__": "option_overload 1",
                "__repr__": "Dhcp4OptionOverload(value=1)",
                "__bytes__": b"\x34\x01\x01",
                "value": 1,
                "includes_file": True,
                "includes_sname": False,
            },
        },
        {
            "_description": "Overload value 2 — 'sname' field carries options.",
            "_args": [2],
            "_results": {
                "__len__": 3,
                "__str__": "option_overload 2",
                "__repr__": "Dhcp4OptionOverload(value=2)",
                "__bytes__": b"\x34\x01\x02",
                "value": 2,
                "includes_file": False,
                "includes_sname": True,
            },
        },
        {
            "_description": "Overload value 3 — both fields carry options.",
            "_args": [3],
            "_results": {
                "__len__": 3,
                "__str__": "option_overload 3",
                "__repr__": "Dhcp4OptionOverload(value=3)",
                "__bytes__": b"\x34\x01\x03",
                "value": 3,
                "includes_file": True,
                "includes_sname": True,
            },
        },
    ]
)
class TestDhcp4OptionOverloadAssembler(TestCase):
    """
    The DHCPv4 Option Overload option assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build the SUT.
        """

        self._option = Dhcp4OptionOverload(*self._args)

    def test__dhcp4__option__overload__len(self) -> None:
        """
        Ensure 'len(option)' equals the documented 3-byte total.

        Reference: RFC 2132 §9.3 (option layout: 1 + 1 + 1 bytes).
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected len for case: {self._description}",
        )

    def test__dhcp4__option__overload__bytes(self) -> None:
        """
        Ensure 'bytes(option)' matches the wire-format byte sequence.

        Reference: RFC 2132 §9.3 (wire-format diagram).
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__dhcp4__option__overload__includes_file(self) -> None:
        """
        Ensure 'includes_file' matches the documented decoding for
        each overload value.

        Reference: RFC 2132 §9.3 (value 1 / 3 ⇒ file).
        """

        self.assertEqual(
            self._option.includes_file,
            self._results["includes_file"],
            msg=f"Unexpected includes_file for case: {self._description}",
        )

    def test__dhcp4__option__overload__includes_sname(self) -> None:
        """
        Ensure 'includes_sname' matches the documented decoding
        for each overload value.

        Reference: RFC 2132 §9.3 (value 2 / 3 ⇒ sname).
        """

        self.assertEqual(
            self._option.includes_sname,
            self._results["includes_sname"],
            msg=f"Unexpected includes_sname for case: {self._description}",
        )

    def test__dhcp4__option__overload__from_buffer(self) -> None:
        """
        Ensure 'from_buffer' round-trips back to the original value.

        Reference: RFC 2132 §9.3 (wire-format round-trip).
        """

        parsed = Dhcp4OptionOverload.from_buffer(self._results["__bytes__"])

        self.assertEqual(
            parsed.value,
            self._results["value"],
            msg=f"Unexpected round-trip value for case: {self._description}",
        )


class TestDhcp4OptionOverloadIntegrity(TestCase):
    """
    The DHCPv4 Option Overload option integrity-check tests.
    """

    def test__dhcp4__option__overload__bad_length(self) -> None:
        """
        Ensure 'from_buffer' raises when the TLV's length byte does
        not equal 1.

        Reference: RFC 2132 §9.3 (length = 1).
        """

        bad_buffer = b"\x34\x02\x01\x00"  # length=2 (wrong; must be 1)

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionOverload.from_buffer(bad_buffer)

        self.assertIn(
            "length value must be 3 bytes",
            str(error.exception),
            msg="Bad-length DHCPv4 Option Overload must raise Dhcp4IntegrityError.",
        )

    def test__dhcp4__option__overload__bad_value(self) -> None:
        """
        Ensure 'from_buffer' raises when the value byte is outside
        the {1, 2, 3} set.

        Reference: RFC 2132 §9.3 (value must be 1, 2, or 3).
        """

        bad_buffer = b"\x34\x01\x07"  # value=7 (illegal)

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionOverload.from_buffer(bad_buffer)

        self.assertIn(
            "value must be 1, 2, or 3",
            str(error.exception),
            msg="Out-of-range value must raise Dhcp4IntegrityError.",
        )

    def test__dhcp4__option__overload__wrong_type(self) -> None:
        """
        Ensure 'from_buffer' refuses a buffer whose first byte is
        not 'Dhcp4OptionType.OPTION_OVERLOAD'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        bad_buffer = b"\x33\x01\x01"  # type=51 (Lease Time)

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionOverload.from_buffer(bad_buffer)

        self.assertIn(
            f"option type must be {Dhcp4OptionType.OPTION_OVERLOAD!r}",
            str(error.exception),
            msg="Wrong-type buffer must trigger the type assertion.",
        )
