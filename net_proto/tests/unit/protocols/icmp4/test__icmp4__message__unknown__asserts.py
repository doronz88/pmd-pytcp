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
Module contains tests for the ICMPv4 unknown message assembler & parser asserts.

net_addr/tests/unit/protocols/icmp4/test__icmp4__message__unknown__asserts.py

ver 3.0.4
"""


from typing import Any

from testslide import TestCase

from net_proto import (
    UINT_16__MAX,
    UINT_16__MIN,
    Icmp4Code,
    Icmp4MessageUnknown,
    Icmp4Type,
    inet_cksum,
)


class TestIcmp4MessageUnknownAssemblerAsserts(TestCase):
    """
    The ICMPv4 unknown message assembler constructor argument assert tests.
    """

    def setUp(self) -> None:
        """
        Create the default arguments for the ICMPv4 unknown message
        constructor.
        """

        self._kwargs: dict[str, Any] = {
            "type": Icmp4Type.from_int(255),
            "code": Icmp4Code.from_int(255),
            "cksum": 0,
            "data": b"",
        }

    def test__icmp4__message__unknown__type__not_Icmp4Type(self) -> None:
        """
        Ensure the ICMPv4 message constructor raises an exception
        when the provided 'type' argument is not an Icmp4Type.
        """

        self._kwargs["type"] = value = "not an Icmp4Type"

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'type' field must be an Icmp4Type. Got: {type(value)!r}",
        )

    def test__icmp4__message__unknown__code__not_Icmp4Code(self) -> None:
        """
        Ensure the ICMPv4 message constructor raises an exception
        when the provided 'code' argument is not an Icmp4Code.
        """

        self._kwargs["code"] = value = "not an Icmp4Code"

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'code' field must be an Icmp4Code. Got: {type(value)!r}",
        )

    def test__icmp4__message__unknown__cksum__under_min(self) -> None:
        """
        Ensure the ICMPv4 unknown message assembler constructor raises
        an exception when the provided 'cksum' argument is lower than
        the minimum supported value.
        """

        self._kwargs["cksum"] = value = UINT_16__MIN - 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. " f"Got: {value!r}",
        )

    def test__icmp4__message__unknown__cksum__over_max(self) -> None:
        """
        Ensure the ICMPv4 unknown message assembler constructor raises
        an exception when the provided 'cksum' argument is higher than
        the maximum supported value.
        """

        self._kwargs["cksum"] = value = UINT_16__MAX + 1

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'cksum' field must be a 16-bit unsigned integer. " f"Got: {value!r}",
        )

    def test__icmp4__message__unknown__data__not_bytes(self) -> None:
        """
        Ensure the ICMPv4 message constructor raises an exception
        when the provided 'data' argument is not bytes.
        """

        self._kwargs["data"] = value = "not bytes or memoryview"

        with self.assertRaises(AssertionError) as error:
            Icmp4MessageUnknown(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"The 'data' field must be a bytes, bytearray or memoryview. " f"Got: {type(value)!r}",
        )


class TestIcmp4MessageUnknownParserAsserts(TestCase):
    """
    The ICMPv4 unknown message parser argument constructor assert tests.
    """

    def test__icmp4__message__unknown__wrong_type(self) -> None:
        """
        Ensure the ICMPv4 unknown message parser raises an exception when
        the provided 'buffer' argument contains incorrect 'type' field.
        """

        for type in range(0, 256):
            if type not in Icmp4Type.get_known_values():
                continue

            buffer = bytearray(
                # ICMPv4 Known Type Template
                #   Type     : {type}
                #   Code     : 0
                #   Checksum : computed below
                #   Rest     : 0x00000000
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            buffer[0] = type
            buffer[2:4] = inet_cksum(buffer).to_bytes(2)

            with self.assertRaises(AssertionError) as error:
                Icmp4MessageUnknown.from_buffer(buffer)

            self.assertEqual(
                str(error.exception),
                f"The 'type' field must not be known. Got: {Icmp4Type.from_int(type)!r}",
            )
