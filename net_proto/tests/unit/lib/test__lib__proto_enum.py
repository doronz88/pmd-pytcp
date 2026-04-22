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
This module contains tests for the NetProto ProtoEnum base enum class.

net_proto/tests/unit/lib/test__lib__proto_enum.py

ver 3.0.4
"""


from unittest import TestCase

from net_proto.lib.proto_enum import ProtoEnum, ProtoEnumByte, ProtoEnumWord


class TestNetProtoLibProtoEnumHierarchy(TestCase):
    """
    The NetProto ProtoEnum class hierarchy tests.
    """

    def test__net_proto__lib__proto_enum__byte_is_proto_enum(self) -> None:
        """
        Ensure 'ProtoEnumByte' subclasses 'ProtoEnum'.
        """

        self.assertTrue(issubclass(ProtoEnumByte, ProtoEnum))

    def test__net_proto__lib__proto_enum__word_is_proto_enum(self) -> None:
        """
        Ensure 'ProtoEnumWord' subclasses 'ProtoEnum'.
        """

        self.assertTrue(issubclass(ProtoEnumWord, ProtoEnum))


class TestNetProtoLibProtoEnumByteBasics(TestCase):
    """
    The NetProto ProtoEnumByte known-member tests.
    """

    def setUp(self) -> None:
        class ByteEnum(ProtoEnumByte):
            """Test-scoped byte enum."""

            ALPHA = 0x01
            BETA_GAMMA = 0x02

        self._enum = ByteEnum

    def test__net_proto__lib__proto_enum__byte__int(self) -> None:
        """
        Ensure 'int()' returns the numeric value of a known byte member.
        """

        self.assertEqual(int(self._enum.ALPHA), 0x01)
        self.assertEqual(int(self._enum.BETA_GAMMA), 0x02)

    def test__net_proto__lib__proto_enum__byte__str(self) -> None:
        """
        Ensure '__str__()' title-cases the member name and strips underscores.
        """

        self.assertEqual(str(self._enum.ALPHA), "Alpha")
        self.assertEqual(str(self._enum.BETA_GAMMA), "Beta Gamma")

    def test__net_proto__lib__proto_enum__byte__bytes(self) -> None:
        """
        Ensure 'bytes()' serializes a ProtoEnumByte member as one big-endian byte.
        """

        self.assertEqual(bytes(self._enum.ALPHA), b"\x01")
        self.assertEqual(bytes(self._enum.BETA_GAMMA), b"\x02")

    def test__net_proto__lib__proto_enum__byte__is_unknown_false(self) -> None:
        """
        Ensure known byte enum members report 'is_unknown' as False.
        """

        self.assertFalse(self._enum.ALPHA.is_unknown)
        self.assertFalse(self._enum.BETA_GAMMA.is_unknown)

    def test__net_proto__lib__proto_enum__byte__get_known_values(self) -> None:
        """
        Ensure 'get_known_values()' returns every declared member value.
        """

        self.assertEqual(
            sorted(self._enum.get_known_values()),
            [0x01, 0x02],
        )

    def test__net_proto__lib__proto_enum__byte__contains_instance(self) -> None:
        """
        Ensure the overridden instance-level '__contains__' uses known values.
        """

        self.assertIn(0x01, self._enum.ALPHA)
        self.assertNotIn(0x99, self._enum.ALPHA)


class TestNetProtoLibProtoEnumByteFromInt(TestCase):
    """
    The NetProto ProtoEnumByte from_int() tests.
    """

    def setUp(self) -> None:
        class ByteEnum(ProtoEnumByte):
            KNOWN = 5

        self._enum = ByteEnum

    def test__net_proto__lib__proto_enum__byte__from_int_known(self) -> None:
        """
        Ensure 'from_int()' returns the known member for its declared value.
        """

        self.assertIs(self._enum.from_int(5), self._enum.KNOWN)

    def test__net_proto__lib__proto_enum__byte__from_int_unknown(self) -> None:
        """
        Ensure 'from_int()' registers and returns an 'UNKNOWN_{value}' member.
        """

        member = self._enum.from_int(77)

        self.assertEqual(member.value, 77)
        self.assertTrue(member.is_unknown)
        self.assertEqual(member.name, "UNKNOWN_77")

    def test__net_proto__lib__proto_enum__byte__from_int_unknown_idempotent(
        self,
    ) -> None:
        """
        Ensure repeated 'from_int()' on the same unknown value returns the same member.
        """

        first = self._enum.from_int(123)
        second = self._enum.from_int(123)

        self.assertIs(first, second)

    def test__net_proto__lib__proto_enum__byte__unknown_excluded_from_known_values(
        self,
    ) -> None:
        """
        Ensure newly registered unknowns are not reported by 'get_known_values()'.
        """

        self._enum.from_int(200)

        self.assertNotIn(200, self._enum.get_known_values())

    def test__net_proto__lib__proto_enum__byte__unknown_str_title(self) -> None:
        """
        Ensure 'UNKNOWN_{value}' renders via the default 'title()' formatter
        on the base ProtoEnum class (ProtoEnumByte does not override __str__).
        """

        member = self._enum.from_int(45)
        self.assertEqual(str(member), "Unknown 45")


class TestNetProtoLibProtoEnumByteFromBytes(TestCase):
    """
    The NetProto ProtoEnumByte from_bytes() tests.
    """

    def setUp(self) -> None:
        class ByteEnum(ProtoEnumByte):
            A = 0x10
            B = 0xFE

        self._enum = ByteEnum

    def test__net_proto__lib__proto_enum__byte__from_bytes_known(self) -> None:
        """
        Ensure 'from_bytes()' returns the known member for an exact single-byte input.
        """

        self.assertIs(self._enum.from_bytes(b"\x10"), self._enum.A)
        self.assertIs(self._enum.from_bytes(b"\xfe"), self._enum.B)

    def test__net_proto__lib__proto_enum__byte__from_bytes_truncates(self) -> None:
        """
        Ensure 'from_bytes()' only consumes the first byte of the input buffer.
        """

        self.assertIs(self._enum.from_bytes(b"\x10\xff\xab"), self._enum.A)

    def test__net_proto__lib__proto_enum__byte__from_bytes_unknown(self) -> None:
        """
        Ensure 'from_bytes()' registers and returns an unknown for a novel value.
        """

        member = self._enum.from_bytes(b"\x99")

        self.assertEqual(member.value, 0x99)
        self.assertTrue(member.is_unknown)

    def test__net_proto__lib__proto_enum__byte__from_bytes_empty(self) -> None:
        """
        Ensure 'from_bytes()' treats an empty buffer as the integer value 0.
        """

        member = self._enum.from_bytes(b"")

        self.assertEqual(member.value, 0)
        self.assertTrue(member.is_unknown)


class TestNetProtoLibProtoEnumWordBasics(TestCase):
    """
    The NetProto ProtoEnumWord known-member tests.
    """

    def setUp(self) -> None:
        class WordEnum(ProtoEnumWord):
            HEAD = 0x1234
            TAIL_END = 0xABCD

        self._enum = WordEnum

    def test__net_proto__lib__proto_enum__word__int(self) -> None:
        """
        Ensure 'int()' returns the numeric value of a known word member.
        """

        self.assertEqual(int(self._enum.HEAD), 0x1234)
        self.assertEqual(int(self._enum.TAIL_END), 0xABCD)

    def test__net_proto__lib__proto_enum__word__bytes(self) -> None:
        """
        Ensure 'bytes()' serializes a ProtoEnumWord member as two big-endian bytes.
        """

        self.assertEqual(bytes(self._enum.HEAD), b"\x12\x34")
        self.assertEqual(bytes(self._enum.TAIL_END), b"\xab\xcd")

    def test__net_proto__lib__proto_enum__word__str(self) -> None:
        """
        Ensure '__str__()' title-cases the member name and strips underscores.
        """

        self.assertEqual(str(self._enum.HEAD), "Head")
        self.assertEqual(str(self._enum.TAIL_END), "Tail End")

    def test__net_proto__lib__proto_enum__word__is_unknown_false(self) -> None:
        """
        Ensure known word enum members report 'is_unknown' as False.
        """

        self.assertFalse(self._enum.HEAD.is_unknown)
        self.assertFalse(self._enum.TAIL_END.is_unknown)


class TestNetProtoLibProtoEnumWordFromInt(TestCase):
    """
    The NetProto ProtoEnumWord from_int() tests.
    """

    def setUp(self) -> None:
        class WordEnum(ProtoEnumWord):
            KNOWN = 0x0800

        self._enum = WordEnum

    def test__net_proto__lib__proto_enum__word__from_int_known(self) -> None:
        """
        Ensure 'from_int()' returns the known member for its declared value.
        """

        self.assertIs(self._enum.from_int(0x0800), self._enum.KNOWN)

    def test__net_proto__lib__proto_enum__word__from_int_unknown(self) -> None:
        """
        Ensure 'from_int()' registers and returns an 'UNKNOWN_{value}' member.
        """

        member = self._enum.from_int(0xABCD)

        self.assertEqual(member.value, 0xABCD)
        self.assertTrue(member.is_unknown)
        self.assertEqual(member.name, f"UNKNOWN_{0xABCD}")

    def test__net_proto__lib__proto_enum__word__from_int_unknown_idempotent(
        self,
    ) -> None:
        """
        Ensure repeated 'from_int()' on the same unknown value returns the same member.
        """

        first = self._enum.from_int(0x1000)
        second = self._enum.from_int(0x1000)

        self.assertIs(first, second)


class TestNetProtoLibProtoEnumWordFromBytes(TestCase):
    """
    The NetProto ProtoEnumWord from_bytes() tests.
    """

    def setUp(self) -> None:
        class WordEnum(ProtoEnumWord):
            A = 0x0102
            B = 0xFFEE

        self._enum = WordEnum

    def test__net_proto__lib__proto_enum__word__from_bytes_known(self) -> None:
        """
        Ensure 'from_bytes()' returns the known member for an exact two-byte input.
        """

        self.assertIs(self._enum.from_bytes(b"\x01\x02"), self._enum.A)
        self.assertIs(self._enum.from_bytes(b"\xff\xee"), self._enum.B)

    def test__net_proto__lib__proto_enum__word__from_bytes_truncates(self) -> None:
        """
        Ensure 'from_bytes()' only consumes the first two bytes of the buffer.
        """

        self.assertIs(self._enum.from_bytes(b"\x01\x02\xff\xff"), self._enum.A)

    def test__net_proto__lib__proto_enum__word__from_bytes_unknown(self) -> None:
        """
        Ensure 'from_bytes()' registers and returns an unknown for a novel value.
        """

        member = self._enum.from_bytes(b"\xde\xad")

        self.assertEqual(member.value, 0xDEAD)
        self.assertTrue(member.is_unknown)

    def test__net_proto__lib__proto_enum__word__from_bytes_short(self) -> None:
        """
        Ensure 'from_bytes()' accepts a single-byte input and treats it as 0x00XX.
        """

        member = self._enum.from_bytes(b"\x05")

        self.assertEqual(member.value, 0x05)

    def test__net_proto__lib__proto_enum__word__from_bytes_empty(self) -> None:
        """
        Ensure 'from_bytes()' treats an empty buffer as the integer value 0.
        """

        member = self._enum.from_bytes(b"")

        self.assertEqual(member.value, 0)
        self.assertTrue(member.is_unknown)
