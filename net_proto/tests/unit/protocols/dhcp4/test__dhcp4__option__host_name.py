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

ver 3.0.5
"""

from dataclasses import FrozenInstanceError
from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionHostName,
    Dhcp4OptionType,
)


class TestDhcp4OptionHostNameAsserts(TestCase):
    """
    The DHCPv4 Host Name option constructor argument assert tests.
    """

    def test__dhcp4__option__host_name__not_str(self) -> None:
        """
        Ensure the DHCPv4 Host Name option constructor raises an exception
        when the provided 'host_name' argument is not a str.
        """

        value = 123

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionHostName(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'host_name' field must be a str. Got: {type(value)!r}",
            msg="Unexpected 'host_name' type assert message.",
        )

    def test__dhcp4__option__host_name__rejects_bytes(self) -> None:
        """
        Ensure the DHCPv4 Host Name option constructor rejects bytes input.
        """

        value = b"host"

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionHostName(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'host_name' field must be a str. Got: {type(value)!r}",
            msg="Unexpected 'host_name' type assert message for bytes.",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Host Name option (single char).",
            "_args": ["a"],
            "_results": {
                "__len__": 3,
                "__str__": "host_name a",
                "__repr__": "Dhcp4OptionHostName(host_name='a')",
                "__bytes__": (
                    # DHCPv4 Host Name option [RFC 2132]
                    #   Code : 0x0c (12, Host Name)
                    #   Len  : 0x01 (1 byte)
                    #   Data : 61   ('a')
                    b"\x0c\x01\x61"
                ),
                "host_name": "a",
                "type": Dhcp4OptionType.HOST_NAME,
                "len": 3,
            },
        },
        {
            "_description": "The DHCPv4 Host Name option (short).",
            "_args": ["host"],
            "_results": {
                "__len__": 6,
                "__str__": "host_name host",
                "__repr__": "Dhcp4OptionHostName(host_name='host')",
                "__bytes__": (
                    # DHCPv4 Host Name option [RFC 2132]
                    #   Code : 0x0c (12, Host Name)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : 68 6f 73 74   ('host')
                    b"\x0c\x04\x68\x6f\x73\x74"
                ),
                "host_name": "host",
                "type": Dhcp4OptionType.HOST_NAME,
                "len": 6,
            },
        },
        {
            "_description": "The DHCPv4 Host Name option (alnum-hyphen).",
            "_args": ["tom-tit-tot-01"],
            "_results": {
                "__len__": 16,
                "__str__": "host_name tom-tit-tot-01",
                "__repr__": "Dhcp4OptionHostName(host_name='tom-tit-tot-01')",
                "__bytes__": (
                    # DHCPv4 Host Name option [RFC 2132]
                    #   Code : 0x0c (12, Host Name)
                    #   Len  : 0x0e (14 bytes)
                    #   Data : 74 6f 6d 2d 74 69 74 2d 74 6f 74 2d 30 31
                    #          ('tom-tit-tot-01')
                    b"\x0c\x0e\x74\x6f\x6d\x2d\x74\x69\x74\x2d\x74\x6f\x74\x2d\x30\x31"
                ),
                "host_name": "tom-tit-tot-01",
                "type": Dhcp4OptionType.HOST_NAME,
                "len": 16,
            },
        },
        {
            "_description": "The DHCPv4 Host Name option (empty).",
            "_args": [""],
            "_results": {
                "__len__": 2,
                "__str__": "host_name ",
                "__repr__": "Dhcp4OptionHostName(host_name='')",
                "__bytes__": (
                    # DHCPv4 Host Name option [RFC 2132]
                    #   Code : 0x0c (12, Host Name)
                    #   Len  : 0x00 (0 bytes)
                    #   Data : (empty)
                    b"\x0c\x00"
                ),
                "host_name": "",
                "type": Dhcp4OptionType.HOST_NAME,
                "len": 2,
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
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Host Name option object with testcase arguments.
        """

        self._option = Dhcp4OptionHostName(*self._args)

    def test__dhcp4__option__host_name__len(self) -> None:
        """
        Ensure '__len__()' returns code + len + hostname bytes.
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__dhcp4__option__host_name__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical log line.
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__dhcp4__option__host_name__repr(self) -> None:
        """
        Ensure '__repr__()' renders the dataclass form.
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__dhcp4__option__host_name__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected bytes output for case: {self._description}",
        )

    def test__dhcp4__option__host_name__memoryview(self) -> None:
        """
        Ensure the option supports the buffer protocol.
        """

        self.assertEqual(
            bytes(memoryview(self._option)),
            self._results["__bytes__"],
            msg=f"Unexpected memoryview output for case: {self._description}",
        )

    def test__dhcp4__option__host_name__field(self) -> None:
        """
        Ensure the 'host_name' field reflects the constructor argument.
        """

        self.assertEqual(
            self._option.host_name,
            self._results["host_name"],
            msg=f"Unexpected 'host_name' for case: {self._description}",
        )

    def test__dhcp4__option__host_name__type(self) -> None:
        """
        Ensure the 'type' field is always HOST_NAME.
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__dhcp4__option__host_name__len_field(self) -> None:
        """
        Ensure the 'len' field matches __len__().
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' field for case: {self._description}",
        )

    def test__dhcp4__option__host_name__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option.
        """

        self.assertEqual(
            Dhcp4OptionHostName.from_buffer(bytes(self._option)),
            self._option,
            msg=f"Roundtrip must preserve equality for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Host Name option (single char).",
            "_args": [b"\x0c\x01\x61" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionHostName(host_name="a"),
            },
        },
        {
            "_description": "The DHCPv4 Host Name option (short).",
            "_args": [b"\x0c\x04\x68\x6f\x73\x74" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionHostName(host_name="host"),
            },
        },
        {
            "_description": "The DHCPv4 Host Name option (alnum-hyphen).",
            "_args": [b"\x0c\x0e\x74\x6f\x6d\x2d\x74\x69\x74\x2d\x74\x6f\x74\x2d\x30\x31" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionHostName(host_name="tom-tit-tot-01"),
            },
        },
        {
            "_description": "The DHCPv4 Host Name option (empty).",
            "_args": [b"\x0c\x00" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionHostName(host_name=""),
            },
        },
    ]
)
class TestDhcp4OptionHostNameParser(TestCase):
    """
    The DHCPv4 Host Name option parser (success) tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__dhcp4__option__host_name__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' produces the expected option and ignores the
        trailing bytes beyond the advertised length.
        """

        option = Dhcp4OptionHostName.from_buffer(*self._args)

        self.assertEqual(
            option,
            self._results["option"],
            msg=f"Unexpected parser output for case: {self._description}",
        )


class TestDhcp4OptionHostNameParserErrors(TestCase):
    """
    The DHCPv4 Host Name option parser error tests.
    """

    def test__dhcp4__option__host_name__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        2-byte type+len header.
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionHostName.from_buffer(b"\x0c")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv4 Host Name option must be 2 bytes. Got: 1",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp4__option__host_name__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option type byte is not 12.
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionHostName.from_buffer(b"\xfe\x01a")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv4 Host Name option type must be {Dhcp4OptionType.HOST_NAME!r}. "
            f"Got: {Dhcp4OptionType.from_int(254)!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp4__option__host_name__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionHostName.from_buffer(b"\x0c\x01")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Host Name option length value must "
            "be less than or equal to the length of provided bytes (2). Got: 3",
            msg="Unexpected integrity-error message.",
        )


class TestDhcp4OptionHostNameBehavior(TestCase):
    """
    The DHCPv4 Host Name option behavioral tests.
    """

    def test__dhcp4__option__host_name__equality(self) -> None:
        """
        Ensure two options with equal 'host_name' compare equal.
        """

        self.assertEqual(
            Dhcp4OptionHostName("host"),
            Dhcp4OptionHostName("host"),
            msg="Options with identical host_name must compare equal.",
        )

    def test__dhcp4__option__host_name__inequality(self) -> None:
        """
        Ensure two options with different 'host_name' compare unequal.
        """

        self.assertNotEqual(
            Dhcp4OptionHostName("host-a"),
            Dhcp4OptionHostName("host-b"),
            msg="Options with different host_name must not compare equal.",
        )

    def test__dhcp4__option__host_name__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.
        """

        option = Dhcp4OptionHostName("host")

        with self.assertRaises(FrozenInstanceError):
            option.host_name = "other"  # type: ignore[misc]

    def test__dhcp4__option__host_name__type_cannot_be_overridden(self) -> None:
        """
        Ensure 'type' cannot be supplied via the constructor (init=False).
        """

        with self.assertRaises(TypeError):
            Dhcp4OptionHostName(  # type: ignore[call-arg]
                type=Dhcp4OptionType.HOST_NAME,
                host_name="host",
            )
