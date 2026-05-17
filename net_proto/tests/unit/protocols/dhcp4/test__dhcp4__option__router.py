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
Module contains tests for the DHCPv4 Router option code.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__option__router.py

ver 3.0.5
"""

from dataclasses import FrozenInstanceError
from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_addr import Ip4Address
from net_proto import (
    Dhcp4IntegrityError,
    Dhcp4OptionRouter,
    Dhcp4OptionType,
)


class TestDhcp4OptionRouterAsserts(TestCase):
    """
    The DHCPv4 Router option constructor argument assert tests.
    """

    def test__dhcp4__option__router__not_list(self) -> None:
        """
        Ensure the constructor raises an exception when the provided
        'routers' argument is not a list.
        """

        value = Ip4Address("192.0.2.1")

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionRouter(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'routers' field must be a list. Got: {type(value)!r}",
            msg="Unexpected 'routers' type assert message.",
        )

    def test__dhcp4__option__router__rejects_tuple(self) -> None:
        """
        Ensure the constructor rejects a tuple of Ip4Address values — only a
        bare list is allowed.
        """

        value = (Ip4Address("192.0.2.1"),)

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionRouter(value)  # type: ignore[arg-type]

        self.assertEqual(
            str(error.exception),
            f"The 'routers' field must be a list. Got: {type(value)!r}",
            msg="Unexpected 'routers' type assert message for tuple.",
        )

    def test__dhcp4__option__router__element_not_Ip4Address(self) -> None:
        """
        Ensure the constructor raises an exception when the provided
        'routers' list contains a non-Ip4Address element.
        """

        value: list[Any] = [Ip4Address(), "not an Ip4Address"]

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionRouter(value)

        self.assertEqual(
            str(error.exception),
            f"The 'routers' field must be a list of Ip4Address elements. " f"Got: {[type(item) for item in value]!r}",
            msg="Unexpected 'routers' element type assert message.",
        )

    def test__dhcp4__option__router__rejects_str_ip_elements(self) -> None:
        """
        Ensure the constructor rejects a list of dotted-decimal strings —
        Ip4Address instances are required.
        """

        value: list[Any] = ["192.0.2.1"]

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionRouter(value)

        self.assertEqual(
            str(error.exception),
            f"The 'routers' field must be a list of Ip4Address elements. " f"Got: {[type(item) for item in value]!r}",
            msg="Unexpected 'routers' element type assert message for str.",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Router option (empty list).",
            "_args": [[]],
            "_results": {
                "__len__": 2,
                "__str__": "router []",
                "__repr__": "Dhcp4OptionRouter(routers=[])",
                "__bytes__": (
                    # DHCPv4 Router option [RFC 2132]
                    #   Code : 0x03 (3, Router)
                    #   Len  : 0x00 (0 bytes)
                    #   Data : (empty)
                    b"\x03\x00"
                ),
                "routers": [],
                "type": Dhcp4OptionType.ROUTER,
                "len": 2,
            },
        },
        {
            "_description": "The DHCPv4 Router option (one router).",
            "_args": [[Ip4Address("192.0.2.1")]],
            "_results": {
                "__len__": 6,
                "__str__": "router ['192.0.2.1']",
                "__repr__": "Dhcp4OptionRouter(routers=[Ip4Address('192.0.2.1')])",
                "__bytes__": (
                    # DHCPv4 Router option [RFC 2132]
                    #   Code : 0x03 (3, Router)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : c0 00 02 01   (192.0.2.1)
                    b"\x03\x04\xc0\x00\x02\x01"
                ),
                "routers": [Ip4Address("192.0.2.1")],
                "type": Dhcp4OptionType.ROUTER,
                "len": 6,
            },
        },
        {
            "_description": "The DHCPv4 Router option (two routers).",
            "_args": [[Ip4Address("192.0.2.1"), Ip4Address("198.51.100.5")]],
            "_results": {
                "__len__": 10,
                "__str__": "router ['192.0.2.1', '198.51.100.5']",
                "__repr__": "Dhcp4OptionRouter(routers=[Ip4Address('192.0.2.1'), Ip4Address('198.51.100.5')])",
                "__bytes__": (
                    # DHCPv4 Router option [RFC 2132]
                    #   Code : 0x03 (3, Router)
                    #   Len  : 0x08 (8 bytes)
                    #   Data : c0 00 02 01   (192.0.2.1)
                    #          c6 33 64 05   (198.51.100.5)
                    b"\x03\x08\xc0\x00\x02\x01\xc6\x33\x64\x05"
                ),
                "routers": [
                    Ip4Address("192.0.2.1"),
                    Ip4Address("198.51.100.5"),
                ],
                "type": Dhcp4OptionType.ROUTER,
                "len": 10,
            },
        },
        {
            "_description": "The DHCPv4 Router option (TEST-NET-3 router).",
            "_args": [[Ip4Address("203.0.113.10")]],
            "_results": {
                "__len__": 6,
                "__str__": "router ['203.0.113.10']",
                "__repr__": "Dhcp4OptionRouter(routers=[Ip4Address('203.0.113.10')])",
                "__bytes__": (
                    # DHCPv4 Router option [RFC 2132]
                    #   Code : 0x03 (3, Router)
                    #   Len  : 0x04 (4 bytes)
                    #   Data : cb 00 71 0a   (203.0.113.10)
                    b"\x03\x04\xcb\x00\x71\x0a"
                ),
                "routers": [Ip4Address("203.0.113.10")],
                "type": Dhcp4OptionType.ROUTER,
                "len": 6,
            },
        },
        {
            "_description": "The DHCPv4 Router option (three routers).",
            "_args": [
                [
                    Ip4Address("192.0.2.1"),
                    Ip4Address("198.51.100.5"),
                    Ip4Address("203.0.113.10"),
                ]
            ],
            "_results": {
                "__len__": 14,
                "__str__": "router ['192.0.2.1', '198.51.100.5', '203.0.113.10']",
                "__repr__": (
                    "Dhcp4OptionRouter(routers=[Ip4Address('192.0.2.1'), "
                    "Ip4Address('198.51.100.5'), Ip4Address('203.0.113.10')])"
                ),
                "__bytes__": (
                    # DHCPv4 Router option [RFC 2132]
                    #   Code : 0x03 (3, Router)
                    #   Len  : 0x0c (12 bytes)
                    #   Data : c0 00 02 01   (192.0.2.1)
                    #          c6 33 64 05   (198.51.100.5)
                    #          cb 00 71 0a   (203.0.113.10)
                    b"\x03\x0c\xc0\x00\x02\x01\xc6\x33\x64\x05\xcb\x00\x71\x0a"
                ),
                "routers": [
                    Ip4Address("192.0.2.1"),
                    Ip4Address("198.51.100.5"),
                    Ip4Address("203.0.113.10"),
                ],
                "type": Dhcp4OptionType.ROUTER,
                "len": 14,
            },
        },
    ]
)
class TestDhcp4OptionRouterAssembler(TestCase):
    """
    The DHCPv4 Router option assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the DHCPv4 Router option object with testcase arguments.
        """

        self._option = Dhcp4OptionRouter(*self._args)

    def test__dhcp4__option__router__len(self) -> None:
        """
        Ensure '__len__()' returns 2 + 4 * number-of-routers.
        """

        self.assertEqual(
            len(self._option),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__dhcp4__option__router__str(self) -> None:
        """
        Ensure '__str__()' renders the canonical log line.
        """

        self.assertEqual(
            str(self._option),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__dhcp4__option__router__repr(self) -> None:
        """
        Ensure '__repr__()' renders the dataclass form.
        """

        self.assertEqual(
            repr(self._option),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__dhcp4__option__router__bytes(self) -> None:
        """
        Ensure 'bytes()' yields the expected wire image.
        """

        self.assertEqual(
            bytes(self._option),
            self._results["__bytes__"],
            msg=f"Unexpected bytes output for case: {self._description}",
        )

    def test__dhcp4__option__router__memoryview(self) -> None:
        """
        Ensure the option supports the buffer protocol.
        """

        self.assertEqual(
            bytes(memoryview(self._option)),
            self._results["__bytes__"],
            msg=f"Unexpected memoryview output for case: {self._description}",
        )

    def test__dhcp4__option__router__field(self) -> None:
        """
        Ensure the 'routers' field reflects the constructor argument.
        """

        self.assertEqual(
            self._option.routers,
            self._results["routers"],
            msg=f"Unexpected 'routers' for case: {self._description}",
        )

    def test__dhcp4__option__router__type(self) -> None:
        """
        Ensure the 'type' field is always ROUTER (3).
        """

        self.assertEqual(
            self._option.type,
            self._results["type"],
            msg=f"Unexpected 'type' for case: {self._description}",
        )

    def test__dhcp4__option__router__len_field(self) -> None:
        """
        Ensure the 'len' field matches __len__().
        """

        self.assertEqual(
            self._option.len,
            self._results["len"],
            msg=f"Unexpected 'len' field for case: {self._description}",
        )

    def test__dhcp4__option__router__roundtrip(self) -> None:
        """
        Ensure bytes(option) parses back into an equal option.
        """

        self.assertEqual(
            Dhcp4OptionRouter.from_buffer(bytes(self._option)),
            self._option,
            msg=f"Roundtrip must preserve equality for case: {self._description}",
        )


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 Router option (empty list).",
            "_args": [b"\x03\x00" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionRouter([]),
            },
        },
        {
            "_description": "The DHCPv4 Router option (one router).",
            "_args": [b"\x03\x04\xc0\x00\x02\x01" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionRouter([Ip4Address("192.0.2.1")]),
            },
        },
        {
            "_description": "The DHCPv4 Router option (two routers).",
            "_args": [b"\x03\x08\xc0\x00\x02\x01\xc6\x33\x64\x05" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionRouter([Ip4Address("192.0.2.1"), Ip4Address("198.51.100.5")]),
            },
        },
        {
            "_description": "The DHCPv4 Router option (three routers).",
            "_args": [b"\x03\x0c\xc0\x00\x02\x01\xc6\x33\x64\x05\xcb\x00\x71\x0a" + b"ZH0PA"],
            "_results": {
                "option": Dhcp4OptionRouter(
                    [
                        Ip4Address("192.0.2.1"),
                        Ip4Address("198.51.100.5"),
                        Ip4Address("203.0.113.10"),
                    ]
                ),
            },
        },
    ]
)
class TestDhcp4OptionRouterParser(TestCase):
    """
    The DHCPv4 Router option parser (success) tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__dhcp4__option__router__from_buffer(self) -> None:
        """
        Ensure 'from_buffer()' produces the expected option and ignores the
        trailing bytes beyond the advertised length.
        """

        option = Dhcp4OptionRouter.from_buffer(*self._args)

        self.assertEqual(
            option,
            self._results["option"],
            msg=f"Unexpected parser output for case: {self._description}",
        )


class TestDhcp4OptionRouterParserErrors(TestCase):
    """
    The DHCPv4 Router option parser error tests.
    """

    def test__dhcp4__option__router__minimum_length(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the buffer is shorter than the
        2-byte type+len header.
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionRouter.from_buffer(b"\x03")

        self.assertEqual(
            str(error.exception),
            "The minimum length of the DHCPv4 Router option must be 2 bytes. Got: 1",
            msg="Unexpected minimum-length assert message.",
        )

    def test__dhcp4__option__router__wrong_type(self) -> None:
        """
        Ensure 'from_buffer()' asserts when the option type byte is not 3.
        """

        with self.assertRaises(AssertionError) as error:
            Dhcp4OptionRouter.from_buffer(b"\xfe\x04\xc0\x00\x02\x01")

        self.assertEqual(
            str(error.exception),
            f"The DHCPv4 Router option type must be {Dhcp4OptionType.ROUTER!r}. "
            f"Got: {Dhcp4OptionType.from_int(254)!r}",
            msg="Unexpected wrong-type assert message.",
        )

    def test__dhcp4__option__router__length_not_multiple_of_4(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        length (less header) is not a multiple of 4.
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionRouter.from_buffer(b"\x03\x03\x01\x02\x03")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Router option length value (less header) "
            "must be a multiple of 4. Got: 3",
            msg="Unexpected length-modulo integrity error message.",
        )

    def test__dhcp4__option__router__advertised_len_exceeds_buffer(self) -> None:
        """
        Ensure 'from_buffer()' raises Dhcp4IntegrityError when the advertised
        length exceeds the remaining bytes in the buffer.
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4OptionRouter.from_buffer(b"\x03\x04")

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][DHCPv4] The DHCPv4 Router option length value must "
            "be less than or equal to the length of provided bytes (2). Got: 6",
            msg="Unexpected buffer-too-short integrity error message.",
        )


class TestDhcp4OptionRouterBehavior(TestCase):
    """
    The DHCPv4 Router option behavioral tests.
    """

    def test__dhcp4__option__router__equality(self) -> None:
        """
        Ensure two options with equal 'routers' compare equal.
        """

        self.assertEqual(
            Dhcp4OptionRouter([Ip4Address("192.0.2.1")]),
            Dhcp4OptionRouter([Ip4Address("192.0.2.1")]),
            msg="Options with identical routers must compare equal.",
        )

    def test__dhcp4__option__router__inequality(self) -> None:
        """
        Ensure two options with different 'routers' compare unequal.
        """

        self.assertNotEqual(
            Dhcp4OptionRouter([Ip4Address("192.0.2.1")]),
            Dhcp4OptionRouter([Ip4Address("198.51.100.5")]),
            msg="Options with different routers must not compare equal.",
        )

    def test__dhcp4__option__router__inequality_by_count(self) -> None:
        """
        Ensure two options with different router counts compare unequal.
        """

        self.assertNotEqual(
            Dhcp4OptionRouter([Ip4Address("192.0.2.1")]),
            Dhcp4OptionRouter([Ip4Address("192.0.2.1"), Ip4Address("198.51.100.5")]),
            msg="Options with different router counts must not compare equal.",
        )

    def test__dhcp4__option__router__is_frozen(self) -> None:
        """
        Ensure the option cannot be mutated after construction.
        """

        option = Dhcp4OptionRouter([Ip4Address("192.0.2.1")])

        with self.assertRaises(FrozenInstanceError):
            option.routers = [Ip4Address("198.51.100.5")]  # type: ignore[misc]

    def test__dhcp4__option__router__type_cannot_be_overridden(self) -> None:
        """
        Ensure 'type' cannot be supplied via the constructor (init=False).
        """

        with self.assertRaises(TypeError):
            Dhcp4OptionRouter(  # type: ignore[call-arg]
                [Ip4Address("192.0.2.1")],
                type=Dhcp4OptionType.ROUTER,
            )
