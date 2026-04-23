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
Module contains tests for the IPv4 options support code.

net_proto/tests/unit/protocols/ip4/test__ip4__options.py

ver 3.0.4
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore

from net_proto import (
    Ip4IntegrityError,
    Ip4OptionEol,
    Ip4OptionNop,
    Ip4Options,
    Ip4OptionType,
    Ip4OptionUnknown,
)


@parameterized_class(
    [
        {
            "_description": "Ip4Options with three Nops and a trailing Eol.",
            "_args": [
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionEol(),
            ],
            "_results": {
                "__len__": 4,
                "__str__": "nop, nop, nop, eol",
                "__repr__": "Ip4Options(options=[Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionEol()])",
                # IPv4 options wire format:
                #   Byte 0: 0x01 (Ip4OptionType.NOP)
                #   Byte 1: 0x01 (Ip4OptionType.NOP)
                #   Byte 2: 0x01 (Ip4OptionType.NOP)
                #   Byte 3: 0x00 (Ip4OptionType.EOL)
                "__bytes__": b"\x01\x01\x01\x00",
                "__bool__": True,
            },
        },
        {
            "_description": "Ip4Options with an unknown option followed by Nops.",
            "_args": [
                Ip4OptionUnknown(type=Ip4OptionType.from_int(255), data=b"\xaa\xbb"),
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionNop(),
            ],
            "_results": {
                "__len__": 8,
                "__str__": "unk-255-4, nop, nop, nop, nop",
                "__repr__": (
                    f"Ip4Options(options=[Ip4OptionUnknown(type={Ip4OptionType.from_int(255)!r}, "
                    "len=4, data=b'\\xaa\\xbb'), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop(), Ip4OptionNop()])"
                ),
                # IPv4 options wire format:
                #   Bytes 0-3: 0xff 0x04 0xaa 0xbb (UNKNOWN_255, len=4, data=0xaabb)
                #   Bytes 4-7: 0x01 0x01 0x01 0x01 (four Ip4OptionType.NOP bytes)
                "__bytes__": b"\xff\x04\xaa\xbb\x01\x01\x01\x01",
                "__bool__": True,
            },
        },
        {
            "_description": "Empty Ip4Options container.",
            "_args": [],
            "_results": {
                "__len__": 0,
                "__str__": "",
                "__repr__": "Ip4Options(options=[])",
                "__bytes__": b"",
                "__bool__": False,
            },
        },
    ]
)
class TestIp4OptionsAssembler(TestCase):
    """
    The Ip4Options container assembler tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build the Ip4Options container from the parametrized option list.
        """

        self._ip4_options = Ip4Options(*self._args)

    def test__ip4_options__len(self) -> None:
        """
        Ensure '__len__()' returns the sum of the per-option lengths.
        """

        self.assertEqual(
            len(self._ip4_options),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__ip4_options__str(self) -> None:
        """
        Ensure '__str__()' returns the comma-joined per-option log strings.
        """

        self.assertEqual(
            str(self._ip4_options),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__ip4_options__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.
        """

        self.assertEqual(
            repr(self._ip4_options),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__ip4_options__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the concatenated wire bytes.
        """

        self.assertEqual(
            bytes(self._ip4_options),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__ip4_options__bool(self) -> None:
        """
        Ensure '__bool__()' is True iff the container is non-empty.
        """

        self.assertEqual(
            bool(self._ip4_options),
            self._results["__bool__"],
            msg=f"Unexpected __bool__ for case: {self._description}",
        )


class TestIp4OptionsSequenceProtocol(TestCase):
    """
    The Ip4Options inherited sequence-protocol tests (__iter__,
    __getitem__, __contains__, __eq__, and index).
    """

    def setUp(self) -> None:
        """
        Build a mixed Nop/Eol fixture so every protocol method has at
        least one present and at least one absent member to probe.
        """

        self._nop = Ip4OptionNop()
        self._eol = Ip4OptionEol()
        self._unknown = Ip4OptionUnknown(type=Ip4OptionType.from_int(255), data=b"")
        self._options = Ip4Options(self._nop, self._nop, self._eol)

    def test__ip4_options__iter(self) -> None:
        """
        Ensure iterating Ip4Options yields the stored options in order.
        """

        self.assertEqual(
            list(self._options),
            [self._nop, self._nop, self._eol],
            msg="Iteration must yield stored options in insertion order.",
        )

    def test__ip4_options__getitem(self) -> None:
        """
        Ensure indexing returns the option at the requested position.
        """

        self.assertEqual(
            self._options[0],
            self._nop,
            msg="Ip4Options[0] must return the first option.",
        )
        self.assertEqual(
            self._options[-1],
            self._eol,
            msg="Ip4Options[-1] must return the last option.",
        )

    def test__ip4_options__contains__present(self) -> None:
        """
        Ensure 'in' returns True for a present option.
        """

        self.assertIn(
            self._eol,
            self._options,
            msg="Ip4Options must report a present Eol option via 'in'.",
        )

    def test__ip4_options__contains__absent(self) -> None:
        """
        Ensure 'in' returns False for an absent option.
        """

        self.assertNotIn(
            self._unknown,
            self._options,
            msg="Ip4Options must report an absent unknown option via 'in'.",
        )

    def test__ip4_options__eq(self) -> None:
        """
        Ensure __eq__ compares underlying option lists.
        """

        self.assertEqual(
            self._options,
            Ip4Options(self._nop, self._nop, self._eol),
            msg="Equal-content Ip4Options must compare equal.",
        )
        self.assertNotEqual(
            self._options,
            Ip4Options(self._nop, self._eol),
            msg="Unequal-content Ip4Options must compare not equal.",
        )
        self.assertNotEqual(
            self._options,
            [self._nop, self._nop, self._eol],
            msg="Ip4Options must not compare equal to a plain list of options.",
        )

    def test__ip4_options__index(self) -> None:
        """
        Ensure 'index' returns the position of the first matching option.
        """

        self.assertEqual(
            self._options.index(self._eol),
            2,
            msg="Ip4Options.index must return the position of a present option.",
        )


@parameterized_class(
    [
        {
            "_description": "Parse three Nops and a trailing Eol.",
            # IPv4 options wire format:
            #   Byte 0: 0x01 (NOP)
            #   Byte 1: 0x01 (NOP)
            #   Byte 2: 0x01 (NOP)
            #   Byte 3: 0x00 (EOL) -> parser stops here
            "_buffer": b"\x01\x01\x01\x00",
            "_expected": Ip4Options(
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionEol(),
            ),
        },
        {
            "_description": "Parse Nops followed by an Eol, trailing padding ignored.",
            # IPv4 options wire format:
            #   Byte 0: 0x01 (NOP)
            #   Byte 1: 0x00 (EOL) -> parser stops here
            #   Bytes 2-3: 0xff 0xff (padding past EOL, never inspected)
            "_buffer": b"\x01\x00\xff\xff",
            "_expected": Ip4Options(Ip4OptionNop(), Ip4OptionEol()),
        },
        {
            "_description": "Parse an unknown option followed by padding Nops.",
            # IPv4 options wire format:
            #   Bytes 0-3: 0xff 0x04 0xaa 0xbb (UNKNOWN_255, len=4, data=0xaabb)
            #   Bytes 4-7: 0x01 0x01 0x01 0x01 (four NOPs)
            "_buffer": b"\xff\x04\xaa\xbb\x01\x01\x01\x01",
            "_expected": Ip4Options(
                Ip4OptionUnknown(type=Ip4OptionType.from_int(255), data=b"\xaa\xbb"),
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionNop(),
                Ip4OptionNop(),
            ),
        },
        {
            "_description": "Parse an empty options buffer.",
            "_buffer": b"",
            "_expected": Ip4Options(),
        },
    ]
)
class TestIp4OptionsParser(TestCase):
    """
    The Ip4Options.from_buffer round-trip tests.
    """

    _description: str
    _buffer: bytes
    _expected: Ip4Options

    def test__ip4_options__from_buffer(self) -> None:
        """
        Ensure from_buffer parses the buffer into the expected option
        sequence, stopping at the first Eol and dispatching unknown
        type bytes to Ip4OptionUnknown.
        """

        self.assertEqual(
            Ip4Options.from_buffer(memoryview(self._buffer)),
            self._expected,
            msg=f"Unexpected parse result for case: {self._description}",
        )


class TestIp4OptionsValidateIntegrity(TestCase):
    """
    The Ip4Options.validate_integrity tests. The validator is run by
    Ip4Parser over the *entire* IPv4 header (starting at offset
    IP4__HEADER__LEN = 20) so the fixtures below prepend a 20-byte
    filler to place the options at the expected offset.
    """

    _HEADER_FILLER = b"\x00" * 20

    def test__ip4_options__validate_integrity__happy_path(self) -> None:
        """
        Ensure a well-formed options buffer (Nop-Nop-Eol + padding)
        passes validation without raising.
        """

        # Frame layout: 20 filler header bytes + NOP + NOP + EOL + padding.
        # hlen covers the first 24 bytes, so validator stops at EOL.
        frame = self._HEADER_FILLER + b"\x01\x01\x00\x00"

        Ip4Options.validate_integrity(frame=frame, hlen=24)

    def test__ip4_options__validate_integrity__empty_options(self) -> None:
        """
        Ensure hlen == IP4__HEADER__LEN (no options at all) passes
        validation without raising.
        """

        Ip4Options.validate_integrity(frame=self._HEADER_FILLER, hlen=20)

    def test__ip4_options__validate_integrity__eol_before_end(self) -> None:
        """
        Ensure an Eol byte short-circuits the validator; bytes past the
        Eol are not inspected.
        """

        # The 0xff byte at offset 22 would normally trigger the
        # "option length must be greater than 1" branch (0x00 at
        # offset 23 is the putative length byte) — the Eol at offset
        # 20 short-circuits before the validator looks at them.
        frame = self._HEADER_FILLER + b"\x00\xff\x00\x00"

        Ip4Options.validate_integrity(frame=frame, hlen=24)

    def test__ip4_options__validate_integrity__option_length_too_small(self) -> None:
        """
        Ensure the validator raises Ip4IntegrityError when an unknown
        option declares a length less than 2.
        """

        # Options: 0xff 0x01 0x00 0x00 -> unknown option, len=1 (<2).
        frame = self._HEADER_FILLER + b"\xff\x01\x00\x00"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4Options.validate_integrity(frame=frame, hlen=24)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv4] The IPv4 option length must be greater than 1. Got: 1.",
            msg="Unexpected integrity-error message for option length < 2.",
        )

    def test__ip4_options__validate_integrity__option_overruns_header(self) -> None:
        """
        Ensure the validator raises Ip4IntegrityError when an unknown
        option declares a length that extends past the header.
        """

        # Options: 0xff 0x05 ... -> declared len=5 starting at offset
        # 20, which would reach offset 25 > hlen=24.
        frame = self._HEADER_FILLER + b"\xff\x05\x00\x00"

        with self.assertRaises(Ip4IntegrityError) as error:
            Ip4Options.validate_integrity(frame=frame, hlen=24)

        self.assertEqual(
            str(error.exception),
            "[INTEGRITY ERROR][IPv4] The IPv4 option length must not extend past the header length. "
            "Got: offset=25, hlen=24",
            msg="Unexpected integrity-error message for option overrun.",
        )
