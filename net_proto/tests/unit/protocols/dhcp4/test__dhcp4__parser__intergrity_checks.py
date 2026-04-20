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
##   GNU General Public License for more details.                              ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
Module contains tests for the DHCPv4 packet parser integrity checks.

The parser's integrity validator enforces a single invariant: the received
frame must be at least DHCP4__HEADER__LEN (240) bytes long. Any shorter frame
must produce a Dhcp4IntegrityError before parsing begins.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__intergrity_checks.py

ver 3.0.4
"""


from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore

from net_proto import DHCP4__HEADER__LEN, Dhcp4IntegrityError, Dhcp4Parser


@parameterized_class(
    [
        {
            "_description": "The packet is empty (zero length).",
            "_args": [b""],
            "_results": {
                "error_message": (f"The minimum packet length must be {DHCP4__HEADER__LEN} " "bytes, got 0 bytes."),
            },
        },
        {
            "_description": "The packet has a single byte.",
            "_args": [b"\x00"],
            "_results": {
                "error_message": (f"The minimum packet length must be {DHCP4__HEADER__LEN} " "bytes, got 1 bytes."),
            },
        },
        {
            "_description": ("The packet length is lower than the DHCPv4 minimum header length by 1."),
            "_args": [b"\x00" * (DHCP4__HEADER__LEN - 1)],
            "_results": {
                "error_message": (
                    f"The minimum packet length must be {DHCP4__HEADER__LEN} "
                    f"bytes, got {DHCP4__HEADER__LEN - 1} bytes."
                ),
            },
        },
        {
            "_description": ("The packet length is roughly half of the DHCPv4 minimum header length."),
            "_args": [b"\x00" * (DHCP4__HEADER__LEN // 2)],
            "_results": {
                "error_message": (
                    f"The minimum packet length must be {DHCP4__HEADER__LEN} "
                    f"bytes, got {DHCP4__HEADER__LEN // 2} bytes."
                ),
            },
        },
    ]
)
class TestDhcp4ParserIntegrityChecks(TestCase):
    """
    The DHCPv4 packet parser integrity checks tests.
    """

    _description: str
    _args: list[Any]
    _results: dict[str, Any]

    def test__dhcp4__parser__from_buffer(self) -> None:
        """
        Ensure the DHCPv4 packet parser raises Dhcp4IntegrityError with the
        expected '[INTEGRITY ERROR][DHCPv4]'-prefixed message for every
        under-length frame.
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4Parser(*self._args)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][DHCPv4] {self._results['error_message']}",
            msg=f"Unexpected integrity error message for case: {self._description}",
        )


class TestDhcp4ParserIntegrityChecksBoundary(TestCase):
    """
    Boundary tests for the DHCPv4 packet parser integrity validator.
    """

    def test__dhcp4__parser__integrity_check_passes_at_minimum_length(
        self,
    ) -> None:
        """
        Ensure a frame of exactly DHCP4__HEADER__LEN bytes passes integrity
        validation. The parse step still fails on header content checks, but
        the integrity phase must not raise Dhcp4IntegrityError.
        """

        with self.assertRaises(Exception) as error:
            Dhcp4Parser(memoryview(b"\x00" * DHCP4__HEADER__LEN))

        self.assertNotIsInstance(
            error.exception,
            Dhcp4IntegrityError,
            msg=(
                "At exactly DHCP4__HEADER__LEN the integrity check must pass; "
                "failures here must originate from header parsing, not integrity."
            ),
        )

    def test__dhcp4__parser__integrity_check_message_uses_actual_length(
        self,
    ) -> None:
        """
        Ensure the error message reports the exact length of the provided
        buffer (not a truncated or cached value).
        """

        frame = memoryview(b"\x00" * 37)

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4Parser(frame)

        self.assertIn(
            "got 37 bytes.",
            str(error.exception),
            msg="Error message must include the actual short frame length.",
        )
