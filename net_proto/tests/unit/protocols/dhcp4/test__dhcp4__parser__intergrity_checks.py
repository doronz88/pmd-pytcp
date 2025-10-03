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
Module contains tests for the DHCPv4 packet integrity checks.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__integrity_checks.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_proto import DHCP4__HEADER__LEN, Dhcp4IntegrityError, Dhcp4Parser

testcases: list[dict[str, Any]] = [
    {
        "_description": ("The packet length is lower than the DHCPv4 minimum header length by 1."),
        "_args": [
            b"\x00" * (DHCP4__HEADER__LEN - 1),
        ],
        "_kwargs": {},
        "_results": {
            "error_message": (
                f"The minimum packet length must be {DHCP4__HEADER__LEN} bytes, " f"got {DHCP4__HEADER__LEN - 1} bytes."
            ),
        },
    },
    {
        "_description": "The packet is empty (zero length).",
        "_args": [
            b"",
        ],
        "_kwargs": {},
        "_results": {
            "error_message": (f"The minimum packet length must be {DHCP4__HEADER__LEN} bytes, " "got 0 bytes."),
        },
    },
]


@parameterized_class(testcases)
class TestDhcp4ParserIntegrityChecks(TestCase):
    """
    The DHCPv4 packet parser integrity checks tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__dhcp4__parser__from_buffer(self) -> None:
        """
        Ensure the DHCPv4 packet parser raises integrity error on malformed packets.
        """

        with self.assertRaises(Dhcp4IntegrityError) as error:
            Dhcp4Parser(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][DHCPv4] {self._results['error_message']}",
        )
