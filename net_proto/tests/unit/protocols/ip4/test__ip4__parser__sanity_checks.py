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
This module contains tests for the IPv4 packet sanity checks.

net_proto/tests/unit/protocols/ip4/test__ip4__parser__sanity_checks.py

ver 3.0.4
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore

from net_proto import Ip4Parser, Ip4SanityError, PacketRx


@parameterized_class(
    [
        {
            "_description": "TTL field is zero.",
            # 20-byte IPv4 frame with ttl=0 (byte 8), a correctly
            # recomputed checksum (bytes 10-11 = 0xd824), and otherwise
            # valid fields so the integrity checks pass and the sanity
            # validator raises on 'ttl == 0'.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x40\x00\x00\xff\xd8\x24" b"\x0a\x14\x1e\x28\x32\x3c\x46\x50"),
            "_results": {
                "error_message": "Value of the 'ttl' field must be greater than 0.",
            },
        },
        {
            "_description": "Source address is a multicast address (224.0.0.1).",
            # src bytes 12-15 = 0xe0000001 (224.0.0.1 is in the IPv4
            # multicast range 224.0.0.0/4). cksum = 0x215e.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\x21\x5e" b"\xe0\x00\x00\x01\x32\x3c\x46\x50"),
            "_results": {
                "error_message": "Value of the 'src' field must not be a multicast address.",
            },
        },
        {
            "_description": "Source address is a reserved address (240.0.0.1).",
            # src bytes 12-15 = 0xf0000001 (240.0.0.1 is in the reserved
            # range 240.0.0.0/4 excluding 255.255.255.255). cksum=0x115e.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\x11\x5e" b"\xf0\x00\x00\x01\x32\x3c\x46\x50"),
            "_results": {
                "error_message": "Value of the 'src' field must not be a reserved address.",
            },
        },
        {
            "_description": "Source address is the limited broadcast (255.255.255.255).",
            # src bytes 12-15 = 0xffffffff (limited broadcast).
            # cksum = 0x0160.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x40\x00\xff\xff\x01\x60" b"\xff\xff\xff\xff\x32\x3c\x46\x50"),
            "_results": {
                "error_message": "Value of the 'src' field must not be a limited broadcast address.",
            },
        },
        {
            "_description": "DF and MF flags set simultaneously.",
            # Bytes 6-7 = 0x6000 (DF=1, MF=1, offset=0). The parser runs
            # the 'flag_df and flag_mf' check before the
            # 'flag_df and offset != 0' check, so this case lands in
            # the simultaneous-flags branch. cksum = 0xb923.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x60\x00\xff\xff\xb9\x23" b"\x0a\x14\x1e\x28\x32\x3c\x46\x50"),
            "_results": {
                "error_message": "Flags 'DF' and 'MF' must not be set simultaneously.",
            },
        },
        {
            "_description": "DF flag set with a non-zero fragment offset.",
            # Bytes 6-7 = 0x4100 -> DF=1, MF=0, offset=0x100<<3 = 2048.
            # cksum = 0xd823.
            "_frame_rx": (b"\x45\xff\x00\x14\xff\xff\x41\x00\xff\xff\xd8\x23" b"\x0a\x14\x1e\x28\x32\x3c\x46\x50"),
            "_results": {
                "error_message": "Value of the 'offset' field must be 0 when 'DF' flag is set.",
            },
        },
    ]
)
class TestIp4ParserSanityChecks(TestCase):
    """
    The IPv4 packet parser sanity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Wrap the parametrized frame in a PacketRx so it can be fed to
        Ip4Parser.
        """

        self._packet_rx = PacketRx(self._frame_rx)

    def test__ip4__parser__sanity_error(self) -> None:
        """
        Ensure the IPv4 packet parser raises Ip4SanityError with the
        expected message for each semantically invalid frame.
        """

        with self.assertRaises(Ip4SanityError) as error:
            Ip4Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][IPv4] {self._results['error_message']}",
            msg=f"Unexpected sanity-error message for case: {self._description}",
        )
