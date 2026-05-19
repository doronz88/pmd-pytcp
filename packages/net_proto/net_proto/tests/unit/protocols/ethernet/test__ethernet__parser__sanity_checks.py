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
This module contains tests for the Ethernet II packet parser sanity checks.

The parser's sanity validator enforces the DIX/Ethernet II convention that
the 16-bit 'type' field must hold a value of at least 0x0600. Any smaller
value (as used by the obsolete 802.3 length framing) must produce an
EthernetSanityError after header parsing.

net_proto/tests/unit/protocols/ethernet/test__ethernet__parser__sanity_checks.py

ver 3.0.6
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import EthernetParser, EthernetSanityError, PacketRx


@parameterized_class(
    [
        {
            "_description": "The 'type' field value is 0x0000 (null Ethertype).",
            "_frame_rx": (
                # Ethernet II
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 11:12:13:14:15:16
                #   Ethertype       : 0x0000 (< 0x0600, illegal for Ethernet II)
                #   Frame length    : 14 bytes
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x11\x12\x13\x14\x15\x16\x00\x00"
            ),
            "_results": {
                "error_message": "The minimum 'type' field value must be 0x0600. Got: 0x0000.",
            },
        },
        {
            "_description": "The 'type' field value is 0x0001 (below the Ethernet II minimum).",
            "_frame_rx": (
                # Ethernet II
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 11:12:13:14:15:16
                #   Ethertype       : 0x0001 (< 0x0600, illegal for Ethernet II)
                #   Frame length    : 14 bytes
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x11\x12\x13\x14\x15\x16\x00\x01"
            ),
            "_results": {
                "error_message": "The minimum 'type' field value must be 0x0600. Got: 0x0001.",
            },
        },
        {
            "_description": "The 'type' field value is 0x05ff (one below the Ethernet II minimum).",
            "_frame_rx": (
                # Ethernet II
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 11:12:13:14:15:16
                #   Ethertype       : 0x05ff (< 0x0600, illegal for Ethernet II)
                #   Frame length    : 14 bytes
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x11\x12\x13\x14\x15\x16\x05\xff"
            ),
            "_results": {
                "error_message": "The minimum 'type' field value must be 0x0600. Got: 0x05ff.",
            },
        },
    ]
)
class TestEthernetParserSanityChecks(TestCase):
    """
    The Ethernet packet parser sanity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def test__ethernet__parser__raises_sanity_error_on_legacy_length(self) -> None:
        """
        Ensure the Ethernet packet parser raises EthernetSanityError with the
        expected '[SANITY ERROR][Ethernet]'-prefixed message for every frame
        whose 'type' field encodes the obsolete 802.3 length framing.
        """

        with self.assertRaises(EthernetSanityError) as error:
            EthernetParser(PacketRx(self._frame_rx))

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][Ethernet] {self._results['error_message']}",
            msg=f"Unexpected sanity error message for case: {self._description}",
        )


class TestEthernetParserSanityChecksBoundary(TestCase):
    """
    Boundary tests for the Ethernet packet parser sanity validator.
    """

    def test__ethernet__parser__sanity_check_passes_at_exact_minimum(self) -> None:
        """
        Ensure a frame with a 'type' field of exactly 0x0600 (the documented
        Ethernet II minimum) passes the sanity validator — no exception is
        raised and parse state is exposed on the PacketRx.
        """

        frame = (
            # Ethernet II
            #   Destination MAC : a1:b2:c3:d4:e5:f6
            #   Source MAC      : 11:12:13:14:15:16
            #   Ethertype       : 0x0600 (== Ethernet II minimum)
            #   Frame length    : 14 bytes
            b"\xa1\xb2\xc3\xd4\xe5\xf6\x11\x12\x13\x14\x15\x16\x06\x00"
        )

        packet_rx = PacketRx(frame)
        parser = EthernetParser(packet_rx)

        self.assertEqual(
            int(parser.type),
            0x0600,
            msg="Ethertype at the 0x0600 boundary must be accepted by sanity.",
        )
        self.assertIs(
            packet_rx.ethernet,
            parser,
            msg="PacketRx.ethernet must reference the successful parser instance.",
        )

    def test__ethernet__parser__sanity_check_message_uses_actual_type_value(self) -> None:
        """
        Ensure the error message echoes the exact 'type' field value that was
        parsed out of the frame.
        """

        frame = (
            # Ethernet II
            #   Destination MAC : a1:b2:c3:d4:e5:f6
            #   Source MAC      : 11:12:13:14:15:16
            #   Ethertype       : 0x0123 (< 0x0600)
            #   Frame length    : 14 bytes
            b"\xa1\xb2\xc3\xd4\xe5\xf6\x11\x12\x13\x14\x15\x16\x01\x23"
        )

        with self.assertRaises(EthernetSanityError) as error:
            EthernetParser(PacketRx(frame))

        self.assertIn(
            "Got: 0x0123.",
            str(error.exception),
            msg="Error message must include the actual 'type' field value.",
        )
