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
This module contains tests for the Ethernet 802.3 packet parser sanity checks.

The Ethernet 802.3 parser currently defines no sanity checks: every frame
that clears the integrity validator parses successfully. This module nails
that contract down with explicit tests so that any future sanity check
added to the parser must be accompanied by a matching test (and cannot
regress the no-error path silently).

net_proto/tests/unit/protocols/ethernet_802_3/test__ethernet_802_3__parser__sanity_checks.py

ver 3.0.4
"""


from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore

from net_addr import MacAddress
from net_proto import (
    ETHERNET_802_3__PAYLOAD__MAX_LEN,
    Ethernet8023Parser,
    Ethernet8023SanityError,
    PacketRx,
)


@parameterized_class(
    [
        {
            "_description": "Minimum-sized valid frame with no payload (dlen == 0).",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 11:12:13:14:15:16
                #   Length          : 0x0000 (empty payload)
                #   Frame length    : 14 bytes
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x11\x12\x13\x14\x15\x16\x00\x00"
            ),
            "_results": {
                "dst": MacAddress("a1:b2:c3:d4:e5:f6"),
                "src": MacAddress("11:12:13:14:15:16"),
                "dlen": 0,
            },
        },
        {
            "_description": "Broadcast-destined frame with a small payload.",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 00:11:22:33:44:55
                #   Length          : 0x0004 (4 bytes)
                #   Payload bytes   : 4
                b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x00\x04"
                b"\xde\xad\xbe\xef"
            ),
            "_results": {
                "dst": MacAddress("ff:ff:ff:ff:ff:ff"),
                "src": MacAddress("00:11:22:33:44:55"),
                "dlen": 4,
            },
        },
        {
            "_description": "Maximum-payload frame (dlen == 1500).",
            "_frame_rx": (
                # Ethernet 802.3
                #   Destination MAC : a1:b2:c3:d4:e5:f6
                #   Source MAC      : 11:12:13:14:15:16
                #   Length          : 0x05dc (1500 bytes == maximum)
                #   Payload bytes   : 1500
                b"\xa1\xb2\xc3\xd4\xe5\xf6\x11\x12\x13\x14\x15\x16\x05\xdc"
                + b"Z" * ETHERNET_802_3__PAYLOAD__MAX_LEN
            ),
            "_results": {
                "dst": MacAddress("a1:b2:c3:d4:e5:f6"),
                "src": MacAddress("11:12:13:14:15:16"),
                "dlen": ETHERNET_802_3__PAYLOAD__MAX_LEN,
            },
        },
    ]
)
class TestEthernet8023ParserSanityChecks(TestCase):
    """
    The Ethernet 802.3 packet parser sanity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def test__ethernet_802_3__parser__sanity_accepts_valid_frame(self) -> None:
        """
        Ensure every frame that clears the integrity validator also clears
        the sanity validator — i.e. the Ethernet 802.3 parser defines no
        sanity constraints today and parses the frame without raising.
        """

        try:
            parser = Ethernet8023Parser(PacketRx(self._frame_rx))
        except Ethernet8023SanityError as error:  # pragma: no cover
            self.fail(f"Unexpected Ethernet8023SanityError for case {self._description!r}: {error!s}")

        self.assertEqual(
            parser.dst,
            self._results["dst"],
            msg=f"Unexpected 'dst' for case: {self._description}",
        )
        self.assertEqual(
            parser.src,
            self._results["src"],
            msg=f"Unexpected 'src' for case: {self._description}",
        )
        self.assertEqual(
            parser.dlen,
            self._results["dlen"],
            msg=f"Unexpected 'dlen' for case: {self._description}",
        )


class TestEthernet8023ParserSanityCheckContract(TestCase):
    """
    The Ethernet 802.3 parser sanity validator contract tests.
    """

    def test__ethernet_802_3__parser__sanity_error_class_is_wired(self) -> None:
        """
        Ensure Ethernet8023SanityError is importable and carries the
        canonical '[SANITY ERROR][Ethernet 802.3]'-prefixed message —
        even though the parser never raises it today, the error class
        is part of the public API and must stay ready for future use.
        """

        error = Ethernet8023SanityError("probe")

        self.assertEqual(
            str(error),
            "[SANITY ERROR][Ethernet 802.3] probe",
            msg="Ethernet8023SanityError must produce the canonical prefixed message.",
        )

    def test__ethernet_802_3__parser__sanity_validator_is_callable_no_op(self) -> None:
        """
        Ensure '_validate_sanity()' is an implemented no-op on the parser —
        calling it a second time on a parsed instance must not raise.
        """

        frame = (
            # Ethernet 802.3
            #   Destination MAC : 11:22:33:44:55:66
            #   Source MAC      : 77:88:99:aa:bb:cc
            #   Length          : 0x0000 (empty payload)
            #   Frame length    : 14 bytes
            b"\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\x00\x00"
        )

        parser = Ethernet8023Parser(PacketRx(frame))

        self.assertIsNone(
            parser._validate_sanity(),  # noqa: SLF001
            msg="'_validate_sanity()' must be a no-op returning None.",
        )
