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
Module contains tests for the ICMPv4 unknown message parser.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__unknown__parser.py

ver 3.0.6
"""

from types import SimpleNamespace
from typing import Any, cast
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore[import-untyped]

from net_proto import (
    Icmp4Code,
    Icmp4MessageUnknown,
    Icmp4Parser,
    Icmp4Type,
    Ip4Parser,
    PacketRx,
)


def _packet_rx_with_ip4(frame: bytes) -> PacketRx:
    """
    Build a PacketRx with a minimal IPv4 stub whose 'payload_len' matches
    the full frame (the only field Icmp4Parser reads off 'packet_rx.ip4').
    """

    packet_rx = PacketRx(frame)
    packet_rx.ip4 = cast(Ip4Parser, SimpleNamespace(payload_len=len(frame)))
    return packet_rx


@parameterized_class(
    [
        {
            "_description": "ICMPv4 unknown message (type 255, code 255), 16-byte data.",
            "_frame_rx": (
                # ICMPv4 Unknown Message
                #   Type     : 255 (Unknown)
                #   Code     : 255 (Unknown)
                #   Checksum : 0x3129
                #   Data     : b"0123456789ABCDEF" (16 bytes)
                b"\xff\xff\x31\x29\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                b"\x43\x44\x45\x46"
            ),
            "_results": {
                "message": Icmp4MessageUnknown(
                    type=Icmp4Type.from_int(255),
                    code=Icmp4Code.from_int(255),
                    cksum=0x3129,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "ICMPv4 unknown message (type 1, code 2), empty data.",
            "_frame_rx": (
                # ICMPv4 Unknown Message
                #   Type     : 1 (Unknown)
                #   Code     : 2 (Unknown)
                #   Checksum : 0xfefd
                #   Data     : none (bare 4-byte header)
                b"\x01\x02\xfe\xfd"
            ),
            "_results": {
                "message": Icmp4MessageUnknown(
                    type=Icmp4Type.from_int(1),
                    code=Icmp4Code.from_int(2),
                    cksum=0xFEFD,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv4 unknown message (type 1, code 0), maximum data (65511 bytes).",
            "_frame_rx": (
                # ICMPv4 Unknown Message (at IPv4 payload maximum)
                #   Type     : 1 (Unknown)
                #   Code     : 0
                #   Checksum : 0xf74f
                #   Data     : b"X" * 65511 (IP4__PAYLOAD__MAX_LEN - ICMP4__HEADER__LEN)
                b"\x01\x00\xf7\x4f"
                + b"X" * 65511
            ),
            "_results": {
                "message": Icmp4MessageUnknown(
                    type=Icmp4Type.from_int(1),
                    code=Icmp4Code.from_int(0),
                    cksum=0xF74F,
                    data=b"X" * 65511,
                ),
            },
        },
    ]
)
class TestIcmp4MessageUnknownParser(TestCase):
    """
    The ICMPv4 unknown message parser tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Build a PacketRx for the parametrized frame.
        """

        self._packet_rx = _packet_rx_with_ip4(self._frame_rx)

    def test__icmp4__message__unknown__parser(self) -> None:
        """
        Ensure the ICMPv4 parser produces an Icmp4MessageUnknown instance
        whose fields match the expected reference message for each frame.
        """

        icmp4_parser = Icmp4Parser(self._packet_rx)

        # Materialize 'data' from memoryview to bytes for structural equality.
        object.__setattr__(
            icmp4_parser.message,
            "data",
            bytes(cast(Icmp4MessageUnknown, icmp4_parser.message).data),
        )

        self.assertEqual(
            icmp4_parser.message,
            self._results["message"],
            msg=f"Parsed message mismatch for case: {self._description}",
        )

    def test__icmp4__message__unknown__parser__frame_advanced(self) -> None:
        """
        Ensure the ICMPv4 parser advances 'packet_rx.frame' past the
        parsed unknown message.
        """

        Icmp4Parser(self._packet_rx)

        self.assertEqual(
            len(self._packet_rx.frame),
            0,
            msg=f"Frame must be fully consumed by the parser for case: {self._description}",
        )
