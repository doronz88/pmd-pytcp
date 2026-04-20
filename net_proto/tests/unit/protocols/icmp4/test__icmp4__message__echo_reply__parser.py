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
Module contains tests for the ICMPv4 Echo Reply message parser.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__echo_reply__parser.py

ver 3.0.4
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore

from net_proto import Icmp4MessageEchoReply, Icmp4Parser, PacketRx
from net_proto.tests.lib.testcase__packet_rx__ip4 import TestCasePacketRxIp4


@parameterized_class(
    [
        {
            "_description": "ICMP4 Echo Reply message, empty data.",
            "_frame_rx": (
                # ICMPv4 Echo Reply
                #   Type     : 0 (Echo Reply)
                #   Code     : 0 (Default)
                #   Checksum : 0xfb94
                #   Identifier: 12345
                #   Sequence : 54321
                #   Data len : 0 bytes
                #
                #   Summary  : Echo reply matching request ID 12345/seq 54321, empty payload.
                b"\x00\x00\xfb\x94\x30\x39\xd4\x31"
            ),
            "_results": {
                "message": Icmp4MessageEchoReply(
                    cksum=64404,
                    id=12345,
                    seq=54321,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMP4 Echo Reply message, non-empty data.",
            "_frame_rx": (
                # ICMPv4 Echo Reply
                #   Type     : 0 (Echo Reply)
                #   Code     : 0 (Default)
                #   Checksum : 0x2cbe
                #   Identifier: 12345
                #   Sequence : 54321
                #   Data len : 16 bytes ("0123456789ABCDEF")
                #
                #   Summary  : Echo reply carrying 16-byte payload from original request.
                b"\x00\x00\x2c\xbe\x30\x39\xd4\x31\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_results": {
                "message": Icmp4MessageEchoReply(
                    cksum=11454,
                    id=12345,
                    seq=54321,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "ICMP4 Echo Reply message, maximum length of data.",
            "_frame_rx": (
                # ICMPv4 Echo Reply
                #   Type     : 0 (Echo Reply)
                #   Code     : 0 (Default)
                #   Checksum : 0x26cb
                #   Identifier: 11111
                #   Sequence : 22222
                #   Data len : 65507 bytes ("X" * 65507)
                #
                #   Summary  : Echo reply at maximum payload size (65507 bytes).
                b"\x00\x00\x26\xcb\x2b\x67\x56\xce"
                + b"X" * 65507
            ),
            "_results": {
                "message": Icmp4MessageEchoReply(
                    cksum=9931,
                    id=11111,
                    seq=22222,
                    data=b"X" * 65507,
                ),
            },
        },
    ]
)
class TestIcmp4MessageEchoReplyParser(TestCasePacketRxIp4):
    """
    The ICMPv4 Echo Reply message parser tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp4__message__echo_reply__parser(self) -> None:
        """
        Ensure the ICMPv4 'Echo Reply' message 'from_bytes()' method
        creates a proper message object.
        """

        icmp4_parser = Icmp4Parser(self._packet_rx)

        # Convert the 'data' field from memoryview to bytes so we can compare.
        object.__setattr__(
            icmp4_parser.message,
            "data",
            bytes(cast(Icmp4MessageEchoReply, icmp4_parser.message).data),
        )

        self.assertEqual(
            icmp4_parser.message,
            self._results["message"],
        )
