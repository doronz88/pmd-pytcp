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
Module contains tests for the ICMPv4 unknown message parser.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__unknown__parser.py

ver 3.0.4
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore

from net_proto import (
    Icmp4Code,
    Icmp4MessageUnknown,
    Icmp4Parser,
    Icmp4Type,
    PacketRx,
)
from net_proto.tests.lib.testcase__packet_rx__ip4 import TestCasePacketRxIp4


@parameterized_class(
    [
        {
            "_description": "ICMPv4 unknown message.",
            "_frame_rx": [
                # ICMPv4 Unknown Message
                #   Type     : 255 (Unknown)
                #   Code     : 255 (Unknown)
                #   Checksum : 0x3129
                #   Data len : 16 bytes ("0123456789ABCDEF")
                #
                #   Summary  : Vendor-specific or unsupported ICMP message with 16-byte payload.
                b"\xff\xff\x31\x29\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                b"\x43\x44\x45\x46",
            ],
            "_results": {
                "message": Icmp4MessageUnknown(
                    type=Icmp4Type.from_int(255),
                    code=Icmp4Code.from_int(255),
                    cksum=12585,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
    ]
)
class TestIcmp4MessageUnknownParser(TestCasePacketRxIp4):
    """
    The ICMPv4 unknown message parser tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp4__message__unknown__parser(self) -> None:
        """
        Ensure the ICMPv4 unknown message 'from_bytes()' method creates
        a proper message object.
        """

        icmp4_parser = Icmp4Parser(self._packet_rx)

        # Convert the 'data' field from memoryview to bytes so we can compare.
        object.__setattr__(
            icmp4_parser.message,
            "data",
            bytes(cast(Icmp4MessageUnknown, icmp4_parser.message).data),
        )

        self.assertEqual(
            icmp4_parser.message,
            self._results["message"],
        )
