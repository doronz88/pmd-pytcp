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
Module contains tests for the ICMPv6 MLDv2 Report message parser integrity
checks.

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__message__report__parser__integrity_checks.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from net_proto import Icmp6IntegrityError, Icmp6Parser, PacketRx
from net_proto.tests.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6


@parameterized_class(
    [
        {
            "_description": ("ICMPv6 MLDv2 message, " "the 'ICMP6_HEADER_LEN <= self._ip6__dlen' condition not met."),
            "_frame_rx": (
                # ICMPv6 MLDv2 Report
                #   Type     : 143 (MLDv2 Report)
                #   Code     : 0
                #   Checksum : 0x70?? (truncated)
                #   Frame len: 3 bytes (< 4-byte minimum header)
                #
                #   Summary  : Frame shorter than ICMPv6 header length.
                b"\x8f\x00\x70"
            ),
            "_mocked_values": {
                "ip6__dlen": 3,
            },
            "_results": {
                "error_message": (
                    "The condition 'ICMP6__HEADER__LEN <= self._ip6__dlen "
                    "<= len(self._frame)' must be met. Got: ICMP6__HEADER__LEN=4, "
                    "self._ip6__dlen=3, len(self._frame)=3"
                ),
            },
        },
        {
            "_description": (
                "ICMPv6 MLDv2 Report message, " "the 'self._ip6__dlen <= len(self._frame)' condition not met."
            ),
            "_frame_rx": (
                # ICMPv6 MLDv2 Report
                #   Type     : 143
                #   Code     : 0
                #   Checksum : 0x70ff
                #   Record count: 0x0000 (partial)
                #   Frame len : 7 bytes (< 8-byte minimum header)
                #
                #   Summary   : Declared payload exceeds available frame length.
                b"\x8f\x00\x70\xff\x00\x00\x00"
            ),
            "_mocked_values": {
                "ip6__dlen": 8,
            },
            "_results": {
                "error_message": (
                    "The condition 'ICMP6__HEADER__LEN <= self._ip6__dlen "
                    "<= len(self._frame)' must be met. Got: ICMP6__HEADER__LEN=4, "
                    "self._ip6__dlen=8, len(self._frame)=7"
                ),
            },
        },
        {
            "_description": ("ICMPv6 MLDv2 message, " "the 'ICMP6__MLD2__REPORT__LEN <= ip6__dlen' condition not met."),
            "_frame_rx": (
                # ICMPv6 MLDv2 Report
                #   Type     : 143
                #   Code     : 0
                #   Checksum : 0x70ff
                #   Record count: 0x0000 (claims 0 groups)
                #   Frame len : 8 bytes (minimum header)
                #
                #   Summary   : Payload shorter than required MLDv2 report length.
                b"\x8f\x00\x70\xff\x00\x00\x00\x00"
            ),
            "_mocked_values": {
                "ip6__dlen": 7,
            },
            "_results": {
                "error_message": (
                    "The condition 'ICMP6__MLD2__REPORT__LEN <= ip6__dlen <= len(frame)' "
                    "is not met. Got: ICMP6__MLD2__REPORT__LEN=8, ip6__dlen=7, len(frame)=8"
                ),
            },
        },
        {
            "_description": (
                "ICMPv6 MLDv2 message, the "
                "'record_offset + ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN <= ip6__dlen' "
                "condition not met."
            ),
            "_frame_rx": (
                # ICMPv6 MLDv2 Report
                #   Type     : 143
                #   Code     : 0
                #   Checksum : 0x1582
                #   Record cnt: 0x0002 (2 records advertised)
                #   Record 0 : Type 0x01 (MODE_IS_INCLUDE), Aux len 0x00, Src count 0x0002
                #              Multicast address ff02::1
                #   Record 1 : Type 0x20 (illegal/extended), Aux len 0x01, Src count 0x0db8
                #              Multicast address ::2 (truncated)
                #   Frame len: 60 bytes (records truncated)
                #
                #   Summary  : Multicast address record overruns available payload.
                b"\x8f\x00\x15\x82\x00\x00\x00\x02\x01\x00\x00\x02\xff\x02\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
            ),
            "_mocked_values": {},
            "_results": {
                "error_message": (
                    "The condition 'record_offset + ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN "
                    "<= ip6__dlen' is not met. Got: record_offset=60, "
                    "ICMP6__MLD2__MULTICAST_ADDRESS_RECORD__LEN=20, ip6__dlen=60"
                ),
            },
        },
        {
            "_description": ("ICMPv6 MLDv2 message, the 'record_offset == ip6__dlen' condition not met."),
            "_frame_rx": (
                # ICMPv6 MLDv2 Report
                #   Type     : 143
                #   Code     : 0
                #   Checksum : 0x1583
                #   Record cnt: 0x0001
                #   Record    : Type 0x01 (MODE_IS_INCLUDE), Aux len 0x00, Src count 0x0002
                #               Multicast address ff02::1 with source list 2001:db8::1, 2001:db8::2
                #   Frame len : 60 bytes
                #
                #   Summary   : Recorded offset does not match payload length (truncated data).
                b"\x8f\x00\x15\x83\x00\x00\x00\x01\x01\x00\x00\x02\xff\x02\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
            ),
            "_mocked_values": {
                "ip6__dlen": 59,
            },
            "_results": {
                "error_message": (
                    "The condition 'record_offset == ip6__dlen' is not met. " "Got: record_offset=60, ip6__dlen=59"
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Report, invalid checksum.",
            "_frame_rx": (
                # ICMPv6 MLDv2 Report
                #   Type     : 143
                #   Code     : 0
                #   Checksum : 0x0000 (invalid)
                #   Record cnt: 0x0000
                #   Data len : 0 bytes
                #
                #   Summary  : MLDv2 report with checksum cleared to zero.
                b"\x8f\x00\x00\x00\x00\x00\x00\x00"
            ),
            "_mocked_values": {},
            "_results": {
                "error_message": "The packet checksum must be valid.",
            },
        },
    ]
)
class TestIcmp6Mld2MessageReportParserIntegrityChecks(TestCasePacketRxIp6):
    """
    The ICMPv6 MLDv2 Report message parser integrity checks tests.
    """

    _description: str
    _frame_rx: bytes
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp6__mld2__message__report__parser(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message parser raises integrity error
        on malformed packets.
        """

        with self.assertRaises(Icmp6IntegrityError) as error:
            Icmp6Parser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[INTEGRITY ERROR][ICMPv6] {self._results["error_message"]}",
        )
