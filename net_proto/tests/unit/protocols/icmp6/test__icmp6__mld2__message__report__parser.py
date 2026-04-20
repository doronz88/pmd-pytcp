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
Module contains tests for the ICMPv6 MLDv2 Report message parser.

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__message__report__parser.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from net_addr import Ip6Address
from net_proto import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
    Icmp6Mld2ReportMessage,
    Icmp6Parser,
    PacketRx,
)
from net_proto.tests.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6


@parameterized_class(
    [
        {
            "_description": "ICMPv6 MLDv2 Report message, no records.",
            "_frame_rx": (
                # ICMPv6 MLDv2 Report
                #   Type     : 143 (MLDv2 Report)
                #   Code     : 0
                #   Checksum : 0x70ff
                #   Record cnt: 0x0000
                #   Data len : 0 bytes
                #
                #   Summary  : Minimal MLDv2 report with no multicast address records.
                b"\x8f\x00\x70\xff\x00\x00\x00\x00"
            ),
            "_mocked_values": {
                "ip6__hop": 1,
            },
            "_results": {
                "message": Icmp6Mld2ReportMessage(
                    cksum=28927,
                    records=[],
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Report message, single record.",
            "_frame_rx": (
                # ICMPv6 MLDv2 Report
                #   Type     : 143 (MLDv2 Report)
                #   Code     : 0
                #   Checksum : 0x1583
                #   Record cnt: 0x0001
                #   Record    : Type 0x01 (MODE_IS_INCLUDE)
                #              Aux len 0x00, Src count 0x0002
                #              Multicast address ff02::1
                #              Sources: 2001:db8::1, 2001:db8::2
                #
                #   Summary  : MLDv2 report containing a single include-mode record.
                b"\x8f\x00\x15\x83\x00\x00\x00\x01\x01\x00\x00\x02\xff\x02\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
            ),
            "_mocked_values": {
                "ip6__hop": 1,
            },
            "_results": {
                "message": Icmp6Mld2ReportMessage(
                    cksum=5507,
                    records=[
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                            multicast_address=Ip6Address("ff02::1"),
                            source_addresses=[
                                Ip6Address("2001:db8::1"),
                                Ip6Address("2001:db8::2"),
                            ],
                        ),
                    ],
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Report message, multiple records.",
            "_frame_rx": (
                # ICMPv6 MLDv2 Report
                #   Type     : 143 (MLDv2 Report)
                #   Code     : 0
                #   Checksum : 0x52f0
                #   Record cnt: 0x0004
                #   Record 0 : Type 0x01 (MODE_IS_INCLUDE), Src cnt 0x0001, Aux len 0x04
                #              Multicast address ff02::1, Source 2001:db8::1, Aux data "0123456789ABCDEF"
                #   Record 1 : Type 0x02 (MODE_IS_EXCLUDE), Src cnt 0x0003, Aux len 0x08
                #              Multicast address ff02::2, Sources 2001:db8::2/3/4, Aux data "0123456789ABCDEF"*2
                #   Record 2 : Type 0x03 (CHANGE_TO_INCLUDE), Src cnt 0x0004, Aux len 0x00
                #              Multicast address ff02::3, Sources 2001:db8::6/7/8/9
                #   Record 3 : Type 0x06 (BLOCK_OLD_SOURCES), Src cnt 0x0000, Aux len 0x10
                #              Multicast address ff02::4, Aux data "0123456789ABCDEF"*4
                #
                #   Summary  : Comprehensive MLDv2 report with multiple record types, sources, and aux data.
                b"\x8f\x00\x52\xf0\x00\x00\x00\x04\x01\x04\x00\x01\xff\x02\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x20\x01\x0d\xb8"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x02\x08\x00\x03"
                b"\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
                b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
                b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03"
                b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
                b"\x03\x00\x00\x04\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x03\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x06\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x08\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x09\x06\x10\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x04\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46"
            ),
            "_mocked_values": {
                "ip6__hop": 1,
            },
            "_results": {
                "message": Icmp6Mld2ReportMessage(
                    cksum=21232,
                    records=[
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                            multicast_address=Ip6Address("ff02::1"),
                            source_addresses=[
                                Ip6Address("2001:db8::1"),
                            ],
                            aux_data=b"0123456789ABCDEF",
                        ),
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE,
                            multicast_address=Ip6Address("ff02::2"),
                            source_addresses=[
                                Ip6Address("2001:db8::2"),
                                Ip6Address("2001:db8::3"),
                                Ip6Address("2001:db8::4"),
                            ],
                            aux_data=b"0123456789ABCDEF0123456789ABCDEF",
                        ),
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE,
                            multicast_address=Ip6Address("ff02::3"),
                            source_addresses=[
                                Ip6Address("2001:db8::6"),
                                Ip6Address("2001:db8::7"),
                                Ip6Address("2001:db8::8"),
                                Ip6Address("2001:db8::9"),
                            ],
                        ),
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.BLOCK_OLD_SOURCES,
                            multicast_address=Ip6Address("ff02::4"),
                            aux_data=(b"0123456789ABCDEF0123456789ABCDEF" b"0123456789ABCDEF0123456789ABCDEF"),
                        ),
                    ],
                ),
            },
        },
    ]
)
class TestIcmp6Mld2MessageReportParser(TestCasePacketRxIp6):
    """
    The ICMPv6 MLDv2 Report message parser tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp6__mld2__message__report__parser__from_bytes(self) -> None:
        """
        Ensure the ICMPv6 MLDv2 Report message 'from_bytes()' method
        creates a proper message object.
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
        )
