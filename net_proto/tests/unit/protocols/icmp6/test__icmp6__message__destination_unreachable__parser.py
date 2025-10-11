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
Module contains tests for the ICMPv6 Destination Unreachable message parser.

net_proto/tests/unit/protocols/icmp4/test__icmp6__message__destination_unreachable__parser.py

ver 3.0.4
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore

from net_proto import (
    Icmp6DestinationUnreachableCode,
    Icmp6MessageDestinationUnreachable,
    Icmp6Parser,
    PacketRx,
)
from net_proto.tests.lib.testcase__packet_rx__ip6 import TestCasePacketRxIp6


@parameterized_class(
    [
        {
            "_description": "ICMPv6 Destination Unreachable (No Route) message.",
            "_frame_rx": [
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 0 (No Route)
                #   Checksum : 0xfeff
                #   Data len : 0 bytes
                #
                #   Summary  : IPv6 host indicates no route to destination.
                b"\x01\x00\xfe\xff\x00\x00\x00\x00",
            ],
            "mocked_values": {},
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.NO_ROUTE,
                    cksum=65279,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Prohibited) message.",
            "_frame_rx": [
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 1 (Administratively Prohibited)
                #   Checksum : 0xfefe
                #   Data len : 0 bytes
                #
                #   Summary  : Traffic administratively prohibited to destination.
                b"\x01\x01\xfe\xfe\x00\x00\x00\x00",
            ],
            "mocked_values": {},
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.PROHIBITED,
                    cksum=65278,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Scope) message.",
            "_frame_rx": [
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 2 (Beyond Scope)
                #   Checksum : 0xfefd
                #   Data len : 0 bytes
                #
                #   Summary  : Destination beyond scope of source address.
                b"\x01\x02\xfe\xfd\x00\x00\x00\x00",
            ],
            "mocked_values": {},
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.SCOPE,
                    cksum=65277,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Address) message.",
            "_frame_rx": [
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 3 (Address Unreachable)
                #   Checksum : 0xfefc
                #   Data len : 0 bytes
                #
                #   Summary  : Destination address unreachable for the source.
                b"\x01\x03\xfe\xfc\x00\x00\x00\x00",
            ],
            "mocked_values": {},
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.ADDRESS,
                    cksum=65276,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Port) message.",
            "_frame_rx": [
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 4 (Port Unreachable)
                #   Checksum : 0xfefb
                #   Data len : 0 bytes
                #
                #   Summary  : Target transport port unreachable.
                b"\x01\x04\xfe\xfb\x00\x00\x00\x00",
            ],
            "mocked_values": {},
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.PORT,
                    cksum=65275,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Failed Policy) message.",
            "_frame_rx": [
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 5 (Source Failed Policy)
                #   Checksum : 0xfefa
                #   Data len : 0 bytes
                #
                #   Summary  : Source address failed ingress/egress policy.
                b"\x01\x05\xfe\xfa\x00\x00\x00\x00",
            ],
            "mocked_values": {},
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.FAILED_POLICY,
                    cksum=65274,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Reject Route) message.",
            "_frame_rx": [
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 6 (Reject Route)
                #   Checksum : 0xfef9
                #   Data len : 0 bytes
                #
                #   Summary  : Router rejects route to destination.
                b"\x01\x06\xfe\xf9\x00\x00\x00\x00",
            ],
            "mocked_values": {},
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.REJECT_ROUTE,
                    cksum=65273,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable (Source Routing Header) message.",
            "_frame_rx": [
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 7 (Error in Source Routing Header)
                #   Checksum : 0xfef8
                #   Data len : 0 bytes
                #
                #   Summary  : Error processing IPv6 source routing header.
                b"\x01\x07\xfe\xf8\x00\x00\x00\x00",
            ],
            "mocked_values": {},
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.SOURCE_ROUTING_HEADER,
                    cksum=65272,
                    data=b"",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable message, non-empty payload.",
            "_frame_rx": [
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 4 (Port Unreachable)
                #   Checksum : 0x3025
                #   Data len : 16 bytes ("0123456789ABCDEF")
                #
                #   Summary  : Port unreachable message carrying 16-byte offending payload.
                b"\x01\x04\x30\x25\x00\x00\x00\x00\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x41\x42\x43\x44\x45\x46",
            ],
            "mocked_values": {},
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.PORT,
                    cksum=12325,
                    data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": "ICMPv6 Destination Unreachable message, maximum length payload.",
            "_args": [
                # ICMPv6 Destination Unreachable
                #   Type     : 1 (Destination Unreachable)
                #   Code     : 4 (Port Unreachable)
                #   Checksum : 0x6a67
                #   Data len : 1232 bytes ("X" * 1232)
                #
                #   Summary  : Port unreachable message with maximum captured payload.
                b"\x01\x04\x6a\x67\x00\x00\x00\x00"
                + b"X" * 1232,
            ],
            "mocked_values": {},
            "_results": {
                "message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.PORT,
                    cksum=27239,
                    data=b"X" * 1232,
                ),
            },
        },
    ]
)
class TestIcmp6MessageDestinationUnreachableParser(TestCasePacketRxIp6):
    """
    The ICMPv6 Destination Unreachable message parser tests.
    """

    _description: str
    _frame_rx: bytes
    _mocked_values: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__icmp6__message__destination_unreachable__parser(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 Destination Unreachable message 'message()'
        method creates a proper message object.
        """

        icmp6_parser = Icmp6Parser(self._packet_rx)

        # Convert the 'data' field from memoryview to bytes so we can compare.
        object.__setattr__(
            icmp6_parser.message,
            "data",
            bytes(cast(Icmp6MessageDestinationUnreachable, icmp6_parser.message).data),
        )

        self.assertEqual(
            icmp6_parser.message,
            self._results["message"],
        )
