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
Module contains tests for the ICMPv4 Destination Unreachable message assembler.

net_proto/tests/unit/protocols/icmp4/test__icmp4__message__destination_unreachable__assembler.py

ver 3.0.4
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_proto import (
    Icmp4Assembler,
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
    Icmp4Type,
)
from net_proto.lib.buffer import Buffer


@parameterized_class(
    [
        {
            "_description": "ICMPv4 Destination Unreachable (Network) message.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.NETWORK,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Network, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".NETWORK: 0>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 0 (Network)
                    #   Checksum : 0xfcff
                    #   Next-Hop : 0x00000000
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Network unreachable notification with empty payload.
                    b"\x03\x00\xfc\xff\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.NETWORK,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Host) message.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.HOST,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Host, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".HOST: 1>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 1 (Host)
                    #   Checksum : 0xfcfe
                    #   Next-Hop : 0x00000000
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Host unreachable notification with empty payload.
                    b"\x03\x01\xfc\xfe\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.HOST,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Protocol) message.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.PROTOCOL,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Protocol, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".PROTOCOL: 2>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 2 (Protocol)
                    #   Checksum : 0xfcfd
                    #   Next-Hop : 0x00000000
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Protocol unreachable notification with empty payload.
                    b"\x03\x02\xfc\xfd\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.PROTOCOL,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable - (Port) message.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.PORT,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Port, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".PORT: 3>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 3 (Port)
                    #   Checksum : 0xfcfc
                    #   Next-Hop : 0x00000000
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Port unreachable notification with empty payload.
                    b"\x03\x03\xfc\xfc\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.PORT,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Fragmentation Needed) message.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED,
                "mtu": 1200,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Fragmentation Needed, mtu 1200, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".FRAGMENTATION_NEEDED: 4>, cksum=0, mtu=1200, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 4 (Fragmentation Needed)
                    #   Checksum : 0xf84b
                    #   Next-Hop : 0x000004b0 (MTU 1200)
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Fragmentation needed notification with MTU set to 1200.
                    b"\x03\x04\xf8\x4b\x00\x00\x04\xb0"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED,
                "cksum": 0,
                "mtu": 1200,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Source Route Failed) message.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.SOURCE_ROUTE_FAILED,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Source Route Failed, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".SOURCE_ROUTE_FAILED: 5>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 5 (Source Route Failed)
                    #   Checksum : 0xfcfa
                    #   Next-Hop : 0x00000000
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Source route failed notification with empty payload.
                    b"\x03\x05\xfc\xfa\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.SOURCE_ROUTE_FAILED,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Network Unknown) message.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.NETWORK_UNKNOWN,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Network Unknown, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".NETWORK_UNKNOWN: 6>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 6 (Network Unknown)
                    #   Checksum : 0xfcf9
                    #   Next-Hop : 0x00000000
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Network unknown notification with empty payload.
                    b"\x03\x06\xfc\xf9\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.NETWORK_UNKNOWN,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Host Unknown) message.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.HOST_UNKNOWN,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Host Unknown, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".HOST_UNKNOWN: 7>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 7 (Host Unknown)
                    #   Checksum : 0xfcf8
                    #   Next-Hop : 0x00000000
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Host unknown notification with empty payload.
                    b"\x03\x07\xfc\xf8\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.HOST_UNKNOWN,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Source Host Isolated) message.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.SOURCE_HOST_ISOLATED,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Source Host Isolated, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".SOURCE_HOST_ISOLATED: 8>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 8 (Source Host Isolated)
                    #   Checksum : 0xfcf7
                    #   Next-Hop : 0x00000000
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Source host isolated notification with empty payload.
                    b"\x03\x08\xfc\xf7\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.SOURCE_HOST_ISOLATED,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Network Prohibited) message'.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.NETWORK_PROHIBITED,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Network Prohibited, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".NETWORK_PROHIBITED: 9>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 9 (Network Prohibited)
                    #   Checksum : 0xfcf6
                    #   Next-Hop : 0x00000000
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Network administratively prohibited notification.
                    b"\x03\x09\xfc\xf6\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.NETWORK_PROHIBITED,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Host Prohibited) message.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.HOST_PROHIBITED,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Host Prohibited, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".HOST_PROHIBITED: 10>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 10 (Host Prohibited)
                    #   Checksum : 0xfcf5
                    #   Next-Hop : 0x00000000
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Host administratively prohibited notification.
                    b"\x03\x0a\xfc\xf5\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.HOST_PROHIBITED,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Network TOS) message.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.NETWORK_TOS,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Network TOS, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".NETWORK_TOS: 11>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 11 (Network TOS)
                    #   Checksum : 0xfcf4
                    #   Next-Hop : 0x00000000
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Network TOS unreachable notification with empty payload.
                    b"\x03\x0b\xfc\xf4\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.NETWORK_TOS,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Host TOS) message.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.HOST_TOS,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Host TOS, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".HOST_TOS: 12>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 12 (Host TOS)
                    #   Checksum : 0xfcf3
                    #   Next-Hop : 0x00000000
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Host TOS unreachable notification with empty payload.
                    b"\x03\x0c\xfc\xf3\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.HOST_TOS,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Communication Prohibited) message.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.COMMUNICATION_PROHIBITED,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Communication Prohibited, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".COMMUNICATION_PROHIBITED: 13>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 13 (Communication Prohibited)
                    #   Checksum : 0xfcf2
                    #   Next-Hop : 0x00000000
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Communication administratively prohibited notification.
                    b"\x03\x0d\xfc\xf2\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.COMMUNICATION_PROHIBITED,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Host Precedence) message.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.HOST_PRECEDENCE,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Host Precedence, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".HOST_PRECEDENCE: 14>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 14 (Host Precedence)
                    #   Checksum : 0xfcf1
                    #   Next-Hop : 0x00000000
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Host precedence violation notification with empty payload.
                    b"\x03\x0e\xfc\xf1\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.HOST_PRECEDENCE,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable (Precedence Cutoff) message.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.PRECEDENCE_CUTOFF,
                "data": b"",
            },
            "_results": {
                "__len__": 8,
                "__str__": "ICMPv4 Destination Unreachable - Precedence Cutoff, len 8 (8+0)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".PRECEDENCE_CUTOFF: 15>, cksum=0, mtu=None, data=b'')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 15 (Precedence Cutoff)
                    #   Checksum : 0xfcf0
                    #   Next-Hop : 0x00000000
                    #   Data len : 0 bytes
                    #
                    #   Summary  : Precedence cutoff in effect notification with empty payload.
                    b"\x03\x0f\xfc\xf0\x00\x00\x00\x00"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.PRECEDENCE_CUTOFF,
                "cksum": 0,
                "data": b"",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable message, non-empty payload.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.PORT,
                "data": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 24,
                "__str__": "ICMPv4 Destination Unreachable - Port, len 24 (8+16)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    ".PORT: 3>, cksum=0, mtu=None, data=b'0123456789ABCDEF')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 3 (Port)
                    #   Checksum : 0x2e26
                    #   Next-Hop : 0x00000000
                    #   Data len : 16 bytes
                    #
                    #   Summary  : Port unreachable with 16-byte payload echoing offending packet.
                    b"\x03\x03\x2e\x26\x00\x00\x00\x00\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.PORT,
                "cksum": 0,
                "data": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "ICMPv4 Destination Unreachable message, maximum length payload.",
            "_kwargs": {
                "code": Icmp4DestinationUnreachableCode.PORT,
                "data": b"X" * 65507,
            },
            "_results": {
                "__len__": 556,
                "__str__": "ICMPv4 Destination Unreachable - Port, len 556 (8+548)",
                "__repr__": (
                    "Icmp4MessageDestinationUnreachable(code=<Icmp4DestinationUnreachableCode"
                    f".PORT: 3>, cksum=0, mtu=None, data=b'{"X" * 548}')"
                ),
                "__bytes__": (
                    # ICMPv4 Destination Unreachable
                    #   Type     : 3 (Destination Unreachable)
                    #   Code     : 3 (Port)
                    #   Checksum : 0x6e6e
                    #   Next-Hop : 0x00000000
                    #   Data len : 548 bytes
                    #
                    #   Summary  : Port unreachable carrying maximum-length payload (548 bytes).
                    b"\x03\x03\x6e\x6e\x00\x00\x00\x00"
                    + b"X" * 548
                ),
                "type": Icmp4Type.DESTINATION_UNREACHABLE,
                "code": Icmp4DestinationUnreachableCode.PORT,
                "cksum": 0,
                "data": b"X" * 548,
            },
        },
    ]
)
class TestIcmp4MessageDestinationUnreachableAssembler(TestCase):
    """
    The ICMPv4 Destination Unreachable message assembler tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the ICMPv4 Destination Unreachable message assembler object with
        testcase arguments.
        """

        self._icmp4__assembler = Icmp4Assembler(icmp4__message=Icmp4MessageDestinationUnreachable(**self._kwargs))

    def test__icmp4__message__destination_unreachable__assembler__len(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message '__len__()' method returns
        a correct value.
        """

        self.assertEqual(
            len(self._icmp4__assembler),
            self._results["__len__"],
        )

    def test__icmp4__message__destination_unreachable__assembler__str(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message '__str__()' method returns
        a correct value.
        """

        self.assertEqual(
            str(self._icmp4__assembler),
            self._results["__str__"],
        )

    def test__icmp4__message__destination_unreachable__assembler__repr(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message '__repr__()' method returns
        a correct value.
        """

        self.assertEqual(
            repr(self._icmp4__assembler),
            self._results["__repr__"],
        )

    def test__icmp4__message__destination_unreachable__assembler__bytes(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message '__bytes__()' method returns
        a correct value.
        """

        self.assertEqual(
            bytes(self._icmp4__assembler),
            self._results["__bytes__"],
        )

    def test__icmp4__message__destination_unreachable__assembler__type(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message 'type' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp4__assembler.message.type,
            self._results["type"],
        )

    def test__icmp4__message__destination_unreachable__assembler__code(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message 'code' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp4__assembler.message.code,
            self._results["code"],
        )

    def test__icmp4__message__destination_unreachable__assembler__cksum(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message 'cksum' field contains
        a correct value.
        """

        self.assertEqual(
            self._icmp4__assembler.message.cksum,
            self._results["cksum"],
        )

    def test__icmp4__message__destination_unreachable__assembler__mtu(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message 'mtu' field contains
        a correct value.
        """

        if "mtu" in self._results:
            self.assertEqual(
                cast(
                    Icmp4MessageDestinationUnreachable,
                    self._icmp4__assembler.message,
                ).mtu,
                self._results["mtu"],
            )

    def test__icmp4__message__destination_unreachable__assembler__data(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message 'data' field contains
        a correct value.
        """

        self.assertEqual(
            cast(
                Icmp4MessageDestinationUnreachable,
                self._icmp4__assembler.message,
            ).data,
            self._results["data"],
        )

    def test__icmp4__messsage__destination_unreachable__assembler__assemble(
        self,
    ) -> None:
        """
        Ensure the ICMPv4 Destination Unreachable message 'assemble()' method returns
        a correct value.
        """

        buffers: list[Buffer] = []

        self._icmp4__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
        )
