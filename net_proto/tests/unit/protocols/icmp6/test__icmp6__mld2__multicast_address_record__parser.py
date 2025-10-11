#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-present Sebastian Majewski                           #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


"""
This module contains tests for the ICMPv6 MLDv2 Multicast Address Record parser.

net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__multicast_address_record__parser.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_addr import Ip6Address
from net_proto import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)


@parameterized_class(
    [
        {
            "_description": "ICMPv6 MLDv2 Multicast Address Record (Mode Is Include).",
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Record type   : 0x01 (MODE_IS_INCLUDE)
                #   Aux data len  : 0
                #   Source count  : 0
                #   Multicast addr: ff02::1
                #   Payload       : None
                #
                #   Summary       : Include-mode record for ff02::1 with no sources or aux data.
                b"\x01\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01"
            ),
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Multicast Address Record (Mode Is Exclude).",
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Record type   : 0x02 (MODE_IS_EXCLUDE)
                #   Aux data len  : 0
                #   Source count  : 0
                #   Multicast addr: ff02::1
                #
                #   Summary       : Exclude-mode record for ff02::1 with no sources.
                b"\x02\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01"
            ),
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Multicast Address Record (Change To Include).",
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Record type   : 0x03 (CHANGE_TO_INCLUDE)
                #   Aux data len  : 0
                #   Source count  : 0
                #   Multicast addr: ff02::1
                #
                #   Summary       : Change-to-include record signalling switch to include mode.
                b"\x03\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01"
            ),
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Multicast Address Record (Change To Exclude).",
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Record type   : 0x04 (CHANGE_TO_EXCLUDE)
                #   Aux data len  : 0
                #   Source count  : 0
                #   Multicast addr: ff02::1
                #
                #   Summary       : Change-to-exclude record transitioning group to exclude mode.
                b"\x04\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01"
            ),
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Multicast Address Record (Allow New Sources).",
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Record type   : 0x05 (ALLOW_NEW_SOURCES)
                #   Aux data len  : 0
                #   Source count  : 0
                #   Multicast addr: ff02::1
                #
                #   Summary       : Allow-new-sources record with no explicit source list.
                b"\x05\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01"
            ),
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.ALLOW_NEW_SOURCES,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": "ICMPv6 MLDv2 Multicast Address Record (Block Old Sources).",
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Record type   : 0x06 (BLOCK_OLD_SOURCES)
                #   Aux data len  : 0
                #   Source count  : 0
                #   Multicast addr: ff02::1
                #
                #   Summary       : Block-old-sources record without specific sources to block.
                b"\x06\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01"
            ),
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.BLOCK_OLD_SOURCES,
                    multicast_address=Ip6Address("ff02::1"),
                ),
            },
        },
        {
            "_description": ("ICMPv6 MLDv2 Multicast Address Record', multiple sources, no aux data."),
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Record type   : 0x01 (MODE_IS_INCLUDE)
                #   Aux data len  : 0
                #   Source count  : 3
                #   Multicast addr: ff02::1
                #   Sources       : 2001:db8::1, 2001:db8::2, 2001:db8::3
                #
                #   Summary       : Include-mode record listing three source addresses.
                b"\x01\x00\x00\x03\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x02\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x03"
            ),
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                    source_addresses=[
                        Ip6Address("2001:db8::1"),
                        Ip6Address("2001:db8::2"),
                        Ip6Address("2001:db8::3"),
                    ],
                ),
            },
        },
        {
            "_description": ("ICMPv6 'MLDv2 Multicast Address Record', no sources, aux data."),
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Record type   : 0x01 (MODE_IS_INCLUDE)
                #   Aux data len  : 4 (16 bytes)
                #   Source count  : 0
                #   Multicast addr: ff02::1
                #   Aux data      : "0123456789ABCDEF"
                #
                #   Summary       : Include-mode record carrying 16 bytes of auxiliary data.
                b"\x01\x04\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                b"\x43\x44\x45\x46"
            ),
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                    aux_data=b"0123456789ABCDEF",
                ),
            },
        },
        {
            "_description": ("ICMPv6 'MLDv2 Multicast Address Record', multiple sources, aux data."),
            "_frame_rx": (
                # MLDv2 Multicast Address Record
                #   Record type   : 0x01 (MODE_IS_INCLUDE)
                #   Aux data len  : 4 (16 bytes)
                #   Source count  : 3
                #   Multicast addr: ff02::1
                #   Sources       : 2001:db8::1, 2001:db8::2, 2001:db8::3
                #   Aux data      : "0123456789ABCDEF"
                #
                #   Summary       : Include-mode record with three sources and 16 bytes of aux data.
                b"\x01\x04\x00\x03\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x01\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x02\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x03\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42"
                b"\x43\x44\x45\x46"
            ),
            "_results": {
                "from_bytes": Icmp6Mld2MulticastAddressRecord(
                    type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                    multicast_address=Ip6Address("ff02::1"),
                    source_addresses=[
                        Ip6Address("2001:db8::1"),
                        Ip6Address("2001:db8::2"),
                        Ip6Address("2001:db8::3"),
                    ],
                    aux_data=b"0123456789ABCDEF",
                ),
            },
        },
    ]
)
class TestIcmp6Mld2MulticastAddressRecordParser(TestCase):
    """
    The ICMPv6 MLDv2 Multicast Address Record parser tests.
    """

    _description: str
    _frame_rx: bytes
    _results: dict[str, Any]

    def test__icmp6__mld2__multicast_address_record__parser__from_buffer(
        self,
    ) -> None:
        """
        Ensure the ICMPv6 MLDv2 Multicast Address Record method 'from_buffer()'
        creates a proper message object.
        """

        self.assertEqual(
            Icmp6Mld2MulticastAddressRecord.from_buffer(self._frame_rx + b"ZH0PA"),
            self._results["from_bytes"],
        )
