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
##   GNU General Public License for more details.                              ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains the DHCPv4 packet parser operation tests.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__parser__operation.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_addr.ip4_address import Ip4Address
from net_addr.ip4_mask import Ip4Mask
from net_proto import (
    DHCP4__HEADER__LEN,
    Dhcp4Header,
    Dhcp4MessageType,
    Dhcp4OptionClientId,
    Dhcp4OptionEnd,
    Dhcp4OptionLeaseTime,
    Dhcp4OptionMessageType,
    Dhcp4OptionPad,
    Dhcp4OptionParamReqList,
    Dhcp4OptionReqIpAddr,
    Dhcp4OptionRouter,
    Dhcp4Options,
    Dhcp4OptionServerId,
    Dhcp4OptionSubnetMask,
    Dhcp4OptionType,
    Dhcp4Parser,
)


def _dhcp4_header(
    *,
    op: int = 0x01,  # BOOTREQUEST
    htype: int = 0x01,  # Ethernet
    hlen: int = 0x06,  # MAC length
    hops: int = 0x00,
    xid: bytes = b"\x12\x34\x56\x78",
    secs: bytes = b"\x00\x00",
    flags: bytes = b"\x00\x00",
    ciaddr: bytes = b"\x00\x00\x00\x00",
    yiaddr: bytes = b"\x00\x00\x00\x00",
    siaddr: bytes = b"\x00\x00\x00\x00",
    giaddr: bytes = b"\x00\x00\x00\x00",
    chaddr_mac: bytes = b"\x00\x11\x22\x33\x44\x55",
) -> bytes:
    """
    Build a DHCPv4 header (including BOOTP 236 bytes + DHCP magic cookie).
    """

    assert len(chaddr_mac) == 6
    chaddr = chaddr_mac + b"\x00" * (16 - 6)

    sname = b"\x00" * 64
    file_ = b"\x00" * 128
    cookie = b"\x63\x82\x53\x63"  # 99,130,83,99

    header = bytes([op, htype, hlen, hops]) + xid + secs + flags
    header += ciaddr + yiaddr + siaddr + giaddr
    header += chaddr + sname + file_ + cookie

    assert (
        len(header) == DHCP4__HEADER__LEN
    ), f"Got header len {len(header)}, expected {DHCP4__HEADER__LEN}"

    return header


DHCP4_HEADER = _dhcp4_header()


testcases: list[dict[str, Any]] = [
    {
        "_description": "DHCPv4 packet with only Message Type (DISCOVER) and End.",
        "_args": [
            memoryview(
                DHCP4_HEADER
                + b"\x35\x01\x01"  # message_type = DISCOVER
                + b"\xff"  # End
            ),
        ],
        "_kwargs": {},
        "_results": {
            "header_bytes": DHCP4_HEADER,
            "options": Dhcp4Options(
                Dhcp4OptionMessageType(Dhcp4MessageType.DISCOVER),
                Dhcp4OptionEnd(),
            ),
        },
    },
    {
        "_description": "DHCPv4 packet with a rich mix of options, pads, trailing ignored bytes (no HostName).",
        "_args": [
            memoryview(
                DHCP4_HEADER
                + (
                    b"\x01\x04\xff\xff\xff\x00"  # subnet_mask 255.255.255.0
                    b"\x03\x08\xc0\x00\x02\x01\xc6\x33\x64\x05"  # router 192.0.2.1, 198.51.100.5
                    b"\x36\x04\xc0\x00\x02\x01"  # server_id 192.0.2.1
                    b"\x33\x04\x00\x00\x00\x3c"  # lease_time 60
                    b"\x3d\x07\x01\xde\xad\xbe\xef\x00\x01"  # client_id 01:de:ad:be:ef:00:01
                    b"\x00\x00"  # Pad, Pad
                    b"\x32\x04\x01\x02\x03\x04"  # req_ip_addr 1.2.3.4
                    b"\x37\x02\x0c\x35"  # param_req_list [HOST_NAME, MESSAGE_TYPE]
                    b"\x35\x01\x03"  # message_type = REQUEST
                    b"\xff"  # End
                    b"\x00\x00\x00"  # ignored
                )
            )
        ],
        "_kwargs": {},
        "_results": {
            "header_bytes": DHCP4_HEADER,
            "options": Dhcp4Options(
                Dhcp4OptionSubnetMask(Ip4Mask("255.255.255.0")),
                Dhcp4OptionRouter(
                    [
                        Ip4Address("192.0.2.1"),
                        Ip4Address("198.51.100.5"),
                    ]
                ),
                Dhcp4OptionServerId(Ip4Address("192.0.2.1")),
                Dhcp4OptionLeaseTime(60),
                Dhcp4OptionClientId(b"\x01\xde\xad\xbe\xef\x00\x01"),
                Dhcp4OptionPad(),
                Dhcp4OptionPad(),
                Dhcp4OptionReqIpAddr(Ip4Address("1.2.3.4")),
                Dhcp4OptionParamReqList(
                    [
                        Dhcp4OptionType.HOST_NAME,
                        Dhcp4OptionType.MESSAGE_TYPE,
                    ]
                ),
                Dhcp4OptionMessageType(Dhcp4MessageType.REQUEST),
                Dhcp4OptionEnd(),
            ),
        },
    },
    {
        "_description": "DHCPv4 packet with empty ClientId (no HostName).",
        "_args": [
            memoryview(
                DHCP4_HEADER
                + (
                    b"\x3d\x00"  # client_id empty
                    b"\xff"  # End
                )
            )
        ],
        "_kwargs": {},
        "_results": {
            "header_bytes": DHCP4_HEADER,
            "options": Dhcp4Options(
                Dhcp4OptionClientId(b""),
                Dhcp4OptionEnd(),
            ),
        },
    },
]


@parameterized_class(testcases)
class TestDhcp4ParserOperation(TestCase):
    """
    The DHCPv4 packet parser operation tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__dhcp4__parser__from_bytes(self) -> None:
        """
        Ensure the DHCPv4 packet parser creates the proper header and options objects.
        """

        dhcp_parser = Dhcp4Parser(*self._args, **self._kwargs)

        expected_header = Dhcp4Header.from_bytes(
            memoryview(self._results["header_bytes"])
        )

        self.assertEqual(
            dhcp_parser.header,
            expected_header,
        )

        self.assertEqual(
            dhcp_parser.options,
            self._results["options"],
        )
