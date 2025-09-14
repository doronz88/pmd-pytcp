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
Module contains tests for the DHCPv4 options support code (parsing only),
mirroring the style of the TCP options parsing tests.

net_proto/tests/unit/protocols/dhcp4/test__dhcp4__options.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore
from testslide import TestCase

from net_addr.ip4_address import Ip4Address
from net_addr.ip4_mask import Ip4Mask
from net_proto import (
    Dhcp4MessageType,
    Dhcp4OptionClientId,
    Dhcp4OptionEnd,
    Dhcp4OptionHostName,
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
)


@parameterized_class(
    [
        {
            "_description": "The DHCPv4 options (I) — single option + End.",
            "_args": [
                b"\x35\x01\x01"  # message_type=DISCOVER
                b"\xff"  # End
            ],
            "_kwargs": {},
            "_results": {
                "options": Dhcp4Options(
                    Dhcp4OptionMessageType(Dhcp4MessageType.DISCOVER),
                    Dhcp4OptionEnd(),
                ),
            },
        },
        {
            "_description": "The DHCPv4 options (II) — rich mix, pads, trailing data.",
            "_args": [
                b"\x01\x04\xff\xff\xff\x00"  # subnet_mask 255.255.255.0
                b"\x03\x08\xc0\x00\x02\x01\xc6\x33\x64\x05"  # router 192.0.2.1, 198.51.100.5
                b"\x36\x04\xc0\x00\x02\x01"  # server_id 192.0.2.1
                b"\x33\x04\x00\x00\x00\x3c"  # lease_time 60
                b"\x3d\x07\x01\xde\xad\xbe\xef\x00\x01"  # client_id 01:de:ad:be:ef:00:01
                b"\x00\x00"  # Pad, Pad
                b"\x0c\x04\x68\x6f\x73\x74"  # host_name "host"
                b"\x32\x04\x01\x02\x03\x04"  # req_ip_addr 1.2.3.4
                b"\x37\x02\x0c\x35"  # param_req_list [HOST_NAME, MESSAGE_TYPE]
                b"\x35\x01\x03"  # message_type=REQUEST
                b"\xff"  # End
                b"\x00\x00\x00",  # bytes after End ignored
            ],
            "_kwargs": {},
            "_results": {
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
                    Dhcp4OptionHostName("host"),
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
            "_description": "The DHCPv4 options (III) — only End.",
            "_args": [
                b"\xff",
            ],
            "_kwargs": {},
            "_results": {
                "options": Dhcp4Options(
                    Dhcp4OptionEnd(),
                ),
            },
        },
        {
            "_description": "The DHCPv4 options (IV) — options behind End are ignored.",
            "_args": [
                b"\x36\x04\xc0\x00\x02\x01"  # server_id 192.0.2.1
                b"\xff"  # End
                b"\x01\x04\xff\xff\xff\x00",  # subnet_mask (ignored)
            ],
            "_kwargs": {},
            "_results": {
                "options": Dhcp4Options(
                    Dhcp4OptionServerId(Ip4Address("192.0.2.1")),
                    Dhcp4OptionEnd(),
                ),
            },
        },
        {
            "_description": "The DHCPv4 options (V) — empty/zero-length valued options allowed.",
            "_args": [
                b"\x3d\x00"  # client_id empty
                b"\x0c\x00"  # host_name empty
                b"\xff",
            ],
            "_kwargs": {},
            "_results": {
                "options": Dhcp4Options(
                    Dhcp4OptionClientId(b""),
                    Dhcp4OptionHostName(""),
                    Dhcp4OptionEnd(),
                ),
            },
        },
    ]
)
class TestDhcp4OptionsParser(TestCase):
    """
    The 'Dhcp4Options' class parser tests (analogous to TCP options).
    """

    _description: str
    _args: Any
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__dhcp4__options__from_buffer(self) -> None:
        """
        Ensure the 'Dhcp4Options' class parser creates the proper options object.
        """

        dhcp4_options = Dhcp4Options.from_buffer(*self._args, **self._kwargs)

        self.assertEqual(
            dhcp4_options,
            self._results["options"],
        )
