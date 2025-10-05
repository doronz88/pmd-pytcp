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
This module contains tests for the ARP packet parser operation.

net_proto/tests/unit/protocols/arp/test__arp__parser__operation.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from net_addr import Ip4Address, MacAddress
from net_proto import ArpHeader, ArpOperation, ArpParser, PacketRx
from net_proto.tests.lib.testcase__packet_rx import TestCasePacketRx


@parameterized_class(
    [
        {
            "_description": "ARP Request.",
            "_args": [
                (
                    # ARP (Ethernet/IPv4)
                    #   Hardware type : 1 (Ethernet)
                    #   Protocol type : 0x0800 (IPv4)
                    #   HLEN / PLEN   : 6 / 4
                    #   Operation     : 1 (Request)
                    #   Sender MAC    : 02:00:00:00:00:91
                    #   Sender IP     : 10.0.1.91
                    #   Target MAC    : 00:00:00:00:00:07
                    #   Target IP     : 10.0.1.7
                    #
                    #   Summary       : Unicast ARP request — "Who has 10.0.1.7? Tell 10.0.1.91."
                    b"\x00\x01\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x0a\x00"
                    b"\x01\x5b\x00\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                ),
            ],
            "_kwargs": {},
            "_results": {
                "header": ArpHeader(
                    oper=ArpOperation.REQUEST,
                    sha=MacAddress("02:00:00:00:00:91"),
                    spa=Ip4Address("10.0.1.91"),
                    tha=MacAddress("00:00:00:00:00:07"),
                    tpa=Ip4Address("10.0.1.7"),
                ),
            },
        },
        {
            "_description": "ARP Reply.",
            "_args": [
                (
                    # ARP (Ethernet/IPv4)
                    #   Hardware type : 1 (Ethernet)
                    #   Protocol type : 0x0800 (IPv4)
                    #   HLEN / PLEN   : 6 / 4
                    #   Operation     : 2 (Reply)
                    #   Sender MAC    : 02:00:00:00:00:07
                    #   Sender IP     : 10.0.1.7
                    #   Target MAC    : 02:00:00:00:00:91
                    #   Target IP     : 10.0.1.91
                    #
                    #   Summary       : Unicast ARP reply — "10.0.1.7 is at 02:00:00:00:00:07."
                    b"\x00\x01\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x07\x0a\x00"
                    b"\x01\x07\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x5b"
                ),
            ],
            "_kwargs": {},
            "_results": {
                "header": ArpHeader(
                    oper=ArpOperation.REPLY,
                    sha=MacAddress("02:00:00:00:00:07"),
                    spa=Ip4Address("10.0.1.7"),
                    tha=MacAddress("02:00:00:00:00:91"),
                    tpa=Ip4Address("10.0.1.91"),
                ),
            },
        },
    ]
)
class TestArpHeaderParserOperation(TestCasePacketRx):
    """
    The ARP packet parser operation tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__arp__parser(self) -> None:
        """
        Ensure the ARP packet parser creates the proper header, options
        and payload objects and also updates the appropriate 'tx_packet'
        object fields.
        """

        arp_parser = ArpParser(self._packet_rx)

        self.assertEqual(
            arp_parser.header,
            self._results["header"],
        )

        self.assertIs(
            self._packet_rx.arp,
            arp_parser,
        )

        self.assertEqual(
            bytes(self._packet_rx.frame),
            b"",
        )
