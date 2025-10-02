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
This module contains tests for the ARP packet sanity checks.

net_addr/tests/unit/protocols/arp/test__arp__parser__sanity_checks.py

ver 3.0.4
"""


from typing import Any, cast

from parameterized import parameterized_class  # type: ignore

from net_addr.mac_address import MacAddress
from net_proto import ArpParser, ArpSanityError, PacketRx
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from net_proto.tests.lib.testcase__packet_rx import TestCasePacketRx


@parameterized_class(
    [
        {
            "_description": "The value of the 'prlen' field is incorrect.",
            "_args": [
                b"\x00\x01\x08\x00\x06\x04\x00\x00\x02\x00\x00\x00\x00\x91\x0a\x00"
                b"\x01\x5b\x00\x00\x00\x00\x00\x07\x0a\x00\x01\x07",
            ],
            "_kwargs": {},
            "_results": {
                "error_message": "The 'oper' field value must be one of [1, 2], got 0.",
            },
        },
        {
            "_description": "The SHA address is unspecified.",
            "_args": [
                b"\x00\x01\x08\x00\x06\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07",
            ],
            "_kwargs": {},
            "_results": {
                "error_message": "The 'sha' field value 00:00:00:00:00:00 must not be a "
                "unspecified MAC address."
            },
        },
        {
            "_description": "The SHA address is multicast.",
            "_args": [
                b"\x00\x01\x08\x00\x06\x04\x00\x01\x01\x00\x5e\x00\x00\x01\x0a\x00"
                b"\x01\x5b\x00\x00\x00\x00\x00\x07\x0a\x00\x01\x07",
            ],
            "_kwargs": {},
            "_results": {
                "error_message": "The 'sha' field value 01:00:5e:00:00:01 must not be a "
                "multicast MAC address."
            },
        },
        {
            "_description": "The SHA address is broadcast.",
            "_args": [
                b"\x00\x01\x08\x00\x06\x04\x00\x01\xff\xff\xff\xff\xff\xff\x0a\x00"
                b"\x01\x5b\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07",
            ],
            "_kwargs": {},
            "_results": {
                "error_message": "The 'sha' field value ff:ff:ff:ff:ff:ff must not be a "
                "broadcast MAC address."
            },
        },
        {
            "_description": "The SHA address doesn't match the Ethernet source address.",
            "_args": [
                b"\x00\x01\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x91\x0a\x00"
                b"\x01\x5b\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07",
            ],
            "_kwargs": {},
            "_results": {
                "error_message": "The 'sha' field value 02:00:00:00:00:91 does not match the "
                "Ethernet frame 'src' field value 02:00:00:00:00:07."
            },
        },
    ]
)
class TestArpParserSanityChecks(TestCasePacketRx):
    """
    The ARP packet parser sanity checks tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    _packet_rx: PacketRx

    def test__arp__parser(self) -> None:
        """
        Ensure the ARP packet parser raises sanity errors on crazy packets.
        """

        if "Ethernet source address." in self._description:
            self._packet_rx.ethernet = cast(
                EthernetParser,
                EthernetAssembler(
                    ethernet__src=MacAddress("02:00:00:00:00:07"),
                ),
            )

        with self.assertRaises(ArpSanityError) as error:
            ArpParser(self._packet_rx)

        self.assertEqual(
            str(error.exception),
            f"[SANITY ERROR][ARP] {self._results["error_message"]}",
        )
