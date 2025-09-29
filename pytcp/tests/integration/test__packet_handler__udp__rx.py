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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
This module contains unit tests for the Packet Handler UDP RX operations.

pytcp/tests/unit/test__packet_handler__udp__rx.py

ver 3.0.4
"""


from parameterized import parameterized_class  # type: ignore

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.tests.lib.network_testcase import NetworkTestCase


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv4/UDP to closed port",
            "_frames_rx": [
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x3f\x00\x01\x00\x00\x40\x11\x64\x4c\x0a\x00\x01\x5b\x0a\x00"
                b"\x01\x07\x03\xe8\x07\xd0\x00\x2b\xa2\x10\x54\x65\x73\x74\x20\x55"
                b"\x44\x50\x20\x70\x61\x63\x6b\x65\x74\x20\x73\x65\x6e\x74\x20\x74"
                b"\x6f\x20\x63\x6c\x6f\x73\x65\x64\x20\x70\x6f\x72\x74",
            ],
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x5b\x00\x00\x00\x00\x40\x01\x64\x41\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\x03\x13\x9b\x00\x00\x00\x00\x45\x00\x00\x3f\x00\x01"
                b"\x00\x00\x40\x11\x64\x4c\x0a\x00\x01\x5b\x0a\x00\x01\x07\x03\xe8"
                b"\x07\xd0\x00\x2b\xa2\x10\x54\x65\x73\x74\x20\x55\x44\x50\x20\x70"
                b"\x61\x63\x6b\x65\x74\x20\x73\x65\x6e\x74\x20\x74\x6f\x20\x63\x6c"
                b"\x6f\x73\x65\x64\x20\x70\x6f\x72\x74",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                udp__pre_parse=1,
                udp__no_socket_match__respond_icmp4_unreachable=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp4__pre_assemble=1,
                icmp4__destination_unreachable__port__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/UDP to closed port",
            "_frames_rx": [
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x2b\x11\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x03\xe8\x07\xd0\x00\x2b\x5c\x66\x54\x65"
                b"\x73\x74\x20\x55\x44\x50\x20\x70\x61\x63\x6b\x65\x74\x20\x73\x65"
                b"\x6e\x74\x20\x74\x6f\x20\x63\x6c\x6f\x73\x65\x64\x20\x70\x6f\x72"
                b"\x74",
            ],
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x5b\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x01\x04\x31\x2b\x00\x00\x00\x00\x60\x00"
                b"\x00\x00\x00\x2b\x11\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x03\xe8\x07\xd0\x00\x2b\x5c\x66\x54\x65"
                b"\x73\x74\x20\x55\x44\x50\x20\x70\x61\x63\x6b\x65\x74\x20\x73\x65"
                b"\x6e\x74\x20\x74\x6f\x20\x63\x6c\x6f\x73\x65\x64\x20\x70\x6f\x72"
                b"\x74",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                udp__pre_parse=1,
                udp__no_socket_match__respond_icmp6_unreachable=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__destination_unreachable__port__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv4/UDP Echo",
            "_frames_rx": [
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                b"\x00\x27\x00\x01\x00\x00\x40\x11\x64\x64\x0a\x00\x01\x5b\x0a\x00"
                b"\x01\x07\x15\x97\x00\x07\x00\x13\x81\x3f\x54\x6f\x6d\x20\x54\x69"
                b"\x74\x20\x54\x6f\x74",
            ],
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x27\x00\x00\x00\x00\x40\x11\x64\x65\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x00\x07\x15\x97\x00\x13\x81\x3f\x54\x6f\x6d\x20\x54\x69"
                b"\x74\x20\x54\x6f\x74",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                udp__pre_parse=1,
                udp__echo_native__respond_udp=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                udp__pre_assemble=1,
                udp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "Ethernet/IPv6/UDP Echo",
            "_frames_rx": [
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x13\x11\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x15\x97\x00\x07\x00\x13\x3b\x95\x54\x6f"
                b"\x6d\x20\x54\x69\x74\x20\x54\x6f\x74",
            ],
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x13\x11\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x00\x07\x15\x97\x00\x13\x3b\x95\x54\x6f"
                b"\x6d\x20\x54\x69\x74\x20\x54\x6f\x74",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                udp__pre_parse=1,
                udp__echo_native__respond_udp=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                udp__pre_assemble=1,
                udp__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
    ]
)
class TestPacketHandlerUdpRx(NetworkTestCase):
    """
    Test the Packet Handler UDP RX operations.
    """

    _description: str
    _frames_rx: list[bytes]
    _expected__frames_tx: list[bytes] | None
    _expected__packet_stats_rx: PacketStatsRx | None
    _expected__packet_stats_tx: PacketStatsTx | None

    _frames_tx: list[bytes]

    def test__packet_handler__udp__rx(self) -> None:
        """
        Validate that receiving UDP packet works as expected.
        """

        for frame_rx in self._frames_rx:
            self._packet_handler._phrx_ethernet(PacketRx(frame_rx))

        self.assertEqual(
            self._frames_tx,
            self._expected__frames_tx,
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx,
            self._expected__packet_stats_rx,
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            self._expected__packet_stats_tx,
        )
