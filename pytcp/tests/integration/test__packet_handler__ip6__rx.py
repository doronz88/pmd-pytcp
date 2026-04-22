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
This module contains integration tests for the Packet Handler IPv6 RX operations.

pytcp/tests/integration/test__packet_handler__ip6__rx.py

ver 3.0.4
"""


from parameterized import parameterized_class  # type: ignore

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.tests.lib.network_testcase import NetworkTestCase


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv6 - dst unknown",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07 (our MAC)
                #   Source MAC      : 52:54:00:df:85:37
                #   Ethertype       : 0x86dd (IPv6)
                #   Frame length    : 54 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 6 / 0x00 / 0x00000
                #   Payload Length : 0 bytes
                #   Next Header    : 59 (No Next Header)
                #   Hop Limit      : 64
                #   Source IP      : 2603:9000:e307:9f09::1fa1
                #   Destination IP : 2603:9000:e307:9f09:0:ff:fe55:5555 (unknown)
                #
                # Summary: IPv6 datagram targeting an address the stack does not own; expect a drop.
                b"\x02\x00\x00\x00\x00\x07\x52\x54\x00\xdf\x85\x37\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\x3b\x40\x26\x03\x90\x00\xe3\x07\x9f\x09\x00\x00"
                b"\x00\x00\x00\x00\x1f\xa1\x26\x03\x90\x00\xe3\x07\x9f\x09\x00\x00"
                b"\x00\xff\xfe\x55\x55\x55"
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unknown__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/IPv6 - malformed IPv6 (truncated below header length), failed parse drop",
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91, type=0x86dd
                # IPv6: header truncated to 39 bytes (one byte short of the 40-byte minimum).
                #
                # Summary: Truncated IPv6 frame triggers Ip6Parser to raise; bumps
                #          'ip6__failed_parse__drop' and skips dst classification entirely.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\x3b\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/IPv6 - dst is our unicast, unsupported next header (99), drop",
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91, type=0x86dd
                # IPv6: src=2001:db8:0:1::91, dst=2001:db8:0:1::7 (us), next=99, plen=4
                #
                # Summary: Bumps 'ip6__dst_unicast' (classifier) and 'ip6__no_proto_support__drop'
                #          (default match arm).
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x04\x63\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                ip6__no_proto_support__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": ("Ethernet/IPv6 - dst is our solicited-node multicast, unsupported next header (99), drop"),
            "_frames_rx": [
                # Ethernet II: dst=33:33:ff:00:00:07 (solicited-node MAC for ::7), src=02:00:00:00:00:91
                # IPv6: src=2001:db8:0:1::91, dst=ff02::1:ff00:7 (solicited-node multicast for ::7), next=99
                #
                # Summary: Bumps 'ip6__dst_multicast' (classifier) and 'ip6__no_proto_support__drop'.
                b"\x33\x33\xff\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x04\x63\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x01\xff\x00\x00\x07\x00\x00\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_multicast=1,
                ip6__pre_parse=1,
                ip6__dst_multicast=1,
                ip6__no_proto_support__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
    ]
)
class TestPacketHandlerIp6Rx(NetworkTestCase):
    """
    Test the Packet Handler IPv6 RX operations.
    """

    _description: str
    _frames_rx: list[bytes]
    _expected__frames_tx: list[bytes]
    _expected__packet_stats_rx: PacketStatsRx
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__packet_handler__ip6__rx(self) -> None:
        """
        Ensure the Packet Handler processes the received IPv6
        frames as expected for each parametrized case.
        """

        for frame_rx in self._frames_rx:
            self._packet_handler._phrx_ethernet(PacketRx(frame_rx))

        self.assertEqual(
            self._frames_tx,
            self._expected__frames_tx,
            msg=f"Unexpected TX frames for case: {self._description}",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx,
            self._expected__packet_stats_rx,
            msg=f"Unexpected RX packet stats for case: {self._description}",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            self._expected__packet_stats_tx,
            msg=f"Unexpected TX packet stats for case: {self._description}",
        )
