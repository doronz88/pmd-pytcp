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
This module contains integration tests for the Packet Handler Ethernet 802.3 RX operations.

pytcp/tests/integration/test__packet_handler__ethernet_802_3__rx.py

ver 3.0.4
"""


from parameterized import parameterized_class  # type: ignore

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.tests.lib.network_testcase import NetworkTestCase


@parameterized_class(
    [
        {
            "_description": "Ethernet 802.3 - dst unknown",
            "_frames_rx": [
                # Ethernet 802.3
                #   Destination MAC : 02:00:00:99:99:99 (foreign)
                #   Source MAC      : 52:54:00:df:85:37
                #   Length          : 0x0000 (invalid/treated as LLC length)
                #
                # Summary: Frame addressed to an unknown MAC; stack drops before further processing.
                b"\x02\x00\x00\x99\x99\x99\x52\x54\x00\xdf\x85\x37\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet_802_3__pre_parse=1,
                ethernet_802_3__dst_unknown__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet 802.3 - malformed header",
            "_frames_rx": [
                # Ethernet 802.3
                #   Destination MAC : 02:00:00:77:77:77 (foreign)
                #   Source MAC      : 52:54:00:df:85:37
                #   Length          : <missing byte> (frame too short)
                #
                # Summary: Malformed Ethernet 802.3 header (length field truncated) triggers parse drop.
                b"\x02\x00\x00\x77\x77\x77\x52\x54\x00\xdf\x85\x37\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet_802_3__pre_parse=1,
                ethernet_802_3__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
    ]
)
class TestPacketHandlerEthernet8023Rx(NetworkTestCase):
    """
    Test the Packet Handler Ethernet 802.3 RX operations.
    """

    _description: str
    _frames_rx: list[bytes]
    _expected__frames_tx: list[bytes] | None
    _expected__packet_stats_rx: PacketStatsRx | None
    _expected__packet_stats_tx: PacketStatsTx | None

    _frames_tx: list[bytes]

    def test__packet_handler__ethernet_802_3__rx(self) -> None:
        """
        Validate that receiving Ethernet 802.3 packet works as expected.
        """

        for frame_rx in self._frames_rx:
            self._packet_handler._phrx_ethernet_802_3(PacketRx(frame_rx))

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
