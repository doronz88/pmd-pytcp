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
This module contains integration tests for the Packet Handler Ethernet RX operations.

pytcp/tests/integration/test__packet_handler__ethernet__rx.py

ver 3.0.4
"""


from parameterized import parameterized_class  # type: ignore

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.tests.lib.network_testcase import NetworkTestCase


@parameterized_class(
    [
        {
            "_description": "Ethernet - dst unknown",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:99:99:99 (not in our table)
                #   Source MAC      : 52:54:00:df:85:37
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 14 bytes
                #
                # Summary: IPv4 frame to an unknown unicast MAC; the Ethernet layer drops it.
                b"\x02\x00\x00\x99\x99\x99\x52\x54\x00\xdf\x85\x37\x08\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unknown__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet - malformed header",
            "_frames_rx": [
                # Ethernet II (truncated)
                #   Destination MAC : 02:00:00:77:77:77
                #   Source MAC      : 52:54:00:df:85:37
                #   Captured length : 13 bytes (shorter than mandatory 14-byte header)
                #
                # Summary: Short Ethernet header without an Ethertype field; parsing fails.
                b"\x02\x00\x00\x77\x77\x77\x52\x54\x00\xdf\x85\x37\x0a",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
    ]
)
class TestPacketHandlerEthernetRx(NetworkTestCase):
    """
    Test the Packet Handler Ethernet RX operations.
    """

    _description: str
    _frames_rx: list[bytes]
    _expected__frames_tx: list[bytes] | None
    _expected__packet_stats_rx: PacketStatsRx | None
    _expected__packet_stats_tx: PacketStatsTx | None

    _frames_tx: list[bytes]

    def test__packet_handler__ethernet__rx(self) -> None:
        """
        Ensure the Packet Handler processes the received Ethernet
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
