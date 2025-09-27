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
This module contains unit tests for the Packet Handler Ethernet 802.3 RX operations.

pytcp/tests/unit/test__packet_handler__ethernet_802_3__rx.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.network_testcase import NetworkTestCase


@parameterized_class(
    [
        {
            "_description": "Ethernet 802.3 - dst unknown",
            "_args": [
                PacketRx(
                    b"\x02\x00\x00\x99\x99\x99\x52\x54\x00\xdf\x85\x37\x00\x00"
                ),
            ],
            "_kwargs": {},
            "_expected__frames_tx": [],
            "_expected__tx_status": None,
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet_802_3__pre_parse=1,
                ethernet_802_3__dst_unknown__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet 802.3 - malformed header",
            "_args": [
                PacketRx(
                    b"\x02\x00\x00\x77\x77\x77\x52\x54\x00\xdf\x85\x37\x00"
                ),
            ],
            "_kwargs": {},
            "_expected__frames_tx": [],
            "_expected__tx_status": None,
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet_802_3__pre_parse=1,
                ethernet_802_3__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
            "_expected__error": None,
        },
    ]
)
class TestPacketHandlerEthernet8023Rx(NetworkTestCase):
    """
    Test the Packet Handler Ethernet 802.3 RX operations.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _expected__frames_tx: list[bytes] | None
    _expected__tx_status: TxStatus | None
    _expected__packet_stats_rx: PacketStatsRx | None
    _expected__packet_stats_tx: PacketStatsTx | None
    _expected__error: Exception | None

    _frames_tx: list[bytes]

    def test__packet_handler__ethernet_802_3__rx(self) -> None:
        """
        Validate that receiving Ethernet 802.3 packet works as expected.
        """

        if self._expected__error is None:
            self._packet_handler._phrx_ethernet_802_3(
                *self._args, **self._kwargs
            )

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

        else:
            with self.assertRaises(type(self._expected__error)) as error:
                self._packet_handler._phrx_ethernet_802_3(
                    *self._args, **self._kwargs
                )

            self.assertEqual(str(error.exception), str(self._expected__error))
