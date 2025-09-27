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
This module contains unit tests for the Packet Handler ARP RX operations.

pytcp/tests/unit/test__packet_handler__arp__rx.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.packet_stats import PacketStatsTx, PacketStatsRx
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.network_testcase import NetworkTestCase


@parameterized_class(
    [
        {
            "_description": "Ethernet/ARP - request, unknown TPA, drop",
            "_args": [
                PacketRx(
                    b"\xff\xff\xff\xff\xff\xff\x52\x54\x00\xdf\x85\x37\x08\x06\x00\x01"
                    b"\x08\x00\x06\x04\x00\x01\x52\x54\x00\xdf\x85\x37\xc0\xa8\x09\x66"
                    b"\x00\x00\x00\x00\x00\x00\xc0\xa8\x09\x37",
                ),
            ],
            "_kwargs": {},
            "_expected__frames_tx": [],
            "_expected__tx_status": None,
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__tpa_unknown__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
            "_expected__error": None,
        },
    ]
)
class TestPacketHandlerArpRx(NetworkTestCase):
    """
    Test the Packet Handler ARP RX operations.
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

    def test__packet_handler__arp__rx(self) -> None:
        """
        Validate that receiving ARP packet works as expected.
        """

        if self._expected__error is None:
            self._packet_handler._phrx_ethernet(*self._args, **self._kwargs)

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
                self._packet_handler._phrx_ethernet(*self._args, **self._kwargs)

            self.assertEqual(str(error.exception), str(self._expected__error))
