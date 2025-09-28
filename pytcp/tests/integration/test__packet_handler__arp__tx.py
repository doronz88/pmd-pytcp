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
This module contains unit tests for the Packet Handler ARP TX operations.

pytcp/tests/unit/test__packet_handle__arp__tx.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from net_proto import ArpOperation
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    MAC__BROADCAST,
    MAC__UNSPECIFIED,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
    NetworkTestCase,
)


@parameterized_class(
    [
        {
            "_description": "Ethernet/ARP - request",
            "_kwargs": {
                "ethernet__src": STACK__MAC_ADDRESS,
                "ethernet__dst": MAC__BROADCAST,
                "arp__oper": ArpOperation.REQUEST,
                "arp__sha": STACK__MAC_ADDRESS,
                "arp__spa": STACK__IP4_HOST.address,
                "arp__tha": MAC__UNSPECIFIED,
                "arp__tpa": HOST_A__IP4_ADDRESS,
            },
            "_expected__frames_tx": [
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x5b",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_request__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/ARP - reply",
            "_kwargs": {
                "ethernet__src": STACK__MAC_ADDRESS,
                "ethernet__dst": HOST_A__MAC_ADDRESS,
                "arp__oper": ArpOperation.REPLY,
                "arp__sha": STACK__MAC_ADDRESS,
                "arp__spa": STACK__IP4_HOST.address,
                "arp__tha": HOST_A__MAC_ADDRESS,
                "arp__tpa": HOST_A__IP4_ADDRESS,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                b"\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x5b",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_reply__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
            "_expected__error": None,
        },
    ]
)
class TestPacketHandlerArpTx(NetworkTestCase):
    """
    Test the Packet Handler ARP TX operations.
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__frames_tx: list[bytes] | None
    _expected__tx_status: TxStatus | None
    _expected__packet_stats_tx: PacketStatsTx | None
    _expected__error: Exception | None

    _frames_tx: list[bytes]

    def test__packet_handler__arp__tx(self) -> None:
        """
        Validate that sending ARP packet works as expected.
        """

        if self._expected__error is None:
            self.assertEqual(
                self._packet_handler._phtx_arp(**self._kwargs),
                self._expected__tx_status,
            )

            self.assertEqual(
                self._frames_tx,
                self._expected__frames_tx,
            )

            self.assertEqual(
                self._packet_handler.packet_stats_tx,
                self._expected__packet_stats_tx,
            )

        else:
            with self.assertRaises(type(self._expected__error)) as error:
                self._packet_handler._phtx_arp(**self._kwargs)

            self.assertEqual(str(error.exception), str(self._expected__error))
