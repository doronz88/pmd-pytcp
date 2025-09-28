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
This module contains unit tests for the Packet Handler ICMPv4 RX operations.

pytcp/tests/unit/test__packet_handler__icmp4__rx.py

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
            "_description": "Ethernet/IPv4/ICMPv4 Echo Request",
            "_args": [
                PacketRx(
                    b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00\x45\x00"
                    b"\x00\x5c\x3a\x2f\x40\x00\x40\x01\xea\x10\x0a\x00\x01\x5b\x0a\x00"
                    b"\x01\x07\x08\x00\xd9\x7d\x00\x07\x00\x0a\x88\x9f\xba\x60\x00\x00"
                    b"\x00\x00\x29\xad\x06\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15"
                    b"\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25"
                    b"\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35"
                    b"\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
                ),
            ],
            "_kwargs": {},
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x5c\x00\x00\x00\x00\x40\x01\x64\x40\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x00\x00\xe1\x7d\x00\x07\x00\x0a\x88\x9f\xba\x60\x00\x00"
                b"\x00\x00\x29\xad\x06\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15"
                b"\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25"
                b"\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip4__pre_parse=1,
                ip4__dst_unicast=1,
                icmp4__pre_parse=1,
                icmp4__echo_request__respond_echo_reply=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp4__pre_assemble=1,
                icmp4__echo_reply__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
    ]
)
class TestPacketHandlerIcmp4Rx(NetworkTestCase):
    """
    Test the Packet Handler ICMPv4 RX operations.
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

    def test__packet_handler__icmp4__rx(self) -> None:
        """
        Validate that receiving ICMPv4 packet works as expected.
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
