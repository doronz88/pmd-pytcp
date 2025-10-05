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
This module contains unit tests for the Packet Handler IPv6 TX operations.

pytcp/tests/unit/test__packet_handler__ip6__tx.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP6_ADDRESS,
    HOST_B__IP6_ADDRESS,
    HOST_C__IP6_ADDRESS,
    IP6__MULTICAST__ALL_NODES,
    IP6__UNSPECIFIED,
    STACK__IP6_HOST,
    NetworkTestCase,
)


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv6 - src valid, dst unicast local network",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_A__IP6_ADDRESS,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\xff\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv6 - src not owned drop, dst unicast local network",
            "_kwargs": {
                "ip6__src": HOST_B__IP6_ADDRESS,
                "ip6__dst": HOST_A__IP6_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPED__IP6__SRC_NOT_OWNED,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__src_not_owned__drop=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv6 - src multicast replace, dst unicast local network",
            "_kwargs": {
                "ip6__src": IP6__MULTICAST__ALL_NODES,
                "ip6__dst": HOST_A__IP6_ADDRESS,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\xff\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__src_multicast__replace=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv6 - src multicast drop, dst unicast local network",
            "_kwargs": {
                "ip6__src": IP6__MULTICAST__ALL_NODES,
                "ip6__dst": HOST_A__IP6_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPED__IP6__SRC_MULTICAST,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__src_multicast__drop=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv6 - src unspecified replace, dst unicast local network",
            "_kwargs": {
                "ip6__src": IP6__UNSPECIFIED,
                "ip6__dst": HOST_A__IP6_ADDRESS,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\xff\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__src_network_unspecified__replace_local=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv6 - src unspecified replace, dst unicast external network",
            "_kwargs": {
                "ip6__src": IP6__UNSPECIFIED,
                "ip6__dst": HOST_C__IP6_ADDRESS,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\xff\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x02\x00\x00"
                b"\x00\x00\x00\x00\x00\x50"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__src_network_unspecified__replace_external=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__extnet__gw_nd_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv6 - src unspecified drop, dst unicast local network",
            "_kwargs": {
                "ip6__src": IP6__UNSPECIFIED,
                "ip6__dst": HOST_A__IP6_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPED__IP6__SRC_UNSPECIFIED,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__src_unspecified__drop=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv6 - src valid, dst unspecified drop",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": IP6__UNSPECIFIED,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPED__IP6__DST_UNSPECIFIED,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__dst_unspecified__drop=1,
            ),
            "_expected__error": None,
        },
    ]
)
class TestPacketHandlerIp6Tx(NetworkTestCase):
    """
    Test the Packet Handler IPv6 TX operations.
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__frames_tx: list[bytes] | None
    _expected__tx_status: TxStatus | None
    _expected__packet_stats_tx: PacketStatsTx | None
    _expected__error: Exception | None

    _frames_tx: list[bytes]

    def test__packet_handler__ip6__tx(self) -> None:
        """
        Validate that sending IPv6 packet works as expected.
        """

        if any(
            pattern in self._description
            for pattern in (
                "src multicast drop",
                "src limited broadcast drop",
                "src unspecified drop",
            )
        ):
            self._packet_handler._ip6_host = []

        if self._expected__error is None:
            self.assertEqual(
                self._packet_handler._phtx_ip6(**self._kwargs),
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
                self._packet_handler._phtx_ip6(**self._kwargs)

            self.assertEqual(str(error.exception), str(self._expected__error))
