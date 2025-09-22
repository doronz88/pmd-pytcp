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
This module contains unit tests for the Packet Handler Ethernet TX operations.

pytcp/tests/unit/test__packet_handler__ethernet__tx.py

ver 3.0.4
"""


from typing import Any, Callable

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__IP6_ADDRESS,
    HOST_A__MAC_ADDRESS,
    HOST_B__IP4_ADDRESS,
    HOST_B__IP6_ADDRESS,
    HOST_C__IP4_ADDRESS,
    HOST_C__IP6_ADDRESS,
    IP4__BROADCAST__LIMITED,
    IP4__MULTICAST__ALL_NODES,
    IP6__MULTICAST__ALL_NODES,
    MAC__UNSPECIFIED,
    STACK__IP4_GATEWAY,
    STACK__IP4_HOST,
    STACK__IP6_GATEWAY,
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
    NetworkTestCase,
)

# Due to heavy dependency of IPv4/IPv6 protocols on Ethernet mechanisms
# the Ethernet tests are mostly executed using IPv4/IPv6 packets.


@parameterized_class(
    [
        {
            "_description": "IPv4 packet to unicast address on local network",
            "_args": [],
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_A__IP4_ADDRESS,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x63\x8a\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "IPv4 packet to multicast address",
            "_args": [],
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": IP4__MULTICAST__ALL_NODES,
            },
            "_expected__frames_tx": [
                b"\x01\x00\x5e\x00\x00\x01\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x8e\xe3\x0a\x00\x01\x07\xe0\x00"
                b"\x00\x01",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__multicast__send=1,
            ),
        },
        {
            "_description": "IPv4 packet to limited broadcast address",
            "_args": [],
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": IP4__BROADCAST__LIMITED,
            },
            "_expected__frames_tx": [
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x6e\xe5\x0a\x00\x01\x07\xff\xff"
                b"\xff\xff",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__limited_broadcast__send=1,
            ),
        },
        {
            "_description": "IPv4 packet to local network broadcast address",
            "_args": [],
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": STACK__IP4_HOST.network.broadcast,
            },
            "_expected__frames_tx": [
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x62\xe6\x0a\x00\x01\x07\x0a\x00"
                b"\x01\xff",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__network_broadcast__send=1,
            ),
        },
        {
            "_description": "IPv4 packet to local network address",
            "_args": [],
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": STACK__IP4_HOST.network.address,
            },
            "_expected__frames_tx": [
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x63\xe5\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x00",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__network_broadcast__send=1,
            ),
        },
        {
            "_description": "IPv4 packet to unicast address on local network - ARP cache miss",
            "_args": [],
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_B__IP4_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPED__ETHERNET__DST_ARP_CACHE_MISS,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_miss__drop=1,
            ),
        },
        {
            "_description": "IPv4 packet to unicast address on external network",
            "_args": [],
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_C__IP4_ADDRESS,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x14\x00\x00\x00\x00\x40\xff\x62\xb3\x0a\x00\x01\x07\x0a\x00"
                b"\x02\x32",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__extnet__gw_arp_cache_hit__send=1,
            ),
        },
        {
            "_description": "IPv4 packet to unicast address on external network - no gateway",
            "_args": [],
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_C__IP4_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPED__ETHERNET__DST_NO_GATEWAY_IP4,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__extnet__no_gw__drop=1,
            ),
        },
        {
            "_description": "IPv4 packet to unicast address on external network - gateway ARP cache miss",
            "_args": [],
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_C__IP4_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPED__ETHERNET__DST_GATEWAY_ARP_CACHE_MISS,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__extnet__gw_arp_cache_miss__drop=1,
            ),
        },
        {
            "_description": "IPv6 packet to unicast address on local network",
            "_args": [],
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_A__IP6_ADDRESS,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\xff\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91",
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
        },
        {
            "_description": "IPv6 packet to multicast address",
            "_args": [],
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": IP6__MULTICAST__ALL_NODES,
            },
            "_expected__frames_tx": [
                b"\x33\x33\x00\x00\x00\x01\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\xff\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\xff\x01\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x01",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__multicast__send=1,
            ),
        },
        {
            "_description": "IPv6 packet to unicast address on local network - ND cache miss",
            "_args": [],
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_B__IP6_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPED__ETHERNET__DST_ND_CACHE_MISS,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_miss__drop=1,
            ),
        },
        {
            "_description": "IPv6 packet to unicast address on external network",
            "_args": [],
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_C__IP6_ADDRESS,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x00\xff\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x02\x00\x00"
                b"\x00\x00\x00\x00\x00\x50",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__extnet__gw_nd_cache_hit__send=1,
            ),
        },
        {
            "_description": "IPv6 packet to unicast address on external network - no gateway",
            "_args": [],
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_C__IP6_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPED__ETHERNET__DST_NO_GATEWAY_IP6,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__extnet__no_gw__drop=1,
            ),
        },
        {
            "_description": "IPv6 packet to unicast address on external network - gateway ND cache miss",
            "_args": [],
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_C__IP6_ADDRESS,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPED__ETHERNET__DST_GATEWAY_ND_CACHE_MISS,
            "_expected__packet_stats_tx": PacketStatsTx(
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__extnet__gw_nd_cache_miss__drop=1,
            ),
        },
        {
            "_description": "Ethernet packet with specified source MAC address",
            "_args": [],
            "_kwargs": {
                "ethernet__src": STACK__MAC_ADDRESS,
                "ethernet__dst": HOST_A__MAC_ADDRESS,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\xff\xff",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "Ethernet packet with unspecified source MAC address",
            "_args": [],
            "_kwargs": {
                "ethernet__src": MAC__UNSPECIFIED,
                "ethernet__dst": HOST_A__MAC_ADDRESS,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\xff\xff"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "Ethernet packet with unspecified destination MAC address",
            "_args": [],
            "_kwargs": {
                "ethernet__src": STACK__MAC_ADDRESS,
                "ethernet__dst": MAC__UNSPECIFIED,
            },
            "_expected__frames_tx": [],
            "_expected__tx_status": TxStatus.DROPED__ETHERNET__DST_RESOLUTION_FAIL,
            "_expected__packet_stats_tx": PacketStatsTx(
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_unspec__drop=1,
            ),
        },
    ]
)
class TestPacketHandlerEthernetTx(NetworkTestCase):
    """
    Test the Packet Handler Ethernet TX operations.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _expected__frames_tx: list[bytes]
    _expected__tx_status: TxStatus
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__packet_handler__ethernet__tx(self) -> None:
        """
        Validate that sending Ethernet packet works as expected.
        """

        STACK__IP4_HOST.gateway = STACK__IP4_GATEWAY
        STACK__IP6_HOST.gateway = STACK__IP6_GATEWAY

        if "no gateway" in self._description:
            STACK__IP4_HOST.gateway = None
            STACK__IP6_HOST.gateway = None

        if (
            "gateway ARP cache miss" in self._description
            or "gateway ND cache miss" in self._description
        ):
            STACK__IP4_HOST.gateway = HOST_B__IP4_ADDRESS
            STACK__IP6_HOST.gateway = HOST_B__IP6_ADDRESS

        tx_handler: Callable[..., TxStatus]

        if "IPv4" in self._description:
            tx_handler = self._packet_handler._phtx_ip4
        elif "IPv6" in self._description:
            tx_handler = self._packet_handler._phtx_ip6
        else:
            tx_handler = self._packet_handler._phtx_ethernet

        self.assertEqual(
            tx_handler(*self._args, **self._kwargs),
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
