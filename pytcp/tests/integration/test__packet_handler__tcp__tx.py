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
This module contains unit tests for the Packet Handler TCP TX operations.

pytcp/tests/unit/test__packet_handler__tcp__tx.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__IP6_ADDRESS,
    STACK__IP4_HOST,
    STACK__IP6_HOST,
    NetworkTestCase,
)


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv4/TCP - no payload",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x00\x00\x40\x06\x64\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x00"
                b"\x00\x00\x8d\xcb\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - seq",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__seq": 12345,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x00\x00\x40\x06\x64\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x30\x39\x00\x00\x00\x00\x50\x00"
                b"\x00\x00\x5d\x92\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - ack",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__ack": 12345,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x00\x00\x40\x06\x64\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x30\x39\x50\x00"
                b"\x00\x00\x5d\x92\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag ns",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_ns": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x00\x00\x40\x06\x64\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x51\x00"
                b"\x00\x00\x8c\xcb\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ns=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag cwr",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_cwr": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x00\x00\x40\x06\x64\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x80"
                b"\x00\x00\x8d\x4b\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_cwr=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag ece",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_ece": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x00\x00\x40\x06\x64\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x40"
                b"\x00\x00\x8d\x8b\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ece=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag urg",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_urg": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x00\x00\x40\x06\x64\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x20"
                b"\x00\x00\x8d\xab\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_urg=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag ack",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_ack": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x00\x00\x40\x06\x64\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x10"
                b"\x00\x00\x8d\xbb\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ack=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag psh",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_psh": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x00\x00\x40\x06\x64\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x08"
                b"\x00\x00\x8d\xc3\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_psh=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag rst",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_rst": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x00\x00\x40\x06\x64\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x04"
                b"\x00\x00\x8d\xc7\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_rst=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag syn",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_syn": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x00\x00\x40\x06\x64\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02"
                b"\x00\x00\x8d\xc9\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_syn=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - flag fin",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_fin": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x00\x00\x40\x06\x64\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x01"
                b"\x00\x00\x8d\xca\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_fin=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - win",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__win": 12345,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x00\x00\x40\x06\x64\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x00"
                b"\x30\x39\x5d\x92\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - urg",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__urg": 12345,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x28\x00\x00\x00\x00\x40\x06\x64\x6f\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x00"
                b"\x00\x00\x5d\x92\x30\x39"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - data",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__payload": b"01234567890ABCDEF" * 50,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x03\x7a\x00\x00\x00\x00\x40\x06\x61\x1d\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x50\x00"
                b"\x00\x00\xa8\x97\x00\x00\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - option mss",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__mss": 12345,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x2c\x00\x00\x00\x00\x40\x06\x64\x6b\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x60\x00"
                b"\x00\x00\x4b\x8a\x00\x00\x02\x04\x30\x39"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__opt_mss=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv4/TCP - option wscale",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__wscale": 14,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x00\x2c\x00\x00\x00\x00\x40\x06\x64\x6b\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00\x00\x00\x60\x00"
                b"\x00\x00\x79\xb6\x00\x00\x01\x03\x03\x0e"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__opt_wscale=1,
                tcp__opt_nop=1,
                tcp__send=1,
                ip4__pre_assemble=1,
                ip4__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip4_lookup=1,
                ethernet__dst_unspec__ip4_lookup__locnet__arp_cache_hit__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv6/TCP - no payload",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x00\x00\x00\x48\x21\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - seq",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__seq": 12345,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x30\x39\x00\x00"
                b"\x00\x00\x50\x00\x00\x00\x17\xe8\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - ack",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__ack": 12345,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x30\x39\x50\x00\x00\x00\x17\xe8\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - flag ns",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_ns": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x51\x00\x00\x00\x47\x21\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ns=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - flag cwr",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_cwr": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x80\x00\x00\x47\xa1\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_cwr=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - flag ece",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_ece": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x40\x00\x00\x47\xe1\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ece=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - flag urg",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_urg": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x20\x00\x00\x48\x01\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_urg=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - flag ack",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_ack": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x10\x00\x00\x48\x11\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_ack=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - flag psh",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_psh": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x08\x00\x00\x48\x19\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_psh=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - flag rst",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_rst": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x04\x00\x00\x48\x1d\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_rst=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - flag syn",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_syn": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x02\x00\x00\x48\x1f\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_syn=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - flag fin",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__flag_fin": True,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x01\x00\x00\x48\x20\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__flag_fin=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - win",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__win": 12345,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x00\x30\x39\x17\xe8\x00\x00"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - urg",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__urg": 12345,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x14\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x00\x00\x00\x17\xe8\x30\x39"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - data",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__payload": b"01234567890ABCDEF" * 50,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x03\x66\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x50\x00\x00\x00\x62\xed\x00\x00\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
                b"\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32"
                b"\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30"
                b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45"
                b"\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44"
                b"\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42\x43"
                b"\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41\x42"
                b"\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x41"
                b"\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
                b"\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
                b"\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37\x38"
                b"\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36\x37"
                b"\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35\x36"
                b"\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34"
                b"\x35\x36\x37\x38\x39\x30\x41\x42\x43\x44\x45\x46"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - option mss",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__mss": 12345,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x18\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x60\x00\x00\x00\x05\xe0\x00\x00\x02\x04\x30\x39"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__opt_mss=1,
                tcp__send=1,
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
            "_description": "Ethernet/IPv6/TCP - option wscale",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__wscale": 14,
            },
            "_expected__frames_tx": [
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x18\x06\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x03\xe8\x07\xd0\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x60\x00\x00\x00\x34\x0c\x00\x00\x01\x03\x03\x0e"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                tcp__pre_assemble=1,
                tcp__opt_wscale=1,
                tcp__opt_nop=1,
                tcp__send=1,
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
            "_description": "TCP - IPv4/IPv6 version mismatch",
            "_kwargs": {
                "ip__src": STACK__IP4_HOST.address,
                "ip__dst": HOST_A__IP6_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__urg": 12345,
            },
            "_expected__frames_tx": None,
            "_expected__tx_status": None,
            "_expected__packet_stats_tx": None,
            "_expected__error": ValueError("Invalid IP address version combination: 10.0.1.7 -> 2001:db8:0:1::91"),
        },
        {
            "_description": "TCP - IPv6/IPv4 version mismatch",
            "_kwargs": {
                "ip__src": STACK__IP6_HOST.address,
                "ip__dst": HOST_A__IP4_ADDRESS,
                "tcp__sport": 1000,
                "tcp__dport": 2000,
                "tcp__urg": 12345,
            },
            "_expected__frames_tx": None,
            "_expected__tx_status": None,
            "_expected__packet_stats_tx": None,
            "_expected__error": ValueError("Invalid IP address version combination: 2001:db8:0:1::7 -> 10.0.1.91"),
        },
    ]
)
class TestPacketHandlerTcpTx(NetworkTestCase):
    """
    Test the Packet Handler TCP TX operations.
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__frames_tx: list[bytes] | None
    _expected__tx_status: TxStatus | None
    _expected__packet_stats_tx: PacketStatsTx | None
    _expected__error: Exception | None

    _frames_tx: list[bytes]

    def test__packet_handler__tcp__tx(self) -> None:
        """
        Validate that sending TCP packet works as expected.
        """

        if self._expected__error is None:
            self.assertEqual(
                self._packet_handler._phtx_tcp(**self._kwargs),
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
                self._packet_handler._phtx_tcp(**self._kwargs)

            self.assertEqual(str(error.exception), str(self._expected__error))
