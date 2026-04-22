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
This module contains integration tests for the Packet Handler ICMPv6 RX operations.

pytcp/tests/integration/test__packet_handler__icmp6__rx.py

ver 3.0.4
"""


from parameterized import parameterized_class  # type: ignore

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.tests.lib.network_testcase import NetworkTestCase


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv6/ICMPv6 Echo Request",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07 (our MAC)
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 126 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0048 (72 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::91
                #   Destination IP : 2001:db8:0:1::7
                #
                # ICMPv6
                #   Type/Code       : 128 / 0 (Echo Request)
                #   Checksum        : 0x04ef
                #   Identifier      : 0x0007
                #   Sequence        : 0x000a
                #   Payload         : 64 bytes (timestamp + pattern)
                #
                # Summary: ICMPv6 echo request targeting the stack; expect an echo reply.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x48\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x80\x00\x04\xef\x00\x07\x00\x0a\x88\x9f"
                b"\xba\x60\x00\x00\x00\x00\x29\xad\x06\x00\x00\x00\x00\x00\x10\x11"
                b"\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21"
                b"\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 126 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0048 (72 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 255
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # ICMPv6
                #   Type/Code       : 129 / 0 (Echo Reply)
                #   Checksum        : 0x03ef
                #   Identifier      : 0x0007
                #   Sequence        : 0x000a
                #   Payload         : 64 bytes mirrored from request
                #
                # Summary: ICMPv6 echo reply from the stack sent back to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x48\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x81\x00\x03\xef\x00\x07\x00\x0a\x88\x9f"
                b"\xba\x60\x00\x00\x00\x00\x29\xad\x06\x00\x00\x00\x00\x00\x10\x11"
                b"\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21"
                b"\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                icmp6__pre_parse=1,
                icmp6__echo_request__respond_echo_reply=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__echo_reply__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": (
                "Ethernet/IPv6/ICMPv6 - ND Neighbor Solicitation (unicast dst), respond with Neighbor Advertisement"
            ),
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07 (our MAC)
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 78 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0020 (32 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 255
                #   Source IP      : 2001:db8:0:1::91
                #   Destination IP : 2001:db8:0:1::7
                #
                # ICMPv6 Neighbor Solicitation
                #   Flags          : 0x00000000
                #   Target         : 2001:db8:0:1::7
                #   Options        : Source Link-Layer (02:00:00:00:00:91)
                #
                # Summary: Unicast NS asking for our address.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x20\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x87\x00\xeb\x45\x00\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07\x01\x01"
                b"\x02\x00\x00\x00\x00\x91",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 86 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0020 (32 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 255
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # ICMPv6 Neighbor Advertisement
                #   Flags          : 0x60000000 (Solicited + Override)
                #   Target         : 2001:db8:0:1::7
                #   Options        : Target Link-Layer (02:00:00:00:00:07)
                #
                # Summary: Solicited neighbor advertisement sent to the unicast requester.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x20\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x88\x00\xa9\xcf\x40\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07\x02\x01"
                b"\x02\x00\x00\x00\x00\x07",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                icmp6__pre_parse=1,
                icmp6__nd_neighbor_solicitation=1,
                icmp6__nd_neighbor_solicitation__update_nd_cache=1,
                icmp6__nd_neighbor_solicitation__target_stack__respond=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__nd__neighbor_advertisement__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": (
                "Ethernet/IPv6/ICMPv6 - ND Neighbor Solicitation (unicast dst, no SLLA), "
                "respond with Neighbor Advertisement"
            ),
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 33:33:ff:00:00:07 (solicited-node multicast)
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 86 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0018 (24 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 255
                #   Source IP      : 2001:db8:0:1::91
                #   Destination IP : ff02::1:ff00:7
                #
                # ICMPv6 Neighbor Solicitation
                #   Flags          : 0x00000000
                #   Target         : 2001:db8:0:1::7
                #   Options        : none (no SLLA)
                #
                # Summary: Multicast NS without source LLA option.
                b"\x33\x33\xff\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x18\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x01\xff\x00\x00\x07\x87\x00\x1e\x95\x00\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 86 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0020 (32 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 255
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # ICMPv6 Neighbor Advertisement
                #   Flags          : 0x60000000 (Solicited + Override)
                #   Target         : 2001:db8:0:1::7
                #   Options        : Target Link-Layer (02:00:00:00:00:07)
                #
                # Summary: Neighbor advertisement responding despite missing SLLA.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x20\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x88\x00\xa9\xcf\x40\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07\x02\x01"
                b"\x02\x00\x00\x00\x00\x07",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_multicast=1,
                ip6__pre_parse=1,
                ip6__dst_multicast=1,
                icmp6__pre_parse=1,
                icmp6__nd_neighbor_solicitation=1,
                icmp6__nd_neighbor_solicitation__target_stack__respond=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__nd__neighbor_advertisement__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": (
                "Ethernet/IPv6/ICMPv6 - ND Neighbor Solicitation (multicast dst), "
                "respond with Neighbor Advertisement"
            ),
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 33:33:ff:00:00:07 (solicited-node multicast)
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 86 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0020 (32 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 255
                #   Source IP      : 2001:db8:0:1::91
                #   Destination IP : ff02::1:ff00:7
                #
                # ICMPv6 Neighbor Solicitation
                #   Flags          : 0x00000000
                #   Target         : 2001:db8:0:1::7
                #   Options        : Source Link-Layer (02:00:00:00:00:91)
                #
                # Summary: Multicast NS asking for our address.
                b"\x33\x33\xff\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x20\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x01\xff\x00\x00\x07\x87\x00\x1a\xfb\x00\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07\x01\x01"
                b"\x02\x00\x00\x00\x00\x91",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 86 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0020 (32 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 255
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # ICMPv6 Neighbor Advertisement
                #   Flags          : 0x60000000 (Solicited + Override)
                #   Target         : 2001:db8:0:1::7
                #   Options        : Target Link-Layer (02:00:00:00:00:07)
                #
                # Summary: Neighbor advertisement reply to multicast solicitation.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x20\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x88\x00\xa9\xcf\x40\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07\x02\x01"
                b"\x02\x00\x00\x00\x00\x07",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_multicast=1,
                ip6__pre_parse=1,
                ip6__dst_multicast=1,
                icmp6__pre_parse=1,
                icmp6__nd_neighbor_solicitation=1,
                icmp6__nd_neighbor_solicitation__update_nd_cache=1,
                icmp6__nd_neighbor_solicitation__target_stack__respond=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__nd__neighbor_advertisement__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": (
                "Ethernet/IPv6/ICMPv6 - ND Neighbor Solicitation (multicast dst, no SLLA), "
                "respond with Neighbor Advertisement"
            ),
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 33:33:ff:00:00:07 (solicited-node multicast)
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 78 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0018 (24 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 255
                #   Source IP      : 2001:db8:0:1::91
                #   Destination IP : ff02::1:ff00:7
                #
                # ICMPv6 Neighbor Solicitation
                #   Flags          : 0x00000000
                #   Target         : 2001:db8:0:1::7
                #   Options        : none (no SLLA)
                #
                # Summary: Multicast NS without source LLA option.
                b"\x33\x33\xff\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x18\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x01\xff\x00\x00\x07\x87\x00\x1e\x95\x00\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 86 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0020 (32 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 255
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # ICMPv6 Neighbor Advertisement
                #   Flags          : 0x60000000 (Solicited + Override)
                #   Target         : 2001:db8:0:1::7
                #   Options        : Target Link-Layer (02:00:00:00:00:07)
                #
                # Summary: Neighbor advertisement responding despite missing SLLA.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x20\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x88\x00\xa9\xcf\x40\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07\x02\x01"
                b"\x02\x00\x00\x00\x00\x07",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_multicast=1,
                ip6__pre_parse=1,
                ip6__dst_multicast=1,
                icmp6__pre_parse=1,
                icmp6__nd_neighbor_solicitation=1,
                icmp6__nd_neighbor_solicitation__update_nd_cache=0,
                icmp6__nd_neighbor_solicitation__target_stack__respond=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__nd__neighbor_advertisement__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__locnet__nd_cache_hit__send=1,
            ),
        },
        {
            "_description": (
                "Ethernet/IPv6/ICMPv6 - ND Neighbor Solicitation (DAD), respond with Neighbor Advertisement"
            ),
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 33:33:ff:00:00:07 (solicited-node multicast)
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 86 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0018 (24 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 255
                #   Source IP      : :: (unspecified)
                #   Destination IP : ff02::1:ff00:7
                #
                # ICMPv6 Neighbor Solicitation (DAD)
                #   Flags          : 0x00000000
                #   Target         : 2001:db8:0:1::7 (candidate address)
                #   Options        : none
                #
                # Summary: Duplicate Address Detection probe for our IPv6 address.
                b"\x33\x33\xff\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x18\x3a\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x01\xff\x00\x00\x07\x87\x00\x4c\xe0\x00\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 33:33:00:00:00:01 (all-nodes multicast)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 86 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0020 (32 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 255
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : ff02::1 (all-nodes)
                #
                # ICMPv6 Neighbor Advertisement
                #   Flags          : 0x20000000 (Override only)
                #   Target         : 2001:db8:0:1::7
                #   Options        : Target Link-Layer (02:00:00:00:00:07)
                #
                # Summary: Gratuitous neighbor advertisement defending our address during DAD.
                b"\x33\x33\x00\x00\x00\x01\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x20\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x01\x88\x00\xf9\x16\x20\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07\x02\x01"
                b"\x02\x00\x00\x00\x00\x07",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_multicast=1,
                ip6__pre_parse=1,
                ip6__dst_multicast=1,
                icmp6__pre_parse=1,
                icmp6__nd_neighbor_solicitation=1,
                icmp6__nd_neighbor_solicitation__dad=1,
                icmp6__nd_neighbor_solicitation__target_stack__respond=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__nd__neighbor_advertisement__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__multicast__send=1,
            ),
        },
    ]
)
class TestPacketHandlerIcmp6Rx(NetworkTestCase):
    """
    Test the Packet Handler ICMPv6 RX operations.
    """

    _description: str
    _frames_rx: list[bytes]
    _expected__frames_tx: list[bytes] | None
    _expected__packet_stats_rx: PacketStatsRx | None
    _expected__packet_stats_tx: PacketStatsTx | None

    _frames_tx: list[bytes]

    def test__packet_handler__icmp6__rx(self) -> None:
        """
        Ensure the Packet Handler processes the received ICMPv6
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
