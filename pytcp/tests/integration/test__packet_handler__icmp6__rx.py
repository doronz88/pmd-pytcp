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

from net_addr import Ip6Address, MacAddress
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
        {
            "_description": "Ethernet/IPv6/ICMPv6 - Echo Reply, no matching raw socket",
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91, type=0x86dd
                # IPv6: src=2001:db8:0:1::91, dst=2001:db8:0:1::7, hop=64, plen=13
                # ICMPv6: type=129 (Echo Reply), id=7, seq=10, data="hello"
                #
                # Summary: Echo reply addressed to us with no matching RAW socket installed.
                #          Bumps 'icmp6__echo_reply' and returns silently.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x0d\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x81\x00\xde\xc8\x00\x07\x00\x0a\x68\x65"
                b"\x6c\x6c\x6f",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                icmp6__pre_parse=1,
                icmp6__echo_reply=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": (
                "Ethernet/IPv6/ICMPv6 - Destination Unreachable, valid embedded IPv6+UDP, " "no matching UDP socket"
            ),
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07, src=02:00:00:00:00:91, type=0x86dd
                # IPv6: src=2001:db8:0:1::91, dst=2001:db8:0:1::7, hop=64, plen=56
                # ICMPv6: type=1 (Destination Unreachable), code=4 (Port)
                #         data = original IPv6 (40B) + UDP (8B):
                #           IPv6: src=2001:db8:0:1::7, dst=2001:db8:0:1::91, next=UDP, plen=8
                #           UDP : sport=12345, dport=54321, len=8, cksum=0
                #
                # Summary: Embedded IPv6+UDP packet passes the integrity gauntlet but no matching
                #          UDP socket is installed. Bumps 'icmp6__destination_unreachable'.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x38\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x01\x04\xd0\xb5\x00\x00\x00\x00\x60\x00"
                b"\x00\x00\x00\x08\x11\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x30\x39\xd4\x31\x00\x08\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                icmp6__pre_parse=1,
                icmp6__destination_unreachable=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": (
                "Ethernet/IPv6/ICMPv6 - Destination Unreachable, embedded data fails IPv6 integrity check"
            ),
            "_frames_rx": [
                # ICMPv6 type=1, embedded data = 48 zero bytes (frame[0]>>4 == 0, fails 'IPv6 version' check)
                #
                # Summary: Embedded data exists but is not a valid IPv6 packet.
                #          Integrity gauntlet rejects it; the function bumps
                #          'icmp6__destination_unreachable' and returns without UDP socket lookup.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x38\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x01\x04\xa2\x7d\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                icmp6__pre_parse=1,
                icmp6__destination_unreachable=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/IPv6/ICMPv6 - Router Advertisement, prefix info learned",
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07 (us), src=02:00:00:00:00:91, type=0x86dd
                # IPv6: src=fe80::91 (link-local, RFC 4861), dst=2001:db8:0:1::7, hop=255 (RFC 4861)
                # ICMPv6: type=134 (RA), hop=64, M/O=0, lifetime=1800, reachable=0, retrans=0
                #         option = Prefix Information (L+A flags set, 30-day valid, 7-day preferred,
                #                  prefix=2001:db8:0:abcd::/64)
                #
                # Summary: RA carrying a single prefix; handler appends (prefix, src) to
                #          '_icmp6_ra__prefixes' and releases the '_icmp6_ra__event' semaphore.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x30\x3a\xff\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x86\x00\x20\xbe\x40\x00\x07\x08\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x03\x04\x40\xc0\x00\x27\x8d\x00\x00\x09"
                b"\x3a\x80\x00\x00\x00\x00\x20\x01\x0d\xb8\x00\x00\xab\xcd\x00\x00"
                b"\x00\x00\x00\x00\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                icmp6__pre_parse=1,
                icmp6__nd_router_advertisement=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": ("Ethernet/IPv6/ICMPv6 - Neighbor Advertisement with TLLA, non-DAD, ND cache update"),
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07, src=02:00:00:00:00:91, type=0x86dd
                # IPv6: src=2001:db8:0:1::91 (unicast), dst=2001:db8:0:1::7, hop=255 (RFC 4861)
                # ICMPv6: type=136 (NA), flags S=1, target=2001:db8:0:1::91
                #         option TLLA = 02:00:00:00:00:91
                #
                # Summary: Non-DAD NA with TLLA option triggers an ND cache update
                #          ('icmp6__nd_neighbor_advertisement__update_nd_cache').
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x20\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x88\x00\xa8\xbb\x40\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x91\x02\x01"
                b"\x02\x00\x00\x00\x00\x91",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                icmp6__pre_parse=1,
                icmp6__nd_neighbor_advertisement=1,
                icmp6__nd_neighbor_advertisement__update_nd_cache=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": ("Ethernet/IPv6/ICMPv6 - Neighbor Advertisement without TLLA, non-DAD, no cache update"),
            "_frames_rx": [
                # Ethernet II: dst=02:00:00:00:00:07, src=02:00:00:00:00:91, type=0x86dd
                # IPv6: src=2001:db8:0:1::91, dst=2001:db8:0:1::7, hop=255
                # ICMPv6: type=136 (NA), flags S=1, target=2001:db8:0:1::91, no options
                #
                # Summary: Non-DAD NA without a TLLA option silently no-ops on the cache.
                #          Only 'icmp6__nd_neighbor_advertisement' is bumped.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x18\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x88\x00\xad\x55\x40\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x91",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                icmp6__pre_parse=1,
                icmp6__nd_neighbor_advertisement=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/IPv6/ICMPv6 - unknown type (200), classified as unknown",
            "_frames_rx": [
                # ICMPv6 type=200 (unassigned), code=0, no payload.
                #
                # Summary: Falls through the type-match dispatch to '__phrx_icmp6__unknown',
                #          bumps 'icmp6__unknown'.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x04\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\xc8\x00\xdb\xb4",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                icmp6__pre_parse=1,
                icmp6__unknown=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/IPv6/ICMPv6 - malformed (truncated) — failed parse drop",
            "_frames_rx": [
                # ICMPv6: only 4 bytes (type=128, code=0, cksum=0) — truncated below the
                #         8-byte minimum the Icmp6Parser expects for an Echo Request.
                #
                # Summary: Truncated ICMPv6 message triggers Icmp6Parser to raise, bumping
                #          'icmp6__failed_parse__drop' and skipping all message-type dispatch.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
                b"\x00\x00\x00\x04\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x80\x00\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                ip6__pre_parse=1,
                ip6__dst_unicast=1,
                icmp6__pre_parse=1,
                icmp6__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
    ]
)
class TestPacketHandlerIcmp6Rx(NetworkTestCase):
    """
    Test the Packet Handler ICMPv6 RX operations.
    """

    _description: str
    _frames_rx: list[bytes]
    _expected__frames_tx: list[bytes]
    _expected__packet_stats_rx: PacketStatsRx
    _expected__packet_stats_tx: PacketStatsTx

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


class TestPacketHandlerIcmp6RxRouterSolicitation(NetworkTestCase):
    """
    Test the Packet Handler dispatch of an ICMPv6 Router Solicitation.

    RFC 4861 requires RS to be sent to the all-routers multicast address
    (ff02::2) at hop limit 255, so the test joins the corresponding IPv6
    and Ethernet multicast groups in setUp before driving the frame.
    """

    _ALL_ROUTERS__IP6 = Ip6Address("ff02::2")
    _ALL_ROUTERS__MAC = MacAddress("33:33:00:00:00:02")

    def setUp(self) -> None:
        """
        Join the all-routers IPv6 and Ethernet multicast groups so the
        RS frame passes the RX classifier.
        """

        super().setUp()
        self._packet_handler._mac_multicast.append(self._ALL_ROUTERS__MAC)
        self._packet_handler._ip6_multicast.append(self._ALL_ROUTERS__IP6)

    def test__packet_handler__icmp6__rx__router_solicitation(self) -> None:
        """
        Ensure an inbound ICMPv6 Router Solicitation reaches the
        '__phrx_icmp6__nd_router_solicitation' dispatch arm and
        bumps 'icmp6__nd_router_solicitation'.
        """

        # Ethernet II: dst=33:33:00:00:00:02 (all-routers), src=02:00:00:00:00:91
        # IPv6: src=fe80::91, dst=ff02::2, hop=255 (RFC 4861), plen=8
        # ICMPv6: type=133 (Router Solicitation), code=0, cksum=0x7ca6, no options
        frame_rx = (
            b"\x33\x33\x00\x00\x00\x02\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
            b"\x00\x00\x00\x08\x3a\xff\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x91\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x02\x85\x00\x7c\xa6\x00\x00\x00\x00"
        )

        self._packet_handler._phrx_ethernet(PacketRx(frame_rx))

        self.assertEqual(
            self._frames_tx,
            [],
            msg="Router Solicitation handler must not transmit any frame.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx,
            PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_multicast=1,
                ip6__pre_parse=1,
                ip6__dst_multicast=1,
                icmp6__pre_parse=1,
                icmp6__nd_router_solicitation=1,
            ),
            msg="icmp6__nd_router_solicitation must be bumped for a valid inbound RS.",
        )


class TestPacketHandlerIcmp6RxMld2Report(NetworkTestCase):
    """
    Test the Packet Handler dispatch of an ICMPv6 MLDv2 Report.

    RFC 3810 MLDv2 Reports are sent to ff02::16 at hop limit 1. The
    test joins the corresponding IPv6 and Ethernet multicast groups in
    setUp.
    """

    _MLD2_ROUTERS__IP6 = Ip6Address("ff02::16")
    _MLD2_ROUTERS__MAC = MacAddress("33:33:00:00:00:16")

    def setUp(self) -> None:
        """
        Join the MLDv2-routers IPv6 and Ethernet multicast groups.
        """

        super().setUp()
        self._packet_handler._mac_multicast.append(self._MLD2_ROUTERS__MAC)
        self._packet_handler._ip6_multicast.append(self._MLD2_ROUTERS__IP6)

    def test__packet_handler__icmp6__rx__mld2_report(self) -> None:
        """
        Ensure an inbound ICMPv6 MLDv2 Report reaches the
        '__phrx_icmp6__mld2_report' dispatch arm and bumps
        'icmp6__mld2_report'.
        """

        # Ethernet II: dst=33:33:00:00:00:16, src=02:00:00:00:00:91
        # IPv6: src=fe80::91, dst=ff02::16, hop=1 (RFC 3810), plen=8
        # ICMPv6: type=143 (MLDv2 Report), code=0, cksum=0x7292, 0 records
        frame_rx = (
            b"\x33\x33\x00\x00\x00\x16\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
            b"\x00\x00\x00\x08\x3a\x01\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x91\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x16\x8f\x00\x72\x92\x00\x00\x00\x00"
        )

        self._packet_handler._phrx_ethernet(PacketRx(frame_rx))

        self.assertEqual(
            self._frames_tx,
            [],
            msg="MLDv2 Report handler must not transmit any frame.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_rx,
            PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_multicast=1,
                ip6__pre_parse=1,
                ip6__dst_multicast=1,
                icmp6__pre_parse=1,
                icmp6__mld2_report=1,
            ),
            msg="icmp6__mld2_report must be bumped for a valid inbound MLDv2 Report.",
        )


class TestPacketHandlerIcmp6RxNeighborAdvertisementDad(NetworkTestCase):
    """
    Test the Packet Handler dispatch of a Neighbor Advertisement whose
    target address matches the DAD candidate IPv6 address currently
    being probed. The handler must record the TLLA, release the DAD
    semaphore, and bump the DAD-specific stat.
    """

    _CANDIDATE__IP6 = Ip6Address("2001:db8:0:1::5")

    def setUp(self) -> None:
        """
        Install a DAD candidate on the packet handler so the NA
        target matches and the DAD branch fires.
        """

        super().setUp()
        self._packet_handler._icmp6_nd_dad__ip6_unicast_candidate = self._CANDIDATE__IP6

    def test__packet_handler__icmp6__rx__na_dad_match(self) -> None:
        """
        Ensure an NA whose target equals the DAD candidate IP bumps
        'icmp6__nd_neighbor_advertisement__run_dad', captures the
        peer's TLLA into '_icmp6_nd_dad__tlla', and releases the
        '_icmp6_nd_dad__event' semaphore.
        """

        # Ethernet II: dst=02:00:00:00:00:07, src=02:00:00:00:00:91
        # IPv6: src=2001:db8:0:1::91, dst=2001:db8:0:1::7, hop=255
        # ICMPv6: type=136 (NA), flags S=1, target=2001:db8:0:1::5 (our DAD candidate)
        #         option TLLA = 02:00:00:00:00:91
        frame_rx = (
            b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x86\xdd\x60\x00"
            b"\x00\x00\x00\x20\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
            b"\x00\x00\x00\x00\x00\x91\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
            b"\x00\x00\x00\x00\x00\x07\x88\x00\xa9\x47\x40\x00\x00\x00\x20\x01"
            b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x05\x02\x01"
            b"\x02\x00\x00\x00\x00\x91"
        )

        self._packet_handler._phrx_ethernet(PacketRx(frame_rx))

        self.assertEqual(
            self._packet_handler.packet_stats_rx.icmp6__nd_neighbor_advertisement,
            1,
            msg="icmp6__nd_neighbor_advertisement must be bumped for any inbound NA.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.icmp6__nd_neighbor_advertisement__run_dad,
            1,
            msg="NA matching the DAD candidate must bump '__run_dad'.",
        )
        self.assertEqual(
            self._packet_handler._icmp6_nd_dad__tlla,
            MacAddress("02:00:00:00:00:91"),
            msg="Handler must capture the peer TLLA from the NA into '_icmp6_nd_dad__tlla'.",
        )
        self.assertTrue(
            self._packet_handler._icmp6_nd_dad__event.acquire(blocking=False),
            msg="Handler must release the '_icmp6_nd_dad__event' semaphore for DAD NAs.",
        )
