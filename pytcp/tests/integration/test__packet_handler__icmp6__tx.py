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
This module contains integration tests for the Packet Handler ICMPv6 TX operations.

pytcp/tests/integration/test__packet_handler__icmp6__tx.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from net_addr.ip6_address import Ip6Address
from net_proto.protocols.icmp6.message.icmp6__message__destination_unreachable import (
    Icmp6DestinationUnreachableCode,
    Icmp6MessageDestinationUnreachable,
)
from net_proto.protocols.icmp6.message.icmp6__message__echo_reply import (
    Icmp6MessageEchoReply,
)
from net_proto.protocols.icmp6.message.icmp6__message__echo_request import (
    Icmp6MessageEchoRequest,
)
from net_proto.protocols.icmp6.message.mld2.icmp6__mld2__message__report import (
    Icmp6Mld2ReportMessage,
)
from net_proto.protocols.icmp6.message.mld2.icmp6__mld2__multicast_address_record import (
    Icmp6Mld2MulticastAddressRecord,
    Icmp6Mld2MulticastAddressRecordType,
)
from net_proto.protocols.icmp6.message.nd.icmp6__nd__message__neighbor_advertisement import (
    Icmp6NdMessageNeighborAdvertisement,
)
from net_proto.protocols.icmp6.message.nd.icmp6__nd__message__neighbor_solicitation import (
    Icmp6NdMessageNeighborSolicitation,
)
from net_proto.protocols.icmp6.message.nd.icmp6__nd__message__router_advertisement import (
    Icmp6NdMessageRouterAdvertisement,
)
from net_proto.protocols.icmp6.message.nd.icmp6__nd__message__router_solicitation import (
    Icmp6NdMessageRouterSolicitation,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__pi import (
    Icmp6NdOptionPi,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__slla import (
    Icmp6NdOptionSlla,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__option__tlla import (
    Icmp6NdOptionTlla,
)
from net_proto.protocols.icmp6.message.nd.option.icmp6__nd__options import (
    Icmp6NdOptions,
)
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP6_ADDRESS,
    IP6__MULTICAST__ALL_NODES,
    IP6__MULTICAST__ALL_ROUTERS,
    IP6__MULTICAST__MLD2_ROUTERS,
    IP6__UNSPECIFIED,
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
    NetworkTestCase,
)


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv6/ICMPv6 - Echo Request",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_A__IP6_ADDRESS,
                "icmp6__message": Icmp6MessageEchoRequest(
                    id=12345,
                    seq=54320,
                    data=b"0123456789ABCDEF" * 20,
                ),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 382 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0148 (328 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # ICMPv6
                #   Type/Code       : 128 / 0 (Echo Request)
                #   Checksum        : 0xf53e
                #   Identifier      : 12345
                #   Sequence        : 54320
                #   Payload         : 320 bytes ("0123456789ABCDEF" * 20)
                #
                # Summary: ICMPv6 echo request with large payload headed to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x01\x48\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x80\x00\xf5\x3e\x30\x39\xd4\x30\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__echo_request__send=1,
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
            "_description": "Ethernet/IPv6/ICMPv6 - Echo Reply",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_A__IP6_ADDRESS,
                "icmp6__message": Icmp6MessageEchoReply(
                    id=12345,
                    seq=54320,
                    data=b"0123456789ABCDEF" * 20,
                ),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 382 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0148 (328 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # ICMPv6
                #   Type/Code       : 129 / 0 (Echo Reply)
                #   Checksum        : 0xf43e
                #   Identifier      : 12345
                #   Sequence        : 54320
                #   Payload         : 320 bytes mirrored from the request
                #
                # Summary: ICMPv6 echo reply returning the same payload to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x01\x48\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x81\x00\xf4\x3e\x30\x39\xd4\x30\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
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
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv6/ICMPv6 - Destination Unreachable, port",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_A__IP6_ADDRESS,
                "icmp6__message": Icmp6MessageDestinationUnreachable(
                    code=Icmp6DestinationUnreachableCode.PORT,
                    data=b"0123456789ABCDEF" * 100,
                ),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 1294 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x04d8 (1240 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 64
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : 2001:db8:0:1::91
                #
                # ICMPv6
                #   Type/Code       : 1 / 4 (Destination Unreachable - Port)
                #   Checksum        : 0x6741
                #   Payload         : 1232 bytes (original datagram excerpt)
                #
                # Summary: ICMPv6 destination unreachable (port) with a large quoted packet body.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x04\xd8\x3a\x40\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x01\x04\x67\x41\x00\x00\x00\x00\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31"
                b"\x32\x33\x34\x35\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__destination_unreachable__port__send=1,
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
            "_description": "Ethernet/IPv6/ICMPv6 - ND Router Solicitation",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": IP6__MULTICAST__ALL_ROUTERS,
                "ip6__hop": 255,
                "icmp6__message": Icmp6NdMessageRouterSolicitation(
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(STACK__MAC_ADDRESS),
                    ),
                ),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 33:33:00:00:00:02 (all-routers multicast)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 70 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0010 (16 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 255
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : ff02::2 (all routers)
                #
                # ICMPv6 Router Solicitation
                #   Options        : Source Link-Layer (02:00:00:00:00:07)
                #   Checksum       : 0x4ae7
                #
                # Summary: Router solicitation advertising our MAC to local routers.
                b"\x33\x33\x00\x00\x00\x02\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x10\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x02\x85\x00\x4a\xe7\x00\x00\x00\x00\x01\x01"
                b"\x02\x00\x00\x00\x00\x07",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__nd__router_solicitation__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__multicast__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv6/ICMPv6 - ND Router Advertisement",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": IP6__MULTICAST__ALL_NODES,
                "ip6__hop": 255,
                "icmp6__message": Icmp6NdMessageRouterAdvertisement(
                    hop=64,
                    flag_m=True,
                    flag_o=True,
                    router_lifetime=1800,
                    reachable_time=900,
                    retrans_timer=300,
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(STACK__MAC_ADDRESS),
                        Icmp6NdOptionPi(
                            flag_l=True,
                            flag_a=False,
                            flag_r=True,
                            valid_lifetime=7200,
                            preferred_lifetime=3600,
                            prefix=STACK__IP6_HOST.network,
                        ),
                    ),
                ),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 33:33:00:00:00:01 (all-nodes multicast)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 110 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0038 (56 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 255
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : ff02::1 (all nodes)
                #
                # ICMPv6 Router Advertisement
                #   Checksum        : 0x61b9
                #   Hop Limit       : 64
                #   Flags           : M=1, O=1
                #   Router Lifetime : 1800 s
                #   Reachable Time  : 900 ms
                #   Retrans Timer   : 300 ms
                #   Options         : SLLA + Prefix Information (2001:db8:0:1::/64)
                #
                # Summary: Router advertisement broadcasting stack parameters to local hosts.
                b"\x33\x33\x00\x00\x00\x01\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x38\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x01\x86\x00\x61\xb9\x40\xc0\x07\x08\x00\x00"
                b"\x03\x84\x00\x00\x01\x2c\x01\x01\x02\x00\x00\x00\x00\x07\x03\x04"
                b"\x40\xa0\x00\x00\x1c\x20\x00\x00\x0e\x10\x00\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__nd__router_advertisement__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__multicast__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv6/ICMPv6 - ND Neighbor Advertisement",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_A__IP6_ADDRESS,
                "ip6__hop": 255,
                "icmp6__message": Icmp6NdMessageNeighborAdvertisement(
                    target_address=STACK__IP6_HOST.address,
                    flag_r=False,
                    flag_s=True,
                    flag_o=True,
                    options=Icmp6NdOptions(
                        Icmp6NdOptionTlla(STACK__MAC_ADDRESS),
                    ),
                ),
            },
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
                #   Options        : TLLA (02:00:00:00:00:07)
                #
                # Summary: Neighbor advertisement conveying our MAC and target address to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x20\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x91\x88\x00\x89\xcf\x60\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07\x02\x01"
                b"\x02\x00\x00\x00\x00\x07"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
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
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv6/ICMPv6 - ND Neighbor Solicitation",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": HOST_A__IP6_ADDRESS.solicited_node_multicast,
                "ip6__hop": 255,
                "icmp6__message": Icmp6NdMessageNeighborSolicitation(
                    target_address=HOST_A__IP6_ADDRESS,
                    options=Icmp6NdOptions(
                        Icmp6NdOptionSlla(STACK__MAC_ADDRESS),
                    ),
                ),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 33:33:00:00:00:91 (solicited-node multicast for host A)
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
                #   Destination IP : ff02::1:ff00:91
                #
                # ICMPv6 Neighbor Solicitation
                #   Flags          : 0x00000000
                #   Target         : 2001:db8:0:1::91
                #   Options        : SLLA (02:00:00:00:00:07)
                #
                # Summary: Neighbor solicitation probing host A for its MAC address.
                b"\x33\x33\xff\x00\x00\x91\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x20\x3a\xff\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x01\xff\x00\x00\x91\x87\x00\x1a\xfb\x00\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x91\x01\x01"
                b"\x02\x00\x00\x00\x00\x07"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__nd__neighbor_solicitation__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__multicast__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv6/ICMPv6 - ND Neighbor Solicitation, DAD variant",
            "_kwargs": {
                "ip6__src": IP6__UNSPECIFIED,
                "ip6__dst": STACK__IP6_HOST.address.solicited_node_multicast,
                "ip6__hop": 255,
                "icmp6__message": Icmp6NdMessageNeighborSolicitation(
                    target_address=STACK__IP6_HOST.address,
                    options=Icmp6NdOptions(),
                ),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 33:33:ff:00:00:07 (solicited-node multicast)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 78 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0018 (24 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 255
                #   Source IP      : ::
                #   Destination IP : ff02::1:ff00:7
                #
                # ICMPv6 Neighbor Solicitation (DAD)
                #   Flags          : 0x00000000
                #   Target         : 2001:db8:0:1::7
                #   Options        : none
                #
                # Summary: DAD neighbor solicitation emitted with unspecified source.
                b"\x33\x33\xff\x00\x00\x07\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x18\x3a\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x01\xff\x00\x00\x07\x87\x00\x4c\xe0\x00\x00\x00\x00\x20\x01"
                b"\x0d\xb8\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__nd__neighbor_solicitation__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ip6__src_unspecified__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__multicast__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/IPv6/ICMPv6 - MLDv2 Report",
            "_kwargs": {
                "ip6__src": STACK__IP6_HOST.address,
                "ip6__dst": IP6__MULTICAST__MLD2_ROUTERS,
                "ip6__hop": 1,
                "icmp6__message": Icmp6Mld2ReportMessage(
                    records=[
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_EXCLUDE,
                            multicast_address=Ip6Address("ff02::a"),
                        ),
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.CHANGE_TO_INCLUDE,
                            multicast_address=Ip6Address("ff02::b"),
                        ),
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_EXCLUDE,
                            multicast_address=Ip6Address("ff02::c"),
                        ),
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.MODE_IS_INCLUDE,
                            multicast_address=Ip6Address("ff02::d"),
                        ),
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.ALLOW_NEW_SOURCES,
                            multicast_address=Ip6Address("ff02::e"),
                        ),
                        Icmp6Mld2MulticastAddressRecord(
                            type=Icmp6Mld2MulticastAddressRecordType.ALLOW_NEW_SOURCES,
                            multicast_address=Ip6Address("ff02::f"),
                        ),
                    ]
                ),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 33:33:00:00:00:16 (MLDv2 routers multicast)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x86DD (IPv6)
                #   Frame length    : 182 bytes
                #
                # IPv6
                #   Version / Traffic Class / Flow Label : 0x60000000
                #   Payload Length : 0x0080 (128 bytes)
                #   Next Header    : 58 (ICMPv6)
                #   Hop Limit      : 1
                #   Source IP      : 2001:db8:0:1::7
                #   Destination IP : ff02::16 (MLDv2 routers)
                #
                # ICMPv6 MLDv2 Report
                #   Record Count    : 6
                #   Records         : {CHANGE_TO_EXCLUDE ff02::a, CHANGE_TO_INCLUDE ff02::b,
                #                     MODE_IS_EXCLUDE ff02::c, MODE_IS_INCLUDE ff02::d,
                #                     ALLOW_NEW_SOURCES ff02::e, ALLOW_NEW_SOURCES ff02::f}
                #   Checksum        : 0x3508
                #
                # Summary: MLDv2 report advertising multicast memberships to routers.
                b"\x33\x33\x00\x00\x00\x16\x02\x00\x00\x00\x00\x07\x86\xdd\x60\x00"
                b"\x00\x00\x00\x80\x3a\x01\x20\x01\x0d\xb8\x00\x00\x00\x01\x00\x00"
                b"\x00\x00\x00\x00\x00\x07\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x16\x8f\x00\x35\x08\x00\x00\x00\x06\x04\x00"
                b"\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x0a\x03\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x0b\x02\x00\x00\x00\xff\x02\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x01\x00\x00\x00\xff\x02"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0d\x05\x00"
                b"\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x0e\x05\x00\x00\x00\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x0f"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp6__pre_assemble=1,
                icmp6__mld2__report__send=1,
                ip6__pre_assemble=1,
                ip6__mtu_ok__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_unspec__fill=1,
                ethernet__dst_unspec__ip6_lookup=1,
                ethernet__dst_unspec__ip6_lookup__multicast__send=1,
            ),
            "_expected__error": None,
        },
    ]
)
class TestPacketHandlerIcmp6Tx(NetworkTestCase):
    """
    Test the Packet Handler ICMPv6 TX operations.
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__frames_tx: list[bytes] | None
    _expected__tx_status: TxStatus | None
    _expected__packet_stats_tx: PacketStatsTx | None
    _expected__error: Exception | None

    _frames_tx: list[bytes]

    def test__packet_handler__icmp6__tx(self) -> None:
        """
        Ensure the Packet Handler ICMPv6 TX path produces the
        expected frames, statuses, and statistics for each
        parametrized case.
        """

        if self._expected__error is None:
            self.assertEqual(
                self._packet_handler._phtx_icmp6(**self._kwargs),
                self._expected__tx_status,
                msg=f"Unexpected TxStatus for case: {self._description}",
            )

            self.assertEqual(
                self._frames_tx,
                self._expected__frames_tx,
                msg=f"Unexpected TX frames for case: {self._description}",
            )

            self.assertEqual(
                self._packet_handler.packet_stats_tx,
                self._expected__packet_stats_tx,
                msg=f"Unexpected TX packet stats for case: {self._description}",
            )

        else:
            with self.assertRaises(type(self._expected__error)) as error:
                self._packet_handler._phtx_icmp6(**self._kwargs)

            self.assertEqual(
                str(error.exception),
                str(self._expected__error),
                msg=f"Unexpected error message for case: {self._description}",
            )
