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
This module contains integration tests for the Packet Handler ICMPv4 TX operations.

pytcp/tests/integration/test__packet_handler__icmp4__tx.py

ver 3.0.4
"""


from typing import Any

from parameterized import parameterized_class  # type: ignore

from net_proto.protocols.icmp4.message.icmp4__message__destination_unreachable import (
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
)
from net_proto.protocols.icmp4.message.icmp4__message__echo_reply import (
    Icmp4MessageEchoReply,
)
from net_proto.protocols.icmp4.message.icmp4__message__echo_request import (
    Icmp4MessageEchoRequest,
)
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
    NetworkTestCase,
)


@parameterized_class(
    [
        {
            "_description": "Ethernet/IPv4/ICMPv4 - Echo Request",
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_A__IP4_ADDRESS,
                "icmp4__message": Icmp4MessageEchoRequest(
                    id=12345,
                    seq=54320,
                    data=b"0123456789ABCDEF" * 20,
                ),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 362 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x015c (348 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 1 (ICMP)
                #   Header Checksum : 0x6340
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # ICMPv4
                #   Type/Code       : 8 / 0 (Echo Request)
                #   Checksum        : 0xcacd
                #   Identifier      : 12345
                #   Sequence        : 54320
                #   Payload         : 320 bytes ("0123456789ABCDEF" * 20)
                #
                # Summary: ICMPv4 echo request emitted with large payload toward host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x01\x5c\x00\x00\x00\x00\x40\x01\x63\x40\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x08\x00\xca\xcd\x30\x39\xd4\x30\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp4__pre_assemble=1,
                icmp4__echo_request__send=1,
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
            "_description": "Ethernet/IPv4/ICMPv4 - Echo Reply",
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_A__IP4_ADDRESS,
                "icmp4__message": Icmp4MessageEchoReply(
                    id=12345,
                    seq=54320,
                    data=b"0123456789ABCDEF" * 20,
                ),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 362 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x015c (348 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 1 (ICMP)
                #   Header Checksum : 0x6340
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # ICMPv4
                #   Type/Code       : 0 / 0 (Echo Reply)
                #   Checksum        : 0xd2cd
                #   Identifier      : 12345
                #   Sequence        : 54320
                #   Payload         : 320 bytes mirrored from the request
                #
                # Summary: ICMPv4 echo reply with matching payload returned to host A.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x01\x5c\x00\x00\x00\x00\x40\x01\x63\x40\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x00\x00\xd2\xcd\x30\x39\xd4\x30\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
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
        {
            "_description": "Ethernet/IPv4/ICMPv4 - Destination Unreachable, port",
            "_kwargs": {
                "ip4__src": STACK__IP4_HOST.address,
                "ip4__dst": HOST_A__IP4_ADDRESS,
                "icmp4__message": Icmp4MessageDestinationUnreachable(
                    code=Icmp4DestinationUnreachableCode.PORT,
                    data=b"0123456789ABCDEF" * 100,
                ),
            },
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0800 (IPv4)
                #   Frame length    : 590 bytes
                #
                # IPv4
                #   Version / IHL    : 4 / 5
                #   DSCP / ECN      : 0x00
                #   Total Length    : 0x0240 (576 bytes)
                #   Identification  : 0x0000
                #   Flags / Offset  : 0x0000
                #   TTL             : 64
                #   Protocol        : 1 (ICMP)
                #   Header Checksum : 0x625c
                #   Source IP       : 10.0.1.7
                #   Destination IP  : 10.0.1.91
                #
                # ICMPv4
                #   Type/Code       : 3 / 3 (Destination Unreachable - Port)
                #   Checksum        : 0x2211
                #   Unused          : 0
                #   Payload         : 552 bytes (original datagram excerpt)
                #
                # Summary: ICMPv4 destination-unreachable dispatched with sizable payload snapshot.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x00\x45\x00"
                b"\x02\x40\x00\x00\x00\x00\x40\x01\x62\x5c\x0a\x00\x01\x07\x0a\x00"
                b"\x01\x5b\x03\x03\x22\x11\x00\x00\x00\x00\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33\x34\x35"
                b"\x36\x37\x38\x39\x41\x42\x43\x44\x45\x46\x30\x31\x32\x33"
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                icmp4__pre_assemble=1,
                icmp4__destination_unreachable__port__send=1,
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
class TestPacketHandlerIcmp4Tx(NetworkTestCase):
    """
    Test the Packet Handler ICMPv4 TX operations.
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__frames_tx: list[bytes] | None
    _expected__tx_status: TxStatus | None
    _expected__packet_stats_tx: PacketStatsTx | None
    _expected__error: Exception | None

    _frames_tx: list[bytes]

    def test__packet_handler__icmp4__tx(self) -> None:
        """
        Ensure the Packet Handler ICMPv4 TX path produces the
        expected frames, statuses, and statistics for each
        parametrized case.
        """

        if self._expected__error is None:
            self.assertEqual(
                self._packet_handler._phtx_icmp4(**self._kwargs),
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
                self._packet_handler._phtx_icmp4(**self._kwargs)

            self.assertEqual(
                str(error.exception),
                str(self._expected__error),
                msg=f"Unexpected error message for case: {self._description}",
            )
