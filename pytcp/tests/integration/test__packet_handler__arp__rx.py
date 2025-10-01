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


from parameterized import parameterized_class  # type: ignore

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.tests.lib.network_testcase import NetworkTestCase


@parameterized_class(
    [
        {
            "_description": "Ethernet/ARP - request, unknown TPA on local network",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 1 (Request)
                #   Sender MAC      : 02:00:00:00:00:91
                #   Sender IP       : 10.0.1.91
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.92
                #
                # Summary: Broadcast ARP request — “Who has 10.0.1.92? Tell 10.0.1.91.”
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x5b"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x5c",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__update_arp_cache_other=1,
                arp__op_request__tpa_unknown__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - request, unknown TPA on another network",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 52:54:00:df:85:37
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 1 (Request)
                #   Sender MAC      : 52:54:00:df:85:37
                #   Sender IP       : 192.168.9.102
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 192.168.9.55
                #
                # Summary: Broadcast ARP request — “Who has 192.168.9.55? Tell 192.168.9.102.”
                b"\xff\xff\xff\xff\xff\xff\x52\x54\x00\xdf\x85\x37\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x52\x54\x00\xdf\x85\x37\xc0\xa8\x09\x66"
                b"\x00\x00\x00\x00\x00\x00\xc0\xa8\x09\x37",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__tpa_unknown__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - request for stack MAC, broadcasted",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 1 (Request)
                #   Sender MAC      : 02:00:00:00:00:91
                #   Sender IP       : 10.0.1.91
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.7
                #
                # Summary: Broadcast ARP request — “Who has 10.0.1.7? Tell 10.0.1.91.”
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x5b"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 2 (Reply)
                #   Sender MAC      : 02:00:00:00:00:07
                #   Sender IP       : 10.0.1.7
                #   Target MAC      : 02:00:00:00:00:91
                #   Target IP       : 10.0.1.91
                #
                # Summary: Unicast ARP reply — “10.0.1.7 is at 02:00:00:00:00:07.”
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                b"\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x5b",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__tpa_stack__respond=1,
                arp__op_request__update_arp_cache_direct=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_reply__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "Ethernet/ARP - request for stack MAC, unicasted",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 1 (Request)
                #   Sender MAC      : 02:00:00:00:00:91
                #   Sender IP       : 10.0.1.91
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.7
                #
                # Summary: Unicast ARP request — “Who has 10.0.1.7? Tell 10.0.1.91.”
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x5b"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 2 (Reply)
                #   Sender MAC      : 02:00:00:00:00:07
                #   Sender IP       : 10.0.1.7
                #   Target MAC      : 02:00:00:00:00:91
                #   Target IP       : 10.0.1.91
                #
                # Summary: Unicast ARP reply — “10.0.1.7 is at 02:00:00:00:00:07.”
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                b"\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x5b",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__tpa_stack__respond=1,
                arp__op_request__update_arp_cache_direct=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_reply__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "Ethernet/ARP - reply received, update ARP cache",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 2 (Reply)
                #   Sender MAC      : 02:00:00:00:00:91
                #   Sender IP       : 10.0.1.91
                #   Target MAC      : 02:00:00:00:00:07
                #   Target IP       : 10.0.1.7
                #
                # Summary: Unicast ARP reply — “10.0.1.91 is at 02:00:00:00:00:91.”
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x5b"
                b"\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                arp__pre_parse=1,
                arp__op_reply=1,
                arp__op_reply__update_arp_cache_direct=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - gratuitous ARP received (SPA == TPA, broadcast)",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 2 (Reply)
                #   Sender MAC      : 02:00:00:00:00:91
                #   Sender IP       : 10.0.1.145
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.145
                #
                # Summary: Broadcast Gratuitous ARP (reply flavor) — “10.0.1.145 is at 02:00:00:00:00:91.”
                #          (TPA = SPA, THA all zeros)
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x91"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x91",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_reply=1,
                arp__op_reply__update_arp_cache_gratuitous=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - bogon request (SHA=00:00:00:00:00:00), drop",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 1 (Request)
                #   Sender MAC      : 00:00:00:00:00:00   # ARP Probe (SHA = 0)
                #   Sender IP       : 0.0.0.0             # ARP Probe (SPA = 0.0.0.0)
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.7
                #
                # Summary: ARP Probe for 10.0.1.7 from host with Ethernet MAC 02:00:00:00:00:91.
                #          Per RFC 5227, this is a probe (SHA=0, SPA=0.0.0.0); receivers should not reply.
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
    ]
)
class TestPacketHandlerArpRx(NetworkTestCase):
    """
    Test the Packet Handler ARP RX operations.
    """

    _description: str
    _frames_rx: list[bytes]
    _expected__frames_tx: list[bytes] | None
    _expected__packet_stats_rx: PacketStatsRx | None
    _expected__packet_stats_tx: PacketStatsTx | None

    _frames_tx: list[bytes]

    def test__packet_handler__arp__rx(self) -> None:
        """
        Validate that receiving ARP packet works as expected.
        """

        for frame_rx in self._frames_rx:
            self._packet_handler._phrx_ethernet(PacketRx(frame_rx))

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
