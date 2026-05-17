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
This module contains integration tests for the Packet Handler ARP RX operations.

pytcp/tests/integration/packet_handler/test__packet_handler__arp__rx.py

ver 3.0.5
"""

from parameterized import parameterized_class  # type: ignore[import-untyped]

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
                arp__op_request__tpa_unknown=1,
                arp__op_request__update_arp_cache=1,
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
                arp__op_request__tpa_unknown=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - unsupported ARP operation, drop",
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
                #   Operation       : 3 (unsupported)
                #   Sender MAC      : 02:00:00:00:00:91
                #   Sender IP       : 10.0.1.91
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.7
                #
                # Summary: Broadcast ARP frame with an unsupported operation code; parser rejects it.
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x03\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x5b"
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
                arp__op_request__tpa_stack=1,
                arp__op_request__respond=1,
                arp__op_request__update_arp_cache=1,
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
                arp__op_request__tpa_stack=1,
                arp__op_request__respond=1,
                arp__op_request__update_arp_cache=1,
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
            "_description": "Ethernet/ARP - request (SHA=00:00:00:00:00:00), drop",
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
                #   Sender MAC      : 00:00:00:00:00:00
                #   Sender IP       : 0.0.0.0
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.7
                #
                # Summary: SHA is 00:00:00:00:00:00 — drop packet.
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
        {
            "_description": "Ethernet/ARP - request probe (SPA=0.0.0.0) for stack IP, broadcasted",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 02:00:00:00:00:91
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4) — PROBE (DAD/announcement style request)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 1 (Request)
                #   Sender MAC      : 02:00:00:00:00:91
                #   Sender IP       : 0.0.0.0            (PROBE)
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.7           (our IP)
                #
                # Summary: Broadcast ARP probe (RFC 5227) — “Is 10.0.1.7 in use?”.
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x00\x00\x00\x00"
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
                #   Target IP       : 0.0.0.0
                #
                # Summary: Unicast ARP reply from 10.0.1.7 -> 02:00:00:00:00:91, TPA unspecified.
                b"\x02\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                b"\x02\x00\x00\x00\x00\x91\x00\x00\x00\x00",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__probe=1,
                arp__op_request__respond=1,
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
            "_description": "Ethernet/ARP - request with SPA == our IP -> send gratuitous ARP as defense",
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
                #   Sender IP       : 10.0.1.7
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.91
                #
                # Summary: Broadcast ARP request — “Who has 10.0.1.91? Tell 10.0.1.7.”
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x07"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x5b",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
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
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.7
                #
                # Summary: Broadcast Gratuitous ARP (reply flavor) — “10.0.1.7 is at 02:00:00:00:00:07.”
                #          (SPA == TPA, THA = 00:00:00:00:00:00)
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__conflict__defend=1,
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
            "_description": "Ethernet/ARP - request looped back: frame sourced from our own MAC, drop",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 1 (Request)
                #   Sender MAC      : 02:00:00:00:00:07
                #   Sender IP       : 10.0.1.7
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.91
                #
                # Summary: Broadcast ARP Request — “Who has 10.0.1.91? Tell 10.0.1.7 (02:00:00:00:00:07).”
                #          (THA = 00:00:00:00:00:00)
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x5b",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__looped__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - probe looped back: frame sourced from our own MAC, drop",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 02:00:00:00:00:07
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 1 (Request)
                #   Sender MAC      : 02:00:00:00:00:07
                #   Sender IP       : 0.0.0.0  (ARP Probe)
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.91
                #
                # Summary: Broadcast ARP Probe — “Who has 10.0.1.91? Tell 0.0.0.0 (02:00:00:00:00:07).”
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x07\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x5b",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__looped__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - request, SHA/Ethernet-src mismatch, drop",
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
                #   Sender MAC      : 52:54:00:df:85:37     # NOTE: differs from Ethernet src MAC
                #   Sender IP       : 10.0.1.91
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.7
                #
                # Summary: Broadcast ARP request — “Who has 10.0.1.7? Tell 10.0.1.91.”
                #          Warning: Ethernet source MAC (02:00:00:00:00:91) ≠ ARP SHA (52:54:00:df:85:37).
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x52\x54\x00\xdf\x85\x37\x0a\x00\x01\x5b"
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
        {
            "_description": "Ethernet/ARP - gratuitous request: SPA == TPA, broadcast dst, no reply expected",
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
                #   Target IP       : 10.0.1.91   (same as SPA)
                #
                # Summary: Gratuitous ARP Request — “Who has 10.0.1.91? Tell 10.0.1.91.” (announcement)
                #          We do not answer, but we still learn the SPA -> SHA mapping.
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x5b"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x5b",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__gratuitous=1,
                arp__op_request__update_arp_cache=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": (
                "Ethernet/ARP - gratuitous request announcing candidate IP 10.0.1.5 we are probing: "
                "conflict detected, no reply"
            ),
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
                #   Sender IP       : 10.0.1.5   (candidate address we are probing)
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.5   (same as SPA)
                #
                # Summary: Gratuitous ARP Request — “Who has 10.0.1.5? Tell 10.0.1.5.”
                #          (Announcement of an address we’re probing -> conflict)
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x05"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x05",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__gratuitous=1,
                arp__op_request__probe_conflict__gratuitous=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - reply, update ARP cache",
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
                arp__op_reply__direct=1,
                arp__op_reply__update_arp_cache=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - reply, gratuitous ARP, SPA == TPA, broadcast",
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
                arp__op_reply__gratuitous=1,
                arp__op_reply__update_arp_cache=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - reply, SHA != Ethernet.src, drop",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07
                #   Source MAC      : 02:00:00:00:00:92
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 2 (Reply)
                #   Sender MAC (SHA): 02:00:00:00:00:91    # NOTE: differs from Ethernet src MAC (…:92)
                #   Sender IP (SPA) : 10.0.1.91
                #   Target MAC (THA): 02:00:00:00:00:07
                #   Target IP (TPA) : 10.0.1.7
                #
                # Summary: Unicast ARP reply — “10.0.1.91 is at 02:00:00:00:00:91.”
                #          Warning: L2 src MAC ≠ ARP SHA (…:92 vs …:91) — some stacks will drop this as inconsistent.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x92\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x5b"
                b"\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                arp__pre_parse=1,
                arp__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - reply with unspecified SHA, drop",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07
                #   Source MAC      : 00:00:00:00:00:00   # unspecified / all zeros
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 2 (Reply)
                #   Sender MAC (SHA): 00:00:00:00:00:00   # invalid, must be unicast
                #   Sender IP (SPA) : 10.0.1.91
                #   Target MAC (THA): 02:00:00:00:00:07
                #   Target IP (TPA) : 10.0.1.7
                #
                # Summary: Unicast ARP reply claiming “10.0.1.91 is at 00:00:00:00:00:00.”
                #          Invalid — SHA is unspecified.
                b"\x02\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x5b"
                b"\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                arp__pre_parse=1,
                arp__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - reply with multicast SHA, drop",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07
                #   Source MAC      : 01:00:5e:00:00:01   # IPv4 multicast MAC (invalid as a host source)
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 2 (Reply)
                #   Sender MAC (SHA): 01:00:5e:00:00:01   # multicast; should be unicast for a valid ARP reply
                #   Sender IP (SPA) : 10.0.1.91
                #   Target MAC (THA): 02:00:00:00:00:07
                #   Target IP (TPA) : 10.0.1.7
                #
                # Summary: Unicast ARP reply purporting “10.0.1.91 is at 01:00:5e:00:00:01.”
                #          This is malformed/invalid because the sender MAC is a multicast address.
                #          Robust stacks typically drop ARP with non-unicast SHA
                #          (and often non-unicast Ethernet source).
                b"\x02\x00\x00\x00\x00\x07\x01\x00\x5e\x00\x00\x01\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x01\x00\x5e\x00\x00\x01\x0a\x00\x01\x5b"
                b"\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                arp__pre_parse=1,
                arp__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - reply with broadcast SHA, drop",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07
                #   Source MAC      : ff:ff:ff:ff:ff:ff   # broadcast (invalid as a host source)
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 2 (Reply)
                #   Sender MAC (SHA): ff:ff:ff:ff:ff:ff   # broadcast, not valid for ARP reply
                #   Sender IP (SPA) : 10.0.1.91
                #   Target MAC (THA): 02:00:00:00:00:07
                #   Target IP (TPA) : 10.0.1.7
                #
                # Summary: Unicast ARP reply claiming “10.0.1.91 is at ff:ff:ff:ff:ff:ff.”
                #          Invalid — SHA is broadcast, must be unicast.
                b"\x02\x00\x00\x00\x00\x07\xff\xff\xff\xff\xff\xff\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\xff\xff\xff\xff\xff\xff\x0a\x00\x01\x5b"
                b"\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                arp__pre_parse=1,
                arp__failed_parse__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - reply with SPA == our IP, send gratuitous ARP as defense",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07 (our MAC)
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
                #   Sender IP       : 10.0.1.7           (our IP — conflict)
                #   Target MAC      : 02:00:00:00:00:07  (our MAC)
                #   Target IP       : 10.0.1.7
                #
                # Summary: Unicast ARP reply claiming our IP (conflict). We must defend with a broadcast GARP.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x07"
                b"\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 02:00:00:00:00:07 (our MAC)
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 2 (Reply)
                #   Sender MAC      : 02:00:00:00:00:07  (our MAC)
                #   Sender IP       : 10.0.1.7           (our IP)
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.7
                #
                # Summary: Broadcast Gratuitous ARP (reply flavor) — “10.0.1.7 is at 02:00:00:00:00:07.”
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                arp__pre_parse=1,
                arp__op_reply=1,
                arp__op_reply__conflict__defend=1,
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
            "_description": "Ethernet/ARP - reply looped back: frame sourced from our own MAC, drop",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : ff:ff:ff:ff:ff:ff (broadcast)
                #   Source MAC      : 02:00:00:00:00:07 (our MAC)
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 2 (Reply)
                #   Sender MAC      : 02:00:00:00:00:07 (our MAC)
                #   Sender IP       : 10.0.1.7          (our IP)
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.7
                #
                # Summary: Broadcast Gratuitous ARP (reply flavor) that we originated (looped back).
                #          Must be dropped and not learned.
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_reply=1,
                arp__op_reply__looped__drop=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": (
                "Ethernet/ARP - gratuitous reply announcing candidate IP 10.0.1.5 we are probing: "
                "conflict detected, no learn/no reply"
            ),
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
                #   Sender IP       : 10.0.1.5   (candidate address we are probing)
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.5   (same as SPA)
                #
                # Summary: Gratuitous ARP Reply — “10.0.1.5 is at 02:00:00:00:00:91.”
                #          (Announcement of an address we’re probing -> conflict)
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x05"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x05",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_reply=1,
                arp__op_reply__gratuitous=1,
                arp__op_reply__probe_conflict__gratuitous=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": (
                "Ethernet/ARP - reply to our probe: SPA matches candidate IP we are probing, " "conflict detected"
            ),
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07 (our MAC, we sent probe)
                #   Source MAC      : 02:00:00:00:00:91 (foreign host)
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 44 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 2 (Reply)
                #   Sender MAC      : 02:00:00:00:00:91
                #   Sender IP       : 10.0.1.5   (candidate IP we’re probing)
                #   Target MAC      : 02:00:00:00:00:07 (our MAC)
                #   Target IP       : 0.0.0.0   (unspecified, per ARP probe reply)
                #
                # Summary: Foreign host responds to our ARP probe with a unicast ARP reply,
                # claiming the candidate IP. This indicates conflict -> we must not claim it.
                b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x05"
                b"\x02\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                arp__pre_parse=1,
                arp__op_reply=1,
                arp__op_reply__probe_conflict=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - reply, direct to our MAC, SPA in foreign subnet, no cache update",
            "_frames_rx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:07 (our MAC)
                #   Source MAC      : 52:54:00:df:85:37
                #   Ethertype       : 0x0806 (ARP)
                #   Frame length    : 42 bytes
                #
                # ARP (Ethernet/IPv4)
                #   Hardware type   : 1 (Ethernet)
                #   Protocol type   : 0x0800 (IPv4)
                #   HLEN / PLEN     : 6 / 4
                #   Operation       : 2 (Reply)
                #   Sender MAC      : 52:54:00:df:85:37
                #   Sender IP       : 192.168.9.102      (foreign subnet — not in 10.0.1.0/24)
                #   Target MAC      : 02:00:00:00:00:07  (our MAC)
                #   Target IP       : 10.0.1.7           (our IP)
                #
                # Summary: Unicast ARP reply addressed to us with an SPA outside any of our subnets.
                #          We process it as a direct reply but the cache update is silently skipped
                #          because SPA is not in any of our networks.
                b"\x02\x00\x00\x00\x00\x07\x52\x54\x00\xdf\x85\x37\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x52\x54\x00\xdf\x85\x37\xc0\xa8\x09\x66"
                b"\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_unicast=1,
                arp__pre_parse=1,
                arp__op_reply=1,
                arp__op_reply__direct=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": (
                "Ethernet/ARP - reply, gratuitous (SPA == TPA, broadcast), SPA in foreign subnet, " "no cache update"
            ),
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
                #   Operation       : 2 (Reply)
                #   Sender MAC      : 52:54:00:df:85:37
                #   Sender IP       : 192.168.9.102      (foreign subnet — not in 10.0.1.0/24)
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 192.168.9.102      (same as SPA)
                #
                # Summary: Broadcast Gratuitous ARP (reply flavor) — “192.168.9.102 is at 52:54:00:df:85:37.”
                #          We classify it as a gratuitous reply but skip the cache update because
                #          SPA is not in any of our networks.
                b"\xff\xff\xff\xff\xff\xff\x52\x54\x00\xdf\x85\x37\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x52\x54\x00\xdf\x85\x37\xc0\xa8\x09\x66"
                b"\x00\x00\x00\x00\x00\x00\xc0\xa8\x09\x66",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_reply=1,
                arp__op_reply__gratuitous=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": (
                "Ethernet/ARP - reply, broadcast non-gratuitous (SPA != TPA, THA set), " "cache update only"
            ),
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
                #   Sender IP       : 10.0.1.91
                #   Target MAC      : 02:00:00:00:00:07   (set, not unspecified)
                #   Target IP       : 10.0.1.7            (≠ SPA, so not gratuitous form)
                #
                # Summary: Broadcast ARP reply that is neither "direct" (dst != our MAC)
                #          nor "gratuitous" (SPA != TPA, THA != 0). Not RFC-defined; PyTCP
                #          falls through to __update_arp_cache and learns the SPA->SHA mapping
                #          because SPA is in our subnet. Pins current cache-injection-permissive
                #          behavior so future hardening will surface as a deliberate test change.
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x91\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x91\x0a\x00\x01\x5b"
                b"\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07",
            ],
            "_expected__frames_tx": [],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_reply=1,
                arp__op_reply__update_arp_cache=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(),
        },
        {
            "_description": "Ethernet/ARP - request from foreign SPA for our IP, respond, no cache update",
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
                #   Sender IP       : 192.168.9.102      (foreign subnet — not in 10.0.1.0/24)
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.7           (our IP)
                #
                # Summary: RFC 826-valid request from a foreign-subnet SPA for our IP.
                #          We must reply (TPA matches), but the cache update is skipped
                #          because SPA is not in any of our networks.
                b"\xff\xff\xff\xff\xff\xff\x52\x54\x00\xdf\x85\x37\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x52\x54\x00\xdf\x85\x37\xc0\xa8\x09\x66"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07",
            ],
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 52:54:00:df:85:37
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
                #   Target MAC      : 52:54:00:df:85:37
                #   Target IP       : 192.168.9.102
                #
                # Summary: Unicast ARP reply — “10.0.1.7 is at 02:00:00:00:00:07.”
                b"\x52\x54\x00\xdf\x85\x37\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                b"\x52\x54\x00\xdf\x85\x37\xc0\xa8\x09\x66",
            ],
            "_expected__packet_stats_rx": PacketStatsRx(
                ethernet__pre_parse=1,
                ethernet__dst_broadcast=1,
                arp__pre_parse=1,
                arp__op_request=1,
                arp__op_request__tpa_stack=1,
                arp__op_request__respond=1,
            ),
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_reply__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
    ]
)
class TestPacketHandlerArpRx(NetworkTestCase):
    """
    Test the Packet Handler ARP RX operations.
    """

    _description: str
    _frames_rx: list[bytes]
    _expected__frames_tx: list[bytes]
    _expected__packet_stats_rx: PacketStatsRx
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__packet_handler__arp__rx(self) -> None:
        """
        Ensure the Packet Handler processes the received ARP frames
        as expected for each parametrized case.
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
