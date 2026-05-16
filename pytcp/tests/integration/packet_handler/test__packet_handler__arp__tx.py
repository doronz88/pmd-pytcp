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
This module contains integration tests for the Packet Handler ARP TX operations.

pytcp/tests/integration/packet_handler/test__packet_handler__arp__tx.py

ver 3.0.5
"""

from typing import Any

from parameterized import parameterized_class  # type: ignore

from net_proto import ArpOperation
from pytcp.lib.packet_stats import PacketStatsTx
from pytcp.lib.tx_status import TxStatus
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    MAC__BROADCAST,
    MAC__UNSPECIFIED,
    STACK__IP4_HOST,
    STACK__IP4_HOST__CANDIDATE,
    STACK__MAC_ADDRESS,
    NetworkTestCase,
)


@parameterized_class(
    [
        {
            "_description": "Ethernet/ARP - request, broadcast resolution lookup",
            "_kwargs": {
                "ethernet__src": STACK__MAC_ADDRESS,
                "ethernet__dst": MAC__BROADCAST,
                "arp__oper": ArpOperation.REQUEST,
                "arp__sha": STACK__MAC_ADDRESS,
                "arp__spa": STACK__IP4_HOST.address,
                "arp__tha": MAC__UNSPECIFIED,
                "arp__tpa": HOST_A__IP4_ADDRESS,
            },
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
                #   Operation       : 1 (Request)
                #   Sender MAC      : 02:00:00:00:00:07
                #   Sender IP       : 10.0.1.7
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.91
                #
                # Summary: Broadcast ARP request — “Who has 10.0.1.91? Tell 10.0.1.7.”
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x5b",
            ],
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_request__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
            "_expected__error": None,
        },
        {
            "_description": "Ethernet/ARP - reply, unicast direct response",
            "_kwargs": {
                "ethernet__src": STACK__MAC_ADDRESS,
                "ethernet__dst": HOST_A__MAC_ADDRESS,
                "arp__oper": ArpOperation.REPLY,
                "arp__sha": STACK__MAC_ADDRESS,
                "arp__spa": STACK__IP4_HOST.address,
                "arp__tha": HOST_A__MAC_ADDRESS,
                "arp__tpa": HOST_A__IP4_ADDRESS,
            },
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
            "_expected__tx_status": TxStatus.PASSED__ETHERNET__TO_TX_RING,
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
class TestPacketHandlerArpTx(NetworkTestCase):
    """
    Test the Packet Handler ARP TX operations (success path).
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__frames_tx: list[bytes]
    _expected__tx_status: TxStatus
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__packet_handler__arp__tx(self) -> None:
        """
        Ensure the Packet Handler ARP TX path produces the expected
        frames, statuses, and statistics for each parametrized case.
        """

        self.assertEqual(
            self._packet_handler._phtx_arp(**self._kwargs),
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


@parameterized_class(
    [
        {
            "_description": "Ethernet/ARP - invalid ArpOperation, raises ValueError",
            "_kwargs": {
                "ethernet__src": STACK__MAC_ADDRESS,
                "ethernet__dst": MAC__BROADCAST,
                # ArpOperation.from_int extends the enum with UNKNOWN_<value>;
                # this is the only way to construct an out-of-spec member that
                # exercises the 'case _:' arm in '_phtx_arp'.
                "arp__oper": ArpOperation.from_int(0x55),
                "arp__sha": STACK__MAC_ADDRESS,
                "arp__spa": STACK__IP4_HOST.address,
                "arp__tha": MAC__UNSPECIFIED,
                "arp__tpa": HOST_A__IP4_ADDRESS,
            },
            "_expected__error": ValueError("Invalid ARP operation: Unknown 85"),
        },
    ]
)
class TestPacketHandlerArpTxErrors(NetworkTestCase):
    """
    Test the Packet Handler ARP TX operations (error path).
    """

    _description: str
    _kwargs: dict[str, Any]
    _expected__error: Exception

    def test__packet_handler__arp__tx__error(self) -> None:
        """
        Ensure the Packet Handler ARP TX path raises the expected
        exception for each parametrized case.
        """

        with self.assertRaises(type(self._expected__error)) as error:
            self._packet_handler._phtx_arp(**self._kwargs)

        self.assertEqual(
            str(error.exception),
            str(self._expected__error),
            msg=f"Unexpected error message for case: {self._description}",
        )


class TestPacketHandlerArpTxNoIp4Support(NetworkTestCase):
    """
    Test the Packet Handler ARP TX path when IPv4 protocol support is
    disabled — '_phtx_arp' must short-circuit before assembly.
    """

    def setUp(self) -> None:
        """
        Build the standard mock stack, then disable IPv4 protocol
        support on the packet handler so the ARP TX path takes the
        no-protocol-support branch.
        """

        super().setUp()
        self._packet_handler._ip4_support = False

    def test__packet_handler__arp__tx__no_ip4_support(self) -> None:
        """
        Ensure '_phtx_arp' returns 'DROPPED__ARP__NO_PROTOCOL_SUPPORT'
        and bumps the 'arp__no_proto_support__drop' stat without
        emitting any frame when IPv4 support is disabled.
        """

        tx_status = self._packet_handler._phtx_arp(
            ethernet__src=STACK__MAC_ADDRESS,
            ethernet__dst=MAC__BROADCAST,
            arp__oper=ArpOperation.REQUEST,
            arp__sha=STACK__MAC_ADDRESS,
            arp__spa=STACK__IP4_HOST.address,
            arp__tha=MAC__UNSPECIFIED,
            arp__tpa=HOST_A__IP4_ADDRESS,
        )

        self.assertEqual(
            tx_status,
            TxStatus.DROPPED__ARP__NO_PROTOCOL_SUPPORT,
            msg="'_phtx_arp' must return 'DROPPED__ARP__NO_PROTOCOL_SUPPORT' when IPv4 is disabled.",
        )

        self.assertEqual(
            self._frames_tx,
            [],
            msg="No frame must be emitted when IPv4 protocol support is disabled.",
        )

        self.assertEqual(
            self._packet_handler.packet_stats_tx,
            PacketStatsTx(
                arp__pre_assemble=1,
                arp__no_proto_support__drop=1,
            ),
            msg="Only 'arp__pre_assemble' and 'arp__no_proto_support__drop' must be bumped.",
        )


@parameterized_class(
    [
        {
            "_description": "_send_arp_announcement - gratuitous request claiming our IP",
            "_method_name": "_send_arp_announcement",
            "_kwargs": {"ip4_unicast": STACK__IP4_HOST.address},
            "_clear_ip4_host": False,
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
                #   Operation       : 1 (Request)
                #   Sender MAC      : 02:00:00:00:00:07
                #   Sender IP       : 10.0.1.7
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.7   (= SPA — gratuitous announcement)
                #
                # Summary: ARP Announcement (RFC 5227) — broadcast gratuitous request,
                #          SPA == TPA, claiming 10.0.1.7.
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07",
            ],
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_request__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "_send_gratuitous_arp - gratuitous reply announcing our IP",
            "_method_name": "_send_gratuitous_arp",
            "_kwargs": {"ip4_unicast": STACK__IP4_HOST.address},
            "_clear_ip4_host": False,
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
                #   Target IP       : 10.0.1.7   (= SPA — gratuitous announcement)
                #
                # Summary: Gratuitous ARP (reply flavor) — broadcast unsolicited reply,
                #          SPA == TPA, announcing 10.0.1.7 -> 02:00:00:00:00:07.
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x02\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x07",
            ],
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_reply__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "_send_arp_probe - probe for candidate IP (RFC 5227 §2.1.1)",
            "_method_name": "_send_arp_probe",
            "_kwargs": {"ip4_unicast": STACK__IP4_HOST__CANDIDATE.address},
            "_clear_ip4_host": False,
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
                #   Operation       : 1 (Request)
                #   Sender MAC      : 02:00:00:00:00:07
                #   Sender IP       : 0.0.0.0    (RFC 5227 probe: SPA unspecified)
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.5   (candidate IP)
                #
                # Summary: ARP Probe (RFC 5227) — “Is 10.0.1.5 in use? Replies tell me.”
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x07\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x05",
            ],
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_request__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "_send_arp_reply - unicast reply to peer",
            "_method_name": "_send_arp_reply",
            "_kwargs": {
                "arp__spa": STACK__IP4_HOST.address,
                "arp__tha": HOST_A__MAC_ADDRESS,
                "arp__tpa": HOST_A__IP4_ADDRESS,
            },
            "_clear_ip4_host": False,
            "_expected__frames_tx": [
                # Ethernet II
                #   Destination MAC : 02:00:00:00:00:91 (= arp__tha)
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
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_reply__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "send_arp_request - resolution lookup with own IP populated",
            "_method_name": "send_arp_request",
            "_kwargs": {"arp__tpa": HOST_A__IP4_ADDRESS},
            "_clear_ip4_host": False,
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
                #   Operation       : 1 (Request)
                #   Sender MAC      : 02:00:00:00:00:07
                #   Sender IP       : 10.0.1.7   (first entry of '_ip4_unicast')
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.91
                #
                # Summary: Broadcast ARP request — “Who has 10.0.1.91? Tell 10.0.1.7.”
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x07\x0a\x00\x01\x07"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x5b",
            ],
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_request__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
        {
            "_description": "send_arp_request - resolution lookup with empty '_ip4_unicast' (pre-DAD)",
            "_method_name": "send_arp_request",
            "_kwargs": {"arp__tpa": HOST_A__IP4_ADDRESS},
            "_clear_ip4_host": True,
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
                #   Operation       : 1 (Request)
                #   Sender MAC      : 02:00:00:00:00:07
                #   Sender IP       : 0.0.0.0    ('_ip4_unicast' is empty -> default 'Ip4Address()')
                #   Target MAC      : 00:00:00:00:00:00
                #   Target IP       : 10.0.1.91
                #
                # Summary: Broadcast ARP request issued before DAD has assigned a stack IP;
                #          'send_arp_request' falls back to the unspecified SPA.
                b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06\x00\x01"
                b"\x08\x00\x06\x04\x00\x01\x02\x00\x00\x00\x00\x07\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x0a\x00\x01\x5b",
            ],
            "_expected__packet_stats_tx": PacketStatsTx(
                arp__pre_assemble=1,
                arp__op_request__send=1,
                ethernet__pre_assemble=1,
                ethernet__src_spec=1,
                ethernet__dst_spec__send=1,
            ),
        },
    ]
)
class TestPacketHandlerArpTxHelpers(NetworkTestCase):
    """
    Test the Packet Handler ARP TX helper methods that compose
    '_phtx_arp' calls (_send_arp_announcement, _send_gratuitous_arp,
    _send_arp_probe, _send_arp_reply, send_arp_request).
    """

    _description: str
    _method_name: str
    _kwargs: dict[str, Any]
    _clear_ip4_host: bool
    _expected__frames_tx: list[bytes]
    _expected__packet_stats_tx: PacketStatsTx

    _frames_tx: list[bytes]

    def test__packet_handler__arp__tx__helper(self) -> None:
        """
        Ensure each ARP TX helper method emits the expected wire frame
        and bumps the expected TX statistics.
        """

        if self._clear_ip4_host:
            self._packet_handler._ip4_ifaddr = []

        getattr(self._packet_handler, self._method_name)(**self._kwargs)

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
