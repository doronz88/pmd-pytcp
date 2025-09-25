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
# pyright: reportUnknownMemberType=false


"""
This module contains base testcase for PyTCP Packet Handler tests.

pytcp/tests/unit/test__packet_handle__arp__tx.py

ver 3.0.4
"""


from typing import cast

from testslide import TestCase
from testslide.strict_mock import StrictMock

from net_addr import Ip4Address, Ip4Host, Ip6Address, Ip6Host, MacAddress
from net_proto.lib.buffer import Buffer
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from pytcp import stack
from pytcp.stack.arp_cache import ArpCache
from pytcp.stack.nd_cache import NdCache
from pytcp.stack.packet_handler import PacketHandlerL2
from pytcp.stack.tx_ring import TxRing

# # #  IPv4
#
#           .7  10.0.1.0/24  .1          .1  10.0.2.0/24  .50
#   [STACK] ------------------- [ROUTER] -------------------- [HOST C]
#             |
#             |   .91
#             |------ [HOST A] (working arp cache resolution)
#             |
#             |   .92
#             |------ [HOST B] (not working arp cache resolution)
#

# # #  IPv6
#
#        .7  2001:db8:0:1::/64  .1    .1  2001:db8:0:2::/64  .50
#        .7  fe80::/64          .1    .1  fe80::             .50
#   [STACK] ------------------- [ROUTER A] -------------------- [HOST C]
#             |
#             |    .2
#             |------ [ROUTER B] (not working nd cache resolution)
#             |
#             |   .91
#             |------ [HOST A] (working nd cache resolution)
#             |
#             |   .92
#             |------ [HOST B] (not working nd cache resolution)
#

# Set the PyTCP stack addressing.
STACK__MAC_ADDRESS = MacAddress("02:00:00:00:00:07")
STACK__IP4_HOST = Ip4Host("10.0.1.7/24")
STACK__IP4_GATEWAY = Ip4Address("10.0.1.1")
STACK__IP4_HOST.gateway = STACK__IP4_GATEWAY
STACK__IP4_GATEWAY_MAC_ADDRESS = MacAddress("02:00:00:00:00:01")
STACK__IP6_HOST = Ip6Host("2001:db8:0:1::7/64")
STACK__IP6_GATEWAY = Ip6Address("fe80::1")
STACK__IP6_HOST.gateway = STACK__IP6_GATEWAY
STACK__IP6_GATEWAY_MAC_ADDRESS = MacAddress("02:00:00:00:00:01")

# Set the test device's addressing.
HOST_A__MAC_ADDRESS = MacAddress("02:00:00:00:00:91")
HOST_A__IP4_ADDRESS = Ip4Address("10.0.1.91")
HOST_A__IP6_ADDRESS = Ip6Address("2001:db8:0:1::91")
HOST_B__IP4_ADDRESS = Ip4Address("10.0.1.92")
HOST_B__IP6_ADDRESS = Ip6Address("2001:db8:0:1::92")
HOST_C__IP4_ADDRESS = Ip4Address("10.0.2.50")
HOST_C__IP6_ADDRESS = Ip6Address("2001:db8:0:2::50")
ROUTER_B__IP6_ADDRESS = Ip6Address("fe80::2")

# Set common addresses.
MAC__UNSPECIFIED = MacAddress("00:00:00:00:00:00")
MAC__BROADCAST = MacAddress("ff:ff:ff:ff:ff:ff")
IP4__UNSPECIFIED = Ip4Address("0.0.0.0")
IP4__BROADCAST__LIMITED = Ip4Address("255.255.255.255")
IP4__MULTICAST__ALL_NODES = Ip4Address("224.0.0.1")
IP6__UNSPECIFIED = Ip6Address("::")
IP6__MULTICAST__ALL_NODES = Ip6Address("ff01::1")
IP6__MULTICAST__ALL_ROUTERS = Ip6Address("ff01::2")


class NetworkTestCase(TestCase):
    """
    Base class for all unit tests that require mock network.
    """

    _frames_tx: list[bytes]

    _packet_handler: PacketHandlerL2

    def setUp(self) -> None:
        """
        Prepare the test case.
        """

        self.maxDiff = None

        super().setUp()

        # Patch the PyTCP stack settings to values suitable for unit tests.
        stack.__dict__.update(
            {
                "LOG__CHANNEL": set(),
                "IP6__SUPPORT": True,
                "IP4__SUPPORT": True,
                "INTERFACE__TAP__MTU": 1500,
                "INTERFACE__TUN__MTU": 1500,
            }
        )

        # Create mock Packet Handler object and prepare it for tests.

        def _mock_enqueue(packet_tx: EthernetAssembler) -> None:
            """
            Mock 'TxRing.enqueue()' method to record the assembled frames.
            """

            buffers: list[Buffer] = []
            packet_tx.assemble(buffers)
            frame_tx = b"".join(buffers)

            self.assertEqual(
                frame_tx,
                bytes(packet_tx),
                "Mismatch between output of 'assemble()' and 'bytes()' methods.",
            )

            self._frames_tx.append(frame_tx)

        # Mock the TxRing so we can record the assembled frames.
        mock_TxRing = cast(TxRing, StrictMock(template=TxRing))

        self.mock_callable(
            target=mock_TxRing,
            method="enqueue",
        ).with_implementation(
            func=_mock_enqueue,
        )

        # Mock the ArpCache so we can get predictable responses.
        mock_ArpCache = cast(ArpCache, StrictMock(template=ArpCache))

        self.mock_callable(
            target=mock_ArpCache,
            method="find_entry",
        ).for_call(
            ip4_address=HOST_A__IP4_ADDRESS
        ).to_return_value(HOST_A__MAC_ADDRESS)

        self.mock_callable(
            target=mock_ArpCache,
            method="find_entry",
        ).for_call(
            ip4_address=HOST_B__IP4_ADDRESS
        ).to_return_value(None)

        self.mock_callable(
            target=mock_ArpCache,
            method="find_entry",
        ).for_call(
            ip4_address=STACK__IP4_GATEWAY
        ).to_return_value(STACK__IP4_GATEWAY_MAC_ADDRESS)

        # Mock the NdCache so we can get predictable responses.
        mock_NdCache = cast(NdCache, StrictMock(template=NdCache))

        self.mock_callable(
            target=mock_NdCache,
            method="find_entry",
        ).for_call(
            ip6_address=HOST_A__IP6_ADDRESS
        ).to_return_value(HOST_A__MAC_ADDRESS)

        self.mock_callable(
            target=mock_NdCache,
            method="find_entry",
        ).for_call(
            ip6_address=HOST_B__IP6_ADDRESS
        ).to_return_value(None)

        self.mock_callable(
            target=mock_NdCache,
            method="find_entry",
        ).for_call(
            ip6_address=STACK__IP6_GATEWAY
        ).to_return_value(STACK__IP6_GATEWAY_MAC_ADDRESS)

        self.mock_callable(
            target=mock_NdCache,
            method="find_entry",
        ).for_call(
            ip6_address=ROUTER_B__IP6_ADDRESS
        ).to_return_value(None)

        # Prepare PacketHandler object to be used with the tests.
        self._packet_handler = PacketHandlerL2(
            mac_address=STACK__MAC_ADDRESS,
            interface_mtu=1500,
        )

        self._packet_handler._mac_multicast = [
            STACK__IP6_HOST.address.solicited_node_multicast.multicast_mac
        ]
        self._packet_handler._ip4_host = [STACK__IP4_HOST]
        self._packet_handler._ip4_multicast = [IP4__MULTICAST__ALL_NODES]
        self._packet_handler._ip6_host = [STACK__IP6_HOST]
        self._packet_handler._ip6_multicast = [
            IP6__MULTICAST__ALL_NODES,
            STACK__IP6_HOST.address.solicited_node_multicast,
        ]

        # Initialize the list holding the frames "sent" by mock TxRing.
        self._frames_tx = []

        stack.mock__init(
            mock__tx_ring=mock_TxRing,
            mock__arp_cache=mock_ArpCache,
            mock__nd_cache=mock_NdCache,
            mock__packet_handler=self._packet_handler,
        )
