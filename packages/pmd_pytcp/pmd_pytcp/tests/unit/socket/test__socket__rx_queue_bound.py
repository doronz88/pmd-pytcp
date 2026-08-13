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
This module contains the datagram rx-queue bound tests: a socket
the application does not drain must not buffer inbound datagrams
without limit — the UDP/RAW/PACKET rx queues were plain unbounded
lists, so any long-lived unread socket (worst case: the ACD ARP
defense socket, drained once per DHCP T1 — hours — while every ARP
broadcast on the segment lands in it) grew without bound. POSIX
full-receive-buffer semantics: the NEWEST datagram is dropped once
the queue is full.

pmd_pytcp/tests/unit/socket/test__socket__rx_queue_bound.py

ver 3.0.7
"""

from __future__ import annotations

from typing import cast
from unittest import TestCase
from unittest.mock import MagicMock, patch

from pmd_net_proto.lib.enums import IpProto
from pmd_pytcp.socket import SOCKET__DGRAM_RX_QUEUE__MAX_LEN, AddressFamily
from pmd_pytcp.socket.packet__metadata import PacketMetadata
from pmd_pytcp.socket.packet__socket import PacketSocket
from pmd_pytcp.socket.raw__metadata import RawMetadata
from pmd_pytcp.socket.raw__socket import RawSocket
from pmd_pytcp.socket.udp__metadata import UdpMetadata
from pmd_pytcp.socket.udp__socket import UdpSocket


class TestDatagramRxQueueBound(TestCase):
    """
    The datagram rx-queue bound tests.
    """

    def setUp(self) -> None:
        """
        Silence the socket-module log lines for the test duration.
        """

        self.enterContext(patch("pmd_pytcp.socket.udp__socket.log"))
        self.enterContext(patch("pmd_pytcp.socket.raw__socket.log"))
        self.enterContext(patch("pmd_pytcp.socket.packet__socket.log"))

    def test__udp_socket__rx_queue_is_bounded(self) -> None:
        """
        Ensure an unread UDP socket stops queueing datagrams at
        the cap — the newest datagram is dropped, POSIX
        full-receive-buffer semantics.

        Reference: POSIX recv(2)/udp(7) (datagrams beyond the receive buffer are discarded).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        for _ in range(SOCKET__DGRAM_RX_QUEUE__MAX_LEN + 10):
            sock.process_udp_packet(cast(UdpMetadata, MagicMock(spec=UdpMetadata)))

        self.assertEqual(
            len(sock._packet_rx_md),
            SOCKET__DGRAM_RX_QUEUE__MAX_LEN,
            msg="The UDP rx queue must not grow past its cap.",
        )
        sock.close()

    def test__raw_socket__rx_queue_is_bounded(self) -> None:
        """
        Ensure an unread RAW socket stops queueing packets at the
        cap.

        Reference: POSIX raw(7) (packets beyond the receive buffer are discarded).
        """

        sock = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        for _ in range(SOCKET__DGRAM_RX_QUEUE__MAX_LEN + 10):
            sock.process_raw_packet(cast(RawMetadata, MagicMock(spec=RawMetadata)))

        self.assertEqual(
            len(sock._packet_rx_md),
            SOCKET__DGRAM_RX_QUEUE__MAX_LEN,
            msg="The RAW rx queue must not grow past its cap.",
        )
        sock.close()

    def test__packet_socket__rx_queue_is_bounded(self) -> None:
        """
        Ensure an unread AF_PACKET socket stops queueing frames at
        the cap — the ACD ARP defense socket parks between polls
        for up to a DHCP T1 (hours) while every ARP broadcast on
        the segment lands in it.

        Reference: POSIX packet(7) (frames beyond the receive buffer are discarded).
        """

        sock = PacketSocket()
        try:
            for _ in range(SOCKET__DGRAM_RX_QUEUE__MAX_LEN + 10):
                sock.process_packet(cast(PacketMetadata, MagicMock(spec=PacketMetadata)))

            self.assertEqual(
                len(sock._packet_rx_md),
                SOCKET__DGRAM_RX_QUEUE__MAX_LEN,
                msg="The AF_PACKET rx queue must not grow past its cap.",
            )
        finally:
            sock.close()
