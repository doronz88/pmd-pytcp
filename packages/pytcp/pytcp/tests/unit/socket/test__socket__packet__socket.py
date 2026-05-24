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


"""
This module contains tests for the AF_PACKET raw link-layer socket
('PacketSocket') Phase-0 skeleton — construction, ethertype / ifindex
defaults, and the log-string representation.

pytcp/tests/unit/socket/test__socket__packet__socket.py

ver 3.0.6
"""

from typing import override
from unittest import TestCase
from unittest.mock import patch

from net_proto.lib.enums import EtherType
from pytcp.socket import (
    ETH_P_ALL,
    ETH_P_ARP,
    AddressFamily,
    SocketType,
)
from pytcp.socket.packet__socket import PacketSocket


class TestPacketSocket(TestCase):
    """
    The AF_PACKET 'PacketSocket' Phase-0 skeleton tests.
    """

    @override
    def setUp(self) -> None:
        """
        Suppress packet-socket construction log output and register
        cleanup of each socket's backing eventfd.
        """

        self.enterContext(patch("pytcp.socket.packet__socket.log"))

    def _make(self, *, protocol: EtherType | int | None = None) -> PacketSocket:
        """
        Build a 'PacketSocket' and register its eventfd for cleanup.
        """

        sock = PacketSocket(
            family=AddressFamily.PACKET,
            type=SocketType.RAW,
            protocol=protocol,
        )
        self.addCleanup(sock._close_io_runtime)
        return sock

    def test__packet_socket__family_and_type(self) -> None:
        """
        Ensure a 'PacketSocket' reports the PACKET address family and the
        RAW socket type through the base-class property surface.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._make()

        self.assertIs(
            sock.address_family,
            AddressFamily.PACKET,
            msg="PacketSocket.address_family must be AddressFamily.PACKET.",
        )
        self.assertIs(
            sock.socket_type,
            SocketType.RAW,
            msg="PacketSocket.socket_type must be SocketType.RAW.",
        )

    def test__packet_socket__default_protocol_is_eth_p_all(self) -> None:
        """
        Ensure constructing a 'PacketSocket' with no protocol defaults
        its ethertype filter to ETH_P_ALL (capture-all) and leaves it
        unbound from any interface (ifindex 0).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._make()

        self.assertEqual(
            sock.ethertype,
            ETH_P_ALL,
            msg="A PacketSocket with no protocol must default to the ETH_P_ALL filter.",
        )
        self.assertEqual(
            sock.ifindex,
            0,
            msg="A freshly-constructed PacketSocket must be unbound (ifindex 0).",
        )

    def test__packet_socket__explicit_ethertype(self) -> None:
        """
        Ensure an explicit ethertype protocol is stored verbatim as the
        socket's capture / delivery filter.

        Reference: RFC 826 (ARP ethertype 0x0806).
        """

        sock = self._make(protocol=ETH_P_ARP)

        self.assertEqual(
            sock.ethertype,
            EtherType.ARP,
            msg="PacketSocket must store the supplied ethertype filter verbatim.",
        )

    def test__packet_socket__str_format(self) -> None:
        """
        Ensure '__str__' renders the canonical
        'PACKET/RAW/<ethertype>/if<ifindex>' log string.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = self._make(protocol=ETH_P_ARP)

        self.assertEqual(
            str(sock),
            "PACKET/RAW/0x0806/if0",
            msg="PacketSocket.__str__ must render the canonical link-socket log string.",
        )

    def test__packet_socket__rejects_non_raw_type(self) -> None:
        """
        Ensure constructing a 'PacketSocket' with a non-RAW socket type
        is rejected — the Phase-0 skeleton supports SOCK_RAW only.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            PacketSocket(
                family=AddressFamily.PACKET,
                type=SocketType.DGRAM,
                protocol=ETH_P_ALL,
            )
