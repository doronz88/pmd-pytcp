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
This module contains close-during-delivery drain tests for sockets.

pmd_pytcp/tests/unit/socket/test__socket__close_drain.py

ver 3.0.7
"""

from __future__ import annotations

from typing import cast
from unittest import TestCase
from unittest.mock import MagicMock, patch

from pmd_net_proto.lib.enums import IpProto
from pmd_pytcp import stack
from pmd_pytcp.socket import AddressFamily
from pmd_pytcp.socket.raw__metadata import RawMetadata
from pmd_pytcp.socket.raw__socket import RawSocket
from pmd_pytcp.socket.tcp__socket import TcpSocket
from pmd_pytcp.socket.udp__metadata import UdpMetadata
from pmd_pytcp.socket.udp__socket import UdpSocket


class TestSocketCloseDrainUdp(TestCase):
    """
    The 'UdpSocket' close-during-delivery drain tests.
    """

    def setUp(self) -> None:
        """
        Silence the socket-module log line for the duration of the test.
        """

        self.enterContext(patch("pmd_pytcp.socket.udp__socket.log"))

    def test__udp_socket__delivery_after_close_is_dropped(self) -> None:
        """
        Ensure a 'process_udp_packet' that arrives after 'close()' is
        dropped — never appended to the closed socket's RX queue — so
        the RX thread cannot deliver a datagram onto a socket the
        application has already torn down.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock.close()

        sock.process_udp_packet(cast(UdpMetadata, MagicMock(spec=UdpMetadata)))

        self.assertEqual(
            len(sock._packet_rx_md),
            0,
            msg="Delivery to a closed UDP socket must be dropped, not queued.",
        )

    def test__udp_socket__delivery_before_close_is_queued(self) -> None:
        """
        Ensure a 'process_udp_packet' on an open socket still enqueues
        normally — the drain guard must not block live delivery.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = UdpSocket(family=AddressFamily.INET4)

        sock.process_udp_packet(cast(UdpMetadata, MagicMock(spec=UdpMetadata)))

        self.assertEqual(
            len(sock._packet_rx_md),
            1,
            msg="Delivery to an open UDP socket must enqueue normally.",
        )
        sock.close()

    def test__udp_socket__close_sets_closed_flag(self) -> None:
        """
        Ensure 'close()' marks the socket closed so subsequent
        delivery checks observe the closed state.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        self.assertFalse(sock._closed, msg="A fresh socket must not be marked closed.")

        sock.close()

        self.assertTrue(sock._closed, msg="close() must mark the socket closed.")


class TestTcpSocketCloseWithoutSession(TestCase):
    """
    The 'TcpSocket' session-less close tests.
    """

    def setUp(self) -> None:
        """
        Silence the socket-module log lines and isolate the global
        socket registry for the test duration.
        """

        self.enterContext(patch("pmd_pytcp.socket.tcp__socket.log"))
        self._sockets_prior = dict(stack.sockets)
        stack.sockets.clear()

    def tearDown(self) -> None:
        """
        Restore the global socket registry.
        """

        stack.sockets.clear()
        stack.sockets.update(self._sockets_prior)

    def test__tcp_socket__close_without_session_unregisters(self) -> None:
        """
        Ensure 'close()' on a bound-but-never-connected socket —
        which owns no TcpSession — unregisters the socket and
        releases its bound port. Only a session's CLOSED
        transition ever unregisters TCP sockets, so the old
        'assert _tcp_session is not None' left the registry entry
        (and the port, which the ephemeral-port pickers exclude
        while the entry exists) leaked with no recovery path:
        close() itself was the thing that raised.

        Reference: POSIX close(2) (valid on any open socket, connected or not).
        """

        sock = TcpSocket(family=AddressFamily.INET4)
        sock.bind(("0.0.0.0", 12345))
        self.assertIn(
            sock.socket_id,
            stack.sockets,
            msg="bind() must register the socket (test precondition).",
        )

        sock.close()

        self.assertNotIn(
            sock.socket_id,
            stack.sockets,
            msg="close() on a session-less socket must unregister it, releasing the port.",
        )
        self.assertTrue(sock._closed, msg="close() must mark the socket closed.")


class TestSocketCloseDrainRaw(TestCase):
    """
    The 'RawSocket' close-during-delivery drain tests.
    """

    def setUp(self) -> None:
        """
        Silence the socket-module log line for the duration of the test.
        """

        self.enterContext(patch("pmd_pytcp.socket.raw__socket.log"))

    def test__raw_socket__delivery_after_close_is_dropped(self) -> None:
        """
        Ensure a 'process_raw_packet' that arrives after 'close()' is
        dropped — never appended to the closed socket's RX queue.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        sock.close()

        sock.process_raw_packet(cast(RawMetadata, MagicMock(spec=RawMetadata)))

        self.assertEqual(
            len(sock._packet_rx_md),
            0,
            msg="Delivery to a closed RAW socket must be dropped, not queued.",
        )

    def test__raw_socket__delivery_before_close_is_queued(self) -> None:
        """
        Ensure a 'process_raw_packet' on an open socket still enqueues
        normally.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)

        sock.process_raw_packet(cast(RawMetadata, MagicMock(spec=RawMetadata)))

        self.assertEqual(
            len(sock._packet_rx_md),
            1,
            msg="Delivery to an open RAW socket must enqueue normally.",
        )
        sock.close()
