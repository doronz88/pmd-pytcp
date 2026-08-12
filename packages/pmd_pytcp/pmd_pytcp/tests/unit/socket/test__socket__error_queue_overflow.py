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
This module contains the error-queue overflow accounting tests:
the per-socket ICMP error queue is a bounded deque that drops its
oldest entry on overflow, so the readability semaphore must count
only entries that actually remain queued — an unconditional
release() per append accumulates phantom permits during an ICMP
error burst, and the (N+1)th 'recvmsg(MSG_ERRQUEUE)' then acquires
a permit for an empty deque and crashes with IndexError.

pmd_pytcp/tests/unit/socket/test__socket__error_queue_overflow.py

ver 3.0.7
"""

from __future__ import annotations

from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

from pmd_net_addr import Ip4Address
from pmd_pytcp.socket import MSG_ERRQUEUE, AddressFamily
from pmd_pytcp.socket.error_queue import ERROR_QUEUE__MAX_LEN
from pmd_pytcp.socket.tcp__socket import TcpSocket
from pmd_pytcp.socket.udp__socket import UdpSocket

OFFENDER_IP = Ip4Address("10.0.0.9")


class TestSocketErrorQueueOverflow(IsolatedAsyncioTestCase):
    """
    The bounded error-queue overflow accounting tests.
    """

    def setUp(self) -> None:
        """
        Silence the socket-module log lines for the test duration.
        """

        self.enterContext(patch("pmd_pytcp.socket.udp__socket.log"))
        self.enterContext(patch("pmd_pytcp.socket.tcp__socket.log"))

    async def _drain_and_expect_clean_empty(self, sock: "UdpSocket | TcpSocket") -> None:
        """
        Drain every queued error entry, then assert the next
        non-blocking dequeue reports an EMPTY queue (BlockingIOError
        / TimeoutError) instead of crashing on a phantom permit.
        """

        for _ in range(ERROR_QUEUE__MAX_LEN):
            await sock.recvmsg(flags=int(MSG_ERRQUEUE), timeout=0)

        with self.assertRaises(
            (BlockingIOError, TimeoutError),
            msg="Draining past the queued entries must report an empty queue, not crash.",
        ):
            await sock.recvmsg(flags=int(MSG_ERRQUEUE), timeout=0)

    async def test__udp_socket__error_queue_overflow_keeps_semaphore_in_sync(self) -> None:
        """
        Ensure an ICMP error burst that overflows the UDP error
        queue leaves the readability semaphore matching the deque:
        the overflow drops the oldest entry, so the drop's permit
        must not survive it.

        Reference: Linux ip(7) IP_RECVERR (bounded error queue).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock._ip_recverr = True

        for _ in range(ERROR_QUEUE__MAX_LEN + 8):
            sock.notify_unreachable(offender_ip=OFFENDER_IP, embedded_datagram=b"x")

        await self._drain_and_expect_clean_empty(sock)
        sock.close()

    async def test__tcp_socket__error_queue_overflow_keeps_semaphore_in_sync(self) -> None:
        """
        Ensure the TCP error queue keeps the same overflow
        accounting as the UDP one (the producer shape is shared).

        Reference: Linux ip(7) IP_RECVERR (bounded error queue).
        """

        sock = TcpSocket(family=AddressFamily.INET4)
        sock._ip_recverr = True

        for _ in range(ERROR_QUEUE__MAX_LEN + 8):
            sock.notify_unreachable(offender_ip=OFFENDER_IP, embedded_datagram=b"x")

        await self._drain_and_expect_clean_empty(sock)
