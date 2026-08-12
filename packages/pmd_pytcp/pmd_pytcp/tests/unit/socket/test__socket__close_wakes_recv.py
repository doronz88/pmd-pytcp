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
This module contains the datagram-socket close-wakes-recv tests:
'close()' (and stack teardown through it) must wake every blocked
'recv()'-family waiter with EBADF instead of leaving it parked on
the rx semaphore forever — the default socket mode is blocking with
no timeout, so an unwoken waiter (and its task, and everything the
task references) leaks for the loop's lifetime.

pmd_pytcp/tests/unit/socket/test__socket__close_wakes_recv.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import errno
from typing import Union
from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

from pmd_net_proto.lib.enums import IpProto
from pmd_pytcp import stack
from pmd_pytcp.socket import AddressFamily
from pmd_pytcp.socket.packet__socket import PacketSocket
from pmd_pytcp.socket.raw__socket import RawSocket
from pmd_pytcp.socket.udp__socket import UdpSocket
from pmd_pytcp.stack import lifecycle

_AnySocket = Union[UdpSocket, RawSocket, PacketSocket]


class _CloseWakesRecvFixture(IsolatedAsyncioTestCase):
    """
    Shared helpers: park a recv() task and assert it is genuinely
    blocked before the close under test fires.
    """

    def setUp(self) -> None:
        """
        Silence the socket-module log lines for the test duration.
        """

        self.enterContext(patch("pmd_pytcp.socket.udp__socket.log"))
        self.enterContext(patch("pmd_pytcp.socket.raw__socket.log"))
        self.enterContext(patch("pmd_pytcp.socket.packet__socket.log"))

    async def _park_recv(self, sock: _AnySocket) -> "asyncio.Task[bytes]":
        """
        Spawn 'sock.recv()' as a task and let the loop run it up to
        the rx-semaphore wait, asserting it is genuinely parked.
        """

        task = asyncio.get_running_loop().create_task(sock.recv())
        for _ in range(5):
            await asyncio.sleep(0)
        self.assertFalse(
            task.done(),
            msg="recv() must be parked on the rx semaphore before close() fires.",
        )
        return task

    async def _assert_wakes_with_ebadf(self, task: "asyncio.Task[bytes]") -> None:
        """
        Await the parked task with a bound and assert it woke with
        EBADF.
        """

        with self.assertRaises(OSError) as ctx:
            await asyncio.wait_for(task, timeout=1)
        self.assertEqual(
            ctx.exception.errno,
            errno.EBADF,
            msg="A recv() woken by close() must raise EBADF.",
        )


class TestUdpSocketCloseWakesRecv(_CloseWakesRecvFixture):
    """
    The 'UdpSocket' close-wakes-recv tests.
    """

    async def test__udp_socket__close_wakes_blocked_recv(self) -> None:
        """
        Ensure 'close()' wakes a blocked 'recv()' with EBADF —
        nothing else ever releases the rx semaphore of a closed
        socket, so an unwoken waiter parks forever.

        Reference: POSIX close(2)/recv(2) EBADF semantics.
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        task = await self._park_recv(sock)

        sock.close()

        await self._assert_wakes_with_ebadf(task)

    async def test__udp_socket__close_wakes_all_blocked_receivers(self) -> None:
        """
        Ensure 'close()' wakes EVERY blocked receiver, not just
        one: the wake permit must cascade from waiter to waiter.

        Reference: POSIX close(2) (all blocked operations on the fd fail).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        task_a = await self._park_recv(sock)
        task_b = await self._park_recv(sock)

        sock.close()

        await self._assert_wakes_with_ebadf(task_a)
        await self._assert_wakes_with_ebadf(task_b)

    async def test__udp_socket__recv_on_closed_socket_raises_ebadf(self) -> None:
        """
        Ensure 'recv()' on an already-closed socket raises EBADF
        immediately instead of blocking on a semaphore nothing
        will ever release.

        Reference: POSIX recv(2) EBADF.
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sock.close()

        with self.assertRaises(OSError) as ctx:
            await asyncio.wait_for(sock.recv(), timeout=1)
        self.assertEqual(ctx.exception.errno, errno.EBADF)

    async def test__udp_socket__close_wakes_blocked_recvfrom(self) -> None:
        """
        Ensure the wake covers the whole recv family — a blocked
        'recvfrom()' must fail with EBADF on close too.

        Reference: POSIX close(2)/recvfrom(2) EBADF semantics.
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        task = asyncio.get_running_loop().create_task(sock.recvfrom())
        for _ in range(5):
            await asyncio.sleep(0)
        self.assertFalse(task.done())

        sock.close()

        with self.assertRaises(OSError) as ctx:
            await asyncio.wait_for(task, timeout=1)
        self.assertEqual(ctx.exception.errno, errno.EBADF)


class TestRawSocketCloseWakesRecv(_CloseWakesRecvFixture):
    """
    The 'RawSocket' close-wakes-recv tests.
    """

    async def test__raw_socket__close_wakes_blocked_recv(self) -> None:
        """
        Ensure 'close()' wakes a blocked raw-socket 'recv()' with
        EBADF.

        Reference: POSIX close(2)/recv(2) EBADF semantics.
        """

        sock = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        task = await self._park_recv(sock)

        sock.close()

        await self._assert_wakes_with_ebadf(task)


class TestPacketSocketCloseWakesRecv(_CloseWakesRecvFixture):
    """
    The 'PacketSocket' close-wakes-recv tests.
    """

    async def test__packet_socket__close_wakes_blocked_recv(self) -> None:
        """
        Ensure 'close()' wakes a blocked packet-socket 'recv()'
        with EBADF — the ACD defense socket parks here between
        polls, and stack teardown must not strand it.

        Reference: POSIX close(2)/recv(2) EBADF semantics.
        """

        sock = PacketSocket()
        try:
            task = await self._park_recv(sock)

            sock.close()

            await self._assert_wakes_with_ebadf(task)
        finally:
            sock.close()


class TestStackStopWakesDatagramRecv(_CloseWakesRecvFixture):
    """
    The stack-teardown datagram-waiter tests: '_abort_open_sockets'
    (the 'stack.stop()' waiter-release pass) must wake datagram /
    raw waiters via 'close()', not skip them.
    """

    async def test__abort_open_sockets__wakes_blocked_udp_recv(self) -> None:
        """
        Ensure the stack-stop socket pass releases a blocked UDP
        'recv()': the default socket mode is blocking with no
        timeout, so the old skip ("nothing blocks beyond per-call
        timeouts") stranded the waiter past a completed stop().

        Reference: PyTCP teardown contract (stop() leaves no parked waiter behind).
        """

        sock = UdpSocket(family=AddressFamily.INET4)
        sockets_prior = dict(stack.sockets)
        stack.sockets.clear()
        stack.sockets[sock.socket_id] = sock
        try:
            task = await self._park_recv(sock)

            lifecycle._abort_open_sockets()

            await self._assert_wakes_with_ebadf(task)
        finally:
            stack.sockets.clear()
            stack.sockets.update(sockets_prior)
