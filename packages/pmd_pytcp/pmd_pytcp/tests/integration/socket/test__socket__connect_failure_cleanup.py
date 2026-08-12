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
This module contains the 'TcpSocket.connect()' failure-cleanup
integration tests. The invariant under test: a 'connect()' that
raises — for ANY reason, including the awaiting task being cancelled
mid-handshake — leaves nothing registered on the stack. Without the
cleanup, an abandoned half-open session keeps retransmitting SYNs
until the R2 budget expires, holding its registered socket (and its
ephemeral port, which the port pickers exclude while any registered
socket holds it) the whole time; and a 'TcpSessionError("Connection
canceled")' raised by a concurrent 'close()' used to fall through the
error mapping entirely — 'connect()' returned as if it had succeeded
on a dead, unregistered session.

pmd_pytcp/tests/integration/socket/test__socket__connect_failure_cleanup.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio

from pmd_net_addr import Ip4Address
from pmd_pytcp import stack
from pmd_pytcp.protocols.tcp.tcp__enums import FsmState
from pmd_pytcp.socket import AddressFamily
from pmd_pytcp.socket.tcp__socket import TcpSocket
from pmd_pytcp.tests.lib.network_testcase import HOST_A__IP4_ADDRESS
from pmd_pytcp.tests.lib.tcp_testcase import TcpTestCase

PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80


class TestTcpSocketConnectFailureCleanup(TcpTestCase):
    """
    The 'TcpSocket.connect()' failure-cleanup tests.
    """

    async def _start_pending_connect(self, sock: TcpSocket) -> asyncio.Task[None]:
        """
        Launch 'sock.connect()' as a task and yield to the loop until
        the coroutine has driven the session into SYN_SENT and parked
        on the connect event, returning the pending task.
        """

        task = asyncio.ensure_future(sock.connect((str(PEER__IP), PEER__PORT)))
        for _ in range(3):
            await asyncio.sleep(0)

        assert sock._tcp_session is not None, "_start_pending_connect: no session was created"
        assert (
            sock._tcp_session.state is FsmState.SYN_SENT
        ), f"_start_pending_connect: expected SYN_SENT, got {sock._tcp_session.state!r}"
        return task

    async def test__connect__cancelled_mid_handshake_unregisters_socket(self) -> None:
        """
        Ensure cancelling a task blocked in 'connect()' tears the
        half-open session down: the abandoned session must not stay
        registered in 'stack.sockets' retransmitting SYNs (and
        holding its ephemeral port) until the R2 budget expires.

        Reference: RFC 9293 §3.9.1 (ABORT call) — the awaiter abandoning the handshake orphans the TCB.
        """

        sock = TcpSocket(family=AddressFamily.INET4)
        task = await self._start_pending_connect(sock)
        socket_id = sock.socket_id
        self.assertIn(
            socket_id,
            stack.sockets,
            msg="Setup precondition: the connecting socket must be registered.",
        )

        task.cancel()
        with self.assertRaises(asyncio.CancelledError, msg="The cancelled connect() must re-raise."):
            await task

        assert sock._tcp_session is not None
        self.assertIs(
            sock._tcp_session.state,
            FsmState.CLOSED,
            msg="A cancelled connect() must drive the half-open session to CLOSED.",
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg="A cancelled connect() must leave nothing registered in 'stack.sockets'.",
        )

    async def test__connect__concurrent_close_raises_connection_aborted(self) -> None:
        """
        Ensure a 'close()' issued while 'connect()' is pending makes
        'connect()' raise 'ConnectionAbortedError'. The session's
        'TcpSessionError("Connection canceled")' used to fall through
        the refused/timeout error mapping and was silently swallowed —
        'connect()' returned normally on a dead, unregistered session,
        and the caller's first 'send()' failed instead.

        Reference: RFC 9293 §3.10.4 (CLOSE call in SYN-SENT deletes the TCB).
        """

        sock = TcpSocket(family=AddressFamily.INET4)
        task = await self._start_pending_connect(sock)
        socket_id = sock.socket_id

        sock.close()
        with self.assertRaises(
            ConnectionAbortedError,
            msg="connect() must surface the concurrent close as ConnectionAbortedError.",
        ):
            await task

        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg="The closed-while-connecting socket must not stay registered in 'stack.sockets'.",
        )
