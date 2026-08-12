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
This module contains the session-death receiver-wakeup integration
tests: every transition that ends a session's readable life — an
inbound RST in any synchronized state, the peer's FIN moving the
session to TIME_WAIT or CLOSING, a local 'abort()', or a
timer-driven collapse to CLOSED — must wake a blocked 'receive()'
and surface the right signal (an error for reset/abort, EOF for a
graceful peer close). A waiter that sleeps through its session's
death parks its task (and everything the task references) for the
process lifetime; observed live through pymobiledevice3's userspace
tunnel as relay handlers stuck on sockets whose sessions were
already CLOSED and unregistered.

pmd_pytcp/tests/integration/protocols/tcp/test__tcp__session__death_wakes_receiver.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio

from pmd_net_addr import Ip4Address
from pmd_pytcp.protocols.tcp.session import TcpSession
from pmd_pytcp.protocols.tcp.tcp__enums import FsmState
from pmd_pytcp.protocols.tcp.tcp__errors import TcpSessionError
from pmd_pytcp.socket import SHUT_WR
from pmd_pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pmd_pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pmd_pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers chosen well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window.
PEER__WIN: int = 64240


class TestTcpSessionDeathWakesReceiver(TcpTestCase):
    """
    The session-death receiver-wakeup integration tests.
    """

    async def _park_receive(self, session: TcpSession) -> asyncio.Task[bytes]:
        """
        Spawn 'session.receive()' as a task and let the loop run it
        up to its rx-buffer wait, asserting it is genuinely parked
        (not completed) before the test injects the death event.
        """

        task = asyncio.get_running_loop().create_task(session.receive())
        for _ in range(5):
            await asyncio.sleep(0)
        self.assertFalse(
            task.done(),
            msg="receive() must be parked on the rx-buffer event before the death event fires.",
        )
        return task

    def _drive_to_fin_wait_2_half_close(self) -> TcpSession:
        """
        Establish a session, half-close it via 'shutdown(SHUT_WR)'
        (the application keeps reading), drive the FIN out and
        inject the peer's ACK of it, leaving the session in
        FIN_WAIT_2 with an open read side.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._socket.shutdown(SHUT_WR)

        # Tick #1: ESTABLISHED sees the pending close + drained TX
        # buffer, transitions to FIN_WAIT_1. Tick #2: FIN_WAIT_1
        # emits the FIN+ACK.
        self._advance(ms=1)
        self._advance(ms=1)

        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_of_fin)

        assert (
            session.state is FsmState.FIN_WAIT_2
        ), f"_drive_to_fin_wait_2_half_close: session did not reach FIN_WAIT_2; got {session.state!r}"
        return session

    async def test__established__rst_wakes_blocked_receive_with_reset_error(self) -> None:
        """
        Ensure an acceptable inbound RST in ESTABLISHED wakes a
        blocked 'receive()' with a connection-reset error rather
        than leaving it parked or returning a clean EOF: the stream
        was destroyed mid-flight and the application must be able
        to tell that apart from a graceful shutdown.

        Reference: RFC 9293 §3.10.7.4 (RST processing); Linux ECONNRESET recv semantics.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        receive_task = await self._park_receive(session)

        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_rst)
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="The acceptable RST must drive the session to CLOSED.",
        )

        with self.assertRaises(TcpSessionError, msg="A blocked receive() must raise on an inbound RST."):
            await asyncio.wait_for(receive_task, timeout=1)

    async def test__fin_wait_2__rst_wakes_blocked_receive_with_reset_error(self) -> None:
        """
        Ensure an acceptable inbound RST in FIN_WAIT_2 (the
        half-closed, still-reading state) wakes a blocked
        'receive()' with a connection-reset error. This is the
        exact shape observed live through pymobiledevice3's
        userspace tunnel: sessions died out of FIN_WAIT_2 and were
        unregistered while their reader tasks stayed parked
        forever.

        Reference: RFC 9293 §3.10.7.4 (RST processing applies in every synchronized state).
        """

        session = self._drive_to_fin_wait_2_half_close()
        receive_task = await self._park_receive(session)

        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_rst)
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="The acceptable RST must drive the session to CLOSED.",
        )

        with self.assertRaises(TcpSessionError, msg="A blocked receive() must raise on an inbound RST."):
            await asyncio.wait_for(receive_task, timeout=1)

    async def test__fin_wait_2__peer_fin_wakes_blocked_receive_with_eof(self) -> None:
        """
        Ensure the peer's FIN arriving in FIN_WAIT_2 (moving the
        session to TIME_WAIT) wakes a blocked 'receive()' with a
        clean EOF ('b""'): the peer closed gracefully and every
        byte it sent has been delivered. A follow-up 'receive()'
        must return EOF immediately instead of blocking.

        Reference: RFC 9293 §3.6 (half-close: the peer's FIN ends the readable stream).
        """

        session = self._drive_to_fin_wait_2_half_close()
        receive_task = await self._park_receive(session)

        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg="The peer's FIN must move the session to TIME_WAIT.",
        )

        self.assertEqual(
            await asyncio.wait_for(receive_task, timeout=1),
            b"",
            msg="A blocked receive() must return EOF when the peer's FIN arrives in FIN_WAIT_2.",
        )
        self.assertEqual(
            await asyncio.wait_for(session.receive(), timeout=1),
            b"",
            msg="A follow-up receive() in TIME_WAIT must return EOF immediately.",
        )

    async def test__fin_wait_1__simultaneous_close_wakes_blocked_receive_with_eof(self) -> None:
        """
        Ensure the peer's FIN arriving in FIN_WAIT_1 without acking
        our FIN (simultaneous close, moving the session to CLOSING)
        wakes a blocked 'receive()' with a clean EOF: the peer
        closed gracefully, so the half-closed application's read
        side is done.

        Reference: RFC 9293 §3.5 Figure 7 (simultaneous close).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._socket.shutdown(SHUT_WR)
        self._advance(ms=1)
        self._advance(ms=1)

        receive_task = await self._park_receive(session)

        # Peer's FIN acks only our ISS+1 (not our FIN): both FINs
        # crossed — simultaneous close.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(
            session.state,
            FsmState.CLOSING,
            msg="The peer's non-acking FIN in FIN_WAIT_1 must move the session to CLOSING.",
        )

        self.assertEqual(
            await asyncio.wait_for(receive_task, timeout=1),
            b"",
            msg="A blocked receive() must return EOF when the peer's FIN arrives in FIN_WAIT_1.",
        )

    async def test__abort_wakes_blocked_receive_with_error(self) -> None:
        """
        Ensure a local 'abort()' wakes a blocked 'receive()' with a
        connection error — the behavior 'TcpSocket.abort()' has
        always documented ("Pending recv() calls unblock with a
        connection error") but the session never delivered: the
        woken receive() returned a clean EOF instead.

        Reference: RFC 9293 §3.9.1 ABORT ("outstanding RECEIVEs ... [signal] 'connection reset'").
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        receive_task = await self._park_receive(session)

        session._socket.abort()
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="abort() must drive the session to CLOSED.",
        )

        with self.assertRaises(TcpSessionError, msg="A blocked receive() must raise on a local abort()."):
            await asyncio.wait_for(receive_task, timeout=1)

    async def test__time_wait_expiry_leaves_receive_at_eof(self) -> None:
        """
        Ensure 'receive()' called after TIME_WAIT expired the
        session to CLOSED returns EOF immediately: the terminal
        transition must leave the rx event set, not reset the
        session to an unreadable limbo.

        Reference: RFC 9293 §3.10.1 (TIME-WAIT timeout ends the connection).
        """

        session = self._drive_to_fin_wait_2_half_close()

        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        assert session.state is FsmState.TIME_WAIT

        # Drain the EOF once in TIME_WAIT, then expire the 2MSL
        # delay; the CLOSED session must still read as EOF.
        self.assertEqual(await asyncio.wait_for(session.receive(), timeout=1), b"")
        self._expire_timer(session, "time_wait")
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="The 2MSL expiry must drive the session to CLOSED.",
        )
        self.assertEqual(
            await asyncio.wait_for(session.receive(), timeout=1),
            b"",
            msg="receive() on the expired (CLOSED) session must return EOF immediately.",
        )

    async def test__socket_recv_translates_reset_to_connection_reset_error(self) -> None:
        """
        Ensure the socket layer maps the session's reset signal to
        'ConnectionResetError' — the POSIX ECONNRESET parity the
        rest of the socket API follows (connect() maps REFUSED to
        'ConnectionRefusedError' the same way).

        Reference: Linux recv(2) ECONNRESET.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        sock = session._socket

        recv_task = asyncio.get_running_loop().create_task(sock.recv())
        for _ in range(5):
            await asyncio.sleep(0)
        self.assertFalse(
            recv_task.done(),
            msg="recv() must be parked on the rx-buffer event before the RST fires.",
        )

        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_rst)

        with self.assertRaises(
            ConnectionResetError,
            msg="A blocked socket recv() must raise ConnectionResetError on an inbound RST.",
        ):
            await asyncio.wait_for(recv_task, timeout=1)
