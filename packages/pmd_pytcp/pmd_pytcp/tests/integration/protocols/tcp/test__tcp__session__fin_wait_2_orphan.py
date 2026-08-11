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
This module contains the FIN_WAIT_2 orphan-reaper integration tests
(Linux 'net.ipv4.tcp_fin_timeout' parity). An ORPHANED connection —
one whose socket the application has fully closed, so nobody can ever
read the peer's remaining data — must not await the peer's FIN in
FIN_WAIT_2 forever: a peer that vanishes after ACKing our FIN would
otherwise pin the TCB (and its local port, which the ephemeral-port
pickers exclude while the socket stays registered) indefinitely. A
connection merely half-closed via 'shutdown(SHUT_WR)' — the
application still reading — is NOT orphaned and is never reaped, per
the same Linux semantics.

pmd_pytcp/tests/integration/protocols/tcp/test__tcp__session__fin_wait_2_orphan.py

ver 3.0.7
"""

from __future__ import annotations

from pmd_net_addr import Ip4Address
from pmd_pytcp import stack
from pmd_pytcp.protocols.tcp.session import TcpSession
from pmd_pytcp.protocols.tcp.tcp__enums import FsmState
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

# Test-scaled orphan timeout (production default is 60 s).
TEST__FIN_WAIT_2__TIMEOUT_MS: int = 3000


class TestTcpFinWait2OrphanReaper(TcpTestCase):
    """
    The FIN_WAIT_2 orphan-reaper (Linux 'tcp_fin_timeout' parity)
    integration tests.
    """

    def setUp(self) -> None:
        """
        Scale the orphan timeout down to keep the virtual-clock
        advances small; both arm sites read the constant at call
        time so the patch takes effect everywhere.
        """

        super().setUp()
        self._start_patch(
            "pmd_pytcp.protocols.tcp.tcp__constants.TCP__FIN_WAIT_2__TIMEOUT_MS",
            TEST__FIN_WAIT_2__TIMEOUT_MS,
        )

    def _drive_to_fin_wait_2(self, *, orphan: bool) -> TcpSession:
        """
        Establish a session, initiate the active close — a full
        socket 'close()' when 'orphan' is True, a
        'shutdown(SHUT_WR)' half-close otherwise — then drive the
        FIN out and inject the peer's ACK of it, leaving the
        session in FIN_WAIT_2.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        sock = session._socket

        if orphan:
            sock.close()
        else:
            sock.shutdown(SHUT_WR)

        # Tick #1: ESTABLISHED sees '_closing' + drained TX buffer,
        # transitions to FIN_WAIT_1. Tick #2: FIN_WAIT_1 emits the
        # FIN+ACK.
        self._advance(ms=1)
        self._advance(ms=1)

        # Peer ACKs our FIN (ack covers the FIN's sequence byte).
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
        ), f"_drive_to_fin_wait_2: session did not reach FIN_WAIT_2; got {session.state!r}"
        return session

    def test__fin_wait_2__orphaned_close_reaps_after_timeout(self) -> None:
        """
        Ensure an orphaned connection (socket fully closed) whose
        peer never sends its FIN is reaped from FIN_WAIT_2 once the
        orphan timeout expires: the session reaches CLOSED and its
        socket is unregistered from 'stack.sockets', releasing the
        local port.

        Reference: Linux 'net.ipv4.tcp_fin_timeout' (orphan FIN_WAIT_2 reap; deliberate RFC 9293 deviation).
        """

        session = self._drive_to_fin_wait_2(orphan=True)
        socket_id = session._socket.socket_id

        self.assertTrue(
            session._timer_armed("fin_wait_2"),
            msg="Entering FIN_WAIT_2 with a closed socket must arm the orphan reaper.",
        )

        self._advance(ms=TEST__FIN_WAIT_2__TIMEOUT_MS - 1)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="One tick before the orphan timeout, the session must still be in FIN_WAIT_2.",
        )

        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="At the orphan timeout, the reaper must drive the session to CLOSED.",
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg="The reaped session's socket must be unregistered from 'stack.sockets'.",
        )

    def test__fin_wait_2__half_close_is_never_reaped(self) -> None:
        """
        Ensure a 'shutdown(SHUT_WR)' half-close — the application
        still holds the open socket and may read for as long as it
        likes — does NOT arm the orphan reaper: the session stays
        in FIN_WAIT_2 well past the timeout, per RFC 9293's
        unbounded FIN_WAIT_2 hold (and Linux, which reaps only
        orphans).

        Reference: RFC 9293 §3.6 half-close; Linux 'tcp_fin_timeout' applies to orphaned sockets only.
        """

        session = self._drive_to_fin_wait_2(orphan=False)
        socket_id = session._socket.socket_id

        self.assertFalse(
            session._timer_armed("fin_wait_2"),
            msg="A half-closed (non-orphaned) session must NOT arm the orphan reaper.",
        )

        self._advance(ms=TEST__FIN_WAIT_2__TIMEOUT_MS * 2)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="A half-closed session must remain in FIN_WAIT_2 indefinitely.",
        )
        self.assertIn(
            socket_id,
            stack.sockets,
            msg="A half-closed session's socket must stay registered.",
        )

    def test__fin_wait_2__close_after_half_close_arms_reaper(self) -> None:
        """
        Ensure a socket 'close()' issued AFTER the session already
        reached FIN_WAIT_2 via a half-close orphans the connection
        there and then: the CLOSE syscall arms the reaper, and the
        timeout drives the session to CLOSED.

        Reference: Linux 'tcp_fin_timeout' — the orphan clock starts when the socket is closed.
        """

        session = self._drive_to_fin_wait_2(orphan=False)
        socket_id = session._socket.socket_id

        session._socket.close()
        self.assertTrue(
            session._timer_armed("fin_wait_2"),
            msg="close() on a session already in FIN_WAIT_2 must arm the orphan reaper.",
        )

        self._advance(ms=TEST__FIN_WAIT_2__TIMEOUT_MS)
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="The orphan timeout after the late close() must drive the session to CLOSED.",
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg="The reaped session's socket must be unregistered from 'stack.sockets'.",
        )

    def test__fin_wait_2__peer_fin_cancels_reaper(self) -> None:
        """
        Ensure the peer's FIN arriving before the orphan timeout
        follows the normal close path: the session transitions to
        TIME_WAIT, the orphan reaper is cancelled, and TIME_WAIT's
        own 2MSL delay owns the rest of the teardown.

        Reference: RFC 9293 §3.6 (normal close, FIN_WAIT_2 -> TIME_WAIT).
        """

        session = self._drive_to_fin_wait_2(orphan=True)

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
            msg="The peer's FIN must move the session to TIME_WAIT as usual.",
        )
        self.assertFalse(
            session._timer_armed("fin_wait_2"),
            msg="The TIME_WAIT transition must cancel the orphan reaper.",
        )
        self.assertTrue(
            session._timer_armed("time_wait"),
            msg="TIME_WAIT's own 2MSL delay must be armed.",
        )
