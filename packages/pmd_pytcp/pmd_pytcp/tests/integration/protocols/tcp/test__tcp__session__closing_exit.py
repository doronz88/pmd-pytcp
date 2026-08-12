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
This module contains the CLOSING-state exit-guarantee integration
tests (RFC 9293 §3.5 Figure 7 simultaneous close). CLOSING must be
able to make progress on its own: the peer's ACK of our FIN can be
lost — and a peer already in TIME_WAIT retransmits nothing — so
the session must retransmit its FIN on the RTO ladder and, if the
peer never answers, give up through the retransmission budget and
reach CLOSED. A CLOSING state with no timer machinery leaks the
session and its local port forever.

pmd_pytcp/tests/integration/protocols/tcp/test__tcp__session__closing_exit.py

ver 3.0.7
"""

from __future__ import annotations

from pmd_net_addr import Ip4Address
from pmd_pytcp import stack
from pmd_pytcp.protocols.tcp.session import TcpSession
from pmd_pytcp.protocols.tcp.tcp__enums import FsmState
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

# Generous bound on RTO-ladder iterations before declaring the
# retransmission budget broken (the R2 budget is well below this).
MAX_RTO_LADDER_STEPS: int = 32


class TestTcpClosingExit(TcpTestCase):
    """
    The CLOSING-state exit-guarantee integration tests.
    """

    def _drive_to_closing(self) -> TcpSession:
        """
        Establish a session, 'close()' it, drive our FIN out,
        then inject the peer's crossing FIN that does NOT ack
        ours (both FINs in flight — simultaneous close),
        leaving the session in CLOSING with our FIN unacked.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._socket.close()

        # Tick #1: ESTABLISHED sees the pending close + drained
        # TX buffer, transitions to FIN_WAIT_1. Tick #2:
        # FIN_WAIT_1 emits the FIN+ACK.
        self._advance(ms=1)
        self._advance(ms=1)

        # Peer's FIN acks only our ISS+1 (not our FIN): the two
        # FINs crossed on the wire.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)

        assert (
            session.state is FsmState.CLOSING
        ), f"_drive_to_closing: session did not reach CLOSING; got {session.state!r}"
        return session

    def test__closing__retransmits_fin_on_rto(self) -> None:
        """
        Ensure a session in CLOSING retransmits its unacked FIN
        when the retransmission timer expires: the peer's ACK
        of our FIN can be lost, and a peer already in TIME_WAIT
        will never retransmit anything on its own — our FIN
        retransmission is the only stimulus that can complete
        the close.

        Reference: RFC 9293 §3.8.1 (retransmission covers FIN-bearing segments); §3.5 Figure 7.
        """

        session = self._drive_to_closing()

        self._expire_timer(session, "retransmit")
        frames = self._advance(ms=1)

        fin_retransmits = [
            probe for probe in map(self._parse_tx, frames) if "FIN" in probe.flags and probe.seq == LOCAL__ISS + 1
        ]
        self.assertTrue(
            fin_retransmits,
            msg="CLOSING must retransmit the unacked FIN when the retransmission timer expires.",
        )

    def test__closing__acked_fin_retransmit_reaches_time_wait(self) -> None:
        """
        Ensure the lost-ACK simultaneous close completes: after
        CLOSING retransmits the FIN, the peer's (re)ACK of it
        must move the session to TIME_WAIT with the 2MSL delay
        armed — the RFC 9293 §3.5 Figure 7 lower path.

        Reference: RFC 9293 §3.5 Figure 7 (simultaneous close), §3.10.7.4 (CLOSING: FIN acked -> TIME-WAIT).
        """

        session = self._drive_to_closing()

        self._expire_timer(session, "retransmit")
        self._advance(ms=1)

        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_of_fin)

        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg="The peer's ACK of our retransmitted FIN must move CLOSING to TIME_WAIT.",
        )
        self.assertTrue(
            session._timer_armed("time_wait"),
            msg="TIME_WAIT's 2MSL delay must be armed.",
        )

    def test__closing__retransmission_budget_exhaustion_reaches_closed(self) -> None:
        """
        Ensure a CLOSING session whose peer has vanished gives
        up through the retransmission budget and reaches CLOSED,
        unregistering its socket and releasing the local port —
        the Linux 'tcp_orphan_retries'-style backstop. Without
        it, one lost ACK from a dead peer pins the session (and
        its port) for the process lifetime.

        Reference: RFC 9293 §3.8.3 R2 give-up; Linux 'tcp_orphan_retries'.
        """

        session = self._drive_to_closing()
        socket_id = session._socket.socket_id

        for _ in range(MAX_RTO_LADDER_STEPS):
            if session.state is FsmState.CLOSED:
                break
            self._expire_timer(session, "retransmit")
            self._advance(ms=1)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="CLOSING with a vanished peer must exhaust the retransmission budget and reach CLOSED.",
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg="The collapsed session's socket must be unregistered from 'stack.sockets'.",
        )
