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
This module contains integration tests for the TCP TIME_WAIT state
behaviour in the 'TcpSession' state machine: the eventual transition
to CLOSED after the TIME_WAIT delay elapses, and the handling of
late peer-FIN retransmits per RFC 9293 §3.10.7.5.

Reference RFCs:
    RFC 9293 §3.10.7.5   TIME-WAIT state segment processing
    RFC 9293 §3.10.4     CLOSE Call
    RFC 9293 §3.4.2      MSL / 2 * MSL = TIME_WAIT delay (PyTCP
                         deviates from the RFC's 240 s suggestion;
                         see the TIME_WAIT_DELAY constant)

pytcp/tests/integration/protocols/tcp/test__tcp__session__close__time_wait.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.tcp__session import (
    FsmState,
    SysCall,
    TcpSession,
)
from pytcp.socket import AddressFamily
from pytcp.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_session_testcase import TcpSessionTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers chosen well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN+ACK reply.
PEER__MSS: int = 1460

# Test-only override of the TIME_WAIT delay so the suite runs fast
# without burning 30 s of virtual time per scenario. Value chosen to
# be small enough that the test can step around the boundary cleanly
# but large enough that the boundary tick is unambiguous.
TEST__TIME_WAIT_DELAY_MS: int = 100


class TestTcpClose__TimeWait(TcpSessionTestCase):
    """
    Integration tests for TIME_WAIT state behaviour - delay-driven
    transition to CLOSED and (per RFC 9293 §3.10.7.5) the response
    to a late-arriving peer-FIN retransmit.
    """

    def _make_active_session(self, *, iss: int) -> TcpSession:
        """
        Build a 'TcpSocket' / 'TcpSession' pair the way 'connect()'
        would. Returns the session in CLOSED state.
        """

        self._force_iss(iss)

        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = STACK__PORT
        sock._remote_ip_address = PEER__IP
        sock._remote_port = PEER__PORT

        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=STACK__PORT,
            remote_ip_address=PEER__IP,
            remote_port=PEER__PORT,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock

        return session

    def _drive_handshake_to_established(self, *, iss: int, peer_iss: int) -> TcpSession:
        """
        Drive the active-open three-way handshake to ESTABLISHED.
        """

        session = self._make_active_session(iss=iss)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss,
            ack=iss + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        assert (
            session.state is FsmState.ESTABLISHED
        ), f"Handshake setup failed: state is {session.state!r}, expected ESTABLISHED."
        return session

    def _drive_to_time_wait(self, *, iss: int, peer_iss: int) -> TcpSession:
        """
        Drive the session through an active-close that lands in
        TIME_WAIT: handshake -> close() -> FIN+ACK fires -> peer
        ACKs our FIN -> peer's FIN+ACK -> we ACK and transition
        to TIME_WAIT.
        """

        session = self._drive_handshake_to_established(iss=iss, peer_iss=peer_iss)
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)

        # Peer ACKs our FIN.
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss + 1,
            ack=iss + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_of_fin)
        assert session.state is FsmState.FIN_WAIT_2, f"Setup failed: state is {session.state!r}, expected FIN_WAIT_2."

        # Peer sends FIN+ACK.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss + 1,
            ack=iss + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        assert session.state is FsmState.TIME_WAIT, f"Setup failed: state is {session.state!r}, expected TIME_WAIT."

        return session

    def test__close_time_wait__delay_expiry_transitions_to_closed(self) -> None:
        """
        Ensure the TIME_WAIT state transitions to CLOSED only
        after the configured TIME_WAIT delay elapses, and that
        the socket is unregistered from 'stack.sockets' on
        the transition.

        Reference: RFC 9293 §3.4.2 (TIME-WAIT 2*MSL).
        """

        # Patch TIME_WAIT_DELAY before driving the FSM into TIME_WAIT
        # so the timer is registered with the small test value.
        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.TIME_WAIT_DELAY",
            TEST__TIME_WAIT_DELAY_MS,
        )

        session = self._drive_to_time_wait(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        self.assertIn(
            socket_id,
            stack.sockets,
            msg="Setup precondition: socket must be registered in TIME_WAIT.",
        )

        # Advance to one tick before the boundary. The timer is
        # still counting down; state must not have changed yet.
        pre_boundary_tx = self._advance(ms=TEST__TIME_WAIT_DELAY_MS - 1)
        self.assertEqual(
            pre_boundary_tx,
            [],
            msg=(
                f"During the {TEST__TIME_WAIT_DELAY_MS - 1} ms before "
                "TIME_WAIT timer expiry, no segments may fire - the "
                "session is idle awaiting the timer."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg=(
                "Just before the TIME_WAIT timer expires, state must "
                "still be TIME_WAIT - the boundary tick is what "
                "triggers the transition."
            ),
        )

        # The boundary tick fires the timer-expired branch.
        boundary_tx = self._advance(ms=1)
        self.assertEqual(
            boundary_tx,
            [],
            msg=(
                "TIME_WAIT timer expiry must produce no outbound " "segment - it is a state-only transition to CLOSED."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=("After the TIME_WAIT delay elapses, state " "must transition to CLOSED."),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "On transition to CLOSED, '_change_state' must "
                "unregister the socket from 'stack.sockets' so the "
                "4-tuple can be reused for a fresh connection."
            ),
        )

    def test__close_time_wait__late_peer_fin_retransmit_elicits_ack_and_rearms_timer(self) -> None:
        """
        Ensure a peer-issued FIN retransmit arriving while we
        are in TIME_WAIT elicits an ACK acknowledging peer's
        FIN AND restarts the 2*MSL timer. Without this
        behaviour, a peer that did not receive our original
        ACK of its FIN cannot confirm the connection is
        closed cleanly.

        Reference: RFC 9293 §3.10.7.5 (TIME-WAIT segment processing).
        """

        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.TIME_WAIT_DELAY",
            TEST__TIME_WAIT_DELAY_MS,
        )

        session = self._drive_to_time_wait(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 2,
            msg=("Setup precondition: 'RCV.NXT' must have advanced " "past peer's FIN's one byte of sequence space."),
        )

        # Peer retransmits its FIN+ACK at the original wire shape.
        # The retransmit means peer did not receive our original
        # ACK so it is replaying the same byte of sequence space.
        peer_fin_retransmit = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        retransmit_inline = self._drive_rx(frame=peer_fin_retransmit)

        # The spec encoding: exactly one outbound ACK fires.
        self.assertEqual(
            len(retransmit_inline),
            1,
            msg=(
                "Peer's FIN retransmit in TIME_WAIT MUST elicit "
                "exactly one outbound ACK per RFC 9293 §3.10.7.5 "
                "('Acknowledge it, and restart the 2 MSL timeout'). "
                "Current code's '_tcp_fsm_time_wait' takes no "
                "'packet_rx_md' parameter and the FSM dispatcher "
                "(line 1898) does not pass one - the FIN is silently "
                "dropped, leaving the peer to retransmit until its "
                "own budget exhausts."
            ),
        )
        ack = self._parse_tx(retransmit_inline[0])
        self._assert_segment(
            ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 2,
            ack=PEER__ISS + 2,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg=(
                "After processing the FIN retransmit, state must "
                "remain TIME_WAIT - the retransmit is not a fresh "
                "close and should not advance the FSM."
            ),
        )

        # Step 5: advance (delay - 1) ms. The TIME_WAIT timer was
        # restarted on FIN retransmit, so we still have the full
        # delay grace period before expiry.
        pre_boundary_tx = self._advance(ms=TEST__TIME_WAIT_DELAY_MS - 1)
        self.assertEqual(
            pre_boundary_tx,
            [],
            msg=(
                "During the restarted-TIME_WAIT grace period, no "
                "segments may fire - the session is idle awaiting "
                "the new boundary."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg=(
                f"State must still be TIME_WAIT "
                f"{TEST__TIME_WAIT_DELAY_MS - 1} ms after the FIN "
                "retransmit - the timer was restarted by the FIN "
                "ACK path, not the original entry to TIME_WAIT, so "
                "the boundary is shifted out by the full delay."
            ),
        )

        # Step 6: one more ms past the restarted boundary -> CLOSED.
        boundary_tx = self._advance(ms=1)
        self.assertEqual(
            boundary_tx,
            [],
            msg="Restarted-TIME_WAIT timer expiry must produce no segment.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=("After the restarted TIME_WAIT timer expires, state " "must transition to CLOSED."),
        )


class TestTcpClose__TimeWaitRfc1337(TcpSessionTestCase):
    """
    Integration tests for the RFC 1337 'TIME-WAIT Assassination
    Hazards' mitigations. RFC 1337 §4 identifies three hazards
    where late-arriving segments could prematurely terminate
    TIME-WAIT and corrupt subsequent connections:

        1. Old duplicate FIN: must re-ACK and stay in TIME-WAIT
           (RFC 9293 §3.10.7.5; covered by
           'late_peer_fin_retransmit_elicits_ack_and_rearms_timer'
           above).
        2. Old duplicate RST: MUST be silently dropped; TIME-
           WAIT MUST NOT close. PyTCP's '_tcp_fsm_time_wait'
           handler doesn't recognise RST as a recognised
           segment type, so it falls through to the implicit
           drop. This test pins that behaviour against future
           regressions.
        3. New SYN: must elicit a challenge ACK without
           transitioning out of TIME-WAIT.

    The PAWS check shipped in commit '79ed38e' (RFC 7323 §5)
    extends mitigation #2 to ALSO drop stale-TSval segments,
    not just RSTs.
    """

    def _make_active_session(self, *, iss: int) -> TcpSession:
        """Build a 'TcpSocket' / 'TcpSession' pair."""

        self._force_iss(iss)
        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = STACK__PORT
        sock._remote_ip_address = PEER__IP
        sock._remote_port = PEER__PORT
        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=STACK__PORT,
            remote_ip_address=PEER__IP,
            remote_port=PEER__PORT,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        return session

    def _drive_handshake_to_established(self, *, iss: int, peer_iss: int) -> TcpSession:
        """Drive the active-open three-way handshake to ESTABLISHED."""

        session = self._make_active_session(iss=iss)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss,
            ack=iss + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert session.state is FsmState.ESTABLISHED
        return session

    def _drive_to_time_wait(self, *, iss: int, peer_iss: int) -> TcpSession:
        """Drive a normal active-close into TIME_WAIT."""

        session = self._drive_handshake_to_established(iss=iss, peer_iss=peer_iss)
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)

        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss + 1,
            ack=iss + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_of_fin)

        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss + 1,
            ack=iss + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        assert session.state is FsmState.TIME_WAIT
        return session

    def test__rfc1337__rst_in_time_wait_does_not_terminate(self) -> None:
        """
        Ensure a peer RST arriving during TIME_WAIT is
        silently dropped: the session stays in TIME_WAIT
        until its 2*MSL delay timer naturally expires; no
        outbound segment fires in response.

        Reference: RFC 1337 §3 (TIME-WAIT assassination mitigations).
        """

        session = self._drive_to_time_wait(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,
            ack=LOCAL__ISS + 2,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_tx = self._drive_rx(frame=peer_rst)

        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg=(
                "A peer RST during TIME_WAIT MUST be "
                "silently dropped; state MUST stay TIME_WAIT. "
                f"Got state={session.state!r}."
            ),
        )
        self.assertEqual(
            rst_tx,
            [],
            msg=("The RST MUST be silently dropped; no " "outbound segment may fire in response."),
        )

    def test__rfc1337__syn_in_time_wait_elicits_challenge_ack_without_state_change(self) -> None:
        """
        Ensure a new SYN arriving at TIME_WAIT elicits a
        challenge ACK with our current SND.NXT and RCV.NXT
        and does NOT transition out of TIME_WAIT.

        Reference: RFC 9293 §3.10.7.4 (SYN-on-synchronized challenge ACK).
        Reference: RFC 1337 §3 (TIME-WAIT assassination mitigations).
        """

        session = self._drive_to_time_wait(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_5000,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        challenge_tx = self._drive_rx(frame=peer_syn)

        self.assertEqual(
            len(challenge_tx),
            1,
            msg=(
                "RFC 1337 §4 hazard #3 / RFC 9293 §3.10.7.4: "
                "a SYN in TIME_WAIT MUST elicit exactly one "
                f"challenge ACK. Got {len(challenge_tx)} "
                "frames."
            ),
        )
        probe = self._parse_tx(challenge_tx[0])
        self.assertEqual(
            probe.flags & frozenset({"ACK", "RST", "SYN", "FIN"}),
            frozenset({"ACK"}),
            msg=(
                "RFC 9293 §3.10.7.4: challenge ACK is an "
                "ACK-only segment (no RST/SYN/FIN). Got "
                f"flags={probe.flags!r}."
            ),
        )
        self.assertEqual(
            probe.seq,
            LOCAL__ISS + 2,  # post-FIN: seq = ISS + SYN + FIN = ISS + 2
            msg=("RFC 9293 §3.10.7.4: challenge ACK seq MUST " "equal SND.NXT."),
        )
        self.assertEqual(
            probe.ack,
            PEER__ISS + 2,  # post-peer-FIN: ack = peer_ISS + SYN + FIN = peer_ISS + 2
            msg=("RFC 9293 §3.10.7.4: challenge ACK ack MUST " "equal RCV.NXT."),
        )
        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg=(
                "RFC 1337 §4 hazard #3: a SYN in TIME_WAIT "
                "MUST NOT transition out of TIME_WAIT. Got "
                f"state={session.state!r}."
            ),
        )
