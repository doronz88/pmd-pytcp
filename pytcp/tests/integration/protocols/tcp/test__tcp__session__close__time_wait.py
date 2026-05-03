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
        Ensure that the TIME_WAIT state transitions to CLOSED only
        AFTER the configured TIME_WAIT delay elapses, and that the
        socket is unregistered from 'stack.sockets' on the
        transition. RFC 9293 §3.10.7.5 / §3.4.2.

        RFC 9293 §3.4.2:

            "TIME-WAIT - represents waiting for enough time to pass
             to be sure the remote TCP endpoint received the
             acknowledgment of its connection termination request."

        Scenario:

            1. Patch 'TIME_WAIT_DELAY' to a small test value
               (TEST__TIME_WAIT_DELAY_MS = 100 ms) so the suite
               does not burn 30 s of virtual time per scenario.
               This is allowed because the test asserts on the
               BOUNDARY behaviour (just-before / just-after the
               configured delay), not on any literal wall-clock
               value of the constant.
            2. Drive an active-close path through ESTABLISHED ->
               FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT. At the
               moment of transition, the TIME_WAIT timer is
               registered with timeout = patched delay.
            3. Advance the clock by (delay - 1) ms. State must
               still be TIME_WAIT - the timer has not yet expired.
            4. Advance one more ms. State must now be CLOSED -
               the boundary tick fires the timer-expired branch
               of '_tcp_fsm_time_wait' (line 1845).
            5. Assert the socket is unregistered from
               'stack.sockets'.

        Assertions:

            * Pre-boundary tick (delay - 1 ms after entry to
              TIME_WAIT): state is TIME_WAIT, no segments emitted.
            * Boundary tick (one more ms): state is CLOSED, no
              segments emitted, socket unregistered.

        This test passes on current code as a positive-control
        regression guard for the TIME_WAIT timer-expiry path.
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
            msg=(
                "After the TIME_WAIT delay elapses, state must "
                "transition to CLOSED per RFC 9293 §3.10.7.5 / "
                "§3.4.2 (line 1845-1846 of '_tcp_fsm_time_wait')."
            ),
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
        Ensure that a peer-issued FIN retransmit arriving while we
        are in TIME_WAIT elicits an ACK acknowledging peer's FIN
        AND restarts the TIME_WAIT timer, per RFC 9293 §3.10.7.5.
        Without this behaviour, a peer that did not receive our
        original ACK of its FIN can never confirm the connection
        is closed cleanly - it will retransmit the FIN until its
        own retransmit limit fires, ultimately RST-ing a
        connection that we have already wrapped up.

        RFC 9293 §3.10.7.5 (TIME-WAIT state segment processing):

            "The only thing that can arrive in this state is a
             retransmission of the remote FIN.  Acknowledge it,
             and restart the 2 MSL timeout."

        The "restart the 2 MSL timeout" clause is critical: a peer
        retransmitting FIN late in our TIME_WAIT window means our
        original ACK was lost. We must re-ACK AND restart the
        timer so the new ACK has the same 2*MSL grace period to
        be observed by the network as the original would have.

        Scenario:

            1. Patch 'TIME_WAIT_DELAY' to a small test value
               (TEST__TIME_WAIT_DELAY_MS = 100 ms).
            2. Drive an active-close path to TIME_WAIT. RCV.NXT =
               PEER__ISS + 2 (we have already seen and ACKed
               peer's FIN once).
            3. Peer retransmits its FIN+ACK at the SAME wire shape
               as the original (seq = PEER__ISS + 1, ack =
               LOCAL__ISS + 2, flags={FIN, ACK}). The retransmit
               is at the original seq because the FIN's seq does
               not advance with retransmits - peer is replaying
               the same byte of sequence space.
            4. Drive RX. The TIME_WAIT handler MUST emit an ACK
               at ack = PEER__ISS + 2 (re-acknowledging peer's
               FIN) and restart the TIME_WAIT timer.
            5. Advance (delay - 1) ms. State must still be
               TIME_WAIT - the restarted timer has not yet
               expired (it has its full 100 ms grace period).
               The original timer (which would have expired by
               now) was replaced by the restart.
            6. Advance one more ms. State must now be CLOSED.

        Assertions:

            * Step 3-4: exactly one outbound ACK fires with
              correct seq/ack/flags. The spec encoding.
            * Step 4: state remains TIME_WAIT (the FIN
              retransmit is not a fresh close).
            * Step 5: after (delay - 1) ms past the FIN retransmit,
              state is still TIME_WAIT - the restart took effect.
            * Step 6: after one more ms, state is CLOSED.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_time_wait' (line 1835-
        1846) is currently a single timer-only branch:

            def _tcp_fsm_time_wait(self, *, timer: bool | None) -> None:
                if timer and stack.timer.is_expired(f"{self}-time_wait"):
                    self._change_state(FsmState.CLOSED)

        It accepts no 'packet_rx_md' parameter at all. The FSM
        dispatcher (line 1897-1898) reflects this:

            case FsmState.TIME_WAIT:
                self._tcp_fsm_time_wait(timer=timer)

        i.e. inbound packets are silently dropped on the floor in
        TIME_WAIT. The peer's FIN retransmit will get no reply,
        will eventually exhaust the peer's retransmit budget, and
        the peer will RST our 4-tuple after we are already gone -
        exactly what TIME_WAIT exists to prevent.

        The fix has three parts:

        1. Add a 'packet_rx_md: TcpMetadata | None = None' parameter
           to '_tcp_fsm_time_wait'.

        2. Add an inbound-packet branch that recognises a
           FIN-bearing segment with seq matching the original FIN
           ('seq + 1 == self._rcv_nxt'), emits the ACK, and
           restarts the TIME_WAIT timer:

               if packet_rx_md and packet_rx_md.tcp__flag_fin:
                   if packet_rx_md.tcp__seq + 1 == self._rcv_nxt:
                       self._transmit_packet(flag_ack=True)
                       stack.timer.register_timer(
                           name=f"{self}-time_wait",
                           timeout=TIME_WAIT_DELAY,
                       )
                   return

        3. Update the FSM dispatcher to pass 'packet_rx_md':

               case FsmState.TIME_WAIT:
                   self._tcp_fsm_time_wait(
                       packet_rx_md=packet_rx_md,
                       timer=timer,
                   )

        On current code this test will see zero outbound TX after
        the FIN retransmit - failing the inline-TX-count assertion.
        Subsequent assertions (state still TIME_WAIT after delay-1)
        also fail because the original timer was never restarted
        and would expire on the very advance.
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
