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
This module contains integration tests for the normal TCP connection
termination paths in the 'TcpSession' state machine - the active-close
4-way handshake (ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT)
and the passive-close path (ESTABLISHED → CLOSE_WAIT → LAST_ACK →
CLOSED) per RFC 9293 §3.10.4.

The simultaneous-close path (ESTABLISHED → FIN_WAIT_1 → CLOSING →
TIME_WAIT) is covered by 'close__simultaneous.py'; the TIME_WAIT
expiry mechanics are covered by 'close__time_wait.py'.

Reference RFCs:
    RFC 9293 §3.10.4    CLOSE Call
    RFC 9293 §3.5       Closing a Connection
    RFC 9293 §3.10.7.5  TIME-WAIT state segment processing

pytcp/tests/integration/socket/test__socket__tcp__session__close__normal.py

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


class TestTcpClose__Normal(TcpSessionTestCase):
    """
    Integration tests for the normal active-close and passive-close
    paths through the TCP FSM.
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

    def test__close_active__textbook_4way_close_walks_through_fin_wait_1_fin_wait_2_time_wait(self) -> None:
        """
        Ensure that an application-driven 'close()' on an idle
        ESTABLISHED session walks the FSM through the canonical
        active-close 4-way handshake described by RFC 9293 §3.10.4 /
        §3.5, with each transition emitting (or accepting) the
        wire-level segment shape the spec mandates.

        The textbook trajectory:

            ESTABLISHED
                | local 'close()'
                v                                   send FIN+ACK -->
            FIN_WAIT_1
                |                                   <-- receive ACK
                v                                       (of our FIN)
            FIN_WAIT_2
                |                                   <-- receive FIN+ACK
                v                                       (peer's close)
            TIME_WAIT                               send ACK -->
                |                                       (of peer's FIN)
                | (TIME_WAIT_DELAY elapses)
                v
            CLOSED

        RFC 9293 §3.10.4 (CLOSE Call, ESTABLISHED state):

            "Queue this until all preceding SENDs have been segmentized,
             then form a FIN segment and send it.  In any case, enter
             FIN-WAIT-1 state."

        and §3.10.7.4 (FIN-WAIT-1 segment processing):

            "If our FIN is now acknowledged, then enter FIN-WAIT-2 ..."
            "If the FIN bit is set, ... acknowledge the segment, ...
             and enter the TIME-WAIT state."

        Scenario:

            1. Drive the active-open handshake to ESTABLISHED. The
               TX buffer is empty - no in-flight data complicates the
               close.
            2. Application calls 'session.close()'. This sets the
               '_closing' flag in '_tcp_fsm_established's CLOSE-syscall
               branch (line 1504-1506); state is still ESTABLISHED at
               this point.
            3. Tick #1: ESTABLISHED's timer branch sees
               '_closing AND not _tx_buffer' and transitions to
               FIN_WAIT_1. NO segment is emitted on this tick - the
               transition only flips state; the FIN goes out from the
               FIN_WAIT_1 timer handler on the next tick.
            4. Tick #2: FIN_WAIT_1's '_transmit_data' enters the
               '_state in {FIN_WAIT_1, LAST_ACK} and _snd_nxt !=
               _snd_fin' branch (line 770) and emits the FIN+ACK at
               SEQ = LOCAL__ISS + 1, ACK = PEER__ISS + 1, no payload.
            5. Peer ACKs our FIN with ack = LOCAL__ISS + 2 (covering
               the FIN's one byte of sequence space). FIN_WAIT_1's
               handler processes the ACK and, seeing 'ack >= _snd_fin',
               transitions to FIN_WAIT_2.
            6. Peer sends its FIN+ACK with seq = PEER__ISS + 1,
               ack = LOCAL__ISS + 2. FIN_WAIT_2's handler emits our
               final ACK (ACK = PEER__ISS + 2, covering peer's FIN
               byte) and transitions to TIME_WAIT.

        Assertions on each step's wire shape and state:

            * Tick #1 emits no segments.
            * Tick #2 emits exactly one FIN+ACK with the spec'd
              SEQ/ACK/flags/payload.
            * After peer's ACK of our FIN: state is FIN_WAIT_2; no
              segment emitted (ACKs of FIN do not require a reply).
            * After peer's FIN+ACK: state is TIME_WAIT; exactly one
              outbound bare-ACK with ack = PEER__ISS + 2 emerges.

        This test passes on current code as a positive-control
        regression guard. It exercises the canonical happy path
        through the entire active-close subgraph, which is the
        common case for a client-initiated graceful shutdown.
        Future changes to '_tcp_fsm_established's CLOSE-syscall
        branch, '_tcp_fsm_fin_wait_1', '_tcp_fsm_fin_wait_2', or the
        FIN-emit branch in '_transmit_data' are all caught here.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Setup precondition: idle ESTABLISHED, no in-flight data.
        self.assertEqual(
            len(session._tx_buffer),
            0,
            msg="Setup precondition: TX buffer must be empty before close().",
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: state must be ESTABLISHED before close().",
        )

        # Application calls close(). _closing flag is set; state
        # is still ESTABLISHED at this exact moment (the transition
        # happens on the next timer tick).
        session.close()
        self.assertTrue(
            session._closing,
            msg=(
                "After close() in ESTABLISHED, '_closing' must be "
                "set (line 1505 of _tcp_fsm_established's CLOSE branch)."
            ),
        )

        # Tick #1: ESTABLISHED's timer branch sees _closing AND empty
        # buffer; transitions to FIN_WAIT_1. No segment emitted on
        # this tick - the FIN fires from the FIN_WAIT_1 handler on
        # the next tick.
        transition_tx = self._advance(ms=1)
        self.assertEqual(
            transition_tx,
            [],
            msg=(
                "The ESTABLISHED -> FIN_WAIT_1 transition tick must "
                "emit no segment - state changes only; the FIN goes "
                "out from FIN_WAIT_1's timer handler on the next "
                "tick."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg=(
                "After the transition tick, state must be FIN_WAIT_1 "
                "('_closing AND not _tx_buffer' triggers the "
                "transition in '_tcp_fsm_established's timer branch)."
            ),
        )

        # Tick #2: FIN_WAIT_1's timer handler emits the FIN+ACK.
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg=(
                "FIN_WAIT_1's first timer tick must emit exactly one "
                "FIN+ACK segment via '_transmit_data's "
                "FIN-retransmit branch (line 770)."
            ),
        )
        fin_seg = self._parse_tx(fin_tx[0])
        self._assert_segment(
            fin_seg,
            flags=frozenset({"FIN", "ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
        )

        # Peer ACKs our FIN. ack = LOCAL__ISS + 2 covers the FIN's
        # one byte of sequence space.
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        peer_ack_inline = self._drive_rx(frame=peer_ack_of_fin)
        self.assertEqual(
            peer_ack_inline,
            [],
            msg=(
                "Peer's ACK of our FIN must not elicit any inline "
                "TX - ACK of an ACK is not a thing in TCP. The "
                "session simply transitions FIN_WAIT_1 -> FIN_WAIT_2."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg=(
                "After peer's ACK of our FIN (with 'ack >= _snd_fin'), "
                "state must transition to FIN_WAIT_2 per RFC 9293 "
                "§3.10.7.4."
            ),
        )

        # Peer sends its own FIN+ACK to close its half of the
        # connection. seq = PEER__ISS + 1 (no peer data was sent),
        # ack = LOCAL__ISS + 2 (still covers our FIN).
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        peer_fin_inline = self._drive_rx(frame=peer_fin)
        self.assertEqual(
            len(peer_fin_inline),
            1,
            msg=(
                "Peer's FIN+ACK must elicit exactly one outbound ACK "
                "(acknowledging peer's FIN byte). FIN_WAIT_2 -> "
                "TIME_WAIT transition per RFC 9293 §3.10.7.4."
            ),
        )
        final_ack = self._parse_tx(peer_fin_inline[0])
        self._assert_segment(
            final_ack,
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
                "After receiving peer's FIN+ACK in FIN_WAIT_2, state "
                "must transition to TIME_WAIT per RFC 9293 §3.10.7.4."
            ),
        )

    def test__close_passive__peer_fin_first_walks_through_close_wait_last_ack_closed(self) -> None:
        """
        Ensure that when the peer initiates the close (sends FIN
        before our application calls 'close()'), the FSM walks
        through the canonical passive-close path described by
        RFC 9293 §3.10.4 / §3.5, with each transition emitting the
        wire-level segment shape the spec mandates.

        The textbook trajectory:

            ESTABLISHED                              <-- receive FIN+ACK
                |                                        (peer's close)
                v                                    send ACK -->
            CLOSE_WAIT                                   (of peer's FIN)
                |
                | local 'close()' (after application
                |  drains '_rx_buffer' and chooses
                |  to close its half too)
                v                                    send FIN+ACK -->
            LAST_ACK
                |                                    <-- receive ACK
                v                                        (of our FIN)
            CLOSED

        RFC 9293 §3.10.4 (CLOSE Call, CLOSE-WAIT state):

            "Queue this request until all preceding SENDs have been
             segmentized; then send a FIN segment, enter LAST-ACK
             state."

        and §3.10.7.4 (ESTABLISHED segment processing, FIN bit):

            "If the FIN bit is set, signal the user 'connection
             closing' and return any pending RECEIVEs with same
             message, advance RCV.NXT over the FIN, and send an
             acknowledgment for the FIN.  Note that FIN implies
             PUSH for any segment text not yet delivered to the
             user."

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Peer sends FIN+ACK with no data
               (seq=PEER__ISS+1, ack=LOCAL__ISS+1). The FIN consumes
               one byte of sequence space.
            3. The ESTABLISHED FIN+ACK handler runs '_process_ack_packet'
               (which advances 'RCV.NXT' to PEER__ISS+2 because
               'seg_end' includes the FIN flag), notifies the
               application via '_event__rx_buffer.set()', and
               transitions to CLOSE_WAIT. The current FIN+ACK
               handler emits an inline ACK only when the FIN-bearing
               segment also carries data; for a pure FIN it relies
               on the delayed-ACK timer to fire the ACK on the
               first CLOSE_WAIT tick.
            4. Tick #1 (post-FIN): CLOSE_WAIT's timer branch runs
               '_delayed_ack', which fires the bare ACK acknowledging
               peer's FIN at ack=PEER__ISS+2.
            5. Application calls 'session.close()'. CLOSE_WAIT's
               CLOSE-syscall branch sets '_closing = True'; state
               stays CLOSE_WAIT.
            6. Tick #2: CLOSE_WAIT's timer branch sees
               '_closing AND not _tx_buffer' and transitions to
               LAST_ACK. No segment emitted on this tick.
            7. Tick #3: LAST_ACK's timer branch enters
               '_transmit_data's FIN-emit branch (line 770) and
               emits FIN+ACK at seq=LOCAL__ISS+1, ack=PEER__ISS+2.
            8. Peer ACKs our FIN with ack=LOCAL__ISS+2. LAST_ACK's
               handler transitions to CLOSED.

        Assertions on each step's wire shape and state:

            * Peer's FIN+ACK arrival produces no inline TX
              (delayed-ACK governs).
            * Tick #1 emits exactly one bare ACK acknowledging
              peer's FIN.
            * After 'close()' but before tick #2: state still
              CLOSE_WAIT, '_closing' set.
            * Tick #2 emits no segment (state-only transition).
            * Tick #3 emits exactly one FIN+ACK with the spec'd
              SEQ/ACK/flags/payload.
            * After peer's ACK of our FIN: state is CLOSED, the
              socket is unregistered from 'stack.sockets'.

        This test passes on current code as a positive-control
        regression guard for the canonical passive-close subgraph.
        Future changes to '_tcp_fsm_established's FIN+ACK branch,
        '_tcp_fsm_close_wait', '_tcp_fsm_last_ack', or the FIN-emit
        branch in '_transmit_data' are all caught here. It also
        documents the (RFC-permitted) choice to delay the FIN's
        ACK rather than sending it inline.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: state must be ESTABLISHED before peer initiates close.",
        )

        # Peer sends FIN+ACK to close its half. No data; the FIN
        # alone consumes one byte of sequence space.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        fin_inline = self._drive_rx(frame=peer_fin)
        self.assertEqual(
            fin_inline,
            [],
            msg=(
                "Peer's pure FIN+ACK (no data) must not produce an "
                "inline ACK from the ESTABLISHED FIN+ACK branch - "
                "the inline ACK fires only when the FIN-bearing "
                "segment also carries data; a delayed-ACK from the "
                "first CLOSE_WAIT tick covers the pure-FIN case."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg=("After peer's FIN+ACK in ESTABLISHED, state must " "transition to CLOSE_WAIT per RFC 9293 §3.10.7.4."),
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 2,
            msg=(
                "'RCV.NXT' must advance past the FIN's one byte of "
                "sequence space - '_process_ack_packet' adds "
                "'flag_fin' into 'seg_end' (line 893)."
            ),
        )

        # Tick #1: CLOSE_WAIT's timer branch fires the delayed ACK
        # acknowledging peer's FIN.
        delayed_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(delayed_ack_tx),
            1,
            msg=(
                "First CLOSE_WAIT tick must emit exactly one bare ACK "
                "acknowledging peer's FIN. The delayed-ACK timer is "
                "not yet armed at this point, so 'is_expired' returns "
                "True and the ACK fires immediately."
            ),
        )
        delayed_ack = self._parse_tx(delayed_ack_tx[0])
        self._assert_segment(
            delayed_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 2,
            payload=b"",
        )

        # Application calls close().
        session.close()
        self.assertTrue(
            session._closing,
            msg=(
                "After close() in CLOSE_WAIT, '_closing' must be set "
                "(line 1772 of '_tcp_fsm_close_wait's CLOSE branch)."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg=(
                "close() in CLOSE_WAIT only sets '_closing'; the "
                "transition to LAST_ACK happens on the next timer "
                "tick when the buffer is observed empty."
            ),
        )

        # Tick #2: CLOSE_WAIT -> LAST_ACK transition. No segment.
        transition_tx = self._advance(ms=1)
        self.assertEqual(
            transition_tx,
            [],
            msg=(
                "The CLOSE_WAIT -> LAST_ACK transition tick must "
                "emit no segment - state changes only; the FIN goes "
                "out from LAST_ACK's timer handler on the next tick."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg=(
                "After the transition tick, state must be LAST_ACK "
                "('_closing AND not _tx_buffer' triggers the "
                "transition in '_tcp_fsm_close_wait's timer branch, "
                "line 1706)."
            ),
        )

        # Tick #3: LAST_ACK's timer handler emits our FIN+ACK.
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg=(
                "LAST_ACK's first timer tick must emit exactly one "
                "FIN+ACK segment via '_transmit_data's FIN-retransmit "
                "branch (line 770)."
            ),
        )
        fin_seg = self._parse_tx(fin_tx[0])
        self._assert_segment(
            fin_seg,
            flags=frozenset({"FIN", "ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 2,
            payload=b"",
        )

        # Peer ACKs our FIN with ack = LOCAL__ISS + 2.
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        peer_ack_inline = self._drive_rx(frame=peer_ack_of_fin)
        self.assertEqual(
            peer_ack_inline,
            [],
            msg=(
                "Peer's ACK of our FIN must not elicit any inline TX "
                "- LAST_ACK's ACK handler simply transitions to CLOSED."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=("After peer's ACK of our FIN in LAST_ACK, state must " "be CLOSED per RFC 9293 §3.10.7.4."),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "On transition to CLOSED, '_change_state' must "
                "unregister the socket from 'stack.sockets' (line "
                "540) so the 4-tuple can be reused."
            ),
        )

    def test__close_active__pending_tx_data_drains_before_fin_is_emitted(self) -> None:
        """
        Ensure that an application-driven 'close()' on an ESTABLISHED
        session with unacknowledged data still in the TX buffer does
        NOT preempt the in-flight data: the buffered bytes must be
        transmitted (and on PyTCP's stricter implementation, also
        acknowledged by the peer) before the FIN segment goes out.
        The FIN's SEQ must follow the last data byte so the peer's
        cumulative-ACK arithmetic is consistent.

        RFC 9293 §3.10.4 (CLOSE Call, ESTABLISHED state):

            "Queue this until all preceding SENDs have been
             segmentized, then form a FIN segment and send it.  In
             any case, enter FIN-WAIT-1 state."

        The "queue this until" clause is the key contract: an
        application that has called 'send(data)' followed by 'close()'
        must see its data delivered to the peer with the FIN as the
        terminator, not as a flag interleaved with or preempting the
        data. PyTCP implements a stricter variant: the
        ESTABLISHED -> FIN_WAIT_1 transition fires only when
        '_closing AND not _tx_buffer' (line 1339), which means the
        buffer must drain AND the data must be acknowledged. This
        is RFC-compliant (the RFC's "queue this" clause permits any
        arbitrary delay before forming the FIN, not just "until
        segmentized") and avoids the edge case of a FIN getting
        retransmit-tangled with unacked data.

        Scenario:

            1. Drive the active-open handshake to ESTABLISHED.
               Pre-set '_snd_ewn = PEER__WIN' so the data send is
               not throttled by slow-start.
            2. Application sends 2 * MSS of data ("A"*1460 + "B"*1460).
               The bytes go into '_tx_buffer'; nothing is on the wire
               yet.
            3. Application calls 'session.close()'. '_closing' is set;
               state stays ESTABLISHED. The buffer still holds 2920
               bytes of unsent data.
            4. Tick #1: '_transmit_data' emits the first data segment
               ('A'*1460) at SEQ=LOCAL__ISS+1. The closing transition
               does NOT fire because '_tx_buffer' is non-empty.
            5. Tick #2: '_transmit_data' emits the second data segment
               ('B'*1460) at SEQ=LOCAL__ISS+1+1460. Still no FIN; still
               ESTABLISHED.
            6. Peer ACKs both segments cumulatively
               (ack=LOCAL__ISS+1+2920). '_tx_buffer' purges all 2920
               bytes.
            7. Tick #3: '_transmit_data' is a no-op (buffer empty);
               then '_closing AND not _tx_buffer' triggers the
               transition to FIN_WAIT_1. No segment emitted on this
               tick.
            8. Tick #4: FIN_WAIT_1's '_transmit_data' enters the
               FIN-emit branch (line 770) and emits FIN+ACK at
               SEQ=LOCAL__ISS+1+2920 (the byte AFTER the last data
               byte we sent). The FIN consumes one byte of sequence
               space, so '_snd_fin' lands at LOCAL__ISS+1+2920+1.

        Assertions on each step's wire shape and state:

            * Tick #1 emits exactly one data segment with payload
              'A'*1460 at SEQ=LOCAL__ISS+1; flags include neither
              FIN nor SYN; state stays ESTABLISHED.
            * Tick #2 emits exactly one data segment with payload
              'B'*1460 at SEQ=LOCAL__ISS+1+1460; no FIN; state
              stays ESTABLISHED.
            * Peer's cumulative ACK drains '_tx_buffer' to zero
              and advances 'SND.UNA' to LOCAL__ISS+1+2920.
            * Tick #3 emits no segment but transitions ESTABLISHED
              -> FIN_WAIT_1.
            * Tick #4 emits exactly one FIN+ACK at
              SEQ=LOCAL__ISS+1+2920 (immediately after the data
              tail) with no payload; state stays FIN_WAIT_1
              awaiting peer's ACK of the FIN.

        This test passes on current code as a positive-control
        regression guard for the ordering invariant that data
        precedes FIN. Future changes to the close-syscall branch
        in '_tcp_fsm_established' or to the closing-transition
        condition that allowed the FIN to be emitted before
        '_tx_buffer' drained would be caught here - the FIN's
        SEQ would land inside or before the data range, breaking
        the cumulative-ACK arithmetic and risking peer rejection
        of either the data or the FIN.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._snd_ewn = PEER__WIN

        # Application enqueues 2 * MSS of data.
        payload_a = b"A" * 1460
        payload_b = b"B" * 1460
        session.send(data=payload_a + payload_b)

        # Application calls close() while data is still in '_tx_buffer'.
        session.close()
        self.assertTrue(
            session._closing,
            msg="Setup precondition: '_closing' must be set after close().",
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "close() with a non-empty TX buffer must not transition "
                "out of ESTABLISHED - the FIN must follow the data."
            ),
        )
        self.assertEqual(
            len(session._tx_buffer),
            2 * 1460,
            msg="Setup precondition: '_tx_buffer' must hold 2 MSS of unsent data.",
        )

        # Tick #1: first data segment fires. No FIN.
        seg1_tx = self._advance(ms=1)
        self.assertEqual(
            len(seg1_tx),
            1,
            msg="Tick #1 must emit exactly one segment (the first data segment).",
        )
        seg1 = self._parse_tx(seg1_tx[0])
        self._assert_segment(
            seg1,
            seq=LOCAL__ISS + 1,
            payload=payload_a,
        )
        self.assertNotIn(
            "FIN",
            seg1.flags,
            msg=(
                "First data segment MUST NOT carry FIN - the FIN may "
                "only appear after all queued data is segmentized "
                "(RFC 9293 §3.10.4 'Queue this until all preceding "
                "SENDs have been segmentized')."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED while data is still in '_tx_buffer'.",
        )

        # Tick #2: second data segment fires. Still no FIN.
        seg2_tx = self._advance(ms=1)
        self.assertEqual(
            len(seg2_tx),
            1,
            msg="Tick #2 must emit exactly one segment (the second data segment).",
        )
        seg2 = self._parse_tx(seg2_tx[0])
        self._assert_segment(
            seg2,
            seq=LOCAL__ISS + 1 + len(payload_a),
            payload=payload_b,
        )
        self.assertNotIn(
            "FIN",
            seg2.flags,
            msg=(
                "Second data segment MUST NOT carry FIN - the FIN "
                "follows the data tail, not riding on the last data "
                "segment."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED until '_tx_buffer' drains.",
        )

        # Peer cumulatively ACKs both segments.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 2 * 1460,
            flags=("ACK",),
            win=PEER__WIN,
        )
        peer_ack_inline = self._drive_rx(frame=peer_ack)
        self.assertEqual(
            peer_ack_inline,
            [],
            msg=(
                "Peer's cumulative ACK must not produce inline TX; "
                "data drain alone does not trigger the FIN immediately."
            ),
        )
        self.assertEqual(
            len(session._tx_buffer),
            0,
            msg="'_tx_buffer' must be drained after the peer's cumulative ACK.",
        )
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1 + 2 * 1460,
            msg="'SND.UNA' must advance to cover all ACKed data.",
        )

        # Tick #3: empty-buffer transition to FIN_WAIT_1. No segment.
        transition_tx = self._advance(ms=1)
        self.assertEqual(
            transition_tx,
            [],
            msg=(
                "The ESTABLISHED -> FIN_WAIT_1 transition tick (after "
                "buffer drain) must emit no segment; the FIN goes out "
                "from FIN_WAIT_1's timer handler on the next tick."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg=(
                "After the buffer drains, '_closing AND not _tx_buffer' "
                "fires the ESTABLISHED -> FIN_WAIT_1 transition."
            ),
        )

        # Tick #4: FIN+ACK fires at SEQ immediately after the data
        # tail.
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg=(
                "FIN_WAIT_1's first timer tick must emit exactly one "
                "FIN+ACK segment via '_transmit_data's FIN-retransmit "
                "branch."
            ),
        )
        fin_seg = self._parse_tx(fin_tx[0])
        self._assert_segment(
            fin_seg,
            flags=frozenset({"FIN", "ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1 + 2 * 1460,
            ack=PEER__ISS + 1,
            payload=b"",
        )
        self.assertEqual(
            session._snd_fin,
            LOCAL__ISS + 1 + 2 * 1460 + 1,
            msg=(
                "After emitting the FIN, '_snd_fin' must equal the "
                "post-FIN 'SND.NXT' (data_end + 1) - this is what "
                "FIN_WAIT_1's ACK-acceptance check uses to recognise "
                "the peer's ACK of our FIN."
            ),
        )

    def test__close_passive__data_bearing_fin_elicits_inline_cumulative_ack(self) -> None:
        """
        Ensure that a peer FIN+ACK that ALSO carries data is handled
        as a single atomic event: the data is enqueued into
        '_rx_buffer', RCV.NXT advances past both the data and the
        FIN's one byte of sequence space, an inline cumulative ACK
        fires immediately (not delayed), and the FSM transitions to
        CLOSE_WAIT. The data must remain in '_rx_buffer' so the
        application can drain it via 'recv()' even after the peer
        has closed its half.

        RFC 9293 §3.10.7.4 (ESTABLISHED segment processing, sequencing
        across data and FIN):

            "If the FIN bit is set, signal the user 'connection
             closing' and return any pending RECEIVEs with same
             message, advance RCV.NXT over the FIN, and send an
             acknowledgment for the FIN.  Note that FIN implies
             PUSH for any segment text not yet delivered to the
             user."

        and from §3.10.4 (CLOSE-WAIT semantics):

            "CLOSE-WAIT - represents waiting for a connection
             termination request from the local user."

        The PyTCP implementation collapses the data-with-FIN case
        into a single inline ACK (rather than letting the delayed-
        ACK timer cover it), which is the RFC's recommended path
        for FIN-bearing segments per the "send an acknowledgment
        for the FIN" clause and the "PUSH" semantics that imply
        immediate delivery.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Peer sends FIN+ACK with a payload (b"final-data",
               10 bytes) at SEQ=PEER__ISS+1. The segment carries
               BOTH new data AND the FIN.
            3. Drive RX. The ESTABLISHED FIN+ACK branch runs
               '_process_ack_packet' (which advances RCV.NXT to
               PEER__ISS+1+10+1 because 'seg_end' includes both
               data length and 'flag_fin'), then takes the
               'if packet_rx_md.tcp__data' branch (line 1478) to
               emit an INLINE ACK acknowledging both the data and
               the FIN, and transitions to CLOSE_WAIT.

        Assertions on the inline ACK:

            * Exactly one inline TX frame produced by the FIN
              arrival.
            * Flags = {ACK} (no FIN, no SYN, no RST).
            * 'ack = PEER__ISS + 1 + 10 + 1' - the cumulative
              acknowledgement covers all 10 data bytes AND the
              FIN's one-byte sequence consumption.
            * 'seq = LOCAL__ISS + 1' - we have not advanced our
              own send sequence (no data sent on our side).
            * 'payload = b""' - bare ACK.
            * Advertised window = 65535 - 10 (the new buffer
              occupancy after the data was enqueued; per the
              receive-window-shrink fix from commit 'f3c3392').

        Side assertions on session state:

            * State is CLOSE_WAIT.
            * 'RCV.NXT == PEER__ISS + 1 + 10 + 1' - past the data
              and the FIN.
            * '_rx_buffer == b"final-data"' - the application can
              still recv() the data even though the peer has
              closed its half.
            * '_event__rx_buffer' is set (so 'recv()' can wake up
              and observe both the data and the connection-closing
              signal).

        This test passes on current code as a positive-control
        regression guard for the data-with-FIN inline-ACK path
        (line 1478 of '_tcp_fsm_established'). It catches any
        future change that:
          - Defers the ACK to the delayed-ACK timer when data is
            present (would break the "send an acknowledgment for
            the FIN" RFC clause).
          - Discards the data when the FIN flag is set (a real
            risk during refactors that branch on FIN before
            looking at payload).
          - Computes 'ack' without including the FIN's one-byte
            sequence consumption (would leave the peer
            retransmitting the FIN forever).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Peer sends FIN+ACK with a payload. The segment carries
        # both new data and the connection-close signal.
        peer_payload = b"final-data"
        peer_fin_with_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK", "PSH"),
            win=PEER__WIN,
            payload=peer_payload,
        )
        inline_tx = self._drive_rx(frame=peer_fin_with_data)

        # The inline ACK fires immediately for FIN-bearing segments
        # with data per RFC 9293 §3.10.7.4 and the explicit
        # 'if packet_rx_md.tcp__data' branch in
        # '_tcp_fsm_established's FIN+ACK handler (line 1478).
        self.assertEqual(
            len(inline_tx),
            1,
            msg=(
                "Peer's data-bearing FIN+ACK must produce exactly one "
                "inline ACK - RFC 9293 §3.10.7.4 mandates 'send an "
                "acknowledgment for the FIN' and the data-bearing "
                "branch fires the ACK without waiting for the "
                "delayed-ACK timer."
            ),
        )
        ack = self._parse_tx(inline_tx[0])
        self._assert_segment(
            ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1 + len(peer_payload) + 1,
            payload=b"",
            win=65535 - len(peer_payload),
        )

        # State assertions: the FSM has moved to CLOSE_WAIT, the
        # data is in '_rx_buffer' awaiting application recv(), and
        # RCV.NXT has advanced past both data and FIN.
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg=(
                "After peer's data-bearing FIN+ACK in ESTABLISHED, "
                "state must transition to CLOSE_WAIT per RFC 9293 "
                "§3.10.7.4."
            ),
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1 + len(peer_payload) + 1,
            msg=(
                "'RCV.NXT' must advance past BOTH the data ("
                f"{len(peer_payload)} bytes) AND the FIN's one byte "
                "of sequence space - '_process_ack_packet' adds "
                "'len(tcp__data) + flag_fin' into 'seg_end' so a "
                "single update covers both."
            ),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            peer_payload,
            msg=(
                "The data piggybacked on peer's FIN must be enqueued "
                "into '_rx_buffer' so the application can recv() it "
                "even after the peer has closed its half. Discarding "
                "the data because of the FIN flag would break the "
                "'FIN implies PUSH' RFC clause and lose application "
                "bytes."
            ),
        )
        self.assertTrue(
            session._event__rx_buffer.is_set(),
            msg=(
                "The '_event__rx_buffer' must be set on the FIN+ACK "
                "branch (line 1482 of '_tcp_fsm_established') so a "
                "blocked 'recv()' wakes up and observes both the "
                "final data and the connection-closing signal."
            ),
        )

    def test__close_passive__close_wait_pre_fin_data_retransmit_elicits_ack_per_rfc_3_10_7_4(self) -> None:
        """
        Ensure that when a peer retransmits previously-received
        pre-FIN data while we are in CLOSE_WAIT, we respond with
        an ACK reply per RFC 9293 §3.10.7.4 step 1, rather than
        silently dropping the segment. The retransmit's payload
        is unacceptable (SEG.SEQ + SEG.LEN <= RCV.NXT - all bytes
        already cumulatively-acknowledged before peer's FIN), but
        the spec requires unacceptable segments to elicit an ACK
        so peer's retransmit machinery sees fresh activity and
        can stop retransmitting.

        RFC 9293 §3.10.7.4 step 1:

            "If an incoming segment is not acceptable, an
             acknowledgment should be sent in reply (unless the
             RST bit is set, if so drop the segment and return):
             <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>. After sending
             the acknowledgment, drop the unacceptable segment
             and return."

        The CLOSE_WAIT handler in PyTCP today has no receive-
        window acceptability check at the top and no fallback
        ACK for unacceptable segments; only segments matching
        one of the four explicit branches (suspected-retransmit
        dup-ACK, OOO data, regular bare ACK, RST) elicit any
        outbound activity. A pre-FIN data retransmit fits NONE
        of those branches (its seq is below RCV.NXT and it
        carries data), so it falls through silently. Peer's
        retransmit timer fires repeatedly until RTO clears the
        connection - wasted bandwidth and visible peer-side
        latency.

        Same gap exists in CLOSING / FIN_WAIT_1 / FIN_WAIT_2 /
        LAST_ACK; this test pins the CLOSE_WAIT case as the
        canonical example. The fix is structurally shared with
        the ESTABLISHED Phase 7 DSACK handler: extract the
        receive-window acceptability check + always-ACK reply
        into a helper and apply it to all synchronized states.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Peer sends 50 bytes of data. Drain so the bytes
               are delivered to '_rx_buffer' and the delayed
               ACK fires (RCV.NXT advances to PEER__ISS + 1 +
               50; RCV.UNA == RCV.NXT).
            3. Peer sends FIN. We transition to CLOSE_WAIT;
               RCV.NXT advances past the FIN to PEER__ISS + 1
               + 50 + 1; we ACK the FIN.
            4. Application sends 4 bytes (so SND.MAX >
               SND.UNA - the test exercises the unacceptable-
               segment-with-piggybacked-ACK case where peer's
               retransmit HAS ack info that would advance our
               SND.UNA if processed; per RFC 9293 §3.10.7.4
               step 1 that ACK info MUST NOT be processed
               because the segment is unacceptable and
               dropped).
            5. Peer retransmits the original 50-byte data
               segment with seq = PEER__ISS + 1 (below our
               RCV.NXT) AND ack = LOCAL__ISS + 1 + 4 (cum-
               ACKing our 4-byte send). The segment is
               unacceptable per RFC 9293 §3.10.7.4 receive-
               window check.
            6. Inspect the inline TX. Per RFC 9293 §3.10.7.4
               step 1 we MUST emit one ACK reply.

        Required wire shape of the ACK reply:

            seq       = LOCAL__ISS + 1 + 4    (= our SND.NXT)
            ack       = PEER__ISS + 1 + 50 + 1 (= our RCV.NXT,
                                               post-FIN)
            flags     = {ACK}
            payload   = b""

        Side effects asserted:

            * Exactly one outbound ACK fires.
            * 'session._snd_una' is unchanged (peer's piggy-
              backed ACK info was NOT processed - the
              unacceptable segment was dropped at the
              acceptability check, before the ACK-field
              processing in §3.10.7.4 step 5).
            * 'session._rcv_nxt' is unchanged (data not re-
              delivered, no overlap recompute).
            * 'session._rx_buffer' contents unchanged (the
              data is already in there from step 2; the
              retransmit MUST NOT double-deliver).
            * 'session.state' remains CLOSE_WAIT.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_close_wait' has no
        receive-window acceptability check and no fall-through
        unacceptable-segment ACK reply. The retransmit falls
        through to the end of the handler (the 'return' just
        below the 'Regular data/ACK packet' branch) without
        emitting any outbound segment. Today this test fails
        at the 'len(retransmit_tx) == 1' assertion - the
        actual count is 0.

        Fix outline (separate commit): extract the receive-
        window acceptability check from
        '_tcp_fsm_established' into a helper
        '_check_segment_acceptability(packet_rx_md)' that
        returns True/False and emits the RFC 9293 §3.10.7.4
        step 1 ACK reply when False. Apply the helper at the
        top of '_tcp_fsm_close_wait' (and ideally
        '_tcp_fsm_fin_wait_1', '_fin_wait_2', '_closing',
        '_last_ack' - same RFC mandate).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Peer sends 50 bytes of data.
        peer_payload = b"X" * 50
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        self._drive_rx(frame=peer_data)
        # Drain the delayed ACK.
        self._advance(ms=200)

        # Peer sends FIN. We transition to CLOSE_WAIT.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 50,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="Setup precondition: peer's FIN must put session in CLOSE_WAIT.",
        )

        # Application sends 4 bytes so SND.MAX > SND.UNA. This
        # gives peer's retransmit-with-piggybacked-ACK something
        # to potentially (incorrectly) advance SND.UNA against;
        # per RFC the ACK info MUST be ignored because the
        # segment fails the acceptability check.
        session._snd_ewn = PEER__WIN
        session.send(data=b"OUT!")
        self._advance(ms=1)

        snd_una_before = session._snd_una
        snd_nxt_before = session._snd_nxt
        rcv_nxt_before = session._rcv_nxt
        rx_buffer_before = bytes(session._rx_buffer)

        # Peer retransmits the original 50-byte data segment
        # with a piggybacked ACK that would advance SND.UNA if
        # processed (it cum-ACKs our 4-byte send). The segment
        # is unacceptable per RFC 9293 §3.10.7.4 - SEG.SEQ +
        # SEG.LEN = PEER__ISS + 1 + 50 = current RCV.NXT - 1
        # (just below RCV.NXT, fully duplicate).
        retransmit = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 4,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        retransmit_tx = self._drive_rx(frame=retransmit)

        self.assertEqual(
            len(retransmit_tx),
            1,
            msg=(
                "RFC 9293 §3.10.7.4 step 1: an unacceptable "
                "segment in CLOSE_WAIT MUST elicit an ACK reply "
                "carrying our current SND.NXT and RCV.NXT, so "
                "peer's retransmit machinery sees fresh activity "
                "and can stop retransmitting. PyTCP today drops "
                "the segment silently; peer keeps retransmitting "
                "until RTO."
            ),
        )
        ack_probe = self._parse_tx(retransmit_tx[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertEqual(
            session._snd_una,
            snd_una_before,
            msg=(
                "Per RFC 9293 §3.10.7.4 step 1 the unacceptable "
                "segment is dropped BEFORE the ACK-field processing "
                "step 5; peer's piggybacked ACK info MUST NOT "
                "advance SND.UNA."
            ),
        )
        self.assertEqual(
            session._rcv_nxt,
            rcv_nxt_before,
            msg="RCV.NXT must not advance on a fully-duplicate segment.",
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            rx_buffer_before,
            msg=(
                "Already-delivered data must not be re-enqueued "
                "into '_rx_buffer'; the retransmit's payload "
                "duplicates bytes the application has already "
                "consumed (or will, on next 'recv()')."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="State must remain CLOSE_WAIT after a fully-duplicate retransmit.",
        )

    def test__close_active__fin_wait_1_unacceptable_segment_elicits_ack_per_rfc_3_10_7_4(self) -> None:
        """
        Ensure that FIN_WAIT_1 honours RFC 9293 §3.10.7.4 step 1
        and emits an ACK reply on unacceptable inbound segments
        rather than silently dropping them. Same RFC mandate as
        the CLOSE_WAIT case (commit '7f0d18b' fixed via
        '_check_segment_acceptability') and the ESTABLISHED case
        (covered since Phase 7 DSACK + the fix in '7f0d18b' /
        'df96d27'); FIN_WAIT_1 was the first sibling state left
        without the helper.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Peer sends 50 bytes of data; drain past delayed
               ACK so RCV.NXT advances and the bytes are
               acknowledged.
            3. Application calls close(); two ticks transition
               ESTABLISHED -> FIN_WAIT_1 and emit our FIN.
            4. Peer retransmits the original 50-byte data
               segment with seq = PEER__ISS + 1 (entirely below
               RCV.NXT - fully duplicate, unacceptable per
               §3.10.7.4 step 1).
            5. Per RFC §3.10.7.4 step 1: ACK reply with our
               current SND.NXT and RCV.NXT.
            6. Today: silent drop.

        Required wire shape of the ACK reply:

            seq       = LOCAL__ISS + 2     (= our SND.NXT post-FIN)
            ack       = PEER__ISS + 1 + 50 (= our RCV.NXT)
            flags     = {ACK}
            payload   = b""

        Assertions:

            * Exactly one outbound ACK fires inline on the
              retransmit's arrival.
            * 'session.state' remains FIN_WAIT_1 (the unacceptable
              segment is dropped, not processed; SND.UNA does not
              advance past our FIN).

        [FLAGS BUG] - 'TcpSession._tcp_fsm_fin_wait_1' has no
        receive-window acceptability check at the top. Segments
        with seq below RCV.NXT (fully duplicate) match none of
        the explicit branches (suspected-retransmit dup-ACK
        requires no-data; OOO branch requires seq > rcv_nxt;
        regular bare ACK requires seq == rcv_nxt; FIN+ACK
        requires seq == rcv_nxt; RST handlers require seq ==
        rcv_nxt) and fall through silently.

        Fix outline (separate commit): route the helper at the
        top of '_tcp_fsm_fin_wait_1' below the SYN-bearing
        branch (which preempts acceptability per RFC 5961 §4):

            if packet_rx_md is not None and not self._check_segment_acceptability(packet_rx_md):
                return

        Same one-liner that '7f0d18b' added to ESTABLISHED and
        CLOSE_WAIT. The helper handles RST exception, DSACK case-1
        stash, and the rate-limited ACK reply uniformly.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Peer sends 50 bytes of data and we drain the delayed-ACK
        # so RCV.NXT advances.
        peer_payload = b"X" * 50
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        self._drive_rx(frame=peer_data)
        self._advance(ms=200)

        # Application close() -> two ticks: state transition then
        # FIN emit. Final state: FIN_WAIT_1.
        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: close() must transition to FIN_WAIT_1.",
        )
        self.assertEqual(
            session._snd_fin,
            LOCAL__ISS + 2,
            msg="Setup precondition: our FIN must have fired (SND.FIN = LOCAL__ISS + 2).",
        )

        snd_una_before = session._snd_una
        snd_nxt_before = session._snd_nxt
        rcv_nxt_before = session._rcv_nxt

        # Peer retransmits the original 50-byte data segment - seq
        # entirely below RCV.NXT, fully duplicate, unacceptable per
        # RFC §3.10.7.4 step 1.
        retransmit = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        retransmit_tx = self._drive_rx(frame=retransmit)

        self.assertEqual(
            len(retransmit_tx),
            1,
            msg=(
                "RFC 9293 §3.10.7.4 step 1: an unacceptable segment "
                "in FIN_WAIT_1 MUST elicit an ACK reply with our "
                "current SND.NXT and RCV.NXT, the same way ESTABLISHED "
                "and CLOSE_WAIT handle it. PyTCP today drops the "
                "segment silently because '_tcp_fsm_fin_wait_1' has "
                "no acceptability check at the top."
            ),
        )
        ack_probe = self._parse_tx(retransmit_tx[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertEqual(
            session._snd_una,
            snd_una_before,
            msg=(
                "Per RFC §3.10.7.4 step 1 the unacceptable segment "
                "is dropped after the empty-ACK reply; SND.UNA must "
                "NOT advance."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="State must remain FIN_WAIT_1 after a fully-duplicate retransmit.",
        )

    def test__close_active__fin_wait_2_unacceptable_segment_elicits_ack_per_rfc_3_10_7_4(self) -> None:
        """
        Ensure that FIN_WAIT_2 honours RFC 9293 §3.10.7.4 step 1
        and emits an ACK reply on unacceptable inbound segments.
        Sibling-state coverage for the same gap class as the
        FIN_WAIT_1 test above.

        Setup: drive ESTABLISHED -> close() -> FIN_WAIT_1 ->
        peer ACKs our FIN -> FIN_WAIT_2. Then peer retransmits
        old data; today silent drop, after fix ACK reply.

        Assertions: same as FIN_WAIT_1; per RFC §3.10.7.4 step 1
        an unacceptable segment elicits an ACK with our current
        SND.NXT and RCV.NXT.

        [FLAGS BUG] - '_tcp_fsm_fin_wait_2' has no acceptability
        check at the top. Same fix shape as FIN_WAIT_1 / CLOSE_WAIT
        / ESTABLISHED: route through '_check_segment_acceptability'.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        peer_payload = b"X" * 50
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        self._drive_rx(frame=peer_data)
        self._advance(ms=200)

        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        self._advance(ms=1)
        # Peer ACKs our FIN -> FIN_WAIT_2.
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 50,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_of_fin)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="Setup precondition: peer's ACK of our FIN must transition to FIN_WAIT_2.",
        )

        snd_nxt_before = session._snd_nxt
        rcv_nxt_before = session._rcv_nxt

        retransmit = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        retransmit_tx = self._drive_rx(frame=retransmit)

        self.assertEqual(
            len(retransmit_tx),
            1,
            msg=(
                "RFC 9293 §3.10.7.4 step 1: an unacceptable segment "
                "in FIN_WAIT_2 MUST elicit an ACK reply. PyTCP today "
                "drops it silently because '_tcp_fsm_fin_wait_2' has "
                "no acceptability check at the top."
            ),
        )
        ack_probe = self._parse_tx(retransmit_tx[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="State must remain FIN_WAIT_2 after a fully-duplicate retransmit.",
        )

    def test__close_passive__last_ack_unacceptable_segment_elicits_ack_per_rfc_3_10_7_4(self) -> None:
        """
        Ensure that LAST_ACK honours RFC 9293 §3.10.7.4 step 1
        and emits an ACK reply on unacceptable inbound segments.
        Sibling-state coverage; LAST_ACK is reached on the
        passive-close path: peer FIN -> we go to CLOSE_WAIT ->
        application close() -> LAST_ACK (waiting for peer's ACK
        of our FIN).

        Setup: drive ESTABLISHED -> peer FIN -> CLOSE_WAIT ->
        application close() -> LAST_ACK. Then peer retransmits
        old data; today silent drop, after fix ACK reply.

        [FLAGS BUG] - '_tcp_fsm_last_ack' has no acceptability
        check at the top. Same fix shape as the sibling states.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        peer_payload = b"X" * 50
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        self._drive_rx(frame=peer_data)
        self._advance(ms=200)

        # Peer FIN -> CLOSE_WAIT.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 50,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="Setup precondition: peer's FIN must transition to CLOSE_WAIT.",
        )

        # Application close() in CLOSE_WAIT -> deferred LAST_ACK.
        # First tick transitions CLOSE_WAIT -> LAST_ACK; second
        # tick fires our FIN.
        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="Setup precondition: close() in CLOSE_WAIT must transition to LAST_ACK.",
        )

        snd_nxt_before = session._snd_nxt
        rcv_nxt_before = session._rcv_nxt

        retransmit = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        retransmit_tx = self._drive_rx(frame=retransmit)

        self.assertEqual(
            len(retransmit_tx),
            1,
            msg=(
                "RFC 9293 §3.10.7.4 step 1: an unacceptable segment "
                "in LAST_ACK MUST elicit an ACK reply. PyTCP today "
                "drops it silently because '_tcp_fsm_last_ack' has "
                "no acceptability check at the top."
            ),
        )
        ack_probe = self._parse_tx(retransmit_tx[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="State must remain LAST_ACK after a fully-duplicate retransmit.",
        )

    def test__close_active__fin_wait_1_unacceptable_ack_beyond_snd_max_triggers_empty_ack(self) -> None:
        """
        Ensure that FIN_WAIT_1's ACK-only handler emits an
        empty-ACK reply when peer sends 'tcp__ack > SND.MAX'
        per RFC 9293 §3.10.7.4 step 5. Sibling-state coverage
        for the gap class fixed in CLOSING (commit '95a2a4e').

        Setup: drive close() to FIN_WAIT_1. Peer sends bare ACK
        with ack acknowledging unsent data. Today silent drop;
        after fix empty-ACK reply with our SND.NXT / RCV.NXT.

        [FLAGS BUG] - the FIN_WAIT_1 ACK-only branch exits
        without emitting on unacceptable-ACK fallthrough. Same
        fix shape as CLOSING.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: state must be FIN_WAIT_1.",
        )

        snd_nxt_before = session._snd_nxt
        rcv_nxt_before = session._rcv_nxt

        peer_unacceptable_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 0xDEAD,
            flags=("ACK",),
            win=PEER__WIN,
        )
        unacceptable_ack_inline = self._drive_rx(frame=peer_unacceptable_ack)

        self.assertEqual(
            len(unacceptable_ack_inline),
            1,
            msg=(
                "RFC 9293 §3.10.7.4 step 5: an ACK acknowledging "
                "unsent data ('SEG.ACK > SND.NXT') in FIN_WAIT_1 "
                "MUST elicit an empty-ACK reply. PyTCP today "
                "drops it silently."
            ),
        )
        ack_probe = self._parse_tx(unacceptable_ack_inline[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="State must remain FIN_WAIT_1 after an unacceptable ACK.",
        )

    def test__close_active__fin_wait_2_unacceptable_ack_beyond_snd_max_triggers_empty_ack(self) -> None:
        """
        Same gap class as the FIN_WAIT_1 test above; this one
        covers FIN_WAIT_2.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        self._advance(ms=1)

        # Peer ACKs our FIN -> FIN_WAIT_2.
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_of_fin)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="Setup precondition: state must be FIN_WAIT_2.",
        )

        snd_nxt_before = session._snd_nxt
        rcv_nxt_before = session._rcv_nxt

        peer_unacceptable_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 0xDEAD,
            flags=("ACK",),
            win=PEER__WIN,
        )
        unacceptable_ack_inline = self._drive_rx(frame=peer_unacceptable_ack)

        self.assertEqual(
            len(unacceptable_ack_inline),
            1,
            msg=(
                "RFC 9293 §3.10.7.4 step 5: an ACK acknowledging "
                "unsent data ('SEG.ACK > SND.NXT') in FIN_WAIT_2 "
                "MUST elicit an empty-ACK reply."
            ),
        )
        ack_probe = self._parse_tx(unacceptable_ack_inline[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="State must remain FIN_WAIT_2 after an unacceptable ACK.",
        )

    def test__close_passive__last_ack_unacceptable_ack_beyond_snd_max_triggers_empty_ack(self) -> None:
        """
        Same gap class as the FIN_WAIT_1 / FIN_WAIT_2 tests
        above; this one covers LAST_ACK.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Peer FIN -> CLOSE_WAIT.
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
            FsmState.CLOSE_WAIT,
            msg="Setup precondition: peer's FIN must transition to CLOSE_WAIT.",
        )
        # Application close() in CLOSE_WAIT -> LAST_ACK.
        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="Setup precondition: state must be LAST_ACK.",
        )

        snd_nxt_before = session._snd_nxt
        rcv_nxt_before = session._rcv_nxt

        peer_unacceptable_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,  # past peer's FIN
            ack=LOCAL__ISS + 0xDEAD,
            flags=("ACK",),
            win=PEER__WIN,
        )
        unacceptable_ack_inline = self._drive_rx(frame=peer_unacceptable_ack)

        self.assertEqual(
            len(unacceptable_ack_inline),
            1,
            msg=(
                "RFC 9293 §3.10.7.4 step 5: an ACK acknowledging "
                "unsent data ('SEG.ACK > SND.NXT') in LAST_ACK "
                "MUST elicit an empty-ACK reply."
            ),
        )
        ack_probe = self._parse_tx(unacceptable_ack_inline[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="State must remain LAST_ACK after an unacceptable ACK.",
        )

    def test__close_passive__close_wait_post_fin_data_elicits_ack_without_enqueue(self) -> None:
        """
        Ensure that when peer (RFC-violatingly) sends data after
        their own FIN - i.e. an in-window segment in CLOSE_WAIT
        with 'seq == RCV.NXT' carrying payload - the receiver
        emits an empty ACK so peer's retransmit machinery sees
        fresh activity, but does NOT enqueue the data into
        '_rx_buffer' (RFC 9293 §3.10.7.4 step 7 lists ESTABLISHED,
        FIN-WAIT-1, FIN-WAIT-2 as the states that deliver segment
        text - CLOSE_WAIT is NOT listed) and does NOT advance
        RCV.NXT past it.

        RFC 9293 §3.10.7.4 step 7 (Segment Text Processing):

            "ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2 STATE:
             Once in the ESTABLISHED state, it is possible to
             deliver segment text to user RECEIVE buffers."

        The list omits CLOSE-WAIT, CLOSING, LAST-ACK, and
        TIME-WAIT - all post-half-close states where the local
        application has been signalled EOF and MUST NOT receive
        further bytes. A peer that sends data past their own
        FIN is RFC-violating; the receiver must not pass those
        bytes up to the application (BSD socket semantics:
        recv() returns b"" once peer FIN'd; appending fresh
        data after EOF would break that contract). But the
        receiver still needs to acknowledge the segment was
        received so peer's retransmit timer backs off; without
        an ACK reply, peer's TCP retransmits indefinitely until
        their R2 fires.

        The "ACK without enqueue" pattern is the conservative
        BSD-stack approach. The stricter alternative (RST on
        post-FIN data, treating it as a protocol error per
        RFC 9293 §3.10.7.2's "any other incoming control or
        data ... will be processed in the SYN-RECEIVED state"
        clause read very strictly) is also legal but more
        aggressive; PyTCP follows the conservative path
        elsewhere (e.g. SYN piggybacked data on listener
        handshake is queued, not dropped or RST'd) so this
        test pins the conservative variant.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Peer sends FIN+ACK at seq=PEER__ISS+1, ack=
               LOCAL__ISS+1. Session transitions ESTABLISHED ->
               CLOSE_WAIT; RCV.NXT advances to PEER__ISS+2.
            3. Peer (RFC-violatingly) sends a fresh data
               segment at seq=PEER__ISS+2 (= RCV.NXT) carrying
               b"X" * 50.
            4. Snapshot '_rx_buffer' before; should remain
               unchanged after.
            5. Drive RX. Inspect inline TX list.

        Assertions:

            * Exactly one outbound ACK fires inline.
            * The ACK carries 'ack=PEER__ISS+2' (= current
              RCV.NXT, NOT advanced past peer's post-FIN data).
            * 'session._rx_buffer' is unchanged - the data
              must NOT be enqueued past peer's FIN (would
              corrupt application's post-EOF view of the
              stream).
            * 'session._rcv_nxt' is unchanged at PEER__ISS+2 -
              accepting the post-FIN data into the receive
              sequence space would violate RFC 9293's "FIN
              consumes the last byte of the sequence space"
              invariant.
            * Session state stays CLOSE_WAIT.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_close_wait's regular
        ACK branch (line ~2711) gates the '_process_ack_packet'
        call on 'not packet_rx_md.tcp__data', so any data-
        bearing in-order segment falls through to bare 'return'
        without an ACK reply. The upstream
        '_check_segment_acceptability' DID accept the segment
        (in window, len > 0, RCV.WND > 0) but only emits an ACK
        on UNACCEPTABLE inputs. Net effect: silent drop. Peer
        retransmits indefinitely until their own R2 fires
        (~100 s+ later).

        Fix outline (separate commit):

            Drop the 'not packet_rx_md.tcp__data' clause from
            the regular-data branch and add an explicit "data
            in CLOSE_WAIT" path that processes the ACK field
            but does NOT enqueue or advance RCV.NXT, then emits
            the cum-ACK so peer's retransmit timer backs off.

        Severity: LOW. Only affects RFC-violating peers
        (sending data past their own FIN) but the silent-drop
        behaviour wastes peer-side bandwidth on the
        retransmit-storm and pins peer's TCP in ESTABLISHED
        until their R2 expires.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Step 2: peer FIN+ACK -> CLOSE_WAIT.
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
            FsmState.CLOSE_WAIT,
            msg="Setup precondition: state must be CLOSE_WAIT after peer FIN.",
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 2,
            msg=("Setup precondition: RCV.NXT must have advanced past " "peer's FIN to PEER__ISS+2."),
        )
        rx_buffer_before = bytes(session._rx_buffer)
        rcv_nxt_before = session._rcv_nxt

        # Step 3: peer sends post-FIN data at seq == RCV.NXT.
        # RFC violation by peer, but PyTCP must respond
        # gracefully.
        post_fin_data = b"X" * 50
        peer_post_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,  # == RCV.NXT
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=post_fin_data,
        )
        post_fin_tx = self._drive_rx(frame=peer_post_fin)

        # Spec: exactly one ACK fires inline.
        self.assertEqual(
            len(post_fin_tx),
            1,
            msg=(
                "Peer's post-FIN data segment in CLOSE_WAIT MUST "
                "elicit exactly one outbound ACK so peer's "
                "retransmit machinery backs off. Today the "
                "regular-data branch's 'not packet_rx_md.tcp__data' "
                "clause makes the segment fall through to silent "
                "drop. Fix: drop the clause and add an explicit "
                f"'data in CLOSE_WAIT' ACK-without-enqueue path. Got: {post_fin_tx!r}"
            ),
        )
        ack_probe = self._parse_tx(post_fin_tx[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            ack=rcv_nxt_before,
        )

        # Spec: '_rx_buffer' is unchanged - the data must not
        # leak past peer's FIN into the application's view of
        # the stream.
        self.assertEqual(
            bytes(session._rx_buffer),
            rx_buffer_before,
            msg=(
                "Peer's post-FIN data MUST NOT be enqueued into "
                "'_rx_buffer'. Application's recv() returns b\"\" "
                "after peer's FIN signals EOF; appending fresh "
                "bytes after that signal breaks BSD socket "
                "semantics. RFC 9293 §3.10.7.4 step 7 lists only "
                "ESTABLISHED / FIN-WAIT-1 / FIN-WAIT-2 as the "
                "states that deliver segment text - CLOSE_WAIT "
                "is NOT among them."
            ),
        )

        # Spec: 'RCV.NXT' is unchanged - accepting the data into
        # the receive sequence space would violate the "FIN
        # consumes the last byte of seq space" invariant.
        self.assertEqual(
            session._rcv_nxt,
            rcv_nxt_before,
            msg=(
                "Peer's post-FIN data MUST NOT advance RCV.NXT - "
                "RCV.NXT was set to 'peer_fin_seq + 1' when peer's "
                "FIN was processed; advancing it further would "
                "treat post-FIN bytes as legitimate sequence space."
            ),
        )

        # Spec: state stays CLOSE_WAIT - the post-FIN data is
        # an anomaly, not a state-transition trigger.
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="State must remain CLOSE_WAIT after post-FIN data.",
        )

    def test__close_passive__close_wait_ooo_post_fin_data_must_not_queue(self) -> None:
        """
        Ensure that when peer (RFC-violatingly) sends OOO data in
        CLOSE_WAIT - data with 'seq > RCV.NXT', i.e. PAST the
        seq just past their own FIN - the segment is NOT stored
        in 'self._ooo_packet_queue'. The OOO queue normally
        buffers segments awaiting RCV.NXT to advance to fill a
        gap; in CLOSE_WAIT, RCV.NXT can NEVER advance past
        peer's FIN seq + 1 (peer FIN'd so the seq space is
        capped), so any OOO entry stored here is a permanent
        leak with no drain path.

        RFC 9293 §3.10.7.4 step 7 (Segment Text Processing)
        omits CLOSE-WAIT from the list of states that deliver
        segment text. Combined with the FIN's "no further data"
        invariant, OOO data in CLOSE_WAIT is doubly-illegal:
        peer should not have sent it, AND it cannot become
        deliverable even if we buffered it.

        The conservative response: emit a bare cum-ACK to nudge
        peer's retransmit machinery toward backoff (same shape
        as the in-order post-FIN-data sibling test above), but
        do NOT store the segment in '_ooo_packet_queue'. No
        DSACK case-2 marker either - the entire OOO branch is
        rejected, so there is nothing to mark.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Peer FIN+ACK -> CLOSE_WAIT. RCV.NXT = PEER__ISS+2.
            3. Peer sends OOO data segment at seq = PEER__ISS +
               1 + 100 (= RCV.NXT + 99) with 50-byte payload.
               This is past peer's own FIN AND OOO above
               RCV.NXT.
            4. Drive RX. Inspect inline TX list and queue state.

        Assertions:

            * Exactly one outbound ACK fires inline.
            * The ACK carries 'ack = PEER__ISS + 2' (=
              current RCV.NXT, unchanged).
            * 'session._ooo_packet_queue' is empty - the
              segment must NOT be stored.
            * '_rx_buffer' is unchanged.
            * 'RCV.NXT' is unchanged.
            * Session stays in CLOSE_WAIT.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_close_wait's OOO
        branch (line ~2701) mirrors ESTABLISHED's structurally
        but never got the DSACK case-2 detection added in
        commit 'b69e8b1' (since the case-2 work focused on
        ESTABLISHED). More importantly, even with case-2
        detection, the segment would still be stored in the
        OOO queue - and in CLOSE_WAIT that storage is a leak
        (no drain path). The fix replaces the OOO storage
        branch with a bare ACK reply, dropping the data
        entirely.

        Severity: LOW (only triggers on RFC-violating peers)
        but the behaviour is wrong: OOO entries in CLOSE_WAIT
        accumulate without bound for a misbehaving peer, each
        holding a 'TcpMetadata' reference that survives until
        the session reaches CLOSED.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

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
            FsmState.CLOSE_WAIT,
            msg="Setup precondition: state must be CLOSE_WAIT after peer FIN.",
        )
        rx_buffer_before = bytes(session._rx_buffer)
        rcv_nxt_before = session._rcv_nxt
        ooo_count_before = len(session._ooo_packet_queue)
        self.assertEqual(
            ooo_count_before,
            0,
            msg="Setup precondition: OOO queue must be empty after the FIN-only transition.",
        )

        # Peer sends OOO data segment past their own FIN.
        ooo_payload = b"X" * 50
        peer_ooo_post_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 100,  # > RCV.NXT (= PEER__ISS+2)
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=ooo_payload,
        )
        ooo_tx = self._drive_rx(frame=peer_ooo_post_fin)

        self.assertEqual(
            len(ooo_tx),
            1,
            msg=(
                "Peer's OOO post-FIN data segment in CLOSE_WAIT "
                "MUST elicit exactly one outbound ACK. Today the "
                "OOO branch DOES emit the ACK (matches "
                "ESTABLISHED's behaviour) but the assertion below "
                "on the queue size is the [FLAGS BUG] anchor."
            ),
        )
        ack_probe = self._parse_tx(ooo_tx[0])
        self._assert_segment(
            ack_probe,
            flags=frozenset({"ACK"}),
            ack=rcv_nxt_before,
        )

        # Spec: the segment must NOT be stored in the OOO queue.
        # Today's code stores it indefinitely (no path to drain
        # because RCV.NXT cannot advance past peer's FIN).
        self.assertEqual(
            len(session._ooo_packet_queue),
            0,
            msg=(
                "Peer's OOO post-FIN data MUST NOT be stored in "
                "'_ooo_packet_queue'. RCV.NXT in CLOSE_WAIT can "
                "NEVER advance past peer's FIN seq + 1 (peer "
                "FIN'd so the receive sequence space is capped), "
                "so any OOO entry stored here is a permanent leak "
                "with no drain path. Today the branch at "
                "'tcp__session.py:2704' stores the segment "
                "regardless. Fix: replace the OOO-storage branch "
                "with a bare ACK reply."
            ),
        )

        # Spec: '_rx_buffer' unchanged (no enqueue) and RCV.NXT
        # unchanged (no advance).
        self.assertEqual(
            bytes(session._rx_buffer),
            rx_buffer_before,
            msg="Peer's OOO post-FIN data MUST NOT be enqueued into '_rx_buffer'.",
        )
        self.assertEqual(
            session._rcv_nxt,
            rcv_nxt_before,
            msg="Peer's OOO post-FIN data MUST NOT advance RCV.NXT.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="State must remain CLOSE_WAIT after OOO post-FIN data.",
        )
