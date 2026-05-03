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
This module contains integration tests for RST-driven termination
of a synchronized TCP session in the 'TcpSession' state machine.
A peer-issued RST in any synchronized state drops the connection
to CLOSED with no graceful 4-way handshake; the application's
pending 'recv()' / 'send()' calls observe the abort.

The tests cover:

    - RST acceptance per RFC 9293 §3.10.7.4 / RFC 5961 §3:
        * RCV.NXT == SEG.SEQ           -> reset connection
        * in-window but != RCV.NXT     -> challenge ACK
        * out of receive window        -> silently drop
    - State coverage: ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2,
      CLOSE_WAIT, LAST_ACK.

Reference RFCs:
    RFC 9293 §3.10.7.4   Synchronized state segment processing
    RFC 9293 §3.5        Reset Generation / Acceptance
    RFC 5961 §3          Mitigating Blind RST Attacks (folded
                         into 9293; cited for the original threat
                         model)

pytcp/tests/integration/protocols/tcp/test__tcp__session__close__rst.py

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


class TestTcpClose__Rst(TcpSessionTestCase):
    """
    Integration tests for RST-driven termination of synchronized
    TCP sessions across all close-related states.
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

    def test__close_rst__rst_in_established_drops_to_closed_and_wakes_blocked_recv(self) -> None:
        """
        Ensure that a peer-issued RST+ACK on a synchronized
        ESTABLISHED session drops the FSM to CLOSED with no graceful
        4-way handshake, no outbound segment, and notifies any
        blocked 'recv()' / 'send()' caller via '_event__rx_buffer'
        per RFC 9293 §3.10.7.4 / §3.5.

        RFC 9293 §3.10.7.4 (synchronized state, RST bit set, in-
        window seq matching RCV.NXT):

            "If the RST bit is set then, any outstanding RECEIVEs
             and SEND should receive 'reset' responses.  All
             segment queues should be flushed.  Users should also
             receive an unsolicited general 'connection reset'
             signal.  Enter the CLOSED state, delete the TCB, and
             return."

        and §3.10.7.4 RST acceptance (the in-window=match-RCV.NXT
        case):

            "RCV.NXT == SEG.SEQ ... TCP MUST reset the connection."

        Scenario:

            1. Drive handshake to ESTABLISHED. The receive buffer
               is empty, no in-flight data; both sides are idle.
            2. Peer sends RST+ACK at SEQ = PEER__ISS + 1
               (== RCV.NXT) and ACK = LOCAL__ISS + 1
               (in [SND.UNA, SND.MAX]). This is the canonical
               connection-abort segment.
            3. Drive RX. The ESTABLISHED RST+ACK branch (line
               1487-1500) runs, sets '_event__rx_buffer' to wake
               any blocked 'recv()', and changes state to CLOSED
               (which also unregisters the socket from
               'stack.sockets' via '_change_state').

        Assertions:

            * No outbound segment is produced - RST is unilateral
              by definition; the receiver must not respond per
              RFC 9293 §3.5.2 ("Reset Generation / Acceptance":
              "An incoming segment containing a RST is discarded
              after processing").
            * State is CLOSED.
            * Socket is unregistered from 'stack.sockets'.
            * '_event__rx_buffer' is set so a blocked 'recv()'
              wakes up.

        This test passes on current code as a positive-control
        regression guard for the canonical RST-acceptance path
        in ESTABLISHED. Future changes that:

          - Forgot to set '_event__rx_buffer' before transitioning
            (would leave 'recv()' callers blocked forever).
          - Added a stray '_transmit_packet(flag_ack=True)' in
            response (RST is a unidirectional abort).
          - Failed to call '_change_state' (the socket would
            linger in 'stack.sockets' as a stale ESTABLISHED
            entry and any new connection on the same 4-tuple
            would collide).

        are all caught here.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: state must be ESTABLISHED before RST.",
        )
        self.assertIn(
            socket_id,
            stack.sockets,
            msg="Setup precondition: socket must be registered before RST.",
        )

        # Peer sends RST+ACK at the canonical "matches RCV.NXT,
        # in-window ACK" position - the unambiguous abort signal.
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg=(
                "Peer's RST+ACK must produce NO outbound segment. "
                "RFC 9293 §3.5.2 / §3.10.7.4 - 'an incoming segment "
                "containing a RST is discarded after processing'. The "
                "receiver does not generate any reply to a RST."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's RST+ACK with seq==RCV.NXT and in-window ack "
                "must transition state to CLOSED per RFC 9293 §3.10.7.4."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "On transition to CLOSED, '_change_state' must "
                "unregister the socket from 'stack.sockets' (line 540) "
                "so the 4-tuple can be reused for a fresh connection."
            ),
        )
        self.assertTrue(
            session._event__rx_buffer.is_set(),
            msg=(
                "The RST handler must set '_event__rx_buffer' (line "
                "1497) so a blocked 'recv()' wakes up and observes "
                "the connection-reset signal. RFC 9293 §3.10.7.4: "
                "'any outstanding RECEIVEs and SEND should receive "
                '"reset" responses ... Users should also receive '
                'an unsolicited general "connection reset" signal\'.'
            ),
        )

    def test__close_rst__rst_in_fin_wait_1_drops_to_closed(self) -> None:
        """
        Ensure that a peer-issued RST+ACK arriving while we are in
        FIN_WAIT_1 (we have sent our FIN and are awaiting its ACK)
        drops the connection to CLOSED with no outbound segment, per
        RFC 9293 §3.10.7.4.

        FIN_WAIT_1 is a synchronized state, so the same RST
        acceptance rule as ESTABLISHED applies: an in-window
        SEG.SEQ matching RCV.NXT triggers the connection abort. The
        differentiator from the ESTABLISHED case is that 'SND.MAX'
        has advanced past the FIN (SND.MAX = LOCAL__ISS + 2), so
        the RST's ACK can validly fall anywhere in the
        '[SND.UNA, SND.MAX]' range - whether or not peer's RST
        ack covers our FIN.

        RFC 9293 §3.10.7.4 (synchronized state, RST bit set):

            "If the RST bit is set then, any outstanding RECEIVEs
             and SEND should receive 'reset' responses.  All
             segment queues should be flushed.  Users should also
             receive an unsolicited general 'connection reset'
             signal.  Enter the CLOSED state, delete the TCB, and
             return."

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Application calls 'close()'. Tick #1: state-only
               transition to FIN_WAIT_1. Tick #2: our FIN+ACK fires
               at SEQ = LOCAL__ISS + 1, advancing SND.MAX to
               LOCAL__ISS + 2.
            3. Peer sends RST+ACK at SEQ = PEER__ISS + 1
               (== RCV.NXT) and ACK = LOCAL__ISS + 2 (the value
               that would normally indicate a FIN-ACK, but here
               just placed in the valid '[SND.UNA, SND.MAX]'
               window).
            4. Drive RX. The FIN_WAIT_1 RST+ACK branch (line
               1576-1585) runs and changes state to CLOSED.

        Assertions:

            * No outbound segment is produced.
            * State is CLOSED.
            * Socket is unregistered from 'stack.sockets'.

        Note on '_event__rx_buffer': the FIN_WAIT_1 RST handler
        currently does NOT set '_event__rx_buffer' (line 1582-1584
        only changes state); the rationale being that an
        application that has called 'close()' has implicitly
        promised not to issue further 'recv()' calls. This test
        does NOT assert on the event because the RFC does not
        strictly mandate the wake (it says "outstanding RECEIVEs
        ... should receive reset responses", but post-close()
        outstanding recv()s are an application bug, not an
        implementation requirement). The corresponding ESTABLISHED
        test does assert on the event because pre-close() recv()s
        are common.

        This test passes on current code as a positive-control
        regression guard for the FIN_WAIT_1 RST acceptance path.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        # Walk into FIN_WAIT_1 by closing and ticking through the
        # transition + FIN-emit ticks.
        session.close()
        self._advance(ms=1)
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg="Setup precondition: FIN_WAIT_1's first tick must emit our FIN+ACK.",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: state must be FIN_WAIT_1 after the FIN-emit tick.",
        )
        self.assertEqual(
            session._snd_max,
            LOCAL__ISS + 2,
            msg=("Setup precondition: 'SND.MAX' must reflect the " "post-FIN sequence number (LOCAL__ISS + 2)."),
        )

        # Peer sends RST+ACK with seq matching RCV.NXT and ack in
        # the valid send window (here at LOCAL__ISS + 2, the FIN's
        # post-byte boundary).
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg=(
                "Peer's RST+ACK in FIN_WAIT_1 must produce NO "
                "outbound segment - RST is unilateral and the "
                "receiver does not reply."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's RST+ACK with seq==RCV.NXT and in-window ack "
                "while in FIN_WAIT_1 must transition state to CLOSED "
                "per RFC 9293 §3.10.7.4. The graceful 4-way close "
                "is aborted; we do not wait for the FIN+ACK exchange."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "On transition to CLOSED, '_change_state' must "
                "unregister the socket from 'stack.sockets' so the "
                "4-tuple can be reused."
            ),
        )

    def test__close_rst__rst_in_fin_wait_2_drops_to_closed(self) -> None:
        """
        Ensure that a peer-issued RST+ACK arriving while we are in
        FIN_WAIT_2 (we have sent our FIN and received its ACK; we
        are awaiting peer's FIN) drops the connection to CLOSED
        with no outbound segment, per RFC 9293 §3.10.7.4.

        FIN_WAIT_2 is a fully synchronized state - we have closed
        our half cleanly and are waiting on the peer's close. A
        peer-side RST aborts the wait without requiring the FIN
        exchange to complete. Differentiates from FIN_WAIT_1 by
        having SND.UNA already advanced past the FIN
        (SND.UNA = SND.MAX = LOCAL__ISS + 2).

        RFC 9293 §3.10.7.4 (synchronized state, RST bit set):

            "If the RST bit is set then ... Enter the CLOSED state,
             delete the TCB, and return."

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Application calls 'close()'. Tick #1 transitions to
               FIN_WAIT_1; tick #2 emits our FIN+ACK at SEQ =
               LOCAL__ISS + 1.
            3. Peer ACKs our FIN with ack = LOCAL__ISS + 2. State
               transitions FIN_WAIT_1 -> FIN_WAIT_2 (per RFC's
               'if our FIN is now acknowledged' clause); SND.UNA
               advances to LOCAL__ISS + 2.
            4. Peer sends RST+ACK at SEQ = PEER__ISS + 1
               (== RCV.NXT, since peer has not sent its FIN yet)
               and ACK = LOCAL__ISS + 2 (the only valid value in
               '[SND.UNA, SND.MAX]' since both are now at
               LOCAL__ISS + 2).
            5. Drive RX. The FIN_WAIT_2 RST+ACK branch (line
               1637-1647) runs and changes state to CLOSED.

        Assertions:

            * No outbound segment is produced.
            * State is CLOSED.
            * Socket is unregistered from 'stack.sockets'.

        This test passes on current code as a positive-control
        regression guard for the FIN_WAIT_2 RST acceptance path.
        Note: like FIN_WAIT_1's RST handler, FIN_WAIT_2's does
        not set '_event__rx_buffer' on transition - the
        post-close() outstanding-recv() rationale applies equally
        here.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        # Walk into FIN_WAIT_2: close, transition tick, FIN-emit
        # tick, then peer ACKs our FIN.
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: state must be FIN_WAIT_1 after FIN-emit tick.",
        )

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
            msg="Setup precondition: state must be FIN_WAIT_2 after peer ACKs our FIN.",
        )
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 2,
            msg="Setup precondition: 'SND.UNA' must have advanced past our FIN.",
        )

        # Peer sends RST+ACK at the canonical match position.
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg="Peer's RST+ACK in FIN_WAIT_2 must produce NO outbound segment.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's RST+ACK with seq==RCV.NXT and in-window ack "
                "while in FIN_WAIT_2 must transition state to CLOSED "
                "per RFC 9293 §3.10.7.4."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=("On transition to CLOSED, '_change_state' must " "unregister the socket from 'stack.sockets'."),
        )

    def test__close_rst__rst_with_ack_in_close_wait_must_reset_per_rfc9293(self) -> None:
        """
        Ensure that a peer-issued RST+ACK arriving while we are in
        CLOSE_WAIT (peer has closed its half, we have not yet
        called 'close()') drops the connection to CLOSED. Per
        RFC 9293 §3.10.7.4, any RST in synchronized state aborts
        the connection regardless of whether the ACK flag is set
        on that segment.

        RFC 9293 §3.10.7.4 (segment processing in synchronized
        states, RST bit set):

            "If the RST bit is set then ... Enter the CLOSED state,
             delete the TCB, and return."

        The text qualifies the action by RST acceptance (sequence
        in receive window matching RCV.NXT) but NOT by the ACK
        flag. RFC convention is that RSTs always carry ACK to
        validate the segment to the receiver, so the canonical
        shape from a conformant peer is RST+ACK - exactly what
        the current code's CLOSE_WAIT handler refuses to match.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Peer sends FIN+ACK to close its half. State
               transitions to CLOSE_WAIT, RCV.NXT advances past
               peer's FIN to PEER__ISS + 2.
            3. Tick to fire the delayed ACK of peer's FIN
               (housekeeping; not strictly necessary for the
               test but mirrors realistic timing).
            4. Peer sends RST+ACK at SEQ = PEER__ISS + 2
               (== RCV.NXT) and ACK = LOCAL__ISS + 1 (in
               '[SND.UNA, SND.MAX]'). This is the standard
               peer-aborts-connection segment.
            5. Drive RX. The current code's CLOSE_WAIT RST
               branch (lines 1752-1767) requires
               'all({tcp__flag_rst}) and not any({tcp__flag_ack,
               tcp__flag_fin, tcp__flag_syn})' - it FAILS to
               match the RST+ACK shape and falls through. Per
               RFC 9293, the connection must reset.

        Assertions:

            * No outbound segment in response to the RST+ACK
              (RST is unilateral; receiver must not reply).
            * State is CLOSED (the spec encoding).
            * Socket is unregistered from 'stack.sockets'.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_close_wait's RST
        branch (line 1752-1767) only matches RST WITHOUT the
        ACK flag set:

            and all({packet_rx_md.tcp__flag_rst})
            and not any({
                packet_rx_md.tcp__flag_ack,
                packet_rx_md.tcp__flag_fin,
                packet_rx_md.tcp__flag_syn,
            })

        A conformant peer always sets ACK on its RST per
        RFC convention, so this branch never fires in real
        traffic. The connection lingers in CLOSE_WAIT with
        no further state change unless the application
        eventually calls 'close()' (which transitions to
        LAST_ACK and ultimately tries to deliver our FIN
        to a peer that has already RST-aborted - probably
        eliciting another RST that LAST_ACK does handle).

        The fix is to relax the predicate to match RST
        regardless of ACK flag, mirroring what the
        ESTABLISHED / FIN_WAIT_1 / FIN_WAIT_2 / LAST_ACK
        branches already do (those match RST+ACK explicitly,
        which is the inverse asymmetry; ideally all five
        states would accept RST regardless of ACK):

            and packet_rx_md.tcp__flag_rst
            and not any({
                packet_rx_md.tcp__flag_fin,
                packet_rx_md.tcp__flag_syn,
            })

        Note that ESTABLISHED / FIN_WAIT_1 / FIN_WAIT_2 /
        LAST_ACK match RST+ACK (and so silently drop pure
        RST), while CLOSE_WAIT matches pure RST (and so
        silently drops RST+ACK). The full fix is to make
        all five branches uniformly accept RST with or
        without ACK; this test surfaces the CLOSE_WAIT
        half of the asymmetry. The pure-RST-in-ESTABLISHED
        case can be covered by a follow-up test once the
        single fix lands.

        On current code this test will fail with state still
        CLOSE_WAIT after the RST+ACK arrival.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        # Walk into CLOSE_WAIT by having peer send FIN+ACK first.
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
            msg="Setup precondition: state must be CLOSE_WAIT after peer's FIN+ACK.",
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 2,
            msg="Setup precondition: 'RCV.NXT' must have advanced past peer's FIN.",
        )

        # Tick to fire the delayed ACK of peer's FIN. This drains
        # the housekeeping state and leaves the session in a clean
        # CLOSE_WAIT.
        self._advance(ms=1)

        # Peer sends RST+ACK at the canonical "matches RCV.NXT,
        # in-window ACK" position.
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg=(
                "Peer's RST+ACK in CLOSE_WAIT must produce NO "
                "outbound segment - RST is unilateral and the "
                "receiver does not reply."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's RST+ACK in CLOSE_WAIT MUST transition state "
                "to CLOSED per RFC 9293 §3.10.7.4 - any RST in a "
                "synchronized state aborts the connection regardless "
                "of the ACK flag. Current code's CLOSE_WAIT RST "
                "handler (lines 1752-1767) only matches pure RST "
                "(no ACK), so it ignores the canonical RST+ACK "
                "shape that conformant TCPs send."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "On transition to CLOSED, '_change_state' must "
                "unregister the socket from 'stack.sockets' so the "
                "4-tuple can be reused."
            ),
        )

    def test__close_rst__rst_in_last_ack_drops_to_closed(self) -> None:
        """
        Ensure that a peer-issued RST+ACK arriving while we are in
        LAST_ACK (we have sent our FIN after the peer closed first
        and we are awaiting peer's ACK of our FIN) drops the
        connection to CLOSED with no outbound segment, per RFC 9293
        §3.10.7.4.

        LAST_ACK is the symmetric counterpart of FIN_WAIT_2 from
        the passive-close path:

            ESTABLISHED      <-- peer FIN+ACK -->      CLOSE_WAIT
                                                          | local close()
                                                          v
                                                       LAST_ACK

        Either side seeing a RST in either state must abort. This
        scenario covers the LAST_ACK half.

        RFC 9293 §3.10.7.4 (synchronized state, RST bit set):

            "If the RST bit is set then ... Enter the CLOSED state,
             delete the TCB, and return."

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Peer sends FIN+ACK; state -> CLOSE_WAIT,
               RCV.NXT = PEER__ISS + 2.
            3. Tick to drain the delayed ACK of peer's FIN.
            4. Application calls 'close()'. Tick #1 transitions
               CLOSE_WAIT -> LAST_ACK. Tick #2 emits our FIN+ACK
               at SEQ = LOCAL__ISS + 1; SND.MAX advances to
               LOCAL__ISS + 2.
            5. Peer sends RST+ACK at SEQ = PEER__ISS + 2
               (== RCV.NXT) and ACK = LOCAL__ISS + 1 (a valid
               value in '[SND.UNA, SND.MAX]'). The peer is
               aborting before it has had a chance to ACK our
               FIN, so its ack still points at the pre-FIN seq.
            6. Drive RX. The LAST_ACK RST+ACK branch (line
               1808-1818) runs and changes state to CLOSED.

        Assertions:

            * No outbound segment is produced.
            * State is CLOSED.
            * Socket is unregistered from 'stack.sockets'.

        This test passes on current code as a positive-control
        regression guard for the LAST_ACK RST acceptance path.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        # Walk into LAST_ACK via the passive-close path.
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
            msg="Setup precondition: state must be CLOSE_WAIT after peer's FIN+ACK.",
        )

        # Tick to drain delayed ACK.
        self._advance(ms=1)

        # close() then transition tick + FIN-emit tick.
        session.close()
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="Setup precondition: state must be LAST_ACK after the transition tick.",
        )
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg="Setup precondition: LAST_ACK's first tick must emit our FIN+ACK.",
        )
        self.assertEqual(
            session._snd_max,
            LOCAL__ISS + 2,
            msg=("Setup precondition: 'SND.MAX' must reflect the " "post-FIN sequence number (LOCAL__ISS + 2)."),
        )

        # Peer sends RST+ACK at the canonical match position.
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg="Peer's RST+ACK in LAST_ACK must produce NO outbound segment.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's RST+ACK with seq==RCV.NXT and in-window ack "
                "while in LAST_ACK must transition state to CLOSED "
                "per RFC 9293 §3.10.7.4."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=("On transition to CLOSED, '_change_state' must " "unregister the socket from 'stack.sockets'."),
        )

    def test__close_rst__bare_rst_in_established_must_drop_to_closed(self) -> None:
        """
        Ensure that a peer-issued BARE RST (the RST flag set, the
        ACK flag cleared) with seq == RCV.NXT in ESTABLISHED aborts
        the connection per RFC 9293 §3.10.7.4. The ACK flag is NOT
        a precondition for valid RST processing; both bare RST
        and RST+ACK are spec-legal abort signals.

        RFC 9293 §3.10.7.4 (synchronized state, RST validation):

            "In all states except SYN-SENT, all reset (RST)
             segments are validated by checking their SEQ-fields.
             A reset is valid if its sequence number is in the
             window."

        Note the absence of any ACK-flag precondition: the
        validity check is purely a window check on SEG.SEQ. The
        five "<SEQ=...><CTL=RST>" outbound forms enumerated in
        RFC 9293 §3.5.2 also confirm the bare-RST shape is the
        spec-mandated form for several abort scenarios; a
        receiving peer must accept it.

        Real-world peers (Linux, BSD, Windows) almost always send
        RST+ACK because of historical convention, so the gap
        does not bite typical interop. But a spec-compliant
        peer that legitimately sends bare RST (e.g. abort from
        SYN-SENT after our handshake completed but before our
        third-leg ACK arrived; abort from a half-open recovery
        path) cannot tear down our session, which is an
        observable RFC violation.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_established' line
        2418-2426 gates the RST-handling branch on
        'all({tcp__flag_rst, tcp__flag_ack})':

            if (
                packet_rx_md
                and all({packet_rx_md.tcp__flag_rst, packet_rx_md.tcp__flag_ack})
                and not any({packet_rx_md.tcp__flag_fin, packet_rx_md.tcp__flag_syn})
            ):
                if self._check_rst_acceptability(packet_rx_md):
                    self._event__rx_buffer.set()
                    self._change_state(FsmState.CLOSED)
                return

        A bare RST has 'tcp__flag_ack=False', so 'all({rst, ack})'
        is False and the branch never fires. The segment falls
        through every other branch (none match a bare RST) and
        the function returns silently with state unchanged. The
        connection hangs forever from peer's perspective.

        The same predicate-shape error affects four sibling
        states with the same root cause (commit '991931e' added
        the three-way RST helper across six sync states but
        left the strict 'all({rst, ack})' predicate in place
        for five of them):

          - '_tcp_fsm_fin_wait_1'   line ~2539-2546
          - '_tcp_fsm_fin_wait_2'   line ~2626-2633
          - '_tcp_fsm_closing'      line ~2706-2713
          - '_tcp_fsm_last_ack'     line ~2917-2926

        SYN_RCVD ('_tcp_fsm_syn_rcvd' line ~2207-2221) and
        CLOSE_WAIT ('_tcp_fsm_close_wait' line ~2836-2848) use
        the broader 'tcp__flag_rst and not any({fin, syn})'
        predicate and accept bare RSTs correctly. The CLOSE_WAIT
        inline comment explicitly notes that the strict-ACK
        predicate "would (and previously did) make this branch
        never fire in real traffic" - the same fix the comment
        describes was applied to CLOSE_WAIT and SYN_RCVD but the
        five other sync states still carry the old strict
        predicate.

        Severity: MEDIUM. Real RFC compliance gap. Most peers
        send RST+ACK, so the gap rarely bites in practice;
        peers that send bare RST cannot abort us in any of the
        five affected states.

        Fix outline (separate commit): drop 'tcp__flag_ack' from
        the predicate in all five branches - replace
        'all({rst, ack})' with 'tcp__flag_rst', mirroring
        CLOSE_WAIT / SYN_RCVD. The '_check_rst_acceptability'
        helper already handles both shapes correctly: line
        ~1014-1021 short-circuits the ack-range guard for bare
        RST so the case-1 reset path remains reachable.

        Scenario:

            1. Drive handshake to ESTABLISHED (canonical setup).
            2. Peer sends BARE RST (flags={"RST"}, no ACK) at
               SEQ = PEER__ISS + 1 (== RCV.NXT). The 'ack' field
               is left at 0 - it is meaningless for a bare RST
               and the helper skips its validation.
            3. Drive RX. The ESTABLISHED RST branch MUST run,
               accept the RST via '_check_rst_acceptability',
               and transition to CLOSED.

        Assertions:

            * No outbound segment is produced (RST is a
              unidirectional abort).
            * State is CLOSED.
            * Socket is unregistered from 'stack.sockets'.

        On current code this test fails at the state assertion:
        the bare RST is silently dropped, state stays
        ESTABLISHED, and the socket remains registered. Mirror
        of the corresponding RST+ACK test above which passes -
        the only difference is the flag set on peer's segment.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: state must be ESTABLISHED before RST.",
        )
        self.assertIn(
            socket_id,
            stack.sockets,
            msg="Setup precondition: socket must be registered before RST.",
        )

        # Peer sends a BARE RST (no ACK flag) at the canonical
        # "matches RCV.NXT" position. 'ack=0' is meaningless for a
        # bare RST and ignored by '_check_rst_acceptability' per
        # the bare-RST short-circuit at line ~1014-1021.
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=0,
            flags=("RST",),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg=(
                "Peer's bare RST must produce NO outbound segment. "
                "RFC 9293 §3.5.2 / §3.10.7.4 - 'an incoming segment "
                "containing a RST is discarded after processing'."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's bare RST (no ACK flag) with seq==RCV.NXT MUST "
                "abort the connection per RFC 9293 §3.10.7.4 - the "
                "RST validity check is a pure SEG.SEQ window check; "
                "the ACK flag is not a precondition. Today the "
                "ESTABLISHED RST branch predicate "
                "'all({tcp__flag_rst, tcp__flag_ack})' silently drops "
                "bare RSTs, leaving the connection stuck in "
                "ESTABLISHED. Fix: replace the predicate with bare "
                "'tcp__flag_rst', mirroring CLOSE_WAIT / SYN_RCVD. "
                f"Got state: {session.state!r}."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "On the bare-RST-driven transition to CLOSED, "
                "'_change_state' must unregister the socket from "
                "'stack.sockets' so the 4-tuple can be reused. "
                "Today the predicate gate prevents the transition "
                "from happening at all, leaving the socket "
                "registered indefinitely."
            ),
        )

    def test__close_rst__bare_rst_in_fin_wait_1_must_drop_to_closed(self) -> None:
        """
        Ensure that a peer-issued BARE RST (RST flag set, ACK flag
        cleared) with seq == RCV.NXT in FIN_WAIT_1 aborts the
        connection per RFC 9293 §3.10.7.4. The ACK flag is NOT a
        precondition for valid RST processing in any synchronized
        state - FIN_WAIT_1 is no different from ESTABLISHED in this
        respect.

        [FLAGS BUG] - same predicate-shape error as ESTABLISHED
        (see 'test__close_rst__bare_rst_in_established_must_drop_to_closed'
        for the full rationale and fix outline). The
        '_tcp_fsm_fin_wait_1' RST branch (line ~2539-2546) gates on
        'all({tcp__flag_rst, tcp__flag_ack})', so a bare RST is
        silently dropped and state stays in FIN_WAIT_1 forever from
        peer's perspective. Fix is the same: replace
        'all({rst, ack})' with bare 'tcp__flag_rst', mirroring
        CLOSE_WAIT / SYN_RCVD.

        Differentiator from the ESTABLISHED case: 'SND.MAX' has
        advanced past the FIN we sent (SND.MAX = LOCAL__ISS + 2),
        so the check the helper performs validates against the
        post-FIN range. For a bare RST the helper short-circuits
        the ack-range guard at '_check_rst_acceptability' line
        ~1014-1021, so the post-FIN range expansion is
        observationally a no-op for this scenario.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. 'close()'; transition tick + FIN-emit tick. State is
               FIN_WAIT_1, SND.MAX = LOCAL__ISS + 2.
            3. Peer sends BARE RST at SEQ = PEER__ISS + 1
               (== RCV.NXT) with no ACK flag and ack=0.
            4. Drive RX. The FIN_WAIT_1 RST branch MUST run, accept
               the RST via '_check_rst_acceptability', and
               transition to CLOSED.

        Assertions:

            * No outbound segment is produced.
            * State is CLOSED.
            * Socket is unregistered from 'stack.sockets'.

        On current code the state assertion fails - bare RST is
        silently dropped, state stays FIN_WAIT_1.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        session.close()
        self._advance(ms=1)
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg="Setup precondition: FIN_WAIT_1's first tick must emit our FIN+ACK.",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: state must be FIN_WAIT_1 after the FIN-emit tick.",
        )

        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=0,
            flags=("RST",),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg=("Peer's bare RST in FIN_WAIT_1 must produce NO " "outbound segment."),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's bare RST (no ACK flag) with seq==RCV.NXT in "
                "FIN_WAIT_1 MUST abort the connection per RFC 9293 "
                "§3.10.7.4. Today the FIN_WAIT_1 RST branch predicate "
                "'all({tcp__flag_rst, tcp__flag_ack})' silently drops "
                "bare RSTs. Fix: replace with bare 'tcp__flag_rst'. "
                f"Got state: {session.state!r}."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "On the bare-RST-driven transition to CLOSED, " "the socket must be unregistered from 'stack.sockets'."
            ),
        )

    def test__close_rst__bare_rst_in_fin_wait_2_must_drop_to_closed(self) -> None:
        """
        Ensure that a peer-issued BARE RST (RST flag set, ACK flag
        cleared) with seq == RCV.NXT in FIN_WAIT_2 aborts the
        connection per RFC 9293 §3.10.7.4. The ACK flag is NOT a
        precondition for valid RST processing in any synchronized
        state.

        [FLAGS BUG] - same predicate-shape error as ESTABLISHED
        (see 'test__close_rst__bare_rst_in_established_must_drop_to_closed'
        for the full rationale and fix outline). The
        '_tcp_fsm_fin_wait_2' RST branch (line ~2626-2633) gates on
        'all({tcp__flag_rst, tcp__flag_ack})', so a bare RST is
        silently dropped and the connection stays in FIN_WAIT_2.

        Differentiator from the FIN_WAIT_1 case: SND.UNA has
        advanced past our FIN (peer ACKed it; SND.UNA = SND.MAX =
        LOCAL__ISS + 2). The bare-RST short-circuit in the helper
        applies the same way; the test still asserts CLOSED.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. 'close()'; transition tick + FIN-emit tick.
            3. Peer ACKs our FIN; state -> FIN_WAIT_2.
            4. Peer sends BARE RST at SEQ = PEER__ISS + 1
               (== RCV.NXT) with no ACK flag and ack=0.
            5. Drive RX. The FIN_WAIT_2 RST branch MUST run and
               transition to CLOSED.

        Assertions:

            * No outbound segment produced.
            * State is CLOSED.
            * Socket unregistered.

        On current code the state assertion fails - bare RST is
        silently dropped, state stays FIN_WAIT_2.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

        session.close()
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
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="Setup precondition: state must be FIN_WAIT_2 after peer ACKs our FIN.",
        )

        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=0,
            flags=("RST",),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg="Peer's bare RST in FIN_WAIT_2 must produce NO outbound segment.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's bare RST (no ACK flag) with seq==RCV.NXT in "
                "FIN_WAIT_2 MUST abort the connection per RFC 9293 "
                "§3.10.7.4. Today the FIN_WAIT_2 RST branch predicate "
                "'all({tcp__flag_rst, tcp__flag_ack})' silently drops "
                "bare RSTs. Fix: replace with bare 'tcp__flag_rst'. "
                f"Got state: {session.state!r}."
            ),
        )
        self.assertNotIn(socket_id, stack.sockets, msg="Socket must be unregistered after CLOSED transition.")

    def test__close_rst__bare_rst_in_last_ack_must_drop_to_closed(self) -> None:
        """
        Ensure that a peer-issued BARE RST (RST flag set, ACK flag
        cleared) with seq == RCV.NXT in LAST_ACK aborts the
        connection per RFC 9293 §3.10.7.4. The ACK flag is NOT a
        precondition for valid RST processing in any synchronized
        state.

        [FLAGS BUG] - same predicate-shape error as ESTABLISHED
        (see 'test__close_rst__bare_rst_in_established_must_drop_to_closed'
        for the full rationale and fix outline). The
        '_tcp_fsm_last_ack' RST branch (line ~2917-2926) gates on
        'all({tcp__flag_rst, tcp__flag_ack})', so a bare RST is
        silently dropped and the connection stays in LAST_ACK
        forever (or until peer ACKs our FIN, which a bare-RST-issuing
        peer is unlikely to do).

        LAST_ACK is the symmetric counterpart of FIN_WAIT_2 from
        the passive-close path. The bug applies in exactly the
        same way; the only differentiator is the path used to
        walk into the state (peer FINs first; we close).

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Peer FIN+ACK -> CLOSE_WAIT.
            3. Tick to drain delayed ACK.
            4. 'close()'; transition tick (-> LAST_ACK) + FIN-emit
               tick.
            5. Peer sends BARE RST at SEQ = PEER__ISS + 2
               (== RCV.NXT after peer's FIN) with no ACK flag and
               ack=0.
            6. Drive RX. The LAST_ACK RST branch MUST run and
               transition to CLOSED.

        Assertions:

            * No outbound segment produced.
            * State is CLOSED.
            * Socket unregistered.

        On current code the state assertion fails - bare RST is
        silently dropped, state stays LAST_ACK.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        socket_id = session._socket.socket_id

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
            msg="Setup precondition: state must be CLOSE_WAIT after peer's FIN+ACK.",
        )
        self._advance(ms=1)

        session.close()
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="Setup precondition: state must be LAST_ACK after the transition tick.",
        )
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg="Setup precondition: LAST_ACK's first tick must emit our FIN+ACK.",
        )

        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,
            ack=0,
            flags=("RST",),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg="Peer's bare RST in LAST_ACK must produce NO outbound segment.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's bare RST (no ACK flag) with seq==RCV.NXT in "
                "LAST_ACK MUST abort the connection per RFC 9293 "
                "§3.10.7.4. Today the LAST_ACK RST branch predicate "
                "'all({tcp__flag_rst, tcp__flag_ack})' silently drops "
                "bare RSTs. Fix: replace with bare 'tcp__flag_rst'. "
                f"Got state: {session.state!r}."
            ),
        )
        self.assertNotIn(socket_id, stack.sockets, msg="Socket must be unregistered after CLOSED transition.")

    def test__close_rst__in_window_rst_not_at_rcv_nxt_must_elicit_challenge_ack(self) -> None:
        """
        Ensure that a peer-issued RST with a sequence number that
        falls WITHIN the current receive window but does NOT exactly
        match RCV.NXT elicits a challenge ACK rather than being
        silently dropped or accepted as a reset. This is the RFC
        5961 §3.2 blind-RST attack mitigation, folded into RFC 9293
        §3.10.7.4.

        RFC 9293 §3.10.7.4 (RST acceptance, three-way classification):

            "1) If the RST bit is set and the sequence number
                exactly matches the next expected sequence number
                (RCV.NXT), then TCP endpoints MUST reset the
                connection ...

             2) If the RST bit is set and the sequence number does
                not exactly match the next expected sequence value,
                yet is within the current receive window, TCP
                endpoints MUST send an acknowledgment (challenge
                ACK) ...

             3) If the RST bit is set and the sequence number is
                outside the current receive window, TCP endpoints
                MUST silently drop the segment."

        Cases (1) and (3) are handled correctly by the current
        code (reset on RCV.NXT match; silent drop on out-of-
        window) - though the latter is incidental: the strict
        'seq == rcv_nxt' check means EVERY non-matching seq
        falls through silently, regardless of whether it is in-
        window or not. Case (2) is therefore mishandled - in-
        window-but-mismatched RSTs are dropped silently rather
        than eliciting the mandated challenge ACK.

        The threat model: an off-path attacker who can guess the
        4-tuple but not the in-flight sequence space can flood
        the connection with RSTs at random seq values. With the
        challenge-ACK mitigation, only an exact-match RST resets;
        every other in-window guess just produces an ACK the
        attacker cannot leverage. Without the mitigation, the
        in-window guesses are silently dropped, which is harmless
        but trades a security-positive signal (the challenge ACK)
        for nothing. Worse, future relaxations of the strict
        'seq == rcv_nxt' check (e.g. someone "fixing" it to allow
        RST anywhere in-window to reset) would re-open the very
        attack the challenge-ACK mitigation defends against. The
        challenge ACK is therefore a load-bearing safety net that
        must be present.

        Scenario:

            1. Drive handshake to ESTABLISHED.
               RCV.NXT = PEER__ISS + 1, RCV.WND = 65535 - 0 =
               65535 (empty receive buffer).
            2. Peer sends RST+ACK at SEQ = PEER__ISS + 1 + 10 -
               i.e. 10 bytes past RCV.NXT but well within the
               65535-byte receive window. ACK = LOCAL__ISS + 1
               (in '[SND.UNA, SND.MAX]').
            3. Drive RX. Per RFC 9293 §3.10.7.4 case (2), the
               session MUST emit a challenge ACK pointing at
               its current RCV.NXT (i.e. ack = PEER__ISS + 1)
               and MUST NOT change state.

        Assertions:

            * Exactly ONE inline TX frame is emitted - the
              challenge ACK (the spec encoding).
            * The challenge ACK carries flags={ACK}, no other.
            * 'ack = PEER__ISS + 1' (== current RCV.NXT) -
              confirms the challenge ACK points at our true
              receive frontier, not at the bogus seq the
              attacker offered.
            * 'seq = LOCAL__ISS + 1' - we have not advanced our
              own send sequence.
            * State remains ESTABLISHED - the RST is REJECTED
              (out-of-RCV.NXT seq fails the acceptance check).

        [FLAGS BUG] - all five close-related state RST handlers
        use the strict 'packet_rx_md.tcp__seq == self._rcv_nxt'
        check (lines 1494, 1582, 1644, 1764, 1815). When the
        seq does not match, the branch returns silently - no
        challenge ACK is emitted, in-window or not. RFC 9293
        §3.10.7.4 case (2) requires the ACK reply for any
        in-window mismatched seq.

        The fix is to add a challenge-ACK emit on the
        'in-window AND seq != rcv_nxt' fall-through. Concrete
        skeleton (one of several legal arrangements):

            if (
                packet_rx_md
                and all({tcp__flag_rst, tcp__flag_ack})
                and not any({tcp__flag_fin, tcp__flag_syn})
            ):
                if (
                    packet_rx_md.tcp__seq == self._rcv_nxt
                    and self._snd_una <= packet_rx_md.tcp__ack <= self._snd_max
                ):
                    self._event__rx_buffer.set()
                    self._change_state(FsmState.CLOSED)
                elif (
                    self._rcv_nxt
                    <= packet_rx_md.tcp__seq
                    < self._rcv_nxt + self._rcv_wnd
                ):
                    # In-window but mismatched: RFC 9293
                    # §3.10.7.4 case 2 challenge ACK.
                    self._transmit_packet(flag_ack=True)
                # Out of window: silently drop (RFC case 3).
                return

        The same shape applies to all five close-related state
        handlers. A follow-up consolidation could extract the
        three-way classifier into a helper.

        On current code this test fails at the inline-TX-count
        assertion: zero frames emitted instead of one.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: state must be ESTABLISHED.",
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1,
            msg="Setup precondition: RCV.NXT after handshake must be PEER__ISS + 1.",
        )

        # Peer sends RST+ACK at seq = RCV.NXT + 10 - 10 bytes past
        # the next-expected, but well within the 65535-byte receive
        # window. This is the RFC 5961 §3.2 / RFC 9293 §3.10.7.4
        # case (2) input: in-window but mismatched seq.
        bogus_offset = 10
        peer_rst_off_seq = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + bogus_offset,
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst_off_seq)

        # The spec encoding: exactly one challenge ACK fires.
        self.assertEqual(
            len(rst_inline),
            1,
            msg=(
                "Peer's RST with in-window mismatched seq MUST elicit "
                "exactly one challenge ACK per RFC 9293 §3.10.7.4 "
                "case (2) / RFC 5961 §3.2. Current code's strict "
                "'seq == rcv_nxt' check (line 1494) makes the RST+ACK "
                "branch fall through with no reply, leaving the "
                "blind-RST attack mitigation absent."
            ),
        )

        challenge_ack = self._parse_tx(rst_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
        )

        # The RST is REJECTED. State stays ESTABLISHED.
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "An in-window-but-mismatched RST MUST NOT reset the "
                "connection - only an exact 'seq == RCV.NXT' RST "
                "qualifies for case (1)'s reset. State must remain "
                "ESTABLISHED while the challenge ACK invites the peer "
                "to retransmit at the correct seq if the RST is "
                "legitimate."
            ),
        )

    def test__close_rst__in_window_rst_in_fin_wait_1_must_elicit_challenge_ack(self) -> None:
        """
        Ensure FIN_WAIT_1's RST handler honours the RFC 9293
        §3.10.7.4 / RFC 5961 §3.2 three-way classification: an
        in-window-but-mismatched RST (seq != RCV.NXT) elicits a
        challenge ACK rather than a silent drop. Companion to the
        ESTABLISHED case-2 test above; same threat model, same
        spec text - FIN_WAIT_1 is a synchronized state and
        inherits the rule.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_fin_wait_1's RST+ACK
        branch (line 2363-2375) uses strict
        'tcp__seq == self._rcv_nxt' equality. Today the in-window
        mismatch case falls through to silent drop. The fix
        mirrors ESTABLISHED's three-way logic landed in commit
        '9a1d7f5' - or, cleaner, a shared helper
        '_check_rst_acceptability(md) -> bool' that returns True
        for case-1 (caller resets connection), False otherwise
        (helper has emitted the case-2 challenge ACK if
        applicable, or silently dropped for case-3 out-of-window).

        Scenario:

            1. Drive handshake → ESTABLISHED.
            2. close() + tick → FIN_WAIT_1 + tick → FIN+ACK out.
            3. Peer RST+ACK at seq = PEER__ISS + 1 + 10
               (in-window mismatched).
            4. Assert: one outbound challenge ACK with seq =
               LOCAL__ISS + 2 (post-FIN), ack = PEER__ISS + 1.
               State stays FIN_WAIT_1.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: state must be FIN_WAIT_1.",
        )
        snd_nxt_before = session._snd_nxt
        rcv_nxt_before = session._rcv_nxt

        peer_rst_off_seq = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 10,
            ack=LOCAL__ISS + 2,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst_off_seq)

        self.assertEqual(
            len(rst_inline),
            1,
            msg=(
                "Peer's RST with in-window mismatched seq in "
                "FIN_WAIT_1 MUST elicit exactly one challenge ACK "
                "per RFC 9293 §3.10.7.4 case (2). Today the RST "
                "handler's strict 'seq == rcv_nxt' check makes the "
                "branch fall through with no reply."
            ),
        )
        challenge_ack = self._parse_tx(rst_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="In-window-mismatched RST must NOT reset the connection in FIN_WAIT_1.",
        )

    def test__close_rst__in_window_rst_in_fin_wait_2_must_elicit_challenge_ack(self) -> None:
        """
        Ensure FIN_WAIT_2's RST handler honours the RFC 9293
        §3.10.7.4 case-2 challenge-ACK rule. Same gap class as the
        FIN_WAIT_1 sibling above.

        [FLAGS BUG] - '_tcp_fsm_fin_wait_2's RST+ACK branch
        (line 2453-2465) uses strict 'tcp__seq == self._rcv_nxt'.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session.close()
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
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="Setup precondition: state must be FIN_WAIT_2.",
        )
        snd_nxt_before = session._snd_nxt
        rcv_nxt_before = session._rcv_nxt

        peer_rst_off_seq = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 10,
            ack=LOCAL__ISS + 2,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst_off_seq)

        self.assertEqual(
            len(rst_inline),
            1,
            msg=(
                "Peer's RST with in-window mismatched seq in "
                "FIN_WAIT_2 MUST elicit exactly one challenge ACK "
                "per RFC 9293 §3.10.7.4 case (2)."
            ),
        )
        challenge_ack = self._parse_tx(rst_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="In-window-mismatched RST must NOT reset the connection in FIN_WAIT_2.",
        )

    def test__close_rst__in_window_rst_in_close_wait_must_elicit_challenge_ack(self) -> None:
        """
        Ensure CLOSE_WAIT's RST handler honours the RFC 9293
        §3.10.7.4 case-2 challenge-ACK rule. Same gap class as the
        FIN_WAIT_1 / FIN_WAIT_2 siblings above.

        [FLAGS BUG] - '_tcp_fsm_close_wait's RST branch
        (line 2638-2652) uses strict 'tcp__seq == self._rcv_nxt'.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Drive into CLOSE_WAIT via peer FIN+ACK.
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
            msg="Setup precondition: state must be CLOSE_WAIT.",
        )
        snd_nxt_before = session._snd_nxt
        rcv_nxt_before = session._rcv_nxt

        peer_rst_off_seq = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=rcv_nxt_before + 10,
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst_off_seq)

        self.assertEqual(
            len(rst_inline),
            1,
            msg=(
                "Peer's RST with in-window mismatched seq in "
                "CLOSE_WAIT MUST elicit exactly one challenge ACK "
                "per RFC 9293 §3.10.7.4 case (2)."
            ),
        )
        challenge_ack = self._parse_tx(rst_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="In-window-mismatched RST must NOT reset the connection in CLOSE_WAIT.",
        )

    def test__close_rst__in_window_rst_in_last_ack_must_elicit_challenge_ack(self) -> None:
        """
        Ensure LAST_ACK's RST handler honours the RFC 9293
        §3.10.7.4 case-2 challenge-ACK rule. Same gap class as the
        FIN_WAIT_1 / FIN_WAIT_2 / CLOSE_WAIT siblings above.

        [FLAGS BUG] - '_tcp_fsm_last_ack's RST+ACK branch
        (line 2721-2733) uses strict 'tcp__seq == self._rcv_nxt'.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Drive CLOSE_WAIT then LAST_ACK.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        session.close()
        self._advance(ms=1)  # CLOSE_WAIT → LAST_ACK transition tick
        self._advance(ms=1)  # FIN-emit tick
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="Setup precondition: state must be LAST_ACK.",
        )
        snd_nxt_before = session._snd_nxt
        rcv_nxt_before = session._rcv_nxt

        peer_rst_off_seq = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=rcv_nxt_before + 10,
            ack=LOCAL__ISS + 2,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_rst_off_seq)

        self.assertEqual(
            len(rst_inline),
            1,
            msg=(
                "Peer's RST with in-window mismatched seq in "
                "LAST_ACK MUST elicit exactly one challenge ACK "
                "per RFC 9293 §3.10.7.4 case (2)."
            ),
        )
        challenge_ack = self._parse_tx(rst_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="In-window-mismatched RST must NOT reset the connection in LAST_ACK.",
        )

    def test__close_rst__session_teardown_unregisters_per_session_timer_entries(self) -> None:
        """
        Ensure that when a session terminates (state -> CLOSED via
        peer RST or any other path), the per-session entries
        registered into 'stack.timer' are unregistered. PyTCP today
        leaves entries like '<session>-delayed_ack',
        '<session>-retransmit_seq-{seq}', '<session>-time_wait',
        '<session>-persist', and '<session>-challenge_ack' in
        'stack.timer._timers' indefinitely after the session is
        gone - a slow accumulating memory leak across long-running
        stack instances with many connection churns.

        The leak is benign in short-lived test runs (each TestCase
        builds a fresh 'FakeTimer' via 'TcpSessionTestCase.setUp'
        so cross-test contamination is impossible) but a real
        production concern: a long-running stack handling thousands
        of connections per second would slowly grow the
        'stack.timer._timers' dict with stale entries that match no
        live session.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Send 100 bytes of data so a per-seq retransmit timer
               is armed under name '<session>-retransmit_seq-{seq}'.
            3. Peer sends a small data segment so the delayed-ACK
               timer is armed under '<session>-delayed_ack'.
            4. Sanity-check: 'stack.timer._timers' contains at
               least one entry whose key starts with the session's
               name prefix.
            5. Peer sends a clean RST (seq == RCV.NXT) which
               transitions state to CLOSED via
               '_tcp_fsm_established's RST handler.
            6. Inspect 'stack.timer._timers' AFTER the session is
               CLOSED. Assert: no entries whose key starts with
               the session's name prefix.

        [FLAGS BUG] - 'TcpSession._change_state' (line ~660 area)
        unregisters the socket from 'stack.sockets' on CLOSED
        transition but does NOT clean up the per-session timer
        entries registered via 'stack.timer.register_timer' over
        the session's lifetime.

        Fix outline (separate commit): in '_change_state' on
        transition to CLOSED, iterate 'stack.timer._timers' and
        pop every key whose prefix matches 'str(self)'. (Or
        track registered names in a per-instance set as they
        are registered, and pop the tracked set on teardown.)
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._snd_ewn = PEER__WIN

        # Send 100 bytes so a per-seq retransmit timer is armed.
        session.send(data=b"X" * 100)
        self._advance(ms=1)

        # Peer sends data so the delayed-ACK timer is armed.
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"hello",
        )
        self._drive_rx(frame=peer_data)

        session_prefix = f"{session}"
        timers_before = {name: ms for name, ms in self._timer.pending_timers.items() if name.startswith(session_prefix)}
        self.assertGreater(
            len(timers_before),
            0,
            msg=(
                "Setup precondition: at least one session-prefixed "
                "timer entry must be registered in 'stack.timer' "
                "after 'send()' and inbound peer-data have armed "
                "'-retransmit_seq-{seq}' and '-delayed_ack' entries. "
                f"Got: {timers_before}"
            ),
        )

        # Peer sends a clean RST. State -> CLOSED via
        # '_tcp_fsm_established's RST handler.
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 5,  # RCV.NXT after we processed peer's 5-byte data
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_rst)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="Setup precondition: peer's clean RST must transition session to CLOSED.",
        )

        # The bug: per-session timer entries survive the session's
        # CLOSED transition.
        timers_after = {name: ms for name, ms in self._timer.pending_timers.items() if name.startswith(session_prefix)}
        self.assertEqual(
            len(timers_after),
            0,
            msg=(
                "After the session has terminated (state -> CLOSED), "
                "all per-session entries in 'stack.timer._timers' "
                "MUST be unregistered. Today the entries persist "
                f"({timers_after}). On a long-running stack handling "
                "many connection churns this accumulates as a slow "
                "memory leak. Fix: '_change_state' on CLOSED must "
                "pop every per-session entry."
            ),
        )

    def test__close_rst__session_teardown_unregisters_tcp_fsm_callback_task(self) -> None:
        """
        Ensure that when a session terminates (state -> CLOSED),
        the 'TimerTask' that 'TcpSession.__init__' registered to
        drive the per-millisecond 'tcp_fsm' callback is removed
        from 'stack.timer._tasks'. Today the task remains
        forever; its bound-method reference holds the
        'TcpSession' instance alive against garbage collection
        and the timer keeps invoking 'tcp_fsm(timer=True)' on
        every tick on a dead session - hitting
        '_tcp_fsm_closed' as a no-op but still consuming CPU
        per tick per dead session.

        Companion to commit '93b99e4' / 'ea28db4' which closed
        the parallel '_timers'-dict leak (named-delay-timer
        entries leaked the same way until '_change_state'
        learned to pop them on CLOSED). The 'tcp_fsm' task is
        the OTHER half of the timer-side per-session
        registration (the named-delay-timer half is
        'register_timer'; this half is 'register_method'); the
        cleanup in '_change_state' did not extend to it.

        Scenario:

            1. Drive handshake to ESTABLISHED. The session's
               '__init__' has already registered 'self.tcp_fsm'
               with 'stack.timer.register_method(method=...)'
               so 'stack.timer._tasks' contains a
               '_FakeTimerTask' whose 'method' attribute is
               'session.tcp_fsm'.
            2. Sanity-check: filter '_tasks' to entries bound
               to 'session' and confirm exactly one match.
            3. Peer sends a clean RST. State -> CLOSED via
               '_tcp_fsm_established's RST handler.
            4. Inspect '_tasks' AFTER the session has reached
               CLOSED. Per spec, no task bound to 'session'
               should remain.

        Assertions:

            * After CLOSED: count of session-bound tasks in
              'stack.timer._tasks' is zero.

        [FLAGS BUG] - 'TcpSession._change_state' (line ~660
        area) on CLOSED transition unregisters the socket
        ('stack.sockets.pop') and the named-delay-timer entries
        ('stack.timer.unregister_timers_with_prefix' added in
        commit 'ea28db4') but does NOT remove the 'TimerTask'
        bound to the session's 'tcp_fsm'.

        The 'register_method' / '_tasks' API has no symmetric
        'unregister_method' helper today (parallel to the
        'register_timer' / '_timers' API which gained
        'unregister_timers_with_prefix' in 'ea28db4'). The fix
        adds 'unregister_method(method)' to both production
        'Timer' and the test 'FakeTimer', then calls it from
        '_change_state' on CLOSED.

        Fix outline (separate commit):

          - 'pytcp/stack/timer.py' adds an
            'unregister_method(method, /)' helper that filters
            'self._tasks' by bound-method equality.
          - 'pytcp/tests/lib/fake_timer.py' mirrors the API.
          - 'pytcp/socket/tcp__session.py' '_change_state' on
            CLOSED transition calls
            'stack.timer.unregister_method(self.tcp_fsm)'
            alongside 'stack.timer.unregister_timers_with_prefix'.
          - The three SimpleNamespace stubs in unit-test
            fixtures (lifecycle.py / fsm.py / syscalls.py) gain
            an 'unregister_method' field.

        Severity: MEDIUM - real but slow-burn. On a long-
        running production stack the per-session task survives
        forever, holding the session alive against GC (memory
        leak per session: full TX/RX buffers, scoreboard,
        locks, events) AND firing 'tcp_fsm(timer=True)' once
        per tick (CPU drain growing linearly with dead-session
        count). On the LAN/loopback testbed the leak is
        invisible because the test harness rebuilds 'FakeTimer'
        per test.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Sanity check: 'stack.timer._tasks' contains exactly one
        # task bound to this session. The task fires
        # 'session.tcp_fsm(timer=True)' on every tick and was
        # added by 'TcpSession.__init__'.
        session_tasks_before = [
            task for task in self._timer._tasks if getattr(task.method, "__self__", None) is session
        ]
        self.assertEqual(
            len(session_tasks_before),
            1,
            msg=(
                "Setup precondition: 'stack.timer._tasks' MUST "
                "contain exactly one task bound to the session "
                "after handshake. Without this precondition the "
                "test below is vacuous."
            ),
        )

        # Peer sends a clean RST. State -> CLOSED via
        # '_tcp_fsm_established's RST handler.
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,  # RCV.NXT
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_rst)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="Setup precondition: peer's clean RST must transition session to CLOSED.",
        )

        # The bug: the per-session 'TimerTask' survives the
        # CLOSED transition. It keeps firing on every tick,
        # holds 'session' alive against GC, and burns CPU per
        # tick.
        session_tasks_after = [task for task in self._timer._tasks if getattr(task.method, "__self__", None) is session]
        self.assertEqual(
            len(session_tasks_after),
            0,
            msg=(
                "After the session has terminated (state -> "
                "CLOSED), the 'TimerTask' that '__init__' "
                "registered for the session's 'tcp_fsm' callback "
                "MUST be removed from 'stack.timer._tasks'. "
                f"Today the task survives ({session_tasks_after}). "
                "On a long-running stack the dead-session task "
                "fires 'tcp_fsm(timer=True)' on every tick "
                "(burning CPU per tick per dead session) and the "
                "bound-method reference holds the 'TcpSession' "
                "instance alive against GC (leaking ~several KB "
                "per session). Fix: add an 'unregister_method' "
                "helper to 'Timer' / 'FakeTimer' and call it "
                "from '_change_state' on CLOSED."
            ),
        )
