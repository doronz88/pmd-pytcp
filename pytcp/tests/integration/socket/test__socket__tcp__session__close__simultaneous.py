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
This module contains integration tests for the simultaneous-close
path through the TCP FSM in the 'TcpSession' state machine, where
both peers send FIN before either acknowledges the other's FIN.
The trajectory is ESTABLISHED → FIN_WAIT_1 → CLOSING → TIME_WAIT
per RFC 9293 §3.10.4 / §3.10.7.4.

The active-close and passive-close paths are covered by
'close__normal.py'; the TIME_WAIT expiry mechanics are covered
by 'close__time_wait.py'.

Reference RFCs:
    RFC 9293 §3.10.4    CLOSE Call
    RFC 9293 §3.10.7.4  Synchronized state segment processing
    RFC 9293 §3.5       Closing a Connection (state diagram)

pytcp/tests/integration/socket/test__socket__tcp__session__close__simultaneous.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.socket import AddressFamily
from pytcp.socket.tcp__session import (
    FsmState,
    SysCall,
    TcpSession,
)
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


class TestTcpClose__Simultaneous(TcpSessionTestCase):
    """
    Integration tests for the simultaneous-close path where both
    peers send FIN before either acknowledges the other's FIN.
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

    def test__close_simultaneous__both_sides_fin_walks_through_fin_wait_1_closing_time_wait(self) -> None:
        """
        Ensure that the simultaneous-close path - where both peers
        send FIN before either has ACKed the other's FIN - walks the
        FSM through ESTABLISHED → FIN_WAIT_1 → CLOSING → TIME_WAIT
        per RFC 9293 §3.10.4 / §3.10.7.4 / §3.5.

        The simultaneous-close trajectory:

            ESTABLISHED
                | local 'close()' (and peer's close fires concurrently)
                v                                send FIN+ACK -->
            FIN_WAIT_1                           <-- receive FIN+ACK
                | (peer's FIN+ACK does NOT             (peer's FIN)
                |  ack our FIN; we send our             ack < SND.FIN
                |  ACK of peer's FIN)                because peer hadn't
                v                                seen ours yet
            CLOSING                              <-- receive ACK
                |                                    (peer's ACK of our FIN)
                v                                ack == SND.NXT
            TIME_WAIT                                (== SND.FIN)
                |
                | (TIME_WAIT_DELAY elapses)
                v
            CLOSED

        RFC 9293 §3.10.7.4 (FIN-WAIT-1 segment processing, FIN bit
        case where the FIN segment does NOT carry an ack of our FIN):

            "If the FIN bit is set ... acknowledge the segment, ...
             If our FIN is now acknowledged, then enter the TIME-WAIT
             state, ... otherwise enter the CLOSING state."

        and §3.10.7.4 (CLOSING segment processing):

            "If SEG.ACK acks our FIN, then enter the TIME-WAIT
             state, ... otherwise ignore the segment."

        Scenario:

            1. Drive the active-open handshake to ESTABLISHED.
            2. Application calls 'close()'. '_closing' is set; state
               is still ESTABLISHED.
            3. Tick #1: ESTABLISHED → FIN_WAIT_1 (state-only).
            4. Tick #2: FIN+ACK fires at SEQ=LOCAL__ISS+1,
               ACK=PEER__ISS+1. '_snd_fin' is now LOCAL__ISS+2.
            5. Peer's FIN+ACK arrives at seq=PEER__ISS+1,
               ack=LOCAL__ISS+1 - NOTE: ack=LOCAL__ISS+1, NOT
               LOCAL__ISS+2; peer was closing simultaneously and
               had not yet seen our FIN, so peer's ack still
               points at the pre-FIN SEQ. This is the defining
               feature of simultaneous close.
            6. The FIN_WAIT_1 FIN+ACK branch runs
               '_process_ack_packet' (advancing RCV.NXT past
               peer's FIN), emits an inline ACK at ack=PEER__ISS+2,
               then checks 'if packet_rx_md.tcp__ack >= self._snd_fin'.
               Peer's ack (LOCAL__ISS+1) is BELOW our SND.FIN
               (LOCAL__ISS+2), so the branch enters the CLOSING
               state instead of TIME_WAIT.
            7. Peer ACKs our FIN with ack=LOCAL__ISS+2.
            8. CLOSING's ACK handler matches
               'ack == self._snd_nxt' (LOCAL__ISS+2 ==
               LOCAL__ISS+2) and the in-window guard
               'self._snd_una <= ack <= self._snd_max'
               (LOCAL__ISS+1 <= LOCAL__ISS+2 <= LOCAL__ISS+2),
               advances SND.UNA, transitions to TIME_WAIT, and
               arms the TIME_WAIT delay timer.

        Assertions on each step's wire shape and state:

            * Tick #2 emits exactly one FIN+ACK with the spec'd
              SEQ/ACK/flags/payload; '_snd_fin = LOCAL__ISS + 2'.
            * After peer's FIN+ACK with non-fin-acking ack:
                - Exactly one inline ACK acknowledging peer's FIN
                  (ack=PEER__ISS+2).
                - State is CLOSING (NOT TIME_WAIT).
                - 'RCV.NXT' advanced past peer's FIN.
            * After peer's ACK of our FIN: state is TIME_WAIT.

        This test passes on current code as a positive-control
        regression guard for the simultaneous-close subgraph.
        Future changes to the FIN_WAIT_1 FIN+ACK branch's
        'ack >= self._snd_fin' check (line 1565) or to CLOSING's
        'ack == self._snd_nxt' check (line 1671) are caught here.

        Note on CLOSING's strict 'ack == _snd_nxt' check:
        RFC 9293 §3.10.7.4's looser CLOSING-state rule is "if
        SEG.ACK acks our FIN" (i.e. 'ack >= _snd_fin'). PyTCP's
        equality check is stricter - it only matches the EXACT
        ACK value at the moment of the FIN. In the canonical
        simultaneous-close flow exercised here, the two are
        equivalent because '_snd_nxt == _snd_fin' after we send
        the FIN and no further data goes out (TCP forbids data
        after FIN). The deviation only matters if a buggy peer
        sends 'ack > _snd_fin', which is out of spec on their
        side; this test does not flag the deviation as a bug.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Application initiates close. Tick to fire the
        # ESTABLISHED -> FIN_WAIT_1 transition, then tick again to
        # emit our FIN+ACK.
        session.close()
        transition_tx = self._advance(ms=1)
        self.assertEqual(
            transition_tx,
            [],
            msg="ESTABLISHED -> FIN_WAIT_1 transition tick must emit no segment.",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="State must be FIN_WAIT_1 after the transition tick.",
        )

        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg="FIN_WAIT_1's first timer tick must emit our FIN+ACK.",
        )
        our_fin = self._parse_tx(fin_tx[0])
        self._assert_segment(
            our_fin,
            flags=frozenset({"FIN", "ACK"}),
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
        )
        self.assertEqual(
            session._snd_fin,
            LOCAL__ISS + 2,
            msg="'_snd_fin' must equal post-FIN 'SND.NXT' (LOCAL__ISS + 2).",
        )

        # Peer's FIN+ACK arrives but its ACK does NOT cover our FIN.
        # This is the defining characteristic of simultaneous close:
        # peer was closing concurrently and had not yet seen our FIN.
        peer_fin_simultaneous = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        peer_fin_inline = self._drive_rx(frame=peer_fin_simultaneous)

        # The FIN+ACK branch in FIN_WAIT_1 emits an inline ACK
        # acknowledging peer's FIN, then transitions to CLOSING
        # (because peer's ack < our SND.FIN).
        self.assertEqual(
            len(peer_fin_inline),
            1,
            msg=(
                "Peer's simultaneous FIN+ACK must elicit exactly one "
                "inline ACK acknowledging peer's FIN per the FIN+ACK "
                "branch in '_tcp_fsm_fin_wait_1' (line 1559)."
            ),
        )
        ack_of_peer_fin = self._parse_tx(peer_fin_inline[0])
        self._assert_segment(
            ack_of_peer_fin,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 2,
            ack=PEER__ISS + 2,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSING,
            msg=(
                "After peer's FIN+ACK whose ack does NOT cover our FIN "
                "(ack=LOCAL__ISS+1 < SND.FIN=LOCAL__ISS+2), state must "
                "transition to CLOSING per RFC 9293 §3.10.7.4 - NOT to "
                "TIME_WAIT (TIME_WAIT requires peer to also have ACKed "
                "our FIN)."
            ),
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 2,
            msg="'RCV.NXT' must advance past peer's FIN's one byte of sequence space.",
        )

        # Peer ACKs our FIN. ack=LOCAL__ISS+2 covers our FIN's seq
        # byte.
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 2,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        closing_ack_inline = self._drive_rx(frame=peer_ack_of_fin)
        self.assertEqual(
            closing_ack_inline,
            [],
            msg=(
                "Peer's ACK of our FIN in CLOSING must not produce "
                "inline TX - CLOSING's ACK handler simply transitions "
                "to TIME_WAIT and arms the TIME_WAIT timer."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.TIME_WAIT,
            msg=(
                "After peer's ACK of our FIN in CLOSING, state must "
                "transition to TIME_WAIT per RFC 9293 §3.10.7.4 - "
                "both halves of the connection have now had their "
                "FINs acknowledged."
            ),
        )
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 2,
            msg=("'SND.UNA' must advance to LOCAL__ISS+2 after CLOSING's " "ACK handler runs (line 1672)."),
        )
