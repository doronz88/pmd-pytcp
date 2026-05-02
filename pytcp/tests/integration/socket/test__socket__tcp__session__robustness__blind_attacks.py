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
This module contains integration tests for the TCP blind-attack
robustness mitigations described by RFC 9293 §3.10.7.4 (folding
RFC 5961). Specifically, this file targets the SYN-in-synchronized-
state challenge-ACK rule for the FSM states that the existing
'TcpSession' implementation does NOT yet handle: FIN_WAIT_1,
FIN_WAIT_2, CLOSE_WAIT, CLOSING, LAST_ACK, TIME_WAIT.

ESTABLISHED and SYN_RCVD already emit the challenge ACK
(line 1354 and 1247 respectively, surfaced and fixed in the
'handshake__active.py' / 'handshake__passive.py' files). The
remaining six synchronized states share the same RFC 9293
mandate but currently silently drop a SYN-bearing segment,
leaving the connection vulnerable to blind reset attacks where
an off-path adversary injects a SYN and waits for the legitimate
peer's confused response to leak sequence-space information.

The blind-RST mitigation (in-window-but-mismatched RST -> challenge
ACK) is covered by 'close__rst.py' scenario #6.

The blind-data-injection mitigation (data with bogus ACK -> empty
ACK reply) is covered by 'data_transfer__recv.py' scenario #4
(commit '7893c97').

Reference RFCs:
    RFC 9293 §3.10.7.4   Synchronized state segment processing
    RFC 5961 §4          Mitigating Blind Connection Attacks (SYN
                         injection)
    RFC 5961 §3          Blind RST Attacks (covered separately)
    RFC 5961 §5          Blind Data Injection (covered separately)

pytcp/tests/integration/socket/test__socket__tcp__session__robustness__blind_attacks.py

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


class TestTcpRobustness__BlindAttacks(TcpSessionTestCase):
    """
    Integration tests for the SYN-in-synchronized-state challenge-
    ACK rule across the FSM states that currently lack the
    mitigation (FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT, CLOSING,
    LAST_ACK, TIME_WAIT).
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

    def test__robustness__syn_in_fin_wait_1_must_elicit_challenge_ack(self) -> None:
        """
        Ensure that a peer-issued SYN arriving while we are in
        FIN_WAIT_1 (we have sent our FIN and are awaiting its ACK)
        elicits a challenge ACK at our current SND.NXT / RCV.NXT
        and does NOT change state, per RFC 9293 §3.10.7.4 (folding
        RFC 5961 §4).

        RFC 9293 §3.10.7.4 (synchronized state, SYN bit set):

            "If the SYN bit is set in these synchronized states, it
             may be either a legitimate new connection attempt
             (e.g., in the case of TIME-WAIT), an error where the
             connection should be reset, or the result of an attack
             attempt, as described in RFC 5961 [9].  For the TIME-
             WAIT state, new connections can be accepted if the
             Timestamp Option is used and meets expectations (per
             [40]).  For all other cases, RFC 5961 provides a
             mitigation with applicability to some situations,
             though there are also alternatives that offer cryptographic
             protection (see RFC 5925 [37]).  RFC 5961 recommends
             that in these synchronized states, if the SYN bit is
             set, irrespective of the sequence number, TCP endpoints
             MUST send a 'challenge ACK' to the remote peer."

        And RFC 5961 §4 (the recommended mitigation):

            "If the SYN bit is set, irrespective of the sequence
             number, TCP MUST send an ACK (also referred to as
             challenge ACK) to the remote peer."

        The current 'TcpSession' implementation handles this rule
        in ESTABLISHED (line 1354) and SYN_RCVD (line 1247) but
        not in any of the other synchronized states. A peer (or
        attacker) sending a SYN to a session in FIN_WAIT_1 will
        see no reply at all - the FSM dispatcher routes the
        segment into '_tcp_fsm_fin_wait_1', which has no SYN-
        matching branch (its three branches match ACK-only,
        FIN+ACK, and RST+ACK with SYN explicitly excluded), so
        the SYN falls through and is silently dropped.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Application calls 'close()'. Tick #1 transitions
               to FIN_WAIT_1; tick #2 emits our FIN+ACK at
               SEQ = LOCAL__ISS + 1. SND.NXT advances to
               LOCAL__ISS + 2 (post-FIN), SND.MAX = LOCAL__ISS + 2.
            3. Peer (or off-path attacker) sends a SYN to our
               4-tuple. The wire shape mimics a fresh handshake
               attempt: flags = {SYN}, seq chosen arbitrarily
               (the RFC says "irrespective of the sequence
               number" - the attacker does not know RCV.NXT),
               no MSS option, no payload.
            4. Drive RX. Per RFC 9293 §3.10.7.4 / RFC 5961 §4,
               we MUST emit a challenge ACK pointing at our
               current SND.NXT and RCV.NXT (i.e. seq = LOCAL__ISS
               + 2, ack = PEER__ISS + 1). State must NOT change.

        Assertions:

            * Exactly ONE inline TX frame is emitted - the
              challenge ACK (the spec encoding).
            * The challenge ACK carries flags = {ACK}.
            * 'seq = LOCAL__ISS + 2' (== current SND.NXT after FIN).
            * 'ack = PEER__ISS + 1' (== current RCV.NXT, no peer
              data was sent).
            * State remains FIN_WAIT_1 - the SYN is REJECTED, the
              graceful 4-way close is unaffected.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_fin_wait_1' (line 1508-
        1585) has no SYN-matching branch. The three branches it
        does have (ACK-only at 1525, FIN+ACK at 1550, RST+ACK at
        1576) all explicitly exclude SYN via 'not any({tcp__flag_syn})'.
        A SYN-bearing segment falls through and is silently dropped,
        leaving FIN_WAIT_1 vulnerable to the blind-attack scenario
        the RFC mandates a challenge-ACK defence against.

        The fix mirrors the existing pattern in '_tcp_fsm_established'
        (line 1354):

            if packet_rx_md and packet_rx_md.tcp__flag_syn:
                self._transmit_packet(flag_ack=True)
                return

        placed near the top of '_tcp_fsm_fin_wait_1's segment-
        handling chain (after the timer branch). The same one-
        liner is needed in the other five close-related state
        handlers; this test surfaces FIN_WAIT_1 specifically as
        the most impactful (active-close path).

        On current code this test will see zero outbound TX after
        the SYN arrives - failing the inline-TX-count assertion.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

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
            session._snd_nxt,
            LOCAL__ISS + 2,
            msg=("Setup precondition: 'SND.NXT' must reflect the " "post-FIN sequence number (LOCAL__ISS + 2)."),
        )

        # Peer (or attacker) sends a fresh SYN to our 4-tuple.
        # The seq is intentionally arbitrary to encode the RFC's
        # "irrespective of the sequence number" rule.
        attacker_syn_seq = 0x4000_0000  # well clear of legitimate seq space
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=attacker_syn_seq,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
        )
        syn_inline = self._drive_rx(frame=peer_syn)

        # The spec encoding: exactly one challenge ACK fires.
        self.assertEqual(
            len(syn_inline),
            1,
            msg=(
                "Peer's SYN in FIN_WAIT_1 MUST elicit exactly one "
                "challenge ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4 "
                "('irrespective of the sequence number, TCP endpoints "
                "MUST send a challenge ACK'). Current code's "
                "'_tcp_fsm_fin_wait_1' has no SYN-matching branch and "
                "the segment falls through silently."
            ),
        )
        challenge_ack = self._parse_tx(syn_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 2,
            ack=PEER__ISS + 1,
            payload=b"",
        )

        # State must remain FIN_WAIT_1. The SYN is rejected; the
        # graceful 4-way close is unaffected.
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg=(
                "A SYN in FIN_WAIT_1 MUST NOT change state - the "
                "challenge ACK is the only response, and the in-"
                "progress close continues normally."
            ),
        )

    def test__robustness__syn_in_fin_wait_2_must_elicit_challenge_ack(self) -> None:
        """
        Ensure that a peer-issued SYN arriving while we are in
        FIN_WAIT_2 (we have sent our FIN and received its ACK; we
        are awaiting peer's FIN) elicits a challenge ACK and does
        NOT change state, per RFC 9293 §3.10.7.4 / RFC 5961 §4.

        Same RFC mandate as the FIN_WAIT_1 case - 'irrespective of
        the sequence number, TCP endpoints MUST send a challenge
        ACK to the remote peer'. Differentiates from FIN_WAIT_1 by
        having SND.UNA already advanced to SND.MAX (peer ACKed our
        FIN), which means the challenge ACK's seq is the same
        post-FIN value (LOCAL__ISS + 2) but RCV.NXT remains at
        PEER__ISS + 1 (peer has not sent its FIN yet - that would
        have transitioned us to TIME_WAIT).

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Application calls 'close()'. Tick #1 transitions
               to FIN_WAIT_1; tick #2 emits our FIN+ACK.
            3. Peer ACKs our FIN; state -> FIN_WAIT_2; SND.UNA
               advances to LOCAL__ISS + 2.
            4. Peer (or attacker) sends a SYN at arbitrary seq.
            5. Drive RX. Per RFC, we MUST emit a challenge ACK
               at seq=LOCAL__ISS+2, ack=PEER__ISS+1, and state
               must remain FIN_WAIT_2.

        Assertions:

            * Exactly one inline TX - the challenge ACK.
            * 'seq = LOCAL__ISS + 2', 'ack = PEER__ISS + 1', flags
              = {ACK}.
            * State remains FIN_WAIT_2.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_fin_wait_2' (line 1587-
        1647) has no SYN-matching branch. Same fix pattern as
        FIN_WAIT_1 applies.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Walk into FIN_WAIT_2.
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

        # Attacker SYN.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x4000_0000,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
        )
        syn_inline = self._drive_rx(frame=peer_syn)

        self.assertEqual(
            len(syn_inline),
            1,
            msg=(
                "Peer's SYN in FIN_WAIT_2 MUST elicit exactly one "
                "challenge ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4. "
                "Current code's '_tcp_fsm_fin_wait_2' has no SYN-"
                "matching branch and the segment falls through "
                "silently."
            ),
        )
        challenge_ack = self._parse_tx(syn_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 2,
            ack=PEER__ISS + 1,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg="A SYN in FIN_WAIT_2 MUST NOT change state.",
        )

    def test__robustness__syn_in_close_wait_must_elicit_challenge_ack(self) -> None:
        """
        Ensure that a peer-issued SYN arriving while we are in
        CLOSE_WAIT (peer closed first; we have not yet called
        'close()') elicits a challenge ACK and does NOT change
        state, per RFC 9293 §3.10.7.4 / RFC 5961 §4.

        CLOSE_WAIT is unique among the close-related states in
        that we have NOT sent our FIN yet - SND.NXT is still at
        LOCAL__ISS + 1 - while RCV.NXT has advanced past peer's
        FIN to PEER__ISS + 2. The challenge ACK therefore
        acknowledges peer's FIN cumulatively.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Peer sends FIN+ACK; state -> CLOSE_WAIT,
               RCV.NXT = PEER__ISS + 2.
            3. Without ticking (so the delayed ACK of peer's FIN
               has not yet fired), peer/attacker sends a SYN at
               arbitrary seq.
            4. Drive RX. Per RFC, we MUST emit a challenge ACK
               at seq=LOCAL__ISS+1, ack=PEER__ISS+2 (acking the
               FIN cumulatively), and state must remain CLOSE_WAIT.

        Assertions:

            * Exactly one inline TX - the challenge ACK.
            * 'seq = LOCAL__ISS + 1' (we have not sent our FIN).
            * 'ack = PEER__ISS + 2' (acknowledges peer's FIN).
            * flags = {ACK}.
            * State remains CLOSE_WAIT.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_close_wait' (line 1690-
        1773) has no SYN-matching branch. Same fix pattern as
        the other states.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Walk into CLOSE_WAIT.
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

        # Attacker SYN before any tick fires the delayed ACK.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x4000_0000,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
        )
        syn_inline = self._drive_rx(frame=peer_syn)

        self.assertEqual(
            len(syn_inline),
            1,
            msg=(
                "Peer's SYN in CLOSE_WAIT MUST elicit exactly one "
                "challenge ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4. "
                "Current code's '_tcp_fsm_close_wait' has no SYN-"
                "matching branch and the segment falls through "
                "silently."
            ),
        )
        challenge_ack = self._parse_tx(syn_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 2,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="A SYN in CLOSE_WAIT MUST NOT change state.",
        )

    def test__robustness__syn_in_closing_must_elicit_challenge_ack(self) -> None:
        """
        Ensure that a peer-issued SYN arriving while we are in
        CLOSING (we and peer have both sent FIN; we have received
        and acknowledged peer's FIN but ours is not yet ACKed)
        elicits a challenge ACK and does NOT change state, per
        RFC 9293 §3.10.7.4 / RFC 5961 §4.

        CLOSING is the simultaneous-close state - both sides FIN,
        neither has ACKed the other's FIN yet at the moment of
        transition. After we ACK peer's FIN, we are awaiting peer's
        ACK of our FIN.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Application calls 'close()'. Tick #1 transitions
               to FIN_WAIT_1; tick #2 emits our FIN+ACK.
            3. Peer sends FIN+ACK with ack=LOCAL__ISS+1 (does
               NOT ack our FIN; the simultaneous-close marker).
               State -> CLOSING; we emit inline ACK at
               ack=PEER__ISS+2.
            4. Attacker sends a SYN at arbitrary seq.
            5. Per RFC, we MUST emit a challenge ACK at
               seq=LOCAL__ISS+2, ack=PEER__ISS+2, and state must
               remain CLOSING.

        Assertions:

            * Exactly one inline TX in response to the SYN -
              the challenge ACK.
            * 'seq = LOCAL__ISS + 2' (post-FIN), 'ack = PEER__ISS
              + 2' (acknowledges peer's FIN cumulatively),
              flags={ACK}.
            * State remains CLOSING.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_closing' (line 1649-
        1688) has no SYN-matching branch. Same fix pattern.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Walk to FIN_WAIT_1.
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)

        # Simultaneous-close FIN+ACK with non-fin-acking ack.
        peer_fin_simultaneous = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin_simultaneous)
        self.assertIs(
            session.state,
            FsmState.CLOSING,
            msg="Setup precondition: state must be CLOSING.",
        )

        # Attacker SYN.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x4000_0000,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
        )
        syn_inline = self._drive_rx(frame=peer_syn)

        self.assertEqual(
            len(syn_inline),
            1,
            msg=(
                "Peer's SYN in CLOSING MUST elicit exactly one "
                "challenge ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4. "
                "Current code's '_tcp_fsm_closing' has no SYN-"
                "matching branch and the segment falls through "
                "silently."
            ),
        )
        challenge_ack = self._parse_tx(syn_inline[0])
        self._assert_segment(
            challenge_ack,
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
            msg="A SYN in CLOSING MUST NOT change state.",
        )

    def test__robustness__syn_in_last_ack_must_elicit_challenge_ack(self) -> None:
        """
        Ensure that a peer-issued SYN arriving while we are in
        LAST_ACK (we sent our FIN after the peer closed first; we
        are awaiting peer's ACK of our FIN) elicits a challenge
        ACK and does NOT change state, per RFC 9293 §3.10.7.4 /
        RFC 5961 §4.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Peer sends FIN+ACK; state -> CLOSE_WAIT.
            3. Tick to drain delayed ACK of peer's FIN.
            4. Application calls 'close()'. Tick #1: state ->
               LAST_ACK. Tick #2: our FIN+ACK fires at SEQ =
               LOCAL__ISS + 1. SND.NXT advances to LOCAL__ISS + 2.
            5. Attacker sends a SYN.
            6. Per RFC, we MUST emit a challenge ACK at
               seq=LOCAL__ISS+2, ack=PEER__ISS+2, and state must
               remain LAST_ACK.

        Assertions:

            * Exactly one inline TX in response to the SYN.
            * 'seq = LOCAL__ISS + 2', 'ack = PEER__ISS + 2', flags
              = {ACK}.
            * State remains LAST_ACK.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_last_ack' (line 1775-
        1818) has no SYN-matching branch.
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
        self._advance(ms=1)

        session.close()
        self._advance(ms=1)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="Setup precondition: state must be LAST_ACK.",
        )

        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x4000_0000,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
        )
        syn_inline = self._drive_rx(frame=peer_syn)

        self.assertEqual(
            len(syn_inline),
            1,
            msg=(
                "Peer's SYN in LAST_ACK MUST elicit exactly one "
                "challenge ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4. "
                "Current code's '_tcp_fsm_last_ack' has no SYN-"
                "matching branch."
            ),
        )
        challenge_ack = self._parse_tx(syn_inline[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 2,
            ack=PEER__ISS + 2,
            payload=b"",
        )
        self.assertIs(
            session.state,
            FsmState.LAST_ACK,
            msg="A SYN in LAST_ACK MUST NOT change state.",
        )

    def test__robustness__syn_in_time_wait_must_elicit_challenge_ack(self) -> None:
        """
        Ensure that a peer-issued SYN arriving while we are in
        TIME_WAIT (active close completed; we are waiting out the
        2 MSL grace period) elicits a challenge ACK and does NOT
        change state, per RFC 9293 §3.10.7.4 / RFC 5961 §4.

        RFC 9293 §3.10.7.4 mentions a special-case exception for
        TIME_WAIT:

            "For the TIME-WAIT state, new connections can be
             accepted if the Timestamp Option is used and meets
             expectations (per [40])."

        i.e. RFC 6191 / RFC 7323's PAWS allows recycling the
        4-tuple from TIME_WAIT into a fresh connection if the
        SYN's TSecr establishes that the new SYN is "newer" than
        any segment that could still be in flight from the prior
        connection. PyTCP does NOT currently implement the
        Timestamp Option (see harness factory's 'paws_ts'
        sentinel that raises NotImplementedError), so the
        TIME_WAIT-specific recycling path is unreachable. The
        default RFC 9293 §3.10.7.4 / RFC 5961 §4 behaviour
        applies: emit a challenge ACK, no state change.

        Scenario:

            1. Drive an active-close path to TIME_WAIT (via
               ESTABLISHED -> FIN_WAIT_1 -> FIN_WAIT_2 ->
               TIME_WAIT).
            2. Attacker sends a SYN at arbitrary seq with NO
               timestamp option (the PyTCP-supported case).
            3. Per RFC, we MUST emit a challenge ACK at
               seq=LOCAL__ISS+2, ack=PEER__ISS+2, and state
               must remain TIME_WAIT.

        Assertions:

            * Exactly one inline TX in response to the SYN.
            * 'seq = LOCAL__ISS + 2', 'ack = PEER__ISS + 2', flags
              = {ACK}.
            * State remains TIME_WAIT.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_time_wait' (post the
        TIME_WAIT FIN-retransmit fix from commit '323c96c') now
        accepts a 'packet_rx_md' parameter and has one inbound
        branch (FIN retransmit -> ACK + restart timer). It still
        has no SYN-matching branch, so a SYN falls through to
        the return at the bottom of the FIN branch (which doesn't
        match SYN-only) and is silently dropped. The fix is the
        same one-line pattern applied to the other five close-
        related state handlers.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Walk to TIME_WAIT via the active-close path.
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
            msg="Setup precondition: state must be TIME_WAIT.",
        )

        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x4000_0000,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
        )
        syn_inline = self._drive_rx(frame=peer_syn)

        self.assertEqual(
            len(syn_inline),
            1,
            msg=(
                "Peer's SYN in TIME_WAIT (without a Timestamp "
                "option, since PyTCP does not support PAWS) MUST "
                "elicit exactly one challenge ACK per RFC 9293 "
                "§3.10.7.4 / RFC 5961 §4. Current code's "
                "'_tcp_fsm_time_wait' has no SYN-matching branch."
            ),
        )
        challenge_ack = self._parse_tx(syn_inline[0])
        self._assert_segment(
            challenge_ack,
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
            msg="A SYN in TIME_WAIT (without PAWS) MUST NOT change state.",
        )

    def test__blind_attack__challenge_ack_burst_is_rate_limited_per_rfc_5961_3(self) -> None:
        """
        Ensure that a burst of unacceptable segments arriving in a
        sub-1-second window does NOT produce one challenge ACK per
        inbound segment. Per RFC 5961 §3, the receiver MUST rate-
        limit challenge-ACK responses to mitigate ACK-amplification
        DoS attacks where a small volume of malicious or buggy
        inbound segments produces a large outbound ACK flood.

        RFC 5961 §3 (Mitigating Blind Reset Attacks):

            "It is recommended that the implementation rate-limit
             the response to ACK segments. ...  A method of
             implementing the SHOULD-recommendation is to choose a
             sliding window size of one second and allow at most
             one challenge ACK per window."

        Linux's default is one challenge-ACK per second; RFC 5961
        leaves the exact rate to the implementation but the
        principle is firm: one inbound unacceptable segment
        should not amplify into one outbound ACK without bound.

        Attack vector: a flood of out-of-window data segments
        (e.g. blind injection by an off-path attacker, or a
        misbehaving peer in a retransmit storm). Each one passes
        the receive-window acceptability check at
        '_check_segment_acceptability' (introduced in commit
        '7f0d18b') and emits an empty-ACK reply. With no rate
        limit, the receiver becomes an amplifier - an inbound
        segment trickle becomes an outbound ACK flood, saturating
        the local link and giving the attacker the amplification
        they sought.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Drain any post-handshake state.
            3. Send 10 unacceptable data segments back-to-back
               within a sub-1-second window. Each segment has
               'seq' below RCV.NXT (fully duplicate, RFC §3.10.7.4
               unacceptable) so each currently elicits one
               challenge ACK.
            4. Inspect the inline TX list. Per RFC 5961 §3, the
               total outbound ACK count MUST be small (default:
               one per second window).

        Assertions:

            * Total outbound challenge-ACK frames across all 10
              inbound segments is at most 2 (= one for the
              opening sliding window + one allowance margin).
              The exact threshold is implementation-defined per
              RFC 5961 §3; the test asserts the principle, not
              a specific numeric limit.

        [FLAGS BUG] - 'TcpSession._check_segment_acceptability'
        emits 'self._transmit_packet(flag_ack=True)' on every
        unacceptable non-RST segment with no rate limit. Same
        gap exists in the SYN-bearing branches in ESTABLISHED /
        CLOSE_WAIT (each blind SYN-in-synchronized-state gets
        an immediate challenge ACK) and in the OOO branch's
        capped-at-2 dup-ACK emissions. RFC 5961 §3 mandates a
        unified rate limit across ALL challenge-ACK emission
        sites.

        Fix outline (separate commit):

          - Add '_challenge_ack_window_start: int = 0' and
            '_challenge_ack_count: int = 0' attributes (or
            equivalent token-bucket / sliding-window state)
            to 'TcpSession.__init__'.
          - Add a '_emit_challenge_ack()' helper that:
              * Reads the current virtual-clock millisecond.
              * If we are in a new 1-second window since
                '_challenge_ack_window_start', reset the count
                and update the window-start.
              * If '_challenge_ack_count' is at the limit (1
                per RFC 5961 §3 recommendation), suppress the
                emission and return.
              * Else fire 'self._transmit_packet(flag_ack=True)'
                and increment the count.
          - Replace every challenge-ACK emission site
            (acceptability helper, SYN-bearing branches, OOO
            branch) with the helper.

        On current code this test fails with TX count == 10:
        every unacceptable segment elicits a challenge ACK.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Drain any post-handshake state (delayed-ACK timers, etc.).
        self._advance(ms=200)

        # Peer sends 10 unacceptable data segments back-to-back.
        # Each carries seq below RCV.NXT (fully duplicate; the
        # acceptability check rejects each segment with an ACK
        # reply).
        unacceptable_segments_count = 10
        before_count = len(self._frames_tx)
        for _ in range(unacceptable_segments_count):
            unacceptable_segment = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS,  # below RCV.NXT (= PEER__ISS + 1)
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
                payload=b"X",  # 1 byte, fully below RCV.NXT
            )
            self._drive_rx(frame=unacceptable_segment)
        after_count = len(self._frames_tx)
        burst_tx_count = after_count - before_count

        # Per RFC 5961 §3, the burst MUST be rate-limited. The
        # exact threshold is implementation-defined (Linux uses
        # 1/sec); we assert the principle: the count is bounded
        # well below the inbound count. Allow up to 2 challenge
        # ACKs (one for the opening window + a small
        # implementation margin); 10 inbound -> 10 outbound is
        # clearly broken.
        self.assertLessEqual(
            burst_tx_count,
            2,
            msg=(
                f"RFC 5961 §3: a burst of {unacceptable_segments_count} "
                "unacceptable segments arriving in a sub-1-second "
                "window MUST be rate-limited to at most ~1 challenge "
                "ACK. PyTCP today emits one ACK per inbound segment "
                f"(observed {burst_tx_count} outbound ACKs) - this is "
                "an ACK-amplification DoS vector. Fix: introduce a "
                "'_emit_challenge_ack' helper that enforces a 1-per-"
                "second sliding-window rate limit and route all "
                "challenge-ACK emission sites through it."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Sanity: rate-limited or not, the burst MUST NOT change FSM state.",
        )
