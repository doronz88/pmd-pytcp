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
This module contains integration tests for the TCP Selective
Acknowledgment (SACK) option support in the 'TcpSession' state
machine per RFC 2018 / RFC 6675.

The tests in this file follow the phased plan in
'.claude/rules/tcp_sack_implementation.md'. Phase 1 lands two
positive-control regression guards: the parser decodes inbound
SACK options without crashing, and the session has no scoreboard
state today (so the wire-level behaviour stops short of any
RFC 6675 loss-recovery side effect). Subsequent phases will turn
SACK on as an active feature.

Reference RFCs:
    RFC 2018            TCP Selective Acknowledgment Options
    RFC 2883            DSACK extension (deferred to phase 7)
    RFC 6675            Conservative Loss Recovery using SACK
    RFC 9293 §3.10.7.4  Synchronized state segment processing

pytcp/tests/integration/socket/test__socket__tcp__session__sack.py

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

# Deterministic addressing for log readability and reproducibility.
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


class TestTcpSession__Sack(TcpSessionTestCase):
    """
    Integration tests for the TCP SACK option in the session FSM.
    Phase 1 covers the wire-level passthrough only: the parser
    decodes SACK options and the session ignores them silently
    (no scoreboard state today).
    """

    def _make_active_session(self, *, iss: int) -> TcpSession:
        """
        Build a 'TcpSocket' / 'TcpSession' pair wired up the way
        'TcpSocket.connect()' would wire them. Returns the session
        in CLOSED state ready for the caller to drive CONNECT.
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
        Drive the active-open three-way handshake to ESTABLISHED and
        return the session. Peer offers MSS only; SACK-Permitted is
        not part of the phase-1 negotiation.
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

    def test__sack__inbound_sack_option_does_not_crash_parser(self) -> None:
        """
        Ensure that an inbound ACK segment carrying a SACK option
        (RFC 2018 §3) is consumed by the wire path without raising
        and without forcing a state transition. The TCP parser
        already decodes 'TcpOptionSack' into a list of
        '(left, right)' blocks; this test guards against a
        regression where a future change to the parser, the FSM's
        option-reading logic, or the segment-factory mistakenly
        rejects or crashes on a SACK-bearing segment.

        Scenario:

            1. Drive the active-open handshake to ESTABLISHED.
               (Bilateral SACK-Permitted negotiation is out of
               scope for phase 1; the session does not advertise
               SACK-Permitted and so the SACK option arriving on
               peer's later segment is, strictly speaking, an
               RFC 2018 §2 violation. The receiver MUST NOT crash
               on it - it should be silently consumed.)
            2. Peer sends a bare-ACK segment carrying a SACK option
               with one block. The block edges are arbitrary -
               nothing in current code reads them.
            3. Drive RX. No exception. Session stays in ESTABLISHED.
               No RST. No challenge ACK. No inline TX at all (the
               segment is a pure dup-ACK with no new data).

        Assertions:

            * '_drive_rx' returns without raising.
            * No outbound frames produced.
            * 'session.state is FsmState.ESTABLISHED'.

        Passes today as a positive control / regression guard for
        the existing 'TcpOptionSack' parser support. A future
        SACK-implementation patch that rewires the option parsing
        path or the FSM option reader must keep this test green.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        peer_ack_with_sack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(0xDEAD_BEEF, 0xDEAD_BF13)],
        )
        inline_tx = self._drive_rx(frame=peer_ack_with_sack)

        self.assertEqual(
            inline_tx,
            [],
            msg=(
                "An inbound SACK-bearing dup-ACK must not elicit any "
                "inline TX from the FSM today; the option is decoded "
                "by the parser and silently consumed."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "An inbound SACK-bearing segment must not force a "
                "state transition out of ESTABLISHED; SACK is "
                "informational, never a control signal at the FSM "
                "level."
            ),
        )

    def test__sack__inbound_sack_option_does_not_yet_update_scoreboard_state(self) -> None:
        """
        Ensure that an inbound SACK option does not yet drive any
        loss-recovery side effect on our send side: PyTCP today has
        no '_sack_scoreboard' attribute on 'TcpSession', no
        RFC 6675 NextSeg / IsLost / Pipe machinery, and no
        SACK-aware fast-retransmit path. Wire-level decoding is in
        place (covered by the previous test); the FSM stops short
        of acting on what it sees.

        The phased SACK plan adds the scoreboard in phase 2 and
        wires the ingestion path in phase 4. Until then this test
        documents - and protects - the wire-level passthrough as
        the contract: SACK information arrives, gets decoded, and
        is dropped on the floor.

        Scenario:

            1. Drive the active-open handshake to ESTABLISHED.
            2. Application sends 200 bytes so we have outstanding
               unacked TX bytes the SACK option could theoretically
               reference.
            3. Drain the outbound data segment so the wire state
               settles.
            4. Peer sends a dup-ACK carrying a SACK block claiming
               to have received bytes that lie strictly above
               'SND.UNA' inside our outstanding range. RFC 6675's
               NextSeg / IsLost would, in the future, treat this
               block as evidence of loss - but only once the
               scoreboard exists to record it.
            5. Inspect session state. The scoreboard attribute is
               not present. The send-side counters are unchanged
               from the pre-ACK snapshot. No fast retransmit fires.

        Assertions:

            * 'TcpSession' instance has no '_sack_scoreboard'
              attribute - the scoreboard is introduced in phase 2.
            * '_snd_una', '_snd_nxt', '_snd_max' unchanged after
              the SACK-bearing dup-ACK.
            * No outbound TX (no fast retransmit, no challenge ACK,
              no anomalous reply).
            * 'session.state is FsmState.ESTABLISHED'.

        Passes today as a positive control / regression guard for
        the absence of half-baked SACK scoreboard state. The first
        phase-2 commit that introduces 'SackScoreboard' will need
        to drop the no-attribute assertion (or replace it with the
        new scoreboard's empty-state invariant), making this test
        a load-bearing tripwire for phase 2 wiring.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Bypass slow-start so the application's send drains in one
        # outbound segment - we want a clean post-data state to
        # contrast with after the SACK-bearing dup-ACK arrives.
        session._snd_ewn = PEER__WIN

        payload = b"X" * 200
        session.send(data=payload)
        self._advance(ms=1)

        snd_una_before = session._snd_una
        snd_nxt_before = session._snd_nxt
        snd_max_before = session._snd_max

        self.assertFalse(
            hasattr(session, "_sack_scoreboard"),
            msg=(
                "TcpSession must NOT have a '_sack_scoreboard' "
                "attribute today - the scoreboard is introduced in "
                "phase 2 of the SACK plan. If this assertion fails "
                "the scoreboard has shipped and this test should "
                "be replaced with the empty-state invariant of the "
                "new scoreboard."
            ),
        )

        # Peer sends a dup-ACK whose SACK block claims to have
        # received the upper half of our outstanding range.
        sacked_left = LOCAL__ISS + 1 + 100
        sacked_right = LOCAL__ISS + 1 + 200
        peer_dup_ack_with_sack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(sacked_left, sacked_right)],
        )
        inline_tx = self._drive_rx(frame=peer_dup_ack_with_sack)

        self.assertEqual(
            inline_tx,
            [],
            msg=(
                "SACK information today is informational only; the "
                "session must not synthesise any reply (no fast "
                "retransmit, no challenge ACK, no scoreboard-driven "
                "TX). Phase 5 will change that."
            ),
        )
        self.assertEqual(
            session._snd_una,
            snd_una_before,
            msg=(
                "A dup-ACK with SACK info must not advance SND.UNA - " "the cumulative ACK in the segment is unchanged."
            ),
        )
        self.assertEqual(
            session._snd_nxt,
            snd_nxt_before,
            msg=(
                "SND.NXT must not be perturbed by a SACK-bearing "
                "dup-ACK; only fast-retransmit / NextSeg-driven "
                "logic touches SND.NXT, and neither exists yet."
            ),
        )
        self.assertEqual(
            session._snd_max,
            snd_max_before,
            msg=(
                "SND.MAX must not be perturbed by a SACK-bearing "
                "dup-ACK; nothing on the SACK ingestion path "
                "extends the sent-bytes high-water mark today."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Session must remain in ESTABLISHED after a SACK-"
                "bearing dup-ACK; the option does not affect the "
                "FSM transition rules."
            ),
        )
