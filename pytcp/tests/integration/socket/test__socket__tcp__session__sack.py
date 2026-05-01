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
LISTEN__PORT: int = 80
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80
PEER__PASSIVE_PORT: int = 33000

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
    Phase 1 covers the wire-level passthrough; phase 3 covers
    bilateral SACK-Permitted negotiation and receive-side SACK
    block emission on outbound ACKs when out-of-order data is
    queued.
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

    def _make_listen_session(self, *, iss: int) -> TcpSession:
        """
        Build a wildcard-bound listening 'TcpSocket' / 'TcpSession'
        pair the way 'TcpSocket.listen()' would wire them, drive
        the LISTEN syscall so the FSM transitions CLOSED -> LISTEN,
        and return the session.
        """

        self._force_iss(iss)

        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = LISTEN__PORT
        sock._remote_ip_address = Ip4Address()
        sock._remote_port = 0

        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=LISTEN__PORT,
            remote_ip_address=Ip4Address(),
            remote_port=0,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock

        session.tcp_fsm(syscall=SysCall.LISTEN)
        return session

    def _drive_handshake_to_established(
        self,
        *,
        iss: int,
        peer_iss: int,
        peer_sackperm: bool = False,
    ) -> TcpSession:
        """
        Drive the active-open three-way handshake to ESTABLISHED and
        return the session. 'peer_sackperm' controls whether the
        peer's SYN+ACK carries the SACK-Permitted option; pass True
        when the test needs bilateral SACK negotiation to succeed.
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
            sackperm=peer_sackperm,
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

    def test__sack__outbound_syn_advertises_sack_permitted(self) -> None:
        """
        Ensure that an active-open session emits its initial SYN
        with the SACK-Permitted option per RFC 2018 §2. Without our
        advertisement the bilateral SACK negotiation cannot
        complete, peer has no reason to enable SACK, and any later
        loss-recovery RFC 6675 machinery is dead - the connection
        falls back to the count-based dup-ACK fast-retransmit path
        only.

        RFC 2018 §2 (SACK-Permitted Option):

            "The SACK-permitted option is offered to the remote end
             during TCP setup as an option to an opening SYN packet.
             ... It MUST NOT be sent on non-SYN segments."

        Concretely:

            * The outbound SYN MUST carry the SACK-Permitted option.
            * The session must default to advertising it
              ('_advertise_sack = True') so SACK is the modern
              throughput-friendly default, opt-out via
              '_advertise_sack = False' before CONNECT.

        Scenario:

            1. Build a session and emit our outbound SYN.
            2. Parse the SYN frame and inspect the SACK-Permitted
               option presence.

        Assertions:

            * The outbound SYN carries 'sackperm = True' on the
              wire.

        [FLAGS BUG] - 'TcpSession._transmit_packet' (line 577)
        currently has no SACK-Permitted plumbing: there is no
        'self._advertise_sack' attribute, no 'tcp__sackperm'
        parameter on 'send_tcp_packet', and no encoder branch in
        'packet_handler__tcp__tx.py'. The fix is the phase-3
        implementation: add '_advertise_sack: bool = True' and
        '_send_sack: bool = False' attributes, route a 'sackperm'
        flag through the TX path, and emit
        'TcpOptionSackperm' on outbound SYN/SYN+ACK iff
        'self._advertise_sack' (and, for SYN+ACK, peer's SYN
        carried the option per the bilateral mirror rule).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        syn_probe = self._parse_tx(syn_tx[0])
        self._assert_segment(
            syn_probe,
            flags=frozenset({"SYN"}),
            sackperm=True,
        )
        self.assertTrue(
            session._advertise_sack,
            msg="The default value of 'TcpSession._advertise_sack' must be True.",
        )

    def test__sack__bilateral_sack_negotiation_sets_send_sack(self) -> None:
        """
        Ensure that when both sides advertise SACK-Permitted on
        their SYN exchange, the active-open session records the
        successful bilateral negotiation by setting
        'self._send_sack = True'. Per RFC 2018 §2 SACK is bilateral:
        each side may send SACK information only if BOTH sides
        offered SACK-Permitted on their respective SYNs.

        RFC 2018 §3 (Sending the SACK option):

            "If sent at all, an SACK option that specifies n blocks
             will have a length of 8*n+2 bytes, so the 40 bytes
             available for TCP options can specify a maximum of 4
             blocks. ... The SACK option is to be used to convey
             extended acknowledgment information from the receiver
             to the sender over an established connection. The SACK
             option SHOULD be sent if the SACK-permitted option was
             received during connection establishment."

        Scenario:

            1. Drive an active-open handshake with peer's SYN+ACK
               carrying the SACK-Permitted option.
            2. Inspect 'session._send_sack' after ESTABLISHED.

        Assertions:

            * 'session._send_sack is True' iff bilateral negotiation
              succeeded (we advertised AND peer echoed).
            * 'session.state is FsmState.ESTABLISHED'.

        [FLAGS BUG] - 'TcpSession' has no '_send_sack' attribute
        today; '_tcp_fsm_syn_sent' has no SACK-Permitted gate. The
        phase-3 implementation must mirror the WSCALE pattern:
        after '_process_ack_packet' on peer's SYN+ACK, set
        'self._send_sack = self._advertise_sack and
        packet_rx_md.tcp__sackperm'. 'tcp__sackperm' must be
        plumbed through 'TcpMetadata' from the inbound parser path.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )
        self.assertTrue(
            session._send_sack,
            msg=(
                "After bilateral SACK-Permitted negotiation the session "
                "must record success in '_send_sack = True' so the FSM "
                "knows it may emit SACK options on subsequent outbound "
                "ACKs (RFC 2018 §3)."
            ),
        )

    def test__sack__out_of_order_data_segment_elicits_sack_block_in_outbound_ack(self) -> None:
        """
        Ensure that when a peer's data segment arrives out of order
        (gap before it), the resulting outbound dup-ACK carries a
        SACK option whose single block reports the buffered OOO
        range '[seq, seq + len(payload))' per RFC 2018 §4. Without
        this, the peer cannot distinguish "we never received that
        data" from "we received it, but a different segment was
        lost", and SACK-driven loss recovery cannot run.

        RFC 2018 §4 (Generating the SACK option):

            "If the data receiver decides to send a SACK option, ...
             the first SACK block (i.e., the one immediately
             following the kind and length fields in the option)
             MUST specify the contiguous block of data containing
             the segment which triggered this ACK, unless that
             segment advanced the Acknowledgment Number field in
             the header."

        Scenario:

            1. Drive an active-open handshake with bilateral SACK
               negotiation succeeded.
            2. Peer sends an OOO data segment - 100 bytes at
               'seq = PEER__ISS + 1 + 100' (skipping over 100 bytes
               of expected data; RCV.NXT is still 'PEER__ISS + 1').
            3. Inspect the inline TX. Exactly one outbound ACK
               must fire pointing at the missing RCV.NXT, AND the
               ACK must carry a SACK option with one block
               containing the OOO range.

        Assertions:

            * Inline TX list has exactly 1 frame.
            * The frame is an ACK with 'ack = PEER__ISS + 1' (gap
              cumulative ACK; RCV.NXT unchanged).
            * The ACK's 'sack_blocks' equals the single tuple
              '[(PEER__ISS + 1 + 100, PEER__ISS + 1 + 200)]'.

        [FLAGS BUG] - '_tcp_fsm_established' (line 1573) emits
        '_transmit_packet(flag_ack=True)' on the OOO branch with
        no SACK option plumbing. The phase-3 fix builds the SACK
        option block list from '_ooo_packet_queue' (each entry
        contributing one '(seq, seq + len(payload))' pair) and
        passes it to 'send_tcp_packet' / '_phtx_tcp', which
        encodes it as 'TcpOptionSack' alongside any other options.
        The emission is gated on 'self._send_sack' so peers that
        did not offer SACK do not receive one.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        # Sanity: bilateral negotiation must have succeeded so the
        # SACK-emit path is enabled.
        self.assertTrue(
            session._send_sack,
            msg="Setup precondition: bilateral SACK negotiation must have succeeded.",
        )

        ooo_seg = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 100,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X" * 100,
        )
        ooo_tx = self._drive_rx(frame=ooo_seg)
        self.assertEqual(
            len(ooo_tx),
            1,
            msg=("An OOO segment arriving above RCV.NXT must elicit " "exactly one outbound ACK pointing at the gap."),
        )
        ooo_ack = self._parse_tx(ooo_tx[0])
        self._assert_segment(
            ooo_ack,
            flags=frozenset({"ACK"}),
            ack=PEER__ISS + 1,
            sack_blocks=[(PEER__ISS + 1 + 100, PEER__ISS + 1 + 200)],
        )

    def test__sack__multiple_ooo_segments_yield_multiple_sack_blocks(self) -> None:
        """
        Ensure that when multiple OOO segments are buffered, the
        outbound SACK option carries one block per disjoint OOO
        range, up to RFC 2018 §3's maximum of 4 blocks per option.

        RFC 2018 §3 (Format):

            "If sent at all, a SACK option that specifies n blocks
             will have a length of 8*n+2 bytes, so the 40 bytes
             available for TCP options can specify a maximum of 4
             blocks."

        Scenario:

            1. Drive handshake with bilateral SACK.
            2. Peer sends OOO segment A at 'PEER__ISS + 1 + 100',
               100 bytes. SACK option on the dup-ACK reports
               '[seg_a_left, seg_a_right)'.
            3. Peer sends OOO segment B at 'PEER__ISS + 1 + 300'
               (disjoint; gap between them), 100 bytes. The dup-ACK
               on this arrival carries TWO SACK blocks: A and B
               (the first slot per RFC 2018 §4 is the segment
               triggering this ACK, so 'B' is first).

        Assertions:

            * The dup-ACK on B's arrival carries exactly 2 SACK
              blocks covering both OOO ranges.

        [FLAGS BUG] - the OOO emit path has no SACK plumbing
        (per the previous test). Once SACK is wired,
        '_build_sack_blocks' reads the full '_ooo_packet_queue' and
        emits up to 4 disjoint blocks. The phase-3 fix must
        iterate the queue (not just the most recent arrival) so
        prior OOO context survives the next dup-ACK.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )
        self.assertTrue(
            session._send_sack,
            msg="Setup precondition: bilateral SACK negotiation must have succeeded.",
        )

        # First OOO segment.
        seg_a = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 100,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"A" * 100,
        )
        self._drive_rx(frame=seg_a)

        # Second OOO segment (disjoint from the first).
        seg_b = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 300,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"B" * 100,
        )
        seg_b_tx = self._drive_rx(frame=seg_b)
        self.assertEqual(
            len(seg_b_tx),
            1,
            msg="A second OOO arrival must trigger exactly one dup-ACK with SACK info.",
        )
        seg_b_ack = self._parse_tx(seg_b_tx[0])
        self.assertEqual(
            sorted(seg_b_ack.sack_blocks),
            sorted(
                [
                    (PEER__ISS + 1 + 100, PEER__ISS + 1 + 200),
                    (PEER__ISS + 1 + 300, PEER__ISS + 1 + 400),
                ]
            ),
            msg=(
                "The dup-ACK on the second OOO arrival must carry "
                "two SACK blocks - one per buffered OOO range - so "
                "peer can plan retransmits for both gaps. RFC 2018 §3."
            ),
        )

    def test__sack__cumulative_ack_drains_ooo_queue_clears_sack_blocks(self) -> None:
        """
        Ensure that once the gap is filled and the OOO queue
        drains, subsequent outbound ACKs no longer carry SACK
        blocks - the data is now cumulatively ACKed and the
        scoreboard contribution is zero. This is the receiver-side
        SACK lifecycle: blocks appear when data arrives out of
        order, persist until the gap fills, then disappear.

        RFC 2018 §4 (Generating the SACK option):

            "The SACK option is advisory, in that, while it
             notifies the data sender that the data receiver has
             received the indicated segments, the data receiver is
             permitted to later discard data which have been
             reported in a SACK option. ... If the data receiver
             chooses to discard such data, ... the data receiver
             will reflect the lower right edge in subsequent SACK
             options sent by the data receiver."

        For PyTCP the simpler invariant: after cumulative ACK
        absorbs the OOO queue, no SACK option appears on later
        outbound ACKs because there are no buffered out-of-order
        ranges left.

        Scenario:

            1. Drive handshake with bilateral SACK.
            2. Peer sends OOO segment at 'PEER__ISS + 1 + 100',
               100 bytes. Dup-ACK with SACK fires.
            3. Peer sends gap-fill segment at 'PEER__ISS + 1',
               100 bytes. The session processes both segments
               (gap-fill + OOO drained) and fires a cumulative ACK.
            4. Inspect the cumulative ACK: no SACK option (queue
               is now empty).

        Assertions:

            * After gap fill, '_ooo_packet_queue' is empty.
            * The cumulative ACK carries no SACK blocks
              ('sack_blocks=[]').

        [FLAGS BUG] - the underlying SACK emission path does not
        yet exist. Once it does, the empty-queue case must
        gracefully omit the option - building an empty SACK option
        is illegal per RFC 2018 §3 (every option carries at least
        one block).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        # OOO segment lands first.
        ooo_seg = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 100,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X" * 100,
        )
        ooo_tx = self._drive_rx(frame=ooo_seg)

        # Sanity: the OOO arrival's dup-ACK MUST carry a SACK block
        # so the lifecycle "blocks present during gap" -> "blocks
        # cleared after fill" is fully exercised.
        self.assertEqual(
            len(ooo_tx),
            1,
            msg="Setup precondition: OOO arrival must elicit one dup-ACK.",
        )
        ooo_ack_probe = self._parse_tx(ooo_tx[0])
        self.assertEqual(
            ooo_ack_probe.sack_blocks,
            ((PEER__ISS + 1 + 100, PEER__ISS + 1 + 200),),
            msg=(
                "Setup precondition: the OOO dup-ACK must carry a SACK "
                "block reporting the buffered range so the post-fill "
                "clearing assertion below is meaningful."
            ),
        )

        # Gap-fill arrives.
        gap_fill = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"Y" * 100,
        )
        fill_tx = self._drive_rx(frame=gap_fill)

        self.assertEqual(
            session._ooo_packet_queue,
            {},
            msg=(
                "Gap-fill must drain the entire OOO queue: the cumulative "
                "ACK now covers everything that used to be buffered."
            ),
        )

        self.assertEqual(
            len(fill_tx),
            1,
            msg="The gap-fill arrival must produce exactly one cumulative ACK.",
        )
        fill_ack = self._parse_tx(fill_tx[0])
        self._assert_segment(
            fill_ack,
            flags=frozenset({"ACK"}),
            ack=PEER__ISS + 1 + 200,
            sack_blocks=[],
        )

    def test__sack__passive_open_mirrors_peer_sack_permitted_offer(self) -> None:
        """
        Ensure that when a peer's SYN to a listening socket carries
        SACK-Permitted, our SYN+ACK reply mirrors the offer back
        per RFC 2018 §2's bilateral negotiation. The passive-open
        SACK semantics match the WSCALE pattern: we echo only when
        peer offered, and we never echo on a SYN where peer was
        silent on SACK (next test).

        Scenario:

            1. Build a LISTEN-state session.
            2. Peer sends SYN with SACK-Permitted.
            3. Drive RX. Listening session transitions to SYN_RCVD;
               on the next tick the child session's SYN+ACK fires.
            4. Inspect the SYN+ACK: it MUST carry SACK-Permitted.

        Assertions:

            * The child session's SYN+ACK 'sackperm = True'.

        [FLAGS BUG] - '_tcp_fsm_listen' has no '_send_sack' /
        '_advertise_sack' / 'packet_rx_md.tcp__sackperm' wiring.
        The phase-3 fix mirrors the WSCALE pattern: after peer's
        SYN, set 'self._send_sack = self._advertise_sack and
        packet_rx_md.tcp__sackperm', and gate the SYN+ACK's
        SACK-Permitted emission on the same combined predicate.
        """

        listen_session = self._make_listen_session(iss=LOCAL__ISS)
        peer_syn = build_tcp4(
            sport=PEER__PASSIVE_PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            sackperm=True,
        )
        self._drive_rx(frame=peer_syn)
        self.assertIs(
            listen_session.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: listening session must mutate into SYN_RCVD on peer's SYN.",
        )
        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK must fire on the first tick after peer's SYN.",
        )
        syn_ack_probe = self._parse_tx(syn_ack_tx[0])
        self._assert_segment(
            syn_ack_probe,
            flags=frozenset({"SYN", "ACK"}),
            sackperm=True,
        )

    def test__sack__passive_open_omits_sack_when_peer_did_not_offer(self) -> None:
        """
        Ensure that when a peer's SYN does NOT carry SACK-Permitted,
        our SYN+ACK reply also omits it - the bilateral mirror rule
        forces the negotiation to fail closed. This is the
        regression-guard counterpart to the prior test.

        Scenario:

            1. Build a LISTEN-state session.
            2. Peer sends SYN with no SACK-Permitted.
            3. Drive RX. Listening session transitions to SYN_RCVD;
               on the next tick the child SYN+ACK fires.
            4. Inspect the SYN+ACK: SACK-Permitted MUST be absent.

        Assertions:

            * The child session's SYN+ACK 'sackperm = False'.

        Passes today as a positive control / regression guard for
        the bilateral mirror rule (peer didn't offer, we don't
        echo). A future SACK patch that wires up SACK-Permitted on
        outbound SYN+ACKs without gating on peer's offer would
        echo accidentally and be caught here. The '_send_sack
        is False' invariant is asserted by the bilateral-success
        test ('bilateral_sack_negotiation_sets_send_sack') in the
        positive direction; this regression-test only pins the
        wire shape.
        """

        listen_session = self._make_listen_session(iss=LOCAL__ISS)
        peer_syn = build_tcp4(
            sport=PEER__PASSIVE_PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            sackperm=False,
        )
        self._drive_rx(frame=peer_syn)
        self.assertIs(
            listen_session.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: listening session must mutate into SYN_RCVD on peer's SYN.",
        )
        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK must fire on the first tick after peer's SYN.",
        )
        syn_ack_probe = self._parse_tx(syn_ack_tx[0])
        self._assert_segment(
            syn_ack_probe,
            flags=frozenset({"SYN", "ACK"}),
            sackperm=False,
        )
