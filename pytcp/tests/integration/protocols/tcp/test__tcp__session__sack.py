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

pytcp/tests/integration/protocols/tcp/test__tcp__session__sack.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.tcp__loss_recovery import pipe
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

    def test__sack__inbound_sack_blocks_silently_consumed_when_send_sack_disabled(self) -> None:
        """
        Ensure that when the bilateral SACK negotiation has NOT
        succeeded ('_send_sack = False'), an inbound ACK carrying
        SACK blocks is silently consumed: the scoreboard is not
        updated, no scoreboard-driven TX fires, and the send-side
        counters do not move. Per RFC 2018 §3, SACK information is
        meaningful only when the option was offered bilaterally
        during connection establishment; outside that envelope the
        receiver SHOULD ignore inbound SACK info.

        The phase-1 'inbound_sack_option_does_not_crash_parser'
        test pinned the wire-level passthrough; this one pins the
        FSM-level no-effect when '_send_sack = False'. After phase
        4 wiring, '_sack_scoreboard' exists on every 'TcpSession'
        instance, so this test is now a regression guard for the
        ingestion gate.

        Scenario:

            1. Drive the active-open handshake WITHOUT bilateral
               SACK ('peer_sackperm=False' default), so
               'session._send_sack' ends up False.
            2. Application sends 200 bytes so we have outstanding
               unacked TX bytes the SACK option could reference.
            3. Drain the outbound data segment.
            4. Peer sends a dup-ACK carrying a SACK block claiming
               receipt of the upper half of our outstanding range.
            5. Inspect session state.

        Assertions:

            * 'session._send_sack is False'.
            * 'session._sack_scoreboard.blocks() == []' - the
              ingestion gate refused to update the scoreboard.
            * '_snd_una', '_snd_nxt', '_snd_max' unchanged.
            * No outbound TX (no fast retransmit, no anomalous
              reply).
            * 'session.state is FsmState.ESTABLISHED'.

        Passes today as a positive control / regression guard for
        the '_send_sack' ingestion gate after phase 4 lands. A
        future change that ingests SACK info unconditionally
        (regardless of bilateral negotiation outcome) would be
        caught by the empty-scoreboard assertion here.
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
            session._send_sack,
            msg=(
                "Setup precondition: bilateral SACK negotiation must "
                "have failed (peer didn't offer) so '_send_sack' is "
                "False - this test pins the ingestion-gate behaviour."
            ),
        )
        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [],
            msg=(
                "A fresh ESTABLISHED session must start with an empty "
                "SACK scoreboard - nothing has been peer-SACKed yet."
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
                "An inbound dup-ACK without bilateral SACK must not "
                "synthesise any reply; SACK info is informational and "
                "the count-based dup-ACK threshold has not been met."
            ),
        )
        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [],
            msg=(
                "With '_send_sack = False' the scoreboard MUST remain "
                "empty even when peer sends SACK blocks - the "
                "ingestion gate per RFC 2018 §3 refuses to record "
                "SACK info on a connection where bilateral "
                "negotiation failed."
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
                "dup-ACK below the count-based fast-retransmit "
                "threshold."
            ),
        )
        self.assertEqual(
            session._snd_max,
            snd_max_before,
            msg=(
                "SND.MAX must not be perturbed by a SACK-bearing "
                "dup-ACK; nothing on the SACK ingestion path "
                "extends the sent-bytes high-water mark."
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

    def test__sack__inbound_sack_block_updates_scoreboard(self) -> None:
        """
        Ensure that when bilateral SACK is enabled and peer sends
        an ACK carrying a SACK block describing receipt of bytes
        in our outstanding (unacked) range, the session ingests
        that block into '_sack_scoreboard' per RFC 2018 §3-§4.
        Without this, the scoreboard cannot inform RFC 6675's
        NextSeg / IsLost / Pipe machinery in phase 5.

        RFC 2018 §4 (Generating the SACK option):

            "Each contiguous block of data queued at the data
             receiver is defined in the SACK option by two 32-bit
             unsigned integers in network byte order: ... Left
             Edge of Block ... Right Edge of Block ... This is the
             sequence number immediately following the last
             sequence number of this block."

        Scenario:

            1. Drive an active-open handshake with bilateral SACK.
            2. Application sends 200 bytes so 'SND.UNA = ISS+1' and
               'SND.MAX = ISS+1+200'.
            3. Drain the outbound data segment.
            4. Peer sends a dup-ACK (cumulative ack unchanged at
               'ISS+1') carrying a SACK block
               '[ISS+1+100, ISS+1+200)' reporting receipt of the
               upper half of our outstanding bytes.
            5. Inspect 'session._sack_scoreboard.blocks()'.

        Assertions:

            * '_sack_scoreboard.blocks() == [(ISS+1+100, ISS+1+200)]'
              after the SACK-bearing dup-ACK is processed.
            * '_send_sack is True' (precondition).

        [FLAGS BUG] - 'TcpSession' has no '_sack_scoreboard'
        attribute today (it's introduced in phase 4) and
        '_process_ack_packet' has no SACK-block ingestion path.
        The fix wires the ingestion: 'TcpMetadata' grows
        'tcp__sack_blocks' populated from
        'packet_rx.tcp._options.sack' in
        'packet_handler__tcp__rx.py'; '_process_ack_packet' / the
        dup-ACK '_retransmit_packet_request' branch loops over the
        blocks and calls 'self._sack_scoreboard.add_block(left,
        right)' for each block whose edges fall inside
        '[SND.UNA, SND.MAX]' (RFC 2018 §5: be liberal in what we
        accept; out-of-window blocks are dropped).
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

        # Bypass slow-start so the application's send drains in
        # one outbound segment.
        session._snd_ewn = PEER__WIN
        session.send(data=b"X" * 200)
        self._advance(ms=1)

        sacked_left = LOCAL__ISS + 1 + 100
        sacked_right = LOCAL__ISS + 1 + 200
        peer_dup_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(sacked_left, sacked_right)],
        )
        self._drive_rx(frame=peer_dup_ack)

        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [(sacked_left, sacked_right)],
            msg=(
                "An inbound SACK block describing in-window bytes "
                "must be ingested into the scoreboard so RFC 6675's "
                "NextSeg / IsLost / Pipe wrappers (phase 5) can "
                "consult it."
            ),
        )

    def test__sack__cumulative_ack_prunes_scoreboard_below_snd_una(self) -> None:
        """
        Ensure that when peer's cumulative ACK advances 'SND.UNA'
        past a SACK-recorded range, the corresponding block is
        pruned from the scoreboard. The scoreboard's contract
        per RFC 6675 §3 is that it tracks bytes we sent that are
        unacked-but-sacked; once cumulatively-acked, those bytes
        are no longer in flight and the scoreboard entry is dead.

        Scenario:

            1. Drive an active-open handshake with bilateral SACK.
            2. Application sends 200 bytes.
            3. Drain the outbound data segment.
            4. Peer sends a dup-ACK with SACK block
               '[ISS+1+100, ISS+1+200)' - scoreboard ingests it.
            5. Peer sends a normal ACK with cumulative ack
               'ISS+1+200' (advancing SND.UNA past the entire
               sacked range).
            6. Inspect '_sack_scoreboard.blocks()' - empty.

        Assertions:

            * After the cumulative ACK, '_snd_una' has advanced
              to 'ISS+1+200'.
            * '_sack_scoreboard.blocks() == []' - prune_below has
              dropped the now-redundant entry.

        [FLAGS BUG] - both '_sack_scoreboard' and the
        prune-on-cumulative-ack path are introduced in phase 4.
        The fix wires 'prune_below(self._snd_una)' inside
        '_process_ack_packet' immediately after the SND.UNA
        update so blocks below the new cumulative-ack high-water
        mark are dropped before subsequent block ingestion.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._snd_ewn = PEER__WIN
        session.send(data=b"X" * 200)
        self._advance(ms=1)

        # First ACK ingests a SACK block.
        sacked_left = LOCAL__ISS + 1 + 100
        sacked_right = LOCAL__ISS + 1 + 200
        first_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(sacked_left, sacked_right)],
        )
        self._drive_rx(frame=first_ack)
        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [(sacked_left, sacked_right)],
            msg="Setup precondition: scoreboard must hold the SACK block before the cum-ACK advance.",
        )

        # Second ACK: cumulative-ack advances past the sacked range.
        second_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 200,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=second_ack)

        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1 + 200,
            msg="Setup precondition: cumulative-ACK must advance SND.UNA past the sacked range.",
        )
        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [],
            msg=(
                "The scoreboard MUST be pruned once the cumulative ACK "
                "absorbs the sacked range - 'prune_below(SND.UNA)' "
                "drops blocks whose right edge lies at or below the "
                "new SND.UNA per RFC 6675 §3 / RFC 2018 §3."
            ),
        )

    def test__sack__out_of_window_sack_block_silently_dropped(self) -> None:
        """
        Ensure that an inbound SACK block whose edges fall outside
        '[SND.UNA, SND.MAX]' is silently dropped. Such a block
        cannot describe legitimate in-flight bytes - the receiver
        cannot have SACKed bytes we never sent. RFC 2018 §5
        ("being liberal in what we accept") permits silently
        ignoring it without dropping the segment.

        Scenario:

            1. Drive handshake with bilateral SACK.
            2. Send 200 bytes so 'SND.MAX = ISS+1+200'.
            3. Drain.
            4. Peer sends an ACK with SACK block
               '[ISS+1+1000, ISS+1+1100)' - well past 'SND.MAX'.
            5. Inspect '_sack_scoreboard.blocks()' - empty.

        Assertions:

            * '_sack_scoreboard.blocks() == []' - the out-of-
              window block was filtered out and never reached
              the scoreboard.

        [FLAGS BUG] - the scoreboard does not yet exist (phase 4).
        After the implementation lands the ingestion path must
        gate every block on
        'le32(SND.UNA, left) AND le32(right, SND.MAX) AND
        lt32(left, right)'; blocks failing the gate are silently
        dropped.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._snd_ewn = PEER__WIN
        session.send(data=b"X" * 200)
        self._advance(ms=1)

        out_of_window_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(LOCAL__ISS + 1 + 1000, LOCAL__ISS + 1 + 1100)],
        )
        self._drive_rx(frame=out_of_window_ack)

        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [],
            msg=(
                "A SACK block whose edges fall outside "
                "'[SND.UNA, SND.MAX]' MUST be silently dropped - the "
                "block cannot describe legitimate in-flight bytes "
                "(RFC 2018 §5). The scoreboard must remain empty."
            ),
        )

    def test__sack__three_dup_sacks_above_gap_trigger_fast_retransmit(self) -> None:
        """
        Ensure that three SACK-bearing dup-ACKs above the gap at
        SND.UNA accumulate in the scoreboard as three distinct
        blocks AND trigger fast retransmit. RFC 6675 §3's
        scoreboard-driven IsLost predicate fires when three
        discontiguous SACKed ranges sit above an unsacked seq;
        the count-based RFC 5681 §3.2 path also fires after the
        third dup-ACK. The test pins both invariants: scoreboard
        ingestion of three blocks, and outbound fast-retransmit
        of the gap segment.

        Scenario:

            1. Drive an active-open handshake with bilateral SACK.
            2. Application sends 4*MSS bytes so 'SND.UNA = ISS+1'
               and 'SND.MAX = ISS+1+4*MSS'.
            3. Drain the outbound data segment.
            4. Peer sends three SACK-bearing dup-ACKs in
               succession, each reporting one new disjoint range
               above the gap:
                 dup #1: SACK [ISS+1+1*MSS, ISS+1+2*MSS)
                 dup #2: SACK [ISS+1+2*MSS, ISS+1+3*MSS)  *
                 dup #3: SACK [ISS+1+3*MSS, ISS+1+4*MSS)  *
               (* Note: these are adjacent and would coalesce in
               our scoreboard; to keep three distinct blocks we
               leave 1-byte gaps between them.)
            5. Fast retransmit fires on the third dup-ACK and
               emits one outbound segment starting at SND.UNA
               (the gap).

        Assertions:

            * After all three dup-ACKs: scoreboard holds three
              distinct blocks.
            * One outbound segment fires on the third dup-ACK.
            * The retransmitted seq equals 'SND.UNA' (= the gap),
              matching both the count-based fall-back and the
              SACK-driven NextSeg in this single-gap scenario.

        Passes today as a positive control / regression guard for
        the SACK-aware dup-ACK ingestion path. The phase-5
        wiring of NextSeg means the retransmit's seq comes from
        'next_seg(...)' when bilateral SACK is enabled (and
        falls back to '_snd_una' otherwise); in single-gap
        scenarios both produce the same value.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._snd_ewn = PEER__WIN
        mss = session._snd_mss
        session.send(data=b"X" * (4 * mss))
        # '_transmit_data' sends one MSS-sized segment per timer
        # tick; advance enough ticks so all 4 outstanding
        # segments fire and SND.MAX = LOCAL__ISS + 1 + 4*MSS.
        # The post-handshake retransmit-timer cadence puts each
        # tick safely under PACKET_RETRANSMIT_TIMEOUT.
        for _ in range(4):
            self._advance(ms=1)
        self.assertEqual(
            session._snd_max,
            LOCAL__ISS + 1 + 4 * mss,
            msg="Setup precondition: all 4 MSS-sized segments must drain before the dup-ACK matrix runs.",
        )

        # Three SACK-bearing dup-ACKs, each adding one new block.
        # 1-byte gaps between the blocks prevent coalescing in
        # the scoreboard so the IsLost count rule sees three
        # distinct entries.
        block_1 = (LOCAL__ISS + 1 + 1 * mss, LOCAL__ISS + 1 + 1 * mss + 100)
        block_2 = (LOCAL__ISS + 1 + 2 * mss, LOCAL__ISS + 1 + 2 * mss + 100)
        block_3 = (LOCAL__ISS + 1 + 3 * mss, LOCAL__ISS + 1 + 3 * mss + 100)

        for blk in (block_1, block_2, block_3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
                sack_blocks=[blk],
            )
            self._drive_rx(frame=dup_ack)

        # After all three dup-ACKs the scoreboard holds three
        # distinct blocks (insertion order preserved by
        # 'SackScoreboard.blocks()').
        self.assertEqual(
            sorted(session._sack_scoreboard.blocks()),
            sorted([block_1, block_2, block_3]),
            msg=(
                "Three SACK-bearing dup-ACKs MUST accumulate three "
                "distinct blocks in the scoreboard - one ingestion "
                "per dup-ACK."
            ),
        )

        # The third dup-ACK sets '_snd_nxt' back to the gap;
        # the actual retransmit fires on the next timer tick
        # via '_transmit_data'. Advance one tick and capture
        # the resulting outbound segment.
        retransmit_tx = self._advance(ms=1)
        self.assertEqual(
            len(retransmit_tx),
            1,
            msg=(
                "The third dup-ACK MUST elicit exactly one outbound "
                "fast-retransmit segment on the next timer tick per "
                "RFC 5681 §3.2."
            ),
        )
        retransmit_probe = self._parse_tx(retransmit_tx[0])
        self._assert_segment(
            retransmit_probe,
            flags=frozenset({"ACK"}),
            seq=LOCAL__ISS + 1,
            payload=b"X" * mss,
        )

    def test__sack__pipe_excludes_sacked_bytes_from_in_flight_estimate(self) -> None:
        """
        Ensure that 'pipe()' applied to the session's
        '_sack_scoreboard' excludes peer-SACKed bytes from the
        in-flight estimate per RFC 6675 §4. The phase-5 helper
        is intended to bound the sender's effective window
        during recovery so dup-ACK-driven cwnd inflation does
        not over-commit; this test pins the integration of the
        helper against the live session scoreboard.

        Scenario:

            1. Drive handshake with bilateral SACK.
            2. Send 4*MSS bytes, drain.
            3. Peer SACKs the upper 2*MSS bytes (one block).
            4. Compute 'pipe(scoreboard, snd_una, snd_max)'.
            5. Verify the result equals
               '(SND.MAX - SND.UNA) - 2*MSS = 2*MSS' - the lower
               half remains in-flight, the upper half does not.

        Assertions:

            * 'pipe(scoreboard, snd_una, snd_max) == 2*mss'.
            * The session's '_sack_scoreboard' contains the
              SACKed range (sanity check on ingestion path).

        Passes today as a positive control / regression guard for
        the helper-against-live-session integration. The pipe()
        return value is not yet consumed by '_snd_ewn' bounding;
        a future phase will wire that.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._snd_ewn = PEER__WIN
        mss = session._snd_mss
        session.send(data=b"X" * (4 * mss))
        for _ in range(4):
            self._advance(ms=1)

        # Peer SACKs the upper 2*MSS bytes (one contiguous block).
        sacked_left = LOCAL__ISS + 1 + 2 * mss
        sacked_right = LOCAL__ISS + 1 + 4 * mss
        sack_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(sacked_left, sacked_right)],
        )
        self._drive_rx(frame=sack_ack)

        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [(sacked_left, sacked_right)],
            msg="Setup precondition: scoreboard must hold the SACKed range.",
        )

        in_flight = pipe(
            scoreboard=session._sack_scoreboard,
            snd_una=session._snd_una,
            snd_max=session._snd_max,
        )
        self.assertEqual(
            in_flight,
            2 * mss,
            msg=(
                "Pipe must subtract the 2*MSS SACKed bytes from "
                "the 4*MSS in-flight range, returning 2*MSS bytes "
                "still considered in flight."
            ),
        )

    def test__sack__byte_rule_triggers_fast_retransmit_on_first_dup_sack(self) -> None:
        """
        Ensure that the RFC 6675 §3 IsLost byte-rule fires fast
        retransmit on the FIRST SACK-bearing dup-ACK when peer
        reports MORE THAN '(dup_thresh - 1) * SMSS' bytes
        SACKed above SND.UNA. This is the SACK-aware shortcut
        around RFC 5681 §3.2's count-based threshold: with rich
        SACK info, the receiver-evidence is already strong
        enough to declare loss after one dup-ACK, recovering
        faster on bursty / contiguous-loss patterns.

        RFC 6675 §3 (IsLost):

            "This routine returns whether the given sequence
             number is considered to be lost. ... The routine
             returns true when either DupThresh discontiguous
             SACKed sequences have arrived above 'SeqNum' or
             more than (DupThresh - 1) * SMSS bytes with
             sequence numbers greater than 'SeqNum' have been
             SACKed."

        Scenario:

            1. Drive an active-open handshake with bilateral
               SACK negotiation.
            2. Application sends 4*MSS bytes; drain so SND.MAX =
               LOCAL__ISS + 1 + 4*MSS.
            3. Peer sends ONE SACK-bearing dup-ACK reporting a
               single contiguous SACK block of '2*MSS + 1'
               bytes - just over the byte-rule threshold of
               '(3-1)*MSS = 2*MSS'.
            4. The byte-rule fires; '_recovery_point' is set;
               '_snd_nxt' rewinds to SND.UNA via NextSeg.
            5. Next timer tick: one outbound retransmit fires
               at SEQ=SND.UNA.
            6. A SECOND dup-ACK with the same SACK info MUST
               NOT re-fire the retransmit (one-shot per loss
               event guarded by '_recovery_point').

        Assertions:

            * '_recovery_point' is non-zero after the 1st
              dup-SACK (we entered recovery via byte rule).
            * Exactly one outbound retransmit segment fires on
              the next tick.
            * Retransmit's SEQ equals SND.UNA, payload is the
              first MSS bytes of our outstanding data.
            * A 2nd dup-SACK followed by a tick produces no
              additional retransmit.

        Passes today as a positive control / regression guard
        for the byte-rule trigger and the '_recovery_point'
        one-shot. Without phase 5b's IsLost branch, the
        sender would wait for the 3rd dup-ACK before firing -
        a measurable latency penalty on contiguous-loss
        patterns where peer can pack many sacked bytes into
        one block.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._snd_ewn = PEER__WIN
        mss = session._snd_mss
        session.send(data=b"X" * (4 * mss))
        for _ in range(4):
            self._advance(ms=1)
        self.assertEqual(
            session._snd_max,
            LOCAL__ISS + 1 + 4 * mss,
            msg="Setup precondition: all 4 MSS-sized segments must drain.",
        )

        # Single SACK block carrying '2*MSS + 1' bytes - just
        # over the byte-rule threshold.
        sacked_left = LOCAL__ISS + 1 + mss
        sacked_right = sacked_left + 2 * mss + 1
        self.assertLessEqual(
            sacked_right,
            LOCAL__ISS + 1 + 4 * mss,
            msg="Setup precondition: the test SACK block must lie within [SND.UNA, SND.MAX].",
        )
        first_dup_sack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(sacked_left, sacked_right)],
        )
        self._drive_rx(frame=first_dup_sack)

        # Byte-rule fired; we entered recovery.
        self.assertNotEqual(
            session._recovery_point,
            0,
            msg=(
                "The IsLost byte-rule MUST fire fast retransmit on "
                "the first dup-SACK when peer reports > 2*MSS "
                "bytes SACKed above SND.UNA - '_recovery_point' "
                "must be non-zero (RFC 6675 §3, RFC 5681 §3.2)."
            ),
        )

        # Next tick fires the retransmit at SND.UNA (the gap
        # in this single-gap scenario; NextSeg returns SND.UNA).
        retransmit_tx = self._advance(ms=1)
        self.assertEqual(
            len(retransmit_tx),
            1,
            msg="Setup expectation: exactly one outbound retransmit on the next tick after byte-rule trigger.",
        )
        retransmit_probe = self._parse_tx(retransmit_tx[0])
        self._assert_segment(
            retransmit_probe,
            flags=frozenset({"ACK"}),
            seq=LOCAL__ISS + 1,
            payload=b"X" * mss,
        )

        # A second dup-SACK during recovery MUST NOT re-enter
        # recovery. The '_recovery_point' guard suppresses the
        # re-trigger; '_recovery_point' must remain at the same
        # non-zero value from the original entry. (Subsequent
        # outbound data may still flow through '_transmit_data'
        # past SND.NXT - that is normal sliding-window
        # operation, not a re-fire of the retransmit.)
        recovery_point_after_first = session._recovery_point
        second_dup_sack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(sacked_left, sacked_right)],
        )
        self._drive_rx(frame=second_dup_sack)
        self.assertEqual(
            session._recovery_point,
            recovery_point_after_first,
            msg=(
                "A second dup-SACK during recovery MUST NOT re-enter "
                "recovery - '_recovery_point' stays unchanged at the "
                "original SND.MAX marker (RFC 5681 §3.2 step 4 / "
                "RFC 6675 §5 one-shot)."
            ),
        )

    def test__sack__recovery_skips_already_sacked_bytes(self) -> None:
        """
        Ensure that during fast-retransmit recovery the sender
        skips over peer-SACKed ranges in 'SND.NXT' so subsequent
        outbound segments do not redundantly retransmit bytes
        peer already received. RFC 6675 §5 multi-gap recovery:
        the scoreboard tells the sender what NOT to resend, and
        '_transmit_data' consults it before each transmission
        during recovery.

        Scenario:

            1. Drive an active-open handshake with bilateral
               SACK negotiation.
            2. Application sends 4*MSS bytes (segments 1, 2, 3,
               4); drain so SND.MAX = LOCAL__ISS + 1 + 4*MSS.
            3. Peer sends three dup-ACKs each reporting the
               same SACK block covering segments 2 and 3
               '[LOCAL__ISS + 1 + MSS, LOCAL__ISS + 1 + 3*MSS)'.
               Segments 1 and 4 are presumed lost / out-of-
               order.
            4. The third dup-ACK triggers fast retransmit
               (count rule). '_snd_nxt' rewinds to SND.UNA.
            5. Tick #1: outbound retransmit at SEQ = SND.UNA
               (segment 1, the first gap).
            6. After segment 1 is sent, SND.NXT = SND.UNA + MSS
               which sits inside the SACKed block. On tick #2,
               '_advance_snd_nxt_past_sacked' jumps SND.NXT to
               the right edge of the SACKed block (= SND.UNA +
               3*MSS = segment 4's start).
            7. Tick #2 outbound: SEQ = SND.UNA + 3*MSS
               (segment 4), NOT SND.UNA + MSS (segment 2).

        Assertions:

            * After 3 dup-ACKs: '_recovery_point' is non-zero.
            * Tick #1 retransmit has SEQ = SND.UNA.
            * Tick #2 retransmit has SEQ = SND.UNA + 3*MSS
              (the segment-4 boundary), demonstrating the
              skip past sacked segments 2 and 3.

        Passes today as a positive control / regression guard
        for the recovery-side SACK-skip logic. Without the
        skip, tick #2 would resend segment 2 - bandwidth wasted
        on bytes peer already SACKed.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._snd_ewn = PEER__WIN
        mss = session._snd_mss
        session.send(data=b"X" * (4 * mss))
        for _ in range(4):
            self._advance(ms=1)
        self.assertEqual(
            session._snd_max,
            LOCAL__ISS + 1 + 4 * mss,
            msg="Setup precondition: all 4 MSS-sized segments must drain.",
        )

        # Three dup-ACKs each reporting the same SACK block
        # covering segments 2 and 3 (= [SND.UNA+MSS, SND.UNA+3*MSS)).
        # Single-block ingestion coalesces (idempotent) so the
        # scoreboard ends with one entry, but the count-rule
        # fires on the 3rd dup-ACK.
        sacked_left = LOCAL__ISS + 1 + 1 * mss
        sacked_right = LOCAL__ISS + 1 + 3 * mss
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
                sack_blocks=[(sacked_left, sacked_right)],
            )
            self._drive_rx(frame=dup_ack)

        self.assertNotEqual(
            session._recovery_point,
            0,
            msg="Setup precondition: 3 dup-ACKs must enter recovery via count rule.",
        )

        # Tick #1: retransmit segment 1 (= the gap at SND.UNA).
        retransmit_1_tx = self._advance(ms=1)
        self.assertEqual(
            len(retransmit_1_tx),
            1,
            msg="Tick #1 must produce exactly one retransmit at the SND.UNA gap.",
        )
        retransmit_1_probe = self._parse_tx(retransmit_1_tx[0])
        self._assert_segment(
            retransmit_1_probe,
            flags=frozenset({"ACK"}),
            seq=LOCAL__ISS + 1,
            payload=b"X" * mss,
        )

        # Tick #2: '_advance_snd_nxt_past_sacked' jumps SND.NXT
        # past the SACKed block (segments 2 and 3) so the next
        # outbound segment carries SEQ = SND.UNA + 3*MSS, NOT
        # SND.UNA + MSS (which would re-send bytes peer already
        # has).
        retransmit_2_tx = self._advance(ms=1)
        self.assertEqual(
            len(retransmit_2_tx),
            1,
            msg="Tick #2 must produce one segment - past the SACKed range.",
        )
        retransmit_2_probe = self._parse_tx(retransmit_2_tx[0])
        self._assert_segment(
            retransmit_2_probe,
            flags=frozenset({"ACK", "PSH"}),
            seq=LOCAL__ISS + 1 + 3 * mss,
            payload=b"X" * mss,
        )

    def test__sack__dsack__fully_duplicate_segment_elicits_dsack_in_outbound_ack(self) -> None:
        """
        Ensure that when peer retransmits a segment whose entire
        payload range we have already received and cumulatively
        acknowledged, the next outbound ACK carries a DSACK
        report per RFC 2883 §4 - the duplicated range is encoded
        as the FIRST SACK block.

        RFC 2883 §4 (Reporting Full Duplicate Segments):

            "If the data receiver receives a duplicate of a
             previously received segment, it MUST ... send a
             D-SACK option in the next acknowledgement. The
             D-SACK block is the first SACK block in the
             SACK option."

        Scenario:

            1. Drive an active-open handshake with bilateral
               SACK negotiation.
            2. Peer sends segment 1 (50 bytes) - we deliver and
               eventually acknowledge.
            3. Drain the delayed-ACK so RCV.NXT is settled at
               'PEER__ISS + 1 + 50' from peer's view.
            4. Peer re-sends the SAME segment (= fully
               duplicate retransmit). Inline drive: one
               outbound ACK with a SACK option whose FIRST
               block reports the duplicate range.

        Assertions:

            * Exactly one inline outbound ACK fires on the
              duplicate-segment arrival.
            * The ACK's SACK option contains exactly one block
              equal to '(PEER__ISS + 1, PEER__ISS + 1 + 50)' -
              the DSACK report of the duplicated range.
            * Session state remains ESTABLISHED.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        # Peer sends segment 1 (50 bytes).
        payload = b"abcdefghij" * 5  # 50 bytes
        seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=payload,
        )
        self._drive_rx(frame=seg1)
        # Drain the delayed-ACK so the receive state settles
        # before we test the duplicate path. (The delayed-ACK
        # interval is 100ms by default; advance well past it.)
        self._advance(ms=200)

        rx_buffer_before = bytes(session._rx_buffer)
        rcv_nxt_before = session._rcv_nxt

        # Peer re-sends segment 1 - fully duplicate.
        seg1_dup = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=payload,
        )
        dup_tx = self._drive_rx(frame=seg1_dup)

        self.assertEqual(
            len(dup_tx),
            1,
            msg=(
                "A fully-duplicate inbound segment MUST elicit "
                "exactly one outbound ACK so peer's retransmit "
                "machinery sees fresh activity (RFC 2883 §4)."
            ),
        )
        dup_ack_probe = self._parse_tx(dup_tx[0])
        self._assert_segment(
            dup_ack_probe,
            flags=frozenset({"ACK"}),
            ack=rcv_nxt_before,
            sack_blocks=[(PEER__ISS + 1, PEER__ISS + 1 + 50)],
        )
        # Sanity: rx_buffer is unchanged - the duplicate brought
        # no new bytes and the FSM did not double-deliver.
        self.assertEqual(
            bytes(session._rx_buffer),
            rx_buffer_before,
            msg="A fully-duplicate segment must NOT re-enqueue bytes into '_rx_buffer'.",
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Duplicate-segment receipt must not perturb the FSM state.",
        )

    def test__sack__dsack__inbound_dsack_below_snd_una_detected_and_not_ingested(self) -> None:
        """
        Ensure that when peer sends an ACK whose SACK option's
        first block reports a range entirely below SND.UNA, the
        sender recognises the DSACK signature (RFC 2883 §4),
        increments '_dsack_received', and does NOT add the
        DSACK range to the loss-recovery scoreboard.

        RFC 2883 §4 (Recognising D-SACK signatures):

            "First, the data sender determines whether or not
             the SACK information includes a D-SACK option ...
             If the SACK option contains an SACK block ...
             where the right edge of that block ... is less
             than or equal to the cumulative acknowledgement
             ... then that information represents a duplicate
             segment received by the data receiver."

        Scenario:

            1. Drive handshake with bilateral SACK; pre-set
               '_snd_ewn = PEER__WIN' and send 2*MSS bytes;
               drain so SND.MAX = LOCAL__ISS + 1 + 2*MSS.
            2. Peer sends an ACK whose cumulative-ACK advances
               SND.UNA to 'LOCAL__ISS + 1 + 2*MSS' AND whose
               SACK option carries one block
               '[LOCAL__ISS + 1, LOCAL__ISS + 1 + 100)' - a
               range entirely below the new SND.UNA, signalling
               peer received those bytes twice.

        Assertions:

            * After the ACK: 'session._dsack_received == 1'.
            * 'session._sack_scoreboard.blocks() == []' - the
              DSACK block was NOT ingested into the scoreboard
              (it would never produce useful in-flight info
              since it is below SND.UNA).
            * 'session._snd_una == LOCAL__ISS + 1 + 2 * mss'
              - the cumulative ACK still advanced normally.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._snd_ewn = PEER__WIN
        mss = session._snd_mss
        session.send(data=b"X" * (2 * mss))
        for _ in range(2):
            self._advance(ms=1)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 2 * mss,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(LOCAL__ISS + 1, LOCAL__ISS + 1 + 100)],
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._dsack_received,
            1,
            msg=(
                "An inbound SACK option whose first block lies "
                "entirely below SND.UNA MUST be recognised as a "
                "DSACK report and increment '_dsack_received'."
            ),
        )
        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [],
            msg=(
                "A DSACK block describes already-acknowledged "
                "bytes; it MUST NOT be added to the in-flight "
                "scoreboard."
            ),
        )
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1 + 2 * mss,
            msg="Cumulative-ACK advancement must proceed normally despite the DSACK report.",
        )

    def test__sack__dsack__inbound_dsack_contained_in_outer_block_detected(self) -> None:
        """
        Ensure that the second DSACK signature per RFC 2883 §4
        is recognised: when the first SACK block lies entirely
        within a subsequent SACK block in the same option, the
        first block is a DSACK marker (peer received those bytes
        twice and is reporting the duplicate alongside the
        normal SACK info).

        RFC 2883 §4 (Recognising D-SACK signatures):

            "If the SACK option contains an SACK block ... that
             reports duplicate contiguous sequence space inside
             a SACK block ... then ... that information
             represents a duplicate segment."

        Scenario:

            1. Drive handshake with bilateral SACK; send 4*MSS,
               drain so SND.MAX = LOCAL__ISS + 1 + 4*MSS.
            2. Peer sends an ACK with TWO SACK blocks:
                  block 1 (DSACK):  [LOCAL__ISS + 1 + MSS,
                                     LOCAL__ISS + 1 + MSS + 100)
                  block 2 (outer): [LOCAL__ISS + 1 + MSS,
                                     LOCAL__ISS + 1 + 3*MSS)
               Block 1 is entirely contained within block 2.
            3. The sender recognises block 1 as DSACK
               (contained-in-outer) and ingests only block 2
               into the scoreboard.

        Assertions:

            * 'session._dsack_received == 1'.
            * Scoreboard contains only the outer block (block 2).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        session._snd_ewn = PEER__WIN
        mss = session._snd_mss
        session.send(data=b"X" * (4 * mss))
        for _ in range(4):
            self._advance(ms=1)

        outer_left = LOCAL__ISS + 1 + mss
        outer_right = LOCAL__ISS + 1 + 3 * mss
        dsack_inner_left = outer_left
        dsack_inner_right = outer_left + 100
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[
                (dsack_inner_left, dsack_inner_right),  # DSACK marker
                (outer_left, outer_right),  # outer covers it
            ],
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._dsack_received,
            1,
            msg=(
                "An inbound SACK option whose first block lies "
                "entirely within a subsequent block MUST be "
                "recognised as a DSACK report (RFC 2883 §4 "
                "second signature)."
            ),
        )
        self.assertEqual(
            session._sack_scoreboard.blocks(),
            [(outer_left, outer_right)],
            msg=(
                "The outer SACK block must be ingested into the "
                "scoreboard normally; only the contained DSACK "
                "marker is excluded."
            ),
        )

    def test__sack__dsack__case_2__full_duplicate_of_ooo_queued_segment_elicits_dsack(self) -> None:
        """
        Ensure that when peer retransmits an OOO segment whose
        range exactly matches an entry already buffered in our
        OOO queue, the next outbound ACK carries a DSACK report
        per RFC 2883 §4 case 2 - the duplicated range is encoded
        as the FIRST SACK block, followed by the regular SACK
        block(s) describing the OOO queue. The DSACK block being
        contained inside (or equal to) one of the regular blocks
        is the wire signature that distinguishes RFC 2883 case 2
        from a plain RFC 2018 SACK option.

        RFC 2883 §3 (Reporting Duplicate Segments):

            "Each duplicate contiguous sequence of data received
             is reported in at most one D-SACK block in the SACK
             option of an acknowledgement. ... [The data
             receiver] uses the first SACK block to specify the
             sequence numbers of the duplicate segment received."

        RFC 2883 §4 case 2:

            "[T]he D-SACK block is followed by an additional
             SACK block. ... the first block of a SACK option
             is contained within the second SACK block."

        Why case 2 matters: a peer that triggers a spurious RTO
        retransmit while a cum-ACK gap is still open will hit
        this path (the duplicated bytes are still OOO from our
        side, since the gap below them has not been filled).
        Case 2 is the more common spurious-retransmit signal in
        practice; case 1 only fires when peer retransmits past
        bytes we already cumulatively ACKed. Without case 2
        generation the peer's Eifel / RFC 3522 spurious-
        retransmit detector cannot fire, leaving cwnd halved
        unnecessarily.

        Scenario:

            1. Drive an active-open handshake with bilateral
               SACK negotiation succeeded.
            2. Peer sends OOO segment 1 (100 bytes at
               'seq = PEER__ISS + 1 + 100', leaving a 100-byte
               gap before RCV.NXT). One outbound dup-ACK with a
               single SACK block describes the OOO range.
            3. Peer re-sends the SAME OOO segment 1 (full
               duplicate of OOO-queued bytes - same seq, same
               len). Our OOO queue overwrites the existing
               entry with the new (identical) record; one
               outbound ACK fires with a SACK option that has
               TWO blocks - DSACK [seq, seq + 100] FIRST,
               regular OOO [seq, seq + 100] SECOND. Case 2
               signature satisfied: block 0 contained in (in
               this case equal to, which counts) block 1.

        Assertions:

            * Exactly one inline outbound ACK on the duplicate
              OOO arrival.
            * 'ack = PEER__ISS + 1' (gap cum-ACK unchanged).
            * 'sack_blocks' equals
              '[(PEER__ISS + 1 + 100, PEER__ISS + 1 + 200),
                (PEER__ISS + 1 + 100, PEER__ISS + 1 + 200)]'
              - DSACK first, regular block second.
            * Session state remains ESTABLISHED.

        [FLAGS BUG] - The OOO ingestion path in
        '_tcp_fsm_established' (line ~2096-2107) stores
        'self._ooo_packet_queue[packet_rx_md.tcp__seq] =
        packet_rx_md' without checking whether the new
        segment's byte range overlaps any existing OOO entry.
        Today the duplicate is silently overwritten and the
        outbound ACK has only the regular SACK block, no DSACK
        signal. Per RFC 2883 §3 this duplicate event SHOULD be
        reported.

        Fix outline (separate commit):

            Compute the overlap of the inbound segment's
            'tcp__seq' / 'seg_end' against every existing entry
            in 'self._ooo_packet_queue'. If any overlap is non-
            empty, set 'self._pending_dsack' to the union of
            overlap ranges (in the canonical case-2 case the
            first overlap suffices because subsequent blocks
            extend the signature, but the conservative impl
            takes the merged extent across all overlapping
            entries). The existing '_build_sack_blocks' helper
            already emits '_pending_dsack' as block 0; no other
            code change is required.

        Severity: MEDIUM - real interop polish that improves
        the peer's ability to detect spurious retransmits.
        Without it, we fail to advertise duplicate-OOO events
        per RFC 2883 §3 and the peer's congestion response to
        a spurious RTO stays pessimistic for an extra RTT.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
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
        first_tx = self._drive_rx(frame=ooo_seg)
        self.assertEqual(
            len(first_tx),
            1,
            msg="Setup precondition: first OOO segment elicits exactly one dup-ACK.",
        )

        # Peer retransmits the EXACT same OOO segment.
        ooo_seg_dup = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 100,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X" * 100,
        )
        dup_tx = self._drive_rx(frame=ooo_seg_dup)

        self.assertEqual(
            len(dup_tx),
            1,
            msg=(
                "A retransmit of an OOO-queued segment MUST "
                "elicit exactly one outbound ACK so peer's "
                "retransmit machinery sees fresh activity "
                "(RFC 2883 §3)."
            ),
        )
        dup_ack_probe = self._parse_tx(dup_tx[0])
        self._assert_segment(
            dup_ack_probe,
            flags=frozenset({"ACK"}),
            ack=PEER__ISS + 1,
            sack_blocks=[
                (PEER__ISS + 1 + 100, PEER__ISS + 1 + 200),  # DSACK marker
                (PEER__ISS + 1 + 100, PEER__ISS + 1 + 200),  # regular OOO block
            ],
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Duplicate-OOO receipt must not perturb the FSM state.",
        )

    def test__sack__dsack__case_2__partial_overlap_with_ooo_queued_segment_elicits_dsack(self) -> None:
        """
        Ensure that when peer's OOO segment partially overlaps
        an existing entry in our OOO queue, the next outbound
        ACK carries a DSACK report whose range is the
        intersection of the new segment with the existing entry
        per RFC 2883 §4 case 2. The peer's spurious-retransmit
        detector fires on the contained-block signature.

        RFC 2883 §3:

            "Each duplicate contiguous sequence of data
             received is reported in at most one D-SACK block."

        Scenario:

            1. Drive an active-open handshake with bilateral
               SACK negotiation succeeded.
            2. Peer sends OOO segment 1: 'seq = PEER__ISS + 1
               + 100', 100 bytes, range [PEER__ISS + 101,
               PEER__ISS + 201).
            3. Peer sends OOO segment 2: 'seq = PEER__ISS + 1
               + 150', 100 bytes, range [PEER__ISS + 151,
               PEER__ISS + 251). The first 50 bytes overlap
               segment 1 (both already in the OOO queue).
            4. The resulting outbound ACK has SACK blocks:
                 - block 0 (DSACK): [PEER__ISS + 151,
                   PEER__ISS + 201) - the overlap range.
                 - block 1 (regular): [PEER__ISS + 101,
                   PEER__ISS + 201) - the original OOO entry.
                 - block 2 (regular): [PEER__ISS + 151,
                   PEER__ISS + 251) - the new OOO entry.
               The DSACK block (151, 201) is contained in
               block 1 (101, 201). Case 2 signature satisfied.

        Assertions:

            * Exactly one inline outbound ACK fires on the
              second OOO arrival.
            * 'sack_blocks[0]' equals the overlap range.
            * 'sack_blocks' contains both regular OOO entries.

        [FLAGS BUG] - Same root cause as the full-duplicate
        case: the OOO ingestion path does not detect the
        partial overlap, no '_pending_dsack' is set, and the
        ACK has only the two regular OOO blocks.

        Fix: same overlap computation as the case-1 sibling.
        """

        self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 100,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X" * 100,
        )
        first_tx = self._drive_rx(frame=seg1)
        self.assertEqual(
            len(first_tx),
            1,
            msg="Setup precondition: first OOO segment elicits exactly one dup-ACK.",
        )

        # Second OOO segment overlaps the first by 50 bytes.
        seg2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 150,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"Y" * 100,
        )
        overlap_tx = self._drive_rx(frame=seg2)

        self.assertEqual(
            len(overlap_tx),
            1,
            msg=(
                "An OOO segment overlapping a queued entry MUST "
                "elicit exactly one outbound ACK reporting the "
                "duplicate range via DSACK (RFC 2883 §3)."
            ),
        )
        overlap_ack_probe = self._parse_tx(overlap_tx[0])
        self._assert_segment(
            overlap_ack_probe,
            flags=frozenset({"ACK"}),
            ack=PEER__ISS + 1,
            sack_blocks=[
                (PEER__ISS + 1 + 150, PEER__ISS + 1 + 200),  # DSACK overlap
                (PEER__ISS + 1 + 100, PEER__ISS + 1 + 200),  # original OOO
                (PEER__ISS + 1 + 150, PEER__ISS + 1 + 250),  # new OOO
            ],
        )

    def test__sack__dsack__case_2__disjoint_ooo_segments_emit_no_dsack(self) -> None:
        """
        Ensure that when peer's OOO segments do NOT overlap any
        existing OOO-queue entry, the resulting SACK option
        carries only regular SACK blocks - no DSACK marker. The
        case-2 signature is reserved exclusively for the
        duplicate-range case; emitting a spurious DSACK on
        every OOO arrival would corrupt the peer's spurious-
        retransmit detector.

        RFC 2883 §3:

            "[The receiver] uses the first SACK block to
             specify the sequence numbers of the duplicate
             segment received."

        I.e. the DSACK signature implies a duplicate event
        actually occurred. Disjoint OOO ingestion is not a
        duplicate event and must not trigger DSACK emission.

        Scenario:

            1. Drive handshake with bilateral SACK
               negotiation succeeded.
            2. Peer sends OOO segment 1: 'seq = PEER__ISS + 1
               + 100', 100 bytes (range [101, 201)).
            3. Peer sends OOO segment 2: 'seq = PEER__ISS + 1
               + 300', 100 bytes (range [301, 401)). Disjoint
               from segment 1 - 100-byte gap between them.
            4. The resulting ACK has SACK blocks:
                 - block 0 (regular): (101, 201)
                 - block 1 (regular): (301, 401)
               No DSACK marker.

        Assertions:

            * Exactly one inline outbound ACK on the second
              OOO arrival.
            * 'sack_blocks' has exactly 2 entries: the two
              regular OOO ranges.
            * The first block does NOT lie inside any later
              block (case-2 signature absent).

        Passes today as a regression guard: pins the negative
        control so a future overly-eager case-2 emission cannot
        slip in. Already passes - confirms the current code
        does not emit spurious DSACKs.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

        seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 100,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X" * 100,
        )
        self._drive_rx(frame=seg1)

        # Second OOO segment - DISJOINT from the first.
        seg2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 300,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"Y" * 100,
        )
        disjoint_tx = self._drive_rx(frame=seg2)

        self.assertEqual(
            len(disjoint_tx),
            1,
            msg="A disjoint OOO segment MUST elicit exactly one outbound ACK.",
        )
        disjoint_ack_probe = self._parse_tx(disjoint_tx[0])
        self._assert_segment(
            disjoint_ack_probe,
            flags=frozenset({"ACK"}),
            ack=PEER__ISS + 1,
            sack_blocks=[
                (PEER__ISS + 1 + 100, PEER__ISS + 1 + 200),
                (PEER__ISS + 1 + 300, PEER__ISS + 1 + 400),
            ],
        )
        # Sanity: the case-2 signature requires block-0 to be
        # contained in a later block. Confirm that NEITHER
        # block-0 sits inside any later block here - the
        # negative-control invariant.
        block0 = (PEER__ISS + 1 + 100, PEER__ISS + 1 + 200)
        block1 = (PEER__ISS + 1 + 300, PEER__ISS + 1 + 400)
        self.assertFalse(
            block1[0] <= block0[0] and block0[1] <= block1[1],
            msg="Negative control: block-0 must NOT lie inside any later block (no spurious DSACK signature).",
        )
        self.assertIsNone(
            session._pending_dsack,
            msg="Disjoint OOO ingestion must not stash a pending DSACK report.",
        )

    def test__sack__cross_rfc__paws_drops_stale_segment_before_dsack_detector(self) -> None:
        """
        Cross-RFC regression guard (Phase B1 of the test-coverage
        audit): a stale-TSval segment that would otherwise be
        a DSACK candidate (fully duplicate, below RCV.NXT) MUST
        be dropped by RFC 7323 §5 PAWS BEFORE the RFC 2883 DSACK
        detector fires; no DSACK report on the next outbound ACK.
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )
        # Promote the session to bilateral TSopt. The handshake
        # helper doesn't drive TSopt; flip the flags directly so
        # the post-handshake test focus is on the PAWS+DSACK
        # interaction, not on the negotiation.
        session._send_ts = True
        session._ts_recent = 0x1234_5678

        # Drive an in-order data segment so RCV.NXT advances,
        # creating the precondition for a "fully duplicate" segment.
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=0x1234_5679,
            tsecr=0x1234_5678,
            payload=b"hello",
        )
        self._drive_rx(frame=peer_data)
        # Drain the delayed-ACK timer so '_pending_dsack' state is
        # observable cleanly.
        self._advance(ms=400)
        session._pending_dsack = None

        # Now drive a stale-TSval, fully-duplicate segment. The
        # DSACK detector at '_check_segment_acceptability' would
        # ordinarily latch '_pending_dsack' for this segment; PAWS
        # must drop the segment first.
        stale_dup = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=0x1234_5670,  # < _ts_recent
            tsecr=0x1234_5678,
            payload=b"hello",
        )
        self._drive_rx(frame=stale_dup)

        self.assertIsNone(
            session._pending_dsack,
            msg=(
                "Cross-RFC: PAWS-rejected segment MUST NOT latch a "
                "pending DSACK report. The PAWS check at the FSM "
                "dispatch boundary fires BEFORE the DSACK detector "
                "in '_check_segment_acceptability'."
            ),
        )
