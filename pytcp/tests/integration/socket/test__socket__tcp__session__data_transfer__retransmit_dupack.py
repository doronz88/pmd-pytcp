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
This module contains integration tests for the TCP fast-retransmit
machinery in the 'TcpSession' state machine, covering the duplicate-
ACK trigger threshold prescribed by RFC 5681 §3.2.

The tests in this file drive the session through the active-open
handshake to ESTABLISHED, transmit a single full-MSS data segment,
then feed the peer's duplicate ACKs one at a time through the real
RX path. Assertions cover both the count threshold ("third duplicate
ACK is the trigger") and the wire-level shape of the resulting fast
retransmit (same seq, same payload as the original, no peer ACK
required).

Reference RFCs:
    RFC 5681 §3.2        Fast Retransmit / Fast Recovery
    RFC 9293 §3.7.6      Loss recovery using duplicate ACK feedback
    RFC 6675             Conservative loss recovery (informational
                         backdrop; not asserted here)

pytcp/tests/integration/socket/test__socket__tcp__session__data_transfer__retransmit_dupack.py

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


class TestTcpDataTransfer__RetransmitDupack(TcpSessionTestCase):
    """
    Integration tests for the dup-ACK-triggered fast-retransmit
    threshold and the wire-level shape of the retransmit it produces.
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

    def test__dupack__third_duplicate_ack_triggers_fast_retransmit(self) -> None:
        """
        Ensure that the fast-retransmit algorithm fires only on the
        THIRD duplicate ACK from the peer, not earlier, and that the
        resulting retransmit reuses the original SEQ and payload
        byte-for-byte (RFC 5681 §3.2 / RFC 9293 §3.7.6).

        RFC 5681 §3.2:

            "The fast retransmit algorithm uses the arrival of 3
             duplicate ACKs (4 ACKs without the arrival of any other
             intervening packets) as an indication that a segment has
             been lost.  ...  After the fast retransmit algorithm
             sends what appears to be the missing segment, the 'fast
             recovery' algorithm governs the transmission of new data
             until a non-duplicate ACK arrives."

        A 'duplicate ACK' for this purpose is a received segment that
        (per the same RFC's stricter clause):

            * carries 'SEG.ACK == SND.UNA' (no advance), and
            * carries no data, no SYN, no FIN, and
            * the sender has outstanding unacknowledged data.

        Scenario:

            1. Drive handshake to ESTABLISHED. Pre-set '_snd_ewn' to
               peer's full advertised window so the initial transmit
               is not throttled by slow-start.
            2. Application sends one full-MSS data segment (1460 B,
               all 'X'). On the next tick the original segment fires
               at SEQ = LOCAL__ISS + 1.
            3. Peer sends DUP-ACK #1 (ACK = LOCAL__ISS + 1, no data).
               Tick once. NO retransmit may fire - we are still one
               dup-ACK below the RFC-mandated trigger.
            4. Peer sends DUP-ACK #2. Tick once. Still NO retransmit
               permitted - we are exactly two dup-ACKs in, RFC 5681
               §3.2 names the THIRD as the trigger.
            5. Peer sends DUP-ACK #3. Tick once. Exactly ONE
               retransmit must fire, carrying the original SEQ
               (LOCAL__ISS + 1), the original payload byte-for-byte,
               and PSH | ACK (PSH because it was the last segment of
               the 'send()' call - RFC 1122 §4.2.2.2).

        State assertions:

            * 'session.state' remains ESTABLISHED throughout.
            * 'SND.UNA' is unchanged from LOCAL__ISS + 1 (peer never
               advanced our ack).
            * The fast-retransmit counter is keyed by the dup-ACK's
              ACK value; we don't assert on it directly (private
              bookkeeping), but the wire-level retransmit count is
              the externally visible contract that fully captures
              the threshold rule.

        [FLAGS BUG] - 'TcpSession._retransmit_packet_request' uses
        the predicate 'counter > 1' to gate the retransmit, which
        fires on the SECOND duplicate ACK. RFC 5681 §3.2 mandates
        the THIRD. Step 4 of the scenario above will currently
        observe a premature retransmit on the tick after dup-ACK #2,
        and step 5 will observe a SECOND (already-redundant)
        retransmit on the tick after dup-ACK #3.

        The fix is a one-character change in
        'pytcp/socket/tcp__session.py' line 817:

            if self._tx_retransmit_request_counter[...] > 1:   # bug
            if self._tx_retransmit_request_counter[...] > 2:   # rfc

        with the test-method docstring above doubling as the spec
        citation in the fix commit body.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._snd_ewn = PEER__WIN

        payload = b"X" * 1460
        session.send(data=payload)

        # Original transmission on the next tick.
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup precondition: the original data segment must fire on the first tick.",
        )
        initial_seg = self._parse_tx(initial_tx[0])
        self.assertEqual(
            initial_seg.seq,
            LOCAL__ISS + 1,
            msg="Setup precondition: the original segment must carry SEQ = ISS + 1.",
        )
        self.assertEqual(
            initial_seg.payload,
            payload,
            msg="Setup precondition: the original segment must carry the application's payload byte-for-byte.",
        )

        # Helper: build one dup-ACK frame (same shape every time).
        def dupack_frame() -> bytes:
            return build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )

        # DUP-ACK #1: counter = 1. Below the RFC threshold.
        dupack_1_inline = self._drive_rx(frame=dupack_frame())
        self.assertEqual(
            dupack_1_inline,
            [],
            msg=(
                "DUP-ACK #1 must not produce any inline TX - the "
                "fast-retransmit handler only sets internal state, "
                "the actual retransmit is timer-driven."
            ),
        )
        dupack_1_tick = self._advance(ms=1)
        self.assertEqual(
            dupack_1_tick,
            [],
            msg=(
                "After DUP-ACK #1 and one tick, NO retransmit may "
                "fire - we are at one dup-ACK out of the three RFC "
                "5681 §3.2 mandates as the trigger."
            ),
        )

        # DUP-ACK #2: counter = 2. Still below the RFC threshold.
        dupack_2_inline = self._drive_rx(frame=dupack_frame())
        self.assertEqual(
            dupack_2_inline,
            [],
            msg="DUP-ACK #2 must not produce any inline TX.",
        )
        dupack_2_tick = self._advance(ms=1)
        self.assertEqual(
            dupack_2_tick,
            [],
            msg=(
                "After DUP-ACK #2 and one tick, NO retransmit may "
                "fire - RFC 5681 §3.2 names the THIRD duplicate ACK "
                "as the trigger, not the second. A retransmit here "
                "indicates the dup-ACK counter threshold is set "
                "below the RFC value (current code uses '> 1' where "
                "'> 2' is required)."
            ),
        )

        # DUP-ACK #3: counter = 3. RFC trigger; one retransmit
        # MUST fire on the next tick.
        dupack_3_inline = self._drive_rx(frame=dupack_frame())
        self.assertEqual(
            dupack_3_inline,
            [],
            msg=(
                "DUP-ACK #3 must not produce inline TX - the handler "
                "resets SND.NXT to SND.UNA but the actual retransmit "
                "is emitted by the next timer-driven '_transmit_data' "
                "pass."
            ),
        )
        dupack_3_tick = self._advance(ms=1)
        self.assertEqual(
            len(dupack_3_tick),
            1,
            msg=(
                "After DUP-ACK #3 and one tick, exactly ONE "
                "retransmit must fire (RFC 5681 §3.2 fast retransmit) "
                "- the lost segment that the peer's three duplicate "
                "ACKs are signalling as missing."
            ),
        )
        retransmit_seg = self._parse_tx(dupack_3_tick[0])
        self.assertEqual(
            retransmit_seg.seq,
            LOCAL__ISS + 1,
            msg=(
                "The fast retransmit must reuse the original SEQ "
                f"({LOCAL__ISS + 1:#x}) per RFC 5681 §3.2 - it is "
                "the missing segment, not a fresh one."
            ),
        )
        self.assertEqual(
            retransmit_seg.payload,
            payload,
            msg=(
                "The fast retransmit must reuse the original payload "
                "byte-for-byte. A different payload would indicate "
                "either TX-buffer corruption or a post-original "
                "send() call leaking into the retransmit."
            ),
        )
        self.assertEqual(
            retransmit_seg.flags,
            frozenset({"PSH", "ACK"}),
            msg=(
                "The fast retransmit must carry the same flag set as "
                "the original segment: PSH (RFC 1122 §4.2.2.2 - last "
                "segment of the write) plus the always-on ACK "
                "piggyback."
            ),
        )

        # State assertions: peer never advanced our ack, session
        # remains alive throughout the dup-ACK sequence.
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1,
            msg=(
                "'SND.UNA' must be unchanged - dup-ACKs by definition "
                "carry 'SEG.ACK == SND.UNA' and so do not advance "
                "the send sequence space."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="The session must remain ESTABLISHED through the full dup-ACK sequence.",
        )

    def test__dupack__data_bearing_same_ack_does_not_count_toward_threshold(self) -> None:
        """
        Ensure that a peer segment carrying 'SEG.ACK == SND.UNA' but
        also delivering NEW DATA does NOT count as a duplicate ACK
        for the fast-retransmit threshold (RFC 5681 §3.2, footnote 4
        of the algorithm definition):

            "(a) the receiver of the ACK has outstanding data, ...
             (b) the incoming acknowledgment carries no data,
             (c) the SYN and FIN bits are both off,
             (d) the acknowledgment number is equal to the greatest
                 acknowledgment received on the given connection ...,
             (e) the advertised window in the incoming acknowledgment
                 equals the advertised window in the last incoming
                 acknowledgment.

             The corresponding ACK is considered a 'duplicate' iff
             all of (a) - (e) hold. ..."

        Concretely: even if the peer ACKs at the same SND.UNA across
        many segments, those segments are bidirectional traffic
        (data flowing toward us at the same time), not loss signals.
        Counting them would falsely trip fast retransmit during a
        normal bulk-receive while we have unacked data in flight.

        Scenario:

            1. Drive handshake to ESTABLISHED. Pre-set '_snd_ewn' so
               our send is unconstrained.
            2. Application sends one full-MSS data segment. Tick:
               original transmit fires at SEQ = LOCAL__ISS + 1.
            3. Peer sends THREE back-to-back data-bearing segments,
               each with 'ack = LOCAL__ISS + 1' (== SND.UNA, never
               advanced) but each carrying 100 bytes of fresh,
               in-order data starting at SEQ = PEER__ISS + 1.
            4. Tick once.

        Per the strict dup-ACK definition above, none of the three
        peer segments qualify as a dup-ACK (clause (b) fails - they
        carry data). They are processed by the data-handling branch
        of '_tcp_fsm_established' as ordinary in-order receive,
        advancing 'RCV.NXT' and queuing payload to '_rx_buffer'.
        '_tx_retransmit_request_counter' must remain at zero entries
        for our SND.UNA, so no fast retransmit is permitted on the
        post-tick clock.

        Assertions:

            * After step 3: zero TX produced inline beyond ACK
              traffic the data-handling path may emit (delayed-ACK
              mechanism may schedule one ACK; we do not constrain
              its presence here, only that NO retransmit of the
              data segment fires).
            * After step 4: NO retransmit at SEQ = LOCAL__ISS + 1
              with the original payload.
            * 'session._tx_retransmit_request_counter' contains no
              entry at LOCAL__ISS + 1 (key never created since none
              of the three segments matched the dup-ACK predicate).
            * 'session._rcv_nxt' advanced by 3 * 100 = 300 bytes.
            * 'session._rx_buffer' holds the 300 bytes in order.
            * State remains ESTABLISHED.

        This test is a positive-control regression guard for the
        'not packet_rx_md.tcp__data' clause in
        'TcpSession._tcp_fsm_established's dup-ACK predicate
        (line 1377). A future change that dropped that clause -
        e.g. counting any same-SND.UNA ACK regardless of payload -
        would break this test by either (a) creating an entry in
        '_tx_retransmit_request_counter[LOCAL__ISS + 1]' or
        (b) firing a spurious retransmit on the post-tick clock.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._snd_ewn = PEER__WIN

        payload = b"X" * 1460
        session.send(data=payload)

        # Original transmission on the next tick.
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup precondition: the original data segment must fire on the first tick.",
        )

        # Three data-bearing segments at ack == SND.UNA, each
        # delivering 100 bytes of fresh in-order data.
        peer_data_chunk = b"Y" * 100
        for index in range(3):
            seg = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1 + index * len(peer_data_chunk),
                ack=LOCAL__ISS + 1,
                flags=("ACK", "PSH"),
                win=PEER__WIN,
                payload=peer_data_chunk,
            )
            inline = self._drive_rx(frame=seg)
            for frame in inline:
                probe = self._parse_tx(frame)
                self.assertNotEqual(
                    probe.payload,
                    payload,
                    msg=(
                        f"After data-bearing segment #{index + 1} at "
                        f"ack == SND.UNA, no retransmit of the original "
                        "data segment is permitted - the segment "
                        "carries data and so cannot count as a "
                        "duplicate ACK per RFC 5681 §3.2 footnote 4(b)."
                    ),
                )

        # The dup-ACK counter must NEVER have been touched.
        self.assertNotIn(
            LOCAL__ISS + 1,
            session._tx_retransmit_request_counter,
            msg=(
                "'_tx_retransmit_request_counter' must contain no "
                "entry for SND.UNA after three data-bearing same-ACK "
                "segments - the dup-ACK predicate excludes "
                "data-bearing segments per RFC 5681 §3.2."
            ),
        )

        # Post-tick: still no retransmit. The buggy '> 1' threshold
        # would only fire if the counter had been incremented; the
        # data-bearing exclusion prevents that, so the post-tick
        # clock is silent.
        post_tick_tx = self._advance(ms=1)
        for frame in post_tick_tx:
            probe = self._parse_tx(frame)
            self.assertNotEqual(
                probe.payload,
                payload,
                msg=(
                    "After three data-bearing segments and one tick, "
                    "no fast retransmit of the original data may fire - "
                    "data-bearing segments do not count toward the "
                    "RFC 5681 §3.2 threshold, so the dup-ACK counter "
                    "stayed at zero and there is nothing to retrigger."
                ),
            )

        # Receive-side state advanced by exactly 3 * 100 bytes.
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1 + 3 * len(peer_data_chunk),
            msg=(
                "'RCV.NXT' must advance by the cumulative length of "
                "the three in-order data chunks - the segments were "
                "processed as normal receive, not silently dropped."
            ),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            peer_data_chunk * 3,
            msg=(
                "'_rx_buffer' must hold the three data chunks in "
                "arrival order - the data-handling branch of the FSM "
                "queued them rather than the dup-ACK branch dropping "
                "them."
            ),
        )

        # Send-side state and FSM unchanged.
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1,
            msg=(
                "'SND.UNA' must be unchanged - the peer's ACK never "
                "advanced and our outstanding data is still in flight."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED through the bidirectional exchange.",
        )

    def test__dupack__fast_retransmit_is_one_shot_per_loss_event(self) -> None:
        """
        Ensure that the fast-retransmit algorithm fires EXACTLY ONCE
        per loss event - additional duplicate ACKs after the third
        MUST NOT cause the lost segment to be retransmitted again
        (RFC 5681 §3.2 steps 3 and 4):

            "3. The lost segment starting at SND.UNA MUST be
                retransmitted ...

             4. For each additional duplicate ACK received (after
                the third), cwnd MUST be incremented by SMSS. ..."

        Step 3's "MUST be retransmitted" is singular. Step 4 names
        the post-threshold action explicitly: cwnd inflation, not
        re-retransmission. A naive implementation that re-fires the
        retransmit on every dup-ACK above the threshold would flood
        the network with redundant copies of the lost segment - a
        textbook congestion-collapse vector.

        Scenario:

            1. Drive handshake to ESTABLISHED. Pre-set '_snd_ewn' so
               the original send is unconstrained.
            2. Application sends one full-MSS data segment. Tick:
               original transmit fires at SEQ = LOCAL__ISS + 1.
            3. Peer sends FIVE back-to-back duplicate ACKs at
               'ack = LOCAL__ISS + 1', no data. Tick once between
               each so the timer-driven '_transmit_data' has a
               chance to act on any state change.
            4. Across the entire 5-dup-ACK sequence, exactly ONE
               retransmit of the original payload may appear on the
               wire. Per-tick observations:

                 * After dup-ACK #1 + tick: 0 retransmits.
                 * After dup-ACK #2 + tick: 0 retransmits (RFC
                   threshold is 3, not 2).
                 * After dup-ACK #3 + tick: 1 retransmit (RFC
                   trigger).
                 * After dup-ACK #4 + tick: 0 retransmits (one-shot
                   rule - additional dup-ACKs inflate cwnd, not
                   re-trigger).
                 * After dup-ACK #5 + tick: 0 retransmits.

            5. State remains ESTABLISHED throughout; SND.UNA is
               unchanged at LOCAL__ISS + 1.

        [FLAGS BUG] - 'TcpSession._retransmit_packet_request' uses
        'counter > 1' as the gate to reset SND.NXT to SND.UNA.
        Because the gate is '>'-style and the counter monotonically
        increases as each dup-ACK arrives, EVERY dup-ACK above the
        threshold re-arms a retransmit on the next tick, not just
        the one that crossed the threshold. This violates two RFC
        clauses simultaneously:

            * The threshold is wrong (fires on #2 instead of #3).
            * The trigger is repeated (fires on #2, #3, #4, #5
              with the current code, instead of exactly once).

        On current code this test will see four retransmits across
        the 5-dup-ACK sequence (one each after dup-ACKs #2, #3, #4,
        #5). The first failing assertion will be the post-tick
        observation after dup-ACK #2.

        The canonical fix in 'pytcp/socket/tcp__session.py:817' is
        to change the threshold from '> 1' to '== 3', so that the
        retransmit trigger is both:

            * delayed to the third dup-ACK (matching the RFC), and
            * one-shot (additional dup-ACKs at counter values 4, 5,
              ... do not re-fire SND.NXT = SND.UNA).

        This single change flips both scenarios #1 and #3 green.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._snd_ewn = PEER__WIN

        payload = b"X" * 1460
        session.send(data=payload)

        # Original transmission on the next tick.
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup precondition: the original data segment must fire on the first tick.",
        )

        def dupack_frame() -> bytes:
            return build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )

        def count_retransmits(frames: list[bytes]) -> int:
            """
            Count outbound segments that look like a retransmit of
            our original data: SEQ = LOCAL__ISS + 1, payload equals
            the original. Anything else (delayed-ACK piggyback,
            etc.) is ignored.
            """

            count = 0
            for frame in frames:
                probe = self._parse_tx(frame)
                if probe.seq == LOCAL__ISS + 1 and probe.payload == payload:
                    count += 1
            return count

        # Per-tick expected retransmit counts. Index N corresponds
        # to "after dup-ACK #(N+1) and one tick".
        expected_per_tick = [0, 0, 1, 0, 0]
        observed_per_tick: list[int] = []

        for index in range(5):
            self._drive_rx(frame=dupack_frame())
            tick_tx = self._advance(ms=1)
            observed_per_tick.append(count_retransmits(tick_tx))

        # Per-tick assertions, surfaced one at a time so the failure
        # message points to exactly which dup-ACK observation
        # diverged from the RFC.
        for index, (expected, observed) in enumerate(zip(expected_per_tick, observed_per_tick), start=1):
            self.assertEqual(
                observed,
                expected,
                msg=(
                    f"After dup-ACK #{index} and one tick, expected "
                    f"{expected} retransmit(s) of the original payload "
                    f"but observed {observed}. RFC 5681 §3.2 mandates "
                    "the trigger on dup-ACK #3 only, with no "
                    "re-firing on subsequent dup-ACKs."
                ),
            )

        # Total across the full 5-dup-ACK sequence: exactly one
        # retransmit (the one-shot rule encoded as a single
        # cumulative invariant).
        self.assertEqual(
            sum(observed_per_tick),
            1,
            msg=(
                "Across the full 5-dup-ACK sequence, exactly ONE "
                "fast retransmit of the lost segment is permitted "
                f"(RFC 5681 §3.2 step 3). Observed "
                f"{sum(observed_per_tick)} retransmits at SEQ = "
                f"{LOCAL__ISS + 1:#x}."
            ),
        )

        # Send-side state and FSM unchanged across the sequence.
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1,
            msg=(
                "'SND.UNA' must be unchanged - dup-ACKs by definition "
                "do not advance SND.UNA, so the send sequence space "
                "remains frozen at LOCAL__ISS + 1."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Session must remain ESTABLISHED across the full "
                "dup-ACK sequence - fast retransmit is a recovery "
                "mechanism within ESTABLISHED, not a state-changing "
                "event."
            ),
        )

    def test__dupack__rto_during_fast_retransmit_recovery_clears_recovery_point(self) -> None:
        """
        Ensure that when an RTO fires while we are still inside a
        fast-retransmit recovery episode, the '_recovery_point'
        marker is cleared so subsequent dup-ACKs can re-enter
        recovery on a fresh loss event. Per RFC 5681 §3.1, RTO
        is a hard reset (cwnd collapses to one SMSS, slow-start
        re-entry); it represents a 'lost the entire window'
        event distinct from the dup-ACK-driven fast-retransmit
        recovery. The RFC 6675 §5 RecoveryPoint marker (the
        SND.MAX at fast-retransmit entry) becomes meaningless
        after RTO: SND.NXT has been rewound to SND.UNA and the
        old SND.MAX no longer corresponds to any in-flight
        boundary.

        Scenario:

            1. Drive handshake to ESTABLISHED. Pre-set
               '_snd_ewn = PEER__WIN' so slow-start does not
               constrain the test setup.
            2. Application sends 1 MSS of data. Drain so the
               segment fires.
            3. Peer sends three dup-ACKs back-to-back. The
               third triggers fast-retransmit:
                   _recovery_point = SND.MAX (non-zero)
                   _snd_nxt = SND.UNA
            4. Drain the fast-retransmit segment. The segment's
               retransmit timer is now at 2000ms (RFC 6298
               exponential back-off; counter incremented once
               by the original send + once by the fast-
               retransmit re-arm).
            5. Advance 3 seconds. The retransmit timer expires;
               '_retransmit_packet_timeout' fires, collapsing
               '_snd_ewn' to one SMSS and rewinding 'SND.NXT'
               to 'SND.UNA' for slow-start re-entry.
            6. Assert: '_recovery_point' is back at zero. A
               subsequent loss event will be eligible to enter
               recovery again.

        Assertions:

            * After the RTO firing: 'session._recovery_point == 0'.
            * Sanity: 'session.state is FsmState.ESTABLISHED'
              (we have not exhausted PACKET_RETRANSMIT_MAX_COUNT
              retries; the connection is still alive).
            * Sanity: 'session._snd_ewn == session._snd_mss'
              (cwnd collapsed to one SMSS per RFC 5681 §3.1).

        [FLAGS BUG] - 'TcpSession._retransmit_packet_timeout' (the
        RTO handler near line 1190) collapses '_snd_ewn' and
        rewinds 'SND.NXT' but does NOT reset '_recovery_point'.
        It stays at the old SND.MAX from the fast-retransmit
        entry. The next dup-ACK following the RTO retransmit
        will hit the 'if self._recovery_point != 0: return'
        guard at the top of '_retransmit_packet_request' and
        SILENTLY SKIP fast-retransmit. Recovery-exit is then
        gated on 'SND.UNA crosses the stale _recovery_point'
        which - after RTO has reset SND.NXT to SND.UNA -
        requires many ACKs of forward-progress data before
        '_recovery_point' clears. Until then, fast-retransmit
        is structurally inhibited.

        Fix outline (separate commit): in
        '_retransmit_packet_timeout', after the abort check but
        before the '_snd_nxt = _snd_una' rewind, set
        'self._recovery_point = 0'. The recovery state is
        meaningless after RTO; the next dup-ACK should evaluate
        recovery entry afresh.

        Same recovery-point lifecycle gap exists on state
        transitions out of ESTABLISHED (e.g. peer FIN -> we
        enter CLOSE_WAIT but '_recovery_point' stays set -
        post-half-close 'send()' that experiences loss is
        blocked from fast-retransmit until the stale marker
        clears). That's a related-but-separate bug class
        ('_change_state' should clear loss-recovery state on
        leaving ESTABLISHED) and tracked separately.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._snd_ewn = PEER__WIN

        # Send 1 MSS and drain so the original segment is on the
        # wire and its RTO timer is armed.
        payload = b"X" * 1460
        session.send(data=payload)
        self._advance(ms=1)

        # Three dup-ACKs back-to-back. The third triggers fast-
        # retransmit.
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)

        self.assertNotEqual(
            session._recovery_point,
            0,
            msg=(
                "Setup precondition: the third dup-ACK MUST trigger "
                "fast-retransmit and set '_recovery_point' to a "
                "non-zero marker (the SND.MAX at recovery entry). "
                "Without this precondition the rest of the test is "
                "vacuous."
            ),
        )

        # Drain the fast-retransmit segment.
        self._advance(ms=1)

        # Wait long enough for the RTO timer on the retransmit to
        # fire. The retransmit re-armed the timer at 2000ms (one
        # back-off doubling); 3 seconds is comfortably past that.
        self._advance(ms=3000)

        self.assertEqual(
            session._recovery_point,
            0,
            msg=(
                "After RTO fires, '_recovery_point' MUST be cleared "
                "to zero - RTO is a hard reset per RFC 5681 §3.1 and "
                "the old recovery marker (SND.MAX at fast-retransmit "
                "entry) is meaningless once SND.NXT has been rewound "
                "to SND.UNA. Today PyTCP leaves '_recovery_point' "
                "set; the next dup-ACK skips fast-retransmit via the "
                "one-shot guard at the top of "
                "'_retransmit_packet_request'. Fix: clear "
                "'self._recovery_point = 0' inside "
                "'_retransmit_packet_timeout'."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Sanity: after one RTO retry the connection must "
                "still be in ESTABLISHED - PACKET_RETRANSMIT_MAX_COUNT "
                "is 6, we have only used 2 retries (initial + fast-"
                "retransmit + 1 RTO)."
            ),
        )
        self.assertEqual(
            session._snd_ewn,
            session._snd_mss,
            msg=(
                "Sanity: RTO MUST collapse '_snd_ewn' to one SMSS "
                "per RFC 5681 §3.1 (slow-start re-entry). If this "
                "assertion fails the RTO did not actually fire, "
                "and the '_recovery_point' assertion above is "
                "vacuous."
            ),
        )

    def test__dupack__peer_fin_during_fast_retransmit_recovery_clears_recovery_point(self) -> None:
        """
        Ensure that when peer's FIN arrives mid-recovery and the
        FSM transitions ESTABLISHED -> CLOSE_WAIT without the
        cumulative ACK advancing past the existing
        '_recovery_point' marker, the marker is cleared as part
        of leaving ESTABLISHED. The RFC 6675 §5 RecoveryPoint is
        a SND.MAX boundary recorded at fast-retransmit entry; it
        is meaningful only inside the ESTABLISHED loss-recovery
        loop. Once the connection has half-closed (peer FIN), any
        post-FIN application 'send()' that experiences loss must
        be eligible to enter recovery afresh in CLOSE_WAIT - the
        old marker references a high-water mark that may or may
        not still be relevant, and leaving it set silently
        inhibits fast-retransmit until cum-ACK eventually crosses
        the stale value.

        Same bug class as the RTO-clears-recovery-point test
        above (commit 'cc736ae' / fix '2f50480'); different
        trigger (peer-driven state transition vs RTO timer
        expiry); same fix surface ('_recovery_point' lifecycle
        on leaving ESTABLISHED).

        Scenario:

            1. Drive handshake to ESTABLISHED. '_snd_ewn =
               PEER__WIN' to bypass slow-start.
            2. Application sends 4 MSS of data. Drain so all
               four segments fire and SND.MAX = LOCAL__ISS + 1
               + 4*MSS.
            3. Three dup-ACKs at 'ack = LOCAL__ISS + 1' trigger
               fast-retransmit:
                 _recovery_point = SND.MAX = LOCAL__ISS + 1 +
                                              4*MSS
                 _snd_nxt = SND.UNA = LOCAL__ISS + 1
            4. Drain the fast-retransmit segment.
            5. Peer sends FIN+ACK with 'ack = LOCAL__ISS + 1'
               (the SAME unchanged cum-ACK; peer is closing
               while still missing our outstanding data). The
               FSM transitions ESTABLISHED -> CLOSE_WAIT
               without SND.UNA advancing past
               '_recovery_point'.
            6. Assert: 'session._recovery_point == 0'. The
               state-leave-ESTABLISHED clears the marker so a
               post-FIN application send + loss can re-enter
               recovery.

        Assertions:

            * After the FIN: 'session.state is FsmState.CLOSE_WAIT'
              (sanity).
            * 'session._recovery_point == 0' (the bug surface).
            * 'session._snd_una' unchanged at LOCAL__ISS + 1
              (sanity: the FIN's piggybacked ACK did not advance
              SND.UNA past the marker, so the natural in-
              '_process_ack_packet' clearing mechanism was NOT
              what cleared the marker).

        [FLAGS BUG] - 'TcpSession._change_state' (and the per-
        state handlers that drive transitions) does not clear
        '_recovery_point' when leaving ESTABLISHED. The marker
        is cleared only inside '_process_ack_packet' when SND.UNA
        crosses it; if peer's FIN cum-ACKs less than the marker
        (the case constructed above), the marker survives the
        transition. Subsequent post-half-close 'send()' that
        experiences loss has '_retransmit_packet_request' short-
        circuit at 'if self._recovery_point != 0: return',
        silently skipping fast-retransmit. The connection
        eventually progresses (cum-ACK eventually crosses the
        stale marker, or RTO fires - which DOES now clear via
        commit '2f50480') but visibly slower than it should.

        Fix outline (separate commit): in '_change_state' (or in
        the ESTABLISHED handlers' transitions out), clear
        'self._recovery_point = 0' when leaving ESTABLISHED.
        '_recovery_point' has no meaning outside the
        ESTABLISHED loss-recovery loop.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._snd_ewn = PEER__WIN
        mss = session._snd_mss

        # Send 4 MSS and drain so SND.MAX is well past SND.UNA.
        session.send(data=b"X" * (4 * mss))
        for _ in range(4):
            self._advance(ms=1)
        self.assertEqual(
            session._snd_max,
            LOCAL__ISS + 1 + 4 * mss,
            msg="Setup precondition: all 4 MSS segments must drain.",
        )

        # Three dup-ACKs back-to-back. Third triggers fast-retransmit.
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)

        self.assertNotEqual(
            session._recovery_point,
            0,
            msg=(
                "Setup precondition: the third dup-ACK MUST trigger "
                "fast-retransmit and set '_recovery_point' to a "
                "non-zero marker."
            ),
        )
        recovery_point_at_entry = session._recovery_point

        # Drain the fast-retransmit segment.
        self._advance(ms=1)

        # Peer sends FIN+ACK with the SAME cum-ACK = LOCAL__ISS+1
        # (no forward progress). State transitions to CLOSE_WAIT
        # WITHOUT SND.UNA advancing past '_recovery_point' - so
        # the natural 'le32(_recovery_point, _snd_una)' clearing
        # path inside '_process_ack_packet' does NOT fire.
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
            msg="Setup precondition: peer's FIN must transition session to CLOSE_WAIT.",
        )
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1,
            msg=(
                "Setup precondition: peer's FIN had cum-ACK = "
                "LOCAL__ISS + 1, so SND.UNA must NOT have advanced "
                "past '_recovery_point'. If this assertion fails "
                "the natural in-'_process_ack_packet' clearing "
                "fired and the test below is vacuous."
            ),
        )
        self.assertEqual(
            session._recovery_point,
            0,
            msg=(
                "Leaving ESTABLISHED MUST clear '_recovery_point' "
                "to zero - the RFC 6675 §5 marker is meaningful "
                "only inside the ESTABLISHED loss-recovery loop. "
                f"Today the marker stays at {recovery_point_at_entry} "
                "(the stale SND.MAX from fast-retransmit entry); "
                "the next dup-ACK in CLOSE_WAIT or any state "
                "transitioned to from here would skip fast-"
                "retransmit via the one-shot guard. Fix: clear "
                "'self._recovery_point = 0' in '_change_state' "
                "when leaving ESTABLISHED, or equivalently in the "
                "ESTABLISHED handlers' transitions out."
            ),
        )
