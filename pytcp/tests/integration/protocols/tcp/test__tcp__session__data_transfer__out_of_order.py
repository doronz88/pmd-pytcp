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
This module contains integration tests for the TCP receive-side
out-of-order (OOO) segment handling in the 'TcpSession' state
machine, covering gap detection, OOO queue storage, fast-retransmit
duplicate-ACK emission, and gap-fill drain semantics per RFC 9293
§3.10.7.4 / §3.4.

The tests in this file drive a session through the active-open
handshake to ESTABLISHED and then feed segments out of order from
the peer, asserting both the receive buffer state and the outbound
ACK shapes that result.

Reference RFCs:
    RFC 9293 §3.10.7.4   Synchronized state segment processing
    RFC 9293 §3.4        Sequence numbers
    RFC 9293 §3.8        Data Communication
    RFC 5681 §3.2        Fast retransmit / fast recovery
    RFC 1122 §4.2.2.20   General TCP requirements

pytcp/tests/integration/protocols/tcp/test__tcp__session__data_transfer__out_of_order.py

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


class TestTcpDataTransfer__OutOfOrder(TcpSessionTestCase):
    """
    Integration tests for inbound out-of-order segment handling and
    the OOO queue / dup-ACK / gap-fill drain machinery.
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

    def test__data_transfer_out_of_order__gap_buffers_segment_and_dup_ack_then_fill_drains(self) -> None:
        """
        Ensure the OOO machinery correctly handles a one-segment gap
        in the inbound stream:

            1. Peer's segment #2 arrives BEFORE segment #1 (gap at
               RCV.NXT). The receiver MUST buffer segment #2 in the
               OOO queue rather than discard it, and emit a fast-
               retransmit duplicate ACK pointing at the still-
               expected RCV.NXT so the peer's sender knows which
               byte is missing per RFC 5681 §3.2.
            2. Peer's segment #1 arrives next, filling the gap. The
               receiver processes segment #1 normally, advancing
               RCV.NXT past it, then drains the OOO queue: segment
               #2 is retrieved at the new RCV.NXT and processed in
               the same call chain, advancing RCV.NXT past it too.
            3. After the drain, '_rx_buffer' contains seg1 + seg2 in
               the order the application sent them, and RCV.NXT
               equals 'PEER__ISS + 1 + 2 * MSS'.

        Wire-level expectations:

            On segment #2 arrival (the OOO one):
                One inline TX = bare ACK with
                    seq = LOCAL__ISS + 1
                    ack = PEER__ISS + 1     (= still-expected RCV.NXT)
                    flags = {ACK}
                    payload = b""

            On segment #1 arrival (the gap-fill):
                One inline TX = cumulative ACK covering BOTH segments:
                    seq = LOCAL__ISS + 1
                    ack = PEER__ISS + 1 + 2 * MSS
                    flags = {ACK}
                    payload = b""
                The cumulative ACK fires inline because seg #1 plus
                the drained seg #2 together hit the
                "ACK every other segment" threshold (count == 2)
                added to '_process_ack_packet' for RFC 1122 §4.2.3.2
                compliance.

        Side effects asserted:

            * After segment #2 arrival:
                - 'session._ooo_packet_queue' contains segment #2 at
                  key 'PEER__ISS + 1 + 1460'.
                - '_rx_buffer' is still empty - we have not delivered
                  out-of-order data to the application.
                - 'session._rcv_nxt' is unchanged at PEER__ISS + 1.

            * After segment #1 arrival (gap-fill + drain):
                - 'session._ooo_packet_queue' is empty.
                - 'session._rx_buffer' equals 'seg1_payload +
                  seg2_payload'.
                - 'session._rcv_nxt' equals
                  'PEER__ISS + 1 + 2 * 1460'.
                - 'session._rcv_una' equals '_rcv_nxt' (the inline
                  cumulative ACK acknowledged everything).

            * State stays ESTABLISHED throughout.

        This test passes on current code as a positive-control
        regression guard for the OOO machinery: the
        '_ooo_packet_queue' storage, the dup-ACK emit on every
        OOO arrival (RFC 5681 §4.2), the recursive drain in
        '_process_ack_packet's 'pop(self._rcv_nxt, None)' branch,
        and the cumulative ACK of the drained chain are all
        exercised end-to-end.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        seg1_payload = b"X" * 1460
        seg2_payload = b"Y" * 1460

        # Peer sends segment #2 FIRST (out of order). seq = peer_ISS+1
        # + 1460 = the byte AFTER segment #1's last byte.
        seg2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 1460,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            payload=seg2_payload,
            win=PEER__WIN,
        )
        ooo_tx = self._drive_rx(frame=seg2)

        # The OOO arrival must trigger one fast-retransmit dup-ACK
        # pointing at the missing RCV.NXT.
        self.assertEqual(
            len(ooo_tx),
            1,
            msg=(
                "An OOO segment arriving with seq > RCV.NXT must "
                "trigger exactly one fast-retransmit dup-ACK pointing "
                f"at the missing RCV.NXT. Got {len(ooo_tx)} TX frames."
            ),
        )
        dup_ack = self._parse_tx(ooo_tx[0])
        self._assert_segment(
            dup_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
            mss=None,
            wscale=None,
            win=65535,
        )
        self.assertIn(
            PEER__ISS + 1 + 1460,
            session._ooo_packet_queue,
            msg=(
                "The OOO segment must be buffered in '_ooo_packet_queue' "
                "keyed by its arrival SEQ so the gap-fill drain can "
                "retrieve it later."
            ),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            b"",
            msg=(
                "Out-of-order data must NOT be delivered to "
                "'_rx_buffer' - it stays in the OOO queue until the "
                "gap is filled."
            ),
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1,
            msg=("RCV.NXT must NOT advance on an OOO arrival - the " "byte we are still expecting is unchanged."),
        )

        # Peer sends segment #1 - the gap-fill.
        seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            payload=seg1_payload,
            win=PEER__WIN,
        )
        gap_fill_tx = self._drive_rx(frame=seg1)

        # The gap-fill arrival processes seg #1 then drains seg #2
        # from the OOO queue. The combined effect (two segments in
        # one drive) crosses the "ACK every other segment" threshold,
        # so a single inline cumulative ACK fires.
        self.assertEqual(
            len(gap_fill_tx),
            1,
            msg=(
                "The gap-fill segment must trigger exactly one inline "
                "cumulative ACK after the OOO drain (every-other-segment "
                f"threshold reached). Got {len(gap_fill_tx)} TX frames."
            ),
        )
        cumulative_ack = self._parse_tx(gap_fill_tx[0])
        self._assert_segment(
            cumulative_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1 + 2 * 1460,
            payload=b"",
            mss=None,
            wscale=None,
            # Advertised window reflects '_rx_buffer' occupancy per
            # RFC 9293 §3.8.6: 65535 max minus the 2 * 1460 bytes
            # delivered to the buffer after the gap-fill drain.
            win=65535 - 2 * 1460,
        )

        # Both payloads delivered in original order.
        self.assertEqual(
            bytes(session._rx_buffer),
            seg1_payload + seg2_payload,
            msg=(
                "After the gap-fill drain, '_rx_buffer' must contain "
                "seg #1 followed by seg #2 in the order the application "
                "intended."
            ),
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1 + 2 * 1460,
            msg=("RCV.NXT must advance past BOTH segments after the " "drain."),
        )
        self.assertEqual(
            session._rcv_una,
            session._rcv_nxt,
            msg=("RCV.UNA must equal RCV.NXT after the inline " "cumulative ACK fires."),
        )
        self.assertEqual(
            session._ooo_packet_queue,
            {},
            msg=("The OOO queue must be empty after the drain - segment " "#2 has been retrieved and processed."),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="OOO handling must not change the session state.",
        )

    def test__data_transfer_out_of_order__multi_gap_delivery_preserves_application_order(self) -> None:
        """
        Ensure the OOO machinery handles MULTIPLE non-contiguous
        gaps in the inbound stream, retaining segments in the OOO
        queue across multiple arrivals and draining them in
        application order once each gap is filled per RFC 9293
        §3.4 / §3.10.7.4.

        Scenario:

            Peer is sending four segments in application order
            (seg1, seg2, seg3, seg4) but they arrive at the
            receiver in the network order [seg2, seg4, seg1,
            seg3]. The receiver therefore sees TWO simultaneous
            gaps after seg2 and seg4 arrive (gap at RCV.NXT, plus
            gap between seg2's tail and seg4's head); only after
            seg1 fills the first gap and seg3 fills the second
            do all four segments drain to the application in
            their original send order.

            Wire arrivals (each segment is exactly 1460 bytes,
            payload distinguished by a unique fill byte so the
            test can verify ordering byte-for-byte):

                seg2: seq = peer_ISS + 1 + 1460,  payload = b"B"
                seg4: seq = peer_ISS + 1 + 4380,  payload = b"D"
                seg1: seq = peer_ISS + 1,         payload = b"A"
                seg3: seq = peer_ISS + 1 + 2920,  payload = b"C"

        Stages and asserted invariants:

            After seg2 arrives:
                - OOO queue: { peer_ISS+1+1460: seg2 }
                - RCV.NXT  : peer_ISS + 1 (unchanged)
                - rx_buffer: empty
                - 1 dup-ACK fires pointing at the missing
                  RCV.NXT.

            After seg4 arrives:
                - OOO queue: { peer_ISS+1+1460: seg2,
                               peer_ISS+1+4380: seg4 }
                - RCV.NXT  : still peer_ISS + 1
                - rx_buffer: empty
                - 1 dup-ACK fires pointing at the missing
                  RCV.NXT.
                - The 'seg2/seg4' OOO queue keys remain
                  distinct - the second OOO arrival did NOT
                  overwrite the first.

            After seg1 arrives (fills first gap):
                - seg1 is processed via '_process_ack_packet';
                  the recursive 'pop(self._rcv_nxt, None)' drain
                  retrieves seg2 at the new RCV.NXT and
                  processes it; seg4's queue entry remains
                  because RCV.NXT is now peer_ISS+1+2*1460,
                  which does NOT equal peer_ISS+1+4380.
                - rx_buffer: seg1_payload + seg2_payload
                - RCV.NXT  : peer_ISS + 1 + 2*1460
                - OOO queue: { peer_ISS+1+4380: seg4 }
                - 1 cumulative ACK covering seg1+seg2.

            After seg3 arrives (fills second gap):
                - seg3 is processed; the recursive drain
                  retrieves seg4 at the new RCV.NXT.
                - rx_buffer: seg1+seg2+seg3+seg4 (all four
                  payloads in send order).
                - RCV.NXT  : peer_ISS + 1 + 4*1460
                - OOO queue: empty.
                - 1 cumulative ACK covering seg3+seg4.

        State stays ESTABLISHED throughout.

        This test passes on current code: the OOO queue is keyed
        by raw 'tcp__seq', distinct gap segments end up in
        separate dictionary entries, and the recursive drain in
        '_process_ack_packet' correctly retrieves only the
        contiguous run starting at the freshly-advanced RCV.NXT.
        The test serves as a regression guard against changes
        that might (a) replace OOO storage with a single-slot
        buffer, (b) break the recursive-drain logic, or (c) lose
        track of distinct OOO segments under retransmit.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        seg1_payload = b"A" * 1460
        seg2_payload = b"B" * 1460
        seg3_payload = b"C" * 1460
        seg4_payload = b"D" * 1460
        seg2_seq = PEER__ISS + 1 + 1460
        seg3_seq = PEER__ISS + 1 + 2 * 1460
        seg4_seq = PEER__ISS + 1 + 3 * 1460

        def _build(seq: int, payload: bytes) -> bytes:
            """Helper: build a peer data segment at the given seq."""
            return build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=seq,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                payload=payload,
                win=PEER__WIN,
            )

        # Stage A: seg2 arrives first (OOO).
        tx_a = self._drive_rx(frame=_build(seg2_seq, seg2_payload))
        self.assertEqual(len(tx_a), 1, msg="seg2 OOO arrival must trigger one dup-ACK.")
        self.assertEqual(
            self._parse_tx(tx_a[0]).ack,
            PEER__ISS + 1,
            msg="seg2 dup-ACK must point at still-missing RCV.NXT = peer_ISS + 1.",
        )
        self.assertIn(seg2_seq, session._ooo_packet_queue, msg="seg2 must be stored in OOO queue.")
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1,
            msg="RCV.NXT must NOT advance on the seg2 OOO arrival.",
        )

        # Stage B: seg4 arrives second (also OOO, distinct gap).
        tx_b = self._drive_rx(frame=_build(seg4_seq, seg4_payload))
        self.assertEqual(len(tx_b), 1, msg="seg4 OOO arrival must trigger one dup-ACK.")
        self.assertEqual(
            self._parse_tx(tx_b[0]).ack,
            PEER__ISS + 1,
            msg="seg4 dup-ACK must point at still-missing RCV.NXT = peer_ISS + 1.",
        )
        self.assertIn(seg2_seq, session._ooo_packet_queue, msg="seg2 must remain in OOO queue after seg4 arrives.")
        self.assertIn(seg4_seq, session._ooo_packet_queue, msg="seg4 must be stored in OOO queue.")
        self.assertEqual(
            len(session._ooo_packet_queue),
            2,
            msg=(
                "OOO queue must hold both seg2 and seg4 as distinct "
                "entries; their keys (peer_ISS+1+1460 vs "
                "peer_ISS+1+4380) must not collide."
            ),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            b"",
            msg="rx_buffer must remain empty while there is a gap at RCV.NXT.",
        )

        # Stage C: seg1 arrives, fills first gap. seg2 drains. seg4
        # remains in OOO queue (RCV.NXT is now at peer_ISS+1+2*1460,
        # not peer_ISS+1+4380).
        tx_c = self._drive_rx(frame=_build(PEER__ISS + 1, seg1_payload))
        self.assertEqual(
            len(tx_c),
            1,
            msg=(
                "seg1 gap-fill drains seg2 too (2 segments processed); "
                "the every-other-segment threshold fires one cumulative "
                "ACK."
            ),
        )
        self.assertEqual(
            self._parse_tx(tx_c[0]).ack,
            PEER__ISS + 1 + 2 * 1460,
            msg="Cumulative ACK after seg1+seg2 drain must cover both.",
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            seg1_payload + seg2_payload,
            msg="rx_buffer must hold seg1 followed by seg2 in send order.",
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1 + 2 * 1460,
            msg="RCV.NXT must equal peer_ISS + 1 + 2*MSS after the seg1+seg2 drain.",
        )
        self.assertNotIn(
            seg2_seq,
            session._ooo_packet_queue,
            msg="seg2 must have been removed from the OOO queue during the drain.",
        )
        self.assertIn(
            seg4_seq,
            session._ooo_packet_queue,
            msg=("seg4 must REMAIN in the OOO queue - the seg3 gap is " "still present so seg4 cannot drain yet."),
        )

        # Stage D: seg3 arrives, fills second gap. seg4 drains.
        tx_d = self._drive_rx(frame=_build(seg3_seq, seg3_payload))
        self.assertEqual(
            len(tx_d),
            1,
            msg=("seg3 gap-fill drains seg4 too; the every-other-segment " "threshold fires one cumulative ACK."),
        )
        self.assertEqual(
            self._parse_tx(tx_d[0]).ack,
            PEER__ISS + 1 + 4 * 1460,
            msg="Cumulative ACK after seg3+seg4 drain must cover everything received.",
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            seg1_payload + seg2_payload + seg3_payload + seg4_payload,
            msg=(
                "rx_buffer must hold all four payloads in their original "
                "application order (A, B, C, D) regardless of the "
                "out-of-order arrival sequence on the wire."
            ),
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1 + 4 * 1460,
            msg="RCV.NXT must equal peer_ISS + 1 + 4*MSS after all four segments drain.",
        )
        self.assertEqual(
            session._ooo_packet_queue,
            {},
            msg="OOO queue must be empty after the final drain.",
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Multi-gap OOO handling must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_out_of_order__overlapping_segment_keeps_new_bytes_only(self) -> None:
        """
        Ensure that a segment whose SEQ lies BEFORE 'RCV.NXT' but
        whose tail extends PAST 'RCV.NXT' is not rejected outright;
        instead the receiver discards the already-received prefix,
        accepts the new tail bytes, advances 'RCV.NXT' accordingly,
        and acknowledges the new boundary, per RFC 9293 §3.10.7.4
        sequence-acceptability rules and §3.4 receive-window
        semantics.

        Concretely, RFC 9293 §3.10.7.4 mandates:

            "A receiver should be tolerant of overlap in segments
             since it is now acceptable for a sender to retransmit
             data with overlap. The receiver should accept the
             segment if any portion of the segment falls within the
             receive window."

        Overlapping segments arise legitimately when:

          - The sender retransmits a segment whose ACK was lost,
            then continues sending fresh data; on a network with
            reordering, the retransmit may arrive at the receiver
            with one combined segment whose head overlaps the
            previously-acked region.
          - A path with re-segmentation (such as a middlebox
            doing TCP normalization) merges two segments into one
            larger frame whose seq covers ground we have already
            processed.

        In all such cases the receiver MUST keep the connection
        making forward progress by accepting the new tail bytes
        rather than silently dropping the whole segment - dropping
        would force the sender to retry, wasting a full RTO.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Peer sends 5 bytes (b"hello") at seq = PEER__ISS + 1.
               Drive RX. Data is delivered to '_rx_buffer'; RCV.NXT
               advances to PEER__ISS + 6. No inline ACK (delayed
               via the timer).
            3. Peer sends an OVERLAPPING segment: seq = PEER__ISS + 1
               (covers the already-received b"hello") with payload
               b"hello world" (11 bytes total = 5 overlap + 6 new).
               Drive RX.
            4. Per RFC: the receiver discards the first 5 bytes
               (already in '_rx_buffer'), enqueues only the new 6
               bytes (b" world"), advances RCV.NXT to PEER__ISS +
               12, and emits an inline ACK acknowledging the new
               boundary.

        Required wire shape of the inline ACK:

            sport     = STACK__PORT
            dport     = PEER__PORT
            seq       = LOCAL__ISS + 1
            ack       = PEER__ISS + 12   (= old RCV.NXT + 6 new bytes)
            flags     = {ACK}
            payload   = b""

        Side effects asserted:

            * '_rx_buffer' equals b"hello world" - the overlap
              prefix was discarded so we do NOT see double-enqueuing
              of b"hello".
            * 'RCV.NXT' equals PEER__ISS + 12.
            * 'RCV.UNA' equals 'RCV.NXT' after the inline ACK
              (since the every-other-segment counter forces an
              inline ACK at 2 segments).
            * State remains ESTABLISHED.

        [FLAGS BUG] - RFC 9293 §3.10.7.4 deviation
        ----------------------------------------------------------
        '_tcp_fsm_established's receive-window guard:

            if packet_rx_md and not self._rcv_nxt
                <= packet_rx_md.tcp__seq
                <= self._rcv_nxt + self._rcv_wnd - len(...):
                ... drop ...
                return

        Requires 'RCV.NXT <= SEG.SEQ', so any segment with SEQ <
        RCV.NXT is rejected outright - regardless of whether its
        tail extends past RCV.NXT and would have delivered new
        bytes. The function returns silently with no outbound
        segment; the sender is given no signal of receipt of the
        overlap.

        Worse, even if the data branch could be reached for an
        overlap segment, '_process_ack_packet' assigns

            self._rcv_nxt = (
                packet_rx_md.tcp__seq
                + len(packet_rx_md.tcp__data)
                + packet_rx_md.tcp__flag_syn
                + packet_rx_md.tcp__flag_fin
            )

        UNCONDITIONALLY - it does not max with the existing
        RCV.NXT, so a stale-duplicate segment whose tail STILL
        does not reach RCV.NXT would actually REWIND RCV.NXT
        backwards, corrupting the connection's seq tracking.
        That second bug is masked today by the window-guard's
        outright drop, but a fix that simply lifts the guard
        without fixing the assignment would expose it.

        This test is expected to FAIL on current code with zero
        outbound segments and an unchanged '_rx_buffer'. Fixing
        it requires:

          (a) Relaxing the window guard to accept any segment
              whose '[SEQ, SEQ+LEN)' interval overlaps the
              receive window '[RCV.NXT, RCV.NXT + RCV.WND)'
              (per RFC 9293 §3.10.7.4 acceptability table).
          (b) In '_process_ack_packet' (or before calling it),
              if 'SEQ < RCV.NXT', slicing the payload to start
              at 'RCV.NXT - SEQ' so only the new bytes are
              enqueued.
          (c) Changing the RCV.NXT assignment to use 'max(...)'
              so a stale duplicate cannot rewind RCV.NXT.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Stage 1: peer sends an in-order 5-byte segment.
        first_payload = b"hello"
        self._drive_rx(
            frame=build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                payload=first_payload,
                win=PEER__WIN,
            )
        )

        self.assertEqual(
            bytes(session._rx_buffer),
            first_payload,
            msg="Setup precondition: first 5 bytes must be in '_rx_buffer'.",
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1 + len(first_payload),
            msg="Setup precondition: RCV.NXT must advance past the first segment.",
        )

        # Stage 2: peer sends an OVERLAPPING segment. seq is back at
        # PEER__ISS+1 (covering the already-received b"hello") but
        # the payload extends past the previous tail by 6 new bytes.
        overlap_payload = b"hello world"
        new_bytes = overlap_payload[len(first_payload) :]
        self.assertEqual(new_bytes, b" world", msg="Test arithmetic: new tail bytes must be b' world'.")

        overlap_segment = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            payload=overlap_payload,
            win=PEER__WIN,
        )
        inline_tx = self._drive_rx(frame=overlap_segment)

        # Per RFC 9293 §3.10.7.4 the receiver must accept the new
        # tail bytes and emit an inline ACK acknowledging the new
        # boundary.
        self.assertEqual(
            len(inline_tx),
            1,
            msg=(
                "An overlapping segment whose tail extends past "
                "RCV.NXT must elicit exactly one inline ACK "
                f"acknowledging the new boundary. Got {len(inline_tx)} "
                "TX frames."
            ),
        )

        ack = self._parse_tx(inline_tx[0])
        self._assert_segment(
            ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1 + len(overlap_payload),
            payload=b"",
            mss=None,
            wscale=None,
            # Advertised window reflects '_rx_buffer' occupancy per
            # RFC 9293 §3.8.6: 65535 max minus the 11 bytes of
            # 'b"hello world"' now in the buffer (the overlap
            # prefix is sliced away, not double-enqueued).
            win=65535 - len(overlap_payload),
        )

        # The receive buffer must contain exactly the original 5
        # bytes followed by the 6 new bytes - the overlap region
        # is discarded so no duplication of b"hello".
        self.assertEqual(
            bytes(session._rx_buffer),
            overlap_payload,
            msg=(
                "After the overlap, '_rx_buffer' must contain the "
                "11 bytes of b'hello world' exactly - the overlap "
                "region (the first 5 bytes that match what was "
                "already received) must be discarded, not "
                "double-enqueued."
            ),
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1 + len(overlap_payload),
            msg=("RCV.NXT must advance to peer_ISS + 1 + 11 after " "consuming the overlap segment's new tail bytes."),
        )
        self.assertEqual(
            session._rcv_una,
            session._rcv_nxt,
            msg=(
                "RCV.UNA must equal RCV.NXT after the inline ACK fires "
                "- the every-other-segment threshold (count == 2 "
                "across the original segment + the overlap) forces "
                "the inline ACK."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Overlap handling must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_out_of_order__five_ooo_segments_emit_at_least_three_dup_acks(self) -> None:
        """
        Ensure that when the peer delivers a burst of out-of-order
        segments past a single gap, PyTCP-as-receiver emits AT LEAST
        three duplicate ACKs at the still-expected RCV.NXT - the
        threshold required to trigger peer's RFC 5681 §3.2 fast-
        retransmit. RFC 5681 §4.2 "Generating Acknowledgments" is
        explicit on the receiver-side requirement:

            "A TCP receiver MUST send an immediate duplicate ACK when
             an out-of-order segment arrives. The purpose of this ACK
             is to inform the sender that a segment was received out
             of order and which sequence number is expected. ... This
             ACK should not be delayed."

        and RFC 5681 §3.2 "Fast Retransmit/Fast Recovery" pins the
        sender-side threshold:

            "When the third duplicate ACK is received, a TCP MUST
             set ssthresh ... and retransmit what appears to be the
             missing segment."

        Without at least three dup-ACKs from the receiver, the sender
        peer cannot trigger fast-retransmit and must wait for the
        retransmit timeout (RTO) - typically 1 second on the first
        loss, growing exponentially via RFC 6298 back-off. The
        per-loss recovery delay drops by ~1-2 orders of magnitude
        when fast-retransmit is reachable, so the threshold is
        load-bearing for any workload where loss is non-zero (lossy
        WAN, mobile / wireless, congested links).

        [FLAGS BUG] - 'TcpSession._tcp_fsm_established' line ~2347
        in the OOO-segment branch caps outbound dup-ACKs at 2 per
        gap via the '_rx_retransmit_request_counter[rcv_nxt] <= 2'
        gate:

            self._rx_retransmit_request_counter[self._rcv_nxt] = (
                self._rx_retransmit_request_counter.get(self._rcv_nxt, 0) + 1
            )
            if self._rx_retransmit_request_counter[self._rcv_nxt] <= 2:
                self._transmit_packet(flag_ack=True)

        The cap is documented in the inline comment at line 432-434
        as intentional ("Keeps track of us sending 'fast retransmit
        request' packets so we can limit their count to 2"), but the
        threshold is wrong: peer needs 3 dup-ACKs, not 2. The
        asymmetry is internally inconsistent - PyTCP's own sender-
        side count-trigger at '_retransmit_packet_request' line ~2293
        correctly fires on the THIRD dup-ACK
        ('count_trigger = ... == 3'), so PyTCP-as-sender expects 3
        from peer but PyTCP-as-receiver emits at most 2 to peer.

        SACK does not save the gap either. Each of the 2 emitted
        ACKs carries a SACK option block reflecting what is in our
        OOO queue at the time:

          - 1st ACK: SACK block for {seg1}.
          - 2nd ACK: SACK blocks for {seg1, seg2}.
          - (counter > 2: no further ACKs, no further SACK
            information delivered to peer.)

        Peer's RFC 6675 §3 IsLost() byte rule fires when MORE THAN
        '(DupThresh - 1) * SMSS' bytes are reported SACKed. With
        DupThresh = 3 and SMSS = 1460, that's > 2920 bytes. With at
        most 2 full-MSS segments reported (= 2920 bytes exactly,
        not strictly more), the byte rule does not fire either.
        Peer falls back to RTO regardless of SACK negotiation.

        Severity: HIGH performance impact. Affects every PyTCP-as-
        receiver connection on a lossy link. The bug only "hides"
        in lossless test environments where the OOO branch is
        rarely exercised.

        Fix outline (separate commit): remove the cap-at-2 gate
        entirely. The OOO segments are naturally rate-limited by
        peer's send cadence (peer emits at most one segment per
        SMSS-worth of cwnd), so PyTCP's outbound dup-ACKs cannot
        exceed peer's outbound segment rate; there is no ACK-flood
        risk to mitigate. The '_rx_retransmit_request_counter' dict
        and its purge-on-cum-ACK plumbing become dead state and can
        be removed in the same commit.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Disable bilateral SACK to focus on the count-based
               RFC 5681 §3.2 path (the SACK byte-rule analysis above
               applies independently; this test pins the count
               path).
            3. Peer delivers 5 OOO segments past the gap at
               RCV.NXT = PEER__ISS + 1 (gap = 1000 bytes; each OOO
               segment is 100 bytes at offsets 1000, 1100, 1200,
               1300, 1400 past PEER__ISS + 1).
            4. Count outbound ACK frames carrying ack ==
               PEER__ISS + 1 (the still-expected RCV.NXT).

        Assertions:

            * Outbound dup-ACK count >= 3.
            * Each outbound dup-ACK has the canonical shape:
              flags={"ACK"}, ack=PEER__ISS+1, seq=LOCAL__ISS+1,
              payload=b"".
            * State stays ESTABLISHED.

        On current code this test fails: only 2 dup-ACKs are
        emitted (the cap-at-2 logic), peer's fast-retransmit cannot
        trigger, peer falls back to RTO. The number-of-dup-ACKs
        assertion is what fires.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Pin the count-based path: disable bilateral SACK so the SACK
        # byte-rule analysis is out of scope for this test. The same
        # cap-at-2 gate would inhibit SACK byte-rule recovery too, but
        # the count-rule is the cleaner failure to pin first.
        session._send_sack = False
        # Clear handshake-residual frames (our SYN, our third-leg ACK)
        # so 'self._frames_tx' below contains only the OOO-burst's
        # outbound dup-ACKs. The third-leg ACK has the same shape as
        # a dup-ACK ('ack == PEER__ISS + 1, seq == LOCAL__ISS + 1,
        # flags={"ACK"}'), so leaving it in would inflate the count.
        self._frames_tx.clear()

        # 5 OOO segments past a 1000-byte gap, each 100 bytes.
        # RCV.NXT stays at PEER__ISS + 1 throughout (the gap is at
        # the start of peer's stream).
        ooo_segment_count = 5
        gap_size = 1000
        ooo_payload_size = 100

        for i in range(ooo_segment_count):
            seg_seq = PEER__ISS + 1 + gap_size + i * ooo_payload_size
            ooo_seg = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=seg_seq,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
                payload=b"X" * ooo_payload_size,
            )
            self._drive_rx(frame=ooo_seg)

        # Count outbound ACK frames at the still-expected RCV.NXT
        # (= PEER__ISS + 1). Each is a dup-ACK from peer's
        # perspective.
        dup_ack_count = 0
        for frame in self._frames_tx:
            probe = self._parse_tx(frame)
            if probe.ack == PEER__ISS + 1 and probe.seq == LOCAL__ISS + 1:
                self.assertEqual(
                    probe.flags,
                    frozenset({"ACK"}),
                    msg=(
                        "Each outbound dup-ACK during the gap MUST be "
                        "a bare ACK with no other flags set. "
                        f"Got: {probe.flags!r}"
                    ),
                )
                self.assertEqual(
                    probe.payload,
                    b"",
                    msg=(
                        "Each outbound dup-ACK during the gap MUST "
                        "carry no payload (it is a control segment). "
                        f"Got {len(probe.payload)} bytes."
                    ),
                )
                dup_ack_count += 1

        self.assertGreaterEqual(
            dup_ack_count,
            3,
            msg=(
                "Per RFC 5681 §4.2, the receiver MUST send an "
                "immediate duplicate ACK on every out-of-order "
                "segment arrival, and per RFC 5681 §3.2 the sender "
                "peer requires at least 3 duplicate ACKs to trigger "
                "fast-retransmit. With "
                f"{ooo_segment_count} OOO segments delivered past "
                "the gap, the receiver MUST emit at least 3 "
                "duplicate ACKs at the still-expected RCV.NXT. "
                "Today '_tcp_fsm_established' line ~2347 caps the "
                "count at 2 via "
                "'_rx_retransmit_request_counter[rcv_nxt] <= 2'; "
                "peer's fast-retransmit never fires from PyTCP-"
                "generated dup-ACKs and peer must wait for RTO. Fix: "
                "remove the cap-at-2 gate; OOO arrivals are rate-"
                "limited by peer's send cadence and cannot flood. "
                f"Got dup-ACK count: {dup_ack_count}."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="OOO-burst handling must not transition the session out of ESTABLISHED.",
        )
