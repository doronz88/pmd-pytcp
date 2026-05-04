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
This module contains integration tests for the RFC 8985 RACK
per-segment xmit_ts substrate (Phase 1 of
'.claude/rules/tcp_rack_tlp.md').

RFC 8985 §5.2 specifies a per-segment 'Segment' tuple holding:

    Segment.xmit_ts        most-recent transmission time
    Segment.end_seq        seq + payload length
    Segment.retransmitted  True iff this segment has ever been
                           retransmitted
    Segment.lost           True iff RACK has declared the segment
                           lost

Phase 1 lands the storage substrate plus two hooks:

    _transmit_packet            inserts a 'RackSegment' for every
                                outbound segment that consumes
                                sequence space (data / SYN / FIN).
    _process_ack_packet         prunes entries whose 'end_seq' has
                                been covered by SND.UNA (modular).

Subsequent phases (RACK Step 1-5, TLP, RTO integration) consume
the dict; Phase 1 only provides the substrate so those phases
can build on top.

Reference RFCs:
    RFC 8985 §5.2   Per-Segment Variables
    RFC 8985 §6.1   Transmitting a data segment
    RFC 9293 §3.4   Modular sequence-number arithmetic

pytcp/tests/integration/protocols/tcp/test__tcp__session__rack.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.tcp__rack import RackSegment
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

# Initial sequence numbers, well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN+ACK reply (1500 - 20 IPv4 - 20 TCP).
PEER__MSS: int = 1460


class TestTcpRackPhase1(TcpSessionTestCase):
    """
    Integration tests for the RFC 8985 §5.2 / §6.1 per-segment
    xmit_ts substrate: dict storage on outbound segments and
    cum-ACK pruning on inbound ACKs.
    """

    def _make_active_session(self, *, iss: int) -> TcpSession:
        """
        Build a 'TcpSocket' / 'TcpSession' pair the way
        'TcpSocket.connect()' would. Returns the session in
        CLOSED state.
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
        Drive the active-open three-way handshake to ESTABLISHED
        and bypass slow-start so the data tests can fire at the
        full advertised window.
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
        session._snd_ewn = PEER__WIN
        return session

    def test__rack__outbound_data_segment_records_rack_segment(self) -> None:
        """
        Ensure that an outbound data segment in ESTABLISHED
        records a 'RackSegment' in 'session._rack_segments'
        keyed by the segment's starting seq, with 'end_seq'
        equal to seq + payload length and 'xmit_ts' equal to
        the virtual clock at the moment the segment fired.

        Reference: RFC 8985 §5.2 (Per-Segment Variables).
        Reference: RFC 8985 §6.1 (Transmitting a data segment).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        payload = b"hello, world!"
        send_seq = session._snd_nxt
        session.send(data=payload)
        send_tick_now_ms = self._timer.now_ms + 1
        self._advance(ms=1)

        self.assertIn(
            send_seq,
            session._rack_segments,
            msg=(
                "An outbound data segment MUST record a 'RackSegment' "
                "entry keyed by the segment's starting seq. Got dict keys: "
                f"{sorted(session._rack_segments)!r}."
            ),
        )

        seg = session._rack_segments[send_seq]
        self.assertIsInstance(
            seg,
            RackSegment,
            msg=(
                "'_rack_segments' values MUST be 'RackSegment' instances "
                "(the typed RFC 8985 §5.2 'Segment' tuple), not bare tuples "
                f"or dicts. Got {type(seg)!r}."
            ),
        )
        self.assertEqual(
            seg.end_seq,
            send_seq + len(payload),
            msg=(
                "RFC 8985 §5.2 'Segment.end_seq' MUST equal "
                f"seq + payload_length. Expected {send_seq + len(payload)}, "
                f"got {seg.end_seq}."
            ),
        )
        self.assertEqual(
            seg.xmit_ts,
            send_tick_now_ms,
            msg=(
                "RFC 8985 §5.2 'Segment.xmit_ts' MUST equal the "
                "virtual clock at the moment '_transmit_packet' "
                f"fired the segment. Expected {send_tick_now_ms}, "
                f"got {seg.xmit_ts}."
            ),
        )
        self.assertFalse(
            seg.lost,
            msg=(
                "A freshly-transmitted segment MUST NOT be marked "
                "lost; 'Segment.lost' is set only by Phase 3 "
                "time-based loss detection."
            ),
        )

    def test__rack__cumulative_ack_prunes_acked_segments(self) -> None:
        """
        Ensure that a cumulative ACK that covers all in-flight
        segments removes their 'RackSegment' entries from the
        dict, keeping the substrate consistent with the wire
        state (no acked segment is "in flight").

        Reference: RFC 8985 §6.1 (xmit_ts dict pruned on cum-ACK).
        Reference: RFC 9293 §3.4 (modular sequence comparison).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Push 3 * PEER__MSS bytes so the TX path emits three
        # full MSS segments on three consecutive ticks (one
        # segment per ms tick is the FSM cadence post-handshake
        # with the wide '_snd_ewn'). Distinct seqs keep
        # 'session._rack_segments' populated with three entries.
        total_payload_len = 3 * PEER__MSS
        session.send(data=b"x" * total_payload_len)
        self._advance(ms=3)

        # Setup invariant: three segments in the dict.
        self.assertEqual(
            len(session._rack_segments),
            3,
            msg=(
                "Setup invariant: three outbound data segments must "
                "produce three 'RackSegment' entries. Got "
                f"{len(session._rack_segments)} entries: "
                f"{sorted(session._rack_segments)!r}."
            ),
        )

        # Peer cum-ACKs everything in one shot.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + total_payload_len,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._rack_segments,
            {},
            msg=(
                "A cum-ACK that covers all in-flight segments MUST "
                "prune their entries from '_rack_segments'. Got "
                f"surviving entries: {sorted(session._rack_segments)!r}."
            ),
        )


class TestTcpRackPhase2(TcpSessionTestCase):
    """
    Integration tests for the RFC 8985 §6.2 step 1-2 update on
    'TcpSession._rack_xmit_ts' / '_rack_end_seq' / '_rack_rtt_ms'
    / '_rack_min_rtt_ms' driven by inbound ACKs.
    """

    def _make_active_session(self, *, iss: int) -> TcpSession:
        """
        Build a 'TcpSocket' / 'TcpSession' pair the way
        'TcpSocket.connect()' would. Returns the session in
        CLOSED state.
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
        Drive the active-open three-way handshake to ESTABLISHED
        and bypass slow-start.
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
        session._snd_ewn = PEER__WIN
        return session

    def test__rack__cum_ack_updates_rack_xmit_ts_and_rtt(self) -> None:
        """
        Ensure that a cum-ACK covering an in-flight segment
        advances '_rack_xmit_ts' to the segment's xmit_ts,
        '_rack_end_seq' to the segment's end_seq, and
        '_rack_rtt_ms' to the observed RTT.

        Reference: RFC 8985 §6.2 (RACK.xmit_ts / RACK.end_seq / RACK.rtt update).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        payload = b"hello, world!"
        send_seq = session._snd_nxt
        session.send(data=payload)
        send_tick_now_ms = self._timer.now_ms + 1
        self._advance(ms=1)

        # Allow some elapsed time before the ACK to produce a
        # measurable RTT.
        self._advance(ms=9)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        observed_rtt_ms = self._timer.now_ms - send_tick_now_ms

        self.assertEqual(
            session._rack_xmit_ts,
            send_tick_now_ms,
            msg=(
                "'_rack_xmit_ts' MUST advance to the acked "
                f"segment's xmit_ts. Expected {send_tick_now_ms}, "
                f"got {session._rack_xmit_ts}."
            ),
        )
        self.assertEqual(
            session._rack_end_seq,
            send_seq + len(payload),
            msg=(
                "'_rack_end_seq' MUST equal the acked segment's "
                f"end_seq. Expected {send_seq + len(payload)}, "
                f"got {session._rack_end_seq}."
            ),
        )
        self.assertEqual(
            session._rack_rtt_ms,
            observed_rtt_ms,
            msg=(
                "'_rack_rtt_ms' MUST equal the observed RTT. "
                f"Expected {observed_rtt_ms}, got {session._rack_rtt_ms}."
            ),
        )

    def test__rack__retransmit_with_stale_rtt_skipped(self) -> None:
        """
        Ensure that a retransmitted segment whose freshly-
        observed rtt is below '_rack_min_rtt_ms' (RFC 8985
        §6.2 step 2 condition 2) does not poison the RACK
        scalars - the rtt is silently discarded.

        Reference: RFC 8985 §6.2 (Karn-style guard: rtt < min_rtt skip).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Send + ACK a first payload at long RTT so '_rack_min_rtt_ms'
        # is seeded above 0.
        first_payload = b"hello"
        session.send(data=first_payload)
        first_send_now_ms = self._timer.now_ms + 1
        self._advance(ms=1)
        self._advance(ms=99)
        first_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(first_payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=first_ack)

        prior_min_rtt = session._rack_min_rtt_ms
        prior_rack_rtt = session._rack_rtt_ms
        self.assertGreater(
            prior_min_rtt,
            0,
            msg=(
                "Setup invariant: the first ACK MUST have seeded "
                "'_rack_min_rtt_ms' above zero so the next ACK has "
                f"a baseline. Got {prior_min_rtt}; first send "
                f"@{first_send_now_ms}."
            ),
        )

        # Now hand-craft a retransmitted RackSegment with rtt
        # well below '_rack_min_rtt_ms' so the rack_update Karn
        # guard fires. We simulate via direct-injection rather
        # than driving an actual retransmit path, since Phase 2
        # only tests the update logic.
        rt_seq = session._snd_nxt
        rt_xmit_ts = self._timer.now_ms - (prior_min_rtt // 2)  # rtt = prior_min_rtt//2 < prior_min_rtt
        session._rack_segments[rt_seq] = RackSegment(
            end_seq=rt_seq + 5,
            xmit_ts=rt_xmit_ts,
            retransmitted=True,
            lost=False,
        )
        session._snd_nxt = rt_seq + 5
        session._snd_max = rt_seq + 5

        # ACK that covers the retransmit.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=rt_seq + 5,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        # The retransmit's rtt was below min_rtt, so RACK
        # scalars must be unchanged.
        self.assertEqual(
            session._rack_min_rtt_ms,
            prior_min_rtt,
            msg=(
                "RFC 8985 §6.2 step 2 condition 2: a retransmit "
                "with 'rtt < min_rtt' MUST be skipped, leaving "
                "'_rack_min_rtt_ms' unchanged."
            ),
        )
        self.assertEqual(
            session._rack_rtt_ms,
            prior_rack_rtt,
            msg=("RFC 8985 §6.2 step 2 condition 2: a skipped " "retransmit MUST NOT update '_rack_rtt_ms'."),
        )

    def test__rack__min_rtt_tracks_smallest_observed(self) -> None:
        """
        Ensure '_rack_min_rtt_ms' tracks the minimum across
        successive ACKs, falling when a new smaller RTT is
        observed.

        Reference: RFC 8985 §B.1 (min_RTT minimum tracking).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # First send + slow ACK -> high RTT.
        first_payload = b"slow!"
        session.send(data=first_payload)
        self._advance(ms=1)
        self._advance(ms=99)
        first_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(first_payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=first_ack)
        first_min_rtt = session._rack_min_rtt_ms

        # Second send + faster ACK -> lower RTT.
        second_payload = b"fast!"
        session.send(data=second_payload)
        self._advance(ms=1)
        self._advance(ms=9)
        second_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(first_payload) + len(second_payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=second_ack)

        self.assertLess(
            session._rack_min_rtt_ms,
            first_min_rtt,
            msg=(
                "'_rack_min_rtt_ms' MUST drop when a smaller RTT "
                f"is observed. Was {first_min_rtt}, expected "
                f"smaller; got {session._rack_min_rtt_ms}."
            ),
        )


class TestTcpRackPhase3(TcpSessionTestCase):
    """
    Integration tests for the RFC 8985 §6.2 step 5 time-based
    loss detection: a segment marked lost when a later-sent
    segment was delivered (cum-ACKed or SACKed) and reo_wnd
    has elapsed.
    """

    def _make_active_session(self, *, iss: int) -> TcpSession:
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
        session._snd_ewn = PEER__WIN
        return session

    def test__rack__time_based_loss_detection_marks_old_segment_lost(self) -> None:
        """
        Ensure that when peer SACKs a later-sent segment but
        the earlier segment is the gap, RACK time-based loss
        detection marks the earlier segment lost (its
        'xmit_ts' replaced with INFINITE_TS, 'lost = True').

        Reference: RFC 8985 §6.2 step 5 (time-based loss detection).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Send 2 * MSS so two distinct segments fire on
        # consecutive ticks. The first segment lives at seq
        # LOCAL__ISS + 1; the second at LOCAL__ISS + 1 + MSS.
        session.send(data=b"x" * (2 * PEER__MSS))
        self._advance(ms=2)
        self.assertEqual(
            len(session._rack_segments),
            2,
            msg=f"Setup invariant: two segments in flight. Got: {sorted(session._rack_segments)}.",
        )

        first_seg_seq = LOCAL__ISS + 1
        second_seg_seq = LOCAL__ISS + 1 + PEER__MSS
        # Allow elapsed time so the SACKed segment will give RACK.xmit_ts > first_seg.xmit_ts.
        self._advance(ms=10)

        # Peer SACKs only the SECOND segment (range [second_seg_seq, second_seg_seq + MSS]).
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,  # cum-ACK does not advance
            flags=("ACK",),
            win=PEER__WIN,
            sack_blocks=[(second_seg_seq, second_seg_seq + PEER__MSS)],
        )
        self._drive_rx(frame=peer_ack)

        first_seg = session._rack_segments.get(first_seg_seq)
        self.assertIsNotNone(
            first_seg,
            msg="Setup invariant: first segment must remain in dict (not cum-ACKed).",
        )
        assert first_seg is not None
        self.assertTrue(
            first_seg.lost,
            msg=(
                "RFC 8985 §6.2 step 5: a segment whose later sibling has "
                "been SACK-acked AND reo_wnd elapsed MUST be marked lost. "
                f"Got first_seg={first_seg!r}."
            ),
        )
