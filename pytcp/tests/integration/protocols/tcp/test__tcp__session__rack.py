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

        # Send three back-to-back payloads. Each tick fires one
        # segment, so three advances drive three segments out.
        payloads = [b"alpha", b"beta!", b"gamma"]
        for payload in payloads:
            session.send(data=payload)
            self._advance(ms=1)

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
        total_payload_len = sum(len(p) for p in payloads)
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
