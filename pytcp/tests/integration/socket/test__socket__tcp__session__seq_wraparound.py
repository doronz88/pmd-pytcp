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
This module contains integration tests for 32-bit TCP sequence-
number wraparound in the 'TcpSession' state machine. Per RFC 9293
§3.4 sequence numbers are 32-bit unsigned integers that wrap
modulo 2**32. Production code in 'tcp__session.py' currently uses
plain Python integer arithmetic for sequence updates and plain
'>' / '<=' comparators for ACK acceptability checks; both fail
across the wrap boundary.

The fix is the deferred migration to 'pytcp.lib.tcp_seq's modular
comparators ('lt32', 'le32', 'gt32', 'ge32', 'add32', 'sub32',
'in_range32') that already exist with full unit-test coverage.
This file is the forcing function for that migration.

Test classes (one TestCase per concern, per the project plan §6.12):

    * TestTcpSeqWraparound__Seq      - outbound seq wraps modularly.
    * TestTcpSeqWraparound__Ack      - ACK across wrap accepted /
                                        comparators wrap-aware.
    * TestTcpSeqWraparound__SeqAndAck - both directions wrap.

Reference RFCs:
    RFC 9293 §3.4    Sequence Numbers
    RFC 9293 §3.10.7.4   Synchronized state segment processing
                          (acceptability checks across the wrap)

pytcp/tests/integration/socket/test__socket__tcp__session__seq_wraparound.py

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

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240
PEER__MSS: int = 1460

# 32-bit modular constants. These mirror what 'pytcp.lib.tcp_seq'
# uses; pinning them here keeps the test arithmetic readable.
SEQ32__MAX: int = 0xFFFF_FFFF
SEQ32__MOD: int = 0x1_0000_0000


class TestTcpSeqWraparound__Seq(TcpSessionTestCase):
    """
    Tests for outbound sequence-number wrap. Force ISS near the
    32-bit ceiling, drive data, and verify the on-the-wire seq
    numbers wrap modularly (i.e. 0xFFFF_FFFF + 1 == 0, not 2**32).
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
            ack=(iss + 1) % SEQ32__MOD,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert (
            session.state is FsmState.ESTABLISHED
        ), f"Handshake setup failed: state is {session.state!r}, expected ESTABLISHED."
        return session

    def test__seq_wraparound__outbound_data_seq_wraps_modularly(self) -> None:
        """
        Ensure that when 'SND.NXT' crosses the 32-bit ceiling
        (0xFFFF_FFFF -> 0x0000_0000), subsequent outbound segments
        carry SEQ values reduced modulo 2**32 - NOT raw Python
        integers larger than 2**32. Per RFC 9293 §3.4 sequence
        numbers ARE modulo 2**32 by design; treating them as
        unbounded Python ints is a representation bug that surfaces
        the moment the wrap occurs.

        RFC 9293 §3.4 (Sequence Numbers):

            "A fundamental notion in the design is that every
             octet of data sent over a TCP connection has a
             sequence number. ... The TCP MUST also use a 32-bit
             sequence number space (MUST-2). ... Sequence
             numbers are unsigned, 32-bit modular."

        Scenario:

            1. Force the local ISS to '0xFFFF_FFFE' so 'SND.NXT'
               starts very close to the wrap boundary.
            2. Drive the active-open handshake to ESTABLISHED.
               SND.NXT = ISS + 1 = 0xFFFF_FFFF post-handshake.
            3. Application sends 'b"AAAA"' (4 bytes). The first
               outbound data segment carries SEQ = 0xFFFF_FFFF
               (still in 32-bit range). Post-segment, 'SND.NXT'
               should be 'add32(0xFFFF_FFFF, 4) = 3'.
            4. Application sends 'b"BBBB"' (4 more bytes). The
               second outbound segment carries SEQ = 3 (the
               wrapped value), NOT '0x1_0000_0003' which is
               outside the 32-bit range.

        Assertions:

            * Outbound segment #1 carries 'seq = 0xFFFF_FFFF'
              and payload = b"AAAA" (sanity).
            * Outbound segment #2 carries 'seq = 3' and
              payload = b"BBBB" (the spec encoding).
            * 'session._snd_nxt' equals '7' (post-segment-2
              wrapped value), NOT '0x1_0000_0007'.

        [FLAGS BUG] - 'TcpSession._transmit_packet' (line 593)
        updates 'SND.NXT' with raw addition:

            self._snd_nxt = seq + len(data) + flag_syn + flag_fin

        After the first 4-byte send, '_snd_nxt = 0xFFFF_FFFF + 4
        = 0x1_0000_0003' - a value that exceeds the 32-bit
        unsigned range. The next outbound segment passes this
        value as 'seq' to 'send_tcp_packet', which packs it via
        'struct.pack("!I", seq)' inside the assembler. 'struct'
        rejects values >= 2**32 with 'struct.error: ushort
        format requires 0 <= number <= 0xffffffff'.

        On current code this test will fail at step 4 - either
        with 'struct.error' propagating up the send path, or with
        'session._snd_nxt' equal to a value outside the 32-bit
        range. The test wraps the second send in 'try / except'
        so the failure surfaces as a clean unittest assertion
        naming the RFC clause rather than as an opaque
        struct-error traceback.

        The fix is the deferred migration of 'tcp__session.py' to
        the 'pytcp.lib.tcp_seq' modular comparators - replacing
        all 'seq + len + flags' assignments with
        'add32(seq, len + flags)' and all '<' / '<=' comparisons
        on sequence numbers with 'lt32' / 'le32' / etc. The
        helpers and their unit tests already exist (commit
        'f3c9484'); this test (and its sibling tests in
        TestTcpSeqWraparound__Ack and TestTcpSeqWraparound__SeqAndAck)
        is the forcing function for the migration.
        """

        session = self._drive_handshake_to_established(
            iss=0xFFFF_FFFE,
            peer_iss=0x0000_2000,
        )
        # Bypass slow-start so two back-to-back segments fire on
        # consecutive ticks.
        session._snd_ewn = PEER__WIN

        self.assertEqual(
            session._snd_nxt,
            0xFFFF_FFFF,
            msg=(
                "Setup precondition: post-handshake 'SND.NXT' must "
                "equal 'ISS + 1' = 0xFFFF_FFFF (just below the wrap)."
            ),
        )

        # Send #1: 4 bytes at seq 0xFFFF_FFFF. The segment fits the
        # 32-bit field; post-segment, 'SND.NXT' must wrap to 3.
        session.send(data=b"AAAA")
        seg1_tx = self._advance(ms=1)
        self.assertEqual(
            len(seg1_tx),
            1,
            msg="Setup precondition: first send must produce one outbound segment.",
        )
        seg1_probe = self._parse_tx(seg1_tx[0])
        self._assert_segment(
            seg1_probe,
            seq=0xFFFF_FFFF,
            payload=b"AAAA",
        )

        # The spec encoding: post-segment-1 'SND.NXT' wraps modularly.
        self.assertEqual(
            session._snd_nxt,
            (0xFFFF_FFFF + 4) % SEQ32__MOD,
            msg=(
                "After sending 4 bytes from seq=0xFFFF_FFFF, "
                "'SND.NXT' must wrap modulo 2**32 to "
                f"'{(0xFFFF_FFFF + 4) % SEQ32__MOD}' per RFC 9293 "
                "§3.4. Catching '0x1_0000_0003' here means the "
                "raw Python addition leaked past the 32-bit "
                "modular space; the next outbound segment will "
                "fail at 'struct.pack(\"!I\", ...)' on the "
                "non-32-bit value."
            ),
        )

        # Send #2: 4 more bytes. Per spec the segment carries
        # seq = 3 (the wrapped value).
        session.send(data=b"BBBB")
        try:
            seg2_tx = self._advance(ms=1)
        except Exception as exc:  # pylint: disable=broad-except
            self.fail(
                f"Sending across the 32-bit seq wrap raised "
                f"'{type(exc).__name__}: {exc}'. RFC 9293 §3.4 "
                "requires sequence numbers to wrap modulo 2**32; "
                "the production code's raw integer arithmetic at "
                "'tcp__session.py:593' propagates a non-32-bit "
                "value into the assembler's 'struct.pack(\"!I\", "
                "...)' call, which rejects it. Fix: migrate "
                "'tcp__session.py' to use 'pytcp.lib.tcp_seq's "
                "'add32' helper."
            )

        self.assertEqual(
            len(seg2_tx),
            1,
            msg="Second send must produce one outbound segment.",
        )
        seg2_probe = self._parse_tx(seg2_tx[0])
        self._assert_segment(
            seg2_probe,
            seq=3,
            payload=b"BBBB",
        )


class TestTcpSeqWraparound__Ack(TcpSessionTestCase):
    """
    Tests for inbound ACK handling across the 32-bit wrap. The
    'TcpSession.tcp_fsm_established' branches use plain '<' / '<='
    comparators to validate 'SND.UNA <= SEG.ACK <= SND.MAX'; once
    the send-sequence range straddles the 32-bit wrap, those
    plain comparators no longer correctly identify which ACKs are
    in-window.
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
            ack=(iss + 1) % SEQ32__MOD,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert (
            session.state is FsmState.ESTABLISHED
        ), f"Handshake setup failed: state is {session.state!r}, expected ESTABLISHED."
        return session

    def test__seq_wraparound__inbound_ack_across_wrap_advances_snd_una(self) -> None:
        """
        Ensure that a peer ACK whose value is modularly inside
        '[SND.UNA, SND.MAX]' but numerically outside (because the
        range straddles the 32-bit wrap) is accepted as in-window
        and advances 'SND.UNA' modularly to the ack value.

        Setup: pre-position the session's send-sequence state so
        the in-window range crosses the wrap:

            SND.UNA = 0xFFFF_FFFE
            SND.NXT = SND.MAX = 0x0000_0010

        Modularly, this represents 18 bytes of in-flight data
        bridging the wrap (0xFFFF_FFFE -> 0xFFFF_FFFF -> 0x0 ->
        0x10). A peer ACK at 'ack = 0x05' is modularly between
        SND.UNA and SND.MAX (specifically, '7 bytes past
        SND.UNA') and per RFC 9293 §3.10.7.4 must be accepted
        and advance SND.UNA to 0x05.

        Numerically, '0xFFFF_FFFE <= 0x05' is FALSE - the plain
        '<=' comparator wrongly rejects this in-window ACK.

        Scenario:

            1. Drive a normal handshake to ESTABLISHED at a tame
               ISS so the FSM bootstrap is straightforward.
            2. Manually set the send-sequence state to straddle
               the wrap (SND.UNA = 0xFFFF_FFFE, SND.NXT =
               SND.MAX = 0x10). Adjust 'tx_buffer_seq_mod' to
               keep '_tx_buffer_una' bounded to 0 so the buffer-
               purge arithmetic does not blow up on the modular
               input.
            3. Peer sends an ACK at SEQ = peer_iss+1, ack = 0x05.
               Modularly this is 7 bytes past SND.UNA, well within
               the 18-byte in-flight range. RFC 9293 §3.10.7.4
               mandates SND.UNA advance to 0x05.

        Assertions:

            * 'session._snd_una' advances to 0x05 after the peer
              ACK is processed (the spec encoding).
            * 'session.state' remains ESTABLISHED.
            * No outbound 'unacceptable ACK' empty-ACK reply
              fires - the ACK is acceptable.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_established' (line 1456
        and parallel sites) uses raw '<=' comparators:

            if (in_order or overlap_with_new) and \\
               self._snd_una <= packet_rx_md.tcp__ack \\
                              <= self._snd_max:

        With SND.UNA = 0xFFFF_FFFE, SND.MAX = 0x10, and ack = 0x05:

            * '0xFFFF_FFFE <= 0x05' is numerically FALSE.

        so the entire 'and'-chain short-circuits to False. The
        segment falls through the data-handling branch, then
        through the 'ack > SND.MAX' empty-ACK reply check
        ('0x05 > 0x10' = False), and finally returns silently.
        SND.UNA does NOT advance. The peer's data sits unacked
        forever; the connection silently drops on the next RTO.

        On current code this test fails at the
        'session._snd_una == 0x05' assertion - SND.UNA stays at
        0xFFFF_FFFE.

        The fix is the deferred 'tcp_seq' migration: replace
        plain '<=' / '<' / '>' / '>=' comparators on sequence
        numbers with 'le32' / 'lt32' / 'gt32' / 'ge32'. The
        helpers and their unit tests already exist; this test
        is the forcing function for the migration.
        """

        # Drive handshake at a tame ISS so FSM bootstrap is
        # ordinary. We then poke the send-sequence state directly
        # to straddle the wrap.
        session = self._drive_handshake_to_established(
            iss=0x0000_1000,
            peer_iss=0x0000_2000,
        )

        # Pre-position SND.UNA/SND.NXT/SND.MAX to straddle the
        # wrap. The 18-byte in-flight range (0xFFFF_FFFE through
        # 0x10 modularly) is what makes ack = 0x05 a legal
        # in-window value the legacy '<=' check rejects.
        session._snd_una = 0xFFFF_FFFE
        session._snd_nxt = 0x0000_0010
        session._snd_max = 0x0000_0010
        # Keep '_tx_buffer_una = max(_snd_una - _tx_buffer_seq_mod, 0)'
        # bounded to zero so the eventual buffer-purge inside
        # '_process_ack_packet' does not blow up on the modular
        # input.
        session._tx_buffer_seq_mod = 0xFFFF_FFFE

        # Peer sends an in-order ACK at the modularly-acceptable
        # ack = 0x05.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_2001,
            ack=0x0000_0005,
            flags=("ACK",),
            win=PEER__WIN,
        )
        ack_inline = self._drive_rx(frame=peer_ack)

        # The spec encoding: SND.UNA advances modularly.
        self.assertEqual(
            session._snd_una,
            0x0000_0005,
            msg=(
                "Peer's ACK at ack=0x05 with SND.UNA=0xFFFF_FFFE "
                "and SND.MAX=0x10 (range straddling the 32-bit "
                "wrap) MUST be accepted as in-window and SND.UNA "
                "MUST advance modularly to 0x05 per RFC 9293 §3.10.7.4. "
                "Current code's raw '<=' comparator rejects the "
                "ACK because 0xFFFF_FFFE <= 0x05 is numerically "
                "False; SND.UNA stays at 0xFFFF_FFFE and peer's "
                "in-flight data is silently unacknowledged. Fix: "
                "replace '<=' with 'le32' from "
                "'pytcp.lib.tcp_seq'."
            ),
        )

        # Sanity: state still ESTABLISHED, no spurious empty-ACK
        # reply (which would fire if the ACK were classified as
        # 'unacceptable / past SND.MAX').
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED after a legal in-window ACK.",
        )
        self.assertEqual(
            ack_inline,
            [],
            msg=(
                "A legal in-window ACK must produce no outbound "
                "segment - it is processed by the data branch, "
                "not the 'unacceptable ACK' empty-reply path."
            ),
        )


class TestTcpSeqWraparound__SeqAndAck(TcpSessionTestCase):
    """
    Tests for inbound RCV.NXT update across the 32-bit wrap. The
    canonical bidirectional-wrap case combines outbound seq wrap
    (covered by the '__Seq' class) with inbound rcv-side wrap (this
    class) - both directions independently break in the same way:
    raw integer arithmetic that escapes the 32-bit modular space.
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
            ack=(iss + 1) % SEQ32__MOD,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert (
            session.state is FsmState.ESTABLISHED
        ), f"Handshake setup failed: state is {session.state!r}, expected ESTABLISHED."
        return session

    def test__seq_wraparound__inbound_data_seq_wrap_advances_rcv_nxt_modularly(self) -> None:
        """
        Ensure that when peer's send-sequence range straddles the
        32-bit wrap, the receive-side update of 'RCV.NXT' wraps
        modularly. Specifically: peer sends a data segment whose
        '(seq + len)' crosses the 32-bit ceiling, and 'RCV.NXT'
        must advance to the wrapped 'seg_end' value, NOT to a
        non-32-bit Python int.

        RFC 9293 §3.4 (Sequence Numbers):

            "Sequence numbers are unsigned, 32-bit modular."

        Scenario:

            1. Drive an active-open handshake at a tame local ISS
               but with peer's ISS pinned to 0xFFFF_FFFC. Post-
               handshake, RCV.NXT = peer_iss + 1 = 0xFFFF_FFFD.
            2. Peer sends an 8-byte data segment 'b"peer-rcv"' at
               SEQ = 0xFFFF_FFFD. The segment spans the wrap:
               seqs 0xFFFF_FFFD, 0xFFFF_FFFE, 0xFFFF_FFFF, then
               0x0, 0x1, 0x2, 0x3, 0x4. Modularly, 'seg_end =
               (seq + 8) mod 2**32 = 0x05'. RCV.NXT must advance
               to 0x05.

        Assertions:

            * 'session._rcv_nxt' is exactly 0x05 after the segment
              is processed (the spec encoding).
            * '_rx_buffer' contains the 8 peer bytes.

        [FLAGS BUG] - 'TcpSession._process_ack_packet' (line 893
        area) computes 'seg_end' with raw addition:

            seg_end = (
                packet_rx_md.tcp__seq
                + len(packet_rx_md.tcp__data)
                + packet_rx_md.tcp__flag_syn
                + packet_rx_md.tcp__flag_fin
            )
            self._rcv_nxt = max(self._rcv_nxt, seg_end)

        For peer_iss=0xFFFF_FFFC, seq=0xFFFF_FFFD, len=8:

            seg_end = 0xFFFF_FFFD + 8 = 0x1_0000_0005   (overflows 32-bit)
            _rcv_nxt = max(0xFFFF_FFFD, 0x1_0000_0005) = 0x1_0000_0005

        RCV.NXT now exceeds the 32-bit unsigned range. The very
        next outbound ACK or delayed-ACK that uses 'RCV.NXT' as
        the ack field will fail at 'struct.pack("!I", ack)'.

        Even if the struct.pack issue were sidestepped, the
        broken state would mis-classify subsequent inbound
        segments (in-order check 'seg_seq == self._rcv_nxt'
        compares the small wrapped seq from the next peer
        segment against a large overflowed RCV.NXT), and the
        connection would break silently.

        On current code this test fails at the 'session._rcv_nxt
        == 5' assertion - RCV.NXT comes back as 0x1_0000_0005
        (4_294_967_301).

        The fix is the same 'tcp_seq' migration that resolves
        scenarios #1 and #2: replace 'seg_end = seq + len + ...'
        with 'add32(seq, len, ...)' (variadic per the previous
        commit), and the 'max(...)' update with a modular
        equivalent ('seg_end if lt32(rcv_nxt, seg_end) else
        rcv_nxt'). Together with the comparator and SND.NXT
        fixes, the migration makes 'tcp__session.py' correct
        across the wrap boundary in both directions.
        """

        session = self._drive_handshake_to_established(
            iss=0x0000_1000,
            peer_iss=0xFFFF_FFFC,
        )

        self.assertEqual(
            session._rcv_nxt,
            0xFFFF_FFFD,
            msg=("Setup precondition: post-handshake 'RCV.NXT' must " "equal 'peer_iss + 1' = 0xFFFF_FFFD."),
        )

        # Peer sends 8 bytes spanning the wrap: seq 0xFFFF_FFFD
        # through 0x04 modularly.
        peer_payload = b"peer-rcv"
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0xFFFF_FFFD,
            ack=0x0000_1001,
            flags=("ACK", "PSH"),
            win=PEER__WIN,
            payload=peer_payload,
        )
        self._drive_rx(frame=peer_data)

        # The spec encoding: RCV.NXT advances modularly.
        expected_rcv_nxt = (0xFFFF_FFFD + len(peer_payload)) % SEQ32__MOD
        self.assertEqual(
            session._rcv_nxt,
            expected_rcv_nxt,
            msg=(
                f"After peer's 8-byte data segment at seq=0xFFFF_FFFD, "
                f"'RCV.NXT' must advance modularly to "
                f"{expected_rcv_nxt:#x} per RFC 9293 §3.4. Catching "
                "0x1_0000_0005 here means the raw addition "
                "'seg_end = seq + len + ...' in "
                "'_process_ack_packet' (line 893 area) leaked past "
                "the 32-bit modular space; the next outbound ACK "
                "will fail at 'struct.pack(\"!I\", ...)'. Fix: "
                "migrate to 'add32' from 'pytcp.lib.tcp_seq'."
            ),
        )

        # Sanity: data was enqueued.
        self.assertEqual(
            bytes(session._rx_buffer),
            peer_payload,
            msg="Peer's payload must be delivered to '_rx_buffer'.",
        )
