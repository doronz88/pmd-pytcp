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
    PACKET_RETRANSMIT_TIMEOUT,
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

        # Peer ACKs the first segment. This advances SND.UNA past
        # the wrap and clears the Minshall partial-in-flight gate
        # (RFC 1122 §4.2.3.4) so the second send's partial does
        # not get deferred. Without this ACK the post-migration
        # Minshall check would see '_snd_sml=3 > _snd_una=0xFFFF_FFFF'
        # modularly (correctly) and defer Send #2 - which is the
        # right Nagle behaviour but unrelated to the seq-wrap
        # contract this test is exercising.
        peer_ack_seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_2001,
            ack=0x0000_0003,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_seg1)

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


class TestTcpSeqWraparound__Purge(TcpSessionTestCase):
    """
    Tests for the retransmit-counter purge loops in
    '_process_ack_packet' across the 32-bit wrap. Three internal
    dicts are keyed by seq: '_tx_retransmit_request_counter',
    '_tx_retransmit_timeout_counter', '_rx_retransmit_request_counter'.
    Each is purged on every cum-ACK advance via a 'seq < ack' loop;
    the raw '<' fails to recognise wraparound and lets stale entries
    accumulate indefinitely.
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

    def test__seq_wraparound__retransmit_counter_purge_across_wrap(self) -> None:
        """
        Ensure that the per-seq retransmit-counter dicts in
        '_process_ack_packet' are correctly purged when the
        cumulative ACK advances PAST a key that lies modularly
        below the new SND.UNA but numerically above it (the wrap
        case).

        Per RFC 9293 §3.4 the purge condition "this seq has been
        cumulatively acknowledged" is a modular comparison
        ('seq is before ack in modular order'); the current
        implementation uses raw Python '<', which is wrong across
        the wrap and lets stale entries leak.

        Scenario:

            1. Drive a normal handshake to ESTABLISHED.
            2. Pre-populate '_tx_retransmit_timeout_counter' with
               an entry at 'seq = 0xFFFF_FFE0' simulating a
               retransmit timer for a segment we previously sent
               near the wrap.
            3. Pre-position session state so SND.UNA straddles
               the wrap and a peer ACK at 'ack = 0x0000_0010' is
               modularly above the entry but numerically below.
            4. Drive the peer ACK. '_process_ack_packet' runs
               its three purge loops - the entry MUST be removed
               because its seq is modularly before the new
               SND.UNA.

        Assertions:

            * '_tx_retransmit_timeout_counter' is empty after the
              ACK is processed.

        [FLAGS BUG] - 'TcpSession._process_ack_packet' uses raw
        Python '<' on the dict keys:

            for seq in list(self._tx_retransmit_timeout_counter):
                if seq < packet_rx_md.tcp__ack:
                    self._tx_retransmit_timeout_counter.pop(seq)

        With seq=0xFFFF_FFE0 and ack=0x10, '0xFFFF_FFE0 < 0x10'
        is numerically False - the entry leaks. After the fix
        ('lt32(seq, packet_rx_md.tcp__ack)') the modular forward
        distance is 0x30 (small + positive + < HALF), so 'lt32'
        returns True and the entry is correctly removed.

        On current code this test fails: the counter still
        contains the stale 0xFFFF_FFE0 key.
        """

        session = self._drive_handshake_to_established(
            iss=0x0000_1000,
            peer_iss=0x0000_2000,
        )

        # Pre-position SND.UNA / SND.MAX to straddle the wrap;
        # entry at 0xFFFF_FFE0 lies just at SND.UNA.
        session._snd_una = 0xFFFF_FFE0
        session._snd_nxt = 0x0000_0010
        session._snd_max = 0x0000_0010
        session._tx_buffer_seq_mod = 0xFFFF_FFE0

        # Plant a stale retransmit-timeout entry.
        session._tx_retransmit_timeout_counter[0xFFFF_FFE0] = 1

        # Peer ACK: cumulatively ACKs everything up to 0x0000_0010
        # (modularly 0x30 bytes past the entry). The purge MUST
        # drop the stale key.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_2001,
            ack=0x0000_0010,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._tx_retransmit_timeout_counter,
            {},
            msg=(
                "After a cum-ACK advance modularly past a "
                "retransmit-counter entry, the entry MUST be "
                "purged. Current code's raw '<' compares "
                "0xFFFF_FFE0 < 0x10 numerically, which is False, "
                "so the stale entry leaks across the wrap. Fix: "
                "migrate the three purge loops in "
                "'_process_ack_packet' to 'lt32' from "
                "'pytcp.lib.tcp_seq'."
            ),
        )


class TestTcpSeqWraparound__HalfCloseAck(TcpSessionTestCase):
    """
    Tests for ACK acceptability across the 32-bit wrap in the
    half-close FSM states (CLOSE_WAIT, FIN_WAIT_1, FIN_WAIT_2,
    CLOSING, LAST_ACK). Each handler uses the chained Python
    comparator 'self._snd_una <= ack <= self._snd_max', which
    fails across the wrap exactly as the ESTABLISHED handler did
    before commit '91abbc4' migrated it. The migration was not
    extended to the half-close family; this test is the forcing
    function for that extension.
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

    def test__seq_wraparound__close_wait_inbound_ack_across_wrap_advances_snd_una(self) -> None:
        """
        Ensure that a peer ACK whose value is modularly inside
        '[SND.UNA, SND.MAX]' but numerically outside (because the
        send-sequence range straddles the wrap) is accepted as
        in-window in CLOSE_WAIT and advances SND.UNA to the ack
        value.

        Setup mirrors the ESTABLISHED test: pre-position SND.UNA
        near the 32-bit ceiling and SND.MAX past the wrap, then
        drive peer's FIN to transition the session to CLOSE_WAIT,
        then send a peer ACK with a modular-acceptable value.

        Scenario:

            1. Drive a normal handshake to ESTABLISHED at a tame
               ISS.
            2. Peer sends FIN; we transition to CLOSE_WAIT.
            3. Pre-position the session's send-sequence state so
               the in-window range crosses the wrap:
                 SND.UNA = 0xFFFF_FFFE
                 SND.MAX = 0x0000_0010
               (18 modular bytes of in-flight data straddling the
               wrap.)
            4. Peer sends an ACK at 'ack = 0x05'. Modularly this
               is 7 bytes past SND.UNA, well within the in-flight
               range. RFC 9293 §3.10.7.4 mandates SND.UNA advance
               to 0x05.

        Assertions:

            * 'session._snd_una' advances to 0x05 after the peer
              ACK.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_close_wait' uses the
        chained Python comparator 'self._snd_una <= ack <=
        self._snd_max' to gate the regular-data/ACK branch. With
        SND.UNA=0xFFFF_FFFE and ack=0x05 the chain evaluates to
        '0xFFFF_FFFE <= 0x05' = False, so the chain
        short-circuits and the segment is silently dropped -
        SND.UNA does not advance. Same gap exists in
        '_tcp_fsm_fin_wait_1', '_tcp_fsm_fin_wait_2',
        '_tcp_fsm_closing', '_tcp_fsm_last_ack'. The fix
        migrates each chain to 'le32' from 'pytcp.lib.tcp_seq'
        ('le32(SND.UNA, ack) AND le32(ack, SND.MAX)').
        """

        session = self._drive_handshake_to_established(
            iss=0x0000_1000,
            peer_iss=0x0000_2000,
        )

        # Drive peer FIN to enter CLOSE_WAIT.
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_2001,
            ack=0x0000_1001,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        assert session.state is FsmState.CLOSE_WAIT, f"Setup failed: expected CLOSE_WAIT, got {session.state!r}."

        # Pre-position send-sequence state to straddle the wrap.
        session._snd_una = 0xFFFF_FFFE
        session._snd_nxt = 0x0000_0010
        session._snd_max = 0x0000_0010
        session._tx_buffer_seq_mod = 0xFFFF_FFFE

        # Peer sends the in-window ACK. Note seq advances past
        # peer's FIN to keep RCV.NXT consistent.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_2002,
            ack=0x0000_0005,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._snd_una,
            0x0000_0005,
            msg=(
                "Peer's in-window ACK at ack=0x05 with "
                "SND.UNA=0xFFFF_FFFE and SND.MAX=0x10 in CLOSE_WAIT "
                "MUST advance SND.UNA modularly to 0x05 per RFC "
                "9293 §3.10.7.4. Current code's chained '<=' "
                "rejects across the wrap. Fix: migrate "
                "'_tcp_fsm_close_wait' (and the other half-close "
                "handlers) to 'le32'."
            ),
        )


class TestTcpSeqWraparound__ReceiveWindow(TcpSessionTestCase):
    """
    Tests for the receive-window acceptability check
    ('RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND') across the 32-bit
    wrap. The right-edge expression 'self._rcv_nxt + self._rcv_wnd'
    is raw Python addition that overflows past 2**32 when
    'self._rcv_nxt' is near the wrap; the resulting comparison
    rejects in-window segments whose seq numerically exceeds
    2**32 even though they are modularly inside the window.
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

    def test__seq_wraparound__receive_window_right_edge_across_wrap_accepts_segment(self) -> None:
        """
        Ensure that a peer data segment whose 'seq' lies modularly
        within the receive window 'RCV.NXT <= SEQ < RCV.NXT +
        RCV.WND' is accepted even when 'RCV.NXT + RCV.WND'
        straddles the 32-bit wrap.

        Setup: pre-position 'self._rcv_nxt = 0xFFFF_FFE0' and
        leave 'self._rcv_wnd_max = 65535' (modular). The window
        right edge is '0xFFFF_FFE0 + 0xFFFF = 0x1_0000_FFDF'
        numerically, which Python represents as a 33-bit int -
        the modular right edge wraps to '0x0000_FFDF'.

        Peer sends a 50-byte segment at 'seq = 0x0000_0010'.
        Modularly: 0x10 lies 0x30 bytes past RCV.NXT and well
        within the 65535-byte window. RFC 9293 §3.10.7.4 says
        the segment is acceptable.

        Numerically: '0xFFFF_FFE0 <= 0x0000_0010' is False, so
        the chained comparator
        'self._rcv_nxt <= packet_rx_md.tcp__seq <= self._rcv_nxt +
        self._rcv_wnd' rejects the segment as out-of-window.
        Today's code drops it silently.

        Assertions:

            * After the segment arrives: 'session._rcv_nxt'
              advances modularly to '0x0000_0010 + 50 = 0x0000_0042'.
            * The segment's bytes appear in 'session._rx_buffer'.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_established' computes
        'seg_end = packet_rx_md.tcp__seq + seg_len' and tests
        'self._rcv_nxt + self._rcv_wnd' with raw Python addition,
        then compares with raw '<' / '<='. Across the wrap this
        family of expressions is wrong. The fix migrates each
        right-edge expression to 'add32' and each comparator to
        'lt32' / 'le32' / 'in_range32'.
        """

        session = self._drive_handshake_to_established(
            iss=0x0000_1000,
            peer_iss=0x0000_2000,
        )

        # Pre-position RCV.NXT near the 32-bit ceiling. We will
        # send peer data at exactly RCV.NXT so the segment is
        # in-order; its 'seg_end' wraps past the 32-bit ceiling,
        # which is what exercises the receive-window
        # acceptability check's modular right-edge computation.
        session._rcv_nxt = 0xFFFF_FFE0
        session._rcv_una = 0xFFFF_FFE0
        session._rcv_ini = 0xFFFF_FFE0

        # Peer sends 50 bytes at seq=RCV.NXT (=0xFFFF_FFE0). The
        # segment's right edge wraps past 0xFFFF_FFFF to 0x12,
        # exercising 'add32' on the seg_end computation and
        # 'lt32 / gt32' on the receive-window acceptability test.
        peer_payload = b"X" * 50
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0xFFFF_FFE0,
            ack=0x0000_1001,
            flags=("ACK",),
            win=PEER__WIN,
            payload=peer_payload,
        )
        self._drive_rx(frame=peer_data)

        # Modularly 50 bytes past 0xFFFF_FFE0 is 0x12 (with 32
        # bytes consumed from 0xFFFF_FFE0 to 0xFFFF_FFFF + 1
        # phantom, then 18 bytes from 0x0 to 0x12).
        self.assertEqual(
            session._rcv_nxt,
            0x0000_0012,
            msg=(
                "An in-order peer data segment whose 'seg_end' "
                "wraps past the 32-bit ceiling MUST be accepted "
                "and advance RCV.NXT modularly to the wrapped "
                "right edge. Current code's raw '+' on "
                "'self._rcv_nxt + self._rcv_wnd' overflows past "
                "2**32 and the raw '>' on 'seg_end > "
                "self._rcv_nxt' rejects the segment because "
                "'0x12 > 0xFFFF_FFE0' is numerically False. Fix: "
                "migrate the receive-window acceptability check "
                "to 'add32' / 'lt32' / 'gt32'."
            ),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            peer_payload,
            msg="In-window data must be delivered to '_rx_buffer'.",
        )


class TestTcpSeqWraparound__FinAck(TcpSessionTestCase):
    """
    Tests for the FIN-ack '>=' check in the half-close states.
    'self._snd_fin' is the seq number of the FIN segment we sent;
    the handler tests 'tcp__ack >= self._snd_fin' to detect that
    peer has cumulatively acked our FIN. The raw '>=' fails
    across the wrap, so a wrap-spanning peer ACK that legitimately
    covers our FIN is treated as not-yet-cum-acked and the FSM
    fails to transition out of FIN_WAIT_1.
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

    def test__seq_wraparound__fin_wait_1_fin_ack_across_wrap_transitions_to_fin_wait_2(self) -> None:
        """
        Ensure that when our FIN seq is near the 32-bit ceiling
        and peer's cumulative ACK has wrapped past it, the
        FIN_WAIT_1 handler recognises the FIN as ACKed and
        transitions to FIN_WAIT_2.

        Setup: drive to FIN_WAIT_1, pre-position '_snd_fin' near
        the wrap, then deliver a peer ACK whose value is
        modularly past '_snd_fin' but numerically below.

        Scenario:

            1. Drive a normal handshake to ESTABLISHED.
            2. Application calls close(); we transition to
               FIN_WAIT_1 and emit FIN.
            3. Pre-position the session's send-sequence state:
                 SND.FIN = 0xFFFF_FFFF
                 SND.UNA = 0xFFFF_FFFE
                 SND.MAX = 0x0000_0000  (post-wrap, 1 byte after FIN)
               In modular terms our FIN occupies seq 0xFFFF_FFFF
               and peer's expected ACK is 0x0000_0000.
            4. Peer sends ACK at 'ack = 0x0000_0001' (covers FIN
               plus one phantom byte modularly).
            5. The FIN_WAIT_1 handler MUST recognise 'ack >=
               SND.FIN' modularly and transition to FIN_WAIT_2.

        Assertions:

            * 'session.state is FsmState.FIN_WAIT_2' after the
              ACK is processed.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_fin_wait_1' uses raw
        '>=':

            if packet_rx_md.tcp__ack >= self._snd_fin:
                self._change_state(FsmState.FIN_WAIT_2)

        With SND.FIN=0xFFFF_FFFF and ack=0x01, '0x01 >=
        0xFFFF_FFFF' is numerically False. The transition does
        not fire and the session sticks in FIN_WAIT_1 until RTO.
        Same gap appears in 'FIN_WAIT_2' / 'CLOSING' transitions
        that test 'ack >= SND.FIN'. Fix: migrate to
        'ge32(packet_rx_md.tcp__ack, self._snd_fin)' from
        'pytcp.lib.tcp_seq'.
        """

        session = self._drive_handshake_to_established(
            iss=0x0000_1000,
            peer_iss=0x0000_2000,
        )

        # Drive close() - we send FIN, transition to FIN_WAIT_1.
        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        assert session.state is FsmState.FIN_WAIT_1, f"Setup failed: expected FIN_WAIT_1, got {session.state!r}."

        # Pre-position state so SND.FIN straddles the wrap. The
        # FIN occupies 1 byte of seq space at SND.FIN; peer's
        # expected ACK is SND.FIN + 1.
        session._snd_fin = 0xFFFF_FFFF
        session._snd_una = 0xFFFF_FFFE
        session._snd_nxt = 0x0000_0000
        session._snd_max = 0x0000_0000
        session._tx_buffer_seq_mod = 0xFFFF_FFFE

        # Peer ACK covers our FIN (and one byte past, modularly
        # making the cum-ACK 0x01).
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_2001,
            ack=0x0000_0000,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_2,
            msg=(
                "When peer's cum-ACK is modularly >= SND.FIN, "
                "the FIN_WAIT_1 handler MUST transition to "
                "FIN_WAIT_2. Current code's raw '>=' compares "
                "0x00 >= 0xFFFF_FFFF numerically (False), so the "
                "transition never fires near the wrap. Fix: "
                "migrate to 'ge32' from 'pytcp.lib.tcp_seq'."
            ),
        )


class TestTcpSeqWraparound__SynSentAck(TcpSessionTestCase):
    """
    Tests for the SYN_SENT-state ACK acceptability check across
    the 32-bit wrap. RFC 9293 §3.10.7.3 step 1 mandates that any
    ACK-bearing segment in SYN_SENT whose 'SEG.ACK' falls outside
    '(SND.UNA, SND.MAX]' must elicit '<SEQ=SEG.ACK><CTL=RST>' and
    the segment be discarded. The check is implemented at
    'tcp__session.py' line 1706 with a chained Python comparator
    'self._snd_una < ack <= self._snd_max' that fails across the
    32-bit wrap. The site escaped the modular-arithmetic
    migration ('91abbc4' / '352199d'); this test is the forcing
    function for the spot fix.

    The bug fires only when the locally-chosen Initial Sequence
    Number is randomly drawn close to the 32-bit ceiling - rare
    in practice (~1-in-4-billion ISS draws) but a real
    interoperability failure when it does fire (peer sees a
    legitimate active-open's SYN+ACK rejected with RST).
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

    def test__seq_wraparound__syn_sent_inbound_syn_ack_with_wrapped_ack_accepted(self) -> None:
        """
        Ensure that when the locally-chosen ISS lies on the 32-bit
        ceiling and the peer's SYN+ACK carries 'ack = ISS + 1'
        which has wrapped past the ceiling to zero, the ACK
        acceptability check accepts the SYN+ACK as in-window and
        the session transitions to ESTABLISHED. RFC 9293 §3.10.7.3
        step 1 ACK acceptability is a modular '(SND.UNA, SND.MAX]'
        check; the chained Python comparator fails across the
        wrap.

        Setup:

            ISS      = 0xFFFF_FFFF (forced via '_force_iss')
            SND.UNA  = 0xFFFF_FFFF (initial)
            Post-SYN-emit:
              SND.NXT = SND.MAX = 0x0000_0000  (wrapped)

        Peer's canonical SYN+ACK:

            seq = peer_iss
            ack = ISS + 1 = 0x0000_0000

        ACK acceptability per RFC 9293 §3.10.7.3 step 1:

            (SND.UNA, SND.MAX]
              = (0xFFFF_FFFF, 0x0000_0000]   # modular

        The interval contains exactly one byte of seq space: the
        single byte at 0x0000_0000 (= the FIN-acked byte after
        our SYN consumed seq 0xFFFF_FFFF). 'ack = 0x0000_0000'
        IS in that interval - the SYN+ACK is acceptable.

        Numerically the chained Python comparator computes:

            0xFFFF_FFFF < 0x0000_0000 <= 0x0000_0000

        which is False (0xFFFF_FFFF < 0 is False), so the check
        rejects the segment as unacceptable, fires
        '<SEQ=SEG.ACK><CTL=RST>', and the session never reaches
        ESTABLISHED. From peer's view the active-open looks like
        a connection-refused.

        Scenario:

            1. Force ISS = 0xFFFF_FFFF.
            2. Drive 'CONNECT'. SYN fires at seq = 0xFFFF_FFFF.
            3. Peer replies with SYN+ACK at seq = peer_iss,
               ack = 0x0000_0000.
            4. Drive RX. The session MUST transition to
               ESTABLISHED.

        Assertions:

            * 'session.state is FsmState.ESTABLISHED' after the
              SYN+ACK is processed.
            * No outbound RST appears on the wire (the
              acceptability check accepts the segment).

        [FLAGS BUG] - 'TcpSession._tcp_fsm_syn_sent' line 1706
        uses the chained Python comparator
        'self._snd_una < ack <= self._snd_max' which fails
        across the 32-bit wrap. Fix: migrate to
        'lt32(self._snd_una, ack) and le32(ack, self._snd_max)'
        (or equivalently 'in_range32(ack, add32(snd_una, 1),
        snd_max)' for the half-open lower bound).

        On current code this test fails: state stays in SYN_SENT
        and an outbound RST appears in the inline TX list.
        """

        session = self._make_active_session(iss=SEQ32__MAX)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        # Tick to fire the outbound SYN.
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        syn_probe = self._parse_tx(syn_tx[0])
        self.assertEqual(
            syn_probe.seq,
            SEQ32__MAX,
            msg="Setup precondition: outbound SYN must carry seq=ISS=0xFFFF_FFFF.",
        )
        self.assertEqual(
            session._snd_max,
            0x0000_0000,
            msg=(
                "Setup precondition: post-SYN-emit 'SND.MAX' must be "
                "the wrapped value 0x0000_0000 (= ISS + 1 modularly)."
            ),
        )

        # Peer's SYN+ACK with ack = ISS + 1 = 0x0000_0000 (the
        # wrapped value). Per RFC 9293 §3.10.7.3 step 1 this is
        # acceptable - 'ack' falls inside '(SND.UNA, SND.MAX]'
        # modularly.
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_2000,  # peer's ISS
            ack=0x0000_0000,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        inline_tx = self._drive_rx(frame=peer_syn_ack)

        # No RST should fire - the SYN+ACK is acceptable.
        rst_frames = [frame for frame in inline_tx if self._parse_tx(frame).flags & {"RST"}]
        self.assertEqual(
            rst_frames,
            [],
            msg=(
                "An acceptable SYN+ACK whose ack value happens to "
                "have wrapped past the 32-bit ceiling MUST NOT "
                "elicit an RST. The chained Python comparator "
                "'self._snd_una < ack <= self._snd_max' computes "
                "'0xFFFF_FFFF < 0x00 <= 0x00' which is False "
                "numerically and wrongly rejects the segment with "
                "'<SEQ=SEG.ACK><CTL=RST>'. Fix: migrate to "
                "'lt32 / le32' from 'pytcp.lib.tcp_seq'."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "The session MUST transition to ESTABLISHED after "
                "peer's acceptable SYN+ACK. Current code rejects the "
                "segment via the broken acceptability check and stays "
                "in SYN_SENT (or transitions to CLOSED if the bogus "
                "RST also drives an internal abort)."
            ),
        )


class TestTcpSeqWraparound__FinSentinel(TcpSessionTestCase):
    """
    Tests the '_snd_fin = 0' sentinel collision in
    '_retransmit_packet_timeout's TX-buffer offset rewind. The
    rewind walks 'self._tx_buffer_seq_mod' back by one when
    'self._snd_nxt in {self._snd_ini, self._snd_fin}', the
    rationale being that SYN and FIN consume one byte of seq
    space without a TX-buffer slot. But when no FIN has been
    sent, '_snd_fin' is the literal value 0 used as a sentinel;
    once 'SND.UNA' wraps modulo 2**32 to exactly 0 and an RTO
    fires, the rewind sets 'SND.NXT = 0', the set membership
    fires its FIN branch on the sentinel value, and the
    walk-back silently corrupts the offset translation.
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

    def test__seq_wraparound__rto_after_snd_una_wraps_to_zero_does_not_corrupt_tx_buffer_offset(self) -> None:
        """
        Ensure that when 'SND.UNA' wraps modulo 2**32 to exactly
        0 and an RTO fires before any FIN has been sent, the
        retransmit fires the queued data byte cleanly - the
        '_snd_fin = 0' sentinel value MUST NOT be confused for
        a real FIN seq matching 'SND.NXT == 0'.

        RFC 9293 §3.4 (Sequence Numbers) defines seq as 32-bit
        modular; values legitimately reach 0 after a wrap. RFC
        9293 §3.10.7.4 (RTO retransmit) does not require any
        special handling at SND.NXT == 0; the retransmit simply
        re-sends the unacked segment.

        [FLAGS BUG] - 'TcpSession._retransmit_packet_timeout'
        line 1335:

            if self._snd_nxt in {self._snd_ini, self._snd_fin}:
                self._tx_buffer_seq_mod = sub32(self._tx_buffer_seq_mod, 1)

        The walk-back is correct for SYN retransmit
        ('snd_nxt == snd_ini') and FIN retransmit
        ('snd_nxt == snd_fin'), since SYN and FIN each consume
        one byte of seq space without occupying a TX-buffer
        slot - the 'snd_ini' / 'snd_fin' increment that
        '_transmit_packet' applied to '_tx_buffer_seq_mod' must
        be unwound on retransmit. But '_snd_fin' is initialised
        to '0' as the "no FIN sent yet" sentinel
        (tcp__session.py:338). Once 'SND.UNA' wraps to exactly
        0 (which it WILL during a connection that crosses the
        seq boundary - the wrap-by-byte advancement guarantees
        landing on the 0 value as it crosses), an RTO triggered
        with 'SND.UNA == 0' rewinds 'SND.NXT' to 0 and the set
        check fires the FIN branch on the sentinel. The
        walk-back of '_tx_buffer_seq_mod' shifts the
        seq-to-buffer-offset translation by one byte, and the
        next '_transmit_data' call slices '_tx_buffer[1:]'
        instead of '_tx_buffer[0:]'. In this single-byte test
        scenario, '_tx_buffer_nxt' becomes 1, 'remaining_data_len'
        becomes 0, and the retransmit silently fails to fire -
        the connection then cycles RTOs until R2 abort. In a
        multi-byte segment scenario the byte-0 elision shifts
        the entire payload by one position, silently corrupting
        peer's view of the data stream (TCP checksum still
        validates, since it covers the corrupted bytes).

        Severity: LOW probability (requires a long-lived
        connection that crosses the seq wrap with an
        unfortunately-timed RTO at exactly 'SND.UNA == 0') but
        HIGH impact (silent data corruption / data-loss).

        Fix outline (separate commit):

          - Replace the sentinel pattern with a separate
            'self._fin_sent: bool = False' flag, set to True
            in '_transmit_packet' alongside
            'self._snd_fin = self._snd_nxt' on 'flag_fin'.
          - Update the rewind check at line 1335:

              if self._snd_nxt == self._snd_ini or (
                  self._fin_sent and self._snd_nxt == self._snd_fin
              ):
                  self._tx_buffer_seq_mod = sub32(self._tx_buffer_seq_mod, 1)

          - Other readers of '_snd_fin' do not need changes -
            they are reached only after a FIN has been sent, so
            the value is a real seq there.

        Scenario:

            1. Force ISS = 0xFFFF_FFFE (handshake-time seq
               offset; post-SYN+ACK SND.UNA lands at
               0xFFFF_FFFF, one byte before the wrap).
            2. Drive the active-open handshake to ESTABLISHED.
               Bypass slow-start by setting '_snd_ewn' to
               peer's window so a 1-byte send fires immediately.
            3. send(b"A"). One outbound segment with
               seq = 0xFFFF_FFFF. Post-segment SND.NXT wraps
               modularly to 0; SND.MAX = 0.
            4. Peer ACKs the byte (ack = 0). SND.UNA advances
               to 0; '_tx_buffer' is purged;
               '_tx_buffer_seq_mod' = 0.
            5. send(b"B"). One outbound segment with seq = 0.
               Post-segment SND.NXT = 1; SND.MAX = 1. Peer
               does not ACK.
            6. Advance the virtual clock by
               'PACKET_RETRANSMIT_TIMEOUT' ms. The RTO timer
               for seq 0 expires; the FSM tick fires
               '_retransmit_packet_timeout' which rewinds
               SND.NXT to SND.UNA (= 0), then runs
               '_transmit_data' to emit the retransmit.

        Assertions:

            * The retransmit tick produces exactly one
              outbound segment.
            * The segment's seq is 0 and its payload is b"B".
            * '_tx_buffer_seq_mod' is unchanged (0) - the
              FIN-sentinel branch did not fire.

        On current code this test fails at the segment-count
        assertion: zero outbound segments, because the
        '_tx_buffer_seq_mod' walk-back makes 'remaining_data_len'
        compute as 0 inside '_transmit_data' and the retransmit
        path silently exits.
        """

        session = self._drive_handshake_to_established(
            iss=0xFFFF_FFFE,
            peer_iss=0x0000_2000,
        )
        # Bypass slow-start so the 1-byte sends fire immediately.
        session._snd_ewn = PEER__WIN

        # Step 3: send 1 byte at SND.NXT = 0xFFFF_FFFF.
        session.send(data=b"A")
        seg1_tx = self._advance(ms=1)
        self.assertEqual(
            len(seg1_tx),
            1,
            msg="Setup precondition: first send must produce one outbound segment.",
        )
        self.assertEqual(
            session._snd_nxt,
            0,
            msg=("Setup precondition: post-send-1 SND.NXT must wrap " "modulo 2**32 to 0."),
        )

        # Step 4: peer ACKs the byte. SND.UNA wraps to 0.
        peer_ack_seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_2001,
            ack=0,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_seg1)
        self.assertEqual(
            session._snd_una,
            0,
            msg=(
                "Setup precondition: post-ACK SND.UNA must equal 0 - "
                "the wrap value that triggers the sentinel collision."
            ),
        )
        self.assertEqual(
            session._tx_buffer_seq_mod,
            0,
            msg=(
                "Setup precondition: '_tx_buffer_seq_mod' must "
                "have advanced to 0 after the cum-ACK purged the "
                "first byte."
            ),
        )

        # Step 5: send 1 byte at SND.NXT = 0. Peer does not ACK.
        # Neutralise Nagle's partial-in-flight gate (RFC 1122
        # §4.2.3.4 Minshall variant) for the RTO retransmit by
        # resetting '_snd_sml' to 'SND.UNA' AFTER the second
        # send fires. Without this, the RTO retransmit path
        # would observe '_snd_sml=1 > _snd_una=0', mark it
        # 'is_partial AND prev_partial_in_flight', and defer the
        # retransmit indefinitely - the deferral would mask the
        # bug under test by always producing zero outbound
        # segments regardless of the FIN-sentinel fix. The
        # Nagle-on-retransmits interaction is a separate gap not
        # covered by this test file.
        session.send(data=b"B")
        seg2_tx = self._advance(ms=1)
        self.assertEqual(
            len(seg2_tx),
            1,
            msg="Setup precondition: second send must produce one outbound segment.",
        )
        session._snd_sml = session._snd_una
        seg2_probe = self._parse_tx(seg2_tx[0])
        self._assert_segment(
            seg2_probe,
            seq=0,
            payload=b"B",
        )

        # Step 6: advance the virtual clock to fire the RTO.
        # 'PACKET_RETRANSMIT_TIMEOUT' is the initial RTO (1000 ms).
        # Advance one extra ms past the timeout so the timer fires
        # cleanly on the boundary tick.
        retransmit_tx = self._advance(ms=PACKET_RETRANSMIT_TIMEOUT + 1)

        # Pick out the retransmit segments from the advance window.
        # Multiple ticks fire while we advance; only the RTO tick
        # produces a TX. The fix produces exactly one retransmit
        # segment with the correct content; the bug produces zero.
        retransmit_segments = [self._parse_tx(frame) for frame in retransmit_tx]
        self.assertEqual(
            len(retransmit_segments),
            1,
            msg=(
                "After the RTO fires, exactly one retransmit segment "
                "MUST be emitted re-sending the unacked byte at "
                "seq=0. Today the rewind at "
                "'tcp__session.py:1335' walks '_tx_buffer_seq_mod' "
                "back by one because '_snd_fin == 0 == SND.NXT' "
                "fires the FIN branch on the sentinel value. The "
                "walk-back makes '_tx_buffer_nxt' overshoot by one, "
                "'remaining_data_len' compute as 0, and "
                "'_transmit_data' silently fail to emit the "
                "retransmit. The connection then cycles RTOs until "
                "R2 abort, with the queued byte never reaching the "
                "wire. Fix: replace the '_snd_fin = 0' sentinel "
                f"with a separate '_fin_sent: bool' flag. Got: {retransmit_segments!r}"
            ),
        )
        self._assert_segment(
            retransmit_segments[0],
            seq=0,
            payload=b"B",
        )

        # Belt-and-braces: '_tx_buffer_seq_mod' must NOT have been
        # decremented by the buggy rewind. The fix preserves the
        # value at 0; the bug subtracts 1 to 0xFFFF_FFFF.
        self.assertEqual(
            session._tx_buffer_seq_mod,
            0,
            msg=(
                "After the RTO, '_tx_buffer_seq_mod' MUST be "
                "unchanged at 0 - the rewind's FIN-walk-back must "
                "NOT fire when no FIN has been sent. Today the "
                "sentinel collision walks it back to 0xFFFF_FFFF, "
                "corrupting the seq-to-buffer-offset translation."
            ),
        )
