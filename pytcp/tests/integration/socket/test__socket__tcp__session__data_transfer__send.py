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
This module contains integration tests for the TCP send-side data
transfer in the 'TcpSession' state machine, covering the application's
'send()' syscall path and the corresponding wire-level segment shape
prescribed by RFC 9293 §3.10.5 / RFC 1122 §4.2.2.2.

The tests in this file drive the session FSM directly: after taking
the session through the three-way handshake to ESTABLISHED via the
active-open path, each test invokes 'session.send(data=...)' and
asserts the wire-level shape of the segment(s) that follow on the
next virtual-clock tick. The full RX/TX path is exercised end to
end - outbound segments flow through the real
'PacketHandler._phtx_tcp -> _phtx_ip4 -> _phtx_ethernet' chain and
land in the mocked 'TxRing'.

Reference RFCs:
    RFC 9293 §3.10.5    SEND syscall semantics
    RFC 9293 §3.7.4     Generating data segments
    RFC 9293 §3.8.6     Window management
    RFC 9293 §3.8.6.1   Zero-window probing / persist timer
    RFC 6298 §2         Computing TCP's retransmission timer
    RFC 1122 §4.2.2.2   PSH bit on last segment of a write
    RFC 1122 §4.2.3.4   Nagle's algorithm

pytcp/tests/integration/socket/test__socket__tcp__session__data_transfer__send.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.socket import AddressFamily
from pytcp.socket.tcp__session import (
    FsmState,
    SysCall,
    TcpSession,
    TcpSessionError,
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


class TestTcpDataTransfer__Send(TcpSessionTestCase):
    """
    Integration tests for the application-driven 'send()' path,
    covering segment shape, segmentation, window management, and
    flow-control behaviours.
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
        Drive the active-open three-way handshake all the way to
        ESTABLISHED and return the session ready for data transfer.

        After this returns:
            session.state == FsmState.ESTABLISHED
            session._snd_nxt == iss + 1
            session._snd_una == iss + 1
            session._rcv_nxt == peer_iss + 1
        """

        session = self._make_active_session(iss=iss)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        # Initial SYN fires on the first tick.
        self._advance(ms=1)

        # Peer's SYN+ACK carries our ISS+1 as ack and its own ISN as seq.
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

        # Sanity: handshake completed.
        assert (
            session.state is FsmState.ESTABLISHED
        ), f"Handshake setup failed: state is {session.state!r}, expected ESTABLISHED."
        assert (
            session._snd_nxt == iss + 1
        ), f"Handshake setup failed: '_snd_nxt' is {session._snd_nxt:#x}, expected {iss + 1:#x}."
        assert (
            session._rcv_nxt == peer_iss + 1
        ), f"Handshake setup failed: '_rcv_nxt' is {session._rcv_nxt:#x}, expected {peer_iss + 1:#x}."

        return session

    def test__data_transfer_send__single_segment_fits_in_mss_emits_psh_ack(self) -> None:
        """
        Ensure that an application 'send()' of a small payload (less
        than MSS) results in a single outbound TCP segment carrying
        the PSH and ACK flags, with SEQ tracking the established
        send-side sequence number, ACK echoing the current RCV.NXT,
        and the payload exactly equal to the bytes the application
        passed.

        RFC 9293 §3.7.4 ("Generating data segments") describes the
        outbound segment shape: every segment carrying data on an
        established connection must also acknowledge the peer's seq
        space (ACK flag set), advance our SND.NXT by the data
        length, and use SND.NXT as the seq it is transmitted at.

        RFC 1122 §4.2.2.2 ("Sender's SWS Avoidance Algorithm" and
        "When to Send Data") additionally MANDATES that the sender
        SHOULD set the PSH bit on the last segment of a sequence of
        pushed data:

            "When the sending TCP receives a SEND call, it has at
             its disposal the data to be sent. ... When all the data
             is sent, the sender SHOULD set the PSH bit in the LAST
             segment."

        Since pytcp's 'TcpSession.send()' does not expose a separate
        'push' parameter, the only sensible interpretation is that
        every byte the application hands us is "pushed" - in which
        case the LAST segment of every 'send()' call must carry PSH.
        For a single-segment send (payload < MSS), that segment IS
        the last segment of the write, so PSH must be set on the
        sole outbound segment.

        Wire shape required:

            sport   = STACK__PORT
            dport   = PEER__PORT
            seq     = LOCAL__ISS + 1   (= SND.NXT post-handshake)
            ack     = PEER__ISS + 1    (= RCV.NXT post-handshake)
            flags   = {PSH, ACK}       (PSH on the last segment of
                                        the write per RFC 1122
                                        §4.2.2.2; ACK always set on
                                        established-state segments)
            payload = b"hello, world!" (the application's bytes,
                                        delivered verbatim)
            win     = 65535            (our advertised receive window)
            mss     = None             (MSS option only on SYN-bearing
                                        segments per RFC 9293 §3.7.1)
            wscale  = None             (WSCALE only on SYN-bearing
                                        segments per RFC 7323 §2.2)

        Side effects asserted:

            * 'session._snd_nxt' advances by len(payload) to
              consume the outbound bytes from sequence space.
            * 'session._snd_una' is unchanged - the peer has not
              yet acknowledged our data; '_snd_una' will only
              advance when the peer's ACK arrives.
            * 'session.state' remains ESTABLISHED throughout.

        [FLAGS BUG] - RFC 1122 §4.2.2.2 deviation
        ----------------------------------------------------------
        Current '_transmit_packet' has no 'flag_psh' parameter and
        '_transmit_data' calls it with 'flag_ack=True, data=...'
        only. The PSH bit is therefore NEVER set on outbound data
        segments, regardless of where they fall in a write
        sequence. Receivers using PSH as a delivery hint may delay
        passing buffered bytes up to the application until they
        observe other delivery cues (delayed ACK timer, buffer
        full, or peer FIN). On interactive workloads (SSH, REPL,
        line-oriented protocols) this manifests as user-visible
        latency.

        This test is expected to FAIL on current code with the
        outbound segment carrying flags={ACK} only; on a correct
        implementation it observes flags={PSH, ACK}. The fix
        requires plumbing a 'flag_psh' parameter through
        '_transmit_packet' and setting it from '_transmit_data'
        whenever the segment being transmitted is the last segment
        of the buffered data (i.e. 'transmit_data_len ==
        remaining_data_len').
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        payload = b"hello, world!"
        bytes_sent = session.send(data=payload)

        self.assertEqual(
            bytes_sent,
            len(payload),
            msg=(
                f"'send()' must return the number of bytes accepted "
                f"into the TX buffer. Got {bytes_sent}, expected "
                f"{len(payload)}."
            ),
        )

        # The actual transmit is gated on the next timer tick.
        tx_frames = self._advance(ms=1)
        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "A single 'send()' of a payload smaller than MSS "
                "must produce exactly one outbound segment on the "
                f"next tick. Got {len(tx_frames)} TX frames."
            ),
        )

        probe = self._parse_tx(tx_frames[0])
        self._assert_segment(
            probe,
            flags=frozenset({"PSH", "ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=payload,
            win=65535,
            mss=None,
            wscale=None,
        )

        self.assertEqual(
            session._snd_nxt,
            LOCAL__ISS + 1 + len(payload),
            msg=(
                "'_snd_nxt' must advance by len(payload) after "
                "transmitting the data segment - this consumes the "
                "outbound bytes from the send sequence space "
                "(RFC 9293 §3.4)."
            ),
        )
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1,
            msg=(
                "'_snd_una' must be unchanged - the peer has not yet "
                "acknowledged our data; '_snd_una' only advances when "
                "the peer's ACK arrives."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Sending data must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_send__back_to_back_writes_respect_advertised_window(self) -> None:
        """
        Ensure that when the application sends more data than peer's
        advertised SND.WND can hold in flight, the sender respects
        the window: it transmits segments up to the window edge and
        then stops, leaving the remainder buffered until the peer
        acknowledges some of the in-flight bytes.

        Per RFC 9293 §3.8.6 ("Window Management") the sender MUST
        ensure that the right edge of any transmitted segment never
        exceeds 'SND.UNA + SND.WND'. Concretely, with no ACKs from
        the peer, the sender's in-flight bytes ('SND.NXT - SND.UNA')
        must not exceed 'SND.WND'; once that limit is reached,
        further '_transmit_data' invocations must produce no segment
        on the wire even though there is buffered data to send.

        Scenario:

            * After the handshake, restrict peer's advertised window
              to '3 * MSS = 4380' bytes (set both '_snd_wnd' and the
              effective send window '_snd_ewn'). The latter bypass
              avoids entangling this test with the slow-start-style
              cwnd doubling, which is exercised separately in the
              data_transfer__window file - here the focus is on
              flow-control respect.
            * Application sends 8000 bytes (well in excess of the
              window).
            * Tick the virtual clock four times. The first three
              ticks must each emit one MSS-sized segment, totalling
              4380 bytes in flight - exactly the window edge. The
              fourth tick must emit nothing because the window is
              full.

        Wire-level expectations across the four ticks:

            Tick 1: segment of 1460 bytes,
                seq=LOCAL__ISS+1, payload=payload[0:1460].
            Tick 2: segment of 1460 bytes,
                seq=LOCAL__ISS+1+1460, payload=payload[1460:2920].
            Tick 3: segment of 1460 bytes,
                seq=LOCAL__ISS+1+2920, payload=payload[2920:4380].
            Tick 4: NO segment - SND.WND respected.

        All three segments carry only the ACK flag (no PSH) because
        even segment 3 is NOT the last segment of the write - 3620
        bytes remain in the TX buffer past 'SND.NXT'. PSH placement
        is governed by RFC 1122 §4.2.2.2 and tested separately; this
        test specifically asserts that 'PSH' is NOT set on segments
        that are stopped by the window edge.

        Final state assertions:

            session._snd_nxt == LOCAL__ISS + 1 + 4380
            session._snd_una == LOCAL__ISS + 1
            in_flight (snd_nxt - snd_una) == 4380 == SND.WND
            len(session._tx_buffer) == 8000   (nothing has been ACKed yet,
                                               so nothing is purged)
            state == ESTABLISHED

        After an additional 100 ms of virtual time (still well below
        the 1 s retransmit timer), the session must remain quiescent
        - no further segments, no spurious retransmits.

        This test passes on current code: '_transmit_data' uses
        'usable_window = self._snd_ewn - self._tx_buffer_nxt' which
        correctly clamps each segment's right edge at the window
        edge. The test exists as a positive-control regression guard
        - a future refactor that loses the window check (e.g. by
        switching to 'min(MSS, remaining_data_len)' alone) would be
        caught immediately.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Restrict the effective and advertised send windows to 3 MSS,
        # bypassing slow-start so the window edge is the only constraint.
        snd_wnd_limit = 3 * 1460
        session._snd_wnd = snd_wnd_limit
        session._snd_ewn = snd_wnd_limit

        payload = b"X" * 8000
        session.send(data=payload)

        # Tick 1: first MSS chunk goes out, no PSH (more buffered).
        tx_1 = self._advance(ms=1)
        self.assertEqual(
            len(tx_1),
            1,
            msg=f"Tick 1 must produce one segment. Got {len(tx_1)}.",
        )
        seg_1 = self._parse_tx(tx_1[0])
        self._assert_segment(
            seg_1,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=payload[0:1460],
            mss=None,
            wscale=None,
        )

        # Tick 2: second MSS chunk.
        tx_2 = self._advance(ms=1)
        self.assertEqual(
            len(tx_2),
            1,
            msg=f"Tick 2 must produce one segment. Got {len(tx_2)}.",
        )
        seg_2 = self._parse_tx(tx_2[0])
        self._assert_segment(
            seg_2,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1 + 1460,
            ack=PEER__ISS + 1,
            payload=payload[1460:2920],
            mss=None,
            wscale=None,
        )

        # Tick 3: third MSS chunk - last that fits in the window.
        tx_3 = self._advance(ms=1)
        self.assertEqual(
            len(tx_3),
            1,
            msg=f"Tick 3 must produce one segment. Got {len(tx_3)}.",
        )
        seg_3 = self._parse_tx(tx_3[0])
        self._assert_segment(
            seg_3,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1 + 2920,
            ack=PEER__ISS + 1,
            payload=payload[2920:4380],
            mss=None,
            wscale=None,
        )

        # Tick 4: window is full - no segment must be emitted even
        # though 3620 bytes remain buffered.
        tx_4 = self._advance(ms=1)
        self.assertEqual(
            tx_4,
            [],
            msg=(
                "Tick 4 must produce NO segment - the in-flight bytes "
                f"({3 * 1460}) equal the advertised window "
                f"({snd_wnd_limit}); RFC 9293 §3.8.6 forbids advancing "
                "SND.NXT past SND.UNA + SND.WND."
            ),
        )

        # Drive 100 more ms of virtual time (still well within the
        # retransmit timer, which fires at 1 s). The session must
        # remain quiescent - no spurious extra segments.
        tx_silent = self._advance(ms=100)
        self.assertEqual(
            tx_silent,
            [],
            msg=(
                "Without peer ACKs, the session must stay quiescent "
                "while the window is full - no spurious data segments "
                "may be emitted before the retransmit timer fires."
            ),
        )

        in_flight = session._snd_nxt - session._snd_una
        self.assertEqual(
            in_flight,
            snd_wnd_limit,
            msg=(
                f"In-flight bytes (SND.NXT - SND.UNA = {in_flight}) "
                f"must equal SND.WND = {snd_wnd_limit} after the window "
                "fills. Any larger value violates RFC 9293 §3.8.6."
            ),
        )
        self.assertEqual(
            session._snd_nxt,
            LOCAL__ISS + 1 + snd_wnd_limit,
            msg="'_snd_nxt' must equal ISS + 1 + SND.WND after the window fills.",
        )
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1,
            msg="'_snd_una' must be unchanged - the peer has not ACKed any data.",
        )
        self.assertEqual(
            len(session._tx_buffer),
            len(payload),
            msg=("TX buffer must still contain all 8000 bytes - none " "have been ACKed and purged yet."),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Window-limited transmission must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_send__zero_window_triggers_persist_probe_at_rto(self) -> None:
        """
        Ensure that when the peer advertises a zero receive window
        and we have buffered data ready to send, the persist timer
        fires after the RTO interval and emits a 1-byte zero-window
        probe per RFC 9293 §3.8.6.1:

            "The transmitting host SHOULD send the first zero-window
             probe when a zero window has existed for the
             retransmission timeout period (see Section 3.8.1), and
             SHOULD increase exponentially the interval between
             successive probes (MUST-58)."

        The probe is a normal data segment containing exactly ONE byte
        of buffered application data, sent at SEQ=SND.UNA (the peer's
        next-expected byte). It is NOT a retransmission; it is a
        liveness/window probe whose purpose is to elicit a window
        update from the peer. Without it, a connection in zero-window
        state would stall indefinitely - the application's data sits
        in the TX buffer forever because there is no spontaneous
        signal that would cause the peer to re-advertise a non-zero
        window.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Application sends 5 bytes. The first segment fires on
               the next tick.
            3. Peer ACKs the 5 bytes BUT advertises 'win=0' on the
               ACK - peer has no receive buffer space available.
            4. Application sends 5 more bytes.
            5. Tick the virtual clock through the persist timeout
               (the RTO, initially 'PACKET_RETRANSMIT_TIMEOUT' = 1 s).
               No segment must fire while the timer counts down.
            6. Just past the timeout, exactly one outbound segment
               must appear: a 1-byte probe carrying the first byte
               of the post-zero-window data.

        Required wire shape of the probe segment:

            sport     = STACK__PORT
            dport     = PEER__PORT
            seq       = SND.UNA          (= LOCAL__ISS + 1 + 5,
                                           the byte the peer is
                                           expecting next)
            ack       = RCV.NXT          (= PEER__ISS + 1)
            flags     = {ACK}            (the probe is a normal
                                           data segment, not a
                                           special control frame;
                                           PSH is unspecified by
                                           the RFC for the probe)
            payload   = 1 byte           (the first byte of the
                                           post-zero-window data:
                                           b"w" from b"world")
            len       = 1

        Side effects asserted:

            * Before t = ACK + 1000 ms, no segment may be emitted -
              the persist timer must not fire prematurely.
            * After the probe fires, 'session._snd_nxt' advances by
              exactly 1 byte (consuming the probe's seq space).
            * 'session._snd_una' and the rest of the buffered data
              remain unchanged - the probe is asking for a window
              update, not draining the buffer.
            * State remains ESTABLISHED throughout.

        [FLAGS BUG] - RFC 9293 §3.8.6.1 deviation
        ----------------------------------------------------------
        '_transmit_data' early-returns when 'usable_window <= 0':

            transmit_data_len = min(self._snd_mss, usable_window,
                                    remaining_data_len)
            if remaining_data_len:
                if transmit_data_len:    # <- 0 is falsy
                    ... transmit ...
                return

        With peer's window at 0, 'usable_window' = 0 and
        'transmit_data_len' = 0; the inner branch is skipped and the
        function returns without scheduling any probe. The persist
        timer is not implemented anywhere in 'TcpSession' - there
        is no 'f"{self}-persist"' timer registration, no probe-emit
        path. As a result, an application that writes data into a
        connection whose peer has temporarily closed the receive
        window stalls forever; only a peer-initiated window update
        (which we have no way of soliciting) or our own retransmit
        timer's eventual abort can break the deadlock.

        This test is expected to FAIL on current code with zero
        outbound segments after the persist interval. The fix
        requires adding a persist timer that registers when we
        observe a zero-window state with buffered data, fires after
        the current RTO, emits a 1-byte segment at SND.UNA, and
        re-arms with double the timeout (per the RFC's exponential
        back-off requirement).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Application send #1: 5 bytes.
        first_payload = b"hello"
        session.send(data=first_payload)
        first_tx = self._advance(ms=1)
        self.assertEqual(
            len(first_tx),
            1,
            msg="Setup precondition: first segment must fire on the next tick after send().",
        )

        # Peer ACKs the 5 bytes but slams the window shut.
        peer_ack_zero_window = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(first_payload),
            flags=("ACK",),
            win=0,
        )
        self._drive_rx(frame=peer_ack_zero_window)

        self.assertEqual(
            session._snd_wnd,
            0,
            msg="Setup precondition: peer's zero-window ACK must have set '_snd_wnd' to 0.",
        )
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1 + len(first_payload),
            msg="Setup precondition: peer ACK'd the first 5 bytes - SND.UNA must have advanced.",
        )

        # Application send #2: 5 more bytes. These cannot go out
        # because the window is shut; they must wait for the persist
        # probe to elicit a window update from the peer.
        second_payload = b"world"
        session.send(data=second_payload)

        snd_una_before_probe = session._snd_una
        snd_nxt_before_probe = session._snd_nxt

        # Tick most of the way through the persist timeout. No
        # segment may fire yet - the RFC requires waiting at least
        # one RTO before the first probe.
        tx_during_wait = self._advance(ms=999)
        self.assertEqual(
            tx_during_wait,
            [],
            msg=(
                "No segment may be emitted during the persist countdown "
                "- the first zero-window probe must wait until at least "
                "one RTO (1000 ms) has elapsed (RFC 9293 §3.8.6.1)."
            ),
        )

        # Cross the persist timeout boundary. Exactly one probe must
        # fire.
        tx_at_probe = self._advance(ms=2)
        self.assertEqual(
            len(tx_at_probe),
            1,
            msg=(
                f"After 1000 ms in zero-window state with buffered data, "
                f"exactly one zero-window probe must fire (RFC 9293 "
                f"§3.8.6.1). Got {len(tx_at_probe)} TX frames."
            ),
        )

        probe = self._parse_tx(tx_at_probe[0])
        self._assert_segment(
            probe,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=snd_una_before_probe,
            ack=PEER__ISS + 1,
            payload=second_payload[:1],
            mss=None,
            wscale=None,
        )

        # The probe is exactly 1 byte and consumes 1 byte of seq
        # space. SND.UNA stays where it was - the peer has not yet
        # acknowledged the probe (and may not, if their window is
        # still genuinely zero).
        self.assertEqual(
            session._snd_nxt,
            snd_nxt_before_probe + 1,
            msg="The persist probe consumes exactly one byte of sequence space.",
        )
        self.assertEqual(
            session._snd_una,
            snd_una_before_probe,
            msg=(
                "SND.UNA must NOT advance during the probe - the probe "
                "is asking for a window update, not draining the buffer."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Zero-window probing must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_send__nagle_suppresses_small_write_with_unacked_data(self) -> None:
        """
        Ensure that when there is unacknowledged data in flight, a
        subsequent small 'send()' is buffered rather than immediately
        transmitted, per Nagle's algorithm as specified in RFC 1122
        §4.2.3.4 ("When to Send Data" -> "Nagle Algorithm"):

            "If there is unacknowledged data (i.e., SND.NXT > SND.UNA),
             then the sending TCP buffers all user data (regardless of
             the PSH bit) until the outstanding data has been
             acknowledged or until the TCP can send a full-sized
             segment (Eff.snd.MSS bytes; see Section 4.2.3.4)."

        Nagle's purpose is to avoid generating "tinygrams" - tiny
        segments whose header overhead dominates the payload, wasting
        bandwidth and inducing unnecessary network load. The
        algorithm coalesces small writes until either:

          (a) all previously-sent data is ACKed, OR
          (b) enough data has accumulated to fill a full MSS.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Application sends 1 byte (b"a"). The session has no
               outstanding data, so Nagle does NOT apply - the byte
               is transmitted immediately on the next tick.
            3. Application sends 1 more byte (b"b"). Now SND.NXT >
               SND.UNA (the b"a" is in flight, unacked) AND the
               buffered amount (1 byte) is far below MSS. Nagle's
               condition (a) and (b) both fail to release the
               write. The next tick must NOT transmit anything.

        Required wire-level expectations:

            Tick after first send: one segment of 1 byte (b"a")
                with seq=LOCAL__ISS+1, payload=b"a".
            Tick after second send (with first byte still unacked):
                NO segment must be emitted.

        End state assertions (after the second send + tick):

            session._snd_nxt == LOCAL__ISS + 1 + 1   (only the b"a"
                                                       byte advanced
                                                       seq space; b"b"
                                                       is still in the
                                                       buffer waiting)
            session._snd_una == LOCAL__ISS + 1       (peer has not
                                                       ACKed yet)
            len(session._tx_buffer) == 2             (both bytes still
                                                       in the buffer
                                                       since no ACK has
                                                       purged them)
            state == ESTABLISHED

        [FLAGS BUG] - RFC 1122 §4.2.3.4 deviation
        ----------------------------------------------------------
        '_transmit_data' has no Nagle guard. Its loop is:

            remaining_data_len = len(self._tx_buffer) - self._tx_buffer_nxt
            usable_window = self._snd_ewn - self._tx_buffer_nxt
            transmit_data_len = min(self._snd_mss, usable_window,
                                    remaining_data_len)
            if remaining_data_len:
                if transmit_data_len:
                    ... transmit ...

        It transmits as soon as ANY buffered data is present and the
        window allows ANY bytes through, regardless of how small the
        segment would be or whether prior bytes are still unacked.
        Each application 'send()' of a small payload immediately
        produces a tinygram, generating 41+ bytes of header overhead
        per byte of payload on interactive workloads.

        RFC 1122 makes Nagle a SHOULD - implementations may omit it
        and provide a TCP_NODELAY-equivalent disable mechanism for
        applications that need the lower latency. PyTCP currently
        does both NEITHER: Nagle is not implemented, and there is no
        per-connection option to turn it off (because there is
        nothing to turn off). The 100%-RFC-compliant behaviour is
        "Nagle on by default", which this test pins.

        This test is expected to FAIL on current code with the second
        tick producing a 1-byte segment. The fix requires adding a
        Nagle guard to '_transmit_data' that suppresses transmission
        when 'self._snd_nxt > self._snd_una' AND
        'transmit_data_len < self._snd_mss', releasing the buffered
        bytes only when an ACK advances 'SND.UNA' (clearing the
        outstanding-data condition) or when the buffered amount
        reaches a full MSS.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # First send: 1 byte. No outstanding data yet, so Nagle does
        # not gate this segment - it must fire on the next tick.
        session.send(data=b"a")
        first_tx = self._advance(ms=1)
        self.assertEqual(
            len(first_tx),
            1,
            msg=(
                "Setup precondition: with no outstanding data, the "
                "first 1-byte 'send()' must transmit immediately on "
                "the next tick (Nagle does not apply when "
                "SND.NXT == SND.UNA)."
            ),
        )
        first_seg = self._parse_tx(first_tx[0])
        self.assertEqual(
            first_seg.payload,
            b"a",
            msg="Setup precondition: first segment must carry the b'a' byte.",
        )

        # Snapshot state before the second send.
        snd_nxt_after_first = session._snd_nxt
        snd_una_after_first = session._snd_una
        self.assertGreater(
            snd_nxt_after_first,
            snd_una_after_first,
            msg=(
                "Setup precondition: SND.NXT must be greater than "
                "SND.UNA - i.e. there must be unacknowledged data in "
                "flight - for Nagle to apply on the next send."
            ),
        )

        # Second send: 1 byte. With outstanding data and a sub-MSS
        # buffered amount, Nagle MUST suppress immediate transmission.
        session.send(data=b"b")
        second_tx = self._advance(ms=1)

        self.assertEqual(
            second_tx,
            [],
            msg=(
                "RFC 1122 §4.2.3.4 (Nagle): with outstanding data "
                "(SND.NXT > SND.UNA) and a sub-MSS buffered amount "
                "(1 byte << MSS), 'send()' must be coalesced - the "
                "buffered byte must NOT be transmitted until either "
                "the outstanding data is ACKed or the buffer reaches "
                "a full MSS. Got "
                f"{len(second_tx)} TX frames (tinygram emission)."
            ),
        )

        # State invariants after the suppressed second send.
        self.assertEqual(
            session._snd_nxt,
            snd_nxt_after_first,
            msg=(
                "'_snd_nxt' must NOT advance during the Nagle-suppressed "
                "tick - the b'b' byte is still buffered, not on the wire."
            ),
        )
        self.assertEqual(
            session._snd_una,
            snd_una_after_first,
            msg="'_snd_una' must be unchanged - the peer has not ACKed anything.",
        )
        self.assertEqual(
            len(session._tx_buffer),
            2,
            msg=(
                "Both bytes must still be in the TX buffer - the b'a' "
                "byte is in flight (not yet ACKed and purged), and the "
                "b'b' byte is waiting for Nagle to release it."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Nagle suppression must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_send__send_in_close_wait_is_allowed_and_transmits_data(self) -> None:
        """
        Ensure that an application can still 'send()' data after the
        peer has closed its write half (i.e. after we have moved to
        CLOSE_WAIT) and that the data is actually transmitted on the
        wire, per RFC 9293 §3.10.4 / §3.5.2:

            "CLOSE-WAIT - represents waiting for a connection
             termination request from the local user."

        TCP connections are independently half-closable. The peer
        sending FIN closes ONLY their send direction (= our receive
        direction); our send direction is still open and we MUST
        accept further writes from the application until WE close.
        Specifically:

          - 'send()' must accept the data into the TX buffer (no
            TcpSessionError).
          - The session's '_transmit_data' path must remain active
            in CLOSE_WAIT and emit a data segment on the next tick.
          - The segment's 'ack' field must include peer's FIN's seq
            byte (i.e. ACK = peer_ISS + 1 + 1 = peer_ISS + 2),
            piggybacking the acknowledgement of the FIN onto our
            outbound data.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Peer sends FIN+ACK with seq=peer_ISS+1 (their
               next-to-send byte; they have sent no data, only the
               FIN). This advances RCV.NXT to peer_ISS+2 and
               transitions us to CLOSE_WAIT.
            3. Application calls 'send(data=b"after fin")'. The 9
               bytes are accepted into the TX buffer; 'send()'
               returns 9.
            4. Tick the virtual clock. '_transmit_data' must fire the
               buffered data as a segment with the spec'd shape.

        Required wire shape of the outbound data segment:

            sport     = STACK__PORT
            dport     = PEER__PORT
            seq       = LOCAL__ISS + 1     (= SND.NXT post-handshake;
                                             peer's FIN+ACK ACKed our
                                             SYN at ISS+1, so SND.UNA
                                             = ISS+1 = SND.NXT and our
                                             next byte is ISS+1)
            ack       = PEER__ISS + 2      (= RCV.NXT; consumes peer's
                                             SYN's 1 byte + FIN's 1
                                             byte from peer's seq
                                             space)
            flags     = {PSH, ACK}         (PSH on the last segment
                                             of the write per RFC 1122
                                             §4.2.2.2; ACK piggybacks
                                             the FIN acknowledgement)
            payload   = b"after fin"
            len       = 9
            mss       = None
            wscale    = None
            win       = 65535

        Side effects asserted:

            * 'session._snd_nxt' advances by len(payload).
            * 'session._snd_una' is unchanged - peer has not ACKed
              our new data.
            * 'session.state' remains 'FsmState.CLOSE_WAIT' (sending
              data does NOT trigger our half-close; only an explicit
              'close()' transitions toward LAST_ACK).
            * The session's '_closing' flag remains False.

        This test pins the contract that 'send()' must work in
        CLOSE_WAIT. Under current code, 'send()' allows CLOSE_WAIT
        explicitly:

            if self._state in {FsmState.ESTABLISHED, FsmState.CLOSE_WAIT}:
                ... extend buffer ...
                return len(data)
            raise TcpSessionError(...)

        and '_transmit_data' includes CLOSE_WAIT in its transmit
        guard. The 'flags={PSH, ACK}' assertion will FAIL until the
        cross-cutting PSH bug surfaced by tests #1 and #2 is fixed;
        all other assertions pass today. The test is therefore a
        positive-control regression guard for the CLOSE_WAIT-send
        path PLUS an additional surface for the PSH bug to be
        verified against.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Peer half-closes by sending FIN+ACK with no data. Their
        # seq is peer_ISS+1 (the byte after their SYN); their ack
        # is LOCAL__ISS+1 (acknowledging our SYN, which they already
        # acked during the handshake's SYN+ACK).
        peer_fin_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin_ack)

        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="Setup precondition: peer's FIN+ACK must transition us to CLOSE_WAIT.",
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 2,
            msg=(
                "Setup precondition: '_rcv_nxt' must equal "
                "peer_ISS + 2 after consuming peer's SYN and FIN seq "
                "bytes."
            ),
        )

        # Application send during CLOSE_WAIT must succeed.
        payload = b"after fin"
        bytes_sent = session.send(data=payload)
        self.assertEqual(
            bytes_sent,
            len(payload),
            msg=(
                f"'send()' must accept all {len(payload)} bytes into "
                f"the TX buffer in CLOSE_WAIT (RFC 9293 §3.10.4 - we "
                f"may still write until WE close). Got {bytes_sent}."
            ),
        )

        snd_una_before = session._snd_una
        snd_nxt_before = session._snd_nxt

        tx_frames = self._advance(ms=1)
        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "A 'send()' in CLOSE_WAIT must produce exactly one "
                "outbound data segment on the next tick. Got "
                f"{len(tx_frames)} TX frames."
            ),
        )

        seg = self._parse_tx(tx_frames[0])
        self._assert_segment(
            seg,
            flags=frozenset({"PSH", "ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 2,
            payload=payload,
            mss=None,
            wscale=None,
            win=65535,
        )

        self.assertEqual(
            session._snd_nxt,
            snd_nxt_before + len(payload),
            msg=("'_snd_nxt' must advance by len(payload) after " "transmitting the data segment in CLOSE_WAIT."),
        )
        self.assertEqual(
            session._snd_una,
            snd_una_before,
            msg=("'_snd_una' must be unchanged - the peer has not yet " "ACK'd the new data."),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg=(
                "Sending data in CLOSE_WAIT must NOT transition the "
                "session - we only move to LAST_ACK when WE close, "
                "via 'session.close()'."
            ),
        )
        self.assertFalse(
            session._closing,
            msg=(
                "Sending data must not set the '_closing' flag - that "
                "flag is owned by 'close()' and gates the eventual "
                "FIN emission."
            ),
        )

    def test__data_transfer_send__send_after_close_raises_immediately(self) -> None:
        """
        Ensure that any 'send()' issued AFTER the application has
        called 'close()' is rejected with 'TcpSessionError', per
        RFC 9293 §3.10.6 ("CLOSE Call"):

            "ESTABLISHED STATE: ...
             Any subsequent SEND issued is illegal and will return
             'error: connection closing' response."

        The spec is clear and unconditional - once 'close()' has
        been invoked, the application has relinquished its right to
        write further data on the connection, and any subsequent
        'send()' MUST be rejected with the same closing-error
        response REGARDLESS of where the FSM currently sits in its
        teardown sequence (still in ESTABLISHED waiting for the TX
        buffer to drain, in FIN_WAIT_1 with the FIN on the wire, in
        FIN_WAIT_2 waiting for peer's FIN, etc.).

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Confirm 'send()' works in this state (positive
               control - the precondition is that send is normally
               legal so we know the post-close raise is meaningful).
            3. Call 'session.close()'. This sets the '_closing'
               flag.
            4. Immediately call 'session.send(data=b"after close")'.
               Expect 'TcpSessionError' to be raised.

        Note that under the current implementation, 'close()' is
        DEFERRED: it sets '_closing = True' but does NOT change the
        FSM state synchronously. The state transition to FIN_WAIT_1
        happens on the next timer tick, gated on
        ('_closing AND not _tx_buffer'). RFC 9293 §3.10.6's rule
        (no SEND after CLOSE) does NOT depend on state having
        transitioned - it depends solely on whether the application
        has called 'close()'. The 100% RFC-compliant test therefore
        invokes 'send()' BEFORE any tick, so the state is still
        ESTABLISHED but '_closing' is True.

        [FLAGS BUG] - RFC 9293 §3.10.6 deviation
        ----------------------------------------------------------
        Current 'TcpSession.send()' guards on FSM state only:

            def send(self, *, data: bytes) -> int:
                if self._state in {FsmState.ESTABLISHED, FsmState.CLOSE_WAIT}:
                    with self._lock__tx_buffer:
                        self._tx_buffer.extend(data)
                        return len(data)
                raise TcpSessionError("TCP session not in ESTABLISHED or CLOSE_WAIT state")

        It does not consult '_closing'. Between 'close()' (which
        sets '_closing = True' but leaves state at ESTABLISHED)
        and the next timer tick (which transitions to FIN_WAIT_1),
        the connection is effectively closed but 'send()' continues
        to accept writes. Those writes get appended to the TX
        buffer; on the tick that fires the FIN, the freshly-buffered
        bytes go out as a data segment AHEAD of the FIN - the
        application's "post-close" data ends up on the wire in
        violation of the spec, breaking the contract that 'close()'
        is a hard write-side termination.

        This test is expected to FAIL on current code; the
        post-close 'send()' returns the byte count instead of
        raising. The fix is to add an early '_closing' check at
        the top of 'send()':

            if self._closing or self._state not in {ESTABLISHED, CLOSE_WAIT}:
                raise TcpSessionError(...)

        With that fix in place this test passes, and the post-close-
        but-pre-tick window where stale writes leak onto the wire
        is closed.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Positive control: 'send()' works in ESTABLISHED before close().
        bytes_sent = session.send(data=b"pre close")
        self.assertEqual(
            bytes_sent,
            len(b"pre close"),
            msg="Setup precondition: 'send()' must work normally in ESTABLISHED before close().",
        )

        # Application closes the connection.
        session.close()
        self.assertTrue(
            session._closing,
            msg="Setup precondition: 'close()' must set the '_closing' flag.",
        )

        # Per RFC 9293 §3.10.6, any subsequent 'send()' must be
        # rejected with the closing-error response.
        with self.assertRaises(TcpSessionError) as error_ctx:
            session.send(data=b"after close")

        self.assertIn(
            "closing",
            str(error_ctx.exception).lower(),
            msg=(
                "RFC 9293 §3.10.6 requires the post-close 'send()' "
                "rejection to surface a 'connection closing' error "
                "to the application. The exception message should "
                "convey that the connection is closing. Got: "
                f"{error_ctx.exception!r}."
            ),
        )

    def test__data_transfer_send__multi_mss_payload_segments_with_psh_only_on_last(self) -> None:
        """
        Ensure that an application 'send()' of a payload larger than
        MSS is segmented into MSS-sized chunks, each chunk emitted on
        a successive virtual-clock tick, with the PSH bit set ONLY
        on the FINAL segment of the write per RFC 1122 §4.2.2.2:

            "When all the data is sent, the sender SHOULD set the
             PSH bit in the LAST segment."

        Implementation strategy:

            * Pre-set 'session._snd_ewn' to the peer's advertised
              receive window (PEER__WIN = 64240). After the handshake
              completes, '_snd_ewn' starts at one MSS (1460); the
              session's slow-start-style window doubling is its own
              concern, exercised separately in the data_transfer__window
              file. Bypassing it here keeps THIS test focused on
              segmentation and the PSH-on-last contract.

            * Send a payload of '3 * MSS - 380 = 4000' bytes. With
              MSS=1460 this produces three segments: 1460 + 1460 +
              1080. The first two are MSS-sized (NOT the last
              segment of the write); the third is a 1080-byte
              fragment that DRAINS the TX buffer (IS the last
              segment of the write).

        Required wire shapes per segment:

            Segment 1 (tick 1):
                seq     = LOCAL__ISS + 1
                ack     = PEER__ISS + 1
                flags   = {ACK}             (no PSH - more data
                                             follows in the buffer)
                payload = first 1460 bytes of the write
                len     = 1460

            Segment 2 (tick 2):
                seq     = LOCAL__ISS + 1 + 1460
                ack     = PEER__ISS + 1
                flags   = {ACK}             (no PSH - 1080 bytes
                                             still in the buffer)
                payload = next 1460 bytes of the write
                len     = 1460

            Segment 3 (tick 3):
                seq     = LOCAL__ISS + 1 + 2920
                ack     = PEER__ISS + 1
                flags   = {PSH, ACK}        (PSH set - this segment
                                             drains the TX buffer
                                             per RFC 1122 §4.2.2.2)
                payload = final 1080 bytes of the write
                len     = 1080

        After all three ticks:

            session._snd_nxt == LOCAL__ISS + 1 + 4000
            session._snd_una == LOCAL__ISS + 1   (peer has not ACKed)
            session.state    == ESTABLISHED

        [FLAGS BUG] - RFC 1122 §4.2.2.2 deviation
        ----------------------------------------------------------
        Same root cause as the single-segment test in this file:
        '_transmit_packet' has no 'flag_psh' parameter, so PSH is
        NEVER set on outbound data segments. Segments 1 and 2 of
        this scenario happen to match the spec because the spec also
        requires PSH NOT be set on non-last segments; segment 3
        fails because the spec REQUIRES PSH and current code never
        sets it.

        The fix is the same single-line plumbing as for test #1:
        thread 'flag_psh' through '_transmit_packet' and set it from
        '_transmit_data' when 'transmit_data_len ==
        remaining_data_len' (the segment drains the buffer = it is
        the last segment of the write at the time of transmission).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Bypass slow-start so all three segments can fly without
        # waiting for peer ACKs - this test is about segmentation and
        # PSH placement, not congestion control.
        session._snd_ewn = PEER__WIN

        payload = b"X" * 4000
        bytes_sent = session.send(data=payload)
        self.assertEqual(
            bytes_sent,
            len(payload),
            msg=f"'send()' must accept all {len(payload)} bytes into the TX buffer. Got {bytes_sent}.",
        )

        # Tick 1: first MSS-sized segment, no PSH.
        tx_tick_1 = self._advance(ms=1)
        self.assertEqual(
            len(tx_tick_1),
            1,
            msg="Tick 1 must produce exactly one outbound segment (the first MSS chunk).",
        )

        seg_1 = self._parse_tx(tx_tick_1[0])
        self._assert_segment(
            seg_1,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=payload[:1460],
            win=65535,
            mss=None,
            wscale=None,
        )

        # Tick 2: second MSS-sized segment, still no PSH (1080 bytes
        # remain in the buffer).
        tx_tick_2 = self._advance(ms=1)
        self.assertEqual(
            len(tx_tick_2),
            1,
            msg="Tick 2 must produce exactly one outbound segment (the second MSS chunk).",
        )

        seg_2 = self._parse_tx(tx_tick_2[0])
        self._assert_segment(
            seg_2,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1 + 1460,
            ack=PEER__ISS + 1,
            payload=payload[1460:2920],
            win=65535,
            mss=None,
            wscale=None,
        )

        # Tick 3: final 1080-byte segment, PSH set (this drains the
        # TX buffer - per RFC 1122 §4.2.2.2 it is the LAST segment of
        # the write).
        tx_tick_3 = self._advance(ms=1)
        self.assertEqual(
            len(tx_tick_3),
            1,
            msg="Tick 3 must produce exactly one outbound segment (the final fragment).",
        )

        seg_3 = self._parse_tx(tx_tick_3[0])
        self._assert_segment(
            seg_3,
            flags=frozenset({"PSH", "ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1 + 2920,
            ack=PEER__ISS + 1,
            payload=payload[2920:],
            win=65535,
            mss=None,
            wscale=None,
        )

        # Final state checks: SND.NXT covers the full 4000 bytes,
        # SND.UNA still at the post-handshake value (peer has not
        # ACKed yet), state stays ESTABLISHED.
        self.assertEqual(
            session._snd_nxt,
            LOCAL__ISS + 1 + len(payload),
            msg=("After three segments totalling len(payload) bytes, " "'_snd_nxt' must equal ISS + 1 + len(payload)."),
        )
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1,
            msg=("'_snd_una' must be unchanged - the peer has not yet " "acknowledged any of the data we sent."),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Sending data must not transition the session out of ESTABLISHED.",
        )
