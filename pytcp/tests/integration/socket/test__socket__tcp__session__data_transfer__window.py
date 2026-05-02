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
This module contains integration tests for the TCP window-management
machinery in the 'TcpSession' state machine, covering both the
receive-side advertisement of '_rcv_wnd' and the send-side handling
of the peer's advertised window (including the WSCALE-when-not-
advertised rule of RFC 7323 §2.2 and the mid-flight window-shrink
robustness rule of RFC 9293 §3.8.6).

Reference RFCs:
    RFC 9293 §3.8.6      Window management (advertised window
                         semantics, robustness against window shrink)
    RFC 9293 §3.10.7.4   Synchronized state segment processing
    RFC 1122 §4.2.2.16   TCP MUST be robust against shrinking windows
    RFC 7323 §2.2        WSCALE option only when offered bilaterally

pytcp/tests/integration/socket/test__socket__tcp__session__data_transfer__window.py

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

# Initial value 'TcpSession' assigns to '_rcv_wnd' (and thus the
# advertised window in our outbound segments before any data has
# been received).
LOCAL__INITIAL_RCV_WND: int = 65535


class TestTcpDataTransfer__Window(TcpSessionTestCase):
    """
    Integration tests for the TCP window-management machinery, both
    the receive-side advertised window we put on outbound segments
    and the send-side interpretation of the peer's advertised window.
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

    def test__window__advertised_rcv_wnd_shrinks_as_rx_buffer_fills(self) -> None:
        """
        Ensure that the advertised receive window in our outbound
        segments SHRINKS as inbound data accumulates in '_rx_buffer'
        but is not yet consumed by 'recv()'. The advertised window is
        the receiver's promise of "how many more bytes I can accept
        right now" - it MUST reflect remaining buffer capacity, or
        the peer's flow-control loop has nothing to throttle against
        and a slow consumer will see unbounded buffer growth.

        RFC 9293 §3.8.6:

            "The window sent in each segment indicates the range of
             sequence numbers the sender of the window (the data
             receiver) is currently prepared to accept.  ...  The
             receiver of data controls the flow of data from the
             sender."

        and §3.8.6.2.1 (window management example):

            "The window indicates an allowed number of octets that
             the sender may transmit before receiving further
             permission."

        and the receiver-half of §3.8.6.2.2:

            "The receiver should generally accept further data only
             up to the right edge of the previously advertised
             window. ... To avoid the SWS [silly window syndrome],
             the receiver SHOULD NOT advertise small increments to
             the right window edge."

        The contract is therefore: advertised window = receive
        buffer capacity remaining (with hysteresis to avoid SWS).
        Constant-65535 advertisement violates the basic contract -
        a slow application can never produce backpressure to the
        peer.

        Scenario:

            1. Drive handshake to ESTABLISHED. Initial advertised
               '_rcv_wnd' is LOCAL__INITIAL_RCV_WND (65535) and
               '_rx_buffer' is empty.
            2. Peer sends DATA SEGMENT #1 (1460 bytes of 'X' at
               SEQ = PEER__ISS + 1). Per RFC 1122 §4.2.3.2's
               "every-other-segment" rule, segment #1 alone arms
               the delayed-ACK timer rather than producing an
               inline ACK; '_rx_buffer' now holds 1460 bytes but
               we have not yet had to advertise the new window on
               the wire.
            3. Peer sends DATA SEGMENT #2 (1460 bytes of 'Y' at
               SEQ = PEER__ISS + 1 + 1460). Two pending unacked
               segments triggers the inline ACK. The ACK is built
               AFTER segment #2's bytes have been enqueued, so the
               buffer occupancy at that moment is 2920 bytes.

        Assertion (the spec encoding):

            * Inline ACK from step 3 carries 'win = 65535 - 2920 =
              62615' - the window advertisement reflects remaining
              buffer capacity per RFC 9293 §3.8.6.

        Side assertions (sanity / setup):

            * Step 2 produces NO inline ACK (delayed-ACK first
              segment).
            * Step 3 produces exactly ONE inline ACK
              (every-other-segment rule).
            * Inline ACK acknowledges both segments cumulatively
              ('ack == PEER__ISS + 1 + 2920').
            * '_rx_buffer' contains 2920 bytes in arrival order
              ('X'*1460 + 'Y'*1460).
            * State remains ESTABLISHED.

        [FLAGS BUG] - 'TcpSession.__init__' sets '_rcv_wnd = 65535'
        on construction and there is no code path anywhere in the
        session that updates it - not after '_enqueue_rx_buffer',
        not after 'recv()' drains the buffer, not on segment send.
        '_transmit_packet' (line 556) reads the constant value and
        passes it as 'tcp__win' on every outbound segment, so the
        advertised window is always 65535 regardless of buffer
        occupancy.

        The fix is to make '_rcv_wnd' a derived quantity rather than
        a stored constant. Two equivalent shapes:

            (a) Update '_rcv_wnd' inside both '_enqueue_rx_buffer'
                (line 598) and the 'recv()' drain block (line 482),
                holding the invariant 'rcv_wnd = MAX - len(_rx_buffer)'
                at all times.
            (b) Compute '_rcv_wnd' as a '@property' returning
                'max(0, MAX - len(self._rx_buffer))'.

        Form (b) is one fewer mutation surface and is preferred
        unless the receive-side acceptability check (lines 1350-
        1356) needs a stable snapshot per packet processing - which
        on inspection it does not, since the buffer length doesn't
        change inside that block.

        On current code this test will see 'win=65535' on the
        inline ACK, failing the assertion '65535 == 62615'.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Setup precondition: window starts at the constant initial
        # value, buffer is empty.
        self.assertEqual(
            session._rcv_wnd,
            LOCAL__INITIAL_RCV_WND,
            msg=(
                "Setup precondition: '_rcv_wnd' starts at the "
                f"initial value {LOCAL__INITIAL_RCV_WND} after the "
                "handshake completes."
            ),
        )
        self.assertEqual(
            len(session._rx_buffer),
            0,
            msg="Setup precondition: '_rx_buffer' is empty before any peer data arrives.",
        )

        # SEGMENT #1: 1460 bytes of 'X' at PEER__ISS + 1. Per the
        # delayed-ACK every-other-segment rule, this segment alone
        # only arms the timer - no inline ACK fires.
        seg1_payload = b"X" * 1460
        seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=seg1_payload,
        )
        seg1_inline = self._drive_rx(frame=seg1)
        self.assertEqual(
            seg1_inline,
            [],
            msg=(
                "Setup precondition: SEGMENT #1 must not produce an "
                "inline ACK - the delayed-ACK every-other-segment "
                "rule (RFC 1122 §4.2.3.2) arms the timer for the "
                "first pending segment and waits for the second."
            ),
        )

        # SEGMENT #2: 1460 bytes of 'Y' at PEER__ISS + 1 + 1460.
        # Two pending segments triggers the inline ACK.
        seg2_payload = b"Y" * 1460
        seg2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + len(seg1_payload),
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=seg2_payload,
        )
        seg2_inline = self._drive_rx(frame=seg2)
        self.assertEqual(
            len(seg2_inline),
            1,
            msg=(
                "Setup precondition: SEGMENT #2 must produce exactly "
                "one inline ACK per the delayed-ACK every-other-segment "
                "rule (RFC 1122 §4.2.3.2)."
            ),
        )

        ack = self._parse_tx(seg2_inline[0])

        # Sanity: the ACK acknowledges both segments cumulatively.
        self.assertEqual(
            ack.ack,
            PEER__ISS + 1 + len(seg1_payload) + len(seg2_payload),
            msg=(
                "The inline ACK must acknowledge both segments "
                "cumulatively, not just SEGMENT #2 alone - "
                "delayed-ACK accumulates and emits a single ACK "
                "covering all pending bytes."
            ),
        )

        # The spec encoding: advertised window reflects the 2920
        # bytes now sitting in '_rx_buffer'. RFC 9293 §3.8.6.
        expected_window = LOCAL__INITIAL_RCV_WND - (len(seg1_payload) + len(seg2_payload))
        self.assertEqual(
            ack.win,
            expected_window,
            msg=(
                f"Advertised receive window must shrink to "
                f"{expected_window} ({LOCAL__INITIAL_RCV_WND} - 2920 "
                "bytes in '_rx_buffer') per RFC 9293 §3.8.6 - the "
                "window indicates remaining capacity, and a "
                f"constant {LOCAL__INITIAL_RCV_WND} advertisement "
                "breaks the peer's flow-control loop. A slow "
                "application would never produce backpressure and "
                "the buffer would grow unbounded."
            ),
        )

        # State assertions: data made it into the buffer in order;
        # session still healthy.
        self.assertEqual(
            bytes(session._rx_buffer),
            seg1_payload + seg2_payload,
            msg=(
                "'_rx_buffer' must hold both segments in arrival "
                "order - the delayed-ACK path enqueues bytes before "
                "deciding whether to emit the ACK."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED through the data-transfer.",
        )

    def test__window__peer_wscale_ignored_when_we_did_not_advertise(self) -> None:
        """
        Ensure that a WSCALE option present on the peer's SYN+ACK is
        IGNORED when we did not offer WSCALE on our outbound SYN. The
        send-side window scale '_snd_wsc' must remain at zero, and the
        peer's advertised window must be applied raw (no shift) to
        '_snd_wnd'.

        RFC 7323 §2.2:

            "A TCP MAY send the WSopt in only the <SYN> segment of
             the connection, but if it is sent in only that segment,
             the connection is opened with the no-window-scaling
             default. ... A WSopt is not legal unless it is offered
             in both directions [in the connection's <SYN> and
             <SYN,ACK>]; if it is offered in only one direction, it
             MUST be ignored."

        The PyTCP stack always sends 'tcp__wscale=0' on its outbound
        SYN / SYN+ACK ('TcpSession._transmit_packet' at line 558),
        which RFC 7323 explicitly equates with "no offer". Therefore,
        regardless of what the peer advertises on the reverse leg,
        the connection MUST be opened with no window scaling on
        either side. Applying the peer's WSCALE in this asymmetric
        case would cause us to over-interpret every subsequent
        'SEG.WND' as 'win << wsc', wildly inflating '_snd_wnd' and
        permitting us to send far past the peer's actual receive
        capacity - a textbook flow-control violation that can drop
        bytes on the floor at the peer or stall the connection on
        the next ACK if peer rejects out-of-window data.

        Scenario:

            1. Build a session and emit our outbound SYN. Confirm
               our SYN's WSCALE option carries 'wscale=0' - i.e. we
               did NOT advertise window scaling.
            2. Peer replies with a SYN+ACK that DOES advertise
               WSCALE = 7 (RFC 7323's "shift by 128" example) and
               'win = 1024' - a deliberately small raw window so
               the bug-vs-fix gap is observable in '_snd_wnd' rather
               than buried in 32-bit arithmetic.
            3. After the handshake completes, inspect:
                  * 'session._snd_wsc == 0' - peer's WSCALE was
                    ignored per RFC 7323 §2.2.
                  * 'session._snd_wnd == 1024' - the raw advertised
                    window applied with NO left shift, NOT
                    '1024 << 7 == 131072'.

        Sanity assertions:

            * State is ESTABLISHED at end.
            * The third-leg ACK we emit on receiving the SYN+ACK
              also carries 'wscale=None' or '0' (we still don't
              advertise WSCALE - the bilateral non-offer is symmetric).

        [FLAGS BUG] - 'TcpSession._tcp_fsm_listen' (line 1028) and
        'TcpSession._tcp_fsm_syn_sent' (line 1121) both unconditionally
        execute:

            self._snd_wsc = packet_rx_md.tcp__wscale

        with no guard checking whether WE advertised WSCALE on our
        outbound SYN. The result: any peer-advertised WSCALE flows
        into '_snd_wsc' and gets applied to '_snd_wnd' on every
        subsequent ACK. Current code with this test:

            _snd_wsc = 7
            _snd_wnd = 1024 << 7 = 131072

        The fix is to gate both assignments on a per-session
        '_advertised_wscale' flag (or, since we currently hard-code
        wscale=0 on outbound SYN at line 558, simply set
        '_snd_wsc = 0' unconditionally and drop the assignment from
        peer metadata until we add bilateral WSCALE support):

            # Asymmetric WSCALE per RFC 7323 §2.2 - we did not
            # advertise, so peer's option is ignored and the shift
            # remains zero.
            self._snd_wsc = 0
            self._snd_wnd = packet_rx_md.tcp__win

        On current code this test will see '_snd_wsc == 7' and
        '_snd_wnd == 131072' and fail at the first of those
        assertions. The test deliberately checks BOTH so a
        future code path that re-introduced the shift via a
        different mechanism still gets caught.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        # PyTCP defaults to advertising WSCALE on outbound SYN
        # (RFC 7323 §2.2 / §2.3 throughput-friendly default).
        # This test deliberately exercises the asymmetric-non-offer
        # path, so opt out of advertising via the
        # '_advertise_wscale' flag before driving CONNECT.
        session._advertise_wscale = False
        session.tcp_fsm(syscall=SysCall.CONNECT)

        # Initial SYN fires on the first tick. Inspect it to confirm
        # we did NOT advertise WSCALE.
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        syn_probe = self._parse_tx(syn_tx[0])
        self.assertIsNone(
            syn_probe.wscale,
            msg=(
                "Setup precondition: our outbound SYN must carry "
                "NO WSCALE option (RFC 7323 §2.2's 'did not offer' "
                "encoding). PyTCP's TX path emits the option only "
                "when 'tcp__wscale' is truthy "
                "(packet_handler__tcp__tx.py line 130), so passing "
                "'tcp__wscale=0' from '_transmit_packet' line 558 "
                "produces the option-absent wire form, and this "
                "test's bilateral-non-offer rule depends on it "
                "staying that way."
            ),
        )

        # Peer's SYN+ACK advertises WSCALE = 7 (a deliberate offer)
        # and a deliberately small raw window so the bug's effect
        # is observable.
        peer_raw_win = 1024
        peer_wscale = 7
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=peer_raw_win,
            mss=PEER__MSS,
            wscale=peer_wscale,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: handshake must complete to ESTABLISHED.",
        )

        # The spec encoding: peer's WSCALE was ignored; '_snd_wsc'
        # remains 0; '_snd_wnd' is the raw advertised window with
        # no left shift.
        self.assertEqual(
            session._snd_wsc,
            0,
            msg=(
                "Peer's WSCALE option (=7) on the SYN+ACK MUST be "
                "ignored because we did not offer WSCALE on our "
                "outbound SYN (RFC 7323 §2.2). '_snd_wsc' must "
                "remain at the no-scaling default of 0."
            ),
        )
        self.assertEqual(
            session._snd_wnd,
            peer_raw_win,
            msg=(
                f"'_snd_wnd' must equal the raw advertised window "
                f"({peer_raw_win}) with no left shift - the peer's "
                f"WSCALE = {peer_wscale} was ignored per RFC 7323 "
                f"§2.2 because the offer was unilateral. Applying "
                f"the shift would yield {peer_raw_win << peer_wscale}, "
                "wildly inflating the send window and permitting "
                "transmission past the peer's actual receive "
                "capacity."
            ),
        )

    def test__window__no_spurious_emissions_when_peer_shrink_makes_usable_window_negative(self) -> None:
        """
        Ensure that when the peer shrinks the advertised window
        mid-flight such that the "usable window"
        (SND.UNA + SND.WND - SND.NXT) goes NEGATIVE, the session
        does NOT emit any spurious segments while waiting for the
        peer to reopen the window or for RTO to fire.

        RFC 9293 §3.8.6:

            "However, a sending TCP peer MUST be robust against
             window shrinking, which may cause the 'usable window'
             (see Section 3.8.6.2.1) to become negative.

             If this happens, the sender SHOULD NOT send new data,
             but SHOULD retransmit normally the old unacknowledged
             data between SND.UNA and SND.UNA+SND.WND. The sender
             MAY also retransmit old data beyond SND.UNA+SND.WND,
             but SHOULD NOT time out the connection if data beyond
             the right window edge is not acknowledged."

        RFC 1122 §4.2.2.16:

            "A TCP receiver SHOULD NOT shrink the window, i.e.,
             move the right window edge to the left.  However, a
             sending TCP MUST be robust against window shrinking,
             which may cause the 'usable window' to become negative."

        "Robust" here means: handle the shrink gracefully, with no
        crashes, no invalid wire output, and no gratuitous traffic
        spam. The current code violates the third clause - it
        emits an empty bare-ACK segment on every timer tick after
        the shrink, because '_transmit_data's gate
        ('if transmit_data_len:') treats the negative
        'transmit_data_len' as truthy and the subsequent slice
        '_tx_buffer[_tx_buffer_nxt : _tx_buffer_nxt + (-N)]'
        produces an empty bytes object that gets shipped through
        '_transmit_packet(data=b\"\")'. The peer then sees a stream
        of duplicate ACKs from us, which (depending on their stack)
        can trip THEIR fast-retransmit logic at three duplicates -
        a textbook congestion-collapse vector triggered by a
        legitimate window shrink.

        Scenario:

            1. Drive handshake to ESTABLISHED. Override the
               post-handshake send-window state so the test sees a
               clean small-window arithmetic:
                  '_snd_ewn = 4380' (3 MSS, bypasses slow-start).
                  '_snd_wnd = 4380' (matches the value we want
                                      peer to have advertised - the
                                      handshake's PEER__WIN of 64240
                                      is too coarse for the shrink
                                      math).
            2. Application sends 4380 bytes. Three full-MSS segments
               fire on the next tick. SND.NXT = LOCAL__ISS + 1 + 4380.
            3. Peer ACKs the FIRST segment (ack = LOCAL__ISS + 1 +
               1460) AND simultaneously SHRINKS the advertised
               window to 1460 (1 MSS). After processing this ACK:
                  SND.UNA = LOCAL__ISS + 1 + 1460
                  SND.WND = 1460
                  Right edge = SND.UNA + SND.WND = LOCAL__ISS + 1 + 2920
                  SND.NXT = LOCAL__ISS + 1 + 4380 (unchanged - already past edge)
                  Usable window = SND.WND - in_flight = 1460 - 2920 = -1460
            4. Application calls 'send()' with another 1460 bytes.
               These go into '_tx_buffer' but cannot be transmitted -
               the new bytes would start at SND.NXT = LOCAL__ISS + 1
               + 4380, which is 1460 bytes past the right edge.
            5. Advance the clock by 10 ms. During this window:
                  * No persist timer (peer's window is 1460, not 0).
                  * No delayed-ACK timer firing (no new data inbound
                    since the shrink ACK).
                  * No RTO firing (RTO is ~1 s).
                  * No legitimate data transmission (usable window
                    is negative).

        Assertion (the spec encoding):

            * 'silent_window_tx' is empty - zero segments emitted in
              the 10 ms window.

        Side assertions (sanity):

            * After the shrink ACK: 'session._snd_una',
              'session._snd_wnd', 'session._snd_ewn' all reflect the
              new state.
            * 'SND.NXT' is unchanged from its pre-shrink value
              (LOCAL__ISS + 1 + 4380).
            * State remains ESTABLISHED.

        [FLAGS BUG] - 'TcpSession._transmit_data' (line 618) opens
        with the unconditional invariant assertion:

            assert self._snd_una <= self._snd_nxt <= \\
                   self._snd_una + self._snd_ewn, \\
                   "*** SEQ outside of TCP sliding window"

        When peer shrinks below in-flight, 'self._snd_ewn' is capped
        to the new 'self._snd_wnd' (the line-922 'min' inside
        '_process_ack_packet'), but 'SND.NXT' is not rolled back -
        we've already transmitted segments past the new right edge,
        and rolling 'SND.NXT' back would itself be invalid. Result:

            SND.NXT > SND.UNA + SND.EWN

        and the assertion fires on the very next timer-driven
        '_transmit_data' invocation. In production builds this is
        an 'AssertionError' that propagates up the FSM dispatch and
        either dies inside the timer thread or aborts the process
        depending on Python's '-O' flag. Either way it is the exact
        opposite of "robust against window shrinking". A subtle
        consequence: if the assertion were stripped (Python '-O'),
        the same path would proceed to compute 'usable_window =
        SND.EWN - _tx_buffer_nxt' as a negative value, pass it
        through 'min()', and emit empty bare-ACK frames on every
        tick - a duplicate-ACK stream that may trip the peer's
        fast-retransmit logic, congestion-collapsing the link.

        The fix has two parts, both required:

        1. Replace the invariant assertion with an early return:

               if not (self._snd_una <= self._snd_nxt
                       <= self._snd_una + self._snd_ewn):
                   return  # peer-shrunk usable window; wait for RTO

           This is the RFC 9293 §3.8.6 "MUST be robust" encoding -
           notice the shrink, refuse to push more data, and let the
           normal RTO machinery cover the unacknowledged segments.

        2. Tighten the inner data-transmit gate so the negative
           'transmit_data_len' path can never fire even if the outer
           guard above is bypassed:

               if transmit_data_len > 0:    # was: if transmit_data_len:

        Both changes are minimal and self-contained. They do not
        affect the linear no-shrink case at all - they only kick
        in when peer shrinks below in-flight data.

        On current code this test will fail at the 'silent_window_tx
        = self._advance(...)' line with an uncaught
        'AssertionError("*** SEQ outside of TCP sliding window")'
        from inside '_transmit_data'. The test wraps the advance
        in 'try / except AssertionError' so the failure surfaces
        as a clean unittest message naming the RFC clause rather
        than as an opaque traceback.
        """

        peer_initial_win = 4380  # 3 * MSS
        peer_shrunk_win = 1460  # 1 * MSS

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Override the handshake-installed send-window state so the
        # arithmetic for the shrink is deterministic and small enough
        # to assert against. The handshake set '_snd_wnd' from the
        # peer's SYN+ACK 'win' (= PEER__WIN = 64240) and '_snd_ewn'
        # to MSS; we want both at the 3-MSS pre-shrink value.
        session._snd_wnd = peer_initial_win
        session._snd_ewn = peer_initial_win

        # Application sends 3 * MSS. All three segments fire on the
        # next tick. SND.NXT advances to LOCAL__ISS + 1 + 4380.
        payload_a = b"A" * 1460
        payload_b = b"B" * 1460
        payload_c = b"C" * 1460
        session.send(data=payload_a + payload_b + payload_c)

        # '_transmit_data' emits at most one segment per timer tick,
        # so we drain three MSS over three ticks.
        initial_tx = self._advance(ms=3)
        self.assertEqual(
            len(initial_tx),
            3,
            msg=(
                "Setup precondition: with '_snd_ewn = 4380' (3 MSS) "
                "and 4380 bytes queued, three full-MSS segments must "
                "fire across three timer ticks (one per tick)."
            ),
        )

        snd_nxt_pre_shrink = session._snd_nxt
        self.assertEqual(
            snd_nxt_pre_shrink,
            LOCAL__ISS + 1 + 4380,
            msg=(
                "Setup precondition: 'SND.NXT' must have advanced past "
                "the three transmitted segments to LOCAL__ISS + 1 + 4380."
            ),
        )

        # Peer ACKs the FIRST segment AND shrinks the window to 1 MSS.
        # After processing this ACK, the right edge sits at
        # SND.UNA + SND.WND = LOCAL__ISS + 1 + 1460 + 1460 =
        # LOCAL__ISS + 1 + 2920, with two segments (B and C) entirely
        # past the new edge.
        peer_shrink_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload_a),
            flags=("ACK",),
            win=peer_shrunk_win,
        )
        self._drive_rx(frame=peer_shrink_ack)

        # Verify the shrink took effect on the session's send-side
        # state.
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1 + len(payload_a),
            msg="The shrink ACK must advance 'SND.UNA' past payload_a.",
        )
        self.assertEqual(
            session._snd_wnd,
            peer_shrunk_win,
            msg=(
                "The shrink ACK's 'win' field must update 'SND.WND' "
                f"to the new {peer_shrunk_win}-byte advertised value."
            ),
        )
        self.assertEqual(
            session._snd_nxt,
            snd_nxt_pre_shrink,
            msg=(
                "The shrink ACK is purely informational about peer's "
                "buffer; it must not move 'SND.NXT' (which still "
                "points at the original 3-segment frontier)."
            ),
        )

        # Application writes another MSS-worth of data after the
        # shrink. These bytes go into '_tx_buffer' but the new
        # SEQ would be LOCAL__ISS + 1 + 4380 - already 1460 bytes
        # past the new right edge.
        post_shrink_payload = b"D" * 1460
        session.send(data=post_shrink_payload)

        # Advance 10 ms. No timer should fire any segment in this
        # window (see scenario docstring for the per-timer breakdown);
        # spec-compliant behaviour is silence. Wrap in try / except so
        # the current code's invariant-assertion crash inside
        # '_transmit_data' surfaces as a clean unittest failure naming
        # the RFC clause rather than as an opaque traceback.
        try:
            silent_window_tx = self._advance(ms=10)
        except AssertionError as exc:  # pragma: no cover - bug path
            self.fail(
                f"Window-shrink robustness: '_transmit_data' crashed "
                f"with AssertionError({exc!s}) on the post-shrink "
                "tick. RFC 9293 §3.8.6 / RFC 1122 §4.2.2.16 require "
                "the sender to be robust against peer window "
                "shrinking, including the case where the new right "
                "edge falls below previously transmitted segments. "
                "The current invariant assertion at line 618 of "
                "tcp__session.py rejects this legal RFC scenario."
            )

        self.assertEqual(
            silent_window_tx,
            [],
            msg=(
                "After a window shrink that pushes the usable window "
                "negative and an application 'send()' that cannot fit, "
                "the wire MUST stay silent until either the peer "
                "reopens the window or RTO fires. RFC 9293 §3.8.6's "
                "robustness clause requires that a sender absorb the "
                "shrink without generating spurious traffic. Got "
                f"{len(silent_window_tx)} unexpected outbound frame(s) "
                "in the 10 ms post-shrink window - typically empty "
                "bare ACKs from '_transmit_data's negative-slice "
                "fall-through."
            ),
        )

        # Sanity: state and frontier unchanged.
        self.assertEqual(
            session._snd_nxt,
            snd_nxt_pre_shrink,
            msg=(
                "'SND.NXT' must not advance during the silent post-shrink "
                "window - no new data can fit and no retransmits are due."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED through the shrink and silent window.",
        )

    def test__window__sub_mss_available_window_is_advertised_as_zero_per_rfc_1122_4_2_3_3(self) -> None:
        """
        Ensure that when the receiver-side available window
        (RCV.WND_MAX - len(_rx_buffer)) drops below one MSS,
        we advertise a window of ZERO rather than a small
        positive value that would invite peer to send a sub-MSS
        segment - the receiver-side Silly Window Syndrome (SWS)
        avoidance rule from RFC 1122 §4.2.3.3.

        RFC 1122 §4.2.3.3 (receiver SWS avoidance):

            "A TCP MUST include a SWS avoidance algorithm in the
             receiver. ... The receiver's SWS avoidance algorithm
             ... is to refrain from sending small window updates.
             The window should not be advertised as smaller than
             the maximum segment size (MSS) reported by the
             receiver, except when the receive buffer is full."

        With WSCALE enabled (default '_rcv_wsc = 7'), each unit on
        the wire represents '1 << 7 = 128' bytes - far less than
        a typical MSS (1460 for IPv4-Ethernet). PyTCP's
        '_transmit_packet' computes the advertised window field
        as 'self._rcv_wnd >> self._rcv_wsc' with no SWS clamp:
        when '_rcv_wnd = 500' (sub-MSS), the advertised value is
        '500 >> 7 = 3' - peer sees a window of '3 << 7 = 384'
        effective bytes and may send a 384-byte segment. That
        segment is sub-MSS, wastes header overhead per byte of
        payload, and triggers the classic SWS pattern of small
        outbound segments grinding the connection to a crawl.

        The fix is the receiver-side SWS clamp: if
        '_rcv_wnd < _rcv_mss' AND '_rcv_wnd > 0', advertise zero
        instead. The peer enters its zero-window persist loop
        and we re-open the window only when the application has
        consumed at least one MSS of buffer space.

        Scenario:

            1. Drive handshake to ESTABLISHED with bilateral
               WSCALE. After: '_rcv_wsc = 7', '_rcv_wnd_max =
               65535', '_rcv_mss' = 1460 (typical IPv4-Ethernet).
            2. Pre-fill '_rx_buffer' to 65_000 bytes so the
               available window is '_rcv_wnd_max - 65_000 = 535'
               (sub-MSS).
            3. Peer sends 1 byte of data so a delayed-ACK is
               armed. Drain past 'DELAYED_ACK_DELAY' so the ACK
               fires.
            4. Inspect the outbound ACK's 'win' field.
            5. Assert: 'win << _rcv_wsc' is either 0 OR >=
               '_rcv_mss'. The current code emits
               '535 >> 7 = 4' (= 512 effective bytes, sub-MSS) -
               in violation of SWS avoidance.

        Assertions:

            * '(probe.win << session._rcv_wsc) == 0 OR
               (probe.win << session._rcv_wsc) >= session._rcv_mss'.

        [FLAGS BUG] - 'TcpSession._transmit_packet' (line 718)
        computes:

            tcp__win = self._rcv_wnd >> self._rcv_wsc

        with no SWS clamp. When '0 < _rcv_wnd < _rcv_mss', the
        right-shift yields a small positive integer that
        represents sub-MSS bytes on the wire after peer applies
        WSCALE.

        Fix outline (separate commit):

            if 0 < self._rcv_wnd < self._rcv_mss:
                tcp__win = 0
            else:
                tcp__win = self._rcv_wnd >> self._rcv_wsc

        Same fix can be unified into the '_rcv_wnd' property
        itself by clamping there, but the property is also read
        by the receive-window acceptability check (line 897-905)
        which wants the un-clamped value. Keeping the SWS clamp
        local to the wire-emission path avoids that interaction.

        Severity: LOW. PyTCP works correctly with sub-MSS
        advertisements - the peer sees a smaller window and
        sends a smaller segment - but the per-byte header
        overhead grows and average throughput drops. Real-world
        impact is limited to slow-consumer scenarios with
        full-sized buffers; on the LAN/loopback testbed the
        application is typically fast enough that '_rcv_wnd'
        stays near '_rcv_wnd_max' and SWS never fires.
        """

        # Drive a custom handshake where peer offers WSCALE so the
        # bilateral negotiation completes and '_rcv_wsc' stays at
        # its default 7 (the file's '_drive_handshake_to_established'
        # does not include WSCALE on peer's SYN+ACK).
        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            wscale=7,
        )
        self._drive_rx(frame=peer_syn_ack)
        self.assertIs(session.state, FsmState.ESTABLISHED)
        self.assertEqual(
            session._rcv_wsc,
            7,
            msg="Setup precondition: bilateral WSCALE must yield '_rcv_wsc = 7'.",
        )

        # Pre-fill '_rx_buffer' so the available window is sub-MSS.
        # '_rcv_wnd' is a property: 'max(0, _rcv_wnd_max - len(_rx_buffer))'.
        target_available = 535  # sub-MSS (< 1460)
        prefill_count = session._rcv_wnd_max - target_available
        with session._lock__rx_buffer:
            session._rx_buffer.extend(b"\x00" * prefill_count)
        self.assertEqual(
            session._rcv_wnd,
            target_available,
            msg=f"Setup precondition: '_rcv_wnd' must be {target_available} after pre-fill.",
        )

        # Peer sends 1 byte to arm a delayed-ACK. Drain past
        # 'DELAYED_ACK_DELAY' so the timer-driven ACK fires.
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X",
        )
        self._drive_rx(frame=peer_data)
        delayed_ack_tx = self._advance(ms=200)

        self.assertEqual(
            len(delayed_ack_tx),
            1,
            msg="Setup precondition: the delayed ACK must fire on the next tick after DELAYED_ACK_DELAY.",
        )
        ack_probe = self._parse_tx(delayed_ack_tx[0])
        effective_window = ack_probe.win << session._rcv_wsc
        self.assertTrue(
            effective_window == 0 or effective_window >= session._rcv_mss,
            msg=(
                f"RFC 1122 §4.2.3.3 receiver SWS avoidance: "
                f"the advertised window's effective byte count "
                f"({effective_window} = {ack_probe.win} << {session._rcv_wsc}) "
                f"MUST be either 0 or >= MSS ({session._rcv_mss}). "
                f"Today PyTCP advertises a small positive window "
                f"({ack_probe.win}) representing {effective_window} "
                f"effective bytes - sub-MSS, in violation of the "
                f"receiver SWS avoidance rule. Fix: clamp 'tcp__win = 0' "
                f"when '0 < self._rcv_wnd < self._rcv_mss' in "
                f"'_transmit_packet' line 718."
            ),
        )

    def test__window__peer_window_update_via_dup_ack_shape_updates_snd_wnd(self) -> None:
        """
        Ensure that a peer ACK whose wire shape matches the
        dup-ACK pattern ('seq == RCV.NXT, ack == SND.UNA, no
        data') BUT carries a different window value than peer's
        previously-advertised window is treated as a window-
        update segment, not a duplicate ACK. The 'send window
        SHOULD be updated' clause in RFC 9293 §3.10.7.4 step 5
        applies whenever 'SND.UNA <= SEG.ACK <= SND.NXT' - it
        does NOT require SEG.ACK to advance SND.UNA.

        RFC 9293 §3.10.7.4 step 5 (window update):

            "If SND.UNA =< SEG.ACK =< SND.NXT, the send window
             should be updated. If (SND.WL1 < SEG.SEQ or (SND.WL1
             = SEG.SEQ and SND.WL2 =< SEG.ACK)), set SND.WND <-
             SEG.WND, set SND.WL1 <- SEG.SEQ, and set SND.WL2 <-
             SEG.ACK."

        and RFC 5681 §2 (duplicate-ACK definition - the part
        PyTCP elides):

            "An acknowledgment is considered a 'duplicate' in the
             following algorithms when ... (e) the advertised
             window in the incoming acknowledgment equals the
             advertised window in the last incoming
             acknowledgment."

        Together: a segment with SEG.ACK == SND.UNA but a NEW
        window value is NOT a duplicate; it is a window-update.
        PyTCP currently misclassifies it.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_established' line
        ~2294-2306 in the dup-ACK branch:

            if (
                packet_rx_md.tcp__seq == self._rcv_nxt
                and packet_rx_md.tcp__ack == self._snd_una
                and not packet_rx_md.tcp__data
            ):
                self._retransmit_packet_request(packet_rx_md)
                return

        The classification ignores the window field, so a
        wnd-update segment is routed to
        '_retransmit_packet_request', which:

          - Increments '_tx_retransmit_request_counter[ack]'
            (priming spurious-fast-retransmit; see the sibling
            test '..._three_wnd_updates_must_not_trigger_spurious_fast_retransmit').
          - Does NOT update '_snd_wnd' (the wnd-update is lost).

        Two consequences this test pins:

          1. The window value is silently dropped. Peer's
             "I want a smaller window now" or "I reopened my
             window" signal does not change our SND.WND, so we
             may continue sending past peer's new right edge
             (window-shrink violation per RFC 1122 §4.2.2.16) or
             keep persist-probing past peer's reopening.

          2. The downstream effect on persist (RFC 9293 §3.8.6.1):
             if peer was at 0-window and reopens via this
             segment, '_persist_active' is not deactivated and we
             keep probing until either persist's RTO fires
             (wasting bandwidth on unnecessary 1-byte probes) or
             a real cum-ACK-advancing segment arrives. The latter
             is bounded by PERSIST_TIMEOUT_MAX = 60 s on the
             worst case.

        Severity: MEDIUM. Modern TCP stacks usually piggyback
        wnd-updates on data ACKs, so the gap rarely bites. But
        peers under memory pressure or shrinking-window
        scenarios DO send standalone wnd-update ACKs, and that
        is exactly when the bug bites hardest.

        Fix outline (separate commit): add a window-comparison
        gate to the dup-ACK classification at line ~2294-2306.
        When 'tcp__win << _snd_wsc != _snd_wnd', route to a new
        wnd-update branch that updates 'self._snd_wnd' and
        deactivates the persist flag if peer reopened the
        window, but does NOT increment the dup-ACK counter or
        double '_snd_ewn' (cwnd grows on cum-ACK progress, not
        wnd-update, per RFC 5681 §3.1).

        Scenario:

            1. Drive handshake to ESTABLISHED. The SYN+ACK
               advertised PEER__WIN = 64240, so 'session._snd_wnd'
               starts at 64240.
            2. Peer sends an ACK with the dup-ACK wire shape
               ('seq = PEER__ISS + 1 = RCV.NXT', 'ack =
               LOCAL__ISS + 1 = SND.UNA', no data) but carrying
               a NEW window value of 20000.
            3. Drive RX. Per RFC 9293 §3.10.7.4 step 5, the
               session MUST update '_snd_wnd' to 20000.

        Assertions:

            * '_snd_wnd' equals 20000 after the wnd-update.
            * State stays ESTABLISHED.

        On current code the test fails: '_snd_wnd' remains at
        the SYN+ACK's PEER__WIN value because the wnd-update was
        misclassified as a dup-ACK and silently dropped.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self.assertEqual(
            session._snd_wnd,
            PEER__WIN,
            msg="Setup precondition: post-handshake SND.WND must equal peer's SYN+ACK win.",
        )

        new_win = 20000
        # Sanity: new_win must differ from PEER__WIN, otherwise the
        # test would be vacuous.
        self.assertNotEqual(
            new_win,
            PEER__WIN,
            msg="Test fixture must use a NEW window value distinct from peer's SYN+ACK win.",
        )

        peer_wnd_update = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=new_win,
        )
        self._drive_rx(frame=peer_wnd_update)

        self.assertEqual(
            session._snd_wnd,
            new_win,
            msg=(
                "Per RFC 9293 §3.10.7.4 step 5, an ACK whose wire "
                "shape matches the dup-ACK pattern but carries a NEW "
                "window value MUST update SND.WND. PyTCP currently "
                "routes such segments to '_retransmit_packet_request' "
                "(line ~2294) which does not update '_snd_wnd', so "
                "the wnd-update is silently dropped. Fix: gate the "
                "dup-ACK classification on the window field per RFC "
                "5681 §2(e); route window-changing segments to a "
                "wnd-update path that calls "
                "'self._snd_wnd = packet_rx_md.tcp__win << "
                "self._snd_wsc' (and deactivates persist if peer "
                f"reopened). Got '_snd_wnd' = {session._snd_wnd}, "
                f"expected {new_win}."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="A wnd-update must not transition the session out of ESTABLISHED.",
        )

    def test__window__three_wnd_updates_must_not_trigger_spurious_fast_retransmit(self) -> None:
        """
        Ensure that three consecutive ACKs with the dup-ACK wire
        shape ('seq == RCV.NXT, ack == SND.UNA, no data') but
        each carrying a DIFFERENT window value do NOT trigger
        fast-retransmit. Per RFC 5681 §2(e), a duplicate ACK
        requires the advertised window to be unchanged from the
        previous ACK; window-changing segments are not duplicates
        and MUST NOT contribute to the fast-retransmit threshold.

        RFC 5681 §2 (duplicate-ACK definition):

            "An acknowledgment is considered a 'duplicate' in the
             following algorithms when ... (e) the advertised
             window in the incoming acknowledgment equals the
             advertised window in the last incoming
             acknowledgment."

        and RFC 5681 §3.2 (fast-retransmit trigger):

            "When the third duplicate ACK is received, a TCP
             MUST set ssthresh ... and retransmit the lost
             segment."

        The "third duplicate" must be a third TRUE duplicate.
        Window-update ACKs are not duplicates; counting them
        toward the fast-retransmit threshold causes spurious
        retransmits, wastes bandwidth, and (under proper RFC
        5681 cwnd) would unnecessarily halve cwnd.

        [FLAGS BUG] - companion to '..._wnd_update_via_dup_ack_shape_updates_snd_wnd':
        '_tcp_fsm_established' line ~2294-2306 routes ALL
        'seq == RCV.NXT, ack == SND.UNA, no data' segments to
        '_retransmit_packet_request' regardless of the window
        field. That helper increments
        '_tx_retransmit_request_counter[ack]' on every call,
        and on the third call fires fast-retransmit via the
        'count_trigger == 3' check at line ~2293.

        For 3 wnd-update ACKs at the same 'ack' value: counter
        hits 3, count_trigger fires, fast-retransmit emits a
        spurious retransmit on the next timer tick, and
        '_recovery_point' is set to '_snd_max' (gating further
        dup-ACK-driven recovery for the rest of the loss event).

        Severity: HIGH when triggered. Three standalone
        wnd-update ACKs from peer at the same ack value cause:

          - One spurious data retransmit.
          - Recovery-point gate set, suppressing legitimate
            fast-retransmit until SND.UNA crosses
            '_recovery_point'.
          - Under proper RFC 5681 cwnd: ssthresh halving and
            cwnd collapse per RFC 5681 §3.2 step 2 (PyTCP's
            simplified '_snd_ewn' model masks this part of the
            damage today; it would emerge once the deferred cwnd
            rework lands).

        Fix outline (separate commit): same root-cause fix as
        '..._wnd_update_via_dup_ack_shape_updates_snd_wnd' -
        add a window-comparison gate to the dup-ACK
        classification, and route window-changing segments to a
        wnd-update path that bypasses
        '_tx_retransmit_request_counter' entirely. Once the
        classification is correct, neither bug fires.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Send 1 MSS of data so SND.UNA < SND.MAX (i.e.
               there is something for fast-retransmit to fire
               on).
            3. Peer sends three ACKs with the dup-ACK shape
               ('seq=PEER__ISS+1, ack=LOCAL__ISS+1, no data')
               but each carrying a DIFFERENT window value
               (10000, 20000, 30000 - all distinct from each
               other and from the SYN+ACK's PEER__WIN).
            4. Advance one timer tick to allow any pending
               fast-retransmit emission to fire.

        Assertions:

            * No retransmit data segment is emitted.
            * '_recovery_point' is still 0 (no recovery
              entered).

        On current code the test fails: peer's three
        wnd-updates are misclassified as dup-ACKs, count_trigger
        fires on the third, '_recovery_point' is set, and a
        spurious retransmit emits on the timer-tick advance.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Bypass slow-start so the data segment fires immediately
        # and SND.MAX advances past SND.UNA - giving fast-retransmit
        # something to fire on.
        session._snd_ewn = PEER__WIN

        session.send(data=b"X" * 1460)
        self._advance(ms=1)
        self.assertEqual(
            session._snd_max,
            LOCAL__ISS + 1 + 1460,
            msg=("Setup precondition: SND.MAX must have advanced past SND.UNA " "after the initial data send."),
        )
        # Clear handshake + initial-data residue so 'self._frames_tx'
        # below contains only any spurious retransmits.
        self._frames_tx.clear()

        # Peer sends three wnd-update ACKs at the same ack value
        # (= SND.UNA, since peer hasn't ACKed our data yet) but with
        # DIFFERENT window values - per RFC 5681 §2(e) these are NOT
        # duplicates.
        for new_win in (10000, 20000, 30000):
            wnd_update = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=new_win,
            )
            self._drive_rx(frame=wnd_update)

        # Advance a timer tick so any pending fast-retransmit
        # ('_retransmit_packet_request' rewinds SND.NXT but the
        # actual transmission happens on the next '_transmit_data'
        # call, which fires from the timer branch) emits.
        self._advance(ms=1)

        retransmits = [self._parse_tx(frame) for frame in self._frames_tx if len(self._parse_tx(frame).payload) > 0]
        self.assertEqual(
            retransmits,
            [],
            msg=(
                "Three peer ACKs with the dup-ACK wire shape but "
                "DIFFERENT window values are wnd-updates per RFC "
                "5681 §2(e), not duplicates. They MUST NOT trigger "
                "fast-retransmit. Today '_tcp_fsm_established' "
                "line ~2294-2306 misclassifies them as dup-ACKs and "
                "'_retransmit_packet_request' fires fast-retransmit "
                "on the third one, emitting a spurious data "
                "retransmit. Fix: add a window-comparison gate to "
                "the dup-ACK classification so wnd-updates skip the "
                "fast-retransmit path entirely. Got "
                f"{len(retransmits)} spurious retransmit(s)."
            ),
        )
        self.assertEqual(
            session._recovery_point,
            0,
            msg=(
                "Three peer wnd-update ACKs MUST NOT enter "
                "fast-retransmit recovery (per RFC 5681 §2(e) they "
                "are not duplicates). Today '_recovery_point' is "
                f"set to SND.MAX = {session._snd_max:#x} on the "
                "spurious third-duplicate trigger, gating further "
                "legitimate fast-retransmit until SND.UNA crosses "
                f"the marker. Got '_recovery_point' = {session._recovery_point:#x}."
            ),
        )
