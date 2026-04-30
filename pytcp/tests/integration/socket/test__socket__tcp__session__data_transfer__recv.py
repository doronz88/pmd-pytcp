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
This module contains integration tests for the TCP receive-side data
transfer in the 'TcpSession' state machine, covering in-order data
delivery, the delayed-ACK mechanism, and out-of-window / unacceptable
segment rejection per RFC 9293 §3.10.7.4 and RFC 1122 §4.2.3.2.

The tests in this file drive a session through the active-open
handshake to ESTABLISHED and then feed data segments from the peer,
asserting both the delivery of bytes into '_rx_buffer' and the wire
shape of any acknowledgements the stack produces.

Reference RFCs:
    RFC 9293 §3.10.7.4   Synchronized state segment processing
    RFC 9293 §3.4        Sequence numbers
    RFC 9293 §3.8        Data Communication
    RFC 1122 §4.2.3.2    When to Send an ACK Segment (delayed ACK,
                         "ACK every other segment", 500 ms ceiling)
    RFC 1122 §4.2.2.20   General TCP requirements

pytcp/tests/integration/socket/test__socket__tcp__session__data_transfer__recv.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.socket import AddressFamily
from pytcp.socket.tcp__session import (
    DELAYED_ACK_DELAY,
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
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers chosen well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN+ACK reply.
PEER__MSS: int = 1460


class TestTcpDataTransfer__Recv(TcpSessionTestCase):
    """
    Integration tests for inbound data segments and the corresponding
    acknowledgement / receive-buffer behaviour.
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
        Drive the active-open three-way handshake to ESTABLISHED and
        return the session ready for receive-side data transfer.
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

    def test__data_transfer_recv__in_order_data_delivered_with_delayed_ack(self) -> None:
        """
        Ensure that in-order data arriving on an ESTABLISHED session
        is queued into '_rx_buffer' and acknowledged via the delayed-
        ACK mechanism per RFC 1122 §4.2.3.2:

            "A TCP SHOULD implement a delayed ACK, but an ACK should
             not be excessively delayed; in particular, the delay
             MUST be less than 0.5 seconds, and in a stream of
             full-sized segments there SHOULD be an ACK for at least
             every second segment."

        Concretely, after a single in-order data segment arrives the
        receiver MUST NOT respond with an immediate ACK on the very
        next tick; instead the ACK is held for the delayed-ACK
        interval (here 'DELAYED_ACK_DELAY = 100 ms'), giving the
        application a chance to piggyback the ACK on outbound data.
        Once the interval elapses (and well before the 500 ms upper
        bound), the ACK fires with 'ack = RCV.NXT' so the peer can
        free its retransmit buffer.

        Scenario:

            1. Drive handshake to ESTABLISHED. The 'delayed_ack'
               timer must be armed at this point so the next inbound
               segment is subject to a fresh delay.
            2. Peer sends one segment of 5 data bytes (b"hello").
               Inline drive must NOT produce any TX - the data
               branch in '_tcp_fsm_established' processes the
               segment without inline ACK; the ACK is delivered by
               the timer-driven delayed-ACK mechanism.
            3. The 5 bytes appear in 'session._rx_buffer'; '_rcv_nxt'
               advances by 5; '_rcv_una' is unchanged (we have not
               yet acknowledged the data).
            4. For the first 50 ms after the data arrives, no TX may
               be emitted - the delayed-ACK timer is still counting
               down.
            5. Within DELAYED_ACK_DELAY + a small grace (i.e. by
               roughly 110 ms after the data arrived), exactly one
               outbound bare ACK fires with 'ack = PEER__ISS + 1 + 5'.

        Required wire shape of the delayed ACK:

            sport     = STACK__PORT
            dport     = PEER__PORT
            seq       = LOCAL__ISS + 1   (= SND.NXT, unchanged)
            ack       = PEER__ISS + 6    (= RCV.NXT, post-data)
            flags     = {ACK}            (bare ACK, no PSH or data)
            payload   = b""
            mss       = None
            wscale    = None
            win       = 65535

        Side effects asserted:

            * '_rcv_una' equals '_rcv_nxt' after the ACK fires.
            * 'session.state' remains ESTABLISHED throughout.

        [FLAGS BUG] - RFC 1122 §4.2.3.2 deviation
        ----------------------------------------------------------
        '_transmit_packet' arms the delayed-ACK timer ONLY when
        called from ESTABLISHED. The third-leg ACK is emitted from
        within the SYN_SENT handler before the state transitions to
        ESTABLISHED, so the timer is never armed during the
        handshake. After the handshake completes, the timer is
        absent from 'stack.timer._timers'; '_delayed_ack.is_expired'
        returns True; and the very FIRST inbound data segment
        triggers an immediate ACK on the next tick rather than being
        delayed. Subsequent segments DO get the delay (because the
        previous ACK's '_transmit_packet' call armed the timer), but
        the first one always slips through with zero delay.

        This test is expected to FAIL on current code - the early-
        window assertion ('no TX within 50 ms') catches the
        immediate-ACK behaviour. The fix is to arm the delayed-ACK
        timer when transitioning into ESTABLISHED (or whenever new
        data is enqueued), so the FIRST received data segment is
        delayed exactly like every subsequent one.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        rcv_una_before = session._rcv_una
        snd_nxt_before = session._snd_nxt

        # Peer sends 5 bytes of in-order data.
        payload = b"hello"
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            payload=payload,
            win=PEER__WIN,
        )
        inline_tx = self._drive_rx(frame=peer_data)

        self.assertEqual(
            inline_tx,
            [],
            msg=(
                "Receiving in-order data must not elicit an immediate "
                "inline ACK from '_tcp_fsm_established'; the ACK is "
                "delivered by the timer-driven delayed-ACK mechanism."
            ),
        )

        # Data is delivered, RCV.NXT advances, RCV.UNA unchanged.
        self.assertEqual(
            bytes(session._rx_buffer),
            payload,
            msg=(
                f"In-order data must be queued into '_rx_buffer'. Got "
                f"{bytes(session._rx_buffer)!r}, expected {payload!r}."
            ),
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1 + len(payload),
            msg=("'_rcv_nxt' must advance by len(payload) after " "consuming the in-order data segment."),
        )
        self.assertEqual(
            session._rcv_una,
            rcv_una_before,
            msg=("'_rcv_una' must be unchanged - we have not yet " "acknowledged the new data."),
        )

        # No ACK during the first half of the delayed-ACK interval.
        early_tx = self._advance(ms=DELAYED_ACK_DELAY // 2)
        self.assertEqual(
            early_tx,
            [],
            msg=(
                f"Within {DELAYED_ACK_DELAY // 2} ms of data receipt, "
                f"no ACK may fire - the delayed-ACK timer (interval "
                f"{DELAYED_ACK_DELAY} ms) is still counting down per "
                "RFC 1122 §4.2.3.2."
            ),
        )

        # Within the delayed-ACK interval (plus a small grace for the
        # tick boundary), exactly one bare ACK must fire.
        ack_tx = self._advance(ms=DELAYED_ACK_DELAY)
        self.assertEqual(
            len(ack_tx),
            1,
            msg=(
                f"Within {DELAYED_ACK_DELAY} ms of the half-interval "
                "tick, exactly one delayed ACK must fire. Got "
                f"{len(ack_tx)} TX frames."
            ),
        )

        ack = self._parse_tx(ack_tx[0])
        self._assert_segment(
            ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=snd_nxt_before,
            ack=PEER__ISS + 1 + len(payload),
            payload=b"",
            mss=None,
            wscale=None,
            # Advertised window reflects '_rx_buffer' occupancy per
            # RFC 9293 §3.8.6: 65535 max minus the bytes still
            # waiting to be drained by 'recv()'.
            win=65535 - len(payload),
        )

        # After the ACK fires, '_rcv_una' must catch up with '_rcv_nxt'.
        self.assertEqual(
            session._rcv_una,
            session._rcv_nxt,
            msg=(
                "After the delayed ACK fires, '_rcv_una' must equal "
                "'_rcv_nxt' - we have acknowledged everything we have "
                "received."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Receiving data must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_recv__back_to_back_full_segments_trigger_immediate_ack(self) -> None:
        """
        Ensure that when two back-to-back full-MSS data segments
        arrive on an ESTABLISHED session, the receiver does NOT
        delay its ACK for both - the second segment MUST trigger an
        immediate inline ACK that covers everything received so far,
        per RFC 1122 §4.2.3.2:

            "in a stream of full-sized segments there SHOULD be an
             ACK for at least every second segment."

        The "every second segment" rule prevents the delayed-ACK
        mechanism from holding back acknowledgements during bulk
        transfers, which would starve the sender's congestion
        window. With MSS-sized segments each carrying the full
        application MSS, the receiver tracks the count of pending
        unacknowledged segments and emits an inline ACK as soon as
        that count reaches two (or whatever the implementation
        threshold is, but at minimum every other segment).

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. Peer sends segment #1 of 1460 bytes
               (seq = PEER__ISS + 1, b"X" * 1460). Drive RX.
               No inline ACK fires - the first segment is subject
               to the delayed-ACK timer.
            3. Peer sends segment #2 of 1460 bytes
               (seq = PEER__ISS + 1 + 1460, b"Y" * 1460).
               Drive RX. Per the every-other-segment rule, an
               inline ACK MUST fire as the segment is processed.
            4. The inline ACK covers BOTH segments: ack = PEER__ISS
               + 1 + 2920.
            5. Both payloads land in the receive buffer in order.

        Required wire shape of the immediate ACK after segment #2:

            sport     = STACK__PORT
            dport     = PEER__PORT
            seq       = LOCAL__ISS + 1
            ack       = PEER__ISS + 1 + 2 * 1460   (= PEER__ISS + 2921)
            flags     = {ACK}
            payload   = b""
            win       = 65535

        Side effects asserted:

            * 'session._rx_buffer' contains 'seg1_payload +
              seg2_payload' in that order.
            * 'session._rcv_nxt' equals 'PEER__ISS + 1 + 2920'.
            * '_rcv_una' equals '_rcv_nxt' after the inline ACK
              (we acknowledged everything we received).
            * State stays ESTABLISHED.

        [FLAGS BUG] - RFC 1122 §4.2.3.2 deviation
        ----------------------------------------------------------
        The data branch in '_tcp_fsm_established' processes inbound
        data via '_process_ack_packet' without any inline ACK emit.
        It does not track the count of unacknowledged segments, and
        it does not consult the delayed-ACK timer to detect
        back-to-back segments. Both segments end up queued for the
        delayed ACK, which is then released by the timer-driven
        '_delayed_ack' on a subsequent tick rather than inline as
        the second segment is processed.

        This test is expected to FAIL on current code: the second
        segment's inline drive returns no TX (the ACK is held for
        the timer). The fix requires tracking the count of
        unacknowledged segments since the last ACK we emitted, and
        forcing an inline 'self._transmit_packet(flag_ack=True)'
        from '_process_ack_packet' (or from the data branch in
        '_tcp_fsm_established') whenever that count reaches two.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Peer sends two back-to-back full-MSS segments. Each segment
        # carries 1460 bytes of payload, exactly MSS = MTU(1500) -
        # IPv4(20) - TCP(20).
        seg1_payload = b"X" * 1460
        seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            payload=seg1_payload,
            win=PEER__WIN,
        )
        seg2_payload = b"Y" * 1460
        seg2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + 1460,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            payload=seg2_payload,
            win=PEER__WIN,
        )

        # First segment: no inline ACK (subject to delayed-ACK timer).
        inline_tx_1 = self._drive_rx(frame=seg1)
        self.assertEqual(
            inline_tx_1,
            [],
            msg=(
                "The first full-MSS segment in a stream must NOT "
                "elicit an immediate ACK - it is subject to the "
                "delayed-ACK timer (RFC 1122 §4.2.3.2)."
            ),
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1 + 1460,
            msg="After the first segment, '_rcv_nxt' must advance by MSS bytes.",
        )

        # Second segment: per the every-other-segment rule, the
        # receiver MUST emit an inline ACK now.
        inline_tx_2 = self._drive_rx(frame=seg2)
        self.assertEqual(
            len(inline_tx_2),
            1,
            msg=(
                "The second back-to-back full-MSS segment MUST "
                "trigger an immediate inline ACK per RFC 1122 "
                '§4.2.3.2 ("in a stream of full-sized segments '
                "there SHOULD be an ACK for at least every second "
                f'segment"). Got {len(inline_tx_2)} TX frames.'
            ),
        )

        ack = self._parse_tx(inline_tx_2[0])
        self._assert_segment(
            ack,
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
            # of back-to-back segments still in the buffer.
            win=65535 - 2 * 1460,
        )

        # Both payloads delivered in order.
        self.assertEqual(
            bytes(session._rx_buffer),
            seg1_payload + seg2_payload,
            msg=("Both back-to-back segments must be delivered to " "'_rx_buffer' in the order they arrived."),
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1 + 2 * 1460,
            msg="'_rcv_nxt' must equal PEER__ISS + 1 + 2*MSS after both segments.",
        )
        self.assertEqual(
            session._rcv_una,
            session._rcv_nxt,
            msg=(
                "After the inline 'every other segment' ACK fires, "
                "'_rcv_una' must equal '_rcv_nxt' - we have just "
                "acknowledged everything we received."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Receiving back-to-back data must not change session state.",
        )

    def test__data_transfer_recv__bare_ack_with_no_data_does_not_trigger_ack_loop(self) -> None:
        """
        Ensure that a bare ACK from the peer (no SYN, no FIN, no
        RST, no data) acknowledging an already-acknowledged byte
        ('ack = SND.UNA') is processed quietly: '_rcv_nxt' must NOT
        advance, '_snd_una' must NOT advance, and crucially we must
        NOT emit any acknowledgement segment in response. Sending a
        pure ACK in response to a pure ACK would create an infinite
        ACK loop on the wire and is forbidden by basic TCP semantics
        - RFC 9293 §3.8 makes this clear by defining ACK as a
        cumulative-acknowledgement field rather than a request for
        re-acknowledgement.

        Scenario:

            1. Drive handshake to ESTABLISHED. After this:
                 SND.UNA == LOCAL__ISS + 1
                 SND.NXT == LOCAL__ISS + 1
                 RCV.NXT == PEER__ISS + 1
                 RCV.UNA == PEER__ISS + 1
            2. Peer sends a bare ACK at seq = PEER__ISS + 1 with
               ack = LOCAL__ISS + 1 (re-acknowledging our SYN that
               was already acknowledged during the handshake's
               SYN+ACK). No data, no flags other than ACK.
            3. Drive RX. Inline drive must produce NO outbound
               segment - no inline ACK, no inline data.
            4. State variables stay frozen: '_rcv_nxt', '_rcv_una',
               '_snd_una', '_snd_nxt' are all unchanged.
            5. Tick the virtual clock past the delayed-ACK interval
               and verify still no segment - the bare ACK left
               nothing pending that would trigger the timer's
               'rcv_nxt > rcv_una' condition.

        Side effects asserted:

            * 'session._rx_buffer' is empty (the bare ACK carries
              no data).
            * '_rcv_nxt', '_rcv_una', '_snd_una', '_snd_nxt' all
              equal their post-handshake values.
            * State remains ESTABLISHED.
            * No TX inline; no TX after the delayed-ACK interval.

        This test passes on current code as a positive-control
        regression guard. The relevant code paths:

          - '_tcp_fsm_established' receives the bare ACK, hits the
            "Suspected retransmit request" branch (because seq ==
            rcv_nxt, ack == snd_una, and no data). That branch
            increments a per-ack dup-counter but does not transmit
            anything for the first arrival.
          - '_delayed_ack' on the next tick checks 'rcv_nxt >
            rcv_una' - both equal post-handshake, so no ACK fires.

        A future regression that either (a) made the data branch
        unconditionally emit an ACK on every received segment or
        (b) advanced 'rcv_nxt' on a bare ACK would break this test
        immediately and surface the ACK-loop / sequence-corruption
        bug before any users were affected.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        snd_una_before = session._snd_una
        snd_nxt_before = session._snd_nxt
        rcv_nxt_before = session._rcv_nxt
        rcv_una_before = session._rcv_una

        # Peer sends a bare ACK acknowledging our SYN once more.
        bare_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
        )
        inline_tx = self._drive_rx(frame=bare_ack)

        self.assertEqual(
            inline_tx,
            [],
            msg=(
                "A bare ACK with no data must not elicit any inline "
                "outbound segment - sending an ACK in response to a "
                "pure ACK would create an infinite loop on the wire."
            ),
        )

        self.assertEqual(
            bytes(session._rx_buffer),
            b"",
            msg="A bare ACK carries no data; '_rx_buffer' must remain empty.",
        )
        self.assertEqual(
            session._rcv_nxt,
            rcv_nxt_before,
            msg=(
                "'_rcv_nxt' must NOT advance on a bare ACK with no " "data - there is no new sequence space to consume."
            ),
        )
        self.assertEqual(
            session._rcv_una,
            rcv_una_before,
            msg="'_rcv_una' must be unchanged after a bare ACK that elicits no outbound ACK.",
        )
        self.assertEqual(
            session._snd_una,
            snd_una_before,
            msg=(
                "'_snd_una' must be unchanged - the bare ACK "
                "re-acknowledges what was already acknowledged "
                "during the handshake."
            ),
        )
        self.assertEqual(
            session._snd_nxt,
            snd_nxt_before,
            msg="'_snd_nxt' must be unchanged - we have transmitted nothing since the handshake.",
        )

        # Drive past the delayed-ACK interval. Because 'rcv_nxt ==
        # rcv_una', the timer must NOT fire an ACK.
        late_tx = self._advance(ms=DELAYED_ACK_DELAY * 2)
        self.assertEqual(
            late_tx,
            [],
            msg=(
                f"After {DELAYED_ACK_DELAY * 2} ms of virtual time "
                "with no new data received, the delayed-ACK timer "
                "must not fire any ACK - 'rcv_nxt == rcv_una' so "
                "there is nothing to acknowledge."
            ),
        )

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="A bare ACK must not transition the session out of ESTABLISHED.",
        )

    def test__data_transfer_recv__ack_beyond_snd_max_triggers_empty_ack_reply(self) -> None:
        """
        Ensure that a segment whose acknowledgement number is BEYOND
        'SND.MAX' (i.e. acknowledges data we have never sent) is
        rejected per RFC 9293 §3.10.7.4 with an empty-ACK reply
        carrying our current 'SND.NXT' / 'RCV.NXT', and that the
        offending segment is discarded without affecting connection
        state:

            "If the connection is in a synchronized state ..., any
             unacceptable segment (out-of-window sequence number or
             unacceptable acknowledgment number) must be responded
             to with an empty acknowledgment segment (without any
             user data) containing the current send sequence number
             and an acknowledgment indicating the next sequence
             number expected to be received, and the connection
             remains in the same state."

        The unacceptable-ACK case is important because it covers
        forged or stale ACKs that an attacker (or buggy peer stack)
        could use to confuse our retransmit logic. Without an
        explicit empty-ACK reply, the offending sender cannot tell
        their segment was rejected and may keep retrying; with the
        reply, they receive an authoritative statement of our
        current connection state and can correct their behaviour
        (or be ignored as the bug-source).

        Scenario:

            1. Drive handshake to ESTABLISHED. After:
                 SND.UNA == SND.NXT == SND.MAX == LOCAL__ISS + 1
                 RCV.NXT == PEER__ISS + 1
            2. Peer sends a segment at seq = PEER__ISS + 1 (=
               RCV.NXT, so SEQ is acceptable) with ack =
               LOCAL__ISS + 0xDEAD (= LOCAL__ISS + 57005, far
               beyond SND.MAX = LOCAL__ISS + 1). Bare ACK, no
               data.
            3. Drive RX. Per RFC 9293 §3.10.7.4 the receiver MUST
               emit an empty-ACK reply inline. The reply carries
               OUR current SND.NXT (= LOCAL__ISS + 1) as seq and
               OUR current RCV.NXT (= PEER__ISS + 1) as ack.

        Required wire shape of the empty-ACK reply:

            sport     = STACK__PORT
            dport     = PEER__PORT
            seq       = LOCAL__ISS + 1   (= SND.NXT)
            ack       = PEER__ISS + 1    (= RCV.NXT)
            flags     = {ACK}
            payload   = b""
            mss       = None
            wscale    = None
            win       = 65535

        Side effects asserted:

            * 'session._snd_una' is unchanged - the bogus ACK
              acknowledged something we have not sent and must not
              advance our send window.
            * 'session._snd_nxt' is unchanged.
            * 'session._rcv_nxt' is unchanged - the offending
              segment had no data (and even if it had, the spec
              says the segment is discarded).
            * 'session.state' remains ESTABLISHED.

        [FLAGS BUG] - RFC 9293 §3.10.7.4 deviation
        ----------------------------------------------------------
        '_tcp_fsm_established's data branch is gated on three
        sub-conditions that all require
        'self._snd_una <= packet_rx_md.tcp__ack <= self._snd_max':

          - "Suspected retransmit request" requires
            'tcp__ack == self._snd_una'. Fails for ack > snd_max.
          - The OOO-storage branch and the regular-data branch
            require the bound check explicitly.

        When 'tcp__ack > self._snd_max', NONE of the sub-branches
        match; the function returns silently with no outbound
        segment. The peer (or attacker) receives no signal that
        their unacceptable ACK was rejected, and our state stays
        in the dark.

        This test is expected to FAIL on current code with zero TX
        frames. The fix requires an else / fall-through branch in
        the ACK-only handler that emits
        'self._transmit_packet(flag_ack=True)' whenever the inbound
        ACK falls outside (SND.UNA, SND.MAX] - the same
        empty-ACK reply RFC 9293 §3.10.7.4 mandates for any
        unacceptable segment.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        snd_una_before = session._snd_una
        snd_nxt_before = session._snd_nxt
        rcv_nxt_before = session._rcv_nxt

        # Peer sends a segment with an ACK that acknowledges data we
        # have never sent. Pick 0xDEAD as the offset so the bogus
        # ack value is visually unambiguous in failure output.
        bogus_ack_offset = 0xDEAD
        bogus_ack_segment = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + bogus_ack_offset,
            flags=("ACK",),
            win=PEER__WIN,
        )

        inline_tx = self._drive_rx(frame=bogus_ack_segment)

        self.assertEqual(
            len(inline_tx),
            1,
            msg=(
                "An incoming segment with ACK > SND.MAX must elicit "
                "exactly one inline empty-ACK reply per RFC 9293 "
                f"§3.10.7.4. Got {len(inline_tx)} TX frames."
            ),
        )

        ack_reply = self._parse_tx(inline_tx[0])
        self._assert_segment(
            ack_reply,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=snd_nxt_before,
            ack=rcv_nxt_before,
            payload=b"",
            mss=None,
            wscale=None,
            win=65535,
        )

        self.assertEqual(
            session._snd_una,
            snd_una_before,
            msg=("An ACK that exceeds SND.MAX must NOT advance " "'_snd_una' - it acknowledged data we never sent."),
        )
        self.assertEqual(
            session._snd_nxt,
            snd_nxt_before,
            msg="'_snd_nxt' must be unchanged - we have transmitted nothing new.",
        )
        self.assertEqual(
            session._rcv_nxt,
            rcv_nxt_before,
            msg=(
                "'_rcv_nxt' must be unchanged - the offending "
                "segment carried no data, and per RFC 9293 §3.10.7.4 "
                "any data on an unacceptable segment is discarded."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="An unacceptable-ACK segment must not transition the session out of ESTABLISHED.",
        )
