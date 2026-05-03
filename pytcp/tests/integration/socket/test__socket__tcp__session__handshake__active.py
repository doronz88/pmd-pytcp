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
This module contains integration tests for the TCP active-open
('connect') side of the 'TcpSession' state machine, covering the
client role of the three-way handshake defined in RFC 9293 §3.10.7.3.

The tests in this file drive the session's FSM directly via
'tcp_fsm(syscall=SysCall.CONNECT)' rather than going through the
blocking 'TcpSocket.connect()' BSD-API wrapper - the integration
scope is the session, not the socket facade. The full RX/TX path
is exercised end to end: outbound segments flow through the real
'PacketHandler._phtx_tcp -> _phtx_ip4 -> _phtx_ethernet' chain and
land in the mocked 'TxRing'; inbound segments are fed into the real
'_phrx_ethernet' entry point and dispatched to the session via the
real 'TcpSocket.process_tcp_packet'.

Reference RFCs:
    RFC 9293 §3.10.7.3   Active open / SYN-SENT state processing
    RFC 9293 §3.10.7.4   Synchronized state segment processing (challenge ACK)
    RFC 9293 §3.4.1      Initial sequence number selection
    RFC 9293 §3.5.1      Three-way handshake
    RFC 9293 §3.8.3      User Timeout / connection abort
    RFC 6298 §2          Computing TCP's retransmission timer
    RFC 5961 §4          Blind data injection / SYN-on-established mitigation
    RFC 1122 §4.2.3.5    R1 / R2 retransmission limits (R2 >= 100 s)

pytcp/tests/integration/socket/test__socket__tcp__session__handshake__active.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.socket import AddressFamily
from pytcp.socket.tcp__session import ConnError, FsmState, SysCall, TcpSession
from pytcp.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_session_testcase import TcpSessionTestCase

# Deterministic addressing chosen so log output and byte-frame comments
# stay readable. STACK is the host running the SUT, PEER is the
# 'HOST_A' fixture from 'NetworkTestCase' that has a working ARP entry.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers chosen well clear of the 32-bit wrap so
# this baseline test exercises ordinary modular comparisons; the
# wraparound corner is covered separately in the seq_wraparound file.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on the SYN+ACK reply. Picked to
# match the value typical OS stacks send (Linux's MSS-tuned default).
PEER__WIN: int = 64240

# Peer's MSS option value on the SYN+ACK. 1460 is the canonical IPv4
# Ethernet MSS (1500 MTU - 20 byte IPv4 header - 20 byte TCP header).
PEER__MSS: int = 1460


class TestTcpActiveOpen__Handshake(TcpSessionTestCase):
    """
    Integration tests for the client-side three-way handshake driven
    out of 'TcpSession' in the active-open path.
    """

    def _make_active_session(self, *, iss: int) -> TcpSession:
        """
        Build a 'TcpSocket' / 'TcpSession' pair wired up the way
        'TcpSocket.connect()' would wire them - addressing on the
        socket already populated to match the 4-tuple used by the
        peer-side fixtures, ISS deterministically pinned via
        '_force_iss', socket registered in 'stack.sockets' so the
        packet handler's RX dispatch can find it.

        The session is returned in 'CLOSED' state; callers issue
        'tcp_fsm(syscall=SysCall.CONNECT)' to transition into
        'SYN_SENT' before driving the handshake.
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

    def test__active_open__three_way_handshake_completes_to_established(self) -> None:
        """
        Ensure the canonical three-way handshake takes a freshly
        constructed 'TcpSession' from 'CLOSED' through 'SYN_SENT' to
        'ESTABLISHED' and emits exactly the segments RFC 9293 §3.5.1
        prescribes for active open: an initial SYN carrying our ISS,
        then a single ACK in response to the peer's SYN+ACK whose
        SEQ / ACK numbers track the established connection state per
        RFC 9293 §3.10.7.3.

        Stages observed:

            1. CLOSED + SysCall.CONNECT -> SYN_SENT (no segment yet:
               the actual transmit is gated on a timer tick, matching
               production where '_tcp_fsm_closed' only changes state
               and '_transmit_data' in SYN_SENT does the SYN emit).

            2. Virtual-clock tick fires the SYN_SENT timer handler ->
               '_transmit_data' detects 'snd_nxt == snd_ini' and
               sends the initial SYN with seq=ISS, ack=0, our MSS
               option, and our advertised receive window.

            3. Peer's SYN+ACK arrives -> sanity check (ack==ISS+1,
               no payload) succeeds, peer's MSS / WSCALE / window are
               recorded, '_process_ack_packet' advances 'snd_una' and
               'rcv_nxt', the ACK leg is emitted (seq=ISS+1,
               ack=peer_ISS+1, no payload) and state moves to
               ESTABLISHED. The connect-event semaphore is released
               so a blocked 'connect()' caller would unblock.

        The current implementation passes 'tcp__wscale=0' to
        '_phtx_tcp' on initial SYN, but '_phtx_tcp' only emits the
        WSCALE option when the value is truthy ('if tcp__wscale:'),
        so 0 means 'no WSCALE option on the wire' - this test
        therefore asserts 'wscale is None' on the outbound SYN. RFC
        7323 §1.3 specifically permits this (a host that does not
        support window scaling simply omits the option), so it is a
        deliberate stylistic choice rather than a bug, and the test
        documents the contract rather than mandating WSCALE
        advertisement. A separate test in 'options.py' will assert
        that we correctly ignore peer-advertised WSCALE since we did
        not advertise our own (current code does not - 'flag bug').
        """

        # Stage 1: CONNECT syscall.
        session = self._make_active_session(iss=LOCAL__ISS)
        self._assert_no_tx()

        session.tcp_fsm(syscall=SysCall.CONNECT)

        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="CONNECT from CLOSED must transition the session to SYN_SENT.",
        )
        self.assertEqual(
            session._snd_ini,
            LOCAL__ISS,
            msg="'_force_iss' must pin '_snd_ini' to the value supplied to '_make_active_session'.",
        )
        self.assertEqual(
            session._snd_nxt,
            LOCAL__ISS,
            msg="'_snd_nxt' must equal '_snd_ini' immediately after CONNECT - no SYN sent yet.",
        )
        self.assertEqual(
            self._frames_tx,
            [],
            msg="'_tcp_fsm_closed' must not transmit on the CONNECT syscall - the SYN is gated on the timer tick.",
        )

        # Stage 2: Initial SYN goes out on the first virtual-clock tick.
        tx_frames = self._advance(ms=1)

        self.assertEqual(
            len(tx_frames),
            1,
            msg="Exactly one TX frame (the initial SYN) must be emitted on the first SYN_SENT timer tick.",
        )

        syn = self._parse_tx(tx_frames[0])
        self._assert_segment(
            syn,
            flags=frozenset({"SYN"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS,
            ack=0,
            payload=b"",
            mss=1460,  # RFC 6691 - MTU(1500) - IPv4 hdr(20) - TCP hdr(20).
            wscale=7,  # PyTCP's default WSCALE shift; advertised on outbound SYN per RFC 7323 §2.2.
            win=65535,  # SYN's own win is unshifted per RFC 7323 §2.2.
        )
        self.assertEqual(
            session._snd_nxt,
            LOCAL__ISS + 1,
            msg=(
                "After the SYN goes out, '_snd_nxt' must be ISS+1 to "
                "consume the SYN's one-byte sequence space (RFC 9293 §3.4)."
            ),
        )
        self.assertEqual(
            session._snd_max,
            LOCAL__ISS + 1,
            msg="'_snd_max' must track the highest seq we have ever emitted, set to ISS+1 after the initial SYN.",
        )

        # Stage 3: Peer responds with SYN+ACK; we ACK and reach ESTABLISHED.
        syn_ack_frame = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )

        tx_frames = self._drive_rx(frame=syn_ack_frame)

        self.assertEqual(
            len(tx_frames),
            1,
            msg="Exactly one TX frame (the third-leg ACK) must follow processing of the peer's SYN+ACK.",
        )

        ack = self._parse_tx(tx_frames[0])
        self._assert_segment(
            ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
            win=65535,
            mss=None,  # MSS is only exchanged on SYN-bearing segments (RFC 9293 §3.7.1).
            wscale=None,
        )

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Receiving a valid SYN+ACK in SYN_SENT must transition the "
                "session to ESTABLISHED (RFC 9293 §3.10.7.3)."
            ),
        )
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1,
            msg="'_snd_una' must equal ISS+1 after peer ACKs our SYN.",
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1,
            msg="'_rcv_nxt' must equal peer_ISS+1 after consuming the SYN's one byte of sequence space.",
        )
        self.assertEqual(
            session._snd_mss,
            PEER__MSS,
            msg="'_snd_mss' must be clamped to peer's advertised MSS once the handshake completes (RFC 6691).",
        )
        self.assertTrue(
            session._event__connect.acquire(timeout=0),
            msg=(
                "The connect-event semaphore must be released once the "
                "session reaches ESTABLISHED so a blocked 'connect()' "
                "caller unblocks."
            ),
        )

    def test__active_open__syn_ack_with_payload_completes_handshake_and_delivers_data(self) -> None:
        """
        Ensure that an inbound SYN+ACK carrying piggybacked data
        completes the active-open handshake AND queues the data per
        RFC 9293 §3.10.7.3 step 4 -> §3.10.7.4 step 7.

        RFC 9293 §3.10.7.3 step 4 (SYN-SENT, processing SYN+ACK):

            "If SND.UNA < SEG.ACK =< SND.NXT then enter ESTABLISHED
             state and continue processing with the variables set
             ... If there are other controls or text in the segment,
             then continue processing at the sixth step under
             Section 3.10.7.4 where the URG bit is checked,
             otherwise return."

        The "if there are other controls or text" clause is the
        load-bearing one for piggybacked-data on SYN+ACK: when peer
        sends data alongside their SYN+ACK (a fast-start
        optimisation any peer is allowed to use), processing
        continues into §3.10.7.4 step 7:

            "Once in the ESTABLISHED state, it is possible to
             deliver segment text to user RECEIVE buffers. Text
             from segments can be moved into buffers until either
             the buffer is full or the segment is empty. ... Send
             an acknowledgment of the form: <SEQ=SND.NXT>
             <ACK=RCV.NXT><CTL=ACK>."

        Concretely: peer's SYN+ACK with piggybacked data MUST
        transition us to ESTABLISHED, the data MUST be enqueued
        into '_rx_buffer' for the application's eventual 'recv()',
        'RCV.NXT' MUST advance past both the SYN's one byte AND
        every byte of payload, and we MUST emit a third-leg ACK
        whose 'ack' field acknowledges both.

        Wire shape of the SYN+ACK-with-data we feed:

            sport   = PEER__PORT
            dport   = STACK__PORT
            seq     = PEER__ISS
            ack     = LOCAL__ISS + 1
            flags   = {SYN, ACK}
            payload = b"greetings-from-peer"   (19 bytes)

        Required outbound third-leg ACK shape:

            seq     = LOCAL__ISS + 1
            ack     = PEER__ISS + 1 + 19      (consumes peer SYN
                                                + peer payload)
            flags   = {ACK}
            payload = b""

        Side effects asserted:

            * 'session.state' is FsmState.ESTABLISHED.
            * 'session._rx_buffer' equals the payload.
            * 'session._rcv_nxt' equals 'PEER__ISS + 1 + 19'.
            * The connect-event semaphore is released.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_syn_sent' line ~1945-1946
        in the SYN+ACK handling branch:

            if packet_rx_md.tcp__ack == self._snd_nxt and not packet_rx_md.tcp__data:
                ...
                self._change_state(FsmState.ESTABLISHED)

        The 'not packet_rx_md.tcp__data' sanity check rejects any
        SYN+ACK that carries a payload. The branch body is skipped,
        the function falls through every other branch (none match a
        SYN+ACK with data), and returns silently. State stays
        SYN_SENT, '_rx_buffer' stays empty, 'RCV.NXT' is unchanged
        (still 0, since '_rcv_ini' was never set), no third-leg ACK
        is emitted.

        Peer keeps retransmitting their SYN+ACK-with-data on their
        RTO; PyTCP keeps silently dropping. The connection
        eventually times out at peer's R2 (~100 s) or via PyTCP's
        own R2-driven abort.

        Severity: MEDIUM. Affects every peer stack that piggybacks
        application data on the SYN+ACK as a fast-start
        optimisation. Symmetric sister of the SYN_RCVD-third-leg-
        ACK-with-data bug pinned by the test
        'test__passive_open__third_leg_ack_with_payload_completes_handshake_and_delivers_data'
        in close__rst.py - same root-cause pattern ('not data'
        guard on a sanity check that should not gate the state
        transition), and a single combined fix can address both
        branches.

        Fix outline (separate commit, paired with the SYN_RCVD
        sister fix): drop the 'not data' guard from the sanity
        check, then enqueue any payload into '_rx_buffer' and
        advance 'RCV.NXT' past the data BEFORE the state
        transition fires. The shape mirrors the existing LISTEN-
        side handling for SYN-with-data (see
        'test__passive_open__syn_with_payload_to_listen_queues_data_and_acks_it').

        Scenario:

            1. CONNECT syscall. Tick to fire the initial SYN.
            2. Peer responds with SYN+ACK carrying 19-byte
               payload at 'seq = PEER__ISS, ack = LOCAL__ISS + 1'.
            3. Drive RX. The session MUST transition to ESTABLISHED
               and queue the data; the third-leg ACK MUST
               acknowledge both the SYN and the payload.

        On current code this test fails: the data-bearing SYN+ACK
        is silently dropped, state stays SYN_SENT.
        """

        # Stage 1: drive into SYN_SENT and emit the initial SYN.
        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="Setup precondition: state must be SYN_SENT after the SYN tick.",
        )
        self._frames_tx.clear()

        # Stage 2: peer sends SYN+ACK with piggybacked data.
        payload = b"greetings-from-peer"
        syn_ack_with_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            payload=payload,
        )
        tx_frames = self._drive_rx(frame=syn_ack_with_data)

        # Stage 3: assert ESTABLISHED + data delivered + third-leg
        # ACK fired with the data-acknowledging ack value.
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Per RFC 9293 §3.10.7.3 step 4, an acceptable SYN+ACK "
                "in SYN_SENT MUST transition the session to "
                "ESTABLISHED, regardless of whether the segment also "
                "carries data. Today '_tcp_fsm_syn_sent' line ~1945-"
                "1946 gates on 'not packet_rx_md.tcp__data', so a "
                "data-bearing SYN+ACK is silently dropped and the "
                "session stays in SYN_SENT. Fix: drop the 'not data' "
                "guard; enqueue the payload into '_rx_buffer' and "
                "advance 'RCV.NXT' past it before the state "
                f"transition fires. Got state: {session.state!r}."
            ),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            payload,
            msg=(
                "Per RFC 9293 §3.10.7.3 step 4 -> §3.10.7.4 step 7, "
                "the data piggybacked on the SYN+ACK MUST be enqueued "
                "into '_rx_buffer' so the application can receive it "
                f"via 'recv()'. Got: {bytes(session._rx_buffer)!r}, "
                f"expected: {payload!r}."
            ),
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1 + len(payload),
            msg=(
                "Per RFC 9293 §3.10.7.4 step 7, 'RCV.NXT' MUST "
                "advance past BOTH the SYN's one byte AND every byte "
                f"of payload. Got: {session._rcv_nxt:#x}, expected: "
                f"{PEER__ISS + 1 + len(payload):#x}."
            ),
        )
        self.assertGreaterEqual(
            len(tx_frames),
            1,
            msg=(
                "Per RFC 9293 §3.10.7.4 step 7, after enqueueing the "
                "SYN+ACK's payload the session MUST emit the third-"
                "leg ACK so peer learns the data is received. Today "
                "no outbound ACK is emitted because the data-bearing "
                "SYN+ACK is silently dropped. Got "
                f"{len(tx_frames)} TX frame(s)."
            ),
        )
        if tx_frames:
            third_leg = self._parse_tx(tx_frames[-1])
            self.assertEqual(
                third_leg.flags,
                frozenset({"ACK"}),
                msg="The third-leg reply must be a bare ACK (no SYN / FIN / RST flags).",
            )
            self.assertEqual(
                third_leg.seq,
                LOCAL__ISS + 1,
                msg="The third-leg ACK's SEQ must equal SND.NXT after our SYN was sent (= LOCAL__ISS + 1).",
            )
            self.assertEqual(
                third_leg.ack,
                PEER__ISS + 1 + len(payload),
                msg=(
                    "The third-leg ACK's ack field MUST acknowledge "
                    "both peer's SYN's one byte AND every byte of "
                    f"peer's piggybacked payload. Got: "
                    f"{third_leg.ack:#x}, expected: "
                    f"{PEER__ISS + 1 + len(payload):#x}."
                ),
            )

        # The connect-event semaphore must release on ESTABLISHED so
        # a blocked 'connect()' caller unblocks.
        self.assertTrue(
            session._event__connect.acquire(timeout=0),
            msg=(
                "The connect-event semaphore must be released once "
                "the session reaches ESTABLISHED, even when the "
                "transition was driven by a data-bearing SYN+ACK."
            ),
        )

    def test__active_open__rst_ack_to_outbound_syn_yields_connection_refused(self) -> None:
        """
        Ensure that when our initial SYN provokes a RST+ACK from the
        peer (the canonical "connection refused" response a host
        sends for a SYN to a closed port - see RFC 9293 §3.10.7.2),
        the SYN_SENT state machine accepts the RST, transitions
        directly to CLOSED, signals the connect-event semaphore with
        'ConnError.REFUSED' so 'TcpSession.connect()' would raise
        'TcpSessionError("Connection refused")' to the caller, and
        emits no segment in response (RFC 9293 §3.10.7.3 explicitly
        forbids replying to an RST that has been accepted - doing so
        would create a RST/RST loop with the peer).

        Required wire-level shape of an acceptable RST in SYN_SENT,
        per RFC 9293 §3.10.7.3 read in conjunction with the RFC 5961
        §3 blind-reset mitigation that the same section folds in:

          - The RST and ACK flags must both be set; SYN and FIN must
            be clear. (A bare RST is dropped because we cannot tell
            whether it acknowledges our SYN; only a RST+ACK with an
            acceptable ACK is acted upon.)
          - The ACK number must equal SND.NXT (i.e. ISS+1). The spec
            allows SND.UNA < SEG.ACK <= SND.NXT but recommends the
            stricter '== SND.NXT' check; the current implementation
            uses the strict form and this test pins that contract.
          - The SEQ number must equal RCV.NXT, which in SYN_SENT is
            still 0 because we have not yet seen any peer segment.
            This is the RFC 5961 mitigation - it prevents an
            off-window blind RST attacker from tearing down our
            embryonic connection.

        Side effects asserted post-RST:

          - 'session.state is FsmState.CLOSED'
          - '_connection_error is ConnError.REFUSED'
          - '_event__connect.acquire(timeout=0) is True' (the connect
            syscall is unblocked with the REFUSED signal)
          - The socket is unregistered from 'stack.sockets' by
            '_change_state(FsmState.CLOSED)' so subsequent inbound
            packets to the same 4-tuple are not delivered to the
            now-dead session.
        """

        # Drive the session to SYN_SENT and emit the initial SYN.
        session = self._make_active_session(iss=LOCAL__ISS)
        socket_id = session.socket.socket_id
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg=(
                "SYN_SENT setup precondition: exactly one SYN must have "
                "been transmitted before driving the RST scenario."
            ),
        )

        # Peer responds with RST+ACK acknowledging our SYN.
        rst_ack_frame = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0,
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=0,
        )

        tx_frames = self._drive_rx(frame=rst_ack_frame)

        self.assertEqual(
            tx_frames,
            [],
            msg=(
                "An accepted RST in SYN_SENT must not provoke any "
                "outbound segment - replying to a peer RST is "
                "forbidden by RFC 9293 §3.10.7.3 to avoid RST/RST "
                "loops."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "An RST+ACK with an acceptable ACK in SYN_SENT must "
                "transition the session to CLOSED (RFC 9293 §3.10.7.3)."
            ),
        )
        self.assertIs(
            session._connection_error,
            ConnError.REFUSED,
            msg=(
                "The session must record 'ConnError.REFUSED' so that a "
                "blocked 'TcpSession.connect()' caller raises "
                "'TcpSessionError(\"Connection refused\")' on unblock."
            ),
        )
        self.assertTrue(
            session._event__connect.acquire(timeout=0),
            msg=(
                "The connect-event semaphore must be released when the "
                "session is reset so a blocked 'connect()' caller "
                "unblocks rather than hanging until the retransmit "
                "timeout fires."
            ),
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg=(
                "Transitioning to CLOSED must unregister the socket from "
                "'stack.sockets' so subsequent packets to the same "
                "4-tuple do not reach the dead session "
                "(RFC 9293 §3.10.4 / TCB deletion)."
            ),
        )

    def test__active_open__bare_rst_in_syn_sent_dropped_silently_per_rfc_9293_3_10_7_3(self) -> None:
        """
        Ensure that a peer-issued BARE RST (RST flag set, ACK flag
        cleared) arriving in SYN_SENT is dropped silently per RFC
        9293 §3.10.7.3 step 2, regardless of the seq/ack values
        carried on the segment. SYN_SENT's RST handling is
        DIFFERENT from the synchronized states' rule precisely
        because we have no way to validate that a bare RST was
        issued in response to OUR SYN versus injected by an
        off-path attacker - the spec mandates we wait for the
        explicit RST+ACK confirmation.

        RFC 9293 §3.10.7.3 step 2 (SYN-SENT, RST handling):

            "If the RST bit is set,
              If the ACK was acceptable then signal the user
              'error: connection reset', drop the segment, enter
              CLOSED state, delete TCB, and return.
              Otherwise (no ACK), drop the segment and return."

        Note the explicit "Otherwise (no ACK), drop the segment
        and return" clause: bare RST in SYN_SENT is dropped, not
        accepted. This DIFFERS from the synchronized-state rule
        in §3.10.7.4 where bare RST IS valid (subject to the
        SEG.SEQ window check). The asymmetry is deliberate:

          - Synchronized states have an established RCV.NXT, so a
            bare RST's seq can be window-validated against the
            same 32-bit window an attacker would need to guess.
          - SYN_SENT has no established window yet. The only way
            to bind the RST to OUR connection is via SEG.ACK
            (which must equal SND.NXT = ISS + 1). A bare RST has
            no acceptable-ACK path, so the only safe action is to
            drop it.

        This test acts as a positive-control regression guard
        against a future "uniform fix" that loosens the SYN_SENT
        predicate from 'all({tcp__flag_rst, tcp__flag_ack})' to
        bare 'tcp__flag_rst' alongside the (correct) loosening
        in the five synchronized-state branches (ESTABLISHED /
        FIN_WAIT_1 / FIN_WAIT_2 / CLOSING / LAST_ACK). The
        SYN_SENT branch's strict 'all({rst, ack})' predicate is
        intentional and must NOT be uniformly relaxed.

        The danger is concrete: today the SYN_SENT branch has an
        inner sanity check 'tcp__seq == 0 and tcp__ack ==
        self._snd_nxt'. A bare RST with ack = LOCAL__ISS + 1
        carries an "acceptable-looking" ack value (the ACK flag
        is cleared, so the value is a wire-level field whose
        contents the spec says should be ignored). Today's outer
        predicate filters out bare RSTs before the inner check
        ever runs. If the predicate is loosened uniformly, the
        bare RST enters the branch, the inner check
        ('seq==0 and ack==SND.NXT') passes for a peer that
        constructs the segment to look acceptable, and the
        connection silently transitions to CLOSED - giving an
        off-path blind-RST attacker a tool to abort embryonic
        connections.

        Scenario:

            1. Drive into SYN_SENT and emit our SYN.
            2. Peer sends a BARE RST (flags={"RST"}, ACK flag
               CLEARED) at SEQ = 0 and ACK = LOCAL__ISS + 1
               (the value that, paired with the ACK flag, would
               make the canonical RST+ACK acceptable).
            3. Drive RX. The session MUST stay in SYN_SENT, MUST
               NOT release the connect-event semaphore, MUST NOT
               record any '_connection_error', and MUST NOT
               unregister the socket from 'stack.sockets'.

        Assertions:

            * State remains SYN_SENT.
            * '_connection_error' is still 'ConnError.NONE'.
            * '_event__connect.acquire(timeout=0)' returns False
              (semaphore was not released by an erroneous abort).
            * Socket still registered in 'stack.sockets'.
            * No outbound segment is produced.

        This test PASSES on current code as a positive-control
        regression guard. It is the companion to the five
        '[FLAGS BUG]' bare-RST tests in close__rst.py /
        close__simultaneous.py: those motivate loosening the
        predicate in five branches, this test pins the SYN_SENT
        branch's strict-ACK predicate as INTENTIONAL.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        socket_id = session.socket.socket_id
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: exactly one SYN must have been emitted before the bare RST.",
        )
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="Setup precondition: state must be SYN_SENT after the SYN was emitted.",
        )

        # Peer sends a BARE RST with an "acceptable-looking" ack
        # value but the ACK flag CLEARED. Today the outer
        # 'all({rst, ack})' predicate filters this out before the
        # inner sanity check; the test pins that filter.
        bare_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0,
            ack=LOCAL__ISS + 1,
            flags=("RST",),
            win=0,
        )
        rst_inline = self._drive_rx(frame=bare_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg=(
                "A bare RST in SYN_SENT must produce NO outbound "
                "segment - it is dropped silently per RFC 9293 "
                "§3.10.7.3 step 2 ('Otherwise (no ACK), drop the "
                "segment and return')."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg=(
                "A bare RST in SYN_SENT MUST NOT transition the "
                "session to CLOSED. RFC 9293 §3.10.7.3 step 2 "
                "explicitly requires 'no ACK -> drop the segment'. "
                "If this assertion fails, the SYN_SENT RST predicate "
                "has been over-broadened (likely as part of a "
                "uniform 'all({rst, ack}) -> tcp__flag_rst' rewrite "
                "that conflated the synchronized-state rule with "
                "SYN_SENT's stricter rule). The fix for the five "
                "synchronized-state RST branches MUST NOT be applied "
                "to SYN_SENT - the strict-ACK predicate at line "
                "~2092 is intentional. "
                f"Got state: {session.state!r}."
            ),
        )
        self.assertIs(
            session._connection_error,
            ConnError.NONE,
            msg=(
                "'_connection_error' must remain ConnError.NONE - a "
                "dropped bare RST does not signal the user an error. "
                "If this fires, the SYN_SENT RST handler ran "
                "erroneously on a segment it should have ignored."
            ),
        )
        self.assertFalse(
            session._event__connect.acquire(timeout=0),
            msg=(
                "The connect-event semaphore must NOT be released by "
                "a bare RST in SYN_SENT - the connection has not been "
                "refused, just spuriously poked. A blocked 'connect()' "
                "caller must remain blocked until the legitimate "
                "RST+ACK refusal or the R2 timeout fires."
            ),
        )
        self.assertIn(
            socket_id,
            stack.sockets,
            msg=(
                "The socket must remain registered in 'stack.sockets' - "
                "a dropped bare RST does not delete the TCB. If this "
                "fires, the SYN_SENT branch erroneously called "
                "'_change_state(CLOSED)' which unregisters the socket."
            ),
        )

    def test__active_open__silent_peer_retransmits_per_rfc6298_until_r2(self) -> None:
        """
        Ensure that when the peer never replies to our SYN, the
        SYN_SENT state machine retransmits at the cadence prescribed
        by RFC 6298 §2 (initial RTO 1 s, doubling on every retry) and
        does NOT abort the connection before R2 = 100 s of total
        elapsed time has been exhausted (RFC 9293 §3.8.3 incorporating
        RFC 1122 §4.2.3.5: "R2 SHOULD correspond to at least 100
        seconds").

        Concretely, the RFC-compliant cadence over the first 60
        seconds of silence must produce SYN retransmits at
        approximately:

            t =   0 s   initial SYN
            t =   1 s   1st retransmit (RTO = 1 s)
            t =   3 s   2nd retransmit (RTO doubled to 2 s)
            t =   7 s   3rd retransmit (RTO doubled to 4 s)
            t =  15 s   4th retransmit (RTO doubled to 8 s)
            t =  31 s   5th retransmit (RTO doubled to 16 s)
            t =  63 s   6th retransmit (RTO doubled to 32 s)

        i.e. by t = 60 s we must have observed at least six SYN
        transmissions (the initial plus five retransmits) and the
        session must STILL be in SYN_SENT - the spec floor on R2 is
        100 s, well beyond 60 s.

        Each retransmit must reuse our ISS as SEQ (we are
        retransmitting the SAME segment, not opening a new
        connection) and must carry the SYN flag with the same option
        block we originally advertised.

        [FLAGS BUG] - RFC 9293 §3.8.3 deviation
        ----------------------------------------------------------
        The current 'tcp__session.py' uses
        'PACKET_RETRANSMIT_MAX_COUNT = 3' and aborts the session at
        the third retransmit's timer expiry. With the doubling
        cadence above, that means the session is forced to CLOSED at
        roughly t = 15 s (after 1 + 2 + 4 + 8 = 15 s of cumulative
        retransmit timeouts), more than 6x earlier than R2 = 100 s
        permits. A blocked 'connect()' caller therefore sees a
        connection-timeout error far sooner than RFC 9293 / RFC 1122
        promise.

        This test pins the RFC-compliant behaviour and is expected to
        FAIL on the current implementation; the failure is the proof
        of the bug. Fixing it requires raising the retransmit limit
        (or, better, switching to a wall-clock R2 budget) so total
        elapsed time before abort is at least 100 s.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        # Drive 60 seconds of virtual time with the peer staying silent.
        # All TX produced during the window is captured in one list.
        tx_frames = self._advance(ms=60_000)

        # Every TX must be a SYN retransmission of our original ISS - no
        # state-change side effects allowed while waiting for the peer.
        probes = [self._parse_tx(frame) for frame in tx_frames]
        for index, probe in enumerate(probes):
            self.assertEqual(
                probe.flags,
                frozenset({"SYN"}),
                msg=(
                    f"Retransmit #{index} must carry only the SYN flag "
                    f"(no ACK / RST / FIN). Got flags={probe.flags!r}."
                ),
            )
            self.assertEqual(
                probe.seq,
                LOCAL__ISS,
                msg=(
                    f"Retransmit #{index} must reuse the original ISS "
                    f"as SEQ (RFC 6298 §2 retransmits the same segment). "
                    f"Got seq=0x{probe.seq:08x}, expected 0x{LOCAL__ISS:08x}."
                ),
            )
            self.assertEqual(
                probe.ack,
                0,
                msg=(
                    f"Retransmit #{index} must carry ACK=0 since we have "
                    f"not yet received any segment from the peer."
                ),
            )

        # By t = 60 s, the RFC 6298 doubling cadence (1, 3, 7, 15, 31, 63 s)
        # must have produced at least six SYN transmissions: the initial
        # SYN at t = ~1 ms plus five retransmits within 60 s.
        self.assertGreaterEqual(
            len(probes),
            6,
            msg=(
                f"By t = 60 s of peer silence, the RFC 6298 cadence "
                f"(initial + retransmits at 1, 3, 7, 15, 31 s) must "
                f"produce at least 6 SYN transmissions. Got {len(probes)} "
                f"- 'PACKET_RETRANSMIT_MAX_COUNT = 3' aborts the "
                f"connection too early per RFC 1122 §4.2.3.5 R2 >= 100 s."
            ),
        )

        # Most important: the session must NOT have aborted yet. R2 is
        # at least 100 s, so at t = 60 s the connection is still alive
        # and 'TcpSession.connect()' is still blocked waiting.
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg=(
                "After 60 s of peer silence, the session must remain in "
                "SYN_SENT. RFC 1122 §4.2.3.5 R2 (incorporated by RFC "
                "9293 §3.8.3) requires the connection-abort timeout to "
                "be at least 100 s; aborting at t < 100 s violates the "
                "spec and causes 'connect()' to return ETIMEDOUT to the "
                "caller far earlier than required."
            ),
        )
        self.assertIs(
            session._connection_error,
            ConnError.NONE,
            msg=(
                "No connection error must be recorded while the session "
                "is still legitimately retrying SYN within R2."
            ),
        )
        self.assertFalse(
            session._event__connect.acquire(timeout=0),
            msg=(
                "The connect-event semaphore must not yet be released "
                "while the session is still validly retransmitting "
                "within R2 - releasing it would unblock 'connect()' "
                "with a spurious timeout."
            ),
        )

    def test__active_open__retransmitted_syn_ack_in_established_emits_challenge_ack(self) -> None:
        """
        Ensure that when a peer's third-leg ACK gets lost in flight
        and the peer retransmits its SYN+ACK while we have already
        moved to ESTABLISHED, we respond with a "challenge ACK" per
        RFC 9293 §3.10.7.4 (folding RFC 5961 §4) rather than silently
        dropping the segment, tearing down the connection, or
        attempting a fresh handshake.

        Wire shape of the retransmitted SYN+ACK:

            seq = peer_ISS                   (peer is replaying their
                                              original handshake segment,
                                              not advancing)
            ack = our_ISS + 1                (still acknowledges only our
                                              SYN, not any data)
            flags = {SYN, ACK}

        From the peer's perspective, this is a perfectly legal
        retransmission - their RTO fired before they observed our
        third-leg ACK. From our perspective in ESTABLISHED, however,
        the SYN flag set on a segment from an already-established
        4-tuple is suspicious. RFC 5961 §4 (which RFC 9293 §3.10.7.4
        incorporates verbatim) prescribes:

            "a challenge ACK MUST be sent ... [carrying] the values
             SND.NXT and RCV.NXT for SEG.SEQ and SEG.ACK, respectively"

        In other words: respond with a normal ACK keyed to our
        current connection state. This serves two purposes -
        (a) if the peer was legitimately retransmitting, our challenge
        ACK satisfies them and the connection continues normally;
        (b) if the SYN was forged by an attacker who guessed the
        4-tuple but did not observe our ISN, the challenge ACK gives
        the legitimate peer a chance to RST the spoofed segment.

        Required side effects:

            * Exactly one outbound segment, an ACK with
              flags = {ACK}, seq = SND.NXT (= our_ISS + 1),
              ack = RCV.NXT (= peer_ISS + 1), payload = b"".
            * 'session.state' remains 'FsmState.ESTABLISHED'.
            * 'session._snd_una' / '_rcv_nxt' unchanged - the
              retransmitted SYN+ACK is acknowledging data we already
              processed; reprocessing it would double-count the SYN's
              one-byte sequence space and corrupt our window.

        [FLAGS BUG] - RFC 9293 §3.10.7.4 / RFC 5961 §4 deviation
        ----------------------------------------------------------
        '_tcp_fsm_established' has no branch matching SYN+ACK; the
        outer receive-window check
        '_rcv_nxt <= seg.seq <= _rcv_nxt + _rcv_wnd - len(data)'
        rejects the retransmission outright (the peer's seq =
        peer_ISS is one byte before our _rcv_nxt = peer_ISS + 1)
        and the handler returns silently, emitting nothing. The peer
        receives no acknowledgement, retries on its own RTO, and may
        eventually give up and RST the connection. The connection
        looks established to us but is functionally one-way until the
        peer either gets through with data we ACK directly or aborts.

        This test is expected to FAIL on current code. Fixing it
        requires adding a SYN-on-established branch that emits the
        challenge ACK before the receive-window check trims the
        segment.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        # Drive the handshake to ESTABLISHED.
        self._advance(ms=1)  # initial SYN goes out
        syn_ack_frame = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=syn_ack_frame)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Setup precondition: handshake must have reached " "ESTABLISHED before driving the lost-ACK scenario."
            ),
        )
        snd_una_before = session._snd_una
        rcv_nxt_before = session._rcv_nxt

        # Peer's third-leg ACK was lost in flight; their RTO fires and
        # they retransmit the SAME SYN+ACK. Drive it into our session.
        retransmitted_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        tx_frames = self._drive_rx(frame=retransmitted_syn_ack)

        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "Receiving a SYN-bearing segment in ESTABLISHED must "
                "emit exactly one challenge ACK per RFC 9293 §3.10.7.4 "
                "/ RFC 5961 §4. Got "
                f"{len(tx_frames)} TX frames."
            ),
        )

        challenge_ack = self._parse_tx(tx_frames[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
            mss=None,
            wscale=None,
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "A challenge ACK is informational only - it must NOT "
                "transition the session out of ESTABLISHED "
                '(RFC 5961 §4: "the connection state is not changed").'
            ),
        )
        self.assertEqual(
            session._snd_una,
            snd_una_before,
            msg=(
                "A challenge ACK does not consume sequence space - "
                "'_snd_una' must be unchanged. Reprocessing the "
                "retransmitted SYN's ACK would double-count and "
                "corrupt the send window."
            ),
        )
        self.assertEqual(
            session._rcv_nxt,
            rcv_nxt_before,
            msg=(
                "Reprocessing a retransmitted SYN+ACK must not advance "
                "'_rcv_nxt' - the SYN's one byte of sequence space was "
                "already consumed during the original handshake."
            ),
        )

    def test__active_open__bare_ack_with_unacceptable_ack_in_syn_sent_emits_rst(self) -> None:
        """
        Ensure that a bare ACK (no SYN, no RST, no FIN) arriving in
        SYN_SENT with an UNACCEPTABLE acknowledgement number triggers
        the RFC 9293 §3.10.7.3 step 1 response: emit a RST whose
        sequence number is the offending SEG.ACK, then discard the
        segment. The session must remain in SYN_SENT - this kind of
        spurious ACK does not signal that the peer believes the
        connection is up, so we keep waiting for a legitimate
        SYN+ACK and continue retransmitting our SYN on the normal
        cadence.

        Wire shape of the spurious bare ACK we feed:

            seq   = 0       (peer has not sent any prior segment from
                             our perspective; arbitrary in this case)
            ack   = 0       (clearly unacceptable: 0 <= ISS = 0x1000)
            flags = {ACK}   (no SYN, no RST, no FIN)

        Acceptability test per RFC 9293 §3.10.7.3 step 1 requires
        'SND.UNA < SEG.ACK =< SND.NXT'. In SYN_SENT after our initial
        SYN, SND.UNA = ISS and SND.NXT = ISS + 1, so the only
        acceptable ACK value is ISS + 1; any other value triggers the
        reset path.

        Required outbound RST shape (RFC 9293 §3.10.7.3 step 1
        verbatim: '<SEQ=SEG.ACK><CTL=RST>'):

            seq     = SEG.ACK   (i.e. 0 in this test, the bogus value
                                 we received - we echo it back to make
                                 absolutely clear which segment we are
                                 rejecting)
            ack     = 0         (RST does not acknowledge anything)
            flags   = {RST}     (no ACK flag - the spec form is bare
                                 RST, not RST+ACK)
            payload = b""

        And critically:

            * 'session.state' remains 'FsmState.SYN_SENT' - a spurious
              ACK is not a connection event; only an RST or a valid
              SYN(+ACK) changes our state from SYN_SENT.
            * 'session._snd_una' is unchanged - the bogus ACK
              acknowledged nothing we sent.

        [FLAGS BUG] - RFC 9293 §3.10.7.3 step 1 deviation
        ----------------------------------------------------------
        '_tcp_fsm_syn_sent' has only three packet-driven branches:
        SYN+ACK, bare SYN (simultaneous open), and RST+ACK. A bare
        ACK matches none of them and falls through to the bottom of
        the function unprocessed. No RST is emitted, the segment is
        silently dropped, and the spurious peer is free to repeat.
        Worse, an attacker who can guess our 4-tuple but not our ISS
        can send forged ACK floods knowing they will be ignored
        rather than visibly rejected.

        This test is expected to FAIL on current code. Fixing it
        requires a bare-ACK branch in '_tcp_fsm_syn_sent' that
        evaluates 'SND.UNA < seg.ack <= SND.NXT' and, on rejection,
        emits the spec'd <SEQ=SEG.ACK><CTL=RST> reply.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg=(
                "SYN_SENT setup precondition: exactly one SYN must "
                "have been transmitted before driving the bare-ACK "
                "scenario."
            ),
        )

        snd_una_before = session._snd_una
        snd_nxt_before = session._snd_nxt

        # Peer sends a bare ACK with an unacceptable ACK number. ack=0
        # is clearly outside (SND.UNA=ISS, SND.NXT=ISS+1] so RFC 9293
        # §3.10.7.3 step 1 mandates a RST in response.
        bogus_ack_value = 0
        bogus_bare_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0,
            ack=bogus_ack_value,
            flags=("ACK",),
            win=PEER__WIN,
        )

        tx_frames = self._drive_rx(frame=bogus_bare_ack)

        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "An unacceptable bare ACK in SYN_SENT must elicit "
                "exactly one outbound segment (a bare RST) per RFC "
                f"9293 §3.10.7.3 step 1. Got {len(tx_frames)} TX frames."
            ),
        )

        rst = self._parse_tx(tx_frames[0])
        self._assert_segment(
            rst,
            flags=frozenset({"RST"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=bogus_ack_value,
            ack=0,
            payload=b"",
            mss=None,
            wscale=None,
        )

        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg=(
                "A spurious bare ACK must NOT transition the session "
                "out of SYN_SENT - we keep waiting for the legitimate "
                "SYN+ACK from the peer (RFC 9293 §3.10.7.3 step 1: "
                "the segment is discarded after the RST is sent)."
            ),
        )
        self.assertEqual(
            session._snd_una,
            snd_una_before,
            msg=("A bogus bare ACK must not advance '_snd_una' - it " "acknowledged nothing we sent."),
        )
        self.assertEqual(
            session._snd_nxt,
            snd_nxt_before,
            msg=(
                "Sending the RST in response to a bogus ACK must not "
                "advance our own '_snd_nxt' - the RST consumes no "
                "sequence space (RFC 9293 §3.4)."
            ),
        )

    def test__active_open__syn_ack_with_unacceptable_ack_in_syn_sent_emits_rst(self) -> None:
        """
        Ensure that a SYN+ACK arriving in SYN_SENT whose ACK number
        is outside the acceptable window '(SND.UNA, SND.NXT]' is
        rejected per RFC 9293 §3.10.7.3 step 1: a bare RST with
        '<SEQ=SEG.ACK><CTL=RST>' is emitted, the segment is
        discarded, and the session stays in SYN_SENT to keep waiting
        for a legitimate SYN+ACK from the real peer.

        This is the SYN-bit-set sibling of the bare-ACK case in the
        previous test. RFC 9293 §3.10.7.3 specifies the ACK
        acceptability check (step 1) BEFORE the RST check (step 2),
        the security check (step 3), and the SYN check (step 4) - in
        other words, the presence of the SYN flag does not exempt the
        peer from sending an acceptable ACK. A SYN+ACK with a bogus
        ACK number is just as malformed as a bare ACK with the same
        bogus value, and gets the same RFC response.

        Wire shape of the rogue SYN+ACK we feed:

            seq   = peer_ISS  (legitimate-looking sender ISN)
            ack   = 0xDEADBEEF  (clearly outside (ISS, ISS+1])
            flags = {SYN, ACK}

        The acceptability test 'SND.UNA < SEG.ACK <= SND.NXT' folds
        into 'SEG.ACK == ISS+1' in SYN_SENT, so any other value
        (whether linearly larger like '0xDEADBEEF', linearly smaller
        like '0', or modularly distant) triggers the reset path.
        Choosing '0xDEADBEEF' makes the offending value visually
        unambiguous in failure messages and packet captures.

        Required outbound RST shape (RFC 9293 §3.10.7.3 step 1):

            seq     = SEG.ACK = 0xDEADBEEF
            ack     = 0                    (no ACK flag set)
            flags   = {RST}                (bare RST, NOT RST+ACK)
            payload = b""

        Side effects asserted:

            * 'session.state' remains 'FsmState.SYN_SENT'. Crucially,
              we do NOT transition to ESTABLISHED - the SYN we
              ostensibly received must be discarded along with the
              bogus ACK because step 1's "discard the segment" applies
              to the whole segment, not just its ACK field.
            * 'session._snd_una' and '_rcv_nxt' are unchanged: we did
              not process the SYN, so peer's ISN is not recorded; we
              did not consume any of our own sequence space, so
              '_snd_una' stays at ISS.
            * '_event__connect' is NOT released - 'connect()' must
              keep blocking; spurious SYN+ACK from a wrong peer is not
              a connection event.

        [FLAGS BUG] - RFC 9293 §3.10.7.3 step 1 deviation
        ----------------------------------------------------------
        The SYN+ACK branch in '_tcp_fsm_syn_sent' tests
        'tcp__ack == self._snd_nxt' as an inner sanity check; if it
        fails, the branch silently 'falls through' to the next
        if-block and ultimately the function returns without action.
        No RST is emitted. An attacker (or a misconfigured peer) can
        therefore send streams of malformed SYN+ACKs and we will
        ignore them rather than visibly rejecting them, prolonging
        the SYN_SENT window in which the legitimate peer might
        otherwise win the race.

        This test is expected to FAIL on current code. Fixing it
        requires lifting step 1 (ACK-acceptability + RST) out of the
        per-flag-combination branches and running it as the very
        first thing the SYN_SENT handler does on every incoming
        ACK-bearing segment - matching the order RFC 9293 §3.10.7.3
        prescribes.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg=(
                "SYN_SENT setup precondition: exactly one SYN must "
                "have been transmitted before driving the bogus "
                "SYN+ACK scenario."
            ),
        )

        snd_una_before = session._snd_una
        snd_nxt_before = session._snd_nxt
        rcv_nxt_before = session._rcv_nxt

        # Peer sends SYN+ACK with a clearly unacceptable ACK number.
        # 0xDEADBEEF is far outside the only valid value ISS+1=0x1001
        # and is visually unambiguous in failure output.
        bogus_ack_value = 0xDEAD_BEEF
        rogue_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=bogus_ack_value,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )

        tx_frames = self._drive_rx(frame=rogue_syn_ack)

        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "A SYN+ACK with an unacceptable ACK in SYN_SENT must "
                "elicit exactly one outbound segment (a bare RST) per "
                f"RFC 9293 §3.10.7.3 step 1. Got {len(tx_frames)} "
                "TX frames."
            ),
        )

        rst = self._parse_tx(tx_frames[0])
        self._assert_segment(
            rst,
            flags=frozenset({"RST"}),
            sport=STACK__PORT,
            dport=PEER__PORT,
            seq=bogus_ack_value,
            ack=0,
            payload=b"",
            mss=None,
            wscale=None,
        )

        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg=(
                "A SYN+ACK with an unacceptable ACK must NOT transition "
                "the session to ESTABLISHED - step 1 of RFC 9293 "
                "§3.10.7.3 mandates discarding the whole segment, so "
                "the SYN is never processed and the session stays in "
                "SYN_SENT awaiting a legitimate SYN+ACK."
            ),
        )
        self.assertEqual(
            session._snd_una,
            snd_una_before,
            msg=("A bogus SYN+ACK must not advance '_snd_una' - the " "rejected ACK acknowledged nothing."),
        )
        self.assertEqual(
            session._snd_nxt,
            snd_nxt_before,
            msg=(
                "Sending the RST must not advance '_snd_nxt' - the " "RST consumes no sequence space (RFC 9293 §3.4)."
            ),
        )
        self.assertEqual(
            session._rcv_nxt,
            rcv_nxt_before,
            msg=(
                "A rejected SYN+ACK's SYN must not be processed - "
                "'_rcv_nxt' must not advance to peer_ISS+1, since we "
                "are still treating the peer's ISN as unknown."
            ),
        )
        self.assertFalse(
            session._event__connect.acquire(timeout=0),
            msg=(
                "The connect-event semaphore must not be released by "
                "a rejected SYN+ACK - 'connect()' must keep blocking "
                "until a legitimate handshake completes or R2 elapses."
            ),
        )

    def test__active_open__rst_in_simultaneous_open_syn_rcvd_unblocks_connect(self) -> None:
        """
        Ensure that when an active-open caller is blocked on
        '_event__connect' and the session traverses
        SYN_SENT → SYN_RCVD (via the simultaneous-open path -
        peer's bare SYN crossing our outbound SYN) → CLOSED
        (via peer RST), the connect-event semaphore is
        released with 'ConnError.REFUSED'. Today the SYN_RCVD
        RST handler only calls '_change_state(CLOSED)' and
        leaves the blocked 'connect()' caller hanging on the
        semaphore forever.

        RFC 9293 §3.10.7.4 (synchronized state RST handling):

            "If the RST bit is set then ... any outstanding
             RECEIVEs and SEND should receive 'reset'
             responses. ... Users should also receive an
             unsolicited general 'connection reset' signal."

        SYN-RECEIVED is a synchronized state, and the active-
        open caller blocked on 'connect()' is the analog of
        the "outstanding RECEIVE" the spec calls out. Failing
        to release the semaphore violates the contract and
        produces an application-level deadlock.

        Threat model: a peer that opens connections
        simultaneously and then resets them (legitimately or
        adversarially) can pin our 'connect()' callers in a
        blocked-forever state. The SYN_SENT RST handler
        already releases the semaphore correctly (commit
        '9a1d7f5' precedent / line 2032 of 'tcp__session.py');
        SYN_RCVD's two RST branches (RST+ACK and bare RST)
        do not.

        Scenario:

            1. Build active-open session with LOCAL__ISS.
               Issue CONNECT. Tick once to emit SYN.
               State = SYN_SENT.
            2. Verify the connect-event semaphore is NOT yet
               released - sanity for the "blocked connect"
               precondition.
            3. Peer sends a bare SYN (no ACK) - the
               simultaneous-open trigger. SYN_SENT's SYN-only
               branch transitions to SYN_RCVD and emits a
               SYN+ACK.
            4. Verify the connect-event semaphore is STILL
               not released - we are still mid-handshake.
            5. Peer sends RST+ACK with seq=PEER_ISS+1 (=
               RCV.NXT), ack=LOCAL__ISS+1 (= SND.NXT).
               Session transitions SYN_RCVD → CLOSED.

        Assertions:

            * State is CLOSED.
            * 'session._connection_error' is
              'ConnError.REFUSED' so a blocked
              'TcpSession.connect()' caller receives the
              'TcpSessionError("Connection refused")'
              propagation rather than a generic timeout or
              an indefinite hang.
            * 'session._event__connect.acquire(timeout=0)'
              returns True - the semaphore was released, the
              blocked caller would unblock.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_syn_rcvd's RST and
        RST+ACK branches (line ~2123 and ~2143) call only
        '_change_state(FsmState.CLOSED)' and 'return'. They
        do not set '_connection_error' and do not release
        '_event__connect'. This contrasts with
        '_tcp_fsm_syn_sent's RST+ACK handler (line ~2032)
        which correctly does both.

        Fix outline (separate commit):

            Mirror the SYN_SENT shape - on RST acceptance in
            SYN_RCVD, set
            'self._connection_error = ConnError.REFUSED' and
            call 'self._event__connect.release()' before the
            state transition. The release on a non-blocked
            semaphore is harmless (Semaphore.release() just
            increments the counter), so a single fix applies
            uniformly to both the active-open simultaneous-
            open caller (blocked) and the passive-open
            listener-fork child (not blocked).
        """

        # Step 1: drive active-open to SYN_SENT and emit our SYN.
        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="Setup precondition: state must be SYN_SENT after CONNECT and SYN emit.",
        )
        # Step 2: connect-event semaphore is NOT yet released.
        self.assertFalse(
            session._event__connect.acquire(timeout=0),
            msg=(
                "Setup precondition: connect-event semaphore must "
                "not be released while the handshake is still in "
                "progress (SYN_SENT)."
            ),
        )

        # Step 3: peer sends bare SYN (simultaneous-open trigger).
        # SYN_SENT's SYN-only branch transitions to SYN_RCVD and
        # emits a SYN+ACK.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        syn_ack_tx = self._drive_rx(frame=peer_syn)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg=(
                "Setup precondition: peer's bare SYN in SYN_SENT "
                "must elicit one outbound SYN+ACK as the "
                "simultaneous-open response."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.SYN_RCVD,
            msg=(
                "Setup precondition: peer's bare SYN must transition " "the session to SYN_RCVD per RFC 9293 §3.10.7.3."
            ),
        )
        # Step 4: connect-event semaphore is STILL not released.
        self.assertFalse(
            session._event__connect.acquire(timeout=0),
            msg=(
                "Setup precondition: connect-event semaphore must "
                "still not be released in SYN_RCVD - the handshake "
                "is not complete yet."
            ),
        )

        # Step 5: peer sends RST+ACK at canonical match position.
        # Post-Bug-C fix ('d7a57f6'): the simultaneous-open
        # handler bootstraps '_rcv_nxt' from peer's SYN, so
        # 'RCV.NXT == PEER__ISS + 1' here. The RST's seq must
        # match.
        peer_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,  # == _rcv_nxt
            ack=LOCAL__ISS + 1,
            flags=("RST", "ACK"),
            win=PEER__WIN,
        )
        rst_tx = self._drive_rx(frame=peer_rst)
        self.assertEqual(
            rst_tx,
            [],
            msg=(
                "Peer's RST+ACK in SYN_RCVD must produce NO outbound "
                "segment - RST is unilateral and the receiver does "
                "not reply (RFC 9293 §3.10.7.3)."
            ),
        )

        # The actual contract checks: state, connection_error, and
        # connect-event release.
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=(
                "Peer's RST+ACK with acceptable seq/ack in SYN_RCVD "
                "must transition the session to CLOSED per RFC 9293 "
                "§3.10.7.4."
            ),
        )
        self.assertIs(
            session._connection_error,
            ConnError.REFUSED,
            msg=(
                "On RST in SYN_RCVD with a blocked active-open "
                "caller, the session MUST record "
                "'ConnError.REFUSED' so the blocked "
                "'TcpSession.connect()' raises "
                "'TcpSessionError(\"Connection refused\")' on "
                "unblock, mirroring the SYN_SENT RST handler "
                "behaviour. Today the SYN_RCVD RST branch only "
                "calls '_change_state(CLOSED)' without setting "
                "'_connection_error'."
            ),
        )
        self.assertTrue(
            session._event__connect.acquire(timeout=0),
            msg=(
                "On RST in SYN_RCVD, the connect-event semaphore "
                "MUST be released so the blocked active-open caller "
                "unblocks. Today the SYN_RCVD RST branch only "
                "transitions state to CLOSED; the semaphore is "
                "never released, so any 'connect()' caller that "
                "reached SYN_RCVD via simultaneous open hangs "
                "forever on '_event__connect.acquire()'. Fix: "
                "mirror the SYN_SENT RST handler (line 2032 of "
                "'tcp__session.py') which sets "
                "'_connection_error = ConnError.REFUSED' and calls "
                "'_event__connect.release()' before the state "
                "transition."
            ),
        )

    def test__active_open__simultaneous_open_bootstraps_peer_state_from_bare_syn(self) -> None:
        """
        Ensure that when peer's bare SYN crosses our outbound
        SYN (the simultaneous-open path per RFC 9293 §3.5.1
        figure 8), the SYN+ACK we emit acknowledges peer's
        SYN sequence number AND we bootstrap peer-derived
        session state from peer's SYN options - mirroring the
        passive-open / listener-fork pattern in
        '_tcp_fsm_listen' (line ~1709-1747).

        RFC 9293 §3.5.1 (Simultaneous Connection Synchronization):

            "[The simultaneous-open] sequence of events is
             illustrated in Figure 8. ... The principal reason
             for the three-way handshake is to prevent old
             duplicate connection initiations from causing
             confusion."

        The third leg of the handshake requires our SYN+ACK
        to carry 'ack = peer_isn + 1' so peer accepts it as
        the acknowledgment of their SYN. Without this,
        peer's TCP rejects the SYN+ACK as not acknowledging
        their SYN, and the connection never establishes -
        both ends sit in SYN_SENT / SYN_RCVD until R2 fires.

        Equivalently: 'self._rcv_nxt' MUST be advanced past
        peer's SYN seq (to 'peer_isn + 1') before the SYN+ACK
        is emitted, and various peer-derived bookkeeping
        ('_rcv_ini', '_snd_mss' clamp, '_snd_wnd', WSCALE /
        SACK negotiation, '_peer_contacted' flag) MUST also
        be initialised from peer's SYN options - the
        listener-fork pattern at '_tcp_fsm_listen' lines
        ~1709-1747 does all of this.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_syn_sent's SYN-only
        branch (line ~2024-2029):

            if packet_rx_md.tcp__ack == 0 and not packet_rx_md.tcp__data:
                self._transmit_packet(flag_syn=True, flag_ack=True)
                self._change_state(FsmState.SYN_RCVD)
                return

        … doesn't bootstrap any peer-side state. The
        '_transmit_packet' call uses the default 'ack =
        self._rcv_nxt = 0' (the __init__ value) so the
        SYN+ACK we emit has 'ack=0' - peer rejects it. The
        SYN+ACK's 'seq' also defaults to 'self._snd_nxt =
        LOCAL__ISS + 1' (post-original-SYN advance) instead
        of 'LOCAL__ISS' (peer expected our same SYN seq with
        their ACK piggybacked).

        Severity: HIGH for simultaneous-open scenarios - the
        path is completely broken. Probability: rare in
        practice because most TCP stacks don't trigger
        simultaneous open, but when it does happen the
        handshake silently fails until R2 expires (~127 s).

        Fix outline (separate commit):

            Mirror the listener-fork bootstrap pattern from
            '_tcp_fsm_listen' lines ~1709-1747:

              - Clamp '_snd_mss' to peer's MSS bound.
              - Set '_snd_wnd = packet_rx_md.tcp__win'.
              - Run WSCALE / SACK bilateral negotiation on
                peer's options.
              - Set '_rcv_ini = packet_rx_md.tcp__seq' and
                '_rcv_nxt = add32(peer_seq, 1)'.
              - Set '_peer_contacted = True' (Bug C's
                companion - same flag introduced for #3).
              - Call '_transmit_packet(flag_syn=True,
                flag_ack=True, seq=self._snd_ini)' so the
                SYN+ACK consumes the same seq as our
                original SYN, not advances past it.

        Scenario:

            1. Build active-open session with LOCAL__ISS.
               Issue CONNECT. Tick once to emit SYN.
               State = SYN_SENT.
            2. Peer sends bare SYN with seq=PEER__ISS,
               win=PEER__WIN, mss=PEER__MSS. Drive RX.
            3. Inspect inline TX (the SYN+ACK we should
               emit) and inspect bootstrapped session state.

        Assertions:

            * Exactly one outbound segment fires (the
              SYN+ACK).
            * SYN+ACK 'seq = LOCAL__ISS' (reuses our
              original SYN's seq; doesn't advance past).
            * SYN+ACK 'ack = PEER__ISS + 1' (acknowledges
              peer's SYN).
            * 'session._rcv_nxt == PEER__ISS + 1'.
            * 'session._rcv_ini == PEER__ISS'.
            * 'session._snd_mss == PEER__MSS' (clamped to
              peer's MSS).
            * 'session._snd_wnd == PEER__WIN'.
            * 'session._peer_contacted is True'.
            * State is SYN_RCVD.

        Today the SYN+ACK has 'ack=0' (the most observable
        symptom) and none of the bootstrapped state is set.
        """

        # Step 1: drive active-open to SYN_SENT and emit SYN.
        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="Setup precondition: state must be SYN_SENT.",
        )

        # Step 2: peer sends bare SYN (simultaneous-open trigger).
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        syn_ack_tx = self._drive_rx(frame=peer_syn)

        # Step 3: inspect outbound SYN+ACK and bootstrapped state.
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg=(
                "Peer's bare SYN in SYN_SENT must elicit exactly "
                "one outbound SYN+ACK (the simultaneous-open "
                "response per RFC 9293 §3.10.7.3)."
            ),
        )
        syn_ack_probe = self._parse_tx(syn_ack_tx[0])

        # The fundamental wire-level assertion: the SYN+ACK MUST
        # acknowledge peer's SYN.
        self.assertEqual(
            syn_ack_probe.ack,
            PEER__ISS + 1,
            msg=(
                "The SYN+ACK we emit in response to peer's bare "
                "SYN MUST carry 'ack = PEER__ISS + 1' to "
                "acknowledge peer's SYN. Today the SYN-only "
                "handler at '_tcp_fsm_syn_sent' line ~2024 calls "
                "'_transmit_packet' without bootstrapping "
                "'_rcv_nxt' from peer's SYN, so the default "
                "'ack = self._rcv_nxt = 0' is used. Peer's TCP "
                "rejects our SYN+ACK as not acknowledging their "
                "SYN, and the connection never establishes."
            ),
        )

        # The SYN+ACK should reuse our original SYN's seq
        # (LOCAL__ISS), not advance past it. RFC 9293 §3.5.1:
        # the simultaneous-open SYN+ACK is functionally a
        # retransmit of our original SYN with peer's ACK
        # piggybacked.
        self.assertEqual(
            syn_ack_probe.seq,
            LOCAL__ISS,
            msg=(
                "The SYN+ACK MUST carry 'seq = LOCAL__ISS' (= "
                "the same seq as our original SYN); the "
                "SYN+ACK is RFC 9293 §3.5.1's 'reuse of our "
                "SYN seq with peer's ACK piggybacked'. Today "
                "the SYN+ACK uses 'seq = LOCAL__ISS + 1' (the "
                "post-original-SYN advance of SND.NXT)."
            ),
        )

        # Bootstrapped peer-side state.
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1,
            msg=(
                "'_rcv_nxt' MUST be advanced past peer's SYN "
                "seq before the SYN+ACK is emitted - mirroring "
                "the listener-fork bootstrap pattern."
            ),
        )
        self.assertEqual(
            session._rcv_ini,
            PEER__ISS,
            msg="'_rcv_ini' MUST record peer's ISN for downstream consistency.",
        )
        self.assertEqual(
            session._snd_mss,
            PEER__MSS,
            msg=("'_snd_mss' MUST be clamped to peer's MSS " "advertisement (RFC 6691)."),
        )
        self.assertEqual(
            session._snd_wnd,
            PEER__WIN,
            msg="'_snd_wnd' MUST be initialised from peer's advertised window.",
        )
        self.assertTrue(
            session._peer_contacted,
            msg=(
                "'_peer_contacted' MUST be set to True once peer's "
                "first segment has been processed - same flag "
                "introduced in commit 'e5e12dc' for the R2-abort "
                "RST emission gate."
            ),
        )

        # State transition.
        self.assertIs(
            session.state,
            FsmState.SYN_RCVD,
            msg="State must transition to SYN_RCVD per RFC 9293 §3.10.7.3.",
        )

    def test__active_open__simultaneous_open_completes_to_established_without_parent_socket(self) -> None:
        """
        Ensure the simultaneous-open path completes the three-way
        handshake to ESTABLISHED when peer's third-leg ACK
        arrives, releasing the connect-event semaphore so the
        blocked active-open caller unblocks. The session has NO
        parent socket (it was created via 'TcpSocket(family=...)'
        directly, not via the listener-fork pattern), so the
        SYN_RCVD ACK-only handler MUST NOT assert
        '_parent_socket is not None'.

        RFC 9293 §3.5.1 Figure 8 (Simultaneous Connection
        Synchronization):

            "TCP A                                            TCP B
             1.  CLOSED                                       CLOSED
             2.  SYN-SENT  --> <SEQ=100><CTL=SYN>             ...
             3.  SYN-RECEIVED <-- <SEQ=300><CTL=SYN>          <-- SYN-SENT
             ...
             5.  ESTABLISHED <-- <SEQ=300><ACK=101><CTL=SYN,ACK> <-- SYN-RECEIVED
             ..."

        Step 5 (peer's third leg) is what this test drives. The
        FSM must transition to ESTABLISHED and unblock the
        active-open CONNECT caller.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_syn_rcvd' lines
        ~2148-2158 unconditionally fetch and assert the
        parent socket:

            self._change_state(FsmState.ESTABLISHED)
            parent_socket = self._socket._parent_socket
            assert parent_socket is not None, "child TcpSocket must always have a parent_socket set"
            parent_socket._tcp_accept.append(self._socket)
            parent_socket._event__tcp_session_established.release()
            self._event__connect.release()
            return

        For active-open simultaneous-open the socket has no
        parent ('_parent_socket = None' set in
        'TcpSocket.__init__'); the assert fires and the test
        crashes with an 'AssertionError'. This bug was hidden
        before commit '9ecdd42' (Bug C fix) because the
        simultaneous-open SYN+ACK we previously emitted carried
        'ack=0' (the uninitialised '_rcv_nxt' default), peer's
        TCP rejected it, and the third-leg ACK never arrived -
        so this code path was unreachable. Closing Bug C made
        the path reachable in this new way.

        Severity: HIGH for simultaneous-open scenarios. The path
        was 'silently broken' before; now it 'crashes with
        AssertionError'. Either way the active-open caller
        cannot complete a simultaneous-open handshake.

        The comment immediately AFTER the assert
        ("'_event__connect.release()': this is needed only in
        case of tcp simultaneous open") acknowledges that
        simultaneous open exists, but the assert above
        contradicts that awareness - the parent_socket lookup
        is unconditional even though the comment knows
        simultaneous open won't have one.

        Fix outline (separate commit):

            Gate the parent-socket plumbing on its presence:

                self._change_state(FsmState.ESTABLISHED)
                parent_socket = self._socket._parent_socket
                if parent_socket is not None:
                    parent_socket._tcp_accept.append(self._socket)
                    parent_socket._event__tcp_session_established.release()
                self._event__connect.release()
                return

            Active-open simultaneous-open has no parent socket
            but DOES need the connect-event release; passive-
            open listener-fork has both. The 'if not None'
            gate handles both paths uniformly.

        Scenario:

            1. Build active-open session with LOCAL__ISS.
               Issue CONNECT. Tick once to emit SYN. State
               = SYN_SENT.
            2. Peer sends bare SYN (simultaneous-open
               trigger). Post-Bug-C-fix the handler
               bootstraps peer state, emits SYN+ACK, and
               transitions to SYN_RCVD.
            3. Peer sends third-leg ACK (acks our SYN+ACK).
               Drive RX.

        Assertions:

            * Driving the third-leg ACK must NOT raise
              (today: AssertionError fires).
            * State is ESTABLISHED.
            * 'session._event__connect.acquire(timeout=0)'
              returns True (semaphore released, blocked
              CONNECT would unblock).
            * '_socket._parent_socket' is None (sanity check
              of the precondition that distinguishes active-
              from passive-open).
        """

        # Step 1: drive active-open to SYN_SENT and emit SYN.
        session = self._make_active_session(iss=LOCAL__ISS)
        # Sanity precondition: the socket has no parent. This is
        # what makes the simultaneous-open path different from
        # the listener-fork path.
        self.assertIsNone(
            session._socket._parent_socket,
            msg=(
                "Setup precondition: an active-open socket has "
                "no parent (it was created directly via "
                "'TcpSocket(family=...)' rather than via the "
                "listener-fork pattern in '_tcp_fsm_listen')."
            ),
        )
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )

        # Step 2: peer sends bare SYN (simultaneous open). This
        # transitions us to SYN_RCVD and emits SYN+ACK. Already
        # tested by 'test__active_open__simultaneous_open_bootstraps_peer_state_from_bare_syn';
        # we just drive past it here.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)
        self.assertIs(
            session.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: peer's bare SYN must transition session to SYN_RCVD.",
        )

        # Step 3: peer sends third-leg ACK to our SYN+ACK.
        # Today this raises AssertionError on the
        # 'parent_socket is not None' assert; post-fix it
        # transitions cleanly to ESTABLISHED.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,  # == _rcv_nxt
            ack=LOCAL__ISS + 1,  # == _snd_nxt (post-SYN+ACK at _snd_ini)
            flags=("ACK",),
            win=PEER__WIN,
        )
        # The drive itself MUST NOT raise. Wrap in 'try' so the
        # test failure carries a specific message rather than
        # an opaque traceback if the AssertionError propagates.
        try:
            self._drive_rx(frame=peer_ack)
        except AssertionError as exc:
            self.fail(
                "Driving peer's third-leg ACK in simultaneous-open "
                "SYN_RCVD raised 'AssertionError' from the production "
                "code's 'assert parent_socket is not None' at "
                f"'_tcp_fsm_syn_rcvd' line ~2153: {exc}. The active-"
                "open simultaneous-open path has no parent socket; "
                "the SYN_RCVD ACK-only handler must gate the parent-"
                "socket plumbing on 'parent_socket is not None' so "
                "it skips it cleanly for the active-open path while "
                "preserving it for passive-open."
            )

        # Spec: state transitions to ESTABLISHED.
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "After peer's third-leg ACK in simultaneous-open "
                "SYN_RCVD, state MUST transition to ESTABLISHED "
                "per RFC 9293 §3.5.1 figure 8 step 5."
            ),
        )
        # Spec: connect-event semaphore released.
        self.assertTrue(
            session._event__connect.acquire(timeout=0),
            msg=(
                "On simultaneous-open completion, "
                "'_event__connect' MUST be released so the "
                "blocked active-open CONNECT caller unblocks."
            ),
        )

    def test__active_open__close_in_syn_sent_unblocks_connect_with_canceled(self) -> None:
        """
        Ensure that 'close()' issued mid-handshake from SYN_SENT
        releases the connect-event semaphore with the dedicated
        'ConnError.CANCELED' signal, so a blocked
        'TcpSession.connect()' caller (typically a different
        thread) unblocks with
        'TcpSessionError("Connection canceled")' rather than
        hanging forever on the dead session.

        RFC 9293 §3.10.4 (CLOSE call) governs the close-during-
        connect transition. PyTCP's SYN_SENT close handler
        moves state to CLOSED but does not signal the blocked
        connect caller; without an explicit unblock the calling
        thread sits on '_event__connect.acquire()' until the
        application is killed.

        Threat model: a multi-threaded application with one
        thread blocked on 'connect()' and another that calls
        'close()' (e.g. shutdown initiated from a control
        plane) hangs the connect thread. PyTCP doesn't ship a
        wrapper that triggers this today, but downstream users
        wrapping the session in 'asyncio' / 'concurrent.futures'
        could trip the race.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_syn_sent's CLOSE
        syscall handler (line ~2049):

            if syscall is SysCall.CLOSE:
                self._change_state(FsmState.CLOSED)
                return

        … doesn't set '_connection_error' and doesn't release
        '_event__connect'. The session is unregistered from
        'stack.sockets' but the connect-blocked thread is left
        hanging.

        Severity: LOW (rare race - requires multi-threaded
        app to exhibit) but real correctness gap.

        Fix outline (separate commit):

          - Add 'ConnError.CANCELED' enum value (semantically
            distinct from REFUSED 'peer-side rejection' and
            TIMEOUT 'R2 expired').
          - Add a corresponding branch in 'TcpSession.connect()'
            so the canceled-error raises
            'TcpSessionError("Connection canceled")'.
          - SYN_SENT close handler: set
            '_connection_error = ConnError.CANCELED', call
            '_event__connect.release()', then transition to
            CLOSED.

        Scenario:

            1. Build active-open session with LOCAL__ISS.
               Issue CONNECT. Tick once to emit SYN. State =
               SYN_SENT. '_event__connect' is NOT yet
               released.
            2. Issue CLOSE syscall while still in SYN_SENT.

        Assertions:

            * State is CLOSED.
            * 'session._connection_error is ConnError.CANCELED'.
            * 'session._event__connect.acquire(timeout=0)' is
              True.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="Setup precondition: state must be SYN_SENT.",
        )
        self.assertFalse(
            session._event__connect.acquire(timeout=0),
            msg=(
                "Setup precondition: connect-event semaphore must "
                "not be released while the handshake is in progress."
            ),
        )

        # Issue CLOSE syscall while in SYN_SENT (simulating a
        # different thread calling 'session.close()' while the
        # connect-thread is blocked on '_event__connect').
        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg=("CLOSE in SYN_SENT must transition to CLOSED per " "RFC 9293 §3.10.4."),
        )
        self.assertIs(
            session._connection_error,
            ConnError.CANCELED,
            msg=(
                "CLOSE in SYN_SENT MUST record "
                "'ConnError.CANCELED' so the blocked CONNECT "
                "caller raises "
                "'TcpSessionError(\"Connection canceled\")' on "
                "unblock. Today the SYN_SENT CLOSE handler only "
                "calls '_change_state(CLOSED)' without setting "
                "'_connection_error'."
            ),
        )
        self.assertTrue(
            session._event__connect.acquire(timeout=0),
            msg=(
                "On CLOSE in SYN_SENT, '_event__connect' MUST be "
                "released so the blocked CONNECT caller unblocks. "
                "Today the SYN_SENT CLOSE handler doesn't release "
                "the semaphore; multi-threaded apps that close a "
                "connecting session deadlock the connect thread."
            ),
        )

    def test__active_open__close_in_syn_rcvd_unblocks_connect_with_canceled(self) -> None:
        """
        Ensure that 'close()' issued mid-handshake from
        SYN_RCVD (reached via simultaneous open) releases the
        connect-event semaphore with 'ConnError.CANCELED' so a
        blocked CONNECT caller unblocks. Same gap class as the
        SYN_SENT sibling above.

        SYN_RCVD's CLOSE handler currently transitions to
        FIN_WAIT_1 to drive the post-half-close FIN exchange,
        but doesn't signal the blocked CONNECT caller. The
        eventual transition to CLOSED via the FIN exchange
        also doesn't release '_event__connect' (none of the
        FIN_WAIT_1 / FIN_WAIT_2 / TIME_WAIT handlers do), so
        the CONNECT caller remains blocked through the entire
        graceful-close lifecycle.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_syn_rcvd's CLOSE
        syscall handler (line ~2207):

            if syscall is SysCall.CLOSE:
                self._change_state(FsmState.FIN_WAIT_1)
                return

        … doesn't set '_connection_error' or release
        '_event__connect'.

        Fix outline: same shape as SYN_SENT's CLOSE handler
        fix - set 'CANCELED', release semaphore, then
        transition.

        Scenario:

            1. Drive active-open to SYN_SENT, emit SYN.
            2. Peer's bare SYN crosses ours -> SYN_RCVD
               (simultaneous open).
            3. Issue CLOSE while in SYN_RCVD.

        Assertions:

            * State is FIN_WAIT_1.
            * 'session._connection_error is
              ConnError.CANCELED'.
            * 'session._event__connect.acquire(timeout=0)' is
              True.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        # Drive SYN_SENT -> SYN_RCVD via peer's bare SYN
        # (simultaneous-open trigger).
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)
        self.assertIs(
            session.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: state must be SYN_RCVD.",
        )

        # Issue CLOSE syscall while in SYN_RCVD.
        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg=(
                "CLOSE in SYN_RCVD must transition to FIN_WAIT_1 "
                "per RFC 9293 §3.10.4 (so the FIN exchange can "
                "drive the post-half-close cleanup)."
            ),
        )
        self.assertIs(
            session._connection_error,
            ConnError.CANCELED,
            msg=(
                "CLOSE in SYN_RCVD MUST record "
                "'ConnError.CANCELED' so the blocked CONNECT "
                "caller raises "
                "'TcpSessionError(\"Connection canceled\")' on "
                "unblock."
            ),
        )
        self.assertTrue(
            session._event__connect.acquire(timeout=0),
            msg=(
                "On CLOSE in SYN_RCVD, '_event__connect' MUST be "
                "released so the blocked CONNECT caller unblocks. "
                "Today the handler only changes state to FIN_WAIT_1 "
                "without releasing the semaphore; the eventual "
                "CLOSED transition (via the FIN exchange) also "
                "doesn't release it, so the CONNECT caller is "
                "stuck for the entire graceful-close lifecycle."
            ),
        )
