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
This module contains integration tests for the TCP passive-open
('listen' / 'accept') side of the 'TcpSession' state machine,
covering the server role of the three-way handshake defined in
RFC 9293 §3.10.7.2.

The tests in this file drive the LISTEN-side FSM directly via
'tcp_fsm(syscall=SysCall.LISTEN)' rather than going through the
blocking 'TcpSocket.accept()' BSD-API wrapper - the integration
scope is the session, not the socket facade. The full RX/TX path
is exercised end to end: outbound segments flow through the real
'PacketHandler._phtx_tcp -> _phtx_ip4 -> _phtx_ethernet' chain and
land in the mocked 'TxRing'; inbound segments are fed into the real
'_phrx_ethernet' entry point and dispatched to the listening socket
via the real 'TcpSocket.process_tcp_packet'.

A passive-open session has a more complex life cycle than the active-
open path: the original listening 'TcpSession' mutates IN PLACE into
a child session bound to the incoming peer's 4-tuple, and a fresh
'TcpSession' is created to take over the wildcarded LISTEN role
(see '_tcp_fsm_listen' for the in-place transformation). Tests in
this file therefore assert against both objects: the listening
socket / its NEW session ('still in LISTEN, ready for the next
SYN'), and the newly-spawned child socket / the OLD-now-child
session ('transitioned to SYN_RCVD, ready to emit SYN+ACK').

Reference RFCs:
    RFC 9293 §3.10.7.2   Passive open / LISTEN state processing
    RFC 9293 §3.5.1      Three-way handshake
    RFC 9293 §3.7.1      MSS option / segment-size negotiation
    RFC 6691 §2          MSS calculation from link MTU
    RFC 5961 §4          SYN-on-established challenge ACK

pytcp/tests/integration/protocols/tcp/test__tcp__session__handshake__passive.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.tcp__session import FsmState, SysCall, TcpSession
from pytcp.socket import AddressFamily, SocketType
from pytcp.socket.socket_id import SocketId
from pytcp.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_session_testcase import TcpSessionTestCase

# Deterministic addressing chosen so log output and byte-frame comments
# stay readable. STACK is the host running the SUT (the listener);
# PEER is the 'HOST_A' fixture that has a working ARP entry.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
LISTEN__PORT: int = 80
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 33000

# Initial sequence numbers chosen well clear of the 32-bit wrap so
# this baseline file exercises ordinary modular comparisons; the
# wraparound corner is covered separately in the seq_wraparound file.
LOCAL__ISS: int = 0x0000_3000
PEER__ISS: int = 0x0000_4000

# Peer's advertised receive window on the SYN it sends.
PEER__WIN: int = 64240

# Peer's MSS option value on the SYN. 1460 is the canonical IPv4
# Ethernet MSS (1500 MTU - 20 byte IPv4 header - 20 byte TCP header).
PEER__MSS: int = 1460


class TestTcpPassiveOpen__Handshake(TcpSessionTestCase):
    """
    Integration tests for the server-side three-way handshake driven
    out of 'TcpSession' in the passive-open path.
    """

    def _make_listen_session(self, *, iss: int) -> tuple[TcpSocket, TcpSession]:
        """
        Build a 'TcpSocket' / 'TcpSession' pair wired up the way
        'TcpSocket.listen()' would wire them - bound to the wildcard
        listen 4-tuple '(STACK__IP, LISTEN__PORT, *, 0)', ISS pinned
        deterministically via '_force_iss', socket registered in
        'stack.sockets' so the packet handler's RX listener-match
        dispatch finds it on the second pass.

        Returns '(listen_socket, listen_session)'. After
        '_tcp_fsm_listen' processes an incoming SYN, the *session*
        attached to the socket will be replaced (the original session
        mutates in place into the child); callers should re-resolve
        the listening session via 'listen_socket._tcp_session' after
        any RX drive.
        """

        self._force_iss(iss)

        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = LISTEN__PORT
        sock._remote_ip_address = Ip4Address()
        sock._remote_port = 0

        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=LISTEN__PORT,
            remote_ip_address=Ip4Address(),
            remote_port=0,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock

        # Drive LISTEN syscall: state CLOSED -> LISTEN.
        session.tcp_fsm(syscall=SysCall.LISTEN)

        return sock, session

    def _child_socket_id(self) -> SocketId:
        """
        Construct the exact-match 'SocketId' the packet handler
        computes for an inbound segment from PEER to STACK on the
        listening port. After the handshake spawns a child socket
        this id is what 'stack.sockets' will key the child by.
        """

        return SocketId(
            address_family=AddressFamily.INET4,
            socket_type=SocketType.STREAM,
            local_address=STACK__IP,
            local_port=LISTEN__PORT,
            remote_address=PEER__IP,
            remote_port=PEER__PORT,
        )

    def test__passive_open__syn_to_listen_spawns_child_and_emits_syn_ack(self) -> None:
        """
        Ensure that when a fresh SYN arrives at a listening socket,
        the LISTEN-state FSM emits a SYN+ACK whose fields match the
        contract RFC 9293 §3.10.7.2 prescribes for the second leg of
        the three-way handshake, while the listening socket itself
        remains available to accept further connections.

        Stages observed:

            1. LISTEN-state session exists, registered in
               'stack.sockets' under the wildcard socket-id pattern
               '(STACK__IP, LISTEN__PORT, <unspecified>, 0)'.

            2. Peer's SYN arrives. The packet handler's RX dispatch
               does not find an exact-match socket, falls back to the
               listening-socket-id patterns derived from the segment's
               4-tuple, finds our wildcard registration, and routes
               the segment to '_tcp_fsm_listen'.

            3. '_tcp_fsm_listen' transforms the listening session
               in place: its addressing is rewritten to the peer's
               4-tuple, a NEW 'TcpSocket' is created bound to that
               peer-specific tuple and registered in 'stack.sockets',
               and the old listening socket gets a fresh 'TcpSession'
               grafted on so it can keep accepting further
               connections. The mutated (now-child) session
               transitions to SYN_RCVD. No segment is emitted from
               '_tcp_fsm_listen' itself - the SYN+ACK is gated on
               the next timer tick via '_transmit_data'.

            4. On the first virtual-clock tick, the child session's
               SYN_RCVD timer handler runs '_transmit_data', which
               detects 'snd_nxt == snd_ini' and emits the SYN+ACK
               with our ISS, ack = peer.SEQ+1, our advertised MSS
               option, and our advertised receive window.

        Expected SYN+ACK fields per RFC 9293 §3.5.1 / §3.10.7.2:

            seq     = LOCAL__ISS               (our ISS)
            ack     = PEER__ISS + 1            (consumes peer's SYN's
                                                one byte of seq space)
            flags   = {SYN, ACK}
            mss     = 1460                     (RFC 6691 §2 -
                                                MTU(1500) - IPv4(20) -
                                                TCP(20))
            wscale  = None                     (we do not advertise
                                                WSCALE - matching the
                                                active-open behaviour
                                                pinned in the active
                                                handshake test)
            win     = 65535
            payload = b""

        Side effects asserted:

            * The original listening socket remains in 'stack.sockets'
              under its wildcard id, with a fresh session attached
              that is back in LISTEN state.
            * A second registration appears in 'stack.sockets' under
              the peer-specific exact-match id; its session is the
              OLD-now-child session, currently in SYN_RCVD.
            * The child session's '_rcv_nxt' equals 'PEER__ISS + 1'
              (peer's SYN consumed one byte of sequence space).
            * The child session's '_snd_ini' / '_snd_nxt' equal our
              forced 'LOCAL__ISS' before the SYN+ACK is sent, and
              advance to 'LOCAL__ISS + 1' after the SYN+ACK consumes
              our SYN's one byte.
            * The child socket's '_parent_socket' points at the
              original listening socket so the eventual ACK can
              find the accept queue.
        """

        listen_socket, original_session = self._make_listen_session(iss=LOCAL__ISS)

        self.assertIs(
            original_session.state,
            FsmState.LISTEN,
            msg="Setup precondition: listening session must be in LISTEN.",
        )

        # Peer sends a SYN to (STACK__IP, LISTEN__PORT). Build the frame
        # with the peer-specific 4-tuple and the customary handshake
        # options.
        syn_frame = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )

        tx_frames = self._drive_rx(frame=syn_frame)

        self.assertEqual(
            tx_frames,
            [],
            msg=(
                "'_tcp_fsm_listen' must not emit any segment inline - "
                "the SYN+ACK is gated on the next timer tick by the "
                "SYN_RCVD '_transmit_data' branch (matches the same "
                "tick-gated pattern as the active-open initial SYN)."
            ),
        )

        # The listening socket has a fresh session in LISTEN now,
        # while the original session has mutated into the child bound
        # to the peer's 4-tuple and is sitting in SYN_RCVD.
        self.assertIn(
            listen_socket.socket_id,
            stack.sockets,
            msg=(
                "The listening socket must remain registered in "
                "'stack.sockets' under its wildcard id so subsequent "
                "SYNs from other peers also reach the listener."
            ),
        )
        self.assertIs(
            stack.sockets[listen_socket.socket_id],
            listen_socket,
            msg="The listening-socket registration must point at the same TcpSocket object.",
        )

        new_listen_session = listen_socket._tcp_session
        self.assertIsNotNone(
            new_listen_session,
            msg="The listening socket must have a fresh session attached after spawning the child.",
        )
        assert new_listen_session is not None  # narrow for mypy
        self.assertIs(
            new_listen_session.state,
            FsmState.LISTEN,
            msg=(
                "After spawning a child, the listening socket's "
                "session must be back in LISTEN state, ready to "
                "accept further inbound SYNs."
            ),
        )
        self.assertIsNot(
            new_listen_session,
            original_session,
            msg=(
                "'_tcp_fsm_listen' must replace the listening session - "
                "the original session has been mutated into the child "
                "bound to the peer's 4-tuple."
            ),
        )

        # The child socket / child session lives under the peer-
        # specific exact-match id.
        child_socket_id = self._child_socket_id()
        self.assertIn(
            child_socket_id,
            stack.sockets,
            msg=(
                "A new child socket bound to the peer's 4-tuple must "
                "be registered in 'stack.sockets' so subsequent "
                "segments from the same peer reach this child rather "
                "than the listener."
            ),
        )
        child_socket = stack.sockets[child_socket_id]
        assert isinstance(child_socket, TcpSocket)
        self.assertIs(
            child_socket._parent_socket,
            listen_socket,
            msg=(
                "The child socket's '_parent_socket' must point at the "
                "original listening socket so the eventual third-leg "
                "ACK can deposit the accepted child onto the listener's "
                "accept queue."
            ),
        )

        child_session = child_socket._tcp_session
        assert child_session is not None
        self.assertIs(
            child_session,
            original_session,
            msg=(
                "The child session must BE the originally returned "
                "session object (mutated in place) - this is how "
                "'_tcp_fsm_listen' implements the LISTEN -> SYN_RCVD "
                "transformation."
            ),
        )
        self.assertIs(
            child_session.state,
            FsmState.SYN_RCVD,
            msg=(
                "After processing the inbound SYN, the child session "
                "must be in SYN_RCVD per RFC 9293 §3.10.7.2, awaiting "
                "the peer's third-leg ACK."
            ),
        )
        self.assertEqual(
            child_session._snd_ini,
            LOCAL__ISS,
            msg=(
                "The child session must inherit the deterministic ISS "
                "we forced via '_force_iss', so the SYN+ACK on the wire "
                "is reproducible."
            ),
        )
        self.assertEqual(
            child_session._snd_nxt,
            LOCAL__ISS,
            msg=(
                "Before the SYN+ACK fires on the next timer tick, "
                "'_snd_nxt' must equal '_snd_ini' - the SYN's one byte "
                "of sequence space is consumed only when the segment "
                "is actually transmitted."
            ),
        )
        self.assertEqual(
            child_session._rcv_nxt,
            PEER__ISS + 1,
            msg=(
                "After processing the peer's SYN, '_rcv_nxt' must equal "
                "PEER__ISS + 1 - consuming the SYN's one byte of "
                "sequence space (RFC 9293 §3.4)."
            ),
        )

        # On the first virtual-clock tick, the child session's SYN_RCVD
        # timer handler emits the SYN+ACK.
        tick_tx = self._advance(ms=1)
        self.assertEqual(
            len(tick_tx),
            1,
            msg=("Exactly one TX frame (the SYN+ACK) must be emitted on " "the first SYN_RCVD timer tick."),
        )

        syn_ack = self._parse_tx(tick_tx[0])
        self._assert_segment(
            syn_ack,
            flags=frozenset({"SYN", "ACK"}),
            sport=LISTEN__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS,
            ack=PEER__ISS + 1,
            payload=b"",
            mss=1460,
            wscale=None,
            win=65535,
        )

        self.assertEqual(
            child_session._snd_nxt,
            LOCAL__ISS + 1,
            msg=(
                "After the SYN+ACK is transmitted, '_snd_nxt' must "
                "advance by one to consume the SYN's sequence space "
                "(RFC 9293 §3.4)."
            ),
        )
        self.assertIs(
            child_session.state,
            FsmState.SYN_RCVD,
            msg=(
                "Sending the SYN+ACK does not move us out of SYN_RCVD; "
                "we wait for the peer's third-leg ACK before "
                "transitioning to ESTABLISHED."
            ),
        )

    def test__passive_open__syn_ack_to_listen_emits_rst(self) -> None:
        """
        Ensure that a SYN+ACK arriving on a listening socket triggers
        '<SEQ=SEG.ACK><CTL=RST>' per RFC 9293 §3.10.7.2 step 2 ("Any
        acknowledgment is bad if it arrives on a connection still in
        the LISTEN state. An acceptable reset segment should be
        formed for any arriving ACK-bearing segment").

        The LISTEN state accepts ONLY a bare SYN as the start of a
        new connection. Any segment that already carries the ACK bit
        - SYN+ACK, bare ACK, FIN+ACK, RST+ACK - cannot legally
        belong to a connection that is still in LISTEN, because no
        SEQ has yet been allocated by the listener for the peer to
        acknowledge. The spec's response is the canonical
        <SEQ=SEG.ACK><CTL=RST> reset, mirroring the SYN_SENT step-1
        rejection of unacceptable ACKs but with stricter scope: in
        LISTEN, ALL ACK-bearing segments are rejected, not just those
        with out-of-window ACK numbers, because the listener has no
        valid window to compare against.

        Wire shape of the rogue SYN+ACK we feed:

            sport = PEER__PORT
            dport = LISTEN__PORT
            seq   = PEER__ISS
            ack   = 0x0000_CAFE   (arbitrary value chosen to be
                                   visually distinct from any session
                                   state we might leak)
            flags = {SYN, ACK}

        Required outbound RST shape (RFC 9293 §3.10.7.2 step 2
        verbatim):

            seq     = SEG.ACK = 0xCAFE
            ack     = 0
            flags   = {RST}                 (bare RST; the ACK flag is
                                             NOT set on the response,
                                             matching the spec form)
            payload = b""

        Side effects asserted:

            * 'listen_socket' is still registered in 'stack.sockets'
              under its wildcard id.
            * 'listen_socket._tcp_session.state is FsmState.LISTEN' -
              the listener has not been disturbed; the next legitimate
              SYN can still proceed normally.
            * The listening session object is the same one we started
              with - no in-place mutation happened, no child was
              spawned (those side effects only follow a legal bare
              SYN).
            * No new entry appears in 'stack.sockets' under the
              peer-specific exact-match id.

        [FLAGS BUG] - RFC 9293 §3.10.7.1 / §3.10.7.2 deviation
        ----------------------------------------------------------
        Two cooperating bugs make this scenario fail:

          (a) 'PacketHandlerTcpRx._phrx_tcp' gates its listener-match
              dispatch on 'flag_syn AND NOT any{ack, fin, rst}', so
              the SYN+ACK never reaches '_tcp_fsm_listen' at all -
              it falls through to the "no socket match" RST emitter
              instead.

          (b) The "no socket match" RST emitter unconditionally sends
              <CTL=RST,ACK><SEQ=0><ACK=SEG.SEQ+1>. That is the right
              form for an ACK-LESS offending segment per RFC 9293
              §3.10.7.1 ("If the ACK bit is off, <SEQ=0><ACK=...>
              <CTL=RST,ACK>"), but for an ACK-BEARING offending
              segment the spec mandates the bare-RST form
              <CTL=RST><SEQ=SEG.ACK> ("If the ACK bit is on,
              <SEQ=SEG.ACK><CTL=RST>.").

        On current code this test therefore observes a RST+ACK with
        'seq=0, ack=PEER__ISS+1' instead of the spec's bare RST with
        'seq=0xCAFE'. The 'flags={RST}' assertion is what fires; the
        rest of the assertions (state stays LISTEN, no child spawned)
        already hold because the packet handler's no-match path is
        stateless from the listener's perspective.

        Two RFC-correct fix paths exist - either is acceptable:

          Fix A: Widen the listener-match logic to also route
                 ACK-bearing segments to the listener, then add a
                 step-2 branch in '_tcp_fsm_listen' that emits the
                 bare-RST response.

          Fix B: Make 'PacketHandlerTcpRx._phrx_tcp' discriminate the
                 RST shape based on whether the offending segment
                 carried the ACK bit, so the no-socket-match path
                 emits the spec form for both cases.

        Fix B is more localized; Fix A keeps the FSM responsible for
        its own state transitions. Either way the wire behaviour
        encoded by this test is the contract that has to hold.
        """

        listen_socket, listen_session = self._make_listen_session(iss=LOCAL__ISS)
        bogus_ack_value = 0x0000_CAFE

        rogue_frame = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=bogus_ack_value,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )

        tx_frames = self._drive_rx(frame=rogue_frame)

        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "An ACK-bearing segment arriving on a listening socket "
                "must elicit exactly one outbound segment (a bare RST) "
                "per RFC 9293 §3.10.7.2 step 2. Got "
                f"{len(tx_frames)} TX frames."
            ),
        )

        rst = self._parse_tx(tx_frames[0])
        self._assert_segment(
            rst,
            flags=frozenset({"RST"}),
            sport=LISTEN__PORT,
            dport=PEER__PORT,
            seq=bogus_ack_value,
            ack=0,
            payload=b"",
            mss=None,
            wscale=None,
        )

        self.assertIn(
            listen_socket.socket_id,
            stack.sockets,
            msg=(
                "The listening socket must remain registered after "
                "rejecting a rogue SYN+ACK - the listener is not "
                "disturbed by spurious ACK-bearing traffic."
            ),
        )
        self.assertIs(
            stack.sockets[listen_socket.socket_id],
            listen_socket,
            msg=(
                "The listening socket registration must still point at "
                "the same TcpSocket object - no replacement happened."
            ),
        )
        self.assertIs(
            listen_socket._tcp_session,
            listen_session,
            msg=(
                "The listening socket's session must be the same "
                "object we started with - rejecting a rogue ACK does "
                "not spawn a child or replace the listener (those side "
                "effects only follow a legal bare SYN)."
            ),
        )
        self.assertIs(
            listen_session.state,
            FsmState.LISTEN,
            msg=(
                "Rejecting a rogue ACK-bearing segment must not change "
                "the listener's state - it stays in LISTEN, ready for "
                "the next legitimate SYN."
            ),
        )

        # No child socket should have been registered under the
        # peer-specific exact-match id.
        self.assertNotIn(
            self._child_socket_id(),
            stack.sockets,
            msg=(
                "No child socket may be registered after rejecting a "
                "rogue ACK-bearing segment - the rejection happens "
                "before any session-spawning code runs."
            ),
        )

    def test__passive_open__syn_with_payload_to_listen_queues_data_and_acks_it(self) -> None:
        """
        Ensure that an initial SYN carrying piggybacked data is
        processed per RFC 9293 §3.10.7.2 step 3:

            "any other incoming control or data (combined with SYN)
             will be processed in the SYN-RECEIVED state, but
             processing of SYN and ACK should not be repeated."

        Concretely, the listener:

          - Accepts the SYN, transitioning the (mutated-in-place)
            child session to SYN_RCVD - the data must NOT cause the
            SYN to be rejected.
          - Queues the data so it is available to the application
            once the connection reaches ESTABLISHED. The simplest
            and canonical implementation is to enqueue into
            '_rx_buffer' immediately, since the existing 'receive()'
            syscall already gates eventual delivery via
            '_event__rx_buffer'.
          - Advances 'RCV.NXT' past both the SYN's one byte and
            every byte of payload, so the SYN+ACK we emit on the
            next timer tick acknowledges the data and the peer does
            not have to retransmit it.

        Wire shape of the SYN-with-data we feed:

            sport   = PEER__PORT
            dport   = LISTEN__PORT
            seq     = PEER__ISS
            ack     = 0
            flags   = {SYN}
            payload = b"hello-world!"   (12 bytes; arbitrary but
                                         non-trivial so the ack
                                         increment is unambiguous)

        Required outbound SYN+ACK shape (after the first virtual-
        clock tick):

            seq     = LOCAL__ISS
            ack     = PEER__ISS + 1 + len(payload)
                    = PEER__ISS + 1 + 12 = PEER__ISS + 13
            flags   = {SYN, ACK}
            mss     = 1460
            wscale  = None
            win     = 65535
            payload = b""

        Side effects asserted:

            * 'child_session._rcv_nxt' equals PEER__ISS + 1 + 12,
              reflecting that we have consumed the entire SYN-with-data
              segment from peer's sequence space.
            * 'child_session._rx_buffer' equals b"hello-world!", the
              data is queued for delivery once ESTABLISHED is reached.
            * Listening socket still accepts further connections (state
              stays LISTEN, registration intact).

        [FLAGS BUG] - RFC 9293 §3.10.7.2 step 3 deviation
        ----------------------------------------------------------
        '_tcp_fsm_listen' guards its SYN-handling branch with the
        inner sanity check
        'packet_rx_md.tcp__ack == 0 and not packet_rx_md.tcp__data'.
        With the data condition tightened to 'not data', any SYN
        carrying piggybacked payload bytes fails the sanity check,
        the branch body is skipped, and the function returns
        silently - no SYN+ACK, no state change, no data queued. The
        peer sees nothing, retransmits the SYN-with-data on its RTO,
        and the cycle repeats indefinitely until peer's R2 elapses
        and the connection times out.

        The RFC explicitly permits and requires processing such
        segments. Fixing this requires:

          (a) Dropping the 'not data' constraint from the sanity
              check, so the SYN itself is accepted regardless of
              piggybacked data.
          (b) Either eagerly enqueueing the data into '_rx_buffer'
              and advancing '_rcv_nxt' past both the SYN and the
              data, OR replaying the segment in the SYN_RCVD state
              after the LISTEN -> SYN_RCVD transition has been
              recorded.

        This test is expected to FAIL on current code with no TX
        frames produced (the listener silently drops); on a correct
        implementation it observes the SYN+ACK with the
        data-acknowledging ack value and the queued data in
        '_rx_buffer'.
        """

        listen_socket, _ = self._make_listen_session(iss=LOCAL__ISS)
        payload = b"hello-world!"

        syn_with_data = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            payload=payload,
        )

        # Driving the SYN-with-data must not produce any inline TX
        # (matching the bare-SYN case - SYN+ACK is gated on the next
        # timer tick by the SYN_RCVD '_transmit_data' branch).
        inline_tx = self._drive_rx(frame=syn_with_data)
        self.assertEqual(
            inline_tx,
            [],
            msg=(
                "'_tcp_fsm_listen' must not emit any segment inline "
                "even for SYN-with-data; the SYN+ACK fires on the "
                "next timer tick like the bare-SYN case."
            ),
        )

        # The child session is the original (mutated-in-place) listening
        # session, now bound to the peer's 4-tuple and in SYN_RCVD.
        child_socket = stack.sockets[self._child_socket_id()]
        assert isinstance(child_socket, TcpSocket)
        child_session = child_socket._tcp_session
        assert child_session is not None

        self.assertIs(
            child_session.state,
            FsmState.SYN_RCVD,
            msg=(
                "Receiving a SYN-with-data must still transition the "
                "child session to SYN_RCVD per RFC 9293 §3.10.7.2 "
                "step 3; data does not gate the SYN handling."
            ),
        )
        self.assertEqual(
            child_session._rcv_nxt,
            PEER__ISS + 1 + len(payload),
            msg=(
                "After processing a SYN-with-data, '_rcv_nxt' must "
                "advance past BOTH the SYN's one byte AND every byte "
                "of payload. Got "
                f"{child_session._rcv_nxt:#x}, expected "
                f"{PEER__ISS + 1 + len(payload):#x}. "
                'RFC 9293 §3.10.7.2 step 3: "any other incoming '
                "control or data (combined with SYN) will be "
                'processed in the SYN-RECEIVED state".'
            ),
        )
        self.assertEqual(
            bytes(child_session._rx_buffer),
            payload,
            msg=(
                "The piggybacked payload must be queued into the "
                "child session's '_rx_buffer' so it is available to "
                "the application once ESTABLISHED is reached, rather "
                "than forcing the peer to retransmit it after the "
                "handshake completes."
            ),
        )

        # On the next tick, the SYN+ACK fires acknowledging both SYN
        # and data.
        tick_tx = self._advance(ms=1)
        self.assertEqual(
            len(tick_tx),
            1,
            msg=(
                "Exactly one TX frame (the SYN+ACK) must be emitted "
                "on the first SYN_RCVD timer tick after a SYN-with-data."
            ),
        )

        syn_ack = self._parse_tx(tick_tx[0])
        self._assert_segment(
            syn_ack,
            flags=frozenset({"SYN", "ACK"}),
            sport=LISTEN__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS,
            ack=PEER__ISS + 1 + len(payload),
            payload=b"",
            mss=1460,
            wscale=None,
            # Advertised window reflects '_rx_buffer' occupancy per
            # RFC 9293 §3.8.6: 65535 max minus the SYN-piggybacked
            # bytes now sitting in the buffer awaiting ESTABLISHED
            # delivery to the application.
            win=65535 - len(payload),
        )

        # The listening socket still accepts further connections.
        self.assertIs(
            listen_socket._tcp_session.state,  # type: ignore[union-attr]
            FsmState.LISTEN,
            msg=("Processing a SYN-with-data must leave the listener " "available to accept further connections."),
        )

    def test__passive_open__third_leg_ack_with_payload_completes_handshake_and_delivers_data(self) -> None:
        """
        Ensure that the peer's third-leg ACK arriving in SYN_RCVD
        with piggybacked data completes the handshake AND queues the
        data per RFC 9293 §3.10.7.4 step 7.

        RFC 9293 §3.10.7.4 step 5 (SYN-RECEIVED, ACK processing on
        the third leg):

            "If SND.UNA < SEG.ACK =< SND.NXT, then enter ESTABLISHED
             state and continue processing with the variables below
             set to: ... [proceed to step 6, then step 7]"

        and step 7 (segment text processing, applies once ESTABLISHED
        is reached or while still in SYN-RECEIVED with data):

            "Once in the ESTABLISHED state, it is possible to deliver
             segment text to user RECEIVE buffers. Text from segments
             can be moved into buffers until either the buffer is
             full or the segment is empty. ... Send an acknowledgment
             of the form: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>."

        Concretely: peer's third-leg ACK with piggybacked data MUST
        transition us to ESTABLISHED, the data MUST be enqueued into
        '_rx_buffer' for the application's eventual 'recv()',
        'RCV.NXT' MUST advance past the data, and we MUST emit an
        ACK acknowledging the data. None of this requires special
        TFO-style negotiation - it is the canonical fast-start
        behaviour any peer is allowed to use.

        Wire shape of the third-leg ACK we feed:

            sport   = PEER__PORT
            dport   = LISTEN__PORT
            seq     = PEER__ISS + 1
            ack     = LOCAL__ISS + 1
            flags   = {ACK}
            payload = b"hello-from-peer"   (15 bytes)

        Required outbound ACK shape (after the segment is processed):

            seq     = LOCAL__ISS + 1
            ack     = PEER__ISS + 1 + 15      (consumes peer's data)
            flags   = {ACK}
            payload = b""

        Side effects asserted:

            * 'child_session.state' is FsmState.ESTABLISHED.
            * 'child_session._rx_buffer' equals the payload.
            * 'child_session._rcv_nxt' equals 'PEER__ISS + 1 + 15'.
            * Listening socket still in LISTEN.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_syn_rcvd' line ~2155-2158
        in the third-leg ACK branch:

            if (
                packet_rx_md.tcp__seq == self._rcv_nxt
                and packet_rx_md.tcp__ack == self._snd_nxt
                and not packet_rx_md.tcp__data
            ):
                self._process_ack_packet(packet_rx_md)
                self._change_state(FsmState.ESTABLISHED)
                ...

        The 'not packet_rx_md.tcp__data' sanity check rejects any
        third-leg ACK that carries a payload. The branch body is
        skipped, the function falls through every other branch
        (none of which match a bare ACK in SYN_RCVD), and returns
        silently. Effects:

          - State stays SYN_RCVD.
          - '_rx_buffer' stays empty.
          - 'RCV.NXT' is unchanged at 'PEER__ISS + 1' (still
            consuming only peer's SYN's seq byte).
          - No ACK is emitted.

        Peer keeps retransmitting their third-leg-ACK-with-data on
        their RTO; PyTCP keeps silently dropping. The connection
        eventually times out at peer's R2 (~100 s).

        Severity: MEDIUM. Affects every peer stack that piggybacks
        application data on the third-leg ACK as a fast-start
        optimisation. Modern HTTP/QUIC-aware kernels and embedded
        TCP stacks under load both do this. The same root-cause
        pattern affects '_tcp_fsm_syn_sent' line ~1945-1946 (the
        symmetric SYN+ACK-with-data case in the active-open path);
        a complete fix touches both branches.

        Fix outline (separate commit): drop the 'not data' guard
        from the sanity check, then enqueue any payload into
        '_rx_buffer' and advance 'RCV.NXT' past the data before
        the state transition fires. The shape mirrors the LISTEN-
        side fix already applied to '_tcp_fsm_listen' for the
        SYN-with-data case (see test
        'test__passive_open__syn_with_payload_to_listen_queues_data_and_acks_it').
        After enqueueing, emit a cumulative ACK so peer learns
        their data is received - without it peer would keep
        retransmitting until they noticed the cumulative-ACK from
        the next outbound segment, which may not happen soon if
        we have nothing to send.

        Scenario:

            1. Drive into SYN_RCVD via a bare SYN; tick to fire the
               SYN+ACK.
            2. Peer sends third-leg ACK with 15-byte payload at
               'seq = PEER__ISS + 1' (consumes our SYN+ACK's ack
               point), 'ack = LOCAL__ISS + 1' (acknowledges our SYN).
            3. Drive RX. The session MUST transition to ESTABLISHED
               and queue the data.

        On current code this test fails: the data-bearing third-leg
        ACK is silently dropped, state stays SYN_RCVD, '_rx_buffer'
        empty.
        """

        listen_socket, _ = self._make_listen_session(iss=LOCAL__ISS)

        # Stage 1: drive SYN -> child in SYN_RCVD; tick SYN+ACK out.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)
        self._advance(ms=1)  # SYN+ACK fires.

        child_socket = stack.sockets[self._child_socket_id()]
        assert isinstance(child_socket, TcpSocket)
        child_session = child_socket._tcp_session
        assert child_session is not None
        self.assertIs(
            child_session.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: child must be in SYN_RCVD after the SYN+ACK tick.",
        )
        # Clear the SYN+ACK from the TX log so the assertions below
        # only reflect the third-leg-ACK-with-data response.
        self._frames_tx.clear()

        # Stage 2: peer sends third-leg ACK with piggybacked data.
        payload = b"hello-from-peer"
        third_leg_with_data = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=payload,
        )
        tx_frames = self._drive_rx(frame=third_leg_with_data)

        # Stage 3: assert ESTABLISHED + data delivered.
        self.assertIs(
            child_session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Per RFC 9293 §3.10.7.4 step 5, a SYN_RCVD third-leg "
                "ACK whose 'ack' is in (SND.UNA, SND.NXT] MUST "
                "transition the session to ESTABLISHED, regardless "
                "of whether the segment also carries data. Today "
                "'_tcp_fsm_syn_rcvd' line ~2155-2158 gates on "
                "'not packet_rx_md.tcp__data', so a data-bearing "
                "third-leg ACK is silently dropped and the child "
                "session stays in SYN_RCVD. Fix: drop the 'not "
                "data' guard; enqueue the payload into '_rx_buffer' "
                "and advance 'RCV.NXT' past it before the state "
                f"transition fires. Got state: {child_session.state!r}."
            ),
        )
        self.assertEqual(
            bytes(child_session._rx_buffer),
            payload,
            msg=(
                "Per RFC 9293 §3.10.7.4 step 7, the data piggybacked "
                "on the third-leg ACK MUST be enqueued into the "
                "child session's '_rx_buffer' so the application can "
                f"receive it via 'recv()'. Got: "
                f"{bytes(child_session._rx_buffer)!r}, expected: "
                f"{payload!r}."
            ),
        )
        self.assertEqual(
            child_session._rcv_nxt,
            PEER__ISS + 1 + len(payload),
            msg=(
                "Per RFC 9293 §3.10.7.4 step 7 ('it advances RCV.NXT "
                "over the data accepted'), 'RCV.NXT' MUST advance "
                "past every byte of the third-leg ACK's payload. "
                f"Got: {child_session._rcv_nxt:#x}, expected: "
                f"{PEER__ISS + 1 + len(payload):#x}."
            ),
        )
        # The cumulative ACK acknowledging the data should fire on
        # this same drive (RFC 9293 §3.10.7.4 step 7: 'Send an
        # acknowledgment of the form: <SEQ=SND.NXT><ACK=RCV.NXT>
        # <CTL=ACK>'). Without it, peer keeps retransmitting their
        # data segment until our next outbound segment piggybacks
        # the cumulative ACK - which may take a while.
        self.assertGreaterEqual(
            len(tx_frames),
            1,
            msg=(
                "Per RFC 9293 §3.10.7.4 step 7, after enqueueing "
                "the third-leg ACK's payload the receiver MUST send "
                "an acknowledgment so peer learns the data is "
                "received. Without it peer's RTO fires and they "
                "needlessly retransmit. Today no outbound ACK is "
                "emitted because the data-bearing third-leg ACK is "
                f"silently dropped. Got {len(tx_frames)} TX frame(s)."
            ),
        )
        if tx_frames:
            cum_ack = self._parse_tx(tx_frames[-1])
            self.assertEqual(
                cum_ack.flags,
                frozenset({"ACK"}),
                msg=("The reply must be a bare ACK (no SYN / FIN / RST flags) per RFC 9293 §3.10.7.4 step 7."),
            )
            self.assertEqual(
                cum_ack.seq,
                LOCAL__ISS + 1,
                msg=("The reply's SEQ must equal SND.NXT after our SYN+ACK was sent (= LOCAL__ISS + 1)."),
            )
            self.assertEqual(
                cum_ack.ack,
                PEER__ISS + 1 + len(payload),
                msg=(
                    "The reply's ACK must acknowledge every byte of "
                    "peer's third-leg payload. Got: "
                    f"{cum_ack.ack:#x}, expected: "
                    f"{PEER__ISS + 1 + len(payload):#x}."
                ),
            )

        # The listening socket is unaffected.
        self.assertIs(
            listen_socket._tcp_session.state,  # type: ignore[union-attr]
            FsmState.LISTEN,
            msg=("Third-leg ACK on the child session must not disturb the listener."),
        )

    def test__passive_open__syn_without_mss_option_defaults_send_mss_to_536(self) -> None:
        """
        Ensure that when an inbound SYN omits the MSS option (a legal
        but uncommon shape - e.g. an old or minimal client), the
        listener falls back to the RFC 9293 §3.7.1 default IPv4 send
        MSS of 536 octets (= 576-byte default IPv4 MTU minus 20 byte
        IPv4 header minus 20 byte TCP header), per the spec's MUST-15:

            "If an MSS Option is not received at connection setup,
             TCP MUST assume a default send MSS of 536 (576-40) for
             IPv4 ..."

        This is a positive-control test for the absent-MSS fallback
        on the IPv4 path. The corresponding IPv6 default (1220 octets
        = 1280 minimum IPv6 MTU minus 40 byte IPv6 header minus 20
        byte TCP header) is exercised separately in the IPv6 file
        where the wrong-default bug currently lives.

        Wire shape of the inbound SYN we feed:

            sport   = PEER__PORT
            dport   = LISTEN__PORT
            seq     = PEER__ISS
            ack     = 0
            flags   = {SYN}
            mss     = (option not emitted at all)
            wscale  = (option not emitted at all)
            payload = b""

        Required outbound SYN+ACK shape and side effects:

            * SYN+ACK still carries OUR MSS option set to the
              MTU-derived value (1460 octets for the harness's
              1500 byte interface MTU). Peer's omission of MSS does
              not affect what we advertise; we always advertise our
              own receive-MSS based on our local MTU.
            * 'child_session._snd_mss' equals 536 - the spec default
              that governs every segment we will emit on this
              connection going forward, since the peer expressed no
              preference. Sending larger segments would risk
              fragmentation on legacy paths whose MTU is unknown.
            * 'child_session._rcv_mss' equals 1460 - what we would
              accept inbound, derived from our local MTU and used
              as the value advertised in our outbound SYN+ACK MSS
              option.

        This test passes on current code: the parser's
        'TcpOptionsProperties.mss' accessor returns the protocol-level
        default constant 'TCP__MIN_MSS = 536' when the option is
        absent, and '_tcp_fsm_listen' computes
        'min(packet_rx_md.tcp__mss, stack.interface_mtu - 40) =
        min(536, 1460) = 536', which is exactly the RFC-mandated
        fallback for IPv4. The test pins this contract so a future
        refactor that switched the parser to expose 'None' (or any
        other non-536 sentinel) for absent MSS would be caught
        immediately.
        """

        listen_socket, _ = self._make_listen_session(iss=LOCAL__ISS)

        syn_no_mss = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=None,  # explicitly omit MSS option from outbound TCP options
        )

        self._drive_rx(frame=syn_no_mss)

        # The child session is the (mutated-in-place) original session.
        child_socket = stack.sockets[self._child_socket_id()]
        assert isinstance(child_socket, TcpSocket)
        child_session = child_socket._tcp_session
        assert child_session is not None

        self.assertEqual(
            child_session._snd_mss,
            536,
            msg=(
                "When the peer's SYN omits the MSS option, "
                "'_snd_mss' must default to the RFC 9293 §3.7.1 "
                "IPv4 fallback of 536 octets (= 576 default MTU - 20 "
                "IPv4 hdr - 20 TCP hdr). Got "
                f"_snd_mss={child_session._snd_mss}."
            ),
        )
        self.assertEqual(
            child_session._rcv_mss,
            1460,
            msg=(
                "'_rcv_mss' is derived from our own MTU "
                "(stack.interface_mtu - 40 for IPv4) and is unaffected "
                "by what the peer advertises - it determines the value "
                "we send in our outbound MSS option."
            ),
        )

        # On the next tick, the SYN+ACK fires advertising OUR MSS
        # regardless of peer's omission.
        tick_tx = self._advance(ms=1)
        self.assertEqual(
            len(tick_tx),
            1,
            msg="Exactly one TX frame (the SYN+ACK) must be emitted on the first SYN_RCVD timer tick.",
        )

        syn_ack = self._parse_tx(tick_tx[0])
        self._assert_segment(
            syn_ack,
            flags=frozenset({"SYN", "ACK"}),
            sport=LISTEN__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS,
            ack=PEER__ISS + 1,
            payload=b"",
            mss=1460,  # our advertised MSS based on our MTU; absence on peer's SYN does not gate ours
            wscale=None,
            win=65535,
        )

        # Listener still accepts further connections.
        self.assertIs(
            listen_socket._tcp_session.state,  # type: ignore[union-attr]
            FsmState.LISTEN,
            msg=(
                "Processing a SYN without MSS option must leave the "
                "listener available to accept further connections."
            ),
        )

    def test__passive_open__concurrent_syns_from_distinct_peers_spawn_independent_children(self) -> None:
        """
        Ensure that a single listening socket can serve multiple
        simultaneous in-flight handshakes correctly: three SYNs from
        three distinct 4-tuples must spawn three independent child
        sessions, each in SYN_RCVD with its own '_rcv_nxt' tracking
        the corresponding peer's ISN, while the listening socket
        remains available throughout to accept further connections.

        Per RFC 9293 §3.10.7.2 the LISTEN-state response to a SYN is
        purely additive: the listener spawns a new TCB
        (Transmission Control Block) for the incoming 4-tuple,
        records the peer's ISN, transitions THAT TCB to SYN_RCVD, and
        leaves the LISTEN-state TCB untouched. A correctly
        implemented stack must therefore handle a burst of N
        unrelated SYNs by ending up with N independent children plus
        one still-listening socket - the existence of any earlier
        in-flight handshake must not influence later ones.

        Scenario:

            * Three SYNs from HOST_A's MAC/IP but three DIFFERENT
              source ports (33000, 33001, 33002) - the 4-tuple key
              that distinguishes children in 'stack.sockets' is the
              full (local_ip, local_port, remote_ip, remote_port)
              quadruple, so distinct source ports are sufficient.
            * Each peer announces a DIFFERENT ISN (0x4000, 0x5000,
              0x6000) so the per-child '_rcv_nxt' values are
              distinguishable in assertions.
            * After the three SYNs are driven, three child sockets
              must exist in 'stack.sockets' under the three
              peer-specific exact-match ids. Each child session must
              be in SYN_RCVD with the correct '_rcv_nxt' = peer's
              ISN + 1.
            * On the next virtual-clock tick, three SYN+ACKs must be
              emitted - one per child - each ack-ing its own peer's
              ISN. The listening socket's LISTEN-state session
              produces no segment on the tick (LISTEN handler has no
              timer branch).

        Implementation notes for the reader:

        '_tcp_fsm_listen' processes each SYN by mutating the CURRENT
        listening session in place into the new child and grafting a
        fresh listening session onto the original 'TcpSocket'. So
        across three SYNs we accumulate three different
        'TcpSession' objects - the originally-returned session is
        now child #1, the second-generation session is now child #2,
        and so on. The listening socket's '_tcp_session' attribute
        is replaced THREE times, ending up pointing at a fourth
        'TcpSession' that is in LISTEN waiting for a fourth SYN.

        This test passes on current code: the in-place-mutation
        pattern in '_tcp_fsm_listen', although unconventional,
        correctly preserves child independence because each new
        listening session is constructed fresh (its FSM state, ISS,
        receive buffer, and timers are all separately allocated)
        before being mutated.
        """

        listen_socket, _ = self._make_listen_session(iss=LOCAL__ISS)

        # (peer_port, peer_iss) tuples - same source IP HOST_A__IP
        # for all three so the mocked ARP cache resolves cleanly,
        # different source ports so each 4-tuple is unique.
        peers: list[tuple[int, int]] = [
            (33000, 0x0000_4000),
            (33001, 0x0000_5000),
            (33002, 0x0000_6000),
        ]

        for peer_port, peer_iss in peers:
            syn_frame = build_tcp4(
                sport=peer_port,
                dport=LISTEN__PORT,
                seq=peer_iss,
                ack=0,
                flags=("SYN",),
                win=PEER__WIN,
                mss=PEER__MSS,
            )
            inline_tx = self._drive_rx(frame=syn_frame)
            self.assertEqual(
                inline_tx,
                [],
                msg=(
                    f"SYN from HOST_A:{peer_port} must not produce any "
                    f"inline TX - SYN+ACK is gated on the next timer tick."
                ),
            )

        # Three children must now be registered, each under its own
        # peer-specific exact-match socket-id.
        for peer_port, peer_iss in peers:
            child_id = SocketId(
                address_family=AddressFamily.INET4,
                socket_type=SocketType.STREAM,
                local_address=STACK__IP,
                local_port=LISTEN__PORT,
                remote_address=PEER__IP,
                remote_port=peer_port,
            )
            self.assertIn(
                child_id,
                stack.sockets,
                msg=(
                    f"Child socket for HOST_A:{peer_port} must be "
                    f"registered in 'stack.sockets'. Concurrent "
                    f"handshakes must not overwrite each other's "
                    f"registrations."
                ),
            )
            child_socket = stack.sockets[child_id]
            assert isinstance(child_socket, TcpSocket)
            child_session = child_socket._tcp_session
            assert child_session is not None
            self.assertIs(
                child_session.state,
                FsmState.SYN_RCVD,
                msg=(
                    f"Child session for HOST_A:{peer_port} must be in "
                    f"SYN_RCVD; the existence of other in-flight "
                    f"handshakes must not perturb its state."
                ),
            )
            self.assertEqual(
                child_session._rcv_nxt,
                peer_iss + 1,
                msg=(
                    f"Child session for HOST_A:{peer_port} must have "
                    f"_rcv_nxt = {peer_iss + 1:#x} (= peer ISN + 1). "
                    f"Got {child_session._rcv_nxt:#x}. A bug here "
                    f"would indicate concurrent SYNs are clobbering "
                    f"each other's '_rcv_nxt'."
                ),
            )
            self.assertIs(
                child_socket._parent_socket,
                listen_socket,
                msg=(
                    f"Child socket for HOST_A:{peer_port} must point "
                    f"at the original listening socket via "
                    f"'_parent_socket' so its eventual third-leg ACK "
                    f"deposits the accepted child onto the right "
                    f"accept queue."
                ),
            )

        # The listening socket itself is still in LISTEN, ready for a
        # fourth SYN.
        new_listener_session = listen_socket._tcp_session
        assert new_listener_session is not None
        self.assertIs(
            new_listener_session.state,
            FsmState.LISTEN,
            msg=(
                "After spawning three children, the listening socket "
                "must still have a LISTEN-state session attached so "
                "subsequent SYNs from other peers continue to be "
                "accepted."
            ),
        )
        self.assertIn(
            listen_socket.socket_id,
            stack.sockets,
            msg=(
                "The listening socket's wildcard registration must "
                "remain in 'stack.sockets' across the burst of SYNs."
            ),
        )

        # On the next virtual-clock tick, every child emits its
        # SYN+ACK. The listener's LISTEN-state session produces
        # nothing (LISTEN handler has no timer branch).
        tick_tx = self._advance(ms=1)
        self.assertEqual(
            len(tick_tx),
            len(peers),
            msg=(
                f"Expected {len(peers)} SYN+ACKs (one per child) on "
                f"the first tick after the SYN burst. Got "
                f"{len(tick_tx)}."
            ),
        )

        # Match TX frames to peers by destination port - the three
        # children fire in registration order but a future change to
        # the timer's task ordering should not break this test.
        probes = [self._parse_tx(frame) for frame in tick_tx]
        probes_by_dport = {probe.dport: probe for probe in probes}
        self.assertEqual(
            set(probes_by_dport),
            {peer_port for peer_port, _ in peers},
            msg=(
                "The set of destination ports across the emitted "
                "SYN+ACKs must exactly equal the set of source ports "
                "from the inbound SYN burst."
            ),
        )

        for peer_port, peer_iss in peers:
            probe = probes_by_dport[peer_port]
            self._assert_segment(
                probe,
                flags=frozenset({"SYN", "ACK"}),
                sport=LISTEN__PORT,
                dport=peer_port,
                seq=LOCAL__ISS,
                ack=peer_iss + 1,
                payload=b"",
                mss=1460,
                wscale=None,
                win=65535,
            )

    def test__passive_open__retransmitted_syn_in_syn_rcvd_emits_challenge_ack(self) -> None:
        """
        Ensure that a duplicate SYN arriving on an existing SYN_RCVD
        child (i.e. the peer retransmitted their SYN because they did
        not see our SYN+ACK) is rejected with a challenge ACK per
        RFC 9293 §3.10.7.4 step 1 / step 4, NOT silently dropped and
        NOT used to spawn a duplicate child session.

        This is the symmetric analog of the active-open
        'retransmitted SYN+ACK in ESTABLISHED' challenge-ACK rule
        already covered in 'handshake__active.py' test #4: any
        SYN-bearing segment arriving on a child in a synchronized
        state (per RFC 9293 SYN_RECEIVED is one of those states)
        must trigger a challenge ACK rather than re-running the
        handshake or being silently dropped.

        The retransmitted SYN's sequence number equals the peer's
        original ISN, which - now that we have processed the original
        SYN - is one byte BEFORE our 'RCV.NXT' (= ISN+1). Per RFC
        9293 §3.10.7.4 step 1 the segment is therefore
        'unacceptable' (its seq is outside the receive window
        '[RCV.NXT, RCV.NXT + RCV.WND)') and must trigger an
        acknowledgement reply with the canonical form:

            <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        Step 4 of the same section also independently mandates a
        challenge ACK for any SYN-bearing segment in a synchronized
        state ("Implementations MUST send a 'challenge ACK' to the
        remote peer"), so the response shape is the same regardless
        of which step the implementation triggers on first.

        Wire shape of the retransmitted SYN we feed:

            sport   = PEER__PORT
            dport   = LISTEN__PORT
            seq     = PEER__ISS         (same as the original SYN)
            ack     = 0
            flags   = {SYN}
            mss     = PEER__MSS
            payload = b""

        Required outbound challenge-ACK shape:

            seq     = LOCAL__ISS + 1    (= SND.NXT, post-SYN+ACK)
            ack     = PEER__ISS + 1     (= RCV.NXT)
            flags   = {ACK}             (no SYN bit; bare ACK)
            payload = b""
            mss     = None              (MSS / WSCALE only on SYN-bearing
                                         segments)
            wscale  = None
            win     = 65535             (our advertised receive window)

        Side effects asserted:

            * No NEW socket registration appears under the peer's
              4-tuple - only the original child socket from SYN #1
              remains in 'stack.sockets'.
            * The existing child session stays in 'FsmState.SYN_RCVD' -
              its FSM state, '_snd_nxt' (= ISS+1), '_rcv_nxt'
              (= PEER__ISS+1), '_snd_una', and '_snd_max' all
              unchanged.
            * '_event__connect' is not released - the handshake has
              not completed and the listening socket's accept-event
              must not fire.

        [FLAGS BUG] - RFC 9293 §3.10.7.4 deviation
        ----------------------------------------------------------
        '_tcp_fsm_syn_rcvd' has no branch that matches a bare SYN.
        Its three packet-driven branches require ACK, RST+ACK, or
        bare RST respectively; a SYN-only segment falls through and
        the handler returns silently. As a result:

          - The peer's retransmit-SYN train is invisible to us until
            our OWN SYN+ACK retransmit timer eventually delivers the
            handshake's second leg. In high-loss environments where
            both retransmit timers fire repeatedly, the peer can
            see no acknowledgement of its retransmits at all, which
            confuses some implementations.
          - An off-path attacker can send forged SYN segments to the
            child's 4-tuple knowing they will be ignored, learning
            nothing from the silence but also receiving no signal
            that their probe failed.

        This test is expected to FAIL on current code. The fix
        mirrors the SYN-on-established branch added to
        '_tcp_fsm_established' for active-open #4: a SYN-bearing
        segment in '_tcp_fsm_syn_rcvd' must emit a challenge ACK
        and return, before any other per-flag processing.

        (Some implementations - notably Linux and BSD - go further
        and retransmit the SYN+ACK on a duplicate SYN with matching
        seq, accelerating handshake completion. That behaviour is
        outside RFC 9293's normative text and would change the
        observable outbound shape from a bare ACK to a SYN+ACK; this
        test pins the spec'd challenge-ACK shape, leaving the
        practical optimisation as a possible follow-up.)
        """

        listen_socket, _ = self._make_listen_session(iss=LOCAL__ISS)

        original_syn = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=original_syn)

        # Tick once so the SYN+ACK fires - this advances our SND.NXT
        # to ISS+1, which is the value the challenge ACK must echo.
        self._advance(ms=1)

        child_socket_id = self._child_socket_id()
        child_socket = stack.sockets[child_socket_id]
        assert isinstance(child_socket, TcpSocket)
        child_session_before = child_socket._tcp_session
        assert child_session_before is not None
        snd_nxt_before = child_session_before._snd_nxt
        snd_una_before = child_session_before._snd_una
        rcv_nxt_before = child_session_before._rcv_nxt
        sockets_before = set(stack.sockets)

        self.assertIs(
            child_session_before.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: child session must be in SYN_RCVD before driving the retransmit.",
        )
        self.assertEqual(
            snd_nxt_before,
            LOCAL__ISS + 1,
            msg=("Setup precondition: '_snd_nxt' must equal ISS+1 " "after the SYN+ACK was emitted on the first tick."),
        )

        # Peer retransmits the same SYN (same seq, same options).
        retransmitted_syn = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )

        tx_frames = self._drive_rx(frame=retransmitted_syn)

        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "A retransmitted SYN arriving on a SYN_RCVD child "
                "must elicit exactly one outbound segment (a "
                "challenge ACK) per RFC 9293 §3.10.7.4 step 1 / "
                f"step 4. Got {len(tx_frames)} TX frames."
            ),
        )

        challenge_ack = self._parse_tx(tx_frames[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=LISTEN__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
            mss=None,
            wscale=None,
            win=65535,
        )

        # The child session must be unchanged - same object, same
        # state, same sequence-number bookkeeping. The retransmit
        # carries no new information so processing it must be
        # idempotent on our state.
        child_session_after = child_socket._tcp_session
        self.assertIs(
            child_session_after,
            child_session_before,
            msg=(
                "A retransmitted SYN must not replace the child "
                "session - the existing session object must remain "
                "attached to the child socket."
            ),
        )
        assert child_session_after is not None
        self.assertIs(
            child_session_after.state,
            FsmState.SYN_RCVD,
            msg=(
                "A challenge ACK must not transition the child out "
                'of SYN_RCVD (RFC 9293 §3.10.7.4: "the connection '
                'state is not changed").'
            ),
        )
        self.assertEqual(
            child_session_after._snd_nxt,
            snd_nxt_before,
            msg="Challenge ACK consumes no sequence space - '_snd_nxt' must be unchanged.",
        )
        self.assertEqual(
            child_session_after._snd_una,
            snd_una_before,
            msg="Challenge ACK does not affect '_snd_una' - the original SYN+ACK is still unacknowledged.",
        )
        self.assertEqual(
            child_session_after._rcv_nxt,
            rcv_nxt_before,
            msg=(
                "Reprocessing a duplicate SYN must not advance "
                "'_rcv_nxt' - the SYN's one byte was already consumed "
                "during the original handshake processing."
            ),
        )

        # No new socket may be registered. Same set of registrations
        # as before the retransmit drive.
        self.assertEqual(
            set(stack.sockets),
            sockets_before,
            msg=(
                "A retransmitted SYN must not spawn a duplicate child "
                "socket. The set of registrations in 'stack.sockets' "
                "must be exactly what existed before the retransmit "
                "drive."
            ),
        )

        # Listener still LISTEN.
        self.assertIs(
            listen_socket._tcp_session.state,  # type: ignore[union-attr]
            FsmState.LISTEN,
            msg=("Processing a duplicate SYN on a child must not " "disturb the listener's state."),
        )

    def test__passive_open__syn_to_established_child_emits_challenge_ack(self) -> None:
        """
        Ensure that a SYN arriving at a child session that has
        already reached ESTABLISHED triggers a challenge ACK per
        RFC 9293 §3.10.7.4 step 4 (folding RFC 5961 §4 verbatim),
        rather than tearing down the connection or attempting a
        fresh handshake.

        This is the passive-open analog of the active-open
        challenge-ACK rule (see the active-open file's
        'retransmitted_syn_ack_in_established' test): once a 4-tuple
        is in any synchronized state, ANY SYN-bearing segment
        arriving on it must elicit a challenge ACK formatted as

            <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>

        and the segment itself must be discarded without state
        change.

        The arriving SYN can come from three sources, all of which
        the spec treats identically: (a) a stale duplicate from a
        prior incarnation of the connection that took the same
        4-tuple, (b) a forged segment by an off-path attacker who
        guessed the 4-tuple but not the ISN, or (c) a remote stack
        that has lost state and believes itself to be in CLOSED.
        Replying with a challenge ACK lets the legitimate peer (if
        case (a) or (c)) RST the spurious segment off the wire,
        while teaching the attacker (case (b)) nothing about our
        state.

        Scenario stages:

            1. Drive the full handshake to ESTABLISHED on the child:
               peer SYN -> our SYN+ACK (on the next tick) -> peer's
               third-leg ACK -> child transitions to ESTABLISHED.
               Snapshot 'SND.NXT', 'RCV.NXT', 'SND.UNA' so the
               test can later assert they are unchanged.
            2. Inject a bare SYN to the child's 4-tuple with an
               arbitrary seq value (0xDEAD_BEEF, chosen far from any
               legitimate sequence-space value so it is visually
               unambiguous in failure output).
            3. Verify exactly one outbound bare ACK is emitted with
               the spec'd challenge-ACK shape.
            4. Verify the child stays in ESTABLISHED, with all
               sequence bookkeeping unchanged.

        Wire shape of the rogue SYN we inject:

            sport   = PEER__PORT
            dport   = LISTEN__PORT
            seq     = 0xDEAD_BEEF       (arbitrary, well outside any
                                         legitimate seq this connection
                                         would see)
            ack     = 0
            flags   = {SYN}
            payload = b""

        Required outbound challenge-ACK shape:

            seq     = LOCAL__ISS + 1    (= SND.NXT, post-handshake)
            ack     = PEER__ISS + 1     (= RCV.NXT, post-handshake)
            flags   = {ACK}
            payload = b""
            mss     = None
            wscale  = None
            win     = 65535

        This test passes on current code thanks to the SYN-on-
        established branch added to '_tcp_fsm_established' in commit
        'ed54376' (the active-open #4 fix). That branch matches any
        SYN-bearing segment in ESTABLISHED and emits
        '_transmit_packet(flag_ack=True)' before any other per-flag
        processing, which produces exactly the challenge-ACK shape
        this test asserts. The test exists primarily as a positive-
        control regression guard: a future refactor that removed or
        moved the branch would be caught immediately by both the
        active-open and passive-open challenge-ACK tests in lockstep.
        """

        # Stage 1: drive handshake to ESTABLISHED.
        listen_socket, _ = self._make_listen_session(iss=LOCAL__ISS)

        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)
        self._advance(ms=1)  # SYN+ACK fires

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        child_socket = stack.sockets[self._child_socket_id()]
        assert isinstance(child_socket, TcpSocket)
        child_session = child_socket._tcp_session
        assert child_session is not None
        self.assertIs(
            child_session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Setup precondition: child must reach ESTABLISHED "
                "after the third-leg ACK before driving the "
                "challenge-ACK scenario."
            ),
        )

        snd_nxt_before = child_session._snd_nxt
        snd_una_before = child_session._snd_una
        rcv_nxt_before = child_session._rcv_nxt
        sockets_before = set(stack.sockets)

        # Stage 2: inject a SYN to the established child's 4-tuple.
        rogue_syn = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=0xDEAD_BEEF,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        tx_frames = self._drive_rx(frame=rogue_syn)

        # Stage 3: verify the challenge-ACK shape.
        self.assertEqual(
            len(tx_frames),
            1,
            msg=(
                "A SYN arriving on an ESTABLISHED child must elicit "
                "exactly one outbound challenge ACK per RFC 9293 "
                f"§3.10.7.4. Got {len(tx_frames)} TX frames."
            ),
        )

        challenge_ack = self._parse_tx(tx_frames[0])
        self._assert_segment(
            challenge_ack,
            flags=frozenset({"ACK"}),
            sport=LISTEN__PORT,
            dport=PEER__PORT,
            seq=LOCAL__ISS + 1,
            ack=PEER__ISS + 1,
            payload=b"",
            mss=None,
            wscale=None,
            win=65535,
        )

        # Stage 4: verify state unchanged.
        self.assertIs(
            child_session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Challenge ACK must not transition the child out of "
                'ESTABLISHED (RFC 9293 §3.10.7.4: "the connection '
                'state is not changed").'
            ),
        )
        self.assertEqual(
            child_session._snd_nxt,
            snd_nxt_before,
            msg="Challenge ACK consumes no sequence space; '_snd_nxt' must be unchanged.",
        )
        self.assertEqual(
            child_session._snd_una,
            snd_una_before,
            msg=("Rogue SYN's ACK was 0 - it acknowledges nothing - so '_snd_una' must be unchanged."),
        )
        self.assertEqual(
            child_session._rcv_nxt,
            rcv_nxt_before,
            msg=(
                "The rogue SYN's seq is far outside our receive "
                "window and is not legitimately part of this "
                "connection's data stream; '_rcv_nxt' must be "
                "unchanged."
            ),
        )
        self.assertEqual(
            set(stack.sockets),
            sockets_before,
            msg="A rogue SYN must not spawn a new child or otherwise perturb 'stack.sockets'.",
        )
        self.assertIs(
            listen_socket._tcp_session.state,  # type: ignore[union-attr]
            FsmState.LISTEN,
            msg="Processing a rogue SYN on an established child must not disturb the listener.",
        )
