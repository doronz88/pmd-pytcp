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
This module contains integration tests for the RFC 6298 RTO sample
collection (Phase 2 of '.claude/rules/tcp_rto_integration.md').

RFC 6298 §4 specifies how the RTT estimator MUST collect samples
from outbound segments and the corresponding ACKs:

    "TCP MUST use Karn's algorithm [KP87] for taking RTT samples.
     That is, RTT samples MUST NOT be made using segments that were
     retransmitted (and thus for which it is ambiguous whether the
     reply was for the first instance of the packet or a later
     instance)."

    "Traditionally, TCP implementations use coarse grain clocks to
     measure the RTT and trigger the RTO, ... [section 4 paragraph
     describes single-sample-per-RTT cadence]."

The Phase 2 work installs a single-pending-sample tracker on
'TcpSession':

    _rto_state: RtoState                    # initial_state() in __init__
    _rtt_sample_seq: Seq32 | None = None    # seq we're sampling
    _rtt_sample_send_time_ms: int | None    # virtual clock at send
    _rtt_sample_retransmitted: bool = False # Karn's flag

with three hook points:

    _transmit_packet  - records a fresh sample iff none is pending.
    _process_ack_packet - harvests on ACK passing sample seq, runs
                          'update' iff Karn's flag is False, then
                          clears the tracker.
    _retransmit_packet_timeout - sets Karn's flag on the in-flight
                                 sample so the eventual ACK does
                                 not poison the smoothed estimate.

The retransmit-timer logic itself is unchanged in Phase 2:
'_rto_state.rto_ms' is observed but the per-seq backoff machinery
('_tx_retransmit_timeout_counter') still drives the wire cadence.
Phase 3 (a follow-up commit set) replaces the per-seq machinery
with the session-level RTO timer.

The tests below exercise the six invariants of Phase 2 and are
expected to FAIL today against a session that does not yet expose
'_rto_state' / '_rtt_sample_seq' / '_rtt_sample_send_time_ms' /
'_rtt_sample_retransmitted'. The fix commit adds the fields and
the three hook points; this test file flips green at that point.

Reference RFCs:
    RFC 6298 §2     RTO computation
    RFC 6298 §3     Karn's algorithm
    RFC 6298 §4     Single-sample-per-RTT cadence
    RFC 9293 §3.8.4 references RFC 6298 by inclusion

pytcp/tests/integration/protocols/tcp/test__tcp__session__rto.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.tcp__rto import (
    INITIAL_RTO_MS,
    RtoState,
    initial_state,
    update,
)
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

# Peer's MSS option value on its SYN+ACK reply (1500 - 20 - 20 IPv4).
PEER__MSS: int = 1460


class TestTcpRtoSampling(TcpSessionTestCase):
    """
    Integration tests for the RFC 6298 RTO sample-collection
    machinery: pending-sample tracker, single-sample-per-RTT
    cadence, harvest-on-ACK, Karn-tainted-on-retransmit.
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

        The SYN itself is sampled by 'fix_phase_2': sample_seq=iss,
        send_time=0. Peer's SYN+ACK arrives at virtual time t=1 ms
        and harvests the sample (RTT ~ 1 ms), leaving '_rto_state'
        at 'update(initial_state(), 1)' and '_rtt_sample_seq' back
        to 'None'.
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

        # Bypass slow-start so the data tests can fire immediately
        # without entangling with the RFC 5681 §3.1 cwnd doubling
        # cadence. Tests of the cwnd interaction are out of scope
        # for Phase 2 (and properly belong to a future RFC 5681
        # cwnd-rework project).
        session._snd_ewn = PEER__WIN
        return session

    def test__rto__outbound_data_segment_records_pending_sample(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 6298 §4 sampling: an outbound data segment in
        ESTABLISHED records a pending RTT sample on 'TcpSession'.

        Scenario:

            * Drive handshake to ESTABLISHED. Post-handshake the
              SYN sample has already been harvested by peer's
              SYN+ACK, so '_rtt_sample_seq' is 'None'.
            * Send a small payload; advance one tick so
              '_transmit_data' fires.
            * Assert '_rtt_sample_seq' equals the seq of the data
              segment ('LOCAL__ISS + 1', i.e., the byte
              immediately after the consumed SYN).
            * Assert '_rtt_sample_send_time_ms' equals the virtual
              clock at the moment '_transmit_packet' fired.
            * Assert '_rtt_sample_retransmitted' is False (the
              segment is fresh, not a retransmit).

        Fails today: 'TcpSession' has no '_rtt_sample_seq' field;
        the assertion below raises 'AttributeError'.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Post-handshake the SYN sample has been harvested.
        self.assertIsNone(
            session._rtt_sample_seq,
            msg=(
                "RFC 6298 §4: post-handshake the SYN sample MUST "
                "have been harvested by peer's SYN+ACK; "
                "'_rtt_sample_seq' should be 'None'."
            ),
        )

        payload = b"hello, world!"
        session.send(data=payload)
        send_tick_now_ms = self._timer.now_ms + 1
        self._advance(ms=1)

        self.assertEqual(
            session._rtt_sample_seq,
            LOCAL__ISS + 1,
            msg=(
                "RFC 6298 §4: an outbound data segment in "
                "ESTABLISHED MUST record a pending RTT sample "
                "with sample_seq equal to the segment's seq."
            ),
        )
        self.assertEqual(
            session._rtt_sample_send_time_ms,
            send_tick_now_ms,
            msg=(
                "RFC 6298 §4: the recorded send-time MUST equal "
                "the virtual clock at the moment "
                "'_transmit_packet' fired."
            ),
        )
        self.assertFalse(
            session._rtt_sample_retransmitted,
            msg=(
                "RFC 6298 §3: a fresh outbound segment MUST mark "
                "the pending sample as not-retransmitted; Karn's "
                "flag is set only on retransmit."
            ),
        )

    def test__rto__ack_covering_pending_sample_harvests_and_updates_rto_state(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 6298 §2.2 / §2.3: an ACK whose ack-field passes
        the pending sample seq harvests the sample, advances the
        '_rto_state' via 'update(prior, observed_rtt_ms)', and
        clears the sample tracker.

        Scenario:

            * Drive handshake to ESTABLISHED. Capture the post-
              handshake '_rto_state' (already updated once by the
              SYN sample harvest).
            * Send a payload; advance one tick so the data
              segment fires (and the sample is recorded).
            * Advance an additional 9 ms with no peer activity so
              the harvested RTT is exactly 10 ms.
            * Drive a peer ACK covering the data segment.
            * Compute 'expected = update(pre_ack_state, 10)' and
              assert '_rto_state == expected'.
            * Assert '_rtt_sample_seq is None' (cleared after
              harvest).

        Fails today: missing '_rto_state' / '_rtt_sample_seq'
        fields on 'TcpSession'.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        pre_ack_state = session._rto_state

        payload = b"hello, world!"
        session.send(data=payload)
        self._advance(ms=1)
        sample_send_time = session._rtt_sample_send_time_ms

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

        observed_rtt_ms = self._timer.now_ms - (sample_send_time or 0)
        expected_state = update(pre_ack_state, observed_rtt_ms)

        self.assertEqual(
            session._rto_state,
            expected_state,
            msg=(
                f"RFC 6298 §2.3: ACK harvesting the pending sample "
                f"MUST fold 'observed_rtt_ms={observed_rtt_ms}' "
                f"into the prior state via 'update'. Expected "
                f"{expected_state!r}, got {session._rto_state!r}."
            ),
        )
        self.assertIsNone(
            session._rtt_sample_seq,
            msg=(
                "RFC 6298 §4: after harvest the sample tracker "
                "MUST be cleared so the next outbound segment can "
                "start a fresh sample."
            ),
        )

    def test__rto__additional_data_while_sample_pending_does_not_overwrite(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 6298 §4 single-sample-per-RTT cadence:
        additional outbound segments fired while a previous
        sample is still pending MUST NOT overwrite the pending
        sample.

        Scenario:

            * Drive handshake to ESTABLISHED.
            * Send a 2*MSS payload (2920 bytes). Advance one tick
              so the first segment fires; '_rtt_sample_seq' is
              recorded as 'LOCAL__ISS + 1'.
            * Advance another tick so the second segment fires.
              '_transmit_data' calls '_transmit_packet' for the
              second segment; the hook MUST NOT overwrite the
              sample because '_rtt_sample_seq' is already set.
            * Assert '_rtt_sample_seq' is still 'LOCAL__ISS + 1'
              (not 'LOCAL__ISS + 1 + PEER__MSS').

        Fails today: missing fields on 'TcpSession'.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        payload = b"x" * (2 * PEER__MSS)
        session.send(data=payload)

        first_tx = self._advance(ms=1)
        self.assertEqual(
            len(first_tx),
            1,
            msg=(f"Setup invariant: first tick must produce exactly " f"one segment. Got {len(first_tx)}."),
        )
        first_sample_seq = session._rtt_sample_seq

        second_tx = self._advance(ms=1)
        self.assertEqual(
            len(second_tx),
            1,
            msg=(f"Setup invariant: second tick must produce the " f"second segment. Got {len(second_tx)}."),
        )

        self.assertEqual(
            session._rtt_sample_seq,
            first_sample_seq,
            msg=(
                "RFC 6298 §4: while a sample is pending, "
                "subsequent outbound segments MUST NOT overwrite "
                "'_rtt_sample_seq'. Single-sample-per-RTT cadence."
            ),
        )
        self.assertEqual(
            first_sample_seq,
            LOCAL__ISS + 1,
            msg=("Setup invariant: first sample seq must equal the " "first segment's seq."),
        )

    def test__rto__post_harvest_next_outbound_starts_fresh_sample(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 6298 §4: once the pending sample has been
        harvested by a covering ACK, the next outbound data
        segment MUST start a fresh sample.

        Scenario:

            * Drive handshake to ESTABLISHED.
            * Send first payload, advance, peer-ACK it. Sample is
              harvested; '_rtt_sample_seq' is 'None'.
            * Send second payload, advance.
            * Assert '_rtt_sample_seq' equals the seq of the
              second segment (post-first-ACK
              'LOCAL__ISS + 1 + len(first_payload)').
            * Assert '_rtt_sample_send_time_ms' is the virtual
              clock at the second-segment send (later than the
              first-segment send time).

        Fails today: missing fields on 'TcpSession'.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        first_payload = b"hello"
        session.send(data=first_payload)
        self._advance(ms=1)

        first_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(first_payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=first_ack)
        self.assertIsNone(
            session._rtt_sample_seq,
            msg=(
                "Setup invariant: the first sample must have been "
                "harvested by the first ACK before the second "
                "segment fires."
            ),
        )

        second_payload = b"world"
        session.send(data=second_payload)
        second_send_now_ms = self._timer.now_ms + 1
        self._advance(ms=1)

        self.assertEqual(
            session._rtt_sample_seq,
            LOCAL__ISS + 1 + len(first_payload),
            msg=(
                "RFC 6298 §4: after a sample is harvested, the "
                "next outbound segment MUST start a fresh sample "
                "with sample_seq equal to the new segment's seq."
            ),
        )
        self.assertEqual(
            session._rtt_sample_send_time_ms,
            second_send_now_ms,
            msg=(
                "RFC 6298 §4: the fresh sample's send-time MUST "
                "equal the virtual clock at the second-segment "
                "send."
            ),
        )
        self.assertFalse(
            session._rtt_sample_retransmitted,
            msg=(
                "RFC 6298 §3: a fresh post-harvest sample is not "
                "Karn-tainted; '_rtt_sample_retransmitted' MUST "
                "be False."
            ),
        )

    def test__rto__retransmit_marks_pending_sample_as_karn_tainted(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 6298 §3 (Karn's algorithm): when a segment with
        a pending sample is retransmitted via the timeout path,
        the sample MUST be marked tainted so the eventual ACK does
        not produce an RTT sample.

            "Karn's algorithm prevents the RTO estimator from
             being polluted by samples derived from retransmitted
             segments, where the sender cannot tell whether the
             ACK was for the original transmission or one of the
             retransmits."

        Scenario:

            * Drive handshake to ESTABLISHED.
            * Send a payload, advance one tick so the data
              segment fires and the sample is recorded.
            * Advance past 'PACKET_RETRANSMIT_TIMEOUT' (1000 ms)
              with no peer ACK so '_retransmit_packet_timeout'
              fires.
            * Assert '_rtt_sample_retransmitted' is True (Karn's
              flag set).
            * Assert '_rtt_sample_seq' is unchanged (still the
              same segment).

        Fails today: missing fields on 'TcpSession'.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        payload = b"hello, world!"
        session.send(data=payload)
        self._advance(ms=1)
        original_sample_seq = session._rtt_sample_seq

        # Advance past the per-seq retransmit timeout (1000 ms)
        # so '_retransmit_packet_timeout' fires.
        self._advance(ms=1001)

        self.assertTrue(
            session._rtt_sample_retransmitted,
            msg=(
                "RFC 6298 §3 (Karn): retransmit of the sampled "
                "segment MUST set '_rtt_sample_retransmitted' so "
                "the eventual ACK does not poison the smoothed "
                "estimate."
            ),
        )
        self.assertEqual(
            session._rtt_sample_seq,
            original_sample_seq,
            msg=(
                "RFC 6298 §3: Karn's algorithm taints the sample "
                "but does NOT clear it - 'sample_seq' must remain "
                "set so the harvest path can recognise the "
                "covering ACK and skip 'update'."
            ),
        )

    def test__rto__ack_of_karn_tainted_sample_clears_but_does_not_update_state(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 6298 §3 (Karn's algorithm): an ACK that
        harvests a Karn-tainted sample MUST clear the sample
        tracker WITHOUT folding the observed RTT into
        '_rto_state'. The smoothed estimator stays stale until a
        fresh non-retransmitted sample arrives.

        Scenario:

            * Drive handshake to ESTABLISHED.
            * Send a payload, advance, taint via retransmit
              timeout (as in scenario #5). Capture the post-taint
              '_rto_state' so we can verify it is unchanged.
            * Drive a peer ACK covering the (re)transmitted
              segment.
            * Assert '_rtt_sample_seq is None' (cleared).
            * Assert '_rto_state' is UNCHANGED from the pre-ACK
              snapshot - 'update' MUST NOT have run on this
              ambiguous sample.

        Fails today: missing fields on 'TcpSession'.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        payload = b"hello, world!"
        session.send(data=payload)
        self._advance(ms=1)

        # Taint the sample via retransmit timeout fire.
        self._advance(ms=1001)
        assert session._rtt_sample_retransmitted, (
            "Setup invariant: the retransmit timeout must have "
            "fired and tainted the pending sample before the "
            "covering ACK arrives."
        )
        pre_ack_rto_state = session._rto_state

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertIsNone(
            session._rtt_sample_seq,
            msg=(
                "RFC 6298 §3: harvest of a Karn-tainted sample "
                "MUST clear the sample tracker even though the "
                "smoothed estimate is not updated."
            ),
        )
        self.assertEqual(
            session._rto_state,
            pre_ack_rto_state,
            msg=(
                "RFC 6298 §3 (Karn): the tainted sample's RTT "
                "MUST NOT be folded into '_rto_state'. Expected "
                f"the unchanged pre-ACK state {pre_ack_rto_state!r}, "
                f"got {session._rto_state!r}."
            ),
        )


class TestTcpRtoInitialization(TcpSessionTestCase):
    """
    Construction-time invariants for the RFC 6298 RTO state on a
    fresh 'TcpSession'.
    """

    def test__rto__fresh_session_initializes_rto_state_to_initial(self) -> None:
        """
        Ensure RFC 6298 §2.1: a freshly-constructed 'TcpSession'
        starts with '_rto_state == initial_state()' (SRTT and
        RTTVAR uninitialised, RTO at 'INITIAL_RTO_MS') and an
        empty sample tracker.

        Passes today as a positive control / regression guard
        for the construction-time invariant: this commit adds
        the field declarations to 'TcpSession.__init__' so the
        attributes exist with the canonical default values. The
        sister tests in 'TestTcpRtoSampling' below assert the
        runtime behaviour that the fix commit wires up.
        """

        self._force_iss(LOCAL__ISS)

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

        self.assertEqual(
            session._rto_state,
            initial_state(),
            msg=(
                "RFC 6298 §2.1: a fresh session MUST initialise "
                f"'_rto_state' to 'initial_state()' "
                f"(srtt_ms=None, rttvar_ms=None, rto_ms="
                f"{INITIAL_RTO_MS})."
            ),
        )
        self.assertIsNone(
            session._rtt_sample_seq,
            msg="A fresh session has no pending sample.",
        )
        self.assertIsNone(
            session._rtt_sample_send_time_ms,
            msg="A fresh session has no pending sample.",
        )
        self.assertFalse(
            session._rtt_sample_retransmitted,
            msg="A fresh session's sample tracker is not Karn-tainted.",
        )

        self.assertIsInstance(
            session._rto_state,
            RtoState,
            msg=("'_rto_state' must be the typed 'RtoState' " "dataclass from 'pytcp.protocols.tcp.tcp__rto'."),
        )


class TestTcpRtoRetransmitTimer(TcpSessionTestCase):
    """
    Integration tests for the RFC 6298 §5 session-level retransmit
    timer machinery (Phase 3 of '.claude/rules/tcp_rto_integration.md').

    Phase 3 replaces PyTCP's per-seq retransmit-timer family
    ('f"{session}-retransmit_seq-{seq}"' keyed by '_tx_retransmit_timeout_counter')
    with a single session-level timer 'f"{session}-retransmit"' driven
    by '_rto_state.rto_ms'. The five RFC 6298 §5 invariants the new
    machinery must satisfy:

        §5.1  Every time a packet containing data is sent (including
              a retransmission), if the timer is not running, start
              it running so that it will expire after RTO seconds.
        §5.2  When all outstanding data has been acknowledged, turn
              off the retransmission timer.
        §5.3  When an ACK is received that acknowledges new data,
              restart the retransmission timer so that it will
              expire after RTO seconds.
        §5.4  Retransmit the earliest segment that has not been
              acknowledged.
        §5.5  Set RTO = RTO * 2 ('back off the timer'), capped at
              the upper bound (MAX_RTO_MS).

    The tests below exercise §5.1 / §5.2 / §5.5 directly. §5.3 and
    §5.4 are covered transitively by the existing
    'data_transfer__retransmit_timeout' integration suite (whose
    cadence assertions stay green via the 'MIN_RTO_MS' clamp).
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

    def test__rto__data_transmit_arms_session_level_retransmit_timer(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 6298 §5.1: when a data segment is sent and no
        retransmit timer is currently running, the session arms a
        single 'f"{session}-retransmit"' timer (NOT the legacy
        'f"{session}-retransmit_seq-{seq}"' family) with timeout
        equal to '_rto_state.rto_ms'.

        Scenario:

            * Drive handshake to ESTABLISHED.
            * Send a payload; advance one tick so '_transmit_data'
              fires the data segment.
            * Assert 'f"{session}-retransmit"' is registered in
              'stack.timer.pending_timers'.
            * Assert its remaining time equals
              '_rto_state.rto_ms' (= 1000 ms post-handshake).
            * Assert NO 'f"{session}-retransmit_seq-..."' key
              survives - the per-seq family is gone.

        Fails today: the per-seq family is still in use; the new
        session-level name is never registered.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        payload = b"hello, world!"
        session.send(data=payload)
        self._advance(ms=1)

        session_retransmit_timer = f"{session}-retransmit"
        self.assertIn(
            session_retransmit_timer,
            self._timer.pending_timers,
            msg=(
                f"RFC 6298 §5.1: a data send while no retransmit "
                f"timer is running MUST arm "
                f"'{session_retransmit_timer}'. Got pending timers: "
                f"{sorted(self._timer.pending_timers)!r}."
            ),
        )
        self.assertEqual(
            self._timer.pending_timers[session_retransmit_timer],
            session._rto_state.rto_ms,
            msg=(
                f"RFC 6298 §5.1 / §5.6: the session-level retransmit "
                f"timer MUST be armed with '_rto_state.rto_ms' "
                f"(= {session._rto_state.rto_ms} ms post-handshake), "
                f"not a hand-rolled exponential of "
                f"'PACKET_RETRANSMIT_TIMEOUT'."
            ),
        )

        legacy_per_seq_keys = [k for k in self._timer.pending_timers if k.startswith(f"{session}-retransmit_seq-")]
        self.assertEqual(
            legacy_per_seq_keys,
            [],
            msg=(
                "Phase 3 retires the per-seq retransmit-timer family. "
                "No 'f\"{session}-retransmit_seq-X\"' keys may survive "
                f"after a fresh data send. Got: {legacy_per_seq_keys!r}."
            ),
        )

    def test__rto__cumulative_ack_draining_in_flight_stops_retransmit_timer(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 6298 §5.2: when a cumulative ACK fully drains
        the in-flight bytes (all sent data is acknowledged), the
        retransmit timer MUST be turned off.

            "(5.2) When all outstanding data has been acknowledged,
                   turn off the retransmission timer."

        Scenario:

            * Drive handshake to ESTABLISHED.
            * Send a payload; advance one tick so the data segment
              fires (and the retransmit timer is armed).
            * Drive a peer ACK covering all in-flight bytes.
            * Assert NO timer whose name contains 'retransmit'
              remains in 'stack.timer.pending_timers' (the session-
              level entry was unregistered AND no leftover per-seq
              entry from the legacy machinery).

        Fails today: the legacy machinery purges
        '_tx_retransmit_timeout_counter' on cum-ACK but does NOT
        unregister the still-counting 'f"{session}-retransmit_seq-X"'
        timer in 'stack.timer._timers'. Phase 3 explicitly turns
        the session-level timer off.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        payload = b"hello, world!"
        session.send(data=payload)
        self._advance(ms=1)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        retransmit_keys = [k for k in self._timer.pending_timers if "retransmit" in k]
        self.assertEqual(
            retransmit_keys,
            [],
            msg=(
                "RFC 6298 §5.2: a cum-ACK that drains all in-flight "
                "bytes MUST turn off the retransmission timer. "
                "Today the legacy per-seq machinery only purges its "
                "internal counter dict and leaves the named stack-"
                "timer entry counting down; Phase 3 must explicitly "
                "unregister 'f\"{session}-retransmit\"'. Got "
                f"surviving keys: {retransmit_keys!r}."
            ),
        )

    def test__rto__retransmit_timeout_backs_off_rto_state(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 6298 §5.5: when the retransmit timer expires,
        '_rto_state.rto_ms' MUST be doubled via 'tcp__rto.back_off'
        (capped at 'MAX_RTO_MS') and the timer re-armed with the
        new value.

            "(5.5) The host MUST set RTO <- RTO * 2 ('back off the
                   timer'). The maximum value discussed in (2.5)
                   may be used to provide an upper bound to this
                   doubling operation."

        Scenario:

            * Drive handshake to ESTABLISHED. Capture the post-
              handshake '_rto_state' (rto_ms = 1000 via
              'MIN_RTO_MS' clamp).
            * Send a payload; advance one tick so the data
              segment fires and the timer is armed.
            * Advance past the timer's deadline (~1001 ms with
              the post-handshake clamp) so
              '_retransmit_packet_timeout' fires.
            * Assert '_rto_state.rto_ms' has doubled (= 2000 ms).
            * Assert SRTT and RTTVAR are unchanged - back_off
              touches only RTO, leaves the smoothed estimator
              alone (Karn's algorithm separates sample-driven
              updates from timeout-driven backoffs).
            * Assert 'f"{session}-retransmit"' is re-armed with
              the new 'rto_ms = 2000' (RFC 6298 §5.6).

        Fails today: '_retransmit_packet_timeout' uses a hand-
        rolled '1000 * (1 << count)' formula and does NOT touch
        '_rto_state'.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        pre_backoff_state = session._rto_state

        payload = b"hello, world!"
        session.send(data=payload)
        self._advance(ms=1)

        # Advance to exactly the per-handshake-clamped RTO
        # boundary. With the MIN_RTO_MS clamp the timer is armed
        # at 1000 ms; the last tick of this advance is the one
        # that drops the timer to 0 AND fires
        # '_retransmit_packet_timeout' (FakeTimer ticks _timers
        # before _tasks, so the post-backoff re-arm sees the new
        # 'rto_ms' decremented zero further times by 'advance'
        # before the assertion sees it).
        self._advance(ms=1000)

        self.assertEqual(
            session._rto_state.rto_ms,
            pre_backoff_state.rto_ms * 2,
            msg=(
                f"RFC 6298 §5.5: retransmit timeout MUST double "
                f"'_rto_state.rto_ms' via 'back_off'. Pre-backoff "
                f"rto_ms={pre_backoff_state.rto_ms}; expected "
                f"{pre_backoff_state.rto_ms * 2} post-backoff; got "
                f"{session._rto_state.rto_ms}."
            ),
        )
        self.assertEqual(
            session._rto_state.srtt_ms,
            pre_backoff_state.srtt_ms,
            msg=(
                "RFC 6298 §5.5 'back_off' MUST NOT touch SRTT - "
                "Karn's algorithm separates sample-driven updates "
                "from timeout-driven backoffs."
            ),
        )
        self.assertEqual(
            session._rto_state.rttvar_ms,
            pre_backoff_state.rttvar_ms,
            msg=(
                "RFC 6298 §5.5 'back_off' MUST NOT touch RTTVAR - "
                "Karn's algorithm separates sample-driven updates "
                "from timeout-driven backoffs."
            ),
        )

        session_retransmit_timer = f"{session}-retransmit"
        self.assertIn(
            session_retransmit_timer,
            self._timer.pending_timers,
            msg=(
                f"RFC 6298 §5.6: after back_off, the retransmit "
                f"timer MUST be re-armed with the new rto_ms. "
                f"Got pending timers: "
                f"{sorted(self._timer.pending_timers)!r}."
            ),
        )
        self.assertEqual(
            self._timer.pending_timers[session_retransmit_timer],
            session._rto_state.rto_ms,
            msg=(
                f"RFC 6298 §5.6: the re-armed timer's timeout "
                f"MUST equal the post-backoff "
                f"'_rto_state.rto_ms = {session._rto_state.rto_ms}'."
            ),
        )


class TestTcpRtoRestartAfterIdle(TcpSessionTestCase):
    """
    Integration tests for the RFC 6298 §5.7 restart-after-idle
    behaviour (Phase 4 of '.claude/rules/tcp_rto_integration.md').

    When a session has been silent for longer than the in-flight
    'rto_ms' the smoothed RTT estimator may be stale - the
    network conditions that produced the current SRTT/RTTVAR may
    no longer hold. Phase 4 hooks '_transmit_packet' so the next
    outbound segment after a long idle resets '_rto_state' to
    'initial_state()' and the §4 sample-collection hook then
    re-establishes the estimator from scratch on the next
    covering ACK.

    The reset is gated on:

        '_last_send_time_ms is not None'
        AND 'now_ms - _last_send_time_ms > _rto_state.rto_ms'
        AND segment carries a data/SYN/FIN byte (i.e. it
            consumes sequence space the peer can ACK back)

    so a fresh session never spuriously resets, and a quiescent
    burst spaced under 'rto_ms' preserves the smoothed estimate
    that drives subsequent retransmit timing.
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

    def _send_one_payload_and_ack(self, *, session: TcpSession, seq_offset: int, payload: bytes) -> None:
        """
        Send 'payload', drive the data segment out on the next
        tick, then drive a peer ACK that fully covers it. Used
        to put the session into the post-handshake quiescent
        state where the retransmit timer is off (§5.2 satisfied)
        and a subsequent idle period can be observed cleanly.
        """

        session.send(data=payload)
        self._advance(ms=1)
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + seq_offset + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

    def test__rto__idle_longer_than_rto_resets_state_to_initial(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 6298 §5.7: a session that has been quiescent
        for longer than the in-flight 'rto_ms' MUST reset
        '_rto_state' to 'initial_state()' on the next outbound
        segment, so a stale smoothed estimator does not drive
        spurious retransmits with a now-too-short RTO.

        Scenario:

            * Drive handshake to ESTABLISHED. Post-handshake
              '_rto_state' = update(initial, 1) = (1, 0, 1000)
              with the 'MIN_RTO_MS' clamp keeping rto_ms at
              1000.
            * Send first payload, advance, peer-ACK. Timer
              turns off (§5.2); '_last_send_time_ms' was
              recorded at the first send.
            * Advance well past 'rto_ms' of virtual time
              (2000 ms here vs. 1000 ms RTO). No peer activity.
            * Send second payload; advance one tick so the
              segment fires.
            * Assert '_rto_state == initial_state()' - the
              §5.7 reset took effect inside '_transmit_packet'
              before the new sample was recorded.
            * Assert the new sample tracker fields are set
              for the second segment - the reset does not
              wipe sample collection itself.

        Fails today: '_last_send_time_ms' does not exist on
        'TcpSession'; the test attribute access raises
        'AttributeError'. After the fix, the §5.7 reset hook
        in '_transmit_packet' restores 'initial_state()' on
        the second-payload send.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Step 1: send + ACK first payload so the session
        # reaches a quiescent state (timer off, all in-flight
        # acked).
        first_payload = b"hello"
        self._send_one_payload_and_ack(
            session=session,
            seq_offset=0,
            payload=first_payload,
        )
        first_send_time = session._last_send_time_ms
        self.assertIsNotNone(
            first_send_time,
            msg="Setup invariant: '_last_send_time_ms' must be recorded after the first send.",
        )

        # Step 2: idle longer than rto_ms (= 1000 ms post-clamp).
        self._advance(ms=2000)

        # Step 3: send second payload.
        second_payload = b"world"
        session.send(data=second_payload)
        self._advance(ms=1)

        self.assertEqual(
            session._rto_state,
            initial_state(),
            msg=(
                f"RFC 6298 §5.7: idle for "
                f"{self._timer.now_ms - (first_send_time or 0)} ms > "
                f"rto_ms={1000}; '_rto_state' MUST reset to "
                f"'initial_state()' on the next data send. Got "
                f"{session._rto_state!r}."
            ),
        )
        self.assertEqual(
            session._rtt_sample_seq,
            LOCAL__ISS + 1 + len(first_payload),
            msg=(
                "RFC 6298 §4: the §5.7 reset must not interfere "
                "with sample collection - the new outbound "
                "segment still records its sample seq."
            ),
        )

    def test__rto__idle_shorter_than_rto_preserves_state(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 6298 §5.7 reset is gated on the idle period
        EXCEEDING 'rto_ms'. A burst of writes spaced shorter
        than the smoothed RTO is normal application behaviour
        and MUST preserve the smoothed estimator.

        Scenario:

            * Drive handshake to ESTABLISHED.
            * Send + ACK first payload to enter quiescent
              state. Capture '_rto_state' = (1, 0, 1000)
              post-handshake-and-first-ACK.
            * Idle 500 ms (well under 'rto_ms' = 1000 ms).
            * Send second payload; advance one tick so the
              segment fires.
            * Assert '_rto_state' is unchanged from the pre-
              idle snapshot - the short idle did not trigger
              the §5.7 reset.

        Fails today: '_last_send_time_ms' does not exist on
        'TcpSession'; the test attribute access raises
        'AttributeError'. After the fix, the §5.7 idle check
        evaluates 'False' (now - last_send = 501 < rto_ms =
        1000) and '_rto_state' remains the harvested value.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        first_payload = b"hello"
        self._send_one_payload_and_ack(
            session=session,
            seq_offset=0,
            payload=first_payload,
        )
        pre_idle_state = session._rto_state
        self.assertIsNotNone(
            session._last_send_time_ms,
            msg="Setup invariant: '_last_send_time_ms' must be recorded after the first send.",
        )

        # Short idle, well under rto_ms = 1000 ms.
        self._advance(ms=500)

        second_payload = b"world"
        session.send(data=second_payload)
        self._advance(ms=1)

        self.assertEqual(
            session._rto_state,
            pre_idle_state,
            msg=(
                "RFC 6298 §5.7: the idle-reset is gated on the "
                "idle period EXCEEDING 'rto_ms'. A 500 ms idle "
                "with rto_ms=1000 must not trigger the reset; "
                f"'_rto_state' must remain at "
                f"{pre_idle_state!r}. Got {session._rto_state!r}."
            ),
        )

    def test__rto__transmit_updates_last_send_time(self) -> None:
        """
        [FLAGS BUG]

        Ensure that '_transmit_packet' records the virtual
        clock at every outbound segment that consumes sequence
        space (data / SYN / FIN), so the §5.7 idle check has
        an accurate baseline.

        Scenario:

            * Drive handshake to ESTABLISHED. Post-handshake
              '_last_send_time_ms' must be set (the SYN send
              counted).
            * Send a payload; advance one tick. After the
              data segment fires, '_last_send_time_ms' must
              equal the virtual clock at that send.

        Fails today: '_last_send_time_ms' does not exist on
        'TcpSession'; the test attribute access raises
        'AttributeError'.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # SYN consumed sequence space at t=0; handshake helper
        # advances 1 ms before delivering SYN+ACK, so the
        # post-handshake '_last_send_time_ms' is the SYN send
        # time (= 0 ms on FakeTimer's virtual clock).
        self.assertIsNotNone(
            session._last_send_time_ms,
            msg=(
                "RFC 6298 §5.7 baseline: '_last_send_time_ms' "
                "MUST be recorded by the SYN send during "
                "handshake. Otherwise the first post-handshake "
                "data send sees 'None' and skips the §5.7 reset "
                "check entirely."
            ),
        )

        payload = b"hello, world!"
        session.send(data=payload)
        send_tick_now_ms = self._timer.now_ms + 1
        self._advance(ms=1)

        self.assertEqual(
            session._last_send_time_ms,
            send_tick_now_ms,
            msg=(
                "RFC 6298 §5.7 tracking: '_last_send_time_ms' "
                "MUST equal the virtual clock at the moment "
                "'_transmit_packet' fired the data segment."
            ),
        )


class TestTcpRtoSynFloor(TcpSessionTestCase):
    """
    Integration tests for the RFC 6298 §5.7 SECOND clause: the
    SYN-RTO 3-second floor.

    RFC 6298 §5.7 second sentence:

        "If the timer expires awaiting the ACK of a SYN segment
         and the TCP implementation is using an RTO less than
         3 seconds, the RTO MUST be re-initialized to 3 seconds
         when data transmission begins (i.e., after the three-
         way handshake completes)."

    The floor protects against pathologically aggressive RTOs
    in environments where the SYN's RTT measurement (clamped to
    MIN_RTO_MS = 1000 ms by the RFC 6298 §2.4 lower bound) is
    optimistic relative to the path's actual RTT. By forcing
    rto_ms >= 3000 ms after a SYN retransmit, the first
    post-handshake data send is given a more conservative
    timeout while the connection re-acquires fresh RTT samples.

    The floor applies ONLY when the SYN was retransmitted at
    least once (i.e., '_retransmit_count > 0' at handshake
    completion). If the peer's SYN+ACK arrives before any SYN
    retransmit fires, no floor applies - the canonical RTT
    measurement (typically clamped to MIN_RTO_MS) stands.
    """

    def _make_active_session(self, *, iss: int) -> TcpSession:
        """Build a 'TcpSocket' / 'TcpSession' pair."""

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

    def test__rto__post_syn_retransmit_handshake_floors_rto_at_3000ms(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 6298 §5.7 second clause: when the SYN was
        retransmitted at least once (peer's SYN+ACK arrives only
        after the SYN retransmit fired), the post-handshake
        '_rto_state.rto_ms' MUST be >= 3000 ms when data
        transmission begins.

        Scenario:

            * Drive an active-open SYN; observe the initial SYN.
            * Advance virtual time past the initial RTO
              (1000 ms) so the SYN's retransmit timer fires.
              '_retransmit_count' increments to 1.
            * Drive peer's SYN+ACK so the handshake completes.
            * Assert state == ESTABLISHED.
            * Assert '_retransmit_count > 0' (setup invariant -
              we DID retransmit the SYN).
            * Assert '_rto_state.rto_ms >= 3000' per RFC 6298
              §5.7.

        Fails today: PyTCP applies a uniform MIN_RTO_MS = 1000
        floor and does not enforce the SYN-specific 3-second
        floor when the handshake completes after a SYN
        retransmit. After the post-handshake '_process_ack_packet'
        on the SYN+ACK, '_rto_state.rto_ms' is whatever the
        SRTT/RTTVAR estimator yields (typically 1000 ms via the
        MIN_RTO_MS clamp).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        # Initial SYN goes out on the first tick.
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup invariant: connect must emit one SYN frame on the first tick.",
        )

        # Advance past the initial RTO so the SYN's retransmit
        # timer fires at least once.
        self._advance(ms=1500)
        self.assertGreaterEqual(
            session._retransmit_count,
            1,
            msg=(
                "Setup invariant: after 1.5 s of peer silence, the SYN's "
                "retransmit timer (RTO=1000 ms) MUST have fired at least "
                f"once. Got _retransmit_count={session._retransmit_count}."
            ),
        )

        # Peer's SYN+ACK arrives; handshake completes.
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup invariant: handshake MUST complete on peer SYN+ACK.",
        )
        self.assertGreaterEqual(
            session._rto_state.rto_ms,
            3000,
            msg=(
                "RFC 6298 §5.7 second clause: when the SYN was "
                "retransmitted at least once before the handshake "
                "completed, '_rto_state.rto_ms' MUST be re-initialized "
                "to >= 3000 ms when data transmission begins. Got "
                f"_rto_state.rto_ms={session._rto_state.rto_ms} ms; the "
                "SYN-RTO floor is not being enforced."
            ),
        )

    def test__rto__post_clean_handshake_no_syn_retransmit_skips_3000ms_floor(self) -> None:
        """
        Regression guard: when the SYN was NOT retransmitted
        (peer's SYN+ACK arrives before any SYN-RTO timer fires),
        the RFC 6298 §5.7 second-clause floor does NOT apply.
        '_rto_state.rto_ms' is whatever the canonical SRTT /
        RTTVAR estimator yields - typically 1000 ms via the
        MIN_RTO_MS clamp.

        This pins the negative case so the §5.7 fix above
        cannot accidentally penalise clean (retransmit-free)
        handshakes.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        # Peer's SYN+ACK arrives within the initial RTO window;
        # no SYN retransmit fires.
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup invariant: clean handshake reaches ESTABLISHED.",
        )
        self.assertEqual(
            session._retransmit_count,
            0,
            msg=(
                "Setup invariant: no SYN retransmit fired before peer's "
                f"SYN+ACK; _retransmit_count must be 0. Got "
                f"{session._retransmit_count}."
            ),
        )
        self.assertLess(
            session._rto_state.rto_ms,
            3000,
            msg=(
                "RFC 6298 §5.7: the 3-second floor applies ONLY when "
                "the SYN was retransmitted. A clean handshake's "
                "post-handshake '_rto_state.rto_ms' MUST be the "
                "canonical estimator output (typically 1000 ms via "
                f"MIN_RTO_MS), NOT 3000 ms. Got "
                f"_rto_state.rto_ms={session._rto_state.rto_ms} ms."
            ),
        )
