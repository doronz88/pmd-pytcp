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
This module contains integration tests for the TCP retransmit-on-
timeout (RTO) machinery in the 'TcpSession' state machine, covering
exponential back-off cadence per RFC 6298 §2 and the connection-
abort timeout per RFC 1122 §4.2.3.5 R2 / RFC 9293 §3.8.3.

The tests in this file drive a session through the active-open
handshake to ESTABLISHED, send a full-MSS data segment, then keep
the peer silent so the retransmit timer can drive its full cadence
of probes. Assertions cover both the wire shape of each retransmit
(same seq, same payload, ACK-only flags) and the count / timing of
transmissions across the full RTO window.

Reference RFCs:
    RFC 6298 §2          Computing TCP's Retransmission Timer
    RFC 9293 §3.8.3      User Timeout / connection abort
    RFC 1122 §4.2.3.5    R1 / R2 retransmission limits

pytcp/tests/integration/socket/test__socket__tcp__session__data_transfer__retransmit_timeout.py

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

# Initial sequence numbers chosen well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN+ACK reply.
PEER__MSS: int = 1460


class TestTcpDataTransfer__RetransmitTimeout(TcpSessionTestCase):
    """
    Integration tests for the RTO retransmit machinery: cadence,
    payload preservation, and connection-abort timing.
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

    def test__retransmit_timeout__silent_peer_retransmits_per_rfc6298_cadence(self) -> None:
        """
        Ensure that when an in-flight data segment goes unacknowledged
        the retransmit timer fires per RFC 6298 §2 with exponential
        back-off (initial RTO = 1 s, doubled per retry), and the
        connection stays alive past the RFC 1122 §4.2.3.5 R2 floor of
        100 s before any abort is considered:

            "(2.1) Until a round-trip time (RTT) measurement has been
                   made for a segment sent between the sender and
                   receiver, the sender SHOULD set RTO <- 1 second ...
             (5.5) The host MUST set RTO <- RTO * 2 (\"back off the
                   timer\")."

            "(R2) ... the value of the timeout that should cause a
                  TCP to give up ... at least 100 seconds."

        Concretely, with the initial RTO of 1 s and exponential
        doubling, a silent peer must see retransmits at approximately
        the following times after the initial transmission:

            t =   1 s    1st retransmit
            t =   3 s    2nd retransmit (RTO -> 2 s)
            t =   7 s    3rd retransmit (RTO -> 4 s)
            t =  15 s    4th retransmit (RTO -> 8 s)
            t =  31 s    5th retransmit (RTO -> 16 s)
            t =  63 s    6th retransmit (RTO -> 32 s)

        i.e. by t = 60 s of peer silence we must have observed at
        least five retransmits (initial + retransmits at 1, 3, 7,
        15, 31 s, with the 63 s one not yet fired). Each retransmit
        must reuse the original SEQ and payload byte-for-byte
        (RFC 6298 §2 retransmits the SAME segment, not a fresh one)
        and the session must remain in ESTABLISHED throughout - only
        after the R2 floor (>= 100 s) elapses may the implementation
        consider abort.

        Scenario:

            * Drive handshake to ESTABLISHED. Pre-set '_snd_ewn' to
              peer's advertised window so slow-start does not
              constrain the initial transmission.
            * Application sends one full-MSS data segment (1460 B,
              all 'X'). Full MSS bypasses Nagle entirely so no
              partial-segment deferral interferes with the cadence.
            * Tick once - the initial segment fires.
            * Drive 60 s of virtual time with the peer staying silent.
            * Inspect the captured TX list:
                - Every frame is a retransmit of the same seq /
                  payload as the initial.
                - Frame count >= 5 (the cadence above).
                - 'session.state' remains ESTABLISHED.
                - 'session._snd_una' is unchanged (no peer ACK has
                  arrived).

        This test passes on current code thanks to the
        'PACKET_RETRANSMIT_MAX_COUNT = 6' constant set by commit
        'efb8343' (which raised the limit from 3 to 6 to satisfy R2).
        It serves as a positive-control regression guard against
        future changes that might:

          - Lower the retransmit count below the R2 floor.
          - Skip back-off doubling (each retransmit at fixed RTO).
          - Mutate the seq or payload across retransmits.
          - Trigger a premature abort (state transition out of
            ESTABLISHED before R2).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._snd_ewn = PEER__WIN

        payload = b"X" * 1460
        session.send(data=payload)

        # Initial transmission on the next tick.
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup precondition: initial data segment must fire on the first tick.",
        )
        initial_seg = self._parse_tx(initial_tx[0])
        self.assertEqual(
            initial_seg.payload,
            payload,
            msg="Initial segment payload must equal what 'send()' was called with.",
        )
        self.assertEqual(
            initial_seg.seq,
            LOCAL__ISS + 1,
            msg="Initial segment seq must equal SND.NXT post-handshake.",
        )

        # Drive 60 seconds of virtual time with the peer silent. The
        # captured TX list will hold the initial-plus-retransmits
        # cadence.
        retransmits = self._advance(ms=60_000)

        # Per RFC 6298 doubling cadence (1, 3, 7, 15, 31 s within
        # 60 s), the retransmit count must be at least 5.
        self.assertGreaterEqual(
            len(retransmits),
            5,
            msg=(
                f"Within 60 s of peer silence, the RFC 6298 doubling "
                f"cadence (1, 3, 7, 15, 31 s) must produce at least 5 "
                f"retransmits. Got {len(retransmits)} - check the "
                "exponential-back-off arithmetic and "
                "PACKET_RETRANSMIT_MAX_COUNT."
            ),
        )

        # Each retransmit reuses the original SEQ and payload.
        for index, frame in enumerate(retransmits, start=1):
            probe = self._parse_tx(frame)
            self.assertEqual(
                probe.seq,
                initial_seg.seq,
                msg=(
                    f"Retransmit #{index} must reuse the original SEQ "
                    f"= 0x{initial_seg.seq:08x} per RFC 6298 §2 (same "
                    f"segment, not a fresh one). Got "
                    f"0x{probe.seq:08x}."
                ),
            )
            self.assertEqual(
                probe.payload,
                payload,
                msg=(
                    f"Retransmit #{index} must reuse the original "
                    f"payload byte-for-byte. Got "
                    f"{len(probe.payload)} bytes vs expected "
                    f"{len(payload)}."
                ),
            )
            self.assertEqual(
                probe.flags,
                frozenset({"PSH", "ACK"}),
                msg=(
                    f"Retransmit #{index} must carry the same flag set "
                    "as the original segment (PSH on the last segment "
                    "of the write, ACK piggyback)."
                ),
            )

        # Session remains alive past the R2 floor of 100 s. Within
        # the 60 s observation window, no abort is permissible.
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "After 60 s of silence, the session must still be in "
                "ESTABLISHED - RFC 1122 §4.2.3.5 R2 requires the abort "
                "timeout to be at least 100 s, well past the 60 s "
                "observation window."
            ),
        )
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1,
            msg=(
                "'_snd_una' must be unchanged - the peer has not ACK'd "
                "any of our data so the send sequence space remains "
                "frozen at the initial SND.NXT."
            ),
        )

    def test__retransmit_timeout__peer_ack_mid_back_off_clears_counters_and_grows_window(self) -> None:
        """
        Ensure that when a peer ACK arrives in the middle of the
        retransmit back-off window, the receiver-side bookkeeping
        unwinds cleanly:

            * The retransmit-timeout counter for the now-acknowledged
              SEQ is purged from '_tx_retransmit_timeout_counter', so
              subsequent expirations of the still-pending timer are
              silently ignored.
            * 'SND.UNA' advances past the acknowledged data, freeing
              the corresponding range of the TX buffer.
            * '_snd_ewn' doubles (slow-start growth per RFC 5681 §3.1
              and the simplified slow-start-style logic in
              '_process_ack_packet'), restoring sending capacity that
              the retransmit-timeout reset had collapsed back to one
              MSS.
            * No spurious retransmits fire on subsequent ticks - the
              session has nothing to retransmit and the cleared
              counter prevents the still-armed timer from re-entering
              the abort logic.

        Scenario:

            1. Drive handshake to ESTABLISHED. Pre-set '_snd_ewn' to
               peer's full advertised window so the initial
               transmission goes out unconstrained.
            2. Application sends one full-MSS data segment (1460 B).
               Tick once - initial transmit fires.
            3. Advance ~1.5 s of virtual time. The first retransmit
               (RTO = 1 s after initial) fires inside this window.
               '_snd_ewn' is reset to MSS and
               '_tx_retransmit_timeout_counter[SND.UNA]' is bumped
               from 0 to 1.
            4. Snapshot pre-ACK state: counter present, '_snd_una'
               unchanged, '_snd_ewn' equal to MSS.
            5. Peer ACKs with ack = SND.NXT (= LOCAL__ISS + 1 + 1460),
               implicitly acknowledging both the initial transmit
               and the retransmit.
            6. Drive RX. '_process_ack_packet' runs and:
                 - advances 'SND.UNA' to LOCAL__ISS + 1 + 1460
                 - purges 'tx_retransmit_timeout_counter' entries
                   with seq < SND.UNA
                 - doubles '_snd_ewn'
            7. Advance an additional 10 s of virtual time. No TX may
               fire during this window - all retransmit state has
               been cleared and the TX buffer has been purged of
               acknowledged bytes.

        Side effects asserted:

            * 'tx_retransmit_timeout_counter' no longer contains the
              key 'LOCAL__ISS + 1'.
            * '_snd_una' equals 'LOCAL__ISS + 1 + 1460'.
            * '_snd_ewn' is strictly greater than the value it had
              after the retransmit reset (MSS = 1460).
            * 'len(_tx_buffer)' is zero (acknowledged bytes purged).
            * State remains ESTABLISHED throughout.

        This test passes on current code as a positive-control
        regression guard for '_process_ack_packet's counter-purge
        loop (and the per-tick ACK doubling of '_snd_ewn'). A
        future change that removed the purge or skipped the slow-
        start growth would be caught immediately - the post-ACK
        retransmit timer would still fire (counter not cleared) or
        the connection would stay throttled at one-MSS bursts.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._snd_ewn = PEER__WIN

        payload = b"X" * 1460
        session.send(data=payload)

        # Initial transmission.
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup precondition: initial data segment must fire on the first tick.",
        )

        # Advance past the first retransmit boundary (RTO = 1 s after
        # initial). Within this window the first retransmit fires and
        # '_snd_ewn' collapses back to one MSS.
        retransmit_window_tx = self._advance(ms=1500)
        self.assertGreaterEqual(
            len(retransmit_window_tx),
            1,
            msg=(
                "Setup precondition: the first retransmit must fire "
                "within 1500 ms of the initial transmission "
                "(RTO = 1 s + tick latency)."
            ),
        )

        # Snapshot pre-ACK state.
        self.assertIn(
            LOCAL__ISS + 1,
            session._tx_retransmit_timeout_counter,
            msg=(
                "Pre-ACK precondition: the retransmit-timeout counter "
                "for SND.UNA must be present after the first retransmit "
                "fired."
            ),
        )
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1,
            msg="Pre-ACK precondition: SND.UNA must still be at the initial ISS+1.",
        )
        snd_ewn_before_ack = session._snd_ewn
        self.assertEqual(
            snd_ewn_before_ack,
            session._snd_mss,
            msg=(
                "Pre-ACK precondition: '_snd_ewn' must be back at one "
                "MSS after the retransmit-timeout reset collapsed it."
            ),
        )

        # Peer ACKs the data, covering both the initial transmit and
        # any retransmits.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertNotIn(
            LOCAL__ISS + 1,
            session._tx_retransmit_timeout_counter,
            msg=(
                "After the ACK arrives, the retransmit-timeout counter "
                "for the acknowledged SEQ must be purged from "
                "'_tx_retransmit_timeout_counter' so the still-armed "
                "stack-timer entry is silently ignored on its next "
                "expiry."
            ),
        )
        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1 + len(payload),
            msg=("'SND.UNA' must advance past the acknowledged data " "after the peer ACK is processed."),
        )
        self.assertGreater(
            session._snd_ewn,
            snd_ewn_before_ack,
            msg=(
                "'_snd_ewn' must grow on a successful ACK "
                "(slow-start-style doubling per "
                "'_process_ack_packet') - the retransmit-timeout "
                "reset had collapsed it back to one MSS."
            ),
        )
        self.assertEqual(
            len(session._tx_buffer),
            0,
            msg=("The TX buffer must be empty after the peer ACKs all " "outstanding data."),
        )

        # Advance an additional 10 s of virtual time. The cleared
        # retransmit-timeout counter must prevent any spurious
        # retransmits even though the stack-level timer entry may
        # still be in 'stack.timer._timers' counting down.
        silent_window_tx = self._advance(ms=10_000)
        self.assertEqual(
            silent_window_tx,
            [],
            msg=(
                "After the peer ACK clears the retransmit state, NO "
                "further TX may fire on subsequent ticks - the TX "
                "buffer is empty and the counter purge has neutered "
                "the still-armed stack timer."
            ),
        )

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="The peer ACK must leave the session in ESTABLISHED.",
        )

    def test__retransmit_timeout__fin_wait_1_timer_retransmits_fin_not_data(self) -> None:
        """
        Ensure that once a session has transitioned to FIN_WAIT_1
        (because the application called 'close()' and the TX buffer
        had drained), subsequent retransmit-timer expirations
        retransmit ONLY the FIN segment - they MUST NOT re-send any
        data segments at sequence numbers that have already been
        acknowledged or that lie past the FIN.

        Per RFC 9293 §3.10.4 / §3.5.2 the FIN_WAIT_1 state means we
        have sent our FIN and are awaiting the peer's ACK of it. Any
        prior data has by definition been fully acknowledged before
        we issued FIN (the ESTABLISHED -> FIN_WAIT_1 transition is
        gated on '_closing AND not _tx_buffer'). Retransmitting data
        in this state would reuse SEQ numbers the peer has already
        ACK'd, confuse the cumulative-ACK arithmetic, and risk
        sliding past the right edge of the peer's receive window if
        their FIN-ACK has trimmed the window down.

        Scenario:

            1. Drive handshake to ESTABLISHED. Pre-set '_snd_ewn' to
               peer's full window so the data goes out unconstrained.
            2. Application sends one full-MSS data segment. Tick
               once - initial transmit.
            3. Peer ACKs the data: '_snd_una' advances past the
               segment, the retransmit-timeout counter for the data
               SEQ is purged, and the TX buffer is drained.
            4. Application calls 'close()'. '_closing' is set; state
               is still ESTABLISHED.
            5. First tick after 'close()': '_tcp_fsm_established's
               timer branch runs '_transmit_data' (no-op, buffer
               empty), then sees '_closing AND not _tx_buffer' and
               transitions to FIN_WAIT_1. No segment is emitted on
               this tick.
            6. Second tick: '_tcp_fsm_fin_wait_1's timer branch runs
               '_transmit_data', which falls through the
               ESTABLISHED-only data block and hits the FIN-
               retransmit block ('SND.NXT != SND.FIN'). The FIN is
               emitted at SEQ = LOCAL__ISS + 1 + 1460.
            7. Drive 60 s of virtual time with the peer silent. The
               FIN's retransmit timer cycles through the RFC 6298
               cadence; every retransmit MUST be a FIN, not a data
               segment.

        Assertions on each retransmit:

            * 'FIN' in 'flags'.
            * 'payload == b""' (FIN-only, no data).
            * 'seq == LOCAL__ISS + 1 + 1460' (the original FIN's
              SEQ, not any data SEQ).

        Plus state assertions:

            * After step 5, 'session.state' is FsmState.FIN_WAIT_1.
            * After step 7 (60 s of silence), 'session.state' is
              still FsmState.FIN_WAIT_1 - well within the R2 floor.

        This test passes on current code as a positive-control
        regression guard. The plan's '[FLAGS BUG]' note about
        '_tcp_fsm_fin_wait_1' "calling '_transmit_data' on every
        tick - could retransmit data" is not actually realised
        today because '_transmit_data's data-emit block is gated on
        'state in {ESTABLISHED, CLOSE_WAIT}', so the FIN_WAIT_1
        timer path correctly falls through to the FIN-retransmit
        branch. The test serves as a regression guard against
        future changes that might widen the data-emit gate or split
        '_transmit_data' in a way that lets data leak into
        FIN_WAIT_1's retransmit path.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._snd_ewn = PEER__WIN

        payload = b"X" * 1460
        session.send(data=payload)

        # Initial transmit.
        self._advance(ms=1)

        # Peer ACKs the data.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._snd_una,
            LOCAL__ISS + 1 + len(payload),
            msg="Setup precondition: peer's ACK must have advanced SND.UNA past the data.",
        )
        self.assertEqual(
            len(session._tx_buffer),
            0,
            msg="Setup precondition: TX buffer must be empty after the data is acknowledged.",
        )

        # Application closes the connection.
        session.close()
        self.assertTrue(
            session._closing,
            msg="Setup precondition: 'close()' must set the '_closing' flag.",
        )

        # First tick after 'close()': state transitions to FIN_WAIT_1
        # because the TX buffer is empty. No segment fires on this tick.
        transition_tx = self._advance(ms=1)
        self.assertEqual(
            transition_tx,
            [],
            msg=(
                "The ESTABLISHED -> FIN_WAIT_1 transition tick must "
                "not emit any segment (the FIN fires on the next tick "
                "via the FIN_WAIT_1 timer handler)."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg=(
                "After the transition tick, state must be FIN_WAIT_1 "
                "('_closing AND not _tx_buffer' triggers the "
                "transition)."
            ),
        )

        # Second tick: FIN_WAIT_1's timer handler emits the FIN.
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg=(
                "The first FIN_WAIT_1 timer tick must emit exactly one "
                "outbound FIN segment via '_transmit_data's "
                "FIN-retransmit block."
            ),
        )
        fin_seg = self._parse_tx(fin_tx[0])
        self.assertIn(
            "FIN",
            fin_seg.flags,
            msg="The first outbound segment in FIN_WAIT_1 must carry the FIN flag.",
        )
        self.assertEqual(
            fin_seg.payload,
            b"",
            msg="The FIN must carry no application payload.",
        )
        fin_seq = fin_seg.seq

        # Drive 60 s of virtual time with the peer silent. The FIN's
        # retransmit timer cycles through RFC 6298 doubling. Capture
        # all retransmits and verify each is a FIN, not data.
        retransmits = self._advance(ms=60_000)

        self.assertGreaterEqual(
            len(retransmits),
            4,
            msg=(
                "Within 60 s of peer silence, the RFC 6298 doubling "
                "cadence (1, 3, 7, 15, 31 s after the initial FIN) "
                f"must produce at least 4 FIN retransmits. Got "
                f"{len(retransmits)}."
            ),
        )

        for index, frame in enumerate(retransmits, start=1):
            probe = self._parse_tx(frame)
            self.assertIn(
                "FIN",
                probe.flags,
                msg=(
                    f"Retransmit #{index} in FIN_WAIT_1 must carry FIN "
                    "flag - retransmitting a data segment here would "
                    "reuse already-acknowledged SEQ space and violate "
                    "RFC 9293 §3.10.4."
                ),
            )
            self.assertEqual(
                probe.payload,
                b"",
                msg=(
                    f"Retransmit #{index} in FIN_WAIT_1 must carry no "
                    "payload - the FIN is a control segment, and any "
                    "data byte would risk re-sending data the peer "
                    "has already acknowledged."
                ),
            )
            self.assertEqual(
                probe.seq,
                fin_seq,
                msg=(
                    f"Retransmit #{index} in FIN_WAIT_1 must reuse the "
                    f"original FIN's SEQ ({fin_seq:#x}). A different "
                    "SEQ would indicate either data leakage from the "
                    "ESTABLISHED-state transmit block or post-FIN "
                    "sequence drift."
                ),
            )

        # Session must still be in FIN_WAIT_1 after 60 s - well
        # within the R2 floor.
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg=("After 60 s of silent retransmits, the session must " "still be in FIN_WAIT_1 (R2 = 100 s minimum)."),
        )

    def test__retransmit_timeout__sub_mss_partial_segment_retransmits_despite_nagle(self) -> None:
        """
        Ensure that when an in-flight sub-MSS ("partial") segment
        goes unacknowledged the RTO retransmits it on the timer
        boundary, even though Nagle's Minshall variant
        (RFC 1122 §4.2.3.4) ordinarily defers a fresh partial
        while a previous partial is still in flight. RFC 1122
        §4.2.3.4 governs FRESH transmits to avoid generating
        tinygrams when a stream of small writes accumulates; it
        does NOT apply to retransmits, which are by definition
        re-sending the very same partial that is "in flight".

        RFC 1122 §4.2.3.4 (Sender's SWS Avoidance / Nagle):

            "[The sender] SHOULD NOT send small segments if there
             is unacknowledged data."

        and §4.2.3.4 explanatory text on "send" being the
        application-driven generation:

            "[The Nagle algorithm] solves the small-packet
             problem by delaying transmission ... when the user
             passes data to TCP, TCP will ... wait until either
             one MSS of data ... or all unacknowledged data has
             been ACKed."

        RFC 6298 (RTO retransmission) does NOT defer to Nagle:
        the retransmit machinery re-sends "the earliest segment
        that has not been acknowledged" once the RTO timer
        fires, regardless of segment size or Nagle state.

        [FLAGS BUG] - 'TcpSession._transmit_data' applies the
        Nagle gate (line ~1183) unconditionally before any
        outbound segment, including RTO-driven retransmits:

            is_partial = transmit_data_len < self._snd_mss
            prev_partial_in_flight = gt32(self._snd_sml, self._snd_una)
            if is_partial and prev_partial_in_flight:
                return  # defer

        On RTO retransmit:

          - '_retransmit_packet_timeout' rewinds 'SND.NXT' to
            'SND.UNA' (= the partial we want to re-send).
          - Control falls through to '_transmit_data' on the
            same FSM tick.
          - 'is_partial' is True (the segment IS a partial -
            we're retransmitting the original partial).
          - 'prev_partial_in_flight = gt32(_snd_sml, _snd_una)'
            is True (the partial we sent originally is still in
            flight - that's why we're retransmitting).
          - Nagle defers.

        The retransmit counter ('_tx_retransmit_timeout_counter')
        only increments inside '_transmit_packet', which never
        runs because the deferral exits '_transmit_data' before
        reaching it. The RFC 1122 §4.2.3.5 R2 floor (=
        'PACKET_RETRANSMIT_MAX_COUNT') is therefore never
        reached either. The connection HANGS indefinitely until
        an external timeout kills it.

        Severity: HIGH. Affects every connection that loses an
        unacked sub-MSS segment - typical for interactive
        traffic (SSH keystrokes, RPC control messages, HTTP
        chunked headers, partial database commits). Not a
        seq-wrap-rare class; this is everyday workload.

        Fix outline (separate commit):

            Detect "we are retransmitting" via a modular check:
            'lt32(self._snd_nxt, self._snd_max)'. The RTO
            handler rewinds 'SND.NXT' to 'SND.UNA' while
            leaving 'SND.MAX' at the high-water mark, so this
            inequality is True iff the next segment to send
            covers ground we have already transmitted. Skip
            the Nagle gate when retransmitting:

                is_retransmit = lt32(self._snd_nxt, self._snd_max)
                ...
                if is_partial and prev_partial_in_flight and not is_retransmit:
                    return  # defer

        Scenario:

            1. Drive handshake to ESTABLISHED. Pre-set
               '_snd_ewn' to peer's advertised window so
               slow-start does not constrain the initial send.
            2. Application sends 100 bytes (sub-MSS partial).
               One outbound segment with seq = ISS + 1, payload
               b"X" * 100.
            3. Peer stays silent. Wait
               'PACKET_RETRANSMIT_TIMEOUT' (1 s) plus a tick
               for the boundary.
            4. The RTO MUST fire and the segment MUST be
               retransmitted byte-for-byte at the same seq.

        Assertions:

            * Initial send produces exactly one segment
              (sanity).
            * After the RTO advance: exactly one retransmit
              segment is captured, with matching seq/payload.
            * Session is still in ESTABLISHED.

        On current code this test fails at the retransmit
        segment-count assertion: zero retransmits emitted
        because the Nagle gate defers, the retransmit counter
        does not increment, R2 is never reached, and the
        connection is silently stuck.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Bypass slow-start so the partial fires on the first tick.
        session._snd_ewn = PEER__WIN

        # Step 2: send a 100-byte sub-MSS partial.
        partial_payload = b"X" * 100
        session.send(data=partial_payload)
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup precondition: initial send must produce exactly one outbound segment.",
        )
        initial_probe = self._parse_tx(initial_tx[0])
        self._assert_segment(
            initial_probe,
            seq=LOCAL__ISS + 1,
            payload=partial_payload,
        )

        # Step 3: peer stays silent. Advance past the initial RTO.
        # 'PACKET_RETRANSMIT_TIMEOUT' is 1000 ms (the initial
        # RTO); +1 ms past the boundary so the timer fires on
        # the boundary tick.
        retransmit_tx = self._advance(ms=PACKET_RETRANSMIT_TIMEOUT + 1)
        retransmit_segments = [self._parse_tx(frame) for frame in retransmit_tx]

        # Step 4: the RTO MUST fire one retransmit. Today the
        # Nagle gate defers and zero retransmits emit.
        self.assertEqual(
            len(retransmit_segments),
            1,
            msg=(
                "After the RTO timer expires on a sub-MSS partial "
                "in flight, exactly one retransmit segment MUST be "
                "emitted carrying the same seq and payload as the "
                "original. Today '_transmit_data's Nagle gate "
                "(RFC 1122 §4.2.3.4 Minshall variant) treats the "
                "RTO retransmit identically to a fresh partial "
                "transmit, observes 'prev_partial_in_flight=True' "
                "(the partial we are retransmitting IS still in "
                "flight), and defers indefinitely. The retransmit "
                "counter never increments, R2 is never reached, "
                "and the connection is silently stuck. Affects "
                "every interactive workload that drops a sub-MSS "
                f"segment. Got: {retransmit_segments!r}"
            ),
        )
        self._assert_segment(
            retransmit_segments[0],
            seq=LOCAL__ISS + 1,
            payload=partial_payload,
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Session must remain ESTABLISHED through the RTO retransmit.",
        )

    def test__retransmit_timeout__rto_with_peer_zero_window_respects_flow_control(self) -> None:
        """
        Ensure that when an RTO fires while peer has advertised
        a 0-window, the retransmit path respects peer's flow-
        control: '_snd_ewn' must collapse to 0 (clamped to
        '_snd_wnd'), and no MSS-sized data segment must hit the
        wire. The persist machinery handles probing while the
        window is closed (RFC 9293 §3.8.6.1 / RFC 1122
        §4.2.2.17).

        RFC 9293 §3.8.6.1 (Zero-Window Probing):

            "The transmitting host SHOULD send the first
             zero-window probe when a zero window has existed
             for the retransmission timeout period ... and
             SHOULD increase exponentially the interval between
             successive probes."

        RFC 1122 §4.2.2.16 (right-edge of window):

            "[The TCP sender] MUST be robust against window
             shrinking, which may cause the 'usable window' ...
             to become negative."

        Both RFCs implicitly require the sender to respect the
        receiver's advertised window across retransmits. The
        RTO mechanism does NOT exempt itself from this
        constraint; RFC 6298 §5 (retransmit) does not say "send
        regardless of window."

        [FLAGS BUG] - 'TcpSession._retransmit_packet_timeout'
        line 1378-1380:

            self._snd_ewn = self._snd_mss
            self._snd_nxt = self._snd_una

        '_snd_ewn = self._snd_mss' is unconditional. It does
        NOT clamp to '_snd_wnd'. If peer advertised a 0-window
        before this RTO fired (typical when peer's app is slow
        to drain their receive buffer), the post-RTO
        'transmit_data_len = min(MSS, _snd_ewn=MSS,
        remaining)' computes as a positive number; the
        retransmit then sends data despite peer's
        flow-control restriction.

        Severity: MEDIUM. Real RFC-conformance gap. Fires on
        every RTO that occurs while peer's window is 0.
        Probability is non-trivial in workloads where peer's
        application is slow.

        Fix outline (separate commit):

            self._snd_ewn = min(self._snd_mss, self._snd_wnd)
            self._snd_nxt = self._snd_una

        Post-fix the RTO + 0-window scenario flows like:

          - RTO: '_snd_ewn = min(MSS, 0) = 0'.
          - '_transmit_data' sees 'transmit_data_len = 0' and
            falls to the persist branch, which arms the
            persist timer; no data segment goes out.
          - Persist machinery handles probing as designed
            (RFC 9293 §3.8.6.1).

        Scenario:

            1. Drive handshake to ESTABLISHED. Bypass
               slow-start by setting '_snd_ewn = PEER__WIN' so
               the initial send fires at full MSS (or as much
               as we ask).
            2. send(b"X" * 100). One outbound segment fires at
               seq = LOCAL__ISS + 1.
            3. Simulate peer advertising 0-window AFTER we
               sent. We set 'session._snd_wnd = 0' and
               'session._snd_ewn = 0' directly because the
               '_process_ack_packet' path for an ACK that
               doesn't advance SND.UNA gets intercepted by
               ESTABLISHED's dup-ACK branch (which doesn't
               update '_snd_wnd'). The state-direct setup is
               equivalent to peer's "ACK with new-data + win=0"
               having been processed.
            4. Advance past 'PACKET_RETRANSMIT_TIMEOUT' so the
               RTO timer for our unacked segment fires.

        Assertions:

            * Post-RTO 'session._snd_ewn == 0' (clamped to
              peer's 0-window).
            * No data-bearing outbound segment fires during
              the RTO advance window. Pre-fix the test would
              see a 100-byte retransmit emitted in violation
              of peer's flow-control.

        On current code this test fails at the assertion that
        no data-bearing segment fires - one 100-byte segment
        gets emitted post-RTO despite peer's 0-window.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Bypass slow-start so the initial send fires at full MSS.
        session._snd_ewn = PEER__WIN

        # Step 2: send 100 bytes. One segment fires.
        payload = b"X" * 100
        session.send(data=payload)
        initial_tx = self._advance(ms=1)
        self.assertEqual(
            len(initial_tx),
            1,
            msg="Setup precondition: initial send must produce one outbound segment.",
        )

        # Step 3: simulate peer's 0-window state. State-direct
        # because the ACK-only "ack==SND.UNA + win=0" frame would
        # be intercepted by ESTABLISHED's dup-ACK branch which
        # doesn't update '_snd_wnd'. This is equivalent to peer
        # having processed a fresh ACK that advances SND.UNA AND
        # advertises win=0.
        session._snd_wnd = 0
        session._snd_ewn = 0

        # Step 4: advance past PACKET_RETRANSMIT_TIMEOUT so the
        # RTO timer for the unacked segment fires.
        rto_tx = self._advance(ms=PACKET_RETRANSMIT_TIMEOUT + 1)

        # Spec: post-RTO '_snd_ewn' must reflect peer's 0-window.
        self.assertEqual(
            session._snd_ewn,
            0,
            msg=(
                "After RTO with peer's 0-window, '_snd_ewn' MUST "
                "be 0 (clamped to '_snd_wnd'). Today "
                "'_retransmit_packet_timeout' sets '_snd_ewn = "
                "self._snd_mss' unconditionally, ignoring peer's "
                "advertised window. Fix: clamp via "
                "'_snd_ewn = min(self._snd_mss, self._snd_wnd)'."
            ),
        )

        # Spec: no data-bearing segment fires; persist machinery
        # handles probing once the window is closed. (Persist
        # probes are 1-byte and may or may not fire depending on
        # exact timing; we assert no MSS-class data segment.)
        rto_segments = [self._parse_tx(frame) for frame in rto_tx]
        data_segments = [seg for seg in rto_segments if len(seg.payload) > 1]
        self.assertEqual(
            data_segments,
            [],
            msg=(
                "After RTO with peer's 0-window, NO data-bearing "
                "segment larger than 1 byte may be emitted - peer's "
                "advertised window forbids it (RFC 9293 §3.8.6.1 / "
                "RFC 1122 §4.2.2.16). Today the RTO retransmit "
                "fires a full 100-byte segment in violation of "
                f"peer's flow-control. Got: {data_segments!r}"
            ),
        )

    def test__retransmit_timeout__fin_retransmit_does_not_drift_tx_buffer_seq_mod(self) -> None:
        """
        Ensure that retransmitting the FIN segment after RTO leaves
        '_tx_buffer_seq_mod' unchanged. The FIN consumes one byte of
        sequence space but no slot in the TX buffer; on the original
        send '_transmit_packet' bumps '_tx_buffer_seq_mod' by 1 to
        account for that phantom byte. On every subsequent retransmit
        the same bump fires again, so '_retransmit_packet_timeout'
        MUST walk the anchor back by 1 BEFORE the retransmit-driven
        '_transmit_data' call to keep '_tx_buffer_seq_mod' aligned
        with the post-original-FIN value across the entire
        retransmit cycle.

        Per RFC 9293 §3.4 sequence numbers are 32-bit modular and
        every TX-side anchor MUST stay aligned with 'SND.NXT' minus
        unsent-buffer offset; otherwise the next 'send()' or
        retransmit reads the wrong slice of '_tx_buffer'.

        [FLAGS BUG] - 'TcpSession._retransmit_packet_timeout' line
        ~1448:

            if self._snd_nxt == self._snd_ini or (
                self._fin_sent and self._snd_nxt == self._snd_fin
            ):
                self._tx_buffer_seq_mod = sub32(self._tx_buffer_seq_mod, 1)

        '_snd_fin' is assigned at '_transmit_packet' line ~853 AFTER
        'self._snd_nxt = add32(seq, len(data), flag_syn, flag_fin)'
        has already advanced past the FIN's seq, so '_snd_fin =
        post-FIN-seq = FIN_seq + 1'. After RTO the rewind line ~1426
        sets '_snd_nxt = _snd_una', and on the canonical "FIN went
        out, peer ACKed everything before it but not the FIN" path
        '_snd_una == FIN_seq == _snd_fin - 1'. The check
        'self._snd_nxt == self._snd_fin' is therefore ALWAYS False
        in the path it was meant to catch - the second branch is
        unreachable. The walk-back never fires and the next
        '_transmit_packet' (FIN retransmit) re-bumps
        '_tx_buffer_seq_mod' by 1 without compensation. Each
        subsequent retransmit drifts by another +1.

        Severity: LOW in current usage. FIN_WAIT_1 / LAST_ACK only
        reach '_transmit_data' with an empty TX buffer, so the
        corrupted offset is not read for new content, and modular
        'add32' / 'sub32' arithmetic recovers the anchor when the
        peer eventually ACKs the FIN. But the invariant is still
        broken; a future change that writes to '_tx_buffer' from
        FIN_WAIT_1 / LAST_ACK (or that introduces a half-duplex
        path where post-FIN data could be queued) would silently
        corrupt the read offset. The dead-code branch also
        misleads anyone reading the rewind logic.

        Fix outline (separate commit):

            Compare against the FIN's seq (pre-bump), not
            post-FIN-seq:

                if self._snd_nxt == self._snd_ini or (
                    self._fin_sent
                    and self._snd_nxt == sub32(self._snd_fin, 1)
                ):
                    self._tx_buffer_seq_mod = sub32(self._tx_buffer_seq_mod, 1)

            After rewind, 'self._snd_nxt == _snd_una == FIN_seq ==
            sub32(_snd_fin, 1)' - the branch fires, the anchor walks
            back by 1, and the post-retransmit '_tx_buffer_seq_mod'
            stays at its post-original-FIN value across the entire
            retransmit cycle.

        Scenario:

            1. Drive handshake to ESTABLISHED.
            2. 'close()' with an empty TX buffer. First tick
               transitions to FIN_WAIT_1; second tick emits the FIN.
            3. Snapshot '_tx_buffer_seq_mod' immediately after the
               original FIN sent.
            4. Drive three RTO cycles (1 s, 3 s, 7 s of cumulative
               virtual time) with the peer silent. Each cycle MUST
               emit exactly one FIN retransmit at the original
               FIN's seq.
            5. After each retransmit, '_tx_buffer_seq_mod' MUST
               equal the snapshot value taken in step 3.

        On current code the snapshot-equality assertion fails: the
        anchor drifts by +1 per retransmit (1 -> 2 -> 3).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Empty TX buffer; close immediately.
        session.close()
        # First tick: ESTABLISHED -> FIN_WAIT_1 (no segment emitted).
        self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="Setup precondition: empty-buffer close transitions to FIN_WAIT_1 on the first tick.",
        )
        # Second tick: FIN emitted by the FIN_WAIT_1 timer branch.
        fin_tx = self._advance(ms=1)
        self.assertEqual(
            len(fin_tx),
            1,
            msg="Setup precondition: the FIN_WAIT_1 timer tick after close() must emit exactly one FIN.",
        )
        original_fin = self._parse_tx(fin_tx[0])
        self.assertIn(
            "FIN",
            original_fin.flags,
            msg="Setup precondition: the segment emitted in step 2 must carry the FIN flag.",
        )

        # Snapshot the post-original-FIN anchor. This is the value
        # every subsequent retransmit MUST preserve.
        baseline_seq_mod = session._tx_buffer_seq_mod

        # Drive three RTO cycles with the peer silent. Cumulative
        # delays: 1 s, 1+2=3 s, 1+2+4=7 s. We advance a small
        # margin past each boundary so the timer fires.
        for cycle, cumulative_ms in enumerate((1_000, 3_000, 7_000), start=1):
            already_advanced_ms = (0, 1_000, 3_000)[cycle - 1]
            delta_ms = cumulative_ms - already_advanced_ms + 1
            retransmits = self._advance(ms=delta_ms)
            self.assertEqual(
                len(retransmits),
                1,
                msg=(
                    f"RTO cycle #{cycle}: the FIN_WAIT_1 retransmit "
                    f"machinery MUST emit exactly one FIN retransmit "
                    f"per cycle. Got {len(retransmits)}."
                ),
            )
            probe = self._parse_tx(retransmits[0])
            self.assertEqual(
                probe.seq,
                original_fin.seq,
                msg=(
                    f"RTO cycle #{cycle}: the FIN retransmit MUST "
                    f"reuse the original FIN's seq "
                    f"(0x{original_fin.seq:08x}). A different seq "
                    f"would indicate post-FIN sequence drift. "
                    f"Got 0x{probe.seq:08x}."
                ),
            )
            self.assertEqual(
                session._tx_buffer_seq_mod,
                baseline_seq_mod,
                msg=(
                    f"RTO cycle #{cycle}: '_tx_buffer_seq_mod' MUST "
                    f"equal its post-original-FIN value "
                    f"(0x{baseline_seq_mod:08x}). Today the rewind "
                    f"check 'self._snd_nxt == self._snd_fin' in "
                    f"'_retransmit_packet_timeout' is unreachable "
                    f"because '_snd_fin' holds post-FIN-seq while "
                    f"the rewind sets '_snd_nxt = _snd_una = "
                    f"FIN_seq = _snd_fin - 1'; the walk-back never "
                    f"fires and the next '_transmit_packet' "
                    f"re-bumps '_tx_buffer_seq_mod' by 1 per "
                    f"retransmit. Got 0x{session._tx_buffer_seq_mod:08x} "
                    f"(drift "
                    f"+{(session._tx_buffer_seq_mod - baseline_seq_mod) & 0xFFFFFFFF})."
                ),
            )
