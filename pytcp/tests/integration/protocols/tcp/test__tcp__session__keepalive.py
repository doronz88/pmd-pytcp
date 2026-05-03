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
This module contains integration tests for the TCP keep-alive
mechanism per RFC 1122 §4.2.3.6.

RFC 1122 §4.2.3.6 mandates four behavioural invariants:
    1. The keep-alive mechanism MUST default to OFF.
    2. The application MUST be able to enable / disable keep-alive
       per-connection (in PyTCP, via 'TcpSession._keepalive_enabled').
    3. The keep-alive idle timer MUST default to no less than 2 h
       (the constant 'KEEPALIVE_IDLE_TIME = 7_200_000' satisfies this
       at the implementation level; tests patch it to small values).
    4. After the idle timer expires, the implementation emits a
       probe ('ACK' with 'SEG.SEQ = SND.NXT - 1' so peer's TCP
       responds with an ACK at the current SND.NXT without
       delivering any segment text to peer's application). On
       probe-ack the idle timer is rearmed; on lack of response the
       probe is retransmitted every 'KEEPALIVE_PROBE_INTERVAL', and
       after 'KEEPALIVE_PROBE_MAX_COUNT' unanswered probes the
       connection is declared dead.

The tests in this file are tests-first against the planned
implementation: scenario 1 is a positive-control regression guard
that passes today (no probe emission with the flag default OFF),
and scenarios 2-6 are '[FLAGS BUG]' failures that the fix commits
will flip green.

Reference RFCs:
    RFC 1122 §4.2.3.6   TCP keep-alive
    RFC 9293 §3.8.4     references and defers to RFC 1122

pytcp/tests/integration/protocols/tcp/test__tcp__session__keepalive.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.tcp__constants import DELAYED_ACK_DELAY
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

# Peer's MSS option value on its SYN+ACK reply.
PEER__MSS: int = 1460

# Test-tunable keep-alive parameters. The production defaults
# (7200 s / 75 s / 9) are too coarse for unit-style integration
# tests; we patch them to small values so a full probe / tear-
# down cycle completes in a few hundred milliseconds of virtual
# time. The patched values are the SAME RFC-compliant shape -
# only the magnitudes change.
TEST__KEEPALIVE_IDLE_TIME_MS: int = 100
TEST__KEEPALIVE_PROBE_INTERVAL_MS: int = 50
TEST__KEEPALIVE_PROBE_MAX_COUNT: int = 3


class TestTcpKeepalive(TcpSessionTestCase):
    """
    Integration tests for the RFC 1122 §4.2.3.6 keep-alive
    mechanism: opt-in semantics, idle-timer arming, probe wire
    shape, probe-ack reset, exhaustion tear-down.
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

    def _patch_keepalive_constants(self) -> None:
        """
        Patch the production keep-alive constants to small test
        values so a full probe / tear-down cycle completes in a
        few hundred milliseconds of virtual time.
        """

        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.KEEPALIVE_IDLE_TIME",
            TEST__KEEPALIVE_IDLE_TIME_MS,
        )
        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.KEEPALIVE_PROBE_INTERVAL",
            TEST__KEEPALIVE_PROBE_INTERVAL_MS,
        )
        self._start_patch(
            "pytcp.protocols.tcp.tcp__constants.KEEPALIVE_PROBE_MAX_COUNT",
            TEST__KEEPALIVE_PROBE_MAX_COUNT,
        )

    def test__keepalive__disabled_by_default_no_probe_ever_fires(self) -> None:
        """
        Ensure RFC 1122 §4.2.3.6's "MUST default to off" invariant:
        a session that has not been opted in via
        '_keepalive_enabled = True' MUST NOT emit any keep-alive
        probe regardless of how long the connection sits idle.

            "If keep-alive are included, the application MUST be
             able to turn them on or off for each TCP connection,
             and they MUST default to off."

        Scenario:

            * Drive handshake to ESTABLISHED. Confirm the
              '_keepalive_enabled' default is False.
            * Patch the keep-alive constants to small test values
              so any spuriously-armed timer would fire well within
              the test window.
            * Advance virtual time by 5x the patched
              KEEPALIVE_IDLE_TIME with no peer activity.
            * Assert the captured TX list is empty - no keep-alive
              probe was emitted.
            * Assert state remains ESTABLISHED (no tear-down).

        This test passes today as a positive control / regression
        guard for the default-off invariant. It will continue to
        pass after the fix commits as long as the keep-alive
        machinery correctly gates on '_keepalive_enabled'.
        """

        self._patch_keepalive_constants()
        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        self.assertFalse(
            session._keepalive_enabled,
            msg="RFC 1122 §4.2.3.6: '_keepalive_enabled' MUST default to False.",
        )

        idle_tx = self._advance(ms=TEST__KEEPALIVE_IDLE_TIME_MS * 5)

        self.assertEqual(
            idle_tx,
            [],
            msg=(
                "RFC 1122 §4.2.3.6: a session with keep-alive disabled "
                "(default) MUST NOT emit any probe regardless of idle time."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="An idle keep-alive-disabled session must remain ESTABLISHED.",
        )

    def test__keepalive__enabled_idle_session_emits_probe_after_idle_time(self) -> None:
        """
        [FLAGS BUG]

        Ensure that when '_keepalive_enabled = True' and the
        connection has been idle (no inbound or outbound data) for
        'KEEPALIVE_IDLE_TIME', the session emits exactly one
        keep-alive probe per RFC 1122 §4.2.3.6.

            "An implementation SHOULD send a keep-alive segment
             with no data; however, it MAY be configurable to
             send a keep-alive segment containing one garbage
             octet, for compatibility with erroneous TCP
             implementations."

        Scenario:

            * Drive handshake to ESTABLISHED.
            * Set '_keepalive_enabled = True' (after handshake so
              the bilateral-negotiation paths are not affected; the
              flag is purely local).
            * Patch keep-alive constants to small test values.
            * Advance virtual time by exactly 'TEST__KEEPALIVE_IDLE_TIME_MS'
              with peer silent. Expect: zero TX during this window
              (timer not yet expired).
            * Advance one more ms past the boundary. Expect: exactly
              one keep-alive probe captured.
            * Assert state remains ESTABLISHED throughout.

        Current code: NO keep-alive timer is armed anywhere; the
        '_advance' calls observe zero TX through the full window.
        The test asserts that the boundary advance produces a
        probe, which fails.

        Fix outline: in TcpSession.__init__, when
        '_keepalive_enabled' transitions True (or unconditionally
        post-handshake, whichever the implementation chooses) arm
        a 'KEEPALIVE_IDLE_TIME'-ms timer named '<session>-keepalive'.
        On expiry emit a probe via '_transmit_packet' with
        'flag_ack=True, seq=SND.NXT - 1' and re-arm the timer with
        'KEEPALIVE_PROBE_INTERVAL'.
        """

        self._patch_keepalive_constants()
        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._keepalive_enabled = True

        # Pre-boundary advance: the idle timer should NOT yet fire.
        pre_boundary_tx = self._advance(ms=TEST__KEEPALIVE_IDLE_TIME_MS - 1)
        self.assertEqual(
            pre_boundary_tx,
            [],
            msg=(
                f"RFC 1122 §4.2.3.6: in the {TEST__KEEPALIVE_IDLE_TIME_MS - 1} ms "
                "before the idle timer expires, no keep-alive probe must be emitted."
            ),
        )

        # Boundary advance: idle timer expires, probe must fire.
        boundary_tx = self._advance(ms=2)
        self.assertEqual(
            len(boundary_tx),
            1,
            msg=(
                f"RFC 1122 §4.2.3.6: after {TEST__KEEPALIVE_IDLE_TIME_MS} ms of "
                "idle time, a keep-alive probe MUST be emitted (got "
                f"{len(boundary_tx)} TX frames)."
            ),
        )

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="A keep-alive probe must not change the session state.",
        )

    def test__keepalive__probe_wire_shape_is_ack_with_seq_snd_nxt_minus_one(self) -> None:
        """
        [FLAGS BUG]

        Ensure the keep-alive probe wire shape is an ACK with
        'SEG.SEQ = SND.NXT - 1' and no payload, per RFC 1122
        §4.2.3.6:

            "If a keep-alive segment is sent with no data, it MUST
             ... be sent with SEG.SEQ = SND.NXT - 1 ..."

        The 'minus one' shape forces peer's TCP to respond with an
        ACK acknowledging the current SND.NXT (the probe's seq is
        one byte before what peer last received, so peer's TCP
        treats it as an already-received byte and dup-ACKs); peer's
        application sees no segment text. This is the canonical
        liveness check.

        Scenario:

            * Drive handshake to ESTABLISHED, enable keep-alive,
              patch constants.
            * Drive past the idle boundary so the probe fires.
            * Parse the probe TX. Assert:
                - flag_ack = True
                - flag_syn / flag_fin / flag_rst = False
                - seq = session._snd_nxt - 1 (captured BEFORE the
                  probe to avoid a moving target)
                - payload is empty
                - ack = session._rcv_nxt (current expected from-peer
                  seq, signalling we have all peer bytes)

        Current code: no probe is emitted, so the parse step has
        nothing to inspect and the test fails on the 'len == 1'
        precondition.

        Fix outline: the probe emission in '_transmit_packet'
        should be a regular ACK with explicit 'seq=SND.NXT - 1'
        kwarg. Modular arithmetic via 'sub32(self._snd_nxt, 1)'
        per RFC 9293 §3.4 so the wrap-around case is handled.
        """

        self._patch_keepalive_constants()
        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._keepalive_enabled = True

        snd_nxt_before = session._snd_nxt
        rcv_nxt_before = session._rcv_nxt

        boundary_tx = self._advance(ms=TEST__KEEPALIVE_IDLE_TIME_MS + 1)
        self.assertEqual(
            len(boundary_tx),
            1,
            msg="Setup precondition: keep-alive probe must fire on idle expiry.",
        )

        probe = self._parse_tx(boundary_tx[0])

        self.assertEqual(
            probe.flags,
            frozenset({"ACK"}),
            msg=("RFC 1122 §4.2.3.6: keep-alive probe must carry ONLY the ACK " f"flag. Got flags={probe.flags!r}."),
        )
        self.assertEqual(
            probe.seq,
            (snd_nxt_before - 1) & 0xFFFF_FFFF,
            msg=(
                "RFC 1122 §4.2.3.6: keep-alive probe SEG.SEQ must equal "
                f"SND.NXT - 1 = {(snd_nxt_before - 1) & 0xFFFF_FFFF}; "
                f"got {probe.seq}."
            ),
        )
        self.assertEqual(
            probe.ack,
            rcv_nxt_before,
            msg=("Keep-alive probe SEG.ACK must reflect the current RCV.NXT " f"({rcv_nxt_before}); got {probe.ack}."),
        )
        self.assertEqual(
            probe.payload,
            b"",
            msg="RFC 1122 §4.2.3.6: keep-alive probe must carry no payload.",
        )

    def test__keepalive__peer_ack_of_probe_rearms_idle_timer(self) -> None:
        """
        [FLAGS BUG]

        Ensure that when peer responds to a keep-alive probe with
        an ACK at SND.NXT, the implementation treats it as a probe-
        ack and re-arms the idle timer for another full
        KEEPALIVE_IDLE_TIME interval. Per RFC 1122 §4.2.3.6 this is
        the normal liveness-confirmed path: an alive peer responds
        promptly to the probe, and the connection should not flood
        the wire with more probes.

        Scenario:

            * Drive handshake to ESTABLISHED, enable keep-alive,
              patch constants.
            * Trigger the first probe at the idle boundary.
            * Feed peer's ACK reply (ACK at SND.NXT, no data) via
              '_drive_rx'.
            * Advance another (KEEPALIVE_IDLE_TIME - 1) ms with no
              peer activity. Expect: zero further TX (idle timer
              re-armed, not yet expired).
            * Advance past the boundary. Expect: exactly one new
              keep-alive probe (the SECOND probe, indicating the
              timer was correctly re-armed and re-fired after the
              full idle interval).

        Current code: no first probe fires, so the cascade never
        starts; the assertion on the second probe count fails on
        the first precondition.

        Fix outline: on inbound ACK that hits the idle session's
        ACK branch (no in-flight data, ack at SND.NXT), reset the
        keep-alive probe-counter to 0 and re-arm the idle timer.
        Care: this ACK shape is also the dup-ACK shape, so the
        keep-alive bookkeeping must not interfere with RFC 5681
        §3.2 fast-retransmit accounting (the simplest gate is
        'no in-flight data' - the dup-ACK counter should not
        increment when SND.UNA == SND.NXT, which the
        '_retransmit_packet_request' fast-retransmit path already
        depends on).
        """

        self._patch_keepalive_constants()
        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._keepalive_enabled = True

        # First probe.
        first_tx = self._advance(ms=TEST__KEEPALIVE_IDLE_TIME_MS + 1)
        self.assertEqual(
            len(first_tx),
            1,
            msg="Setup precondition: first keep-alive probe must fire on idle expiry.",
        )

        # Peer's probe-ack: ACK at our current SND.NXT, no data.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=session._rcv_nxt,
            ack=session._snd_nxt,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        # Just before the next idle boundary, no probe yet.
        pre_boundary_tx = self._advance(ms=TEST__KEEPALIVE_IDLE_TIME_MS - 1)
        self.assertEqual(
            pre_boundary_tx,
            [],
            msg=(
                "After a probe-ack, the idle timer must be re-armed for the full "
                f"{TEST__KEEPALIVE_IDLE_TIME_MS} ms - no further probes within that window."
            ),
        )

        # Past the next boundary, the second probe fires.
        second_boundary_tx = self._advance(ms=2)
        self.assertEqual(
            len(second_boundary_tx),
            1,
            msg=(
                "After the re-armed idle timer expires, a SECOND keep-alive probe "
                "MUST fire. Got "
                f"{len(second_boundary_tx)} TX frames (probe-ack did not re-arm)."
            ),
        )

    def test__keepalive__unanswered_probes_tear_down_connection_after_threshold(
        self,
    ) -> None:
        """
        [FLAGS BUG]

        Ensure that when peer is silent and 'KEEPALIVE_PROBE_MAX_COUNT'
        consecutive probes go unanswered, the connection is torn
        down (state -> CLOSED) per RFC 1122 §4.2.3.6:

            "Implementers MAY include in their TCPs a keep-alive
             mechanism ... If keep-alive are implemented, this
             configuration MUST limit the number of probe segments
             sent ..."

        Common practice (Linux 'tcp_keepalive_probes = 9'): after
        N unanswered probes the kernel marks the connection dead
        and the next syscall returns ETIMEDOUT.

        Scenario:

            * Drive handshake to ESTABLISHED, enable keep-alive,
              patch constants (TEST__KEEPALIVE_PROBE_MAX_COUNT = 3).
            * Trigger the first probe at the idle boundary.
            * Stay silent for the full probe-retransmit window:
              advance by KEEPALIVE_PROBE_MAX_COUNT *
              KEEPALIVE_PROBE_INTERVAL ms.
            * Assert:
                - At least KEEPALIVE_PROBE_MAX_COUNT probes were
                  emitted (the initial idle-boundary probe plus the
                  retries; the exact count depends on the
                  implementation choosing whether the boundary
                  probe counts toward the max).
                - 'session.state' is no longer ESTABLISHED (the
                  connection has been torn down).

        Current code: no probes fire at all, so the second
        assertion fails (state stays ESTABLISHED indefinitely).

        Fix outline: track an unanswered-probe counter on the
        session ('_keepalive_probes_unacked'); each probe emission
        increments it, each probe-ack resets it to 0. When it
        reaches KEEPALIVE_PROBE_MAX_COUNT, transition to CLOSED
        (or RST + CLOSED, per RFC 9293 abort semantics) and
        signal any blocked recv() / send() with a connection-reset
        error.
        """

        self._patch_keepalive_constants()
        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._keepalive_enabled = True

        # Run the full idle + probe-retransmit window. Total virtual
        # time: KEEPALIVE_IDLE_TIME (initial wait) +
        # (KEEPALIVE_PROBE_MAX_COUNT + 1) * KEEPALIVE_PROBE_INTERVAL
        # for safety past the tear-down boundary.
        total_ms = (
            TEST__KEEPALIVE_IDLE_TIME_MS + (TEST__KEEPALIVE_PROBE_MAX_COUNT + 1) * TEST__KEEPALIVE_PROBE_INTERVAL_MS
        )
        all_tx = self._advance(ms=total_ms)

        probe_count = len(all_tx)
        self.assertGreaterEqual(
            probe_count,
            TEST__KEEPALIVE_PROBE_MAX_COUNT,
            msg=(
                "RFC 1122 §4.2.3.6: at least KEEPALIVE_PROBE_MAX_COUNT="
                f"{TEST__KEEPALIVE_PROBE_MAX_COUNT} probes must be emitted before "
                f"the connection is declared dead. Got {probe_count} probes."
            ),
        )
        self.assertIsNot(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "RFC 1122 §4.2.3.6: after KEEPALIVE_PROBE_MAX_COUNT unanswered "
                "probes, the connection must be torn down (state must transition "
                "out of ESTABLISHED). State is still ESTABLISHED, indicating no "
                "tear-down occurred."
            ),
        )

    def test__keepalive__data_activity_resets_idle_timer(self) -> None:
        """
        [FLAGS BUG]

        Ensure that data-bearing peer activity resets the keep-alive
        idle timer per RFC 1122 §4.2.3.6's "idle" definition: the
        timer counts time since the LAST observed segment, not time
        since handshake. After a reset, the timer must re-arm to
        fire one full KEEPALIVE_IDLE_TIME later (NOT immediately,
        not at the original boundary).

        The test is structured to fail today on the FINAL "probe
        fires after the new boundary" assertion, which requires the
        keep-alive feature to actually exist. A weaker shape that
        only checked "no probe in a small post-data window" would
        pass vacuously today (no probes ever fire without the
        feature) and would also tolerate a broken implementation
        that disarms the timer entirely on data activity instead of
        re-arming it.

        Scenario:

            * Drive handshake to ESTABLISHED, enable keep-alive,
              patch constants.
            * Advance to (KEEPALIVE_IDLE_TIME - margin) ms. No probe
              yet (we are just before the original boundary).
            * Feed peer data (1 byte). The session inline-ACKs.
            * Advance through what WOULD have been the original
              idle boundary (now (KEEPALIVE_IDLE_TIME + margin) ms
              since handshake). Expect: no keep-alive probe -
              the timer was reset by the data activity, so the
              old boundary is no longer relevant. Filter out the
              data-ACK so we only count probes (probes use
              seq=SND.NXT-1; data-acks use seq=SND.NXT).
            * Advance further to one tick past the NEW boundary
              ((KEEPALIVE_IDLE_TIME - margin) + KEEPALIVE_IDLE_TIME
              + 1 ms since handshake). Expect: exactly one keep-
              alive probe fires - this proves the timer was
              correctly RE-ARMED, not just disarmed.

        Current code (no keep-alive implementation): the final
        "probe fires after the new boundary" assertion fails
        because no probe ever fires. This is the [FLAGS BUG].

        Fix outline: tag the ACK-processing path in
        '_process_ack_packet' and the data-enqueue path in
        '_tcp_fsm_established' / '_tcp_fsm_close_wait' /
        '_tcp_fsm_fin_wait_*' with a helper that re-arms the
        keep-alive idle timer for KEEPALIVE_IDLE_TIME and resets
        the unanswered-probe counter. The same helper fires on
        outbound data-bearing transmits in '_transmit_data'.
        """

        self._patch_keepalive_constants()
        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._keepalive_enabled = True

        margin_ms = 30
        # Advance to just before the original idle boundary.
        pre_data_tx = self._advance(ms=TEST__KEEPALIVE_IDLE_TIME_MS - margin_ms)
        self.assertEqual(
            pre_data_tx,
            [],
            msg="Setup: no probe must fire before the idle boundary.",
        )

        # Peer sends one byte. The session inline-ACKs at the
        # post-data RCV.NXT (so seq=SND.NXT, distinguishable from
        # a probe at seq=SND.NXT-1).
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=session._rcv_nxt,
            ack=session._snd_nxt,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"X",
        )
        ack_tx = self._drive_rx(frame=peer_data)
        snd_nxt_after_data = session._snd_nxt

        def _is_probe(frame: bytes) -> bool:
            """A probe is the ACK with seq=SND.NXT-1; data-ACKs use seq=SND.NXT."""
            return self._parse_tx(frame).seq != snd_nxt_after_data

        # Advance through the ORIGINAL boundary (now at
        # IDLE_TIME + margin total since handshake) and just past
        # it. If the timer was NOT reset, a probe would have fired
        # somewhere in this window.
        through_old_boundary_tx = self._advance(ms=2 * margin_ms)
        probes_before_new_boundary = sum(1 for frame in (ack_tx + through_old_boundary_tx) if _is_probe(frame))
        self.assertEqual(
            probes_before_new_boundary,
            0,
            msg=(
                "RFC 1122 §4.2.3.6: data activity must reset the idle timer; "
                f"no keep-alive probe must fire within {2 * margin_ms} ms after a "
                f"peer data segment (i.e., past the ORIGINAL idle boundary). "
                f"Got {probes_before_new_boundary} probe(s)."
            ),
        )

        # Advance to one tick past the EFFECTIVE new boundary.
        # Peer data triggers the RFC 1122 §4.2.3.2 delayed-ACK
        # timer (DELAYED_ACK_DELAY ms). When that timer fires,
        # the session emits its inline ACK to peer's data; that
        # outbound ACK itself counts as activity for keep-alive
        # purposes and resets the idle timer to KEEPALIVE_IDLE_TIME.
        # The keep-alive probe therefore fires at
        # 'data_arrival + DELAYED_ACK_DELAY + KEEPALIVE_IDLE_TIME'.
        # We are currently '2 * margin_ms' past data arrival, so
        # the remaining advance is the difference.
        new_boundary_offset = DELAYED_ACK_DELAY + TEST__KEEPALIVE_IDLE_TIME_MS
        remaining_to_new_boundary = new_boundary_offset - 2 * margin_ms + 1
        new_boundary_tx = self._advance(ms=remaining_to_new_boundary)
        probes_at_new_boundary = sum(1 for frame in new_boundary_tx if _is_probe(frame))
        self.assertEqual(
            probes_at_new_boundary,
            1,
            msg=(
                "RFC 1122 §4.2.3.6: after data activity resets the idle timer, "
                "the timer must re-arm and fire ONE probe at the new effective "
                f"boundary ({new_boundary_offset} ms after data arrival, "
                "accounting for the §4.2.3.2 delayed-ACK that the session sends "
                f"in response to peer's data). Got {probes_at_new_boundary} "
                "probe(s) - the timer either disarmed entirely or never fired."
            ),
        )
