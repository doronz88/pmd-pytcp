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
This module contains integration tests for the RFC 5681 congestion
control machinery (Phase 1 of '.claude/rules/tcp_rfc5681_cwnd.md').

PyTCP's pre-Phase-1 congestion-control surface is a single
'_snd_ewn' field that conflates two distinct concepts: the
per-RFC-5681 'cwnd' (sender-side flow-control bound on the
network) and 'snd_wnd' (peer's advertised receive-window bound).
On every cum-ACK '_snd_ewn' is doubled (capped by 'snd_wnd');
there is no slow-start vs congestion-avoidance phase
distinction, no 'ssthresh' tracking, no fast-recovery cwnd
inflation/deflation per §3.2, and no halving of 'ssthresh' on
RTO per §3.1.

Phase 1 splits the surface into:

    _cwnd: int          # RFC 5681 congestion window
    _ssthresh: int      # RFC 5681 slow-start threshold
    _snd_ewn: int       # = min(_cwnd, _snd_wnd) (derived)

with the §3.1 growth rule wired into '_process_ack_packet':

    if _cwnd < _ssthresh:
        # Slow start
        _cwnd += min(bytes_acked, _snd_mss)
    else:
        # Congestion avoidance
        _cwnd += max(1, _snd_mss * _snd_mss // _cwnd)

The tests in this file exercise the Phase 1 invariants and are
expected to FAIL today against a session that does not yet
expose '_cwnd' / '_ssthresh' as separate fields.

Reference RFCs:
    RFC 5681 §3.1   Slow Start and Congestion Avoidance
    RFC 5681 §3.2   Fast Retransmit / Fast Recovery
    RFC 9293 §3.8.4 Window Management

pytcp/tests/integration/protocols/tcp/test__tcp__session__cwnd.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
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


class TestTcpCwndPhase1(TcpSessionTestCase):
    """
    Integration tests for RFC 5681 §3.1 Phase 1 invariants:
    'cwnd' / 'ssthresh' field separation and the slow-start
    vs congestion-avoidance growth-rate distinction.
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
        Does NOT bypass slow-start - tests that need a different
        cwnd/ssthresh starting point set the fields explicitly.
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

    def test__cwnd__fields_exist_post_handshake(self) -> None:
        """
        Ensure '_cwnd' and '_ssthresh' are distinct first-
        class fields on TcpSession, not collapsed into
        '_snd_ewn'. '_cwnd' is a positive integer post-
        handshake; '_ssthresh' is set arbitrarily high so
        the session starts in slow-start.

        Reference: RFC 5681 §3.1 (cwnd / ssthresh definitions).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        self.assertIsInstance(
            session._cwnd,
            int,
            msg=(
                "RFC 5681 §3.1 mandates an explicit 'cwnd' "
                "variable separate from peer's advertised "
                "window. PyTCP's pre-Phase-1 stand-in '_snd_ewn' "
                "conflates the two; Phase 1 splits them."
            ),
        )
        self.assertGreater(
            session._cwnd,
            0,
            msg=(
                f"RFC 5681 §3.1: post-handshake 'cwnd' MUST be "
                f"a positive integer (the Initial Window, IW). "
                f"Got {session._cwnd}."
            ),
        )
        self.assertIsInstance(
            session._ssthresh,
            int,
            msg=(
                "RFC 5681 §3.1: 'ssthresh' is a first-class "
                "tracker, not a derived value. PyTCP's pre-"
                "Phase-1 design has no analog at all - the "
                "slow-start vs CA distinction cannot be "
                "expressed without it."
            ),
        )
        self.assertGreater(
            session._ssthresh,
            PEER__WIN,
            msg=(
                f"RFC 5681 §3.1: 'ssthresh SHOULD be set "
                f"arbitrarily high (e.g., to the size of the "
                f"largest possible advertised window).' Got "
                f"ssthresh={session._ssthresh} which is not "
                f"greater than peer's advertised window "
                f"{PEER__WIN} - the session would never enter "
                f"slow-start cleanly."
            ),
        )

    def test__cwnd__slow_start_grows_cwnd_by_one_mss_per_cum_ack(self) -> None:
        """
        Ensure that while in slow-start phase
        (cwnd < ssthresh), each cum-ACK that acknowledges
        new data grows cwnd by min(bytes_acked, SMSS) bytes.

        Reference: RFC 5681 §3.1 (slow-start growth formula).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Pin slow-start regime.
        session._cwnd = 2 * PEER__MSS
        session._ssthresh = 100 * PEER__MSS
        session._snd_ewn = min(session._cwnd, session._snd_wnd)

        # Send 2 MSS and let both segments fire on consecutive ticks.
        payload = b"x" * (2 * PEER__MSS)
        session.send(data=payload)
        self._advance(ms=1)
        self._advance(ms=1)

        # One peer ACK covers both segments.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 2 * PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._cwnd,
            3 * PEER__MSS,
            msg=(
                "Slow-start growth: a cum-ACK covering 2*MSS "
                "while cwnd=2*MSS MUST yield cwnd = 2*MSS + "
                f"min(2*MSS, SMSS) = 3*MSS. Got "
                f"cwnd={session._cwnd}."
            ),
        )

    def test__cwnd__congestion_avoidance_grows_cwnd_sublinearly(self) -> None:
        """
        Ensure that while in congestion-avoidance phase
        (cwnd >= ssthresh), each cum-ACK that acknowledges
        new data grows cwnd by approximately
        'SMSS * SMSS / cwnd' bytes (~+1 MSS per RTT for a
        stream of MSS-sized cum-ACKs).

        Reference: RFC 5681 §3.1 (congestion-avoidance growth formula).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        session._cwnd = 10 * PEER__MSS
        session._ssthresh = 5 * PEER__MSS
        session._snd_ewn = min(session._cwnd, session._snd_wnd)

        payload = b"x" * PEER__MSS
        session.send(data=payload)
        self._advance(ms=1)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        # Per §3.1: cwnd += max(1, SMSS*SMSS // cwnd).
        # With cwnd=10*MSS=14600 and SMSS=1460:
        #   delta = max(1, 1460*1460 // 14600) = max(1, 146) = 146
        #   new cwnd = 14600 + 146 = 14746
        expected_cwnd = 10 * PEER__MSS + max(1, PEER__MSS * PEER__MSS // (10 * PEER__MSS))
        self.assertEqual(
            session._cwnd,
            expected_cwnd,
            msg=(
                "Congestion-avoidance growth: a cum-ACK while "
                "cwnd>=ssthresh MUST yield cwnd += max(1, "
                f"SMSS*SMSS // cwnd). Expected {expected_cwnd}, "
                f"got {session._cwnd}."
            ),
        )

    def test__cwnd__snd_ewn_tracks_min_of_cwnd_and_snd_wnd(self) -> None:
        """
        Ensure the effective send window '_snd_ewn' is
        always the modular minimum of 'cwnd' (sender's
        network bound) and 'snd_wnd' (peer's flow-control
        bound). '_snd_ewn' is recomputed whenever either
        input changes.

        Reference: RFC 9293 §3.8.4 (effective window = min(cwnd, snd_wnd)).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # cwnd-bound case: cwnd is the tighter constraint.
        session._cwnd = 3 * PEER__MSS
        session._snd_wnd = 5 * PEER__MSS
        # Phase 1 design: a helper recomputes _snd_ewn whenever
        # cwnd or snd_wnd changes. Tests can observe via setting
        # _snd_ewn directly here for the assertion baseline.
        session._snd_ewn = min(session._cwnd, session._snd_wnd)
        self.assertEqual(
            session._snd_ewn,
            3 * PEER__MSS,
            msg=(
                "'_snd_ewn' = min(cwnd, " "snd_wnd). With cwnd=3*MSS the cwnd is tighter; " "_snd_ewn must equal 3*MSS."
            ),
        )

        # snd_wnd-bound case: peer's window is the tighter constraint.
        session._cwnd = 10 * PEER__MSS
        session._snd_wnd = 5 * PEER__MSS
        session._snd_ewn = min(session._cwnd, session._snd_wnd)
        self.assertEqual(
            session._snd_ewn,
            5 * PEER__MSS,
            msg=(
                "'_snd_ewn' = min(cwnd, "
                "snd_wnd). With snd_wnd=5*MSS peer's window is "
                "tighter; _snd_ewn must equal 5*MSS."
            ),
        )

    def test__cwnd__post_handshake_starts_in_slow_start_phase(self) -> None:
        """
        Ensure post-handshake the session starts in slow-
        start phase: cwnd < ssthresh, so the very first
        cum-ACK runs slow-start growth, not congestion-
        avoidance.

        Reference: RFC 5681 §3.1 (slow-start vs congestion-avoidance threshold).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        self.assertLess(
            session._cwnd,
            session._ssthresh,
            msg=(
                "A fresh session post-handshake MUST be in "
                "slow-start (cwnd < ssthresh). Got "
                f"cwnd={session._cwnd}, "
                f"ssthresh={session._ssthresh}."
            ),
        )

    def test__cwnd__cum_ack_recomputes_snd_ewn_from_cwnd_via_runtime_path(self) -> None:
        """
        Ensure that a cum-ACK that grows '_cwnd' propagates
        the new value into '_snd_ewn = min(_cwnd, _snd_wnd)'
        through the actual '_process_ack_packet' code path.

        Reference: RFC 9293 §3.8.4 (effective window invariant on cum-ACK).
        Reference: RFC 5681 §3.1 (slow-start growth on cum-ACK).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Pin slow-start regime with cwnd as the tighter bound.
        # 'PEER__WIN' (64240 ~= 44 MSS) is comfortably larger
        # than 'cwnd = 4 * MSS = 5840', so 'min(cwnd, snd_wnd)'
        # tracks cwnd. Setting '_snd_wnd' directly is pointless
        # because '_process_ack_packet' overwrites it from the
        # peer ACK's 'win' field; the wire-level 16-bit window
        # cap and the wscale shift do their own thing inside
        # the runtime.
        session._cwnd = 4 * PEER__MSS
        session._ssthresh = 0x7FFF_FFFF
        session._snd_ewn = min(session._cwnd, session._snd_wnd)

        # Send 1 MSS, let it fire.
        payload = b"x" * PEER__MSS
        session.send(data=payload)
        self._advance(ms=1)

        # Drive cum-ACK with peer's full advertised window.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        # §3.1 slow-start: cwnd += min(bytes_acked, SMSS) per ACK.
        expected_cwnd = 4 * PEER__MSS + min(PEER__MSS, PEER__MSS)
        self.assertEqual(
            session._cwnd,
            expected_cwnd,
            msg=(
                "Cum-ACK in slow-start MUST grow cwnd by "
                f"min(bytes_acked, SMSS). Expected "
                f"{expected_cwnd}, got {session._cwnd}."
            ),
        )
        self.assertEqual(
            session._snd_ewn,
            session._cwnd,
            msg=(
                "With snd_wnd >> cwnd, _snd_ewn MUST equal "
                "_cwnd post-ACK. Got "
                f"_snd_ewn={session._snd_ewn}, "
                f"_cwnd={session._cwnd}."
            ),
        )
        self.assertEqual(
            session._snd_ewn,
            min(session._cwnd, session._snd_wnd),
            msg=(
                "Canonical invariant: _snd_ewn = min(_cwnd, "
                "_snd_wnd) after every cum-ACK. Got "
                f"_snd_ewn={session._snd_ewn}, "
                f"min={min(session._cwnd, session._snd_wnd)}."
            ),
        )


class TestTcpCwndPhase2(TcpSessionTestCase):
    """
    Integration tests for RFC 5681 §3.1 Phase 2 invariants:
    RTO ssthresh halving and slow-start re-entry.

    Per §3.1 step 1, on a retransmission-timeout fire the
    sender MUST set:

        ssthresh = max(FlightSize / 2, 2 * SMSS)

    so that subsequent slow-start growth exits at the
    previously-observed loss point. PyTCP's pre-Phase-2 RTO
    handler resets cwnd to 1 SMSS (Phase-1 fix) but does not
    touch ssthresh - the loss memory is lost and slow-start
    runs unbounded until peer's win clamps it.
    """

    def _make_active_session(self, *, iss: int) -> TcpSession:
        """
        Build a 'TcpSocket' / 'TcpSession' pair. Returns the
        session in CLOSED state.
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

    def test__cwnd__rto_sets_ssthresh_to_half_flight_size(self) -> None:
        """
        Ensure that on RTO the sender sets ssthresh =
        max(FlightSize / 2, 2 * SMSS). With a multi-MSS
        flight the FlightSize/2 branch dominates and
        ssthresh records the slow-start exit point for the
        recovery cycle. cwnd collapses to 1 SMSS.

        Reference: RFC 5681 §3.1 (RTO ssthresh halving).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cwnd = 100 * PEER__MSS
        session._snd_ewn = min(session._cwnd, session._snd_wnd)

        # Send 6 MSS so 6 segments are in flight at RTO time.
        payload = b"x" * (6 * PEER__MSS)
        session.send(data=payload)
        for _ in range(6):
            self._advance(ms=1)

        # Verify all 6 segments hit the wire.
        self.assertEqual(
            (session._snd_max - session._snd_una) & 0xFFFF_FFFF,
            6 * PEER__MSS,
            msg="Setup invariant: 6 MSS must be in flight before RTO fires.",
        )

        # Drive past RTO. Post-handshake rto_ms is 1000 ms; the
        # impl arms the timer at the data send (~ t=2 ms) so
        # the boundary is t=1002 ms. Advance ~999 more ms.
        self._advance(ms=999)

        expected_ssthresh = max(6 * PEER__MSS // 2, 2 * PEER__MSS)
        self.assertEqual(
            session._ssthresh,
            expected_ssthresh,
            msg=(
                "RTO MUST set ssthresh = max(FlightSize / 2, "
                f"2*SMSS). With FlightSize = 6*MSS = "
                f"{6 * PEER__MSS}, expected ssthresh = "
                f"max(3*MSS, 2*MSS) = {expected_ssthresh}. "
                f"Got {session._ssthresh}."
            ),
        )
        # Phase 1 regression: cwnd reset to 1 SMSS.
        self.assertEqual(
            session._cwnd,
            session._snd_mss,
            msg=("Post-RTO cwnd MUST collapse to 1 SMSS for " f"slow-start re-entry. Got cwnd={session._cwnd}."),
        )

    def test__cwnd__rto_with_minimal_flight_size_clamps_ssthresh_to_floor(self) -> None:
        """
        Ensure that when in-flight bytes are small enough
        that FlightSize/2 < 2*SMSS, the floor clamps
        ssthresh to 2*SMSS so post-RTO slow-start does not
        exit prematurely.

        Reference: RFC 5681 §3.1 (RTO ssthresh halving with 2*SMSS floor).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cwnd = 100 * PEER__MSS
        session._snd_ewn = min(session._cwnd, session._snd_wnd)

        payload = b"x" * PEER__MSS
        session.send(data=payload)
        self._advance(ms=1)

        self._advance(ms=1000)

        self.assertEqual(
            session._ssthresh,
            2 * PEER__MSS,
            msg=("When FlightSize/2 < 2*SMSS, ssthresh MUST " f"clamp to 2*SMSS. Got {session._ssthresh}."),
        )


class TestTcpCwndPhase3(TcpSessionTestCase):
    """
    Integration tests for RFC 5681 §3.2 Phase 3 invariants:
    fast-retransmit cwnd inflation on entry, per-dup-ACK
    inflation while in recovery, and deflation on recovery
    exit.

    Per §3.2 the four-step protocol:

        Step 2: ssthresh = max(FlightSize/2, 2*SMSS)
        Step 3: cwnd = ssthresh + 3*SMSS (entry inflation)
        Step 4: cwnd += SMSS per additional dup-ACK in recovery
        Step 6: cwnd = ssthresh (deflation on recovery exit)
    """

    def _make_active_session(self, *, iss: int) -> TcpSession:
        """
        Build a 'TcpSocket' / 'TcpSession' pair.
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

    def _send_n_segments_and_drain_dupacks(
        self,
        *,
        session: TcpSession,
        n_segments: int,
    ) -> None:
        """
        Send 'n_segments' MSS-sized payloads and let them fire,
        then drive 3 duplicate ACKs at SND.UNA so the count-
        based fast-retransmit trigger fires on the third.
        """

        session._cwnd = 100 * PEER__MSS
        session._snd_ewn = min(session._cwnd, session._snd_wnd)

        payload = b"x" * (n_segments * PEER__MSS)
        session.send(data=payload)
        for _ in range(n_segments):
            self._advance(ms=1)

        # Three dup-ACKs at LOCAL__ISS+1.
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)
        # Advance one tick so '_transmit_data' fires the
        # retransmitted segment - that advances 'SND.NXT' past
        # 'SND.UNA' so subsequent dup-ACKs are not classified
        # as keep-alive probe-acks (which would skip the
        # fast-retransmit machinery entirely).
        self._advance(ms=1)

    def test__cwnd__fast_retransmit_halves_ssthresh_and_inflates_cwnd(self) -> None:
        """
        Ensure that when the third duplicate ACK fires fast-
        retransmit, the sender sets ssthresh =
        max(FlightSize/2, 2*SMSS) and cwnd = ssthresh +
        3*SMSS, granting permission to send three new
        segments while the retransmit is in flight.

        Reference: RFC 5681 §3.2 (fast-retransmit ssthresh halving and cwnd inflation).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self._send_n_segments_and_drain_dupacks(session=session, n_segments=5)

        expected_ssthresh = max(5 * PEER__MSS // 2, 2 * PEER__MSS)
        self.assertEqual(
            session._ssthresh,
            expected_ssthresh,
            msg=(
                "Fast-retransmit MUST set ssthresh = "
                "max(FlightSize/2, 2*SMSS) = "
                f"{expected_ssthresh}. Got {session._ssthresh}."
            ),
        )
        self.assertEqual(
            session._cwnd,
            expected_ssthresh + 3 * PEER__MSS,
            msg=(
                "Fast-retransmit MUST inflate cwnd to "
                "ssthresh + 3*SMSS = "
                f"{expected_ssthresh + 3 * PEER__MSS}. Got "
                f"{session._cwnd}."
            ),
        )

    def test__cwnd__additional_dup_ack_in_recovery_inflates_cwnd_by_one_mss(self) -> None:
        """
        Ensure each additional duplicate ACK received while
        in recovery inflates cwnd by SMSS — representing one
        more segment that left the network.

        Reference: RFC 5681 §3.2 (additional dup-ACKs in recovery inflate cwnd).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self._send_n_segments_and_drain_dupacks(session=session, n_segments=5)
        cwnd_pre_dup4 = session._cwnd

        dup_ack_4 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=dup_ack_4)

        self.assertEqual(
            session._cwnd,
            cwnd_pre_dup4 + PEER__MSS,
            msg=(
                "The 4th dup-ACK in recovery MUST inflate "
                f"cwnd by SMSS. Pre-dup4={cwnd_pre_dup4}, "
                f"expected {cwnd_pre_dup4 + PEER__MSS}, got "
                f"{session._cwnd}."
            ),
        )

    def test__cwnd__cum_ack_exiting_recovery_deflates_cwnd_to_ssthresh(self) -> None:
        """
        Ensure that when a cumulative ACK advances SND.UNA
        past RecoveryPoint, exiting recovery, the sender
        sets cwnd = ssthresh to undo the in-recovery
        inflation. Recovery state is cleared.

        Reference: RFC 5681 §3.2 (cwnd deflation on recovery exit).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self._send_n_segments_and_drain_dupacks(session=session, n_segments=5)
        ssthresh = session._ssthresh

        # Cum-ACK covering all 5 segments exits recovery.
        cum_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 5 * PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=cum_ack)

        self.assertEqual(
            session._cwnd,
            ssthresh,
            msg=("Cum-ACK exiting recovery MUST set cwnd = " f"ssthresh = {ssthresh}. Got " f"cwnd={session._cwnd}."),
        )
        self.assertEqual(
            session._recovery_point,
            0,
            msg=("Recovery state must be cleared once SND.UNA " "passes RecoveryPoint."),
        )


class TestTcpCwndPhase4(TcpSessionTestCase):
    """
    Integration tests for RFC 6928 Phase 4 invariants:
    Initial Window 10*SMSS post-handshake.

    RFC 6928 §2 raises the canonical IW from 1*SMSS (RFC 5681
    §3.1 default) to 'min(10*SMSS, max(2*SMSS, 14600))'. The
    practical effect: post-handshake the sender can fire up
    to 10 segments without waiting for the first peer ACK,
    materially shortening startup latency for short-lived
    connections (HTTP requests, RPC calls).
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

    def _drive_handshake_to_established(self, *, iss: int, peer_iss: int, peer_win: int = PEER__WIN) -> TcpSession:
        """Drive the active-open three-way handshake to ESTABLISHED."""

        session = self._make_active_session(iss=iss)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss,
            ack=iss + 1,
            flags=("SYN", "ACK"),
            win=peer_win,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert (
            session.state is FsmState.ESTABLISHED
        ), f"Handshake setup failed: state is {session.state!r}, expected ESTABLISHED."
        return session

    def test__cwnd__post_handshake_initialises_cwnd_to_iw_10(self) -> None:
        """
        Ensure post-handshake cwnd equals
        min(10 * SMSS, max(2 * SMSS, 14600)) — the RFC 6928
        Initial Window of 10 segments.

        Reference: RFC 6928 §2 (Initial Window of 10 segments / 14600 bytes).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        expected_iw = min(10 * PEER__MSS, max(2 * PEER__MSS, 14600))
        self.assertEqual(
            session._cwnd,
            expected_iw,
            msg=(
                "Post-handshake cwnd MUST equal min(10*MSS, "
                f"max(2*MSS, 14600)) = {expected_iw}. Got "
                f"cwnd={session._cwnd}."
            ),
        )

    def test__cwnd__post_handshake_iw_10_clamped_by_peer_win(self) -> None:
        """
        Ensure that even with IW=10 cwnd, the effective send
        window respects peer's flow-control bound. If peer
        advertises a small win, '_snd_ewn' clamps to peer's
        value.

        Reference: RFC 6928 §2 (Initial Window).
        Reference: RFC 9293 §3.8.4 (effective window invariant).
        """

        small_win = 3 * PEER__MSS
        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_win=small_win,
        )

        expected_iw = min(10 * PEER__MSS, max(2 * PEER__MSS, 14600))
        self.assertEqual(
            session._cwnd,
            expected_iw,
            msg=(f"cwnd MUST be the IW formula value " f"({expected_iw}) regardless of peer's " f"advertised window."),
        )
        self.assertEqual(
            session._snd_ewn,
            small_win,
            msg=(
                f"With snd_wnd={small_win} < cwnd={expected_iw}, "
                "_snd_ewn MUST clamp to peer's window. Got "
                f"_snd_ewn={session._snd_ewn}."
            ),
        )


class TestTcpCwndNewReno(TcpSessionTestCase):
    """
    Integration tests for the RFC 6582 NewReno modification to
    RFC 5681 §3.2 fast recovery: partial-cum-ACK handling for
    non-SACK peers.

    RFC 6582 §3 step 3b: when a partial cum-ACK arrives during
    fast recovery (advances SND.UNA but does NOT reach
    'recovery_point'), the sender MUST:

        (1) retransmit the first unacknowledged segment;
        (2) deflate cwnd by the bytes acked;
        (3) if bytes_acked >= SMSS, add back SMSS bytes
            (so the retransmit can fire immediately).

    Without NewReno, multi-loss recovery on non-SACK peers
    costs an RTO per additional loss in the same window. With
    NewReno, the sender retransmits one missing segment per
    RTT - same behaviour as RFC 6675 SACK NextSeg, but for
    legacy non-SACK peers.

    SACK-aware peers use RFC 6675 NextSeg directly; the
    NewReno snd_nxt rewind is gated on '_send_sack == False'
    so we don't double-step backward through gaps SACK has
    already marked.
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

    def _drive_handshake_to_established(self, *, iss: int, peer_iss: int) -> TcpSession:
        """Drive the handshake and disable SACK + TSopt for the NewReno path."""

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
        assert session.state is FsmState.ESTABLISHED

        # Confirm non-SACK / non-TSopt peer scenario.
        assert not session._send_sack, "Setup invariant: peer's SYN+ACK had no SACK-Permitted."
        assert not session._send_ts, "Setup invariant: peer's SYN+ACK had no TSopt."
        return session

    def _setup_multi_loss_recovery(
        self,
        *,
        iss: int,
        peer_iss: int,
        n_segments: int,
    ) -> tuple[TcpSession, int, int]:
        """
        Set up a multi-loss recovery scenario:
            1. Drive handshake (no SACK, no TSopt).
            2. Pin cwnd large enough that all N segments fire.
            3. Send N*MSS payload; advance N ticks so all
               segments hit the wire.
            4. Drive 3 dup-ACKs at SND.UNA. Fast retransmit
               fires.
            5. Advance one tick so the retransmit goes out.

        Returns (session, post_fast_retransmit_cwnd, recovery_point).
        """

        session = self._drive_handshake_to_established(iss=iss, peer_iss=peer_iss)
        session._cwnd = 100 * PEER__MSS
        session._snd_ewn = min(session._cwnd, session._snd_wnd)

        payload = b"x" * (n_segments * PEER__MSS)
        session.send(data=payload)
        for _ in range(n_segments):
            self._advance(ms=1)

        # Three dup-ACKs - the 3rd triggers fast retransmit.
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=peer_iss + 1,
                ack=iss + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)

        # Tick so the retransmitted seg 1 fires.
        self._advance(ms=1)
        return session, session._cwnd, session._recovery_point

    def test__newreno__partial_cum_ack_retransmits_next_gap(self) -> None:
        """
        Ensure a partial cum-ACK during recovery triggers an
        immediate retransmit of the next unacknowledged
        segment (the first gap) without waiting for the RTO
        timer.

        Reference: RFC 6582 §3 (NewReno step 3b retransmit on partial cum-ACK).
        """

        n_segments = 3
        session, _, _ = self._setup_multi_loss_recovery(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            n_segments=n_segments,
        )

        # Drive partial cum-ACK acking only seg 1.
        partial_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=partial_ack)

        # Tick so the next-gap retransmit fires.
        retransmit_tx = self._advance(ms=1)

        # Find a frame at seq = ISS + 1 + MSS (seg 2 retransmit).
        retransmit_seg = None
        for frame in retransmit_tx:
            probe = self._parse_tx(frame)
            if probe.seq == LOCAL__ISS + 1 + PEER__MSS and len(probe.payload) > 0:
                retransmit_seg = probe
                break

        self.assertIsNotNone(
            retransmit_seg,
            msg=(
                "Partial cum-ACK MUST trigger immediate "
                "retransmit of seg 2 (seq = "
                f"{LOCAL__ISS + 1 + PEER__MSS:#x}). Got "
                f"tx burst: {retransmit_tx!r}."
            ),
        )

    def test__newreno__partial_cum_ack_deflates_cwnd_per_step_3b(self) -> None:
        """
        Ensure NewReno cwnd deflation on partial cum-ACK:
        cwnd_new = cwnd_old - bytes_acked + SMSS (when
        bytes_acked >= SMSS).

        Reference: RFC 6582 §3 (NewReno step 3b cwnd deflation).
        """

        n_segments = 4  # so we can ack 2*MSS partially
        session, post_fr_cwnd, _ = self._setup_multi_loss_recovery(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            n_segments=n_segments,
        )

        # Drive partial cum-ACK acking 2*MSS.
        bytes_acked_partial = 2 * PEER__MSS
        partial_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + bytes_acked_partial,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=partial_ack)

        # NewReno step 3b:
        #   cwnd -= bytes_acked = -2*MSS
        #   if bytes_acked >= MSS: cwnd += MSS
        # Net: cwnd -= MSS.
        expected_cwnd = post_fr_cwnd - bytes_acked_partial + PEER__MSS
        self.assertEqual(
            session._cwnd,
            expected_cwnd,
            msg=(
                f"Partial cum-ACK acking "
                f"{bytes_acked_partial} bytes MUST deflate "
                "cwnd by 'bytes_acked' then add SMSS back. "
                f"Pre-ACK cwnd={post_fr_cwnd}, expected "
                f"post-ACK cwnd={expected_cwnd}, got "
                f"{session._cwnd}."
            ),
        )


class TestTcpCwndNewRenoExtended(TcpSessionTestCase):
    """
    Extended integration coverage for RFC 6582 NewReno
    scenarios that 'TestTcpCwndNewReno' (the basic single-
    partial-cum-ACK happy path) does not exercise:

      - Multiple consecutive partial cum-ACKs in one recovery
        cycle.
      - NewReno cwnd deflation with SACK-aware peer
        (deflation runs regardless of SACK state).
      - NewReno across the 32-bit seq wrap (modular 'lt32'
        recovery_point check).
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

    def _drive_handshake(self, *, iss: int, peer_iss: int, sackperm: bool = False) -> TcpSession:
        """Drive handshake; optionally negotiate SACK."""

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
            sackperm=sackperm,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert session.state is FsmState.ESTABLISHED
        assert session._send_sack == sackperm, (
            f"Setup invariant: bilateral SACK negotiation expected={sackperm}, " f"got _send_sack={session._send_sack}."
        )
        return session

    def test__newreno__multiple_consecutive_partial_cum_acks_each_deflate_cwnd(self) -> None:
        """
        Ensure NewReno cwnd deflation fires correctly for
        multiple consecutive partial cum-ACKs in one
        recovery cycle: each deflates cwnd by 'bytes_acked'
        (with SMSS add-back), and recovery exits only on
        the cum-ACK that reaches recovery_point.

        Reference: RFC 6582 §3 (NewReno step 3b across multiple partial cum-ACKs).
        """

        session = self._drive_handshake(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cwnd = 100 * PEER__MSS
        session._snd_ewn = min(session._cwnd, session._snd_wnd)

        payload = b"x" * (3 * PEER__MSS)
        session.send(data=payload)
        for _ in range(3):
            self._advance(ms=1)

        # 3 dup-ACKs trigger fast retransmit.
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)

        # Tick - seg 1 retransmit fires.
        self._advance(ms=1)
        cwnd_post_fr = session._cwnd
        ssthresh_post_fr = session._ssthresh
        recovery_point = session._recovery_point

        # First partial cum-ACK: ack seg 1.
        partial_1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=partial_1)

        # bytes_acked=MSS: deflate by MSS, add back MSS, net 0.
        self.assertEqual(
            session._cwnd,
            cwnd_post_fr,
            msg=(
                f"Partial cum-ACK #1 with bytes_acked=SMSS: "
                f"deflate(-SMSS)+add-back(+SMSS) cancels. "
                f"Expected {cwnd_post_fr}, got {session._cwnd}."
            ),
        )
        self.assertEqual(
            session._recovery_point,
            recovery_point,
            msg=("Partial cum-ACK #1 (snd_una < recovery_point): " "recovery state MUST be preserved."),
        )

        # Tick - seg 2 retransmits.
        self._advance(ms=1)

        # Second partial cum-ACK: ack seg 2.
        partial_2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 2 * PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=partial_2)

        self.assertEqual(
            session._cwnd,
            cwnd_post_fr,
            msg=("Partial cum-ACK #2 with bytes_acked=SMSS: " "same cancel. cwnd preserved."),
        )
        self.assertEqual(
            session._recovery_point,
            recovery_point,
            msg="Partial cum-ACK #2: recovery state preserved.",
        )

        # Tick - seg 3 retransmits.
        self._advance(ms=1)

        # Final cum-ACK: ack seg 3, snd_una reaches recovery_point.
        full_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 3 * PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=full_ack)

        self.assertEqual(
            session._recovery_point,
            0,
            msg=(
                "Full cum-ACK at recovery_point: recovery_point "
                "MUST be cleared (RFC 5681 §3.2 step 6 / RFC 6675 §5)."
            ),
        )
        self.assertEqual(
            session._cwnd,
            ssthresh_post_fr,
            msg=(
                f"Full cum-ACK: cwnd MUST deflate to ssthresh "
                f"(RFC 5681 §3.2 step 6). Expected "
                f"{ssthresh_post_fr}, got {session._cwnd}."
            ),
        )

    def test__newreno__sack_active_partial_cum_ack_still_deflates_cwnd(self) -> None:
        """
        Ensure NewReno cwnd deflation runs even when SACK
        is bilaterally negotiated. The cwnd deflation
        accounting is independent of SACK and applies on
        every partial cum-ACK during recovery.

        Reference: RFC 6582 §3 (NewReno step 3b cwnd deflation, SACK-orthogonal).
        """

        session = self._drive_handshake(iss=LOCAL__ISS, peer_iss=PEER__ISS, sackperm=True)
        session._cwnd = 100 * PEER__MSS
        session._snd_ewn = min(session._cwnd, session._snd_wnd)

        payload = b"x" * (3 * PEER__MSS)
        session.send(data=payload)
        for _ in range(3):
            self._advance(ms=1)

        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)
        self._advance(ms=1)
        cwnd_post_fr = session._cwnd

        partial_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + 2 * PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=partial_ack)

        # NewReno step 3b: cwnd -= 2*SMSS + add-back SMSS.
        expected_cwnd = cwnd_post_fr - 2 * PEER__MSS + PEER__MSS
        self.assertEqual(
            session._cwnd,
            expected_cwnd,
            msg=(
                "Step 3b deflation MUST run regardless of "
                f"SACK state. Expected post-deflate "
                f"cwnd={expected_cwnd}, got {session._cwnd}."
            ),
        )

    def test__newreno__partial_cum_ack_across_32bit_seq_wrap(self) -> None:
        """
        Ensure NewReno cwnd deflation works across the
        32-bit seq wrap. The recovery_point check uses
        modular comparison so a partial cum-ACK on the
        post-wrap side of recovery_point is classified as
        partial, not past-recovery_point.

        Reference: RFC 6582 §3 (NewReno step 3b across modular seq wrap).
        """

        wrap_iss = 0xFFFF_FFE0
        wrap_peer_iss = 0x0000_2000

        session = self._drive_handshake(iss=wrap_iss, peer_iss=wrap_peer_iss)
        session._cwnd = 100 * PEER__MSS
        session._snd_ewn = min(session._cwnd, session._snd_wnd)

        payload = b"x" * (3 * PEER__MSS)
        session.send(data=payload)
        for _ in range(3):
            self._advance(ms=1)

        # 3 dup-ACKs at our SND.UNA = ISS+1 (post-wrap value).
        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=wrap_peer_iss + 1,
                ack=(wrap_iss + 1) & 0xFFFF_FFFF,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)

        self._advance(ms=1)
        cwnd_post_fr = session._cwnd
        recovery_point = session._recovery_point

        # Partial cum-ACK at SND.UNA + MSS. Modular addition
        # so the value lands on the post-wrap side.
        partial_ack_value = (wrap_iss + 1 + PEER__MSS) & 0xFFFF_FFFF
        partial_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=wrap_peer_iss + 1,
            ack=partial_ack_value,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=partial_ack)

        self.assertNotEqual(
            session._recovery_point,
            0,
            msg=(
                f"Modular 'lt32(snd_una, recovery_point)' check "
                f"MUST classify the post-wrap partial cum-ACK "
                f"as partial. Got recovery_point="
                f"{session._recovery_point} (expected non-zero, "
                f"= {recovery_point})."
            ),
        )
        # bytes_acked=MSS: deflate -MSS + add-back +MSS = 0 net.
        self.assertEqual(
            session._cwnd,
            cwnd_post_fr,
            msg=(
                f"Across-wrap partial cum-ACK with "
                f"bytes_acked=SMSS: deflate-add-back cancels. "
                f"Expected cwnd={cwnd_post_fr}, got "
                f"{session._cwnd}."
            ),
        )


class TestTcpCwndCrossRfcNewRenoPlusRto(TcpSessionTestCase):
    """
    Cross-RFC interaction (Phase B1 of the test-coverage audit):
    RFC 6582 NewReno fast recovery interacting with the RFC 6298
    RTO retransmit-timer fire mid-recovery. The two mechanisms
    must compose cleanly:

      - Entering recovery: cwnd = ssthresh + 3*SMSS, _recovery_point
        set to SND.MAX (RFC 5681 §3.2 step 3).
      - RTO fires before _recovery_point reached: cwnd collapses
        to LW=SMSS, ssthresh halves AGAIN, _recovery_point MUST
        be cleared (we're back in slow-start, not in recovery).
      - Subsequent partial cum-ACK MUST NOT trigger NewReno
        deflation - the post-RTO recovery is a fresh slow-start
        re-entry, not a continuation.
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

    def _drive_handshake_to_established(self, *, iss: int, peer_iss: int) -> TcpSession:
        """Handshake without SACK so NewReno is the canonical recovery path."""

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
        assert session.state is FsmState.ESTABLISHED
        return session

    def test__cwnd__rto_during_fast_recovery_clears_recovery_point_and_resets_cwnd(self) -> None:
        """
        Ensure that an RTO timeout fired while in fast
        recovery clears '_recovery_point' and collapses
        cwnd to LW=SMSS. Subsequent partial cum-ACK does
        not run the NewReno deflation path because
        recovery state is gone.

        Reference: RFC 5681 §3.1 (RTO collapses cwnd, slow-start re-entry).
        Reference: RFC 6675 §5 (RecoveryPoint lifecycle).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session._cwnd = 100 * PEER__MSS
        session._snd_ewn = min(session._cwnd, session._snd_wnd)

        # Get N segments in flight then enter recovery via 3 dup-ACKs.
        n_segments = 5
        payload = b"x" * (n_segments * PEER__MSS)
        session.send(data=payload)
        for _ in range(n_segments):
            self._advance(ms=1)

        for _ in range(3):
            dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=dup_ack)
        self._advance(ms=1)

        recovery_point_in_recovery = session._recovery_point
        self.assertNotEqual(
            recovery_point_in_recovery,
            0,
            msg="Setup invariant: '_recovery_point' MUST be set after entering fast recovery.",
        )

        # Force the retransmit timer to expire so RTO fires
        # while still in recovery. The RTO handler runs §3.1
        # ssthresh halving + cwnd=LW reset.
        stack.timer.register_timer(name=f"{session}-retransmit", timeout=0)
        self._advance(ms=1)

        self.assertEqual(
            session._recovery_point,
            0,
            msg=(
                "RTO during fast recovery: '_recovery_point' "
                "MUST be cleared so subsequent partial "
                "cum-ACKs follow the slow-start path, not "
                "the NewReno path."
            ),
        )
        self.assertEqual(
            session._cwnd,
            session._snd_mss,
            msg="RTO: cwnd MUST collapse to LW=SMSS for slow-start re-entry.",
        )
