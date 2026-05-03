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
        [FLAGS BUG]

        Ensure RFC 5681 §3.1: '_cwnd' and '_ssthresh' are
        distinct first-class fields on 'TcpSession', not
        collapsed into '_snd_ewn'.

        Scenario:

            * Drive handshake to ESTABLISHED.
            * Assert '_cwnd' is a positive integer (post-
              handshake the canonical IW value, currently 1
              SMSS pre-Phase-4, IW = 10*MSS post-Phase-4).
            * Assert '_ssthresh' is set to a value strictly
              greater than peer's advertised window so the
              session starts in the slow-start phase per §3.1
              ("ssthresh SHOULD be set arbitrarily high").

        Fails today: 'TcpSession' has no '_cwnd' / '_ssthresh'
        fields; the attribute access raises 'AttributeError'.
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
        [FLAGS BUG]

        Ensure RFC 5681 §3.1: while in slow-start phase
        ('cwnd < ssthresh'), each cum-ACK that acknowledges new
        data MUST grow cwnd by 'min(bytes_acked, SMSS)' bytes.
        The current pre-Phase-1 stand-in doubles '_snd_ewn'
        per cum-ACK, which is a stronger growth rate that
        diverges from the RFC for any cum-ACK covering more
        than 1 MSS or any cum-ACK after the first.

        Scenario:

            * Drive handshake to ESTABLISHED. Manually pin
              cwnd = 2 * MSS and ssthresh = 100 * MSS so the
              session is firmly in slow-start.
            * Send 2 MSS of payload; advance two ticks so both
              segments fire.
            * Drive a single peer ACK covering both segments
              (ack = ISS + 1 + 2*MSS).
            * Assert cwnd post-ACK = 3 * MSS (= 2*MSS +
              min(2*MSS, MSS)) per RFC 5681 §3.1.
            * Pre-Phase-1 behaviour: cwnd doubled to 4 * MSS,
              violating §3.1's "at most SMSS bytes per ACK"
              clause.

        Fails today: missing fields on 'TcpSession' (the test
        attribute access for cwnd/ssthresh raises
        'AttributeError' before the growth-rate assertion runs).
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
                f"RFC 5681 §3.1 slow-start growth: a cum-ACK "
                f"covering 2*MSS while cwnd=2*MSS MUST yield "
                f"cwnd = 2*MSS + min(2*MSS, SMSS) = 3*MSS. "
                f"Pre-Phase-1 stand-in doubles cwnd to 4*MSS. "
                f"Got cwnd={session._cwnd}."
            ),
        )

    def test__cwnd__congestion_avoidance_grows_cwnd_sublinearly(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 5681 §3.1: while in congestion-avoidance
        phase ('cwnd >= ssthresh'), each cum-ACK that
        acknowledges new data MUST grow cwnd by approximately
        'SMSS * SMSS / cwnd' bytes (≈ +1 MSS per RTT for a
        stream of MSS-sized cum-ACKs).

        Concretely the recommended formula from §3.1 page 6:

            cwnd += SMSS * SMSS / cwnd

        with integer arithmetic and a floor of 1 byte to avoid
        stalling progress on very large cwnd values.

        Scenario:

            * Drive handshake to ESTABLISHED. Pin cwnd =
              10 * MSS and ssthresh = 5 * MSS so cwnd >=
              ssthresh and the session is in CA.
            * Send 1 MSS of payload; advance one tick so the
              segment fires.
            * Drive a peer ACK covering the segment.
            * Assert cwnd post-ACK = 10*MSS + max(1,
              MSS*MSS // (10*MSS)) = 10*MSS + MSS//10
              = 14600 + 146 = 14746 per the §3.1 formula.
            * Pre-Phase-1 behaviour: cwnd doubled to 20*MSS
              regardless of ssthresh, ignoring the slow-start
              vs CA distinction entirely.

        Fails today: missing fields on 'TcpSession'.
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
                f"RFC 5681 §3.1 congestion-avoidance growth: a "
                f"cum-ACK while cwnd>=ssthresh MUST yield cwnd "
                f"+= max(1, SMSS*SMSS // cwnd). Expected "
                f"{expected_cwnd}, got {session._cwnd}. The "
                f"pre-Phase-1 stand-in doubles cwnd "
                f"unconditionally - violating §3.1's CA-phase "
                f"linear-growth mandate."
            ),
        )

    def test__cwnd__snd_ewn_tracks_min_of_cwnd_and_snd_wnd(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 9293 §3.8.4 / RFC 5681 §3.1: the effective
        send window '_snd_ewn' is always the modular minimum of
        'cwnd' (sender's network bound) and 'snd_wnd' (peer's
        flow-control bound). After Phase 1 splits the two,
        '_snd_ewn' MUST be recomputed whenever either input
        changes.

        Scenario:

            * Drive handshake to ESTABLISHED.
            * Set cwnd = 3 * MSS, snd_wnd = 5 * MSS. Force
              '_snd_ewn' update via a no-op cwnd write.
            * Assert '_snd_ewn == min(3*MSS, 5*MSS) = 3*MSS'.
            * Set cwnd = 10 * MSS, snd_wnd = 5 * MSS. Force
              '_snd_ewn' update.
            * Assert '_snd_ewn == min(10*MSS, 5*MSS) = 5*MSS'.

        This invariant is the contract that lets all the
        existing call sites of '_snd_ewn' (the wire-level
        transmit gate in '_transmit_data', the persist
        machinery, the recovery exit) keep functioning
        unchanged after Phase 1 - they continue to read a
        single bound that already accounts for both
        constraints.

        Fails today: '_cwnd' does not exist; '_snd_ewn' is
        the only window field and is set via a doubling
        formula that doesn't respect any 'min(cwnd, snd_wnd)'
        invariant.
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
                "RFC 9293 §3.8.4: '_snd_ewn' = min(cwnd, "
                "snd_wnd). With cwnd=3*MSS the cwnd is tighter; "
                "_snd_ewn must equal 3*MSS."
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
                "RFC 9293 §3.8.4: '_snd_ewn' = min(cwnd, "
                "snd_wnd). With snd_wnd=5*MSS peer's window is "
                "tighter; _snd_ewn must equal 5*MSS."
            ),
        )

    def test__cwnd__post_handshake_starts_in_slow_start_phase(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 5681 §3.1: post-handshake the session starts
        in slow-start phase. The §3.1 invariant "if cwnd <
        ssthresh, slow-start" must hold immediately after the
        handshake completes - otherwise the very first cum-ACK
        would run congestion-avoidance growth on a fresh
        connection that has no loss-history yet, contradicting
        the spec.

        Scenario:

            * Drive handshake to ESTABLISHED.
            * Assert cwnd < ssthresh.

        Fails today: missing fields on 'TcpSession'.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        self.assertLess(
            session._cwnd,
            session._ssthresh,
            msg=(
                f"RFC 5681 §3.1: a fresh session post-handshake "
                f"MUST be in slow-start (cwnd < ssthresh). Got "
                f"cwnd={session._cwnd}, ssthresh="
                f"{session._ssthresh}. If ssthresh is too low, "
                f"the first cum-ACK runs CA on an unloaded "
                f"connection - wrong by the §3.1 narrative."
            ),
        )

    def test__cwnd__cum_ack_recomputes_snd_ewn_from_cwnd_via_runtime_path(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 9293 §3.8.4 / RFC 5681 §3.1 contract under
        the actual '_process_ack_packet' code path: a cum-ACK
        that grows '_cwnd' MUST propagate the new value into
        '_snd_ewn = min(_cwnd, _snd_wnd)'. This is the
        runtime-driven complement of the
        'snd_ewn_tracks_min_of_cwnd_and_snd_wnd' regression
        guard - that test sets fields manually, this one drives
        a real peer ACK and asserts the runtime maintains the
        invariant.

        Scenario:

            * Drive handshake to ESTABLISHED. Pin
              cwnd = 4 * MSS, ssthresh = INT32_MAX (default,
              guarantees slow-start phase). Pin
              snd_wnd = 100 * MSS so cwnd is the tighter bound.
            * Send 1 MSS; advance one tick so the segment
              fires.
            * Drive a peer ACK covering the segment. Per RFC
              5681 §3.1 the runtime MUST grow cwnd to
              4*MSS + min(MSS, MSS) = 5*MSS, and per RFC 9293
              §3.8.4 propagate that into _snd_ewn = min(5*MSS,
              100*MSS) = 5*MSS.
            * Assert post-ACK '_cwnd == 5*MSS'.
            * Assert post-ACK '_snd_ewn == _cwnd' (the runtime
              recomputed it from the new cwnd).
            * Assert post-ACK '_snd_ewn == min(_cwnd,
              _snd_wnd)' (the canonical RFC 9293 §3.8.4
              invariant).

        Fails today: '_process_ack_packet' computes
        '_snd_ewn = min(_snd_ewn << 1, _snd_wnd)' directly,
        ignoring '_cwnd' entirely. Post-ACK '_snd_ewn' would
        be 8*MSS (doubled), '_cwnd' stays at 4*MSS (no
        runtime touches it), so the invariant breaks.
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
                f"RFC 5681 §3.1: cum-ACK in slow-start MUST "
                f"grow cwnd by min(bytes_acked, SMSS). Expected "
                f"{expected_cwnd}, got {session._cwnd}. The "
                f"runtime '_process_ack_packet' has no §3.1 "
                f"growth hook today."
            ),
        )
        self.assertEqual(
            session._snd_ewn,
            session._cwnd,
            msg=(
                f"RFC 9293 §3.8.4: with snd_wnd >> cwnd, "
                f"_snd_ewn MUST equal _cwnd post-ACK. The "
                f"runtime currently does '_snd_ewn = "
                f"min(_snd_ewn << 1, _snd_wnd)' which doubles "
                f"_snd_ewn to {2 * 4 * PEER__MSS} bytes "
                f"regardless of _cwnd; got "
                f"_snd_ewn={session._snd_ewn}, "
                f"_cwnd={session._cwnd}."
            ),
        )
        self.assertEqual(
            session._snd_ewn,
            min(session._cwnd, session._snd_wnd),
            msg=(
                f"RFC 9293 §3.8.4 canonical invariant: _snd_ewn "
                f"= min(_cwnd, _snd_wnd) after every cum-ACK. "
                f"Got _snd_ewn={session._snd_ewn}, "
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
        [FLAGS BUG]

        Ensure RFC 5681 §3.1 step 1: on RTO, the sender MUST
        set 'ssthresh = max(FlightSize / 2, 2 * SMSS)'. With
        a multi-MSS flight at the moment of RTO, the
        FlightSize/2 branch dominates: ssthresh records the
        midpoint between the unacked low-water mark and the
        high-water mark, which becomes the slow-start exit
        point on the recovery cycle.

        Scenario:

            * Drive handshake to ESTABLISHED. Pin cwnd =
              100 * MSS so slow-start does not constrain the
              initial 6-MSS flight.
            * Send 6 * MSS of payload. Advance 6 ticks so all
              segments fire (FlightSize = 6 * MSS at peak).
            * Don't peer-ACK. Advance past the RTO timer
              (1000 ms post-handshake-clamp) so
              '_retransmit_packet_timeout' fires.
            * Assert post-RTO ssthresh = max(6*MSS / 2, 2*MSS)
              = max(3*MSS, 2*MSS) = 3*MSS.

        Fails today: '_retransmit_packet_timeout' resets cwnd
        to 1 SMSS but does not touch ssthresh. Pre-Phase-2
        ssthresh stays at the constructor default (INT32_MAX),
        which would let the post-RTO slow-start run unbounded.
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
                f"RFC 5681 §3.1 step 1: RTO MUST set ssthresh "
                f"= max(FlightSize / 2, 2*SMSS). With "
                f"FlightSize = 6*MSS = {6 * PEER__MSS}, "
                f"expected ssthresh = max(3*MSS, 2*MSS) = "
                f"{expected_ssthresh}. Got "
                f"{session._ssthresh}."
            ),
        )
        # Phase 1 regression: cwnd reset to 1 SMSS.
        self.assertEqual(
            session._cwnd,
            session._snd_mss,
            msg=(
                f"Phase 1 regression: post-RTO cwnd MUST collapse "
                f"to 1 SMSS for slow-start re-entry. Got "
                f"cwnd={session._cwnd}."
            ),
        )

    def test__cwnd__rto_with_minimal_flight_size_clamps_ssthresh_to_floor(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 5681 §3.1 step 1's '2*SMSS' floor: when the
        in-flight bytes are small enough that 'FlightSize/2 <
        2*SMSS', the floor clamps ssthresh to 2*SMSS. Without
        this clamp, a single small unacked segment would set
        ssthresh below the canonical minimum and the post-RTO
        slow-start would exit prematurely.

        Scenario:

            * Drive handshake to ESTABLISHED.
            * Send 1 MSS only. FlightSize = 1*MSS, so
              FlightSize/2 = 730 bytes < 2*MSS = 2920.
            * Don't peer-ACK. Advance past RTO.
            * Assert post-RTO ssthresh = 2 * MSS (the floor).

        Fails today: ssthresh untouched by RTO.
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
            msg=(
                f"RFC 5681 §3.1 step 1 floor: when FlightSize/2 "
                f"= {PEER__MSS // 2} bytes < 2*SMSS = "
                f"{2 * PEER__MSS}, ssthresh MUST clamp to "
                f"2*SMSS. Got {session._ssthresh}."
            ),
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

    def test__cwnd__fast_retransmit_halves_ssthresh_and_inflates_cwnd(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 5681 §3.2 steps 2 + 3: when the third
        duplicate ACK fires fast-retransmit, the sender MUST
            ssthresh = max(FlightSize/2, 2*SMSS)
            cwnd = ssthresh + 3*SMSS

        Inflation by 3*SMSS compensates for the three segments
        that left the network (the dup-ACKs prove they
        arrived); the +3 gives the sender permission to send
        three NEW segments while the retransmit is in flight.

        Scenario:

            * Drive handshake to ESTABLISHED. Pin cwnd large.
            * Send 5 * MSS so 5 segments are in flight.
            * Drive 3 dup-ACKs at SND.UNA. The 3rd fires fast-
              retransmit.
            * Assert ssthresh = max(5*MSS/2, 2*MSS) = 3650.
            * Assert cwnd = ssthresh + 3*MSS = 3650 + 4380
              = 8030.

        Fails today: '_retransmit_packet_request' sets
        '_recovery_point' but does not touch cwnd or ssthresh.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        self._send_n_segments_and_drain_dupacks(session=session, n_segments=5)

        expected_ssthresh = max(5 * PEER__MSS // 2, 2 * PEER__MSS)
        self.assertEqual(
            session._ssthresh,
            expected_ssthresh,
            msg=(
                f"RFC 5681 §3.2 step 2: fast-retransmit MUST "
                f"set ssthresh = max(FlightSize/2, 2*SMSS) = "
                f"{expected_ssthresh}. Got {session._ssthresh}."
            ),
        )
        self.assertEqual(
            session._cwnd,
            expected_ssthresh + 3 * PEER__MSS,
            msg=(
                f"RFC 5681 §3.2 step 3: fast-retransmit MUST "
                f"inflate cwnd to ssthresh + 3*SMSS = "
                f"{expected_ssthresh + 3 * PEER__MSS}. Got "
                f"{session._cwnd}."
            ),
        )

    def test__cwnd__additional_dup_ack_in_recovery_inflates_cwnd_by_one_mss(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 5681 §3.2 step 4: each additional duplicate
        ACK received while in recovery MUST inflate cwnd by
        SMSS - representing one more segment that left the
        network and grants permission to send one more new
        segment.

        Scenario:

            * Set up fast-retransmit recovery as in scenario #1.
              Capture cwnd post-fast-retransmit.
            * Drive a 4th duplicate ACK at the same ack value.
            * Assert cwnd grew by exactly SMSS.

        Fails today: dup-ACKs in recovery fall into the early-
        return branch of '_retransmit_packet_request' without
        any cwnd adjustment.
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
                f"RFC 5681 §3.2 step 4: the 4th dup-ACK in "
                f"recovery MUST inflate cwnd by SMSS. "
                f"Pre-dup4={cwnd_pre_dup4}, expected "
                f"{cwnd_pre_dup4 + PEER__MSS}, got "
                f"{session._cwnd}."
            ),
        )

    def test__cwnd__cum_ack_exiting_recovery_deflates_cwnd_to_ssthresh(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 5681 §3.2 step 6: when a cumulative ACK
        advances SND.UNA past RecoveryPoint, exiting recovery,
        the sender MUST set 'cwnd = ssthresh' to undo the
        in-recovery inflation.

        Scenario:

            * Set up fast-retransmit recovery as in scenario #1.
              Capture ssthresh.
            * Drive a cum-ACK with 'ack = SND.MAX' (which equals
              RecoveryPoint = LOCAL__ISS + 1 + 5*MSS).
            * Assert cwnd post-ACK == ssthresh (deflated).
            * Assert recovery state cleared
              ('_recovery_point == 0').

        Fails today: '_process_ack_packet' clears
        '_recovery_point' on exit but does not set cwnd =
        ssthresh, leaving cwnd at the inflated post-recovery
        value plus whatever §3.1 growth fired on the cum-ACK.
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
            msg=(
                f"RFC 5681 §3.2 step 6: cum-ACK exiting recovery "
                f"MUST set cwnd = ssthresh = {ssthresh} (the "
                f"value set in step 2). Got cwnd={session._cwnd}."
            ),
        )
        self.assertEqual(
            session._recovery_point,
            0,
            msg=("Recovery state must be cleared once SND.UNA " "passes RecoveryPoint."),
        )
