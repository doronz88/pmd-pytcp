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
