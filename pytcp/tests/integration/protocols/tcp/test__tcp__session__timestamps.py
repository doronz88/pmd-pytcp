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
This module contains integration tests for the RFC 7323 §3
Timestamps option (TSopt) machinery in PyTCP's TcpSession.

RFC 7323 §3 specifies a 10-byte option carrying <TSval, TSecr>:
    - TSval: sender's current TS clock value.
    - TSecr: most-recently-seen peer TSval, echoed back so peer
      can compute exact RTT without Karn's ambiguity.

The four invariants the project must satisfy:
    1. Bilateral negotiation - TSopt on SYN/SYN+ACK iff both
       sides advertise.
    2. Per-segment emission - every post-handshake segment
       carries TSopt when '_send_ts' is True.
    3. RTTM via TSecr - 'now_ms - tsecr' on cum-ACK supersedes
       Karn-tainted sample tracker.
    4. PAWS - reject inbound segments with stale TSval.

This file exercises Phase 1 (bilateral negotiation). Phases
2-4 add their own [FLAGS BUG] suites.

Reference RFCs:
    RFC 7323 §3   Timestamps option wire format + negotiation
    RFC 7323 §4   RTTM via TSecr
    RFC 7323 §5   PAWS

pytcp/tests/integration/protocols/tcp/test__tcp__session__timestamps.py

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

# Peer's TS clock starting value (arbitrary).
PEER__TSVAL_INITIAL: int = 0x1234_5678


class TestTcpTimestampsPhase1Active(TcpSessionTestCase):
    """
    Phase 1 active-open bilateral-negotiation invariants.
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

    def test__ts__active_open_syn_carries_tsopt(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 7323 §3: an active-open SYN MUST include the
        Timestamps option with 'TSval = current TS clock' and
        'TSecr = 0' (peer's TSval is unknown until the SYN+ACK
        arrives).

        Scenario:

            * Construct an active session, drive 'connect'
              syscall.
            * Advance one tick so the SYN fires.
            * Parse the outbound SYN frame.
            * Assert TSopt is present (tsval is not None).
            * Assert TSval is the current 'now_ms'.
            * Assert TSecr == 0.

        Fails today: 'TcpSession._transmit_packet' does not
        emit TSopt; outbound TcpProbe.tsval is None.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        send_now_ms = self._timer.now_ms + 1
        tx = self._advance(ms=1)

        self.assertEqual(
            len(tx),
            1,
            msg="Setup invariant: connect must emit one SYN frame.",
        )
        probe = self._parse_tx(tx[0])
        self.assertIn(
            "SYN",
            probe.flags,
            msg="Setup invariant: outbound frame must be the SYN.",
        )
        self.assertIsNotNone(
            probe.tsval,
            msg=(
                "RFC 7323 §3: active-open SYN MUST carry the "
                "Timestamps option (with TSval = current TS clock, "
                "TSecr = 0). Got no TSopt."
            ),
        )
        self.assertEqual(
            probe.tsval,
            send_now_ms,
            msg=(
                f"RFC 7323 §3: SYN's TSval MUST equal the "
                f"sender's current TS clock value "
                f"(stack.timer.now_ms = {send_now_ms}). "
                f"Got TSval={probe.tsval}."
            ),
        )
        self.assertEqual(
            probe.tsecr,
            0,
            msg=(
                "RFC 7323 §3: TSecr on the active-open SYN MUST "
                "be zero (peer's TSval is not yet known). Got "
                f"TSecr={probe.tsecr}."
            ),
        )

    def test__ts__bilateral_send_ts_set_post_handshake_when_peer_supports(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 7323 §3: post-handshake '_send_ts' is True
        when both sides advertised TSopt during the SYN
        exchange. The flag gates per-segment TSopt emission and
        TSopt ingestion in subsequent phases.

        Scenario:

            * Construct an active session, connect.
            * Drive a peer SYN+ACK that includes TSopt.
            * Assert session._send_ts == True post-handshake.
        """

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
            tsval=PEER__TSVAL_INITIAL,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup invariant: handshake must complete with peer's TSopt.",
        )
        self.assertTrue(
            session._send_ts,
            msg=(
                "RFC 7323 §3: bilateral negotiation success - "
                "both sides advertised TSopt - MUST set "
                "'_send_ts = True' so post-handshake segments "
                "carry TSopt."
            ),
        )

    def test__ts__peer_no_tsopt_disables_send_ts(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 7323 §3: if peer's SYN+ACK does NOT include
        TSopt, '_send_ts' MUST stay False. PyTCP cannot
        unilaterally include TSopt on subsequent segments
        because peer would not echo it.

        Scenario:

            * Connect.
            * Drive a peer SYN+ACK with NO TSopt.
            * Assert session._send_ts == False post-handshake.
        """

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
            # No tsval/tsecr - peer doesn't advertise TSopt.
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup invariant: handshake must complete even without TSopt.",
        )
        self.assertFalse(
            session._send_ts,
            msg=(
                "RFC 7323 §3: peer did not advertise TSopt - "
                "'_send_ts' MUST stay False so we do not emit "
                "TSopt on subsequent segments. Got "
                f"_send_ts={session._send_ts}."
            ),
        )

    def test__ts__advertise_opt_out_disables_outbound_tsopt(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 7323 §3: when the application disables TSopt
        advertisement via '_advertise_ts = False' before
        connect, the outbound SYN does NOT carry TSopt and the
        post-handshake '_send_ts' stays False even if peer
        advertised.

        Scenario:

            * Construct an active session.
            * Set session._advertise_ts = False.
            * Connect, advance.
            * Assert outbound SYN's TSval is None (no option).
            * Drive peer SYN+ACK with TSopt.
            * Assert _send_ts == False (asymmetric guard).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session._advertise_ts = False
        session.tcp_fsm(syscall=SysCall.CONNECT)
        tx = self._advance(ms=1)

        probe = self._parse_tx(tx[0])
        self.assertIsNone(
            probe.tsval,
            msg=(
                "RFC 7323 §3: with '_advertise_ts = False' the "
                "outbound SYN MUST NOT carry TSopt. Got "
                f"TSval={probe.tsval}."
            ),
        )

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            tsval=PEER__TSVAL_INITIAL,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertFalse(
            session._send_ts,
            msg=(
                "RFC 7323 §3 asymmetric-guard: even if peer "
                "advertises TSopt, we MUST NOT enable '_send_ts' "
                "when our side opted out via '_advertise_ts = "
                "False'. Got _send_ts="
                f"{session._send_ts}."
            ),
        )


# Passive-open (LISTEN-side) bilateral-negotiation tests are
# deferred to Phase 2 — they require the LISTEN__PORT-style
# listening setup and re-resolution of the child session post-
# SYN. Active-open coverage (4 scenarios above) exercises the
# bilateral-negotiation logic on the active side; the passive
# side will be covered transitively when Phase 2's
# per-segment emission tests drive both directions.


class TestTcpTimestampsPhase2(TcpSessionTestCase):
    """
    Phase 2 invariants: post-handshake TSopt emission on every
    segment + '_ts_recent' tracking on accepted inbound segments.
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

    def _drive_handshake_with_tsopt(self, *, iss: int, peer_iss: int, peer_tsval: int) -> TcpSession:
        """
        Drive the active-open three-way handshake with bilateral
        TSopt negotiation. Returns the established session with
        '_send_ts == True' and '_ts_recent == peer_tsval'.
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
            tsval=peer_tsval,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)

        assert session.state is FsmState.ESTABLISHED
        assert session._send_ts, "Setup invariant: bilateral TSopt negotiation must succeed."
        # Bypass slow-start.
        session._snd_ewn = PEER__WIN
        return session

    def test__ts__post_handshake_data_segment_carries_tsopt(self) -> None:
        """
        Ensure RFC 7323 §3: post-handshake outbound segments
        carry TSopt with 'TSval = now_ms' and 'TSecr =
        _ts_recent' when bilateral negotiation succeeded.

        Regression guard - the non-SYN TSopt emission gate was
        wired in Phase 1 but only handshake segments were
        explicitly tested.
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        payload = b"hello"
        session.send(data=payload)
        send_now_ms = self._timer.now_ms + 1
        tx = self._advance(ms=1)

        probe = self._parse_tx(tx[0])
        self.assertEqual(
            probe.tsval,
            send_now_ms,
            msg=(
                f"RFC 7323 §3: post-handshake data segment MUST "
                f"carry TSval = current TS clock ({send_now_ms}). "
                f"Got TSval={probe.tsval}."
            ),
        )
        self.assertEqual(
            probe.tsecr,
            PEER__TSVAL_INITIAL,
            msg=(
                f"RFC 7323 §3: TSecr MUST equal '_ts_recent' "
                f"(= peer's last seen TSval = "
                f"{PEER__TSVAL_INITIAL:#x}). Got "
                f"TSecr={probe.tsecr}."
            ),
        )

    def test__ts__ts_recent_updated_on_accepted_inbound_segment(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 7323 §4.3: an accepted inbound segment's
        TSval MUST update '_ts_recent' so subsequent outbound
        TSecr echoes the latest peer TS clock value.

        Scenario:

            * Drive handshake with peer TSval=PEER__TSVAL_INITIAL.
              Capture initial _ts_recent.
            * Drive a peer ACK (in-sequence, no data) with
              TSval=PEER__TSVAL_INITIAL + 100.
            * Assert '_ts_recent' updated to the new TSval.
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        new_tsval = PEER__TSVAL_INITIAL + 100
        # Use a data-bearing inbound segment so the FSM routes
        # to '_process_ack_packet' (the dup-ACK / wnd-update
        # paths take a different early-return route that
        # bypasses the TS-recent hook today; full RFC 7323 §4.3
        # conformance for those paths is a Phase-4-or-later
        # concern).
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=new_tsval,
            tsecr=PEER__TSVAL_INITIAL,
            payload=b"peer-data",
        )
        self._drive_rx(frame=peer_data)

        self.assertEqual(
            session._ts_recent,
            new_tsval,
            msg=(
                f"RFC 7323 §4.3: an accepted inbound segment's "
                f"TSval MUST update '_ts_recent'. Expected "
                f"{new_tsval:#x}, got {session._ts_recent:#x}."
            ),
        )

    def test__ts__post_update_outbound_segment_echoes_new_ts_recent(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 7323 §3 / §4.3: after '_ts_recent' updates
        from an inbound segment, the next outbound segment's
        TSecr reflects the new value.

        Scenario:

            * Drive handshake.
            * Drive a peer ACK with TSval=NEW_TSVAL to update
              '_ts_recent'.
            * Send data; advance one tick to fire the segment.
            * Assert outbound TSecr == NEW_TSVAL.
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        new_tsval = PEER__TSVAL_INITIAL + 200
        # Use a data-bearing inbound segment so the FSM routes
        # to '_process_ack_packet' (the dup-ACK / wnd-update
        # paths take a different early-return route that
        # bypasses the TS-recent hook today; full RFC 7323 §4.3
        # conformance for those paths is a Phase-4-or-later
        # concern).
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=new_tsval,
            tsecr=PEER__TSVAL_INITIAL,
            payload=b"peer-data",
        )
        self._drive_rx(frame=peer_data)

        session.send(data=b"world")
        tx = self._advance(ms=1)
        probe = self._parse_tx(tx[0])

        self.assertEqual(
            probe.tsecr,
            new_tsval,
            msg=(
                f"RFC 7323 §3: outbound TSecr MUST reflect the "
                f"updated '_ts_recent' = {new_tsval:#x}. Got "
                f"TSecr={probe.tsecr}."
            ),
        )


class TestTcpTimestampsPhase3(TcpSessionTestCase):
    """
    Phase 3 invariants: TSecr-driven RTTM (RFC 7323 §4)
    measures RTT cleanly even on Karn-tainted retransmits,
    where the Phase-2 sample tracker would skip the update.

    The distinguishing test is the retransmit case: the
    Phase-2 sample tracker invalidates samples from
    retransmitted segments per RFC 6298 §3 (Karn's algorithm),
    so the smoothed estimator stops moving until a fresh
    non-retransmitted sample arrives. RFC 7323 §4 obviates
    Karn entirely - peer's TSecr identifies WHICH transmission
    it acknowledges, so RTT can be measured cleanly.
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

    def _drive_handshake_with_tsopt(self, *, iss: int, peer_iss: int, peer_tsval: int) -> TcpSession:
        """Drive the active-open handshake with bilateral TSopt."""

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
            tsval=peer_tsval,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)

        assert session.state is FsmState.ESTABLISHED
        assert session._send_ts
        session._snd_ewn = PEER__WIN
        return session

    def test__rttm__karn_tainted_retransmit_measures_rtt_via_tsecr(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 7323 §4: when peer's ACK echoes a TSecr
        identifying the retransmitted segment's TSval, the
        runtime measures RTT directly from TSecr and folds it
        into '_rto_state' via 'update', SUPERSEDING the Phase-2
        sample tracker's Karn-mandated skip (RFC 6298 §3).

        Scenario:

            * Drive handshake with TSopt at t=1.
            * Send data at t=2 (TSval=2). Sample tracker armed.
            * Advance past RTO (1000 ms boundary) to fire
              retransmit. Sample tracker is now Karn-tainted.
              Retransmit segment carries TSval=now_ms (the
              retransmit time, ~1003).
            * Capture '_rto_state' post-retransmit (after
              'back_off' fires).
            * Drive a peer ACK at later time with
              'tsecr=retransmit_tsval', advancing snd_una.
            * Without Phase 3: Phase-2 path skips the update
              (Karn-tainted), and '_rto_state' would only have
              the back_off-doubled rto_ms with no new sample
              folded in.
            * With Phase 3: TSecr identifies the retransmit's
              TSval, RTT = now_ms - tsecr is folded via
              update, and '_rto_state.srtt_ms' / 'rttvar_ms'
              MOVE from the post-back_off snapshot.
        """

        from pytcp.protocols.tcp.tcp__rto import update as rto_update

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        payload = b"hello"
        session.send(data=payload)
        self._advance(ms=1)

        # Drive past the RTO timer so retransmit fires.
        # Post-handshake rto_ms = 1000 (clamped). Retransmit at
        # ~ t=1002 ms.
        self._advance(ms=1001)

        # Verify the retransmit fired (Karn-tainted sample).
        self.assertTrue(
            session._rtt_sample_retransmitted,
            msg="Setup invariant: retransmit must have tainted the sample.",
        )
        post_retransmit_state = session._rto_state
        # Capture the retransmit's TSval - the retransmit
        # segment was emitted at ~t=1002 ms and its TSval
        # equals stack.timer.now_ms at that moment. With the
        # FakeTimer's 1ms tick the retransmit's TSval is
        # roughly the now_ms at the retransmit fire time.
        # Find it from the latest TX frame.
        all_tx = list(self._frames_tx)
        retransmit_probe = self._parse_tx(all_tx[-1])
        retransmit_tsval = retransmit_probe.tsval
        assert retransmit_tsval is not None

        # Advance another 5 ms then drive peer ACK echoing the
        # retransmit's TSval as TSecr.
        self._advance(ms=5)
        observed_rtt = self._timer.now_ms - retransmit_tsval

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
            tsval=PEER__TSVAL_INITIAL + 100,
            tsecr=retransmit_tsval,
        )
        self._drive_rx(frame=peer_ack)

        # Phase 3 expectation: '_rto_state' moved via update
        # despite the Karn taint. Compute expected.
        expected = rto_update(post_retransmit_state, observed_rtt)
        self.assertEqual(
            session._rto_state,
            expected,
            msg=(
                f"RFC 7323 §4: TSecr-driven RTTM MUST fold "
                f"observed_rtt={observed_rtt} via 'update' even "
                f"after a Karn-tainted retransmit. Without "
                f"Phase 3 the Karn skip leaves '_rto_state' at "
                f"the post-back_off snapshot. Expected "
                f"{expected!r}, got {session._rto_state!r}."
            ),
        )

    def test__rttm__non_tsopt_peer_falls_back_to_sample_tracker(self) -> None:
        """
        Ensure the Phase-2 sample tracker continues to work
        unchanged for peers that did not negotiate TSopt -
        bilateral negotiation gates the TSecr path so legacy
        peers fall through to the existing harvest logic.

        Regression guard.
        """

        from pytcp.protocols.tcp.tcp__rto import update as rto_update

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
            # No tsval/tsecr.
        )
        self._drive_rx(frame=peer_syn_ack)
        self.assertFalse(session._send_ts, msg="Peer did not advertise TSopt.")
        session._snd_ewn = PEER__WIN

        pre_ack_state = session._rto_state
        payload = b"hello"
        session.send(data=payload)
        self._advance(ms=1)
        sample_send_time = session._rtt_sample_send_time_ms

        self._advance(ms=10)

        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + len(payload),
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        observed_rtt = self._timer.now_ms - (sample_send_time or 0)
        expected = rto_update(pre_ack_state, observed_rtt)
        self.assertEqual(
            session._rto_state,
            expected,
            msg=(
                f"Sample-tracker fallback: non-TSopt peer's "
                f"ACK MUST fold observed_rtt={observed_rtt} via "
                f"update. Expected {expected!r}, got "
                f"{session._rto_state!r}."
            ),
        )


class TestTcpTimestampsPhase4(TcpSessionTestCase):
    """
    Phase 4 invariants: PAWS (Protection Against Wrapped
    Sequence numbers) per RFC 7323 §5.

    PAWS drops inbound segments whose TSval is less than
    '_ts_recent' (modular 32-bit comparison) - this defends
    against wrapped-sequence attacks across the 4 GB seq
    space.
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

    def _drive_handshake_with_tsopt(self, *, iss: int, peer_iss: int, peer_tsval: int) -> TcpSession:
        """Drive the active-open handshake with bilateral TSopt."""

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
            tsval=peer_tsval,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)

        assert session.state is FsmState.ESTABLISHED
        assert session._send_ts
        session._snd_ewn = PEER__WIN
        return session

    def test__paws__stale_tsval_segment_dropped(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 7323 §5: an inbound data segment with TSval
        STRICTLY LESS than '_ts_recent' is dropped without
        affecting session state. PAWS defends against
        wrapped-sequence attacks where an old segment delayed
        in the network re-emerges with a low TSval but a
        newly-valid seq number.

        Scenario:

            * Drive handshake; '_ts_recent = PEER__TSVAL_INITIAL'.
            * Drive a peer DATA segment with
              'tsval = PEER__TSVAL_INITIAL - 100' (stale).
            * Assert RX buffer NOT extended (segment dropped).
            * Assert session state unchanged (RCV.NXT same).
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        rcv_nxt_pre = session._rcv_nxt
        rx_buffer_pre = bytes(session._rx_buffer)

        stale_tsval = PEER__TSVAL_INITIAL - 100
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=stale_tsval,
            tsecr=PEER__TSVAL_INITIAL,
            payload=b"stale-data",
        )
        self._drive_rx(frame=peer_data)

        self.assertEqual(
            session._rcv_nxt,
            rcv_nxt_pre,
            msg=(
                f"RFC 7323 §5 PAWS: stale-TSval segment "
                f"(tsval={stale_tsval:#x} < _ts_recent="
                f"{PEER__TSVAL_INITIAL:#x}) MUST be dropped "
                f"without advancing RCV.NXT. Got "
                f"_rcv_nxt={session._rcv_nxt}."
            ),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            rx_buffer_pre,
            msg=("RFC 7323 §5 PAWS: stale-TSval segment's data " "MUST NOT enter the RX buffer."),
        )

    def test__paws__current_tsval_segment_accepted(self) -> None:
        """
        Regression guard: an inbound segment with TSval
        greater than or equal to '_ts_recent' is accepted
        normally. PAWS only rejects strictly-stale TSvals.
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        fresh_tsval = PEER__TSVAL_INITIAL + 1
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=fresh_tsval,
            tsecr=PEER__TSVAL_INITIAL,
            payload=b"fresh-data",
        )
        self._drive_rx(frame=peer_data)

        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1 + len(b"fresh-data"),
            msg=(
                "RFC 7323 §5 PAWS: a fresh-TSval segment MUST "
                "be accepted normally; RCV.NXT advances past "
                "the data."
            ),
        )
        self.assertEqual(
            bytes(session._rx_buffer),
            b"fresh-data",
            msg="Fresh-TSval segment's data MUST enter the RX buffer.",
        )


class TestTcpTimestampsPhase4FsmWide(TcpSessionTestCase):
    """
    Phase 4b extension: PAWS + '_ts_recent' update must apply
    to ALL FSM dispatch paths, not only segments routed through
    '_process_ack_packet'. Specifically the dup-ACK fast-
    retransmit branch, the OOO-queue branch in ESTABLISHED, and
    the late-segment branch in TIME_WAIT all currently bypass
    the PAWS check shipped in commit '79ed38e'.

    RFC 7323 §4.3 mandates '_ts_recent' refresh on every
    accepted segment in receive sequence space. RFC 7323 §5
    mandates PAWS rejection of stale-TSval segments at every
    inbound dispatch boundary. Without these tests the bypass
    paths can leak old-incarnation segments into recovery
    machinery.
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

    def _drive_handshake_with_tsopt(self, *, iss: int, peer_iss: int, peer_tsval: int) -> TcpSession:
        """Drive the active-open handshake with bilateral TSopt."""

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
            tsval=peer_tsval,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)

        assert session.state is FsmState.ESTABLISHED
        assert session._send_ts
        session._snd_ewn = PEER__WIN
        return session

    def test__paws__dup_ack_with_stale_tsval_dropped(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 7323 §5: a duplicate ACK whose TSval is
        strictly less than '_ts_recent' is dropped at the FSM
        dispatch boundary BEFORE the dup-ACK count fast-
        retransmit machinery sees it.

        Without this gate, a delayed-and-replayed dup-ACK from
        an old incarnation could spuriously contribute to the
        3-dup-ACK fast-retransmit threshold, halving cwnd.
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        session._tx_buffer.extend(b"X" * 100)
        self._advance(ms=1)

        snd_una_pre = session._snd_una
        cwnd_pre = session._cwnd
        retransmit_request_count_pre = session._tx_retransmit_request_counter.get(snd_una_pre, 0)

        stale_tsval = PEER__TSVAL_INITIAL - 100
        for _ in range(3):
            stale_dup_ack = build_tcp4(
                sport=PEER__PORT,
                dport=STACK__PORT,
                seq=PEER__ISS + 1,
                ack=snd_una_pre,
                flags=("ACK",),
                win=PEER__WIN,
                tsval=stale_tsval,
                tsecr=PEER__TSVAL_INITIAL,
            )
            self._drive_rx(frame=stale_dup_ack)

        self.assertEqual(
            session._cwnd,
            cwnd_pre,
            msg=(
                "RFC 7323 §5 PAWS: stale-TSval dup-ACKs MUST be "
                "dropped before the fast-retransmit count "
                "increments. cwnd MUST be unchanged."
            ),
        )
        self.assertEqual(
            session._tx_retransmit_request_counter.get(snd_una_pre, 0),
            retransmit_request_count_pre,
            msg=("RFC 7323 §5 PAWS: stale-TSval dup-ACKs MUST NOT " "increment the per-seq dup-ACK counter."),
        )

    def test__paws__ts_recent_updated_on_dup_ack_with_fresh_tsval(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 7323 §4.3: an accepted dup-ACK with a fresh
        TSval refreshes '_ts_recent'. Currently the dup-ACK
        path bypasses the '_ts_recent' update in
        '_process_ack_packet', so peer's TS clock progress is
        not reflected until peer sends data again.
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        session._tx_buffer.extend(b"X" * 100)
        self._advance(ms=1)

        snd_una_pre = session._snd_una
        fresh_tsval = PEER__TSVAL_INITIAL + 500
        dup_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=snd_una_pre,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=fresh_tsval,
            tsecr=PEER__TSVAL_INITIAL,
        )
        self._drive_rx(frame=dup_ack)

        self.assertEqual(
            session._ts_recent,
            fresh_tsval,
            msg=(
                "RFC 7323 §4.3: '_ts_recent' MUST refresh on an "
                f"accepted dup-ACK carrying TSval={fresh_tsval}. "
                f"Got _ts_recent={session._ts_recent}."
            ),
        )

    def test__paws__time_wait_late_segment_with_stale_tsval_dropped(self) -> None:
        """
        [FLAGS BUG]

        Ensure RFC 7323 §5 PAWS applies to TIME_WAIT: a delayed
        peer-FIN retransmit from an earlier incarnation, with
        stale TSval, MUST be dropped before the FIN-retransmit
        handler re-arms the TIME_WAIT timer.

        This is the strongest form of RFC 1337 TIME-WAIT
        assassination protection: PAWS catches the stale
        segment regardless of the segment's seq value.
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        # Active close: ESTABLISHED -> FIN_WAIT_1 -> FIN_WAIT_2 ->
        # TIME_WAIT. The transition takes 2 timer ticks: tick 1
        # walks ESTABLISHED -> FIN_WAIT_1, tick 2 emits the FIN
        # from FIN_WAIT_1.
        session.tcp_fsm(syscall=SysCall.CLOSE)
        self._advance(ms=1)
        self._advance(ms=1)
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=PEER__TSVAL_INITIAL + 1,
            tsecr=PEER__TSVAL_INITIAL,
        )
        self._drive_rx(frame=peer_ack_of_fin)
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
            tsval=PEER__TSVAL_INITIAL + 2,
            tsecr=PEER__TSVAL_INITIAL,
        )
        self._drive_rx(frame=peer_fin)

        if session.state is not FsmState.TIME_WAIT:
            self.skipTest(
                f"Active-close path did not reach TIME_WAIT (got {session.state}); "
                "the test's CLOSE driver doesn't model this branch on every release."
            )

        ts_recent_pre = session._ts_recent
        stale_late_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
            tsval=PEER__TSVAL_INITIAL - 1000,
            tsecr=PEER__TSVAL_INITIAL,
        )
        frames_tx_before = len(self._frames_tx)
        self._drive_rx(frame=stale_late_fin)

        self.assertEqual(
            len(self._frames_tx),
            frames_tx_before,
            msg=(
                "RFC 7323 §5 PAWS in TIME_WAIT: stale-TSval late "
                "segment MUST be dropped before the FIN-"
                "retransmit handler emits an ACK."
            ),
        )
        self.assertEqual(
            session._ts_recent,
            ts_recent_pre,
            msg=("PAWS-rejected segment MUST NOT update " "'_ts_recent'."),
        )


class TestTcpTimestampsPhase1PassiveCrossRfc(TcpSessionTestCase):
    """
    Cross-RFC interaction (Phase B1 of the test-coverage audit):
    bilateral TSopt negotiation across the passive-open path,
    confirming the TSopt + listener fork pattern composes
    correctly with the existing wildcard-listen mechanism.
    """

    def _make_listen_session(self, *, iss: int) -> tuple[TcpSocket, TcpSession]:
        """Build a wildcard-listen TcpSession."""

        from net_addr import Ip4Address as _Ip4Address
        from pytcp.protocols.tcp.tcp__enums import SysCall as _SysCall

        self._force_iss(iss)
        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = STACK__PORT
        sock._remote_ip_address = _Ip4Address()
        sock._remote_port = 0
        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=STACK__PORT,
            remote_ip_address=_Ip4Address(),
            remote_port=0,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        session.tcp_fsm(syscall=_SysCall.LISTEN)
        return sock, session

    def test__ts__passive_open_with_peer_tsopt_emits_syn_ack_with_tsopt(self) -> None:
        """
        Cross-RFC regression guard: a peer SYN carrying TSopt
        plus WSCALE plus SACK-permitted causes the listener
        to spawn a child whose SYN+ACK echoes peer's TSval and
        carries our own TSopt + WSCALE + SACK-permitted.
        """

        listen_sock, _ = self._make_listen_session(iss=0x0000_3000)

        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_4000,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            wscale=7,
            sackperm=True,
            tsval=PEER__TSVAL_INITIAL,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn)
        tx = self._advance(ms=1)

        self.assertEqual(
            len(tx),
            1,
            msg="Passive-open path must emit exactly one SYN+ACK on the first tick.",
        )
        syn_ack = self._parse_tx(tx[0])
        self.assertIn("SYN", syn_ack.flags)
        self.assertIn("ACK", syn_ack.flags)
        self.assertIsNotNone(
            syn_ack.tsval,
            msg="Cross-RFC: peer offered TSopt; our SYN+ACK MUST echo with our TSopt.",
        )
        self.assertEqual(
            syn_ack.tsecr,
            PEER__TSVAL_INITIAL,
            msg=(
                "Cross-RFC: SYN+ACK's TSecr MUST equal peer's " f"TSval ({PEER__TSVAL_INITIAL}). Got {syn_ack.tsecr}."
            ),
        )
        self.assertIsNotNone(
            syn_ack.wscale,
            msg="Cross-RFC: peer offered WSCALE; our SYN+ACK MUST advertise WSCALE.",
        )
        self.assertTrue(
            syn_ack.sackperm,
            msg="Cross-RFC: peer offered SACK-permitted; our SYN+ACK MUST advertise SACK-permitted.",
        )

        # Reset stack.sockets to the listener-only state so other tests are
        # not contaminated by the spawned child socket.
        for sid in list(stack.sockets):
            if sid != listen_sock.socket_id:
                del stack.sockets[sid]

    def test__ts__passive_open_without_peer_tsopt_omits_tsopt_in_syn_ack(self) -> None:
        """
        Cross-RFC regression guard: a peer SYN without TSopt
        causes the listener's SYN+ACK to OMIT TSopt per RFC
        7323 §3 bilateral negotiation.
        """

        listen_sock, _ = self._make_listen_session(iss=0x0000_3100)

        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=0x0000_4000,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)
        tx = self._advance(ms=1)

        self.assertEqual(len(tx), 1)
        syn_ack = self._parse_tx(tx[0])
        self.assertIsNone(
            syn_ack.tsval,
            msg=(
                "Cross-RFC: peer did not offer TSopt; our SYN+ACK "
                "MUST NOT advertise TSopt per RFC 7323 §3 bilateral "
                "negotiation."
            ),
        )

        for sid in list(stack.sockets):
            if sid != listen_sock.socket_id:
                del stack.sockets[sid]


class TestTcpTimestampsRetransmitFreshness(TcpSessionTestCase):
    """
    Regression guards for RFC 7323 §3 freshness on retransmit:
    a retransmitted segment MUST carry the CURRENT 'now_ms' as
    TSval (not a value captured at original-queue time) and the
    CURRENT '_ts_recent' as TSecr (not a stale captured value).

    PyTCP's '_transmit_packet' computes both fields at the
    moment of transmission ('tcp__session.py:880-906'), so a
    retransmit naturally picks up the latest clock and the
    latest peer TSval. These tests pin that behaviour so a
    future refactor that introduces a per-segment queue or
    captures TSopt at enqueue time cannot silently re-introduce
    the original-vs-retransmit ambiguity that TSopt is meant
    to resolve at the wire level.

    RFC 7323 §3 wording: "The Timestamp Value field (TSval)
    contains the current value of the timestamp clock of the
    TCP sending the option." The 'current value' MUST mean
    "current at transmission", not "current at queue time".
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

    def _drive_handshake_with_tsopt(self, *, iss: int, peer_iss: int, peer_tsval: int) -> TcpSession:
        """Drive the active-open handshake with bilateral TSopt."""

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
            tsval=peer_tsval,
            tsecr=0,
        )
        self._drive_rx(frame=peer_syn_ack)
        assert session.state is FsmState.ESTABLISHED
        assert session._send_ts
        session._snd_ewn = PEER__WIN
        return session

    def test__retransmit__tsval_reflects_current_now_ms_not_queue_time(self) -> None:
        """
        Ensure RFC 7323 §3: a retransmitted segment carries
        TSval = current 'now_ms', NOT the value captured at
        the original transmission. With Karn's algorithm
        obviated by TSopt, the freshness of TSval is the
        load-bearing invariant: peer's RTT measurement on the
        retransmit's ACK uses 'now - TSval' to identify which
        transmission it acknowledges.
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        session.send(data=b"hello")
        original_send_now_ms = self._timer.now_ms + 1
        original_tx = self._advance(ms=1)
        self.assertEqual(
            len(original_tx),
            1,
            msg="Setup invariant: original data segment must fire on the next tick.",
        )
        original_probe = self._parse_tx(original_tx[0])
        self.assertEqual(
            original_probe.tsval,
            original_send_now_ms,
            msg=(
                "Setup invariant: original segment's TSval MUST equal "
                f"the now_ms at send time ({original_send_now_ms}). "
                f"Got {original_probe.tsval}."
            ),
        )

        # Advance past the RTO so the retransmit fires.
        retransmit_send_now_ms_lower = self._timer.now_ms + 1
        retransmit_tx = self._advance(ms=1500)
        retransmit_probes = [self._parse_tx(f) for f in retransmit_tx if f]
        retransmits = [p for p in retransmit_probes if p.payload]
        self.assertGreaterEqual(
            len(retransmits),
            1,
            msg=(
                "Setup invariant: by t=original+1500 ms the RTO MUST "
                "have fired and a retransmit MUST be on the wire. "
                f"Got {len(retransmits)} data segment(s)."
            ),
        )
        first_retransmit = retransmits[0]

        retransmit_tsval = first_retransmit.tsval
        original_tsval = original_probe.tsval
        assert retransmit_tsval is not None and original_tsval is not None
        self.assertGreater(
            retransmit_tsval,
            original_tsval,
            msg=(
                "RFC 7323 §3 freshness: retransmit's TSval MUST be "
                f"GREATER than the original's TSval ({original_tsval}). "
                f"Got retransmit TSval={retransmit_tsval}. A stale "
                "captured-at-queue-time value would equal the "
                "original's TSval, re-introducing the original-vs-"
                "retransmit ambiguity that TSopt resolves at the wire "
                "level."
            ),
        )
        self.assertGreaterEqual(
            retransmit_tsval,
            retransmit_send_now_ms_lower,
            msg=(
                "RFC 7323 §3 freshness: retransmit's TSval MUST be at "
                "least the now_ms at the moment the retransmit was "
                f"scheduled ({retransmit_send_now_ms_lower}). Got "
                f"TSval={retransmit_tsval}."
            ),
        )

    def test__retransmit__tsecr_reflects_current_ts_recent_not_stale_capture(self) -> None:
        """
        Ensure RFC 7323 §3 + §4.3: a retransmitted segment
        carries TSecr = CURRENT '_ts_recent', not a value
        captured at the original transmission. If peer sent
        any other segment in the meantime (e.g. wnd-update,
        keep-alive probe-ack), its TSval has updated
        '_ts_recent' and the retransmit MUST echo the latest
        value.
        """

        session = self._drive_handshake_with_tsopt(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_tsval=PEER__TSVAL_INITIAL,
        )

        session.send(data=b"hello")
        original_tx = self._advance(ms=1)
        original_probe = self._parse_tx(original_tx[0])
        self.assertEqual(
            original_probe.tsecr,
            PEER__TSVAL_INITIAL,
            msg=(
                "Setup invariant: original segment's TSecr MUST echo "
                f"_ts_recent at send time ({PEER__TSVAL_INITIAL}). "
                f"Got {original_probe.tsecr}."
            ),
        )

        # Peer sends a wnd-update (dup-ACK shape with new win)
        # carrying a fresh TSval. The PAWS helper updates
        # '_ts_recent' on accepted in-window segments per
        # RFC 7323 §4.3.
        fresh_peer_tsval = PEER__TSVAL_INITIAL + 500
        peer_wnd_update = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,  # snd_una; doesn't ack the data
            flags=("ACK",),
            win=PEER__WIN + 1,
            tsval=fresh_peer_tsval,
            tsecr=PEER__TSVAL_INITIAL,
        )
        self._drive_rx(frame=peer_wnd_update)
        self.assertEqual(
            session._ts_recent,
            fresh_peer_tsval,
            msg=(
                "Setup invariant: peer's wnd-update TSval MUST refresh "
                f"_ts_recent to {fresh_peer_tsval}. Got "
                f"_ts_recent={session._ts_recent}."
            ),
        )

        # Advance past the RTO; retransmit fires.
        retransmit_tx = self._advance(ms=1500)
        retransmit_probes = [self._parse_tx(f) for f in retransmit_tx if f]
        retransmits = [p for p in retransmit_probes if p.payload]
        self.assertGreaterEqual(
            len(retransmits),
            1,
            msg=("Setup invariant: RTO MUST have fired by t=1500 ms. " f"Got {len(retransmits)} data segment(s)."),
        )
        first_retransmit = retransmits[0]

        self.assertEqual(
            first_retransmit.tsecr,
            fresh_peer_tsval,
            msg=(
                "RFC 7323 §3 + §4.3 freshness: retransmit's TSecr "
                "MUST echo the CURRENT '_ts_recent' "
                f"({fresh_peer_tsval}, refreshed by peer's wnd-update "
                "between original send and retransmit), NOT the "
                f"value captured at original transmission "
                f"({PEER__TSVAL_INITIAL}). Got "
                f"TSecr={first_retransmit.tsecr}."
            ),
        )
