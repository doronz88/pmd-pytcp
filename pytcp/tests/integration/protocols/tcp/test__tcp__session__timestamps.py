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
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=new_tsval,
            tsecr=PEER__TSVAL_INITIAL,
        )
        self._drive_rx(frame=peer_ack)

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
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            tsval=new_tsval,
            tsecr=PEER__TSVAL_INITIAL,
        )
        self._drive_rx(frame=peer_ack)

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
