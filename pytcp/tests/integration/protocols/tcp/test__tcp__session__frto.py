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
This module contains integration tests for RFC 5682 F-RTO
(Forward RTO-Recovery) in 'TcpSession'. F-RTO detects
"spurious" RTOs - where the timeout fires but the original
segments were actually delivered (the ACK was just delayed,
e.g. due to a brief latency spike). On detection, the
session restores the pre-RTO cwnd and ssthresh values, so a
single spurious RTO does not collapse the connection's
throughput. Without F-RTO, every spurious RTO reduces cwnd
to 1 MSS and halves ssthresh - on lossy networks (mobile
handoffs, satellite, wifi) this materially degrades
throughput.

PyTCP implements a SIMPLIFIED F-RTO: the first post-RTO ACK
that advances SND.UNA to the pre-RTO SND.MAX is treated as
the spurious signal, and pre-RTO cwnd/ssthresh are restored.
This handles the canonical spurious case (ACK was delayed,
all originals delivered) without the 2-segment probe step
in the strict RFC 5682 §3 algorithm. The probe step would
only help for the "in between" case where some originals
were delivered but not all - rare in practice.

pytcp/tests/integration/protocols/tcp/test__tcp__session__frto.py

ver 3.0.4
"""

from net_addr import Ip4Address  # noqa: F401
from pytcp import stack
from pytcp.protocols.tcp.tcp__constants import PACKET_RETRANSMIT_TIMEOUT
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

# Initial sequence numbers.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised window + MSS.
PEER__WIN: int = 64240
PEER__MSS: int = 1460


class TestTcpSession__Frto(TcpSessionTestCase):
    """
    Integration tests for the RFC 5682 F-RTO spurious-RTO
    detection and recovery undo.
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
        """
        Drive an active-open three-way handshake to ESTABLISHED
        and bypass slow-start so the test can trigger F-RTO
        cleanly without entanglement with the §3.1 cwnd
        doubling cadence.
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

        # Bypass slow-start: tests of F-RTO restoration need
        # a deterministic non-slow-start cwnd/ssthresh state
        # that the spurious-event path can revert to.
        session._snd_ewn = PEER__WIN
        return session

    def test__frto__spurious_rto_restores_pre_rto_cwnd_and_ssthresh(self) -> None:
        """
        Ensure that when an RTO fires, the original segments
        are subsequently acknowledged in full (the canonical
        "ACK was just delayed" spurious-RTO scenario), the
        session restores the pre-RTO cwnd and ssthresh
        values. Without F-RTO, the connection collapses
        cwnd to 1 MSS and halves ssthresh on every spurious
        timeout, materially degrading throughput on lossy
        networks where brief latency spikes are common
        (mobile handoffs, wifi roaming, satellite jitter).

        Reference: RFC 5682 §3.1 (F-RTO spurious-RTO detection).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Send 3 segments worth of data; record cwnd/ssthresh
        # before the RTO fires so we can assert restoration.
        payload = b"A" * PEER__MSS + b"B" * PEER__MSS + b"C" * PEER__MSS
        session.send(data=payload)
        self._advance(ms=1)

        cwnd_before_rto = session._cwnd
        ssthresh_before_rto = session._ssthresh
        snd_max_at_rto = session._snd_max

        # Don't ACK; advance past PACKET_RETRANSMIT_TIMEOUT
        # so the RTO fires. After RTO, cwnd is collapsed to
        # 1 MSS and ssthresh is halved per RFC 5681 §3.1.
        self._advance(ms=PACKET_RETRANSMIT_TIMEOUT + 1)

        self.assertNotEqual(
            session._cwnd,
            cwnd_before_rto,
            msg=(
                "Setup precondition: RTO MUST collapse cwnd "
                "below the pre-RTO value before F-RTO can "
                f"restore it. Got cwnd={session._cwnd}, "
                f"cwnd_before_rto={cwnd_before_rto}."
            ),
        )

        # Peer's cumulative ACK arrives covering ALL three
        # original segments. In the spurious-RTO scenario,
        # the originals were delivered but the ACK was just
        # delayed - now it covers seq up to the pre-RTO
        # SND.MAX, the canonical signal.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=snd_max_at_rto,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack)

        self.assertEqual(
            session._cwnd,
            cwnd_before_rto,
            msg=(
                "RFC 5682 §3.1: when the first post-RTO ACK "
                "covers all pre-RTO outstanding data, the RTO "
                "is spurious and cwnd MUST be restored to its "
                f"pre-RTO value. Got cwnd={session._cwnd}, "
                f"expected {cwnd_before_rto}."
            ),
        )
        self.assertEqual(
            session._ssthresh,
            ssthresh_before_rto,
            msg=(
                "RFC 5682 §3.1: spurious-RTO detection MUST "
                "restore ssthresh to the pre-RTO value. Got "
                f"ssthresh={session._ssthresh}, expected "
                f"{ssthresh_before_rto}."
            ),
        )

    def test__frto__genuine_rto_keeps_cwnd_halved(self) -> None:
        """
        Ensure that when an RTO fires and the first post-RTO
        ACK covers ONLY the retransmitted segment (not the
        full pre-RTO outstanding data) - the canonical
        "genuine packet loss" scenario - the session does
        NOT restore pre-RTO cwnd / ssthresh. The RTO
        recovery cadence (cwnd=1 MSS slow-start, halved
        ssthresh) stays in effect because the partial-ACK
        signature confirms data really was lost.

        Reference: RFC 5682 §3.1 (F-RTO genuine-RTO regression guard).
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Same 3-segment send so flight_size matches the
        # spurious test for symmetry.
        payload = b"A" * PEER__MSS + b"B" * PEER__MSS + b"C" * PEER__MSS
        session.send(data=payload)
        self._advance(ms=1)

        cwnd_before_rto = session._cwnd
        ssthresh_before_rto = session._ssthresh

        # Don't ACK; trigger RTO.
        self._advance(ms=PACKET_RETRANSMIT_TIMEOUT + 1)

        ssthresh_after_rto = session._ssthresh

        # Peer's ACK covers only the FIRST segment (the
        # retransmit) - segments B and C were genuinely
        # lost. ack = LOCAL__ISS + 1 + PEER__MSS = end of A.
        peer_partial_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1 + PEER__MSS,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_partial_ack)

        self.assertLess(
            session._cwnd,
            cwnd_before_rto,
            msg=(
                "RFC 5682 §3.1: when the first post-RTO ACK "
                "covers only the retransmit (not all pre-RTO "
                "data), the RTO was genuine and cwnd MUST "
                "NOT be restored to the pre-RTO value. "
                "Slow-start growth on the partial cum-ACK is "
                "expected, but cwnd should stay well below "
                f"the pre-RTO {cwnd_before_rto}. Got "
                f"cwnd={session._cwnd}."
            ),
        )
        self.assertEqual(
            session._ssthresh,
            ssthresh_after_rto,
            msg=(
                "RFC 5682 §3.1: genuine-RTO recovery MUST "
                "leave ssthresh at its halved post-RTO value "
                "(F-RTO restoration MUST NOT fire). Got "
                f"ssthresh={session._ssthresh}, expected "
                f"{ssthresh_after_rto} (which is < pre-RTO "
                f"{ssthresh_before_rto})."
            ),
        )
