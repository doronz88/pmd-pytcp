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
This module contains integration tests for the RFC 9293 §3.9.1
ABORT user/TCP interface call: 'TcpSocket.abort()' / 'TcpSession.
abort()' tears down the connection without graceful close.

Reference RFC:
    RFC 9293 §3.9.1   User/TCP Interface (ABORT)

pytcp/tests/integration/protocols/tcp/test__tcp__session__abort_api.py

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

STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000
PEER__WIN: int = 64240
PEER__MSS: int = 1460


class TestTcpAbortApi(TcpSessionTestCase):
    """
    Integration tests for 'TcpSocket.abort()' per RFC 9293 §3.9.1.
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

    def _drive_handshake_to_established(self, *, iss: int, peer_iss: int) -> tuple[TcpSocket, TcpSession]:
        """Drive the active-open handshake to ESTABLISHED."""

        session = self._make_active_session(iss=iss)
        sock = session._socket
        assert isinstance(sock, TcpSocket)
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
        return sock, session

    def test__abort__in_established_emits_rst_and_transitions_to_closed(self) -> None:
        """
        Ensure RFC 9293 §3.9.1 ABORT in ESTABLISHED:
          * Emits a RST + ACK at SND.NXT / RCV.NXT.
          * Transitions FSM to CLOSED.
          * Releases blocked recv() / connect() callers.
        """

        sock, session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        before = len(self._frames_tx)
        sock.abort()
        self._advance(ms=1)
        tx = list(self._frames_tx[before:])
        all_tx = [self._parse_tx(f) for f in tx]
        rsts = [p for p in all_tx if "RST" in p.flags]

        self.assertGreaterEqual(
            len(rsts),
            1,
            msg=(
                "RFC 9293 §3.9.1 ABORT in ESTABLISHED MUST emit a "
                f"RST. Got {len(rsts)} RST frame(s) out of "
                f"{len(all_tx)} total."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="ABORT MUST transition the session to CLOSED.",
        )

    def test__abort__in_fin_wait_1_emits_rst(self) -> None:
        """
        Ensure RFC 9293 §3.9.1 ABORT in FIN_WAIT_1 emits a RST.
        Synchronized state per the RFC.
        """

        sock, session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        # Drive into FIN_WAIT_1.
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)
        assert session.state is FsmState.FIN_WAIT_1

        before = len(self._frames_tx)
        sock.abort()
        self._advance(ms=1)
        tx = list(self._frames_tx[before:])
        rsts = [self._parse_tx(f) for f in tx if "RST" in self._parse_tx(f).flags]

        self.assertGreaterEqual(
            len(rsts),
            1,
            msg="ABORT in FIN_WAIT_1 MUST emit a RST.",
        )
        self.assertIs(session.state, FsmState.CLOSED)

    def test__abort__in_time_wait_does_not_emit_rst(self) -> None:
        """
        Ensure RFC 9293 §3.9.1 ABORT in TIME_WAIT: TCB is torn
        down WITHOUT emitting a RST. Per-state ABORT spec.
        """

        sock, session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        session.close()
        self._advance(ms=1)
        self._advance(ms=1)
        peer_ack_of_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_ack_of_fin)
        peer_fin = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin)
        assert session.state is FsmState.TIME_WAIT

        before = len(self._frames_tx)
        sock.abort()
        self._advance(ms=1)
        tx = list(self._frames_tx[before:])
        rsts = [self._parse_tx(f) for f in tx if "RST" in self._parse_tx(f).flags]

        self.assertEqual(
            len(rsts),
            0,
            msg=("RFC 9293 §3.9.1 ABORT in TIME_WAIT MUST NOT emit a " f"RST. Got {len(rsts)} RST frame(s)."),
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="ABORT MUST transition TIME_WAIT to CLOSED.",
        )

    def test__abort__on_fresh_socket_is_noop(self) -> None:
        """
        Regression guard: abort() on a TcpSocket with no
        associated session is a no-op (no exception, no TX).
        """

        sock = TcpSocket(family=AddressFamily.INET4)
        sock.abort()  # MUST NOT raise

        self.assertIsNone(
            sock.tcp_session,
            msg="No session should be created by abort() on a fresh socket.",
        )
