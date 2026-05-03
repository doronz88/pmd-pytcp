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
Integration tests for the BSD-socket 'shutdown(how)' half-close
per RFC 9293 §3.9.1 + POSIX shutdown semantics.

pytcp/tests/integration/protocols/tcp/test__tcp__session__shutdown_api.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.tcp__session import (
    FsmState,
    SysCall,
    TcpSession,
    TcpSessionError,
)
from pytcp.socket import SHUT_RD, SHUT_RDWR, SHUT_WR, AddressFamily
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


class TestTcpShutdownApi(TcpSessionTestCase):
    """
    Integration tests for 'TcpSocket.shutdown(how)' /
    'TcpSession.shutdown(how)' per RFC 9293 §3.9.1 +
    POSIX shutdown semantics.
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

    def test__shutdown_wr__triggers_fin_emission(self) -> None:
        """
        Ensure shutdown(SHUT_WR) triggers the same FIN-emission
        path as close(): session transitions to FIN_WAIT_1, FIN
        goes out on the wire.
        """

        sock, session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock.shutdown(SHUT_WR)
        self._advance(ms=1)
        self._advance(ms=1)

        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="shutdown(SHUT_WR) MUST transition to FIN_WAIT_1.",
        )
        self.assertTrue(
            session._shut_wr,
            msg="_shut_wr MUST be set after shutdown(SHUT_WR).",
        )

    def test__shutdown_wr__rejects_subsequent_send(self) -> None:
        """
        Ensure send() after shutdown(SHUT_WR) raises
        TcpSessionError, like send() after close().
        """

        sock, session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        sock.shutdown(SHUT_WR)

        with self.assertRaises(TcpSessionError):
            session.send(data=b"too late")

    def test__shutdown_rd__discards_subsequent_inbound_data(self) -> None:
        """
        Ensure shutdown(SHUT_RD) silently discards subsequent
        inbound data: peer's segment is acknowledged but its
        bytes never enter '_rx_buffer'.
        """

        sock, session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)
        sock.shutdown(SHUT_RD)

        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"discarded",
        )
        self._drive_rx(frame=peer_data)

        self.assertEqual(
            len(session._rx_buffer),
            0,
            msg=(
                "shutdown(SHUT_RD): inbound data MUST be discarded; "
                f"_rx_buffer MUST stay empty. Got {len(session._rx_buffer)} "
                "bytes."
            ),
        )
        self.assertTrue(
            session._shut_rd,
            msg="_shut_rd MUST be set after shutdown(SHUT_RD).",
        )

    def test__shutdown_rdwr__sets_both_flags_and_emits_fin(self) -> None:
        """
        Ensure shutdown(SHUT_RDWR) is the union of SHUT_RD and
        SHUT_WR: both flags set, FIN emitted.
        """

        sock, session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock.shutdown(SHUT_RDWR)
        self._advance(ms=1)
        self._advance(ms=1)

        self.assertTrue(session._shut_rd)
        self.assertTrue(session._shut_wr)
        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="shutdown(SHUT_RDWR) MUST transition to FIN_WAIT_1.",
        )

    def test__shutdown_wr__idempotent_does_not_re_emit_fin(self) -> None:
        """
        Regression guard: a second shutdown(SHUT_WR) call after
        the first one MUST be a no-op. The FIN is not re-emitted
        at a new seq.
        """

        sock, session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        sock.shutdown(SHUT_WR)
        self._advance(ms=1)
        self._advance(ms=1)
        snd_nxt_after_first = session._snd_nxt

        sock.shutdown(SHUT_WR)
        self._advance(ms=1)

        self.assertEqual(
            session._snd_nxt,
            snd_nxt_after_first,
            msg=(
                "Idempotent shutdown(SHUT_WR) MUST NOT re-advance "
                f"SND.NXT. Pre={snd_nxt_after_first}, post={session._snd_nxt}."
            ),
        )

    def test__shutdown_on_fresh_socket_is_noop(self) -> None:
        """
        Regression guard: shutdown() on a TcpSocket with no
        associated session is a no-op (no exception).
        """

        sock = TcpSocket(family=AddressFamily.INET4)
        sock.shutdown(SHUT_WR)  # MUST NOT raise
        sock.shutdown(SHUT_RD)
        sock.shutdown(SHUT_RDWR)

        self.assertIsNone(sock.tcp_session)
