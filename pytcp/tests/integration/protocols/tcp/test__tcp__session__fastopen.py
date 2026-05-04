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
This module contains integration tests for RFC 7413 TCP Fast Open
(TFO) in 'TcpSession'. RFC 7413 §1 motivates TFO as the mechanism
that lets a TCP connection carry application data on the SYN
itself, eliminating the round-trip cost of the standard 3-way
handshake for short-lived connections (HTTP requests, RPC calls,
DNS over TCP, etc.).

The mechanism splits cleanly into two roles:

  Server side (this file's first scenarios):
    1. Cookie issuance: when peer sends SYN with the TFO option
       carrying an empty cookie (the 'cookie request' form), the
       server generates an opaque, peer-bound cookie (HMAC of the
       peer's IP + a server-side secret) and returns it in the
       SYN+ACK.
    2. Cookie use: when peer's SYN carries a previously-issued
       valid cookie + data payload, the server validates the
       cookie, queues the data for the application, and ACKs the
       data in the SYN+ACK so the application sees the data
       before the third-leg ACK arrives.

  Client side (subsequent scenarios):
    3. Cookie cache: client caches the server's cookie keyed by
       (peer IP, peer port).
    4. Connect-with-data: 'connect()' with data + cached cookie
       emits SYN with cookie + data. The server accepts the data
       in the SYN+ACK, eliminating the data RTT.

The RFC 7413 §2 wire format uses Kind = 34 and a Length field
that distinguishes empty-cookie (Length = 2, request form) from
non-empty-cookie (Length = 6..18, response/use form).

pytcp/tests/integration/protocols/tcp/test__tcp__session__fastopen.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.tcp__session import (
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
LISTEN__PORT: int = 80
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS

# Listen-side ISS pinned for deterministic SYN+ACK seq numbers.
LOCAL__ISS: int = 0x0000_3000

# Peer's advertised receive window on its SYN.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN.
PEER__MSS: int = 1460

# Peer's source ISS on its SYN.
PEER__ISS: int = 0x0000_4000

# Distinct peer source port for the TFO scenarios (avoids
# collision with other TestTcpSession__* classes that bind
# the canonical PEER__PORT = 80 themselves).
PEER__PORT_FOR_FASTOPEN: int = 33500


class TestTcpSession__FastOpen(TcpSessionTestCase):
    """
    Integration tests for RFC 7413 Fast Open (TFO) on
    'TcpSession'. The first scenario pins server-side cookie
    issuance: a SYN with an empty TFO cookie request MUST elicit
    a SYN+ACK that carries a non-empty cookie via the TFO option.
    """

    def _make_listen_session(self, *, iss: int) -> tuple[TcpSocket, TcpSession]:
        """
        Build a 'TcpSocket' / 'TcpSession' pair wired up the way
        'TcpSocket.listen()' would wire them.
        """

        self._force_iss(iss)
        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = LISTEN__PORT
        sock._remote_ip_address = Ip4Address()
        sock._remote_port = 0
        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=LISTEN__PORT,
            remote_ip_address=Ip4Address(),
            remote_port=0,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        session.tcp_fsm(syscall=SysCall.LISTEN)
        return sock, session

    def test__fastopen__server_issues_cookie_on_tfo_request_syn(self) -> None:
        """
        Ensure that when an inbound SYN carries the RFC 7413 §2
        TFO option with an empty cookie (the 'cookie request'
        form, Length = 2), our SYN+ACK reply carries the TFO
        option with a non-empty cookie that the peer can cache
        and present on a subsequent connection. Cookie length
        MUST fall in the RFC 7413 §2 range (4..16 bytes); the
        cookie value itself is opaque from the peer's
        perspective.

        Today PyTCP recognises kind = 34 only as a generic
        unknown TCP option (decoded as 'TcpOptionUnknown'); the
        session ignores it entirely and emits a vanilla SYN+ACK
        with no TFO response. This test pins the desired RFC
        7413 §3.1 behaviour.

        Reference: RFC 7413 §3.1 (server-side cookie issuance on TFO request).
        """

        _listen_sock, _listen_session = self._make_listen_session(iss=LOCAL__ISS)

        # Peer SYN with TFO option carrying an empty cookie
        # (the 'cookie request' form).
        peer_syn_tfo_request = build_tcp4(
            sport=PEER__PORT_FOR_FASTOPEN,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            fastopen_cookie=b"",  # empty cookie -> request form
        )
        self._drive_rx(frame=peer_syn_tfo_request)

        # Tick to fire SYN+ACK from the spawned child's timer.
        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg=("Setup precondition: the SYN+ACK MUST fire on " "the next tick after a SYN arrives."),
        )
        syn_ack = self._parse_tx(syn_ack_tx[0])

        self.assertEqual(
            syn_ack.flags & frozenset({"SYN", "ACK", "RST", "FIN"}),
            frozenset({"SYN", "ACK"}),
            msg=(
                "Setup precondition: outbound segment MUST be a " f"SYN+ACK (no RST/FIN). Got flags={syn_ack.flags!r}."
            ),
        )
        self.assertIsNotNone(
            syn_ack.fastopen_cookie,
            msg=(
                "RFC 7413 §3.1: a SYN+ACK in response to a TFO "
                "cookie request MUST carry the TFO option with a "
                "non-empty cookie. Today the option is absent on "
                "the wire (PyTCP ignores TFO entirely)."
            ),
        )
        # Cookie length per RFC 7413 §2 must be 4..16 bytes.
        assert syn_ack.fastopen_cookie is not None  # mypy
        cookie_len = len(syn_ack.fastopen_cookie)
        self.assertGreaterEqual(
            cookie_len,
            4,
            msg=(
                f"RFC 7413 §2: TFO cookie length MUST be at "
                f"least 4 bytes. Got {cookie_len} bytes "
                f"({syn_ack.fastopen_cookie!r})."
            ),
        )
        self.assertLessEqual(
            cookie_len,
            16,
            msg=(
                f"RFC 7413 §2: TFO cookie length MUST be at "
                f"most 16 bytes. Got {cookie_len} bytes "
                f"({syn_ack.fastopen_cookie!r})."
            ),
        )
