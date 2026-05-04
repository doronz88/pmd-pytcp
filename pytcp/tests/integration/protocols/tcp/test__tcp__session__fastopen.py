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
        Ensure that when an inbound SYN carries the Fast Open
        option with an empty cookie (the cookie-request form,
        Length = 2), our SYN+ACK reply carries the Fast Open
        option with a non-empty 4..16 byte cookie that the
        peer can cache and present on a subsequent connection.
        The cookie value itself is opaque from the peer's
        perspective.

        Reference: RFC 7413 §2 (Fast Open option wire format and cookie length 4..16 bytes).
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

    def test__fastopen__server_discards_syn_data_when_cookie_invalid(self) -> None:
        """
        Ensure that when a peer SYN carries the Fast Open
        option with an INVALID (or empty / cookie-request)
        cookie alongside a data payload, the server
        discards the data and falls back to a standard
        three-way handshake. The SYN+ACK 'ack' field MUST
        cover only the SYN (peer_iss + 1) - NOT the SYN
        plus data length - and the data MUST NOT be queued
        into the receive buffer where a future 'recv()'
        could deliver it to the application. The cookie
        gate is the canonical amplification-attack defence:
        an off-path attacker spoofing a SYN with data
        cannot commit server memory without first proving
        peer-IP reachability via a valid cookie.

        Reference: RFC 7413 §3.1 (server discards data on invalid TFO cookie).
        Reference: RFC 7413 §4.1.2 (cookie validation gate before data acceptance).
        """

        _listen_sock, listen_session = self._make_listen_session(iss=LOCAL__ISS)

        # Peer SYN with the empty-cookie request form
        # (invalid for data acceptance per §4.1.2) plus a
        # non-trivial data payload that would otherwise be
        # delivered to the application's recv() buffer.
        syn_data = b"hello-tfo"
        peer_syn_data_no_cookie = build_tcp4(
            sport=PEER__PORT_FOR_FASTOPEN,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            fastopen_cookie=b"",  # cookie-request form, invalid for data
            payload=syn_data,
        )
        self._drive_rx(frame=peer_syn_data_no_cookie)

        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK MUST fire on the next tick.",
        )
        syn_ack = self._parse_tx(syn_ack_tx[0])

        self.assertEqual(
            syn_ack.flags & frozenset({"SYN", "ACK", "RST", "FIN"}),
            frozenset({"SYN", "ACK"}),
            msg=(
                "Setup precondition: outbound segment MUST be a " f"SYN+ACK (no RST/FIN). Got flags={syn_ack.flags!r}."
            ),
        )
        # The spec encoding: ack covers only the SYN's
        # one byte of seq space; the data is discarded.
        self.assertEqual(
            syn_ack.ack,
            PEER__ISS + 1,
            msg=(
                "RFC 7413 §3.1: SYN+ACK 'ack' MUST equal "
                f"peer_iss + 1 = {PEER__ISS + 1} when the "
                "TFO cookie is invalid - the server MUST NOT "
                "ack the SYN-data. Got "
                f"{syn_ack.ack} (= peer_iss + 1 + "
                f"{syn_ack.ack - PEER__ISS - 1}); the server "
                "is acking the data despite the missing valid "
                "cookie, which violates the §4.1.2 "
                "amplification-attack defence."
            ),
        )
        # Data MUST NOT be queued into the listening child's
        # receive buffer. Today PyTCP queues SYN-data
        # unconditionally per RFC 9293 §3.10.7.2 step 3;
        # the TFO cookie gate is the security override.
        self.assertEqual(
            bytes(listen_session._rx_buffer),
            b"",
            msg=(
                "RFC 7413 §3.1: invalid TFO cookie + SYN-data "
                "MUST result in the data being discarded - the "
                "child session's '_rx_buffer' MUST be empty. "
                f"Got {bytes(listen_session._rx_buffer)!r}."
            ),
        )

    def test__fastopen__server_accepts_syn_data_with_valid_cookie(self) -> None:
        """
        Ensure that when a peer SYN carries the Fast Open
        option with a previously-issued (and therefore
        valid for this peer IP) cookie alongside a data
        payload, the server accepts the data: the SYN+ACK
        'ack' field covers both the SYN and the data
        ('peer_iss + 1 + len(data)') and the data is
        queued into the child session's receive buffer
        ready for the application's eventual 'recv()'.

        The valid cookie is computed via the same HMAC
        helper the server uses for issuance, so the test
        exercises the round-trip the cookie validation
        path is gated on.

        Reference: RFC 7413 §3.1 (server accepts SYN-data on valid TFO cookie).
        """

        from pytcp import stack
        from pytcp.protocols.tcp.tcp__fastopen import generate_cookie

        # Compute the cookie the server WOULD issue for our
        # test peer IP - this is what a peer would have
        # cached after a previous round-trip and would now
        # replay on a TFO-fast-open SYN.
        valid_cookie = generate_cookie(
            peer_address=PEER__IP,
            secret=stack.TCP__FASTOPEN_SECRET,
        )

        _listen_sock, listen_session = self._make_listen_session(iss=LOCAL__ISS)

        syn_data = b"valid-tfo-data"
        peer_syn_with_cookie_and_data = build_tcp4(
            sport=PEER__PORT_FOR_FASTOPEN,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            fastopen_cookie=valid_cookie,
            payload=syn_data,
        )
        self._drive_rx(frame=peer_syn_with_cookie_and_data)

        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK MUST fire on the next tick.",
        )
        syn_ack = self._parse_tx(syn_ack_tx[0])

        # The spec encoding: ack covers SYN + data.
        self.assertEqual(
            syn_ack.ack,
            PEER__ISS + 1 + len(syn_data),
            msg=(
                "RFC 7413 §3.1: SYN+ACK 'ack' MUST equal "
                f"peer_iss + 1 + len(data) = "
                f"{PEER__ISS + 1 + len(syn_data)} when the "
                "TFO cookie is valid. The server has "
                f"accepted the {len(syn_data)} bytes of "
                f"SYN-data. Got {syn_ack.ack}."
            ),
        )
        # Data MUST be queued for delivery to the
        # application via 'recv()'.
        self.assertEqual(
            bytes(listen_session._rx_buffer),
            syn_data,
            msg=(
                "RFC 7413 §3.1: SYN-data with valid TFO "
                "cookie MUST be queued into the child "
                f"session's '_rx_buffer'. Expected "
                f"{syn_data!r}, got "
                f"{bytes(listen_session._rx_buffer)!r}."
            ),
        )

    def _make_active_session(self, *, iss: int) -> TcpSession:
        """
        Build a 'TcpSocket' / 'TcpSession' pair the way
        'connect()' would, returning the session in CLOSED.
        """

        self._force_iss(iss)
        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = PEER__PORT_FOR_FASTOPEN  # arbitrary client port
        sock._remote_ip_address = PEER__IP
        sock._remote_port = LISTEN__PORT
        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=PEER__PORT_FOR_FASTOPEN,
            remote_ip_address=PEER__IP,
            remote_port=LISTEN__PORT,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        return session

    def test__fastopen__active_open_syn_advertises_tfo_cookie_request(self) -> None:
        """
        Ensure that on an active-open connection the
        outbound SYN carries the Fast Open option in the
        cookie-request form (Length = 2, empty cookie).
        This is the canonical client-side first-connect
        behaviour: the client has no cached cookie for
        this server yet, so it advertises an empty cookie
        request to elicit the server's cookie issuance in
        the SYN+ACK reply. On a subsequent connection the
        client would replay the cached cookie + data
        payload to skip the data RTT.

        Reference: RFC 7413 §3.1 (client first connect emits TFO cookie request).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN MUST fire on the first tick.",
        )
        syn = self._parse_tx(syn_tx[0])

        self.assertEqual(
            syn.flags,
            frozenset({"SYN"}),
            msg=("Setup precondition: outbound segment MUST be " f"a pure SYN (active open). Got flags={syn.flags!r}."),
        )
        # The spec encoding: TFO option present with empty
        # cookie payload (Length = 2, the cookie-request form).
        self.assertEqual(
            syn.fastopen_cookie,
            b"",
            msg=(
                "RFC 7413 §3.1: client's active-open SYN MUST "
                "carry the Fast Open option in the cookie-request "
                "form (empty cookie). Got "
                f"fastopen_cookie={syn.fastopen_cookie!r}; "
                "the option appears absent from the wire (None) "
                "today because PyTCP does not yet emit TFO on "
                "outbound active-open SYNs."
            ),
        )
