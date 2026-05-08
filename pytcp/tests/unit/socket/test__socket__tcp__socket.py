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


"""
This module contains tests for the 'TcpSocket' BSD-like TCP socket
implementation. The 'TcpSession' dependency is mocked — its own
behavior lives in the 'test__tcp__session__*.py' files.

pytcp/tests/unit/socket/test__socket__tcp__socket.py

ver 3.0.4
"""

import errno
import fcntl
import select
from types import SimpleNamespace
from typing import cast
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, Ip6Address
from net_proto.lib.enums import IpProto
from pytcp.protocols.tcp.tcp__session import FsmState, TcpSessionError
from pytcp.socket import (
    IPPROTO_TCP,
    SO_KEEPALIVE,
    SOL_SOCKET,
    TCP_FASTOPEN,
    TCP_KEEPCNT,
    TCP_KEEPIDLE,
    TCP_KEEPINTVL,
    TCP_NODELAY,
    AddressFamily,
    SocketType,
    gaierror,
)
from pytcp.socket.tcp__socket import TcpSocket


def _make_packet_handler(
    *,
    ip4_unicast: list[Ip4Address] | None = None,
    ip6_unicast: list[Ip6Address] | None = None,
) -> SimpleNamespace:
    """
    Build a minimal 'packet_handler' stub exposing only the unicast
    address iterables that 'TcpSocket.bind' reads.
    """

    return SimpleNamespace(
        ip4_unicast=ip4_unicast or [Ip4Address("10.0.0.1")],
        ip6_unicast=ip6_unicast or [Ip6Address("2001:db8::1")],
    )


class _TcpSocketTestCase(TestCase):
    """
    Shared fixture that patches the module-level stack globals and the
    'TcpSession' constructor so no real FSM thread is spun up.
    """

    def setUp(self) -> None:
        """
        Install per-test patches on logging, 'stack.sockets',
        'stack.packet_handler', and the 'TcpSession' class.
        """

        self._log_patch = patch("pytcp.socket.tcp__socket.log")
        self._log_patch.start()

        self._sockets: dict = {}
        self._sockets_patch = patch(
            "pytcp.socket.tcp__socket.stack.sockets",
            self._sockets,
        )
        self._sockets_patch.start()

        self._helper_sockets_patch = patch(
            "pytcp.lib.ip_helper.stack.sockets",
            self._sockets,
        )
        self._helper_sockets_patch.start()

        self._handler_patch = patch(
            "pytcp.socket.tcp__socket.stack.packet_handler",
            _make_packet_handler(),
        )
        self._handler_patch.start()

        self._session_cls_patch = patch(
            "pytcp.socket.tcp__socket.TcpSession",
        )
        self._session_cls = self._session_cls_patch.start()
        self._session_cls.return_value = MagicMock()

    def tearDown(self) -> None:
        """
        Tear down every per-test patch.
        """

        self._log_patch.stop()
        self._sockets_patch.stop()
        self._helper_sockets_patch.stop()
        self._handler_patch.stop()
        self._session_cls_patch.stop()


class TestTcpSocketInit(_TcpSocketTestCase):
    """
    The 'TcpSocket.__init__' fresh-socket initialization tests.
    """

    def test__tcp_socket__init_ip4_defaults(self) -> None:
        """
        Ensure a fresh IPv4 TCP socket starts with unspecified
        addresses, both ports at 0, and no session attached. The
        'state' property must report 'FsmState.CLOSED' in this state.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        self.assertIs(s.socket_type, SocketType.STREAM, msg="socket_type must be STREAM.")
        self.assertIs(s.ip_proto, IpProto.TCP, msg="ip_proto must be TCP.")
        self.assertEqual(s.local_ip_address, Ip4Address(), msg="local_ip_address must start unspecified.")
        self.assertEqual(s.remote_ip_address, Ip4Address(), msg="remote_ip_address must start unspecified.")
        self.assertEqual(s.local_port, 0, msg="local_port must start at 0.")
        self.assertEqual(s.remote_port, 0, msg="remote_port must start at 0.")
        self.assertIsNone(s.tcp_session, msg="A fresh socket must have no TcpSession attached.")
        self.assertIsNone(s.parent_socket, msg="A fresh socket must have no parent socket attached.")
        self.assertIs(
            s.state,
            FsmState.CLOSED,
            msg="A fresh socket must report FsmState.CLOSED (no session attached).",
        )

    def test__tcp_socket__init_ip6_defaults(self) -> None:
        """
        Ensure a fresh IPv6 TCP socket starts with the '::' unspecified
        addresses.
        """

        s = TcpSocket(family=AddressFamily.INET6)
        self.assertEqual(s.local_ip_address, Ip6Address(), msg="IPv6 local must start unspecified.")
        self.assertEqual(s.remote_ip_address, Ip6Address(), msg="IPv6 remote must start unspecified.")

    def test__tcp_socket__init_rejects_non_stream(self) -> None:
        """
        Ensure the 'assert type is SocketType.STREAM' guard fires for
        a non-STREAM socket type.
        """

        with self.assertRaises(AssertionError):
            TcpSocket(family=AddressFamily.INET4, type=SocketType.DGRAM)

    def test__tcp_socket__init_rejects_non_tcp_protocol(self) -> None:
        """
        Ensure the 'assert protocol is IpProto.TCP' guard fires for a
        non-TCP protocol argument.
        """

        with self.assertRaises(AssertionError):
            TcpSocket(family=AddressFamily.INET4, protocol=IpProto.UDP)

    def test__tcp_socket__init_with_session_binds_remote(self) -> None:
        """
        Ensure constructing a 'TcpSocket' with an existing
        'tcp_session' adopts the session's local/remote state and
        registers the socket on 'stack.sockets' immediately. This is
        the path taken when a listening socket spawns an accepted
        child.
        """

        session = MagicMock()
        session.local_ip_address = Ip4Address("10.0.0.1")
        session.remote_ip_address = Ip4Address("10.0.0.2")
        session.local_port = 8080
        session.remote_port = 44444
        session.socket = MagicMock()

        s = TcpSocket(family=AddressFamily.INET4, tcp_session=session)

        self.assertIs(s.tcp_session, session, msg="A TcpSocket constructed with a session must keep it attached.")
        self.assertEqual(s.local_ip_address, Ip4Address("10.0.0.1"), msg="Socket must adopt session.local_ip_address.")
        self.assertEqual(
            s.remote_ip_address,
            Ip4Address("10.0.0.2"),
            msg="Socket must adopt session.remote_ip_address.",
        )
        self.assertEqual(s.local_port, 8080, msg="Socket must adopt session.local_port.")
        self.assertEqual(s.remote_port, 44444, msg="Socket must adopt session.remote_port.")
        self.assertIs(
            s.parent_socket,
            session.socket,
            msg="Socket must adopt session.socket as its parent_socket.",
        )
        self.assertIn(
            s.socket_id,
            self._sockets,
            msg="An accepted TcpSocket must register itself on stack.sockets immediately.",
        )


class TestTcpSocketBind(_TcpSocketTestCase):
    """
    The 'TcpSocket.bind' tests.
    """

    def test__tcp_socket__bind_accepts_stack_owned_address(self) -> None:
        """
        Ensure bind() with a stack-owned address and a specific port
        registers the socket on 'stack.sockets'.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.bind(("10.0.0.1", 8080))
        self.assertIn(
            s.socket_id,
            self._sockets,
            msg="bind() must register the socket on stack.sockets.",
        )

    def test__tcp_socket__bind_rejects_rebinding(self) -> None:
        """
        Ensure calling bind() twice raises 'OSError' with Errno 22 —
        the socket can be bound to a specific port exactly once.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.bind(("10.0.0.1", 8080))
        with self.assertRaises(OSError) as context:
            s.bind(("10.0.0.1", 8081))
        self.assertIn(
            "[Errno 22]",
            str(context.exception),
            msg="bind() must raise Errno 22 when called a second time.",
        )

    def test__tcp_socket__bind_rejects_foreign_ip(self) -> None:
        """
        Ensure bind() to a specific IP not owned by the stack raises
        'OSError' with Errno 99.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OSError) as context:
            s.bind(("192.168.99.99", 0))
        self.assertIn(
            "[Errno 99]",
            str(context.exception),
            msg="bind() must raise Errno 99 for a foreign local IP.",
        )

    def test__tcp_socket__bind_rejects_malformed_ip(self) -> None:
        """
        Ensure a malformed IPv4 literal raises 'gaierror'.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(gaierror):
            s.bind(("garbage", 0))

    def test__tcp_socket__bind_rejects_out_of_range_port(self) -> None:
        """
        Ensure bind() raises 'OverflowError' for a port outside the
        0-65535 range.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OverflowError):
            s.bind(("10.0.0.1", 70000))

    def test__tcp_socket__bind_picks_port_when_zero(self) -> None:
        """
        Ensure bind() with a local port of 0 defers to
        'pick_local_port' for ephemeral assignment.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with patch(
            "pytcp.socket.tcp__socket.pick_local_port",
            return_value=40000,
        ):
            s.bind(("10.0.0.1", 0))
        self.assertEqual(
            s.local_port,
            40000,
            msg="bind() with port 0 must assign the value returned by pick_local_port.",
        )

    def test__tcp_socket__bind_rejects_port_in_use(self) -> None:
        """
        Ensure bind() raises 'OSError' with Errno 98 when another
        socket has already claimed the port.
        """

        first = TcpSocket(family=AddressFamily.INET4)
        first.bind(("10.0.0.1", 8080))

        second = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OSError) as context:
            second.bind(("10.0.0.1", 8080))
        self.assertIn(
            "[Errno 98]",
            str(context.exception),
            msg="bind() must raise Errno 98 when the (IP, port) is already in use.",
        )

    def test__tcp_socket__bind_ip6_rejects_malformed(self) -> None:
        """
        Ensure the IPv6 bind() path raises 'gaierror' for malformed
        IPv6 literals.
        """

        s = TcpSocket(family=AddressFamily.INET6)
        with self.assertRaises(gaierror):
            s.bind(("not-a-v6", 0))


class TestTcpSocketConnect(_TcpSocketTestCase):
    """
    The 'TcpSocket.connect' tests.
    """

    def test__tcp_socket__connect_creates_session_and_calls_connect(self) -> None:
        """
        Ensure connect() instantiates a 'TcpSession' with the
        resolved addresses and delegates to its 'connect()' method.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch(
                "pytcp.socket.tcp__socket.pick_local_port",
                return_value=40000,
            ),
        ):
            s.connect(("10.0.0.5", 80))

        self._session_cls.assert_called_once()
        self._session_cls.return_value.connect.assert_called_once_with()
        self.assertEqual(s.remote_ip_address, Ip4Address("10.0.0.5"), msg="connect() must set remote IP.")
        self.assertEqual(s.remote_port, 80, msg="connect() must set remote port.")

    def test__tcp_socket__connect_translates_refused(self) -> None:
        """
        Ensure a 'TcpSessionError("Connection refused")' raised by the
        session is translated into 'ConnectionRefusedError' with the
        Errno 111 message.
        """

        self._session_cls.return_value.connect.side_effect = TcpSessionError("Connection refused")

        s = TcpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            with self.assertRaises(ConnectionRefusedError) as context:
                s.connect(("10.0.0.5", 80))
        self.assertIn(
            "[Errno 111]",
            str(context.exception),
            msg="TcpSessionError('Connection refused') must translate to Errno 111.",
        )

    def test__tcp_socket__connect_translates_timeout(self) -> None:
        """
        Ensure a 'TcpSessionError("Connection timeout")' raised by the
        session is translated into 'TimeoutError' with the Errno 110
        message.
        """

        self._session_cls.return_value.connect.side_effect = TcpSessionError("Connection timeout")

        s = TcpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            with self.assertRaises(TimeoutError) as context:
                s.connect(("10.0.0.5", 80))
        self.assertIn(
            "[Errno 110]",
            str(context.exception),
            msg="TcpSessionError('Connection timeout') must translate to Errno 110.",
        )

    def test__tcp_socket__connect_rejects_unspecified_remote(self) -> None:
        """
        Ensure connecting to '0.0.0.0' raises 'ConnectionRefusedError'
        with the '[Errno 111]' message — unspecified remote is not a
        valid destination for a stream socket.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(ConnectionRefusedError):
            s.connect(("0.0.0.0", 80))

    def test__tcp_socket__connect_rejects_out_of_range_port(self) -> None:
        """
        Ensure connect() raises 'OverflowError' for a port outside
        the 0-65535 range.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OverflowError):
            s.connect(("10.0.0.5", 70000))

    def test__tcp_socket__connect_rejects_malformed_address(self) -> None:
        """
        Ensure a malformed remote-address literal raises 'gaierror'.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(gaierror):
            s.connect(("garbage", 80))


class TestTcpSocketListenAccept(_TcpSocketTestCase):
    """
    The 'TcpSocket.listen' / 'TcpSocket.accept' tests.
    """

    def test__tcp_socket__listen_registers_and_starts_session(self) -> None:
        """
        Ensure listen() creates a 'TcpSession', registers the listening
        socket on 'stack.sockets' under the unspecified key, and
        delegates to the session's 'listen()' method.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s._local_port = 80
        s.listen()

        self.assertIn(
            s.socket_id,
            self._sockets,
            msg="listen() must register the listening socket on stack.sockets.",
        )
        self._session_cls.return_value.listen.assert_called_once_with()

    def test__tcp_socket__accept_returns_socket_and_address(self) -> None:
        """
        Ensure accept() returns a '(socket, (remote_ip_str, port))'
        tuple once the semaphore is signaled.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        # Pre-populate the accept queue with a child socket, then
        # release the semaphore so accept() does not block.
        child = MagicMock()
        child.remote_ip_address = Ip4Address("10.0.0.5")
        child.remote_port = 12345
        s._tcp_accept.append(child)
        s._event__tcp_session_established.release()

        result_socket, result_addr = s.accept()

        self.assertIs(
            result_socket,
            child,
            msg="accept() must return the socket popped from the accept queue.",
        )
        self.assertEqual(
            result_addr,
            ("10.0.0.5", 12345),
            msg="accept() must return (remote_ip_str, remote_port) as the address tuple.",
        )

    def test__tcp_socket__accept_timeout_raises(self) -> None:
        """
        Ensure accept() raises 'TimeoutError' when the semaphore is
        not signaled within the supplied timeout window.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with self.assertRaises(TimeoutError):
            s.accept(timeout=0.01)


class TestTcpSocketSendRecvClose(_TcpSocketTestCase):
    """
    The 'TcpSocket.send' / 'TcpSocket.recv' / 'TcpSocket.close' tests.
    """

    def _connected_socket(self) -> tuple[TcpSocket, MagicMock]:
        """
        Build a 'TcpSocket' with a mocked, attached session — the
        minimum state send() / recv() / close() require. Returns both
        the socket and the bound session mock so tests can configure
        return values / side effects without fighting the 'TcpSession |
        None' static type on the socket's '_tcp_session' slot.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s._local_ip_address = Ip4Address("10.0.0.1")
        s._remote_ip_address = Ip4Address("10.0.0.5")
        s._local_port = 40000
        s._remote_port = 80
        session = MagicMock()
        s._tcp_session = session
        return s, session

    def test__tcp_socket__send_requires_destination(self) -> None:
        """
        Ensure send() on a socket with no remote IP raises
        'BrokenPipeError' (matching the CPython EPIPE shape) so the
        caller sees the same exception as a normal TCP send-after-FIN.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s._tcp_session = MagicMock()
        with self.assertRaises(BrokenPipeError):
            s.send(b"data")

    def test__tcp_socket__send_returns_bytes_sent(self) -> None:
        """
        Ensure send() delegates to the session's send() and returns
        the byte count the session reports.
        """

        s, session = self._connected_socket()
        session.send.return_value = 5

        self.assertEqual(
            s.send(b"hello"),
            5,
            msg="send() must return the byte count reported by the underlying TcpSession.",
        )
        session.send.assert_called_once_with(data=b"hello")

    def test__tcp_socket__send_translates_session_error(self) -> None:
        """
        Ensure a 'TcpSessionError' from the session surfaces as a
        'BrokenPipeError' with the Errno 32 message, matching the
        BSD stream-socket contract.
        """

        s, session = self._connected_socket()
        session.send.side_effect = TcpSessionError("boom")

        with self.assertRaises(BrokenPipeError) as context:
            s.send(b"data")
        self.assertIn(
            "[Errno 32]",
            str(context.exception),
            msg="send() must translate TcpSessionError into BrokenPipeError with Errno 32.",
        )

    def test__tcp_socket__recv_returns_session_data(self) -> None:
        """
        Ensure recv() delegates to 'TcpSession.receive()' and returns
        its byte payload verbatim.
        """

        s, session = self._connected_socket()
        session.receive.return_value = b"payload"

        self.assertEqual(
            s.recv(),
            b"payload",
            msg="recv() must return the bytes returned by TcpSession.receive().",
        )

    def test__tcp_socket__recv_translates_timeout(self) -> None:
        """
        Ensure a 'TimeoutError' raised by the session is re-raised as
        a new 'TimeoutError' with the socket-level message.
        """

        s, session = self._connected_socket()
        session.receive.side_effect = TimeoutError("session")

        with self.assertRaises(TimeoutError) as context:
            s.recv(timeout=0.01)
        self.assertIn(
            "TCP Socket",
            str(context.exception),
            msg="recv() must re-raise TimeoutError with the socket-level prefix.",
        )

    def test__tcp_socket__close_delegates_to_session(self) -> None:
        """
        Ensure close() delegates to 'TcpSession.close()' unconditionally.
        """

        s, session = self._connected_socket()
        s.close()
        session.close.assert_called_once_with()

    def test__tcp_socket__process_tcp_packet_delegates_to_session(self) -> None:
        """
        Ensure 'process_tcp_packet' forwards the received metadata to
        'TcpSession.tcp_fsm'. If there is no session attached, the call
        must be a no-op.
        """

        s, session = self._connected_socket()
        md = MagicMock()
        s.process_tcp_packet(md)
        session.tcp_fsm.assert_called_once_with(md)

    def test__tcp_socket__process_tcp_packet_without_session_is_noop(self) -> None:
        """
        Ensure 'process_tcp_packet' on a socket with no session simply
        returns — it must not raise.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.process_tcp_packet(MagicMock())  # must not raise


class TestTcpSocketStateProperty(_TcpSocketTestCase):
    """
    The 'TcpSocket.state' property tests.
    """

    def test__tcp_socket__state_reflects_session(self) -> None:
        """
        Ensure the 'state' property reads through to
        'tcp_session.state' when a session is attached.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        session = MagicMock()
        session.state = FsmState.ESTABLISHED
        s._tcp_session = session

        self.assertIs(
            s.state,
            FsmState.ESTABLISHED,
            msg="TcpSocket.state must return tcp_session.state when a session is attached.",
        )

    def test__tcp_socket__state_closed_without_session(self) -> None:
        """
        Ensure the 'state' property returns 'FsmState.CLOSED' when no
        session is attached.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        self.assertIs(
            s.state,
            FsmState.CLOSED,
            msg="TcpSocket.state must return CLOSED when tcp_session is None.",
        )


class TestTcpSocketOptions(_TcpSocketTestCase):
    """
    The 'TcpSocket.setsockopt' / 'getsockopt' BSD-API tests, per
    RFC 1122 §4.2.3.6 (keep-alive must be application-controllable
    per connection) and POSIX 'setsockopt' / 'getsockopt' shape.
    """

    def test__tcp_socket__getsockopt__so_keepalive_default_zero(self) -> None:
        """
        Ensure a freshly-constructed 'TcpSocket' reports
        'SO_KEEPALIVE = 0' from 'getsockopt', matching the RFC 1122
        §4.2.3.6 MUST: "If keep-alive are included, ... they MUST
        default to off." Regression guard for the default-off
        invariant at the socket-API layer.
        """

        s = TcpSocket(family=AddressFamily.INET4)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_KEEPALIVE),
            0,
            msg=("RFC 1122 §4.2.3.6: 'SO_KEEPALIVE' MUST default to 0 on a " "freshly-constructed socket."),
        )

    def test__tcp_socket__setsockopt__so_keepalive_stores_one(self) -> None:
        """
        [FLAGS BUG]

        Ensure 'setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)' stores the
        flag and a subsequent 'getsockopt' round-trips it as 1. Today
        'TcpSocket' has no setsockopt / getsockopt methods at all,
        so this fails with AttributeError.

        Fix outline: add 'setsockopt(level, optname, value)' that
        dispatches on '(level, optname)' and stores into
        '_so_keepalive: bool'; add 'getsockopt(level, optname) -> int'
        that reads it back. Validate the (level, optname) pair and
        normalise non-zero 'value' to 1 (matches Linux for boolean
        options).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_KEEPALIVE),
            1,
            msg=("setsockopt(SO_KEEPALIVE, 1) followed by getsockopt(SO_KEEPALIVE) " "must round-trip as 1."),
        )

    def test__tcp_socket__setsockopt__so_keepalive_zero_disables(self) -> None:
        """
        [FLAGS BUG]

        Ensure 'setsockopt(SOL_SOCKET, SO_KEEPALIVE, 0)' after a
        previous '..., 1)' clears the flag. The application must be
        able to disable keep-alive, not just enable it (RFC 1122
        §4.2.3.6 "the application MUST be able to turn them on or
        off for each TCP connection").
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
        s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 0)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_KEEPALIVE),
            0,
            msg="setsockopt(SO_KEEPALIVE, 0) after a prior enable must clear the flag.",
        )

    def test__tcp_socket__setsockopt__nonzero_value_normalises_to_one(self) -> None:
        """
        [FLAGS BUG]

        Ensure boolean-shaped options collapse any non-zero integer
        to 1 on storage, matching Linux 'setsockopt(SO_KEEPALIVE,
        42, ...)' semantics. Without this, a later 'getsockopt'
        would surface a value the application never directly stored.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 42)

        self.assertEqual(
            s.getsockopt(SOL_SOCKET, SO_KEEPALIVE),
            1,
            msg="Boolean options (SO_KEEPALIVE) must normalise any non-zero value to 1.",
        )

    def test__tcp_socket__setsockopt__unknown_level_raises(self) -> None:
        """
        [FLAGS BUG]

        Ensure 'setsockopt' on an unknown 'level' parameter raises
        rather than silently dropping the call. POSIX dictates
        'OSError(ENOPROTOOPT)' / 'OSError(EINVAL)'; PyTCP uses
        'OSError' so the failure shape is greppable across the
        stdlib-compatible boundary.
        """

        s = TcpSocket(family=AddressFamily.INET4)

        with self.assertRaises(
            OSError,
            msg="setsockopt on an unknown 'level' must raise OSError.",
        ):
            s.setsockopt(0xDEAD, SO_KEEPALIVE, 1)

    def test__tcp_socket__setsockopt__unknown_optname_raises(self) -> None:
        """
        [FLAGS BUG]

        Ensure 'setsockopt' on a known level but unknown 'optname'
        parameter raises. Same POSIX semantics as the unknown-level
        case.
        """

        s = TcpSocket(family=AddressFamily.INET4)

        with self.assertRaises(
            OSError,
            msg="setsockopt on an unknown 'optname' must raise OSError.",
        ):
            s.setsockopt(SOL_SOCKET, 0xBEEF, 1)

    def test__tcp_socket__setsockopt__so_keepalive_at_tcp_level_raises(self) -> None:
        """
        [FLAGS BUG]

        Ensure that 'setsockopt(IPPROTO_TCP, SO_KEEPALIVE, 1)'
        (wrong level for SO_KEEPALIVE) raises rather than silently
        succeeding. SO_KEEPALIVE is an SOL_SOCKET-level option;
        applying it at IPPROTO_TCP is a programmer error worth
        flagging at the boundary.
        """

        s = TcpSocket(family=AddressFamily.INET4)

        with self.assertRaises(
            OSError,
            msg="setsockopt with SO_KEEPALIVE at IPPROTO_TCP level must raise.",
        ):
            s.setsockopt(IPPROTO_TCP, SO_KEEPALIVE, 1)

    def test__tcp_socket__getsockopt__unknown_level_raises(self) -> None:
        """
        [FLAGS BUG]

        Ensure 'getsockopt' raises symmetrically for unknown
        '(level, optname)' pairs.
        """

        s = TcpSocket(family=AddressFamily.INET4)

        with self.assertRaises(
            OSError,
            msg="getsockopt on an unknown (level, optname) pair must raise OSError.",
        ):
            s.getsockopt(0xDEAD, SO_KEEPALIVE)

    def test__tcp_socket__connect_propagates_so_keepalive_to_session(self) -> None:
        """
        Ensure 'setsockopt(SO_KEEPALIVE, 1)' followed by 'connect()'
        propagates the flag to the freshly-constructed TcpSession's
        '_keepalive_enabled' attribute. Without this propagation,
        the keep-alive feature has no path from the BSD-socket API
        to the protocol runtime.

        The test uses 'assertIs(..., True)' rather than 'assertTrue'
        because the mocked TcpSession is a MagicMock - reading any
        previously-unset attribute returns a new MagicMock, which
        is truthy. Identity-checking against the literal 'True'
        catches both cases.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
        with (
            patch(
                "pytcp.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            s.connect(("10.0.0.5", 80))

        self.assertIs(
            self._session_cls.return_value._keepalive.enabled,
            True,
            msg=(
                "connect() must propagate '_so_keepalive' to the new TcpSession's "
                "'_keepalive_enabled' so RFC 1122 §4.2.3.6 keep-alive arms."
            ),
        )

    def test__tcp_socket__connect_propagates_default_disable_to_session(self) -> None:
        """
        Ensure connect() without setsockopt sets the new
        TcpSession's '_keepalive_enabled' to False explicitly
        (not "leave unset"), preserving RFC 1122 §4.2.3.6's
        "MUST default to off" invariant via the BSD-socket API.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            s.connect(("10.0.0.5", 80))

        self.assertIs(
            self._session_cls.return_value._keepalive.enabled,
            False,
            msg=(
                "connect() without setsockopt(SO_KEEPALIVE, 1) must explicitly "
                "set '_keepalive_enabled = False' on the session."
            ),
        )

    def test__tcp_socket__listen_propagates_so_keepalive_to_session(self) -> None:
        """
        Ensure 'setsockopt(SO_KEEPALIVE, 1)' followed by 'listen()'
        propagates the flag to the freshly-constructed listening
        TcpSession's '_keepalive_enabled'. Listener-fork children
        inherit through the listening session's flag, so a
        listening socket that opted in via setsockopt produces
        keep-alive-enabled child sessions for every incoming SYN.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)
        s._local_ip_address = Ip4Address("10.0.0.1")
        s._local_port = 80
        s.listen()

        self.assertIs(
            self._session_cls.return_value._keepalive.enabled,
            True,
            msg=(
                "listen() must propagate '_so_keepalive' to the new listening "
                "TcpSession's '_keepalive_enabled' so accepted children inherit."
            ),
        )

    def test__tcp_socket__setsockopt__tcp_keepidle_round_trip(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, N)' stores
        the per-connection idle override and a subsequent
        'getsockopt' returns the same N.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, 600)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_KEEPIDLE),
            600,
            msg="TCP_KEEPIDLE must round-trip via setsockopt / getsockopt.",
        )

    def test__tcp_socket__setsockopt__tcp_keepintvl_round_trip(self) -> None:
        """
        Same shape for TCP_KEEPINTVL.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, 75)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_KEEPINTVL),
            75,
            msg="TCP_KEEPINTVL must round-trip via setsockopt / getsockopt.",
        )

    def test__tcp_socket__setsockopt__tcp_keepcnt_round_trip(self) -> None:
        """
        Same shape for TCP_KEEPCNT.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_KEEPCNT, 5)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_KEEPCNT),
            5,
            msg="TCP_KEEPCNT must round-trip via setsockopt / getsockopt.",
        )

    def test__tcp_socket__getsockopt__tcp_keep_overrides_default_zero(self) -> None:
        """
        Ensure getsockopt for the three TCP_KEEP* overrides
        returns 0 on a fresh socket - the sentinel meaning "no
        override; the session falls back to the global
        'tcp__constants.KEEPALIVE_*' default at runtime."
        """

        s = TcpSocket(family=AddressFamily.INET4)
        self.assertEqual(s.getsockopt(IPPROTO_TCP, TCP_KEEPIDLE), 0)
        self.assertEqual(s.getsockopt(IPPROTO_TCP, TCP_KEEPINTVL), 0)
        self.assertEqual(s.getsockopt(IPPROTO_TCP, TCP_KEEPCNT), 0)

    def test__tcp_socket__connect_propagates_keep_overrides_to_session(self) -> None:
        """
        Ensure setsockopt(IPPROTO_TCP, TCP_KEEP*, ...) followed by
        connect() propagates each override onto the freshly-
        constructed TcpSession's matching field. Without this, the
        per-connection override has no path into the protocol
        runtime.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_KEEPIDLE, 600)
        s.setsockopt(IPPROTO_TCP, TCP_KEEPINTVL, 75)
        s.setsockopt(IPPROTO_TCP, TCP_KEEPCNT, 5)
        with (
            patch(
                "pytcp.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            s.connect(("10.0.0.5", 80))

        self.assertEqual(
            self._session_cls.return_value._keepalive.idle_override,
            600,
            msg="connect() must propagate TCP_KEEPIDLE override to session.",
        )
        self.assertEqual(
            self._session_cls.return_value._keepalive.interval_override,
            75,
            msg="connect() must propagate TCP_KEEPINTVL override to session.",
        )
        self.assertEqual(
            self._session_cls.return_value._keepalive.max_count_override,
            5,
            msg="connect() must propagate TCP_KEEPCNT override to session.",
        )

    def test__tcp_socket__connect_with_data_pre_loads_session_tx_buffer(self) -> None:
        """
        Ensure 'TcpSocket.connect(remote, data=b"...")'
        accepts a 'data' kwarg and pre-loads the freshly-
        constructed 'TcpSession' TX buffer with that data
        before driving the FSM into SYN_SENT. This is the
        ergonomic entry path for client-side TCP Fast Open:
        the application supplies data alongside the connect
        call, and (when a TFO cookie is cached for the
        peer) the SYN itself carries the data on the wire,
        eliminating the data RTT of a vanilla 3WHS-then-
        send sequence.

        Reference: RFC 7413 §3.1 (client connect-with-data API).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        early_data = b"GET / HTTP/1.1\r\n"
        with (
            patch(
                "pytcp.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            s.connect(("10.0.0.5", 80), data=early_data)

        self._session_cls.return_value._tx.buffer.extend.assert_called_with(early_data)

    def test__tcp_socket__getsockopt__tcp_fastopen_default_zero(self) -> None:
        """
        Ensure a freshly-constructed 'TcpSocket' reports
        'TCP_FASTOPEN = 0' from 'getsockopt'. The Linux
        convention treats the value as the TFO accept queue
        depth, with 0 meaning "TFO disabled" - the default
        for a socket that has not opted in via
        'setsockopt'.

        Reference: RFC 7413 §3.1 (server opts in to TFO via setsockopt).
        """

        s = TcpSocket(family=AddressFamily.INET4)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_FASTOPEN),
            0,
            msg=(
                "TCP_FASTOPEN MUST default to 0 (TFO disabled) "
                "on a freshly-constructed socket; the application "
                "explicitly opts in by calling 'setsockopt"
                "(IPPROTO_TCP, TCP_FASTOPEN, qlen)' with a "
                "positive queue depth."
            ),
        )

    def test__tcp_socket__setsockopt__tcp_fastopen_round_trips(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_TCP, TCP_FASTOPEN, qlen)'
        stores the queue depth and a subsequent 'getsockopt'
        returns the same value.

        Reference: RFC 7413 §3.1 (server-side TFO enable via setsockopt).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_FASTOPEN, 16)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_FASTOPEN),
            16,
            msg=("setsockopt(TCP_FASTOPEN, 16) followed by " "getsockopt must round-trip as 16."),
        )

    def test__tcp_socket__setsockopt__tcp_fastopen_zero_disables(self) -> None:
        """
        Ensure 'setsockopt(IPPROTO_TCP, TCP_FASTOPEN, 0)'
        after a previous '..., qlen)' clears the option. The
        application MUST be able to disable TFO on a
        previously-enabled socket.

        Reference: RFC 7413 §3.1 (server opt-out via setsockopt qlen=0).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_FASTOPEN, 16)
        s.setsockopt(IPPROTO_TCP, TCP_FASTOPEN, 0)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_FASTOPEN),
            0,
            msg=("setsockopt(TCP_FASTOPEN, 0) after a prior " "enable must clear the option."),
        )

    def test__tcp_socket__getsockopt__tcp_nodelay_default_zero(self) -> None:
        """
        Ensure a freshly-constructed TcpSocket reports
        TCP_NODELAY = 0 (Nagle enabled by default).

        Reference: RFC 1122 §4.2.3.4 (Nagle SHOULD be implemented).
        """

        s = TcpSocket(family=AddressFamily.INET4)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_NODELAY),
            0,
            msg="TCP_NODELAY must default to 0 (Nagle enabled).",
        )

    def test__tcp_socket__setsockopt__tcp_nodelay_round_trip(self) -> None:
        """
        Ensure setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        followed by getsockopt round-trips as 1.

        Reference: RFC 1122 §4.2.3.4 (application disable of Nagle).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_NODELAY),
            1,
            msg="setsockopt(TCP_NODELAY, 1) must round-trip via getsockopt.",
        )

    def test__tcp_socket__setsockopt__tcp_nodelay_zero_re_enables_nagle(self) -> None:
        """
        Ensure setsockopt(IPPROTO_TCP, TCP_NODELAY, 0) after
        a prior enable re-enables Nagle. The application MUST
        be able to toggle the flag in either direction.

        Reference: RFC 1122 §4.2.3.4 (application toggle).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 0)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_NODELAY),
            0,
            msg="setsockopt(TCP_NODELAY, 0) after a prior enable must clear.",
        )

    def test__tcp_socket__setsockopt__tcp_nodelay_normalises_nonzero_to_one(self) -> None:
        """
        Ensure setsockopt(IPPROTO_TCP, TCP_NODELAY, 42)
        normalises any non-zero integer to 1 on round-trip,
        matching boolean-option semantics.

        Reference: RFC 1122 §4.2.3.4 (boolean toggle).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 42)

        self.assertEqual(
            s.getsockopt(IPPROTO_TCP, TCP_NODELAY),
            1,
            msg="Non-zero TCP_NODELAY value must normalise to 1.",
        )

    def test__tcp_socket__connect_propagates_tcp_nodelay_to_session(self) -> None:
        """
        Ensure setsockopt(TCP_NODELAY, 1) followed by connect()
        propagates the flag to the freshly-constructed
        TcpSession's '_tcp_nodelay' attribute.

        Reference: RFC 1122 §4.2.3.4 (TCP_NODELAY socket-API path).
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        with (
            patch(
                "pytcp.socket.tcp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch("pytcp.socket.tcp__socket.pick_local_port", return_value=40000),
        ):
            s.connect(("10.0.0.5", 80))

        self.assertIs(
            self._session_cls.return_value._tcp_nodelay,
            True,
            msg=("connect() must propagate '_tcp_nodelay' to the new " "TcpSession so the Nagle gate can read it."),
        )


class TestTcpSocketFileno(_TcpSocketTestCase):
    """
    The 'TcpSocket.fileno' / read-readiness signal-and-drain tests.
    """

    def setUp(self) -> None:
        """
        Build a fresh TCP socket. 'tearDown' closes the eventfd
        before the parent fixture stops the 'log' patch.
        """

        super().setUp()
        self._socket = TcpSocket(family=AddressFamily.INET4)

    def tearDown(self) -> None:
        """
        Release the socket's eventfd while the 'log' patch is still
        active, then let the parent tear down the stack stubs.
        '_close_io_runtime' rather than 'close()' here because the
        socket has no session attached.
        """

        try:
            self._socket._close_io_runtime()
        except OSError:
            pass
        super().tearDown()

    def test__tcp_socket__fileno_returns_non_negative_int(self) -> None:
        """
        Ensure 'fileno()' on a TCP socket returns a non-negative
        integer file descriptor for selector consumption.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        fd = self._socket.fileno()

        self.assertIsInstance(
            fd,
            int,
            msg="TcpSocket.fileno() must return an int.",
        )
        self.assertGreaterEqual(
            fd,
            0,
            msg="TcpSocket.fileno() must return a non-negative fd.",
        )

    def test__tcp_socket__fileno_initially_not_select_ready(self) -> None:
        """
        Ensure a freshly-constructed TCP socket reports as not
        readable until either a child connection lands on the
        accept queue or session data lands in the rx buffer.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [],
            msg="A fresh TcpSocket must not be select-readable.",
        )

    def test__tcp_socket__fileno_select_ready_after_accept_queue_appended(self) -> None:
        """
        Ensure a child socket landing on the listening socket's
        accept queue (the listener-fork hook in
        'tcp__fsm__syn_rcvd.py') makes the listening socket
        select-readable so an event-loop accept-loop wakes.

        Reference: PyTCP test infrastructure (no RFC clause).
        Reference: RFC 9293 §3.10.2 (OPEN passive / accept queue delivery).
        """

        child = MagicMock()
        self._socket._tcp_accept.append(child)
        self._socket._event__tcp_session_established.release()
        self._socket._signal_readable()

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [self._socket.fileno()],
            msg="A child appended to the accept queue must mark the listening fd readable.",
        )

    def test__tcp_socket__accept_drains_fileno_when_last_child_consumed(self) -> None:
        """
        Ensure 'accept()' returns the listening fd to the
        not-readable state once the last queued child has been
        consumed — selector-driven accept loops rely on this.

        Reference: PyTCP test infrastructure (no RFC clause).
        Reference: RFC 9293 §3.10.2 (OPEN passive / accept queue delivery).
        """

        child = MagicMock()
        child.remote_ip_address = Ip4Address("10.0.0.5")
        child.remote_port = 12345
        self._socket._tcp_accept.append(child)
        self._socket._event__tcp_session_established.release()
        self._socket._signal_readable()

        self._socket.accept()

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [],
            msg="accept() consuming the last queued child must clear the readable bit.",
        )

    def test__tcp_socket__accept_keeps_fileno_ready_when_more_children_queued(self) -> None:
        """
        Ensure 'accept()' on a queue with more than one pending
        child leaves the listening fd select-readable so the next
        selector tick still wakes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        first = MagicMock()
        first.remote_ip_address = Ip4Address("10.0.0.5")
        first.remote_port = 12345
        second = MagicMock()
        second.remote_ip_address = Ip4Address("10.0.0.6")
        second.remote_port = 12346
        self._socket._tcp_accept.extend([first, second])
        self._socket._event__tcp_session_established.release()
        self._socket._event__tcp_session_established.release()
        self._socket._signal_readable()
        self._socket._signal_readable()

        self._socket.accept()

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [self._socket.fileno()],
            msg="accept() leaving children queued must keep the listening fd readable.",
        )

    def test__tcp_socket__close_io_runtime_closes_underlying_fd(self) -> None:
        """
        Ensure '_close_io_runtime()' tears down the eventfd backing
        'fileno()' on a TCP socket.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        fd = self._socket.fileno()
        self._socket._close_io_runtime()

        with self.assertRaises(OSError) as context:
            fcntl.fcntl(fd, fcntl.F_GETFD)

        self.assertEqual(
            context.exception.errno,
            errno.EBADF,
            msg="_close_io_runtime() must close the eventfd backing fileno() (EBADF).",
        )


class TestTcpSocketNonBlocking(_TcpSocketTestCase):
    """
    The 'TcpSocket.setblocking' non-blocking-recv / accept tests.
    """

    def setUp(self) -> None:
        """
        Build a non-blocking TCP socket. tearDown releases the
        eventfd before the parent fixture stops the 'log' patch.
        """

        super().setUp()
        self._socket = TcpSocket(family=AddressFamily.INET4)
        self._socket.setblocking(False)

    def tearDown(self) -> None:
        """
        Close the eventfd before the parent tears down patches.
        """

        try:
            self._socket._close_io_runtime()
        except OSError:
            pass
        super().tearDown()

    def test__tcp_socket__recv_raises_blocking_io_error_when_no_data(self) -> None:
        """
        Ensure 'recv()' on a non-blocking TCP socket with an empty
        rx buffer raises 'BlockingIOError(EAGAIN)' to match POSIX
        'O_NONBLOCK' semantics.

        Reference: PyTCP test infrastructure (no RFC clause).
        Reference: RFC 9293 §3.10.5 (RECEIVE call).
        """

        session = MagicMock()
        session.receive.side_effect = TimeoutError("no data ready")
        self._socket._tcp_session = session
        self._socket._remote_ip_address = Ip4Address("10.0.0.5")
        self._socket._remote_port = 80

        with self.assertRaises(BlockingIOError) as context:
            self._socket.recv()

        self.assertEqual(
            context.exception.errno,
            errno.EAGAIN,
            msg="Non-blocking recv() with no data must raise BlockingIOError(EAGAIN).",
        )

    def test__tcp_socket__recv_passes_zero_timeout_when_non_blocking(self) -> None:
        """
        Ensure 'recv()' on a non-blocking TCP socket forwards
        'timeout=0' to 'TcpSession.receive' so the session does not
        wait — the per-call non-blocking attempt is what makes
        BlockingIOError translation correct.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        session = MagicMock()
        session.receive.return_value = b"data"
        self._socket._tcp_session = session
        self._socket._remote_ip_address = Ip4Address("10.0.0.5")
        self._socket._remote_port = 80

        self._socket.recv()

        session.receive.assert_called_once_with(byte_count=None, timeout=0)

    def test__tcp_socket__recv_per_call_timeout_overrides_non_blocking(self) -> None:
        """
        Ensure an explicit 'timeout=' parameter takes precedence
        over the 'setblocking(False)' flag — per-call timeout wins,
        matching CPython socket semantics.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        session = MagicMock()
        session.receive.side_effect = TimeoutError("session timeout")
        self._socket._tcp_session = session
        self._socket._remote_ip_address = Ip4Address("10.0.0.5")
        self._socket._remote_port = 80

        with self.assertRaises(TimeoutError):
            self._socket.recv(timeout=0.01)

    def test__tcp_socket__accept_raises_blocking_io_error_when_no_child(self) -> None:
        """
        Ensure 'accept()' on a non-blocking listening TCP socket
        with an empty accept queue raises 'BlockingIOError(EAGAIN)'.

        Reference: PyTCP test infrastructure (no RFC clause).
        Reference: RFC 9293 §3.10.2 (OPEN passive / accept queue delivery).
        """

        with self.assertRaises(BlockingIOError) as context:
            self._socket.accept()

        self.assertEqual(
            context.exception.errno,
            errno.EAGAIN,
            msg="Non-blocking accept() with no child queued must raise BlockingIOError(EAGAIN).",
        )

    def test__tcp_socket__accept_returns_child_when_non_blocking_and_queued(self) -> None:
        """
        Ensure 'accept()' on a non-blocking socket returns the
        queued child immediately when one is available.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        child = MagicMock()
        child.remote_ip_address = Ip4Address("10.0.0.5")
        child.remote_port = 12345
        self._socket._tcp_accept.append(child)
        self._socket._event__tcp_session_established.release()
        self._socket._signal_readable()

        result, _ = self._socket.accept()

        self.assertIs(
            result,
            child,
            msg="Non-blocking accept() with a queued child must return it.",
        )

    def test__tcp_socket__accept_per_call_timeout_overrides_non_blocking(self) -> None:
        """
        Ensure an explicit 'timeout=' on 'accept()' takes precedence
        over the 'setblocking(False)' flag and yields 'TimeoutError'
        on elapse.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TimeoutError):
            self._socket.accept(timeout=0.01)


class TestTcpSocketAcceptInheritsBlocking(_TcpSocketTestCase):
    """
    The 'TcpSocket.accept' child-inherits-parent-blocking tests.
    """

    def test__tcp_socket__accept_child_inherits_parent_blocking_default(self) -> None:
        """
        Ensure a child socket popped by 'accept()' inherits the
        parent listening socket's default 'blocking=True' flag.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        parent = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(parent._close_io_runtime)

        child = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(child._close_io_runtime)
        child._remote_ip_address = Ip4Address("10.0.0.5")
        child._remote_port = 12345
        parent._tcp_accept.append(child)
        parent._event__tcp_session_established.release()
        parent._signal_readable()

        accepted, _ = parent.accept()

        self.assertTrue(
            cast(TcpSocket, accepted).getblocking(),
            msg="accept() child must inherit the parent's blocking=True default.",
        )

    def test__tcp_socket__accept_child_inherits_parent_blocking_false(self) -> None:
        """
        Ensure a child socket popped by 'accept()' inherits the
        parent listening socket's 'setblocking(False)' configuration
        — required so async frameworks that flip the listener also
        receive non-blocking children.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        parent = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(parent._close_io_runtime)
        parent.setblocking(False)

        child = TcpSocket(family=AddressFamily.INET4)
        self.addCleanup(child._close_io_runtime)
        child._remote_ip_address = Ip4Address("10.0.0.5")
        child._remote_port = 12345
        parent._tcp_accept.append(child)
        parent._event__tcp_session_established.release()
        parent._signal_readable()

        accepted, _ = parent.accept()

        self.assertFalse(
            cast(TcpSocket, accepted).getblocking(),
            msg="accept() child must inherit setblocking(False) from the parent.",
        )
