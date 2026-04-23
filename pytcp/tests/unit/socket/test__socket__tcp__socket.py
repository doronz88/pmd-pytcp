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

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, Ip6Address
from net_proto.lib.enums import IpProto
from pytcp.socket import AddressFamily, SocketType, gaierror
from pytcp.socket.tcp__session import FsmState, TcpSessionError
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
        s._event_tcp_session_established.release()

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
        Ensure send() on a socket with no remote IP raises 'OSError'
        with a 'Destination address require' message.
        """

        s = TcpSocket(family=AddressFamily.INET4)
        s._tcp_session = MagicMock()
        with self.assertRaises(OSError):
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
