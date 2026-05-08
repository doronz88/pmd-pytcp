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
This module contains tests for the 'RawSocket' BSD-like raw socket
implementation.

pytcp/tests/unit/socket/test__socket__raw__socket.py

ver 3.0.4
"""

import errno
import fcntl
import select
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip4Address, Ip6Address
from net_proto.lib.enums import IpProto
from pytcp.lib.tx_status import TxStatus
from pytcp.socket import AddressFamily, SocketType, gaierror
from pytcp.socket.raw__metadata import RawMetadata
from pytcp.socket.raw__socket import RawSocket


def _make_packet_handler(
    *,
    ip4_unicast: list[Ip4Address] | None = None,
    ip6_unicast: list[Ip6Address] | None = None,
) -> SimpleNamespace:
    """
    Build a minimal 'packet_handler' stub that exposes the attributes
    and methods 'RawSocket' touches: the two unicast-address iterables
    plus 'send_ip4_packet' / 'send_ip6_packet' callables returning a
    'TxStatus'.
    """

    return SimpleNamespace(
        ip4_unicast=ip4_unicast or [Ip4Address("10.0.0.1")],
        ip6_unicast=ip6_unicast or [Ip6Address("2001:db8::1")],
        send_ip4_packet=lambda **_: TxStatus.PASSED__ETHERNET__TO_TX_RING,
        send_ip6_packet=lambda **_: TxStatus.PASSED__ETHERNET__TO_TX_RING,
    )


class _RawSocketTestCase(TestCase):
    """
    Shared fixture for 'RawSocket' tests that pins the module-level
    'log' and 'stack' dependencies so the real stack singletons are
    never touched from the unit-test process.
    """

    def setUp(self) -> None:
        """
        Patch logging, the socket registry, and the packet handler for
        the duration of the test.
        """

        self._log_patch = patch("pytcp.socket.raw__socket.log")
        self._log_patch.start()
        self._sockets: dict = {}
        self._sockets_patch = patch(
            "pytcp.socket.raw__socket.stack.sockets",
            self._sockets,
        )
        self._sockets_patch.start()
        self._handler = _make_packet_handler()
        self._handler_patch = patch(
            "pytcp.socket.raw__socket.stack.packet_handler",
            self._handler,
        )
        self._handler_patch.start()

    def tearDown(self) -> None:
        """
        Tear down the module-level stack patches.
        """

        self._log_patch.stop()
        self._sockets_patch.stop()
        self._handler_patch.stop()


class TestRawSocketInit(_RawSocketTestCase):
    """
    The 'RawSocket.__init__' tests.
    """

    def test__raw_socket__init_ip4_no_protocol_raises_eprotonosupport(self) -> None:
        """
        Ensure constructing an IPv4 'RawSocket' with no explicit
        protocol raises 'OSError(EPROTONOSUPPORT)'. Raw sockets must
        carry an explicit IANA next-header value; there is no
        meaningful default, so PyTCP mirrors Linux's 'sys_socket'
        behavior of returning 'EPROTONOSUPPORT' for this case.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import errno

        with self.assertRaises(OSError) as context:
            RawSocket(AddressFamily.INET4)
        self.assertEqual(
            context.exception.errno,
            errno.EPROTONOSUPPORT,
            msg="RawSocket(INET4) with no protocol must raise OSError(EPROTONOSUPPORT).",
        )

    def test__raw_socket__init_ip6_no_protocol_raises_eprotonosupport(self) -> None:
        """
        Ensure constructing an IPv6 'RawSocket' with no explicit
        protocol raises 'OSError(EPROTONOSUPPORT)' — symmetric with
        the IPv4 case.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        import errno

        with self.assertRaises(OSError) as context:
            RawSocket(AddressFamily.INET6)
        self.assertEqual(
            context.exception.errno,
            errno.EPROTONOSUPPORT,
            msg="RawSocket(INET6) with no protocol must raise OSError(EPROTONOSUPPORT).",
        )

    def test__raw_socket__init_explicit_protocol(self) -> None:
        """
        Ensure an explicit 'protocol=' is stored on '_ip_proto' and
        the 'local_port' shadow mirrors 'int(protocol)' so the
        socket-registry lookup key is unique per protocol.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)

        self.assertIs(s.address_family, AddressFamily.INET4, msg="address_family must be INET4.")
        self.assertIs(s.socket_type, SocketType.RAW, msg="socket_type must be RAW.")
        self.assertIs(
            s.ip_proto,
            IpProto.ICMP4,
            msg="Explicit IpProto.ICMP4 must be stored on _ip_proto.",
        )
        self.assertEqual(
            s.local_ip_address,
            Ip4Address(),
            msg="local_ip_address must start unspecified for IPv4.",
        )
        self.assertEqual(
            s.remote_ip_address,
            Ip4Address(),
            msg="remote_ip_address must start unspecified for IPv4.",
        )
        self.assertEqual(
            s.local_port,
            int(IpProto.ICMP4),
            msg="local_port must equal int(ip_proto) after construction.",
        )
        self.assertEqual(s.remote_port, 0, msg="remote_port must start at 0 for raw sockets.")

    def test__raw_socket__init_explicit_ipv6_protocol(self) -> None:
        """
        Ensure an explicit IPv6 protocol (e.g. 'IpProto.ICMP6') is
        stored on '_ip_proto' and selects the IPv6 unspecified-
        address placeholders for the local/remote bind state.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        s = RawSocket(family=AddressFamily.INET6, protocol=IpProto.ICMP6)

        self.assertIs(
            s.ip_proto,
            IpProto.ICMP6,
            msg="Explicit IpProto.ICMP6 must be stored on _ip_proto.",
        )
        self.assertEqual(
            s.local_ip_address,
            Ip6Address(),
            msg="local_ip_address must start unspecified for IPv6.",
        )
        self.assertEqual(
            s.remote_ip_address,
            Ip6Address(),
            msg="remote_ip_address must start unspecified for IPv6.",
        )

    def test__raw_socket__init_rejects_non_raw_type(self) -> None:
        """
        Ensure constructing with any 'SocketType' other than 'RAW'
        fires the 'assert type is SocketType.RAW' guard.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            RawSocket(
                family=AddressFamily.INET4,
                type=SocketType.STREAM,
                protocol=IpProto.ICMP4,
            )


class TestRawSocketBind(_RawSocketTestCase):
    """
    The 'RawSocket.bind' tests.
    """

    def test__raw_socket__bind_accepts_stack_owned_address(self) -> None:
        """
        Ensure binding to a specific local IPv4 address that the stack
        owns succeeds, updates 'local_ip_address', and registers the
        socket in 'stack.sockets'.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.bind(("10.0.0.1", 0))

        self.assertEqual(
            s.local_ip_address,
            Ip4Address("10.0.0.1"),
            msg="bind() must set local_ip_address to the provided stack-owned address.",
        )
        self.assertIn(
            s.socket_id,
            self._sockets,
            msg="bind() must register the socket on stack.sockets under its socket_id.",
        )

    def test__raw_socket__bind_accepts_unspecified_address(self) -> None:
        """
        Ensure binding to '0.0.0.0' (the unspecified IPv4 address) is
        always accepted regardless of the stack's unicast list — it
        represents a wildcard bind.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.bind(("0.0.0.0", 0))

        self.assertEqual(
            s.local_ip_address,
            Ip4Address(),
            msg="bind() must accept the IPv4 unspecified address as a wildcard.",
        )

    def test__raw_socket__bind_rejects_foreign_address(self) -> None:
        """
        Ensure binding to an IPv4 address not owned by the stack raises
        'OSError' with the canonical Errno 99 message.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with self.assertRaises(OSError) as context:
            s.bind(("192.168.99.99", 0))
        self.assertIn(
            "[Errno 99]",
            str(context.exception),
            msg="bind() must raise with Errno 99 when the local IP is not stack-owned.",
        )

    def test__raw_socket__bind_rejects_malformed_ip4(self) -> None:
        """
        Ensure a malformed IPv4 literal raises 'gaierror' — the
        stack-level alias for 'socket.gaierror'.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with self.assertRaises(gaierror):
            s.bind(("not-an-ip", 0))

    def test__raw_socket__bind_ip6_rejects_foreign_address(self) -> None:
        """
        Ensure the IPv6 branch also checks the stack's unicast set and
        raises Errno 99 when the address is not owned.
        """

        s = RawSocket(family=AddressFamily.INET6, protocol=IpProto.ICMP6)
        with self.assertRaises(OSError) as context:
            s.bind(("2001:db8:dead::1", 0))
        self.assertIn(
            "[Errno 99]",
            str(context.exception),
            msg="bind() must raise with Errno 99 for foreign IPv6 addresses.",
        )

    def test__raw_socket__bind_ip6_rejects_malformed_address(self) -> None:
        """
        Ensure malformed IPv6 literals raise 'gaierror'.
        """

        s = RawSocket(family=AddressFamily.INET6, protocol=IpProto.ICMP6)
        with self.assertRaises(gaierror):
            s.bind(("not-a-v6", 0))


class TestRawSocketConnect(_RawSocketTestCase):
    """
    The 'RawSocket.connect' tests.
    """

    def test__raw_socket__connect_sets_remote_and_picks_local(self) -> None:
        """
        Ensure connect() validates the remote IP, delegates to
        'pick_local_ip_address' when the local IP is unspecified, and
        stores both sides plus the remote port.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with patch(
            "pytcp.socket.raw__socket.pick_local_ip_address",
            return_value=Ip4Address("10.0.0.1"),
        ) as pick:
            s.connect(("10.0.0.5", 7))

        pick.assert_called_once()
        self.assertEqual(
            s.local_ip_address,
            Ip4Address("10.0.0.1"),
            msg="connect() must set the local IP from pick_local_ip_address when starting unspecified.",
        )
        self.assertEqual(
            s.remote_ip_address,
            Ip4Address("10.0.0.5"),
            msg="connect() must set the remote IP from the address argument.",
        )
        self.assertEqual(s.remote_port, 7, msg="connect() must store the remote port verbatim.")

    def test__raw_socket__connect_rejects_out_of_range_port(self) -> None:
        """
        Ensure connect() raises 'OverflowError' for a port value
        outside the 0-65535 inclusive range.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with self.assertRaises(OverflowError):
            s.connect(("10.0.0.5", 70000))

    def test__raw_socket__connect_rejects_malformed_remote_address(self) -> None:
        """
        Ensure connect() raises 'gaierror' when the remote address
        literal is malformed.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with self.assertRaises(gaierror):
            s.connect(("not-an-ip", 7))

    def test__raw_socket__connect_rejects_unroutable_remote(self) -> None:
        """
        Ensure connect() raises 'gaierror' when the helper cannot pick
        a local IP address (both the stack-provided and fallback
        picks would be unspecified).
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with patch(
            "pytcp.socket.raw__socket.pick_local_ip_address",
            return_value=Ip4Address(),
        ):
            with self.assertRaises(gaierror):
                s.connect(("10.0.0.5", 7))


class TestRawSocketSend(_RawSocketTestCase):
    """
    The 'RawSocket.send' / 'RawSocket.sendto' tests.
    """

    def test__raw_socket__send_requires_connect(self) -> None:
        """
        Ensure send() raises 'OSError' with the Errno 89 message when
        called before connect(), because the remote IP is still the
        unspecified placeholder.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with self.assertRaises(OSError) as context:
            s.send(b"data")
        self.assertIn(
            "[Errno 89]",
            str(context.exception),
            msg="send() must raise with Errno 89 when no destination is set.",
        )

    def test__raw_socket__send_ip4_returns_bytes_sent(self) -> None:
        """
        Ensure send() dispatches to 'send_ip4_packet' for an IPv4 raw
        socket and returns 'len(data)' on 'PASSED__ETHERNET__TO_TX_RING'.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with patch(
            "pytcp.socket.raw__socket.pick_local_ip_address",
            return_value=Ip4Address("10.0.0.1"),
        ):
            s.connect(("10.0.0.5", 7))
        self.assertEqual(
            s.send(b"hello"),
            5,
            msg="send() must return the number of bytes enqueued for transmission.",
        )

    def test__raw_socket__send_ip6_returns_bytes_sent(self) -> None:
        """
        Ensure send() dispatches to 'send_ip6_packet' for an IPv6 raw
        socket.
        """

        s = RawSocket(family=AddressFamily.INET6, protocol=IpProto.ICMP6)
        with patch(
            "pytcp.socket.raw__socket.pick_local_ip_address",
            return_value=Ip6Address("2001:db8::1"),
        ):
            s.connect(("2001:db8::2", 7))
        self.assertEqual(
            s.send(b"data"),
            4,
            msg="send() on an IPv6 raw socket must route through send_ip6_packet.",
        )

    def test__raw_socket__send_returns_zero_on_drop(self) -> None:
        """
        Ensure send() returns 0 when the TX path reports any status
        other than 'PASSED__ETHERNET__TO_TX_RING'.
        """

        handler = _make_packet_handler()
        handler.send_ip4_packet = lambda **_: TxStatus.DROPPED__ETHERNET__DST_RESOLUTION_FAIL
        with patch("pytcp.socket.raw__socket.stack.packet_handler", handler):
            s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
            with patch(
                "pytcp.socket.raw__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ):
                s.connect(("10.0.0.5", 7))
            self.assertEqual(
                s.send(b"data"),
                0,
                msg="send() must return 0 when the packet is dropped on the TX path.",
            )

    def test__raw_socket__sendto_does_not_require_connect(self) -> None:
        """
        Ensure sendto() can transmit without a prior connect() — it
        derives the remote from its 'address' argument and the local
        from 'pick_local_ip_address'.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with patch(
            "pytcp.socket.raw__socket.pick_local_ip_address",
            return_value=Ip4Address("10.0.0.1"),
        ):
            self.assertEqual(
                s.sendto(b"hello", ("10.0.0.5", 7)),
                5,
                msg="sendto() must return the number of bytes enqueued without requiring connect().",
            )

    def test__raw_socket__sendto_ip6_returns_bytes_sent(self) -> None:
        """
        Ensure sendto() dispatches to 'send_ip6_packet' for an IPv6
        raw socket.
        """

        s = RawSocket(family=AddressFamily.INET6, protocol=IpProto.ICMP6)
        with patch(
            "pytcp.socket.raw__socket.pick_local_ip_address",
            return_value=Ip6Address("2001:db8::1"),
        ):
            self.assertEqual(
                s.sendto(b"data", ("2001:db8::2", 7)),
                4,
                msg="sendto() on an IPv6 raw socket must route through send_ip6_packet.",
            )


class TestRawSocketReceive(_RawSocketTestCase):
    """
    The 'RawSocket.recv' / 'RawSocket.recvfrom' / 'process_raw_packet'
    tests.
    """

    def _make_md(self) -> RawMetadata:
        """
        Build a canonical IPv4 'RawMetadata' envelope to feed the
        socket's receive path.
        """

        from net_addr import IpVersion

        return RawMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            ip__proto=IpProto.ICMP4,
            raw__data=b"payload",
        )

    def test__raw_socket__process_raw_packet_enqueues(self) -> None:
        """
        Ensure 'process_raw_packet' appends the metadata to the RX
        queue and releases the 'packet_rx_md_ready' semaphore exactly
        once per packet.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.process_raw_packet(self._make_md())

        self.assertEqual(
            len(s._packet_rx_md),
            1,
            msg="process_raw_packet must enqueue exactly one metadata entry.",
        )

    def test__raw_socket__recv_returns_payload(self) -> None:
        """
        Ensure recv() dequeues the next metadata entry, returns its
        'raw__data' as 'bytes', and honors the queued-packet ordering.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.process_raw_packet(self._make_md())

        self.assertEqual(
            s.recv(),
            b"payload",
            msg="recv() must return the queued metadata's raw__data as bytes.",
        )

    def test__raw_socket__recv_timeout_raises(self) -> None:
        """
        Ensure recv() with a finite timeout raises 'TimeoutError' when
        no packet arrives within the window.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with self.assertRaises(TimeoutError):
            s.recv(timeout=0.01)

    def test__raw_socket__recvfrom_returns_payload_and_addr(self) -> None:
        """
        Ensure recvfrom() returns a (bytes, (str_ip, 0)) tuple. The
        port is always 0 for raw sockets since there is no L4 port.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.process_raw_packet(self._make_md())

        data, addr = s.recvfrom()
        self.assertEqual(
            data,
            b"payload",
            msg="recvfrom() must return the raw__data as the first tuple element.",
        )
        self.assertEqual(
            addr,
            ("10.0.0.2", 0),
            msg="recvfrom() must return (remote_ip_str, 0) as the second tuple element.",
        )

    def test__raw_socket__recvfrom_timeout_raises(self) -> None:
        """
        Ensure recvfrom() with a finite timeout raises 'TimeoutError'
        when no packet arrives within the window.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        with self.assertRaises(TimeoutError):
            s.recvfrom(timeout=0.01)


class TestRawSocketClose(_RawSocketTestCase):
    """
    The 'RawSocket.close' teardown tests.
    """

    def test__raw_socket__close_removes_socket_from_registry(self) -> None:
        """
        Ensure close() removes the socket from 'stack.sockets' so
        subsequent packets cannot reach it. Closing a socket that was
        never bound is a no-op.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.bind(("10.0.0.1", 0))
        self.assertIn(
            s.socket_id,
            self._sockets,
            msg="Precondition: bind() must register the socket.",
        )

        s.close()

        self.assertNotIn(
            s.socket_id,
            self._sockets,
            msg="close() must remove the socket from stack.sockets.",
        )

    def test__raw_socket__close_is_idempotent(self) -> None:
        """
        Ensure close() does not raise when called on an unbound socket
        — it must treat 'socket not in registry' as success.
        """

        s = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        s.close()  # must not raise


class TestRawSocketFileno(_RawSocketTestCase):
    """
    The 'RawSocket.fileno' / read-readiness signal-and-drain tests.
    """

    def _make_md(self, data: bytes = b"payload") -> RawMetadata:
        """
        Build a canonical IPv4 'RawMetadata' envelope.
        """

        from net_addr import IpVersion

        return RawMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            ip__proto=IpProto.ICMP4,
            raw__data=data,
        )

    def setUp(self) -> None:
        """
        Build a fresh raw socket. 'tearDown' closes it before the
        parent fixture stops the 'log' patch so the close-time log
        line stays suppressed.
        """

        super().setUp()
        self._socket = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)

    def tearDown(self) -> None:
        """
        Close the socket while the 'log' patch is still active, then
        let the parent tear down the stack stubs.
        """

        try:
            self._socket.close()
        except OSError:
            pass
        super().tearDown()

    def test__raw_socket__fileno_returns_non_negative_int(self) -> None:
        """
        Ensure 'fileno()' on a raw socket returns a non-negative
        integer file descriptor for selector consumption.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        fd = self._socket.fileno()

        self.assertIsInstance(
            fd,
            int,
            msg="RawSocket.fileno() must return an int.",
        )
        self.assertGreaterEqual(
            fd,
            0,
            msg="RawSocket.fileno() must return a non-negative fd.",
        )

    def test__raw_socket__fileno_initially_not_select_ready(self) -> None:
        """
        Ensure a freshly-constructed raw socket is not select-readable
        before any packet has been delivered.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [],
            msg="A fresh RawSocket must not be select-readable.",
        )

    def test__raw_socket__fileno_select_ready_after_packet_arrives(self) -> None:
        """
        Ensure 'process_raw_packet' transitions the fd into the
        select-readable state.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_raw_packet(self._make_md())

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [self._socket.fileno()],
            msg="process_raw_packet must mark the fd as select-readable.",
        )

    def test__raw_socket__fileno_drained_after_recv_consumes_last_packet(self) -> None:
        """
        Ensure 'recv()' returns the fd to the not-readable state
        once the last queued packet has been consumed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._socket.process_raw_packet(self._make_md())
        self._socket.recv()

        rlist, _, _ = select.select([self._socket.fileno()], [], [], 0)

        self.assertEqual(
            rlist,
            [],
            msg="recv() draining the last packet must clear the readable bit.",
        )

    def test__raw_socket__close_closes_underlying_fd(self) -> None:
        """
        Ensure 'close()' tears down the eventfd backing 'fileno()'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        fd = self._socket.fileno()
        self._socket.close()

        with self.assertRaises(OSError) as context:
            fcntl.fcntl(fd, fcntl.F_GETFD)

        self.assertEqual(
            context.exception.errno,
            errno.EBADF,
            msg="close() must close the eventfd backing fileno() (EBADF on syscall).",
        )


class TestRawSocketNonBlocking(_RawSocketTestCase):
    """
    The 'RawSocket.setblocking' non-blocking-recv tests.
    """

    def setUp(self) -> None:
        """
        Build a non-blocking raw socket. tearDown closes it before
        the parent fixture stops the 'log' patch.
        """

        super().setUp()
        self._socket = RawSocket(family=AddressFamily.INET4, protocol=IpProto.ICMP4)
        self._socket.setblocking(False)

    def tearDown(self) -> None:
        """
        Close the socket before the parent tears down patches.
        """

        try:
            self._socket.close()
        except OSError:
            pass
        super().tearDown()

    def test__raw_socket__recv_raises_blocking_io_error_when_no_data(self) -> None:
        """
        Ensure 'recv()' on a non-blocking raw socket with an empty
        queue raises 'BlockingIOError(EAGAIN)' to match POSIX
        'O_NONBLOCK' semantics.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(BlockingIOError) as context:
            self._socket.recv()

        self.assertEqual(
            context.exception.errno,
            errno.EAGAIN,
            msg="Non-blocking recv() with no data must raise BlockingIOError(EAGAIN).",
        )

    def test__raw_socket__recvfrom_raises_blocking_io_error_when_no_data(self) -> None:
        """
        Ensure 'recvfrom()' parallels 'recv()' in raising
        'BlockingIOError(EAGAIN)' on a non-blocking socket with an
        empty queue.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(BlockingIOError) as context:
            self._socket.recvfrom()

        self.assertEqual(
            context.exception.errno,
            errno.EAGAIN,
            msg="Non-blocking recvfrom() with no data must raise BlockingIOError(EAGAIN).",
        )
