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
This module contains tests for the 'UdpSocket' BSD-like UDP socket
implementation.

pytcp/tests/unit/socket/test__socket__udp__socket.py

ver 3.0.4
"""


from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from net_addr import Ip4Address, Ip6Address, IpVersion
from net_proto.lib.enums import IpProto
from pytcp.lib.tx_status import TxStatus
from pytcp.socket import AddressFamily, SocketType, gaierror
from pytcp.socket.udp__metadata import UdpMetadata
from pytcp.socket.udp__socket import UdpSocket


def _make_packet_handler(
    *,
    ip4_unicast: list[Ip4Address] | None = None,
    ip6_unicast: list[Ip6Address] | None = None,
    tx_status: TxStatus = TxStatus.PASSED__ETHERNET__TO_TX_RING,
) -> SimpleNamespace:
    """
    Build a minimal 'packet_handler' stub exposing the unicast address
    iterables plus a 'send_udp_packet' callable that returns the
    requested 'TxStatus'.
    """

    return SimpleNamespace(
        ip4_unicast=ip4_unicast or [Ip4Address("10.0.0.1")],
        ip6_unicast=ip6_unicast or [Ip6Address("2001:db8::1")],
        send_udp_packet=lambda **_: tx_status,
    )


class _UdpSocketTestCase(TestCase):
    """
    Shared fixture for 'UdpSocket' tests that stubs the stack's module
    globals ('sockets', 'packet_handler') and suppresses log output.
    """

    def setUp(self) -> None:
        """
        Install the module-level stack patches and a fresh, empty
        socket registry.
        """

        self._log_patch = patch("pytcp.socket.udp__socket.log")
        self._log_patch.start()

        self._sockets: dict = {}
        self._sockets_patch = patch(
            "pytcp.socket.udp__socket.stack.sockets",
            self._sockets,
        )
        self._sockets_patch.start()

        self._handler = _make_packet_handler()
        self._handler_patch = patch(
            "pytcp.socket.udp__socket.stack.packet_handler",
            self._handler,
        )
        self._handler_patch.start()

        # is_address_in_use reads stack.sockets directly, so mirror the
        # patch on that module as well.
        self._helper_sockets_patch = patch(
            "pytcp.lib.ip_helper.stack.sockets",
            self._sockets,
        )
        self._helper_sockets_patch.start()

    def tearDown(self) -> None:
        """
        Tear down the module-level stack patches.
        """

        self._log_patch.stop()
        self._sockets_patch.stop()
        self._handler_patch.stop()
        self._helper_sockets_patch.stop()


class TestUdpSocketInit(_UdpSocketTestCase):
    """
    The 'UdpSocket.__init__' tests.
    """

    def test__udp_socket__init_ip4_defaults(self) -> None:
        """
        Ensure a fresh IPv4 UDP socket starts with unspecified
        local/remote IPs, both ports at 0, and the fixed socket_type
        + ip_proto mix.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        self.assertIs(s.socket_type, SocketType.DGRAM, msg="socket_type must be DGRAM.")
        self.assertIs(s.ip_proto, IpProto.UDP, msg="ip_proto must be UDP.")
        self.assertEqual(s.local_ip_address, Ip4Address(), msg="local_ip_address must start unspecified.")
        self.assertEqual(s.remote_ip_address, Ip4Address(), msg="remote_ip_address must start unspecified.")
        self.assertEqual(s.local_port, 0, msg="local_port must start at 0.")
        self.assertEqual(s.remote_port, 0, msg="remote_port must start at 0.")

    def test__udp_socket__init_ip6_defaults(self) -> None:
        """
        Ensure a fresh IPv6 UDP socket starts with the '::' unspecified
        address on both ends.
        """

        s = UdpSocket(family=AddressFamily.INET6)
        self.assertEqual(s.local_ip_address, Ip6Address(), msg="IPv6 local_ip_address must start unspecified.")
        self.assertEqual(s.remote_ip_address, Ip6Address(), msg="IPv6 remote_ip_address must start unspecified.")

    def test__udp_socket__init_rejects_non_dgram(self) -> None:
        """
        Ensure the 'assert type is SocketType.DGRAM' guard fires when
        a non-DGRAM socket type is supplied.
        """

        with self.assertRaises(AssertionError):
            UdpSocket(family=AddressFamily.INET4, type=SocketType.STREAM)

    def test__udp_socket__init_rejects_non_udp_protocol(self) -> None:
        """
        Ensure the 'assert protocol is IpProto.UDP' guard fires for a
        non-UDP protocol argument.
        """

        with self.assertRaises(AssertionError):
            UdpSocket(family=AddressFamily.INET4, protocol=IpProto.TCP)


class TestUdpSocketBind(_UdpSocketTestCase):
    """
    The 'UdpSocket.bind' tests.
    """

    def test__udp_socket__bind_picks_port_when_zero(self) -> None:
        """
        Ensure bind() with a zero local port defers to
        'pick_local_port' and registers the resulting port on the
        socket.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with patch(
            "pytcp.socket.udp__socket.pick_local_port",
            return_value=40000,
        ):
            s.bind(("10.0.0.1", 0))
        self.assertEqual(
            s.local_port,
            40000,
            msg="bind() with local port 0 must assign the port picked by pick_local_port.",
        )

    def test__udp_socket__bind_with_specific_port(self) -> None:
        """
        Ensure bind() with a specific local port accepts it when no
        other socket is using it.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.bind(("10.0.0.1", 8080))
        self.assertEqual(s.local_port, 8080, msg="bind() with a specific port must use that port verbatim.")

    def test__udp_socket__bind_twice_raises(self) -> None:
        """
        Ensure binding an already-bound socket raises 'OSError' with
        Errno 22 — the socket can be bound exactly once.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.bind(("10.0.0.1", 8080))
        with self.assertRaises(OSError) as context:
            s.bind(("10.0.0.1", 8081))
        self.assertIn(
            "[Errno 22]",
            str(context.exception),
            msg="bind() must raise Errno 22 when called on a socket bound to a specific port.",
        )

    def test__udp_socket__bind_rejects_out_of_range_port(self) -> None:
        """
        Ensure bind() raises 'OverflowError' for a port value outside
        the 0-65535 range.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OverflowError):
            s.bind(("10.0.0.1", 70000))

    def test__udp_socket__bind_rejects_foreign_ip(self) -> None:
        """
        Ensure bind() to a specific IPv4 address not owned by the
        stack raises 'OSError' with Errno 99.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OSError) as context:
            s.bind(("192.168.99.99", 0))
        self.assertIn(
            "[Errno 99]",
            str(context.exception),
            msg="bind() must raise Errno 99 when the local IP is not stack-owned.",
        )

    def test__udp_socket__bind_rejects_malformed_ip(self) -> None:
        """
        Ensure a malformed IPv4 literal raises 'gaierror'.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(gaierror):
            s.bind(("garbage", 0))

    def test__udp_socket__bind_ip6_accepts_stack_owned(self) -> None:
        """
        Ensure bind() on an IPv6 socket accepts a stack-owned address.
        """

        s = UdpSocket(family=AddressFamily.INET6)
        s.bind(("2001:db8::1", 9090))
        self.assertEqual(
            s.local_ip_address,
            Ip6Address("2001:db8::1"),
            msg="bind() must set local_ip_address on an IPv6 socket.",
        )

    def test__udp_socket__bind_ip6_rejects_malformed(self) -> None:
        """
        Ensure a malformed IPv6 literal raises 'gaierror'.
        """

        s = UdpSocket(family=AddressFamily.INET6)
        with self.assertRaises(gaierror):
            s.bind(("not-a-v6", 0))

    def test__udp_socket__bind_rejects_port_in_use(self) -> None:
        """
        Ensure bind() to a port already claimed by another socket
        raises 'OSError' with Errno 98.
        """

        first = UdpSocket(family=AddressFamily.INET4)
        first.bind(("10.0.0.1", 8080))

        second = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OSError) as context:
            second.bind(("10.0.0.1", 8080))
        self.assertIn(
            "[Errno 98]",
            str(context.exception),
            msg="bind() must raise Errno 98 when the (IP, port) is already in use.",
        )


class TestUdpSocketConnect(_UdpSocketTestCase):
    """
    The 'UdpSocket.connect' tests.
    """

    def test__udp_socket__connect_sets_remote_and_picks_local(self) -> None:
        """
        Ensure connect() picks a local IP via 'pick_local_ip_address'
        when unspecified, picks a local port via 'pick_local_port'
        when unbound, and stores both sides of the remote address.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.socket.udp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch(
                "pytcp.socket.udp__socket.pick_local_port",
                return_value=40000,
            ),
        ):
            s.connect(("10.0.0.5", 5353))

        self.assertEqual(s.local_ip_address, Ip4Address("10.0.0.1"), msg="connect() must pick the local IP.")
        self.assertEqual(s.local_port, 40000, msg="connect() must pick the local port.")
        self.assertEqual(s.remote_ip_address, Ip4Address("10.0.0.5"), msg="connect() must store the remote IP.")
        self.assertEqual(s.remote_port, 5353, msg="connect() must store the remote port.")

    def test__udp_socket__connect_rejects_out_of_range_port(self) -> None:
        """
        Ensure connect() raises 'OverflowError' for a remote port
        outside the 0-65535 range.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OverflowError):
            s.connect(("10.0.0.5", 70000))

    def test__udp_socket__connect_rejects_malformed_address(self) -> None:
        """
        Ensure a malformed remote-address literal raises 'gaierror'.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(gaierror):
            s.connect(("garbage", 7))

    def test__udp_socket__connect_unspecified_remote_marks_unreachable(self) -> None:
        """
        Ensure connecting to '0.0.0.0' (unspecified) flips the internal
        'unreachable' flag, which translates to 'ConnectionRefusedError'
        on the next send()/recv() call.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with patch(
            "pytcp.socket.udp__socket.pick_local_ip_address",
            return_value=Ip4Address("10.0.0.1"),
        ):
            with patch("pytcp.socket.udp__socket.pick_local_port", return_value=40000):
                s.connect(("0.0.0.0", 7))
        self.assertTrue(
            s._unreachable,
            msg="connect() to the unspecified remote address must mark the socket unreachable.",
        )


class TestUdpSocketSend(_UdpSocketTestCase):
    """
    The 'UdpSocket.send' / 'UdpSocket.sendto' tests.
    """

    def _connected_socket(self) -> UdpSocket:
        """
        Construct a connected IPv4 UDP socket ready for send().
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.socket.udp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch(
                "pytcp.socket.udp__socket.pick_local_port",
                return_value=40000,
            ),
        ):
            s.connect(("10.0.0.5", 5353))
        return s

    def test__udp_socket__send_requires_connect(self) -> None:
        """
        Ensure send() raises 'OSError' with Errno 89 when neither the
        remote IP nor the remote port is set.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OSError) as context:
            s.send(b"data")
        self.assertIn(
            "[Errno 89]",
            str(context.exception),
            msg="send() must raise Errno 89 when no destination is set.",
        )

    def test__udp_socket__send_returns_bytes_sent(self) -> None:
        """
        Ensure send() returns 'len(data)' when 'send_udp_packet'
        reports 'PASSED__ETHERNET__TO_TX_RING'.
        """

        s = self._connected_socket()
        self.assertEqual(s.send(b"hello"), 5, msg="send() must return len(data) on success.")

    def test__udp_socket__send_returns_zero_on_drop(self) -> None:
        """
        Ensure send() returns 0 when the TX path reports a drop
        status.
        """

        handler = _make_packet_handler(tx_status=TxStatus.DROPED__ETHERNET__DST_RESOLUTION_FAIL)
        with patch("pytcp.socket.udp__socket.stack.packet_handler", handler):
            s = self._connected_socket()
            self.assertEqual(s.send(b"data"), 0, msg="send() must return 0 when the packet is dropped.")

    def test__udp_socket__send_clears_unreachable_and_raises(self) -> None:
        """
        Ensure send() on a socket flagged unreachable clears the flag
        and raises 'ConnectionRefusedError' — subsequent send()s see
        a clean state.
        """

        s = self._connected_socket()
        s.notify_unreachable()
        with self.assertRaises(ConnectionRefusedError):
            s.send(b"data")
        self.assertFalse(
            s._unreachable,
            msg="send() must clear the unreachable flag after translating it into ConnectionRefusedError.",
        )

    def test__udp_socket__sendto_does_not_require_connect(self) -> None:
        """
        Ensure sendto() works on an unbound socket — it picks a local
        port via 'pick_local_port' and derives the remote from its
        argument.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with (
            patch(
                "pytcp.socket.udp__socket.pick_local_ip_address",
                return_value=Ip4Address("10.0.0.1"),
            ),
            patch(
                "pytcp.socket.udp__socket.pick_local_port",
                return_value=40000,
            ),
        ):
            self.assertEqual(
                s.sendto(b"hello", ("10.0.0.5", 5353)),
                5,
                msg="sendto() must return len(data) on success without requiring connect().",
            )

    def test__udp_socket__sendto_rejects_out_of_range_port(self) -> None:
        """
        Ensure sendto() raises 'OverflowError' for a remote port
        outside the 0-65535 range.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(OverflowError):
            s.sendto(b"data", ("10.0.0.5", 70000))

    def test__udp_socket__sendto_uses_existing_local_port(self) -> None:
        """
        Ensure sendto() on an already-bound socket reuses the existing
        local port rather than picking a new one.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.bind(("10.0.0.1", 4444))
        with patch(
            "pytcp.socket.udp__socket.pick_local_ip_address",
            return_value=Ip4Address("10.0.0.1"),
        ):
            s.sendto(b"hello", ("10.0.0.5", 5353))
        self.assertEqual(
            s.local_port,
            4444,
            msg="sendto() must reuse the existing local_port of a bound socket.",
        )


class TestUdpSocketReceive(_UdpSocketTestCase):
    """
    The 'UdpSocket.recv' / 'UdpSocket.recvfrom' / 'process_udp_packet'
    tests.
    """

    def _make_md(self, data: bytes = b"payload") -> UdpMetadata:
        """
        Build a canonical IPv4 'UdpMetadata' envelope with the given
        payload.
        """

        return UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            udp__local_port=1234,
            udp__remote_port=5678,
            udp__data=memoryview(data),
        )

    def test__udp_socket__process_udp_packet_enqueues(self) -> None:
        """
        Ensure 'process_udp_packet' appends the envelope and releases
        the RX semaphore exactly once per call.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.process_udp_packet(self._make_md())
        self.assertEqual(
            len(s._packet_rx_md),
            1,
            msg="process_udp_packet must enqueue exactly one metadata entry.",
        )

    def test__udp_socket__recv_returns_payload(self) -> None:
        """
        Ensure recv() dequeues a single queued packet and returns its
        payload as 'bytes'.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.process_udp_packet(self._make_md())
        self.assertEqual(
            s.recv(),
            b"payload",
            msg="recv() must return the queued payload as bytes.",
        )

    def test__udp_socket__recv_timeout_raises(self) -> None:
        """
        Ensure recv() with a finite timeout raises 'TimeoutError' when
        no packet arrives.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(TimeoutError):
            s.recv(timeout=0.01)

    def test__udp_socket__recv_unreachable_raises(self) -> None:
        """
        Ensure recv() on a socket flagged unreachable raises
        'ConnectionRefusedError' and clears the flag.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.notify_unreachable()
        with self.assertRaises(ConnectionRefusedError):
            s.recv()
        self.assertFalse(
            s._unreachable,
            msg="recv() must clear the unreachable flag after translating it into ConnectionRefusedError.",
        )

    def test__udp_socket__recv_mv_returns_memoryview(self) -> None:
        """
        Ensure recv__mv() returns the underlying memoryview without
        copying through 'bytes'. Downstream parsers rely on the
        zero-copy behavior.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.process_udp_packet(self._make_md())
        data = s.recv__mv()
        self.assertIsInstance(
            data,
            memoryview,
            msg="recv__mv() must return a memoryview (zero-copy).",
        )
        self.assertEqual(
            bytes(data),
            b"payload",
            msg="recv__mv() must return the queued payload.",
        )

    def test__udp_socket__recvfrom_returns_payload_and_addr(self) -> None:
        """
        Ensure recvfrom() returns a (bytes, (str_ip, port)) tuple
        extracted from the metadata's remote-side fields.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.process_udp_packet(self._make_md())
        data, addr = s.recvfrom()
        self.assertEqual(data, b"payload", msg="recvfrom() must return the queued payload as bytes.")
        self.assertEqual(
            addr,
            ("10.0.0.2", 5678),
            msg="recvfrom() must return (remote_ip_str, remote_port) as the second tuple element.",
        )

    def test__udp_socket__recvfrom_timeout_raises(self) -> None:
        """
        Ensure recvfrom() with a finite timeout raises 'TimeoutError'
        when no packet arrives.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        with self.assertRaises(TimeoutError):
            s.recvfrom(timeout=0.01)


class TestUdpSocketClose(_UdpSocketTestCase):
    """
    The 'UdpSocket.close' teardown tests.
    """

    def test__udp_socket__close_removes_socket_from_registry(self) -> None:
        """
        Ensure close() removes the socket from 'stack.sockets' so
        subsequent packets cannot be routed to it.
        """

        s = UdpSocket(family=AddressFamily.INET4)
        s.bind(("10.0.0.1", 8080))
        self.assertIn(
            s.socket_id,
            self._sockets,
            msg="Precondition: bind() must register the socket.",
        )

        s.close()

        self.assertNotIn(
            s.socket_id,
            self._sockets,
            msg="close() must unregister the socket from stack.sockets.",
        )
