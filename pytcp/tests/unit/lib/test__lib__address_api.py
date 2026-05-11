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
This module contains tests for the IPv4 address-control API
('Ip4AddressApi') in 'pytcp/lib/address_api.py'.

pytcp/tests/unit/lib/test__lib__address_api.py

ver 3.0.4
"""

from typing import TYPE_CHECKING, cast, override
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, Ip4Host
from pytcp.lib.address_api import Ip4AddressApi

if TYPE_CHECKING:
    from pytcp.stack.packet_handler import PacketHandlerL2


class _FakePacketHandler:
    """
    Minimal packet-handler stand-in for 'Ip4AddressApi' tests —
    exposes only the '_ip4_host' attribute the API mutates.
    Using a hand-rolled class avoids the autospec ceremony for
    a 50-attribute production class.
    """

    def __init__(self) -> None:
        self._ip4_host: list[Ip4Host] = []


class TestIp4AddressApiAddHost(TestCase):
    """
    'Ip4AddressApi.add_host' installs an Ip4Host on the stack's
    address list.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the API's '<stack>' log line and stand up a fake
        packet handler for the API to mutate.
        """

        self.enterContext(patch("pytcp.lib.address_api.log"))
        self._packet_handler = _FakePacketHandler()
        self._api = Ip4AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__add_host_appends_to_packet_handler_list(self) -> None:
        """
        Ensure 'add_host' appends the supplied 'Ip4Host' to the
        packet handler's '_ip4_host' list.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        host = Ip4Host("10.0.0.5/24")

        self._api.add_host(ip4_host=host)

        self.assertEqual(
            self._packet_handler._ip4_host,
            [host],
            msg="add_host must append the supplied Ip4Host to the packet handler list.",
        )

    def test__ip4_address_api__add_host_preserves_existing_hosts(self) -> None:
        """
        Ensure 'add_host' is additive — pre-existing hosts on the
        packet handler list survive an add_host call. Mirrors
        Linux RTM_NEWADDR semantics (additive, not replacing).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        existing = Ip4Host("10.0.0.4/24")
        self._packet_handler._ip4_host.append(existing)

        new = Ip4Host("10.0.0.5/24")
        self._api.add_host(ip4_host=new)

        self.assertEqual(
            self._packet_handler._ip4_host,
            [existing, new],
            msg="add_host must preserve pre-existing hosts.",
        )


class TestIp4AddressApiRemoveHost(TestCase):
    """
    'Ip4AddressApi.remove_host' removes hosts keyed by address and
    optionally ABORTs bound TCP sessions per the RFC 5227 §2.4-final
    SHOULD (deliberate deviation from Linux's silent-rot).
    """

    @override
    def setUp(self) -> None:
        """
        Silence the API's log line and stand up a fake packet
        handler pre-populated with a single host.
        """

        self.enterContext(patch("pytcp.lib.address_api.log"))
        self._packet_handler = _FakePacketHandler()
        self._target_host = Ip4Host("10.0.0.5/24")
        self._other_host = Ip4Host("10.0.0.6/24")
        self._packet_handler._ip4_host = [self._target_host, self._other_host]
        self._api = Ip4AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__remove_host_drops_matching_address(self) -> None:
        """
        Ensure 'remove_host' filters out every Ip4Host whose
        '.address' equals the supplied 'ip4_address' and leaves
        other hosts intact.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.object(Ip4AddressApi, "_abort_bound_tcp_sessions"):
            self._api.remove_host(ip4_address=Ip4Address("10.0.0.5"))

        self.assertEqual(
            self._packet_handler._ip4_host,
            [self._other_host],
            msg="remove_host must drop only the host matching the supplied address.",
        )

    def test__ip4_address_api__remove_host_default_aborts_bound_sessions(self) -> None:
        """
        Ensure 'remove_host' defaults to ABORTing TCP sessions
        bound to the address — the deliberate deviation from
        Linux's silent-rot behaviour.

        Reference: RFC 5227 §2.4 final paragraph (hosts SHOULD actively reset existing connections).
        """

        with patch.object(Ip4AddressApi, "_abort_bound_tcp_sessions") as mock_abort:
            self._api.remove_host(ip4_address=Ip4Address("10.0.0.5"))

        mock_abort.assert_called_once_with(Ip4Address("10.0.0.5"))

    def test__ip4_address_api__remove_host_abort_false_skips_abort(self) -> None:
        """
        Ensure 'remove_host(abort_bound_sessions=False)' performs
        the address removal without aborting TCP sessions —
        Linux-parity "silent rot" semantic for diagnostics or
        for callers with their own teardown discipline.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.object(Ip4AddressApi, "_abort_bound_tcp_sessions") as mock_abort:
            self._api.remove_host(
                ip4_address=Ip4Address("10.0.0.5"),
                abort_bound_sessions=False,
            )

        mock_abort.assert_not_called()
        self.assertEqual(
            self._packet_handler._ip4_host,
            [self._other_host],
            msg="remove_host(abort=False) must still remove the address from the host list.",
        )

    def test__ip4_address_api__remove_host_unknown_address_is_noop(self) -> None:
        """
        Ensure 'remove_host' for an address not present on the
        packet handler list is a no-op (still aborts any matching
        TCP sessions, but the list filter naturally leaves
        everything intact).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.object(Ip4AddressApi, "_abort_bound_tcp_sessions"):
            self._api.remove_host(ip4_address=Ip4Address("10.0.0.99"))

        self.assertEqual(
            self._packet_handler._ip4_host,
            [self._target_host, self._other_host],
            msg="remove_host for an unknown address must leave the host list unchanged.",
        )


class TestIp4AddressApiReplaceHost(TestCase):
    """
    'Ip4AddressApi.replace_host' atomically swaps an old address
    for a new Ip4Host — RTM_NEWADDR-before-RTM_DELADDR ordering.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up a fake packet handler with one host installed
        that the test will swap out.
        """

        self.enterContext(patch("pytcp.lib.address_api.log"))
        self._packet_handler = _FakePacketHandler()
        self._old_host = Ip4Host("10.0.0.5/24")
        self._packet_handler._ip4_host = [self._old_host]
        self._api = Ip4AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__replace_host_installs_new_and_removes_old(self) -> None:
        """
        Ensure 'replace_host' ends with the new host installed
        and the old address removed — net effect equivalent to
        'remove_host(old) + add_host(new)' but with the install-
        before-remove ordering Linux RTNETLINK guarantees.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        new_host = Ip4Host("10.0.0.7/24")

        with patch.object(Ip4AddressApi, "_abort_bound_tcp_sessions"):
            self._api.replace_host(
                old_address=Ip4Address("10.0.0.5"),
                new_host=new_host,
            )

        self.assertEqual(
            self._packet_handler._ip4_host,
            [new_host],
            msg="replace_host must leave only the new host installed; the old address is removed.",
        )

    def test__ip4_address_api__replace_host_installs_new_before_removing_old(self) -> None:
        """
        Ensure 'replace_host' installs the new host BEFORE
        removing the old (matching Linux RTM_NEWADDR →
        RTM_DELADDR ordering). The transient overlap is observable
        by stubbing '_abort_bound_tcp_sessions' to capture the
        host-list state at the moment of the abort.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        new_host = Ip4Host("10.0.0.7/24")
        snapshot_at_abort: list[Ip4Host] = []

        def _snapshot(_: Ip4Address) -> None:
            snapshot_at_abort.extend(self._packet_handler._ip4_host)

        with patch.object(Ip4AddressApi, "_abort_bound_tcp_sessions", side_effect=_snapshot):
            self._api.replace_host(
                old_address=Ip4Address("10.0.0.5"),
                new_host=new_host,
            )

        # At the moment '_abort_bound_tcp_sessions' fired (during
        # the remove_host half of the swap), BOTH old and new must
        # have been present on the list.
        self.assertIn(
            new_host,
            snapshot_at_abort,
            msg="replace_host must install the new host BEFORE the abort-and-remove of the old.",
        )
        self.assertIn(
            self._old_host,
            snapshot_at_abort,
            msg="replace_host must NOT have removed the old host before the abort fired.",
        )


class TestIp4AddressApiListIp4Hosts(TestCase):
    """
    'Ip4AddressApi.list_ip4_hosts' returns a read-only snapshot of
    the stack's IPv4 address list.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up a fake packet handler with two hosts installed
        so the snapshot test has something to read.
        """

        self.enterContext(patch("pytcp.lib.address_api.log"))
        self._packet_handler = _FakePacketHandler()
        self._packet_handler._ip4_host = [Ip4Host("10.0.0.5/24"), Ip4Host("10.0.0.6/24")]
        self._api = Ip4AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__list_returns_tuple_copy(self) -> None:
        """
        Ensure 'list_ip4_hosts' returns a tuple (immutable) snapshot
        — the caller cannot mutate stack state through it. Matches
        the Phase-3 "introspection is read-only / copy-by-value"
        contract from CLAUDE.md.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        snapshot = self._api.list_ip4_hosts()

        self.assertIsInstance(
            snapshot,
            tuple,
            msg="list_ip4_hosts must return a tuple (immutable snapshot).",
        )
        self.assertEqual(
            len(snapshot),
            2,
            msg="Snapshot must contain every host installed on the packet handler.",
        )

    def test__ip4_address_api__list_decouples_from_underlying_list(self) -> None:
        """
        Ensure mutating the underlying packet handler list AFTER
        calling 'list_ip4_hosts' does NOT mutate the returned
        snapshot — the tuple is a copy, not a view.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        snapshot = self._api.list_ip4_hosts()
        before_len = len(snapshot)

        self._packet_handler._ip4_host.clear()

        self.assertEqual(
            len(snapshot),
            before_len,
            msg="The returned snapshot must be decoupled from subsequent stack mutations.",
        )


class TestIp4AddressApiAbortBoundSessions(TestCase):
    """
    '_abort_bound_tcp_sessions' issues SysCall.ABORT to every TCP
    session whose local_address matches the supplied IPv4 address.
    """

    def test__ip4_address_api__abort_dispatches_abort_syscall_to_matching_sessions(self) -> None:
        """
        Ensure '_abort_bound_tcp_sessions' walks every session in
        'stack.sockets' and issues 'SysCall.ABORT' against the
        ones whose 'local_address' equals the target IPv4
        address. Sessions on other addresses are left alone.

        Reference: RFC 5227 §2.4 final paragraph (hosts SHOULD actively reset existing connections).
        Reference: RFC 9293 §3.10.7.4 (ABORT emits RST and tears the session down).
        """

        from pytcp import stack
        from pytcp.protocols.tcp.tcp__session import SysCall

        target_addr = Ip4Address("10.0.0.5")
        other_addr = Ip4Address("10.0.0.99")

        match_session = MagicMock(name="MatchingTcpSession")
        other_session = MagicMock(name="OtherTcpSession")
        match_sock = MagicMock(name="MatchingSocket", _tcp_session=match_session)
        other_sock = MagicMock(name="OtherSocket", _tcp_session=other_session)

        match_socket_id = MagicMock(local_address=target_addr)
        other_socket_id = MagicMock(local_address=other_addr)

        fake_sockets = {match_socket_id: match_sock, other_socket_id: other_sock}

        with patch.object(stack, "sockets", fake_sockets):
            Ip4AddressApi._abort_bound_tcp_sessions(target_addr)

        match_session.tcp_fsm.assert_called_once_with(syscall=SysCall.ABORT)
        other_session.tcp_fsm.assert_not_called()

    def test__ip4_address_api__abort_skips_non_tcp_sockets(self) -> None:
        """
        Ensure '_abort_bound_tcp_sessions' silently skips sockets
        whose '_tcp_session' attribute is None (UDP / raw sockets)
        — only TCP sessions need explicit ABORT.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from pytcp import stack

        target_addr = Ip4Address("10.0.0.5")
        udp_sock = MagicMock(name="UdpSocket", _tcp_session=None)
        udp_socket_id = MagicMock(local_address=target_addr)
        fake_sockets = {udp_socket_id: udp_sock}

        with patch.object(stack, "sockets", fake_sockets):
            Ip4AddressApi._abort_bound_tcp_sessions(target_addr)

        # No assertion needed beyond "doesn't raise" — the UDP
        # socket has no '_tcp_session.tcp_fsm' attribute, so a
        # naive call would AttributeError. The implementation
        # must gate on the None check.
