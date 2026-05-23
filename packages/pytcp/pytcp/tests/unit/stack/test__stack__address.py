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

pytcp/tests/unit/stack/test__stack__address.py

ver 3.0.6
"""

from typing import TYPE_CHECKING, cast, override
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, Ip4IfAddr, MacAddress
from pytcp import stack
from pytcp.runtime.interface_table import InterfaceTable
from pytcp.stack.address import (
    ConflictEvent,
    Ip4AddressApi,
    ProbeResult,
)

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2


class _FakePacketHandler:
    """
    Minimal packet-handler stand-in for 'Ip4AddressApi' tests —
    exposes only the '_ip4_ifaddr' attribute the API mutates plus
    the RFC 5227 ACD-helper methods the API delegates to.
    Using a hand-rolled class avoids the autospec ceremony for
    a 50-attribute production class.
    """

    def __init__(self) -> None:
        self._ip4_ifaddr: list[Ip4IfAddr] = []
        # The new ACD API methods on 'Ip4AddressApi' delegate to
        # these helpers. Tests configure 'probe_result' and
        # 'announce_calls' to drive / observe behaviour.
        self.probe_result: bool = True
        self.probe_peer_mac: MacAddress | None = None
        self.probe_calls: list[Ip4Address] = []
        self.announce_calls: list[Ip4Address] = []
        self.gratuitous_arp_calls: list[Ip4Address] = []
        self._ip4_arp_dad__registry = _FakeRegistry()

    def _arp_dad_probe_address(self, ip4_unicast: Ip4Address, /) -> bool:
        self.probe_calls.append(ip4_unicast)
        self._ip4_arp_dad__registry.peer_info_table[ip4_unicast] = self.probe_peer_mac
        return self.probe_result

    def _arp_dad_announce_address(self, ip4_unicast: Ip4Address, /) -> None:
        self.announce_calls.append(ip4_unicast)

    def _send_gratuitous_arp(self, *, ip4_unicast: Ip4Address) -> None:
        self.gratuitous_arp_calls.append(ip4_unicast)


class _FakeRegistry:
    """Records 'peer_info' lookups; tests preload mac results."""

    def __init__(self) -> None:
        self.peer_info_table: dict[Ip4Address, MacAddress | None] = {}

    def peer_info(self, candidate: Ip4Address, /) -> MacAddress | None:
        return self.peer_info_table.get(candidate)


class TestIp4AddressApiAddHost(TestCase):
    """
    'Ip4AddressApi.add_ifaddr' installs an Ip4IfAddr on the stack's
    address list.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the API's '<stack>' log line and stand up a fake
        packet handler for the API to mutate.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._packet_handler = _FakePacketHandler()
        self._api = Ip4AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__add_host_appends_to_packet_handler_list(self) -> None:
        """
        Ensure 'add_ifaddr' appends the supplied 'Ip4IfAddr' to the
        packet handler's '_ip4_ifaddr' list.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        host = Ip4IfAddr("10.0.0.5/24")

        self._api.add_ifaddr(ip4_ifaddr=host)

        self.assertEqual(
            self._packet_handler._ip4_ifaddr,
            [host],
            msg="add_ifaddr must append the supplied Ip4IfAddr to the packet handler list.",
        )

    def test__ip4_address_api__add_host_preserves_existing_hosts(self) -> None:
        """
        Ensure 'add_ifaddr' is additive — pre-existing hosts on the
        packet handler list survive an add_ifaddr call. Mirrors
        Linux RTM_NEWADDR semantics (additive, not replacing).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        existing = Ip4IfAddr("10.0.0.4/24")
        self._packet_handler._ip4_ifaddr.append(existing)

        new = Ip4IfAddr("10.0.0.5/24")
        self._api.add_ifaddr(ip4_ifaddr=new)

        self.assertEqual(
            self._packet_handler._ip4_ifaddr,
            [existing, new],
            msg="add_ifaddr must preserve pre-existing hosts.",
        )

    def test__ip4_address_api__add_host_atomically_rebinds_list(self) -> None:
        """
        Ensure 'add_ifaddr' rebinds '_ip4_ifaddr' to a fresh list
        object rather than mutating the existing list in place, so the
        TX worker iterating the list during source-address selection
        always reads a consistent snapshot (Phase 4 single-writer-safe
        read — control-plane mutation must not be observable mid-update
        by the reading TX thread).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        original_list = self._packet_handler._ip4_ifaddr

        self._api.add_ifaddr(ip4_ifaddr=Ip4IfAddr("10.0.0.5/24"))

        self.assertIsNot(
            self._packet_handler._ip4_ifaddr,
            original_list,
            msg="add_ifaddr must rebind _ip4_ifaddr to a new list, not mutate the existing one in place.",
        )


class TestIp4AddressApiRemoveHost(TestCase):
    """
    'Ip4AddressApi.remove_ifaddr' removes hosts keyed by address and
    optionally ABORTs bound TCP sessions per the RFC 5227 §2.4-final
    SHOULD (deliberate deviation from Linux's silent-rot).
    """

    @override
    def setUp(self) -> None:
        """
        Silence the API's log line and stand up a fake packet
        handler pre-populated with a single host.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._packet_handler = _FakePacketHandler()
        self._target_host = Ip4IfAddr("10.0.0.5/24")
        self._other_host = Ip4IfAddr("10.0.0.6/24")
        self._packet_handler._ip4_ifaddr = [self._target_host, self._other_host]
        self._api = Ip4AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__remove_host_drops_matching_address(self) -> None:
        """
        Ensure 'remove_ifaddr' filters out every Ip4IfAddr whose
        '.address' equals the supplied 'ip4_address' and leaves
        other hosts intact.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.object(Ip4AddressApi, "_abort_bound_tcp_sessions"):
            self._api.remove_ifaddr(ip4_address=Ip4Address("10.0.0.5"))

        self.assertEqual(
            self._packet_handler._ip4_ifaddr,
            [self._other_host],
            msg="remove_ifaddr must drop only the host matching the supplied address.",
        )

    def test__ip4_address_api__remove_host_default_aborts_bound_sessions(self) -> None:
        """
        Ensure 'remove_ifaddr' defaults to ABORTing TCP sessions
        bound to the address — the deliberate deviation from
        Linux's silent-rot behaviour.

        Reference: RFC 5227 §2.4 final paragraph (hosts SHOULD actively reset existing connections).
        """

        with patch.object(Ip4AddressApi, "_abort_bound_tcp_sessions") as mock_abort:
            self._api.remove_ifaddr(ip4_address=Ip4Address("10.0.0.5"))

        mock_abort.assert_called_once_with(Ip4Address("10.0.0.5"))

    def test__ip4_address_api__remove_host_abort_false_skips_abort(self) -> None:
        """
        Ensure 'remove_ifaddr(abort_bound_sessions=False)' performs
        the address removal without aborting TCP sessions —
        Linux-parity "silent rot" semantic for diagnostics or
        for callers with their own teardown discipline.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.object(Ip4AddressApi, "_abort_bound_tcp_sessions") as mock_abort:
            self._api.remove_ifaddr(
                ip4_address=Ip4Address("10.0.0.5"),
                abort_bound_sessions=False,
            )

        mock_abort.assert_not_called()
        self.assertEqual(
            self._packet_handler._ip4_ifaddr,
            [self._other_host],
            msg="remove_ifaddr(abort=False) must still remove the address from the host list.",
        )

    def test__ip4_address_api__remove_host_unknown_address_is_noop(self) -> None:
        """
        Ensure 'remove_ifaddr' for an address not present on the
        packet handler list is a no-op (still aborts any matching
        TCP sessions, but the list filter naturally leaves
        everything intact).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch.object(Ip4AddressApi, "_abort_bound_tcp_sessions"):
            self._api.remove_ifaddr(ip4_address=Ip4Address("10.0.0.99"))

        self.assertEqual(
            self._packet_handler._ip4_ifaddr,
            [self._target_host, self._other_host],
            msg="remove_ifaddr for an unknown address must leave the host list unchanged.",
        )


class TestIp4AddressApiReplaceHost(TestCase):
    """
    'Ip4AddressApi.replace_ifaddr' atomically swaps an old address
    for a new Ip4IfAddr — RTM_NEWADDR-before-RTM_DELADDR ordering.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up a fake packet handler with one host installed
        that the test will swap out.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._packet_handler = _FakePacketHandler()
        self._old_host = Ip4IfAddr("10.0.0.5/24")
        self._packet_handler._ip4_ifaddr = [self._old_host]
        self._api = Ip4AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__replace_host_installs_new_and_removes_old(self) -> None:
        """
        Ensure 'replace_ifaddr' ends with the new host installed
        and the old address removed — net effect equivalent to
        'remove_ifaddr(old) + add_ifaddr(new)' but with the install-
        before-remove ordering Linux RTNETLINK guarantees.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        new_host = Ip4IfAddr("10.0.0.7/24")

        with patch.object(Ip4AddressApi, "_abort_bound_tcp_sessions"):
            self._api.replace_ifaddr(
                old_address=Ip4Address("10.0.0.5"),
                new_ifaddr=new_host,
            )

        self.assertEqual(
            self._packet_handler._ip4_ifaddr,
            [new_host],
            msg="replace_ifaddr must leave only the new host installed; the old address is removed.",
        )

    def test__ip4_address_api__replace_host_installs_new_before_removing_old(self) -> None:
        """
        Ensure 'replace_ifaddr' installs the new host BEFORE
        removing the old (matching Linux RTM_NEWADDR →
        RTM_DELADDR ordering). The transient overlap is observable
        by stubbing '_abort_bound_tcp_sessions' to capture the
        host-list state at the moment of the abort.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        new_host = Ip4IfAddr("10.0.0.7/24")
        snapshot_at_abort: list[Ip4IfAddr] = []

        def _snapshot(_: Ip4Address) -> None:
            snapshot_at_abort.extend(self._packet_handler._ip4_ifaddr)

        with patch.object(Ip4AddressApi, "_abort_bound_tcp_sessions", side_effect=_snapshot):
            self._api.replace_ifaddr(
                old_address=Ip4Address("10.0.0.5"),
                new_ifaddr=new_host,
            )

        # At the moment '_abort_bound_tcp_sessions' fired (during
        # the remove_ifaddr half of the swap), BOTH old and new must
        # have been present on the list.
        self.assertIn(
            new_host,
            snapshot_at_abort,
            msg="replace_ifaddr must install the new host BEFORE the abort-and-remove of the old.",
        )
        self.assertIn(
            self._old_host,
            snapshot_at_abort,
            msg="replace_ifaddr must NOT have removed the old host before the abort fired.",
        )


class TestIp4AddressApiListIp4Hosts(TestCase):
    """
    'Ip4AddressApi.list_ip4_ifaddrs' returns a read-only snapshot of
    the stack's IPv4 address list.
    """

    @override
    def setUp(self) -> None:
        """
        Stand up a fake packet handler with two hosts installed
        so the snapshot test has something to read.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._packet_handler = _FakePacketHandler()
        self._packet_handler._ip4_ifaddr = [Ip4IfAddr("10.0.0.5/24"), Ip4IfAddr("10.0.0.6/24")]
        self._api = Ip4AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__list_returns_tuple_copy(self) -> None:
        """
        Ensure 'list_ip4_ifaddrs' returns a tuple (immutable) snapshot
        — the caller cannot mutate stack state through it. Matches
        the Phase-3 "introspection is read-only / copy-by-value"
        contract from CLAUDE.md.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        snapshot = self._api.list_ip4_ifaddrs()

        self.assertIsInstance(
            snapshot,
            tuple,
            msg="list_ip4_ifaddrs must return a tuple (immutable snapshot).",
        )
        self.assertEqual(
            len(snapshot),
            2,
            msg="Snapshot must contain every host installed on the packet handler.",
        )

    def test__ip4_address_api__list_decouples_from_underlying_list(self) -> None:
        """
        Ensure mutating the underlying packet handler list AFTER
        calling 'list_ip4_ifaddrs' does NOT mutate the returned
        snapshot — the tuple is a copy, not a view.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        snapshot = self._api.list_ip4_ifaddrs()
        before_len = len(snapshot)

        self._packet_handler._ip4_ifaddr.clear()

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
        from pytcp.protocols.tcp.tcp__enums import SysCall

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


class TestIp4AddressApiProbe(TestCase):
    """
    'Ip4AddressApi.probe' runs an RFC 5227 §2.1.1 ARP Probe
    against the supplied address and returns a 'ProbeResult'
    capturing success and (on conflict) the peer MAC.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the API's '<stack>' log line and stand up a fake
        packet handler the API will delegate to.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._packet_handler = _FakePacketHandler()
        self._api = Ip4AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__probe_clean_returns_success(self) -> None:
        """
        Ensure 'probe' returns 'ProbeResult.success=True' with
        no conflict-source info when the underlying probe
        helper reports a clean probe.

        Reference: RFC 5227 §2.1.1 (clean probe means no conflict observed).
        """

        target = Ip4Address("10.0.1.42")
        self._packet_handler.probe_result = True

        result = self._api.probe(address=target)

        self.assertEqual(
            result,
            ProbeResult(success=True, address=target),
            msg="Clean probe must return ProbeResult(success=True, address=target).",
        )
        self.assertEqual(
            self._packet_handler.probe_calls,
            [target],
            msg="probe must call _arp_dad_probe_address once with the target.",
        )

    def test__ip4_address_api__probe_conflict_returns_peer_info(self) -> None:
        """
        Ensure 'probe' returns 'ProbeResult.success=False' with
        the peer MAC captured by the registry when the probe
        helper reports a conflict.

        Reference: RFC 5227 §2.1.1 (conflict observed during probe).
        """

        target = Ip4Address("10.0.1.42")
        peer_mac = MacAddress("02:00:00:00:00:99")
        self._packet_handler.probe_result = False
        self._packet_handler.probe_peer_mac = peer_mac

        result = self._api.probe(address=target)

        self.assertEqual(
            result.success,
            False,
            msg="Conflict probe must return success=False.",
        )
        self.assertEqual(
            result.conflict_sender_mac,
            peer_mac,
            msg="Conflict probe must surface the conflicting peer MAC.",
        )


class TestIp4AddressApiAnnounce(TestCase):
    """
    'Ip4AddressApi.announce' delegates to the underlying RFC
    5227 §2.3 ANNOUNCE_NUM gratuitous-ARP burst helper.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the API's '<stack>' log line and stand up a fake
        packet handler the API delegates to.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._packet_handler = _FakePacketHandler()
        self._api = Ip4AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__announce_delegates_to_helper(self) -> None:
        """
        Ensure 'announce' calls the underlying
        '_arp_dad_announce_address' helper with the supplied
        address.

        Reference: RFC 5227 §2.3 (ANNOUNCE_NUM gratuitous ARP Announcements).
        """

        target = Ip4Address("10.0.1.42")

        self._api.announce(address=target)

        self.assertEqual(
            self._packet_handler.announce_calls,
            [target],
            msg="announce must invoke _arp_dad_announce_address with the target.",
        )


class TestIp4AddressApiClaimWithAcd(TestCase):
    """
    'Ip4AddressApi.claim_with_acd' is the composite probe +
    announce + install primitive — the single-call surface used
    by the static-host claim path and (in the future) by the
    RFC 3927 link-local autoconfig client.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the API's '<stack>' log line and stand up a fake
        packet handler the API delegates to.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._packet_handler = _FakePacketHandler()
        self._api = Ip4AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__claim_clean_installs_and_announces(self) -> None:
        """
        Ensure a clean probe leads to: announce burst fires,
        host is installed via 'add_ifaddr', and the return value
        reports success.

        Reference: RFC 5227 §2.1.1 + §2.3 (probe-then-announce on success).
        """

        host = Ip4IfAddr("169.254.42.42/16")
        self._packet_handler.probe_result = True

        result = self._api.claim_with_acd(ip4_ifaddr=host)

        self.assertTrue(
            result.success,
            msg="Clean claim must return success=True.",
        )
        self.assertEqual(
            result.address,
            host.address,
            msg="Claim result must carry the claimed address.",
        )
        self.assertEqual(
            self._packet_handler.probe_calls,
            [host.address],
            msg="claim_with_acd must probe the address.",
        )
        self.assertEqual(
            self._packet_handler.announce_calls,
            [host.address],
            msg="Clean claim must announce the address.",
        )
        self.assertIn(
            host,
            self._packet_handler._ip4_ifaddr,
            msg="Clean claim must install the host via add_ifaddr.",
        )

    def test__ip4_address_api__claim_conflict_does_not_install(self) -> None:
        """
        Ensure a conflict during probe results in
        success=False, no announce fires, and the host is NOT
        installed — the address remains contested.

        Reference: RFC 5227 §2.1.1 (conflict during probe must prevent claim).
        """

        host = Ip4IfAddr("169.254.42.42/16")
        peer_mac = MacAddress("02:00:00:00:00:99")
        self._packet_handler.probe_result = False
        self._packet_handler.probe_peer_mac = peer_mac

        result = self._api.claim_with_acd(ip4_ifaddr=host)

        self.assertFalse(
            result.success,
            msg="Conflicting claim must return success=False.",
        )
        self.assertEqual(
            result.conflict_sender_mac,
            peer_mac,
            msg="Conflicting claim must surface the peer MAC.",
        )
        self.assertEqual(
            self._packet_handler.announce_calls,
            [],
            msg="Conflicting claim must NOT announce.",
        )
        self.assertNotIn(
            host,
            self._packet_handler._ip4_ifaddr,
            msg="Conflicting claim must NOT install the host.",
        )


class TestIp4AddressApiSendGratuitousArp(TestCase):
    """
    'Ip4AddressApi.send_gratuitous_arp' fires a single RFC 5227
    §2.4(b)-style defensive gratuitous ARP — the public-API
    form of the existing '_send_gratuitous_arp' helper.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the API's '<stack>' log line and stand up a fake
        packet handler the API delegates to.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._packet_handler = _FakePacketHandler()
        self._api = Ip4AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__send_gratuitous_arp_delegates(self) -> None:
        """
        Ensure 'send_gratuitous_arp' calls the underlying
        '_send_gratuitous_arp' helper with the supplied
        address.

        Reference: RFC 5227 §2.4(b) (single defensive gratuitous ARP).
        """

        target = Ip4Address("169.254.42.42")

        self._api.send_gratuitous_arp(address=target)

        self.assertEqual(
            self._packet_handler.gratuitous_arp_calls,
            [target],
            msg="send_gratuitous_arp must invoke _send_gratuitous_arp with the target.",
        )


class TestIp4AddressApiSubscribeConflicts(TestCase):
    """
    'Ip4AddressApi.subscribe_conflicts' registers a callback
    fired by the ARP RX path on post-claim conflicts; the
    matching '_fire_conflict_event' internal entry-point
    fans events out to registered subscribers.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the API's '<stack>' log line and stand up a fake
        packet handler the API delegates to.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._packet_handler = _FakePacketHandler()
        self._api = Ip4AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__subscribe_fires_callback_on_matching_address(self) -> None:
        """
        Ensure a subscription's callback fires when
        '_fire_conflict_event' is invoked for the subscribed
        address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        target = Ip4Address("169.254.42.42")
        events: list[ConflictEvent] = []

        self._api.subscribe_conflicts(
            address=target,
            on_conflict=events.append,
        )

        event = ConflictEvent(
            address=target,
            sender_mac=MacAddress("02:00:00:00:00:99"),
            timestamp=12.5,
        )
        self._api._fire_conflict_event(event=event)

        self.assertEqual(
            events,
            [event],
            msg="Subscriber's callback must fire on a matching conflict event.",
        )

    def test__ip4_address_api__subscribe_callback_skipped_on_non_matching(self) -> None:
        """
        Ensure a subscription's callback does NOT fire when
        '_fire_conflict_event' is invoked for a different
        address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        subscribed = Ip4Address("169.254.42.42")
        other = Ip4Address("169.254.99.99")
        events: list[ConflictEvent] = []

        self._api.subscribe_conflicts(
            address=subscribed,
            on_conflict=events.append,
        )

        event = ConflictEvent(
            address=other,
            sender_mac=MacAddress("02:00:00:00:00:99"),
            timestamp=12.5,
        )
        self._api._fire_conflict_event(event=event)

        self.assertEqual(
            events,
            [],
            msg="Non-matching conflict event must NOT fire the callback.",
        )

    def test__ip4_address_api__unsubscribe_stops_callback(self) -> None:
        """
        Ensure 'unsubscribe_conflicts' removes the callback so
        further events for the same address do not fire it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        target = Ip4Address("169.254.42.42")
        events: list[ConflictEvent] = []

        handle = self._api.subscribe_conflicts(
            address=target,
            on_conflict=events.append,
        )
        self._api.unsubscribe_conflicts(handle=handle)

        event = ConflictEvent(
            address=target,
            sender_mac=MacAddress("02:00:00:00:00:99"),
            timestamp=12.5,
        )
        self._api._fire_conflict_event(event=event)

        self.assertEqual(
            events,
            [],
            msg="After unsubscribe the callback must not fire.",
        )

    def test__ip4_address_api__multiple_subscribers_all_fire(self) -> None:
        """
        Ensure multiple subscriptions for the same address all
        receive the event when one is fired.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        target = Ip4Address("169.254.42.42")
        events_a: list[ConflictEvent] = []
        events_b: list[ConflictEvent] = []

        self._api.subscribe_conflicts(address=target, on_conflict=events_a.append)
        self._api.subscribe_conflicts(address=target, on_conflict=events_b.append)

        event = ConflictEvent(
            address=target,
            sender_mac=MacAddress("02:00:00:00:00:99"),
            timestamp=12.5,
        )
        self._api._fire_conflict_event(event=event)

        self.assertEqual(events_a, [event], msg="Subscriber A must receive the event.")
        self.assertEqual(events_b, [event], msg="Subscriber B must receive the event.")


class TestIp4AddressApiAbortBoundTcpSessionsPublic(TestCase):
    """
    'Ip4AddressApi.abort_bound_tcp_sessions' is the public-API
    wrapper around the existing private '_abort_bound_tcp_sessions'
    static method.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the API's '<stack>' log line and stand up a fake
        packet handler the API delegates to.
        """

        self.enterContext(patch("pytcp.stack.address.log"))
        self._packet_handler = _FakePacketHandler()
        self._api = Ip4AddressApi(packet_handler=cast("PacketHandlerL2", self._packet_handler))

    def test__ip4_address_api__abort_bound_tcp_sessions_public_delegates(self) -> None:
        """
        Ensure the public 'abort_bound_tcp_sessions' method
        delegates to the same logic the static helper exposes —
        the public form is for consumers that prefer the API
        surface over the static helper.

        Reference: RFC 5227 §2.4 (active reset of sessions on address abandon).
        """

        target = Ip4Address("169.254.42.42")

        # Patch the static helper to verify delegation.
        with patch.object(Ip4AddressApi, "_abort_bound_tcp_sessions") as helper:
            self._api.abort_bound_tcp_sessions(address=target)

        helper.assert_called_once_with(target)


class TestIp4AddressApiInterfaceSelector(TestCase):
    """
    The 'Ip4AddressApi.interface(ifindex)' device-selector tests.
    """

    def setUp(self) -> None:
        """
        Register two fake interfaces in a fresh 'stack.interfaces'
        table; bind the API singleton to interface 1.
        """

        self._iface_1 = _FakePacketHandler()
        self._iface_2 = _FakePacketHandler()
        table = InterfaceTable()
        table[1] = cast("PacketHandlerL2", self._iface_1)
        table[2] = cast("PacketHandlerL2", self._iface_2)
        self.enterContext(patch.object(stack, "interfaces", table))
        self._api = Ip4AddressApi(packet_handler=cast("PacketHandlerL2", self._iface_1))

    def test__address_api__interface__add_ifaddr_lands_on_named_interface(self) -> None:
        """
        Ensure 'interface(ifindex).add_ifaddr' installs the address on
        that interface's own '_ip4_ifaddr' list, leaving other
        interfaces' address lists untouched.

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        host = Ip4IfAddr("10.0.2.7/24")
        self._api.interface(2).add_ifaddr(ip4_ifaddr=host)

        self.assertEqual(
            self._iface_2._ip4_ifaddr,
            [host],
            msg="interface(2).add_ifaddr must install on interface 2's address list.",
        )
        self.assertEqual(
            self._iface_1._ip4_ifaddr,
            [],
            msg="interface 1's address list must be untouched.",
        )

    def test__address_api__interface__list_reads_named_interface(self) -> None:
        """
        Ensure 'interface(ifindex).list_ip4_ifaddrs' reads that
        interface's own address list.

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        host = Ip4IfAddr("10.0.2.7/24")
        self._iface_2._ip4_ifaddr = [host]

        self.assertEqual(
            self._api.interface(2).list_ip4_ifaddrs(),
            (host,),
            msg="interface(2).list_ip4_ifaddrs must read interface 2's address list.",
        )

    def test__address_api__interface__unknown_ifindex_raises(self) -> None:
        """
        Ensure 'interface(ifindex)' on an unregistered ifindex raises
        KeyError — the registry has no such device.

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        with self.assertRaises(KeyError):
            self._api.interface(99)


class TestIp4AddressApiUnboundTool(TestCase):
    """
    The 'Ip4AddressApi' unbound userspace-tool tests — an
    'Ip4AddressApi()' built with no handler is the device-independent
    tool ('ip addr'); bare reads / mutations resolve the sole registered
    interface (transitional crutch) and explicit '.interface(ifindex)'
    selection always works.
    """

    @override
    def setUp(self) -> None:
        """
        Silence the API's '<stack>' log line.
        """

        self.enterContext(patch("pytcp.stack.address.log"))

    def _install(self, count: int) -> list[_FakePacketHandler]:
        """
        Register 'count' fake interfaces in a fresh 'stack.interfaces'
        table and return them.
        """

        ifaces = [_FakePacketHandler() for _ in range(count)]
        table = InterfaceTable()
        for iface in ifaces:
            table.add(cast("PacketHandlerL2", iface))
        self.enterContext(patch.object(stack, "interfaces", table))
        return ifaces

    def test__address_api__unbound_tool__bare_read_resolves_sole_interface(self) -> None:
        """
        Ensure a bare read on the unbound tool resolves to the single
        registered interface when exactly one exists (the transitional
        N=1 crutch).

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        (iface,) = self._install(1)
        host = Ip4IfAddr("10.0.0.5/24")
        iface._ip4_ifaddr = [host]
        tool = Ip4AddressApi()

        self.assertEqual(
            tool.list_ip4_ifaddrs(),
            (host,),
            msg="The unbound tool must read the sole interface's address list.",
        )

    def test__address_api__unbound_tool__bare_mutation_resolves_sole_interface(self) -> None:
        """
        Ensure a bare mutation on the unbound tool lands on the single
        registered interface when exactly one exists.

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        (iface,) = self._install(1)
        host = Ip4IfAddr("10.0.0.5/24")
        tool = Ip4AddressApi()

        tool.add_ifaddr(ip4_ifaddr=host)

        self.assertEqual(
            iface._ip4_ifaddr,
            [host],
            msg="The unbound tool's add_ifaddr must land on the sole interface.",
        )

    def test__address_api__unbound_tool__bare_read_raises_when_no_interface(self) -> None:
        """
        Ensure a bare read on the unbound tool raises when no interface
        is registered — there is no device to report on.

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        self._install(0)
        tool = Ip4AddressApi()

        with self.assertRaises(RuntimeError):
            tool.list_ip4_ifaddrs()

    def test__address_api__unbound_tool__bare_read_raises_when_ambiguous(self) -> None:
        """
        Ensure a bare read on the unbound tool raises when more than one
        interface is registered — the caller must select a device via
        'interface(ifindex)'.

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        self._install(2)
        tool = Ip4AddressApi()

        with self.assertRaises(RuntimeError):
            tool.list_ip4_ifaddrs()

    def test__address_api__unbound_tool__interface_selector_works_when_ambiguous(self) -> None:
        """
        Ensure explicit 'interface(ifindex)' selection on the unbound
        tool reads the named device even when several interfaces are
        registered (where a bare read would be ambiguous).

        Reference: PyTCP test infrastructure (Phase-3 Address API surface).
        """

        ifaces = self._install(3)
        host = Ip4IfAddr("10.0.2.7/24")
        ifaces[1]._ip4_ifaddr = [host]
        tool = Ip4AddressApi()

        self.assertEqual(
            tool.interface(2).list_ip4_ifaddrs(),
            (host,),
            msg="interface(2) on the unbound tool must read interface 2's address list.",
        )
