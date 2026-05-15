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
This module contains unit tests for the 'PacketHandler' base classes.

pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__init.py

ver 3.0.4
"""

from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, Ip4Host, Ip6Address, Ip6Host, MacAddress
from pytcp import stack
from pytcp.lib.packet_stats import PacketStatsRx, PacketStatsTx
from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3

# Snapshot log channels so 'setUpModule' can silence output during this
# module's tests and 'tearDownModule' can restore the global state.
_ORIGINAL_LOG_CHANNEL: set[str] = stack.LOG__CHANNEL


def setUpModule() -> None:
    """
    Silence log output for the duration of this module's tests.
    """

    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the snapshot of log channels after this module's tests finish.
    """

    stack.LOG__CHANNEL = _ORIGINAL_LOG_CHANNEL


STACK__MAC_UNICAST = MacAddress("02:00:00:00:00:07")
STACK__IP4_HOST = Ip4Host("10.0.1.7/24")
STACK__IP6_HOST = Ip6Host("2001:db8:0:1::7/64")


def _build_l2_handler() -> PacketHandlerL2:
    """
    Build a 'PacketHandlerL2' with IPv4/IPv6 addressing disabled so
    the constructor does not spawn DHCP / ND discovery threads.
    """

    return PacketHandlerL2(
        mac_address=STACK__MAC_UNICAST,
        interface_mtu=1500,
        ip4_support=False,
        ip6_support=False,
    )


def _build_l3_handler() -> PacketHandlerL3:
    """
    Build a 'PacketHandlerL3' with IPv4/IPv6 addressing disabled.
    """

    return PacketHandlerL3(
        interface_mtu=1500,
        ip4_support=False,
        ip6_support=False,
    )


class TestPacketHandlerBaseConstruction(TestCase):
    """
    The 'PacketHandler' __init__ invariants tests.
    """

    def test__stack__packet_handler__init__empty_defaults(self) -> None:
        """
        Ensure the base constructor creates empty host / candidate /
        multicast lists and zeroed IP id counters.
        """

        h = _build_l2_handler()

        self.assertIsInstance(h._packet_stats_rx, PacketStatsRx)
        self.assertIsInstance(h._packet_stats_tx, PacketStatsTx)
        self.assertEqual(h._ip4_host, [])
        self.assertEqual(h._ip6_host, [])
        self.assertEqual(h._ip4_host_candidate, [])
        self.assertEqual(h._ip6_host_candidate, [])
        self.assertEqual(h._ip4_multicast, [])
        self.assertEqual(h._ip6_multicast, [])
        self.assertEqual(h._ip4_id, 0)
        self.assertEqual(h._ip6_id, 0)
        self.assertEqual(h._ip4_frag_table.flows, {})
        self.assertEqual(h._ip6_frag_table.flows, {})
        self.assertEqual(h._interface_mtu, 1500)

    def test__stack__packet_handler__init__ip4_host_seeds_candidate(self) -> None:
        """
        Ensure passing 'ip4_host=' seeds the candidate list (the
        address still has to pass DAD before moving to _ip4_host).
        """

        h = PacketHandlerL2(
            mac_address=STACK__MAC_UNICAST,
            interface_mtu=1500,
            ip4_support=False,
            ip6_support=False,
            ip4_host=STACK__IP4_HOST,
        )

        self.assertEqual(
            h._ip4_host_candidate,
            [STACK__IP4_HOST],
            msg="ip4_host constructor arg must seed the _ip4_host_candidate list.",
        )

    def test__stack__packet_handler__init__ip6_host_seeds_candidate(self) -> None:
        """
        Ensure passing 'ip6_host=' seeds the candidate list.
        """

        h = PacketHandlerL2(
            mac_address=STACK__MAC_UNICAST,
            interface_mtu=1500,
            ip4_support=False,
            ip6_support=False,
            ip6_host=STACK__IP6_HOST,
        )

        self.assertEqual(
            h._ip6_host_candidate,
            [STACK__IP6_HOST],
            msg="ip6_host constructor arg must seed the _ip6_host_candidate list.",
        )


class TestPacketHandlerAddressProperties(TestCase):
    """
    The address-list property accessor tests.
    """

    def test__stack__packet_handler__init__ip4_unicast_derived_from_hosts(self) -> None:
        """
        Ensure '_ip4_unicast' returns the addresses of the configured
        IPv4 hosts in order.
        """

        h = _build_l2_handler()
        h._ip4_host = [STACK__IP4_HOST]

        self.assertEqual(h._ip4_unicast, [STACK__IP4_HOST.address])
        self.assertEqual(h.ip4_unicast, [STACK__IP4_HOST.address])

    def test__stack__packet_handler__init__ip6_unicast_derived_from_hosts(self) -> None:
        """
        Ensure '_ip6_unicast' returns the addresses of the configured
        IPv6 hosts in order.
        """

        h = _build_l2_handler()
        h._ip6_host = [STACK__IP6_HOST]

        self.assertEqual(h._ip6_unicast, [STACK__IP6_HOST.address])
        self.assertEqual(h.ip6_unicast, [STACK__IP6_HOST.address])

    def test__stack__packet_handler__init__ip4_broadcast_includes_limited(self) -> None:
        """
        Ensure '_ip4_broadcast' returns per-host network broadcasts
        plus the all-ones limited broadcast.
        """

        h = _build_l2_handler()
        h._ip4_host = [STACK__IP4_HOST]

        self.assertIn(
            STACK__IP4_HOST.network.broadcast,
            h._ip4_broadcast,
            msg="Per-host network broadcast must appear in _ip4_broadcast.",
        )
        self.assertIn(
            Ip4Address(0xFFFFFFFF),
            h._ip4_broadcast,
            msg="255.255.255.255 (limited broadcast) must always appear in _ip4_broadcast.",
        )


class TestPacketHandlerAddressAssignment(TestCase):
    """
    The assign / remove host+multicast helper tests.
    """

    def test__stack__packet_handler__init__assign_remove_ip4_host(self) -> None:
        """
        Ensure '_assign_ip4_host' / '_remove_ip4_host' mutate the
        host list without affecting anything else.
        """

        h = _build_l2_handler()

        h._assign_ip4_host(STACK__IP4_HOST)
        self.assertEqual(h._ip4_host, [STACK__IP4_HOST])
        self.assertEqual(h._ip4_unicast, [STACK__IP4_HOST.address])

        h._remove_ip4_host(STACK__IP4_HOST)
        self.assertEqual(h._ip4_host, [])
        self.assertEqual(h._ip4_unicast, [])

    def test__stack__packet_handler__init__l2_ip6_assign_also_adds_mac_multicast(self) -> None:
        """
        Ensure PacketHandlerL2's '_assign_ip6_multicast' appends the
        matching multicast MAC to '_mac_multicast' (needed so the L2
        filter accepts frames for the joined group) and invokes the
        MLDv2 listener-report sender.
        """

        h = _build_l2_handler()
        h._send_icmp6_multicast_listener_report = MagicMock()  # type: ignore[method-assign]

        addr = Ip6Address("ff02::1:3")
        h._assign_ip6_multicast(addr)

        self.assertIn(addr, h._ip6_multicast)
        self.assertIn(addr.multicast_mac, h._mac_multicast)
        h._send_icmp6_multicast_listener_report.assert_called_once()

    def test__stack__packet_handler__init__l2_ip6_remove_also_removes_mac_multicast(self) -> None:
        """
        Ensure '_remove_ip6_multicast' removes both the IPv6 entry and
        the matching MAC multicast.
        """

        h = _build_l2_handler()
        h._send_icmp6_multicast_listener_report = MagicMock()  # type: ignore[method-assign]

        addr = Ip6Address("ff02::1:3")
        h._assign_ip6_multicast(addr)
        h._remove_ip6_multicast(addr)

        self.assertNotIn(addr, h._ip6_multicast)
        self.assertNotIn(addr.multicast_mac, h._mac_multicast)

    def test__stack__packet_handler__init__l3_ip6_assign_no_mac_side_effects(self) -> None:
        """
        Ensure PacketHandlerL3 '_assign_ip6_multicast' does NOT touch
        any MAC multicast list (L3 stack has no MAC filter).
        """

        h = _build_l3_handler()
        h._send_icmp6_multicast_listener_report = MagicMock()  # type: ignore[method-assign]

        addr = Ip6Address("ff02::1:3")
        h._assign_ip6_multicast(addr)

        self.assertIn(addr, h._ip6_multicast)
        self.assertFalse(
            hasattr(h, "_mac_multicast"),
            msg="PacketHandlerL3 must not carry a _mac_multicast attribute.",
        )


class TestPacketHandlerL3CreateStackAddressing(TestCase):
    """
    The L3-specific addressing-bootstrap tests.
    """

    def test__stack__packet_handler__init__l3_create_ip4_addressing_promotes_candidates(self) -> None:
        """
        Ensure PacketHandlerL3's '_create_stack_ip4_addressing' moves
        every candidate into '_ip4_host' (no DAD on L3).
        """

        h = _build_l3_handler()
        h._ip4_host_candidate = [STACK__IP4_HOST]

        h._create_stack_ip4_addressing()

        self.assertEqual(h._ip4_host, [STACK__IP4_HOST])
        self.assertEqual(h._ip4_host_candidate, [])

    def test__stack__packet_handler__init__l3_create_ip4_disables_ip4_when_empty(self) -> None:
        """
        Ensure '_create_stack_ip4_addressing' turns off '_ip4_support'
        when no candidates could be assigned.
        """

        h = _build_l3_handler()
        h._ip4_support = True
        h._ip4_host_candidate = []

        h._create_stack_ip4_addressing()

        self.assertFalse(h._ip4_support)

    def test__stack__packet_handler__init__l3_create_ip6_addressing_promotes_and_joins_all_nodes(self) -> None:
        """
        Ensure PacketHandlerL3's '_create_stack_ip6_addressing' joins
        ff02::1 (all-nodes) and promotes every candidate.
        """

        h = _build_l3_handler()
        h._send_icmp6_multicast_listener_report = MagicMock()  # type: ignore[method-assign]
        h._ip6_host_candidate = [STACK__IP6_HOST]

        h._create_stack_ip6_addressing()

        self.assertIn(Ip6Address("ff02::1"), h._ip6_multicast)
        self.assertIn(STACK__IP6_HOST, h._ip6_host)


class TestPacketHandlerL2SubsystemLoop(TestCase):
    """
    The L2 subsystem-loop dispatch tests.
    """

    def test__stack__packet_handler__init__l2_loop_dispatches_ethernet_2(self) -> None:
        """
        Ensure an Ethernet II frame (ethertype > 802.3 max) is routed
        to '_phrx_ethernet', and an 802.3 frame is routed to
        '_phrx_ethernet_802_3'.
        """

        h = _build_l2_handler()
        h._phrx_ethernet = MagicMock()  # type: ignore[method-assign]
        h._phrx_ethernet_802_3 = MagicMock()  # type: ignore[method-assign]

        eth2 = MagicMock()
        eth2.frame = b"\x00" * 12 + b"\x08\x00" + b"\x00" * 46
        eth_802_3 = MagicMock()
        eth_802_3.frame = b"\x00" * 12 + b"\x00\x46" + b"\x00" * 60

        with patch.object(stack, "rx_ring", MagicMock()) as mock_rx_ring:
            mock_rx_ring.dequeue.side_effect = [eth2, eth_802_3, None]
            h._subsystem_loop()
            h._subsystem_loop()
            h._subsystem_loop()

        h._phrx_ethernet.assert_called_once_with(eth2)
        h._phrx_ethernet_802_3.assert_called_once_with(eth_802_3)


class TestPacketHandlerL3SubsystemLoop(TestCase):
    """
    The L3 subsystem-loop dispatch tests.
    """

    def test__stack__packet_handler__init__l3_loop_routes_by_ethertype(self) -> None:
        """
        Ensure the L3 loop inspects bytes 2-3 of the TUN framing to
        decide IPv4 vs IPv6 dispatch, advances the frame pointer past
        the 4-byte TUN header, and honors the support flags.
        """

        h = _build_l3_handler()
        h._ip4_support = True
        h._ip6_support = True
        h._phrx_ip4 = MagicMock()  # type: ignore[method-assign]
        h._phrx_ip6 = MagicMock()  # type: ignore[method-assign]

        # TUN framing: 4-byte header; bytes[2:4] = EtherType.
        ip4_packet = MagicMock()
        ip4_packet.frame = b"\x00\x00\x08\x00" + b"IPV4_PAYLOAD"
        ip6_packet = MagicMock()
        ip6_packet.frame = b"\x00\x00\x86\xdd" + b"IPV6_PAYLOAD"
        unknown = MagicMock()
        unknown.frame = b"\x00\x00\xff\xff" + b"UNKNOWN_PAYLOAD"

        with patch.object(stack, "rx_ring", MagicMock()) as mock_rx_ring:
            mock_rx_ring.dequeue.side_effect = [ip4_packet, ip6_packet, unknown, None]
            h._subsystem_loop()
            h._subsystem_loop()
            h._subsystem_loop()

        h._phrx_ip4.assert_called_once_with(ip4_packet)
        h._phrx_ip6.assert_called_once_with(ip6_packet)
        # The unknown ethertype case logs a warning but doesn't dispatch.

    def test__stack__packet_handler__init__l3_loop_gates_on_support_flags(self) -> None:
        """
        Ensure the L3 loop drops IPv4 when '_ip4_support' is False and
        IPv6 when '_ip6_support' is False.
        """

        h = _build_l3_handler()
        h._ip4_support = False
        h._ip6_support = False
        h._phrx_ip4 = MagicMock()  # type: ignore[method-assign]
        h._phrx_ip6 = MagicMock()  # type: ignore[method-assign]

        ip4_packet = MagicMock()
        ip4_packet.frame = b"\x00\x00\x08\x00" + b"IPV4_PAYLOAD"
        ip6_packet = MagicMock()
        ip6_packet.frame = b"\x00\x00\x86\xdd" + b"IPV6_PAYLOAD"

        with patch.object(stack, "rx_ring", MagicMock()) as mock_rx_ring:
            mock_rx_ring.dequeue.side_effect = [ip4_packet, ip6_packet, None]
            h._subsystem_loop()
            h._subsystem_loop()

        h._phrx_ip4.assert_not_called()
        h._phrx_ip6.assert_not_called()
