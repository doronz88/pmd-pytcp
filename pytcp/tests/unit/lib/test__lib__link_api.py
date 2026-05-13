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
This module contains tests for the Phase-1 link-control API
('LinkApi') in 'pytcp/lib/link_api.py'. Phase 0 covers the
read-only minimum surface — 'mac_address', 'mtu', and
'interface_layer' — that closes the
'packet_handler._mac_unicast' reach-through used by the
DHCPv4 and RFC 3927 link-local construction call sites.

pytcp/tests/unit/lib/test__lib__link_api.py

ver 3.0.4
"""

from typing import TYPE_CHECKING, cast
from unittest import TestCase

from net_addr import MacAddress
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.link_api import LinkApi

if TYPE_CHECKING:
    from pytcp.stack.packet_handler import PacketHandlerL2, PacketHandlerL3


class _FakePacketHandlerL2:
    """
    Minimal L2 packet-handler stand-in for 'LinkApi' tests —
    exposes only the attributes 'LinkApi' reads
    ('_mac_unicast', '_interface_mtu', '_interface_layer').
    Using a hand-rolled class avoids the autospec ceremony
    for the production PacketHandlerL2 class (which carries
    ~50 attributes irrelevant to the API surface under
    test).
    """

    _interface_layer: InterfaceLayer = InterfaceLayer.L2

    def __init__(
        self,
        *,
        mac_unicast: MacAddress,
        interface_mtu: int,
    ) -> None:
        self._mac_unicast = mac_unicast
        self._interface_mtu = interface_mtu


class _FakePacketHandlerL3:
    """
    Minimal L3 packet-handler stand-in for 'LinkApi' tests.
    Has '_interface_mtu' and '_interface_layer' but
    deliberately NO '_mac_unicast' attribute — L3 (TUN) has
    no Ethernet layer and therefore no MAC.
    """

    _interface_layer: InterfaceLayer = InterfaceLayer.L3

    def __init__(self, *, interface_mtu: int) -> None:
        self._interface_mtu = interface_mtu


class TestLinkApiMacAddress(TestCase):
    """
    'LinkApi.mac_address' returns the bound packet handler's
    MAC on L2, and None on L3 (where there is no MAC).
    """

    def test__link_api__mac_address__l2_returns_packet_handler_mac(self) -> None:
        """
        Ensure 'mac_address' returns the unicast MAC of the
        bound L2 packet handler.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.mac_address,
            MacAddress("02:00:00:00:00:07"),
            msg="LinkApi.mac_address must reflect the bound L2 handler's _mac_unicast.",
        )

    def test__link_api__mac_address__l3_returns_none(self) -> None:
        """
        Ensure 'mac_address' returns None when bound to an L3
        packet handler — L3 (TUN) has no Ethernet layer and
        therefore no MAC to report.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL3(interface_mtu=1500)
        api = LinkApi(packet_handler=cast("PacketHandlerL3", handler))

        self.assertIsNone(
            api.mac_address,
            msg="LinkApi.mac_address must be None on L3 (no Ethernet, no MAC).",
        )


class TestLinkApiMtu(TestCase):
    """
    'LinkApi.mtu' returns the bound packet handler's
    interface MTU as an integer.
    """

    def test__link_api__mtu__l2_returns_packet_handler_mtu(self) -> None:
        """
        Ensure 'mtu' returns the bound L2 packet handler's
        '_interface_mtu' as a plain int.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.mtu,
            1500,
            msg="LinkApi.mtu must reflect the bound handler's _interface_mtu.",
        )

    def test__link_api__mtu__non_default_value(self) -> None:
        """
        Ensure 'mtu' returns whatever non-default value the
        bound packet handler advertises — the API must not
        cache or alias the value at construction time.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=9000,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertEqual(
            api.mtu,
            9000,
            msg="LinkApi.mtu must read the live handler attribute, not a cached value.",
        )

    def test__link_api__mtu__l3_returns_packet_handler_mtu(self) -> None:
        """
        Ensure 'mtu' returns the bound L3 packet handler's
        '_interface_mtu' even when no MAC is set.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL3(interface_mtu=1500)
        api = LinkApi(packet_handler=cast("PacketHandlerL3", handler))

        self.assertEqual(
            api.mtu,
            1500,
            msg="LinkApi.mtu must work on L3 handlers (no MAC) as well.",
        )


class TestLinkApiInterfaceLayer(TestCase):
    """
    'LinkApi.interface_layer' reports the bound packet
    handler's layer (L2 or L3) via the canonical
    'InterfaceLayer' enum.
    """

    def test__link_api__interface_layer__l2(self) -> None:
        """
        Ensure 'interface_layer' returns 'InterfaceLayer.L2'
        when bound to an L2 (TAP) packet handler.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL2(
            mac_unicast=MacAddress("02:00:00:00:00:07"),
            interface_mtu=1500,
        )
        api = LinkApi(packet_handler=cast("PacketHandlerL2", handler))

        self.assertIs(
            api.interface_layer,
            InterfaceLayer.L2,
            msg="LinkApi.interface_layer must report L2 for TAP handlers.",
        )

    def test__link_api__interface_layer__l3(self) -> None:
        """
        Ensure 'interface_layer' returns 'InterfaceLayer.L3'
        when bound to an L3 (TUN) packet handler.

        Reference: PyTCP test infrastructure (Phase-3 Link API surface).
        """

        handler = _FakePacketHandlerL3(interface_mtu=1500)
        api = LinkApi(packet_handler=cast("PacketHandlerL3", handler))

        self.assertIs(
            api.interface_layer,
            InterfaceLayer.L3,
            msg="LinkApi.interface_layer must report L3 for TUN handlers.",
        )
