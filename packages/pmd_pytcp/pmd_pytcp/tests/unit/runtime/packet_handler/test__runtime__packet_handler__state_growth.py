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
This module contains the packet-handler state-growth tests: the
per-address / per-router bookkeeping dicts must shrink when their
subjects go away. On the "runs for days" profile, RFC 8981
temp-address rotation mints a fresh address per preferred-lifetime
per prefix and an on-link attacker can spoof RAs from arbitrary
link-local sources, so any table without a removal path grows
monotonically.

pmd_pytcp/tests/unit/runtime/packet_handler/test__runtime__packet_handler__state_growth.py

ver 3.0.7
"""

from __future__ import annotations

from unittest import TestCase
from unittest.mock import patch

from pmd_net_addr import Ip6Address, Ip6IfAddr, MacAddress
from pmd_pytcp.protocols.icmp6.nd.nd__router_state import Icmp6DefaultRouter
from pmd_pytcp.runtime.packet_handler import Icmp6DadState, PacketHandlerL2

STACK__MAC = MacAddress("02:00:00:00:00:07")


def _build_l2_handler() -> PacketHandlerL2:
    """
    Build a 'PacketHandlerL2' with IPv4/IPv6 autoconfiguration off.
    """

    return PacketHandlerL2(
        mac_address=STACK__MAC,
        interface_mtu=1500,
        ip4_support=False,
        ip6_support=False,
    )


class TestPacketHandlerStateGrowth(TestCase):
    """
    The packet-handler state-growth tests.
    """

    def setUp(self) -> None:
        """
        Silence the packet-handler log lines for the test duration.
        """

        self.enterContext(patch("pmd_pytcp.runtime.packet_handler.log"))

    def test__remove_ip6_host__drops_the_dad_state_entry(self) -> None:
        """
        Ensure removing an IPv6 host address also drops its DAD
        registry entry: entries were added on every claim but
        removed only on DAD CONFLICT, so each rotated-out RFC 8981
        temp address left a stale VALID entry forever — monotonic
        growth on exactly the runs-for-days profile the sweeps
        exist for.

        Reference: RFC 4862 §5.4 (DAD state is per-address; the address is gone).
        """

        handler = _build_l2_handler()
        ip6_host = Ip6IfAddr("2001:db8::7/64")
        # Seed the address, its multicast joins, and the DAD state
        # directly ('_assign_ip6_host' emits MLD through the
        # not-initialized global timer in this bare-handler fixture).
        snm = ip6_host.address.solicited_node_multicast
        handler._ip6_ifaddr = [*handler._ip6_ifaddr, ip6_host]
        handler._ip6_multicast = [*handler._ip6_multicast, snm]
        handler._mac_multicast = [*handler._mac_multicast, snm.multicast_mac]
        handler._icmp6_dad__states = {
            **handler._icmp6_dad__states,
            ip6_host.address: Icmp6DadState.VALID,
        }

        handler._remove_ip6_host(ip6_host=ip6_host)

        self.assertNotIn(
            ip6_host.address,
            handler._icmp6_dad__states,
            msg="Removing an address must drop its DAD registry entry.",
        )

    def test__default_router_list__expired_entries_are_purged_on_access(self) -> None:
        """
        Ensure the default-router accessor removes expired entries
        from the underlying list instead of only filtering the
        returned view: one stale entry per distinct RA source
        address otherwise persists forever, and an on-link
        attacker spoofing many link-local sources grows the list
        without bound.

        Reference: RFC 4861 §6.3.5 (timed-out default routers are removed from the list).
        """

        handler = _build_l2_handler()
        handler._icmp6_default_routers = [
            Icmp6DefaultRouter(address=Ip6Address(f"fe80::{i:x}"), lifetime=1, expires_at=0.0)
            for i in range(1, 6)
        ]

        active = handler.get_icmp6_default_routers()

        self.assertEqual(active, [], msg="Expired routers must not be returned.")
        self.assertEqual(
            handler._icmp6_default_routers,
            [],
            msg="Expired routers must be purged from the underlying list, not just filtered.",
        )
