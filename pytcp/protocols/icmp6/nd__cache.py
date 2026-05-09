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
This module contains the IPv6 Neighbor Discovery cache — a
thin adapter on top of the generic 'NeighborCache[A]' NUD
state machine at 'pytcp/lib/neighbor.py'. Phase 3 of the NUD
migration plan ('docs/refactor/nud_state_machine.md') and the
mirror of the IPv4 ARP cache adapter shipped in Phase 2.

The adapter supplies the IPv6-specific solicit callback —
ICMPv6 Neighbor Solicitation — and inherits everything else
(state machine, timers, queued-packet semantics, PERMANENT
escape hatch, sysctl-driven knobs) from the parent class.

pytcp/protocols/icmp6/nd__cache.py

ver 3.0.4
"""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from pytcp import stack
from pytcp.lib.neighbor import NeighborCache

if TYPE_CHECKING:
    from net_addr import Ip6Address, MacAddress


class NdCache(NeighborCache["Ip6Address"]):
    """
    The IPv6 Neighbor Discovery cache. Inherits the full NUD
    state machine from 'NeighborCache[Ip6Address]' and supplies
    the wire-level solicit callback (ICMPv6 Neighbor Solicitation
    via 'PacketHandler.send_icmp6_neighbor_solicitation'). The
    public surface is overridden with kw-only wrappers
    ('ip6_address=', 'mac_address=') that match the established
    PyTCP convention.

    Queued-packet semantics ('flush_callback') are not wired —
    PyTCP's IPv6 TX path does not currently queue packets on
    cache miss. The base class accepts a None flush_callback
    and silently drops queued packets; if PyTCP grows IPv6
    packet-queueing later, this adapter supplies the
    flush_callback at that point.
    """

    @override
    def __init__(self) -> None:
        """
        Initialise the ND cache. The Subsystem name is "ICMPv6
        ND Cache" (legacy log channel "nd-c"); the parent class
        wires the FSM machinery + sysctl-driven timers.
        """

        super().__init__(
            name="ICMPv6 ND Cache",
            solicit_callback=self._solicit_ns,
            flush_callback=None,
        )

    # ------------------------------------------------------------
    # Public API — kw-only wrappers preserve the legacy ND
    # call-site convention while delegating to the generic
    # NeighborCache positional API.
    # ------------------------------------------------------------

    def find_entry(self, *, ip6_address: "Ip6Address") -> "MacAddress | None":  # type: ignore[override]
        """
        Look up the MAC for an IPv6 address; on miss, fire a
        multicast Neighbor Solicitation and return None.
        """

        return super().find_entry(ip6_address)

    def add_entry(  # type: ignore[override]
        self,
        *,
        ip6_address: "Ip6Address",
        mac_address: "MacAddress",
    ) -> None:
        """
        Install / refresh the IPv6-MAC mapping in response to
        an inbound Neighbor Advertisement. Transitions the
        entry to NUD_REACHABLE.
        """

        super().add_entry(ip6_address, mac_address)

    def add_permanent_entry(  # type: ignore[override]
        self,
        *,
        ip6_address: "Ip6Address",
        mac_address: "MacAddress",
    ) -> None:
        """
        Install a PERMANENT static-neighbour entry. Dynamic ND
        learning never overrides PERMANENT entries.
        """

        super().add_permanent_entry(ip6_address, mac_address)

    def confirm_reachability(self, *, ip6_address: "Ip6Address") -> None:  # type: ignore[override]
        """
        Upper-layer fastpath: promote a STALE / DELAY / PROBE
        entry directly to REACHABLE without firing a unicast
        NS probe. Called by the TCP layer on in-window ACK.
        """

        super().confirm_reachability(ip6_address)

    # ------------------------------------------------------------
    # Protocol-specific callback consumed by NeighborCache.
    # ------------------------------------------------------------

    def _solicit_ns(
        self,
        ip6_address: "Ip6Address",
        cached_mac: "MacAddress | None",  # noqa: ARG002
    ) -> None:
        """
        Fire an ICMPv6 Neighbor Solicitation. The existing
        'send_icmp6_neighbor_solicitation' helper handles both
        the multicast (INCOMPLETE) and unicast (PROBE) wire
        forms internally based on the destination address; the
        cached_mac argument is accepted for the callback
        contract but not currently used for wire-form
        differentiation. Future refinement: split into
        multicast / unicast call paths the way ArpCache does.

        Routes through the live PacketHandler instance on
        'pytcp.stack'.
        """

        assert isinstance(stack.packet_handler, (stack.PacketHandlerL2, stack.PacketHandlerL3))
        stack.packet_handler.send_icmp6_neighbor_solicitation(
            icmp6_ns_target_address=ip6_address,
        )
