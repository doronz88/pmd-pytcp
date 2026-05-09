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
This module contains the IPv4 ARP cache — a thin adapter on
top of the generic 'NeighborCache[A]' NUD state machine at
'pytcp/lib/neighbor.py'. Phase 2 of the NUD migration plan
('docs/refactor/nud_state_machine.md').

The adapter supplies the IPv4-specific solicit and flush
callbacks: broadcast or unicast ARP Request for solicits
(driven by 'cached_mac is None / not None'), Ethernet TX
ring dispatch with destination-MAC rewrite for flushes.

pytcp/protocols/arp/arp__cache.py

ver 3.0.4
"""

from __future__ import annotations

from typing import TYPE_CHECKING, override

from pytcp import stack
from pytcp.lib.neighbor import NeighborCache

if TYPE_CHECKING:
    from net_addr import Ip4Address, MacAddress
    from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler


class ArpCache(NeighborCache["Ip4Address"]):
    """
    The IPv4 ARP cache. Inherits the full NUD state machine
    from 'NeighborCache[Ip4Address]' and supplies the wire-
    level callbacks ('_solicit_arp', '_flush_packet'). The
    public surface ('find_entry', 'add_entry',
    'enqueue_pending', 'add_permanent_entry',
    'confirm_reachability') is overridden with kw-only
    wrappers that match the established PyTCP convention
    ('ip4_address=', 'mac_address=', 'ethernet_packet_tx=').
    """

    @override
    def __init__(self) -> None:
        """
        Initialise the ARP cache. The Subsystem name is "ARP
        Cache" (legacy log channel "arp-c"); the parent class
        wires the FSM machinery + sysctl-driven timers.
        """

        super().__init__(
            name="ARP Cache",
            solicit_callback=self._solicit_arp,
            flush_callback=self._flush_packet,
        )

    # ------------------------------------------------------------
    # Public API — kw-only wrappers preserve the legacy ARP
    # call-site convention while delegating to the generic
    # NeighborCache positional API.
    # ------------------------------------------------------------

    def find_entry(self, *, ip4_address: "Ip4Address") -> "MacAddress | None":  # type: ignore[override]
        """
        Look up the MAC for an IPv4 address; on miss, fire a
        broadcast ARP Request and return None. See
        'NeighborCache.find_entry' for full FSM semantics.
        """

        return super().find_entry(ip4_address)

    def add_entry(  # type: ignore[override]
        self,
        *,
        ip4_address: "Ip4Address",
        mac_address: "MacAddress",
    ) -> None:
        """
        Install / refresh the IPv4-MAC mapping in response to
        an inbound ARP Reply. Transitions the entry to
        NUD_REACHABLE; flushes any queued packet.
        """

        super().add_entry(ip4_address, mac_address)

    def add_permanent_entry(  # type: ignore[override]
        self,
        *,
        ip4_address: "Ip4Address",
        mac_address: "MacAddress",
    ) -> None:
        """
        Install a PERMANENT static-neighbour entry. Dynamic
        ARP learning never overrides PERMANENT entries.
        """

        super().add_permanent_entry(ip4_address, mac_address)

    def confirm_reachability(self, *, ip4_address: "Ip4Address") -> None:  # type: ignore[override]
        """
        Upper-layer fastpath: promote a STALE / DELAY / PROBE
        entry directly to REACHABLE without firing a unicast
        ARP probe. Called by the TCP layer on in-window ACK.
        """

        super().confirm_reachability(ip4_address)

    def enqueue_pending(  # type: ignore[override]
        self,
        *,
        ip4_address: "Ip4Address",
        ethernet_packet_tx: "EthernetAssembler",
    ) -> None:
        """
        Save the most recently dropped outbound Ethernet
        packet for an unresolved IPv4 address so the FSM can
        deliver it post-resolution (RFC 1122 §2.3.2.2).
        """

        super().enqueue_pending(ip4_address, ethernet_packet_tx)

    # ------------------------------------------------------------
    # Protocol-specific callbacks consumed by NeighborCache.
    # ------------------------------------------------------------

    def _solicit_arp(
        self,
        ip4_address: "Ip4Address",
        cached_mac: "MacAddress | None",
    ) -> None:
        """
        Fire an ARP Request — broadcast for INCOMPLETE state
        (cached_mac is None), unicast to the cached MAC for
        PROBE state (RFC 1122 §2.3.2.1 IMPL (2)). Routes
        through the live PacketHandlerL2 instance on
        'pytcp.stack'.
        """

        # Late-resolved import keeps this module decoupled
        # from the packet handler at module load time —
        # 'pytcp.stack.packet_handler' is only assigned by
        # 'stack.init()'.
        assert isinstance(stack.packet_handler, stack.PacketHandlerL2)
        if cached_mac is None:
            stack.packet_handler.send_arp_request(arp__tpa=ip4_address)
        else:
            stack.packet_handler.send_arp_unicast_request(
                arp__tpa=ip4_address,
                ethernet__dst=cached_mac,
            )

    def _flush_packet(self, packet: object, mac_address: "MacAddress") -> None:
        """
        Dispatch a queued Ethernet packet through the TX ring
        with the destination MAC rewritten to the resolved
        value. The 'object' parameter type comes from the
        generic 'NeighborCache' surface; the actual type at
        runtime is always 'EthernetAssembler' for ARP.
        """

        from net_proto.protocols.ethernet.ethernet__assembler import (
            EthernetAssembler,
        )

        assert isinstance(
            packet, EthernetAssembler
        ), f"ArpCache._flush_packet got non-Ethernet payload: {type(packet)!r}"
        packet.dst = mac_address
        stack.tx_ring.enqueue(packet)
