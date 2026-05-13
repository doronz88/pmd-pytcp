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
This module contains the Phase-1 link-control API ('LinkApi')
— the kernel/userspace boundary surface that consumer code
(the DHCPv4 client, the RFC 3927 link-local autoconfig client,
future operator-config tools) uses to read link-level state
(MAC, MTU, interface layer) without reaching into
'PacketHandler' internals. The Linux equivalents are
'ip link show' / RTNETLINK 'RTM_GETLINK' / 'RTM_NEWLINK'.

Phase 0 ships only the read-only minimum surface — MAC, MTU,
interface layer. Subsequent phases add interface name
(Phase 1), running state + flags (Phase 2), stats
introspection (Phase 3), and mutation via 'set_mtu' /
'set_mac_address' (Phase 4). See
'docs/refactor/link_api.md' for the full plan.

pytcp/lib/link_api.py

ver 3.0.4
"""

from typing import TYPE_CHECKING

from net_addr import MacAddress
from pytcp.lib.interface_layer import InterfaceLayer

if TYPE_CHECKING:
    from pytcp.stack.packet_handler import PacketHandlerL2, PacketHandlerL3


class LinkApi:
    """
    Phase-1 link-control surface — mirrors Linux 'ip link
    show' / RTNETLINK 'RTM_GETLINK' semantics for the
    read-only subset.

    Phase-1 implementation: thin properties over
    'PacketHandler._mac_unicast' / '_interface_mtu' /
    '_interface_layer'. Consumer code — DHCPv4 client,
    RFC 3927 link-local autoconfig client, future
    operator-config CLI — uses ONLY this surface to read
    link-level facts. Never reaches into 'packet_handler.*'
    directly. This is the architectural seam the Phase-3
    north-star turns into a real IPC channel; the wrapper
    internals swap from direct attribute reads to
    RTNETLINK-equivalent message routing without any
    consumer change.

    Phase 0 covers MAC + MTU + interface layer. Phases 1-4
    add interface name, running state, flags, stats, and
    mutation. See 'docs/refactor/link_api.md' for the full
    roadmap.
    """

    def __init__(
        self,
        *,
        packet_handler: "PacketHandlerL2 | PacketHandlerL3",
    ) -> None:
        """
        Bind the API to a packet handler instance. The packet
        handler owns the underlying link-level state; the API
        is the only sanctioned consumer of reads against that
        state.
        """

        self._packet_handler = packet_handler

    @property
    def mac_address(self) -> MacAddress | None:
        """
        Return the interface's unicast MAC address — Linux
        'ip link show eth0 | grep link/ether' equivalent.

        Returns None on L3 (TUN) interfaces, which have no
        Ethernet layer and therefore no MAC. The packet
        handler stores '_mac_unicast' only on the L2
        subclass; the 'getattr' fallback handles the L3
        case without an isinstance check.
        """

        return getattr(self._packet_handler, "_mac_unicast", None)

    @property
    def mtu(self) -> int:
        """
        Return the interface MTU in bytes — Linux
        'ip link show eth0 | grep mtu' equivalent.
        """

        return self._packet_handler._interface_mtu

    @property
    def name(self) -> str | None:
        """
        Return the interface name plumbed through by
        'stack.init()' (e.g. 'tap7', 'tun7') — Linux
        'ip link show' first-column equivalent.

        Returns None when the packet handler was
        constructed without an interface name — e.g. a
        unit-test fixture or 'mock__init' that skipped
        the name plumbing.
        """

        return self._packet_handler._interface_name

    @property
    def interface_layer(self) -> InterfaceLayer:
        """
        Return the interface layer (L2 = TAP, L3 = TUN) —
        Linux 'ip link show eth0 | grep link/' equivalent.
        """

        return self._packet_handler._interface_layer
