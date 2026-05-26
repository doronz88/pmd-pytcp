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
This module contains the multicast-membership-control API
('MembershipApi') — the kernel/userspace boundary surface for joining
and leaving IPv4 multicast groups on an interface. The Linux
equivalents are the 'IP_ADD_MEMBERSHIP' / 'IP_DROP_MEMBERSHIP' socket
options (which dispatch here) and 'ip maddr'. The IGMP host state
machine (signalling membership to routers) layers on top of the group
state this API maintains.

pytcp/stack/membership.py

ver 3.0.6
"""

from typing import TYPE_CHECKING

from net_addr import Ip4Address
from pytcp.lib.logger import log

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3

# The IPv4 all-systems group every host joins permanently and never
# leaves (RFC 1112 §4); the membership API refuses to drop it.
IP4__MULTICAST__ALL_SYSTEMS = Ip4Address("224.0.0.1")


class MembershipApi:
    """
    The multicast-membership-control surface — joins / leaves IPv4
    multicast groups on an interface and exposes the current group
    set. Mirrors the Linux 'IP_ADD_MEMBERSHIP' / 'IP_DROP_MEMBERSHIP'
    socket options and 'ip maddr'.

    Consumer code — the BSD socket facade's membership options, the
    example apps, future operator-config tools — uses ONLY this
    surface. It never reaches into 'packet_handler._ip4_multicast'
    directly; that is the Phase-3 architectural seam.

    Membership is presence-based per interface (a group is joined or
    not). Per-socket join refcounting — so a group survives until the
    last socket leaves — is a deferred enhancement; today the first
    'leave' drops the group.
    """

    def __init__(
        self,
        *,
        packet_handler: "PacketHandlerL2 | PacketHandlerL3 | None" = None,
    ) -> None:
        """
        Construct the membership-control API. With no 'packet_handler'
        this is the unbound, device-independent TOOL — operate on a
        specific interface via 'interface(ifindex)'. With a
        'packet_handler' (as returned by 'interface(ifindex)') it is a
        VIEW bound to that one interface.
        """

        self._packet_handler = packet_handler

    def _resolve_handler(self) -> "PacketHandlerL2 | PacketHandlerL3":
        """
        Return the interface this API operates on — the handler bound by
        'interface(ifindex)'. The unbound tool has no default device;
        every operation MUST select one first, mirroring Linux requiring
        an explicit interface. Raises 'RuntimeError' on the unbound tool.
        """

        if self._packet_handler is not None:
            return self._packet_handler

        raise RuntimeError(
            "The bare membership tool has no default device; select one via " "'stack.membership.interface(ifindex)'."
        )

    def interface(self, ifindex: int, /) -> "MembershipApi":
        """
        Return a 'MembershipApi' bound to the interface registered under
        'ifindex' — the device selector. Raises 'KeyError' when no
        interface is registered under 'ifindex'.
        """

        from pytcp import stack

        return MembershipApi(packet_handler=stack.interfaces[ifindex])

    def join(self, *, group: Ip4Address) -> None:
        """
        Join the IPv4 multicast 'group' on the bound interface — Linux
        'IP_ADD_MEMBERSHIP' equivalent. Idempotent: re-joining a group
        the interface already listens on is a no-op. Raises 'ValueError'
        for a non-multicast address.
        """

        if not group.is_multicast:
            raise ValueError(f"The 'group' must be a multicast address. Got: {group!r}")

        handler = self._resolve_handler()
        if group in handler._ip4_multicast:
            return

        handler._assign_ip4_multicast(group)
        __debug__ and log("stack", f"<lg>Membership API</>: joined IPv4 group {group}")

    def leave(self, *, group: Ip4Address) -> None:
        """
        Leave the IPv4 multicast 'group' on the bound interface — Linux
        'IP_DROP_MEMBERSHIP' equivalent. Idempotent: leaving a group the
        interface is not in is a no-op. Refuses to drop the all-systems
        group 224.0.0.1, which a host belongs to permanently (RFC 1112
        §4). Raises 'ValueError' for a non-multicast address.
        """

        if not group.is_multicast:
            raise ValueError(f"The 'group' must be a multicast address. Got: {group!r}")

        if group == IP4__MULTICAST__ALL_SYSTEMS:
            raise ValueError("The all-systems group 224.0.0.1 is joined permanently and cannot be left (RFC 1112 §4).")

        handler = self._resolve_handler()
        if group not in handler._ip4_multicast:
            return

        handler._remove_ip4_multicast(group)
        __debug__ and log("stack", f"<lg>Membership API</>: left IPv4 group {group}")

    def list_memberships(self) -> tuple[Ip4Address, ...]:
        """
        Return a read-only copy-by-value snapshot of the IPv4 multicast
        groups the bound interface listens on — Linux 'ip maddr show'
        equivalent. The returned tuple is immutable; the caller cannot
        mutate stack state through it.
        """

        handler = self._resolve_handler()

        return tuple(handler._ip4_multicast)
