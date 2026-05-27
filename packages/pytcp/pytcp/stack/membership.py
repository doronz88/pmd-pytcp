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

from enum import Enum
from typing import TYPE_CHECKING

from net_addr import Ip4Address
from pytcp.lib.logger import log
from pytcp.protocols.igmp import igmp__constants

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3

# The IPv4 all-systems group every host joins permanently and never
# leaves (RFC 1112 §4); the membership API refuses to drop it.
IP4__MULTICAST__ALL_SYSTEMS = Ip4Address("224.0.0.1")


class MembershipLimitError(ValueError):
    """
    Raised by 'MembershipApi.join' when joining a new group would exceed
    'igmp.max_memberships'. Subclasses 'ValueError' so existing
    'except ValueError' callers still catch it; the BSD socket facade
    catches this specific type to map it to 'ENOBUFS' (Linux
    'IP_ADD_MEMBERSHIP' over 'igmp_max_memberships'), distinct from the
    'EINVAL' it returns for other membership errors.
    """


class MembershipRefKind(Enum):
    """
    The kind of reference held on an IPv4 multicast group membership:
    an operator-API hold ('ip maddr'-style, set-once and idempotent) or
    a per-socket hold ('IP_ADD_MEMBERSHIP', reference-counted). The
    interface keeps a group joined while any reference of either kind
    remains.
    """

    OPERATOR = 1
    SOCKET = 2


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

    def join(self, *, group: Ip4Address, kind: MembershipRefKind = MembershipRefKind.OPERATOR) -> None:
        """
        Join the IPv4 multicast 'group' on the bound interface — Linux
        'IP_ADD_MEMBERSHIP' equivalent. Acquires a reference of 'kind'
        (operator hold by default; the BSD socket facade passes
        'MembershipRefKind.SOCKET'); the actual join + state-change
        Report fires only when the group crosses the not-joined→joined
        edge. The operator hold is idempotent. Raises 'ValueError' for a
        non-multicast address.
        """

        if not group.is_multicast:
            raise ValueError(f"The 'group' must be a multicast address. Got: {group!r}")

        handler = self._resolve_handler()

        # Linux 'net.ipv4.igmp_max_memberships' — cap the number of
        # joined groups. The cap applies only when this acquisition
        # would newly join the group; the implicit all-systems group
        # 224.0.0.1 does not count. Qualified module access so an
        # operator override of 'igmp.max_memberships' resolves on every
        # join.
        if not handler._mc_is_joined(group):
            joined = sum(1 for member in handler._ip4_multicast if member != IP4__MULTICAST__ALL_SYSTEMS)
            if joined >= igmp__constants.IGMP__MAX_MEMBERSHIPS:
                raise MembershipLimitError(
                    f"The multicast-membership limit ({igmp__constants.IGMP__MAX_MEMBERSHIPS}) is reached "
                    f"(sysctl 'igmp.max_memberships'); cannot join {group}."
                )

        handler._mc_ref_acquire(group, kind=kind)
        __debug__ and log("stack", f"<lg>Membership API</>: joined IPv4 group {group} ({kind.name})")

    def leave(self, *, group: Ip4Address, kind: MembershipRefKind = MembershipRefKind.OPERATOR) -> None:
        """
        Leave the IPv4 multicast 'group' on the bound interface — Linux
        'IP_DROP_MEMBERSHIP' equivalent. Releases the reference of 'kind'
        (operator hold by default); the actual leave + state-change Leave
        Report fires only when the last reference of any kind is dropped
        (the joined→not-joined edge). Idempotent. Refuses to drop the
        all-systems group 224.0.0.1, which a host belongs to permanently
        (RFC 1112 §4). Raises 'ValueError' for a non-multicast address.
        """

        if not group.is_multicast:
            raise ValueError(f"The 'group' must be a multicast address. Got: {group!r}")

        if group == IP4__MULTICAST__ALL_SYSTEMS:
            raise ValueError("The all-systems group 224.0.0.1 is joined permanently and cannot be left (RFC 1112 §4).")

        handler = self._resolve_handler()
        handler._mc_ref_release(group, kind=kind)
        __debug__ and log("stack", f"<lg>Membership API</>: left IPv4 group {group} ({kind.name})")

    def list_memberships(self) -> tuple[Ip4Address, ...]:
        """
        Return a read-only copy-by-value snapshot of the IPv4 multicast
        groups the bound interface listens on — Linux 'ip maddr show'
        equivalent. The returned tuple is immutable; the caller cannot
        mutate stack state through it.
        """

        handler = self._resolve_handler()

        return tuple(handler._ip4_multicast)
