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
This module contains the address-control API ('AddressApi') — the
kernel/userspace boundary surface that the DHCPv4 client, the RFC 3927
link-local client and (eventually) operator-config tools use to add /
remove / replace host addresses on the stack. The Linux equivalents are
'RTM_NEWADDR' / 'RTM_DELADDR' (rtnetlink) and 'ip addr'. The verbs are
family-agnostic by design; the IPv6 dispatch arm lands in step 2 of the
unification (docs/refactor/address_api_unification.md).

pytcp/stack/address.py

ver 3.0.6
"""

from typing import TYPE_CHECKING

from net_addr import Ip4Address, Ip4IfAddr
from pytcp.lib.logger import log

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3


class AddressApi:
    """
    The address-control surface — mirrors Linux RTNETLINK
    'RTM_NEWADDR' / 'RTM_DELADDR' / 'ip addr' semantics. The verbs
    ('add' / 'remove' / 'replace' / 'list_ifaddrs') are family-
    agnostic by design (Linux carries the family as a field, not a
    verb); the IPv6 dispatch arm lands in step 2 of the unification
    (docs/refactor/address_api_unification.md), so today the
    implementation handles IPv4 only.

    Implementation: thin wrapper around 'PacketHandler._ip4_ifaddr'
    mutations plus active TCP-session abort via 'SysCall.ABORT'
    (RFC 5227 §2.4-final SHOULD — deliberately stricter than
    Linux's "silent rot" behaviour).

    Consumer code — DHCPv4 client, RFC 3927 link-local client,
    future operator-config CLI — uses ONLY this surface. Never
    reaches into 'packet_handler._ip4_ifaddr' directly. This is the
    architectural seam the Phase-3 north-star turns into a real
    IPC channel; the wrapper internals swap from direct
    attribute mutation to RTNETLINK-equivalent message bus
    routing without any consumer change.
    """

    def __init__(
        self,
        *,
        packet_handler: "PacketHandlerL2 | PacketHandlerL3 | None" = None,
    ) -> None:
        """
        Construct the address-control API. With no 'packet_handler'
        this is the unbound, device-independent TOOL (the 'ip addr'
        equivalent) — operate on a specific interface via
        'interface(ifindex)'. With a 'packet_handler' (as returned by
        'interface(ifindex)') it is a VIEW bound to that one interface;
        its reads / mutations operate on that interface's '_ip4_ifaddr'
        list only.
        """

        self._packet_handler = packet_handler

    def _resolve_handler(self) -> "PacketHandlerL2 | PacketHandlerL3":
        """
        Return the interface this API operates on: the bound handler
        for an 'interface(ifindex)' view, or — for the unbound tool —
        the SOLE registered interface (transitional N=1 crutch). Raises
        'RuntimeError' when the unbound tool is used with zero or more
        than one interface registered, where the caller must select a
        device via 'interface(ifindex)'.

        Phase 6: the sole-interface fallback is the bridge while bare
        consumers migrate to 'interface(ifindex)'; it is removed once
        nothing reads the unbound tool without selecting a device.
        """

        if self._packet_handler is not None:
            return self._packet_handler

        from pytcp import stack

        interfaces = stack.interfaces.values()
        if len(interfaces) == 1:
            return interfaces[0]
        if not interfaces:
            raise RuntimeError(
                "No interface registered. Add one via 'stack.add_interface(...)' "
                "or select a device via 'stack.address.interface(ifindex)'."
            )
        raise RuntimeError(
            "Multiple interfaces registered; the bare address tool is ambiguous. "
            "Select a device via 'stack.address.interface(ifindex)'."
        )

    def interface(self, ifindex: int, /) -> "AddressApi":
        """
        Return an 'AddressApi' bound to the interface registered
        under 'ifindex' — the device selector, Linux 'ip addr … dev
        <ifX>' equivalent. Every read / mutation on the returned
        binding operates on that interface's address list. Raises
        'KeyError' when no interface is registered under 'ifindex'.
        """

        from pytcp import stack

        return AddressApi(packet_handler=stack.interfaces[ifindex])

    def add(self, *, ifaddr: Ip4IfAddr) -> None:
        """
        Install 'ifaddr' on the stack's address list — Linux
        'RTM_NEWADDR' / 'ip addr add' equivalent. Idempotent against
        duplicate-address installs (the caller's responsibility;
        this method does not de-dup).

        Step 1: IPv4 only. The 'Ip6IfAddr' dispatch arm (joining the
        solicited-node multicast group) lands in step 2.
        """

        handler = self._resolve_handler()
        # Atomic-rebind rather than in-place '.append': the TX worker
        # iterates '_ip4_ifaddr' during source-address selection on a
        # different thread, so control-plane mutation must swap a fresh
        # list reference (the reader sees the old or new list whole,
        # never a mid-append state). Mirrors 'remove' below.
        handler._ip4_ifaddr = [*handler._ip4_ifaddr, ifaddr]
        __debug__ and log("stack", f"<lg>Address API</>: added IPv4 host {ifaddr}")

    def remove(
        self,
        *,
        address: Ip4Address,
        abort_bound_sessions: bool = True,
    ) -> None:
        """
        Remove every host whose '.address' equals 'address' from the
        stack's address list — Linux 'RTM_DELADDR' / 'ip addr del'
        equivalent.

        'abort_bound_sessions=True' (the default) actively
        ABORTs every TCP session bound to the removed address
        per RFC 5227 §2.4-final SHOULD — a deliberate deviation
        from Linux's "silent rot" behaviour. Pass False for
        diagnostics or where the caller has its own
        teardown discipline.

        Step 1: IPv4 only. The 'Ip6Address' dispatch arm (leaving the
        solicited-node multicast group) lands in step 2.
        """

        if abort_bound_sessions:
            self._abort_bound_tcp_sessions(address)

        handler = self._resolve_handler()
        before = len(handler._ip4_ifaddr)
        handler._ip4_ifaddr = [host for host in handler._ip4_ifaddr if host.address != address]
        removed = before - len(handler._ip4_ifaddr)
        __debug__ and log(
            "stack",
            f"<lg>Address API</>: removed IPv4 address {address} "
            f"({removed} host(s); abort_bound_sessions={abort_bound_sessions})",
        )

    def replace(
        self,
        *,
        old_address: Ip4Address,
        new_ifaddr: Ip4IfAddr,
        abort_bound_sessions: bool = True,
    ) -> None:
        """
        Atomic-ish swap: install 'new_ifaddr' BEFORE removing the
        host(es) keyed by 'old_address'. The transient overlap
        parallels Linux's 'RTM_NEWADDR' → 'RTM_DELADDR' ordering
        (RTNETLINK guarantees the kernel processes them in the
        order received; a brief window with both addresses present
        is normal).

        TCP sessions bound to 'old_address' are aborted per
        'abort_bound_sessions' once the new address is installed,
        matching the RFC 5227 §2.4-final SHOULD policy 'remove'
        already applies.
        """

        self.add(ifaddr=new_ifaddr)
        self.remove(
            address=old_address,
            abort_bound_sessions=abort_bound_sessions,
        )

    def list_ifaddrs(self) -> tuple[Ip4IfAddr, ...]:
        """
        Return a read-only copy-by-value snapshot of the stack's
        host-address list. Linux equivalent: 'ip addr show'. The
        returned tuple is immutable; the caller cannot mutate stack
        state through it (matches the Phase-3 north-star
        "introspection is read-only" constraint from CLAUDE.md).

        Step 1: IPv4 only, no 'family' filter. The family-filterable
        IPv6-inclusive form ('family=' kwarg) lands in step 2.
        """

        return tuple(self._resolve_handler()._ip4_ifaddr)

    @staticmethod
    def _abort_bound_tcp_sessions(ip4_address: Ip4Address) -> None:
        """
        Issue 'SysCall.ABORT' to every TCP session whose local
        address equals 'ip4_address'. The ABORT syscall emits
        RST and tears the session down per RFC 9293 §3.10.7.4.

        The same primitive lives inline in
        'packet_handler__arp__rx._abandon_ipv4_address' for the
        RFC 5227 §2.4(b) conflict-driven path. Phase-3 cleanup
        may unify the two; for Phase 4 commit A the duplication
        is bounded (~6 lines) and the contexts log differently
        anyway.
        """

        from pytcp import stack
        from pytcp.protocols.tcp.tcp__enums import SysCall

        for socket_id in list(stack.sockets):
            if socket_id.local_address == ip4_address:
                sock = stack.sockets[socket_id]
                session = getattr(sock, "_tcp_session", None)
                if session is not None:
                    session.tcp_fsm(syscall=SysCall.ABORT)
