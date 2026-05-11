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
This module contains the Phase-1 IPv4 address-control API
('Ip4AddressApi') — the kernel/userspace boundary surface that
the DHCPv4 client and (eventually) operator-config tools use to
add / remove / replace addresses on the stack. The Linux
equivalents are 'RTM_NEWADDR' / 'RTM_DELADDR' (rtnetlink) and
'net/ipv4/devinet.c'.

pytcp/lib/address_api.py

ver 3.0.4
"""

from typing import TYPE_CHECKING

from net_addr import Ip4Address, Ip4Host
from pytcp.lib.logger import log

if TYPE_CHECKING:
    from pytcp.stack.packet_handler import PacketHandlerL2, PacketHandlerL3


class Ip4AddressApi:
    """
    Phase-1 IPv4 address-control surface — mirrors Linux RTNETLINK
    'RTM_NEWADDR' / 'RTM_DELADDR' semantics.

    Phase-1 implementation: thin wrapper around
    'PacketHandler._ip4_host' mutations plus active TCP-session
    abort via 'SysCall.ABORT' (RFC 5227 §2.4-final SHOULD —
    deliberately stricter than Linux's "silent rot" behaviour).

    Consumer code — DHCPv4 client, future operator-config CLI,
    future DHCPv6 client — uses ONLY this surface. Never reaches
    into 'packet_handler._ip4_host' directly. This is the
    architectural seam the Phase-3 north-star turns into a real
    IPC channel; the wrapper internals swap from direct
    attribute mutation to RTNETLINK-equivalent message bus
    routing without any consumer change.
    """

    def __init__(
        self,
        *,
        packet_handler: "PacketHandlerL2 | PacketHandlerL3",
    ) -> None:
        """
        Bind the API to a packet handler instance. The packet
        handler owns the underlying '_ip4_host' list; the API is
        the only sanctioned consumer of mutations to that list.
        """

        self._packet_handler = packet_handler

    def add_host(self, *, ip4_host: Ip4Host) -> None:
        """
        Install 'ip4_host' on the stack's IPv4 address list —
        Linux 'RTM_NEWADDR' / 'ip addr add' equivalent.
        Idempotent against duplicate-address installs (the
        caller's responsibility; this method does not de-dup).
        """

        self._packet_handler._ip4_host.append(ip4_host)
        __debug__ and log("stack", f"<lg>Address API</>: added IPv4 host {ip4_host}")

    def remove_host(
        self,
        *,
        ip4_address: Ip4Address,
        abort_bound_sessions: bool = True,
    ) -> None:
        """
        Remove every 'Ip4Host' whose '.address' equals
        'ip4_address' from the stack's IPv4 address list —
        Linux 'RTM_DELADDR' / 'ip addr del' equivalent.

        'abort_bound_sessions=True' (the default) actively
        ABORTs every TCP session bound to the removed address
        per RFC 5227 §2.4-final SHOULD — a deliberate deviation
        from Linux's "silent rot" behaviour. Pass False for
        diagnostics or where the caller has its own
        teardown discipline.
        """

        if abort_bound_sessions:
            self._abort_bound_tcp_sessions(ip4_address)

        before = len(self._packet_handler._ip4_host)
        self._packet_handler._ip4_host = [
            host for host in self._packet_handler._ip4_host if host.address != ip4_address
        ]
        removed = before - len(self._packet_handler._ip4_host)
        __debug__ and log(
            "stack",
            f"<lg>Address API</>: removed IPv4 address {ip4_address} "
            f"({removed} host(s); abort_bound_sessions={abort_bound_sessions})",
        )

    def replace_host(
        self,
        *,
        old_address: Ip4Address,
        new_host: Ip4Host,
        abort_bound_sessions: bool = True,
    ) -> None:
        """
        Atomic-ish swap: install 'new_host' BEFORE removing the
        Ip4Host(es) keyed by 'old_address'. The transient overlap
        parallels Linux's 'RTM_NEWADDR' → 'RTM_DELADDR' ordering
        (RTNETLINK guarantees the kernel processes them in the
        order received; a brief window with both addresses present
        is normal).

        TCP sessions bound to 'old_address' are aborted per
        'abort_bound_sessions' once the new address is installed,
        matching the RFC 5227 §2.4-final SHOULD policy
        Ip4AddressApi.remove_host already applies.
        """

        self.add_host(ip4_host=new_host)
        self.remove_host(
            ip4_address=old_address,
            abort_bound_sessions=abort_bound_sessions,
        )

    def list_ip4_hosts(self) -> tuple[Ip4Host, ...]:
        """
        Return a read-only copy-by-value snapshot of the stack's
        IPv4 host list. Linux equivalent: reading
        '/proc/net/route' + 'ip addr show'. The returned tuple is
        immutable; the caller cannot mutate stack state through
        it (matches the Phase-3 north-star "introspection is
        read-only" constraint from CLAUDE.md).
        """

        return tuple(self._packet_handler._ip4_host)

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
        from pytcp.protocols.tcp.tcp__session import SysCall

        for socket_id in list(stack.sockets):
            if socket_id.local_address == ip4_address:
                sock = stack.sockets[socket_id]
                session = getattr(sock, "_tcp_session", None)
                if session is not None:
                    session.tcp_fsm(syscall=SysCall.ABORT)
