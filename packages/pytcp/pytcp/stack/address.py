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

pytcp/stack/address.py

ver 3.0.6
"""

import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

from net_addr import Ip4Address, Ip4IfAddr, MacAddress
from pytcp.lib.logger import log

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3


@dataclass(frozen=True, kw_only=True, slots=True)
class ConflictEvent:
    """
    Post-claim ARP-conflict event for an installed address.
    Fired by the ARP RX path's RFC 5227 §2.4 conflict detector
    and dispatched to every subscriber registered via
    'Ip4AddressApi.subscribe_conflicts' for the matching
    address.
    """

    address: Ip4Address
    sender_mac: MacAddress
    timestamp: float


@dataclass(frozen=True, kw_only=True, slots=True)
class SubscriptionHandle:
    """
    Opaque handle returned by 'subscribe_conflicts'; pass to
    'unsubscribe_conflicts' to remove the callback.
    """

    address: Ip4Address
    callback_id: int


_OnConflict = Callable[[ConflictEvent], None]


@dataclass(slots=True)
class _Subscriptions:
    """Per-address callback registry. Internal to Ip4AddressApi."""

    by_address: dict[Ip4Address, dict[int, _OnConflict]] = field(default_factory=dict)
    next_id: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


class Ip4AddressApi:
    """
    Phase-1 IPv4 address-control surface — mirrors Linux RTNETLINK
    'RTM_NEWADDR' / 'RTM_DELADDR' semantics.

    Phase-1 implementation: thin wrapper around
    'PacketHandler._ip4_ifaddr' mutations plus active TCP-session
    abort via 'SysCall.ABORT' (RFC 5227 §2.4-final SHOULD —
    deliberately stricter than Linux's "silent rot" behaviour).

    Consumer code — DHCPv4 client, future operator-config CLI,
    future DHCPv6 client — uses ONLY this surface. Never reaches
    into 'packet_handler._ip4_ifaddr' directly. This is the
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

        The conflict-subscription registry lives on the API instance so
        per-address callback fan-out is local to this binding.
        """

        self._packet_handler = packet_handler
        self._subscriptions = _Subscriptions()

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

    def interface(self, ifindex: int, /) -> "Ip4AddressApi":
        """
        Return an 'Ip4AddressApi' bound to the interface registered
        under 'ifindex' — the device selector, Linux 'ip addr … dev
        <ifX>' equivalent. Every read / mutation on the returned
        binding operates on that interface's address list. Raises
        'KeyError' when no interface is registered under 'ifindex'.

        The returned binding has its OWN conflict-subscription registry
        (subscriptions live on the API instance, per '__init__'), so a
        consumer that subscribes via 'interface(ifindex)' must hold the
        returned binding to later unsubscribe through it. Per-interface
        conflict-event fan-out is not yet wired from the RX ARP path;
        when it lands, subscription ownership moves to a per-ifindex
        registry so events route to the right interface's subscribers.
        """

        from pytcp import stack

        return Ip4AddressApi(packet_handler=stack.interfaces[ifindex])

    def add_ifaddr(self, *, ip4_ifaddr: Ip4IfAddr) -> None:
        """
        Install 'ip4_ifaddr' on the stack's IPv4 address list —
        Linux 'RTM_NEWADDR' / 'ip addr add' equivalent.
        Idempotent against duplicate-address installs (the
        caller's responsibility; this method does not de-dup).
        """

        handler = self._resolve_handler()
        # Atomic-rebind rather than in-place '.append': the TX worker
        # iterates '_ip4_ifaddr' during source-address selection on a
        # different thread, so control-plane mutation must swap a fresh
        # list reference (the reader sees the old or new list whole,
        # never a mid-append state). Mirrors 'remove_ifaddr' below.
        handler._ip4_ifaddr = [*handler._ip4_ifaddr, ip4_ifaddr]
        __debug__ and log("stack", f"<lg>Address API</>: added IPv4 host {ip4_ifaddr}")

    def remove_ifaddr(
        self,
        *,
        ip4_address: Ip4Address,
        abort_bound_sessions: bool = True,
    ) -> None:
        """
        Remove every 'Ip4IfAddr' whose '.address' equals
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

        handler = self._resolve_handler()
        before = len(handler._ip4_ifaddr)
        handler._ip4_ifaddr = [host for host in handler._ip4_ifaddr if host.address != ip4_address]
        removed = before - len(handler._ip4_ifaddr)
        __debug__ and log(
            "stack",
            f"<lg>Address API</>: removed IPv4 address {ip4_address} "
            f"({removed} host(s); abort_bound_sessions={abort_bound_sessions})",
        )

    def replace_ifaddr(
        self,
        *,
        old_address: Ip4Address,
        new_ifaddr: Ip4IfAddr,
        abort_bound_sessions: bool = True,
    ) -> None:
        """
        Atomic-ish swap: install 'new_ifaddr' BEFORE removing the
        Ip4IfAddr(es) keyed by 'old_address'. The transient overlap
        parallels Linux's 'RTM_NEWADDR' → 'RTM_DELADDR' ordering
        (RTNETLINK guarantees the kernel processes them in the
        order received; a brief window with both addresses present
        is normal).

        TCP sessions bound to 'old_address' are aborted per
        'abort_bound_sessions' once the new address is installed,
        matching the RFC 5227 §2.4-final SHOULD policy
        Ip4AddressApi.remove_ifaddr already applies.
        """

        self.add_ifaddr(ip4_ifaddr=new_ifaddr)
        self.remove_ifaddr(
            ip4_address=old_address,
            abort_bound_sessions=abort_bound_sessions,
        )

    def list_ip4_ifaddrs(self) -> tuple[Ip4IfAddr, ...]:
        """
        Return a read-only copy-by-value snapshot of the stack's
        IPv4 host list. Linux equivalent: reading
        '/proc/net/route' + 'ip addr show'. The returned tuple is
        immutable; the caller cannot mutate stack state through
        it (matches the Phase-3 north-star "introspection is
        read-only" constraint from CLAUDE.md).
        """

        return tuple(self._resolve_handler()._ip4_ifaddr)

    def abort_bound_tcp_sessions(self, *, address: Ip4Address) -> None:
        """
        Public-API form of '_abort_bound_tcp_sessions' — issue
        'SysCall.ABORT' to every TCP session whose local
        address equals 'address'. Used by RFC 3927 §2.5(a)
        link-local abandon paths and any future DHCPDECLINE-on-
        conflict consumer that needs to reset bound sessions
        before yielding the address.
        """

        self._abort_bound_tcp_sessions(address)

    def subscribe_conflicts(
        self,
        *,
        address: Ip4Address,
        on_conflict: _OnConflict,
    ) -> SubscriptionHandle:
        """
        Register 'on_conflict' to fire whenever the ARP RX path
        observes a post-claim conflict on 'address'. The
        callback fires from the ARP RX thread; long work should
        be deferred to the consumer's own thread. Returns a
        handle for later 'unsubscribe_conflicts'.

        Linux equivalent: 'n_acd' library callback registration
        / 'sd_ipv4ll_set_callback'.
        """

        with self._subscriptions.lock:
            callback_id = self._subscriptions.next_id
            self._subscriptions.next_id += 1
            self._subscriptions.by_address.setdefault(address, {})[callback_id] = on_conflict
        return SubscriptionHandle(address=address, callback_id=callback_id)

    def unsubscribe_conflicts(self, *, handle: SubscriptionHandle) -> None:
        """
        Remove the callback registered for 'handle'. No-op if
        the handle has already been removed or never existed.
        """

        with self._subscriptions.lock:
            callbacks = self._subscriptions.by_address.get(handle.address)
            if callbacks is not None:
                callbacks.pop(handle.callback_id, None)
                if not callbacks:
                    self._subscriptions.by_address.pop(handle.address, None)

    def _fire_conflict_event(self, *, event: ConflictEvent) -> None:
        """
        Internal entry point for the ARP RX path. Dispatches
        'event' to every subscriber registered for
        'event.address'. Exceptions raised by callbacks are
        caught and logged so one buggy subscriber cannot break
        the fan-out chain.
        """

        with self._subscriptions.lock:
            callbacks = list(self._subscriptions.by_address.get(event.address, {}).values())
        for callback in callbacks:
            try:
                callback(event)
            except Exception as exc:  # pylint: disable=broad-exception-caught
                __debug__ and log(
                    "stack",
                    f"<lg>Address API</>: conflict-event callback " f"for {event.address} raised: {exc!r}",
                )

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
