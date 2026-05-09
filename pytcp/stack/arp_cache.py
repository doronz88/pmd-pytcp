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
This module contains class supporting ARP Cache operations.

pytcp/stack/arp_cache.py

ver 3.0.3
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, override

from pytcp import stack
from pytcp.lib.logger import log
from pytcp.lib.subsystem import SUBSYSTEM_SLEEP_TIME__SEC, Subsystem

if TYPE_CHECKING:
    from net_addr import Ip4Address, MacAddress
    from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler


@dataclass(frozen=True, kw_only=True, slots=True)
class CacheEntry:
    """
    Container class for cache entries.
    """

    mac_address: MacAddress
    permanent: bool = False
    create_time: int = field(
        init=False,
        default_factory=lambda: int(time.time()),
    )
    hit_count: int = field(init=False, default=0)

    def hit_count__increment(self) -> None:
        """
        Increment hit count.
        """

        object.__setattr__(self, "hit_count", self.hit_count + 1)

    def hit_count__reset(self) -> None:
        """
        Reset hit count.
        """

        object.__setattr__(self, "hit_count", 0)


@dataclass(slots=True)
class _PendingResolution:
    """
    In-progress ARP resolution state for a single IPv4
    destination. Holds the 'time.monotonic()' timestamp of the
    most recent ARP Request emitted for the address (gates
    subsequent Requests by 'stack.ARP__REQUEST_RATE_LIMIT' per
    RFC 1122 §2.3.2.1) and the most recently queued outbound
    Ethernet packet pending resolution (RFC 1122 §2.3.2.2).
    """

    last_request_at: float = 0.0
    queued_packet: "EthernetAssembler | None" = None


class ArpCache(Subsystem):
    """
    Support for ARP Cache operations.
    """

    _subsystem_name = "ARP Cache"

    _arp_cache: dict[Ip4Address, CacheEntry]
    _pending_resolution: dict[Ip4Address, _PendingResolution]

    _event__stop_subsystem: threading.Event

    @override
    def __init__(self) -> None:
        """
        Initialize ARP Cache.
        """

        super().__init__()

        self._arp_cache = {}
        # Per-destination in-progress-resolution table — RFC 1122
        # §2.3.2.1 outbound-Request rate-limit + §2.3.2.2 saved-
        # unresolved-packet queue. Populated lazily by 'find_entry'
        # / 'enqueue_pending', drained by 'add_entry' on resolution.
        self._pending_resolution = {}

    def __repr__(self) -> str:
        """
        Return string representation of the ARP Cache.
        """

        return repr(self._arp_cache)

    @override
    def _subsystem_loop(self) -> None:
        """
        Maintain the ARP Cache entries.
        """

        for ip4_address in list(self._arp_cache):
            # Skip permanent entries.
            if self._arp_cache[ip4_address].permanent:
                continue

            # If entry age is over maximum age then discard the entry.
            if int(time.time()) - self._arp_cache[ip4_address].create_time > stack.ARP__CACHE__ENTRY_MAX_AGE:
                mac_address = self._arp_cache.pop(ip4_address).mac_address
                __debug__ and log(
                    "arp-c",
                    f"Discarded expir ARP Cache entry - {ip4_address} -> " f"{mac_address}",
                )

            # If entry age is close to maximum age but the entry has been
            # used since last refresh then send out request in attempt
            # to refresh it.
            elif (
                int(time.time()) - self._arp_cache[ip4_address].create_time
                > stack.ARP__CACHE__ENTRY_MAX_AGE - stack.ARP__CACHE__ENTRY_REFRESH_TIME
            ) and self._arp_cache[ip4_address].hit_count:
                self._arp_cache[ip4_address].hit_count__reset()
                assert isinstance(stack.packet_handler, stack.PacketHandlerL2)
                stack.packet_handler.send_arp_request(arp__tpa=ip4_address)
                __debug__ and log(
                    "arp-c",
                    "Trying to refresh expiring ARP Cache entry for "
                    f"{ip4_address} -> "
                    f"{self._arp_cache[ip4_address].mac_address}",
                )

        # Put thread to sleep for a 100 milliseconds.
        self._event__stop_subsystem.wait(SUBSYSTEM_SLEEP_TIME__SEC)

    def add_entry(
        self,
        *,
        ip4_address: Ip4Address,
        mac_address: MacAddress,
    ) -> None:
        """
        Add / refresh an entry in the cache and, if a packet
        was queued against an in-progress resolution for the
        same address, rewrite its Ethernet destination to the
        resolved MAC and dispatch it through the TX ring (RFC
        1122 §2.3.2.2).
        """

        __debug__ and log(
            "arp-c",
            f"<INFO>Adding/refreshing ARP Cache entry - {ip4_address} -> " f"{mac_address}</>",
        )

        self._arp_cache[ip4_address] = CacheEntry(mac_address=mac_address)

        pending = self._pending_resolution.pop(ip4_address, None)
        if pending is not None and pending.queued_packet is not None:
            packet = pending.queued_packet
            packet.dst = mac_address
            __debug__ and log(
                "arp-c",
                f"<INFO>Flushing queued packet for {ip4_address} -> {mac_address}</>",
            )
            stack.tx_ring.enqueue(packet)

    def enqueue_pending(
        self,
        *,
        ip4_address: Ip4Address,
        ethernet_packet_tx: EthernetAssembler,
    ) -> None:
        """
        Save the most recently dropped outbound Ethernet packet
        for an unresolved IPv4 address so 'add_entry' can
        deliver it post-resolution (RFC 1122 §2.3.2.2). A
        second call for the same address overwrites the
        previously queued packet — only the latest is kept,
        matching the SHOULD's "at least one (the latest)"
        wording.
        """

        pending = self._pending_resolution.get(ip4_address)
        if pending is None:
            pending = _PendingResolution()
            self._pending_resolution[ip4_address] = pending
        pending.queued_packet = ethernet_packet_tx

    def find_entry(self, *, ip4_address: Ip4Address) -> MacAddress | None:
        """
        Find entry in cache and return MAC address. On miss,
        dispatch an ARP Request — gated by the per-destination
        rate-limit (RFC 1122 §2.3.2.1) so successive misses
        within the window do not flood the link.
        """

        if arp_entry := self._arp_cache.get(ip4_address, None):
            arp_entry.hit_count__increment()
            __debug__ and log(
                "arp-c",
                f"Found {ip4_address} -> {arp_entry.mac_address} entry, "
                f"age {int(time.time()) - arp_entry.create_time}s, "
                f"hit_count {arp_entry.hit_count}",
            )
            return arp_entry.mac_address

        # Cache miss — gate the ARP Request by RFC 1122 §2.3.2.1.
        now = time.monotonic()
        pending = self._pending_resolution.get(ip4_address)
        if pending is None:
            pending = _PendingResolution()
            self._pending_resolution[ip4_address] = pending

        if now - pending.last_request_at >= stack.ARP__REQUEST_RATE_LIMIT:
            pending.last_request_at = now
            __debug__ and log(
                "arp-c",
                f"Unable to find entry for {ip4_address}, sending ARP request",
            )
            assert isinstance(stack.packet_handler, stack.PacketHandlerL2)
            stack.packet_handler.send_arp_request(arp__tpa=ip4_address)
        else:
            __debug__ and log(
                "arp-c",
                f"Unable to find entry for {ip4_address}, ARP request "
                f"rate-limited (last sent {now - pending.last_request_at:.2f}s ago)",
            )
        return None
