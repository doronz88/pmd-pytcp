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
This module contains the generic Duplicate Address Detection
slot registry shared by IPv4 ARP DAD (RFC 5227) and IPv6 ND
DAD (RFC 4862). 'DadSlotRegistry[A]' is generic over address
type 'A' so both protocols use a single locked-slot
implementation; per-protocol probe-scheduling loops live in
the respective packet-handler paths and consume the registry
only for bookkeeping + atomic RX-thread conflict signalling.

Each candidate gets a slot consisting of:

- 'asyncio.Event'     — set when conflict is observed by the
                        RX path; the worker / boot task
                        polls via 'has_signal()' or awaits
                        the returned 'Event' (via the
                        '_compat.wait_event' helper).
- 'set[bytes]'        — nonces we have emitted for the
                        candidate; only meaningful for ND
                        (RFC 7527 §4.2 Enhanced DAD loop-
                        hairpin drop). ARP never registers
                        nonces.
- 'MacAddress | None' — peer MAC captured when conflict is
                        signalled (ND captures the peer
                        TLLA for logging; ARP leaves None).

All operations (install, register_nonce, teardown,
has_signal, peer_info, try_signal_conflict) run on the one
stack event loop ('docs/refactor/pure_asyncio.md'), so a
worker / boot task cannot tear down a slot mid-RX-signal and
nonce-set mutation cannot interleave with the RX nonce-
membership check — no lock is needed.

pmd_pytcp/lib/dad_slot_registry.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
from enum import Enum

from pmd_net_addr import Ip4Address, Ip6Address, MacAddress
from typing import Generic, TypeVar, Union


class DadSignalResult(Enum):
    """
    Outcome of an atomic 'DadSlotRegistry.try_signal_conflict'
    call. The RX caller branches on this to decide whether to
    fall through to its non-DAD processing path (NOT_DAD),
    drop a loop-hairpin echo silently (LOOP_HAIRPIN — RFC
    7527 §4.2), or charge a peer-conflict counter after the
    slot Event has been signalled (SIGNALED — RFC 4862 §5.4.3
    case (b) and RFC 5227 §2.1).
    """

    NOT_DAD = "NOT_DAD"
    LOOP_HAIRPIN = "LOOP_HAIRPIN"
    SIGNALED = "SIGNALED"


A = TypeVar("A", bound=Union[Ip4Address, Ip6Address])
class DadSlotRegistry(Generic[A]):
    """
    Generic per-candidate DAD slot bookkeeping shared by IPv4
    ARP DAD and IPv6 ND DAD. Generic over the address type so
    one implementation services both protocols.
    """

    def __init__(self) -> None:
        """
        Initialize an empty registry. All access runs on the one
        stack event loop, so no internal lock is needed.
        """

        self._events: dict[A, asyncio.Event] = {}
        self._nonces: dict[A, set[bytes]] = {}
        self._peer_info: dict[A, MacAddress | None] = {}

    def install(self, candidate: A, /) -> asyncio.Event:
        """
        Install a fresh slot for 'candidate' and return the
        slot's Event so the worker / boot task can poll
        ('is_set()') or await it (via '_compat.wait_event').

        Idempotent — overwrites any pre-existing slot for the
        same candidate so a re-claim restarts cleanly.
        """

        event = asyncio.Event()
        self._events[candidate] = event
        self._nonces[candidate] = set()
        self._peer_info[candidate] = None
        return event

    def teardown(self, candidate: A, /) -> None:
        """
        Pop the slot for 'candidate'. No-op if the slot is
        already absent (defensive — the worker may have torn
        down already, or the boot path may double-call on
        cleanup).
        """

        self._events.pop(candidate, None)
        self._nonces.pop(candidate, None)
        self._peer_info.pop(candidate, None)

    def register_nonce(self, candidate: A, nonce: bytes, /) -> None:
        """
        Add 'nonce' to the slot's emitted-nonce set so an
        echo of our own probe ('inbound_nonce' matching one
        we just emitted) can be dropped as a loop-hairpin.
        No-op if no slot exists for 'candidate'.
        """

        if candidate in self._nonces:
            self._nonces[candidate].add(nonce)

    def has_signal(self, candidate: A, /) -> bool:
        """
        Return True if the slot's Event has been set (a
        conflict was observed). Returns False if no slot
        exists for 'candidate'.
        """

        event = self._events.get(candidate)
        return event is not None and event.is_set()

    def peer_info(self, candidate: A, /) -> MacAddress | None:
        """
        Return the captured peer MAC for 'candidate' or None
        if no slot exists or no peer info was captured.
        """

        return self._peer_info.get(candidate)

    def try_signal_conflict(
        self,
        candidate: A,
        /,
        *,
        peer_info: MacAddress | None,
        inbound_nonce: bytes | None,
    ) -> DadSignalResult:
        """
        Atomic RX-path entry point. On the stack loop:

        1. If 'candidate' has no slot, return NOT_DAD. The
           caller falls through to its normal non-DAD
           processing.
        2. If 'inbound_nonce' is non-None and is in the
           slot's emitted-nonce set, return LOOP_HAIRPIN.
           The caller drops the inbound silently (RFC 7527
           §4.2).
        3. Otherwise write 'peer_info' into the slot, set
           the slot Event, and return SIGNALED. The caller
           charges its peer-conflict counter and logs.

        The full check + write + signal is atomic — it runs
        synchronously on the stack loop, so the worker task
        cannot tear down the slot between the membership check
        and the Event.set() call.
        """

        if candidate not in self._events:
            return DadSignalResult.NOT_DAD
        if inbound_nonce is not None and inbound_nonce in self._nonces[candidate]:
            return DadSignalResult.LOOP_HAIRPIN
        self._peer_info[candidate] = peer_info
        self._events[candidate].set()
        return DadSignalResult.SIGNALED
