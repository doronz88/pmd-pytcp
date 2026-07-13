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
This module contains the registry of stack network interfaces,
keyed by ifindex.

pmd_pytcp/runtime/interface_table.py

ver 3.0.7
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Guarded to break a genuine import cycle: 'pmd_pytcp.stack' imports
    # this module at top to declare the module-level 'interfaces'
    # registry, this module would import 'packet_handler' for the
    # handler type, and 'packet_handler' imports 'pmd_pytcp.stack' at top
    # ('from pmd_pytcp import stack'). The handlers are stored opaquely —
    # the table never calls into the class — so the type is needed for
    # annotations only and the runtime import is unnecessary.
    from pmd_pytcp.runtime.packet_handler import PacketHandlerL2, PacketHandlerL3


class InterfaceTable:
    """
    The stack-wide registry of network interfaces keyed by ifindex.

    Each value is a 'PacketHandler' — the handler instance IS the
    per-interface object (it owns the MTU, MAC, addresses, fragment
    tables, IP-id generators, neighbor caches and rings for one
    interface). Linux keys interfaces (and their per-ifindex ARP / ND
    caches, addresses, MTU) by ifindex; this registry mirrors that.

    A dict-compatible replacement for the former bare
    'dict[int, PacketHandler]'. The daemon mutates the registry at
    runtime ('add_interface' / 'remove_interface' = RTNETLINK
    'RTM_NEWLINK' / 'RTM_DELLINK') on the same stack event loop the
    RX / TX / timer callbacks read it from, so no lock is needed
    ('docs/refactor/pure_asyncio.md').

    Iteration accessors ('values' / 'keys' / 'items' / '__iter__')
    return detached snapshots, so a caller can iterate the interface
    set while its own loop body mutates the registry without risking
    'RuntimeError: dictionary changed size during iteration'.
    """

    def __init__(self, *, first_ifindex: int = 1) -> None:
        """
        Initialize an empty registry and the base ifindex the first
        'add' allocates.
        """

        self._first_ifindex = first_ifindex
        self._interfaces: dict[int, "PacketHandlerL2 | PacketHandlerL3"] = {}

    def add(self, handler: "PacketHandlerL2 | PacketHandlerL3", /) -> int:
        """
        Allocate the next ifindex, register 'handler' under it, stamp
        the allocated ifindex onto the handler, and return it.

        The first add into an empty table takes 'first_ifindex';
        thereafter the index is 'max(existing) + 1' — freed indexes are
        never reused, matching the monotonic allocation Linux uses for
        netdev ifindexes. Allocation and store are atomic by
        construction on the single stack loop, so concurrent adds
        receive distinct indexes.
        """

        ifindex = self._first_ifindex if not self._interfaces else max(self._interfaces) + 1
        handler._ifindex = ifindex
        self._interfaces[ifindex] = handler
        return ifindex

    def get(
        self,
        ifindex: int,
        default: "PacketHandlerL2 | PacketHandlerL3 | None" = None,
    ) -> "PacketHandlerL2 | PacketHandlerL3 | None":
        """
        Return the interface registered under 'ifindex', or 'default'.
        """

        return self._interfaces.get(ifindex, default)

    def pop(
        self,
        ifindex: int,
        default: "PacketHandlerL2 | PacketHandlerL3 | None" = None,
    ) -> "PacketHandlerL2 | PacketHandlerL3 | None":
        """
        Remove and return the interface under 'ifindex', or 'default'.
        """

        return self._interfaces.pop(ifindex, default)

    def __getitem__(self, ifindex: int) -> "PacketHandlerL2 | PacketHandlerL3":
        """
        Return the interface registered under 'ifindex' (or raise).
        """

        return self._interfaces[ifindex]

    def __setitem__(self, ifindex: int, handler: "PacketHandlerL2 | PacketHandlerL3") -> None:
        """
        Register 'handler' under 'ifindex', replacing any prior entry.
        """

        self._interfaces[ifindex] = handler

    def __delitem__(self, ifindex: int) -> None:
        """
        Remove the interface registered under 'ifindex' (or raise).
        """

        del self._interfaces[ifindex]

    def __contains__(self, ifindex: int) -> bool:
        """
        Return whether an interface is registered under 'ifindex'.
        """

        return ifindex in self._interfaces

    def __len__(self) -> int:
        """
        Return the number of registered interfaces.
        """

        return len(self._interfaces)

    def __iter__(self) -> Iterator[int]:
        """
        Return an iterator over a snapshot of the registered ifindexes.
        """

        return iter(list(self._interfaces))

    def keys(self) -> list[int]:
        """
        Return a snapshot list of the registered ifindexes.
        """

        return list(self._interfaces.keys())

    def values(self) -> list["PacketHandlerL2 | PacketHandlerL3"]:
        """
        Return a snapshot list of the registered interfaces.
        """

        return list(self._interfaces.values())

    def items(self) -> list[tuple[int, "PacketHandlerL2 | PacketHandlerL3"]]:
        """
        Return a snapshot list of the registered (ifindex, interface)
        pairs.
        """

        return list(self._interfaces.items())

    def clear(self) -> None:
        """
        Remove every registered interface.
        """

        self._interfaces.clear()

    def update(self, other: "Mapping[int, PacketHandlerL2 | PacketHandlerL3]") -> None:
        """
        Bulk-install the mappings from 'other' into the registry.
        """

        self._interfaces.update(other)
