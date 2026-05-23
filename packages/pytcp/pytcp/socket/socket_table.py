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
This module contains the lock-guarded registry of open stack sockets.

pytcp/socket/socket_table.py

ver 3.0.6
"""

import threading
from collections.abc import Iterator, Mapping

from pytcp.socket import socket
from pytcp.socket.socket_id import SocketId


class SocketTable:
    """
    The stack-wide registry of open sockets keyed by 'SocketId'.

    A drop-in, dict-compatible replacement for the former bare
    'dict[SocketId, socket]' that guards every operation with a
    single lock. The bare dict was GIL-atomic per primitive op, but
    the registry is read by the RX-side packet handlers (delivery
    lookups) while app threads register / unregister sockets at
    bind / connect / close time; compound access (and free-threaded
    / no-GIL builds) need the explicit lock.

    Iteration accessors ('values' / 'keys' / 'items' / '__iter__')
    return detached snapshots taken under the lock, so an RX or
    control thread can iterate the open-socket set while another
    thread mutates it without risking
    'RuntimeError: dictionary changed size during iteration'.
    """

    def __init__(self) -> None:
        """
        Initialize an empty registry and its guarding lock.
        """

        self._lock = threading.Lock()
        self._sockets: dict[SocketId, socket] = {}

    def get(self, socket_id: SocketId, default: socket | None = None) -> socket | None:
        """
        Return the socket registered under 'socket_id', or 'default'.
        """

        with self._lock:
            return self._sockets.get(socket_id, default)

    def pop(self, socket_id: SocketId, default: socket | None = None) -> socket | None:
        """
        Remove and return the socket under 'socket_id', or 'default'.
        """

        with self._lock:
            return self._sockets.pop(socket_id, default)

    def __getitem__(self, socket_id: SocketId) -> socket:
        """
        Return the socket registered under 'socket_id' (or raise).
        """

        with self._lock:
            return self._sockets[socket_id]

    def __setitem__(self, socket_id: SocketId, sock: socket) -> None:
        """
        Register 'sock' under 'socket_id', replacing any prior entry.
        """

        with self._lock:
            self._sockets[socket_id] = sock

    def __delitem__(self, socket_id: SocketId) -> None:
        """
        Remove the socket registered under 'socket_id' (or raise).
        """

        with self._lock:
            del self._sockets[socket_id]

    def __contains__(self, socket_id: SocketId) -> bool:
        """
        Return whether a socket is registered under 'socket_id'.
        """

        with self._lock:
            return socket_id in self._sockets

    def __len__(self) -> int:
        """
        Return the number of registered sockets.
        """

        with self._lock:
            return len(self._sockets)

    def __iter__(self) -> Iterator[SocketId]:
        """
        Return an iterator over a snapshot of the registered ids.
        """

        with self._lock:
            return iter(list(self._sockets))

    def keys(self) -> list[SocketId]:
        """
        Return a snapshot list of the registered ids.
        """

        with self._lock:
            return list(self._sockets.keys())

    def values(self) -> list[socket]:
        """
        Return a snapshot list of the registered sockets.
        """

        with self._lock:
            return list(self._sockets.values())

    def items(self) -> list[tuple[SocketId, socket]]:
        """
        Return a snapshot list of the registered (id, socket) pairs.
        """

        with self._lock:
            return list(self._sockets.items())

    def clear(self) -> None:
        """
        Remove every registered socket.
        """

        with self._lock:
            self._sockets.clear()

    def update(self, other: Mapping[SocketId, socket]) -> None:
        """
        Bulk-install the mappings from 'other' into the registry.
        """

        with self._lock:
            self._sockets.update(other)
