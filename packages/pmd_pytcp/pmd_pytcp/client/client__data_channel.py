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
This module contains the shared data-channel plumbing for the client
socket shims.

Every client socket's data path is a real kernel descriptor — the client
end of the daemon's socketpair, passed at open time. Under the
pure-asyncio runtime ('docs/refactor/pure_asyncio.md') the descriptor is
non-blocking and driven by the loop's sock APIs; '_DataChannel' carries
the descriptor, the 'settimeout' default (implemented with
'asyncio.wait_for' — expiry raises the builtin 'TimeoutError', exactly
what the old blocking-socket timeout raised), and the timeout-wrapping
await helper the shims' 'recv' / 'send' flavours share.

pmd_pytcp/client/client__data_channel.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import socket
from typing import Awaitable, TypeVar

_T = TypeVar("_T")


class _DataChannel:
    """
    A non-blocking data-channel descriptor with a 'settimeout' default.
    """

    _data_socket: socket.socket
    _data_timeout: float | None

    def _init_data_channel(self, data_socket: socket.socket, /) -> None:
        """
        Adopt the data-channel socket (made non-blocking for the loop's
        sock APIs) with no default timeout.
        """

        data_socket.setblocking(False)
        self._data_socket = data_socket
        self._data_timeout = None

    def fileno(self) -> int:
        """
        Return the data-channel descriptor, selectable with select / poll
        / epoll.
        """

        return self._data_socket.fileno()

    def settimeout(self, timeout: float | None, /) -> None:
        """
        Set the data-channel default timeout (seconds, or None to wait
        indefinitely). Acts locally — no daemon round trip.
        """

        self._data_timeout = timeout

    def setblocking(self, flag: bool, /) -> None:
        """
        Map the blocking flag onto the timeout default (the descriptor
        itself always stays non-blocking under the asyncio loop):
        blocking = no timeout, non-blocking = zero timeout.
        """

        self._data_timeout = None if flag else 0.0

    async def _wait_data(self, awaitable: "Awaitable[_T]", /) -> _T:
        """
        Await a data-channel operation under the default timeout,
        raising the builtin 'TimeoutError' on expiry.
        """

        if self._data_timeout is None:
            return await awaitable
        try:
            return await asyncio.wait_for(asyncio.ensure_future(awaitable), self._data_timeout)
        except asyncio.TimeoutError:
            raise TimeoutError("timed out") from None

    def _close_data_channel(self) -> None:
        """
        Close the data-channel descriptor.
        """

        try:
            self._data_socket.close()
        except OSError:
            pass
