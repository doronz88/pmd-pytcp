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
This module contains the daemon-side per-socket data bridge.

When a client opens a stream socket the daemon creates a socketpair, hands
one end to the client as its real socket fd, and runs a 'SocketBridge'
shuttling bytes between the other end and the internal stack socket. Two
asyncio pump tasks carry the two directions ('docs/refactor/pure_asyncio.md'):
RX (stack socket -> client) awaits the stack socket's async 'recv'; TX
(client -> stack socket) awaits 'loop.sock_recv' on the socketpair end.
Each propagates a half-close (a read of b"") as a 'shutdown' on the far
side. Teardown is task cancellation — 'stop()' cancels both pumps and
defers the socketpair close to a finaliser task so a pump still parked
inside a loop sock call never races the close. Backpressure falls out of
the socketpair: a slow reader stalls the pump's 'sock_sendall', which
stalls the stack socket and closes the TCP window.

pmd_pytcp/ipc/ipc__socket_bridge.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import socket
from typing import Protocol

from pmd_pytcp._compat import as_buffer

IPC__BRIDGE__CHUNK_SIZE: int = 65536


class BridgedSocket(Protocol):
    """
    The stack-socket surface the data bridge drives (the pure-asyncio
    socket API — 'recv' / 'send' are coroutines, 'shutdown' stays sync).
    """

    async def recv(self, bufsize: int, timeout: float | None = None) -> bytes:
        """
        Receive up to 'bufsize' bytes, waiting up to 'timeout' seconds.
        """
        ...

    async def send(self, data: bytes) -> int:
        """
        Send some of 'data', returning the number of bytes accepted.
        """
        ...

    def shutdown(self, how: int, /) -> None:
        """
        Shut down one or both halves of the connection.
        """
        ...


class SocketBridge:
    """
    A bidirectional byte pump between a stack socket and a socketpair end.
    """

    def __init__(self, stack_socket: BridgedSocket, data_end: socket.socket, /) -> None:
        """
        Bind the bridge to a stack socket and its client-facing socketpair
        end (left unstarted until 'start').
        """

        self._stack_socket = stack_socket
        self._data_end = data_end
        self._data_end.setblocking(False)
        self._task__rx: "asyncio.Task[None] | None" = None
        self._task__tx: "asyncio.Task[None] | None" = None
        self._stopped = False

    def start(self) -> None:
        """
        Spawn the RX and TX pump tasks (requires a running loop).
        """

        loop = asyncio.get_running_loop()
        self._task__rx = loop.create_task(self._pump_rx(), name="IPC-Bridge-RX")
        self._task__tx = loop.create_task(self._pump_tx(), name="IPC-Bridge-TX")

    async def _pump_rx(self) -> None:
        """
        Pump stack-socket RX data out to the client socketpair end.
        """

        loop = asyncio.get_running_loop()

        while True:
            try:
                data = await self._stack_socket.recv(IPC__BRIDGE__CHUNK_SIZE)
            except OSError:
                break

            if not data:
                # Remote closed — signal end-of-stream to the client by
                # half-closing the write side of its socketpair end.
                try:
                    self._data_end.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                break

            try:
                await loop.sock_sendall(self._data_end, data)
            except OSError:
                break

    async def _pump_tx(self) -> None:
        """
        Pump client-written bytes into the stack socket.
        """

        loop = asyncio.get_running_loop()

        while True:
            try:
                data = await loop.sock_recv(self._data_end, IPC__BRIDGE__CHUNK_SIZE)
            except OSError:
                break

            if not data:
                # Client half-closed — propagate as a FIN on the stack
                # socket's write side.
                try:
                    self._stack_socket.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                break

            if not await self._send_all(data):
                break

    async def _send_all(self, data: bytes, /) -> bool:
        """
        Send every byte of 'data' into the stack socket; return False on
        a send error so the caller can stop the pump.
        """

        offset = 0
        while offset < len(data):
            try:
                offset += as_buffer(await self._stack_socket.send(data[offset:]))
            except OSError:
                return False
        return True

    def stop(self) -> None:
        """
        Cancel both pump tasks and close the client-facing socketpair
        end. Sync-safe from loop context: the close is deferred to a
        finaliser task that awaits the cancelled pumps first, so a pump
        still parked in a loop sock call never touches a closed fd. With
        no loop running (the bridge never started) the close is
        immediate.
        """

        if self._stopped:
            return
        self._stopped = True

        tasks = [task for task in (self._task__rx, self._task__tx) if task is not None]
        for task in tasks:
            if not task.done():
                task.cancel()

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is None or not tasks:
            try:
                self._data_end.close()
            except OSError:
                pass
        else:
            loop.create_task(self._finalize(tasks), name="IPC-Bridge-Finalize")

    async def _finalize(self, tasks: "list[asyncio.Task[None]]", /) -> None:
        """
        Await the cancelled pumps' exit, then close the socketpair end.
        """

        await asyncio.gather(*tasks, return_exceptions=True)
        try:
            self._data_end.close()
        except OSError:
            pass

    async def wait_stopped(self) -> None:
        """
        Await both pump tasks' completion after 'stop()'.
        """

        tasks = [task for task in (self._task__rx, self._task__tx) if task is not None]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
