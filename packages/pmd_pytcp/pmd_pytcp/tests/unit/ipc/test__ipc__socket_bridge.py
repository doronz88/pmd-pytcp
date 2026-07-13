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
Tests for the daemon-side per-socket data bridge.

The stack socket the bridge drives is stood in for by a socketpair end
wrapped in '_StackSocketStub', which adapts a plain non-blocking socket
to the pure-asyncio 'recv(bufsize, timeout)' / 'send' / 'shutdown'
surface the bridge calls. The bridge's pump tasks share the test's loop,
so every peer-side read in the assertions is a loop sock call — a
blocking read would starve the pumps.

pmd_pytcp/tests/unit/ipc/test__ipc__socket_bridge.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import socket
from typing_extensions import override
from unittest import IsolatedAsyncioTestCase

from pmd_pytcp.ipc.ipc__socket_bridge import SocketBridge

_DEADLINE__SEC: float = 5.0


class _StackSocketStub:
    """
    Adapt a plain non-blocking socket to the bridge's pure-asyncio
    stack-socket surface.
    """

    def __init__(self, sock: socket.socket, /) -> None:
        sock.setblocking(False)
        self._sock = sock

    async def recv(self, bufsize: int, timeout: float | None = None) -> bytes:
        return await asyncio.get_running_loop().sock_recv(self._sock, bufsize)

    async def send(self, data: bytes) -> int:
        await asyncio.get_running_loop().sock_sendall(self._sock, data)
        return len(data)

    def shutdown(self, how: int, /) -> None:
        self._sock.shutdown(how)


class TestIpcSocketBridge(IsolatedAsyncioTestCase):
    """
    The daemon-side per-socket data-bridge tests.
    """

    @override
    async def asyncSetUp(self) -> None:
        """
        Wire a bridge between a 'stack' socketpair (inner end wrapped in
        the stub, peer end is the simulated remote) and a 'data'
        socketpair (daemon end driven by the bridge, client end is the
        simulated client fd).
        """

        self._stack_inner, self._stack_peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self._data_end, self._client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        for sock in (self._stack_peer, self._client_end):
            sock.setblocking(False)
            self.addCleanup(sock.close)
        self.addCleanup(self._stack_inner.close)

        self._bridge = SocketBridge(_StackSocketStub(self._stack_inner), self._data_end)
        self._bridge.start()
        self.addAsyncCleanup(self._stop_bridge)

    async def _stop_bridge(self) -> None:
        """
        Stop the bridge and await its pumps' exit (plus one loop beat so
        the deferred finaliser closes the daemon-side socketpair end).
        """

        self._bridge.stop()
        await self._bridge.wait_stopped()
        await asyncio.sleep(0)

    async def _recv(self, sock: socket.socket, bufsize: int, /) -> bytes:
        """
        Read from a peer-side socket via the loop (bounded by the test
        deadline) so the bridge pumps keep running while we wait.
        """

        return await asyncio.wait_for(
            asyncio.get_running_loop().sock_recv(sock, bufsize),
            _DEADLINE__SEC,
        )

    async def test__ipc__socket_bridge__rx_stack_to_client(self) -> None:
        """
        Ensure bytes arriving on the stack socket are pumped out to the
        client socketpair end.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        await asyncio.get_running_loop().sock_sendall(self._stack_peer, b"downstream")

        self.assertEqual(
            await self._recv(self._client_end, 64),
            b"downstream",
            msg="The bridge must pump stack-socket RX data to the client end.",
        )

    async def test__ipc__socket_bridge__tx_client_to_stack(self) -> None:
        """
        Ensure bytes the client writes are pumped into the stack socket.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        await asyncio.get_running_loop().sock_sendall(self._client_end, b"upstream")

        self.assertEqual(
            await self._recv(self._stack_peer, 64),
            b"upstream",
            msg="The bridge must pump client-written bytes into the stack socket.",
        )

    async def test__ipc__socket_bridge__bidirectional(self) -> None:
        """
        Ensure both directions pump independently over the same bridge.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        loop = asyncio.get_running_loop()
        await loop.sock_sendall(self._stack_peer, b"a")
        await loop.sock_sendall(self._client_end, b"b")

        self.assertEqual(
            (await self._recv(self._client_end, 8), await self._recv(self._stack_peer, 8)),
            (b"a", b"b"),
            msg="The bridge must pump both directions independently.",
        )

    async def test__ipc__socket_bridge__remote_close_signals_client_eof(self) -> None:
        """
        Ensure a remote close on the stack socket is propagated to the
        client end as end-of-stream (a half-close of the data channel).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._stack_peer.close()

        self.assertEqual(
            await self._recv(self._client_end, 8),
            b"",
            msg="A remote close must surface to the client end as EOF.",
        )

    async def test__ipc__socket_bridge__client_close_signals_stack_fin(self) -> None:
        """
        Ensure a client half-close is propagated to the stack socket as
        a write-side shutdown (FIN).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._client_end.shutdown(socket.SHUT_WR)

        self.assertEqual(
            await self._recv(self._stack_peer, 8),
            b"",
            msg="A client half-close must surface to the stack socket as a FIN.",
        )
