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
Tests for the daemon-side per-socket datagram bridge.

The stack datagram socket the bridge drives is stood in for by
'_DatagramSocketStub', a queue-backed adapter exposing the pure-asyncio
'recvmsg' / 'sendto' / 'send' coroutine surface the bridge calls. A test
injects an inbound datagram to exercise the RX direction and inspects
the stub's outbound list to exercise the TX direction. The bridge's
pump tasks share the test's loop, so waits are awaited, never blocking.

pmd_pytcp/tests/unit/ipc/test__ipc__dgram_bridge.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import socket
from typing_extensions import override
from unittest import IsolatedAsyncioTestCase

from pmd_pytcp.ipc.ipc__dgram_bridge import DatagramBridge
from pmd_pytcp.ipc.ipc__dgram_frame import decode_dgram, encode_dgram

_DEADLINE__SEC: float = 5.0


class _DatagramSocketStub:
    """
    A queue-backed stand-in for a stack datagram socket (pure-asyncio
    surface — the waiting calls are coroutines).
    """

    def __init__(self) -> None:
        self._inbound: "asyncio.Queue[tuple[bytes, list[tuple[int, int, bytes]], tuple[str, int]]]" = asyncio.Queue()
        self.outbound: list[tuple[bytes, tuple[str, int] | None]] = []

    def inject(
        self,
        data: bytes,
        address: tuple[str, int],
        ancdata: list[tuple[int, int, bytes]] | None = None,
        /,
    ) -> None:
        self._inbound.put_nowait((data, ancdata or [], address))

    async def recvmsg(
        self,
        bufsize: int | None,
        ancbufsize: int,
        flags: int,
        timeout: float | None,
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, tuple[str, int]]:
        data, ancdata, address = await self._inbound.get()
        return data, ancdata, 0, address

    async def sendto(self, data: bytes, address: tuple[str, int]) -> int:
        self.outbound.append((data, address))
        return len(data)

    async def send(self, data: bytes) -> int:
        self.outbound.append((data, None))
        return len(data)


class TestIpcDatagramBridge(IsolatedAsyncioTestCase):
    """
    The daemon-side per-socket datagram-bridge tests.
    """

    @override
    async def asyncSetUp(self) -> None:
        """
        Wire a datagram bridge between a stack-socket stub and a
        SOCK_DGRAM data socketpair (daemon end driven by the bridge,
        client end the simulated client fd).
        """

        self._stack = _DatagramSocketStub()
        self._data_end, self._client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._client_end.setblocking(False)
        self.addCleanup(self._client_end.close)

        self._bridge = DatagramBridge(self._stack, self._data_end)
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

    async def _client_recv(self) -> bytes:
        """
        Read one framed datagram off the client end via the loop,
        bounded by the test deadline.
        """

        return await asyncio.wait_for(
            asyncio.get_running_loop().sock_recv(self._client_end, 65600),
            _DEADLINE__SEC,
        )

    async def _wait_for_outbound(self) -> tuple[bytes, tuple[str, int] | None]:
        """
        Await (yielding to the pumps) until the stub has received a
        datagram from the TX pump.
        """

        deadline = asyncio.get_running_loop().time() + _DEADLINE__SEC
        while asyncio.get_running_loop().time() < deadline:
            if self._stack.outbound:
                return self._stack.outbound[0]
            await asyncio.sleep(0.01)
        raise AssertionError("The TX pump did not deliver a datagram to the stack.")

    async def test__ipc__dgram_bridge__rx_frames_sender_address(self) -> None:
        """
        Ensure a datagram the stack receives is framed with its sender
        address and pumped to the client end.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._stack.inject(b"down", ("10.0.1.91", 5000))

        self.assertEqual(
            decode_dgram(await self._client_recv()),
            (("10.0.1.91", 5000), [], b"down"),
            msg="The RX pump must frame a received datagram with its sender address.",
        )

    async def test__ipc__dgram_bridge__rx_frames_ancillary_cmsgs(self) -> None:
        """
        Ensure ancillary control messages a 'recvmsg' yields are framed
        alongside the datagram and pumped to the client end.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._stack.inject(b"tos", ("10.0.1.91", 5000), [(0, 1, b"\x10")])

        self.assertEqual(
            decode_dgram(await self._client_recv()),
            (("10.0.1.91", 5000), [(0, 1, b"\x10")], b"tos"),
            msg="The RX pump must carry recvmsg cmsgs alongside the datagram.",
        )

    async def test__ipc__dgram_bridge__tx_replays_address_as_sendto(self) -> None:
        """
        Ensure an addressed datagram the client writes is replayed into
        the stack as a 'sendto' to that address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        await asyncio.get_running_loop().sock_sendall(
            self._client_end,
            encode_dgram(("10.0.1.7", 80), b"up"),
        )

        self.assertEqual(
            await self._wait_for_outbound(),
            (b"up", ("10.0.1.7", 80)),
            msg="The TX pump must replay an addressed datagram as a sendto.",
        )

    async def test__ipc__dgram_bridge__tx_no_address_is_connected_send(self) -> None:
        """
        Ensure an address-less datagram the client writes is replayed
        into the stack as a connected 'send'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        await asyncio.get_running_loop().sock_sendall(
            self._client_end,
            encode_dgram(None, b"conn"),
        )

        self.assertEqual(
            await self._wait_for_outbound(),
            (b"conn", None),
            msg="The TX pump must replay an address-less datagram as a connected send.",
        )
