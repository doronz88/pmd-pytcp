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
Tests for the daemon-side per-socket AF_PACKET bridge.

The stack AF_PACKET socket the bridge drives is stood in for by
'_LinkSocketStub', a queue-backed adapter exposing the pure-asyncio
'recvfrom' / 'sendto' coroutine surface the bridge calls. A test injects
an inbound frame to exercise the RX direction and inspects the stub's
outbound list to exercise the TX direction. The bridge's pump tasks
share the test's loop, so waits are awaited, never blocking.

pmd_pytcp/tests/unit/ipc/test__ipc__packet_bridge.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import socket
from typing_extensions import override
from unittest import IsolatedAsyncioTestCase

from pmd_net_addr import MacAddress
from pmd_net_proto.lib.enums import EtherType
from pmd_pytcp.ipc.ipc__packet_bridge import PacketBridge
from pmd_pytcp.ipc.ipc__packet_frame import decode_packet, encode_packet
from pmd_pytcp.socket import PacketType
from pmd_pytcp.socket.sockaddr_ll import SockAddrLl

_DEADLINE__SEC: float = 5.0


class _LinkSocketStub:
    """
    A queue-backed stand-in for a stack AF_PACKET socket (pure-asyncio
    surface — the waiting calls are coroutines).
    """

    def __init__(self) -> None:
        self._inbound: "asyncio.Queue[tuple[bytes, SockAddrLl]]" = asyncio.Queue()
        self.outbound: list[tuple[bytes, SockAddrLl]] = []

    def inject(self, frame: bytes, sockaddr_ll: SockAddrLl, /) -> None:
        self._inbound.put_nowait((frame, sockaddr_ll))

    async def recvfrom(self, bufsize: int | None, timeout: float | None) -> tuple[bytes, SockAddrLl]:
        return await self._inbound.get()

    async def sendto(self, data: bytes, address: SockAddrLl) -> int:
        self.outbound.append((data, address))
        return len(data)


class TestIpcPacketBridge(IsolatedAsyncioTestCase):
    """
    The daemon-side per-socket AF_PACKET-bridge tests.
    """

    @override
    async def asyncSetUp(self) -> None:
        """
        Wire a packet bridge between a stack-socket stub and a SOCK_DGRAM
        data socketpair (daemon end driven by the bridge, client end the
        simulated client fd).
        """

        self._stack = _LinkSocketStub()
        self._data_end, self._client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._client_end.setblocking(False)
        self.addCleanup(self._client_end.close)

        self._bridge = PacketBridge(self._stack, self._data_end)
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

    async def _wait_for_outbound(self) -> tuple[bytes, SockAddrLl]:
        """
        Await (yielding to the pumps) until the stub has received a
        frame from the TX pump.
        """

        deadline = asyncio.get_running_loop().time() + _DEADLINE__SEC
        while asyncio.get_running_loop().time() < deadline:
            if self._stack.outbound:
                return self._stack.outbound[0]
            await asyncio.sleep(0.01)
        raise AssertionError("The TX pump did not deliver a frame to the stack.")

    async def test__ipc__packet_bridge__rx_frames_sockaddr_ll(self) -> None:
        """
        Ensure a frame the stack captures is framed with its sockaddr_ll
        and pumped to the client end.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sockaddr_ll = SockAddrLl(
            ifindex=2,
            ethertype=EtherType.ARP,
            pkttype=PacketType.PACKET_HOST,
            mac=MacAddress("02:00:00:00:00:91"),
        )
        self._stack.inject(b"a-frame", sockaddr_ll)

        blob = await asyncio.wait_for(
            asyncio.get_running_loop().sock_recv(self._client_end, 65600),
            _DEADLINE__SEC,
        )

        self.assertEqual(
            decode_packet(blob),
            (sockaddr_ll, b"a-frame"),
            msg="The RX pump must frame a captured frame with its sockaddr_ll.",
        )

    async def test__ipc__packet_bridge__tx_replays_sockaddr_ll(self) -> None:
        """
        Ensure a frame the client writes is replayed into the stack as a
        'sendto' carrying the framed sockaddr_ll.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sockaddr_ll = SockAddrLl(ifindex=3, ethertype=EtherType.IP4, mac=MacAddress("02:00:00:00:00:07"))
        await asyncio.get_running_loop().sock_sendall(
            self._client_end,
            encode_packet(sockaddr_ll, b"out-frame"),
        )

        self.assertEqual(
            await self._wait_for_outbound(),
            (b"out-frame", sockaddr_ll),
            msg="The TX pump must replay a client frame as a sendto with its sockaddr_ll.",
        )
