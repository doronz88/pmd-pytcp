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
This module contains the daemon-side per-socket AF_PACKET bridge.

The link-layer analogue of 'DatagramBridge'. It shuttles whole frames
between a stack AF_PACKET socket and a SOCK_DGRAM socketpair end, framing
each with its 'sockaddr_ll' (see 'ipc__packet_frame') so the link-layer
address survives: the RX pump frames each captured frame with how it
arrived; the TX pump decodes the framed address and replays it as
'sendto'. The pumps are asyncio tasks
('docs/refactor/pure_asyncio.md'); like the datagram bridge, an
AF_PACKET socketpair has no peer-close EOF, so teardown is 'stop'-driven
(task cancellation) from the control-channel disconnect; a frame the
stack refuses is dropped and the pumps keep running.

pmd_pytcp/ipc/ipc__packet_bridge.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import socket
from typing import Protocol

from pmd_pytcp.ipc.ipc__errors import IpcFrameError
from pmd_pytcp.ipc.ipc__packet_frame import decode_packet, encode_packet
from pmd_pytcp.socket.sockaddr_ll import SockAddrLl

IPC__PACKET_BRIDGE__CHUNK_SIZE: int = 65600


class LinkSocket(Protocol):
    """
    The stack AF_PACKET-socket surface the packet bridge drives (the
    pure-asyncio socket API — the waiting calls are coroutines).
    """

    async def recvfrom(self, bufsize: int | None, timeout: float | None) -> tuple[bytes, SockAddrLl]:
        """
        Receive one frame with its 'sockaddr_ll', waiting up to
        'timeout' seconds (None = until cancelled).
        """
        ...

    async def sendto(self, data: bytes, address: SockAddrLl) -> int:
        """
        Send 'data' as a link-layer frame to the interface named by
        'address'.
        """
        ...


class PacketBridge:
    """
    A bidirectional link-frame pump between a stack AF_PACKET socket and
    a SOCK_DGRAM socketpair end.
    """

    def __init__(self, packet_socket: LinkSocket, data_end: socket.socket, /) -> None:
        """
        Bind the bridge to a stack AF_PACKET socket and its client-facing
        SOCK_DGRAM socketpair end (left unstarted until 'start').
        """

        self._packet_socket = packet_socket
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
        self._task__rx = loop.create_task(self._pump_rx(), name="IPC-PacketBridge-RX")
        self._task__tx = loop.create_task(self._pump_tx(), name="IPC-PacketBridge-TX")

    async def _pump_rx(self) -> None:
        """
        Pump stack-captured frames out to the client, framed with their
        'sockaddr_ll'.
        """

        loop = asyncio.get_running_loop()

        while True:
            try:
                frame, sockaddr_ll = await self._packet_socket.recvfrom(None, None)
            except OSError:
                # Transient capture error — skip this read and keep
                # pumping; yield a beat so a persistent error cannot
                # hot-spin the loop.
                await asyncio.sleep(0)
                continue

            try:
                await loop.sock_sendall(self._data_end, encode_packet(sockaddr_ll, frame))
            except OSError:
                break

    async def _pump_tx(self) -> None:
        """
        Pump client-written frames into the stack, replaying each framed
        'sockaddr_ll' as 'sendto'.
        """

        loop = asyncio.get_running_loop()

        while True:
            try:
                blob = await loop.sock_recv(self._data_end, IPC__PACKET_BRIDGE__CHUNK_SIZE)
            except OSError:
                break

            if not blob:
                continue

            try:
                sockaddr_ll, frame = decode_packet(blob)
            except IpcFrameError:
                continue

            try:
                await self._packet_socket.sendto(frame, sockaddr_ll)
            except OSError:
                # The stack refused the frame (e.g. no egress interface);
                # drop it and keep pumping.
                continue

    def stop(self) -> None:
        """
        Cancel both pump tasks and close the client-facing socketpair
        end (deferred to a finaliser task while the loop runs — see
        'SocketBridge.stop').
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
            loop.create_task(self._finalize(tasks), name="IPC-PacketBridge-Finalize")

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
