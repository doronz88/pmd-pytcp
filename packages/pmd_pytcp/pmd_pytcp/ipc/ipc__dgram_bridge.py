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
This module contains the daemon-side per-socket datagram bridge.

The datagram analogue of 'SocketBridge': it shuttles whole datagrams
between a stack datagram socket and a SOCK_DGRAM socketpair end. Two
asyncio pump tasks carry the two directions
('docs/refactor/pure_asyncio.md') — RX (stack 'recvmsg' -> client)
frames each datagram with its sender address; TX (client -> stack)
decodes the framed address and replays it as 'sendto' (or 'send' for a
connected socket). A datagram socket has no peer-close EOF (a SOCK_DGRAM
socketpair read never yields b"" for a closed peer), so teardown is
driven by 'stop' — task cancellation — from the control-channel
disconnect, not by a data-channel signal. A datagram the stack refuses
(e.g. no route) is dropped — UDP is best-effort — and the pumps keep
running.

pmd_pytcp/ipc/ipc__dgram_bridge.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import socket
from typing import Protocol

from pmd_pytcp.ipc.ipc__dgram_frame import decode_dgram, encode_dgram
from pmd_pytcp.ipc.ipc__errors import IpcFrameError

IPC__DGRAM_BRIDGE__CHUNK_SIZE: int = 65600
# Ancillary-data buffer the RX pump offers 'recvmsg', large enough for
# the data-path cmsgs PyTCP emits (IP_TOS / IPV6_TCLASS / IP_OPTIONS).
IPC__DGRAM_BRIDGE__ANCBUF_SIZE: int = 256


class DatagramSocket(Protocol):
    """
    The stack datagram-socket surface the datagram bridge drives (the
    pure-asyncio socket API — the waiting calls are coroutines).
    """

    async def recvmsg(
        self,
        bufsize: int | None,
        ancbufsize: int,
        flags: int,
        timeout: float | None,
    ) -> tuple[bytes, list[tuple[int, int, bytes]], int, tuple[str, int] | tuple[str, int, int, int]]:
        """
        Receive one datagram with its ancillary data and sender address,
        waiting up to 'timeout' seconds (None = until cancelled).
        """
        ...

    async def sendto(self, data: bytes, address: tuple[str, int]) -> int:
        """
        Send 'data' as a datagram to 'address'.
        """
        ...

    async def send(self, data: bytes) -> int:
        """
        Send 'data' as a datagram to the connected peer.
        """
        ...


class DatagramBridge:
    """
    A bidirectional datagram pump between a stack datagram socket and a
    SOCK_DGRAM socketpair end.
    """

    def __init__(self, dgram_socket: DatagramSocket, data_end: socket.socket, /) -> None:
        """
        Bind the bridge to a stack datagram socket and its client-facing
        SOCK_DGRAM socketpair end (left unstarted until 'start').
        """

        self._dgram_socket = dgram_socket
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
        self._task__rx = loop.create_task(self._pump_rx(), name="IPC-DgramBridge-RX")
        self._task__tx = loop.create_task(self._pump_tx(), name="IPC-DgramBridge-TX")

    async def _pump_rx(self) -> None:
        """
        Pump stack-received datagrams out to the client, framed with the
        sender address and any ancillary control messages.
        """

        loop = asyncio.get_running_loop()

        while True:
            try:
                data, ancdata, _flags, address = await self._dgram_socket.recvmsg(
                    None,
                    IPC__DGRAM_BRIDGE__ANCBUF_SIZE,
                    0,
                    None,
                )
            except OSError:
                # A transient receive error (e.g. a cached ICMP
                # unreachable surfaced as ConnectionRefusedError, which
                # clears itself) — skip this read and keep pumping;
                # yield a beat so a persistent error cannot hot-spin
                # the loop.
                await asyncio.sleep(0)
                continue

            try:
                await loop.sock_sendall(self._data_end, encode_dgram((address[0], address[1]), data, ancdata))
            except OSError:
                break

    async def _pump_tx(self) -> None:
        """
        Pump client-written datagrams into the stack, replaying each
        framed address as 'sendto' (or 'send' for a connected socket).
        """

        loop = asyncio.get_running_loop()

        while True:
            try:
                blob = await loop.sock_recv(self._data_end, IPC__DGRAM_BRIDGE__CHUNK_SIZE)
            except OSError:
                break

            if not blob:
                continue

            try:
                # The send side honours no cmsg in PyTCP, so the framed
                # ancillary data (if any) is decoded and ignored here.
                address, _cmsg, payload = decode_dgram(blob)
            except IpcFrameError:
                continue

            try:
                if address is None:
                    await self._dgram_socket.send(payload)
                else:
                    await self._dgram_socket.sendto(payload, address)
            except OSError:
                # The stack refused the datagram (e.g. no route, or no
                # destination on a connected-less send) — drop it; UDP
                # is best-effort, so keep the pump running.
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
            loop.create_task(self._finalize(tasks), name="IPC-DgramBridge-Finalize")

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
