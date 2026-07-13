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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
End-to-end passive-open accept() integration test for the boundary.

An out-of-process client opens a TCP socket on the daemon, listens, and
accepts an inbound connection completed by a peer on the TAP wire — the
daemon spawns a fresh data channel for the accepted child and passes its
fd back via SCM_RIGHTS, so the client gets a real fd for the accepted
connection (Phase 4).

The client's accept() coroutine awaits on the daemon dispatch task (in
'TcpSocket.accept'), so the test spawns accept() as a task and drives the
passive handshake on the same loop; the wire poke yields to the daemon
task, so it completes without deadlock.

pmd_pytcp/tests/integration/ipc/test__ipc__accept.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from typing import cast
from typing_extensions import override

from pmd_pytcp import stack
from pmd_pytcp.client import ClientStack, ClientTcpSocket, connect
from pmd_pytcp.ipc.ipc__server import IpcServer
from pmd_pytcp.socket import AddressFamily, SocketType
from pmd_pytcp.tests.lib.network_testcase import HOST_A__IP4_ADDRESS, STACK__IP4_HOST
from pmd_pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pmd_pytcp.tests.lib.tcp_testcase import TcpTestCase

_LISTEN_PORT: int = 80
_PEER_PORT: int = 50002
_LOCAL_ISS: int = 2000
_PEER_ISS: int = 7000
_PEER_WIN: int = 64240
_PEER_MSS: int = 1460
_DEADLINE__SEC: float = 5.0


class TestIpcAccept(TcpTestCase):
    """
    The out-of-process passive-open accept() integration test.
    """

    _log_channel_prior: set[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        """
        Silence the 'stack'-channel Subsystem lifecycle logging for the
        whole class so the server's cleanup-time stop line stays quiet.
        """

        super().setUpClass()
        cls._log_channel_prior = stack.LOG__CHANNEL
        stack.LOG__CHANNEL = set()

    @classmethod
    @override
    def tearDownClass(cls) -> None:
        """
        Restore the original logger channel set.
        """

        stack.LOG__CHANNEL = cls._log_channel_prior
        super().tearDownClass()

    @override
    async def asyncSetUp(self) -> None:
        """
        Build the mocked TCP runtime (via 'TcpTestCase', sync 'setUp' runs
        first through the MRO) then stand up an 'IpcServer' on a temp
        AF_UNIX path against it. The server needs the running loop.
        """

        await super().asyncSetUp()

        self._tmp_dir = tempfile.mkdtemp(prefix="pmd_pytcp-ipc-")
        self.addCleanup(self._cleanup_tmp_dir)
        self._socket_path = os.path.join(self._tmp_dir, "pmd_pytcp.sock")
        self._server = IpcServer(socket_path=self._socket_path)
        await self._server.start()
        self.addAsyncCleanup(self._stop_server)

    async def _stop_server(self) -> None:
        """
        Stop the server and await its per-client tasks' exit.
        """

        self._server.stop()
        await self._server.wait_stopped()

    def _cleanup_tmp_dir(self) -> None:
        """
        Remove the temp directory and any socket node left in it.
        """

        try:
            os.unlink(self._socket_path)
        except OSError:
            pass
        os.rmdir(self._tmp_dir)

    async def _connect(self) -> ClientStack:
        """
        Open a client stack against the server and register its close.
        """

        client = await connect(socket_path=self._socket_path)
        self.addCleanup(client.close)
        return client

    def _drive_passive_handshake(self) -> None:
        """
        Drive the inbound passive handshake on the wire: peer SYN, the
        timer-gated SYN-ACK, then the peer ACK that completes the
        connection and queues the child for accept.
        """

        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_PEER_PORT,
                dport=_LISTEN_PORT,
                seq=_PEER_ISS,
                flags=("SYN",),
                win=_PEER_WIN,
                mss=_PEER_MSS,
            )
        )
        # The SYN-ACK is gated on the next timer tick (the SYN_RCVD
        # transmit branch), as in the active-open initial SYN.
        self._advance(ms=1)
        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_PEER_PORT,
                dport=_LISTEN_PORT,
                seq=_PEER_ISS + 1,
                ack=_LOCAL_ISS + 1,
                flags=("ACK",),
                win=_PEER_WIN,
            )
        )

    async def test__accept__returns_child_with_peer_and_data(self) -> None:
        """
        Ensure a listening client socket accepts an inbound connection out
        of process: accept() returns a child socket carrying the peer
        address, and data the peer sends on the connection reaches the
        child over its real data-channel fd.

        Reference: RFC 9293 §3.5 (Passive OPEN / connection establishment).
        """

        client = await self._connect()
        listener = cast(ClientTcpSocket, await client.socket(AddressFamily.INET4, SocketType.STREAM))
        self.addAsyncCleanup(listener.close)
        self._force_iss(_LOCAL_ISS)
        await listener.bind((str(STACK__IP4_HOST.address), _LISTEN_PORT))
        await listener.listen()

        # Spawn accept() as a task so the daemon has a pending accept
        # while the passive handshake is driven on the same loop.
        accept_task = asyncio.ensure_future(listener.accept())
        # Yield so the accept request reaches the daemon before the
        # handshake queues the child.
        await asyncio.sleep(0)

        self._drive_passive_handshake()

        child, peer = await asyncio.wait_for(accept_task, timeout=_DEADLINE__SEC)
        self.addAsyncCleanup(child.close)

        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_PEER_PORT,
                dport=_LISTEN_PORT,
                seq=_PEER_ISS + 1,
                ack=_LOCAL_ISS + 1,
                flags=("ACK",),
                win=_PEER_WIN,
                payload=b"hi",
            )
        )

        self.assertEqual(
            (peer, await asyncio.wait_for(child.recv(64), timeout=_DEADLINE__SEC)),
            ((str(HOST_A__IP4_ADDRESS), _PEER_PORT), b"hi"),
            msg="accept() must return the peer address and a child whose fd receives the peer's data.",
        )
