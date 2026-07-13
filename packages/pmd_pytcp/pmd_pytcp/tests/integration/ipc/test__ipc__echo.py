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
End-to-end echo integration test for the kernel/userspace boundary.

An out-of-process client opens a TCP socket on the daemon, connects to a
peer simulated on the TAP wire, and exchanges data over its real
descriptor — the full data plane (control RPC + SCM_RIGHTS data channel +
bridge pump) against the live stack.

The client's 'connect()' coroutine is served on the daemon dispatch task
(which awaits the handshake in 'TcpSession.connect'), so the test spawns
'connect()' as a task and drives the synthetic SYN-ACK on the same loop;
the two cooperate without deadlock because the wire poke yields to the
daemon task between injections.

pmd_pytcp/tests/integration/ipc/test__ipc__echo.py

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

_LOCAL_PORT: int = 50001
_REMOTE_PORT: int = 80
_ISS: int = 1000
_PEER_ISS: int = 5000
_PEER_WIN: int = 64240
_DEADLINE__SEC: float = 5.0


class TestIpcEcho(TcpTestCase):
    """
    The out-of-process TCP echo integration test.
    """

    _log_channel_prior: set[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        """
        Silence the 'stack'-channel Subsystem lifecycle logging for the
        whole class so the server's cleanup-time stop line stays quiet
        (emptied before any per-test snapshot captures it).
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
        AF_UNIX path against it. The server needs the running loop, hence
        the async flavour.
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

    async def _wait_for_local_syn(self) -> None:
        """
        Yield to the loop until the daemon has emitted the active-open
        SYN from the bound local port (so the session is in SYN-SENT and
        will accept the synthetic SYN-ACK), nudging the virtual clock as
        it waits.
        """

        deadline = asyncio.get_running_loop().time() + _DEADLINE__SEC
        while asyncio.get_running_loop().time() < deadline:
            for frame in list(self._frames_tx):
                probe = self._parse_tx(frame)
                if probe.sport == _LOCAL_PORT and "SYN" in probe.flags and "ACK" not in probe.flags:
                    return
            self._advance(ms=1)
            await asyncio.sleep(0.005)
        raise AssertionError("Daemon did not emit the active-open SYN.")

    async def _drive_handshake(self, sock: ClientTcpSocket) -> None:
        """
        Drive 'sock' to ESTABLISHED: spawn the connect coroutine as a
        task, wait for the local SYN, inject the synthetic SYN-ACK, and
        await the connect task.
        """

        self._force_iss(_ISS)
        await sock.bind(("0.0.0.0", _LOCAL_PORT))

        connect_task = asyncio.ensure_future(sock.connect((str(HOST_A__IP4_ADDRESS), _REMOTE_PORT)))

        await self._wait_for_local_syn()
        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_REMOTE_PORT,
                dport=_LOCAL_PORT,
                seq=_PEER_ISS,
                ack=_ISS + 1,
                flags=("SYN", "ACK"),
                win=_PEER_WIN,
            )
        )
        await asyncio.wait_for(connect_task, timeout=_DEADLINE__SEC)

    def _drive_peer_data(self, *, seq: int, payload: bytes) -> None:
        """
        Inject a peer data segment carrying 'payload' on the established
        connection.
        """

        self._drive_rx(
            frame=build_tcp4(
                src_ip=HOST_A__IP4_ADDRESS,
                dst_ip=STACK__IP4_HOST.address,
                sport=_REMOTE_PORT,
                dport=_LOCAL_PORT,
                seq=seq,
                ack=_ISS + 1,
                flags=("ACK",),
                win=_PEER_WIN,
                payload=payload,
            )
        )

    async def test__echo__client_receives_peer_data(self) -> None:
        """
        Ensure data a peer sends on the wire is delivered to the
        out-of-process client over its real data-channel descriptor.

        Reference: RFC 9293 §3.10 (Segment arrives — data delivery to the
        user).
        """

        client = await self._connect()
        sock = cast(ClientTcpSocket, await client.socket(AddressFamily.INET4, SocketType.STREAM))
        self.addAsyncCleanup(sock.close)

        await self._drive_handshake(sock)
        self._drive_peer_data(seq=_PEER_ISS + 1, payload=b"ping")

        self.assertEqual(
            await asyncio.wait_for(sock.recv(64), timeout=_DEADLINE__SEC),
            b"ping",
            msg="The client must receive peer data over its real data-channel fd.",
        )

    async def test__echo__client_data_reaches_the_wire(self) -> None:
        """
        Ensure data the out-of-process client writes to its descriptor is
        carried by the stack onto the wire as a TCP data segment.

        Reference: RFC 9293 §3.10 (SEND call — user data to the network).
        """

        client = await self._connect()
        sock = cast(ClientTcpSocket, await client.socket(AddressFamily.INET4, SocketType.STREAM))
        self.addAsyncCleanup(sock.close)

        await self._drive_handshake(sock)
        await sock.send(b"pong")

        deadline = asyncio.get_running_loop().time() + _DEADLINE__SEC
        seen_payload = b""
        while asyncio.get_running_loop().time() < deadline:
            for frame in list(self._frames_tx):
                probe = self._parse_tx(frame)
                if probe.sport == _LOCAL_PORT and probe.payload:
                    seen_payload = probe.payload
                    break
            if seen_payload:
                break
            self._advance(ms=10)
            await asyncio.sleep(0.01)

        self.assertEqual(
            seen_payload,
            b"pong",
            msg="Data the client wrote must reach the wire as a TCP data segment.",
        )
