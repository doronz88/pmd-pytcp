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
Integration tests for the IPC AF_UNIX server + client PING round-trip.

pmd_pytcp/tests/integration/ipc/test__ipc__server__ping.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from typing_extensions import override
from unittest import IsolatedAsyncioTestCase

from pmd_pytcp import stack
from pmd_pytcp.ipc.ipc__client import IpcClient
from pmd_pytcp.ipc.ipc__enums import IpcMessageKind, IpcOp
from pmd_pytcp.ipc.ipc__server import IpcServer

_LOG__CHANNEL_PRIOR: set[str] = set()


def setUpModule() -> None:
    """
    Silence the 'stack'-channel Subsystem lifecycle logging for the
    duration of this module so the IPC server's Initializing / Starting
    / Stopping lines do not speckle the test progress output.
    """

    global _LOG__CHANNEL_PRIOR
    _LOG__CHANNEL_PRIOR = stack.LOG__CHANNEL
    stack.LOG__CHANNEL = set()


def tearDownModule() -> None:
    """
    Restore the original logger channel set.
    """

    stack.LOG__CHANNEL = _LOG__CHANNEL_PRIOR


class TestIpcServerPing(IsolatedAsyncioTestCase):
    """
    The IPC AF_UNIX server + client PING round-trip tests.
    """

    @override
    async def asyncSetUp(self) -> None:
        """
        Stand up an 'IpcServer' on a temp AF_UNIX path (armed on the
        test's loop) and register its teardown before opening any
        client.
        """

        self._tmp_dir = tempfile.mkdtemp(prefix="pmd_pytcp-ipc-")
        self.addCleanup(self._cleanup_tmp_dir)

        self._socket_path = os.path.join(self._tmp_dir, "pmd_pytcp.sock")
        self._server = IpcServer(socket_path=self._socket_path)
        await self._server.start()
        self.addAsyncCleanup(self._stop_server)

    async def _stop_server(self) -> None:
        """
        Stop the server and await its per-client connection tasks' exit.
        """

        self._server.stop()
        await self._server.wait_stopped()

    def _cleanup_tmp_dir(self) -> None:
        """
        Remove the temp directory and any AF_UNIX socket node left in
        it (runs last in LIFO cleanup order, after the server stops).
        """

        try:
            os.unlink(self._socket_path)
        except OSError:
            pass
        os.rmdir(self._tmp_dir)

    async def _connect(self) -> IpcClient:
        """
        Open a client against the server and register its close.
        """

        client = await IpcClient(socket_path=self._socket_path).open()
        self.addCleanup(client.close)
        return client

    async def test__ipc__server__ping_returns_pong(self) -> None:
        """
        Ensure a client PING over the AF_UNIX control channel elicits
        a 'PONG' reply from the daemon, proving the end-to-end frame +
        envelope + transport path.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = await self._connect()

        self.assertEqual(
            await client.ping(),
            b"PONG",
            msg="A PING request must elicit a b'PONG' reply body.",
        )

    async def test__ipc__server__ping_response_envelope(self) -> None:
        """
        Ensure the PING response is a success-kind message carrying the
        same op and the request's correlation id, so the client can
        match a reply to its request.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = await self._connect()

        response = await client.request(IpcOp.PING)

        self.assertEqual(
            (response.kind, response.op),
            (IpcMessageKind.RESPONSE_OK, IpcOp.PING),
            msg="A PING reply must be RESPONSE_OK with op PING.",
        )

    async def test__ipc__server__correlation_id_echoed(self) -> None:
        """
        Ensure the server echoes the request's correlation id back in
        the response, and the client increments it per request, so
        replies are matchable across multiple in-flight requests.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = await self._connect()

        first = await client.request(IpcOp.PING)
        second = await client.request(IpcOp.PING)

        self.assertEqual(
            (second.req_id, second.req_id - first.req_id),
            (first.req_id + 1, 1),
            msg="The client must increment req_id per request and the server echo it.",
        )

    async def test__ipc__server__sequential_pings(self) -> None:
        """
        Ensure many sequential requests on one connection all succeed,
        proving the per-client dispatch loop keeps serving after the
        first reply.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = await self._connect()

        self.assertEqual(
            [await client.ping() for _ in range(50)],
            [b"PONG"] * 50,
            msg="Every sequential PING on one connection must return b'PONG'.",
        )

    async def test__ipc__server__concurrent_clients(self) -> None:
        """
        Ensure multiple client connections are served simultaneously,
        proving the server spawns an independent dispatch loop per
        accepted connection.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        clients = [await self._connect() for _ in range(4)]

        # Issue the four PINGs concurrently (the loop-native analogue
        # of the old one-thread-per-client concurrency check).
        results = await asyncio.gather(*(client.ping() for client in clients))

        self.assertEqual(
            list(results),
            [b"PONG"] * 4,
            msg="Each concurrently-connected client must receive its own b'PONG'.",
        )

    async def test__ipc__server__unknown_op_returns_error(self) -> None:
        """
        Ensure a request the server has no handler for elicits a
        RESPONSE_ERROR rather than a dropped connection, so a client
        learns the op is unsupported.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = await self._connect()

        # IpcOp has only PING (0) today; 0xFFFF is a not-yet-defined op
        # the client sends directly (op is a raw int vocabulary) to
        # exercise the unsupported-op error path.
        response = await client.request(0xFFFF)

        self.assertEqual(
            response.kind,
            IpcMessageKind.RESPONSE_ERROR,
            msg="An unsupported op must elicit a RESPONSE_ERROR reply.",
        )
