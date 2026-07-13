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
This module contains the 'IpcControlTestCase' base — a 'NetworkTestCase'
extended with a live IPC server and client, for out-of-process
control-API integration tests.

'NetworkTestCase.setUp' installs the mocked runtime and the
'mock__init'-populated 'stack.<api>' control singletons over one
registered interface. This subclass adds an 'IpcServer' on a temp AF_UNIX
path and a '_connect()' helper returning a 'ClientStack', so a test can
drive the daemon's real control APIs from out of process and compare
against the in-process result.

Pure-asyncio ('docs/refactor/pure_asyncio.md'): the daemon serves on
the test's event loop, so this base mixes in
'IsolatedAsyncioTestCase' — the server is armed in 'asyncSetUp' (sync
'NetworkTestCase.setUp' still runs first via the MRO) and tests are
'async def' methods that await the client mirrors directly.

pmd_pytcp/tests/lib/ipc_control_testcase.py

ver 3.0.7
"""

from __future__ import annotations

import os
import tempfile
from typing_extensions import override
from unittest import IsolatedAsyncioTestCase

from pmd_pytcp import stack
from pmd_pytcp.client import ClientStack, connect
from pmd_pytcp.ipc.ipc__server import IpcServer
from pmd_pytcp.tests.lib.network_testcase import NetworkTestCase


class IpcControlTestCase(NetworkTestCase, IsolatedAsyncioTestCase):
    """
    Integration-test base for the out-of-process control-API mirrors.
    """

    _log_channel_prior: set[str]

    @classmethod
    @override
    def setUpClass(cls) -> None:
        """
        Silence the 'stack'-channel Subsystem lifecycle logging for the
        whole class. Emptying 'LOG__CHANNEL' here (before any per-test
        'NetworkTestCase.setUp' snapshots it) means the harness snapshots
        and restores the already-empty channel, so the server's
        cleanup-time 'Stopping IPC Server' line — emitted from an
        'addCleanup' that runs after 'NetworkTestCase.tearDown' restores
        its snapshot — stays silent.
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
        Stand up an 'IpcServer' on a temp AF_UNIX path against the
        mocked runtime built by the (sync) 'NetworkTestCase.setUp' that
        already ran. The server needs the running loop, hence the async
        flavour.
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
        Stop the server and await its per-client connection tasks' exit
        so no daemon task outlives the test's loop.
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

    @property
    def _ifindex(self) -> int:
        """
        Return the ifindex of the single registered fixture interface.
        """

        return stack.link.list_interfaces()[0]
