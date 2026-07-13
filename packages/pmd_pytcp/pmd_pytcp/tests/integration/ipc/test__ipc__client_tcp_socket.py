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
Integration tests for the client-side TCP socket shim.

These exercise 'ClientStack.socket()' and the 'ClientTcpSocket' control
methods (the non-blocking ones — bind / getsockname / setsockopt /
getsockopt / close) over a live IPC server. The connect + data-transfer
path needs a driven TCP wire and lands in the echo test.

pmd_pytcp/tests/integration/ipc/test__ipc__client_tcp_socket.py

ver 3.0.7
"""

from __future__ import annotations

from typing import cast

from pmd_pytcp.client import ClientTcpSocket
from pmd_pytcp.ipc.ipc__errors import IpcRemoteError
from pmd_pytcp.socket import SO_KEEPALIVE, SOL_SOCKET, AddressFamily, SocketType
from pmd_pytcp.tests.lib.ipc_control_testcase import IpcControlTestCase


class TestIpcClientTcpSocket(IpcControlTestCase):
    """
    The client-side TCP socket shim integration tests.
    """

    async def test__client_socket__open_has_real_fileno(self) -> None:
        """
        Ensure an opened client socket exposes a real, selectable file
        descriptor (its data-channel end), so it works with select /
        poll / epoll natively.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = await self._connect()
        sock = cast(ClientTcpSocket, await client.socket(AddressFamily.INET4, SocketType.STREAM))
        self.addAsyncCleanup(sock.close)

        self.assertGreaterEqual(
            sock.fileno(),
            0,
            msg="A client socket must expose a real data-channel file descriptor.",
        )

    async def test__client_socket__bind_then_getsockname(self) -> None:
        """
        Ensure a bind through the client shim is reflected by a
        subsequent getsockname over the same socket.

        Reference: RFC 9293 §3.9 (User/TCP interface).
        """

        client = await self._connect()
        sock = cast(ClientTcpSocket, await client.socket(AddressFamily.INET4, SocketType.STREAM))
        self.addAsyncCleanup(sock.close)

        await sock.bind(("0.0.0.0", 40010))

        self.assertEqual(
            await sock.getsockname(),
            ("0.0.0.0", 40010),
            msg="getsockname must reflect the address bound through the client shim.",
        )

    async def test__client_socket__setsockopt_getsockopt_round_trip(self) -> None:
        """
        Ensure a setsockopt through the client shim is observable via a
        subsequent getsockopt over the same socket.

        Reference: RFC 1122 §4.2.3.6 (TCP keep-alive SO_KEEPALIVE).
        """

        client = await self._connect()
        sock = cast(ClientTcpSocket, await client.socket(AddressFamily.INET4, SocketType.STREAM))
        self.addAsyncCleanup(sock.close)

        await sock.setsockopt(SOL_SOCKET, SO_KEEPALIVE, 1)

        self.assertEqual(
            await sock.getsockopt(SOL_SOCKET, SO_KEEPALIVE),
            1,
            msg="getsockopt must read back the value set through the client shim.",
        )

    async def test__client_socket__close_releases_daemon_handle(self) -> None:
        """
        Ensure closing the client socket releases the daemon handle, so a
        later control call over it surfaces a remote error.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        client = await self._connect()
        sock = cast(ClientTcpSocket, await client.socket(AddressFamily.INET4, SocketType.STREAM))

        await sock.close()

        with self.assertRaises(IpcRemoteError):
            await sock.getsockname()
