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
Tests for the IPC SCM_RIGHTS file-descriptor-passing primitive.

The transport mirrors production: the sending (daemon) end is wrapped in
an asyncio stream connection ('send_frame_with_fd' takes the
'StreamWriter'), while the receiving (client) end stays a raw
non-blocking socket ('recv_frame_with_fd' must capture SCM_RIGHTS
ancillary data, which no 'StreamReader' may own).

pmd_pytcp/tests/unit/ipc/test__ipc__fdpass.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import os
import socket
from typing_extensions import override
from unittest import IsolatedAsyncioTestCase

from pmd_pytcp.ipc.ipc__errors import IpcFrameError
from pmd_pytcp.ipc.ipc__fdpass import recv_frame_with_fd, send_frame_with_fd
from pmd_pytcp.ipc.ipc__frame import IPC__FRAME__MAX_PAYLOAD_LEN, send_frame


class TestIpcFdPass(IsolatedAsyncioTestCase):
    """
    The IPC SCM_RIGHTS fd-passing round-trip tests.
    """

    @override
    async def asyncSetUp(self) -> None:
        """
        Create a connected AF_UNIX stream socketpair as the control
        channel — the sending end wrapped in an asyncio stream
        connection, the receiving end a raw non-blocking socket — and a
        pipe whose read end is the descriptor to pass.
        """

        sock_a, self._sock_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock_b.setblocking(False)
        self.addCleanup(self._sock_b.close)

        self._reader_a, self._writer_a = await asyncio.open_unix_connection(sock=sock_a)
        self.addAsyncCleanup(self._close_writer)

        self._pipe_r, self._pipe_w = os.pipe()
        self.addCleanup(lambda: os.close(self._pipe_r))
        self.addCleanup(lambda: os.close(self._pipe_w))

    async def _close_writer(self) -> None:
        """
        Close the sending end's stream transport.
        """

        try:
            self._writer_a.close()
            await self._writer_a.wait_closed()
        except (OSError, ConnectionError):
            pass

    async def test__ipc__fdpass__payload_round_trip(self) -> None:
        """
        Ensure the framed payload accompanying a passed descriptor is
        recovered intact on the peer end.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        await send_frame_with_fd(self._writer_a, b"with-fd", self._pipe_r)
        payload, received_fd = await recv_frame_with_fd(self._sock_b)
        assert received_fd is not None
        self.addCleanup(lambda: os.close(received_fd))

        self.assertEqual(
            payload,
            b"with-fd",
            msg="recv_frame_with_fd must recover the framed payload intact.",
        )

    async def test__ipc__fdpass__no_fd_returns_none(self) -> None:
        """
        Ensure a frame sent with no attached descriptor (a plain
        'send_frame') is received with a None fd rather than raising, so
        the fd-bearing receive path tolerates an fd-less error response.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        await send_frame(self._writer_a, b"no-fd")
        payload, received_fd = await recv_frame_with_fd(self._sock_b)

        self.assertEqual(
            (payload, received_fd),
            (b"no-fd", None),
            msg="A frame with no attached descriptor must yield a None fd, not raise.",
        )

    async def test__ipc__fdpass__descriptor_is_working_duplicate(self) -> None:
        """
        Ensure the received descriptor is a real working duplicate of
        the sent one — a distinct fd number that reads the same open
        file — so the peer can use it as its own.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        await send_frame_with_fd(self._writer_a, b"", self._pipe_r)
        _, received_fd = await recv_frame_with_fd(self._sock_b)
        assert received_fd is not None
        self.addCleanup(lambda: os.close(received_fd))

        os.write(self._pipe_w, b"through-the-fd")

        self.assertEqual(
            (received_fd != self._pipe_r, os.read(received_fd, 64)),
            (True, b"through-the-fd"),
            msg="The received fd must be a distinct, working duplicate of the sent fd.",
        )

    async def test__ipc__fdpass__sequential_passes(self) -> None:
        """
        Ensure multiple descriptors passed back-to-back are each
        received as their own working duplicate.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        results: list[bytes] = []
        for index in range(3):
            await send_frame_with_fd(self._writer_a, f"msg{index}".encode(), self._pipe_r)
            payload, received_fd = await recv_frame_with_fd(self._sock_b)
            assert received_fd is not None
            os.write(self._pipe_w, b"x")
            results.append(payload + os.read(received_fd, 1))
            os.close(received_fd)

        self.assertEqual(
            results,
            [b"msg0x", b"msg1x", b"msg2x"],
            msg="Each sequential fd-pass must deliver its payload and a working fd.",
        )

    async def test__ipc__fdpass__truncated_prefix_raises(self) -> None:
        """
        Ensure a control stream closed before the full length prefix
        raises 'IpcFrameError' rather than yielding a partial frame.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._writer_a.close()
        await self._writer_a.wait_closed()

        with self.assertRaises(IpcFrameError):
            await recv_frame_with_fd(self._sock_b)

    async def test__ipc__fdpass__oversize_payload_rejected(self) -> None:
        """
        Ensure 'send_frame_with_fd' refuses a payload larger than the
        maximum frame size, mirroring the plain framing guard.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(IpcFrameError):
            await send_frame_with_fd(self._writer_a, bytes(IPC__FRAME__MAX_PAYLOAD_LEN + 1), self._pipe_r)
