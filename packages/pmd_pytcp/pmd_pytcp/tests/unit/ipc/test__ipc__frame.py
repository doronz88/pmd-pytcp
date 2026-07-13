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
Tests for the IPC length-prefixed stream framing codec.

The stream flavours ('send_frame' on a 'StreamWriter' / 'recv_frame' on a
'StreamReader' — the daemon side of the pure-asyncio transport) are
exercised over a real AF_UNIX socketpair whose two ends are wrapped in
asyncio stream connections on the test's loop.

pmd_pytcp/tests/unit/ipc/test__ipc__frame.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import socket
import struct
from typing_extensions import override
from unittest import IsolatedAsyncioTestCase, TestCase

from pmd_pytcp.ipc.ipc__errors import IpcFrameError
from pmd_pytcp.ipc.ipc__frame import (
    IPC__FRAME__LENGTH_PREFIX_LEN,
    IPC__FRAME__MAX_PAYLOAD_LEN,
    pack_frame,
    recv_frame,
    send_frame,
)

_DEADLINE__SEC: float = 5.0


class TestIpcFramePack(TestCase):
    """
    The IPC frame length-prefix packing tests.
    """

    def test__ipc__frame__pack__prepends_length_prefix(self) -> None:
        """
        Ensure 'pack_frame' prepends a 4-byte big-endian unsigned
        length prefix to the payload so the stream peer can recover
        the message boundary.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # IPC frame for payload b"PING" (8 bytes total):
        #   Bytes 0-3 : 0x00000004 -> length prefix = 4
        #   Bytes 4-7 : 0x50494e47 -> payload b"PING"
        frame = pack_frame(b"PING")

        self.assertEqual(
            frame,
            b"\x00\x00\x00\x04PING",
            msg="pack_frame must prepend a 4-byte big-endian length prefix.",
        )

    def test__ipc__frame__pack__empty_payload(self) -> None:
        """
        Ensure 'pack_frame' encodes a zero-length payload as a bare
        length prefix of zero, so empty messages have a valid frame.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # IPC frame for an empty payload (4 bytes total):
        #   Bytes 0-3 : 0x00000000 -> length prefix = 0 (no payload)
        frame = pack_frame(b"")

        self.assertEqual(
            frame,
            b"\x00\x00\x00\x00",
            msg="pack_frame of an empty payload must be the zero length prefix only.",
        )

    def test__ipc__frame__pack__length_prefix_len_constant(self) -> None:
        """
        Ensure the length-prefix width constant matches the actual
        prefix the codec emits, so readers can size their initial
        read against it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            IPC__FRAME__LENGTH_PREFIX_LEN,
            len(struct.pack("!I", 0)),
            msg="IPC__FRAME__LENGTH_PREFIX_LEN must equal the packed prefix width.",
        )

    def test__ipc__frame__pack__oversize_payload_rejected(self) -> None:
        """
        Ensure 'pack_frame' refuses a payload larger than the maximum
        frame size so an absurd length cannot be put on the wire (the
        send-side mirror of the recv-side oversize guard).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        oversize = bytes(IPC__FRAME__MAX_PAYLOAD_LEN + 1)

        with self.assertRaises(IpcFrameError) as error:
            pack_frame(oversize)

        self.assertEqual(
            str(error.exception),
            f"[IPC] Frame payload length {len(oversize)} exceeds the maximum "
            f"of {IPC__FRAME__MAX_PAYLOAD_LEN} bytes.",
            msg="Oversize pack_frame must raise IpcFrameError with the canonical message.",
        )


class TestIpcFrameStream(IsolatedAsyncioTestCase):
    """
    The IPC frame send/recv round-trip tests over a real stream
    socketpair wrapped in asyncio stream connections.
    """

    @override
    async def asyncSetUp(self) -> None:
        """
        Create a connected AF_UNIX stream socketpair and wrap both ends
        in asyncio stream connections on the running loop — writes go
        out on end A's 'StreamWriter', reads come back on end B's
        'StreamReader'.
        """

        sock_a, sock_b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self._reader_a, self._writer_a = await asyncio.open_unix_connection(sock=sock_a)
        self._reader_b, self._writer_b = await asyncio.open_unix_connection(sock=sock_b)
        self.addAsyncCleanup(self._close_streams)

    async def _close_streams(self) -> None:
        """
        Close both stream transports (closing a transport closes the
        underlying socketpair end it owns).
        """

        for writer in (self._writer_a, self._writer_b):
            try:
                writer.close()
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass

    async def test__ipc__frame__roundtrip(self) -> None:
        """
        Ensure a payload written with 'send_frame' is recovered intact
        by 'recv_frame' on the peer end of the stream.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        await send_frame(self._writer_a, b"hello world")

        self.assertEqual(
            await recv_frame(self._reader_b),
            b"hello world",
            msg="recv_frame must recover the exact payload written by send_frame.",
        )

    async def test__ipc__frame__roundtrip__empty_payload(self) -> None:
        """
        Ensure an empty payload round-trips as an empty bytes value,
        distinct from the clean-EOF 'None' sentinel.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        await send_frame(self._writer_a, b"")

        self.assertEqual(
            await recv_frame(self._reader_b),
            b"",
            msg="An empty payload must round-trip as b'' (not None).",
        )

    async def test__ipc__frame__preserves_message_boundaries(self) -> None:
        """
        Ensure multiple frames written back-to-back on one stream are
        read back as separate messages, so the length prefix restores
        the boundaries the byte stream itself does not preserve.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        await send_frame(self._writer_a, b"first")
        await send_frame(self._writer_a, b"second")
        await send_frame(self._writer_a, b"third")

        self.assertEqual(
            [await recv_frame(self._reader_b) for _ in range(3)],
            [b"first", b"second", b"third"],
            msg="recv_frame must restore per-message boundaries from the byte stream.",
        )

    async def test__ipc__frame__large_payload_reassembled(self) -> None:
        """
        Ensure a payload larger than a single kernel stream segment is
        reassembled across partial reads, so the recv loop does not
        assume one read yields the whole payload.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        payload = bytes(range(256)) * 4096  # 1 MiB, will span many reads

        # A 1 MiB payload exceeds the socketpair's kernel send buffer,
        # so 'send_frame' cannot finish draining until the peer reads.
        # Run the send as a concurrent task so 'recv_frame' drains it —
        # awaiting the send to completion first would deadlock the loop.
        send_task = asyncio.ensure_future(send_frame(self._writer_a, payload))

        self.assertEqual(
            await asyncio.wait_for(recv_frame(self._reader_b), _DEADLINE__SEC),
            payload,
            msg="recv_frame must reassemble a multi-segment payload exactly.",
        )

        await asyncio.wait_for(send_task, _DEADLINE__SEC)

    async def test__ipc__frame__clean_eof_returns_none(self) -> None:
        """
        Ensure 'recv_frame' returns None when the peer closes the
        stream at a frame boundary, signalling end-of-stream rather
        than a truncated frame.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._writer_a.close()
        await self._writer_a.wait_closed()

        self.assertIsNone(
            await recv_frame(self._reader_b),
            msg="recv_frame must return None on a clean EOF at a frame boundary.",
        )

    async def test__ipc__frame__truncated_prefix_raises(self) -> None:
        """
        Ensure 'recv_frame' raises 'IpcFrameError' when the peer closes
        after sending only part of the length prefix, so a half-written
        header is reported rather than silently treated as EOF.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._writer_a.write(b"\x00\x00")  # 2 of 4 prefix bytes, then close
        await self._writer_a.drain()
        self._writer_a.close()
        await self._writer_a.wait_closed()

        with self.assertRaises(IpcFrameError) as error:
            await recv_frame(self._reader_b)

        self.assertEqual(
            str(error.exception),
            "[IPC] Stream closed mid-frame while reading the 4-byte length prefix.",
            msg="A truncated length prefix must raise IpcFrameError.",
        )

    async def test__ipc__frame__truncated_payload_raises(self) -> None:
        """
        Ensure 'recv_frame' raises 'IpcFrameError' when the peer closes
        after a complete length prefix but before the full payload, so
        a truncated message is reported rather than returned short.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        # Length prefix announces 10 bytes; only 3 follow before close.
        self._writer_a.write(struct.pack("!I", 10) + b"abc")
        await self._writer_a.drain()
        self._writer_a.close()
        await self._writer_a.wait_closed()

        with self.assertRaises(IpcFrameError) as error:
            await recv_frame(self._reader_b)

        self.assertEqual(
            str(error.exception),
            "[IPC] Stream closed mid-frame: expected 10 payload bytes, got 3.",
            msg="A truncated payload must raise IpcFrameError.",
        )

    async def test__ipc__frame__oversize_prefix_raises(self) -> None:
        """
        Ensure 'recv_frame' rejects a length prefix that announces a
        payload larger than the maximum, so a hostile or corrupt peer
        cannot drive an unbounded allocation.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._writer_a.write(struct.pack("!I", IPC__FRAME__MAX_PAYLOAD_LEN + 1))
        await self._writer_a.drain()

        with self.assertRaises(IpcFrameError) as error:
            await recv_frame(self._reader_b)

        self.assertEqual(
            str(error.exception),
            f"[IPC] Frame length prefix {IPC__FRAME__MAX_PAYLOAD_LEN + 1} exceeds "
            f"the maximum of {IPC__FRAME__MAX_PAYLOAD_LEN} bytes.",
            msg="An oversize length prefix must raise IpcFrameError.",
        )
