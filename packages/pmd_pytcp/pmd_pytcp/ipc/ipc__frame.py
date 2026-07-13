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
This module contains the IPC length-prefixed stream framing codec.

A byte stream (AF_UNIX) has no message boundaries; the IPC control
channel restores them by prefixing every payload with a 4-byte
big-endian unsigned length. This module is the lowest layer of the IPC
codec core — it depends only on the standard library and 'pmd_net_proto'
('Buffer'), reaching into no pmd_pytcp stack internals, so it stays liftable
into a standalone dist (see docs/refactor/kernel_userspace_separation.md
§2).

Pure-asyncio transport ('docs/refactor/pure_asyncio.md'): each helper
comes in two flavours. The daemon side runs over asyncio streams
('recv_frame' on a 'StreamReader', 'send_frame' on a 'StreamWriter') —
its inbound requests never carry descriptors, so stream buffering is
safe there. The client side runs over a raw non-blocking socket via the
loop's sock APIs ('recv_frame_from_socket', 'send_frame_to_socket'):
the response stream can carry SCM_RIGHTS descriptors, which an
eagerly-buffering 'StreamReader' would silently drop (the transport's
plain 'recv' discards ancillary data), so no transport may own the
client's connection socket.

pmd_pytcp/ipc/ipc__frame.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import socket
import struct

from pmd_net_proto.lib.buffer import Buffer
from pmd_pytcp.ipc.ipc__errors import IpcFrameError

IPC__FRAME__LENGTH_PREFIX_STRUCT: str = "! I"
IPC__FRAME__LENGTH_PREFIX_LEN: int = 4
IPC__FRAME__MAX_PAYLOAD_LEN: int = 16 * 1024 * 1024


def pack_frame(payload: Buffer, /) -> bytes:
    """
    Prepend the 4-byte big-endian length prefix to a payload.
    """

    length = len(payload)

    if length > IPC__FRAME__MAX_PAYLOAD_LEN:
        raise IpcFrameError(
            f"Frame payload length {length} exceeds the maximum " f"of {IPC__FRAME__MAX_PAYLOAD_LEN} bytes.",
        )

    return struct.pack(IPC__FRAME__LENGTH_PREFIX_STRUCT, length) + bytes(payload)


def unpack_frame_length(prefix: bytes, /) -> int:
    """
    Decode and bound-check the 4-byte length prefix, shared by every
    read flavour (stream, socket, fd-bearing).
    """

    length = int(struct.unpack(IPC__FRAME__LENGTH_PREFIX_STRUCT, prefix)[0])

    if length > IPC__FRAME__MAX_PAYLOAD_LEN:
        raise IpcFrameError(
            f"Frame length prefix {length} exceeds the maximum " f"of {IPC__FRAME__MAX_PAYLOAD_LEN} bytes.",
        )

    return length


async def send_frame(writer: asyncio.StreamWriter, payload: Buffer, /) -> None:
    """
    Write a single length-prefixed frame to the stream writer (the
    daemon side).
    """

    writer.write(pack_frame(payload))
    await writer.drain()


async def send_frame_to_socket(sock: socket.socket, payload: Buffer, /) -> None:
    """
    Write a single length-prefixed frame to the non-blocking stream
    socket via the loop's 'sock_sendall' (the client side, where no
    transport may own the socket — see the module docstring).
    """

    await asyncio.get_running_loop().sock_sendall(sock, pack_frame(payload))


async def recv_frame(reader: asyncio.StreamReader, /) -> bytes | None:
    """
    Read a single length-prefixed frame from the stream reader.

    Returns the payload bytes, or None when the peer closes the stream
    cleanly at a frame boundary (end of stream). Raises 'IpcFrameError'
    when the stream is closed mid-frame or the announced length exceeds
    the maximum.
    """

    try:
        prefix = await reader.readexactly(IPC__FRAME__LENGTH_PREFIX_LEN)
    except asyncio.IncompleteReadError as error:
        if not error.partial:
            return None
        raise IpcFrameError(
            "Stream closed mid-frame while reading the 4-byte length prefix.",
        ) from error

    length = unpack_frame_length(prefix)

    try:
        payload = await reader.readexactly(length)
    except asyncio.IncompleteReadError as error:
        raise IpcFrameError(
            f"Stream closed mid-frame: expected {length} payload bytes, " f"got {len(error.partial)}.",
        ) from error

    return payload


async def recv_frame_from_socket(sock: socket.socket, /) -> bytes | None:
    """
    Read a single length-prefixed frame from a non-blocking stream
    socket via the loop's sock APIs — the client-side flavour, used on
    connections whose inbound stream can also carry SCM_RIGHTS
    descriptors (so no 'StreamReader' may own the socket).

    Same contract as 'recv_frame': the payload bytes, None on a clean
    boundary EOF, 'IpcFrameError' on truncation / oversize.
    """

    prefix = await recv_exactly(sock, IPC__FRAME__LENGTH_PREFIX_LEN)

    if len(prefix) == 0:
        return None

    if len(prefix) < IPC__FRAME__LENGTH_PREFIX_LEN:
        raise IpcFrameError(
            "Stream closed mid-frame while reading the 4-byte length prefix.",
        )

    length = unpack_frame_length(prefix)

    payload = await recv_exactly(sock, length)

    if len(payload) < length:
        raise IpcFrameError(
            f"Stream closed mid-frame: expected {length} payload bytes, " f"got {len(payload)}.",
        )

    return payload


async def recv_exactly(sock: socket.socket, count: int, /) -> bytes:
    """
    Read exactly 'count' bytes from the non-blocking stream socket,
    looping over partial reads via the loop's 'sock_recv'. Returns fewer
    than 'count' bytes only when the peer closes the stream before
    'count' bytes arrive — the caller distinguishes a clean boundary EOF
    (zero bytes) from a mid-frame truncation (a non-zero short read) by
    the returned length.
    """

    loop = asyncio.get_running_loop()

    chunks: list[bytes] = []
    remaining = count

    while remaining > 0:
        chunk = await loop.sock_recv(sock, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)
