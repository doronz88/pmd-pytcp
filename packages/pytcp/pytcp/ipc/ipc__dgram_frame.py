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
This module contains the IPC datagram data-channel frame codec.

A datagram socket's data channel is a SOCK_DGRAM socketpair, which
preserves message boundaries — one PyTCP datagram is carried as one
AF_UNIX datagram. Each frame prefixes the payload with the peer address
so 'recvfrom' (daemon -> client: who sent it) and 'sendto' (client ->
daemon: where to send it) survive the boundary:

    tag(1) [ port(2) ip(4|16) ] payload

The tag is the address family: 0 = no address (a connected-socket send),
4 = IPv4 (4-byte address), 6 = IPv6 (16-byte address). The IP is packed
with 'inet_pton' and read back with 'inet_ntop', so the address survives
as its canonical string form. This codec is net_proto + stdlib only — no
pytcp stack reach-in (extraction-ready, see
docs/refactor/kernel_userspace_separation.md §2).

pytcp/ipc/ipc__dgram_frame.py

ver 3.0.7
"""

import socket

from net_proto.lib.buffer import Buffer
from pytcp.ipc.ipc__errors import IpcFrameError

IPC__DGRAM__TAG_NONE: int = 0
IPC__DGRAM__TAG_IP4: int = 4
IPC__DGRAM__TAG_IP6: int = 6
IPC__DGRAM__PORT_LEN: int = 2
IPC__DGRAM__IP4_LEN: int = 4
IPC__DGRAM__IP6_LEN: int = 16


def encode_dgram(address: tuple[str, int] | None, payload: Buffer, /) -> bytes:
    """
    Encode a datagram into a framed blob carrying its optional peer
    address ahead of the payload.
    """

    if address is None:
        return bytes([IPC__DGRAM__TAG_NONE]) + bytes(payload)

    host, port = address

    try:
        packed = socket.inet_pton(socket.AF_INET, host)
        tag = IPC__DGRAM__TAG_IP4
    except OSError:
        packed = socket.inet_pton(socket.AF_INET6, host)
        tag = IPC__DGRAM__TAG_IP6

    return bytes([tag]) + port.to_bytes(IPC__DGRAM__PORT_LEN, "big") + packed + bytes(payload)


def decode_dgram(blob: Buffer, /) -> tuple[tuple[str, int] | None, bytes]:
    """
    Decode a framed datagram blob into its optional peer address and
    payload.
    """

    data = bytes(blob)

    if not data:
        raise IpcFrameError("Datagram frame is empty (no address-family tag).")

    tag = data[0]

    if tag == IPC__DGRAM__TAG_NONE:
        return None, data[1:]

    if tag == IPC__DGRAM__TAG_IP4:
        family, ip_len = socket.AF_INET, IPC__DGRAM__IP4_LEN
    elif tag == IPC__DGRAM__TAG_IP6:
        family, ip_len = socket.AF_INET6, IPC__DGRAM__IP6_LEN
    else:
        raise IpcFrameError(f"Datagram frame has an unknown address-family tag {tag}.")

    ip_start = 1 + IPC__DGRAM__PORT_LEN
    payload_start = ip_start + ip_len

    if len(data) < payload_start:
        raise IpcFrameError("Datagram frame is truncated before the end of its address.")

    port = int.from_bytes(data[1:ip_start], "big")
    host = socket.inet_ntop(family, data[ip_start:payload_start])

    return (host, port), data[payload_start:]
