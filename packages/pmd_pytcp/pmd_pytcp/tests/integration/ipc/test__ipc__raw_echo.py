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
End-to-end raw-IP echo integration test for the kernel/userspace boundary.

An out-of-process client opens a raw IPv4 socket on the daemon, binds it,
and exchanges raw IP datagrams with a peer simulated on the TAP wire over
its real SOCK_DGRAM descriptor — exercising the raw-socket leg of the
datagram data plane (a raw socket reuses the datagram bridge). The chosen
next-header has no transport handler, so inbound datagrams are delivered
via the IPv4 raw-socket path.

pmd_pytcp/tests/integration/ipc/test__ipc__raw_echo.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from typing import cast
from typing_extensions import override

from pmd_net_proto.lib.enums import EtherType, IpProto
from pmd_net_proto.lib.packet_rx import PacketRx
from pmd_net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from pmd_net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from pmd_net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from pmd_net_proto.protocols.ip4.ip4__parser import Ip4Parser
from pmd_net_proto.protocols.raw.raw__assembler import RawAssembler
from pmd_pytcp import stack
from pmd_pytcp.client import ClientRawSocket, ClientStack, connect
from pmd_pytcp.ipc.ipc__server import IpcServer
from pmd_pytcp.socket import AddressFamily, SocketType
from pmd_pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)
from pmd_pytcp.tests.lib.udp_testcase import UdpTestCase

# A next-header with no transport demux, so an inbound datagram is
# delivered via the IPv4 raw-socket path rather than a transport handler.
_PROTO: IpProto = IpProto.IP4
_DEADLINE__SEC: float = 5.0


class TestIpcRawEcho(UdpTestCase):
    """
    The out-of-process raw-IP echo integration test.
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
        Build the mocked UDP runtime (via 'UdpTestCase', sync 'setUp'
        runs first through the MRO) then stand up an 'IpcServer' on a
        temp AF_UNIX path against it. The server needs the running loop.
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

    async def _bound_raw_socket(self) -> ClientRawSocket:
        """
        Open and bind a client raw IPv4 socket onto the stack address.
        """

        client = await self._connect()
        sock = cast(
            ClientRawSocket,
            await client.socket(AddressFamily.INET4, SocketType.RAW, _PROTO),
        )
        self.addAsyncCleanup(sock.close)
        await sock.bind((str(STACK__IP4_HOST.address), 0))
        return sock

    def _peer_datagram(self, *, payload: bytes) -> bytes:
        """
        Build an Ethernet/IPv4 raw datagram (next-header '_PROTO') from
        the peer to the bound stack address.
        """

        return bytes(
            EthernetAssembler(
                ethernet__src=HOST_A__MAC_ADDRESS,
                ethernet__dst=STACK__MAC_ADDRESS,
                ethernet__payload=Ip4Assembler(
                    ip4__src=HOST_A__IP4_ADDRESS,
                    ip4__dst=STACK__IP4_HOST.address,
                    ip4__payload=RawAssembler(raw__payload=payload, ip_proto=_PROTO),
                ),
            )
        )

    async def test__raw_echo__client_receives_peer_datagram(self) -> None:
        """
        Ensure a raw IP datagram a peer sends on the wire is delivered to
        the out-of-process client over its real fd, paired with the
        sender's address.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = await self._bound_raw_socket()
        self._drive_udp_rx(frame=self._peer_datagram(payload=b"rawin"))

        self.assertEqual(
            await asyncio.wait_for(sock.recvfrom(), timeout=_DEADLINE__SEC),
            (b"rawin", (str(HOST_A__IP4_ADDRESS), 0)),
            msg="The client must receive the raw IP payload and its sender address over its fd.",
        )

    async def test__raw_echo__client_datagram_reaches_the_wire(self) -> None:
        """
        Ensure a raw IP datagram the out-of-process client writes via
        'sendto' is carried by the stack onto the wire as an IPv4 packet
        with the socket's next-header.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sock = await self._bound_raw_socket()
        await sock.sendto(b"rawout", (str(HOST_A__IP4_ADDRESS), 0))

        deadline = asyncio.get_running_loop().time() + _DEADLINE__SEC
        proto = None
        payload = b""
        while asyncio.get_running_loop().time() < deadline:
            for frame in list(self._frames_tx):
                packet_rx = PacketRx(frame)
                EthernetParser(packet_rx)
                if packet_rx.ethernet.type is not EtherType.IP4:
                    continue
                Ip4Parser(packet_rx)
                if packet_rx.ip4.proto is _PROTO and bytes(packet_rx.ip4.payload):
                    proto = packet_rx.ip4.proto
                    payload = bytes(packet_rx.ip4.payload)
                    break
            if payload:
                break
            await asyncio.sleep(0.01)

        self.assertEqual(
            (proto, payload),
            (_PROTO, b"rawout"),
            msg="A raw datagram the client sent must reach the wire as an IPv4 packet with its next-header.",
        )
