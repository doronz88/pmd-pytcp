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
End-to-end UDP echo integration test for the kernel/userspace boundary.

An out-of-process client opens a UDP socket on the daemon, binds it, and
exchanges datagrams with a peer simulated on the TAP wire over its real
SOCK_DGRAM descriptor — exercising the datagram data plane (control RPC +
SCM_RIGHTS data channel + datagram bridge + per-datagram address framing,
plus the recvmsg ancillary cmsg path) against the live stack. UDP has no
handshake, so both directions run inline on the test's loop.

pmd_pytcp/tests/integration/ipc/test__ipc__udp_echo.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from typing import cast
from typing_extensions import override

from pmd_net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from pmd_net_proto.protocols.ip4.ip4__assembler import Ip4Assembler
from pmd_net_proto.protocols.udp.udp__assembler import UdpAssembler
from pmd_pytcp import stack
from pmd_pytcp.client import ClientStack, ClientUdpSocket, connect
from pmd_pytcp.ipc.ipc__server import IpcServer
from pmd_pytcp.socket import IP_RECVTOS, IP_TOS, IPPROTO_IP, AddressFamily, SocketType
from pmd_pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP4_HOST,
    STACK__MAC_ADDRESS,
)
from pmd_pytcp.tests.lib.udp_testcase import UdpTestCase

_LOCAL_PORT: int = 4444
_REMOTE_PORT: int = 5555
_DEADLINE__SEC: float = 5.0


class TestIpcUdpEcho(UdpTestCase):
    """
    The out-of-process UDP echo integration test.
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
        Build the mocked UDP runtime (via 'UdpTestCase', sync 'setUp' runs
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

    async def _bound_socket(self) -> ClientUdpSocket:
        """
        Open and bind a client UDP socket onto the stack address /
        local port.
        """

        client = await self._connect()
        sock = cast(ClientUdpSocket, await client.socket(AddressFamily.INET4, SocketType.DGRAM))
        self.addAsyncCleanup(sock.close)
        await sock.bind((str(STACK__IP4_HOST.address), _LOCAL_PORT))
        return sock

    def _peer_datagram(self, *, payload: bytes, dscp: int = 0) -> bytes:
        """
        Build an Ethernet/IPv4/UDP datagram from the peer to the bound
        stack socket, optionally marked with a DSCP (the high 6 bits of
        the TOS byte).
        """

        return bytes(
            EthernetAssembler(
                ethernet__src=HOST_A__MAC_ADDRESS,
                ethernet__dst=STACK__MAC_ADDRESS,
                ethernet__payload=Ip4Assembler(
                    ip4__src=HOST_A__IP4_ADDRESS,
                    ip4__dst=STACK__IP4_HOST.address,
                    ip4__dscp=dscp,
                    ip4__payload=UdpAssembler(
                        udp__sport=_REMOTE_PORT,
                        udp__dport=_LOCAL_PORT,
                        udp__payload=payload,
                    ),
                ),
            )
        )

    async def test__udp_echo__client_receives_peer_datagram(self) -> None:
        """
        Ensure a datagram a peer sends on the wire is delivered to the
        out-of-process client over its real fd, paired with the sender's
        address.

        Reference: RFC 768 (UDP — datagram delivery with source address).
        """

        sock = await self._bound_socket()
        self._drive_udp_rx(frame=self._peer_datagram(payload=b"ping"))

        self.assertEqual(
            await asyncio.wait_for(sock.recvfrom(), timeout=_DEADLINE__SEC),
            (b"ping", (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT)),
            msg="The client must receive the peer datagram and its sender address over its fd.",
        )

    async def test__udp_echo__recvmsg_carries_ip_tos_cmsg(self) -> None:
        """
        Ensure that with IP_RECVTOS enabled, an inbound datagram's TOS is
        delivered to the out-of-process client as an IP_TOS ancillary
        control message on recvmsg.

        Reference: RFC 1122 §4.1.4 (IP_TOS reported to the application).
        """

        sock = await self._bound_socket()
        await sock.setsockopt(IPPROTO_IP, IP_RECVTOS, 1)
        # DSCP occupies the high 6 bits of the TOS byte: dscp 8 -> TOS 0x20.
        self._drive_udp_rx(frame=self._peer_datagram(payload=b"marked", dscp=8))

        data, ancdata, _flags, address = await asyncio.wait_for(sock.recvmsg(), timeout=_DEADLINE__SEC)

        self.assertEqual(
            (data, ancdata, address),
            (b"marked", [(int(IPPROTO_IP), int(IP_TOS), b"\x20")], (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT)),
            msg="recvmsg must deliver the inbound TOS as an IP_TOS cmsg when IP_RECVTOS is set.",
        )

    async def test__udp_echo__client_datagram_reaches_the_wire(self) -> None:
        """
        Ensure a datagram the out-of-process client writes via 'sendto'
        is carried by the stack onto the wire as a UDP datagram to that
        address.

        Reference: RFC 768 (UDP — sendto datagram emission).
        """

        sock = await self._bound_socket()
        await sock.sendto(b"pong", (str(HOST_A__IP4_ADDRESS), _REMOTE_PORT))

        deadline = asyncio.get_running_loop().time() + _DEADLINE__SEC
        probe = None
        while asyncio.get_running_loop().time() < deadline:
            for frame in list(self._frames_tx):
                candidate = self._parse_tx(frame)
                if candidate.sport == _LOCAL_PORT and candidate.payload:
                    probe = candidate
                    break
            if probe is not None:
                break
            await asyncio.sleep(0.01)

        assert probe is not None, "The client datagram never reached the wire."
        self.assertEqual(
            (probe.payload, probe.dport, str(probe.ip_dst)),
            (b"pong", _REMOTE_PORT, str(HOST_A__IP4_ADDRESS)),
            msg="A datagram the client sent must reach the wire addressed to the peer.",
        )
