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
This module contains the listener-close teardown integration tests:
closing a listening socket must reset and deregister the
established-but-unaccepted children queued in its accept backlog
(Linux resets un-accepted connections on listener close — an idle
peer would otherwise keep a backlog child ESTABLISHED, registered,
and port-holding forever), and must wake any blocked 'accept()'
with EBADF instead of leaving it parked on a semaphore nothing will
ever release again.

pmd_pytcp/tests/integration/protocols/tcp/test__tcp__session__listener_close.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import errno

from pmd_net_addr import Ip4Address
from pmd_pytcp import stack
from pmd_pytcp.protocols.tcp.session import TcpSession
from pmd_pytcp.protocols.tcp.tcp__enums import SysCall
from pmd_pytcp.socket import AddressFamily, SocketType
from pmd_pytcp.socket.socket_id import SocketId
from pmd_pytcp.socket.tcp__socket import TcpSocket
from pmd_pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pmd_pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pmd_pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
LISTEN__PORT: int = 80
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 33000

# Initial sequence numbers chosen well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_3000
PEER__ISS: int = 0x0000_4000

# Peer's advertised receive window and MSS on its SYN.
PEER__WIN: int = 64240
PEER__MSS: int = 1460


class TestTcpListenerClose(TcpTestCase):
    """
    The listener-close teardown integration tests.
    """

    def _make_listen_socket(self) -> TcpSocket:
        """
        Build a listening 'TcpSocket' wired the way 'listen()'
        would wire it (wildcard 4-tuple, registered, LISTEN).
        """

        self._force_iss(LOCAL__ISS)

        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = LISTEN__PORT
        sock._remote_ip_address = Ip4Address()
        sock._remote_port = 0

        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=LISTEN__PORT,
            remote_ip_address=Ip4Address(),
            remote_port=0,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        session.tcp_fsm(syscall=SysCall.LISTEN)
        return sock

    def _drive_backlog_child(self, listen_socket: TcpSocket) -> SocketId:
        """
        Drive a full inbound handshake so an established child
        lands in the listener's accept backlog; return the child's
        registry id.
        """

        syn_frame = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=syn_frame)
        self._advance(ms=1)  # SYN_RCVD emits the SYN+ACK.

        ack_frame = build_tcp4(
            sport=PEER__PORT,
            dport=LISTEN__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=ack_frame)

        child_id = SocketId(
            address_family=AddressFamily.INET4,
            socket_type=SocketType.STREAM,
            local_address=STACK__IP,
            local_port=LISTEN__PORT,
            remote_address=PEER__IP,
            remote_port=PEER__PORT,
        )
        assert child_id in stack.sockets, "test precondition: backlog child must be registered"
        assert len(listen_socket._tcp_accept) == 1, "test precondition: backlog must hold the child"
        return child_id

    def test__listener_close__resets_and_deregisters_backlog_children(self) -> None:
        """
        Ensure closing a listener aborts every established-but-
        unaccepted child in its backlog: an RST reaches the peer
        and the child's socket is deregistered, releasing its
        port. Without this the children — kept ESTABLISHED by
        idle peers indefinitely — leaked forever.

        Reference: Linux inet_csk_listen_stop (un-accepted connections are reset on listener close).
        """

        listen_socket = self._make_listen_socket()
        child_id = self._drive_backlog_child(listen_socket)

        frames = []
        before = len(self._frames_tx)
        listen_socket.close()
        frames = list(self._frames_tx[before:])

        self.assertNotIn(
            child_id,
            stack.sockets,
            msg="Listener close must deregister the backlog child, releasing its port.",
        )
        self.assertEqual(
            listen_socket._tcp_accept,
            [],
            msg="Listener close must drain the accept backlog.",
        )
        child_rsts = [
            probe
            for probe in map(self._parse_tx, frames)
            if "RST" in probe.flags and probe.sport == LISTEN__PORT and probe.dport == PEER__PORT
        ]
        self.assertTrue(
            child_rsts,
            msg="Listener close must reset the un-accepted peer (RFC 9293 §3.9.1 ABORT).",
        )

    async def test__listener_close__wakes_blocked_accept_with_ebadf(self) -> None:
        """
        Ensure closing the listener wakes a blocked 'accept()'
        with EBADF: nothing else ever releases the accept
        semaphore of a closed listener, so an unwoken waiter (and
        its task) parked for the loop's lifetime.

        Reference: POSIX close(2)/accept(2) EBADF semantics.
        """

        listen_socket = self._make_listen_socket()

        task = asyncio.get_running_loop().create_task(listen_socket.accept())
        for _ in range(5):
            await asyncio.sleep(0)
        self.assertFalse(
            task.done(),
            msg="accept() must be parked on the accept semaphore before close() fires.",
        )

        listen_socket.close()

        with self.assertRaises(OSError) as ctx:
            await asyncio.wait_for(task, timeout=1)
        self.assertEqual(
            ctx.exception.errno,
            errno.EBADF,
            msg="An accept() woken by close() must raise EBADF.",
        )

    async def test__listener_accept_on_closed_socket_raises_ebadf(self) -> None:
        """
        Ensure 'accept()' on an already-closed listener raises
        EBADF immediately instead of blocking on a semaphore
        nothing will ever release.

        Reference: POSIX accept(2) EBADF.
        """

        listen_socket = self._make_listen_socket()
        listen_socket.close()

        with self.assertRaises(OSError) as ctx:
            await asyncio.wait_for(listen_socket.accept(), timeout=1)
        self.assertEqual(ctx.exception.errno, errno.EBADF)


class TestTcpListenerSynBacklog(TcpTestCase):
    """
    The embryonic (SYN_RCVD) admission-bound tests: every inbound
    SYN forked and REGISTERED a child socket + session without any
    counter, so a SYN flood of never-completing handshakes created
    unbounded concurrent sessions — the exact DoS class the
    accept-queue gate's comment claims to defend against, one state
    earlier.
    """

    _TEST__SYN_BACKLOG = 8

    def setUp(self) -> None:
        super().setUp()
        self._start_patch(
            "pmd_pytcp.protocols.tcp.tcp__constants.TCP__SYN_BACKLOG__MAX_COUNT",
            self._TEST__SYN_BACKLOG,
        )

    def test__listener__embryonic_children_are_bounded(self) -> None:
        """
        Ensure a SYN flood cannot fork embryonic children past the
        SYN-backlog cap: the over-cap SYN is dropped silently (the
        peer retransmits; a slot frees once a handshake completes
        or an embryo times out).

        Reference: Linux 'tcp_max_syn_backlog' (bound on SYN_RCVD sockets per listener).
        """

        listen_socket = TestTcpListenerClose._make_listen_socket(self)
        del listen_socket  # registered in stack.sockets; the gate scans the registry

        sockets_before = len(stack.sockets)
        for i in range(self._TEST__SYN_BACKLOG + 5):
            syn_frame = build_tcp4(
                sport=PEER__PORT + i,
                dport=LISTEN__PORT,
                seq=PEER__ISS,
                ack=0,
                flags=("SYN",),
                win=PEER__WIN,
                mss=PEER__MSS,
            )
            self._drive_rx(frame=syn_frame)

        forked = len(stack.sockets) - sockets_before
        self.assertEqual(
            forked,
            self._TEST__SYN_BACKLOG,
            msg="A SYN flood must not fork embryonic children past the SYN-backlog cap.",
        )
