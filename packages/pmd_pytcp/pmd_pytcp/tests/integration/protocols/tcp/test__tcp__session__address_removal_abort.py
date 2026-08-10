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
This module contains the address-removal session-teardown regression
tests, driven end-to-end through a REAL 'TcpSession' (no session
mocks). 'stack.address.remove(...)' must ABORT every TCP session
bound to the removed address: emit RST, drive the session to CLOSED,
and unregister its socket from 'stack.sockets' so the session's
local port returns to the ephemeral pool.

The mock-based cascade tests only assert that the abort entry point
was invoked — they cannot catch an abort path that reaches the
session but doesn't tear it down (e.g. a syscall dispatched to an
FSM state with no syscall handler, which silently no-ops). A session
orphaned that way stays registered forever and permanently consumes
its local port: 'pick_local_port' / 'pick_local_port_for' exclude
every port held by a registered socket, so repeated interface churn
drains the ephemeral pool until connect() raises EADDRINUSE.

pmd_pytcp/tests/integration/protocols/tcp/test__tcp__session__address_removal_abort.py

ver 3.0.7
"""

from __future__ import annotations

from pmd_pytcp import stack
from pmd_pytcp.protocols.tcp.tcp__enums import FsmState
from pmd_pytcp.socket.socket__bind_helpers import pick_local_port
from pmd_pytcp.tests.lib.tcp_testcase import TcpTestCase

LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000
LOCAL__PORT: int = 49152


class TestTcpSessionAddressRemovalAbort(TcpTestCase):
    """
    The 'stack.address.remove' real-session teardown tests.
    """

    def test__address_removal__aborts_established_session_and_releases_port(self) -> None:
        """
        Ensure removing the local address of an ESTABLISHED session
        (through the public Address API, the 'ip addr del' /
        interface-teardown path) emits RST, drives the session to
        CLOSED, and unregisters the socket from 'stack.sockets'.

        Reference: RFC 5227 §2.4 final paragraph (hosts SHOULD actively reset existing connections).
        Reference: RFC 9293 §3.9.1 / §3.10.7.4 (ABORT emits RST in synchronized states and deletes the TCB).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            local_port=LOCAL__PORT,
        )
        socket_id = session._socket.socket_id
        self.assertIn(
            socket_id,
            stack.sockets,
            msg="Sanity: the established session's socket must be registered.",
        )

        self._frames_tx.clear()
        stack.address.remove(address=session._local_ip_address)

        probe = self._parse_tx(self._frames_tx[-1])
        self.assertIn(
            "RST",
            probe.flags,
            msg="Aborting an ESTABLISHED session on address removal must emit RST.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="The aborted session must reach CLOSED.",
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg="The aborted session's socket must be unregistered from 'stack.sockets'.",
        )

    def test__address_removal__frees_local_port_for_reuse(self) -> None:
        """
        Ensure the local port of a session torn down by address
        removal returns to the ephemeral pool. The picker excludes
        every port held by a registered socket, so a session that
        survives the removal registered ('abort' reaching the
        session but not tearing it down) permanently consumes its
        port — under interface churn the pool drains until every
        further pick raises EADDRINUSE.

        Reference: RFC 6056 §3.3.1 (ephemeral port selection excludes in-use ports).
        """

        session = self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            local_port=LOCAL__PORT,
        )

        # Pin the pool to exactly the session's port: while the
        # socket is registered the pick must fail, after the
        # removal-driven teardown it must hand the port back out.
        self._start_patch(
            "pmd_pytcp.socket.socket__bind_helpers._ephemeral_port_pool",
            lambda: range(LOCAL__PORT, LOCAL__PORT + 1),
        )
        with self.assertRaises(OSError, msg="Sanity: the port must be held while the session lives."):
            pick_local_port()

        stack.address.remove(address=session._local_ip_address)

        self.assertEqual(
            pick_local_port(),
            LOCAL__PORT,
            msg="The torn-down session's local port must be pickable again.",
        )
