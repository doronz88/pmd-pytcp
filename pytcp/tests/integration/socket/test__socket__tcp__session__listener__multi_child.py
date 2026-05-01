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
This module contains integration tests for the multi-child listener
behaviour of 'TcpSession' / 'TcpSocket': the application-visible
accept-queue ordering and the (lack of) backlog cap.

The 'concurrent SYNs spawn independent children' invariant is
already covered by 'handshake__passive.py' scenario
'concurrent_syns_from_distinct_peers_spawn_independent_children'.
This file documents two further differentiators that the canonical
passive-handshake test does not exercise:

    * The completed-handshake children are appended to
      'TcpSocket._tcp_accept' in arrival (handshake-completion)
      order, so the application's 'accept()' returns FIFO.
    * The accept queue has no backlog cap. PyTCP's 'TcpSocket.listen()'
      takes no backlog argument and '_tcp_accept' is an unbounded
      'list[socket]'. This is documented behaviour and is intentional
      for the current test scope; a future hardening pass may want
      to add a configurable cap (the DoS implication of an unbounded
      queue is out of scope for this suite per the project plan).

Reference RFCs:
    RFC 9293 §3.10.7.2   Listen-state SYN handling
    RFC 9293 §3.10.4     CLOSE / ACCEPT calls

pytcp/tests/integration/socket/test__socket__tcp__session__listener__multi_child.py

ver 3.0.4
"""

from typing import cast

from net_addr import Ip4Address
from pytcp import stack
from pytcp.socket import AddressFamily
from pytcp.socket.tcp__session import (
    FsmState,
    SysCall,
    TcpSession,
)
from pytcp.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_session_testcase import TcpSessionTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
LISTEN__PORT: int = 80
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS

# Listen-side ISS pinned for deterministic SYN+ACK seq numbers
# across the multi-child lifecycle.
LOCAL__ISS: int = 0x0000_3000

# Peer's advertised receive window on its SYN.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN.
PEER__MSS: int = 1460


class TestTcpListener__MultiChild(TcpSessionTestCase):
    """
    Integration tests for the multi-child accept queue (FIFO order
    and unbounded backlog).
    """

    def _make_listen_session(self, *, iss: int) -> tuple[TcpSocket, TcpSession]:
        """
        Build a 'TcpSocket' / 'TcpSession' pair wired up the way
        'TcpSocket.listen()' would wire them, bound to the wildcard
        listen 4-tuple. The session is driven into LISTEN by the
        'SysCall.LISTEN' below; '_tcp_fsm_listen' will then mutate
        it in place into a child for each incoming SYN.
        """

        self._force_iss(iss)

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
        return sock, session

    def test__listener__accept_queue_is_fifo_and_unbounded_backlog(self) -> None:
        """
        Ensure that completed handshakes accumulate on the listening
        socket's '_tcp_accept' queue in handshake-completion order
        (FIFO, ready for 'accept()' to dequeue with 'pop(0)') and
        that the queue has no backlog cap - five concurrent
        completed handshakes all land cleanly.

        Two behaviours are documented:

            1. FIFO order: 'TcpSession._tcp_fsm_syn_rcvd' (line 1299
               in '_tcp_fsm_syn_rcvd') appends each newly-ESTABLISHED
               child to 'parent._tcp_accept'. 'TcpSocket.accept()'
               (line 336) pops from index 0. The combination is FIFO -
               children are returned to the application in the order
               their handshakes completed, NOT the order their SYNs
               arrived (those can differ if a later SYN's 3WHS
               completes before an earlier one's, e.g. due to the
               peers' ACKs arriving in a different order than their
               SYNs).

            2. Unbounded backlog: 'TcpSocket.listen()' takes no
               backlog argument and '_tcp_accept' is an unbounded
               'list[socket]'. PyTCP does not currently impose a cap;
               five completed handshakes (well past BSD's default
               backlog of 5 or 128) all land successfully.

        Scenario:

            1. Set up a listening socket.
            2. Drive five SYNs from five distinct peer source ports
               (33000-33004), each with a distinct peer ISN
               (0x4000-0x4400). The listener spawns five children,
               each in SYN_RCVD.
            3. Drive a tick to fire all five SYN+ACKs.
            4. Drive five third-leg ACKs in REVERSE order
               (port 33004 first, 33000 last). Each child transitions
               SYN_RCVD -> ESTABLISHED and appends itself to
               'parent._tcp_accept'.
            5. Inspect 'parent._tcp_accept': five entries, in
               handshake-completion order
               (33004, 33003, 33002, 33001, 33000) - NOT SYN-arrival
               order (33000, 33001, 33002, 33003, 33004).

        Assertions:

            * 'parent._tcp_accept' has length 5 (no backlog cap
              kicked in).
            * The list's source-port sequence equals the
              completion-order sequence (reverse of SYN-arrival).
            * Each entry is a 'TcpSocket' whose '_tcp_session' is
              in ESTABLISHED.
            * The listening socket itself is still in LISTEN, ready
              to accept further connections.

        This test passes on current code as a positive-control
        regression guard. A future change that:

            - Replaced the FIFO with a different ordering (e.g. LIFO,
              keyed by SYN arrival, etc.) would be caught by the
              completion-order assertion.
            - Imposed a backlog cap below 5 would shrink
              '_tcp_accept' and fail the length-5 assertion.

        is what this test exists to flag.
        """

        listen_sock, _ = self._make_listen_session(iss=LOCAL__ISS)

        # Five distinct peers, each from HOST_A's IP but a unique
        # source port. The peer ISNs are also distinct so per-child
        # state differs, sharpening assertions.
        peers: list[tuple[int, int]] = [
            (33000, 0x0000_4000),
            (33001, 0x0000_4100),
            (33002, 0x0000_4200),
            (33003, 0x0000_4300),
            (33004, 0x0000_4400),
        ]

        # Drive all five SYNs in arrival order.
        for peer_port, peer_iss in peers:
            syn_frame = build_tcp4(
                sport=peer_port,
                dport=LISTEN__PORT,
                seq=peer_iss,
                ack=0,
                flags=("SYN",),
                win=PEER__WIN,
                mss=PEER__MSS,
            )
            inline = self._drive_rx(frame=syn_frame)
            self.assertEqual(
                inline,
                [],
                msg=(
                    f"SYN from peer port {peer_port} must not produce "
                    "an inline reply - the SYN+ACK fires from the "
                    "spawned child's timer handler on the next tick."
                ),
            )

        # Five SYN+ACKs fire on the first tick, one per child.
        # We do not need to inspect them here - the
        # 'concurrent_syns' test in 'handshake__passive.py' already
        # covers the per-child SYN+ACK shape; what this test is
        # focused on is the completion-order behaviour after.
        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            len(peers),
            msg=(
                f"Setup precondition: exactly {len(peers)} SYN+ACKs "
                "must fire on the first tick (one per spawned child)."
            ),
        )

        # Drive third-leg ACKs in REVERSE order so handshake-
        # completion order != SYN-arrival order.
        completion_order_ports = [port for port, _ in reversed(peers)]
        for peer_port, peer_iss in reversed(peers):
            ack_frame = build_tcp4(
                sport=peer_port,
                dport=LISTEN__PORT,
                seq=peer_iss + 1,
                ack=LOCAL__ISS + 1,
                flags=("ACK",),
                win=PEER__WIN,
            )
            self._drive_rx(frame=ack_frame)

        # The accept queue must hold five children (no backlog cap)
        # in handshake-completion order (= reverse SYN-arrival order
        # in this scenario).
        self.assertEqual(
            len(listen_sock._tcp_accept),
            len(peers),
            msg=(
                f"'_tcp_accept' must hold all {len(peers)} completed " "children - PyTCP does not impose a backlog cap."
            ),
        )
        # Each '_tcp_accept' entry is typed as 'socket' (the abstract
        # base) but is in fact always a 'TcpSocket' here; cast for
        # mypy.
        accepted_children: list[TcpSocket] = [cast(TcpSocket, child) for child in listen_sock._tcp_accept]
        observed_ports = [child._remote_port for child in accepted_children]
        self.assertEqual(
            observed_ports,
            completion_order_ports,
            msg=(
                "'_tcp_accept' entries must appear in handshake-"
                "completion order (FIFO ready for accept()'s pop(0)). "
                f"Expected {completion_order_ports!r}, got "
                f"{observed_ports!r}."
            ),
        )

        # Each queued child is ESTABLISHED.
        for child in accepted_children:
            child_session = child._tcp_session
            assert child_session is not None, "queued child must have a session"
            self.assertIs(
                child_session.state,
                FsmState.ESTABLISHED,
                msg=(
                    f"Child for peer port {child._remote_port} must " "be in ESTABLISHED after its handshake completed."
                ),
            )

        # The listening socket itself is still in LISTEN ready to
        # accept further connections - the multi-child behaviour
        # does not retire the listener.
        listen_session = listen_sock._tcp_session
        assert listen_session is not None, "listening socket must have a session"
        self.assertIs(
            listen_session.state,
            FsmState.LISTEN,
            msg=(
                "The listening socket must remain in LISTEN after "
                "five concurrent handshakes complete - the listener "
                "is reusable across an arbitrary number of children."
            ),
        )
