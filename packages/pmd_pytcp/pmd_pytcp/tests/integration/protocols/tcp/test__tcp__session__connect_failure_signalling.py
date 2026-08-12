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
This module contains the connect-failure signalling integration
tests: every way a pending active open can die must surface as an
error to the blocked 'connect()' caller — never as a false success
(the caller believes it is connected to a session that is still
mid-handshake or already dead) and never as a permanent hang (the
waiter's release forgotten on a timer-driven collapse).

pmd_pytcp/tests/integration/protocols/tcp/test__tcp__session__connect_failure_signalling.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio

from pmd_net_addr import Ip4Address
from pmd_net_proto import (
    Icmp4Assembler,
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
    Ip4Assembler,
    TcpAssembler,
)
from pmd_pytcp.protocols.tcp.session import TcpSession
from pmd_pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pmd_pytcp.protocols.tcp.tcp__errors import TcpSessionError
from pmd_pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pmd_pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pmd_pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers chosen well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window.
PEER__WIN: int = 64240

# Generous bound on RTO-ladder iterations before declaring the
# retransmission budget broken (the R2 budget is well below this).
MAX_RTO_LADDER_STEPS: int = 32


def _build_icmp4_unreachable_frame(*, code: Icmp4DestinationUnreachableCode, embedded_seq: int) -> bytes:
    """
    Build an Ethernet/IPv4/ICMPv4 Destination Unreachable frame
    embedding an IPv4+TCP SYN for the canonical stack->peer flow.
    """

    embedded_tcp = bytes(
        Ip4Assembler(
            ip4__src=STACK__IP,
            ip4__dst=PEER__IP,
            ip4__payload=TcpAssembler(
                tcp__sport=STACK__PORT,
                tcp__dport=PEER__PORT,
                tcp__seq=embedded_seq,
                tcp__flag_syn=True,
            ),
        )
    )
    icmp = Icmp4Assembler(
        icmp4__message=Icmp4MessageDestinationUnreachable(
            code=code,
            data=embedded_tcp,
        ),
    )
    ip4 = bytes(
        Ip4Assembler(
            ip4__src=PEER__IP,
            ip4__dst=STACK__IP,
            ip4__payload=icmp,
        )
    )
    return b"\x02\x00\x00\x00\x00\x07\x02\x00\x00\x00\x00\x91\x08\x00" + ip4


class TestTcpConnectFailureSignalling(TcpTestCase):
    """
    The connect-failure signalling integration tests.
    """

    async def _park_connect(self, session: TcpSession) -> "asyncio.Task[None]":
        """
        Issue the CONNECT syscall, emit the SYN, and park the
        'connect()' awaiter as a task, asserting it is genuinely
        blocked before the failure under test fires.
        """

        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)
        assert session.state is FsmState.SYN_SENT
        task = asyncio.get_running_loop().create_task(session.connect())
        for _ in range(5):
            await asyncio.sleep(0)
        self.assertFalse(
            task.done(),
            msg="connect() must be parked on the connect event before the failure fires.",
        )
        return task

    async def test__syn_sent__soft_icmp_never_reads_as_connect_success(self) -> None:
        """
        Ensure a soft ICMP Host Unreachable during the handshake
        does NOT wake the blocked 'connect()': the error is
        hint-not-proof (a blind attacker spoofing ICMP must not be
        able to kill — or complete! — a pending connect) and the
        handshake may still succeed. The old shape released the
        connect event with an error value 'connect()' never
        mapped, so the caller returned as if CONNECTED to a
        session still mid-handshake.

        Reference: RFC 5927 §6 (hint-not-proof); RFC 1122 §4.2.3.9.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        connect_task = await self._park_connect(session)

        self._drive_rx(
            frame=_build_icmp4_unreachable_frame(
                code=Icmp4DestinationUnreachableCode.HOST,
                embedded_seq=LOCAL__ISS,
            )
        )
        for _ in range(5):
            await asyncio.sleep(0)

        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="A soft unreachable must not abort the pending handshake (advisory).",
        )
        self.assertFalse(
            connect_task.done(),
            msg="A soft unreachable must not wake connect() — least of all as a success.",
        )

        # The handshake may still complete despite the hint.
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_syn_ack)
        await asyncio.wait_for(connect_task, timeout=1)
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="A hinted-at handshake that completes must still connect.",
        )

    async def test__syn_sent__soft_icmp_reported_when_r2_gives_up(self) -> None:
        """
        Ensure a soft unreachable recorded during the handshake is
        reported — in preference to a bare timeout — when the SYN
        retransmission budget finally gives up: the operator
        learns WHY the SYNs went unanswered (Linux 'sk_err_soft'
        parity: 'tcp_write_err' raises 'sk_err_soft ?: ETIMEDOUT').

        Reference: Linux 'tcp_write_timeout'/'tcp_write_err'; RFC 5927 §6.
        """

        from pmd_pytcp import stack

        session = self._make_active_session(iss=LOCAL__ISS)
        connect_task = await self._park_connect(session)
        socket_id = session._socket.socket_id

        self._drive_rx(
            frame=_build_icmp4_unreachable_frame(
                code=Icmp4DestinationUnreachableCode.NETWORK,
                embedded_seq=LOCAL__ISS,
            )
        )

        for _ in range(MAX_RTO_LADDER_STEPS):
            if session.state is FsmState.CLOSED:
                break
            self._expire_timer(session, "retransmit")
            self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="R2 exhaustion must collapse the pending connect to CLOSED.",
        )
        self.assertNotIn(
            socket_id,
            stack.sockets,
            msg="The failed connect's socket must be unregistered (port released).",
        )

        with self.assertRaises(TcpSessionError) as ctx:
            await asyncio.wait_for(connect_task, timeout=1)
        self.assertEqual(
            str(ctx.exception),
            "Network unreachable",
            msg="The recorded soft error must be reported in preference to a bare timeout.",
        )

    async def test__syn_rcvd__r2_exhaustion_releases_blocked_connect(self) -> None:
        """
        Ensure the retransmission-budget give-up in SYN_RCVD
        releases a blocked 'connect()' with a timeout error: a
        crossed-SYN simultaneous open moves the active opener
        SYN_SENT -> SYN_RCVD while its application is still parked
        in connect(); the R2 collapse released the waiter for
        SYN_SENT only, so this path hung the caller forever.

        Reference: RFC 9293 §3.5 Figure 8 (simultaneous open); §3.8.3 R2 give-up.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        connect_task = await self._park_connect(session)

        # The peer's SYN (no ACK) crosses ours: SYN_SENT -> SYN_RCVD.
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_syn)
        self.assertIs(
            session.state,
            FsmState.SYN_RCVD,
            msg="The crossed SYN must move the active opener to SYN_RCVD.",
        )

        # The peer vanishes; exhaust the SYN+ACK retransmission budget.
        for _ in range(MAX_RTO_LADDER_STEPS):
            if session.state is FsmState.CLOSED:
                break
            self._expire_timer(session, "retransmit")
            self._advance(ms=1)
        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="R2 exhaustion in SYN_RCVD must collapse the session to CLOSED.",
        )

        with self.assertRaises(
            TcpSessionError, msg="A blocked connect() must raise when SYN_RCVD exhausts its budget."
        ):
            await asyncio.wait_for(connect_task, timeout=1)
