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
This module contains the timer-quiescence integration tests: the
zero-idle-CPU design holds only if no logical timer is left armed
in the past. An expired deadline that a handler neither re-arms nor
cancels makes '_reschedule' arm the coalesced service at its 1 ms
floor on every pass — a permanent 1 kHz wake loop per session that
defeats the design silently (the handler no-ops, so nothing visibly
misbehaves; the CPU just burns).

pmd_pytcp/tests/integration/protocols/tcp/test__tcp__session__timer_quiescence.py

ver 3.0.7
"""

from __future__ import annotations

from pmd_net_addr import Ip4Address
from pmd_pytcp.protocols.tcp.session import TcpSession
from pmd_pytcp.protocols.tcp.tcp__enums import FsmState
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


class TestTcpTimerQuiescence(TcpTestCase):
    """
    The per-session timer-quiescence integration tests.
    """

    def _establish(self) -> TcpSession:
        return self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

    def _peer_ack(self, *, seq: int, ack: int, win: int = PEER__WIN) -> bytes:
        return build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=seq,
            ack=ack,
            flags=("ACK",),
            win=win,
        )

    def test__persist__deactivation_cancels_the_logical_timer(self) -> None:
        """
        Ensure the peer reopening its window not only clears the
        persist gate but also cancels the 'persist' logical
        deadline: a deactivated-but-armed deadline is permanently
        expired, and '_reschedule' arms the coalesced service at
        the 1 ms floor for it on every pass — a 1 kHz no-op wake
        loop for the rest of the connection.

        Reference: RFC 9293 §3.8.6.1 (persist deactivation on window reopen).
        """

        session = self._establish()

        # Zero-window: send data, peer acks it all but advertises
        # win=0 — the next pump tick arms the persist timer.
        session._tx.buffer.extend(b"x" * 100)
        session._kick_pump()
        self._advance(ms=1)
        self._drive_rx(frame=self._peer_ack(seq=PEER__ISS + 1, ack=LOCAL__ISS + 101, win=0))
        session._tx.buffer.extend(b"y")
        session._kick_pump()
        self._advance(ms=1)
        self.assertIn(
            "persist",
            session._timers._deadlines,
            msg="Zero-window with pending data must arm the persist timer (test precondition).",
        )

        # Peer reopens the window.
        self._drive_rx(frame=self._peer_ack(seq=PEER__ISS + 1, ack=LOCAL__ISS + 101, win=PEER__WIN))

        self.assertFalse(
            session._persist.active,
            msg="Window reopen must deactivate the persist gate.",
        )
        self.assertNotIn(
            "persist",
            session._timers._deadlines,
            msg="Window reopen must cancel the persist deadline, not just clear the gate.",
        )

    def test__closing_flag__does_not_pump_after_the_close_transition(self) -> None:
        """
        Ensure the never-cleared '_closing' flag stops feeding
        '_has_pump_work' once the deferred close transition has
        fired: it exists to drive ESTABLISHED/CLOSE_WAIT into the
        FIN exchange, and counting it afterwards re-arms the 1 ms
        pump for the session's entire post-close life — 30 s of
        1 kHz no-op wakes per gracefully closed connection in
        TIME_WAIT alone.

        Reference: PyTCP zero-idle-CPU design (docs/refactor/pure_asyncio.md).
        """

        session = self._establish()
        session._socket.close()
        self._advance(ms=1)  # ESTABLISHED sees _closing -> FIN_WAIT_1
        self._advance(ms=1)  # FIN_WAIT_1 emits the FIN

        # Peer acks our FIN and sends its own; we ack it -> TIME_WAIT.
        peer_fin_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 2,
            flags=("FIN", "ACK"),
            win=PEER__WIN,
        )
        self._drive_rx(frame=peer_fin_ack)
        assert session.state is FsmState.TIME_WAIT

        # Let the post-transition pump tick settle, then assert the
        # pump is NOT re-armed: nothing is buffered, nothing is in
        # flight, and the 2MSL delay is a logical timer that needs
        # no pacing.
        self._advance(ms=1)
        self.assertNotIn(
            "tx_pump",
            session._timers._deadlines,
            msg="A quiescent TIME_WAIT session must not keep re-arming the 1 ms pump.",
        )

    def test__rack__stale_deadline_is_cancelled_by_the_tick(self) -> None:
        """
        Ensure 'rack_reorder_tick' consumes an expired 'rack'
        deadline even when it declines to act (no RACK state /
        no further loss candidates): leaving the expired deadline
        armed spins the coalesced service at the 1 ms floor until
        an unrelated event happens to re-arm or cancel it.

        Reference: RFC 8985 §6.2 step 5 (reordering timer is one-shot per arm).
        """

        session = self._establish()

        session._arm_timer("rack", 1)
        self._advance(ms=3)

        self.assertNotIn(
            "rack",
            session._timers._deadlines,
            msg="An expired 'rack' deadline the tick declined to act on must be cancelled.",
        )

    def test__tlp__stale_deadline_is_cancelled_by_the_tick(self) -> None:
        """
        Ensure 'tlp_pto_tick' consumes an expired 'tlp' deadline
        even when the probe is declined (probe already disarmed /
        nothing in flight): leaving the expired deadline armed
        spins the coalesced service at the 1 ms floor until the
        next full cum-ACK drain cancels it.

        Reference: RFC 8985 §7.2 (PTO is one-shot per arm).
        """

        session = self._establish()

        session._arm_timer("tlp", 1)
        session._rack_tlp.tlp_armed = False
        self._advance(ms=3)

        self.assertNotIn(
            "tlp",
            session._timers._deadlines,
            msg="An expired 'tlp' deadline the tick declined to act on must be cancelled.",
        )
