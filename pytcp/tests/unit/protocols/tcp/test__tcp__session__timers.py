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
This module contains tests for the TcpSession logical-timer
deadline-map helpers (Phase 1 of the TCP timer-client migration).

pytcp/tests/unit/protocols/tcp/test__tcp__session__timers.py

ver 3.0.4
"""

from types import SimpleNamespace
from typing import override
from unittest import TestCase
from unittest.mock import MagicMock, patch

from pytcp.protocols.tcp.tcp__session import TcpSession
from pytcp.runtime.timer import TimerHandle


class TestTcpSessionTimers(TestCase):
    """
    The TcpSession deadline-map timer-helper tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a bare TcpSession (no __init__) wired to a fake
        'stack.timer' with a controllable virtual clock.
        """

        self._timer = SimpleNamespace(now_ms=1000, cancel=MagicMock())
        self._stack_patch = patch(
            "pytcp.protocols.tcp.tcp__session.stack.timer",
            self._timer,
            create=True,
        )
        self._stack_patch.start()
        self.addCleanup(self._stack_patch.stop)

        self._session = TcpSession.__new__(TcpSession)
        self._session._timer_deadlines = {}
        self._session._service_handle = None

    def test__tcp__timers__arm_sets_absolute_deadline(self) -> None:
        """
        Ensure '_arm_timer' records an absolute deadline of
        'now_ms + delay_ms'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 200)
        self.assertEqual(
            self._session._timer_deadlines["retransmit"],
            1200,
            msg="_arm_timer must store now_ms + delay_ms as the absolute deadline.",
        )

    def test__tcp__timers__expired_false_when_unarmed(self) -> None:
        """
        Ensure '_timer_expired' is False for a timer that was
        never armed — the de-conflation of the legacy
        'is_expired' (which returned True when unarmed).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            self._session._timer_expired("retransmit"),
            msg="An unarmed timer must NOT report expired (de-conflation).",
        )

    def test__tcp__timers__expired_true_at_or_after_deadline(self) -> None:
        """
        Ensure '_timer_expired' becomes True exactly at the
        deadline and stays True after it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("tlp", 50)
        self._timer.now_ms = 1049
        self.assertFalse(
            self._session._timer_expired("tlp"),
            msg="Timer must not be expired one ms before its deadline.",
        )
        self._timer.now_ms = 1050
        self.assertTrue(
            self._session._timer_expired("tlp"),
            msg="Timer must be expired at its exact deadline.",
        )
        self._timer.now_ms = 1100
        self.assertTrue(
            self._session._timer_expired("tlp"),
            msg="Timer must remain expired after its deadline.",
        )

    def test__tcp__timers__armed_true_only_while_pending(self) -> None:
        """
        Ensure '_timer_armed' is True only while the timer is
        armed and has not yet fired (False unarmed, False once
        the deadline passes).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertFalse(
            self._session._timer_armed("rack"),
            msg="An unarmed timer must not report armed.",
        )
        self._session._arm_timer("rack", 30)
        self.assertTrue(
            self._session._timer_armed("rack"),
            msg="A pending timer must report armed.",
        )
        self._timer.now_ms = 1030
        self.assertFalse(
            self._session._timer_armed("rack"),
            msg="A fired timer must no longer report armed.",
        )

    def test__tcp__timers__cancel_clears_deadline(self) -> None:
        """
        Ensure '_cancel_timer' removes the deadline so the timer
        reports neither armed nor expired.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("persist", 100)
        self._session._cancel_timer("persist")
        self.assertNotIn(
            "persist",
            self._session._timer_deadlines,
            msg="_cancel_timer must drop the deadline entry.",
        )
        self.assertFalse(
            self._session._timer_armed("persist"),
            msg="A cancelled timer must not report armed.",
        )
        self.assertFalse(
            self._session._timer_expired("persist"),
            msg="A cancelled timer must not report expired.",
        )

    def test__tcp__timers__cancel_all_clears_map_and_handle(self) -> None:
        """
        Ensure '_cancel_all_timers' empties the deadline map and
        cancels and clears the coalesced service handle.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 100)
        self._session._arm_timer("delayed_ack", 40)
        handle = TimerHandle(method=MagicMock(), args=(), kwargs={}, deadline_ms=0, seq=0)
        self._session._service_handle = handle

        self._session._cancel_all_timers()

        self.assertEqual(
            self._session._timer_deadlines,
            {},
            msg="_cancel_all_timers must empty the deadline map.",
        )
        self._timer.cancel.assert_called_once_with(handle)
        self.assertIsNone(
            self._session._service_handle,
            msg="_cancel_all_timers must clear the service handle.",
        )

    def test__tcp__timers__rearm_overwrites_deadline(self) -> None:
        """
        Ensure re-arming an already-armed timer overwrites its
        deadline rather than keeping the stale one.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 100)
        self._timer.now_ms = 1050
        self._session._arm_timer("retransmit", 100)
        self.assertEqual(
            self._session._timer_deadlines["retransmit"],
            1150,
            msg="Re-arm must overwrite the deadline with the fresh now_ms + delay_ms.",
        )

    def test__tcp__timers__challenge_ack_gate_truth_table(self) -> None:
        """
        Ensure the challenge-ACK gate decision the
        '_send_challenge_ack' path makes is exactly
        'not _timer_armed("challenge_ack")': emit when unarmed,
        suppress while armed-and-unfired, emit again once the
        rate-limit window has elapsed (then re-arm).

        Reference: RFC 5961 §3 (challenge-ACK rate-limit gate).
        """

        # Unarmed -> the gate would emit (not armed).
        self.assertFalse(
            self._session._timer_armed("challenge_ack"),
            msg="Unarmed gate must read not-armed so the first challenge ACK is emitted.",
        )

        # Emit path arms the window.
        self._session._arm_timer("challenge_ack", 1000)
        self.assertTrue(
            self._session._timer_armed("challenge_ack"),
            msg="Within the rate-limit window the gate must read armed so further ACKs are suppressed.",
        )

        # One ms before the window elapses -> still suppressed.
        self._timer.now_ms = 1999
        self.assertTrue(
            self._session._timer_armed("challenge_ack"),
            msg="One ms before the window elapses the gate must still read armed.",
        )

        # At the window boundary -> the gate re-opens (emit again).
        self._timer.now_ms = 2000
        self.assertFalse(
            self._session._timer_armed("challenge_ack"),
            msg="At the rate-limit boundary the gate must read not-armed so a fresh challenge ACK is emitted.",
        )
