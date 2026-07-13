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
This module contains tests for the loop-native 'Timer' — the
pure-asyncio rewrite over 'loop.call_at' ('docs/refactor/
pure_asyncio.md'): no worker, no heap, no lock. The public surface
('call_later' / 'call_periodic' / 'cancel' / 'now_ms' / 'start' /
'stop') is unchanged from the threaded design.

The firing tests drive the loop deterministically: the fire wrapper
'Timer._fire(handle, deadline)' is invoked directly where scheduling
mechanics are under test, and short real delays are used only where
the loop integration itself is the subject.

pmd_pytcp/tests/unit/runtime/test__runtime__timer.py

ver 3.0.7
"""

from __future__ import annotations

from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import MagicMock, patch

import asyncio

from pmd_pytcp.runtime.timer import Timer, TimerHandle


class _TimerTestCase(IsolatedAsyncioTestCase):
    """
    Shared fixture: a started 'Timer' with logging suppressed.
    """

    async def asyncSetUp(self) -> None:
        """
        Suppress timer logging and build + start a fresh 'Timer' on
        the test loop.
        """

        self._timer_log_patch = patch("pmd_pytcp.runtime.timer.log")
        self._timer_log = self._timer_log_patch.start()
        self.addCleanup(self._timer_log_patch.stop)

        self._timer = Timer()
        self._timer.start()

    async def asyncTearDown(self) -> None:
        """
        Stop the timer so no armed loop entry survives the test.
        """

        self._timer.stop()


class TestTimerNowMs(TestCase):
    """
    The 'Timer.now_ms' property tests.
    """

    def setUp(self) -> None:
        """
        Suppress timer logging and build a fresh 'Timer' (no loop
        needed — 'now_ms' is a pure clock read).
        """

        self._timer_log_patch = patch("pmd_pytcp.runtime.timer.log")
        self._timer_log_patch.start()
        self.addCleanup(self._timer_log_patch.stop)

        self._timer = Timer()

    def test__timer__now_ms_returns_int(self) -> None:
        """
        Ensure 'now_ms' returns an int (milliseconds since the
        monotonic-clock epoch), the type the RFC 6298 RTO sampling
        code stores per segment.

        Reference: RFC 6298 §2 (RTT measurement).
        """

        self.assertIsInstance(
            self._timer.now_ms,
            int,
            msg="now_ms must return an int millisecond count.",
        )

    def test__timer__now_ms_is_monotonic(self) -> None:
        """
        Ensure successive 'now_ms' reads never go backwards — the
        property is backed by 'time.monotonic_ns' so wall-clock
        adjustments cannot skew RTT samples.

        Reference: RFC 6298 §2 (RTT measurement).
        """

        first = self._timer.now_ms
        second = self._timer.now_ms
        self.assertGreaterEqual(
            second,
            first,
            msg="now_ms must be monotonically non-decreasing.",
        )

    def test__timer__now_ms_derives_from_monotonic_ns(self) -> None:
        """
        Ensure 'now_ms' is exactly 'time.monotonic_ns() // 1_000_000'
        so every consumer sees the same millisecond epoch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch(
            "pmd_pytcp.runtime.timer.time.monotonic_ns",
            return_value=1_234_567_890_123,
        ):
            self.assertEqual(
                self._timer.now_ms,
                1_234_567,
                msg="now_ms must be monotonic_ns floored to milliseconds.",
            )


class TestTimerRegistrationGuards(_TimerTestCase):
    """
    The 'call_later' / 'call_periodic' argument-guard tests.
    """

    async def test__timer__call_later_rejects_negative_delay(self) -> None:
        """
        Ensure 'call_later' asserts on a negative delay — a negative
        deadline is always a caller bug, not a "fire immediately"
        request.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            self._timer.call_later(-1, MagicMock())

    async def test__timer__call_periodic_rejects_zero_period(self) -> None:
        """
        Ensure 'call_periodic' asserts on a zero period — a 0 ms
        period would spin the loop re-arming itself forever.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            self._timer.call_periodic(0, MagicMock())

    async def test__timer__call_later_returns_tracked_handle(self) -> None:
        """
        Ensure 'call_later' returns a 'TimerHandle' and tracks it on
        the live-handle set so 'stop()' can tear it down.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handle = self._timer.call_later(1_000, MagicMock())

        self.assertIsInstance(
            handle,
            TimerHandle,
            msg="call_later must return a TimerHandle.",
        )
        self.assertIn(
            handle,
            self._timer._handles,
            msg="A scheduled handle must be tracked for stop() teardown.",
        )
        self.assertIsNone(
            handle.period_ms,
            msg="A call_later handle must not carry a period.",
        )

    async def test__timer__call_periodic_handle_carries_period(self) -> None:
        """
        Ensure 'call_periodic' stamps the period onto the handle —
        the fire wrapper re-arms from it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handle = self._timer.call_periodic(250, MagicMock())

        self.assertEqual(
            handle.period_ms,
            250,
            msg="A call_periodic handle must carry its period.",
        )


class TestTimerOneShotFire(_TimerTestCase):
    """
    The one-shot 'call_later' firing tests.
    """

    async def test__timer__call_later_fires_after_delay(self) -> None:
        """
        Ensure a one-shot registration fires exactly once after its
        delay elapses on the real loop.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        callback = MagicMock()
        self._timer.call_later(10, callback)

        await asyncio.sleep(0.05)

        callback.assert_called_once_with()

    async def test__timer__call_later_passes_args_and_kwargs(self) -> None:
        """
        Ensure positional and keyword arguments registered with the
        entry are forwarded verbatim to the callback.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        callback = MagicMock()
        handle = self._timer.call_later(10, callback, 1, "two", key="value")

        self._timer._fire(handle, 0.0)

        callback.assert_called_once_with(1, "two", key="value")

    async def test__timer__one_shot_untracked_after_fire(self) -> None:
        """
        Ensure a fired one-shot handle leaves the live-handle set so
        the set cannot grow without bound over a long-lived stack.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handle = self._timer.call_later(10, MagicMock())

        self._timer._fire(handle, 0.0)

        self.assertNotIn(
            handle,
            self._timer._handles,
            msg="A fired one-shot handle must be untracked.",
        )

    async def test__timer__handler_exception_logged_and_swallowed(self) -> None:
        """
        Ensure a raising callback is logged and swallowed — one bad
        handler must not unwind the loop callback and take other
        timers down with it (same policy as the threaded worker).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        def _boom() -> None:
            raise RuntimeError("boom")

        handle = self._timer.call_later(10, _boom)

        self._timer._fire(handle, 0.0)  # must not raise

        logged = " ".join(str(call_args) for call_args in self._timer_log.call_args_list)
        self.assertIn(
            "Handler raised",
            logged,
            msg="A raising handler must be logged on the 'timer' channel.",
        )


class TestTimerPeriodicFire(_TimerTestCase):
    """
    The periodic 'call_periodic' firing tests.
    """

    async def test__timer__call_periodic_fires_repeatedly(self) -> None:
        """
        Ensure a periodic registration keeps firing every period on
        the real loop until cancelled.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        callback = MagicMock()
        handle = self._timer.call_periodic(10, callback)

        await asyncio.sleep(0.06)
        self._timer.cancel(handle)

        self.assertGreaterEqual(
            callback.call_count,
            2,
            msg="A periodic entry must fire repeatedly until cancelled.",
        )

    async def test__timer__periodic_rearms_at_absolute_deadline(self) -> None:
        """
        Ensure the fire wrapper re-arms a periodic entry by advancing
        the ABSOLUTE deadline by exactly one period ('deadline +
        period'), not by 'now + period' — the interval-based re-arm
        is what keeps a slow callback from drifting the cadence.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handle = self._timer.call_periodic(100, MagicMock())
        loop = asyncio.get_running_loop()

        deadline = loop.time()  # pretend this fire was due exactly now
        self._timer._fire(handle, deadline)

        assert handle._loop_handle is not None
        self.assertAlmostEqual(
            handle._loop_handle.when(),
            deadline + 0.1,
            places=6,
            msg="The periodic re-arm must land at deadline + period (drift-free).",
        )

    async def test__timer__periodic_stays_tracked_after_fire(self) -> None:
        """
        Ensure a periodic handle remains on the live-handle set after
        a fire so 'stop()' can still tear it down.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handle = self._timer.call_periodic(100, MagicMock())

        self._timer._fire(handle, asyncio.get_running_loop().time())

        self.assertIn(
            handle,
            self._timer._handles,
            msg="A live periodic handle must stay tracked across fires.",
        )
        self._timer.cancel(handle)

    async def test__timer__periodic_survives_handler_exception(self) -> None:
        """
        Ensure a raising periodic callback is re-armed anyway — the
        exception policy (log + swallow) must not silently kill the
        periodic train.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        def _boom() -> None:
            raise RuntimeError("boom")

        handle = self._timer.call_periodic(100, _boom)

        self._timer._fire(handle, asyncio.get_running_loop().time())

        self.assertIn(
            handle,
            self._timer._handles,
            msg="A periodic entry must survive its handler raising.",
        )
        self._timer.cancel(handle)


class TestTimerCancel(_TimerTestCase):
    """
    The 'Timer.cancel' tests.
    """

    async def test__timer__cancel_prevents_fire(self) -> None:
        """
        Ensure a cancelled one-shot entry never fires even after its
        delay elapses.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        callback = MagicMock()
        handle = self._timer.call_later(10, callback)

        self._timer.cancel(handle)
        await asyncio.sleep(0.05)

        callback.assert_not_called()

    async def test__timer__cancel_untracks_handle(self) -> None:
        """
        Ensure 'cancel' removes the handle from the live-handle set
        and marks it cancelled.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handle = self._timer.call_later(1_000, MagicMock())

        self._timer.cancel(handle)

        self.assertTrue(
            handle.cancelled,
            msg="cancel() must mark the handle cancelled.",
        )
        self.assertNotIn(
            handle,
            self._timer._handles,
            msg="cancel() must untrack the handle.",
        )

    async def test__timer__cancel_is_idempotent(self) -> None:
        """
        Ensure double-cancel and cancel-after-fire are silent no-ops.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        handle = self._timer.call_later(10, MagicMock())
        self._timer.cancel(handle)
        self._timer.cancel(handle)  # must not raise

        fired = self._timer.call_later(10, MagicMock())
        self._timer._fire(fired, 0.0)
        self._timer.cancel(fired)  # must not raise

    async def test__timer__cancelled_periodic_not_rearmed_by_late_fire(self) -> None:
        """
        Ensure a fire that races a cancellation (the loop callback was
        already queued when 'cancel' ran) neither invokes the callback
        nor re-arms the periodic entry — the 'cancelled' flag is the
        tombstone the fire wrapper honours.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        callback = MagicMock()
        handle = self._timer.call_periodic(100, callback)
        self._timer.cancel(handle)

        self._timer._fire(handle, asyncio.get_running_loop().time())

        callback.assert_not_called()
        self.assertNotIn(
            handle,
            self._timer._handles,
            msg="A cancelled handle must not be re-tracked by a late fire.",
        )


class TestTimerLifecycle(_TimerTestCase):
    """
    The 'Timer.start()' / 'Timer.stop()' lifecycle tests.
    """

    async def test__timer__start_binds_running_loop(self) -> None:
        """
        Ensure 'start()' binds the timer to the caller's running loop
        so later registrations from sync call sites schedule on it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIs(
            self._timer._loop,
            asyncio.get_running_loop(),
            msg="start() must bind the running loop.",
        )

    async def test__timer__stop_cancels_outstanding_handles(self) -> None:
        """
        Ensure 'stop()' cancels every outstanding entry — a stopped
        stack must not fire stale callbacks (the TCP RTO / delayed-ACK
        handlers would touch torn-down state).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        callbacks = [MagicMock() for _ in range(3)]
        handles = [self._timer.call_later(10, callback) for callback in callbacks]
        periodic = self._timer.call_periodic(10, MagicMock())

        self._timer.stop()
        await asyncio.sleep(0.05)

        for callback in callbacks:
            callback.assert_not_called()
        for handle in [*handles, periodic]:
            self.assertTrue(
                handle.cancelled,
                msg="stop() must mark every outstanding handle cancelled.",
            )
        self.assertEqual(
            len(self._timer._handles),
            0,
            msg="stop() must clear the live-handle set.",
        )

    async def test__timer__schedule_before_start_uses_running_loop(self) -> None:
        """
        Ensure a registration made before 'start()' (boot-time
        subsystem construction) still schedules — '_get_loop' falls
        back to the currently running loop.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        timer = Timer()
        callback = MagicMock()
        timer.call_later(10, callback)

        await asyncio.sleep(0.05)

        callback.assert_called_once_with()
        timer.stop()
