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
This module contains tests for the 'Timer' subsystem and its
'TimerTask' helper.

pytcp/tests/unit/runtime/test__runtime__timer.py

ver 3.0.4
"""

from unittest import TestCase
from unittest.mock import MagicMock, patch

from pytcp.runtime.timer import Timer, TimerTask


class TestTimerTaskTick(TestCase):
    """
    The 'TimerTask.tick()' countdown tests.
    """

    def test__timer__task_tick_decrements_remaining_delay(self) -> None:
        """
        Ensure each 'tick()' call decrements '_remaining_delay' by 1
        until it reaches zero — the countdown drives method execution.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        task = TimerTask(
            method=method,
            args=[],
            kwargs={},
            delay=3,
            delay_exp=False,
            repeat_count=0,
            stop_condition=None,
        )
        task.tick()
        self.assertEqual(
            task.remaining_delay,
            2,
            msg="TimerTask.tick() must decrement _remaining_delay by 1.",
        )

    def test__timer__task_tick_invokes_method_at_zero(self) -> None:
        """
        Ensure the registered method fires exactly when the countdown
        hits zero, with the stored args and kwargs forwarded verbatim.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        task = TimerTask(
            method=method,
            args=[1, 2],
            kwargs={"k": "v"},
            delay=1,
            delay_exp=False,
            repeat_count=0,
            stop_condition=None,
        )
        task.tick()
        method.assert_called_once_with(1, 2, k="v")

    def test__timer__task_tick_not_yet_at_zero_skips_method(self) -> None:
        """
        Ensure the method does not fire while '_remaining_delay' is
        still non-zero after decrement — only the final tick triggers.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        task = TimerTask(
            method=method,
            args=[],
            kwargs={},
            delay=3,
            delay_exp=False,
            repeat_count=0,
            stop_condition=None,
        )
        task.tick()
        method.assert_not_called()

    def test__timer__task_tick_stop_condition_aborts_countdown(self) -> None:
        """
        Ensure a 'stop_condition' that returns True zeros the remaining
        delay and prevents the method from ever firing.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        task = TimerTask(
            method=method,
            args=[],
            kwargs={},
            delay=5,
            delay_exp=False,
            repeat_count=-1,
            stop_condition=lambda: True,
        )
        task.tick()
        self.assertEqual(
            task.remaining_delay,
            0,
            msg="An active stop_condition must zero the remaining delay.",
        )
        method.assert_not_called()

    def test__timer__task_tick_infinite_repeat_resets_delay(self) -> None:
        """
        Ensure 'repeat_count=-1' (infinite) causes '_remaining_delay'
        to reset to the original delay after each firing, letting the
        method run indefinitely.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        task = TimerTask(
            method=method,
            args=[],
            kwargs={},
            delay=2,
            delay_exp=False,
            repeat_count=-1,
            stop_condition=None,
        )
        task.tick()
        task.tick()
        self.assertEqual(
            method.call_count,
            1,
            msg="After delay=2 ticks the method must have fired exactly once.",
        )
        self.assertEqual(
            task.remaining_delay,
            2,
            msg="With infinite repeat, _remaining_delay must reset to the original delay after firing.",
        )

    def test__timer__task_tick_finite_repeat_decrements(self) -> None:
        """
        Ensure a finite 'repeat_count' decreases each time the method
        fires so the task eventually stops re-arming itself.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        task = TimerTask(
            method=method,
            args=[],
            kwargs={},
            delay=1,
            delay_exp=False,
            repeat_count=2,
            stop_condition=None,
        )
        task.tick()
        task.tick()
        task.tick()
        self.assertEqual(
            method.call_count,
            3,
            msg="A task with repeat_count=2 must fire a total of 3 times (initial + 2 repeats).",
        )

    def test__timer__task_tick_exponential_backoff(self) -> None:
        """
        Ensure 'delay_exp=True' doubles the remaining delay after each
        firing — the exponential-backoff schedule used by retransmits.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        task = TimerTask(
            method=method,
            args=[],
            kwargs={},
            delay=2,
            delay_exp=True,
            repeat_count=-1,
            stop_condition=None,
        )
        task.tick()
        task.tick()
        # First firing -> next delay is 2 * (1 << 0) = 2.
        self.assertEqual(
            task.remaining_delay,
            2,
            msg="After the first firing with delay_exp, remaining_delay must be delay * 2**0.",
        )


class TestTimerRegisterTimer(TestCase):
    """
    The 'Timer.register_timer' / 'Timer.is_expired' tests.
    """

    def setUp(self) -> None:
        """
        Suppress subsystem-init logging and build a fresh 'Timer'.
        """

        self._log_patch = patch("pytcp.runtime.timer.log")
        self._log_patch.start()
        self._subsystem_log_patch = patch("pytcp.runtime.subsystem.log")
        self._subsystem_log_patch.start()
        self._timer = Timer()

    def tearDown(self) -> None:
        """
        Remove the log patches.
        """

        self._log_patch.stop()
        self._subsystem_log_patch.stop()

    def test__timer__register_timer_stores_timeout(self) -> None:
        """
        Ensure 'register_timer()' stores the caller-supplied timeout
        keyed by name in the internal '_timers' dict.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer.register_timer(name="t1", timeout=10)
        self.assertEqual(
            self._timer._timers["t1"],
            10,
            msg="register_timer() must store the timeout verbatim in _timers.",
        )

    def test__timer__is_expired_true_for_missing(self) -> None:
        """
        Ensure 'is_expired()' returns True for a timer that was never
        registered — the absence case is canonical "expired".

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertTrue(
            self._timer.is_expired("never-registered"),
            msg="is_expired() must return True for a timer that was never registered.",
        )

    def test__timer__is_expired_false_while_counting_down(self) -> None:
        """
        Ensure 'is_expired()' returns False while the timer still has
        a positive timeout.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer.register_timer(name="t1", timeout=5)
        self.assertFalse(
            self._timer.is_expired("t1"),
            msg="is_expired() must return False while the timer has a positive timeout.",
        )

    def test__timer__is_expired_true_after_timeout_zeroed(self) -> None:
        """
        Ensure 'is_expired()' returns True once the timeout has been
        zeroed (simulating countdown completion).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer.register_timer(name="t1", timeout=1)
        self._timer._timers["t1"] = 0
        self.assertTrue(
            self._timer.is_expired("t1"),
            msg="is_expired() must return True when the timeout has decayed to 0.",
        )


class TestTimerRegisterMethod(TestCase):
    """
    The 'Timer.register_method' tests.
    """

    def setUp(self) -> None:
        """
        Suppress logging and build a fresh 'Timer'.
        """

        self._log_patch = patch("pytcp.runtime.timer.log")
        self._log_patch.start()
        self._subsystem_log_patch = patch("pytcp.runtime.subsystem.log")
        self._subsystem_log_patch.start()
        self._timer = Timer()

    def tearDown(self) -> None:
        """
        Remove the log patches.
        """

        self._log_patch.stop()
        self._subsystem_log_patch.stop()

    def test__timer__register_method_appends_task(self) -> None:
        """
        Ensure 'register_method()' appends a new 'TimerTask' to the
        internal '_tasks' list.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock(__name__="m")
        self._timer.register_method(method=method, delay=5)
        self.assertEqual(
            len(self._timer._tasks),
            1,
            msg="register_method() must append exactly one TimerTask.",
        )
        self.assertIsInstance(
            self._timer._tasks[0],
            TimerTask,
            msg="The appended entry must be a TimerTask instance.",
        )

    def test__timer__register_method_defaults(self) -> None:
        """
        Ensure the default 'args' / 'kwargs' arguments materialize as
        empty list / empty dict inside the stored 'TimerTask'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock(__name__="m")
        self._timer.register_method(method=method)
        task = self._timer._tasks[0]
        self.assertEqual(task._args, [], msg="Default args must be an empty list.")
        self.assertEqual(task._kwargs, {}, msg="Default kwargs must be an empty dict.")


class TestTimerSubsystemLoop(TestCase):
    """
    The 'Timer._subsystem_loop' per-tick behavior tests.
    """

    def setUp(self) -> None:
        """
        Suppress logging, patch 'time.sleep' to eliminate real delays,
        and build a fresh 'Timer'.
        """

        self._log_patch = patch("pytcp.runtime.timer.log")
        self._log_patch.start()
        self._subsystem_log_patch = patch("pytcp.runtime.subsystem.log")
        self._subsystem_log_patch.start()
        self._sleep_patch = patch("pytcp.runtime.timer.time.sleep")
        self._sleep_patch.start()
        self._timer = Timer()

    def tearDown(self) -> None:
        """
        Remove every patch.
        """

        self._log_patch.stop()
        self._subsystem_log_patch.stop()
        self._sleep_patch.stop()

    def test__timer__loop_decrements_registered_timers(self) -> None:
        """
        Ensure each loop iteration decrements every registered timer
        by 1.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer.register_timer(name="t1", timeout=3)
        self._timer._subsystem_loop()
        self.assertEqual(
            self._timer._timers["t1"],
            2,
            msg="_subsystem_loop must decrement every registered timer by 1.",
        )

    def test__timer__loop_purges_expired_timers(self) -> None:
        """
        Ensure timers whose timeout reaches 0 are removed from the
        '_timers' dict on the iteration that zeros them.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer.register_timer(name="t1", timeout=1)
        self._timer._subsystem_loop()
        self.assertNotIn(
            "t1",
            self._timer._timers,
            msg="_subsystem_loop must purge timers once their timeout reaches 0.",
        )

    def test__timer__loop_ticks_registered_tasks(self) -> None:
        """
        Ensure each loop iteration calls 'tick()' on every registered
        task.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock(__name__="m")
        self._timer.register_method(method=method, delay=1, repeat_count=0)
        self._timer._subsystem_loop()
        method.assert_called_once_with()

    def test__timer__loop_purges_finished_tasks(self) -> None:
        """
        Ensure non-repeating tasks are removed from '_tasks' once they
        have fired (remaining_delay is 0 and no repeat cycle).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock(__name__="m")
        self._timer.register_method(method=method, delay=1, repeat_count=0)
        self._timer._subsystem_loop()
        self.assertEqual(
            self._timer._tasks,
            [],
            msg="_subsystem_loop must purge tasks that have fired and are not repeating.",
        )


class TestTimerNowMs(TestCase):
    """
    The 'Timer.now_ms' property tests.
    """

    def test__timer__now_ms_returns_int(self) -> None:
        """
        Ensure 'now_ms' returns an int (milliseconds since the
        monotonic-clock epoch), the type the RFC 6298 RTO
        sampling code in 'TcpSession' expects.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.runtime.subsystem.log"):
            timer = Timer()

        self.assertIsInstance(
            timer.now_ms,
            int,
            msg="Timer.now_ms must return an int (milliseconds).",
        )

    def test__timer__now_ms_is_monotonic(self) -> None:
        """
        Ensure two successive 'now_ms' reads return values that
        never decrease — backed by 'time.monotonic_ns()' so the
        property is wall-clock-adjustment safe.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.runtime.subsystem.log"):
            timer = Timer()

        t0 = timer.now_ms
        t1 = timer.now_ms
        self.assertGreaterEqual(
            t1,
            t0,
            msg=f"Timer.now_ms must be monotonic; got t0={t0}, t1={t1}.",
        )

    def test__timer__now_ms_uses_monotonic_ns(self) -> None:
        """
        Ensure 'now_ms' divides 'time.monotonic_ns()' by 1_000_000
        — the documented backing primitive. Pinned via patching
        so a future regression that switched to 'time.time_ns()'
        (wall-clock, jump-prone) is caught.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.runtime.subsystem.log"):
            timer = Timer()

        with patch("pytcp.runtime.timer.time.monotonic_ns", return_value=42_123_456_789):
            self.assertEqual(
                timer.now_ms,
                42_123,
                msg="now_ms must divide monotonic_ns() by 1_000_000.",
            )


class TestTimerUnregister(TestCase):
    """
    The 'Timer.unregister_timers_with_prefix' / 'Timer.unregister_method' tests.
    """

    def setUp(self) -> None:
        """
        Build a Timer in mocked-log mode so registration log lines
        do not leak to stderr.
        """

        self._log_patch = patch("pytcp.runtime.subsystem.log")
        self._log_patch.start()
        self.addCleanup(self._log_patch.stop)
        self._timer_log_patch = patch("pytcp.runtime.timer.log")
        self._timer_log_patch.start()
        self.addCleanup(self._timer_log_patch.stop)

        self._timer = Timer()

    def test__timer__unregister_timers_with_prefix_drops_matching(self) -> None:
        """
        Ensure 'unregister_timers_with_prefix' removes every
        named delay timer whose name starts with the prefix,
        leaving all other entries intact.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer.register_timer(name="session-1-time_wait", timeout=100)
        self._timer.register_timer(name="session-1-delayed_ack", timeout=50)
        self._timer.register_timer(name="session-2-time_wait", timeout=200)
        self._timer.register_timer(name="rate_limit", timeout=1000)

        self._timer.unregister_timers_with_prefix("session-1-")

        self.assertEqual(
            set(self._timer._timers.keys()),
            {"session-2-time_wait", "rate_limit"},
            msg="Only timers prefixed with 'session-1-' must be dropped.",
        )

    def test__timer__unregister_timers_with_prefix_empty_match(self) -> None:
        """
        Ensure 'unregister_timers_with_prefix' is a no-op when no
        registered name matches — does not raise, does not affect
        other entries.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._timer.register_timer(name="rate_limit", timeout=1000)

        self._timer.unregister_timers_with_prefix("session-")

        self.assertEqual(
            set(self._timer._timers.keys()),
            {"rate_limit"},
            msg="No-match prefix must leave the registry unchanged.",
        )

    def test__timer__unregister_method_drops_matching(self) -> None:
        """
        Ensure 'unregister_method' removes every 'TimerTask'
        whose stored method equals the supplied callable. Other
        registered tasks survive.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method_a = MagicMock()
        method_b = MagicMock()
        method_a.__name__ = "method_a"
        method_b.__name__ = "method_b"

        self._timer.register_method(method=method_a, delay=10)
        self._timer.register_method(method=method_a, delay=20)
        self._timer.register_method(method=method_b, delay=30)

        self._timer.unregister_method(method_a)

        self.assertEqual(
            len(self._timer._tasks),
            1,
            msg="Both method_a registrations must be dropped, method_b retained.",
        )
        self.assertIs(
            self._timer._tasks[0].method,
            method_b,
            msg="The surviving task must be the one registered with method_b.",
        )

    def test__timer__unregister_method_no_match(self) -> None:
        """
        Ensure 'unregister_method' is a no-op when no task's
        method matches — does not raise, does not affect other
        entries.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        method = MagicMock()
        method.__name__ = "method"
        other = MagicMock()
        other.__name__ = "other"

        self._timer.register_method(method=method, delay=10)

        self._timer.unregister_method(other)

        self.assertEqual(
            len(self._timer._tasks),
            1,
            msg="No-match unregister must leave the registry unchanged.",
        )


class TestTimerAsserts(TestCase):
    """
    The 'TimerTask' / 'Timer.register_timer' input-assertion tests.
    """

    def test__timer__task_delay_zero_rejected(self) -> None:
        """
        Ensure 'TimerTask(delay=0, ...)' raises AssertionError.
        delay=0 has no defensible semantics (the legacy tick
        decrement-before-check would make the method never fire),
        and no production caller uses it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError) as ctx:
            TimerTask(
                method=MagicMock(),
                args=[],
                kwargs={},
                delay=0,
                delay_exp=False,
                repeat_count=0,
                stop_condition=None,
            )

        self.assertIn(
            "delay must be >= 1",
            str(ctx.exception),
            msg="The assertion message must name the contract violation.",
        )

    def test__timer__task_delay_negative_rejected(self) -> None:
        """
        Ensure 'TimerTask(delay=-1, ...)' raises AssertionError
        — same contract as delay=0.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(AssertionError):
            TimerTask(
                method=MagicMock(),
                args=[],
                kwargs={},
                delay=-1,
                delay_exp=False,
                repeat_count=0,
                stop_condition=None,
            )

    def test__timer__register_timer_timeout_zero_rejected(self) -> None:
        """
        Ensure 'register_timer(timeout=0)' raises AssertionError.
        timeout=0 would expire the timer on the very next tick
        which no production caller wants.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pytcp.runtime.subsystem.log"), patch("pytcp.runtime.timer.log"):
            timer = Timer()

        with self.assertRaises(AssertionError) as ctx:
            timer.register_timer(name="any", timeout=0)

        self.assertIn(
            "timeout must be >= 1",
            str(ctx.exception),
            msg="The assertion message must name the contract violation.",
        )


class TestTimerTaskExponentialFactor(TestCase):
    """
    The '_delay_exp_factor' increment-gating tests (factor must
    increment only when 'delay_exp=True').
    """

    def test__timer__non_exp_task_does_not_grow_factor(self) -> None:
        """
        Ensure a 'TimerTask' with 'delay_exp=False' never
        increments '_delay_exp_factor' across multiple
        execution cycles. Guards against the pre-fix behaviour
        where the factor grew unboundedly even for tasks that
        never read it.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        task = TimerTask(
            method=MagicMock(),
            args=[],
            kwargs={},
            delay=1,
            delay_exp=False,
            repeat_count=3,
            stop_condition=None,
        )

        for _ in range(3):
            task.tick()  # decrement to 0 + execute + reset

        self.assertEqual(
            task._delay_exp_factor,
            0,
            msg="delay_exp=False tasks must keep _delay_exp_factor at 0.",
        )

    def test__timer__exp_task_grows_factor_each_iteration(self) -> None:
        """
        Ensure a 'TimerTask' with 'delay_exp=True' increments
        '_delay_exp_factor' on every reset, producing the
        2**iteration backoff pattern in '_remaining_delay'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        task = TimerTask(
            method=MagicMock(),
            args=[],
            kwargs={},
            delay=1,
            delay_exp=True,
            repeat_count=3,
            stop_condition=None,
        )

        task.tick()  # 1 → 0 → execute, factor: 0 → 1
        self.assertEqual(task._delay_exp_factor, 1)

        task.tick()  # 2 → 1 (after reset to 1*2=2 then -1)
        task.tick()  # 1 → 0 → execute, factor: 1 → 2
        self.assertEqual(task._delay_exp_factor, 2)
