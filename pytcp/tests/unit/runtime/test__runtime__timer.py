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
        """

        self.assertTrue(
            self._timer.is_expired("never-registered"),
            msg="is_expired() must return True for a timer that was never registered.",
        )

    def test__timer__is_expired_false_while_counting_down(self) -> None:
        """
        Ensure 'is_expired()' returns False while the timer still has
        a positive timeout.
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
        """

        method = MagicMock(__name__="m")
        self._timer.register_method(method=method, delay=1, repeat_count=0)
        self._timer._subsystem_loop()
        method.assert_called_once_with()

    def test__timer__loop_purges_finished_tasks(self) -> None:
        """
        Ensure non-repeating tasks are removed from '_tasks' once they
        have fired (remaining_delay is 0 and no repeat cycle).
        """

        method = MagicMock(__name__="m")
        self._timer.register_method(method=method, delay=1, repeat_count=0)
        self._timer._subsystem_loop()
        self.assertEqual(
            self._timer._tasks,
            [],
            msg="_subsystem_loop must purge tasks that have fired and are not repeating.",
        )
