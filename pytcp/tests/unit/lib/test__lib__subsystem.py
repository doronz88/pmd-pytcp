#!/usr/bin/env python3

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
This module contains tests for the 'Subsystem' base class.

pytcp/tests/unit/lib/test__lib__subsystem.py

ver 3.0.4
"""


import io
import threading
from typing import override
from unittest import TestCase
from unittest.mock import patch

from pytcp.lib.subsystem import SUBSYSTEM_SLEEP_TIME__SEC, Subsystem


class _TestSubsystem(Subsystem):
    """
    A concrete 'Subsystem' subclass used only by the tests. Counts loop
    iterations and records whether the optional '_start' / '_stop' hooks
    were invoked, so lifecycle behaviour can be asserted without relying
    on real wall-clock timing.
    """

    _subsystem_name = "test-subsystem"

    def __init__(self, *, info: str | None = None) -> None:
        """
        Initialize the test subsystem, seeding the loop-iteration counter
        and the hook-invocation flags before delegating to the base.
        """

        self.loop_iterations = 0
        self.start_hook_called = False
        self.stop_hook_called = False
        self._loop_event = threading.Event()
        super().__init__(info=info)

    @override
    def _subsystem_loop(self) -> None:
        """
        Increment the iteration counter and, once, signal the test thread
        so it can request the subsystem to stop deterministically.
        """

        self.loop_iterations += 1
        self._loop_event.set()

    @override
    def _start(self) -> None:
        """
        Record that the optional '_start' hook fired so the test can
        verify it is wired through by 'Subsystem.start()'.
        """

        self.start_hook_called = True

    @override
    def _stop(self) -> None:
        """
        Record that the optional '_stop' hook fired so the test can
        verify it is wired through by 'Subsystem.stop()'.
        """

        self.stop_hook_called = True


class _HookOnlySubsystem(Subsystem):
    """
    A 'Subsystem' subclass that exits its loop immediately, so the tests
    can exercise the base-class '_start' / '_stop' pass-throughs without
    the concrete subclass overriding them.
    """

    _subsystem_name = "hook-only-subsystem"

    def __init__(self) -> None:
        """
        Initialize the hook-only subsystem and stop the loop up-front so
        '_subsystem_loop' is never invoked.
        """

        super().__init__()
        self._event__stop_subsystem.set()

    @override
    def _subsystem_loop(self) -> None:
        """
        Unreachable — the stop event is set before the thread starts.
        """


class TestSubsystemModuleConstants(TestCase):
    """
    The 'subsystem' module-level constant tests.
    """

    def test__subsystem__sleep_time_is_positive_float(self) -> None:
        """
        Ensure 'SUBSYSTEM_SLEEP_TIME__SEC' is a positive float so
        subsystems that use it as the poll cadence never busy-spin.
        """

        self.assertIsInstance(
            SUBSYSTEM_SLEEP_TIME__SEC,
            float,
            msg="SUBSYSTEM_SLEEP_TIME__SEC must be a float.",
        )
        self.assertGreater(
            SUBSYSTEM_SLEEP_TIME__SEC,
            0.0,
            msg="SUBSYSTEM_SLEEP_TIME__SEC must be strictly positive.",
        )

    def test__subsystem__sleep_time_matches_canonical_cadence(self) -> None:
        """
        Ensure the canonical poll cadence of 0.1 second is preserved;
        changing it would measurably shift every subsystem's latency and
        must be an intentional, reviewed change.
        """

        self.assertEqual(
            SUBSYSTEM_SLEEP_TIME__SEC,
            0.1,
            msg="SUBSYSTEM_SLEEP_TIME__SEC must remain the canonical 0.1 s cadence.",
        )


class TestSubsystemAbstractContract(TestCase):
    """
    The 'Subsystem' abstract-base-class contract tests.
    """

    def test__subsystem__cannot_be_instantiated_directly(self) -> None:
        """
        Ensure 'Subsystem' is abstract — instantiating it without
        overriding '_subsystem_loop' must raise 'TypeError'.
        """

        with self.assertRaises(TypeError):
            Subsystem()  # type: ignore[abstract]

    def test__subsystem__loop_stub_raises_not_implemented(self) -> None:
        """
        Ensure the abstract '_subsystem_loop' stub body itself raises
        'NotImplementedError' so a subclass that calls 'super()' into
        the default receives the canonical failure.
        """

        with patch("pytcp.lib.subsystem.log"):
            subsystem = _TestSubsystem()

        with self.assertRaises(NotImplementedError):
            Subsystem._subsystem_loop(subsystem)


class TestSubsystemInit(TestCase):
    """
    The 'Subsystem.__init__()' tests.
    """

    def test__subsystem__init_creates_stop_event(self) -> None:
        """
        Ensure '__init__' creates a fresh 'threading.Event' for the stop
        signal and that it starts cleared (subsystem is not yet stopping).
        """

        with patch("pytcp.lib.subsystem.log"):
            subsystem = _TestSubsystem()

        self.assertIsInstance(
            subsystem._event__stop_subsystem,
            threading.Event,
            msg="Subsystem.__init__ must create a 'threading.Event' for the stop signal.",
        )
        self.assertFalse(
            subsystem._event__stop_subsystem.is_set(),
            msg="The stop event must start cleared after '__init__'.",
        )

    def test__subsystem__init_logs_without_info(self) -> None:
        """
        Ensure '__init__' emits an 'Initializing <name>' log line on the
        'stack' channel when no 'info' argument is provided.
        """

        with patch("pytcp.lib.subsystem.log") as mock_log:
            _TestSubsystem()

        mock_log.assert_called_once_with(
            "stack",
            "Initializing test-subsystem",
        )

    def test__subsystem__init_logs_with_info(self) -> None:
        """
        Ensure '__init__' appends a bracketed info tag to the
        'Initializing ...' log line when the caller supplies one.
        """

        with patch("pytcp.lib.subsystem.log") as mock_log:
            _TestSubsystem(info="tap7")

        mock_log.assert_called_once_with(
            "stack",
            "Initializing test-subsystem [tap7]",
        )


class TestSubsystemLifecycle(TestCase):
    """
    The 'Subsystem.start()' / 'Subsystem.stop()' full-lifecycle tests.
    """

    def setUp(self) -> None:
        """
        Redirect 'pytcp.stack.LOG__OUTPUT' to an in-memory buffer so the
        real 'log()' calls driven from the worker thread do not pollute
        the test runner's stderr.
        """

        self._log_patch = patch("pytcp.stack.LOG__OUTPUT", io.StringIO())
        self._log_patch.start()

    def tearDown(self) -> None:
        """
        Restore the original log output stream.
        """

        self._log_patch.stop()

    def test__subsystem__start_runs_thread_and_fires_hooks(self) -> None:
        """
        Ensure 'start()' clears the stop event, launches a worker thread
        that drives '_subsystem_loop()' at least once, and invokes the
        optional '_start()' hook synchronously after thread spawn.
        """

        subsystem = _TestSubsystem()

        try:
            subsystem.start()

            self.assertTrue(
                subsystem._loop_event.wait(timeout=2.0),
                msg="The subsystem loop must execute at least one iteration after start().",
            )
            self.assertTrue(
                subsystem.start_hook_called,
                msg="Subsystem.start() must invoke the '_start' hook after spawning the thread.",
            )
        finally:
            subsystem.stop()

    def test__subsystem__stop_signals_event_and_fires_hook(self) -> None:
        """
        Ensure 'stop()' sets the stop event (terminating the loop) and
        invokes the optional '_stop()' hook. A join after stop must
        complete promptly so the thread exits cleanly.
        """

        subsystem = _TestSubsystem()
        subsystem.start()

        self.assertTrue(
            subsystem._loop_event.wait(timeout=2.0),
            msg="Precondition: the subsystem loop must be running before stop().",
        )

        subsystem.stop()

        self.assertTrue(
            subsystem._event__stop_subsystem.is_set(),
            msg="Subsystem.stop() must set the stop event.",
        )
        self.assertTrue(
            subsystem.stop_hook_called,
            msg="Subsystem.stop() must invoke the '_stop' hook.",
        )

    def test__subsystem__thread_exits_on_stop(self) -> None:
        """
        Ensure the worker thread observes the stop event and exits the
        loop. Tracked by joining every currently-alive non-main thread
        (besides threading internals) after 'stop()'.
        """

        subsystem = _TestSubsystem()
        subsystem.start()
        self.assertTrue(
            subsystem._loop_event.wait(timeout=2.0),
            msg="Precondition: the subsystem loop must be running before stop().",
        )

        subsystem.stop()

        deadline = threading.Event()

        def _watchdog() -> None:
            """
            Release the deadline once every subsystem-spawned thread has
            joined or the 2-second ceiling has elapsed.
            """

            for thread in list(threading.enumerate()):
                if thread is threading.main_thread():
                    continue
                if thread is threading.current_thread():
                    continue
                thread.join(timeout=2.0)
            deadline.set()

        threading.Thread(target=_watchdog).start()

        self.assertTrue(
            deadline.wait(timeout=3.0),
            msg="All subsystem worker threads must exit within a few seconds of stop().",
        )


class TestSubsystemDefaultHooks(TestCase):
    """
    The 'Subsystem' default '_start' / '_stop' no-op hook tests.
    """

    def test__subsystem__default_start_hook_is_noop(self) -> None:
        """
        Ensure the base-class '_start' hook is a no-op that raises
        nothing when invoked. Guards the contract that concrete
        subclasses can skip overriding it.
        """

        with patch("pytcp.lib.subsystem.log"):
            subsystem = _HookOnlySubsystem()

        try:
            subsystem._start()
        except Exception as exc:  # pragma: no cover - fail path
            self.fail(f"Subsystem._start() base implementation must be a silent no-op; raised {exc!r}.")

    def test__subsystem__default_stop_hook_is_noop(self) -> None:
        """
        Ensure the base-class '_stop' hook is a no-op that raises
        nothing when invoked.
        """

        with patch("pytcp.lib.subsystem.log"):
            subsystem = _HookOnlySubsystem()

        try:
            subsystem._stop()
        except Exception as exc:  # pragma: no cover - fail path
            self.fail(f"Subsystem._stop() base implementation must be a silent no-op; raised {exc!r}.")


class TestSubsystemThreadEarlyExit(TestCase):
    """
    The '_thread__subsystem' worker-thread early-exit test.
    """

    def test__subsystem__thread_exits_when_event_preset(self) -> None:
        """
        Ensure the worker function walks past the while-loop when the
        stop event is already set, logs 'Started' / 'Stopped' markers,
        and never invokes '_subsystem_loop'. Exercises the loop-condition
        false branch directly without relying on thread scheduling.
        """

        with patch("pytcp.lib.subsystem.log"):
            subsystem = _TestSubsystem()
        subsystem._event__stop_subsystem.set()

        with patch("pytcp.lib.subsystem.log") as mock_log:
            subsystem._thread__subsystem()

        self.assertEqual(
            subsystem.loop_iterations,
            0,
            msg="_subsystem_loop must not run when the stop event is already set.",
        )
        logged_messages = [call.args[1] for call in mock_log.call_args_list]
        self.assertIn(
            "Started test-subsystem",
            logged_messages,
            msg="The worker must emit the 'Started' marker before checking the stop event.",
        )
        self.assertIn(
            "Stopped test-subsystem",
            logged_messages,
            msg="The worker must emit the 'Stopped' marker after the loop exits.",
        )
