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
This module contains tests for the 'Subsystem' base class — the
task-based pure-asyncio variant ('docs/refactor/pure_asyncio.md'):
'start()' spawns an 'asyncio.Task' on the running loop, 'stop()'
sets the stop event + cancels the task, and 'wait_stopped()'
awaits the worker's actual exit.

pmd_pytcp/tests/unit/runtime/test__runtime__subsystem.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import io
from typing_extensions import override
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import patch

from pmd_pytcp.runtime.subsystem import SUBSYSTEM_SLEEP_TIME__SEC, Subsystem


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
        self._loop_event = asyncio.Event()
        super().__init__(info=info)

    @override
    async def _subsystem_loop(self) -> None:
        """
        Increment the iteration counter, signal the test coroutine so it
        can request the subsystem to stop deterministically, and yield
        the loop so the base wrapper's stop-event check is reachable.
        """

        self.loop_iterations += 1
        self._loop_event.set()
        await asyncio.sleep(0)

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
    async def _subsystem_loop(self) -> None:
        """
        Unreachable — the stop event is set before the task starts.
        """


class TestSubsystemModuleConstants(TestCase):
    """
    The 'subsystem' module-level constant tests.
    """

    def test__subsystem__sleep_time_is_positive_float(self) -> None:
        """
        Ensure 'SUBSYSTEM_SLEEP_TIME__SEC' is a positive float so
        subsystems that use it as the poll cadence never busy-spin.

        Reference: PyTCP test infrastructure (no RFC clause).
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

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            SUBSYSTEM_SLEEP_TIME__SEC,
            0.1,
            msg="SUBSYSTEM_SLEEP_TIME__SEC must remain the canonical 0.1 s cadence.",
        )


class TestSubsystemAbstractContract(IsolatedAsyncioTestCase):
    """
    The 'Subsystem' abstract-base-class contract tests.
    """

    def test__subsystem__cannot_be_instantiated_directly(self) -> None:
        """
        Ensure 'Subsystem' is abstract — instantiating it without
        overriding '_subsystem_loop' must raise 'TypeError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(TypeError):
            Subsystem()  # type: ignore[abstract]

    async def test__subsystem__loop_stub_raises_not_implemented(self) -> None:
        """
        Ensure the abstract '_subsystem_loop' stub body itself raises
        'NotImplementedError' so a subclass that awaits 'super()' into
        the default receives the canonical failure.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pmd_pytcp.runtime.subsystem.log"):
            subsystem = _TestSubsystem()

        with self.assertRaises(NotImplementedError):
            await Subsystem._subsystem_loop(subsystem)


class TestSubsystemInit(TestCase):
    """
    The 'Subsystem.__init__()' tests.
    """

    def test__subsystem__init_creates_stop_event(self) -> None:
        """
        Ensure '__init__' creates a fresh 'asyncio.Event' for the stop
        signal and that it starts cleared (subsystem is not yet stopping).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pmd_pytcp.runtime.subsystem.log"):
            subsystem = _TestSubsystem()

        self.assertIsInstance(
            subsystem._event__stop_subsystem,
            asyncio.Event,
            msg="Subsystem.__init__ must create an 'asyncio.Event' for the stop signal.",
        )
        self.assertFalse(
            subsystem._event__stop_subsystem.is_set(),
            msg="The stop event must start cleared after '__init__'.",
        )

    def test__subsystem__init_logs_without_info(self) -> None:
        """
        Ensure '__init__' emits an 'Initializing <name>' log line on the
        'stack' channel when no 'info' argument is provided.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pmd_pytcp.runtime.subsystem.log") as mock_log:
            _TestSubsystem()

        mock_log.assert_called_once_with(
            "stack",
            "Initializing test-subsystem",
        )

    def test__subsystem__init_logs_with_info(self) -> None:
        """
        Ensure '__init__' appends a bracketed info tag to the
        'Initializing ...' log line when the caller supplies one.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pmd_pytcp.runtime.subsystem.log") as mock_log:
            _TestSubsystem(info="tap7")

        mock_log.assert_called_once_with(
            "stack",
            "Initializing test-subsystem [tap7]",
        )

    def test__subsystem__init_empty_info_string_omits_bracket(self) -> None:
        """
        Ensure an empty 'info' string is treated as 'no info' —
        the bracket suffix is omitted from the 'Initializing X'
        log line because the 'if info' falsy guard catches the
        empty case.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pmd_pytcp.runtime.subsystem.log") as mock_log:
            _TestSubsystem(info="")

        mock_log.assert_called_once_with(
            "stack",
            "Initializing test-subsystem",
        )


class TestSubsystemLifecycle(IsolatedAsyncioTestCase):
    """
    The 'Subsystem.start()' / 'Subsystem.stop()' full-lifecycle tests.
    """

    async def asyncSetUp(self) -> None:
        """
        Redirect 'pmd_pytcp.stack.LOG__OUTPUT' to an in-memory buffer so the
        real 'log()' calls driven from the worker task do not pollute
        the test runner's stderr.
        """

        self._log_patch = patch("pmd_pytcp.stack.LOG__OUTPUT", io.StringIO())
        self._log_patch.start()

    async def asyncTearDown(self) -> None:
        """
        Restore the original log output stream. Worker tasks are awaited
        by each test's own 'wait_stopped()' call, so no task can print
        its terminal "Stopped ..." line after the unpatch.
        """

        self._log_patch.stop()

    async def test__subsystem__start_runs_task_and_fires_hooks(self) -> None:
        """
        Ensure 'start()' clears the stop event, spawns a worker task
        that drives '_subsystem_loop()' at least once, and invokes the
        optional '_start()' hook synchronously after task spawn.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        subsystem = _TestSubsystem()

        try:
            subsystem.start()

            await asyncio.wait_for(subsystem._loop_event.wait(), timeout=2.0)
            self.assertGreaterEqual(
                subsystem.loop_iterations,
                1,
                msg="The subsystem loop must execute at least one iteration after start().",
            )
            self.assertTrue(
                subsystem.start_hook_called,
                msg="Subsystem.start() must invoke the '_start' hook after spawning the task.",
            )
        finally:
            subsystem.stop()
            await subsystem.wait_stopped()

    async def test__subsystem__stop_signals_event_and_fires_hook(self) -> None:
        """
        Ensure 'stop()' sets the stop event (terminating the loop) and
        invokes the optional '_stop()' hook. A 'wait_stopped()' after
        stop must complete promptly so the task exits cleanly.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        subsystem = _TestSubsystem()
        subsystem.start()

        await asyncio.wait_for(subsystem._loop_event.wait(), timeout=2.0)

        subsystem.stop()

        self.assertTrue(
            subsystem._event__stop_subsystem.is_set(),
            msg="Subsystem.stop() must set the stop event.",
        )
        self.assertTrue(
            subsystem.stop_hook_called,
            msg="Subsystem.stop() must invoke the '_stop' hook.",
        )

        await asyncio.wait_for(subsystem.wait_stopped(), timeout=2.0)

    async def test__subsystem__task_exits_on_stop(self) -> None:
        """
        Ensure the worker task observes the stop event / cancellation
        and exits the loop — 'wait_stopped()' must return within a
        bounded time and leave the task in the done state.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        subsystem = _TestSubsystem()
        subsystem.start()
        await asyncio.wait_for(subsystem._loop_event.wait(), timeout=2.0)

        subsystem.stop()

        await asyncio.wait_for(subsystem.wait_stopped(), timeout=2.0)
        assert subsystem._task is not None
        self.assertTrue(
            subsystem._task.done(),
            msg="The worker task must be done after stop() + wait_stopped().",
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

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pmd_pytcp.runtime.subsystem.log"):
            subsystem = _HookOnlySubsystem()

        try:
            subsystem._start()
        except Exception as exc:  # pragma: no cover - fail path
            self.fail(f"Subsystem._start() base implementation must be a silent no-op; raised {exc!r}.")

    def test__subsystem__default_stop_hook_is_noop(self) -> None:
        """
        Ensure the base-class '_stop' hook is a no-op that raises
        nothing when invoked.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pmd_pytcp.runtime.subsystem.log"):
            subsystem = _HookOnlySubsystem()

        try:
            subsystem._stop()
        except Exception as exc:  # pragma: no cover - fail path
            self.fail(f"Subsystem._stop() base implementation must be a silent no-op; raised {exc!r}.")


class TestSubsystemTaskEarlyExit(IsolatedAsyncioTestCase):
    """
    The '_task__subsystem' worker-coroutine early-exit test.
    """

    async def test__subsystem__task_exits_when_event_preset(self) -> None:
        """
        Ensure the worker coroutine walks past the while-loop when the
        stop event is already set, logs 'Started' / 'Stopped' markers,
        and never invokes '_subsystem_loop'. Exercises the loop-condition
        false branch directly without relying on task scheduling.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pmd_pytcp.runtime.subsystem.log"):
            subsystem = _TestSubsystem()
        subsystem._event__stop_subsystem.set()

        with patch("pmd_pytcp.runtime.subsystem.log") as mock_log:
            await subsystem._task__subsystem()

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


class TestSubsystemStartStopEdgeCases(IsolatedAsyncioTestCase):
    """
    Edge cases on the 'Subsystem.start()' / 'Subsystem.stop()'
    safety guards (double-start prevention, stop-before-start no-op).
    """

    async def test__subsystem__stop_before_start_is_safe(self) -> None:
        """
        Ensure 'stop()' is a safe no-op (no exception, no task access)
        when called on a subsystem that has never been started. The
        'self._task is not None' guard in stop() protects the cancel;
        the optional '_stop' hook still fires.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pmd_pytcp.runtime.subsystem.log"):
            subsystem = _TestSubsystem()

        subsystem.stop()

        self.assertTrue(
            subsystem._event__stop_subsystem.is_set(),
            msg="Subsystem.stop() must set the stop event even without prior start().",
        )
        self.assertTrue(
            subsystem.stop_hook_called,
            msg="Subsystem.stop() must invoke the '_stop' hook even without prior start().",
        )
        self.assertIsNone(
            subsystem._task,
            msg="No worker task should be created when stop() is called without start().",
        )

    async def test__subsystem__double_start_asserts(self) -> None:
        """
        Ensure 'start()' raises AssertionError when called while a
        worker task is still running. Prevents the orphan-worker
        bug where the previous task would lose its stop signal
        (cleared by the second start()) and run indefinitely.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pmd_pytcp.stack.LOG__OUTPUT", io.StringIO()):
            subsystem = _TestSubsystem()
            subsystem.start()
            try:
                await asyncio.wait_for(subsystem._loop_event.wait(), timeout=2.0)

                with self.assertRaises(AssertionError) as ctx:
                    subsystem.start()

                self.assertIn(
                    "while a worker is still running",
                    str(ctx.exception),
                    msg="Double-start assert must name the contract violation.",
                )
            finally:
                subsystem.stop()
                await subsystem.wait_stopped()

    async def test__subsystem__restart_after_wait_stopped(self) -> None:
        """
        Ensure a stopped-and-awaited subsystem can be started again —
        the double-start guard gates on 'task.done()', not identity,
        and 'start()' clears the stop event for the fresh run.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pmd_pytcp.stack.LOG__OUTPUT", io.StringIO()):
            subsystem = _TestSubsystem()
            subsystem.start()
            await asyncio.wait_for(subsystem._loop_event.wait(), timeout=2.0)
            subsystem.stop()
            await subsystem.wait_stopped()

            subsystem._loop_event.clear()
            subsystem.start()
            try:
                await asyncio.wait_for(subsystem._loop_event.wait(), timeout=2.0)
            finally:
                subsystem.stop()
                await subsystem.wait_stopped()
