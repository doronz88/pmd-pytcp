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
This module contains the deterministic 'FakeTimer' used by TCP session
integration tests in place of the real 'pytcp.stack.timer.Timer'.

pytcp/tests/lib/fake_timer.py

ver 3.0.4
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class _FakeTimerTask:
    """
    Per-method registration record kept by 'FakeTimer'.
    """

    method: Callable[..., None]
    args: list[Any]
    kwargs: dict[str, Any]
    delay: int
    delay_exp: bool
    repeat_count: int
    stop_condition: Callable[[], bool] | None
    remaining_delay: int = field(init=False)
    delay_exp_factor: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        """
        Initialize the countdown to the configured delay.
        """

        self.remaining_delay = self.delay


class FakeTimer:
    """
    Deterministic in-memory replacement for 'pytcp.stack.timer.Timer'.

    Mirrors only the surface 'TcpSession' and the wider stack-side TCP
    code actually call: 'register_method', 'register_timer',
    'is_expired'. Time advances exclusively through 'advance(ms)';
    no real-clock sleeping happens, so tests are deterministic and
    fast regardless of host load.
    """

    _tasks: list[_FakeTimerTask]
    _timers: dict[str, int]
    _now_ms: int

    def __init__(self) -> None:
        """
        Initialize the fake timer with no registered tasks or timers
        and the virtual clock at zero.
        """

        self._tasks = []
        self._timers = {}
        self._now_ms = 0

    @property
    def now_ms(self) -> int:
        """
        Get the virtual clock value in milliseconds.
        """

        return self._now_ms

    @property
    def pending_timers(self) -> dict[str, int]:
        """
        Get a snapshot of every named timer with strictly positive
        remaining time.
        """

        return dict(self._timers)

    def register_method(
        self,
        *,
        method: Callable[..., None],
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
        delay: int = 1,
        delay_exp: bool = False,
        repeat_count: int = -1,
        stop_condition: Callable[[], bool] | None = None,
    ) -> None:
        """
        Register a method to be invoked by the virtual clock at every
        multiple of 'delay' milliseconds, mirroring the production
        'Timer.register_method' contract.
        """

        self._tasks.append(
            _FakeTimerTask(
                method=method,
                args=[] if args is None else list(args),
                kwargs={} if kwargs is None else dict(kwargs),
                delay=delay,
                delay_exp=delay_exp,
                repeat_count=repeat_count,
                stop_condition=stop_condition,
            )
        )

    def register_timer(self, *, name: str, timeout: int) -> None:
        """
        Register or overwrite a named delay timer with the supplied
        millisecond timeout, matching production 'Timer.register_timer'.
        """

        self._timers[name] = timeout

    def is_expired(self, name: str) -> bool:
        """
        Return True if 'name' is not currently in the pending-timer
        table or its remaining time has reached zero. Matches
        production 'Timer.is_expired' which returns
        'not self._timers.get(name, None)'.
        """

        return not self._timers.get(name, None)

    def advance(self, ms: int) -> None:
        """
        Advance the virtual clock by 'ms' milliseconds, ticking every
        registered task and decrementing every named timer one
        millisecond at a time so callbacks fire at the same cadence
        the production 'Timer._subsystem_loop' would produce.
        """

        assert ms >= 0, f"The 'ms' argument must be non-negative. Got: {ms!r}"

        for _ in range(ms):
            self._now_ms += 1
            self._tick_timers()
            self._tick_tasks()

    def _tick_timers(self) -> None:
        """
        Decrement every named timer by one millisecond, then drop any
        whose remaining time has reached zero so 'is_expired' starts
        returning True for them.
        """

        self._timers = {name: remaining - 1 for name, remaining in self._timers.items() if remaining - 1 > 0}

    def _tick_tasks(self) -> None:
        """
        Decrement every registered task by one millisecond, fire those
        whose countdown reaches zero, then either reset their countdown
        (for repeat_count != 0) or drop them.
        """

        surviving: list[_FakeTimerTask] = []

        for task in self._tasks:
            task.remaining_delay -= 1

            if task.stop_condition is not None and task.stop_condition():
                continue

            if task.remaining_delay > 0:
                surviving.append(task)
                continue

            task.method(*task.args, **task.kwargs)

            if task.repeat_count == 0:
                continue

            task.remaining_delay = task.delay * (1 << task.delay_exp_factor) if task.delay_exp else task.delay
            task.delay_exp_factor += 1

            if task.repeat_count > 0:
                task.repeat_count -= 1

            surviving.append(task)

        self._tasks = surviving
