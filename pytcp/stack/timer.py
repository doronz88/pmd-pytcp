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
This module contains class supporting timer that is used by other stack components.

pytcp/stack/timer.py

ver 3.0.3
"""

import threading
import time
from typing import Any, Callable, override

from pytcp.lib.logger import log
from pytcp.lib.subsystem import Subsystem


class TimerTask:
    """
    Timer task support class.
    """

    _method: Callable[[Any], None]
    _args: list[Any]
    _kwargs: dict[str, Any]
    _delay: int
    _delay_exp: bool
    _repeat_count: int
    _stop_condition: Callable[[], bool] | None
    _remaining_delay: int
    _delay_exp_factor: int

    def __init__(
        self,
        *,
        method: Callable[[Any], None],
        args: list[Any],
        kwargs: dict[str, Any],
        delay: int,
        delay_exp: bool,
        repeat_count: int,
        stop_condition: Callable[[], bool] | None,
    ) -> None:
        """
        Class constructor, repeat_count = -1 means infinite, delay_exp means
        to raise delay time exponentially after each method execution.
        """

        self._method = method
        self._args = args
        self._kwargs = kwargs
        self._delay = delay
        self._delay_exp = delay_exp
        self._repeat_count = repeat_count
        self._stop_condition = stop_condition
        self._remaining_delay = delay
        self._delay_exp_factor = 0

    @property
    def remaining_delay(self) -> int:
        """
        Geter for the '_remaining_delay' attribute.
        """

        return self._remaining_delay

    def tick(self) -> None:
        """
        Tick input from timer.
        """

        self._remaining_delay -= 1

        if self._stop_condition and self._stop_condition():
            self._remaining_delay = 0
            return

        if self._remaining_delay:
            return

        self._method(*self._args, **self._kwargs)

        if self._repeat_count:
            self._remaining_delay = self._delay * (1 << self._delay_exp_factor) if self._delay_exp else self._delay
            self._delay_exp_factor += 1
            if self._repeat_count > 0:
                self._repeat_count -= 1


class Timer(Subsystem):
    """
    Support for stack timer.
    """

    _subsystem_name = "Timer"

    _tasks: list[TimerTask]
    _timers: dict[str, int]

    _event__stop_subsystem: threading.Event

    @override
    def __init__(self) -> None:
        """
        Class constructor.
        """

        super().__init__()

        self._tasks = []
        self._timers = {}

    @property
    def now_ms(self) -> int:
        """
        Get the wall-clock time in milliseconds, used by the RFC
        6298 RTO sample-collection hooks in 'TcpSession' to record
        outbound-segment send times and compute observed RTTs on
        ACK harvest. Backed by 'time.monotonic_ns()' so the value
        increases monotonically and is unaffected by wall-clock
        adjustments. Test deployments swap this 'Timer' for the
        deterministic 'FakeTimer' fixture which exposes the same
        'now_ms' surface over its virtual clock.
        """

        return time.monotonic_ns() // 1_000_000

    @override
    def _subsystem_loop(self) -> None:
        """
        Execute registered methods on every timer tick.
        """

        # Timer has 1ms resolution
        time.sleep(0.001)

        # Adjust registered timers
        for name in self._timers:
            self._timers[name] -= 1

        # Cleanup expired timers
        self._timers = {name: timeout for name, timeout in self._timers.items() if timeout}

        # Tick registered methods
        for task in self._tasks:
            task.tick()

        # Cleanup expired methods
        self._tasks = [task for task in self._tasks if task.remaining_delay]

    def register_method(
        self,
        *,
        method: Callable[[Any], None],
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
        delay: int = 1,
        delay_exp: bool = False,
        repeat_count: int = -1,
        stop_condition: Callable[[], bool] | None = None,
    ) -> None:
        """
        Register method to be executed by timer.
        """

        __debug__ and log(
            "timer",
            f"<r>Registering method: {method.__name__}, delay={delay}</>",
        )

        self._tasks.append(
            TimerTask(
                method=method,
                args=[] if args is None else args,
                kwargs={} if kwargs is None else kwargs,
                delay=delay,
                delay_exp=delay_exp,
                repeat_count=repeat_count,
                stop_condition=stop_condition,
            )
        )

    def register_timer(self, *, name: str, timeout: int) -> None:
        """
        Register delay timer.
        """

        __debug__ and log("timer", f"<r>Registering timer: {name}, timeout={timeout}</>")

        self._timers[name] = timeout

    def is_expired(self, name: str) -> bool:
        """
        Check if timer expired.
        """

        __debug__ and log("timer", f"<r>Active timers: {self._timers}</>")

        return not self._timers.get(name, None)

    def unregister_timers_with_prefix(self, prefix: str, /) -> None:
        """
        Unregister every named delay timer whose name starts with
        'prefix'. Used by 'TcpSession._change_state' on the
        transition to CLOSED to clean up per-session entries from
        'self._timers' so a long-running stack handling many
        connection churns does not slowly accumulate stale
        entries that match no live session.
        """

        __debug__ and log("timer", f"<r>Unregistering timers with prefix: {prefix!r}</>")

        self._timers = {name: timeout for name, timeout in self._timers.items() if not name.startswith(prefix)}

    def unregister_method(self, method: Callable[..., None], /) -> None:
        """
        Unregister every 'TimerTask' previously installed by
        'register_method' whose stored method matches the supplied
        bound method. Used by 'TcpSession._change_state' on the
        transition to CLOSED to drop the per-millisecond 'tcp_fsm'
        callback so a long-running stack does not (a) keep
        invoking the FSM on a dead session every tick or (b) hold
        the 'TcpSession' instance alive against GC via the bound-
        method reference. Companion to 'unregister_timers_with_prefix'
        which handles the named-delay-timer half of the same
        per-session registration.

        Bound methods compare equal when their underlying
        '__self__' and '__func__' are identical, so passing
        'session.tcp_fsm' removes exactly the registration that
        'session.__init__' made.
        """

        __debug__ and log("timer", f"<r>Unregistering method: {method.__name__}</>")

        self._tasks = [task for task in self._tasks if task._method != method]
