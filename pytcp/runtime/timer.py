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
This module contains the stack-wide millisecond-resolution timer.

pytcp/runtime/timer.py

ver 3.0.4
"""

import threading
import time
from typing import Any, Callable, override

from pytcp.lib.logger import log
from pytcp.runtime.subsystem import Subsystem

# Millisecond timer-tick cadence — the worker thread sleeps this
# long between iterations of '_subsystem_loop'. Subclasses of
# 'Subsystem' would normally use 'SUBSYSTEM_SLEEP_TIME__SEC'
# (0.1 s); Timer needs sub-second resolution because every
# countdown unit ('delay' in 'register_method' /  'timeout' in
# 'register_timer') is in milliseconds, and the per-tick
# decrement is what makes a 'delay=1000' register fire at ~1 s.
TIMER_TICK__SEC: float = 0.001


class TimerTask:
    """
    A registered method scheduled by 'Timer.register_method'.
    Counts down 'delay' ticks (1 ms each per 'TIMER_TICK__SEC')
    before invoking the bound method; optionally repeats with
    a linear or exponential backoff and an early-exit
    'stop_condition' predicate.
    """

    _method: Callable[..., None]
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
        method: Callable[..., None],
        args: list[Any],
        kwargs: dict[str, Any],
        delay: int,
        delay_exp: bool,
        repeat_count: int,
        stop_condition: Callable[[], bool] | None,
    ) -> None:
        """
        Class constructor. 'delay' must be >= 1 (countdown is in
        milliseconds; delay=0 has no defensible semantics).
        'repeat_count = -1' means infinite; 'delay_exp' multiplies
        the delay by 2**iteration after each method execution.
        """

        assert delay >= 1, f"TimerTask delay must be >= 1; got {delay}"

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
    def method(self) -> Callable[..., None]:
        """
        Getter for the registered method. Consumed by
        'Timer.unregister_method' which matches by method
        equality (bound methods compare equal when their
        '__self__' and '__func__' are identical).
        """

        return self._method

    @property
    def remaining_delay(self) -> int:
        """
        Getter for the '_remaining_delay' attribute.
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
            if self._delay_exp:
                self._delay_exp_factor += 1
            if self._repeat_count > 0:
                self._repeat_count -= 1


class Timer(Subsystem):
    """
    Stack-wide millisecond-resolution timer Subsystem. Holds two
    parallel registries:

    - '_tasks' — list of 'TimerTask' entries registered via
      'register_method'. Each entry's countdown decrements once
      per tick; when it reaches zero the bound method runs.
    - '_timers' — dict of named delay timers registered via
      'register_timer'. Each entry's timeout decrements once per
      tick; consumers poll via 'is_expired(name)'.

    The worker thread (inherited from 'Subsystem') runs
    '_subsystem_loop' at ~1 ms cadence ('TIMER_TICK__SEC').
    External callers register / unregister from arbitrary stack
    threads; '_lock' (RLock) guards every read / write of both
    registries so concurrent register-during-tick races cannot
    drop entries.

    Note: 'is_expired(name)' returns True for unknown names —
    a never-registered timer is treated as already-expired,
    same as one that counted down to zero.
    """

    _subsystem_name = "Timer"

    _tasks: list[TimerTask]
    _timers: dict[str, int]
    _lock: threading.RLock

    @override
    def __init__(self) -> None:
        """
        Class constructor.
        """

        super().__init__()

        self._tasks = []
        self._timers = {}
        self._lock = threading.RLock()

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

        time.sleep(TIMER_TICK__SEC)

        with self._lock:
            # Adjust registered timers
            for name in self._timers:
                self._timers[name] -= 1

            # Cleanup expired timers
            self._timers = {name: timeout for name, timeout in self._timers.items() if timeout}

            # Tick registered methods. RLock allows a method's
            # body to call back into register_method /
            # unregister_method without deadlocking.
            for task in self._tasks:
                task.tick()

            # Cleanup expired methods
            self._tasks = [task for task in self._tasks if task.remaining_delay]

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
        Register method to be executed by timer.
        """

        __debug__ and log(
            "timer",
            f"<r>Registering method: {method.__name__}, delay={delay}</>",
        )

        task = TimerTask(
            method=method,
            args=[] if args is None else args,
            kwargs={} if kwargs is None else kwargs,
            delay=delay,
            delay_exp=delay_exp,
            repeat_count=repeat_count,
            stop_condition=stop_condition,
        )
        with self._lock:
            self._tasks.append(task)

    def register_timer(self, *, name: str, timeout: int) -> None:
        """
        Register delay timer. 'timeout' must be >= 1 (countdown
        is in milliseconds; timeout=0 would expire on the very
        next tick which the existing call sites never want).
        """

        assert timeout >= 1, f"register_timer timeout must be >= 1; got {timeout}"

        __debug__ and log("timer", f"<r>Registering timer: {name}, timeout={timeout}</>")

        with self._lock:
            self._timers[name] = timeout

    def is_expired(self, name: str) -> bool:
        """
        Check if timer expired. Returns True for an unknown name
        (a never-registered timer collapses with one that
        counted down to zero — the consumer treats both as
        "no longer counting"). Wrap the read in '_lock' so a
        concurrent tick cannot observe a half-updated entry.
        """

        with self._lock:
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

        with self._lock:
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

        with self._lock:
            self._tasks = [task for task in self._tasks if task.method != method]
