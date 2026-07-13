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

pmd_pytcp/runtime/timer.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Callable

from pmd_pytcp.lib.logger import log


class TimerHandle:
    """
    Cancellation handle returned by 'Timer.call_later' and
    'Timer.call_periodic'. Pass it to 'Timer.cancel(handle)' to
    deactivate the entry. Wraps the underlying
    'asyncio.TimerHandle'; a periodic entry is re-armed by the
    fire wrapper with a fresh loop handle each period.
    """

    __slots__ = ("method", "args", "kwargs", "period_ms", "cancelled", "_loop_handle")

    def __init__(
        self,
        *,
        method: Callable[..., None],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        period_ms: int | None = None,
    ) -> None:
        self.method = method
        self.args = args
        self.kwargs = kwargs
        self.period_ms = period_ms
        self.cancelled = False
        self._loop_handle: asyncio.TimerHandle | None = None


class Timer:
    """
    Stack-wide millisecond-resolution timer over the asyncio event
    loop. Each registration maps to one 'loop.call_at' entry —
    there is no worker, no heap and no lock ('pure_asyncio.md';
    everything runs on the one stack loop). Periodic entries are
    re-armed by advancing an absolute deadline by exactly
    'period_ms' (interval-based, so they do not drift).

    The public API is 'call_later' / 'call_periodic' / 'cancel' /
    'now_ms' plus the lifecycle pair 'start' / 'stop' ('stop'
    cancels every outstanding entry so a stopped stack cannot
    fire stale callbacks). Callbacks are plain sync callables run
    on the loop; a raising handler is logged and swallowed, same
    policy as the threaded worker had.
    """

    _subsystem_name = "Timer"

    _handles: "set[TimerHandle]"
    _loop: asyncio.AbstractEventLoop | None

    def __init__(self) -> None:
        """
        Class constructor.
        """

        __debug__ and log("stack", f"Initializing {self._subsystem_name}")

        self._handles = set()
        self._loop = None

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

    def start(self) -> None:
        """
        Bind the timer to the running event loop. Registrations
        made before 'start()' (boot-time subsystem construction)
        are already loop-bound lazily by '_get_loop', so this is
        mostly a lifecycle symmetry point.
        """

        __debug__ and log("stack", f"Starting {self._subsystem_name}")
        self._loop = asyncio.get_running_loop()

    def stop(self) -> None:
        """
        Cancel every outstanding entry so a stopped stack cannot
        fire stale callbacks.
        """

        __debug__ and log("stack", f"Stopping {self._subsystem_name}")

        for handle in list(self._handles):
            handle.cancelled = True
            if handle._loop_handle is not None:
                handle._loop_handle.cancel()
        self._handles.clear()

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """
        Return the loop timers schedule on — the bound loop after
        'start()', else the currently running loop.
        """

        if self._loop is not None:
            return self._loop
        return asyncio.get_running_loop()

    def _fire(self, handle: TimerHandle, deadline: float) -> None:
        """
        Loop callback: run the handle's method (logging a raising
        handler) and re-arm a periodic entry at 'deadline +
        period' (absolute, drift-free).
        """

        if handle.cancelled:
            self._handles.discard(handle)
            return

        if handle.period_ms is not None:
            next_deadline = deadline + handle.period_ms / 1000.0
            handle._loop_handle = self._get_loop().call_at(next_deadline, self._fire, handle, next_deadline)
        else:
            self._handles.discard(handle)

        try:
            handle.method(*handle.args, **handle.kwargs)
        except Exception:  # pylint: disable=broad-exception-caught
            name = getattr(handle.method, "__name__", repr(handle.method))
            __debug__ and log("timer", f"<r>Handler raised: {name}</>")

    def _schedule(self, handle: TimerHandle, delay_ms: int) -> TimerHandle:
        """
        Arm 'handle' 'delay_ms' from now on the loop and track it
        for 'stop()' teardown.
        """

        loop = self._get_loop()
        deadline = loop.time() + delay_ms / 1000.0
        handle._loop_handle = loop.call_at(deadline, self._fire, handle, deadline)
        self._handles.add(handle)
        return handle

    def call_later(
        self,
        delay_ms: int,
        method: Callable[..., None],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> TimerHandle:
        """
        Schedule 'method(*args, **kwargs)' to fire once after
        'delay_ms' milliseconds. Returns a cancellation handle the
        caller must retain if it wants to cancel later.
        """

        assert delay_ms >= 0, f"call_later delay_ms must be >= 0; got {delay_ms}"

        return self._schedule(
            TimerHandle(method=method, args=args, kwargs=kwargs),
            delay_ms,
        )

    def call_periodic(
        self,
        period_ms: int,
        method: Callable[..., None],
        /,
        *args: Any,
        **kwargs: Any,
    ) -> TimerHandle:
        """
        Schedule 'method(*args, **kwargs)' to fire every
        'period_ms' milliseconds, starting 'period_ms' from now.
        Re-armed interval-based (no drift). Returns a cancellation
        handle the caller must retain if it wants to cancel later.
        """

        assert period_ms >= 1, f"call_periodic period_ms must be >= 1; got {period_ms}"

        return self._schedule(
            TimerHandle(method=method, args=args, kwargs=kwargs, period_ms=period_ms),
            period_ms,
        )

    def cancel(self, handle: TimerHandle, /) -> None:
        """
        Cancel 'handle'. Idempotent; a no-op if the handle already
        fired or was already cancelled.
        """

        handle.cancelled = True
        if handle._loop_handle is not None:
            handle._loop_handle.cancel()
        self._handles.discard(handle)
