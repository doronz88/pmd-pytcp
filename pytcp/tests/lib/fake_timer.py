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
integration tests in place of the real 'pytcp.runtime.timer.Timer'.

pytcp/tests/lib/fake_timer.py

ver 3.0.4
"""

import heapq
from collections.abc import Callable
from typing import Any

from pytcp.runtime.timer import TimerHandle

# Heap-key priority bands. Named legacy timers (register_timer)
# clear their flag BEFORE method callbacks (register_method /
# call_*) that share the same millisecond deadline, so a periodic
# fsm tick observing 'is_expired' at the expiry instant sees the
# timer already expired — byte-for-byte the behaviour of the
# previous tick-and-decrement FakeTimer, where '_tick_timers' ran
# ahead of '_tick_tasks' within each millisecond.
_PRIO__NAMED_FLAG: int = 0
_PRIO__METHOD: int = 1


class FakeTimer:
    """
    Deterministic in-memory replacement for 'pytcp.runtime.timer.Timer'.

    Maintains the same heap-based core as the production 'Timer'
    (a min-heap of absolute-deadline entries keyed by
    '(deadline_ms, prio, seq)') but swaps the worker thread for a
    deterministic 'advance(ms)' driver. 'advance' pops and
    dispatches every entry whose deadline falls within the new
    window, in deadline order, re-arming periodics interval-based
    so a single 'advance' may fire a periodic several times.

    Exposes both the new core API ('call_later' / 'call_periodic'
    / 'cancel') and the legacy shim ('register_method' /
    'register_timer' / 'is_expired' / 'unregister_method' /
    'unregister_timers_with_prefix') so existing TCP integration
    tests run unchanged.
    """

    _heap: list[tuple[int, int, int, TimerHandle]]
    _now_ms: int
    _seq: int
    _legacy_method_handles: dict[Callable[..., None], list[TimerHandle]]
    _legacy_named_flags: dict[str, TimerHandle]

    def __init__(self) -> None:
        """
        Initialize the fake timer with an empty heap and the
        virtual clock at zero.
        """

        self._heap = []
        self._now_ms = 0
        self._seq = 0
        self._legacy_method_handles = {}
        self._legacy_named_flags = {}

    @property
    def now_ms(self) -> int:
        """
        Get the virtual clock value in milliseconds.
        """

        return self._now_ms

    @now_ms.setter
    def now_ms(self, value: int) -> None:
        """
        Set the virtual clock, shifting every pending deadline by
        the same delta so relative timing is preserved. This is
        the sanctioned way for clock-wrap tests to jump the clock
        (the old tick-and-decrement FakeTimer kept '_now_ms'
        decoupled from per-task countdowns; the heap core makes
        deadlines absolute, so a raw jump would strand pending
        entries millions of milliseconds in the past).
        """

        delta = value - self._now_ms
        if delta:
            rebased: list[tuple[int, int, int, TimerHandle]] = []
            for _deadline_ms, prio, seq, handle in self._heap:
                handle.deadline_ms += delta
                rebased.append((handle.deadline_ms, prio, seq, handle))
            heapq.heapify(rebased)
            self._heap = rebased
        self._now_ms = value

    @property
    def pending_timers(self) -> dict[str, int]:
        """
        Get a snapshot of every live named legacy timer mapped to
        its remaining milliseconds ('deadline_ms - now_ms').
        """

        return {name: handle.deadline_ms - self._now_ms for name, handle in self._legacy_named_flags.items()}

    def _next_seq(self) -> int:
        """
        Return a fresh monotonic sequence number breaking heap-key
        ties in registration order.
        """

        seq = self._seq
        self._seq += 1
        return seq

    def _schedule(
        self,
        delay_ms: int,
        method: Callable[..., None],
        prio: int,
        period_ms: int | None,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> TimerHandle:
        """
        Build a 'TimerHandle' and push it onto the heap.
        """

        handle = TimerHandle(
            method=method,
            args=args,
            kwargs=kwargs,
            deadline_ms=self._now_ms + delay_ms,
            seq=self._next_seq(),
            period_ms=period_ms,
        )
        heapq.heappush(self._heap, (handle.deadline_ms, prio, handle.seq, handle))
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
        'delay_ms' milliseconds. Returns a cancellation handle.
        """

        assert delay_ms >= 0, f"call_later delay_ms must be >= 0; got {delay_ms}"

        return self._schedule(delay_ms, method, _PRIO__METHOD, None, args, kwargs)

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
        Returns a cancellation handle.
        """

        assert period_ms >= 1, f"call_periodic period_ms must be >= 1; got {period_ms}"

        return self._schedule(period_ms, method, _PRIO__METHOD, period_ms, args, kwargs)

    def cancel(self, handle: TimerHandle, /) -> None:
        """
        Mark 'handle' as cancelled. The next 'advance' that
        surfaces it drops it. Idempotent.
        """

        handle.cancelled = True

    def advance(self, ms: int) -> None:
        """
        Advance the virtual clock by 'ms' milliseconds, dispatching
        every entry whose deadline falls within the new window in
        '(deadline_ms, prio, seq)' order. Periodics re-arm
        interval-based so a long advance fires them once per
        elapsed period. Callbacks observe 'now_ms' equal to the
        entry's deadline.
        """

        assert ms >= 0, f"The 'ms' argument must be non-negative. Got: {ms!r}"

        target = self._now_ms + ms

        while self._heap and self._heap[0][0] <= target:
            deadline_ms, _, _, handle = heapq.heappop(self._heap)

            if handle.cancelled:
                continue

            self._now_ms = deadline_ms

            if handle.period_ms is not None:
                handle.deadline_ms = deadline_ms + handle.period_ms
                handle.seq = self._next_seq()
                heapq.heappush(self._heap, (handle.deadline_ms, _PRIO__METHOD, handle.seq, handle))

            handle.method(*handle.args, **handle.kwargs)

        self._now_ms = target

    # ----------------------------------------------------------------
    # Legacy shim layer — mirrors 'pytcp.runtime.timer.Timer'.
    # ----------------------------------------------------------------

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
        LEGACY. Shim over 'call_later' / 'call_periodic' mirroring
        the production 'Timer.register_method' contract.
        """

        assert delay >= 1, f"register_method delay must be >= 1; got {delay}"
        assert delay_exp is False, "register_method delay_exp not supported"
        assert stop_condition is None, "register_method stop_condition not supported"
        assert repeat_count in (-1, 0), f"register_method repeat_count must be -1 or 0; got {repeat_count}"

        call_args = () if args is None else tuple(args)
        call_kwargs = {} if kwargs is None else kwargs

        if repeat_count == -1:
            handle = self.call_periodic(delay, method, *call_args, **call_kwargs)
        else:
            handle = self.call_later(delay, method, *call_args, **call_kwargs)

        self._legacy_method_handles.setdefault(method, []).append(handle)

    def register_timer(self, *, name: str, timeout: int) -> None:
        """
        LEGACY. Shim over a named-flag one-shot mirroring the
        production 'Timer.register_timer' contract.
        """

        assert timeout >= 1, f"register_timer timeout must be >= 1; got {timeout}"

        old = self._legacy_named_flags.get(name)
        if old is not None:
            old.cancelled = True
        self._legacy_named_flags[name] = self._schedule(
            timeout,
            self._clear_named_flag,
            _PRIO__NAMED_FLAG,
            None,
            (name,),
            {},
        )

    def _clear_named_flag(self, name: str, /) -> None:
        """
        Drop the named-flag entry for 'name' when its legacy timer
        fires so 'is_expired' starts returning True.
        """

        self._legacy_named_flags.pop(name, None)

    def is_expired(self, name: str) -> bool:
        """
        LEGACY. True when 'name' was never registered OR its timer
        has already fired. Matches production
        'Timer.is_expired'.
        """

        return name not in self._legacy_named_flags

    def unregister_timers_with_prefix(self, prefix: str, /) -> None:
        """
        LEGACY. Cancel every named-flag timer whose name starts
        with 'prefix'. Mirrors the production API.
        """

        for name in [n for n in self._legacy_named_flags if n.startswith(prefix)]:
            self._legacy_named_flags[name].cancelled = True
            del self._legacy_named_flags[name]

    def unregister_method(self, method: Callable[..., None], /) -> None:
        """
        LEGACY. Cancel every handle previously installed by
        'register_method' for the supplied bound method. Mirrors
        the production API.
        """

        for handle in self._legacy_method_handles.pop(method, []):
            handle.cancelled = True
