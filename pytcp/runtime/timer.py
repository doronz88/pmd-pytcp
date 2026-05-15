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

import heapq
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, override

from pytcp.lib.logger import log
from pytcp.runtime.subsystem import Subsystem

# Ceiling on the worker's idle wait. When the heap is empty the
# worker blocks on 'threading.Event.wait(timeout=_IDLE_WAKEUP__SEC)'
# rather than forever, so the stop event is re-checked at least
# this often even on a fully idle stack.
_IDLE_WAKEUP__SEC: float = 60.0


@dataclass(slots=True, kw_only=True)
class TimerHandle:
    """
    Cancellation handle returned by 'Timer.call_later' and
    'Timer.call_periodic'. Pass it to 'Timer.cancel(handle)' to
    deactivate the entry; cancellation is lazy (the worker skips
    cancelled handles when they reach the top of the heap).
    """

    method: Callable[..., None]
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    deadline_ms: int
    seq: int
    period_ms: int | None = None
    cancelled: bool = False


@dataclass(slots=True, order=True)
class _HeapEntry:
    """
    Heap node wrapping a 'TimerHandle'. Ordered solely by
    '(deadline_ms, seq)'; the handle itself is excluded from
    comparison so 'heapq' never inspects it.
    """

    deadline_ms: int
    seq: int
    handle: TimerHandle = field(compare=False)


class Timer(Subsystem):
    """
    Stack-wide millisecond-resolution timer Subsystem.

    Maintains a single min-heap of '_HeapEntry' nodes keyed by
    '(deadline_ms, seq)'. The worker thread (inherited from
    'Subsystem') sleeps on a 'threading.Event' until the nearest
    deadline or until a registration / cancellation wakes it, then
    pops and dispatches every due entry. Periodic entries are
    re-armed by advancing their deadline by exactly 'period_ms'
    (interval-based, so they do not drift).

    External callers register / cancel from arbitrary stack
    threads; '_lock' (RLock) guards every heap mutation. Callback
    invocation happens with the lock released so a handler may
    re-enter 'call_later' / 'cancel' without deadlocking.

    A legacy shim layer ('register_method', 'register_timer',
    'is_expired', 'unregister_method',
    'unregister_timers_with_prefix') maps the old name / flag API
    onto the new core so existing TCP / ICMPv6 consumers do not
    churn in the same commit.

    Note: 'is_expired(name)' returns True for unknown names —
    a never-registered named timer collapses with one that has
    already fired.
    """

    _subsystem_name = "Timer"

    _heap: list[_HeapEntry]
    _lock: threading.RLock
    _wakeup: threading.Event
    _seq: int
    _legacy_method_handles: dict[Callable[..., None], list[TimerHandle]]
    _legacy_named_flags: dict[str, TimerHandle]

    @override
    def __init__(self) -> None:
        """
        Class constructor.
        """

        super().__init__()

        self._heap = []
        self._lock = threading.RLock()
        self._wakeup = threading.Event()
        self._seq = 0
        self._legacy_method_handles = {}
        self._legacy_named_flags = {}

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

    def _next_seq(self) -> int:
        """
        Return a fresh monotonic sequence number. Callers hold
        '_lock'; the counter breaks heap-key ties so same-deadline
        entries fire in registration order.
        """

        seq = self._seq
        self._seq += 1
        return seq

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

        with self._lock:
            handle = TimerHandle(
                method=method,
                args=args,
                kwargs=kwargs,
                deadline_ms=self.now_ms + delay_ms,
                seq=self._next_seq(),
            )
            heapq.heappush(self._heap, _HeapEntry(handle.deadline_ms, handle.seq, handle))

        self._wakeup.set()
        return handle

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

        with self._lock:
            handle = TimerHandle(
                method=method,
                args=args,
                kwargs=kwargs,
                deadline_ms=self.now_ms + period_ms,
                seq=self._next_seq(),
                period_ms=period_ms,
            )
            heapq.heappush(self._heap, _HeapEntry(handle.deadline_ms, handle.seq, handle))

        self._wakeup.set()
        return handle

    def cancel(self, handle: TimerHandle, /) -> None:
        """
        Mark 'handle' as cancelled. The worker drops it the next
        time it surfaces at the top of the heap. Idempotent; a
        no-op if the handle already fired or was already cancelled.
        """

        handle.cancelled = True
        self._wakeup.set()

    @override
    def stop(self) -> None:
        """
        Stop the subsystem. Sets the stop event and wakes the
        worker out of its 'Event.wait()' so teardown does not
        block for up to '_IDLE_WAKEUP__SEC' on an idle stack.
        """

        self._event__stop_subsystem.set()
        self._wakeup.set()
        super().stop()

    @override
    def _subsystem_loop(self) -> None:
        """
        Pop and dispatch every due heap entry, re-arm periodics,
        then block until the next deadline or a wakeup signal.
        """

        while True:
            self._wakeup.clear()

            with self._lock:
                now = self.now_ms

                due: list[TimerHandle] = []
                while self._heap and self._heap[0].deadline_ms <= now:
                    entry = heapq.heappop(self._heap)
                    if entry.handle.cancelled:
                        continue
                    due.append(entry.handle)

                for handle in due:
                    if handle.period_ms is not None and not handle.cancelled:
                        handle.deadline_ms += handle.period_ms
                        handle.seq = self._next_seq()
                        heapq.heappush(
                            self._heap,
                            _HeapEntry(handle.deadline_ms, handle.seq, handle),
                        )

                if self._heap:
                    wait_s = max(0.0, (self._heap[0].deadline_ms - now) / 1000.0)
                else:
                    wait_s = _IDLE_WAKEUP__SEC

            for handle in due:
                try:
                    handle.method(*handle.args, **handle.kwargs)
                except Exception:  # pylint: disable=broad-exception-caught
                    name = getattr(handle.method, "__name__", repr(handle.method))
                    __debug__ and log("timer", f"<r>Handler raised: {name}</>")

            if self._event__stop_subsystem.is_set():
                return

            self._wakeup.wait(timeout=wait_s)

            if self._event__stop_subsystem.is_set():
                return

    # ----------------------------------------------------------------
    # Legacy shim layer — maps the old name / flag API onto the new
    # heap core. Removed in a later phase once consumers migrate.
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
        LEGACY. Shim over 'call_later' / 'call_periodic'.

        'repeat_count == -1' maps to 'call_periodic(period_ms=delay)';
        'repeat_count == 0' maps to 'call_later(delay_ms=delay)'. The
        dropped features ('delay_exp', 'stop_condition', finite
        'repeat_count') have no production consumer and are asserted
        out.
        """

        assert delay >= 1, f"register_method delay must be >= 1; got {delay}"
        assert delay_exp is False, "register_method delay_exp not supported"
        assert stop_condition is None, "register_method stop_condition not supported"
        assert repeat_count in (-1, 0), f"register_method repeat_count must be -1 or 0; got {repeat_count}"

        __debug__ and log(
            "timer",
            f"<r>Registering method: {method.__name__}, delay={delay}</>",
        )

        call_args = () if args is None else tuple(args)
        call_kwargs = {} if kwargs is None else kwargs

        if repeat_count == -1:
            handle = self.call_periodic(delay, method, *call_args, **call_kwargs)
        else:
            handle = self.call_later(delay, method, *call_args, **call_kwargs)

        with self._lock:
            self._legacy_method_handles.setdefault(method, []).append(handle)

    def register_timer(self, *, name: str, timeout: int) -> None:
        """
        LEGACY. Shim over 'call_later' that clears a named flag
        instead of invoking a consumer method. Re-registering an
        existing name cancels the prior entry first.
        """

        assert timeout >= 1, f"register_timer timeout must be >= 1; got {timeout}"

        __debug__ and log("timer", f"<r>Registering timer: {name}, timeout={timeout}</>")

        with self._lock:
            old = self._legacy_named_flags.get(name)
            if old is not None:
                old.cancelled = True
            self._legacy_named_flags[name] = self.call_later(timeout, self._clear_named_flag, name)

    def _clear_named_flag(self, name: str, /) -> None:
        """
        Drop the named-flag entry for 'name' when its legacy timer
        fires. After this, 'is_expired(name)' returns True.
        """

        with self._lock:
            self._legacy_named_flags.pop(name, None)

    def is_expired(self, name: str) -> bool:
        """
        LEGACY. True when 'name' was never registered OR its timer
        has already fired (the flag entry was cleared). False only
        while the named timer is still counting down.
        """

        with self._lock:
            __debug__ and log("timer", f"<r>Active timers: {set(self._legacy_named_flags)}</>")
            return name not in self._legacy_named_flags

    def unregister_timers_with_prefix(self, prefix: str, /) -> None:
        """
        LEGACY. Cancel every named-flag timer whose name starts
        with 'prefix'. Used by 'TcpSession._change_state' on the
        CLOSED transition to drop per-session entries.
        """

        __debug__ and log("timer", f"<r>Unregistering timers with prefix: {prefix!r}</>")

        with self._lock:
            for name in [n for n in self._legacy_named_flags if n.startswith(prefix)]:
                self._legacy_named_flags[name].cancelled = True
                del self._legacy_named_flags[name]

    def unregister_method(self, method: Callable[..., None], /) -> None:
        """
        LEGACY. Cancel every 'TimerHandle' previously installed by
        'register_method' for the supplied bound method. Used by
        'TcpSession._change_state' on the CLOSED transition to drop
        the per-tick 'tcp_fsm' callback.
        """

        __debug__ and log("timer", f"<r>Unregistering method: {method.__name__}</>")

        with self._lock:
            for handle in self._legacy_method_handles.pop(method, []):
                handle.cancelled = True

        self._wakeup.set()
