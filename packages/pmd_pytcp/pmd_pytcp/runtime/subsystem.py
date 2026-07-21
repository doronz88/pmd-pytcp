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
This module contains the base class for all of the subsystems used by the stack.

pmd_pytcp/runtime/subsystem.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod

from pmd_pytcp.lib.logger import log

SUBSYSTEM_SLEEP_TIME__SEC = 0.1


class Subsystem(ABC):
    """
    Base class for stack-internal background runtime components.
    Each subclass implements the coroutine '_subsystem_loop()'
    which the base wraps in a 'while not stop_event' loop running
    on an 'asyncio.Task' created by 'start()' and cancelled by
    'stop()'. Used by the DHCP clients and 'NeighborCache' (the
    IPv4 'ArpCache' and IPv6 'NdCache' parents) — every long-lived
    kernel-side runtime that needs an independent flow of control
    on the stack's event loop. (See
    'docs/refactor/pure_asyncio.md' — the whole stack runs on ONE
    event loop; there are no threads.)

    This is a runtime / kernel-side primitive, NOT a Phase-3
    public API surface. Userspace consumers MUST NOT
    subclass it — see CLAUDE.md "no userspace reach-through
    to stack internals". The home in 'pmd_pytcp/runtime/' is
    structurally enforcing that boundary.

    Initialisation contract — subclasses must set
    'self._subsystem_name' BEFORE calling 'super().__init__()'
    because the base init logs an 'Initializing <name>' line
    on the 'stack' channel.
    """

    _subsystem_name: str
    _event__stop_subsystem: asyncio.Event
    _task: "asyncio.Task[None] | None"

    def __init__(self, *, info: str | None = None) -> None:
        """
        Initialize the subsystem.
        """

        log.enabled and log(
            "stack",
            (f"Initializing {self._subsystem_name}" + (f" [{info}]" if info else "")),
        )

        self._event__stop_subsystem = asyncio.Event()
        self._task = None

    def start(self) -> None:
        """
        Start the subsystem. Requires a running event loop — the
        worker is an 'asyncio.Task' on the caller's loop.
        """

        log.enabled and log("stack", f"Starting {self._subsystem_name}")

        # Double-start guard. If a worker task is already running
        # and 'start()' is called again, the previous task would be
        # orphaned (its '_event__stop_subsystem' reset + lost
        # reference). Fail loudly instead.
        assert self._task is None or self._task.done(), (
            f"{self._subsystem_name}.start() called while a worker is still running; " f"call stop() before restart."
        )

        self._event__stop_subsystem.clear()
        self._task = asyncio.get_running_loop().create_task(self._task__subsystem(), name=self._subsystem_name)
        self._start()

    def stop(self) -> None:
        """
        Stop the subsystem. Sets the stop event and cancels the
        worker task; cancellation lands at the worker's next await
        point. Sync-safe from loop context — use 'wait_stopped()'
        to await the worker's actual exit.
        """

        log.enabled and log("stack", f"Stopping {self._subsystem_name}")

        self._event__stop_subsystem.set()
        if self._task is not None and not self._task.done():
            self._task.cancel()
        self._stop()

    async def wait_stopped(self) -> None:
        """
        Await the worker task's completion after 'stop()'. The
        joined task reference is intentionally retained on
        'self._task' so consumers can poll 'done()'; restart via
        'start()' is gated by the double-start assert on 'done()'
        rather than on identity.
        """

        if self._task is not None:
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    def _start(self) -> None:
        """
        Perform additional actions after starting the subsystem.
        """

    def _stop(self) -> None:
        """
        Perform additional actions after stopping the subsystem.
        """

    async def _task__subsystem(self) -> None:
        """
        Run the subsystem loop until the stop event is set or the
        task is cancelled.
        """

        log.enabled and log("stack", f"Started {self._subsystem_name}")

        try:
            while not self._event__stop_subsystem.is_set():
                await self._subsystem_loop()
        except asyncio.CancelledError:
            pass

        log.enabled and log("stack", f"Stopped {self._subsystem_name}")

    @abstractmethod
    async def _subsystem_loop(self) -> None:
        """
        Execute the subsystem operations in a loop.
        """

        raise NotImplementedError
