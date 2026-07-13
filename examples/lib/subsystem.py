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
This module contains the base class for servers and clients used in examples.

Under the pure-asyncio runtime ('docs/refactor/pure_asyncio.md') an
example subsystem is a set of asyncio tasks on the stack's event loop —
'start()' spawns them (it needs a running loop), 'stop()' sets the stop
event and cancels them, and 'is_alive' reads the stop event, exactly
the shape the thread-based helper used to have.

examples/lib/subsystem.py

ver 3.0.7
"""

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Coroutine
from typing import Any

import click

from pmd_net_addr import Ip4Address, Ip6Address, IpVersion
from pmd_pytcp.socket import (
    AF_INET4,
    AF_INET6,
    IPPROTO_ICMP4,
    IPPROTO_ICMP6,
    SOCK_DGRAM,
    SOCK_RAW,
    SOCK_STREAM,
    socket,
)


class Subsystem(ABC):
    """
    Base class for 'user space' services and clients used in examples.
    """

    stack_ip4_address: Ip4Address | None = None
    stack_ip6_address: Ip6Address | None = None

    _subsystem_name: str

    _event__stop_subsystem: asyncio.Event
    _tasks: "list[asyncio.Task[None]]"

    def __init__(self) -> None:
        """
        Initialize the subsystem.
        """

        self._event__stop_subsystem = asyncio.Event()
        self._tasks = []

    @abstractmethod
    def start(self) -> None:
        """
        Start the subsystem (spawn its tasks; requires a running loop).
        """

        raise NotImplementedError

    def stop(self) -> None:
        """
        Stop the subsystem: set the stop event and cancel its tasks.
        """

        self._log("Stopping the subsystem.")

        self._event__stop_subsystem.set()
        for task in self._tasks:
            if not task.done():
                task.cancel()

    async def wait_stopped(self) -> None:
        """
        Await the subsystem tasks' completion after 'stop()'.
        """

        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    def _spawn(self, coroutine: "Coroutine[Any, Any, None]", /) -> None:
        """
        Track one worker task on the running loop.
        """

        self._tasks.append(asyncio.get_running_loop().create_task(coroutine))

    @property
    def is_alive(self) -> bool:
        """
        Check if the subsystem is alive.
        """

        return self._event__stop_subsystem.is_set() is False

    def _log(self, message: str) -> None:
        """
        Log a subsystem message.
        """

        click.secho(
            f"{self._subsystem_name} - {message}",
            bg="bright_blue",
            fg="bright_yellow",
            bold=True,
        )

    def _get_subsystem_socket(self, *, ip_version: IpVersion, protocol_name: str) -> socket:
        """
        Create and bind the subsystem socket.
        """

        selector = (ip_version, protocol_name)
        if selector == (IpVersion.IP6, "TCP"):
            subsystem_socket = socket(family=AF_INET6, type=SOCK_STREAM)
        elif selector == (IpVersion.IP4, "TCP"):
            subsystem_socket = socket(family=AF_INET4, type=SOCK_STREAM)
        elif selector == (IpVersion.IP6, "UDP"):
            subsystem_socket = socket(family=AF_INET6, type=SOCK_DGRAM)
        elif selector == (IpVersion.IP4, "UDP"):
            subsystem_socket = socket(family=AF_INET4, type=SOCK_DGRAM)
        elif selector == (IpVersion.IP6, "ICMP"):
            subsystem_socket = socket(family=AF_INET6, type=SOCK_RAW, protocol=IPPROTO_ICMP6)
        elif selector == (IpVersion.IP4, "ICMP"):
            subsystem_socket = socket(family=AF_INET4, type=SOCK_RAW, protocol=IPPROTO_ICMP4)
        else:
            raise ValueError("Invalid IP versions or protocol combination.")

        self._log(f"Created socket [{subsystem_socket}].")

        return subsystem_socket
