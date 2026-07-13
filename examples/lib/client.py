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
This module contains the 'user space' generic client base class used in
the examples.

A client is a pair of asyncio tasks (sender + receiver) on the stack's
event loop ('docs/refactor/pure_asyncio.md'). 'start()' spawns a boot
task that opens/binds/connects the client socket (connect is a
coroutine on the async socket API) and then runs the two workers.

examples/lib/client.py

ver 3.0.7
"""

from abc import abstractmethod
from typing import override

from examples.lib.subsystem import Subsystem
from pmd_net_addr import Ip4Address, Ip6Address, IpVersion
from pmd_pytcp.socket import (
    IPPROTO_ICMP4,
    IPPROTO_ICMP6,
    socket,
)


class Client(Subsystem):
    """
    Generic client class.
    """

    _protocol_name: str
    _subsystem_name: str
    _local_ip_address: Ip4Address | Ip6Address | None
    _local_port: int
    _remote_ip_address: Ip4Address | Ip6Address
    _remote_port: int
    _client_socket: socket | None

    @override
    def start(self) -> None:
        """
        Start the client (spawns the boot task; requires a running
        loop).
        """

        self._log("Starting the client.")

        if isinstance(self._remote_ip_address, Ip4Address):
            self._local_ip_address = self.stack_ip4_address
        if isinstance(self._remote_ip_address, Ip6Address):
            self._local_ip_address = self.stack_ip6_address

        self._client_socket = None
        self._event__stop_subsystem.clear()

        self._spawn(self._task__client())

    @override
    def stop(self) -> None:
        """
        Stop the client tasks.
        """

        self._log("Stopping the client.")

        super().stop()

    async def _task__client(self) -> None:
        """
        Boot task: open/bind/connect the client socket, then run the
        receiver and sender workers.
        """

        try:
            self._client_socket = await self._get_client_socket()
        except OSError:
            self._event__stop_subsystem.set()
            return

        self._spawn(self._task__receiver())
        self._spawn(self._task__sender())

    async def _get_client_socket(self) -> socket:
        """
        Create, bind and connect the client's socket.
        """

        client_socket = self._get_subsystem_socket(
            ip_version=self._remote_ip_address.version,
            protocol_name=self._protocol_name,
        )

        if self._protocol_name == "ICMP":
            self._local_port = int(IPPROTO_ICMP6 if self._remote_ip_address.version == IpVersion.IP6 else IPPROTO_ICMP4)
            self._remote_port = 0

        try:
            client_socket.bind((str(self._local_ip_address), self._local_port))
            self._log(f"Bound socket to {self._local_ip_address}, port {self._local_port}.")
        except OSError as error:
            self._log(
                f"Unable to bind socket to {self._local_ip_address}, port {self._local_port}. " f"Error: {error!r}.",
            )
            raise error

        try:
            await client_socket.connect((str(self._remote_ip_address), self._remote_port))
            self._log(f"Connection opened to {self._remote_ip_address}, port {self._remote_port}.")
        except OSError as error:
            self._log(
                f"Connection to {self._remote_ip_address}, port {self._remote_port} failed. " f"Error: {error!r}."
            )
            raise error

        return client_socket

    @abstractmethod
    async def _task__sender(self) -> None:
        """
        Task used to send data by the client.
        """

        raise NotImplementedError

    @abstractmethod
    async def _task__receiver(self) -> None:
        """
        Task used to receive data by the client.
        """

        raise NotImplementedError
