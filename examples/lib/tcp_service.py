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
This module contains the 'user space' TCP generic service class used in examples.

examples/lib/tcp_service.py

ver 3.0.7
"""

from typing import override

from examples.lib.service import Service
from pmd_pytcp.socket import socket


class TcpService(Service):
    """
    TCP service class.
    """

    _protocol_name = "TCP"

    @override
    async def _task__service(self) -> None:
        """
        Service task: accept inbound connections and spawn a handler
        task per connection.
        """

        if listening_socket := await self._acquire_service_socket():
            listening_socket.listen()
            self._log("Socket set to listening mode.")

            while not self._event__stop_subsystem.is_set():
                try:
                    connected_socket, (remote_ip_address, remote_port) = await listening_socket.accept(timeout=1)
                except TimeoutError:
                    continue

                self._log(f"Inbound connection received from {remote_ip_address}, port {remote_port}.")
                self._spawn(self._service(socket=connected_socket))
