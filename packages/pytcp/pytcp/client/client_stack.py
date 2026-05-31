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
This module contains the 'ClientStack' — the client-side mirror of the
'pytcp.stack' control surface.

'ClientStack' owns one IPC control connection to the daemon and exposes
a per-plane proxy ('.sysctl', and — as later Phase-1 commits land —
'.route' / '.link' / '.address' / '.neighbor' / '.membership'). Each
proxy mirrors the in-process API's method signatures and marshals calls
across the boundary. 'connect()' is the entry point.

pytcp/client/client_stack.py

ver 3.0.7
"""

from types import TracebackType
from typing import Self

from pytcp.client.client__address import ClientAddress
from pytcp.client.client__link import ClientLink
from pytcp.client.client__membership import ClientMembership
from pytcp.client.client__neighbor import ClientNeighbor
from pytcp.client.client__route import ClientRoute
from pytcp.client.client__sysctl import ClientSysctl
from pytcp.client.client__tcp_socket import ClientTcpSocket
from pytcp.ipc.ipc__client import IpcClient
from pytcp.socket import AddressFamily, SocketType


class ClientStack:
    """
    The client-side mirror of the 'pytcp.stack' control surface.
    """

    def __init__(self, *, socket_path: str) -> None:
        """
        Open an IPC control connection and build the per-plane proxies.
        """

        self._client = IpcClient(socket_path=socket_path)
        self.sysctl = ClientSysctl(self._client)
        self.route = ClientRoute(self._client)
        self.link = ClientLink(self._client)
        self.address = ClientAddress(self._client)
        self.neighbor = ClientNeighbor(self._client)
        self.membership = ClientMembership(self._client)

    def socket(
        self,
        family: AddressFamily = AddressFamily.INET4,
        type: SocketType = SocketType.STREAM,
    ) -> ClientTcpSocket:
        """
        Open a TCP socket on the daemon, returning a client shim whose
        data path is a real selectable descriptor. Mirrors the in-process
        'socket()' factory's family / type arguments; only STREAM (TCP)
        is supported on the client today.
        """

        assert type is SocketType.STREAM, f"Only SocketType.STREAM is supported; got {type!r}."

        return ClientTcpSocket(self._client, family=family)

    def close(self) -> None:
        """
        Close the control connection to the daemon.
        """

        self._client.close()

    def __enter__(self) -> Self:
        """
        Enter the client-stack context, returning the connected stack.
        """

        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """
        Close the control connection on context exit.
        """

        self.close()


def connect(*, socket_path: str) -> ClientStack:
    """
    Connect to a PyTCP daemon and return a 'ClientStack' mirror.
    """

    return ClientStack(socket_path=socket_path)
