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
This module contains the IPC control-channel client connector.

'IpcClient' opens an AF_UNIX stream connection to the daemon and issues
synchronous request/response calls over it: send a framed request, block
for the matching framed response, decode and return it. It is part of
the extraction-ready codec core — net_proto + stdlib only, no pytcp stack
reach-in (see docs/refactor/kernel_userspace_separation.md §2).

pytcp/ipc/ipc__client.py

ver 3.0.7
"""

import socket
import threading
from types import TracebackType
from typing import Self

from net_proto.lib.buffer import Buffer
from pytcp.ipc.ipc__enums import IpcMessageKind, IpcOp
from pytcp.ipc.ipc__errors import IpcConnectionError
from pytcp.ipc.ipc__frame import recv_frame, send_frame
from pytcp.ipc.ipc__message import IpcMessage

IPC__CLIENT__DEFAULT_TIMEOUT__SEC: float = 5.0
IPC__CLIENT__REQ_ID_MASK: int = 0xFFFFFFFF


class IpcClient:
    """
    A synchronous IPC control-channel client connected to the daemon.
    """

    def __init__(
        self,
        *,
        socket_path: str,
        timeout: float = IPC__CLIENT__DEFAULT_TIMEOUT__SEC,
    ) -> None:
        """
        Open an AF_UNIX stream connection to the daemon control socket.
        """

        self._lock = threading.Lock()
        self._next_req_id = 0
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.settimeout(timeout)
        self._socket.connect(socket_path)

    def request(self, op: int, /, *, body: Buffer = b"") -> IpcMessage:
        """
        Send a request for 'op' and return the daemon's response.

        Serialised under a lock so the send-then-receive pair is atomic
        per call, making a single client safe to share across threads.
        """

        with self._lock:
            req_id = self._next_req_id
            self._next_req_id = (self._next_req_id + 1) & IPC__CLIENT__REQ_ID_MASK

            request = IpcMessage(
                kind=IpcMessageKind.REQUEST,
                op=op,
                req_id=req_id,
                body=bytes(body),
            )

            send_frame(self._socket, request.to_bytes())

            payload = recv_frame(self._socket)
            if payload is None:
                raise IpcConnectionError(
                    "Daemon closed the control connection while awaiting a response.",
                )

            return IpcMessage.from_bytes(payload)

    def ping(self) -> bytes:
        """
        Issue a PING and return the response body.
        """

        return self.request(IpcOp.PING).body

    def close(self) -> None:
        """
        Close the control connection to the daemon.
        """

        try:
            self._socket.close()
        except OSError:
            pass

    def __enter__(self) -> Self:
        """
        Enter the client context, returning the connected client.
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
