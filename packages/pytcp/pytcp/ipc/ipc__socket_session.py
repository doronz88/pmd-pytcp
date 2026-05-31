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
This module contains the daemon-side per-client socket session.

'SocketSession' owns the per-client handle table backing the SOCKET_CALL
op: one real 'TcpSocket' plus its 'SocketBridge' per open handle. The
'socket' call creates a socketpair, builds the daemon-side socket, and
returns the client end as a passed file descriptor; subsequent
handle-keyed calls (bind / connect / setsockopt / getsockopt / shutdown /
close / getsockname / getpeername) drive the underlying 'TcpSocket'. The
bridge is started once the connection is opened (the stack socket's
'recv' has no session to read before then). When the client disconnects,
'close_all' reaps every still-open socket — the daemon's analogue of a
kernel closing a process's fds on exit.

This module is daemon-side: it imports the real socket factory and the
bridge, so it stays pytcp-resident (see
docs/refactor/kernel_userspace_separation.md §2).

pytcp/ipc/ipc__socket_session.py

ver 3.0.7
"""

import socket
from typing import Any

from pytcp.ipc.ipc__enums import IpcMessageKind
from pytcp.ipc.ipc__message import IpcMessage
from pytcp.ipc.ipc__socket_bridge import SocketBridge
from pytcp.ipc.ipc__socket_rpc import (
    SocketRequest,
    decode_socket_request,
    encode_socket_error,
    encode_socket_ok,
)
from pytcp.socket import AddressFamily, SocketType
from pytcp.socket import socket as pytcp_socket
from pytcp.socket.tcp__socket import TcpSocket

# The socket methods a client may invoke over SOCKET_CALL. 'listen' /
# 'accept' are deliberately absent — passive open is Phase 4.
_ALLOWED_METHODS: frozenset[str] = frozenset(
    {
        "socket",
        "bind",
        "connect",
        "setsockopt",
        "getsockopt",
        "shutdown",
        "close",
        "getsockname",
        "getpeername",
    },
)


class _DaemonSocket:
    """
    A daemon-side stream socket paired with its client data bridge.
    """

    def __init__(self, tcp_socket: TcpSocket, data_end: socket.socket, /) -> None:
        """
        Bind a daemon stream socket to the daemon end of its data
        socketpair, leaving the bridge unstarted until the connection
        opens.
        """

        self._tcp_socket = tcp_socket
        self._bridge = SocketBridge(tcp_socket, data_end)
        self._bridge_started = False

    @property
    def tcp_socket(self) -> TcpSocket:
        """
        Get the underlying daemon-side TCP socket.
        """

        return self._tcp_socket

    def start_bridge(self) -> None:
        """
        Start the data bridge once (idempotent), after the connection
        has a session for the RX pump to read from.
        """

        if not self._bridge_started:
            self._bridge.start()
            self._bridge_started = True

    def close(self, *, abort: bool) -> None:
        """
        Stop the bridge and tear down the TCP connection — abortively
        (RST) on a client-disconnect reap, gracefully (FIN) on an
        explicit close.
        """

        self._bridge.stop()
        if self._tcp_socket.tcp_session is not None:
            if abort:
                self._tcp_socket.abort()
            else:
                self._tcp_socket.close()


class SocketSession:
    """
    The per-client socket-handle table backing the SOCKET_CALL op.
    """

    def __init__(self) -> None:
        """
        Start with an empty handle table.
        """

        self._sockets: dict[int, _DaemonSocket] = {}
        self._next_handle = 0

    def handle(self, request: IpcMessage, /) -> tuple[IpcMessage, socket.socket | None]:
        """
        Serve one SOCKET_CALL request, returning the response and — for
        the 'socket' call — the client-end socket to pass alongside it.

        Any failure is forwarded as a RESPONSE_ERROR carrying the
        exception's type name and message, which the client turns back
        into an 'IpcRemoteError' (the same boundary translation the
        control plane uses).
        """

        try:
            value, fd_socket = self._invoke(decode_socket_request(request.body))
        except Exception as error:
            return (
                IpcMessage(
                    kind=IpcMessageKind.RESPONSE_ERROR,
                    op=request.op,
                    req_id=request.req_id,
                    body=encode_socket_error(error_type=type(error).__name__, message=str(error)),
                ),
                None,
            )

        return (
            IpcMessage(
                kind=IpcMessageKind.RESPONSE_OK,
                op=request.op,
                req_id=request.req_id,
                body=encode_socket_ok(value),
            ),
            fd_socket,
        )

    def close_all(self) -> None:
        """
        Reap every still-open socket on client disconnect.
        """

        for daemon_socket in list(self._sockets.values()):
            try:
                daemon_socket.close(abort=True)
            except OSError:
                pass
        self._sockets.clear()

    def _invoke(self, request: SocketRequest, /) -> tuple[Any, socket.socket | None]:
        """
        Route an allowlisted socket method to the addressed handle.
        """

        if request.method not in _ALLOWED_METHODS:
            raise KeyError(f"Method {request.method!r} is not a permitted socket call.")

        if request.method == "socket":
            return self._open(family=request.args["family"])

        daemon_socket = self._sockets.get(request.handle) if request.handle is not None else None
        if daemon_socket is None:
            raise KeyError(f"Unknown socket handle {request.handle!r}.")

        tcp_socket = daemon_socket.tcp_socket

        match request.method:
            case "bind":
                tcp_socket.bind(request.args["address"])
                return None, None
            case "connect":
                tcp_socket.connect(request.args["address"])
                daemon_socket.start_bridge()
                return None, None
            case "setsockopt":
                tcp_socket.setsockopt(request.args["level"], request.args["optname"], request.args["value"])
                return None, None
            case "getsockopt":
                return tcp_socket.getsockopt(request.args["level"], request.args["optname"]), None
            case "shutdown":
                tcp_socket.shutdown(request.args["how"])
                return None, None
            case "getsockname":
                return tcp_socket.getsockname(), None
            case "getpeername":
                return tcp_socket.getpeername(), None
            case "close":
                self._sockets.pop(request.handle)  # type: ignore[arg-type]
                daemon_socket.close(abort=False)
                return None, None

        raise KeyError(f"Method {request.method!r} is not a permitted socket call.")

    def _open(self, *, family: AddressFamily) -> tuple[dict[str, int], socket.socket]:
        """
        Create a daemon-side TCP socket plus its data socketpair, assign
        a handle, and return the handle with the client end to pass.
        """

        tcp_socket = pytcp_socket(family=family, type=SocketType.STREAM)
        assert isinstance(tcp_socket, TcpSocket)

        data_end, client_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        handle = self._next_handle
        self._next_handle += 1
        self._sockets[handle] = _DaemonSocket(tcp_socket, data_end)

        return {"handle": handle}, client_end
