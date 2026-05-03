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
This module contains the TCP FSM dispatch table.

Maps every FsmState to its per-state free-function handler defined
in 'pytcp/protocols/tcp/tcp__fsm__<state>.py'. The TcpSession
'tcp_fsm()' entry point uses this table to route events to the
correct handler in O(1) without a 'match'/'case' statement.

pytcp/protocols/tcp/tcp__fsm.py

ver 3.0.4
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.protocols.tcp.tcp__fsm__close_wait import fsm__close_wait
from pytcp.protocols.tcp.tcp__fsm__closed import fsm__closed
from pytcp.protocols.tcp.tcp__fsm__closing import fsm__closing
from pytcp.protocols.tcp.tcp__fsm__established import fsm__established
from pytcp.protocols.tcp.tcp__fsm__fin_wait_1 import fsm__fin_wait_1
from pytcp.protocols.tcp.tcp__fsm__fin_wait_2 import fsm__fin_wait_2
from pytcp.protocols.tcp.tcp__fsm__last_ack import fsm__last_ack
from pytcp.protocols.tcp.tcp__fsm__listen import fsm__listen
from pytcp.protocols.tcp.tcp__fsm__syn_rcvd import fsm__syn_rcvd
from pytcp.protocols.tcp.tcp__fsm__syn_sent import fsm__syn_sent
from pytcp.protocols.tcp.tcp__fsm__time_wait import fsm__time_wait

if TYPE_CHECKING:
    from pytcp.protocols.tcp.tcp__session import TcpSession
    from pytcp.socket.tcp__metadata import TcpMetadata


FsmHandler = Callable[
    ["TcpSession"],  # noqa: F821 - forward reference resolved at TYPE_CHECKING
    None,
]


FSM_HANDLERS: dict[FsmState, Callable[..., None]] = {
    FsmState.CLOSED: fsm__closed,
    FsmState.LISTEN: fsm__listen,
    FsmState.SYN_SENT: fsm__syn_sent,
    FsmState.SYN_RCVD: fsm__syn_rcvd,
    FsmState.ESTABLISHED: fsm__established,
    FsmState.FIN_WAIT_1: fsm__fin_wait_1,
    FsmState.FIN_WAIT_2: fsm__fin_wait_2,
    FsmState.CLOSING: fsm__closing,
    FsmState.CLOSE_WAIT: fsm__close_wait,
    FsmState.LAST_ACK: fsm__last_ack,
    FsmState.TIME_WAIT: fsm__time_wait,
}


def dispatch(
    session: TcpSession,
    *,
    packet_rx_md: TcpMetadata | None = None,
    syscall: SysCall | None = None,
    timer: bool | None = None,
) -> None:
    """
    Dispatch the current FSM event to the per-state handler.
    """

    FSM_HANDLERS[session._state](  # pylint: disable=protected-access
        session,
        packet_rx_md=packet_rx_md,
        syscall=syscall,
        timer=timer,
    )
