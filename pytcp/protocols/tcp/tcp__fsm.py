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

# pylint: disable=protected-access
# pyright: reportPrivateUsage=false

"""
This module contains the TCP FSM dispatch tables.

Each FSM state's per-event-kind handler is a free function in
'pytcp/protocols/tcp/tcp__fsm__<state>.py'. Three dispatch
tables map the FsmState to the matching handler for each
event kind: packet arrival, syscall invocation, and timer
tick. The TcpSession 'tcp_fsm()' entry point picks the
appropriate dispatcher based on which event kwarg is set.

States that have nothing to do for a given event kind are
absent from that event's table - the dispatcher uses dict
'.get()' so the no-op case is a single attribute access.

pytcp/protocols/tcp/tcp__fsm.py

ver 3.0.4
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.protocols.tcp.tcp__fsm__close_wait import (
    fsm__close_wait__packet,
    fsm__close_wait__syscall,
    fsm__close_wait__timer,
)
from pytcp.protocols.tcp.tcp__fsm__closed import fsm__closed__syscall
from pytcp.protocols.tcp.tcp__fsm__closing import fsm__closing__packet
from pytcp.protocols.tcp.tcp__fsm__established import (
    fsm__established__packet,
    fsm__established__syscall,
    fsm__established__timer,
)
from pytcp.protocols.tcp.tcp__fsm__fin_wait_1 import (
    fsm__fin_wait_1__packet,
    fsm__fin_wait_1__timer,
)
from pytcp.protocols.tcp.tcp__fsm__fin_wait_2 import fsm__fin_wait_2__packet
from pytcp.protocols.tcp.tcp__fsm__last_ack import (
    fsm__last_ack__packet,
    fsm__last_ack__timer,
)
from pytcp.protocols.tcp.tcp__fsm__listen import (
    fsm__listen__packet,
    fsm__listen__syscall,
)
from pytcp.protocols.tcp.tcp__fsm__syn_rcvd import (
    fsm__syn_rcvd__packet,
    fsm__syn_rcvd__syscall,
    fsm__syn_rcvd__timer,
)
from pytcp.protocols.tcp.tcp__fsm__syn_sent import (
    fsm__syn_sent__packet,
    fsm__syn_sent__syscall,
    fsm__syn_sent__timer,
)
from pytcp.protocols.tcp.tcp__fsm__time_wait import (
    fsm__time_wait__packet,
    fsm__time_wait__timer,
)

if TYPE_CHECKING:
    from pytcp.protocols.tcp.tcp__session import TcpSession
    from pytcp.socket.tcp__metadata import TcpMetadata


# Per-event-kind dispatch tables. Absence of a state from a
# table means the state has no handler for that event kind
# (the dispatcher treats it as a no-op).

FSM_PACKET_HANDLERS: dict[FsmState, Callable[..., None]] = {
    FsmState.LISTEN: fsm__listen__packet,
    FsmState.SYN_SENT: fsm__syn_sent__packet,
    FsmState.SYN_RCVD: fsm__syn_rcvd__packet,
    FsmState.ESTABLISHED: fsm__established__packet,
    FsmState.FIN_WAIT_1: fsm__fin_wait_1__packet,
    FsmState.FIN_WAIT_2: fsm__fin_wait_2__packet,
    FsmState.CLOSING: fsm__closing__packet,
    FsmState.CLOSE_WAIT: fsm__close_wait__packet,
    FsmState.LAST_ACK: fsm__last_ack__packet,
    FsmState.TIME_WAIT: fsm__time_wait__packet,
}

FSM_SYSCALL_HANDLERS: dict[FsmState, Callable[..., None]] = {
    FsmState.CLOSED: fsm__closed__syscall,
    FsmState.LISTEN: fsm__listen__syscall,
    FsmState.SYN_SENT: fsm__syn_sent__syscall,
    FsmState.SYN_RCVD: fsm__syn_rcvd__syscall,
    FsmState.ESTABLISHED: fsm__established__syscall,
    FsmState.CLOSE_WAIT: fsm__close_wait__syscall,
}

FSM_TIMER_HANDLERS: dict[FsmState, Callable[..., None]] = {
    FsmState.SYN_SENT: fsm__syn_sent__timer,
    FsmState.SYN_RCVD: fsm__syn_rcvd__timer,
    FsmState.ESTABLISHED: fsm__established__timer,
    FsmState.FIN_WAIT_1: fsm__fin_wait_1__timer,
    FsmState.CLOSE_WAIT: fsm__close_wait__timer,
    FsmState.LAST_ACK: fsm__last_ack__timer,
    FsmState.TIME_WAIT: fsm__time_wait__timer,
}


def dispatch_packet(session: TcpSession, packet_rx_md: TcpMetadata) -> None:
    """
    Dispatch an inbound packet event to the per-state packet
    handler for the session's current state. States without a
    packet handler (e.g. CLOSED) silently no-op.
    """

    handler = FSM_PACKET_HANDLERS.get(session._state)
    if handler is not None:
        handler(session, packet_rx_md)


def dispatch_syscall(session: TcpSession, syscall: SysCall) -> None:
    """
    Dispatch a syscall event to the per-state syscall handler
    for the session's current state. States without a syscall
    handler (e.g. CLOSING, FIN_WAIT_1) silently no-op.
    """

    handler = FSM_SYSCALL_HANDLERS.get(session._state)
    if handler is not None:
        handler(session, syscall)


def dispatch_timer(session: TcpSession) -> None:
    """
    Dispatch a timer-tick event to the per-state timer
    handler for the session's current state. States without
    a timer handler (e.g. CLOSED, LISTEN) silently no-op.
    """

    handler = FSM_TIMER_HANDLERS.get(session._state)
    if handler is not None:
        handler(session)
