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

# pyright: reportPrivateUsage=false

"""
This module contains the TCP FSM TIME_WAIT state handler.

pytcp/protocols/tcp/tcp__fsm__time_wait.py

ver 3.0.4
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.protocols.tcp.tcp__seq import add32

if TYPE_CHECKING:
    from pytcp.protocols.tcp.tcp__session import TcpSession
    from pytcp.socket.tcp__metadata import TcpMetadata


def fsm__time_wait(
    session: TcpSession,
    *,
    packet_rx_md: TcpMetadata | None,
    syscall: SysCall | None,
    timer: bool | None,
) -> None:
    """
    TCP FSM TIME_WAIT state handler.
    """

    # Got timer event -> Run TIME_WAIT delay.
    if timer and stack.timer.is_expired(f"{session}-time_wait"):
        session._change_state(FsmState.CLOSED)
        return

    # Got peer FIN retransmit -> Acknowledge it and restart the
    # TIME_WAIT timer per RFC 9293 §3.10.7.5: 'The only thing
    # that can arrive in this state is a retransmission of the
    # remote FIN. Acknowledge it, and restart the 2 MSL
    # timeout.' The FIN's seq does not advance with retransmits,
    # so peer is replaying the same byte of sequence space we
    # already accepted (RCV.NXT - 1).
    if packet_rx_md and packet_rx_md.tcp__flag_fin and add32(packet_rx_md.tcp__seq, 1) == session._rcv_nxt:
        session._transmit_packet(flag_ack=True)
        stack.timer.register_timer(
            name=f"{session}-time_wait",
            timeout=tcp__constants.TIME_WAIT_DELAY,
        )
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - Re-ACKed peer's FIN retransmit and restarted TIME_WAIT timer",
        )
        return

    # Got SYN-bearing segment in TIME_WAIT -> Send a challenge
    # ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4. PyTCP does not
    # implement the Timestamp Option (PAWS), so RFC 9293's
    # TIME_WAIT-special connection-recycling path is unreachable
    # and the default challenge-ACK behaviour applies.
    if packet_rx_md and packet_rx_md.tcp__flag_syn:
        session._emit_challenge_ack()
        __debug__ and log(
            "tcp-ss",
            f"[{session}] - Sent challenge ACK for SYN-in-time_wait (RFC 9293 §3.10.7.4)",
        )
        return
