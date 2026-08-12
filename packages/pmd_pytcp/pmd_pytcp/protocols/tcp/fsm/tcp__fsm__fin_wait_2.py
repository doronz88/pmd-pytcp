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
# pyright: reportPrivateUsage=false, reportUnusedExpression=false

"""
This module contains the TCP FSM FIN_WAIT_2 state handler.

pmd_pytcp/protocols/tcp/fsm/tcp__fsm__fin_wait_2.py

ver 3.0.7
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pmd_pytcp.lib.logger import log
from pmd_pytcp.protocols.tcp import tcp__constants
from pmd_pytcp.protocols.tcp.tcp__enums import ConnError, FsmState, SysCall
from pmd_pytcp.protocols.tcp.tcp__seq import gt32, in_range32

if TYPE_CHECKING:
    from pmd_pytcp.protocols.tcp.session import TcpSession
    from pmd_pytcp.socket.tcp__metadata import TcpMetadata


def fsm__fin_wait_2__timer(session: TcpSession) -> None:
    """
    TCP FSM FIN_WAIT_2 state timer handler.

    Run the orphan reaper (Linux 'tcp_fin_timeout' parity): when
    the named 'fin_wait_2' timer — armed only for ORPHANED
    connections, whose socket the application has fully closed —
    expires without the peer's FIN arriving, transition to
    CLOSED. Deliberate deviation from RFC 9293's unbounded
    FIN_WAIT_2 hold: an orphan has no reader, so holding the TCB
    (and its local port) for a vanished peer serves nobody.
    """

    if session._timer_expired("fin_wait_2"):
        session._change_state(FsmState.CLOSED)


def fsm__fin_wait_2__syscall(session: TcpSession, syscall: SysCall) -> None:
    """
    TCP FSM FIN_WAIT_2 state syscall handler.

    Got CLOSE syscall -> the application has now fully closed a
    connection it had earlier half-closed via 'shutdown(SHUT_WR)';
    nobody can ever read the peer's remaining data, so the
    connection is orphaned. Arm the Linux-'tcp_fin_timeout'-parity
    reaper (see 'fsm__fin_wait_2__timer'); the FIN-exchange
    machinery itself is already in flight.

    Got ABORT syscall -> flush and reset per RFC 9293 §3.9.1
    (FIN_WAIT_2 is synchronized: RST goes on the wire).
    'TcpSession.abort()' owns the per-state semantics and the
    terminal transition to CLOSED that unregisters the socket
    and releases its local port.
    """

    if syscall is SysCall.CLOSE:
        session._arm_timer(
            "fin_wait_2",
            tcp__constants.TCP__FIN_WAIT_2__TIMEOUT_MS,
        )

    if syscall is SysCall.ABORT:
        session.abort()


def fsm__fin_wait_2__packet(session: TcpSession, packet_rx_md: TcpMetadata) -> None:
    """
    TCP FSM FIN_WAIT_2 state packet handler.
    """

    # Got SYN-bearing segment in a synchronized state -> Send a
    # challenge ACK per RFC 9293 §3.10.7.4 / RFC 5961 §4.
    if packet_rx_md.tcp__flag_syn:
        session._emit_challenge_ack()
        log.enabled and log(
            "tcp-ss",
            f"[{session}] - Sent challenge ACK for SYN-in-fin_wait_2 (RFC 9293 §3.10.7.4)",
        )
        return

    # RFC 9293 §3.10.7.4 step 1 receive-window acceptability
    # check; on unacceptable segments the helper emits the
    # mandated ACK reply and returns False, the caller drops.
    if not session._check_segment_acceptability(packet_rx_md):
        return

    # Got ACK packet -> Process data.
    if all({packet_rx_md.tcp__flag_ack}) and not any(
        {
            packet_rx_md.tcp__flag_syn,
            packet_rx_md.tcp__flag_rst,
            packet_rx_md.tcp__flag_fin,
        }
    ):
        # Packet sanity check.
        if packet_rx_md.tcp__seq == session._rcv_seq.nxt and in_range32(
            packet_rx_md.tcp__ack, session._snd_seq.una, session._snd_seq.max
        ):
            session._process_ack_packet(packet_rx_md)
            # Immediately acknowledge the received data if any.
            if packet_rx_md.tcp__data:
                session._transmit_packet(flag_ack=True)
            return
        # RFC 9293 §3.10.7.4 step 5 empty-ACK reply on
        # 'ack > SND.MAX'. Same gap as fixed in CLOSING /
        # FIN_WAIT_1.
        if gt32(packet_rx_md.tcp__ack, session._snd_seq.max):
            session._emit_challenge_ack()
        return

    # Got FIN + ACK packet -> Send ACK packet / change state to TIME_WAIT.
    if all({packet_rx_md.tcp__flag_fin, packet_rx_md.tcp__flag_ack}) and not any(
        {packet_rx_md.tcp__flag_syn, packet_rx_md.tcp__flag_rst}
    ):
        # Packet sanity check.
        if packet_rx_md.tcp__seq == session._rcv_seq.nxt and in_range32(
            packet_rx_md.tcp__ack, session._snd_seq.una, session._snd_seq.max
        ):
            session._process_ack_packet(packet_rx_md)
            # Send out final ACK packet.
            session._transmit_packet(flag_ack=True)
            log.enabled and log(
                "tcp-ss",
                f"[{session}] - Sent final ACK ({session._rcv_seq.nxt}) packet",
            )
            # Change state to TIME_WAIT.
            session._change_state(FsmState.TIME_WAIT)
            # The peer's FIN arrived — the orphan reaper (armed
            # only for application-closed connections) is moot;
            # TIME_WAIT's own 2MSL delay owns the teardown now.
            session._cancel_timer("fin_wait_2")
            # Initialize TIME_WAIT delay
            session._arm_timer("time_wait", tcp__constants.TCP__TIME_WAIT__DELAY_MS)
            return

    # Got RST (bare or RST+ACK) -> Process per RFC 9293 §3.10.7.4
    # three-way classification via the shared helper. Mark the
    # connection reset so a blocked / subsequent 'recv()' on the
    # still-readable half-closed socket raises instead of
    # misreading the destroyed stream as a clean EOF.
    if packet_rx_md.tcp__flag_rst and not any({packet_rx_md.tcp__flag_fin, packet_rx_md.tcp__flag_syn}):
        if session._check_rst_acceptability(packet_rx_md):
            session._connection_error = ConnError.RESET
            session._change_state(FsmState.CLOSED)
