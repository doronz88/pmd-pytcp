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
This module contains the TCP FSM SYN_SENT state handler.

pytcp/protocols/tcp/tcp__fsm__syn_sent.py

ver 3.0.4
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from net_proto.protocols.tcp.tcp__header import TCP__MIN_MSS
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.tcp.tcp__enums import ConnError, FsmState, SysCall
from pytcp.protocols.tcp.tcp__seq import add32, le32, lt32

if TYPE_CHECKING:
    from pytcp.protocols.tcp.tcp__session import TcpSession
    from pytcp.socket.tcp__metadata import TcpMetadata


def fsm__syn_sent(
    session: TcpSession,
    *,
    packet_rx_md: TcpMetadata | None,
    syscall: SysCall | None,
    timer: bool | None,
) -> None:
    """
    TCP FSM SYN_SENT state handler.
    """

    # Got timer event -> Resend SYN packet if its timer expired.
    if timer:
        session._retransmit_packet_timeout()
        session._transmit_data()
        return

    # RFC 9293 §3.10.7.3 step 1: ACK acceptability check.
    # Any incoming segment with ACK set whose SEG.ACK falls outside
    # (SND.UNA, SND.MAX] must elicit '<SEQ=SEG.ACK><CTL=RST>' and the
    # segment itself must be discarded; the RST emit is suppressed if
    # the offending segment also carries the RST bit, to avoid RST/RST
    # loops. This check applies regardless of the SYN / FIN / RST
    # combination on the segment - it must precede the per-flag
    # branches below, matching the order RFC 9293 §3.10.7.3
    # prescribes (step 1 ACK, step 2 RST, step 3 security, step 4 SYN).
    # We bypass '_transmit_packet' for this RST because that helper
    # rewrites '_snd_nxt' from its 'seq' argument, which would corrupt
    # our state by latching the offending peer's ACK number into our
    # send sequence space; the RST itself consumes no sequence space
    # and must leave session bookkeeping untouched.
    # Modular '(SND.UNA, SND.MAX]' check per RFC 9293 §3.4.
    # The chained Python '<' / '<=' fails across the 32-bit
    # wrap when the SYN consumed seq 0xFFFF_FFFF and SND.MAX
    # has wrapped to 0; the modular helpers fire the
    # acceptability test correctly regardless of where in
    # the seq space the ISS happens to fall.
    if (
        packet_rx_md
        and packet_rx_md.tcp__flag_ack
        and not (lt32(session._snd_una, packet_rx_md.tcp__ack) and le32(packet_rx_md.tcp__ack, session._snd_max))
    ):
        if not packet_rx_md.tcp__flag_rst:
            stack.packet_handler.send_tcp_packet(
                ip__local_address=session._local_ip_address,
                ip__remote_address=session._remote_ip_address,
                tcp__local_port=session._local_port,
                tcp__remote_port=session._remote_port,
                tcp__flag_rst=True,
                tcp__seq=packet_rx_md.tcp__ack,
                tcp__ack=0,
                tcp__win=session._rcv_wnd,
            )
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - SYN_SENT: rejected segment with unacceptable "
                f"ACK={packet_rx_md.tcp__ack}, sent RST (RFC 9293 §3.10.7.3)",
            )
        return

    # Got SYN + ACK packet -> Send ACK / change state to ESTABLISHED.
    if (
        packet_rx_md
        and all({packet_rx_md.tcp__flag_syn, packet_rx_md.tcp__flag_ack})
        and not any({packet_rx_md.tcp__flag_fin, packet_rx_md.tcp__flag_rst})
    ):
        # Packet sanity check. RFC 9293 §3.10.7.3 step 4 ("If
        # there are other controls or text in the segment, then
        # continue processing at the sixth step under Section
        # 3.10.7.4 ...") explicitly permits piggybacked data on
        # the SYN+ACK; the data is NOT gated here, it is
        # enqueued into '_rx_buffer' below.
        if packet_rx_md.tcp__ack == session._snd_nxt:
            # Clamp the effective send-MSS to RFC 879 / RFC 6691
            # bounds: at most 'mtu - 40' (so we never fragment on
            # the local link), at least 'TCP__MIN_MSS = 536' (the
            # SMSS floor that 'option absent' would yield - any
            # smaller peer-advertised value, including the
            # malformed 0, is treated as 'option absent').
            session._snd_mss = max(
                TCP__MIN_MSS,
                min(packet_rx_md.tcp__mss, stack.interface_mtu - session._ip_tcp_overhead),
            )
            # Initial '_snd_wnd' = peer's literal SYN+ACK win
            # (unshifted per RFC 7323 §2.2 - "WSopt is not used
            # to scale the value in the window field of the SYN
            # segment itself"). Subsequent post-handshake
            # segments will be shifted by '_snd_wsc' inside
            # '_process_ack_packet'.
            session._snd_wnd = packet_rx_md.tcp__win
            session._rcv_ini = packet_rx_md.tcp__seq
            # Bootstrap RCV.NXT from peer's ISN before
            # '_process_ack_packet' runs - the modular 'max'
            # inside that helper cannot bootstrap from
            # uninitialized 'rcv_nxt = 0' to a peer ISN near
            # the 32-bit wrap (modular distance 0 -> high seq
            # goes the "wrong way"). Mirror the passive-open
            # path's explicit assignment.
            session._rcv_nxt = add32(
                packet_rx_md.tcp__seq,
                packet_rx_md.tcp__flag_syn,
                len(packet_rx_md.tcp__data),
            )
            # Mark peer as contacted so the R2-abort RST
            # gate in '_retransmit_packet_timeout' fires
            # the RST even when 'RCV.NXT' happens to equal
            # 0 (peer's ISN was 0xFFFF_FFFF, modular wrap).
            session._peer_contacted = True
            session._snd_ewn = session._snd_mss
            # Enqueue any piggybacked SYN+ACK data per RFC 9293
            # §3.10.7.4 step 7 BEFORE '_process_ack_packet'
            # runs: the helper's overlap-prefix calculation
            # would otherwise classify all data bytes as
            # already-received (since RCV.NXT was pre-advanced
            # past them above) and silently drop them. Mirrors
            # the LISTEN-side handling for SYN-with-data in
            # '_tcp_fsm_listen'.
            if packet_rx_md.tcp__data:
                session._enqueue_rx_buffer(packet_rx_md.tcp__data)
            # Process ACK packet (uses '_snd_wsc=0' still, so
            # the SYN+ACK's win is preserved unshifted).
            session._process_ack_packet(packet_rx_md)
            # WSCALE bilateral negotiation per RFC 7323 §2.2:
            # store peer's wscale only if WE offered our own.
            # The check 'packet_rx_md.tcp__wscale != 0' is the
            # parser's way of signalling the option was present
            # on the wire (the parser substitutes 0 when the
            # option is absent via 'TcpOptions.wscale or 0').
            # Set '_snd_wsc' AFTER '_process_ack_packet' so the
            # SYN+ACK's literal 'win' value is used unshifted
            # per scenario #6's invariant.
            if session._advertise_wscale and packet_rx_md.tcp__wscale:
                session._snd_wsc = packet_rx_md.tcp__wscale
            else:
                # Bilateral non-offer: no scaling on either side.
                session._rcv_wsc = 0
                session._snd_wsc = 0
            # SACK bilateral negotiation per RFC 2018 §2:
            # active-open mirrors peer's offer. SACK is
            # enabled iff WE advertised on the SYN we sent
            # AND peer echoed SACK-Permitted on the SYN+ACK.
            session._send_sack = session._advertise_sack and packet_rx_md.tcp__sackperm
            # Send initial ACK packet.
            session._transmit_packet(flag_ack=True)
            __debug__ and log(
                "tcp-ss",
                f"[{session}] - Sent initial ACK ({session._rcv_una}) packet",
            )
            # Change state to ESTABLISHED.
            session._change_state(FsmState.ESTABLISHED)
            # Inform connect syscall that connection related event happened.
            session._event__connect.release()
            return

    # Got SYN packet -> Send SYN + ACK packet / change state to SYN_RCVD.
    # Simultaneous-open path per RFC 9293 §3.5.1: peer's bare SYN
    # crossed our outbound SYN before either side saw the other's
    # SYN. Bootstrap peer-side state from peer's SYN options -
    # mirroring the listener-fork pattern in '_tcp_fsm_listen' -
    # then emit a SYN+ACK that reuses our original SYN's seq
    # with peer's ACK piggybacked. The bootstrap is mandatory:
    # without it the SYN+ACK we emit would carry 'ack=0' (the
    # uninitialised '_rcv_nxt' default) and peer's TCP would
    # reject it as not acknowledging their SYN, leaving both
    # ends stuck until R2 fires.
    if (
        packet_rx_md
        and all({packet_rx_md.tcp__flag_syn})
        and not any(
            {
                packet_rx_md.tcp__flag_ack,
                packet_rx_md.tcp__flag_fin,
                packet_rx_md.tcp__flag_rst,
            }
        )
    ):
        # Packet sanity check.
        if packet_rx_md.tcp__ack == 0 and not packet_rx_md.tcp__data:
            # Clamp the effective send-MSS to RFC 879 / RFC 6691
            # bounds: at most 'mtu - overhead', at least
            # 'TCP__MIN_MSS = 536'.
            session._snd_mss = max(
                TCP__MIN_MSS,
                min(packet_rx_md.tcp__mss, stack.interface_mtu - session._ip_tcp_overhead),
            )
            session._snd_wnd = packet_rx_md.tcp__win
            # WSCALE bilateral negotiation per RFC 7323 §2.2.
            if session._advertise_wscale and packet_rx_md.tcp__wscale:
                session._snd_wsc = packet_rx_md.tcp__wscale
            else:
                session._rcv_wsc = 0
                session._snd_wsc = 0
            # SACK bilateral negotiation per RFC 2018 §2.
            session._send_sack = session._advertise_sack and packet_rx_md.tcp__sackperm
            # Receive sequence space: advance past peer's SYN.
            session._rcv_ini = packet_rx_md.tcp__seq
            session._rcv_nxt = add32(packet_rx_md.tcp__seq, packet_rx_md.tcp__flag_syn)
            # Mark peer as contacted so the R2-abort RST gate
            # fires correctly across the seq wrap (commit
            # 'e5e12dc' rationale).
            session._peer_contacted = True
            # Reset slow-start to one MSS now that we know peer's
            # MSS for real.
            session._snd_ewn = session._snd_mss
            # Send SYN + ACK at our original SYN's seq so peer
            # accepts it as the simultaneous-open response. RFC
            # 9293 §3.5.1 figure 8: the simultaneous-open SYN+ACK
            # is functionally a retransmit of our SYN with peer's
            # ACK piggybacked.
            session._transmit_packet(flag_syn=True, flag_ack=True, seq=session._snd_ini)
            # Change state to SYN_RCVD.
            session._change_state(FsmState.SYN_RCVD)
            return

    # Got RST + ACK packet -> Change state to CLOSED.
    if (
        packet_rx_md
        and all({packet_rx_md.tcp__flag_rst, packet_rx_md.tcp__flag_ack})
        and not any({packet_rx_md.tcp__flag_fin, packet_rx_md.tcp__flag_syn})
    ):
        # Packet sanity check.
        if packet_rx_md.tcp__seq == 0 and packet_rx_md.tcp__ack == session._snd_nxt:
            # Change state to CLOSED.
            session._change_state(FsmState.CLOSED)
            # Inform connect syscall that connection related event happened.
            session._connection_error = ConnError.REFUSED
            session._event__connect.release()
        return

    # Got CLOSE syscall -> Change state to CLOSED. Also signal
    # any blocked CONNECT caller (typical for a multi-threaded
    # app with one thread blocked on 'connect()' and another
    # calling 'close()') with 'ConnError.CANCELED' so they
    # unblock with 'TcpSessionError("Connection canceled")'
    # rather than hanging on the dead session forever.
    if syscall is SysCall.CLOSE:
        session._connection_error = ConnError.CANCELED
        session._event__connect.release()
        session._change_state(FsmState.CLOSED)
        return
