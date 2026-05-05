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

from dataclasses import replace
from typing import TYPE_CHECKING

from net_proto.protocols.tcp.tcp__header import TCP__MIN_MSS
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.tcp.tcp__cwnd import initial_window
from pytcp.protocols.tcp.tcp__enums import ConnError, FsmState, SysCall
from pytcp.protocols.tcp.tcp__seq import add32, le32, lt32

if TYPE_CHECKING:
    from pytcp.protocols.tcp.tcp__session import TcpSession
    from pytcp.socket.tcp__metadata import TcpMetadata


def fsm__syn_sent__timer(session: TcpSession) -> None:
    """
    TCP FSM SYN_SENT state timer handler.

    Resend the SYN if its retransmit timer expired and drain
    any TFO-piggybacked TX buffer.
    """

    session._retransmit_packet_timeout()
    session._transmit_data()


def fsm__syn_sent__syscall(session: TcpSession, syscall: SysCall) -> None:
    """
    TCP FSM SYN_SENT state syscall handler.

    Got CLOSE syscall -> Change state to CLOSED. Also signal
    any blocked CONNECT caller (typical for a multi-threaded
    app with one thread blocked on 'connect()' and another
    calling 'close()') with 'ConnError.CANCELED' so they
    unblock with 'TcpSessionError("Connection canceled")'
    rather than hanging on the dead session forever.
    """

    if syscall is SysCall.CLOSE:
        session._connection_error = ConnError.CANCELED
        session._event__connect.release()
        session._change_state(FsmState.CLOSED)


def fsm__syn_sent__packet(session: TcpSession, packet_rx_md: TcpMetadata) -> None:
    """
    TCP FSM SYN_SENT state packet handler.
    """

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
    if packet_rx_md.tcp__flag_ack and not (
        lt32(session._snd_una, packet_rx_md.tcp__ack) and le32(packet_rx_md.tcp__ack, session._snd_max)
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
    if all({packet_rx_md.tcp__flag_syn, packet_rx_md.tcp__flag_ack}) and not any(
        {packet_rx_md.tcp__flag_fin, packet_rx_md.tcp__flag_rst}
    ):
        # Packet sanity check. RFC 9293 §3.10.7.3 step 4 ("If
        # there are other controls or text in the segment, then
        # continue processing at the sixth step under Section
        # 3.10.7.4 ...") explicitly permits piggybacked data on
        # the SYN+ACK; the data is NOT gated here, it is
        # enqueued into '_rx_buffer' below.
        #
        # ACK acceptability per RFC 9293 §3.10.7.3 step 1 is
        # modular '(SND.UNA, SND.MAX]': any ack that advances
        # SND.UNA past at least the SYN (peer_iss + 1) is
        # acceptable. The '== SND.NXT' strict-equality check
        # this replaces was correct for non-TFO sessions where
        # SND.NXT only ever advances on the SYN's one byte,
        # but for RFC 7413 §4.2 TFO partial-acks (server
        # rejects SYN-data; SYN+ACK acks only the SYN, ack <
        # SND.NXT) the equality check would refuse the
        # SYN+ACK and the handshake would stall.
        if lt32(session._snd_una, packet_rx_md.tcp__ack) and le32(packet_rx_md.tcp__ack, session._snd_nxt):
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
            session._cwnd = session._snd_mss
            session._snd_ewn = min(session._cwnd, session._snd_wnd)
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
            # RFC 7413 §4.2 TFO partial-ack handling: when
            # the server rejected our SYN-data
            # (ack < SND.NXT after _process_ack_packet
            # advanced SND.UNA only past the SYN), rewind
            # SND.NXT to SND.UNA so the data still in
            # '_tx_buffer' is re-emitted by '_transmit_data'
            # on the next tick (post-ESTABLISHED). Without
            # the rewind the data would sit unacked until
            # the RTO retransmit timer fires - a one-RTO
            # latency penalty for every TFO failure.
            if lt32(session._snd_una, session._snd_nxt):
                session._snd_nxt = session._snd_una
            # RFC 6928 §2 Initial Window: post-handshake cwnd
            # = min(10*MSS, max(2*MSS, 14600)). Set after
            # '_process_ack_packet' has fired §3.1 growth on
            # the SYN+ACK ack-advance so the IW value is the
            # exact post-handshake cwnd, not IW + 1.
            session._cwnd = initial_window(session._snd_mss)
            session._snd_ewn = min(session._cwnd, session._snd_wnd)
            # RFC 6298 §5.7 second clause: when the SYN was
            # retransmitted at least once before the handshake
            # completed, RTO MUST be re-initialized to >= 3 s
            # when data transmission begins. The floor protects
            # against pathologically aggressive RTOs in
            # environments where the SYN's RTT clamp
            # (MIN_RTO_MS = 1000 ms) is optimistic relative to
            # the path's actual RTT. A clean handshake
            # ('_syn_retransmit_count == 0') skips the floor
            # and uses the canonical estimator output. The
            # dedicated counter survives '_process_ack_packet's
            # reset of the general-purpose '_retransmit_count'
            # so the check is order-independent.
            if session._syn_retransmit_count > 0 and session._rto_state.rto_ms < 3000:
                session._rto_state = replace(session._rto_state, rto_ms=3000)
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
            # RFC 7323 §3 bilateral negotiation: enable post-
            # handshake TSopt iff WE advertised on our SYN AND
            # peer's SYN+ACK carried TSopt. Cache peer's TSval
            # as '_ts_recent' so the third-leg ACK and all
            # subsequent segments echo it via TSecr.
            if session._advertise_ts and packet_rx_md.tcp__tsval is not None:
                session._send_ts = True
                session._ts_recent = packet_rx_md.tcp__tsval
            # RFC 9768 §3.1.1 / §3.1.2 active-side bilateral
            # ECN/AccECN confirmation. The peer's SYN+ACK
            # codepoint disambiguates which protocol it
            # supports. AccECN-capable (AE=1 OR CWR=1) takes
            # precedence; RFC 3168-only (AE=0, CWR=0, ECE=1)
            # is the graceful fallback. Mutual exclusivity is
            # enforced by the order of these branches: at
            # most one of '_accecn_enabled' / '_ecn_enabled'
            # is set.
            # RFC 9768 §3.1.2 fourth-block 'Broken' guard: some
            # older TCP servers incorrectly reflect the SYN's
            # AE+CWR+ECE flags into the SYN/ACK. The client
            # cannot distinguish the reflected (1,1,1) SYN/ACK
            # from a genuine AccECN top-block CE-on-SYN
            # response, so the spec mandates falling back to
            # Not ECN whenever (1,1,1) appears - both halves
            # of the connection skip ECN/AccECN entirely.
            is_broken_reflection = (
                packet_rx_md.tcp__flag_ns and packet_rx_md.tcp__flag_cwr and packet_rx_md.tcp__flag_ece
            )
            if is_broken_reflection:
                pass  # neither _accecn_enabled nor _ecn_enabled set
            elif session._advertise_accecn and (packet_rx_md.tcp__flag_ns or packet_rx_md.tcp__flag_cwr):
                session._accecn_enabled = True
                # RFC 9768 §3.2.2.1: derive the Table-3 ACE value
                # from the inbound SYN+ACK's IP-ECN codepoint so
                # the third-leg ACK encodes it for the server's
                # mangling-detection check. Mapping:
                #   0 (Not-ECT) -> 0b010
                #   1 (ECT(1))  -> 0b011
                #   2 (ECT(0))  -> 0b100
                #   3 (CE)      -> 0b110
                _table3 = {0: 0b010, 1: 0b011, 2: 0b100, 3: 0b110}
                session._accecn_handshake_ack_pending = _table3[packet_rx_md.ip__ecn]
                # RFC 9768 §3.2.2.2: a CE-marked SYN+ACK MUST
                # increment r.cep (one-shot from 5 to 6) so the
                # marking is reliably delivered via the ACE
                # field on subsequent post-handshake segments.
                if packet_rx_md.ip__ecn == 3:
                    session._accecn_r_cep = 6
                # RFC 9768 §3.2.2.3 IP-ECN mangling test
                # (client side). The SYN/ACK's AE+ECE flag
                # pair encodes the IP-ECN codepoint peer
                # observed on the SYN we sent (Table 2):
                # codepoint = (AE << 1) | ECE. PyTCP always
                # transmits Not-ECT (0) on SYNs per RFC 3168
                # §6.1.1, so any peer-observed codepoint
                # other than Not-ECT is an invalid transition
                # of the IP-ECN field along the path - the
                # 'mangling' the §3.2.2.3 procedure detects.
                # The (1,1,1) broken-reflection case is
                # handled by the outer 'is_broken_reflection'
                # branch above and never reaches this point.
                observed_ipecn = (int(packet_rx_md.tcp__flag_ns) << 1) | int(packet_rx_md.tcp__flag_ece)
                if observed_ipecn != 0:
                    session._accecn_mangling_detected = True
            elif session._advertise_ecn and packet_rx_md.tcp__flag_ece and not packet_rx_md.tcp__flag_cwr:
                session._ecn_enabled = True
            # RFC 7413 §3.1 client-side cookie cache update:
            # when peer's SYN+ACK carries a non-empty TFO
            # cookie, cache it against the peer IP via the
            # 'cache_cookie' helper so the cache stays
            # bounded by 'TCP__FASTOPEN_CACHE_MAX_SIZE'
            # (FIFO eviction). Subsequent active-open to
            # the same server can replay the cached cookie
            # until eviction times out the entry.
            if packet_rx_md.tcp__fastopen_cookie:
                from pytcp.protocols.tcp.tcp__fastopen import cache_cookie

                cache_cookie(
                    peer_address=session._remote_ip_address,
                    cookie=bytes(packet_rx_md.tcp__fastopen_cookie),
                )
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
    if all({packet_rx_md.tcp__flag_syn}) and not any(
        {
            packet_rx_md.tcp__flag_ack,
            packet_rx_md.tcp__flag_fin,
            packet_rx_md.tcp__flag_rst,
        }
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
            # RFC 7323 §3 bilateral negotiation (simultaneous-
            # open path): same shape as the SYN+ACK case above.
            if session._advertise_ts and packet_rx_md.tcp__tsval is not None:
                session._send_ts = True
                session._ts_recent = packet_rx_md.tcp__tsval
            # Receive sequence space: advance past peer's SYN.
            session._rcv_ini = packet_rx_md.tcp__seq
            session._rcv_nxt = add32(packet_rx_md.tcp__seq, packet_rx_md.tcp__flag_syn)
            # Mark peer as contacted so the R2-abort RST gate
            # fires correctly across the seq wrap (commit
            # 'e5e12dc' rationale).
            session._peer_contacted = True
            # Reset slow-start to one MSS now that we know peer's
            # MSS for real.
            session._cwnd = session._snd_mss
            session._snd_ewn = min(session._cwnd, session._snd_wnd)
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
    if all({packet_rx_md.tcp__flag_rst, packet_rx_md.tcp__flag_ack}) and not any(
        {packet_rx_md.tcp__flag_fin, packet_rx_md.tcp__flag_syn}
    ):
        # Packet sanity check.
        if packet_rx_md.tcp__seq == 0 and packet_rx_md.tcp__ack == session._snd_nxt:
            # Change state to CLOSED.
            session._change_state(FsmState.CLOSED)
            # Inform connect syscall that connection related event happened.
            session._connection_error = ConnError.REFUSED
            session._event__connect.release()
