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
This module contains the TCP FSM LISTEN state handler.

pytcp/protocols/tcp/tcp__fsm__listen.py

ver 3.0.4
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from net_addr import IpVersion
from net_proto.protocols.tcp.tcp__header import TCP__MIN_MSS
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.tcp.tcp__enums import FsmState, SysCall
from pytcp.protocols.tcp.tcp__seq import add32

if TYPE_CHECKING:
    from pytcp.protocols.tcp.tcp__session import TcpSession
    from pytcp.socket.tcp__metadata import TcpMetadata


def fsm__listen(
    session: TcpSession,
    *,
    packet_rx_md: TcpMetadata | None,
    syscall: SysCall | None,
    timer: bool | None,
) -> None:
    """
    TCP FSM LISTEN state handler.
    """

    from pytcp.protocols.tcp.tcp__session import TcpSession
    from pytcp.socket import AddressFamily
    from pytcp.socket.tcp__socket import TcpSocket

    # Got SYN packet -> Send SYN + ACK packet / change state to SYN_RCVD.
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
        # Packet sanity check. RFC 9293 §3.10.7.2 step 3 explicitly
        # permits piggybacked data on the initial SYN ("any other
        # incoming control or data (combined with SYN) will be
        # processed in the SYN-RECEIVED state"), so the data field
        # is intentionally NOT gated here; it is queued into the
        # child session's receive buffer below.
        if packet_rx_md.tcp__ack == 0:
            # Accept-queue admission gate (POSIX 'listen(backlog)'
            # semantics). When the parent listening socket's
            # accept queue is at capacity, drop the SYN silently.
            # The peer's TCP will retransmit the SYN per its
            # standard retry cycle; if the application has
            # drained a slot via 'accept()' by the time the
            # retransmit lands, the handshake completes
            # normally. Linux and BSD both default to silent
            # drop on overflow (POSIX leaves the choice
            # implementation-defined). The cap protects the
            # listening process from accept-queue exhaustion -
            # one of the oldest TCP-stack DoS classes -
            # without requiring application changes.
            # pylint: disable=protected-access
            accept_q_len = len(session._socket._tcp_accept)
            accept_q_cap = session._socket._backlog
            if accept_q_len >= accept_q_cap:
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - Accept queue full " f"({accept_q_len}/{accept_q_cap}); " "dropping SYN silently",
                )
                return
            # pylint: enable=protected-access
            # Listener fork pattern (RFC 9293 §3.10.7.2). The
            # current 'session' object is the LISTEN-state session.
            # On peer's SYN we mutate it IN PLACE into the new
            # connection's child session (rebinding its 4-tuple
            # to the peer below) and create a FRESH session that
            # takes over the listening role on the original
            # socket. The result: one peer-specific child session
            # transitioning to SYN_RCVD, plus an unchanged
            # listening session ready to accept the next SYN.
            # The pivot relies on TcpSocket / TcpSession holding
            # mutable references to each other - callers that
            # cached 'listen_socket._tcp_session' BEFORE the SYN
            # arrived must re-resolve it after the drive.
            # Capture the listening parent socket reference BEFORE
            # the in-place pivot below clobbers 'session._socket'.
            # Both the fresh listening session and the new child
            # socket inherit RFC 1122 §4.2.3.6 SO_KEEPALIVE from
            # this parent.
            listen_socket = session._socket
            tcp_session = TcpSession(
                local_ip_address=session._local_ip_address,
                local_port=session._local_port,
                remote_ip_address=session._remote_ip_address,
                remote_port=session._remote_port,
                socket=listen_socket,
            )
            tcp_session.listen()
            # Inherit SO_KEEPALIVE on the fresh listening session
            # so each subsequent accept fork carries the flag too.
            tcp_session._keepalive_enabled = listen_socket._so_keepalive
            # Inherit per-connection keep-alive overrides too.
            tcp_session._keepalive_idle_override = listen_socket._tcp_keepidle
            tcp_session._keepalive_interval_override = listen_socket._tcp_keepintvl
            tcp_session._keepalive_max_count_override = listen_socket._tcp_keepcnt
            session._socket._tcp_session = tcp_session  # pylint: disable=protected-access
            # Re-bind 'session' to the peer's 4-tuple and create a
            # new TcpSocket that exposes this child session to
            # the application's eventual 'accept()' caller.
            session._local_ip_address = packet_rx_md.ip__local_address
            session._local_port = packet_rx_md.tcp__local_port
            session._remote_ip_address = packet_rx_md.ip__remote_address
            session._remote_port = packet_rx_md.tcp__remote_port
            session._socket = TcpSocket(
                family=(
                    AddressFamily.INET6 if session._local_ip_address.version == IpVersion.IP6 else AddressFamily.INET4
                ),
                tcp_session=session,
            )
            # Propagate SO_KEEPALIVE from the listening parent
            # onto the new child socket so a future
            # 'getsockopt(SO_KEEPALIVE)' on the accept()'d child
            # round-trips correctly. The per-connection overrides
            # follow the same path so 'getsockopt(TCP_KEEPIDLE)'
            # etc. also round-trip.
            session._socket._so_keepalive = listen_socket._so_keepalive
            session._socket._tcp_keepidle = listen_socket._tcp_keepidle
            session._socket._tcp_keepintvl = listen_socket._tcp_keepintvl
            session._socket._tcp_keepcnt = listen_socket._tcp_keepcnt
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
            session._snd_wnd = packet_rx_md.tcp__win
            # WSCALE bilateral negotiation per RFC 7323 §2.2:
            # passive-open mirrors peer's offer. If peer's SYN
            # carries WSCALE AND we are configured to advertise,
            # store peer's wscale as '_snd_wsc' (we WILL emit
            # WSCALE on the SYN+ACK we send next). Otherwise,
            # both directions clear to 0 - peer's non-offer
            # forces us to non-offer too.
            if session._advertise_wscale and packet_rx_md.tcp__wscale:
                session._snd_wsc = packet_rx_md.tcp__wscale
            else:
                session._rcv_wsc = 0
                session._snd_wsc = 0
            # SACK bilateral negotiation per RFC 2018 §2:
            # passive-open mirrors peer's offer. SACK is
            # enabled iff we are configured to advertise AND
            # peer's SYN carried SACK-Permitted. The flag
            # gates both the SYN+ACK we emit next (which
            # carries SACK-Permitted iff '_send_sack') and
            # subsequent SACK-option emission on outbound
            # ACKs over an OOO-buffered queue.
            session._send_sack = session._advertise_sack and packet_rx_md.tcp__sackperm
            # RFC 7323 §3 bilateral negotiation: enable TSopt
            # on our SYN+ACK and all subsequent segments iff we
            # advertise AND peer's SYN carried TSopt. Cache
            # peer's TSval as '_ts_recent' so the SYN+ACK we
            # emit next echoes it via TSecr.
            if session._advertise_ts and packet_rx_md.tcp__tsval is not None:
                session._send_ts = True
                session._ts_recent = packet_rx_md.tcp__tsval
            # RFC 7413 §3.1 Fast Open server-side cookie
            # issuance: when peer's SYN carries the TFO option,
            # generate an HMAC-bound cookie and stash it for
            # the SYN+ACK that fires on the next tick. The
            # cookie itself is opaque to peer (it just caches
            # and replays); the only invariant is that 'we'
            # can validate it later.
            if packet_rx_md.tcp__fastopen_cookie is not None:
                from pytcp.protocols.tcp.tcp__fastopen import generate_cookie

                session._fastopen_cookie_to_emit = generate_cookie(
                    peer_address=packet_rx_md.ip__remote_address,
                    secret=stack.TCP__FASTOPEN_SECRET,
                )
            session._rcv_ini = packet_rx_md.tcp__seq
            session._cwnd = session._snd_mss
            session._snd_ewn = min(session._cwnd, session._snd_wnd)
            # Make note of the remote SEQ number, advancing past the
            # SYN's one byte AND every byte of any piggybacked payload
            # so the SYN+ACK we emit acknowledges the data and the
            # peer does not have to retransmit it (RFC 9293 §3.10.7.2
            # step 3).
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
            if packet_rx_md.tcp__data:
                session._enqueue_rx_buffer(packet_rx_md.tcp__data)
                __debug__ and log(
                    "tcp-ss",
                    f"[{session}] - Queued {len(packet_rx_md.tcp__data)} bytes "
                    "of SYN-piggybacked data for delivery after ESTABLISHED",
                )
            # Change state to SYN_RCVD; the actual SYN+ACK packet
            # is emitted from that state on the next timer tick by
            # '_transmit_data', which detects 'SND.NXT == SND.INI'
            # in SYN_RCVD and fires the SYN+ACK.
            session._change_state(FsmState.SYN_RCVD)
            return

    # Got CLOSE syscall -> Change state to CLOSED.
    if syscall is SysCall.CLOSE:
        session._change_state(FsmState.CLOSED)
        return
