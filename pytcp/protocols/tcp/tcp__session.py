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
This module contains the class supporting TCP finite state machine.

pytcp/protocols/tcp/tcp__session.py

ver 3.0.4
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, override

from net_addr import Ip4Address, Ip6Address
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.tcp__enums import (
    ConnError,
    FsmState,
    SysCall,
    TcpSessionError,
)
from pytcp.protocols.tcp.tcp__fsm import dispatch as tcp_fsm_dispatch
from pytcp.protocols.tcp.tcp__iss import compute_iss
from pytcp.protocols.tcp.tcp__loss_recovery import is_lost, next_seg
from pytcp.protocols.tcp.tcp__rto import RtoState, back_off, initial_state, update
from pytcp.protocols.tcp.tcp__sack import SackScoreboard
from pytcp.protocols.tcp.tcp__seq import Seq32, add32, gt32, in_range32, le32, lt32, sub32

if TYPE_CHECKING:
    from threading import Event, Lock, RLock, Semaphore

    from pytcp.socket.tcp__metadata import TcpMetadata
    from pytcp.socket.tcp__socket import TcpSocket


class TcpSession:
    """
    The TCP session.
    """

    def __init__(
        self,
        *,
        local_ip_address: Ip6Address | Ip4Address,
        local_port: int,
        remote_ip_address: Ip6Address | Ip4Address,
        remote_port: int,
        socket: TcpSocket,
    ) -> None:
        """
        Initialize the TCP session.
        """

        ###
        # Parameters derived from the socket.
        ###

        self._local_ip_address: Ip6Address | Ip4Address = local_ip_address
        self._local_port: int = local_port
        self._remote_ip_address: Ip6Address | Ip4Address = remote_ip_address
        self._remote_port: int = remote_port

        # Keeps track of the socket that owns this session for
        # the session -> socket communication purposes.
        self._socket: TcpSocket = socket

        ###
        # Buffers.
        ###

        # Keeps data received from peer and not received by application yet.
        self._rx_buffer: bytearray = bytearray()

        # Keeps data sent by application but not acknowledged by peer yet.
        self._tx_buffer: bytearray = bytearray()

        ###
        # Receiving window parameters.
        ###

        # Initial sequence number.
        self._rcv_ini: Seq32 = 0

        # Next sequence number to be received.
        self._rcv_nxt: Seq32 = 0

        # Sequence number we acked.
        self._rcv_una: Seq32 = 0

        # IP+TCP header overhead for MSS calculation. RFC 8200's
        # IPv6 fixed header is 40 bytes (vs IPv4's 20); the TCP
        # header is 20 bytes regardless. The MSS is the largest
        # TCP segment that fits in 'interface_mtu' once both
        # headers are subtracted.
        self._ip_tcp_overhead: int = (40 if isinstance(local_ip_address, Ip6Address) else 20) + 20

        # Maximum segment size.
        self._rcv_mss: int = stack.interface_mtu - self._ip_tcp_overhead

        # Maximum receive-window size advertised to the peer. The
        # actual '_rcv_wnd' value put on outbound segments is
        # derived from this and current '_rx_buffer' occupancy via
        # the '_rcv_wnd' property, so the peer's flow-control loop
        # sees backpressure as the application falls behind on
        # 'recv()' (RFC 9293 §3.8.6).
        self._rcv_wnd_max: int = 65535

        # Window scale advertised on outbound SYN / SYN+ACK per
        # RFC 7323 §2.2. Default 7 yields a maximum advertised
        # window of '65535 << 7 ~= 8 MB', matching the Linux /
        # FreeBSD default. Set to 0 if the bilateral negotiation
        # fails (peer didn't offer / we opted out via
        # '_advertise_wscale = False'); the field is then both
        # the wire-level shift count AND the post-handshake
        # right-shift applied to the outbound 'win' field.
        self._rcv_wsc: int = 7

        # Whether to advertise WSCALE on this session's outbound
        # SYN / SYN+ACK. Defaults True (the modern, throughput-
        # friendly behaviour); test code or constrained-buffer
        # profiles can opt out by setting False before CONNECT
        # / LISTEN. When False, the bilateral-non-offer rule
        # forces '_rcv_wsc = 0' on handshake completion so the
        # post-handshake outbound 'win' is not shifted either.
        self._advertise_wscale: bool = True

        # Whether to advertise SACK-Permitted on this session's
        # outbound SYN / SYN+ACK per RFC 2018 §2. Defaults True
        # (modern default - SACK enables RFC 6675 Conservative
        # Loss Recovery); flip False before CONNECT / LISTEN to
        # opt out. The bilateral-non-offer rule mirrors WSCALE:
        # a session that did not advertise will not enable SACK
        # even if peer offered it, and a session that did
        # advertise will not enable SACK unless peer also
        # offered.
        self._advertise_sack: bool = True

        # Whether SACK is enabled for this session, set after
        # bilateral SACK-Permitted negotiation succeeds in
        # '_tcp_fsm_listen' / '_tcp_fsm_syn_sent'. Gates the
        # emission of SACK options on outbound ACKs over an
        # OOO-buffered receive queue (RFC 2018 §3) and the
        # ingestion of inbound SACK blocks into the scoreboard
        # (phase 4).
        self._send_sack: bool = False

        # RFC 7323 §3 Timestamps option (TSopt) state. The
        # opt-out flag '_advertise_ts' is application-level
        # (default True, can be disabled before connect /
        # listen). The bilateral-success flag '_send_ts' is set
        # by the FSM during handshake when both sides
        # advertised TSopt. '_ts_recent' carries peer's most-
        # recently-seen TSval, echoed back as TSecr on every
        # post-handshake outbound segment so peer can drive
        # exact-RTT measurements per RFC 7323 §4. Phases 1-4
        # of '.claude/rules/tcp_rfc7323_timestamps.md' wire
        # negotiation, emission, RTTM, and PAWS in that order.
        self._advertise_ts: bool = True
        self._send_ts: bool = False
        self._ts_recent: int = 0

        # RFC 1122 §4.2.3.6 keep-alive opt-in flag. Defaults False
        # per the RFC's MUST: "If keep-alive are included, the
        # application MUST be able to turn them on or off for
        # each TCP connection, and they MUST default to off."
        # Set via 'TcpSocket.setsockopt(SOL_SOCKET, SO_KEEPALIVE,
        # 1)'; the socket layer propagates the flag onto this
        # field at TcpSession construction time (see
        # 'TcpSocket.connect()' / 'TcpSocket.listen()' and the
        # listener-fork pivot in 'tcp__fsm__listen.py'). The
        # session-internal keep-alive machinery
        # ('_keepalive_arm_idle' / '_keepalive_tick') is gated
        # on this flag throughout.
        self._keepalive_enabled: bool = False

        # Counter of consecutive unanswered keep-alive probes per
        # RFC 1122 §4.2.3.6. Reset to 0 by '_keepalive_arm_idle'
        # on any peer-acknowledged activity; incremented by
        # '_keepalive_tick' on each probe emission. When the
        # counter reaches 'tcp__constants.KEEPALIVE_PROBE_MAX_COUNT'
        # the connection is declared dead (state -> CLOSED with
        # ConnError.TIMEOUT).
        self._keepalive_probes_unacked: int = 0

        # Linux-style per-connection keep-alive overrides for the
        # idle / probe-interval / max-count parameters. 'None'
        # means "use the global 'tcp__constants.KEEPALIVE_*'
        # default at runtime"; an int value (passed in via
        # 'TcpSocket.setsockopt(IPPROTO_TCP, TCP_KEEP*, ...)' and
        # propagated by 'TcpSocket.connect()' / 'TcpSocket.listen()')
        # overrides for this connection only. Units match the
        # constants: ms for the two timer values, count for the
        # max probes.
        self._keepalive_idle_override: int | None = None
        self._keepalive_interval_override: int | None = None
        self._keepalive_max_count_override: int | None = None

        # Whether the keep-alive timer is currently armed. We need
        # this in addition to 'stack.timer._timers'-membership
        # because production 'Timer.is_expired' returns True both
        # when a timer has not been registered yet AND when its
        # countdown has reached zero - 'is_expired' alone cannot
        # distinguish "never armed" from "fired and pending
        # service". Without this flag, a session that opts in to
        # keep-alive after handshake completion would have
        # '_keepalive_tick' immediately treat the absent timer as
        # expired and fire a probe burst.
        self._keepalive_active: bool = False

        # SACK scoreboard tracking peer-SACKed-but-not-yet-
        # cumulatively-acked send-side ranges per RFC 2018 §3 /
        # RFC 6675 §3. Updated by '_ingest_sack_info' on every
        # ACK that carries a SACK option (gated on
        # '_send_sack'); pruned by '_prune_sack_scoreboard'
        # when SND.UNA advances. Phase 5 will consult it via
        # 'pytcp.protocols.tcp.tcp__loss_recovery' for NextSeg / IsLost /
        # Pipe.
        self._sack_scoreboard: SackScoreboard = SackScoreboard()

        # RFC 6675 §5 RecoveryPoint - the SND.MAX value at the
        # moment the most recent fast-retransmit fired. Zero
        # means "not currently in recovery"; while non-zero it
        # gates further fast-retransmit triggers (the one-shot
        # rule from RFC 5681 §3.2). Cleared by
        # '_process_ack_packet' once 'SND.UNA' advances past
        # 'recovery_point' - the loss event is fully recovered
        # and a new round of dup-ACKs can re-enter recovery.
        self._recovery_point: Seq32 = 0

        # RFC 2883 DSACK: when peer retransmits data we already
        # received (fully-duplicate segment OR overlap prefix of
        # a partially-duplicate segment) we record the duplicate
        # range here so the next outbound ACK's SACK option
        # carries it as the FIRST block. 'None' means no DSACK
        # is pending. 'Build' clears it after consumption.
        self._pending_dsack: tuple[Seq32, Seq32] | None = None

        # Counter of inbound DSACK occurrences detected by the
        # sender side. Incremented in '_ingest_sack_info' when
        # the first SACK block looks like a DSACK marker (right
        # edge below SND.UNA OR contained within a later block).
        # Useful for spurious-retransmit observability; phase 7
        # does not yet wire it into RTO / cwnd.
        self._dsack_received: int = 0

        # RFC 6298 §2 RTO estimator state plus the single-pending-
        # sample tracker that drives '_rto_state' updates per
        # §4 ("one sample per RTT"). The hooks live in
        # '_transmit_packet' (record fresh sample), in
        # '_process_ack_packet' (harvest on covering ACK and run
        # 'update' iff Karn's flag is False), and in
        # '_retransmit_packet_timeout' (set Karn's flag per §3 on
        # the in-flight sample). 'rto_ms' drives the session-level
        # 'f"{self}-retransmit"' timer; on each timeout fire,
        # '_retransmit_packet_timeout' applies 'back_off' (§5.5)
        # and re-arms with the new value. The R2 abort counter
        # ('_retransmit_count') tracks consecutive timeouts since
        # the last cum-ACK that advanced SND.UNA; cleared on
        # progress in '_process_ack_packet'.
        self._rto_state: RtoState = initial_state()
        self._rtt_sample_seq: Seq32 | None = None
        self._rtt_sample_send_time_ms: int | None = None
        self._rtt_sample_retransmitted: bool = False
        self._retransmit_count: int = 0
        # RFC 6298 §5.7 restart-after-idle baseline. 'None' until
        # the first outbound segment fires; '_transmit_packet'
        # then refreshes it on every send that consumes sequence
        # space (data / SYN / FIN). Phase 4 wires the §5.7 reset
        # hook in '_transmit_packet' to compare 'now_ms -
        # _last_send_time_ms' against '_rto_state.rto_ms' and
        # reset the estimator when the silence exceeded the
        # in-flight RTO.
        self._last_send_time_ms: int | None = None

        ###
        # Sending window parameters.
        ###

        # Initial sequence number per RFC 6528 §3: hash of the
        # 4-tuple plus a stack-wide secret, plus a monotonically
        # advancing 'M' clock. Defends against blind sequence-
        # number injection by binding the ISN to the 4-tuple so
        # an attacker who learns one ISN cannot infer ISNs for
        # other connections; the time-driven M component prevents
        # replay of stale ISNs against fresh connections.
        self._snd_ini: Seq32 = compute_iss(
            local_address=local_ip_address,
            local_port=local_port,
            remote_address=remote_ip_address,
            remote_port=remote_port,
            secret=stack.TCP__ISS_SECRET,
            clock_us=time.monotonic_ns() // 1000,
        )

        # Next sequence number to be sent.
        self._snd_nxt: Seq32 = self._snd_ini

        # Maximum sequence number ever sent.
        self._snd_max: Seq32 = self._snd_ini

        # Sequence number not yet acknowledged by peer.
        self._snd_una: Seq32 = self._snd_ini

        # Sequence number of the FIN packet we sent. Only valid
        # when '_fin_sent' is True; until then '_snd_fin' carries
        # the sentinel '0' value and MUST NOT be compared to live
        # 'SND.NXT' / 'SND.UNA' values lest a post-wrap 'SND.NXT
        # == 0' collide with the sentinel and trigger code paths
        # gated on a real FIN seq match.
        self._snd_fin: Seq32 = 0

        # 'True' once '_transmit_packet' has emitted a FIN
        # segment (sets '_snd_fin' to the FIN's seq alongside
        # this flag). Used as the gate on '_snd_fin' reads so
        # the sentinel '0' value cannot be confused for a real
        # post-wrap FIN seq. See the comment on '_snd_fin' above.
        self._fin_sent: bool = False

        # 'True' once any segment has been processed from peer
        # (peer's SYN in the passive-open path, peer's SYN+ACK
        # in the active-open path). Gates the R2-abort RST
        # emission so an aborting session that DID hear from
        # peer signals the abort even when 'RCV.NXT' happens to
        # equal 0 (which it does when peer's ISN was exactly
        # 0xFFFF_FFFF and 'add32(peer_isn, 1)' wraps). Without
        # the explicit flag, the previous 'self._rcv_nxt > 0'
        # gate would suppress the RST whenever peer's ISN hit
        # the wrap-point sentinel - probability 2**-32 but a
        # real correctness gap.
        self._peer_contacted: bool = False

        # Maximum segment size.
        self._snd_mss: int = 536

        # Peer-advertised receive window. Initialised to one SMSS
        # (not 0, not 65535) so the conservative-start path can
        # emit a single segment before peer's first ACK reveals
        # the real window size. Updated to peer's advertised value
        # (shifted by '_snd_wsc' once WSCALE negotiation finishes)
        # in '_process_ack_packet'.
        self._snd_wnd: int = self._snd_mss

        # Effective send window - PyTCP's simplified congestion-
        # control variable that conflates RFC 5681 cwnd and
        # ssthresh. Doubles on each cum-ACK in
        # '_process_ack_packet' (slow-start reuse, no congestion-
        # avoidance phase) and is reset to one SMSS on RTO in
        # '_retransmit_packet_timeout'. The min() clamp against
        # '_snd_wnd' enforces the receiver-imposed flow-control
        # ceiling.
        self._snd_ewn: int = self._snd_mss

        # RFC 5681 Phase 1 fields (see
        # '.claude/rules/tcp_rfc5681_cwnd.md'). Declared with
        # canonical defaults so the [FLAGS BUG] tests-first
        # suite can exercise the attribute access; the actual
        # growth / reduction logic is wired by the Phase 1 fix
        # commit (slow-start vs CA in '_process_ack_packet'),
        # Phase 2 fix (RTO ssthresh halving), and Phase 3 fix
        # (fast-recovery inflation/deflation in
        # '_retransmit_packet_request' and the recovery exit
        # path). Pre-Phase-1, these fields are observable but
        # unused by the runtime - '_snd_ewn' is still the
        # single source of truth.
        self._cwnd: int = self._snd_mss
        # RFC 5681 §3.1: "ssthresh SHOULD be set arbitrarily high
        # (e.g., to the size of the largest possible advertised
        # window)". 'INT32_MAX' (0x7FFFFFFF) is the canonical
        # large-constant choice (mirrors Linux's 'int_max'); it
        # is well above any realistic peer-advertised window so
        # the session enters slow-start cleanly post-handshake.
        self._ssthresh: int = 0x7FFF_FFFF

        # Window scale, initialized to 0 because initial SYN / SYN + ACK packets
        # don't use wscale for backward compatibility.
        self._snd_wsc: int = 0

        # Sequence number of the byte after the most recent sub-MSS ("partial")
        # segment we transmitted. Used by Nagle's algorithm with the Minshall
        # modification (RFC 1122 §4.2.3.4) to defer a subsequent partial segment
        # while a previous partial is still unacknowledged. Initialized to
        # '_snd_ini' so it is strictly less than 'SND.UNA' after the handshake
        # completes, which means "no partial in flight yet".
        self._snd_sml: Seq32 = self._snd_ini

        # Zero-window persist timer state per RFC 9293 §3.8.6.1.
        # '_persist_active' is the sentinel that tells the timer
        # branch in '_tcp_fsm_established' whether a persist probe
        # is scheduled. False means "no probe pending" (we last
        # saw a non-zero peer window); True means "armed and
        # counting down toward the next zero-window probe". The
        # flag flips True when peer advertises 'tcp__win == 0' on
        # an ACK while we still have data to send; it flips False
        # when peer reopens the window. '_persist_timeout' carries
        # the current back-off interval (initial =
        # tcp__constants.PACKET_RETRANSMIT_TIMEOUT, doubled per probe up to
        # tcp__constants.PERSIST_TIMEOUT_MAX).
        self._persist_active: bool = False
        self._persist_timeout: int = tcp__constants.PACKET_RETRANSMIT_TIMEOUT

        # Number of in-order data segments received since we last transmitted
        # an ACK. Tracks the RFC 1122 §4.2.3.2 "ACK every other segment"
        # rule: when this reaches 2 we force an inline ACK rather than
        # waiting for the delayed-ACK timer to fire.
        self._delayed_ack_segments_pending: int = 0

        ###
        # Other variables.
        ###

        # Keeps track of number of DUP packets sent by peer to determine if any
        # is a retransmit request.
        self._tx_retransmit_request_counter: dict[int, int] = {}

        # Used to help translate local_seq_send and snd_una numbers to
        # the TX buffer pointers.
        self._tx_buffer_seq_mod: Seq32 = self._snd_ini

        # TCP FSM (Finite State Machine) state.
        self._state: FsmState = FsmState.CLOSED

        # Wakes the blocked CONNECT syscall once the FSM has reached
        # a terminal handshake outcome (ESTABLISHED, refused, or
        # timed out). 'Semaphore(0)' rather than 'threading.Event'
        # because we want the wake-up to be one-shot per CONNECT
        # call: 'Event' stays set, so a second CONNECT would
        # observe a stale signal; 'Semaphore' counts releases and
        # acquires, naturally consuming the signal.
        self._event__connect: Semaphore = threading.Semaphore(0)

        # Used to inform RECV syscall that there is new data in buffer ready
        # to be picked up.
        self._event__rx_buffer: Event = threading.Event()

        # Used to ensure that only single event can run FSM at given time.
        self._lock__fsm: RLock = threading.RLock()

        # Used to ensure only single event has access to RX buffer at given time.
        self._lock__rx_buffer: Lock = threading.Lock()

        # Used to ensure only single event has access to TX buffer at given time.
        self._lock__tx_buffer: Lock = threading.Lock()

        # Indicates that CLOSE syscall is in progress, this lets to finish
        # sending data before FIN packet is transmitted.
        self._closing: bool = False

        # Out of order packet buffer.
        self._ooo_packet_queue: dict[int, TcpMetadata] = {}

        # Used to report cause of connection failure.
        self._connection_error: ConnError = ConnError.NONE

        # Setup timer to execute FSM time event every millisecond.
        stack.timer.register_method(method=self.tcp_fsm, kwargs={"timer": True})

    @override
    def __str__(self) -> str:
        """
        Get the TCP session string representation.
        """

        return f"{self._local_ip_address}/{self._local_port}/{self._remote_ip_address}/{self._remote_port}"

    @property
    def local_ip_address(self) -> Ip6Address | Ip4Address:
        """
        Get the '_local_ip_address' attribute.
        """

        return self._local_ip_address

    @property
    def remote_ip_address(self) -> Ip6Address | Ip4Address:
        """
        Get the '_remote_ip_address' attribute.
        """

        return self._remote_ip_address

    @property
    def local_port(self) -> int:
        """
        Get the '_local_port' attribute.
        """

        return self._local_port

    @property
    def remote_port(self) -> int:
        """
        Get the '_remote_port' attribute.
        """

        return self._remote_port

    @property
    def socket(self) -> TcpSocket:
        """
        Get the '_socket' attribute.
        """

        return self._socket

    @property
    def state(self) -> FsmState:
        """
        Get the '_state' attribute.
        """

        return self._state

    @property
    def _rcv_wnd(self) -> int:
        """
        Get the current receive-window advertisement: the configured
        maximum minus bytes currently sitting in '_rx_buffer'. The
        advertised window MUST shrink as inbound data accumulates so
        the peer's flow-control loop can throttle their send rate
        when the application is slow to consume (RFC 9293 §3.8.6).
        """

        return max(0, self._rcv_wnd_max - len(self._rx_buffer))

    @property
    def _tx_buffer_nxt(self) -> int:
        """
        Get the 'snd_nxt' number relative to TX buffer.

        Uses modular subtraction (RFC 9293 §3.4) so the returned
        offset is correct across the 32-bit wrap. Plain integer
        subtraction yields a large negative when 'snd_nxt' has
        wrapped past 'tx_buffer_seq_mod' (e.g. snd_nxt=3,
        seq_mod=0xFFFF_FFFF -> raw diff=-0xFFFF_FFFC, modular
        diff=4); the legacy 'max(diff, 0)' clamp would then
        wrongly yield 0 and the next 'transmit_data' call would
        try to re-send the already-sent prefix.
        """

        return (self._snd_nxt - self._tx_buffer_seq_mod) & 0xFFFF_FFFF

    @property
    def _tx_buffer_una(self) -> int:
        """
        Get the 'snd_una' number relative to TX buffer.
        """

        return (self._snd_una - self._tx_buffer_seq_mod) & 0xFFFF_FFFF

    def listen(self) -> None:
        """
        The 'LISTEN' syscall.
        """

        __debug__ and log(
            "tcp-ss",
            f"[{self}] - <ly>[{self._state}]</> - got <r>LISTEN</> syscall",
        )

        self.tcp_fsm(syscall=SysCall.LISTEN)

    def connect(self) -> None:
        """
        The 'CONNECT' syscall.
        """

        __debug__ and log(
            "tcp-ss",
            f"[{self}] - <ly>[{self._state}]</> - got <r>CONNECT</> syscall",
        )

        self.tcp_fsm(syscall=SysCall.CONNECT)
        self._event__connect.acquire()
        if self._state is not FsmState.ESTABLISHED and self._connection_error is ConnError.REFUSED:
            raise TcpSessionError("Connection refused")
        if self._state is not FsmState.ESTABLISHED and self._connection_error is ConnError.TIMEOUT:
            raise TcpSessionError("Connection timeout")
        if self._state is not FsmState.ESTABLISHED and self._connection_error is ConnError.CANCELED:
            raise TcpSessionError("Connection canceled")

    def send(self, *, data: bytes) -> int:
        """
        The 'SEND' syscall.
        """

        # RFC 9293 §3.10.6: once the application has called CLOSE,
        # any subsequent SEND must be rejected with a closing-error
        # response. The state-only check below is not enough because
        # 'close()' is deferred - it sets '_closing = True' but does
        # not transition the FSM out of ESTABLISHED until the next
        # timer tick after the TX buffer drains. Without this guard,
        # the post-close-but-pre-tick window would silently accept
        # writes that get serialised onto the wire ahead of the FIN.
        if self._closing:
            raise TcpSessionError("TCP session is closing")

        if self._state in {FsmState.ESTABLISHED, FsmState.CLOSE_WAIT}:
            with self._lock__tx_buffer:
                self._tx_buffer.extend(data)
                return len(data)

        # This error should be raised when session is locally or fully closed.
        raise TcpSessionError("TCP session not in ESTABLISHED or CLOSE_WAIT state")

    def receive(self, *, byte_count: int | None = None, timeout: float | None = None) -> bytes:
        """
        The 'RECEIVE' syscall.
        """

        # Wait till there is any data in the buffer (this will get bypassed
        # when FSM goes into CLOSE_WAIT or CLOSED).
        if not self._event__rx_buffer.wait(timeout=timeout):
            raise TimeoutError("TCP session receive operation timed out while waiting for data.")

        # If there is no data in RX buffer and remote end closed connection
        # then notify application by returning empty byte string.
        if not self._rx_buffer and self._state in {
            FsmState.CLOSE_WAIT,
            FsmState.CLOSED,
        }:
            return b""

        with self._lock__rx_buffer:
            if byte_count is None:
                byte_count = len(self._rx_buffer)
            else:
                byte_count = min(byte_count, len(self._rx_buffer))

            rx_buffer = self._rx_buffer[:byte_count]
            del self._rx_buffer[:byte_count]

            # Clear the event only when the buffer is fully drained
            # AND the remote end is still open. When the remote
            # closed (CLOSE_WAIT or CLOSED), leave the event set so
            # the next 'receive()' returns 'b""' immediately - the
            # BSD-socket EOF semantics, where a connection-closed
            # state must be re-readable as zero bytes without
            # blocking the caller.
            if not self._rx_buffer and self._state not in {
                FsmState.CLOSE_WAIT,
                FsmState.CLOSED,
            }:
                self._event__rx_buffer.clear()

        return bytes(rx_buffer)

    def close(self) -> None:
        """
        The 'CLOSE' syscall.
        """

        __debug__ and log(
            "tcp-ss",
            f"[{self}] - <ly>[{self._state}]</> - got <r>CLOSE</> syscall, {len(self._tx_buffer)} bytes in TX buffer",
        )

        self.tcp_fsm(syscall=SysCall.CLOSE)

    def _change_state(self, state: FsmState) -> None:
        """
        Change the state of TCP finite state machine.
        """

        old_state = self._state
        self._state = state
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - <ly>[{old_state} -> {self._state}]</>",
        )

        # RFC 6675 §5 RecoveryPoint is meaningful only inside the
        # ESTABLISHED loss-recovery loop. Clear on any transition
        # out of ESTABLISHED so post-half-close 'send()' that
        # experiences loss can re-enter recovery in the new state
        # without being inhibited by the stale marker. The
        # in-'_process_ack_packet' clearing only fires when
        # SND.UNA crosses the marker, which may not happen if
        # peer's transition-driving segment did not advance the
        # cum-ACK far enough (e.g. peer FIN with no cum-ACK
        # progress).
        if old_state is FsmState.ESTABLISHED and state is not FsmState.ESTABLISHED:
            self._recovery_point = 0

        # Unregister session.
        if self._state is FsmState.CLOSED:
            stack.sockets.pop(self._socket.socket_id)
            # Clean up per-session entries in 'stack.timer._timers'
            # so they do not accumulate as stale entries after the
            # session is gone. Timer keys all start with 'str(self)-'
            # (e.g. '<session>-delayed_ack',
            # '<session>-retransmit',
            # '<session>-time_wait', '<session>-persist',
            # '<session>-challenge_ack'); the prefix scan pops them
            # uniformly without per-suffix bookkeeping.
            stack.timer.unregister_timers_with_prefix(f"{self}-")
            # Drop the per-millisecond 'tcp_fsm' callback that
            # '__init__' registered via 'stack.timer.register_method'.
            # Without this, the 'TimerTask' survives forever -
            # firing 'self.tcp_fsm(timer=True)' once per tick on a
            # dead session (CPU drain growing linearly with
            # dead-session count) and pinning the entire
            # 'TcpSession' instance in memory via the bound-method
            # reference (preventing GC). Companion to the prefix
            # scan above which handles the named-delay-timer half
            # of the same per-session registration.
            stack.timer.unregister_method(self.tcp_fsm)
            __debug__ and log("tcp-ss", f"[{self}] - Unregister associated socket")

        # RFC 1122 §4.2.3.6: arm the keep-alive idle timer on the
        # transition into ESTABLISHED (no-op when keep-alive is
        # disabled). Done here rather than in 'fsm__syn_sent' /
        # 'fsm__syn_rcvd' / 'fsm__listen' so all three handshake
        # paths share a single arm site.
        if state is FsmState.ESTABLISHED:
            self._keepalive_arm_idle()

    def _transmit_packet(
        self,
        *,
        seq: int | None = None,
        flag_syn: bool = False,
        flag_ack: bool = False,
        flag_fin: bool = False,
        flag_rst: bool = False,
        flag_psh: bool = False,
        data: bytes = b"",
    ) -> None:
        """
        Send out the TCP packet.
        """

        seq = seq if seq is not None else self._snd_nxt
        ack = self._rcv_nxt if flag_ack else 0

        # RFC 6298 §5.7 restart-after-idle: when a session has
        # been silent for longer than the in-flight 'rto_ms' the
        # smoothed RTT estimator may be stale (the network
        # conditions that produced the current SRTT/RTTVAR may
        # no longer hold). Reset to 'initial_state()' so the
        # next sample re-establishes the estimator from scratch
        # and avoids spurious retransmits with a now-too-short
        # RTO. The '_last_send_time_ms is not None' guard
        # ensures the reset never fires on a fresh session
        # before any send has occurred.
        if (
            (data or flag_syn or flag_fin)
            and self._last_send_time_ms is not None
            and stack.timer.now_ms - self._last_send_time_ms > self._rto_state.rto_ms
        ):
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - RFC 6298 §5.7 idle-reset: now="
                f"{stack.timer.now_ms} last_send="
                f"{self._last_send_time_ms} rto_ms="
                f"{self._rto_state.rto_ms}; resetting estimator",
            )
            self._rto_state = initial_state()

        # RFC 6298 §4 sample collection: record one in-flight RTT
        # sample at a time. The covering ACK harvest hook in
        # '_process_ack_packet' folds the observed RTT into
        # '_rto_state' via 'tcp__rto.update' (skipping the fold
        # iff Karn's flag is set per RFC 6298 §3). The
        # '_rtt_sample_seq is None' gate enforces single-sample-
        # per-RTT cadence: subsequent in-flight segments do not
        # overwrite the pending sample, and a retransmit of the
        # sampled segment lands here with '_rtt_sample_seq' set
        # so no fresh sample is recorded - the original
        # send-time stays paired with the original seq, with the
        # taint flag controlling whether the eventual ACK
        # produces an estimator update.
        if (data or flag_syn or flag_fin) and self._rtt_sample_seq is None:
            self._rtt_sample_seq = seq
            self._rtt_sample_send_time_ms = stack.timer.now_ms
            self._rtt_sample_retransmitted = False

        # RFC 6298 §5.7 idle-baseline tracking: refresh the
        # last-send timestamp on every outbound segment that
        # consumes sequence space, so the §5.7 idle-check above
        # has an accurate baseline for the next send.
        if data or flag_syn or flag_fin:
            self._last_send_time_ms = stack.timer.now_ms

        # WSCALE shift on outbound 'win' field per RFC 7323 §2.3:
        # post-handshake segments use 'rcv_wnd >> rcv_wsc'; the
        # SYN segment itself uses an unshifted value (RFC 7323
        # §2.2's "WSopt is not used to scale the value in the
        # window field of the SYN segment itself"). The SYN+ACK
        # is also a "SYN segment" for this rule.
        if flag_syn:
            tcp__win = min(self._rcv_wnd, 0xFFFF)
        elif 0 < self._rcv_wnd < self._rcv_mss:
            # RFC 1122 §4.2.3.3 receiver SWS avoidance: when the
            # available receive-window is non-zero but smaller
            # than one MSS, advertise zero so peer's persist-
            # probe loop fires rather than peer sending a sub-
            # MSS segment that wastes per-byte header overhead.
            # The next window update fires once the application
            # has consumed at least one MSS of buffer space and
            # '_rcv_wnd >= _rcv_mss' again.
            tcp__win = 0
        else:
            tcp__win = self._rcv_wnd >> self._rcv_wsc

        # WSCALE option presence on outbound SYN / SYN+ACK is
        # gated on '_advertise_wscale' per RFC 7323 §2.2's
        # bilateral non-offer rule. The packet-handler TX path
        # treats 'tcp__wscale=0' as "no option" (falsy guard),
        # which is the bilateral-non-offer wire form.
        tcp__wscale: int | None
        if flag_syn and self._advertise_wscale:
            tcp__wscale = self._rcv_wsc
        elif flag_syn:
            tcp__wscale = 0
        else:
            tcp__wscale = None

        # SACK-Permitted option presence per RFC 2018 §2:
        # active-open SYN emits iff we advertise (peer's view is
        # not yet known); passive-open SYN+ACK emits iff the
        # bilateral negotiation succeeded ('_send_sack' is set
        # in '_tcp_fsm_listen' on peer's SYN). Non-SYN segments
        # never carry the option (RFC 2018 §2: "MUST NOT be sent
        # on non-SYN segments").
        if flag_syn and not flag_ack:
            tcp__sackperm = self._advertise_sack
        elif flag_syn and flag_ack:
            tcp__sackperm = self._send_sack
        else:
            tcp__sackperm = False

        # SACK option blocks per RFC 2018 §3-§4 / RFC 2883 §4:
        # emitted on non-SYN ACKs iff the bilateral negotiation
        # succeeded AND we have at least one block to report -
        # either an OOO-queue entry OR a pending DSACK report.
        # An empty SACK option is illegal per RFC 2018 §3
        # (length must cover at least one 8-byte block).
        tcp__sack_blocks: list[tuple[int, int]] | None
        if not flag_syn and self._send_sack and (self._ooo_packet_queue or self._pending_dsack is not None):
            tcp__sack_blocks = self._build_sack_blocks()
        else:
            tcp__sack_blocks = None

        # RFC 7323 §3 Timestamps option:
        #   - Active-open SYN (flag_syn AND not flag_ack): emit
        #     iff '_advertise_ts'. tsval=now_ms, tsecr=0 (peer's
        #     TSval not yet known).
        #   - Passive-open SYN+ACK (flag_syn AND flag_ack): emit
        #     iff bilateral '_send_ts' set. tsval=now_ms,
        #     tsecr=_ts_recent (peer's TSval from its SYN).
        #   - Non-SYN segments: emit iff '_send_ts'. tsval=now_ms,
        #     tsecr=_ts_recent. (Phase 2 wires this; Phase 1 only
        #     handles handshake.)
        tcp__tsval: int | None
        tcp__tsecr: int | None
        if flag_syn and not flag_ack:
            if self._advertise_ts:
                tcp__tsval = stack.timer.now_ms
                tcp__tsecr = 0
            else:
                tcp__tsval = None
                tcp__tsecr = None
        elif flag_syn and flag_ack:
            if self._send_ts:
                tcp__tsval = stack.timer.now_ms
                tcp__tsecr = self._ts_recent
            else:
                tcp__tsval = None
                tcp__tsecr = None
        else:
            if self._send_ts:
                tcp__tsval = stack.timer.now_ms
                tcp__tsecr = self._ts_recent
            else:
                tcp__tsval = None
                tcp__tsecr = None

        stack.packet_handler.send_tcp_packet(
            ip__local_address=self._local_ip_address,
            ip__remote_address=self._remote_ip_address,
            tcp__local_port=self._local_port,
            tcp__remote_port=self._remote_port,
            tcp__flag_syn=flag_syn,
            tcp__flag_ack=flag_ack,
            tcp__flag_fin=flag_fin,
            tcp__flag_rst=flag_rst,
            tcp__flag_psh=flag_psh,
            tcp__seq=seq,
            tcp__ack=ack,
            tcp__win=tcp__win,
            tcp__mss=self._rcv_mss if flag_syn else None,
            tcp__wscale=tcp__wscale,
            tcp__sackperm=tcp__sackperm,
            tcp__sack_blocks=tcp__sack_blocks,
            tcp__tsval=tcp__tsval,
            tcp__tsecr=tcp__tsecr,
            tcp__payload=data,
        )
        # Mark RCV.UNA = RCV.NXT: the segment we just emitted
        # acknowledged everything up to RCV.NXT (via the piggybacked
        # 'ack' field if 'flag_ack' is set, or trivially otherwise),
        # so there is no longer any pending RX byte the peer is
        # unaware we received. '_delayed_ack' uses the
        # 'RCV.UNA != RCV.NXT' inequality as the gate for firing the
        # next delayed ACK; resetting them to equal here disarms
        # that gate until the next inbound data segment.
        self._rcv_una = self._rcv_nxt
        # Per RFC 9293 §3.4 sequence numbers are 32-bit modular -
        # use 'add32' (variadic) for the post-segment SND.NXT
        # update so the value remains within the 32-bit unsigned
        # range past the wrap.
        self._snd_nxt = add32(seq, len(data), flag_syn, flag_fin)
        # Modular 'max': SND.MAX advances iff SND.NXT is "ahead"
        # of it in the modular 32-bit sense. Plain 'max()' would
        # use numerical order, which is wrong across the wrap.
        if lt32(self._snd_max, self._snd_nxt):
            self._snd_max = self._snd_nxt
        # Modular '+=' on '_tx_buffer_seq_mod' (a Seq32 anchor):
        # raw '+=' would let the value escape the 32-bit range
        # past the wrap; 'add32' clamps to UINT32__MAX.
        self._tx_buffer_seq_mod = add32(self._tx_buffer_seq_mod, flag_syn, flag_fin)

        # In case packet caries FIN flag make note of its SEQ number.
        if flag_fin:
            self._snd_fin = self._snd_nxt
            self._fin_sent = True

        # Whenever we send an ACK-bearing segment (which may also carry
        # data) the peer's pending sequence space is implicitly
        # acknowledged via the piggybacked ACK field, so the
        # every-other-segment counter resets to zero.
        if flag_ack:
            self._delayed_ack_segments_pending = 0

        # RFC 1122 §4.2.3.6: any outbound segment counts as
        # "activity" for keep-alive purposes - reset the idle
        # timer. No-op when keep-alive is disabled. The keep-alive
        # PROBE itself bypasses this method (it goes through
        # 'stack.packet_handler.send_tcp_packet' directly), so a
        # probe emission does not spuriously reset its own timer.
        self._keepalive_arm_idle()

        # If in ESTABLISHED state then reset ACK delay timer.
        if self._state is FsmState.ESTABLISHED:
            stack.timer.register_timer(name=f"{self}-delayed_ack", timeout=tcp__constants.DELAYED_ACK_DELAY)

        # RFC 6298 §5.1: every packet containing data (including a
        # retransmission) starts the retransmit timer if it is not
        # already running. The 'is_expired' check returns True both
        # when the timer has never been registered AND after it has
        # expired, so this branch correctly arms a fresh timer
        # post-§5.2-shutdown without spuriously re-arming a still-
        # running one. Re-arming on every send would diverge from
        # §5.1's "if not running, start it" wording; the §5.3
        # restart-on-cum-ACK fires from '_process_ack_packet'
        # instead, and the timeout-driven re-arm fires from
        # '_retransmit_packet_timeout' after 'back_off'.
        if (data or flag_syn or flag_fin) and stack.timer.is_expired(f"{self}-retransmit"):
            stack.timer.register_timer(
                name=f"{self}-retransmit",
                timeout=self._rto_state.rto_ms,
            )

        __debug__ and log(
            "tcp-ss",
            f"[{self}] - Sent packet_rx_md: {'S' if flag_syn else ''}"
            f"{'F' if flag_fin else ''}{'R' if flag_rst else ''}"
            f"{'A' if flag_ack else ''}, seq {seq}, ack {ack}, "
            f"dlen {len(data)}",
        )

    def _build_sack_blocks(self) -> list[tuple[int, int]]:
        """
        Compute the SACK option block list for the next outbound
        ACK. Layout per RFC 2018 §4 / RFC 2883 §4: when a DSACK
        report is pending it MUST appear as the FIRST block (the
        signal the sender uses to recognise this as a DSACK-
        bearing option), followed by the OOO-queue ranges in
        insertion order. The returned list is capped at RFC 2018
        §3's maximum of 4 blocks per option. The pending DSACK
        is consumed (cleared) by this call so it appears on
        exactly one outbound ACK.
        """

        blocks: list[tuple[int, int]] = []
        if self._pending_dsack is not None:
            blocks.append(self._pending_dsack)
            self._pending_dsack = None
        for seq, packet_rx_md in self._ooo_packet_queue.items():
            if len(blocks) >= 4:
                break
            blocks.append((seq, add32(seq, len(packet_rx_md.tcp__data))))
        return blocks

    def _check_segment_acceptability(self, packet_rx_md: TcpMetadata) -> bool:
        """
        Apply the RFC 9293 §3.10.7.4 step 1 receive-window
        acceptability check to an inbound segment. Return True
        when the segment is acceptable (caller should continue
        processing); return False when the segment is
        unacceptable (caller MUST drop and return - this method
        has already emitted the mandated ACK reply).

        Acceptability table (RFC 9293 §3.10.7.4):

            SEG.LEN == 0:
              RCV.WND > 0  -> RCV.NXT <= SEG.SEQ <= RCV.NXT+RCV.WND
              RCV.WND == 0 -> SEG.SEQ == RCV.NXT
            SEG.LEN > 0:
              RCV.WND > 0  -> SEG.SEQ < RCV.NXT+RCV.WND AND
                              SEG.SEQ + SEG.LEN > RCV.NXT
              RCV.WND == 0 -> not acceptable

        SEG.LEN here counts data plus the SYN / FIN flag bytes
        that also consume sequence space. All comparisons are
        modular per RFC 9293 §3.4.

        On unacceptable segments the spec mandates an ACK reply
        carrying our current SND.NXT / RCV.NXT, EXCEPT when the
        segment carries RST (RFC 9293 §3.10.7.4 step 1 explicit
        RST clause: 'unless the RST bit is set, if so drop the
        segment and return' - replying with an ACK to a blind
        RST would amplify a possible attack).

        RFC 2883 DSACK case 1: when bilateral SACK is enabled
        and the unacceptable segment is a fully-duplicate data
        retransmit (entirely below RCV.NXT), stash the
        duplicated range as a pending DSACK so the next
        outbound ACK reports it as the FIRST SACK block.
        """

        seg_len = len(packet_rx_md.tcp__data) + packet_rx_md.tcp__flag_syn + packet_rx_md.tcp__flag_fin
        seg_end = add32(packet_rx_md.tcp__seq, seg_len)
        if seg_len == 0:
            if self._rcv_wnd > 0:
                acceptable = in_range32(packet_rx_md.tcp__seq, self._rcv_nxt, add32(self._rcv_nxt, self._rcv_wnd))
            else:
                acceptable = packet_rx_md.tcp__seq == self._rcv_nxt
        else:
            if self._rcv_wnd > 0:
                acceptable = lt32(packet_rx_md.tcp__seq, add32(self._rcv_nxt, self._rcv_wnd)) and gt32(
                    seg_end, self._rcv_nxt
                )
            else:
                acceptable = False

        if acceptable:
            return True

        __debug__ and log(
            "tcp-ss",
            f"[{self}] - Packet seq {packet_rx_md.tcp__seq} + " f"{seg_len} doesn't fit into receive window, dropping",
        )
        # RFC 9293 §3.10.7.4 step 1 RST exception: an
        # unacceptable RST is dropped silently to avoid an
        # ACK-amplification path against blind off-path
        # attackers.
        if packet_rx_md.tcp__flag_rst:
            return False
        # RFC 2883 DSACK case 1: stash the duplicate range so
        # the ACK below reports it as the FIRST SACK block.
        if (
            self._send_sack
            and len(packet_rx_md.tcp__data) > 0
            and lt32(packet_rx_md.tcp__seq, self._rcv_nxt)
            and le32(seg_end, self._rcv_nxt)
        ):
            self._pending_dsack = (packet_rx_md.tcp__seq, seg_end)
        # RFC 9293 §3.10.7.4 step 1: ACK the unacceptable
        # segment so peer's retransmit machinery sees fresh
        # activity and can stop retransmitting. Rate-limited
        # per RFC 5961 §3 so a burst of unacceptable segments
        # cannot amplify into an outbound ACK flood.
        self._emit_challenge_ack()
        return False

    def _check_rst_acceptability(self, packet_rx_md: TcpMetadata) -> bool:
        """
        RFC 9293 §3.10.7.4 / RFC 5961 §3.2 three-way RST handling
        for synchronized states. Returns True when the inbound
        RST is in-window AND its 'seq' exactly matches RCV.NXT
        (case 1: caller MUST reset the connection via state ->
        CLOSED). Returns False otherwise; if the segment was
        in-window but its seq did not match RCV.NXT (case 2),
        this method has already emitted a rate-limited challenge
        ACK so a legitimate peer can retransmit at the right
        seq, while a blind off-path attacker cannot leverage the
        silent drop. Out-of-window RSTs (case 3) fall through to
        silent drop with no reply.

        The 'ack' field is also validated against
        '[SND.UNA, SND.MAX]' for case 1 to preserve the
        defensive guard the per-state RST handlers carried
        previously; an RST whose ack value implausibly points
        at unsent data is treated like a case-3 out-of-window
        drop. RFC 9293 does not strictly require this guard but
        the conservative behaviour is harmless and matches the
        pre-helper code's invariant.
        """

        seq = packet_rx_md.tcp__seq
        # The 'ack' field is only meaningful when the ACK flag is
        # set (RFC 9293 §3.1). A bare RST carries no ack value;
        # the in-range guard is skipped in that case so the
        # case-1 reset path remains reachable for peer TCPs that
        # send bare RST instead of the more common RST+ACK.
        ack_acceptable = (not packet_rx_md.tcp__flag_ack) or in_range32(
            packet_rx_md.tcp__ack, self._snd_una, self._snd_max
        )
        if seq == self._rcv_nxt and ack_acceptable:
            return True
        if lt32(self._rcv_nxt, seq) and lt32(seq, add32(self._rcv_nxt, self._rcv_wnd)):
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - In-window mismatched RST (seq={seq}, RCV.NXT={self._rcv_nxt}); challenge-ACK",
            )
            self._emit_challenge_ack()
        return False

    def _emit_challenge_ack(self) -> None:
        """
        RFC 5961 §3 / §4 rate-limited challenge-ACK emission.
        Fires '_transmit_packet(flag_ack=True)' at most once per
        sliding 1-second window so a burst of inbound segments
        (unacceptable seq, unacceptable ack, blind SYN-in-
        synchronized-state, etc.) cannot amplify into an outbound
        ACK flood. Subsequent calls within the window are
        suppressed; the caller's intended observable behaviour
        ('an ACK was emitted in response to this segment') is
        sacrificed in favour of the global rate-limit invariant
        which RFC 5961 mandates as a SHOULD-level requirement.

        Implementation: a per-session 'stack.timer' entry named
        '<session>-challenge_ack' acts as the sliding-window
        gate. 'is_expired' returns True when the entry has fired
        or was never registered - either way we are outside the
        rate-limit window and may emit; otherwise we suppress.
        """

        rate_limit_timer = f"{self}-challenge_ack"
        if not stack.timer.is_expired(rate_limit_timer):
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Challenge ACK suppressed by RFC 5961 §3 rate limit",
            )
            return
        self._transmit_packet(flag_ack=True)
        stack.timer.register_timer(name=rate_limit_timer, timeout=tcp__constants.CHALLENGE_ACK_RATE_LIMIT_MS)

    def _keepalive_arm_idle(self) -> None:
        """
        (Re)arm the keep-alive idle timer per RFC 1122 §4.2.3.6.

        Called from any code path that observes peer activity (an
        inbound data segment, an inbound ACK, or our own outbound
        transmission - peer's eventual response will reset the
        timer naturally) and from '_change_state' on the transition
        into ESTABLISHED. No-op when '_keepalive_enabled' is False.
        Resetting also clears the unanswered-probe counter so a
        fresh idle window starts from zero.
        """

        if not self._keepalive_enabled:
            return
        self._keepalive_probes_unacked = 0
        self._keepalive_active = True
        stack.timer.register_timer(
            name=f"{self}-keepalive",
            timeout=(
                self._keepalive_idle_override
                if self._keepalive_idle_override is not None
                else tcp__constants.KEEPALIVE_IDLE_TIME
            ),
        )

    def _keepalive_tick(self) -> None:
        """
        Per-tick keep-alive timer service.

        Called from the synchronized-state FSM timer branch
        (currently ESTABLISHED only). When the keep-alive timer
        fires, either emit another probe or - if
        'KEEPALIVE_PROBE_MAX_COUNT' probes have already gone
        unanswered - tear the connection down per RFC 1122
        §4.2.3.6. The probe wire shape is an ACK with
        'SEG.SEQ = SND.NXT - 1' so peer's TCP is forced to respond
        with an ACK at the current SND.NXT (which we treat as a
        probe-ack and use to reset the idle timer); peer's
        application sees no segment text. The probe is emitted
        directly via the packet handler rather than via
        '_transmit_packet' because the latter rewrites SND.NXT
        from its 'seq' argument and the probe must consume no
        sequence space.

        Lazy-arm: when 'enable_keepalive' is flipped True after
        handshake completion (e.g. via a setsockopt-equivalent
        path), the first tick sees '_keepalive_enabled = True'
        but '_keepalive_active = False'. Arm the timer here and
        return so the next tick begins the regular idle countdown.
        """

        if not self._keepalive_enabled:
            return
        if not self._keepalive_active:
            self._keepalive_arm_idle()
            return
        if not stack.timer.is_expired(f"{self}-keepalive"):
            return
        max_count = (
            self._keepalive_max_count_override
            if self._keepalive_max_count_override is not None
            else tcp__constants.KEEPALIVE_PROBE_MAX_COUNT
        )
        if self._keepalive_probes_unacked >= max_count:
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Keep-alive: {self._keepalive_probes_unacked} probes "
                "unacked, tearing down connection (RFC 1122 §4.2.3.6)",
            )
            self._connection_error = ConnError.TIMEOUT
            self._event__connect.release()
            self._event__rx_buffer.set()
            self._change_state(FsmState.CLOSED)
            return
        stack.packet_handler.send_tcp_packet(
            ip__local_address=self._local_ip_address,
            ip__remote_address=self._remote_ip_address,
            tcp__local_port=self._local_port,
            tcp__remote_port=self._remote_port,
            tcp__flag_ack=True,
            tcp__seq=sub32(self._snd_nxt, 1),
            tcp__ack=self._rcv_nxt,
            tcp__win=self._rcv_wnd >> self._rcv_wsc,
        )
        self._keepalive_probes_unacked += 1
        stack.timer.register_timer(
            name=f"{self}-keepalive",
            timeout=(
                self._keepalive_interval_override
                if self._keepalive_interval_override is not None
                else tcp__constants.KEEPALIVE_PROBE_INTERVAL
            ),
        )
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - Keep-alive: emitted probe "
            f"{self._keepalive_probes_unacked}/{max_count} "
            f"at seq={sub32(self._snd_nxt, 1)} ack={self._rcv_nxt}",
        )

    def _ingest_sack_info(self, packet_rx_md: TcpMetadata) -> None:
        """
        Ingest peer's SACK blocks from 'packet_rx_md' into the
        send-side scoreboard, gated on '_send_sack' (bilateral
        negotiation succeeded). Per RFC 2018 §5 ("be liberal in
        what we accept") blocks whose edges fall outside
        '[SND.UNA, SND.MAX]' or are degenerate ('left >= right')
        are silently dropped - they cannot describe legitimate
        in-flight bytes.

        Also recognises RFC 2883 DSACK reports: the FIRST SACK
        block is treated as a DSACK marker (and excluded from
        scoreboard ingestion) when either of the RFC 2883 §4
        signatures holds:

          1. Below cum-ACK: 'right <= SND.UNA'. Peer is
             reporting a duplicate of bytes already
             cumulatively acknowledged.
          2. Contained-in-other: the first block lies inside
             one of the subsequent blocks. Peer is reporting
             a duplicate of bytes already SACKed.

        On detection '_dsack_received' is incremented for
        observability; the spurious-retransmit / RTO-management
        consumers of this counter are out of scope for phase 7.
        """

        if not self._send_sack:
            return

        blocks = list(packet_rx_md.tcp__sack_blocks)
        if not blocks:
            return

        # RFC 2883 DSACK detection on the first block.
        first_left, first_right = blocks[0]
        is_dsack = le32(first_right, self._snd_una)
        if not is_dsack:
            for outer_left, outer_right in blocks[1:]:
                if le32(outer_left, first_left) and le32(first_right, outer_right):
                    is_dsack = True
                    break
        if is_dsack:
            self._dsack_received += 1
            blocks = blocks[1:]

        for left, right in blocks:
            if le32(self._snd_una, left) and le32(right, self._snd_max) and lt32(left, right):
                self._sack_scoreboard.add_block(left, right)

    def _prune_sack_scoreboard(self) -> None:
        """
        Drop scoreboard blocks whose right edge is at or below
        the current 'SND.UNA' - the cumulative ACK has absorbed
        them and they cannot inform any further loss recovery
        (RFC 6675 §3 / RFC 2018 §3). Gated on '_send_sack' so the
        pruning is a no-op on connections without bilateral SACK.
        """

        if self._send_sack:
            self._sack_scoreboard.prune_below(self._snd_una)

    def _advance_snd_nxt_past_sacked(self) -> None:
        """
        During fast-retransmit recovery, advance 'SND.NXT' past
        any peer-SACKed range that contains it so the next
        transmission does not redundantly re-send bytes peer
        already received. RFC 6675 §5 multi-gap recovery: the
        sender consults the scoreboard to skip SACKed regions
        and only retransmits genuine gaps. Walks the scoreboard
        in modular order from 'SND.UNA'; since the scoreboard
        coalesces adjacent blocks on insert a single pass
        suffices. No-op when not in recovery, when SACK is
        disabled, or when 'SND.NXT == SND.MAX' (everything we
        intended to send has been sent).
        """

        if self._recovery_point == 0 or not self._send_sack:
            return

        for left, right in sorted(
            self._sack_scoreboard.blocks(),
            key=lambda b: (b[0] - self._snd_una) & 0xFFFF_FFFF,
        ):
            if le32(left, self._snd_nxt) and lt32(self._snd_nxt, right):
                self._snd_nxt = right

    def _enqueue_rx_buffer(self, data: memoryview) -> None:
        """
        Process the incoming segment and enqueue the data
        to be used by socket.
        """

        assert isinstance(data, memoryview)  # memoryview: check to ensure data gets here as memoryview not bytes.

        with self._lock__rx_buffer:
            self._rx_buffer.extend(data)
            # 'Event.set()' is idempotent so this is safe whether the
            # event was already set by a sibling FSM handler or not.
            self._event__rx_buffer.set()

    def _transmit_data(self) -> None:
        """
        Send out data segment from TX buffer using TCP
        sliding window mechanism.
        """

        # RFC 9293 §3.8.6 / RFC 1122 §4.2.2.16: a sender MUST be
        # robust against peer window shrinking. When the peer ACKs
        # less data than is in flight while simultaneously
        # advertising a smaller window, the right edge
        # (SND.UNA + SND.EWN) can fall below SND.NXT and the
        # invariant 'SND.UNA <= SND.NXT <= SND.UNA + SND.EWN' is
        # legitimately violated. The RFC requires the sender to
        # absorb the shrink: refuse to push more data, wait for the
        # peer to reopen the window or for RTO to fire, and let
        # the normal retransmit machinery cover the unacknowledged
        # bytes within SND.UNA..SND.UNA+SND.WND.
        # Modular window-edge check (RFC 9293 §3.4): SND.NXT must
        # fall within the closed interval [SND.UNA, SND.UNA+SND.EWN]
        # in modular 32-bit space. Plain '<=' chained comparison
        # would wrongly reject a SND.NXT that has wrapped past
        # SND.UNA but is still in-window.
        right_edge = add32(self._snd_una, self._snd_ewn)
        if not in_range32(self._snd_nxt, self._snd_una, right_edge):
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Peer-shrunk usable window: SND.NXT={self._snd_nxt} "
                f"is outside [{self._snd_una}, {right_edge}]; "
                "deferring further transmission until peer reopens or RTO fires",
            )
            return

        # Check if we need to (re)transmit initial SYN packet.
        if self._state is FsmState.SYN_SENT and self._snd_nxt == self._snd_ini:
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Transmitting initial SYN packet_rx_md: seq {self._snd_nxt}",
            )
            self._transmit_packet(flag_syn=True)
            return

        # Check if we need to (re)transmit initial SYN + ACK packet.
        if self._state is FsmState.SYN_RCVD and self._snd_nxt == self._snd_ini:
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Transmitting initial SYN + ACK packet_rx_md: seq {self._snd_nxt}",
            )
            self._transmit_packet(flag_syn=True, flag_ack=True)
            return

        # Make sure we in the state that allows sending data out.
        if self._state in {FsmState.ESTABLISHED, FsmState.CLOSE_WAIT}:
            # During fast-retransmit recovery, advance SND.NXT past
            # any peer-SACKed range so the next transmit does not
            # re-send bytes peer already received. RFC 6675 §5
            # multi-gap recovery semantics: with the scoreboard
            # tracking SACKed regions, the sender can skip them
            # entirely and only retransmit genuine gaps. Outside
            # recovery this is a no-op (the high-water-mark
            # invariant 'SND.NXT == SND.MAX' holds, and
            # 'is_sacked(SND.MAX)' is always False since peer
            # cannot SACK bytes we never sent).
            self._advance_snd_nxt_past_sacked()
            remaining_data_len = len(self._tx_buffer) - self._tx_buffer_nxt
            usable_window = self._snd_ewn - self._tx_buffer_nxt
            transmit_data_len = min(self._snd_mss, usable_window, remaining_data_len)
            if remaining_data_len:
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Sliding window <y>[{self._snd_una}|"
                    f"{self._snd_nxt}|{add32(self._snd_una, self._snd_ewn)}]</>",
                )
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - {usable_window} left in window, "
                    f"{remaining_data_len} left in buffer, "
                    f"{transmit_data_len} to be sent",
                )
                if transmit_data_len > 0:
                    # Nagle's algorithm with the Minshall modification
                    # (RFC 1122 §4.2.3.4). Defer a partial (sub-MSS)
                    # segment when a previous partial segment is still
                    # unacknowledged - this avoids generating tinygrams
                    # for a series of small writes while still allowing
                    # the trailing fragment of a single large write to
                    # fire immediately. We track the post-end seq of
                    # the most recent partial in '_snd_sml'; if it is
                    # still ahead of 'SND.UNA', a previous partial is
                    # in flight and we defer until either it gets ACK'd
                    # or the buffered amount reaches a full MSS.
                    #
                    # Nagle applies to FRESH transmits only - RFC 1122
                    # §4.2.3.4 governs application-driven small-write
                    # generation, not the RTO retransmit machinery
                    # (RFC 6298 §2 retransmits the earliest unacked
                    # segment unconditionally). We detect "we are
                    # retransmitting" via 'SND.NXT < SND.MAX
                    # modularly': '_retransmit_packet_timeout' rewinds
                    # SND.NXT to SND.UNA while leaving SND.MAX at the
                    # high-water mark, so this inequality is True iff
                    # the next segment to send covers ground we have
                    # already transmitted. Without this exemption a
                    # sub-MSS partial that is dropped on the wire
                    # would loop in the Nagle gate forever - the
                    # retransmit counter only increments inside
                    # '_transmit_packet', so deferring here also
                    # disables R2-based connection-abort progression,
                    # silently hanging the connection.
                    is_retransmit = lt32(self._snd_nxt, self._snd_max)
                    is_partial = transmit_data_len < self._snd_mss
                    prev_partial_in_flight = gt32(self._snd_sml, self._snd_una)
                    if is_partial and prev_partial_in_flight and not is_retransmit:
                        __debug__ and log(
                            "tcp-ss",
                            f"[{self}] - Nagle: deferring {transmit_data_len}-byte "
                            f"partial segment - previous partial at seq {self._snd_sml} "
                            f"still unacked (SND.UNA={self._snd_una})",
                        )
                        return
                    with self._lock__tx_buffer:
                        transmit_data = self._tx_buffer[self._tx_buffer_nxt : self._tx_buffer_nxt + transmit_data_len]
                    # RFC 1122 §4.2.2.2: PSH MUST be set on the last
                    # segment of a write. The current segment drains
                    # the buffer iff 'transmit_data_len ==
                    # remaining_data_len'; that is the marker for "this
                    # is the last segment of the buffered write".
                    is_last_segment_of_write = transmit_data_len == remaining_data_len
                    __debug__ and log(
                        "tcp-ss",
                        f"[{self}] - Transmitting data segment: seq {self._snd_nxt} len {len(transmit_data)}",
                    )
                    self._transmit_packet(
                        flag_ack=True,
                        flag_psh=is_last_segment_of_write,
                        data=bytes(transmit_data),
                    )
                    # If we just sent a partial, record its post-end
                    # seq so the Minshall check can defer subsequent
                    # partials until this one is ACK'd.
                    if is_partial:
                        self._snd_sml = self._snd_nxt
                else:
                    # Zero-window state: peer has buffered no receive
                    # space but we have data ready to send. Manage the
                    # persist timer per RFC 9293 §3.8.6.1: arm the timer
                    # on first entry into the state, then on each
                    # expiry emit a 1-byte probe at SND.UNA and re-arm
                    # with double the timeout (capped at
                    # tcp__constants.PERSIST_TIMEOUT_MAX). RFC 1122 §4.2.2.17 makes
                    # probing mandatory because without it the
                    # connection would stall indefinitely whenever the
                    # peer temporarily closed its window.
                    persist_timer = f"{self}-persist"
                    if not self._persist_active:
                        self._persist_active = True
                        self._persist_timeout = tcp__constants.PACKET_RETRANSMIT_TIMEOUT
                        stack.timer.register_timer(name=persist_timer, timeout=self._persist_timeout)
                        __debug__ and log(
                            "tcp-ss",
                            f"[{self}] - Persist: zero-window, armed timer " f"with timeout {self._persist_timeout} ms",
                        )
                    elif stack.timer.is_expired(persist_timer):
                        with self._lock__tx_buffer:
                            probe_data = bytes(self._tx_buffer[self._tx_buffer_nxt : self._tx_buffer_nxt + 1])
                        __debug__ and log(
                            "tcp-ss",
                            f"[{self}] - Persist: emitting 1-byte probe at seq {self._snd_nxt}",
                        )
                        self._transmit_packet(flag_ack=True, data=probe_data)
                        # The probe is by definition a partial; track
                        # it for Nagle so subsequent partials defer.
                        self._snd_sml = self._snd_nxt
                        self._persist_timeout = min(self._persist_timeout * 2, tcp__constants.PERSIST_TIMEOUT_MAX)
                        stack.timer.register_timer(name=persist_timer, timeout=self._persist_timeout)
                return

        # Check if we need to (re)transmit final FIN packet.
        if self._state in {FsmState.FIN_WAIT_1, FsmState.LAST_ACK} and self._snd_nxt != self._snd_fin:
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Transmitting final FIN packet_rx_md: seq {self._snd_nxt}",
            )
            self._transmit_packet(flag_fin=True, flag_ack=True)
            return

    def _delayed_ack(self) -> None:
        """
        Run Delayed ACK mechanism.
        """

        if stack.timer.is_expired(f"{self}-delayed_ack"):
            if gt32(self._rcv_nxt, self._rcv_una):
                self._transmit_packet(flag_ack=True)
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Sent out delayed ACK ({self._rcv_nxt})",
                )
            stack.timer.register_timer(name=f"{self}-delayed_ack", timeout=tcp__constants.DELAYED_ACK_DELAY)

    def _retransmit_packet_timeout(self) -> None:
        """
        Retransmit packet after expired timeout.

        RFC 6298 §5 specifies the timer's lifecycle:
            §5.1 Arm on data send if not running.
            §5.2 Stop on cum-ACK that drains all in-flight.
            §5.3 Restart on cum-ACK that advances SND.UNA.
            §5.4 Retransmit the earliest unacked segment.
            §5.5 Back off RTO (cap at MAX_RTO_MS).
            §5.6 Re-arm with the new RTO.
        """

        # RFC 6298 §5: only act when the session-level retransmit
        # timer has fired. 'is_expired' returns True both when the
        # timer is dropped (its countdown reached zero) AND when it
        # was never registered, so the second guard 'snd_una !=
        # snd_max' filters out the quiescent "nothing in flight"
        # case where 'is_expired' is True only because no timer is
        # running.
        if not stack.timer.is_expired(f"{self}-retransmit"):
            return
        if self._snd_una == self._snd_max:
            return

        # RFC 1122 §4.2.3.5 R2: after PACKET_RETRANSMIT_MAX_COUNT
        # consecutive timeouts without progress, abort the
        # connection. The counter resets on every cum-ACK that
        # advances SND.UNA in '_process_ack_packet', so the abort
        # is gated on prolonged silence, not lifetime retransmits.
        if self._retransmit_count >= tcp__constants.PACKET_RETRANSMIT_MAX_COUNT:
            # Send RST to peer iff peer was actually contacted
            # (i.e. we processed at least one inbound segment
            # post-handshake-start). The check uses the explicit
            # '_peer_contacted' flag rather than 'RCV.NXT > 0'
            # because 'RCV.NXT' is a Seq32 that legitimately
            # takes the value 0 when peer's ISN happened to be
            # 0xFFFF_FFFF ('add32(peer_isn, 1)' wraps to 0); a
            # raw '> 0' comparison would suppress the RST in
            # that case.
            if self._peer_contacted:
                self._transmit_packet(flag_rst=True, flag_ack=True, seq=self._snd_una)
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Packet retransmit counter expired, resetting session",
                )
            else:
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Packet retransmit counter expired",
                )
            # If in any state with established connection inform socket
            # about connection failure.
            if self._state in {
                FsmState.ESTABLISHED,
                FsmState.FIN_WAIT_1,
                FsmState.FIN_WAIT_2,
                FsmState.CLOSE_WAIT,
            }:
                self._connection_error = ConnError.TIMEOUT
                self._event__rx_buffer.set()
            # If in SYN_SENT state inform CONNECT syscall that the
            # connection related event happened.
            if self._state is FsmState.SYN_SENT:
                self._connection_error = ConnError.TIMEOUT
                self._event__connect.release()
            # Change state to CLOSED
            self._change_state(FsmState.CLOSED)
            return

        # RFC 6298 §3 (Karn): if the segment now being
        # retransmitted carries a pending RTT sample, taint
        # the sample so the harvest hook in
        # '_process_ack_packet' clears the tracker without
        # folding the (now-ambiguous) RTT into '_rto_state'.
        # The pending sample's send-time and seq remain set
        # so the harvest path can recognise the covering
        # ACK; only the "skip update" flag flips.
        if self._rtt_sample_seq is not None and self._rtt_sample_seq == self._snd_una:
            self._rtt_sample_retransmitted = True

        # RFC 6298 §5.5 binary backoff and §5.6 re-arm with the
        # new RTO. 'back_off' caps at 'MAX_RTO_MS' so a long-
        # silent peer cannot drive 'rto_ms' to overflow.
        self._rto_state = back_off(self._rto_state)
        self._retransmit_count += 1
        stack.timer.register_timer(
            name=f"{self}-retransmit",
            timeout=self._rto_state.rto_ms,
        )
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - RFC 6298 §5.5 back-off: rto_ms -> "
            f"{self._rto_state.rto_ms} (retry "
            f"#{self._retransmit_count})",
        )

        # RFC 5681 §3.1 step 1: on RTO, halve ssthresh so the
        # post-RTO slow-start exits at the previously-observed
        # loss point. The 'max(FlightSize/2, 2*SMSS)' floor
        # prevents a single tiny in-flight segment from
        # collapsing ssthresh below the canonical minimum and
        # prematurely terminating slow-start. FlightSize is
        # computed BEFORE the SND.NXT rewind below so it
        # reflects the unacked-bytes count at the moment of
        # loss detection. Modular subtraction per RFC 9293 §3.4
        # so the value is correct across the 32-bit wrap.
        flight_size = (self._snd_max - self._snd_una) & 0xFFFF_FFFF
        self._ssthresh = max(flight_size // 2, 2 * self._snd_mss)
        # RFC 5681 §3.1: cwnd collapses to LW = 1 SMSS for
        # slow-start re-entry. RFC 9293 §3.8.6.1 / RFC 1122
        # §4.2.2.16 still require respecting peer's advertised
        # window: a 0-window peer means '_snd_ewn = 0' so
        # '_transmit_data' falls through to the persist branch.
        self._cwnd = self._snd_mss
        self._snd_ewn = min(self._cwnd, self._snd_wnd)
        self._snd_nxt = self._snd_una
        # RFC 5681 §3.1 hard reset: an RTO is a fresh loss
        # event, distinct from the dup-ACK-driven fast-
        # retransmit recovery. The RFC 6675 §5 RecoveryPoint
        # marker (the SND.MAX at fast-retransmit entry) is
        # meaningless once SND.NXT has been rewound to
        # SND.UNA above; leaving it set would inhibit the
        # next dup-ACK from re-entering recovery via the
        # one-shot guard in '_retransmit_packet_request'.
        self._recovery_point = 0
        # SYN and FIN consume one byte of sequence space but do
        # not occupy a slot in the TX buffer. After
        # '_transmit_packet' fired the original SYN/FIN it
        # incremented '_tx_buffer_seq_mod' by 1 to account for
        # that phantom byte; on retransmit we walk the offset
        # back so the packet builder finds the pre-SYN/FIN
        # alignment again. The FIN branch compares against
        # 'sub32(_snd_fin, 1)' because '_snd_fin' carries the
        # post-FIN-seq (assigned in '_transmit_packet' AFTER
        # 'SND.NXT' was already advanced past the FIN's byte),
        # while the rewind above sets 'SND.NXT = SND.UNA =
        # FIN_seq = _snd_fin - 1' on the canonical "FIN sent,
        # peer ACKed everything before it but not the FIN"
        # path. The branch is gated on '_fin_sent' to prevent
        # the sentinel '_snd_fin = 0' from colliding with a
        # post-wrap 'SND.NXT == 0xFFFF_FFFF' (which would
        # otherwise walk '_tx_buffer_seq_mod' back spuriously
        # and silently corrupt subsequent transmissions).
        if self._snd_nxt == self._snd_ini or (self._fin_sent and self._snd_nxt == sub32(self._snd_fin, 1)):
            self._tx_buffer_seq_mod = sub32(self._tx_buffer_seq_mod, 1)
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - Got retransmit timeout, sending segment "
            f"{self._snd_nxt}, resetting snd_ewn to {self._snd_ewn}",
        )

    def _retransmit_packet_request(self, packet_rx_md: TcpMetadata) -> None:
        """
        Retransmit packet after receiving fast-retransmit request from
        peer (RFC 5681 §3.2: third duplicate ACK, one-shot per loss
        event).
        """

        # Ingest any SACK blocks carried on this dup-ACK before the
        # fast-retransmit decision so IsLost() sees the latest
        # peer-reported scoreboard state. SND.UNA does not advance
        # on a dup-ACK so no prune is needed here.
        self._ingest_sack_info(packet_rx_md)

        self._tx_retransmit_request_counter[packet_rx_md.tcp__ack] = (
            self._tx_retransmit_request_counter.get(packet_rx_md.tcp__ack, 0) + 1
        )

        # RFC 5681 §3.2 / RFC 6675 §5: enter recovery exactly
        # once per loss event. While 'recovery_point > 0' we are
        # still recovering from an earlier trigger; further
        # dup-ACKs inflate cwnd per RFC 5681 §3.2 step 4 but
        # MUST NOT re-fire the retransmit.
        if self._recovery_point != 0:
            # §3.2 step 4: each additional dup-ACK in recovery
            # represents one more segment that left the network
            # and grants permission to send one more new segment
            # while the retransmit is in flight.
            self._cwnd += self._snd_mss
            self._snd_ewn = min(self._cwnd, self._snd_wnd)
            return

        # Two independent triggers, either of which enters
        # recovery:
        #   - Count-based (RFC 5681 §3.2): the third duplicate
        #     ACK at the same 'ack' value.
        #   - SACK byte-rule (RFC 6675 §3 IsLost): the
        #     receiver has reported MORE THAN '(dup_thresh - 1)
        #     * SMSS' bytes SACKed above SND.UNA. This rule
        #     can fire on the very first dup-ACK if peer
        #     reports a single large SACK block, recovering
        #     faster than the count-based threshold on bursty
        #     loss patterns.
        count_trigger = self._tx_retransmit_request_counter[packet_rx_md.tcp__ack] == 3
        sack_trigger = self._send_sack and is_lost(
            self._snd_una,
            scoreboard=self._sack_scoreboard,
            snd_una=self._snd_una,
            mss=self._snd_mss,
        )
        if not (count_trigger or sack_trigger):
            return

        # RFC 5681 §3.2 step 2: ssthresh = max(FlightSize/2,
        # 2*SMSS). Captures the just-observed loss point so
        # the post-recovery slow-start exits at this boundary.
        # Step 3: cwnd = ssthresh + 3*SMSS - the +3 inflation
        # represents the three segments that left the network
        # (the dup-ACKs prove they arrived) and grants
        # permission to send three new segments while the
        # retransmit is in flight.
        flight_size = (self._snd_max - self._snd_una) & 0xFFFF_FFFF
        self._ssthresh = max(flight_size // 2, 2 * self._snd_mss)
        self._cwnd = self._ssthresh + 3 * self._snd_mss
        self._snd_ewn = min(self._cwnd, self._snd_wnd)

        # Mark RecoveryPoint at SND.MAX so subsequent dup-ACKs
        # within the loss event do not re-trigger; '_process_ack_packet'
        # clears it once the cumulative ACK has fully recovered.
        # Setting to 'max(SND.MAX, 1)' guarantees the marker is
        # non-zero even when SND.MAX wraps to 0; the actual
        # comparison is modular.
        self._recovery_point = self._snd_max if self._snd_max != 0 else 1

        # RFC 6675 §3 NextSeg() chooses the smallest unsacked
        # seq in '[SND.UNA, SND.MAX)' that IsLost() flags as
        # lost. When bilateral SACK is enabled and the
        # scoreboard's contents satisfy IsLost, NextSeg returns
        # the actual gap; in single-gap scenarios this equals
        # 'SND.UNA' (matching the count-based path). When SACK
        # is disabled or the scoreboard is below IsLost
        # thresholds, fall back to '_snd_una' so the count-based
        # RFC 5681 path remains intact for non-SACK peers.
        ns = (
            next_seg(
                scoreboard=self._sack_scoreboard,
                snd_una=self._snd_una,
                snd_max=self._snd_max,
                mss=self._snd_mss,
            )
            if self._send_sack
            else None
        )
        self._snd_nxt = ns if ns is not None else self._snd_una
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - Got retransmit request, sending segment "
            f"{self._snd_nxt}, keeping snd_ewn at {self._snd_ewn}, "
            f"recovery_point {self._recovery_point}",
        )

    def _process_ack_packet(self, packet_rx_md: TcpMetadata) -> None:
        """
        Process regular data/ACK packet.
        """

        # RFC 1122 §4.2.3.6: peer activity (ACK and / or data)
        # resets the keep-alive idle timer. No-op when keep-alive
        # is disabled.
        self._keepalive_arm_idle()

        # RFC 7323 §4.3 _ts_recent update: refresh the cached
        # peer TSval on every accepted inbound segment that
        # carries TSopt. Gated on bilateral '_send_ts' so the
        # update fires only when both sides negotiated. The
        # 'tcp__tsval >= _ts_recent' modular check would
        # ordinarily live here, but during normal forward
        # progress peer's TSval increases monotonically and the
        # update is unconditionally beneficial; PAWS-driven
        # rejection of stale-TSval segments lives at the
        # inbound dispatch (Phase 4 hook).
        if self._send_ts and packet_rx_md.tcp__tsval is not None:
            self._ts_recent = packet_rx_md.tcp__tsval

        # Make note of the local SEQ that has been acked by peer.
        # Modular 'max': SND.UNA advances iff peer's ack is
        # "ahead" of it in the 32-bit modular sense. Plain 'max()'
        # uses numerical order, which is wrong across the wrap.
        if lt32(self._snd_una, packet_rx_md.tcp__ack):
            # Modular bytes-acked computation per RFC 9293 §3.4
            # so the §3.1 cwnd growth formula gets the correct
            # delta when the cum-ACK straddles the 32-bit wrap.
            bytes_acked = (packet_rx_md.tcp__ack - self._snd_una) & 0xFFFF_FFFF
            self._snd_una = packet_rx_md.tcp__ack
            # RFC 5681 §3.1 cwnd growth on cum-ACK that advances
            # SND.UNA. The slow-start vs congestion-avoidance
            # gate is a single 'cwnd < ssthresh' comparison:
            #   - slow start: 'cwnd += min(bytes_acked, SMSS)'
            #     ("at most SMSS bytes for each ACK received")
            #   - CA:         'cwnd += max(1, SMSS*SMSS / cwnd)'
            #     ("approximately SMSS bytes per RTT")
            # The 'max(1, ...)' floor in CA prevents zero growth
            # on very large cwnd values where integer
            # 'SMSS*SMSS // cwnd' rounds down to 0; without it a
            # connection past 'cwnd > SMSS²' would stall.
            if self._cwnd < self._ssthresh:
                self._cwnd += min(bytes_acked, self._snd_mss)
            else:
                self._cwnd += max(1, self._snd_mss * self._snd_mss // self._cwnd)
            # RFC 9293 §3.8.4: the effective send window is
            # 'min(cwnd, snd_wnd)'. Recompute now so
            # '_transmit_data' sees the new value on the same
            # FSM tick.
            self._snd_ewn = min(self._cwnd, self._snd_wnd)
            # RFC 6298 §5.2 / §5.3: peer has acknowledged new
            # data, fresh evidence of liveness. Reset the R2
            # abort counter and manage the retransmit timer:
            # turn it off iff every in-flight byte is now
            # acked (§5.2), else restart it with the current
            # 'rto_ms' (§5.3). 'unregister_timers_with_prefix'
            # with the full timer name as prefix is the
            # canonical "stop this timer" idiom in the
            # codebase; it incidentally drops any legacy
            # 'f"{self}-retransmit_seq-X"' keys too, though
            # Phase 3 no longer creates those.
            self._retransmit_count = 0
            if self._snd_una == self._snd_max:
                stack.timer.unregister_timers_with_prefix(f"{self}-retransmit")
            else:
                stack.timer.register_timer(
                    name=f"{self}-retransmit",
                    timeout=self._rto_state.rto_ms,
                )
        # RFC 6298 §4 sample harvest: peer's cumulative ACK has
        # advanced past the seq of our pending RTT sample. Fold
        # the observed RTT into '_rto_state' iff the sample was
        # not retransmitted (Karn's algorithm, RFC 6298 §3); in
        # either case clear the tracker so the next outbound
        # segment can start a fresh sample. Modular 'gt32' so the
        # harvest fires correctly when both seq and ack straddle
        # the 32-bit wrap.
        if self._rtt_sample_seq is not None and gt32(packet_rx_md.tcp__ack, self._rtt_sample_seq):
            if not self._rtt_sample_retransmitted:
                assert self._rtt_sample_send_time_ms is not None
                observed_rtt_ms = stack.timer.now_ms - self._rtt_sample_send_time_ms
                self._rto_state = update(self._rto_state, observed_rtt_ms)
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - RTT sample harvested: rtt={observed_rtt_ms} ms, " f"rto_state={self._rto_state}",
                )
            else:
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - RTT sample tainted by retransmit (Karn); " f"skipping update of {self._rto_state}",
                )
            self._rtt_sample_seq = None
            self._rtt_sample_send_time_ms = None
            self._rtt_sample_retransmitted = False
        # SACK scoreboard maintenance per RFC 6675 §3 / RFC 2018
        # §3: prune any blocks now absorbed by the cumulative ACK,
        # then ingest fresh blocks the peer reported on this
        # segment. Both are no-ops when '_send_sack' is False.
        self._prune_sack_scoreboard()
        self._ingest_sack_info(packet_rx_md)
        # Exit recovery once SND.UNA has advanced to or past the
        # RecoveryPoint marker (RFC 6675 §5). The loss event is
        # now fully recovered; subsequent dup-ACKs are eligible
        # to re-enter recovery via either trigger. RFC 5681 §3.2
        # step 6 mandates deflating cwnd back to ssthresh on
        # exit so the inflation from steps 3+4 is undone and
        # subsequent §3.1 growth resumes from the previously-
        # observed loss boundary.
        if self._recovery_point != 0 and le32(self._recovery_point, self._snd_una):
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Exiting recovery: SND.UNA={self._snd_una} "
                f"reached RecoveryPoint={self._recovery_point}",
            )
            self._cwnd = self._ssthresh
            self._snd_ewn = min(self._cwnd, self._snd_wnd)
            self._recovery_point = 0
        # Adjust local SEQ accordingly to what peer acked (needed after the
        # retransmit happens and peer is jumping to previously received SEQ).
        if lt32(self._snd_nxt, self._snd_una) and le32(self._snd_una, self._snd_max):
            self._snd_nxt = self._snd_una
        # Update the next-expected receive sequence number, with two
        # protections drawn from RFC 9293 §3.4 / §3.10.7.4:
        #   1. Use 'max(...)' so a stale-duplicate segment whose tail
        #      lies entirely BEFORE our current RCV.NXT cannot REWIND
        #      RCV.NXT backward and corrupt the connection's seq
        #      tracking.
        #   2. Compute the overlap prefix - the count of already-
        #      received bytes at the front of this segment - so the
        #      enqueue path below can slice them off and avoid
        #      double-delivering bytes the application has already
        #      seen on a previous segment.
        # Modular 'seg_end' computation per RFC 9293 §3.4: each
        # operand contributes one or more sequence numbers, and
        # the sum wraps modulo 2**32.
        seg_end = add32(
            packet_rx_md.tcp__seq,
            len(packet_rx_md.tcp__data),
            packet_rx_md.tcp__flag_syn,
            packet_rx_md.tcp__flag_fin,
        )
        # Modular overlap-prefix: how many bytes at the front of
        # this segment we have already received (RCV.NXT - seq,
        # in modular 32-bit space; clamped to 0 if the segment is
        # entirely new).
        if lt32(packet_rx_md.tcp__seq, self._rcv_nxt):
            overlap_prefix = (self._rcv_nxt - packet_rx_md.tcp__seq) & 0xFFFF_FFFF
        else:
            overlap_prefix = 0
        # RFC 2883 DSACK: stash the duplicate-prefix range so the
        # next outbound ACK reports it as the FIRST SACK block.
        # The range is '[seg_seq, seg_seq + overlap_prefix)' which
        # equals '[seg_seq, OLD RCV.NXT)' (RCV.NXT advances later).
        if self._send_sack and overlap_prefix > 0:
            self._pending_dsack = (
                packet_rx_md.tcp__seq,
                add32(packet_rx_md.tcp__seq, overlap_prefix),
            )
        # Modular 'max' on RCV.NXT: advance iff the segment's end
        # is ahead of our current RCV.NXT in modular order.
        if lt32(self._rcv_nxt, seg_end):
            self._rcv_nxt = seg_end
        # In case packet contains data enqueue it. RFC 1122 §4.2.3.2 governs
        # how we acknowledge it: count pending unacked segments since the
        # last ACK, force an inline ACK once two segments are pending
        # ("every other segment"), and otherwise arm the delayed-ACK
        # timer so the ACK fires within tcp__constants.DELAYED_ACK_DELAY rather than
        # immediately. Arming the timer here (rather than only inside
        # '_transmit_packet') ensures the FIRST inbound data segment
        # after the handshake is properly delayed - without this, the
        # delayed-ACK timer would not yet be in 'stack.timer._timers'
        # (the third-leg ACK was emitted from within SYN_SENT, which
        # does not arm the timer), so 'is_expired' would return True on
        # the very next tick and an immediate ACK would slip out.
        if packet_rx_md.tcp__data and overlap_prefix < len(packet_rx_md.tcp__data):
            new_data = packet_rx_md.tcp__data[overlap_prefix:]
            self._enqueue_rx_buffer(new_data)
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Enqueued {len(new_data)} bytes starting at "
                f"{add32(packet_rx_md.tcp__seq, overlap_prefix)} "
                f"(sliced {overlap_prefix} overlap byte(s))",
            )
            self._delayed_ack_segments_pending += 1
            if self._delayed_ack_segments_pending >= 2:
                # RFC 1122 §4.2.3.2: ACK every other segment in a stream
                # of full-sized segments. '_transmit_packet' will reset
                # the counter via the 'flag_ack' branch below.
                self._transmit_packet(flag_ack=True)
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Sent inline ACK (every-other-segment, {self._rcv_nxt})",
                )
            else:
                # First pending segment: ensure the delayed-ACK timer is
                # armed so the timer-driven '_delayed_ack' will fire the
                # ACK after tcp__constants.DELAYED_ACK_DELAY rather than immediately.
                stack.timer.register_timer(name=f"{self}-delayed_ack", timeout=tcp__constants.DELAYED_ACK_DELAY)
        # Purge acked data from TX buffer.
        with self._lock__tx_buffer:
            del self._tx_buffer[: self._tx_buffer_una]
        self._tx_buffer_seq_mod = add32(self._tx_buffer_seq_mod, self._tx_buffer_una)
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - Purged TX buffer up to SEQ {self._snd_una}",
        )
        # Update remote window size.
        if self._snd_wnd != packet_rx_md.tcp__win << self._snd_wsc:
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Updated sending window size {self._snd_wnd} -> {packet_rx_md.tcp__win << self._snd_wsc}",
            )
            self._snd_wnd = packet_rx_md.tcp__win << self._snd_wsc
            # RFC 9293 §3.8.4: '_snd_ewn = min(cwnd, snd_wnd)'.
            # Recompute when peer's advertised window changes so
            # the wire-level transmit gate sees a coherent
            # min(cwnd, snd_wnd) regardless of which side just
            # moved.
            self._snd_ewn = min(self._cwnd, self._snd_wnd)
        # If peer has reopened their receive window, deactivate the
        # persist timer and reset the back-off interval so the next
        # zero-window event starts fresh at the initial RTO
        # (RFC 9293 §3.8.6.1).
        if self._snd_wnd > 0 and self._persist_active:
            __debug__ and log("tcp-ss", f"[{self}] - Persist: peer reopened window, deactivating timer")
            self._persist_active = False
            self._persist_timeout = tcp__constants.PACKET_RETRANSMIT_TIMEOUT
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - cwnd={self._cwnd} ssthresh={self._ssthresh} snd_ewn={self._snd_ewn}",
        )
        # Purge expired tx packet retransmit requests. Modular '<'
        # via 'lt32' so entries near the 32-bit wrap are dropped
        # correctly when SND.UNA advances past them.
        for seq in list(self._tx_retransmit_request_counter):
            if lt32(seq, packet_rx_md.tcp__ack):
                self._tx_retransmit_request_counter.pop(seq)
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Purged expired TX packet retransmit request counter for {seq}",
                )
        # Bring next packet from ooo_packet_queue if available.
        if ooo_packet := self._ooo_packet_queue.pop(self._rcv_nxt, None):
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - <lg>Retrieving packet {self._rcv_nxt} from Out of Order queue</>",
            )
            self.tcp_fsm(ooo_packet)

    def tcp_fsm(
        self,
        packet_rx_md: TcpMetadata | None = None,
        syscall: SysCall | None = None,
        timer: bool | None = None,
    ) -> None:
        """
        Run TCP finite state machine.
        """

        with self._lock__fsm:
            tcp_fsm_dispatch(
                self,
                packet_rx_md=packet_rx_md,
                syscall=syscall,
                timer=timer,
            )
