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

ver 3.0.6
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, override

from net_addr import Ip4Address, Ip6Address
from net_proto.protocols.tcp.tcp__header import TCP__MIN_MSS
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.tcp import tcp__constants
from pytcp.protocols.tcp.fsm.tcp__fsm import dispatch_icmp as tcp_fsm_dispatch_icmp
from pytcp.protocols.tcp.fsm.tcp__fsm import dispatch_packet as tcp_fsm_dispatch_packet
from pytcp.protocols.tcp.fsm.tcp__fsm import dispatch_syscall as tcp_fsm_dispatch_syscall
from pytcp.protocols.tcp.fsm.tcp__fsm import dispatch_timer as tcp_fsm_dispatch_timer
from pytcp.protocols.tcp.session.tcp__session__timers import TcpTimerService
from pytcp.protocols.tcp.session.tcp__session__tx import TcpTxEngine
from pytcp.protocols.tcp.state.tcp__state__accecn import AccEcnState
from pytcp.protocols.tcp.state.tcp__state__advertise import AdvertiseState
from pytcp.protocols.tcp.state.tcp__state__cc import CcState
from pytcp.protocols.tcp.state.tcp__state__ecn_classic import ClassicEcnState
from pytcp.protocols.tcp.state.tcp__state__fastopen import FastOpenState
from pytcp.protocols.tcp.state.tcp__state__keepalive import KeepaliveState
from pytcp.protocols.tcp.state.tcp__state__persist import PersistState
from pytcp.protocols.tcp.state.tcp__state__rack_tlp import RackTlpState
from pytcp.protocols.tcp.state.tcp__state__recv_seq import RecvSeqState
from pytcp.protocols.tcp.state.tcp__state__rtt_sample import RttSampleState
from pytcp.protocols.tcp.state.tcp__state__send_seq import SendSeqState
from pytcp.protocols.tcp.state.tcp__state__shutdown import ShutdownState
from pytcp.protocols.tcp.state.tcp__state__timestamps import TimestampsState
from pytcp.protocols.tcp.state.tcp__state__tx_buffer import TxBufferState
from pytcp.protocols.tcp.state.tcp__state__window import WindowState
from pytcp.protocols.tcp.tcp__cubic import (
    cubic_compute_K,
    cubic_grow_per_ack,
    cubic_loss_event_ssthresh,
    cubic_w_est,
)
from pytcp.protocols.tcp.tcp__cwnd import (
    compute_ecn_event_ssthresh,
    compute_loss_event_ssthresh,
    cwnd_grow_per_ack,
)
from pytcp.protocols.tcp.tcp__enums import (
    CcMode,
    ConnError,
    FsmState,
    SysCall,
)
from pytcp.protocols.tcp.tcp__errors import TcpSessionError
from pytcp.protocols.tcp.tcp__hystart import (
    css_growth_increment,
    enter_css,
    fold_rtt_sample,
    resume_slow_start,
    rotate_round,
    should_exit_slow_start_to_css,
    should_resume_slow_start_from_css,
)
from pytcp.protocols.tcp.tcp__icmp_metadata import IcmpMetadata
from pytcp.protocols.tcp.tcp__iss import compute_iss
from pytcp.protocols.tcp.tcp__loss_recovery import is_lost, next_seg, pipe
from pytcp.protocols.tcp.tcp__plpmtud_adapter import TcpPlpmtudAdapter
from pytcp.protocols.tcp.tcp__rack import (
    RackSegment,
    rack_compute_reo_wnd,
    rack_detect_loss,
    rack_update,
    tlp_process_ack,
)
from pytcp.protocols.tcp.tcp__rto import RtoState, back_off, initial_state, update
from pytcp.protocols.tcp.tcp__sack import SackScoreboard
from pytcp.protocols.tcp.tcp__seq import Seq32, add32, ge32, gt32, in_range32, le32, lt32, sub32

if TYPE_CHECKING:
    from threading import Event, Lock, RLock, Semaphore

    from pytcp.socket.tcp__metadata import TcpMetadata
    from pytcp.socket.tcp__socket import TcpSocket


# Name of the per-session 'tx_pump' FSM-pump logical timer
# (§5.6/§5.7). The §4.3 scope matrix mapping FSM-state to the
# set of logical timers that may wake the session lives on the
# service module 'session/tcp__session__timers.py' alongside
# the '_reschedule_locked' helper that consumes it.
_PUMP: str = "tx_pump"


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

        # TX-side buffer state (raw byte buffer, seq-anchor for
        # buffer-index ↔ sequence-number mapping, fast-retransmit
        # dup-ACK request counter). See 'state/tcp__state__tx_buffer.py'.
        self._tx: TxBufferState = TxBufferState()

        # RFC 9293 §3.4 receive-side seq state (IRS / RCV.NXT /
        # RCV.UNA). Anchored at handshake time via
        # 'self._rcv_seq.reset_to(irs=peer_isn)' once peer's SYN
        # is observed. See 'state/tcp__state__recv_seq.py'.
        self._rcv_seq: RecvSeqState = RecvSeqState()

        # IP+TCP header overhead for MSS calculation. RFC 8200's
        # IPv6 fixed header is 40 bytes (vs IPv4's 20); the TCP
        # header is 20 bytes regardless. The MSS is the largest
        # TCP segment that fits in 'interface_mtu' once both
        # headers are subtracted.
        self._ip_tcp_overhead: int = (40 if isinstance(local_ip_address, Ip6Address) else 20) + 20

        # RFC 9293 §3.7.1 / RFC 7323 §2.3 / RFC 9293 §3.8.4 /
        # RFC 5961 §5 window state container (snd_mss, snd_wnd,
        # snd_wsc, max_window, rcv_mss, rcv_wsc, rcv_wnd_max).
        # See 'state/tcp__state__window.py'.
        self._win: WindowState = WindowState()
        self._win.rcv_mss = self._egress_interface_mtu() - self._ip_tcp_overhead

        # RFC 4821 / RFC 8899 per-session PLPMTUD adapter.
        # Wraps a PmtuSearch engine bound to the remote
        # address's family floor and tracks in-flight probe
        # segments for ACK / loss detection. Lazily mirrors
        # into 'stack.pmtu_state' on first classical PMTU
        # signal (via '_apply_pmtu_update') so per-destination
        # state is shared across sessions to the same peer.
        self._plpmtud_adapter: TcpPlpmtudAdapter = TcpPlpmtudAdapter(
            remote_ip_address=remote_ip_address,
            interface_mtu=self._egress_interface_mtu(),
        )
        # Linux 'tcp_mtu_probing' sysctl equivalent. Default
        # OFF matching Linux's tcp_mtu_probing=0 — operators
        # opt in by flipping this flag. When enabled, the
        # probe-emit hook in '_transmit_data' polls the
        # adapter on each transmission and emits a probe-
        # sized segment when the engine has a candidate
        # larger than the current snd_mss. Linux's
        # intermediate value 1 ("enable after RTO loss
        # suspected to be black-hole") is not yet modeled;
        # PyTCP treats this as a hard on/off boolean.
        self._plpmtud_probing_enabled: bool = False

        # Whether to advertise WSCALE on this session's outbound
        # SYN / SYN+ACK. Defaults True (the modern, throughput-
        # friendly behaviour); test code or constrained-buffer
        # profiles can opt out by setting False before CONNECT
        # / LISTEN. When False, the bilateral-non-offer rule
        # forces '_rcv_wsc = 0' on handshake completion so the
        # post-handshake outbound 'win' is not shifted either.
        # Per-session option-advertise + SACK-active state.
        # Defaults: all 'advertise_*' flags True (modern,
        # throughput-friendly), 'send_sack' False until
        # handshake bilaterally negotiates SACK-Permitted. See
        # 'state/tcp__state__advertise.py' for per-field rationale.
        self._advertise: AdvertiseState = AdvertiseState()
        # RFC 7323 §2 / §4.3 / §5.5 Timestamps state (send_ts
        # bilateral-success flag, ts_recent peer-TSval tracker,
        # ts_recent_updated_at_ms staleness clock). See
        # 'state/tcp__state__timestamps.py'.
        self._ts: TimestampsState = TimestampsState()

        # RFC 9293 §3.8.4 / RFC 1122 §4.2.3.6 keep-alive state
        # (enabled flag, unanswered-probe counter, three
        # setsockopt-equivalent override knobs, lazy-arm gate).
        # See 'state/tcp__state__keepalive.py' for the full
        # per-field rationale. Defaults to disabled per the
        # RFC's MUST.
        self._keepalive: KeepaliveState = KeepaliveState()

        # SACK scoreboard tracking peer-SACKed-but-not-yet-
        # cumulatively-acked send-side ranges per RFC 2018 §3 /
        # RFC 6675 §3. Updated by '_ingest_sack_info' on every
        # ACK that carries a SACK option (gated on
        # '_send_sack'); pruned by '_prune_sack_scoreboard'
        # when SND.UNA advances. Phase 5 will consult it via
        # 'pytcp.protocols.tcp.tcp__loss_recovery' for NextSeg / IsLost /
        # Pipe.
        self._sack_scoreboard: SackScoreboard = SackScoreboard()

        # Per-session congestion-control variables (cwnd, ssthresh,
        # snd_ewn, recovery_point, recover_seq, PRR counters, F-RTO
        # snapshot, CUBIC curve, HyStart++ state). Lives as one
        # coherent object on 'tcp__state__cc.py'. Primary CC fields
        # (cwnd / snd_ewn) are initialised below once 'snd_mss' is
        # known; everything else uses the dataclass's RFC-anchored
        # defaults.
        self._cc: CcState = CcState()

        # RFC 7413 per-session TFO state (cookie pending emission,
        # PendingFastOpenRequests counter flag, SYN-retransmit
        # bypass sentinel). Stack-wide TFO state lives on
        # 'pytcp.stack.tcp_stack' (TcpStack). See
        # 'state/tcp__state__fastopen.py'.
        self._fastopen: FastOpenState = FastOpenState()

        # RFC 7413 §3.1 Fast Open client-side opt-out flag.
        # The fastopen, ecn, accecn advertise flags live on
        # self._advertise (AdvertiseState) above.

        # RFC 3168 classic ECN per-session state (enabled flag,
        # send_ece receiver-echo, send_cwr sender-confirmation,
        # recovery_point one-shot gate). Mutually exclusive with
        # 'self._accecn.enabled' per RFC 9768 §3.1.1. See
        # 'state/tcp__state__ecn_classic.py' for per-field rationale.
        self._ecn: ClassicEcnState = ClassicEcnState()

        # RFC 9768 AccECN per-session state (negotiation flag,
        # codepoint capture, receiver/sender byte counters, ACE
        # encoding state, last-emit tracker, mangling sentinel).
        # Defaults are RFC-anchored on the dataclass — see
        # 'tcp__state__accecn.py' for the full per-field rationale.
        self._accecn: AccEcnState = AccEcnState()

        # F-RTO state, CUBIC F-RTO snapshot, and the FR-CUBIC
        # snapshot all live on 'self._cc' (CcState).
        # Defaults are RFC-anchored on the dataclass; no per-field
        # init needed here.

        # Classic ECN sender + receiver state moved to
        # 'self._ecn' (ClassicEcnState) above.

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

        # RFC 8985 RACK + TLP per-session state (per-segment
        # scoreboard, RACK scalars, fold-tracker set, reorder-
        # window state, DSACK round marker, TLP arming state).
        # Defaults are RFC-anchored on the dataclass — see
        # 'tcp__state__rack_tlp.py' for the full per-field
        # rationale.
        self._rack_tlp: RackTlpState = RackTlpState()

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
        # RFC 6298 §4 single-pending RTT-sample tracker plus the
        # §5.7 idle-baseline 'last_send_time_ms'. See
        # 'state/tcp__state__rtt_sample.py'.
        self._rtt: RttSampleState = RttSampleState()
        self._retransmit_count: int = 0
        # RFC 6298 §5.7 second-clause SYN-retransmit counter.
        # Decoupled from '_retransmit_count' (which
        # '_process_ack_packet' resets on cum-ACK progress per
        # §5.2 / §5.3) so the post-handshake §5.7 floor check
        # is order-independent: the count survives the
        # SND.UNA-advancing handshake-completing ACK and is
        # observable from the ESTABLISHED-transition sites in
        # both '_tcp_fsm_syn_sent' (active open) and
        # '_tcp_fsm_syn_rcvd' (passive / simultaneous open).
        # Incremented in '_retransmit_packet_timeout' iff the
        # session is currently in {SYN_SENT, SYN_RCVD}.
        self._syn_retransmit_count: int = 0
        # 'last_send_time_ms' moved onto self._rtt above.

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
        # RFC 9293 §3.4 send-side seq state (ISS / SND.UNA /
        # SND.NXT / SND.MAX) plus RFC 9293 §3.10.7.4 FIN seq +
        # 'fin_sent' gate plus the RFC 1122 §4.2.3.4 Nagle/Minshall
        # partial-segment seq. Anchored to the freshly-computed
        # ISS via 'reset_to'; see 'state/tcp__state__send_seq.py'
        # for the full per-field rationale.
        iss = compute_iss(
            local_address=local_ip_address,
            local_port=local_port,
            remote_address=remote_ip_address,
            remote_port=remote_port,
            secret=stack.TCP__ISS_SECRET,
            clock_us=time.monotonic_ns() // 1000,
        )
        self._snd_seq: SendSeqState = SendSeqState()
        self._snd_seq.reset_to(iss=iss)

        # 'True' once any segment has been processed from peer
        # (peer's SYN in the passive-open path, peer's SYN+ACK
        # in the active-open path). Gates the R2-abort RST
        # emission so an aborting session that DID hear from
        # peer signals the abort even when 'RCV.NXT' happens to
        # equal 0 (which it does when peer's ISN was exactly
        # 0xFFFF_FFFF and 'add32(peer_isn, 1)' wraps). Without
        # the explicit flag, the previous 'self._rcv_seq.nxt > 0'
        # gate would suppress the RST whenever peer's ISN hit
        # the wrap-point sentinel - probability 2**-32 but a
        # real correctness gap.
        self._peer_contacted: bool = False

        # Conservative-start defaults for snd_wnd / max_window:
        # one SMSS (not 0, not 65535) so the first segment can
        # fire before peer's ACK reveals the real window size.
        # Updated by '_process_ack_packet' on every accepted ACK.
        self._win.snd_wnd = self._win.snd_mss
        self._win.max_window = self._win.snd_mss

        # Initialise the RFC 5681 cwnd and 'snd_ewn' from
        # 'win.snd_mss' now that the MSS is known. 'ssthresh'
        # keeps the dataclass default. See 'state/tcp__state__cc.py'.
        self._cc.cwnd = self._win.snd_mss
        self._cc.snd_ewn = self._win.snd_mss

        # CUBIC curve state ('cubic_w_max', 'cubic_K_ms', etc.) and
        # 'cc_mode' live on 'self._cc'. Override the algorithm per
        # connection via 'setsockopt(IPPROTO_TCP, TCP_CONGESTION,
        # CcMode.RENO.value)'; the dataclass default mirrors
        # Linux's CUBIC-since-2.6.18.

        # 'snd_wsc' lives on self._win and defaults to 0 there
        # (the canonical "initial SYN / SYN+ACK don't use WSCALE"
        # value). Set to peer's WSCALE value at handshake by
        # the FSM SYN_SENT / SYN_RCVD entries.

        # Nagle/Minshall partial-segment seq lives on the SendSeqState
        # dataclass; reset_to(iss=...) above already anchored it.

        # RFC 1122 §4.2.3.4 Nagle disable. When True, the
        # Nagle defer in '_transmit_data' is skipped and
        # partial segments fire immediately. Settable via the
        # BSD socket API:
        # 'setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)'. Default
        # False (Nagle enabled per RFC 1122 SHOULD).
        self._tcp_nodelay: bool = False

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
        self._persist: PersistState = PersistState()
        self._persist.timeout = tcp__constants.PACKET_RETRANSMIT_TIMEOUT

        # Number of in-order data segments received since we last transmitted
        # an ACK. Tracks the RFC 1122 §4.2.3.2 "ACK every other segment"
        # rule: when this reaches 2 we force an inline ACK rather than
        # waiting for the delayed-ACK timer to fire.
        self._delayed_ack_segments_pending: int = 0

        # BSD-socket half-close flags per RFC 9293 §3.9.1 + POSIX
        # 'shutdown()'. '_shut_rd' silently discards subsequent
        # inbound data and makes 'recv()' return 0 once the buffer
        # drains. '_shut_wr' triggers FIN emission (same effect as
        # 'close()' on the write side) but leaves '_shut_rd'
        # untouched so the receive side stays open.
        self._shut: ShutdownState = ShutdownState()

        ###
        # Other variables.
        ###

        # tx_retransmit_request_counter and tx_buffer_seq_mod
        # both moved onto self._tx (TxBufferState) above. Anchor
        # the seq_mod baseline at the freshly-computed ISS.
        self._tx.seq_mod = self._snd_seq.ini

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

        # Per-session timer service — owns the logical-timer
        # deadline map ('_deadlines') and the coalesced service
        # handle ('_service_handle') plus the dedicated lock
        # ('_lock') that guards both. The FSM timer is
        # event-driven — there is no 1 ms periodic. The coalesced
        # service handle (armed by 'TcpTimerService._reschedule_locked'
        # from every public mutator and from the 'tcp_fsm' tail
        # via 'self._timers.reschedule()') drives both
        # logical-timer servicing and the 'tx_pump' FSM-pump
        # (§5.6/§5.7). Closes the no-GIL backlog item T2: the
        # deadline-map mutations no longer ride the FSM lock.
        # Lock ordering for the rest of the session is
        # '_lock__fsm' -> '_timers._lock' -> 'stack.timer._lock';
        # the timer-worker callback re-enters 'tcp_fsm' lock-free.
        self._timers: TcpTimerService = TcpTimerService(self)

        # Per-session TX engine — owns the outbound-segment
        # construction pipeline ('_transmit_packet' + the six
        # '_phase0..5' helpers), the buffered-data send pump
        # ('_transmit_data'), the delayed-ACK emit
        # ('_delayed_ack'), the SACK option builder
        # ('_build_sack_blocks'), and the RFC 5961
        # rate-limited challenge-ACK emit
        # ('_emit_challenge_ack'). Phase 2 of the TcpSession
        # god-class decomposition.
        self._tx_engine: TcpTxEngine = TcpTxEngine(self)

    def _egress_interface_mtu(self) -> int:
        """
        Return the link MTU of the interface that egresses toward this
        session's remote — the per-destination input to MSS computation
        (RFC 6691 §2). Falls back to the default link MTU when no egress
        can be resolved (a reduced context with no interface registered),
        preserving the value the retired 'stack.interface_mtu' global held.
        """

        return stack.egress_interface_mtu(self._remote_ip_address) or stack.INTERFACE__TAP__MTU

    def _arm_timer(self, name: str, delay_ms: int, /) -> None:
        """
        Arm or re-arm the named logical timer to fire 'delay_ms'
        milliseconds from now. Thin delegator over
        'TcpTimerService.arm' — the deadline-map mutation +
        coalesced-service reschedule are serialized under the
        service's own '_lock'.
        """

        self._timers.arm(name, delay_ms)

    def _timer_expired(self, name: str, /) -> bool:
        """
        Return True iff the named logical timer is armed and its
        deadline has passed. An unarmed timer is NOT expired:
        'never armed' and 'fired' are distinct states (see
        '_timer_armed' for the complementary 'still running?'
        query).
        """

        return self._timers.expired(name)

    def _timer_armed(self, name: str, /) -> bool:
        """
        Return True iff the named logical timer is armed and has
        not yet fired (the 'is it still running?' query).
        """

        return self._timers.armed(name)

    def _cancel_timer(self, name: str, /) -> None:
        """
        Cancel the named logical timer if armed. Thin delegator
        over 'TcpTimerService.cancel'.
        """

        self._timers.cancel(name)

    def _cancel_all_timers(self) -> None:
        """
        Cancel every logical timer for this session and release
        the coalesced service handle. The session-teardown sweep
        that drops all of this session's armed timers in one call.
        Thin delegator over 'TcpTimerService.cancel_all'.
        """

        self._timers.cancel_all()

    def _reschedule_service(self) -> None:
        """
        Re-arm the coalesced per-session service handle to the
        soonest deadline among the logical timers serviced in
        the current state. Thin delegator over
        'TcpTimerService.reschedule' — kept on the session as a
        named hook for the rare external caller that needs to
        re-poke the schedule after an out-of-band state change.
        """

        self._timers.reschedule()

    def _has_pump_work(self) -> bool:
        """
        True while the FSM still needs the 1 ms pacing pump:
        unsent buffered data ('_transmit_data' dribbles one
        segment per tick), in-flight data (FIN/retransmit
        progression), or a pending close. When none hold — and
        no logical timer is armed — the session is genuinely
        idle and the pump stops (zero-idle-CPU). delayed-ACK /
        keep-alive / RACK / TLP / persist / TIME_WAIT need no
        entry here: each is a logical timer the coalesced
        '_service_handle' already drives.
        """

        return bool(self._tx.buffer) or self._snd_seq.una != self._snd_seq.max or self._closing

    def _pump_tail(self, state_at_entry: FsmState, external: bool, /) -> None:
        """
        Re-arm the 'tx_pump' FSM-pump (1 ms) at the 'tcp_fsm'
        tail while the FSM still needs ticking. The old 1 ms
        periodic was not merely an event-wake — it was a
        continuous send-pacing clock: '_transmit_data' emits one
        segment per tick, so a multi-segment send needs a tick
        per segment until the buffer drains. Re-pump iff this
        dispatch was an external stimulus (packet / syscall /
        ICMP), changed state, OR there is still pending pacing
        work ('_has_pump_work'). A fully quiescent TIMER
        dispatch (no state change, not external, no pump work)
        does NOT re-pump → zero-idle-CPU. The 1 ms delay (plus
        the 1 ms floor in '_reschedule_service') reproduces the
        periodic's exactly-one-tick-per-millisecond cadence, so
        active transfer is byte-identical. CLOSED is terminal —
        never re-pumped.
        """

        self._cancel_timer(_PUMP)
        if self._state is FsmState.CLOSED:
            return
        if external or self._state is not state_at_entry or self._has_pump_work():
            self._arm_timer(_PUMP, 1)

    def _kick_pump(self) -> None:
        """
        Arm the 'tx_pump' FSM-pump from a NON-'tcp_fsm' mutator
        (§5.7). 'TcpSession.send()' extends the TX buffer
        without routing through 'tcp_fsm', so '_pump_tail' never
        runs to pick up the buffered data; the old 1 ms periodic
        masked this by ticking unconditionally. Audit (Phase 4c,
        confirmed by the Phase-4b full-suite run whose only
        residual was send()-path): the sole non-'tcp_fsm'
        FSM-progression mutator is 'send()'; listen / connect /
        close / shutdown route through 'tcp_fsm', and receive /
        abort need no pump. No-op once CLOSED. Takes the
        'TcpTimerService' lock via '_arm_timer' (the deadline
        map's dedicated guard); the '_state' read is a single
        attribute read whose worst-case outcome on a torn
        transition is one extra pump tick that no-ops in the
        CLOSED branch of the next FSM dispatch — benign.
        """

        if self._state is not FsmState.CLOSED:
            self._arm_timer(_PUMP, 1)

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

        return max(0, self._win.rcv_wnd_max - len(self._rx_buffer))

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

        return (self._snd_seq.nxt - self._tx.seq_mod) & 0xFFFF_FFFF

    @property
    def _tx_buffer_una(self) -> int:
        """
        Get the 'snd_una' number relative to TX buffer.
        """

        return (self._snd_seq.una - self._tx.seq_mod) & 0xFFFF_FFFF

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
        if self._closing or self._shut.wr:
            raise TcpSessionError("TCP session is closing")

        if self._state in {FsmState.ESTABLISHED, FsmState.CLOSE_WAIT}:
            with self._lock__tx_buffer:
                self._tx.buffer.extend(data)
            # Kick the FSM pump OUTSIDE '_lock__tx_buffer' (the
            # 'tcp_fsm' lock order is _lock__fsm -> _lock__tx_buffer;
            # taking _lock__fsm while holding _lock__tx_buffer here
            # would invert it and deadlock).
            self._kick_pump()
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
                # Drain the eventfd backing 'socket.fileno()' so the
                # next selector tick stops firing once the buffer is
                # empty. CLOSE_WAIT / CLOSED are deliberately
                # excluded so peer-FIN EOF stays select-readable as
                # a 0-byte recv() until the application closes its
                # half (matches BSD select-on-read-EOF semantics).
                self._socket._drain_readable()

        return bytes(rx_buffer)

    def close(self) -> None:
        """
        The 'CLOSE' syscall.
        """

        __debug__ and log(
            "tcp-ss",
            f"[{self}] - <ly>[{self._state}]</> - got <r>CLOSE</> syscall, {len(self._tx.buffer)} bytes in TX buffer",
        )

        self.tcp_fsm(syscall=SysCall.CLOSE)

    def shutdown(self, *, how: int) -> None:
        """
        BSD 'shutdown(how)' half-close per RFC 9293 §3.9.1
        + POSIX shutdown semantics.

        'how' values (matching pytcp.socket.SHUT_*):
            SHUT_RD   (0): no further reads. Inbound data is
                           silently discarded; recv() returns 0
                           after the buffer drains.
            SHUT_WR   (1): no further writes. Drains the TX
                           buffer and emits FIN (same effect as
                           close() on the write side); the read
                           side stays open until peer's FIN.
            SHUT_RDWR (2): both. Equivalent to close().

        Idempotent: shutdown() on a direction already shut is a
        no-op. Setting SHUT_WR on an already-closing session
        does NOT re-emit FIN.
        """

        assert how in (0, 1, 2), f"shutdown 'how' must be in {{SHUT_RD, SHUT_WR, SHUT_RDWR}}; got {how}."

        # SHUT_RD or SHUT_RDWR: discard subsequent inbound data
        # and unblock any pending recv() with end-of-stream.
        if how in (0, 2):
            if not self._shut.rd:
                self._shut.rd = True
                # Wake any blocked recv() so it observes the
                # shutdown and returns 0 (the FSM check + empty
                # buffer makes recv() yield empty bytes).
                self._event__rx_buffer.set()
                self._socket._signal_readable()
                __debug__ and log("tcp-ss", f"[{self}] - shutdown(SHUT_RD): receive side closed")

        # SHUT_WR or SHUT_RDWR: trigger FIN emission via the
        # existing close() machinery if not already closing.
        if how in (1, 2):
            if not self._shut.wr and not self._closing:
                self._shut.wr = True
                self.tcp_fsm(syscall=SysCall.CLOSE)
                __debug__ and log("tcp-ss", f"[{self}] - shutdown(SHUT_WR): send side closed")

    def abort(self) -> None:
        """
        The 'ABORT' syscall per RFC 9293 §3.9.1.

        Aborts the connection without graceful close: any pending
        SENDs are discarded, blocked RECEIVEs are released with
        an error, and a RST is emitted for synchronized states
        (SYN_RCVD, ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2,
        CLOSE_WAIT). For unsynchronized states (CLOSED, LISTEN,
        SYN_SENT) and the post-close states (CLOSING, LAST_ACK,
        TIME_WAIT), the TCB is simply torn down without a wire-
        level RST per RFC 9293 §3.9.1's per-state ABORT spec.

        After abort() the session transitions to CLOSED and any
        blocked CONNECT / RECEIVE callers unblock with a connection
        error.
        """

        __debug__ and log(
            "tcp-ss",
            f"[{self}] - <ly>[{self._state}]</> - got <r>ABORT</> syscall",
        )

        if self._state in {
            FsmState.SYN_RCVD,
            FsmState.ESTABLISHED,
            FsmState.FIN_WAIT_1,
            FsmState.FIN_WAIT_2,
            FsmState.CLOSE_WAIT,
        }:
            # RFC 9293 §3.9.1 ABORT in synchronized states: emit
            # RST + ACK at SND.NXT, RCV.NXT.
            self._transmit_packet(flag_rst=True, flag_ack=True, seq=self._snd_seq.nxt)
        # Mark connection as aborted so any blocked recv() raises.
        self._connection_error = ConnError.CANCELED
        self._event__rx_buffer.set()
        self._socket._signal_readable()
        self._event__connect.release()
        self._change_state(FsmState.CLOSED)

    def is_seq_in_window(self, seq: int) -> bool:
        """
        Return True when 'seq' falls in the SND.UNA..SND.NXT range —
        the RFC 5927 §4 acceptability check for an ICMP error
        targeting an embedded TCP segment. ICMP RX handlers call this
        before notifying the session so an off-path attacker cannot
        forge an error for an arbitrary 4-tuple.

        For unsynchronized states (no SND.NXT yet) the check accepts
        anything since no flight is outstanding to validate against.

        Reference: RFC 5927 §4 (ICMP attacks against TCP).
        """

        if self._snd_seq.nxt == 0 and self._snd_seq.una == 0:
            return True

        # Modular comparison via Seq32 wrap-aware arithmetic.
        if self._snd_seq.una <= self._snd_seq.nxt:
            return self._snd_seq.una <= seq <= self._snd_seq.nxt
        return seq >= self._snd_seq.una or seq <= self._snd_seq.nxt

    def _apply_pmtu_update(self, *, next_hop_mtu: int, ip_version: int) -> None:
        """
        Apply an inbound ICMP Path-MTU update to this session.
        Records the next-hop MTU into 'stack.pmtu_cache' for the
        remote address and recomputes 'self._win.snd_mss' from the
        new MTU minus IP+TCP fixed overhead. Called from the
        per-state ICMP handlers ('fsm__syn_sent__icmp' and
        'fsm__icmp__synchronized') for PMTU-category events.

        Implements the optional RFC 1191 §6.5 retransmit walkback:
        when the snd_mss shrink leaves in-flight segments oversized
        for the new path MTU, mark all in-flight segments lost and
        rewind 'snd_nxt' to 'snd_una' so the next timer tick re-emits
        from snd_una at the new (smaller) MSS rather than waiting for
        RTO. Unlike RTO, the walkback does NOT halve cwnd / ssthresh
        and does NOT bump '_retransmit_count' or back off RTO — the
        path narrowed but did not congest, so this is not a loss event.

        Reference: RFC 1191 §6 (PMTUD on the host).
        Reference: RFC 1191 §6.5 (PMTU shrink retransmit walkback).
        Reference: RFC 8201 §4 (IPv6 PMTUD MTU update rule).
        Reference: RFC 9293 §3.7.5 (MSS option update on path-MTU change).
        """

        # Fixed-overhead floor: IPv4 = 20, IPv6 = 40; TCP = 20.
        ip_overhead = 20 if ip_version == 4 else 40
        new_mss = max(next_hop_mtu - ip_overhead - 20, 0)
        # RFC 1191 §6.4 / RFC 791 §3.1 MIN_MTU floor: never let MSS
        # drop below 536 / 1280 on v4 / v6 respectively. The remote
        # peer's MSS option from the handshake is also a ceiling, so
        # only shrink, never grow.
        floor = 536 - 20 if ip_version == 4 else 1280 - 40 - 20
        new_mss = max(new_mss, floor)
        shrunk = new_mss < self._win.snd_mss
        if shrunk:
            self._win.snd_mss = new_mss

        stack.record_classical_pmtu(self._remote_ip_address, next_hop_mtu)

        # Route the classical PMTU signal through the per-session
        # PLPMTUD adapter (which dispatches to the engine), then
        # mirror the engine into the shared 'stack.pmtu_state'
        # registry so siblings to the same destination see the
        # same state.
        now = time.monotonic()
        self._plpmtud_adapter.on_classical_pmtu(next_hop_mtu, now=now)
        stack.record_pmtu_engine(self._remote_ip_address, self._plpmtud_adapter.engine)

        # RFC 1191 §6.5 walkback. Only fire when (a) the MSS actually
        # shrunk and (b) at least one in-flight segment is oversized
        # for the new MSS — single small segments that already fit
        # don't need walking back.
        if shrunk and any(
            (seg.end_seq - seq) & 0xFFFF_FFFF > new_mss for seq, seg in self._rack_tlp.rack_segments.items()
        ):
            from pytcp.protocols.tcp.tcp__rack import INFINITE_TS

            self._rack_tlp.rack_segments = {
                seq: RackSegment(
                    end_seq=seg.end_seq,
                    xmit_ts=INFINITE_TS,
                    retransmitted=seg.retransmitted,
                    lost=True,
                )
                for seq, seg in self._rack_tlp.rack_segments.items()
            }
            self._snd_seq.nxt = self._snd_seq.una
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - <ly>RFC 1191 §6.5 walkback: snd_mss -> "
                f"{new_mss}, snd_nxt rewound to snd_una "
                f"({self._snd_seq.una})</>",
            )

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
            self._cc.recovery_point = 0
            # RFC 6937 §3.1 PRR per-recovery state lives only
            # while a recovery episode is active in ESTABLISHED.
            # Clear alongside RecoveryPoint so half-close and
            # subsequent re-entries start clean.
            self._cc.recover_fs = 0
            self._cc.prr_delivered = 0
            self._cc.prr_out = 0

        # RFC 7413 §3.1 Fast Open server-side cookie state is
        # only meaningful while the session is in SYN_RCVD
        # awaiting the third-leg ACK. Once the handshake
        # completes (ESTABLISHED) or the session aborts (any
        # other terminal state), no further SYN+ACK will
        # fire so the cookie is no longer needed. Clear on
        # any transition out of SYN_RCVD.
        if old_state is FsmState.SYN_RCVD and state is not FsmState.SYN_RCVD:
            self._fastopen.cookie_to_emit = None
            # RFC 7413 §4.2: decrement the global pending-TFO
            # counter when this session leaves SYN_RCVD (either
            # the handshake completes -> ESTABLISHED, or it
            # aborts -> CLOSED). The '_fastopen_pending_counted'
            # guard ensures we only decrement for sessions that
            # were actually counted at TFO acceptance time.
            if self._fastopen.pending_counted:
                stack.tcp_stack.decr_fastopen_pending()
                self._fastopen.pending_counted = False

        # Unregister session.
        if self._state is FsmState.CLOSED:
            stack.sockets.pop(self._socket.socket_id)
            # Cancel every per-session logical timer and release
            # the coalesced service handle so nothing fires
            # against a dead session and it is GC-eligible (the
            # event-driven model has no periodic to unregister).
            self._cancel_all_timers()
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
        Send out the TCP packet. Thin delegator over
        'TcpTxEngine.transmit_packet' — the segment-construction
        pipeline (the six phase helpers) lives on the TX engine.
        """

        self._tx_engine.transmit_packet(
            seq=seq,
            flag_syn=flag_syn,
            flag_ack=flag_ack,
            flag_fin=flag_fin,
            flag_rst=flag_rst,
            flag_psh=flag_psh,
            data=data,
        )

    def _build_sack_blocks(self) -> list[tuple[int, int]]:
        """
        Compute the SACK option block list for the next outbound
        ACK. Thin delegator over 'TcpTxEngine.build_sack_blocks'.
        """

        return self._tx_engine.build_sack_blocks()

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
                acceptable = in_range32(
                    packet_rx_md.tcp__seq, self._rcv_seq.nxt, add32(self._rcv_seq.nxt, self._rcv_wnd)
                )
            else:
                acceptable = packet_rx_md.tcp__seq == self._rcv_seq.nxt
        else:
            if self._rcv_wnd > 0:
                acceptable = lt32(packet_rx_md.tcp__seq, add32(self._rcv_seq.nxt, self._rcv_wnd)) and gt32(
                    seg_end, self._rcv_seq.nxt
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
            self._advertise.send_sack
            and len(packet_rx_md.tcp__data) > 0
            and lt32(packet_rx_md.tcp__seq, self._rcv_seq.nxt)
            and le32(seg_end, self._rcv_seq.nxt)
        ):
            self._pending_dsack = (packet_rx_md.tcp__seq, seg_end)
        # RFC 9293 §3.10.7.4 step 1: ACK the unacceptable
        # segment so peer's retransmit machinery sees fresh
        # activity and can stop retransmitting. Rate-limited
        # per RFC 5961 §3 so a burst of unacceptable segments
        # cannot amplify into an outbound ACK flood.
        self._emit_challenge_ack()
        return False

    def _check_paws_and_update_ts_recent(self, packet_rx_md: TcpMetadata) -> bool:
        """
        RFC 7323 §5 PAWS + §4.3 '_ts_recent' refresh as a
        single helper invoked at every inbound dispatch
        boundary. Returns True when the segment passes PAWS
        (caller may continue normal processing) and False
        when the segment must be silently dropped per §5.4.

        Side effect: on a non-stale segment carrying TSopt,
        '_ts_recent' is refreshed to the segment's TSval.

        Bilateral-success-gated: returns True (and skips both
        the PAWS check and the '_ts_recent' update) when
        '_send_ts' is False or the inbound segment carries no
        TSopt. Legacy non-TSopt peers fall through unchanged.

        Modular comparison via 'lt32' so the check is correct
        across the 32-bit TSval clock wrap (24 days at 1 ms
        granularity).
        """

        if not self._ts.send_ts:
            return True
        # RFC 7323 §3.2: "If a non-<RST> segment is received
        # without a TSopt, a TCP SHOULD silently drop the
        # segment." The SHOULD applies to in-stream segments;
        # SYN-bearing segments are exempt because they may
        # legitimately re-initiate (RFC 6191 §3 4-tuple reuse,
        # RFC 9293 §3.10.7.4 SYN-in-synchronized challenge-ACK
        # path) and the per-segment TSopt expectation has not
        # yet been re-established for the new incarnation.
        if packet_rx_md.tcp__tsval is None:
            if packet_rx_md.tcp__flag_syn:
                return True
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - PAWS: silently dropping segment "
                "missing TSopt on TS-negotiated session "
                "(RFC 7323 §3.2 SHOULD)",
            )
            return False
        # RFC 7323 §4.3 rule (2) Last.ACK.sent gate: TS.Recent
        # is only refreshed when SEG.SEQ <= Last.ACK.sent so an
        # OOO segment cannot inflate TS.Recent and corrupt the
        # TSecr echoed back to the peer's RTT estimator. Last.
        # ACK.sent equals RCV.NXT at the moment of our last
        # outbound ACK and is monotone non-decreasing; using
        # the current RCV.NXT as the upper bound is a tightening
        # safe approximation (it can only suppress refreshes
        # that the strict algorithm would also suppress, never
        # the reverse). SYN-bearing segments are exempt: they
        # establish (or, on RFC 6191 §3 reuse, re-establish)
        # the connection's TS.Recent and the §4.3 algorithm
        # assumes a stable seq-space relationship that has not
        # yet been negotiated for the new incarnation.
        ts_recent_refresh_gate_ok = packet_rx_md.tcp__flag_syn or le32(packet_rx_md.tcp__seq, self._rcv_seq.nxt)
        if lt32(packet_rx_md.tcp__tsval, self._ts.ts_recent):
            # RFC 7323 §5.5 outdated-timestamps mitigation:
            # if the connection has been idle longer than the
            # 24-day threshold, 'TS.Recent' MUST be treated as
            # invalidated and the segment accepted (rule R3
            # then refreshes TS.Recent with the segment's
            # TSval). Without this gate, a recovered idle
            # connection past the 24-day mark would freeze
            # because every subsequent segment's TSval would
            # appear stale until the peer's TS clock wrapped
            # its sign bit. The check requires a non-zero
            # last-update timestamp so freshly-handshaked
            # sessions (initialised to 0) cannot trigger
            # the mitigation spuriously.
            if (
                self._ts.ts_recent_updated_at_ms != 0
                and stack.timer.now_ms - self._ts.ts_recent_updated_at_ms
                > tcp__constants.TS_RECENT_OUTDATED_THRESHOLD_MS
            ):
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - PAWS: TS.Recent outdated past "
                    f"{tcp__constants.TS_RECENT_OUTDATED_THRESHOLD_MS} ms idle threshold, "
                    "accepting segment per RFC 7323 §5.5 mitigation "
                    f"(tsval={packet_rx_md.tcp__tsval}, "
                    f"_ts_recent={self._ts.ts_recent})",
                )
                self._ts.update(tsval=packet_rx_md.tcp__tsval, now_ms=stack.timer.now_ms)
                return True
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - PAWS: dropping stale-TSval segment "
                f"(tsval={packet_rx_md.tcp__tsval} < _ts_recent="
                f"{self._ts.ts_recent})",
            )
            # RFC 7323 §5.3 R1: "Send an acknowledgment in
            # reply" on the PAWS-stale drop so the peer can
            # recover its sender state without waiting for its
            # own RTO. Reuses the rate-limited challenge-ACK
            # emit which is the canonical "ACK at SND.NXT,
            # RCV.NXT" wire shape.
            self._emit_challenge_ack()
            return False
        if ts_recent_refresh_gate_ok:
            self._ts.update(tsval=packet_rx_md.tcp__tsval, now_ms=stack.timer.now_ms)
        return True

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
            packet_rx_md.tcp__ack, self._snd_seq.una, self._snd_seq.max
        )
        if seq == self._rcv_seq.nxt and ack_acceptable:
            return True
        if lt32(self._rcv_seq.nxt, seq) and lt32(seq, add32(self._rcv_seq.nxt, self._rcv_wnd)):
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - In-window mismatched RST (seq={seq}, RCV.NXT={self._rcv_seq.nxt}); challenge-ACK",
            )
            self._emit_challenge_ack()
        return False

    def _reinit_for_rfc6191_reuse(self, packet_rx_md: TcpMetadata) -> None:
        """
        RFC 6191 §3 TIME-WAIT 4-tuple reuse: re-initialise
        this session's runtime state in place so a fresh
        three-way handshake can proceed against peer's new
        SYN. The 4-tuple is unchanged (RFC 6191 reuse
        applies on the same 4-tuple); the helper resets
        send-side seq state to a fresh ISS, refreshes
        peer-derived parameters (MSS / window / WSCALE /
        SACK / TSopt) from the inbound SYN, clears the
        previous-incarnation buffers and recovery state, and
        cancels every per-session timer the prior incarnation
        may have armed.

        After the helper returns, the caller transitions to
        SYN_RCVD and emits the SYN+ACK. The previously-
        registered 'TIME-WAIT' timer is dropped via the
        prefix-keyed unregister so any other per-session
        timers (delayed-ACK, retransmit, persist, keep-
        alive) are also cleared - they would otherwise fire
        against the stale state of the prior connection.
        """

        # Cancel every per-session logical timer the prior
        # incarnation may have armed (TIME-WAIT, retransmit,
        # delayed-ACK, persist, keep-alive, challenge-ACK).
        self._cancel_all_timers()

        # Fresh ISS for the new incarnation. The 4-tuple is
        # unchanged but the time-driven 'M' clock advance in
        # 'compute_iss' guarantees a different ISS from the
        # previous incarnation, preserving RFC 6528's blind-
        # injection defence across the reuse boundary.
        new_iss = compute_iss(
            local_address=self._local_ip_address,
            local_port=self._local_port,
            remote_address=self._remote_ip_address,
            remote_port=self._remote_port,
            secret=stack.TCP__ISS_SECRET,
            clock_us=time.monotonic_ns() // 1000,
        )
        self._snd_seq.ini = new_iss
        self._snd_seq.una = new_iss
        self._snd_seq.nxt = new_iss
        self._snd_seq.max = new_iss
        self._snd_seq.sml = new_iss
        self._snd_seq.fin = 0
        self._snd_seq.fin_sent = False
        self._tx.seq_mod = new_iss

        # Adopt peer's new SYN parameters. MSS is clamped to the
        # RFC 879 / RFC 6691 bounds; an explicit floor at TCP__MIN_MSS
        # treats peer-advertised 0 (or any malformed sub-floor value)
        # as 'option absent'.
        self._win.snd_mss = max(
            TCP__MIN_MSS,
            min(packet_rx_md.tcp__mss, self._egress_interface_mtu() - self._ip_tcp_overhead),
        )
        self._win.snd_wnd = packet_rx_md.tcp__win
        self._win.max_window = self._win.snd_wnd

        # Re-run the bilateral negotiation against peer's new SYN -
        # WSCALE / SACK / TSopt may all differ between incarnations.
        if self._advertise.wscale and packet_rx_md.tcp__wscale:
            self._win.snd_wsc = packet_rx_md.tcp__wscale
        else:
            self._win.rcv_wsc = 0
            self._win.snd_wsc = 0
        self._advertise.send_sack = self._advertise.sack and packet_rx_md.tcp__sackperm
        self._ts.send_ts = self._advertise.ts and packet_rx_md.tcp__tsval is not None
        # '_ts_recent' was already refreshed to peer's new TSval
        # by the PAWS helper in the FSM handler before this point.

        # RFC 5681 §3.1 + RFC 6928 §2: reset cwnd to the post-handshake
        # IW and ssthresh to the canonical large-constant default. The
        # actual IW assignment happens at the SYN_RCVD -> ESTABLISHED
        # transition; here we set the SYN-RCVD-phase value
        # (one SMSS) so the outbound SYN+ACK is emitted correctly.
        self._cc.cwnd = self._win.snd_mss
        self._cc.ssthresh = 0x7FFF_FFFF
        self._cc.snd_ewn = min(self._cc.cwnd, self._win.snd_wnd)

        # Receive-side state from the new SYN.
        self._rcv_seq.ini = packet_rx_md.tcp__seq
        self._rcv_seq.nxt = add32(
            packet_rx_md.tcp__seq,
            packet_rx_md.tcp__flag_syn,
            len(packet_rx_md.tcp__data),
        )
        self._rcv_seq.una = self._rcv_seq.nxt
        self._peer_contacted = True

        # Reset RFC 6298 RTO estimator + sample tracker so the new
        # incarnation re-establishes its own RTT measurements.
        self._rto_state = initial_state()
        self._retransmit_count = 0
        self._rtt.last_send_time_ms = None
        self._rtt.clear()

        # Clear SACK + DSACK + recovery state from the prior incarnation.
        self._sack_scoreboard = SackScoreboard()
        self._cc.recovery_point = 0
        self._cc.recover_fs = 0
        self._cc.prr_delivered = 0
        self._cc.prr_out = 0
        self._pending_dsack = None
        self._dsack_received = 0

        # Clear OOO queue + buffers (TIME-WAIT should already have
        # them empty, but be defensive against state that an earlier
        # bug or a spurious-FIN-retransmit path may have left).
        self._ooo_packet_queue.clear()
        self._tx.buffer.clear()
        self._rx_buffer.clear()

        # Queue any data the new SYN piggybacked (RFC 9293 §3.10.7.2
        # step 3 permits this; rare but legal).
        if packet_rx_md.tcp__data:
            self._enqueue_rx_buffer(packet_rx_md.tcp__data)

    def _hystart_check_phase_transition(self) -> None:
        """
        Apply the RFC 9406 §4.2 phase-transition checks after
        a fresh RTT sample has been folded into the HyStart++
        state. Two transitions are possible:

          - Slow-start -> CSS: the §4.2 delay-increase trigger
            fires (currentRoundMinRTT exceeds lastRoundMinRTT
            by more than RttThresh) — record the baseline and
            switch to Conservative Slow Start.
          - CSS -> Slow-start: the §4.2 spurious-CSS-exit
            check fires (currentRoundMinRTT drops below the
            CSS-entry baseline) — clear CSS state and resume
            normal slow-start.

        Caller MUST have folded the RTT sample BEFORE calling
        this helper. Called from both the TSecr-driven RTTM
        site and the Karn sample-tracker harvest site.

        Reference: RFC 9406 §4.2 (delay-increase trigger / spurious-exit recovery).
        """

        if should_exit_slow_start_to_css(self._cc.hystart_state):
            enter_css(self._cc.hystart_state)
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - RFC 9406 §4.2 HyStart++ SS->CSS: "
                f"currentRoundMinRTT="
                f"{self._cc.hystart_state.current_round_min_rtt_ms} >= "
                f"lastRoundMinRTT="
                f"{self._cc.hystart_state.last_round_min_rtt_ms} + RttThresh; "
                f"baseline={self._cc.hystart_state.css_baseline_min_rtt_ms}",
            )
        elif should_resume_slow_start_from_css(self._cc.hystart_state):
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - RFC 9406 §4.2 HyStart++ CSS->SS: "
                f"currentRoundMinRTT="
                f"{self._cc.hystart_state.current_round_min_rtt_ms} < "
                f"cssBaselineMinRtt="
                f"{self._cc.hystart_state.css_baseline_min_rtt_ms}; "
                "early CSS exit was spurious, resuming slow-start",
            )
            resume_slow_start(self._cc.hystart_state)

    def _emit_challenge_ack(self) -> None:
        """
        RFC 5961 §3 / §4 rate-limited challenge-ACK emission.
        Thin delegator over 'TcpTxEngine.emit_challenge_ack'.
        """

        self._tx_engine.emit_challenge_ack()

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

        if not self._keepalive.enabled:
            return
        self._keepalive.reset_for_idle()
        self._arm_timer(
            "keepalive",
            self._keepalive.idle_timeout(default=tcp__constants.KEEPALIVE_IDLE_TIME),
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

        if not self._keepalive.enabled:
            return
        if not self._keepalive.active:
            self._keepalive_arm_idle()
            return
        if not self._timer_expired("keepalive"):
            return
        max_count = self._keepalive.max_probes(default=tcp__constants.KEEPALIVE_PROBE_MAX_COUNT)
        if self._keepalive.probes_unacked >= max_count:
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Keep-alive: {self._keepalive.probes_unacked} probes "
                "unacked, tearing down connection (RFC 1122 §4.2.3.6)",
            )
            self._connection_error = ConnError.TIMEOUT
            self._event__connect.release()
            self._event__rx_buffer.set()
            self._socket._signal_readable()
            self._change_state(FsmState.CLOSED)
            return
        stack.egress_packet_handler(self._remote_ip_address).send_tcp_packet(
            ip__local_address=self._local_ip_address,
            ip__remote_address=self._remote_ip_address,
            tcp__local_port=self._local_port,
            tcp__remote_port=self._remote_port,
            tcp__flag_ack=True,
            tcp__seq=sub32(self._snd_seq.nxt, 1),
            tcp__ack=self._rcv_seq.nxt,
            tcp__win=self._rcv_wnd >> self._win.rcv_wsc,
        )
        self._keepalive.probes_unacked += 1
        self._arm_timer(
            "keepalive",
            self._keepalive.interval_timeout(default=tcp__constants.KEEPALIVE_PROBE_INTERVAL),
        )
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - Keep-alive: emitted probe "
            f"{self._keepalive.probes_unacked}/{max_count} "
            f"at seq={sub32(self._snd_seq.nxt, 1)} ack={self._rcv_seq.nxt}",
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

        if not self._advertise.send_sack:
            return

        blocks = list(packet_rx_md.tcp__sack_blocks)
        if not blocks:
            return

        # RFC 2883 DSACK detection on the first block.
        first_left, first_right = blocks[0]
        is_dsack = le32(first_right, self._snd_seq.una)
        if not is_dsack:
            for outer_left, outer_right in blocks[1:]:
                if le32(outer_left, first_left) and le32(first_right, outer_right):
                    is_dsack = True
                    break
        if is_dsack:
            self._dsack_received += 1
            # RFC 9438 §4.9.2 spurious-fast-retransmit restore:
            # a DSACK observed during a recovery episode that
            # had snapshotted CUBIC state at FR entry indicates
            # the retransmit was spurious. Roll back W_max, K,
            # epoch_start, W_est, cwnd, and ssthresh to their
            # pre-FR values so post-FR throughput is not
            # artificially anchored at the reduced W_max.
            if self._cc.cc_mode is CcMode.CUBIC and self._cc.fr_cubic_snapshot_valid and self._cc.recovery_point != 0:
                self._cc.restore_fr_cubic_snapshot()
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - RFC 9438 §4.9.2 spurious-FR "
                    "restore: rolled back CUBIC state on DSACK "
                    f"(cwnd={self._cc.cwnd}, ssthresh={self._cc.ssthresh}, "
                    f"W_max={self._cc.cubic_w_max})",
                )
            # RFC 8985 §6.2 step 4 DSACK-round handling. A
            # DSACK observed outside recovery indicates a
            # spurious retransmit (the peer received what we
            # thought was lost), so the reo_wnd_mult is
            # incremented to reduce future spurious losses by
            # using a larger reordering tolerance. Only fires
            # ONCE per round - the '_rack_dsack_round' marker
            # holds SND.MAX at the moment of observation; we
            # wait until SND.UNA crosses it before allowing
            # the next increment, so a burst of DSACKs at the
            # same round boundary doesn't multiply the
            # multiplier away.
            if self._cc.recovery_point == 0:
                self._rack_tlp.maybe_close_dsack_round(snd_una=self._snd_seq.una, snd_max=self._snd_seq.max)
            blocks = blocks[1:]

        # RFC 6937 §3.1 SACK delta tracking: when in recovery,
        # the bytes added to the scoreboard by THIS ingestion
        # count as 'DeliveredData' and feed PRR's per-ACK
        # 'sndcnt = ceil(prr_delivered * ssthresh / RecoverFS)
        # - prr_out' formula. Snapshot the scoreboard total
        # before adding the new blocks; the post-add total
        # minus the snapshot is the exact byte delta (the
        # merge invariant guarantees no overlap so the sum is
        # exact). DSACK blocks are excluded above (the slice
        # 'blocks[1:]') so they do not double-count peer's
        # report of bytes we already knew about.
        bytes_before = self._sack_scoreboard.total_sacked_bytes() if self._cc.recovery_point != 0 else 0

        for left, right in blocks:
            if le32(self._snd_seq.una, left) and le32(right, self._snd_seq.max) and lt32(left, right):
                self._sack_scoreboard.add_block(left, right)

        if self._cc.recovery_point != 0:
            self._cc.prr_delivered += self._sack_scoreboard.total_sacked_bytes() - bytes_before

    def _prune_sack_scoreboard(self) -> None:
        """
        Drop scoreboard blocks whose right edge is at or below
        the current 'SND.UNA' - the cumulative ACK has absorbed
        them and they cannot inform any further loss recovery
        (RFC 6675 §3 / RFC 2018 §3). Gated on '_send_sack' so the
        pruning is a no-op on connections without bilateral SACK.
        """

        if self._advertise.send_sack:
            self._sack_scoreboard.prune_below(self._snd_seq.una)

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

        if self._cc.recovery_point == 0 or not self._advertise.send_sack:
            return

        for left, right in sorted(
            self._sack_scoreboard.blocks(),
            key=lambda b: (b[0] - self._snd_seq.una) & 0xFFFF_FFFF,
        ):
            if le32(left, self._snd_seq.nxt) and lt32(self._snd_seq.nxt, right):
                self._snd_seq.nxt = right

    def _enqueue_rx_buffer(self, data: memoryview) -> None:
        """
        Process the incoming segment and enqueue the data
        to be used by socket.
        """

        assert isinstance(data, memoryview)  # memoryview: check to ensure data gets here as memoryview not bytes.

        # POSIX 'shutdown(SHUT_RD)' silently discards inbound
        # data per RFC 9293 §3.9.1 half-close semantics. The
        # peer's ACK still acknowledges the seq space (advancing
        # RCV.NXT), but the application never sees the bytes.
        if self._shut.rd:
            return

        with self._lock__rx_buffer:
            self._rx_buffer.extend(data)
            # 'Event.set()' is idempotent so this is safe whether the
            # event was already set by a sibling FSM handler or not.
            self._event__rx_buffer.set()
            # Selector readability: an asyncio / trio / selectors
            # consumer waiting on 'self._socket.fileno()' must wake
            # on inbound data. The hook lives under the rx-buffer
            # lock so concurrent recv() drains observe a consistent
            # eventfd state.
            self._socket._signal_readable()

    def _transmit_data(self) -> None:
        """
        Send out data segment from TX buffer using TCP
        sliding window mechanism. Thin delegator over
        'TcpTxEngine.transmit_data'.
        """

        self._tx_engine.transmit_data()

    def _delayed_ack(self) -> None:
        """
        Run Delayed ACK mechanism. Thin delegator over
        'TcpTxEngine.delayed_ack'.
        """

        self._tx_engine.delayed_ack()

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
        # timer has fired. '_timer_expired' is True only when the
        # timer was armed and its deadline has passed (an unarmed
        # timer is NOT expired), so the second guard 'snd_una !=
        # snd_max' is the genuine RFC 6298 §5 "nothing in flight"
        # condition — do not retransmit when there is no unacked
        # data — not a disambiguation crutch.
        if not self._timer_expired("retransmit"):
            return
        if self._snd_seq.una == self._snd_seq.max:
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
                self._transmit_packet(flag_rst=True, flag_ack=True, seq=self._snd_seq.una)
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
                self._socket._signal_readable()
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
        if self._rtt.seq is not None and self._rtt.seq == self._snd_seq.una:
            self._rtt.taint()

        # RFC 8985 §6.3: on RTO, mark all in-flight segments
        # lost. Subsequent retransmit walking treats them as
        # the loss set; the existing _transmit_data
        # machinery (with snd_nxt rewound to snd_una below)
        # will re-fire them. Replace each entry with the
        # 'lost=True / xmit_ts=INFINITE_TS' form per
        # RFC 8985 §5.2.
        from pytcp.protocols.tcp.tcp__rack import INFINITE_TS

        self._rack_tlp.rack_segments = {
            seq: RackSegment(
                end_seq=seg.end_seq,
                xmit_ts=INFINITE_TS,
                retransmitted=seg.retransmitted,
                lost=True,
            )
            for seq, seg in self._rack_tlp.rack_segments.items()
        }

        # RFC 6298 §5.5 binary backoff and §5.6 re-arm with the
        # new RTO. 'back_off' caps at 'MAX_RTO_MS' so a long-
        # silent peer cannot drive 'rto_ms' to overflow.
        self._rto_state = back_off(self._rto_state)
        self._retransmit_count += 1
        # PLPMTUD adapter: declare any in-flight probe lost so
        # the engine sees the RTO event as a probe-loss
        # signal. No-op when no probes were in flight (RFC
        # 4821 §7.5 — data-RTO alone does not feed
        # probe-loss).
        self._plpmtud_adapter.on_rto_timeout(now=time.monotonic())
        # RFC 6298 §5.7 second-clause SYN-retransmit counter.
        # Increment when the retransmit fires while the
        # handshake is still in progress: SYN_SENT (active
        # open's SYN) or SYN_RCVD (passive / simultaneous
        # open's SYN+ACK). Survives '_process_ack_packet's
        # cum-ACK reset of '_retransmit_count' so the §5.7
        # floor checks at the ESTABLISHED-transition sites
        # see the count regardless of evaluation order.
        if self._state in {FsmState.SYN_SENT, FsmState.SYN_RCVD}:
            self._syn_retransmit_count += 1
            # RFC 7413 §4.4: SYN retransmits MUST NOT carry the
            # TFO option or SYN-data. Mark the connection so
            # '_transmit_packet' suppresses TFO emission on the
            # retransmit. Set in SYN_SENT only; the peer side
            # (SYN_RCVD) doesn't replay TFO on its SYN+ACK
            # retransmit by construction.
            if self._state is FsmState.SYN_SENT and self._advertise.fastopen:
                self._fastopen.syn_retransmitted = True
                # RFC 7413 §4.1.3.1: a SYN-RTO during TFO
                # active-open is a strong signal that the path
                # drops TFO-bearing SYNs. Add the peer to the
                # negative-response cache so future active-
                # opens to the same peer skip TFO entirely.
                stack.tcp_stack.mark_fastopen_negative(self._remote_ip_address)
        self._arm_timer("retransmit", self._rto_state.rto_ms)
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - RFC 6298 §5.5 back-off: rto_ms -> "
            f"{self._rto_state.rto_ms} (retry "
            f"#{self._retransmit_count})",
        )

        # RFC 5682 §2.1 step 1: snapshot pre-RTO state and
        # store SND.MAX into 'recover' (= '_frto_pre_snd_max'
        # in PyTCP's vocabulary). The already-in-RTO gate
        # (§2.1 step 1: "If the TCP sender is already in RTO
        # recovery AND 'recover' is larger than or equal to
        # SND.UNA, do not enter step 2 of this algorithm.
        # Instead, store the highest sequence number
        # transmitted so far in variable 'recover'") fires
        # when a second RTO arrives while the first F-RTO is
        # still pending and SND.UNA has not yet covered the
        # original recover marker. In that case, only the
        # recover marker is updated; the original pre-RTO
        # cwnd / ssthresh / CUBIC snapshots are preserved so
        # the eventual restoration anchors at the genuine
        # pre-loss values rather than the post-first-RTO
        # collapsed values.
        already_in_frto = self._cc.frto_step != 0 and not lt32(self._cc.frto_pre_snd_max, self._snd_seq.una)
        if already_in_frto:
            # Update recover only; preserve original snapshots.
            self._cc.frto_pre_snd_max = self._snd_seq.max
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - RFC 5682 §2.1 already-in-RTO gate: "
                f"recover updated to {self._cc.frto_pre_snd_max}; "
                "step 2 skipped (preserving original pre-RTO snapshot)",
            )
        else:
            self._cc.save_frto_snapshot(snd_max=self._snd_seq.max)

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
        flight_size = (self._snd_seq.max - self._snd_seq.una) & 0xFFFF_FFFF
        # RFC 9438 §4.6 + §4.7: in CUBIC mode, replace the RFC
        # 5681 §3.1 0.5 halving with beta_cubic = 0.7 and
        # update '_cubic_w_max' / '_cubic_K_ms' /
        # '_cubic_epoch_start_ms' so the post-RTO CA growth
        # curve has a fresh anchor. Fast convergence (§4.7) is
        # active by default: when the new cwnd is smaller than
        # the W_max from the prior loss event, W_max is reduced
        # further to release bandwidth to new flows.
        if self._cc.cc_mode is CcMode.CUBIC:
            prior_w_max = self._cc.cubic_w_max
            self._cc.ssthresh, self._cc.cubic_w_max = cubic_loss_event_ssthresh(
                cwnd=max(self._cc.cwnd, self._win.snd_mss),
                smss=self._win.snd_mss,
                fast_conv_active=True,
                prior_w_max=prior_w_max,
            )
            self._cc.cubic_w_last_max = prior_w_max
            # Curve epoch reset: post-RTO cwnd = 1 SMSS, so
            # cwnd_epoch = SMSS for the cube-root computation.
            self._cc.cubic_K_ms = cubic_compute_K(
                w_max=self._cc.cubic_w_max,
                cwnd_epoch=self._win.snd_mss,
                smss=self._win.snd_mss,
            )
            self._cc.cubic_epoch_start_ms = stack.timer.now_ms
            self._cc.cubic_in_ca = False
            # RFC 9438 §4.3: reset W_est so the next CA stage
            # bootstraps from cwnd_epoch (re-init on first CA
            # cum-ACK in '_process_ack_packet').
            self._cc.cubic_w_est = 0
        else:
            self._cc.ssthresh = compute_loss_event_ssthresh(flight_size, self._win.snd_mss)
        # RFC 5681 §3.1: cwnd collapses to LW = 1 SMSS for
        # slow-start re-entry. RFC 9293 §3.8.6.1 / RFC 1122
        # §4.2.2.16 still require respecting peer's advertised
        # window: a 0-window peer means '_snd_ewn = 0' so
        # '_transmit_data' falls through to the persist branch.
        self._cc.cwnd = self._win.snd_mss
        self._cc.snd_ewn = min(self._cc.cwnd, self._win.snd_wnd)
        self._snd_seq.nxt = self._snd_seq.una
        # RFC 5681 §3.1 hard reset: an RTO is a fresh loss
        # event, distinct from the dup-ACK-driven fast-
        # retransmit recovery. The RFC 6675 §5 RecoveryPoint
        # marker (the SND.MAX at fast-retransmit entry) is
        # meaningless once SND.NXT has been rewound to
        # SND.UNA above; leaving it set would inhibit the
        # next dup-ACK from re-entering recovery via the
        # one-shot guard in '_retransmit_packet_request'.
        self._cc.recovery_point = 0
        # RFC 6675 §5.1: "A SACK TCP sender SHOULD utilize all
        # SACK information made available during the loss
        # recovery following an RTO." PyTCP retains the SACK
        # scoreboard across the RTO so the post-RTO recovery
        # can use the prior SACK reports to skip already-
        # delivered ranges, matching the RFC 6675 modern
        # interpretation that supersedes RFC 2018 §5's older
        # "turn off SACKed bits" guidance. Reneging by the
        # peer would violate RFC 8985 RACK-TLP's xmit_ts
        # invariants and would be detected separately.
        # RFC 6582 §3.2 step 4: record the highest SND.MAX
        # transmitted before the RTO so a subsequent burst of
        # dup-ACKs (often produced by the post-RTO retransmit
        # storm) cannot re-trigger fast retransmit until the
        # cum-ACK has progressed past the recover marker.
        # Setting this AFTER '_recovery_point = 0' so the
        # '_retransmit_packet_request' entry gate keys on the
        # recover marker rather than the now-cleared
        # recovery point.
        self._cc.recover_seq = self._snd_seq.max
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
        if self._snd_seq.nxt == self._snd_seq.ini or (
            self._snd_seq.fin_sent and self._snd_seq.nxt == sub32(self._snd_seq.fin, 1)
        ):
            self._tx.seq_mod = sub32(self._tx.seq_mod, 1)
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - Got retransmit timeout, sending segment "
            f"{self._snd_seq.nxt}, resetting snd_ewn to {self._cc.snd_ewn}",
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

        # RFC 8985 §6.2 step 1-2 RACK fold + step 5 loss
        # detection on the dup-ACK path. SACK-acked segments
        # advance RACK.xmit_ts even when the cum-ACK does not
        # advance, so a SACK-only dup-ACK can still drive
        # time-based loss detection per RFC 8985 §6.2.
        self._rack_process_ack(packet_rx_md)

        self._tx.retransmit_request_counter[packet_rx_md.tcp__ack] = (
            self._tx.retransmit_request_counter.get(packet_rx_md.tcp__ack, 0) + 1
        )

        # RFC 5681 §3.2 / RFC 6675 §5: enter recovery exactly
        # once per loss event. While 'recovery_point > 0' we are
        # still recovering from an earlier trigger; further
        # dup-ACKs MUST NOT re-fire the retransmit. Cwnd
        # inflation on each dup-ACK is now driven by RFC 6937
        # PRR: a bare dup-ACK delivers no new bytes
        # (DeliveredData = 0) so prr_delivered is unchanged
        # and cwnd stays steady - PRR's proportional pacing
        # replaces the legacy RFC 5681 §3.2 step 4 'cwnd +=
        # SMSS per dup-ACK' rule, which over-inflated cwnd on
        # bare dup-ACK bursts and caused the post-recovery
        # send burst PRR is designed to smooth. SACK-bearing
        # dup-ACKs that delivered new bytes update
        # 'prr_delivered' inside '_ingest_sack_info' and the
        # cwnd recompute on cum-ACK in '_process_ack_packet'
        # picks them up.
        if self._cc.recovery_point != 0:
            return

        # RFC 6582 §3.2 step 4 / step 2 post-RTO gate. After an
        # RTO recorded SND.MAX into '_recover_seq', refuse fast-
        # retransmit entry until SND.UNA has advanced to or past
        # the marker. This prevents the post-RTO retransmit
        # storm's dup-ACK echoes (which carry an old 'ack' value
        # still below the marker) from spuriously triggering a
        # second fast retransmit on top of the just-completed
        # RTO recovery. The 0 sentinel means "no recover marker
        # set" so a fresh connection's first loss event still
        # enters FR.
        if self._cc.recover_seq != 0 and lt32(self._snd_seq.una, self._cc.recover_seq):
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
        count_trigger = self._tx.retransmit_request_counter[packet_rx_md.tcp__ack] == 3
        sack_trigger = self._advertise.send_sack and is_lost(
            self._snd_seq.una,
            scoreboard=self._sack_scoreboard,
            snd_una=self._snd_seq.una,
            mss=self._win.snd_mss,
        )
        # RFC 3042 Limited Transmit: on the first two
        # duplicate ACKs, send one new segment from the TX
        # buffer if budget permits. The budget is
        # 'cwnd + 2*SMSS' total - one extra segment per
        # dup-ACK (1st and 2nd). Limited Transmit injects
        # new segments into the pipe so a small-window
        # flow can still generate three dup-ACKs at the
        # peer and trigger fast retransmit on real loss
        # rather than waiting for an RTO. The third dup-ACK
        # falls through to the count_trigger path below
        # and runs RFC 5681 §3.2 fast retransmit instead.
        count = self._tx.retransmit_request_counter[packet_rx_md.tcp__ack]
        if count in (1, 2) and len(self._tx.buffer) > 0:
            saved_ewn = self._cc.snd_ewn
            self._cc.snd_ewn = min(self._cc.cwnd + count * self._win.snd_mss, self._win.snd_wnd)
            self._transmit_data()
            self._cc.snd_ewn = saved_ewn

        if not (count_trigger or sack_trigger):
            return

        # RFC 5681 §3.2 step 2: ssthresh = max(FlightSize/2,
        # 2*SMSS). Captures the just-observed loss point so
        # the post-recovery slow-start exits at this boundary.
        flight_size = (self._snd_seq.max - self._snd_seq.una) & 0xFFFF_FFFF
        # RFC 9438 §4.6 + §4.7: in CUBIC mode, ssthresh halves
        # by beta_cubic = 0.7 (vs RFC 5681's 0.5). Records
        # '_cubic_w_max' = cwnd-at-loss for the post-recovery
        # cubic curve. Fast convergence (§4.7) reduces W_max
        # further when the new cwnd is smaller than the prior
        # W_max anchor.
        if self._cc.cc_mode is CcMode.CUBIC:
            prior_w_max = self._cc.cubic_w_max
            # RFC 9438 §4.9.2 spurious-fast-retransmit snapshot:
            # capture the pre-FR CUBIC state so a DSACK during
            # this recovery episode can roll back the
            # multiplicative decrease + curve re-anchor below.
            self._cc.save_fr_cubic_snapshot()
            self._cc.ssthresh, self._cc.cubic_w_max = cubic_loss_event_ssthresh(
                cwnd=self._cc.cwnd,
                smss=self._win.snd_mss,
                fast_conv_active=True,
                prior_w_max=prior_w_max,
            )
            self._cc.cubic_w_last_max = prior_w_max
            self._cc.cubic_K_ms = cubic_compute_K(
                w_max=self._cc.cubic_w_max,
                cwnd_epoch=self._cc.ssthresh,
                smss=self._win.snd_mss,
            )
            self._cc.cubic_epoch_start_ms = stack.timer.now_ms
            self._cc.cubic_in_ca = True
            # RFC 9438 §4.3: reset W_est so the next CA stage
            # bootstraps from the post-recovery cwnd anchor.
            self._cc.cubic_w_est = 0
        else:
            self._cc.ssthresh = compute_loss_event_ssthresh(flight_size, self._win.snd_mss)

        # RFC 6937 §3.1 PRR per-recovery state initialisation:
        # snapshot pipe at entry as 'RecoverFS' so the per-ACK
        # send-pacing math has the denominator for the
        # 'prr_delivered * ssthresh / RecoverFS' ratio. Reset
        # the prr_delivered / prr_out counters to zero so the
        # accumulators only cover this recovery episode.
        self._cc.recover_fs = flight_size
        self._cc.prr_delivered = 0
        self._cc.prr_out = 0

        # RFC 6937 §3.1: at entry 'prr_delivered = 0' and
        # 'prr_out = 0' so the per-ACK formula yields
        # 'sndcnt = 0 - 0 = 0' and 'cwnd = pipe + 0 = pipe'.
        # Pipe at entry equals 'flight_size' (no SACKs ingested
        # this ACK). This replaces the legacy RFC 5681 §3.2
        # step 3 'cwnd = ssthresh + 3*SMSS' coarse approximation
        # with PRR's data-driven per-ACK pacing - subsequent
        # ACKs recompute cwnd via the proportional ratio in
        # '_process_ack_packet'.
        self._cc.cwnd = flight_size
        self._cc.snd_ewn = min(self._cc.cwnd, self._win.snd_wnd)

        # Mark RecoveryPoint at SND.MAX so subsequent dup-ACKs
        # within the loss event do not re-trigger; '_process_ack_packet'
        # clears it once the cumulative ACK has fully recovered.
        # Setting to 'max(SND.MAX, 1)' guarantees the marker is
        # non-zero even when SND.MAX wraps to 0; the actual
        # comparison is modular.
        self._cc.recovery_point = self._snd_seq.max if self._snd_seq.max != 0 else 1

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
                snd_una=self._snd_seq.una,
                snd_max=self._snd_seq.max,
                mss=self._win.snd_mss,
            )
            if self._advertise.send_sack
            else None
        )
        self._snd_seq.nxt = ns if ns is not None else self._snd_seq.una
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - Got retransmit request, sending segment "
            f"{self._snd_seq.nxt}, keeping snd_ewn at {self._cc.snd_ewn}, "
            f"recovery_point {self._cc.recovery_point}",
        )

    def _tlp_pto_tick(self) -> None:
        """
        Per-tick service for the RFC 8985 §7.3 Tail Loss
        Probe. Fires when the f'{session}-tlp' timer expires
        and there is data in flight. Prefers sending new data
        from the TX buffer (when available); falls back to
        retransmitting the highest-seq in-flight segment.

        On emission, marks '_tlp_is_retrans' (True for
        retransmit, False for new-data probe) and stashes the
        post-probe SND.MAX in '_tlp_end_seq' so the §7.4
        loss-detection path can reason about the probe's fate.
        Re-arms the RTO timer at 'rto_state.rto_ms' so the
        connection still has a timeout-driven recovery path
        if the probe itself is lost.
        """

        # tlp_armed gates the firing path: only when the
        # arming logic in '_transmit_packet' actually armed
        # the TLP timer should this tick treat a
        # '_timer_expired' result as a real timer expiration.
        # Without this gate a session that armed a TLP, let it
        # fire, and never re-armed would still satisfy the
        # downstream expiry check and _tlp_pto_tick would
        # spuriously fire a retransmit on every FSM tick.
        if not self._rack_tlp.tlp_armed:
            return
        if not self._timer_expired("tlp"):
            return
        if self._snd_seq.una == self._snd_seq.max:
            # Nothing in flight - no tail to probe.
            return
        # RFC 8985 §7 once-per-tail gate: TLP fires at most one
        # probe per outstanding tail. '_tlp_end_seq' is set on
        # probe emission and cleared by §7.4 loss-detection
        # logic (Phase 8) once the probe outcome is determined,
        # OR by '_process_ack_packet' when a cum-ACK drains all
        # in-flight bytes (no tail left).
        if self._rack_tlp.tlp_end_seq is not None:
            return
        # RFC 8985 §8 timer arbitration: if RTO recovery is in
        # progress (this tick's _retransmit_packet_timeout
        # incremented _retransmit_count, OR a fast-recovery is
        # underway, OR F-RTO is active), TLP yields. The
        # ongoing recovery machinery handles the loss already;
        # a TLP probe would race it and emit a duplicate.
        if self._retransmit_count > 0 or self._cc.recovery_point != 0 or self._cc.frto_active:
            return

        # New-data probe path: the TX buffer has bytes past
        # SND.MAX (i.e. data the application has queued but
        # the wire has not yet seen). When this is the case
        # we send the next segment from SND.MAX rather than
        # retransmitting an already-sent one. Compute the
        # buffer offset of SND.MAX modularly so a wrapped
        # session is handled correctly.
        tx_buffer_max = sub32(self._snd_seq.max, self._tx.seq_mod)
        new_data_available = tx_buffer_max < len(self._tx.buffer) and self._cc.snd_ewn > tx_buffer_max
        if new_data_available:
            # Force '_transmit_data' to start at SND.MAX (the
            # bytes immediately past the highest-seq sent).
            self._snd_seq.nxt = self._snd_seq.max
            self._rack_tlp.tlp_is_retrans = False
        else:
            # Retransmit-style probe: walk SND.NXT back by one
            # MSS (or less if in-flight is shorter) so
            # _transmit_data re-sends the highest-seq segment.
            flight_size = (self._snd_seq.max - self._snd_seq.una) & 0xFFFF_FFFF
            walk_back = min(self._win.snd_mss, flight_size)
            self._snd_seq.nxt = sub32(self._snd_seq.max, walk_back)
            self._rack_tlp.tlp_is_retrans = True

        self._transmit_data()
        self._rack_tlp.tlp_end_seq = self._snd_seq.max
        # Probe is in flight; clear armed flag so the next
        # tick's _tlp_pto_tick early-returns. The flag is
        # re-set by '_transmit_packet' when a fresh TLP timer
        # arms, e.g. on a subsequent data send.
        self._rack_tlp.tlp_armed = False

        # RFC 8985 §7.3: re-arm the RTO timer after probe so
        # the connection retains its timeout fallback.
        self._arm_timer("retransmit", self._rto_state.rto_ms)

    def _rack_reorder_tick(self) -> None:
        """
        Per-tick service for the RFC 8985 §6.2 step 5
        reordering timer. When the f'{session}-rack' timer
        has expired, re-run rack_detect_loss with the current
        scalars and reo_wnd to mark any pending 'sent before'
        segments lost. Subsequent ticks may re-arm the timer
        if more candidates exist.
        """

        if not self._timer_expired("rack"):
            return
        if self._rack_tlp.rack_xmit_ts == 0:
            return
        reo_wnd_ms = rack_compute_reo_wnd(
            reordering_seen=self._rack_tlp.rack_reordering_seen,
            reo_wnd_mult=self._rack_tlp.rack_reo_wnd_mult,
            min_rtt_ms=self._rack_tlp.rack_min_rtt_ms,
        )
        self._rack_tlp.rack_segments, rack_timeout_ms = rack_detect_loss(
            segments=self._rack_tlp.rack_segments,
            rack_xmit_ts=self._rack_tlp.rack_xmit_ts,
            rack_end_seq=self._rack_tlp.rack_end_seq,
            reo_wnd_ms=reo_wnd_ms,
            now_ms=stack.timer.now_ms,
        )
        if rack_timeout_ms > 0:
            self._arm_timer("rack", rack_timeout_ms)

    def _rack_process_ack(self, packet_rx_md: TcpMetadata) -> None:
        """
        Apply RFC 8985 §6.2 step 1-2 (rack_update) + step 5
        (rack_detect_loss) on every accepted ACK. Called from
        both '_process_ack_packet' (cum-ACK path) and
        '_retransmit_packet_request' (SACK-only / dup-ACK
        path) after SACK ingest so the scoreboard reflects
        the latest peer-reported state.

        The 'newly acknowledged' set per §6.2 includes BOTH
        cum-ACKed AND SACK-acked segments delivered for the
        first time on this ACK. The '_rack_acked_seqs' guard
        ensures each segment contributes to the rack_update
        scalars exactly once across multiple ACKs.

        For Phase 3 the loss-detection helper is called with
        'reo_wnd_ms=0' (no reordering tolerance); Phase 4
        will compute reo_wnd dynamically via
        'rack_compute_reo_wnd'.
        """

        newly_acked: list[RackSegment] = []
        for seq, seg in self._rack_tlp.rack_segments.items():
            if seq in self._rack_tlp.rack_acked_seqs:
                continue
            cum_acked = le32(seg.end_seq, self._snd_seq.una)
            sack_acked = self._advertise.send_sack and self._sack_scoreboard.is_sacked(sub32(seg.end_seq, 1))
            if cum_acked or sack_acked:
                newly_acked.append(seg)
                self._rack_tlp.rack_acked_seqs.add(seq)
        if newly_acked:
            # RFC 8985 §6.2 step 3 reordering detection. For
            # each newly-acked segment, compare its 'end_seq'
            # to '_rack_fack' (the highest end_seq we have
            # seen acked so far). A delivered segment whose
            # end_seq is strictly below fack means the network
            # has reordered: a later-sent segment was already
            # acked before this one. Once 'reordering_seen' is
            # True it stays True; the §6.2 step 4 reo_wnd
            # computation uses it to switch from the dup-ACK
            # trigger (reo_wnd=0) to the time-based trigger
            # (reo_wnd = min_RTT / 4 * reo_wnd_mult).
            for seg in newly_acked:
                if self._rack_tlp.rack_fack != 0 and lt32(seg.end_seq, self._rack_tlp.rack_fack):
                    self._rack_tlp.rack_reordering_seen = True
                if gt32(seg.end_seq, self._rack_tlp.rack_fack):
                    self._rack_tlp.rack_fack = seg.end_seq
            (
                self._rack_tlp.rack_min_rtt_ms,
                self._rack_tlp.rack_rtt_ms,
                self._rack_tlp.rack_xmit_ts,
                self._rack_tlp.rack_end_seq,
            ) = rack_update(
                newly_acked_segments=newly_acked,
                now_ms=stack.timer.now_ms,
                ts_recent_echo_ms=(packet_rx_md.tcp__tsecr if packet_rx_md.tcp__tsecr else None),
                prior_min_rtt_ms=self._rack_tlp.rack_min_rtt_ms,
                prior_rack_rtt_ms=self._rack_tlp.rack_rtt_ms,
                prior_rack_xmit_ts=self._rack_tlp.rack_xmit_ts,
                prior_rack_end_seq=self._rack_tlp.rack_end_seq,
            )

        if self._rack_tlp.rack_xmit_ts > 0:
            # RFC 8985 §6.2 step 4 dynamic reo_wnd via
            # rack_compute_reo_wnd. Phase 3 used 0; Phase 4
            # adapts based on observed reordering and DSACK
            # rounds.
            reo_wnd_ms = rack_compute_reo_wnd(
                reordering_seen=self._rack_tlp.rack_reordering_seen,
                reo_wnd_mult=self._rack_tlp.rack_reo_wnd_mult,
                min_rtt_ms=self._rack_tlp.rack_min_rtt_ms,
            )
            self._rack_tlp.rack_segments, rack_timeout_ms = rack_detect_loss(
                segments=self._rack_tlp.rack_segments,
                rack_xmit_ts=self._rack_tlp.rack_xmit_ts,
                rack_end_seq=self._rack_tlp.rack_end_seq,
                reo_wnd_ms=reo_wnd_ms,
                now_ms=stack.timer.now_ms,
            )
            # RFC 8985 §6.2 step 5 reordering-timer arming.
            # When rack_detect_loss leaves any 'sent before'
            # segment within its reo_wnd (timeout_ms > 0),
            # arm a single session-level timer at the earliest
            # 'xmit_ts + reo_wnd - now_ms' so the FSM tick can
            # re-run the loss-detection check and mark the
            # segment lost once the window has elapsed.
            if rack_timeout_ms > 0:
                self._arm_timer("rack", rack_timeout_ms)

    def _confirm_neighbor_reachability(self) -> None:
        """
        RFC 4861 §7.3.1 upper-layer reachability confirmation
        — feed the appropriate NUD cache (ARP for IPv4 peers,
        ND for IPv6) the positive-evidence signal from a
        cum-ACK that advanced SND.UNA. Promotes a STALE /
        DELAY / PROBE entry directly to REACHABLE without
        firing a unicast probe; no-op for entries in
        INCOMPLETE / FAILED / PERMANENT or absent from the
        cache.

        Called from '_phase1_cum_ack_side_effects' after the
        SND.UNA-advance check, so dup-ACKs and stale ACKs do
        not fire the hook.
        """

        # The peer's neighbor entry lives in the EGRESS interface's
        # cache (Linux keys ARP / ND per ifindex). Resolve the egress
        # interface and feed its own cache — the Phase-6 successor to the
        # bare 'stack.arp_cache' / 'stack.nd_cache' singletons.
        # Phase 3: a dedicated neighbor-control API will replace this
        # reach-through into the handler's '_arp_cache' / '_nd_cache'.
        handler = stack.egress_packet_handler(self._remote_ip_address)
        if isinstance(self._remote_ip_address, Ip4Address):
            if handler._arp_cache is not None:
                handler._arp_cache.confirm_reachability(ip4_address=self._remote_ip_address)
        elif handler._nd_cache is not None:
            handler._nd_cache.confirm_reachability(ip6_address=self._remote_ip_address)

    def _process_ack_packet(self, packet_rx_md: TcpMetadata) -> None:
        """
        Process regular data/ACK packet.
        """

        # RFC 7323 §5 PAWS + §4.3 '_ts_recent' refresh: handled
        # by '_check_paws_and_update_ts_recent' so the same
        # gate applies on every inbound dispatch path
        # (dup-ACK fast-retransmit, OOO insert, TIME_WAIT late
        # segments, etc.). Stale-TSval segments are silently
        # dropped per RFC 7323 §5.4.
        if not self._check_paws_and_update_ts_recent(packet_rx_md):
            return

        # RFC 1122 §4.2.3.6: peer activity (ACK and / or data)
        # resets the keep-alive idle timer. No-op when keep-alive
        # is disabled.
        self._keepalive_arm_idle()

        self._phase1_cum_ack_side_effects(packet_rx_md)
        self._phase3_harvest_rtt_samples(packet_rx_md)
        # SACK scoreboard maintenance per RFC 6675 §3 / RFC 2018
        # §3: prune any blocks now absorbed by the cumulative ACK,
        # then ingest fresh blocks the peer reported on this
        # segment. Both are no-ops when '_send_sack' is False.
        self._prune_sack_scoreboard()
        self._ingest_sack_info(packet_rx_md)
        self._phase4_loss_detection_and_recovery_exit(packet_rx_md)
        self._phase5_consume_segment_and_postprocess(packet_rx_md)

    def _phase1_cum_ack_side_effects(self, packet_rx_md: TcpMetadata) -> None:
        """
        Phase 1 of the inbound-ACK pipeline. Process the side-
        effects of a cum-ACK that advances SND.UNA: bytes_acked
        compute, SND.UNA advance, RFC 9406 round-boundary rotate,
        RFC 6582 recover_seq decay, RFC 6937 PRR delivered
        accumulation, RFC 9438 / 5681 / 6928 cwnd growth (CUBIC
        vs Reno + HyStart CSS override), RFC 9293 §3.8.4 snd_ewn
        recompute, RFC 6298 retransmit-timer manage, RFC 8985
        §7.2 / §7.4 TLP loss-detect / repair / cancel, and the
        RFC 5682 §2.1 F-RTO step 2 / step 3 spurious-RTO
        detection (delegated to phase 2).

        Returns early when the inbound ACK does not advance
        SND.UNA — dup-ACKs and stale ACKs do not exercise any
        of these side-effects.

        Reference: RFC 5681 §3.1 (slow-start vs CA growth).
        Reference: RFC 5681 §3.2 step 4 (per-dup-ACK inflation).
        Reference: RFC 6298 §5.2 (retransmit-timer off on full drain).
        Reference: RFC 6298 §5.3 (retransmit-timer restart on advance).
        Reference: RFC 6582 §3.2 step 4 (NewReno recover decay).
        Reference: RFC 6928 (initial-window slow-start).
        Reference: RFC 6937 §3.1 (PRR proportional pacing).
        Reference: RFC 8985 §7.2 (TLP cancellation on cum-ACK drain).
        Reference: RFC 8985 §7.4 (TLP loss-detection on inbound ACK).
        Reference: RFC 8985 §7.4.2 (TLP probe-repair CC response).
        Reference: RFC 9293 §3.4 (modular SND.UNA arithmetic).
        Reference: RFC 9293 §3.8.4 (snd_ewn = min(cwnd, snd_wnd)).
        Reference: RFC 9406 §4.2 (HyStart++ round-boundary + CSS).
        Reference: RFC 9438 §4.3 (W_est Reno-friendly tracker).
        Reference: RFC 9438 §4.4 (CUBIC growth in CA).
        Reference: RFC 9438 §4.5 (CUBIC slow-start path).
        """

        # Make note of the local SEQ that has been acked by peer.
        # Modular 'max': SND.UNA advances iff peer's ack is
        # "ahead" of it in the 32-bit modular sense. Plain 'max()'
        # uses numerical order, which is wrong across the wrap.
        if not lt32(self._snd_seq.una, packet_rx_md.tcp__ack):
            return

        # RFC 4861 §7.3.1 upper-layer reachability confirmation:
        # an in-window cum-ACK that advances SND.UNA is positive
        # evidence the neighbour is reachable; promote any
        # STALE / DELAY / PROBE entry directly to REACHABLE
        # without firing a unicast probe (ND for IPv6 peers,
        # ARP for IPv4). Linux's 'NEIGH_UPDATE_F_USE' is the
        # equivalent hook.
        self._confirm_neighbor_reachability()

        # Modular bytes-acked computation per RFC 9293 §3.4
        # so the §3.1 cwnd growth formula gets the correct
        # delta when the cum-ACK straddles the 32-bit wrap.
        bytes_acked = (packet_rx_md.tcp__ack - self._snd_seq.una) & 0xFFFF_FFFF
        self._snd_seq.una = packet_rx_md.tcp__ack
        # PLPMTUD adapter: notify of snd.una advance so any
        # in-flight probe whose seq is now <= new_snd_una
        # gets dispatched as an on_probe_ack event.
        # Linux 'tcp_mtu_probe_success' equivalent: a
        # successful probe ack grows the engine's
        # 'current_mtu'; sync 'self._win.snd_mss' to match
        # so future data segments use the newly-confirmed
        # larger MSS. Detect the growth by snapshotting the
        # engine's current_mtu around the dispatch — only
        # fires when on_probe_ack actually advanced it.
        plpmtud_current_before = self._plpmtud_adapter.current_mtu
        self._plpmtud_adapter.on_snd_una_advance(
            new_snd_una=self._snd_seq.una,
            now=time.monotonic(),
        )
        if self._plpmtud_adapter.current_mtu > plpmtud_current_before:
            engine_mss = self._plpmtud_adapter.current_mtu - self._ip_tcp_overhead
            if engine_mss > self._win.snd_mss:
                self._win.snd_mss = engine_mss
        # RFC 9406 §4.2 round-boundary detection: if SND.UNA
        # has reached or passed the round's window_end_seq,
        # rotate the per-round minRTT trackers. The first
        # round bootstrap-initialises window_end_seq from
        # SND.NXT; subsequent rotations also re-anchor
        # window_end_seq to the current SND.NXT so the next
        # round measures samples until the in-flight
        # high-water mark is acked. CSS_ROUNDS exhaustion
        # is signalled by 'css_rounds_remaining == 0' after
        # rotate_round; that triggers the §4.2 "set
        # ssthresh = cwnd" entry into congestion avoidance.
        if self._cc.cwnd < self._cc.ssthresh:
            if self._cc.hystart_state.window_end_seq == 0:
                # Bootstrap: first round of slow-start.
                self._cc.hystart_state.window_end_seq = self._snd_seq.nxt
            elif not lt32(self._snd_seq.una, self._cc.hystart_state.window_end_seq):
                rotate_round(self._cc.hystart_state, new_window_end_seq=self._snd_seq.nxt)
                if self._cc.hystart_state.in_css and self._cc.hystart_state.css_rounds_remaining == 0:
                    # CSS_ROUNDS exhausted -> ssthresh =
                    # cwnd, enter CA. Clear CSS state.
                    self._cc.ssthresh = self._cc.cwnd
                    resume_slow_start(self._cc.hystart_state)
                    __debug__ and log(
                        "tcp-ss",
                        f"[{self}] - RFC 9406 HyStart++ "
                        "CSS_ROUNDS exhausted; ssthresh = "
                        f"cwnd = {self._cc.cwnd}, entering CA",
                    )
        # RFC 6582 §3.2 step 4 marker decay: clear the
        # recover marker once SND.UNA has reached or passed
        # it. SND.UNA is the next-byte-expected from peer,
        # so 'SND.UNA == recover' means peer has acked the
        # last byte recorded into the marker (recover ==
        # snd_max-at-RTO == one past last data seq); 'ge32'
        # is the right comparison. Subsequent dup-ACK bursts
        # can then drive fast retransmit normally without
        # the post-RTO gate suppressing legitimate loss
        # recovery.
        if self._cc.recover_seq != 0 and ge32(self._snd_seq.una, self._cc.recover_seq):
            self._cc.recover_seq = 0
        # RFC 6937 §3.1 PRR: cumulative bytes ACK'd during
        # recovery feed 'prr_delivered'. Out-of-recovery
        # cum-ACKs do not - the accumulator is scoped to a
        # single recovery episode.
        if self._cc.recovery_point != 0:
            self._cc.prr_delivered += bytes_acked
        # Cwnd update on cum-ACK that advances SND.UNA.
        # Three branches gated on recovery state:
        #   - in recovery, partial cum-ACK (snd_una hasn't
        #     reached recovery_point): RFC 6937 §3.1 PRR
        #     proportional pacing - 'cwnd = pipe + sndcnt'
        #     where sndcnt is computed from the
        #     'prr_delivered * ssthresh / RecoverFS' ratio.
        #     Replaces the RFC 6582 NewReno step 3b
        #     deflation; PRR's per-ACK proportional pacing
        #     subsumes both the deflate-on-partial-ACK
        #     intent and RFC 5681 §3.2 step 4's per-dup-ACK
        #     inflation.
        #   - in recovery, full cum-ACK (snd_una reached
        #     recovery_point): RFC 5681 §3.2 step 6
        #     deflation (cwnd = ssthresh) - handled at the
        #     recovery-exit branch below.
        #   - not in recovery: RFC 5681 §3.1 slow-start vs
        #     congestion-avoidance growth.
        if self._cc.recovery_point != 0 and lt32(self._snd_seq.una, self._cc.recovery_point):
            current_pipe = pipe(
                scoreboard=self._sack_scoreboard,
                snd_una=self._snd_seq.una,
                snd_max=self._snd_seq.max,
            )
            if current_pipe > self._cc.ssthresh:
                # PRR proper: aim for ssthresh/RecoverFS
                # ratio. Integer CEIL via the standard
                # '-(-a // b)' trick to avoid float math.
                target = -(-self._cc.prr_delivered * self._cc.ssthresh // self._cc.recover_fs)
                sndcnt = target - self._cc.prr_out
            else:
                # PRR-CRB / PRR-SSRB: pipe has dropped at
                # or below ssthresh; allow conservative
                # send budget. SSRB (bilateral SACK + new
                # data this ACK) lets cwnd grow up to one
                # SMSS per ACK; CRB (no SACK or no new
                # data) caps at the unsent prr_delivered.
                if self._advertise.send_sack and bytes_acked > 0:
                    limit = max(self._cc.prr_delivered - self._cc.prr_out, bytes_acked) + self._win.snd_mss
                else:
                    limit = self._cc.prr_delivered - self._cc.prr_out
                sndcnt = min(self._cc.ssthresh - current_pipe, limit)
            self._cc.cwnd = current_pipe + max(0, sndcnt)
        else:
            # RFC 9438 §4.4 / §4.5: when '_cc_mode == CUBIC'
            # AND we are in CA (cwnd >= ssthresh), use the
            # cubic growth formula instead of the linear
            # Reno CA branch. Slow-start (cwnd < ssthresh)
            # is handled inside both helpers and yields the
            # same RFC 5681 §3.1 path either way.
            if self._cc.cc_mode is CcMode.CUBIC and self._cc.cwnd >= self._cc.ssthresh:
                self._cc.cubic_in_ca = True
                now_ms = stack.timer.now_ms
                cubic_cwnd = cubic_grow_per_ack(
                    cwnd=self._cc.cwnd,
                    ssthresh=self._cc.ssthresh,
                    w_max=self._cc.cubic_w_max,
                    K_ms=self._cc.cubic_K_ms,
                    epoch_start_ms=self._cc.cubic_epoch_start_ms,
                    now_ms=now_ms,
                    bytes_acked=bytes_acked,
                    smss=self._win.snd_mss,
                    srtt_ms=self._rto_state.srtt_ms or 0,
                )
                # RFC 9438 §4.3: track the Reno-equivalent
                # cwnd ('W_est') in parallel; if the cubic
                # formula yields a smaller cwnd than Reno
                # would, fall back to W_est so CUBIC never
                # under-performs Reno on small-BDP / short-
                # RTT paths. Lazy-initialise on first CA
                # entry from cwnd_epoch.
                if self._cc.cubic_w_est == 0:
                    self._cc.cubic_w_est = self._cc.cwnd
                self._cc.cubic_w_est = cubic_w_est(
                    w_est_prev=self._cc.cubic_w_est,
                    cwnd=self._cc.cwnd,
                    smss=self._win.snd_mss,
                    bytes_acked=bytes_acked,
                )
                self._cc.cwnd = max(cubic_cwnd, self._cc.cubic_w_est)
            else:
                # RFC 9406 §4.2 CSS phase override: when
                # HyStart++ has detected delay-increase and
                # we are in Conservative Slow Start, grow
                # cwnd at 1/CSS_GROWTH_DIVISOR the normal
                # rate. Outside CSS this is the normal
                # RFC 5681 / RFC 6928 slow-start or RFC
                # 5681 §3.1 congestion-avoidance growth via
                # 'cwnd_grow_per_ack'.
                if self._cc.cwnd < self._cc.ssthresh and self._cc.hystart_state.in_css:
                    self._cc.cwnd += css_growth_increment(bytes_acked, self._win.snd_mss)
                else:
                    self._cc.cwnd = cwnd_grow_per_ack(self._cc.cwnd, self._cc.ssthresh, bytes_acked, self._win.snd_mss)
        # RFC 9293 §3.8.4: the effective send window is
        # 'min(cwnd, snd_wnd)'. Recompute now so
        # '_transmit_data' sees the new value on the same
        # FSM tick.
        self._cc.snd_ewn = min(self._cc.cwnd, self._win.snd_wnd)
        # RFC 6298 §5.2 / §5.3: peer has acknowledged new
        # data, fresh evidence of liveness. Reset the R2
        # abort counter and manage the retransmit timer:
        # turn it off iff every in-flight byte is now
        # acked (§5.2), else restart it with the current
        # 'rto_ms' (§5.3) — see the cancel/arm below.
        self._retransmit_count = 0
        # RFC 8985 §7.4 TLP loss-detection on inbound ACK.
        # Apply BEFORE the cum-ACK drain hook so a Case-3
        # ('ack > tlp_end_seq') ACK that also drains the
        # tail can invoke the §7.4.2 CC response. Returns
        # the new '_tlp_end_seq' (None on outcome
        # determined; preserved otherwise) and a flag
        # indicating whether to halve cwnd / ssthresh.
        new_tlp_end_seq, invoke_cc = tlp_process_ack(
            tlp_end_seq=self._rack_tlp.tlp_end_seq,
            tlp_is_retrans=self._rack_tlp.tlp_is_retrans,
            ack_seq=packet_rx_md.tcp__ack,
            has_dsack_for_probe=(self._dsack_received > 0),
            has_sack_blocks=bool(self._sack_scoreboard.blocks()),
        )
        self._rack_tlp.tlp_end_seq = new_tlp_end_seq
        if invoke_cc:
            # RFC 8985 §7.4.2: probe repaired a single
            # tail loss; the network signalled a real
            # loss event so apply the conventional
            # cwnd halving (ssthresh = max(flight/2,
            # 2*SMSS); cwnd = ssthresh).
            from pytcp.protocols.tcp.tcp__cwnd import compute_loss_event_ssthresh

            flight_size = (self._snd_seq.max - self._snd_seq.una) & 0xFFFF_FFFF
            self._cc.ssthresh = compute_loss_event_ssthresh(flight_size, self._win.snd_mss)
            self._cc.cwnd = self._cc.ssthresh
            self._cc.snd_ewn = min(self._cc.cwnd, self._win.snd_wnd)
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - RFC 8985 §7.4.2 TLP probe-repair "
                f"CC: ssthresh={self._cc.ssthresh} cwnd={self._cc.cwnd}",
            )
        if self._snd_seq.una == self._snd_seq.max:
            self._cancel_timer("retransmit")
            # RFC 8985 §7.2 TLP cancellation: when a
            # cum-ACK drains all in-flight bytes, there is
            # no tail to probe. Cancel the TLP timer so a
            # late expiry does not fire a stale probe.
            # Also clear the once-per-tail state so the
            # next tail can fire its own probe.
            self._cancel_timer("tlp")
            self._rack_tlp.cancel_tlp()
        else:
            self._arm_timer("retransmit", self._rto_state.rto_ms)
        self._phase2_frto_spurious_detect()

    def _phase2_frto_spurious_detect(self) -> None:
        """
        Phase 2 of the inbound-ACK pipeline. RFC 5682 §2.1 step 2
        / step 3 F-RTO spurious-RTO detection. Up to two post-RTO
        ACKs classify the RTO:

          step==1 (first post-RTO ACK):
            - SND.UNA covers all pre-RTO data (>= recover):
              single-ACK strong-spurious; restore and exit.
            - SND.UNA partially advances (still < recover):
              step 2b — defer decision to second ACK, set
              frto_step=2 and stay in F-RTO. PyTCP's existing
              _transmit_data flow naturally sends up to 2 new
              segments after this cum-ACK because cwnd was reset
              to 1 SMSS on RTO and slow-start grows it by 1 SMSS
              per ACK.
          step==2 (second post-RTO ACK):
            - SND.UNA advanced further: spurious declared per
              step 3b; restore and exit.
            - (dup-ACK paths are handled in the dup-ACK branch.)

        Caller MUST guard the invocation on cum-ACK advance
        (lt32(self._snd_seq.una, packet_rx_md.tcp__ack) was True at
        the top of phase 1) — F-RTO step transitions assume the
        ACK advances the window.

        Reference: RFC 5682 §2.1 step 2 (single-ACK strong-spurious).
        Reference: RFC 5682 §2.1 step 3b (two-ACK advancing path).
        Reference: RFC 9438 §4.9.1 (CUBIC F-RTO snapshot restore).
        """

        if not self._cc.frto_active:
            return
        fully_covered = not lt32(self._snd_seq.una, self._cc.frto_pre_snd_max)
        if self._cc.frto_step == 1:
            if fully_covered:
                # Single-ACK strong-spurious — restore.
                self._cc.frto_step = 0
                self._cc.frto_active = False
                self._cc.restore_frto_snapshot(snd_wnd=self._win.snd_wnd)
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - RFC 5682 F-RTO: spurious RTO "
                    f"detected, restored cwnd={self._cc.cwnd} "
                    f"ssthresh={self._cc.ssthresh}; "
                    f"RFC 9438 §4.9.1: restored cubic "
                    f"w_max={self._cc.cubic_w_max} "
                    f"K_ms={self._cc.cubic_K_ms}",
                )
            else:
                # Step 2b: partial advance, defer to step 3.
                self._cc.frto_step = 2
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - RFC 5682 §2.1 step 2b: "
                    f"partial first post-RTO ACK "
                    f"(SND.UNA={self._snd_seq.una} < recover="
                    f"{self._cc.frto_pre_snd_max}); waiting "
                    "for second ACK to declare spurious",
                )
        elif self._cc.frto_step == 2:
            # Second ACK that advances the window declares the
            # timeout spurious per §2.1 step 3b. We landed here
            # because the caller's cum-ACK advance gate was True;
            # that's the §2.1 "acknowledgment advances the window"
            # condition.
            self._cc.frto_step = 0
            self._cc.frto_active = False
            self._cc.restore_frto_snapshot(snd_wnd=self._win.snd_wnd)
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - RFC 5682 F-RTO: spurious RTO "
                f"detected, restored cwnd={self._cc.cwnd} "
                f"ssthresh={self._cc.ssthresh}; "
                f"RFC 9438 §4.9.1: restored cubic "
                f"w_max={self._cc.cubic_w_max} "
                f"K_ms={self._cc.cubic_K_ms}",
            )

    def _phase3_harvest_rtt_samples(self, packet_rx_md: TcpMetadata) -> None:
        """
        Phase 3 of the inbound-ACK pipeline. Harvest an RTT sample
        from the inbound ACK via either the RFC 7323 §4 TSecr path
        (preferred when bilateral TSopt is enabled — unambiguous
        even on retransmissions, obviating Karn's algorithm) or
        the RFC 6298 §4 sample-tracker path (Karn-gated). Either
        path also folds the observed RTT into HyStart++ state
        during slow-start so the per-round min-RTT trackers can
        drive the SS->CSS / CSS->SS transitions.

        Independent of cum-ACK advance: a dup-ACK that carries a
        new TSecr can still produce a valid RTT measurement.

        Reference: RFC 6298 §3 (Karn's algorithm).
        Reference: RFC 6298 §4 (RTO RTT-sample update).
        Reference: RFC 7323 §4 (TSecr-driven RTTM).
        Reference: RFC 9406 §4.2 (HyStart++ RTT fold).
        """

        # RFC 7323 §4 TSecr-driven RTTM: peer's TSecr identifies
        # the specific transmission it acknowledges, so the RTT
        # measurement is unambiguous even on retransmitted
        # segments (RFC 7323 §4 obviates Karn's algorithm).
        # When bilateral TSopt is enabled and peer's ACK carries
        # a non-zero TSecr that echoes one of our previous
        # TSvals, fold 'now_ms - tsecr' into '_rto_state' via
        # 'update'. This SUPERSEDES the Phase-2 sample tracker,
        # which would otherwise skip the harvest on Karn-
        # tainted samples. Clear the tracker after to prevent
        # double-folding.
        if self._ts.send_ts and packet_rx_md.tcp__tsecr is not None and packet_rx_md.tcp__tsecr != 0:
            ts_rtt_ms = (stack.timer.now_ms - packet_rx_md.tcp__tsecr) & 0xFFFF_FFFF
            self._rto_state = update(self._rto_state, ts_rtt_ms)
            # RFC 9406 §4.2: fold the RTT sample into HyStart
            # state during slow-start (or CSS) so the per-round
            # min-RTT trackers can drive the SS->CSS / CSS->SS
            # transitions. Skipped after slow-start exits
            # (cwnd >= ssthresh AND not in_css) — HyStart++ is a
            # slow-start-only mechanism.
            if self._cc.cwnd < self._cc.ssthresh or self._cc.hystart_state.in_css:
                fold_rtt_sample(self._cc.hystart_state, ts_rtt_ms)
                self._hystart_check_phase_transition()
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - RFC 7323 §4 TSecr-driven RTTM: "
                f"rtt={ts_rtt_ms} ms via TSecr="
                f"{packet_rx_md.tcp__tsecr}; rto_state="
                f"{self._rto_state}",
            )
            self._rtt.clear()

        # RFC 6298 §4 sample harvest: peer's cumulative ACK has
        # advanced past the seq of our pending RTT sample. Fold
        # the observed RTT into '_rto_state' iff the sample was
        # not retransmitted (Karn's algorithm, RFC 6298 §3); in
        # either case clear the tracker so the next outbound
        # segment can start a fresh sample. Modular 'gt32' so the
        # harvest fires correctly when both seq and ack straddle
        # the 32-bit wrap.
        if self._rtt.seq is not None and gt32(packet_rx_md.tcp__ack, self._rtt.seq):
            if not self._rtt.retransmitted:
                assert self._rtt.send_time_ms is not None
                observed_rtt_ms = stack.timer.now_ms - self._rtt.send_time_ms
                self._rto_state = update(self._rto_state, observed_rtt_ms)
                # RFC 9406 §4.2: see TSecr-fold note above; same
                # HyStart++ feed in the Karn-tracker harvest path.
                if self._cc.cwnd < self._cc.ssthresh or self._cc.hystart_state.in_css:
                    fold_rtt_sample(self._cc.hystart_state, observed_rtt_ms)
                    self._hystart_check_phase_transition()
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - RTT sample harvested: rtt={observed_rtt_ms} ms, " f"rto_state={self._rto_state}",
                )
            else:
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - RTT sample tainted by retransmit (Karn); " f"skipping update of {self._rto_state}",
                )
            self._rtt.clear()

    def _phase4_loss_detection_and_recovery_exit(self, packet_rx_md: TcpMetadata) -> None:
        """
        Phase 4 of the inbound-ACK pipeline. Fold the inbound ACK
        + SACK info into the RACK reorder-window state, prune the
        per-segment dict for entries fully covered by SND.UNA,
        and exit recovery if SND.UNA has reached or passed the
        RecoveryPoint marker.

        Reference: RFC 5681 §3.2 step 6 (cwnd = ssthresh on recovery exit).
        Reference: RFC 6675 §5 (RecoveryPoint sentinel).
        Reference: RFC 6937 §3.1 (PRR per-recovery state reset).
        Reference: RFC 8985 §5.2 (RACK per-segment dict pruning).
        Reference: RFC 8985 §6.2 (RACK fold + reo_wnd_persist decay).
        Reference: RFC 9438 §4.9.2 (FR-CUBIC snapshot scope = one episode).
        """

        # RFC 8985 §6.2 step 1-2 RACK fold + step 5 loss
        # detection. Run AFTER SACK ingest so the scoreboard
        # reflects the latest peer-reported state. Identical
        # invocation in '_retransmit_packet_request' for the
        # dup-ACK path.
        self._rack_process_ack(packet_rx_md)

        # RFC 8985 §5.2 RACK per-segment dict pruning. An entry's
        # 'end_seq' at or below SND.UNA is wholly covered by the
        # cumulative ACK - the segment has been delivered and is
        # no longer in flight. Modular 'le32' so the prune fires
        # correctly when both 'end_seq' and SND.UNA straddle the
        # 32-bit wrap. Phase 1 only ships the storage substrate;
        # Phase 2 onward consumes the dict for time-based loss
        # detection / RACK_sent_after / TLP probe selection. The
        # parallel '_rack_acked_seqs' set is pruned alongside so
        # a future segment that lands at the same seq (post-
        # wrap) is not falsely treated as already-acked.
        self._rack_tlp.prune_segments(snd_una=self._snd_seq.una)
        # Exit recovery once SND.UNA has advanced to or past the
        # RecoveryPoint marker (RFC 6675 §5). The loss event is
        # now fully recovered; subsequent dup-ACKs are eligible
        # to re-enter recovery via either trigger. RFC 5681 §3.2
        # step 6 mandates deflating cwnd back to ssthresh on
        # exit so the inflation from steps 3+4 is undone and
        # subsequent §3.1 growth resumes from the previously-
        # observed loss boundary.
        if self._cc.recovery_point != 0 and le32(self._cc.recovery_point, self._snd_seq.una):
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Exiting recovery: SND.UNA={self._snd_seq.una} "
                f"reached RecoveryPoint={self._cc.recovery_point}",
            )
            self._cc.cwnd = self._cc.ssthresh
            self._cc.snd_ewn = min(self._cc.cwnd, self._win.snd_wnd)
            self._cc.recovery_point = 0
            # RFC 9438 §4.9.2 snapshot is scoped to a single
            # recovery episode; clear on exit so a stray DSACK
            # post-recovery does not roll back unrelated state.
            self._cc.clear_fr_cubic_snapshot()
            # RFC 6937 §3.1 PRR: per-recovery state is scoped
            # to a single recovery episode. Reset on exit so
            # the next loss event snapshots a fresh
            # 'RecoverFS' and re-accumulates from zero.
            self._cc.recover_fs = 0
            self._cc.prr_delivered = 0
            self._cc.prr_out = 0
            # RFC 8985 §6.2 step 4 reo_wnd_persist decay. Each
            # recovery exit decrements the persist counter; on
            # reaching zero, the multiplier and persist counter
            # reset to their defaults so the connection
            # eventually decays back to the canonical reordering
            # tolerance after a long stretch of recoveries
            # without DSACK.
            self._rack_tlp.decay_reo_wnd_persist()

    def _phase5_consume_segment_and_postprocess(self, packet_rx_md: TcpMetadata) -> None:
        """
        Phase 5 of the inbound-ACK pipeline. Consume the inbound
        segment's data + window field, fire the delayed-ACK side-
        effects, purge stale TX-retransmit bookkeeping, and drain
        a queued out-of-order segment if 'rcv_nxt' has advanced
        across it. Last phase; reads everything settled by the
        earlier phases.

        Reference: RFC 9293 §3.4 (RCV.NXT advance protections).
        Reference: RFC 9293 §3.8.4 (snd_ewn = min(cwnd, snd_wnd)).
        Reference: RFC 9293 §3.8.6.1 (persist timer reset on reopen).
        Reference: RFC 9293 §3.10.7.4 (segment-arrives RCV.NXT update).
        Reference: RFC 1122 §4.2.3.2 (delayed-ACK every-other-segment).
        Reference: RFC 2883 §3 (DSACK detection / generation).
        Reference: RFC 5961 §5 (MAX.SND.WND running maximum).
        """

        # Adjust local SEQ accordingly to what peer acked (needed after the
        # retransmit happens and peer is jumping to previously received SEQ).
        if lt32(self._snd_seq.nxt, self._snd_seq.una) and le32(self._snd_seq.una, self._snd_seq.max):
            self._snd_seq.nxt = self._snd_seq.una
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
        if lt32(packet_rx_md.tcp__seq, self._rcv_seq.nxt):
            overlap_prefix = (self._rcv_seq.nxt - packet_rx_md.tcp__seq) & 0xFFFF_FFFF
        else:
            overlap_prefix = 0
        # RFC 2883 DSACK: stash the duplicate-prefix range so the
        # next outbound ACK reports it as the FIRST SACK block.
        # The range is '[seg_seq, seg_seq + overlap_prefix)' which
        # equals '[seg_seq, OLD RCV.NXT)' (RCV.NXT advances later).
        if self._advertise.send_sack and overlap_prefix > 0:
            self._pending_dsack = (
                packet_rx_md.tcp__seq,
                add32(packet_rx_md.tcp__seq, overlap_prefix),
            )
        # Modular 'max' on RCV.NXT: advance iff the segment's end
        # is ahead of our current RCV.NXT in modular order.
        if lt32(self._rcv_seq.nxt, seg_end):
            self._rcv_seq.nxt = seg_end
        # In case packet contains data enqueue it. RFC 1122 §4.2.3.2 governs
        # how we acknowledge it: count pending unacked segments since the
        # last ACK, force an inline ACK once two segments are pending
        # ("every other segment"), and otherwise arm the delayed-ACK
        # timer so the ACK fires within tcp__constants.DELAYED_ACK_DELAY rather than
        # immediately. Arming the timer here (rather than only inside
        # '_transmit_packet') ensures the FIRST inbound data segment
        # after the handshake is properly delayed - without this, the
        # delayed-ACK timer would not yet be armed in '_timer_deadlines'
        # (the third-leg ACK was emitted from within SYN_SENT, which
        # does not arm the timer), so the held ACK would not be
        # deferred and an immediate ACK would slip out.
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
                    f"[{self}] - Sent inline ACK (every-other-segment, {self._rcv_seq.nxt})",
                )
            else:
                # First pending segment: ensure the delayed-ACK timer is
                # armed so the timer-driven '_delayed_ack' will fire the
                # ACK after tcp__constants.DELAYED_ACK_DELAY rather than immediately.
                self._arm_timer("delayed_ack", tcp__constants.DELAYED_ACK_DELAY)
        # Purge acked data from TX buffer.
        with self._lock__tx_buffer:
            self._tx.drain(bytes_count=self._tx_buffer_una)
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - Purged TX buffer up to SEQ {self._snd_seq.una}",
        )
        # Update remote window size.
        if self._win.snd_wnd != packet_rx_md.tcp__win << self._win.snd_wsc:
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Updated sending window size {self._win.snd_wnd} -> "
                f"{packet_rx_md.tcp__win << self._win.snd_wsc}",
            )
            self._win.snd_wnd = packet_rx_md.tcp__win << self._win.snd_wsc
            # RFC 9293 §3.8.4: '_snd_ewn = min(cwnd, snd_wnd)'.
            # Recompute when peer's advertised window changes so
            # the wire-level transmit gate sees a coherent
            # min(cwnd, snd_wnd) regardless of which side just
            # moved.
            self._cc.snd_ewn = min(self._cc.cwnd, self._win.snd_wnd)
        # RFC 5961 §5 'MAX.SND.WND': running maximum of peer's
        # advertised window. Used as the lower-bound tolerance
        # for ACK acceptability ('SND.UNA - MAX.SND.WND <=
        # SEG.ACK <= SND.NXT').
        self._win.bump_max_window(snd_wnd=self._win.snd_wnd)
        # If peer has reopened their receive window, deactivate the
        # persist timer and reset the back-off interval so the next
        # zero-window event starts fresh at the initial RTO
        # (RFC 9293 §3.8.6.1).
        if self._win.snd_wnd > 0 and self._persist.active:
            __debug__ and log("tcp-ss", f"[{self}] - Persist: peer reopened window, deactivating timer")
            self._persist.deactivate(initial_timeout=tcp__constants.PACKET_RETRANSMIT_TIMEOUT)
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - cwnd={self._cc.cwnd} ssthresh={self._cc.ssthresh} snd_ewn={self._cc.snd_ewn}",
        )
        # Purge expired tx packet retransmit requests. Modular '<'
        # via 'lt32' so entries near the 32-bit wrap are dropped
        # correctly when SND.UNA advances past them.
        for seq in list(self._tx.retransmit_request_counter):
            if lt32(seq, packet_rx_md.tcp__ack):
                self._tx.retransmit_request_counter.pop(seq)
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - Purged expired TX packet retransmit request counter for {seq}",
                )
        # Bring next packet from ooo_packet_queue if available.
        if ooo_packet := self._ooo_packet_queue.pop(self._rcv_seq.nxt, None):
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - <lg>Retrieving packet {self._rcv_seq.nxt} from Out of Order queue</>",
            )
            self.tcp_fsm(ooo_packet)

    def tcp_fsm(
        self,
        packet_rx_md: TcpMetadata | None = None,
        syscall: SysCall | None = None,
        timer: bool | None = None,
        icmp: IcmpMetadata | None = None,
    ) -> None:
        """
        Run TCP finite state machine.
        """

        with self._lock__fsm:
            # Phase 4c: snapshot the state before any dispatch so
            # the tail can detect a transition and arm the
            # 'tx_pump' FSM-pump (§5.6/§5.7).
            state_at_entry = self._state

            # Phase 2 of the ICMP-into-FSM refactor: 'icmp' is
            # dispatched through 'FSM_ICMP_HANDLERS' to the per-state
            # handler carrying RFC 5927 §5.2 hard-vs-soft semantics
            # (synchronized states downgrade hard errors to soft;
            # SYN_SENT is the only state allowed to abort).
            if icmp is not None:
                tcp_fsm_dispatch_icmp(self, icmp)
                self._pump_tail(state_at_entry, True)
                return

            # RFC 3168 §6.1.2 / §6.1.3 receiver-side CE echo
            # tracking. Run BEFORE the FSM dispatch so the
            # state-handler-emitted ACK on this segment already
            # carries ECE, and the sender's CWR confirmation
            # observed on the same segment clears the flag.
            if self._ecn.enabled and packet_rx_md is not None:
                if packet_rx_md.tcp__flag_cwr:
                    self._ecn.send_ece = False
                if packet_rx_md.ip__ecn == 3:
                    self._ecn.send_ece = True
            # RFC 9768 §3.2.2 / §3.2.3 receiver-side counter
            # accumulation: r.cep packet counter on CE, plus
            # per-codepoint byte counters from the TCP payload.
            # All counters wrap modulo 2^24 per the option width.
            if self._accecn.enabled and packet_rx_md is not None:
                self._accecn.record_received_codepoint(
                    ip_ecn=packet_rx_md.ip__ecn,
                    payload_len=len(packet_rx_md.tcp__data),
                )
            # RFC 3168 §6.1.2 sender-side response to inbound
            # ECE. Halve ssthresh per RFC 5681 §3.1, collapse
            # cwnd to ssthresh, and arm '_ecn_send_cwr' so the
            # next outbound data segment confirms the response
            # via CWR. One-shot per RTT: '_ecn_recovery_point'
            # = SND.NXT at the moment of response; subsequent
            # ECEs within the same window of data are ignored
            # until SND.UNA crosses the recovery point.
            if (
                self._ecn.enabled
                and packet_rx_md is not None
                and packet_rx_md.tcp__flag_ece
                and (self._ecn.recovery_point == 0 or le32(self._ecn.recovery_point, self._snd_seq.una))
            ):
                flight_size = sub32(self._snd_seq.max, self._snd_seq.una)
                # RFC 8511 ABE: ECN signals early-warning
                # congestion (no actual loss yet); reduce
                # ssthresh by the less-aggressive 0.85
                # multiplier instead of the 0.5 used for
                # genuine packet-loss events.
                self._cc.ssthresh = compute_ecn_event_ssthresh(flight_size, self._win.snd_mss)
                self._cc.cwnd = self._cc.ssthresh
                self._cc.snd_ewn = min(self._cc.cwnd, self._win.snd_wnd)
                self._ecn.arm_cwr_response(snd_nxt=self._snd_seq.nxt)
            # RFC 9768 §3.4 sender-side response to AccECN
            # feedback. When the peer's inbound AccECN option
            # reports an r.CE byte counter higher than our
            # tracked value, treat the delta as a single
            # congestion event: halve ssthresh per RFC 5681
            # §3.1, collapse cwnd to ssthresh, and update the
            # tracker so subsequent ACKs reporting the same
            # cumulative count are idempotent. The same
            # one-shot recovery-point guard the RFC 3168
            # path uses prevents multiple AccECN events
            # within a single RTT from compounding the
            # reduction.
            if (
                self._accecn.enabled
                and packet_rx_md is not None
                and packet_rx_md.tcp__accecn0_counters is not None
                and packet_rx_md.tcp__accecn0_counters[1] is not None
                and packet_rx_md.tcp__accecn0_counters[1] > self._accecn.s_ce_b
                and (self._ecn.recovery_point == 0 or le32(self._ecn.recovery_point, self._snd_seq.una))
            ):
                flight_size = sub32(self._snd_seq.max, self._snd_seq.una)
                # RFC 8511 ABE: same as the RFC 3168 ECN path
                # above - on ECN-class events the sender uses
                # the less-aggressive 0.85 multiplier rather
                # than the 0.5 reserved for genuine packet
                # loss events.
                self._cc.ssthresh = compute_ecn_event_ssthresh(flight_size, self._win.snd_mss)
                self._cc.cwnd = self._cc.ssthresh
                self._cc.snd_ewn = min(self._cc.cwnd, self._win.snd_wnd)
                self._ecn.recovery_point = self._snd_seq.nxt
            # RFC 9768 §3.2.1 sender-side counter mirrors. Update
            # s.e0b / s.ce_b / s.e1b from the inbound option's
            # populated slots (per-slot None per the §3.2.3
            # abbreviation rule). Done outside the cwnd-response
            # gate above so the trackers advance even when the
            # recovery-point guard suppresses the response.
            if self._accecn.enabled and packet_rx_md is not None and packet_rx_md.tcp__accecn0_counters is not None:
                self._accecn.update_sender_counters_from_option(packet_rx_md.tcp__accecn0_counters)
            # RFC 9768 §3.2.2.5 ACE-based fallback. When an
            # AccECN-mode inbound ACK arrives WITHOUT the
            # AccECN option (e.g. a middlebox stripped it),
            # the byte-counter path above cannot detect new
            # CE marks. As a fallback, decode the ACE field
            # from the AE+CWR+ECE flags and compare to the
            # prior 's.cep & 7' value: a positive delta is
            # the apparent CE-marked-segment count since the
            # last seen ACE. If positive, treat as a
            # congestion event (gated by the same one-shot
            # recovery-point guard the byte-counter path
            # uses, so concurrent firing of both paths within
            # one RTT is harmless). The wrap-aware §3.2.2.5.2
            # safest-likely-case correction is omitted here:
            # for typical Internet workloads the option is
            # rarely stripped, so the apparent delta is
            # almost always the true delta; the simpler
            # detection captures the common case without
            # the over-aggressive wrap-correction risk.
            if (
                self._accecn.enabled
                and packet_rx_md is not None
                and packet_rx_md.tcp__accecn0_counters is None
                and not packet_rx_md.tcp__flag_syn
            ):
                incoming_ace = (
                    (int(packet_rx_md.tcp__flag_ns) << 2)
                    | (int(packet_rx_md.tcp__flag_cwr) << 1)
                    | int(packet_rx_md.tcp__flag_ece)
                )
                apparent_delta = self._accecn.apparent_ce_delta(incoming_ace)
                if apparent_delta > 0 and (
                    self._ecn.recovery_point == 0 or le32(self._ecn.recovery_point, self._snd_seq.una)
                ):
                    flight_size = sub32(self._snd_seq.max, self._snd_seq.una)
                    self._cc.ssthresh = compute_ecn_event_ssthresh(flight_size, self._win.snd_mss)
                    self._cc.cwnd = self._cc.ssthresh
                    self._cc.snd_ewn = min(self._cc.cwnd, self._win.snd_wnd)
                    self._ecn.recovery_point = self._snd_seq.nxt
            # Route to the per-event-kind dispatcher.
            # 'tcp_fsm()' is invoked with exactly one of the
            # three kwargs set; pick the matching dispatcher.
            if packet_rx_md is not None:
                tcp_fsm_dispatch_packet(self, packet_rx_md)
            elif syscall is not None:
                tcp_fsm_dispatch_syscall(self, syscall)
            elif timer:
                tcp_fsm_dispatch_timer(self)

            self._pump_tail(state_at_entry, packet_rx_md is not None or syscall is not None)
