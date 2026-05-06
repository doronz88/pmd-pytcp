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
from net_proto.protocols.tcp.tcp__header import TCP__MIN_MSS
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.tcp import tcp__constants
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
    initial_window,
)
from pytcp.protocols.tcp.tcp__enums import (
    CcMode,
    ConnError,
    FsmState,
    SysCall,
)
from pytcp.protocols.tcp.tcp__errors import TcpSessionError
from pytcp.protocols.tcp.tcp__fsm import dispatch_packet as tcp_fsm_dispatch_packet
from pytcp.protocols.tcp.tcp__fsm import dispatch_syscall as tcp_fsm_dispatch_syscall
from pytcp.protocols.tcp.tcp__fsm import dispatch_timer as tcp_fsm_dispatch_timer
from pytcp.protocols.tcp.tcp__iss import compute_iss
from pytcp.protocols.tcp.tcp__loss_recovery import is_lost, next_seg, pipe
from pytcp.protocols.tcp.tcp__rack import (
    RackSegment,
    rack_compute_reo_wnd,
    rack_detect_loss,
    rack_update,
    tlp_calc_pto,
    tlp_process_ack,
)
from pytcp.protocols.tcp.tcp__rto import RtoState, back_off, initial_state, update
from pytcp.protocols.tcp.tcp__sack import SackScoreboard
from pytcp.protocols.tcp.tcp__seq import Seq32, add32, ge32, gt32, in_range32, le32, lt32, sub32

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
        # exact-RTT measurements per RFC 7323 §4. See
        # 'docs/rfc/tcp/rfc7323__timestamps_wscale_paws/adherence.md'
        # for the per-clause spec audit.
        self._advertise_ts: bool = True
        self._send_ts: bool = False
        self._ts_recent: int = 0

        # RFC 7323 §5.5 outdated-timestamps mitigation.
        # Stamps the local monotonic clock value (ms) at
        # which '_ts_recent' was last updated. Used by the
        # PAWS check to detect when the connection has been
        # idle long enough that a strict 'lt32' comparison
        # would freeze a recovering session: per §5.5 the
        # 'TS.Recent' value MUST be invalidated when more
        # than 24 days have elapsed without an update so a
        # stale-but-actually-fresh TSval can be accepted.
        # Initialised to 0 (which the §5.5 helper treats as
        # 'never updated' - the outdated check requires a
        # non-zero baseline before it can fire).
        self._ts_recent_updated_at_ms: int = 0

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

        # RFC 6582 §3.2 step 4: the highest SND.MAX recorded at
        # the most recent RTO boundary. The fast-retransmit
        # entry gate in '_retransmit_packet_request' refuses to
        # enter recovery while 'SND.UNA <= _recover_seq', so
        # post-RTO dup-ACKs from the retransmit storm cannot
        # spuriously re-trigger fast retransmit before the
        # cum-ACK has progressed past the marker. Cleared (back
        # to the sentinel 0) once SND.UNA advances past it; the
        # 0 sentinel disables the gate entirely on a fresh
        # connection so the very first loss event can enter FR
        # without an artificial barrier.
        self._recover_seq: Seq32 = 0

        # RFC 7413 §3.1 Fast Open server-side state. When peer's
        # passive-open SYN carries the TFO option, the LISTEN
        # handler generates a cookie and stashes it here so the
        # SYN+ACK we emit on the next tick carries it back. The
        # field is consumed (cleared back to None) by
        # '_transmit_packet' once the SYN+ACK fires so a SYN+ACK
        # retransmit does not re-issue a stale cookie.
        self._fastopen_cookie_to_emit: bytes | None = None

        # RFC 7413 §4.2 PendingFastOpenRequests bookkeeping: True
        # iff this session was accepted via TFO and counted into
        # 'stack.tcp__fastopen_pending_count'. Cleared by the
        # exit hook in '_change_state' when this session leaves
        # SYN_RCVD, with a matching counter decrement so the
        # global gauge tracks live TFO-accepted handshakes only.
        self._fastopen_pending_counted: bool = False

        # RFC 7413 §4.4 SYN retransmit without TFO. When the
        # SYN timer fires on an active-open TFO connection,
        # the next attempt MUST drop the TFO option and any
        # SYN-data so the second attempt is a plain 3WHS. The
        # flag is set by the SYN-RTO path the first time the
        # active-open SYN re-fires; '_transmit_packet' reads
        # it to suppress the TFO option emission.
        self._fastopen_syn_retransmitted: bool = False

        # RFC 7413 §3.1 Fast Open client-side opt-out flag.
        # Defaults to True so active-open SYNs carry the TFO
        # option in the cookie-request form (empty cookie),
        # eliciting cookie issuance from the server. Mirrors
        # the '_advertise_sack' / '_advertise_ts' /
        # '_advertise_wscale' bilateral-negotiation pattern.
        # Applications that need to suppress TFO on outbound
        # SYNs (interop with broken middleboxes, restricted
        # buffer profiles, etc.) flip this to False before
        # 'CONNECT'.
        self._advertise_fastopen: bool = True

        # RFC 3168 §6.1.1 Explicit Congestion Notification
        # opt-out flag. Defaults to True so the active-open
        # SYN carries ECE+CWR (the canonical ECN-setup
        # signal) and the passive-open SYN+ACK echoes ECE
        # only (ECN-Echo confirmation). Applications that
        # need to suppress ECN on outbound SYNs (interop
        # with broken middleboxes that drop ECT-marked
        # packets) flip this to False before 'CONNECT' /
        # 'LISTEN'.
        self._advertise_ecn: bool = True

        # RFC 9768 §3.1.1 AccECN advertise opt-out flag. When
        # True (default), the active-open SYN carries AE+CWR+ECE
        # (the canonical AccECN-setup signal); when False, the
        # SYN falls back to the RFC 3168 CWR+ECE form if
        # '_advertise_ecn' is also True. AccECN takes precedence
        # over RFC 3168 in negotiation: an AccECN-capable peer
        # responds with one of four AE/CWR/ECE codepoints
        # encoding the IP-ECN it received on our SYN, and the
        # session locks in '_accecn_enabled = True'. A peer that
        # does not understand AccECN responds with the RFC 3168
        # ECE-only form, and the session falls back to classic
        # ECN ('_ecn_enabled = True'). The two flags are
        # mutually exclusive post-handshake.
        self._advertise_accecn: bool = True

        # RFC 3168 §6.1.1 ECN bilateral-success flag.
        # Set True post-handshake when both sides advertised
        # ECN support. While True, outbound data carries IP
        # ECT(0), inbound CE marks are echoed via ECE on the
        # next outbound segment, and inbound ECE triggers
        # cwnd reduction per §6.1.2.
        self._ecn_enabled: bool = False

        # RFC 9768 §3.1.1 AccECN bilateral-success flag. Set
        # True post-handshake when the peer's SYN+ACK carried
        # one of the four AccECN-capable codepoints (AE=1 OR
        # CWR=1, with ECE varying per the IP-ECN of the
        # received SYN). Mutually exclusive with
        # '_ecn_enabled'.
        self._accecn_enabled: bool = False

        # RFC 9768 §3.1.1 passive-side codepoint capture. When
        # an AccECN-setup SYN arrives at LISTEN, the listener
        # captures the IP-ECN codepoint of the received SYN
        # here so '_transmit_packet' can encode it as the
        # corresponding AE/CWR/ECE codepoint on the outbound
        # SYN+ACK. Values: 0=Not-ECT, 1=ECT(1), 2=ECT(0),
        # 3=CE. Unused on the active-open side.
        self._accecn_synack_codepoint: int = 0

        # RFC 9768 §3.2.2.1 active-side handshake ACE encoding.
        # On the active-open client, when an AccECN-confirming
        # SYN+ACK arrives, the SYN_SENT handler stores the
        # Table-3 ACE value (derived from the SYN+ACK's
        # IP-ECN codepoint) here so the third-leg ACK encodes
        # it instead of the regular 'r.cep & 7' value. Cleared
        # by '_transmit_packet' once consumed - subsequent
        # post-handshake ACKs use the regular encoding. None
        # means no handshake-encoded ACK is pending.
        self._accecn_handshake_ack_pending: int | None = None

        # RFC 9768 §3.2.2 receiver-side r.cep counter. Tracks
        # the cumulative count of CE-marked inbound segments
        # (modulo 2^24 per the option counter width). The low
        # 3 bits encode the ACE field on every outbound non-
        # SYN segment as: bit2 -> AE, bit1 -> CWR, bit0 -> ECE.
        # Initial value is 5 (binary 101) per §3.2.2.1, which
        # distinguishes a freshly-negotiated AccECN session
        # from value 0 (which has special meaning in some
        # corner cases). Increments by 1 on each inbound
        # segment with IP-ECN codepoint CE (3).
        self._accecn_r_cep: int = 5

        # RFC 9768 §3.2.3 receiver-side per-codepoint TCP-
        # payload byte counters. Each counter accumulates the
        # cumulative byte count of TCP payload received in
        # segments carrying the corresponding IP-ECN
        # codepoint, modulo 2^24 per the AccECN option's
        # counter width. The three counters are emitted in
        # the AccECN0 option (kind=172) on every outbound
        # non-SYN segment so the sender can compute precise
        # per-codepoint deltas across ACKs. r.e0b and r.e1b
        # initialise to 1 (not 0) per §3.2.1 so a freshly
        # negotiated session is distinguishable from
        # middlebox-zeroed fields; r.ceb initialises to 0
        # because zero CE marks at connection start is the
        # expected steady state.
        self._accecn_r_ect0_b: int = 1
        self._accecn_r_ce_b: int = 0
        self._accecn_r_ect1_b: int = 1

        # RFC 9768 §3.2.3 last-emit tracker for the §3.2.3
        # order choice (AccECN0 vs AccECN1). At each outbound
        # AccECN option emission the session compares the
        # current 'r.ECT(0)' / 'r.ECT(1)' byte counters
        # against the last-emitted values to decide which
        # codepoint changed since last emission, and picks
        # the order that puts the changed counter in the
        # first slot. Initial values match the §3.2.1
        # initial counter values so a freshly-negotiated
        # session sees no change on its first emission.
        # Sentinel '-1' is outside the uint24 range of the real
        # byte counters, so the very first AccECN-option emission
        # always sees 'changed' for all three slots and emits the
        # full Length=11 form to seed the peer with our initial
        # state. Subsequent emissions track real deltas and may
        # abbreviate to Length 8/5/2.
        self._accecn_r_last_emit_e0b: int = -1
        self._accecn_r_last_emit_ceb: int = -1
        self._accecn_r_last_emit_e1b: int = -1

        # RFC 9768 §3.2.1 / §3.2.2.1 sender-side counters.
        # 's.cep' tracks the peer's r.cep value as inferred
        # from the third-leg ACK's ACE field per Table 4 (in
        # SYN-RCVD) and from each subsequent ACK's regular
        # ACE delta (in ESTABLISHED). Initial value is 5 per
        # §3.2.1; Table 4 sets it to 5 or 6 depending on the
        # IP-ECN codepoint the SYN/ACK arrived with.
        # 's.disabled' is the §3.2.2.1 Note 1 sentinel: when
        # the third-leg ACK arrives with ACE=000, the server
        # MUST NOT set ECT on outgoing packets and MUST NOT
        # respond to AccECN feedback for the rest of the
        # connection (it remains an AccECN-feedback-emitting
        # Data Receiver, just not a Data Sender that responds
        # to feedback).
        self._accecn_s_cep: int = 5
        self._accecn_s_disabled: bool = False

        # RFC 9768 §3.2.2.3 IP-ECN mangling detector. Set
        # True when the IP-ECN codepoint peer reports
        # observing on our handshake-leg segment (SYN for
        # client, SYN/ACK for server) does not match the
        # Not-ECT we actually sent per RFC 3168 §6.1.1. PyTCP
        # always emits Not-ECT (codepoint 0) on SYN /
        # SYN/ACK, so any peer-reported codepoint other than
        # Not-ECT is an 'invalid transition' per §3.2.2.3.
        # The flag is purely observational at present - PyTCP
        # currently does not gate outbound ECT marking on it
        # (the §3.1.5 'Sending ECT' clause is not wired into
        # the TX-side ip__ecn gate yet); future work will
        # consume this flag to disable ECT emission on
        # mangled paths while keeping AccECN feedback
        # responsive per the §3.2.2.3 advisory.
        self._accecn_mangling_detected: bool = False

        # RFC 9768 §3.2.1 sender-side per-codepoint byte
        # counters. 's.e0b' / 's.e1b' track the peer's r.e0b /
        # r.e1b values as carried in the AccECN option's byte-
        # count slots; both initialise to 1 per §3.2.1 to
        # match the receiver-side initial values, so the first
        # delta computed against an inbound option is computed
        # off the correct baseline. PyTCP does not currently
        # consume these counters for cwnd response (only the
        # CE counter drives §3.4 reduction), but tracking them
        # is the §3.2.1 mandate and provides the substrate for
        # future L4S/DCTCP-style fine-grained congestion
        # control.
        self._accecn_s_ect0_b: int = 1
        self._accecn_s_ect1_b: int = 1

        # RFC 9768 §3.4 sender-side r.CE tracker. Holds the
        # last peer-reported r.CE byte counter seen in an
        # inbound AccECN option. The 'tcp_fsm' wrapper compares
        # the newly-arrived value against this tracker; a
        # positive delta is the wire signal for a congestion
        # event and triggers the standard RFC 5681 §3.1
        # cwnd-halving response. Updated to the new value
        # after the response so subsequent ACKs reporting the
        # same cumulative count are idempotent.
        self._accecn_s_ce_b: int = 0

        # RFC 5682 F-RTO (Forward RTO-Recovery) state. When an
        # RTO fires, '_frto_active' is set True and the
        # pre-RTO cwnd/ssthresh/SND.MAX are snapshotted before
        # the conventional RFC 5681 §3.1 halving. When the
        # first post-RTO ACK advances SND.UNA to cover the
        # snapshotted SND.MAX (the spurious-RTO signature -
        # all pre-RTO data was delivered), the snapshot is
        # restored and '_frto_active' clears. When the first
        # post-RTO ACK does not cover the snapshotted SND.MAX
        # (genuine RTO - data really was lost),
        # '_frto_active' clears without restoration.
        self._frto_active: bool = False
        self._frto_pre_cwnd: int = 0
        self._frto_pre_ssthresh: int = 0
        self._frto_pre_snd_max: int = 0
        # RFC 5682 §2.1 step tracker. 0 = not in F-RTO; 1 =
        # post-RTO step 1 done, waiting for first post-RTO ACK
        # (step 2); 2 = step 2b entered (partial first ACK),
        # waiting for second ACK (step 3). The step tracker
        # supports the two-ACK spurious-detection sequence
        # (partial-then-advancing) that the prior one-step
        # simplification missed: PyTCP previously cleared
        # '_frto_active' on the first ACK regardless of
        # outcome, so a second ACK could not retroactively
        # declare spurious. The step tracker also drives the
        # already-in-RTO gate (§2.1 step 1's "if recover >=
        # SND.UNA, skip step 2"): a second RTO firing while
        # step != 0 only updates the recover marker without
        # overwriting the original pre-RTO cwnd / ssthresh
        # snapshot, so the eventual restoration sees the
        # genuine pre-loss anchor.
        self._frto_step: int = 0
        # RFC 9438 §4.9.1 CUBIC spurious-timeout state
        # snapshot. Captured alongside the cwnd / ssthresh /
        # SND.MAX snapshot in '_retransmit_packet_timeout',
        # restored alongside them in '_process_ack_packet'
        # when the first post-RTO ACK covers the
        # snapshotted SND.MAX (the spurious signature).
        # Without restoring these the cubic curve would stay
        # anchored at the artificially-reduced W_max even
        # after cwnd is restored, degrading post-recovery
        # throughput.
        self._frto_pre_cubic_w_max: int = 0
        self._frto_pre_cubic_K_ms: int = 0
        self._frto_pre_cubic_epoch_start_ms: int = 0
        self._frto_pre_cubic_w_est: int = 0

        # RFC 9438 §4.9.2 spurious-fast-retransmit state restore.
        # When fast-retransmit fires, snapshot the CUBIC state so a
        # subsequent DSACK observation in the same recovery
        # episode (proving the retransmit was spurious) can roll
        # back W_max / K / epoch_start / W_est to their pre-FR
        # values. Mirrors the F-RTO snapshot pattern; the snapshot
        # is gated by '_fr_cubic_snapshot_valid' so a DSACK
        # outside a recovery episode does not spuriously restore.
        self._fr_pre_cubic_w_max: int = 0
        self._fr_pre_cubic_K_ms: int = 0
        self._fr_pre_cubic_epoch_start_ms: int = 0
        self._fr_pre_cubic_w_est: int = 0
        self._fr_pre_cwnd: int = 0
        self._fr_pre_ssthresh: int = 0
        self._fr_cubic_snapshot_valid: bool = False

        # RFC 3168 §6.1.2 receiver-side CE-echo flag. Set True
        # when an inbound segment arrives with the IP CE
        # codepoint ('11' = 3); every subsequent outbound TCP
        # segment carries the ECE flag as the wire echo back to
        # the sender. Cleared when the sender confirms cwnd
        # reduction by setting CWR on a subsequent segment
        # (RFC 3168 §6.1.3 - the "ECN-Echo flag is set in the
        # ACKs of all subsequent segments until receipt of a
        # segment with the CWR flag set"-style behaviour).
        self._send_ece: bool = False

        # RFC 3168 §6.1.2 sender-side state. '_ecn_send_cwr'
        # is set after responding to an inbound ECE (cwnd /
        # ssthresh halved); the next outbound data segment
        # carries the CWR flag as the wire confirmation,
        # then the flag clears. '_ecn_recovery_point' is the
        # one-shot guard: SND.NXT at the moment of the ECE
        # response; subsequent ECEs are ignored until SND.UNA
        # crosses this point so a single congestion episode
        # halves cwnd at most once per RTT.
        self._ecn_send_cwr: bool = False
        self._ecn_recovery_point: int = 0

        # RFC 6937 PRR per-recovery state. Declared with
        # canonical defaults so the [FLAGS BUG] tests-first
        # suite can exercise the attribute access; the actual
        # send-pacing logic (replacing RFC 5681 §3.2 step 4
        # 'cwnd += SMSS per dup-ACK') is wired by the PRR
        # implementation commit.
        #   _recover_fs:    snapshot of pipe (FlightSize) at
        #                   recovery entry; zero outside recovery.
        #   _prr_delivered: cumulative bytes ACK'd / SACK'd
        #                   during the current recovery episode.
        #   _prr_out:       cumulative bytes sent during the
        #                   current recovery episode.
        # All three reset to zero on recovery exit (when SND.UNA
        # crosses '_recovery_point') so the next loss event
        # snapshots a fresh value.
        self._recover_fs: int = 0
        self._prr_delivered: int = 0
        self._prr_out: int = 0

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

        # RFC 8985 §5.2 RACK per-segment xmit_ts dict, keyed by
        # the segment's starting seq. Populated by
        # '_transmit_packet' for every outbound segment that
        # consumes sequence space (data / SYN / FIN); pruned by
        # '_process_ack_packet' on cum-ACK that covers the
        # entry's 'end_seq'. Phase 1 of the RACK-TLP project
        # ships only the storage substrate; subsequent phases
        # consume it for time-based loss detection (§6.2 step
        # 5), reorder-window adaptation (§6.2 steps 3-4), and
        # TLP probe-segment selection (§7.3).
        self._rack_segments: dict[Seq32, RackSegment] = {}

        # RFC 8985 §5.3 / §6.2 step 1-2 RACK per-connection
        # scalars. Updated by 'rack_update' on every accepted
        # ACK whose cumulative-ACK boundary newly covers
        # segments in '_rack_segments'. Phase 2 of the RACK-TLP
        # project wires the update; subsequent phases consume:
        #   - '_rack_min_rtt_ms' as the lower bound for the
        #     RFC 8985 §6.2 step 2 spurious-retransmit
        #     heuristic and as a floor for the §6.2 step 4
        #     reordering-window calculation.
        #   - '_rack_rtt_ms' as the freshest accepted-sample
        #     RTT, used in §6.2 step 5's loss-detection
        #     timeout formula.
        #   - '_rack_xmit_ts' / '_rack_end_seq' as the latest
        #     'sent_after' lexicographic-key pair, used to
        #     test whether each in-flight segment's xmit_ts is
        #     'before' the most recent successful delivery
        #     (the §6.2 step 5 'rack_sent_after' branch).
        # All four are 0 on a fresh session - the
        # uninitialized sentinel - and remain 0 until the
        # first newly-acked segment is observed.
        self._rack_min_rtt_ms: int = 0
        self._rack_rtt_ms: int = 0
        self._rack_xmit_ts: int = 0
        self._rack_end_seq: Seq32 = 0
        # RFC 8985 §6.2 step 1-2 'newly acknowledged' guard.
        # rack_update only takes RTT samples from segments that
        # have not been folded yet on a prior ACK; an entry is
        # added to '_rack_acked_seqs' once it has contributed
        # to the rack_update scalars and removed when the
        # entry is pruned from '_rack_segments' on cum-ACK.
        # Distinct from cumulative-ACK pruning so SACK-acked
        # segments (covered by the SACK scoreboard but not yet
        # by SND.UNA) are tracked here even while their dict
        # entry stays alive.
        self._rack_acked_seqs: set[Seq32] = set()
        # RFC 8985 §6.2 step 3 reordering detection state.
        # 'reordering_seen' becomes True the first time an ACK
        # delivers a segment whose 'end_seq' is strictly below
        # 'fack' (the highest end_seq cumulatively or
        # selectively acked so far) - that out-of-order
        # delivery is the signal that the network has
        # reordered. Once seen, it stays True for the lifetime
        # of the connection: the §6.2 step 4 reo_wnd
        # computation switches from 0 (use dup-ACK trigger)
        # to 'min_RTT / 4 * reo_wnd_mult' (use time-based
        # trigger with reordering tolerance).
        self._rack_reordering_seen: bool = False
        self._rack_fack: Seq32 = 0
        # RFC 8985 §6.2 step 4 reo_wnd_mult / persist counter.
        # The multiplier scales the 'min_RTT / 4' base when
        # DSACK indicates spurious retransmits (the peer
        # received a segment we thought was lost). The
        # persist counter decrements on each recovery exit
        # and resets the multiplier to 1 after 16 consecutive
        # recoveries without DSACK, so the connection
        # eventually decays back to the canonical reordering
        # tolerance.
        self._rack_reo_wnd_mult: int = 1
        self._rack_reo_wnd_persist: int = 16
        # RFC 8985 §6.2 step 4 DSACK-round marker. Holds the
        # SND.MAX value at the moment a DSACK was observed; the
        # next ACK that advances SND.UNA past this marker
        # closes the round and increments 'reo_wnd_mult'.
        # 'None' means no DSACK round is in progress.
        self._rack_dsack_round: Seq32 | None = None
        # RFC 8985 §7 Tail Loss Probe state. The TLP timer
        # 'f"{self}-tlp"' is armed on every outbound data
        # segment send when no recovery is in progress, and
        # cancelled on cum-ACK that drains all in-flight
        # bytes. When the timer fires, the §7.3 probe-emission
        # path sends a probe (new data preferred, retransmit
        # of highest-seq fallback) to elicit an ACK that lets
        # RACK detect tail-of-flow losses much faster than
        # the RTO timer.
        #
        # '_tlp_is_retrans' marks whether the most recent
        # probe was a retransmit (rather than new data); the
        # §7.4 loss-detection path uses this to decide
        # whether to invoke the CC response.
        # '_tlp_end_seq' is the SND.MAX value at the moment
        # the probe was sent; cleared by the §7.4 detection
        # logic once the probe outcome is determined.
        # '_tlp_max_ack_delay_ms' is the receiver's delayed-
        # ACK upper bound, used by the §7.2 PTO inflation
        # path. Linux defaults to 25 ms.
        self._tlp_is_retrans: bool = False
        self._tlp_end_seq: Seq32 | None = None
        self._tlp_max_ack_delay_ms: int = 25
        # Gate the _tlp_pto_tick firing on actual arming. Set
        # True when '_transmit_packet' registers an
        # 'f"{self}-tlp"' timer; reset False once the probe
        # fires or the timer is cancelled. Distinct from
        # 'stack.timer.is_expired' which conflates "expired"
        # with "never registered".
        self._tlp_armed: bool = False

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

        # RFC 5961 §5 'MAX.SND.WND': the largest 'snd_wnd' value
        # ever observed from peer. Used as the lower-bound
        # tolerance for ACK acceptability ('SND.UNA - MAX.SND.WND
        # <= SEG.ACK <= SND.NXT'); ACKs below 'SND.UNA -
        # MAX.SND.WND' are blind-injected very-stale ACKs and
        # MUST elicit a challenge ACK. Updated alongside
        # '_snd_wnd' in '_process_ack_packet'.
        self._max_window: int = self._snd_mss

        # Effective send window - PyTCP's simplified congestion-
        # control variable that conflates RFC 5681 cwnd and
        # ssthresh. Doubles on each cum-ACK in
        # '_process_ack_packet' (slow-start reuse, no congestion-
        # avoidance phase) and is reset to one SMSS on RTO in
        # '_retransmit_packet_timeout'. The min() clamp against
        # '_snd_wnd' enforces the receiver-imposed flow-control
        # ceiling.
        self._snd_ewn: int = self._snd_mss

        # RFC 5681 cwnd / ssthresh (see
        # 'docs/rfc/tcp/rfc5681__reno_cwnd/adherence.md' for
        # the per-clause spec audit). Slow-start vs CA growth
        # in '_process_ack_packet'; RTO ssthresh halving in
        # '_retransmit_packet_timeout'; fast-recovery
        # inflation / deflation in '_retransmit_packet_request'
        # and the recovery exit path.
        self._cwnd: int = self._snd_mss
        # RFC 5681 §3.1: "ssthresh SHOULD be set arbitrarily high
        # (e.g., to the size of the largest possible advertised
        # window)". 'INT32_MAX' (0x7FFFFFFF) is the canonical
        # large-constant choice (mirrors Linux's 'int_max'); it
        # is well above any realistic peer-advertised window so
        # the session enters slow-start cleanly post-handshake.
        self._ssthresh: int = 0x7FFF_FFFF

        # RFC 9438 CUBIC state (active when '_cc_mode == CUBIC';
        # in 'RENO' mode all fields stay at their initial values
        # and the existing RFC 5681 cwnd helpers run unchanged).
        # Default is CcMode.CUBIC, mirroring Linux's default
        # since kernel 2.6.18. Override per-connection via
        # 'setsockopt(IPPROTO_TCP, TCP_CONGESTION, CcMode.RENO.value)'.
        self._cc_mode: CcMode = CcMode.CUBIC
        # 'W_max' anchor for the cubic curve (bytes). Updated on
        # every loss event (RFC 9438 §4.6); the cubic growth
        # formula uses '_cubic_w_max' as the inflection point.
        self._cubic_w_max: int = 0
        # Prior 'W_max' kept for the §4.7 fast-convergence
        # comparison: when the new W_max is smaller than this
        # one, fast convergence reduces W_max further.
        self._cubic_w_last_max: int = 0
        # Curve inflection time (ms). Computed from the cubic
        # cube-root formula on each loss event (RFC 9438 §4.2
        # figure 2).
        self._cubic_K_ms: int = 0
        # Virtual-clock anchor for the cubic curve (ms). Reset
        # on every loss event so 'W_cubic(t = now - epoch_start)'
        # measures elapsed time since the start of the current
        # CA stage (RFC 9438 §4.2).
        self._cubic_epoch_start_ms: int = 0
        # Reno-friendly W_est tracker (bytes). Updated per
        # cum-ACK in CA when '_cc_mode == CUBIC'. Selected as
        # the active cwnd value when the cubic formula yields a
        # smaller cwnd than Reno would (RFC 9438 §4.3).
        self._cubic_w_est: int = 0
        # Whether the session is currently in the CA phase per
        # RFC 9438 §4.6. True post-loss-event (or after the
        # first cwnd >= ssthresh crossing); the CUBIC formula
        # only fires when this is True. Slow-start exits via
        # the existing Reno path until this flag flips.
        self._cubic_in_ca: bool = False

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
        self._persist_active: bool = False
        self._persist_timeout: int = tcp__constants.PACKET_RETRANSMIT_TIMEOUT

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
        self._shut_rd: bool = False
        self._shut_wr: bool = False

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
        if self._closing or self._shut_wr:
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
            if not self._shut_rd:
                self._shut_rd = True
                # Wake any blocked recv() so it observes the
                # shutdown and returns 0 (the FSM check + empty
                # buffer makes recv() yield empty bytes).
                self._event__rx_buffer.set()
                __debug__ and log("tcp-ss", f"[{self}] - shutdown(SHUT_RD): receive side closed")

        # SHUT_WR or SHUT_RDWR: trigger FIN emission via the
        # existing close() machinery if not already closing.
        if how in (1, 2):
            if not self._shut_wr and not self._closing:
                self._shut_wr = True
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
            self._transmit_packet(flag_rst=True, flag_ack=True, seq=self._snd_nxt)
        # Mark connection as aborted so any blocked recv() raises.
        self._connection_error = ConnError.CANCELED
        self._event__rx_buffer.set()
        self._event__connect.release()
        self._change_state(FsmState.CLOSED)

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
            # RFC 6937 §3.1 PRR per-recovery state lives only
            # while a recovery episode is active in ESTABLISHED.
            # Clear alongside RecoveryPoint so half-close and
            # subsequent re-entries start clean.
            self._recover_fs = 0
            self._prr_delivered = 0
            self._prr_out = 0

        # RFC 7413 §3.1 Fast Open server-side cookie state is
        # only meaningful while the session is in SYN_RCVD
        # awaiting the third-leg ACK. Once the handshake
        # completes (ESTABLISHED) or the session aborts (any
        # other terminal state), no further SYN+ACK will
        # fire so the cookie is no longer needed. Clear on
        # any transition out of SYN_RCVD.
        if old_state is FsmState.SYN_RCVD and state is not FsmState.SYN_RCVD:
            self._fastopen_cookie_to_emit = None
            # RFC 7413 §4.2: decrement the global pending-TFO
            # counter when this session leaves SYN_RCVD (either
            # the handshake completes -> ESTABLISHED, or it
            # aborts -> CLOSED). The '_fastopen_pending_counted'
            # guard ensures we only decrement for sessions that
            # were actually counted at TFO acceptance time.
            if self._fastopen_pending_counted:
                stack.tcp__fastopen_pending_count = max(
                    0, stack.tcp__fastopen_pending_count - 1
                )
                self._fastopen_pending_counted = False

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
            # RFC 5681 §4.1 Restart Window: same idle trigger,
            # reduce cwnd to RW = min(IW, cwnd) so a stale
            # high-cwnd estimate from a prior high-bandwidth
            # period doesn't blast a line-rate burst into a
            # network whose live capacity may have decayed.
            # Skipped on flag_syn (handshake path; cwnd is
            # already the post-handshake IW) and on FIN-only
            # (no data to pace).
            if data:
                rw = min(initial_window(self._snd_mss), self._cwnd)
                if rw < self._cwnd:
                    __debug__ and log(
                        "tcp-ss",
                        f"[{self}] - RFC 5681 §4.1 Restart Window: "
                        f"cwnd {self._cwnd} -> {rw} (IW="
                        f"{initial_window(self._snd_mss)})",
                    )
                    self._cwnd = rw
                    self._snd_ewn = min(self._cwnd, self._snd_wnd)

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

        # RFC 7413 §3.1 Fast Open option emission, two paths:
        #   - Passive-open SYN+ACK: when peer's SYN carried
        #     the TFO option the LISTEN handler stashed a
        #     cookie in '_fastopen_cookie_to_emit' that we
        #     return here. The field is NOT cleared on emit
        #     so SYN+ACK retransmits (RFC 7413 §3.1: peer
        #     that lost the original SYN+ACK still expects
        #     the cookie on the retransmit) carry the same
        #     cookie. The field is cleared on transition to
        #     ESTABLISHED via '_change_state' since no
        #     subsequent SYN+ACK will fire from that state.
        #   - Active-open SYN: by default advertise TFO with
        #     the empty-cookie request form so the server
        #     issues a cookie we can cache for a subsequent
        #     fast-open. The 'b""' placeholder will be
        #     replaced with a cached cookie value when the
        #     client-side cookie cache lands.
        # RFC 3168 §6.1.1 ECN flag emission on SYN segments.
        # Active-open SYN: ECE+CWR (the canonical ECN-setup
        # signal, gated on '_advertise_ecn'). Passive-open
        # SYN+ACK: ECE only (ECN-Echo confirmation, gated
        # on bilateral '_ecn_enabled' set when peer's
        # active-open SYN was seen with ECE+CWR). Non-SYN
        # segments handle ECE / CWR via the data-path
        # echo / reduce mechanism (§6.1.2), wired in a
        # subsequent phase.
        flag_ece = False
        flag_cwr = False
        flag_ns = False
        # RFC 9768 §3.1.1 active-open AccECN-setup SYN. When
        # we advertise AccECN, the SYN carries AE+CWR+ECE -
        # the AE bit (NS position) is the wire signal that
        # distinguishes us from an RFC-3168-only client. A
        # peer that recognises AccECN responds with one of
        # four AE/CWR/ECE codepoints; one that does not
        # responds with the RFC 3168 ECE-only form, and we
        # fall back gracefully in the SYN_SENT handler.
        if flag_syn and not flag_ack and self._advertise_accecn:
            flag_ns = True
            flag_cwr = True
            flag_ece = True
        elif flag_syn and not flag_ack and self._advertise_ecn:
            flag_ece = True
            flag_cwr = True
        # RFC 9768 §3.1.1 passive-side AccECN SYN+ACK. When
        # the listener has accepted an AccECN-setup SYN, the
        # SYN+ACK carries one of four codepoints encoding the
        # IP-ECN of the received SYN:
        #   Not-ECT (00) -> AE=0, CWR=1, ECE=0
        #   ECT(1)  (01) -> AE=0, CWR=1, ECE=1
        #   ECT(0)  (10) -> AE=1, CWR=0, ECE=0
        #   CE      (11) -> AE=1, CWR=1, ECE=1
        # The encoding has AE = bit1 of the IP-ECN codepoint;
        # CWR = (NOT bit1) OR bit0 (i.e. set unless ECT(0));
        # ECE = bit0 of the codepoint XOR'd with bit1 (i.e.
        # set when codepoint is ECT(1) or CE).
        elif flag_syn and flag_ack and self._accecn_enabled:
            cp = self._accecn_synack_codepoint
            flag_ns = bool(cp & 0b10)
            flag_cwr = (cp & 0b10) == 0 or (cp & 0b01) != 0
            flag_ece = bool(cp & 0b01)
        elif flag_syn and flag_ack and self._ecn_enabled:
            flag_ece = True
        # RFC 9768 §3.2.2.1 ACE field encoding on non-SYN
        # segments of an AccECN-capable connection. The 3-bit
        # 'r.cep modulo 8' counter is encoded into the
        # AE+CWR+ECE flags as: bit2 -> AE (NS bit position),
        # bit1 -> CWR, bit0 -> ECE. RST segments stay
        # unmarked per the §3.2 advisory.
        #
        # On the active-open client's third-leg ACK the
        # encoding is the §3.2.2.1 Table-3 handshake form
        # instead of 'r.cep & 7' - the SYN_SENT handler
        # populated '_accecn_handshake_ack_pending' with the
        # Table-3 value derived from the inbound SYN+ACK's
        # IP-ECN codepoint. The pending field is consumed
        # (cleared to None) by this branch so subsequent
        # post-handshake segments fall back to the regular
        # encoding.
        elif self._accecn_enabled and not flag_rst:
            if self._accecn_handshake_ack_pending is not None:
                ace = self._accecn_handshake_ack_pending
                self._accecn_handshake_ack_pending = None
            else:
                ace = self._accecn_r_cep & 0b111
            flag_ns = bool(ace & 0b100)
            flag_cwr = bool(ace & 0b010)
            flag_ece = bool(ace & 0b001)
        # RFC 3168 §6.1.2 / §6.1.3 receiver-side CE echo. On
        # non-SYN segments of an ECN-capable connection, set
        # ECE while the receiver's CE-echo flag is True. The
        # flag was set when an inbound CE-marked segment was
        # observed and is cleared once the sender confirms
        # cwnd reduction by setting CWR on a subsequent
        # segment.
        elif self._ecn_enabled and self._send_ece and not flag_rst:
            flag_ece = True
        # RFC 3168 §6.1.2 sender-side CWR confirmation. After
        # responding to an inbound ECE with cwnd reduction,
        # the first outbound data segment carries CWR as the
        # wire confirmation. The flag clears on emission so
        # subsequent segments stay unmarked unless a new ECN
        # response is triggered.
        if self._ecn_enabled and self._ecn_send_cwr and data:
            flag_cwr = True
            self._ecn_send_cwr = False

        tcp__fastopen_cookie: bytes | None = None
        if flag_syn and flag_ack and self._fastopen_cookie_to_emit is not None:
            tcp__fastopen_cookie = self._fastopen_cookie_to_emit
        elif flag_syn and not flag_ack and self._advertise_fastopen:
            # RFC 7413 §4.1.3.1 negative-response cache
            # bypass: if this peer has previously failed TFO,
            # do NOT include the TFO option on the active-open
            # SYN — fall back to a plain 3WHS so the known-bad
            # path is not exercised. RFC 7413 §4.4 SYN-
            # retransmit-without-TFO bypass: if this is a
            # retransmit of an earlier SYN, drop the TFO option
            # so the second attempt is plain 3WHS. Otherwise
            # emit TFO with the cached cookie if known, else
            # the empty cookie-request form.
            if (
                self._remote_ip_address in stack.tcp__fastopen_negative
                or self._fastopen_syn_retransmitted
            ):
                tcp__fastopen_cookie = None
            else:
                tcp__fastopen_cookie = stack.tcp__fastopen_cookies.get(self._remote_ip_address, b"")

        # RFC 9768 §3.2.3 receiver-side AccECN option emission.
        # On every outbound non-SYN segment of an AccECN-
        # enabled connection, attach an AccECN option with
        # the cumulative byte counters so the sender can
        # compute precise per-codepoint feedback deltas
        # across ACKs. Skipped on SYN-only segments (where
        # the codepoint encoding in AE/CWR/ECE handles
        # negotiation) and RST.
        #
        # Order choice between AccECN0 (Kind 172, ECT(0)
        # first) and AccECN1 (Kind 174, ECT(1) first) per
        # §3.2.3 'whichever order is more efficient': pick
        # AccECN1 when r.ECT(1) advanced since the last
        # emission and r.ECT(0) did not (the L4S-style
        # workload pattern - putting the changed counter
        # first minimises bytes under the abbreviation
        # rule). Otherwise pick AccECN0 (the classic-ECN
        # default and most common case).
        #
        # Length choice per §3.2.3 / §3.2.3.3 abbreviation
        # rule: include any counter that changed since the
        # last emission; once a counter is included, the
        # ordering rule forces all preceding (less-trailing)
        # counters in the natural order to also be included.
        # AccECN0 wire order is e0b, ceb, e1b - so e1b is
        # the most-trailing field and is dropped first when
        # unchanged. AccECN1 wire order is e1b, ceb, e0b -
        # so e0b is the most-trailing field and is dropped
        # first when unchanged. Lengths 11/8/5/2 correspond
        # to including 3/2/1/0 counters respectively.
        #
        # Trackers initialise to -1 (outside the uint24
        # range) so the first emission always picks Length
        # 11 - seeding the peer with the full §3.2.1
        # initial state on the third-leg ACK.
        tcp__accecn0_counters: tuple[int | None, int | None, int | None] | None = None
        tcp__accecn1_counters: tuple[int | None, int | None, int | None] | None = None
        if self._accecn_enabled and not flag_rst and not (flag_syn and not flag_ack):
            e0b_changed = self._accecn_r_ect0_b != self._accecn_r_last_emit_e0b
            ceb_changed = self._accecn_r_ce_b != self._accecn_r_last_emit_ceb
            e1b_changed = self._accecn_r_ect1_b != self._accecn_r_last_emit_e1b
            if e1b_changed and not e0b_changed:
                # AccECN1 (wire order: e1b, ceb, e0b).
                if e0b_changed:
                    # Length 11: all three on wire.
                    tcp__accecn1_counters = (
                        self._accecn_r_ect0_b,
                        self._accecn_r_ce_b,
                        self._accecn_r_ect1_b,
                    )
                elif ceb_changed:
                    # Length 8: drop trailing e0b.
                    tcp__accecn1_counters = (
                        None,
                        self._accecn_r_ce_b,
                        self._accecn_r_ect1_b,
                    )
                else:
                    # Length 5: only e1b on wire (the
                    # gating outer condition guarantees
                    # e1b_changed=True).
                    tcp__accecn1_counters = (
                        None,
                        None,
                        self._accecn_r_ect1_b,
                    )
            else:
                # AccECN0 (wire order: e0b, ceb, e1b).
                if e1b_changed:
                    # Length 11: all three on wire.
                    tcp__accecn0_counters = (
                        self._accecn_r_ect0_b,
                        self._accecn_r_ce_b,
                        self._accecn_r_ect1_b,
                    )
                elif ceb_changed:
                    # Length 8: ee0b + eceb on wire, drop
                    # trailing ee1b.
                    tcp__accecn0_counters = (
                        self._accecn_r_ect0_b,
                        self._accecn_r_ce_b,
                        None,
                    )
                elif e0b_changed:
                    # Length 5: only ee0b on wire.
                    tcp__accecn0_counters = (
                        self._accecn_r_ect0_b,
                        None,
                        None,
                    )
                else:
                    # Length 2: empty option (no counters
                    # changed since last emission).
                    tcp__accecn0_counters = (None, None, None)
            self._accecn_r_last_emit_e0b = self._accecn_r_ect0_b
            self._accecn_r_last_emit_ceb = self._accecn_r_ce_b
            self._accecn_r_last_emit_e1b = self._accecn_r_ect1_b

        # RFC 3168 §6.1.5: when bilateral ECN has been
        # negotiated, every outbound data segment MUST set
        # the IP ECN field to ECT(0) ('10' = 2) so routers
        # along the path can mark it on congestion via the
        # CE codepoint. §6.1.1 forbids ECT on SYNs and §6.1.6
        # advises against ECT on pure ACKs / FIN-only / RST,
        # so the marking is gated on the segment carrying a
        # TCP payload. §6.1.5 also mandates "ECN-capable TCP
        # implementations MUST NOT set either ECT codepoint
        # (ECT(0) or ECT(1)) in the IP header for
        # retransmitted data packets": a segment whose seq
        # is strictly below the current SND.MAX (the high-
        # water mark of seqs we've ever sent) is, by
        # definition, a retransmit since SND.NXT was rewound
        # to SND.UNA on the RTO/FR path. The 'lt32' modular
        # comparison handles the 32-bit seq wrap correctly.
        is_retransmit = bool(data) and lt32(seq, self._snd_max)
        ip__ecn = 2 if (self._ecn_enabled and data and not is_retransmit) else 0
        stack.packet_handler.send_tcp_packet(
            ip__local_address=self._local_ip_address,
            ip__remote_address=self._remote_ip_address,
            ip__ecn=ip__ecn,
            tcp__local_port=self._local_port,
            tcp__remote_port=self._remote_port,
            tcp__flag_syn=flag_syn,
            tcp__flag_ack=flag_ack,
            tcp__flag_fin=flag_fin,
            tcp__flag_rst=flag_rst,
            tcp__flag_psh=flag_psh,
            tcp__flag_ece=flag_ece,
            tcp__flag_cwr=flag_cwr,
            tcp__flag_ns=flag_ns,
            tcp__seq=seq,
            tcp__ack=ack,
            tcp__win=tcp__win,
            # RFC 9293 §3.7.5 / RFC 2675 §5: the MSS option wire
            # field is 16-bit, so '_rcv_mss > 65535' (e.g. on a
            # mis-configured super-jumbo MTU) would otherwise
            # overflow the assembler's uint16 assert. Cap at 65535
            # which RFC 2675 reserves as the "use path-MTU-derived
            # MSS" signal for jumbogram-capable IPv6 paths.
            tcp__mss=min(self._rcv_mss, 0xFFFF) if flag_syn else None,
            tcp__wscale=tcp__wscale,
            tcp__sackperm=tcp__sackperm,
            tcp__sack_blocks=tcp__sack_blocks,
            tcp__tsval=tcp__tsval,
            tcp__tsecr=tcp__tsecr,
            tcp__fastopen_cookie=tcp__fastopen_cookie,
            tcp__accecn0_counters=tcp__accecn0_counters,
            tcp__accecn1_counters=tcp__accecn1_counters,
            tcp__payload=data,
        )
        # RFC 8985 §5.2 / §6.1 RACK per-segment record: insert a
        # 'RackSegment' for every outbound segment that consumes
        # sequence space (data / SYN / FIN). Keyed by the
        # segment's starting seq. If the seq is already in the
        # dict the segment is a retransmit (re-entered
        # '_transmit_packet' with the same '_snd_nxt' after a
        # walkback) - record xmit_ts of the latest transmission
        # AND set 'retransmitted' so RACK §6.2 step 2 can
        # disambiguate samples per Karn's algorithm. Phase 1
        # only ships the storage; Phase 2 onward consumes it.
        if data or flag_syn or flag_fin:
            seg_end_seq = add32(seq, len(data), flag_syn, flag_fin)
            self._rack_segments[seq] = RackSegment(
                end_seq=seg_end_seq,
                xmit_ts=stack.timer.now_ms,
                retransmitted=seq in self._rack_segments,
                lost=False,
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

        # RFC 6937 §3.1 PRR: track 'prr_out' across every
        # outbound segment that consumes sequence space while
        # we are in a recovery episode. The accumulator feeds
        # the per-ACK 'sndcnt' computation
        # ('CEIL(prr_delivered * ssthresh / RecoverFS) -
        # prr_out') so PRR's send-pacing decision sees the
        # actual recovery-episode send rate. The retransmit
        # that fires from the recovery-entry path consumes one
        # SMSS of 'prr_out'; subsequent retransmits or new
        # data sent during recovery accumulate here too.
        if self._recovery_point != 0 and (data or flag_syn or flag_fin):
            self._prr_out += len(data) + flag_syn + flag_fin

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

        # RFC 8985 §7.2 Tail Loss Probe scheduling. Arm the
        # 'f"{self}-tlp"' timer on every outbound data segment
        # so the §7.3 probe-emission path can elicit an ACK if
        # the segment was the last byte of the application's
        # write and peer's ACK is delayed. Skipped while in
        # any recovery (recovery_point != 0 OR _frto_active)
        # because a probe during recovery would race the
        # ongoing retransmit machinery. Only fires for data
        # segments, not SYN / FIN / pure-ACK probes.
        # RFC 8985 §7.2 TLP arming. Gated on:
        #   - data segment fired (not SYN / FIN / pure-ACK),
        #   - no recovery in progress (recovery_point == 0
        #     and not frto_active),
        #   - SRTT measurement available. The RFC permits a
        #     1000 ms fallback when SRTT is unavailable, but
        #     in that regime PTO equals the initial RTO so
        #     TLP and RTO would race; PyTCP defers to the
        #     RTO-only path until the first RTT sample arrives,
        #     then enables TLP for tail-loss probing.
        # Arm TLP only when SRTT is available and non-zero
        # (i.e. a measurable RTT sample exists). The RFC
        # permits a 1000 ms fallback when SRTT is unavailable,
        # but in that regime PTO equals the initial RTO and
        # would race the RTO timer; PyTCP defers to the
        # RTO-only path until a real RTT sample arrives.
        if data and self._recovery_point == 0 and not self._frto_active and (self._rto_state.srtt_ms or 0) > 0:
            flight_size = (self._snd_max - self._snd_una) & 0xFFFF_FFFF
            # Use the IN-FLIGHT RTO timer's actual remaining
            # time (when accessible) so the §7.2 'do not
            # outlast RTO' clamp respects the real expiration.
            # Fall back to None when the timer subsystem does
            # not expose internal state (e.g. unit-test stubs).
            rto_remaining_ms = getattr(stack.timer, "_timers", {}).get(f"{self}-retransmit")
            rto_expiration_ms = (stack.timer.now_ms + rto_remaining_ms) if rto_remaining_ms else None
            pto_ms = tlp_calc_pto(
                srtt_ms=self._rto_state.srtt_ms,
                flight_size=flight_size,
                smss=self._snd_mss,
                max_ack_delay_ms=self._tlp_max_ack_delay_ms,
                rto_expiration_ms=rto_expiration_ms,
                now_ms=stack.timer.now_ms,
            )
            if pto_ms > 0:
                stack.timer.register_timer(name=f"{self}-tlp", timeout=pto_ms)
                self._tlp_armed = True

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

        # RFC 2018 §3 block-cap: at most 4 blocks per SACK
        # option (40-byte options window divided by the 8-byte-
        # per-block + 2-byte SACK header). When TSopt is also
        # being emitted (10 bytes consumed), the cap drops to 3
        # blocks because 10 + 2 + 4*8 = 44 > 40 byte options
        # cap. The §3 examples explicitly enumerate the 3-block
        # cap as the TSopt-coexistence form.
        block_cap = 3 if self._send_ts else 4
        blocks: list[tuple[int, int]] = []
        if self._pending_dsack is not None:
            blocks.append(self._pending_dsack)
            self._pending_dsack = None
        # RFC 2018 §4 first-block ordering: the most recent OOO
        # arrival should be the first block (after any DSACK).
        # PyTCP's '_ooo_packet_queue' is an insertion-ordered
        # dict where the newest entry is the LAST item; reverse
        # the iteration so the newest comes first. The remaining
        # blocks follow in newest-first order, satisfying the
        # §4 "first block reflects triggering segment" intent
        # without an extra triggering-segment tracker.
        for seq, packet_rx_md in reversed(self._ooo_packet_queue.items()):
            if len(blocks) >= block_cap:
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

        if not self._send_ts:
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
        ts_recent_refresh_gate_ok = (
            packet_rx_md.tcp__flag_syn
            or le32(packet_rx_md.tcp__seq, self._rcv_nxt)
        )
        if lt32(packet_rx_md.tcp__tsval, self._ts_recent):
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
                self._ts_recent_updated_at_ms != 0
                and stack.timer.now_ms - self._ts_recent_updated_at_ms > tcp__constants.TS_RECENT_OUTDATED_THRESHOLD_MS
            ):
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - PAWS: TS.Recent outdated past "
                    f"{tcp__constants.TS_RECENT_OUTDATED_THRESHOLD_MS} ms idle threshold, "
                    "accepting segment per RFC 7323 §5.5 mitigation "
                    f"(tsval={packet_rx_md.tcp__tsval}, "
                    f"_ts_recent={self._ts_recent})",
                )
                self._ts_recent = packet_rx_md.tcp__tsval
                self._ts_recent_updated_at_ms = stack.timer.now_ms
                return True
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - PAWS: dropping stale-TSval segment "
                f"(tsval={packet_rx_md.tcp__tsval} < _ts_recent="
                f"{self._ts_recent})",
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
            self._ts_recent = packet_rx_md.tcp__tsval
            self._ts_recent_updated_at_ms = stack.timer.now_ms
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

        # Cancel every per-session timer the prior incarnation may
        # have armed. The prefix matches every timer keyed on
        # 'f"{self}-..."' (TIME-WAIT, retransmit, delayed-ACK,
        # persist, keep-alive idle/probe, challenge-ACK rate limit).
        stack.timer.unregister_timers_with_prefix(f"{self}-")

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
        self._snd_ini = new_iss
        self._snd_una = new_iss
        self._snd_nxt = new_iss
        self._snd_max = new_iss
        self._snd_sml = new_iss
        self._snd_fin = 0
        self._fin_sent = False
        self._tx_buffer_seq_mod = new_iss

        # Adopt peer's new SYN parameters. MSS is clamped to the
        # RFC 879 / RFC 6691 bounds; an explicit floor at TCP__MIN_MSS
        # treats peer-advertised 0 (or any malformed sub-floor value)
        # as 'option absent'.
        self._snd_mss = max(
            TCP__MIN_MSS,
            min(packet_rx_md.tcp__mss, stack.interface_mtu - self._ip_tcp_overhead),
        )
        self._snd_wnd = packet_rx_md.tcp__win
        self._max_window = self._snd_wnd

        # Re-run the bilateral negotiation against peer's new SYN -
        # WSCALE / SACK / TSopt may all differ between incarnations.
        if self._advertise_wscale and packet_rx_md.tcp__wscale:
            self._snd_wsc = packet_rx_md.tcp__wscale
        else:
            self._rcv_wsc = 0
            self._snd_wsc = 0
        self._send_sack = self._advertise_sack and packet_rx_md.tcp__sackperm
        self._send_ts = self._advertise_ts and packet_rx_md.tcp__tsval is not None
        # '_ts_recent' was already refreshed to peer's new TSval
        # by the PAWS helper in the FSM handler before this point.

        # RFC 5681 §3.1 + RFC 6928 §2: reset cwnd to the post-handshake
        # IW and ssthresh to the canonical large-constant default. The
        # actual IW assignment happens at the SYN_RCVD -> ESTABLISHED
        # transition; here we set the SYN-RCVD-phase value
        # (one SMSS) so the outbound SYN+ACK is emitted correctly.
        self._cwnd = self._snd_mss
        self._ssthresh = 0x7FFF_FFFF
        self._snd_ewn = min(self._cwnd, self._snd_wnd)

        # Receive-side state from the new SYN.
        self._rcv_ini = packet_rx_md.tcp__seq
        self._rcv_nxt = add32(
            packet_rx_md.tcp__seq,
            packet_rx_md.tcp__flag_syn,
            len(packet_rx_md.tcp__data),
        )
        self._rcv_una = self._rcv_nxt
        self._peer_contacted = True

        # Reset RFC 6298 RTO estimator + sample tracker so the new
        # incarnation re-establishes its own RTT measurements.
        self._rto_state = initial_state()
        self._retransmit_count = 0
        self._last_send_time_ms = None
        self._rtt_sample_seq = None
        self._rtt_sample_send_time_ms = None
        self._rtt_sample_retransmitted = False

        # Clear SACK + DSACK + recovery state from the prior incarnation.
        self._sack_scoreboard = SackScoreboard()
        self._recovery_point = 0
        self._recover_fs = 0
        self._prr_delivered = 0
        self._prr_out = 0
        self._pending_dsack = None
        self._dsack_received = 0

        # Clear OOO queue + buffers (TIME-WAIT should already have
        # them empty, but be defensive against state that an earlier
        # bug or a spurious-FIN-retransmit path may have left).
        self._ooo_packet_queue.clear()
        self._tx_buffer.clear()
        self._rx_buffer.clear()

        # Queue any data the new SYN piggybacked (RFC 9293 §3.10.7.2
        # step 3 permits this; rare but legal).
        if packet_rx_md.tcp__data:
            self._enqueue_rx_buffer(packet_rx_md.tcp__data)

    def _restore_frto_snapshot(self) -> None:
        """
        Restore the pre-RTO cwnd / ssthresh / CUBIC state on
        an F-RTO spurious-RTO declaration. Called from the
        spurious-detection branch in '_process_ack_packet'
        when either step 2 (single-ACK strong-spurious) or
        step 3b (second-ACK advancing) fires.

        Reference: RFC 5682 §2.1 step 3b (declare spurious + restore).
        Reference: RFC 9438 §4.9.1 (restore CUBIC state).
        """

        self._cwnd = self._frto_pre_cwnd
        self._ssthresh = self._frto_pre_ssthresh
        self._snd_ewn = min(self._cwnd, self._snd_wnd)
        self._cubic_w_max = self._frto_pre_cubic_w_max
        self._cubic_K_ms = self._frto_pre_cubic_K_ms
        self._cubic_epoch_start_ms = self._frto_pre_cubic_epoch_start_ms
        self._cubic_w_est = self._frto_pre_cubic_w_est
        __debug__ and log(
            "tcp-ss",
            f"[{self}] - RFC 5682 F-RTO: spurious RTO "
            f"detected, restored cwnd={self._cwnd} "
            f"ssthresh={self._ssthresh}; "
            f"RFC 9438 §4.9.1: restored cubic "
            f"w_max={self._cubic_w_max} "
            f"K_ms={self._cubic_K_ms}",
        )

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
            # RFC 9438 §4.9.2 spurious-fast-retransmit restore:
            # a DSACK observed during a recovery episode that
            # had snapshotted CUBIC state at FR entry indicates
            # the retransmit was spurious. Roll back W_max, K,
            # epoch_start, W_est, cwnd, and ssthresh to their
            # pre-FR values so post-FR throughput is not
            # artificially anchored at the reduced W_max.
            if (
                self._cc_mode is CcMode.CUBIC
                and self._fr_cubic_snapshot_valid
                and self._recovery_point != 0
            ):
                self._cubic_w_max = self._fr_pre_cubic_w_max
                self._cubic_K_ms = self._fr_pre_cubic_K_ms
                self._cubic_epoch_start_ms = self._fr_pre_cubic_epoch_start_ms
                self._cubic_w_est = self._fr_pre_cubic_w_est
                self._cwnd = self._fr_pre_cwnd
                self._ssthresh = self._fr_pre_ssthresh
                self._fr_cubic_snapshot_valid = False
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - RFC 9438 §4.9.2 spurious-FR "
                    "restore: rolled back CUBIC state on DSACK "
                    f"(cwnd={self._cwnd}, ssthresh={self._ssthresh}, "
                    f"W_max={self._cubic_w_max})",
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
            if self._recovery_point == 0 and (
                self._rack_dsack_round is None or not lt32(self._snd_una, self._rack_dsack_round)
            ):
                self._rack_reo_wnd_mult += 1
                self._rack_dsack_round = self._snd_max
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
        bytes_before = self._sack_scoreboard.total_sacked_bytes() if self._recovery_point != 0 else 0

        for left, right in blocks:
            if le32(self._snd_una, left) and le32(right, self._snd_max) and lt32(left, right):
                self._sack_scoreboard.add_block(left, right)

        if self._recovery_point != 0:
            self._prr_delivered += self._sack_scoreboard.total_sacked_bytes() - bytes_before

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

        # POSIX 'shutdown(SHUT_RD)' silently discards inbound
        # data per RFC 9293 §3.9.1 half-close semantics. The
        # peer's ACK still acknowledges the seq space (advancing
        # RCV.NXT), but the application never sees the bytes.
        if self._shut_rd:
            return

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
            # RFC 7413 §3.1 SYN-with-data: when the active-open
            # SYN is the first transmit AND we have a cached
            # cookie for the peer AND the application has
            # pre-loaded data into '_tx_buffer', slice up to
            # one SMSS of pending bytes onto the SYN itself.
            # Server-side cookie validation (Phase 3) gates
            # whether the bytes are accepted; on rejection
            # the data is replayed via normal retransmit after
            # the third-leg ACK. The slice is gated on cached-
            # cookie presence so a cookie-request SYN (no
            # cached cookie) never carries data - the empty-
            # cookie request form is invalid for data
            # acceptance per §4.1.2.
            tfo_data: bytes = b""
            cached = stack.tcp__fastopen_cookies.get(self._remote_ip_address)
            if cached and self._advertise_fastopen and self._tx_buffer:
                with self._lock__tx_buffer:
                    slice_len = min(self._snd_mss, len(self._tx_buffer))
                    tfo_data = bytes(self._tx_buffer[:slice_len])
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - Transmitting initial SYN packet_rx_md: seq {self._snd_nxt}"
                + (f", carrying {len(tfo_data)} bytes of TFO SYN-data" if tfo_data else ""),
            )
            self._transmit_packet(flag_syn=True, data=tfo_data)
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
            # RFC 6691 §2 Req B: "the sender MUST reduce the
            # TCP data length to account for any IP or TCP
            # options that it is including in the packets that
            # it sends." TSopt = 12 bytes (10 + 2 NOP padding)
            # on every post-handshake segment when bilaterally
            # negotiated. SACK option = 2 (header) + 8*N (block
            # count) bytes, padded to a 4-byte boundary; the
            # block count is bounded by the §3 4-block cap (or
            # 3 with TSopt). AccECN option = 2 + N bytes
            # depending on the abbreviation length. Estimate
            # the upper-bound option overhead conservatively
            # so the data-segment + option-block + fixed
            # headers stay within MTU.
            options_overhead = 0
            if self._send_ts:
                options_overhead += 12  # TSopt 10 bytes + 2 NOPs
            if self._send_sack and (self._ooo_packet_queue or self._pending_dsack is not None):
                # Worst-case SACK option size when we'd emit
                # blocks on a non-SYN segment. With TSopt the
                # cap is 3 blocks (= 2 + 24 = 26, padded to 28);
                # without TSopt it's 4 blocks (= 2 + 32 = 34,
                # padded to 36).
                sack_blocks_cap = 3 if self._send_ts else 4
                options_overhead += ((2 + 8 * sack_blocks_cap + 3) // 4) * 4
            if self._accecn_enabled:
                # AccECN Length 11 (the largest variant)
                # plus 1 NOP for alignment = 12 bytes worst
                # case.
                options_overhead += 12
            mss_for_data = max(self._snd_mss - options_overhead, 1)
            transmit_data_len = min(mss_for_data, usable_window, remaining_data_len)
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
                    # RFC 1122 §4.2.3.4: TCP_NODELAY disables
                    # Nagle for latency-sensitive applications;
                    # when set, partial segments fire even with
                    # a previous partial still unacked.
                    if is_partial and prev_partial_in_flight and not is_retransmit and not self._tcp_nodelay:
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

        # RFC 8985 §6.3: on RTO, mark all in-flight segments
        # lost. Subsequent retransmit walking treats them as
        # the loss set; the existing _transmit_data
        # machinery (with snd_nxt rewound to snd_una below)
        # will re-fire them. Replace each entry with the
        # 'lost=True / xmit_ts=INFINITE_TS' form per
        # RFC 8985 §5.2.
        from pytcp.protocols.tcp.tcp__rack import INFINITE_TS

        self._rack_segments = {
            seq: RackSegment(
                end_seq=seg.end_seq,
                xmit_ts=INFINITE_TS,
                retransmitted=seg.retransmitted,
                lost=True,
            )
            for seq, seg in self._rack_segments.items()
        }

        # RFC 6298 §5.5 binary backoff and §5.6 re-arm with the
        # new RTO. 'back_off' caps at 'MAX_RTO_MS' so a long-
        # silent peer cannot drive 'rto_ms' to overflow.
        self._rto_state = back_off(self._rto_state)
        self._retransmit_count += 1
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
            if self._state is FsmState.SYN_SENT and self._advertise_fastopen:
                self._fastopen_syn_retransmitted = True
                # RFC 7413 §4.1.3.1: a SYN-RTO during TFO
                # active-open is a strong signal that the path
                # drops TFO-bearing SYNs. Add the peer to the
                # negative-response cache so future active-
                # opens to the same peer skip TFO entirely.
                stack.tcp__fastopen_negative.add(self._remote_ip_address)
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
        already_in_frto = self._frto_step != 0 and not lt32(
            self._frto_pre_snd_max, self._snd_una
        )
        if already_in_frto:
            # Update recover only; preserve original snapshots.
            self._frto_pre_snd_max = self._snd_max
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - RFC 5682 §2.1 already-in-RTO gate: "
                f"recover updated to {self._frto_pre_snd_max}; "
                "step 2 skipped (preserving original pre-RTO snapshot)",
            )
        else:
            self._frto_active = True
            self._frto_step = 1
            self._frto_pre_cwnd = self._cwnd
            self._frto_pre_ssthresh = self._ssthresh
            self._frto_pre_snd_max = self._snd_max
            # RFC 9438 §4.9.1: snapshot the CUBIC-specific
            # state alongside the cwnd/ssthresh snapshot so a
            # later spurious-detection event can roll back the
            # full congestion-control state.
            self._frto_pre_cubic_w_max = self._cubic_w_max
            self._frto_pre_cubic_K_ms = self._cubic_K_ms
            self._frto_pre_cubic_epoch_start_ms = self._cubic_epoch_start_ms
            self._frto_pre_cubic_w_est = self._cubic_w_est

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
        # RFC 9438 §4.6 + §4.7: in CUBIC mode, replace the RFC
        # 5681 §3.1 0.5 halving with beta_cubic = 0.7 and
        # update '_cubic_w_max' / '_cubic_K_ms' /
        # '_cubic_epoch_start_ms' so the post-RTO CA growth
        # curve has a fresh anchor. Fast convergence (§4.7) is
        # active by default: when the new cwnd is smaller than
        # the W_max from the prior loss event, W_max is reduced
        # further to release bandwidth to new flows.
        if self._cc_mode is CcMode.CUBIC:
            prior_w_max = self._cubic_w_max
            self._ssthresh, self._cubic_w_max = cubic_loss_event_ssthresh(
                cwnd=max(self._cwnd, self._snd_mss),
                smss=self._snd_mss,
                fast_conv_active=True,
                prior_w_max=prior_w_max,
            )
            self._cubic_w_last_max = prior_w_max
            # Curve epoch reset: post-RTO cwnd = 1 SMSS, so
            # cwnd_epoch = SMSS for the cube-root computation.
            self._cubic_K_ms = cubic_compute_K(
                w_max=self._cubic_w_max,
                cwnd_epoch=self._snd_mss,
                smss=self._snd_mss,
            )
            self._cubic_epoch_start_ms = stack.timer.now_ms
            self._cubic_in_ca = False
            # RFC 9438 §4.3: reset W_est so the next CA stage
            # bootstraps from cwnd_epoch (re-init on first CA
            # cum-ACK in '_process_ack_packet').
            self._cubic_w_est = 0
        else:
            self._ssthresh = compute_loss_event_ssthresh(flight_size, self._snd_mss)
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
        self._recover_seq = self._snd_max
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

        # RFC 8985 §6.2 step 1-2 RACK fold + step 5 loss
        # detection on the dup-ACK path. SACK-acked segments
        # advance RACK.xmit_ts even when the cum-ACK does not
        # advance, so a SACK-only dup-ACK can still drive
        # time-based loss detection per RFC 8985 §6.2.
        self._rack_process_ack(packet_rx_md)

        self._tx_retransmit_request_counter[packet_rx_md.tcp__ack] = (
            self._tx_retransmit_request_counter.get(packet_rx_md.tcp__ack, 0) + 1
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
        if self._recovery_point != 0:
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
        if self._recover_seq != 0 and lt32(self._snd_una, self._recover_seq):
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
        count = self._tx_retransmit_request_counter[packet_rx_md.tcp__ack]
        if count in (1, 2) and len(self._tx_buffer) > 0:
            saved_ewn = self._snd_ewn
            self._snd_ewn = min(self._cwnd + count * self._snd_mss, self._snd_wnd)
            self._transmit_data()
            self._snd_ewn = saved_ewn

        if not (count_trigger or sack_trigger):
            return

        # RFC 5681 §3.2 step 2: ssthresh = max(FlightSize/2,
        # 2*SMSS). Captures the just-observed loss point so
        # the post-recovery slow-start exits at this boundary.
        flight_size = (self._snd_max - self._snd_una) & 0xFFFF_FFFF
        # RFC 9438 §4.6 + §4.7: in CUBIC mode, ssthresh halves
        # by beta_cubic = 0.7 (vs RFC 5681's 0.5). Records
        # '_cubic_w_max' = cwnd-at-loss for the post-recovery
        # cubic curve. Fast convergence (§4.7) reduces W_max
        # further when the new cwnd is smaller than the prior
        # W_max anchor.
        if self._cc_mode is CcMode.CUBIC:
            prior_w_max = self._cubic_w_max
            # RFC 9438 §4.9.2 spurious-fast-retransmit snapshot:
            # capture the pre-FR CUBIC state so a DSACK during
            # this recovery episode can roll back the
            # multiplicative decrease + curve re-anchor below.
            self._fr_pre_cubic_w_max = self._cubic_w_max
            self._fr_pre_cubic_K_ms = self._cubic_K_ms
            self._fr_pre_cubic_epoch_start_ms = self._cubic_epoch_start_ms
            self._fr_pre_cubic_w_est = self._cubic_w_est
            self._fr_pre_cwnd = self._cwnd
            self._fr_pre_ssthresh = self._ssthresh
            self._fr_cubic_snapshot_valid = True
            self._ssthresh, self._cubic_w_max = cubic_loss_event_ssthresh(
                cwnd=self._cwnd,
                smss=self._snd_mss,
                fast_conv_active=True,
                prior_w_max=prior_w_max,
            )
            self._cubic_w_last_max = prior_w_max
            self._cubic_K_ms = cubic_compute_K(
                w_max=self._cubic_w_max,
                cwnd_epoch=self._ssthresh,
                smss=self._snd_mss,
            )
            self._cubic_epoch_start_ms = stack.timer.now_ms
            self._cubic_in_ca = True
            # RFC 9438 §4.3: reset W_est so the next CA stage
            # bootstraps from the post-recovery cwnd anchor.
            self._cubic_w_est = 0
        else:
            self._ssthresh = compute_loss_event_ssthresh(flight_size, self._snd_mss)

        # RFC 6937 §3.1 PRR per-recovery state initialisation:
        # snapshot pipe at entry as 'RecoverFS' so the per-ACK
        # send-pacing math has the denominator for the
        # 'prr_delivered * ssthresh / RecoverFS' ratio. Reset
        # the prr_delivered / prr_out counters to zero so the
        # accumulators only cover this recovery episode.
        self._recover_fs = flight_size
        self._prr_delivered = 0
        self._prr_out = 0

        # RFC 6937 §3.1: at entry 'prr_delivered = 0' and
        # 'prr_out = 0' so the per-ACK formula yields
        # 'sndcnt = 0 - 0 = 0' and 'cwnd = pipe + 0 = pipe'.
        # Pipe at entry equals 'flight_size' (no SACKs ingested
        # this ACK). This replaces the legacy RFC 5681 §3.2
        # step 3 'cwnd = ssthresh + 3*SMSS' coarse approximation
        # with PRR's data-driven per-ACK pacing - subsequent
        # ACKs recompute cwnd via the proportional ratio in
        # '_process_ack_packet'.
        self._cwnd = flight_size
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

        # _tlp_armed gates the firing path: only when the
        # arming logic in '_transmit_packet' actually
        # registered a TLP timer should this tick treat an
        # 'is_expired' result as a real timer expiration.
        # Without this gate, 'is_expired' would return True
        # for any session that never armed a TLP (the timer
        # is absent from the dict), and _tlp_pto_tick would
        # spuriously fire a retransmit on every FSM tick.
        if not self._tlp_armed:
            return
        if not stack.timer.is_expired(f"{self}-tlp"):
            return
        if self._snd_una == self._snd_max:
            # Nothing in flight - no tail to probe.
            return
        # RFC 8985 §7 once-per-tail gate: TLP fires at most one
        # probe per outstanding tail. '_tlp_end_seq' is set on
        # probe emission and cleared by §7.4 loss-detection
        # logic (Phase 8) once the probe outcome is determined,
        # OR by '_process_ack_packet' when a cum-ACK drains all
        # in-flight bytes (no tail left).
        if self._tlp_end_seq is not None:
            return
        # RFC 8985 §8 timer arbitration: if RTO recovery is in
        # progress (this tick's _retransmit_packet_timeout
        # incremented _retransmit_count, OR a fast-recovery is
        # underway, OR F-RTO is active), TLP yields. The
        # ongoing recovery machinery handles the loss already;
        # a TLP probe would race it and emit a duplicate.
        if self._retransmit_count > 0 or self._recovery_point != 0 or self._frto_active:
            return

        # New-data probe path: the TX buffer has bytes past
        # SND.MAX (i.e. data the application has queued but
        # the wire has not yet seen). When this is the case
        # we send the next segment from SND.MAX rather than
        # retransmitting an already-sent one. Compute the
        # buffer offset of SND.MAX modularly so a wrapped
        # session is handled correctly.
        tx_buffer_max = sub32(self._snd_max, self._tx_buffer_seq_mod)
        new_data_available = tx_buffer_max < len(self._tx_buffer) and self._snd_ewn > tx_buffer_max
        if new_data_available:
            # Force '_transmit_data' to start at SND.MAX (the
            # bytes immediately past the highest-seq sent).
            self._snd_nxt = self._snd_max
            self._tlp_is_retrans = False
        else:
            # Retransmit-style probe: walk SND.NXT back by one
            # MSS (or less if in-flight is shorter) so
            # _transmit_data re-sends the highest-seq segment.
            flight_size = (self._snd_max - self._snd_una) & 0xFFFF_FFFF
            walk_back = min(self._snd_mss, flight_size)
            self._snd_nxt = sub32(self._snd_max, walk_back)
            self._tlp_is_retrans = True

        self._transmit_data()
        self._tlp_end_seq = self._snd_max
        # Probe is in flight; clear armed flag so the next
        # tick's _tlp_pto_tick early-returns. The flag is
        # re-set by '_transmit_packet' when a fresh TLP timer
        # arms, e.g. on a subsequent data send.
        self._tlp_armed = False

        # RFC 8985 §7.3: re-arm the RTO timer after probe so
        # the connection retains its timeout fallback.
        stack.timer.register_timer(
            name=f"{self}-retransmit",
            timeout=self._rto_state.rto_ms,
        )

    def _rack_reorder_tick(self) -> None:
        """
        Per-tick service for the RFC 8985 §6.2 step 5
        reordering timer. When the f'{session}-rack' timer
        has expired, re-run rack_detect_loss with the current
        scalars and reo_wnd to mark any pending 'sent before'
        segments lost. Subsequent ticks may re-arm the timer
        if more candidates exist.
        """

        if not stack.timer.is_expired(f"{self}-rack"):
            return
        if self._rack_xmit_ts == 0:
            return
        reo_wnd_ms = rack_compute_reo_wnd(
            reordering_seen=self._rack_reordering_seen,
            reo_wnd_mult=self._rack_reo_wnd_mult,
            min_rtt_ms=self._rack_min_rtt_ms,
        )
        self._rack_segments, rack_timeout_ms = rack_detect_loss(
            segments=self._rack_segments,
            rack_xmit_ts=self._rack_xmit_ts,
            rack_end_seq=self._rack_end_seq,
            reo_wnd_ms=reo_wnd_ms,
            now_ms=stack.timer.now_ms,
        )
        if rack_timeout_ms > 0:
            stack.timer.register_timer(
                name=f"{self}-rack",
                timeout=rack_timeout_ms,
            )

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

        newly_acked = []
        for seq, seg in self._rack_segments.items():
            if seq in self._rack_acked_seqs:
                continue
            cum_acked = le32(seg.end_seq, self._snd_una)
            sack_acked = self._send_sack and self._sack_scoreboard.is_sacked(sub32(seg.end_seq, 1))
            if cum_acked or sack_acked:
                newly_acked.append(seg)
                self._rack_acked_seqs.add(seq)
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
                if self._rack_fack != 0 and lt32(seg.end_seq, self._rack_fack):
                    self._rack_reordering_seen = True
                if gt32(seg.end_seq, self._rack_fack):
                    self._rack_fack = seg.end_seq
            (
                self._rack_min_rtt_ms,
                self._rack_rtt_ms,
                self._rack_xmit_ts,
                self._rack_end_seq,
            ) = rack_update(
                newly_acked_segments=newly_acked,
                now_ms=stack.timer.now_ms,
                ts_recent_echo_ms=(packet_rx_md.tcp__tsecr if packet_rx_md.tcp__tsecr else None),
                prior_min_rtt_ms=self._rack_min_rtt_ms,
                prior_rack_rtt_ms=self._rack_rtt_ms,
                prior_rack_xmit_ts=self._rack_xmit_ts,
                prior_rack_end_seq=self._rack_end_seq,
            )

        if self._rack_xmit_ts > 0:
            # RFC 8985 §6.2 step 4 dynamic reo_wnd via
            # rack_compute_reo_wnd. Phase 3 used 0; Phase 4
            # adapts based on observed reordering and DSACK
            # rounds.
            reo_wnd_ms = rack_compute_reo_wnd(
                reordering_seen=self._rack_reordering_seen,
                reo_wnd_mult=self._rack_reo_wnd_mult,
                min_rtt_ms=self._rack_min_rtt_ms,
            )
            self._rack_segments, rack_timeout_ms = rack_detect_loss(
                segments=self._rack_segments,
                rack_xmit_ts=self._rack_xmit_ts,
                rack_end_seq=self._rack_end_seq,
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
                stack.timer.register_timer(
                    name=f"{self}-rack",
                    timeout=rack_timeout_ms,
                )

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
            if self._recover_seq != 0 and ge32(self._snd_una, self._recover_seq):
                self._recover_seq = 0
            # RFC 6937 §3.1 PRR: cumulative bytes ACK'd during
            # recovery feed 'prr_delivered'. Out-of-recovery
            # cum-ACKs do not - the accumulator is scoped to a
            # single recovery episode.
            if self._recovery_point != 0:
                self._prr_delivered += bytes_acked
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
            if self._recovery_point != 0 and lt32(self._snd_una, self._recovery_point):
                current_pipe = pipe(
                    scoreboard=self._sack_scoreboard,
                    snd_una=self._snd_una,
                    snd_max=self._snd_max,
                )
                if current_pipe > self._ssthresh:
                    # PRR proper: aim for ssthresh/RecoverFS
                    # ratio. Integer CEIL via the standard
                    # '-(-a // b)' trick to avoid float math.
                    target = -(-self._prr_delivered * self._ssthresh // self._recover_fs)
                    sndcnt = target - self._prr_out
                else:
                    # PRR-CRB / PRR-SSRB: pipe has dropped at
                    # or below ssthresh; allow conservative
                    # send budget. SSRB (bilateral SACK + new
                    # data this ACK) lets cwnd grow up to one
                    # SMSS per ACK; CRB (no SACK or no new
                    # data) caps at the unsent prr_delivered.
                    if self._send_sack and bytes_acked > 0:
                        limit = max(self._prr_delivered - self._prr_out, bytes_acked) + self._snd_mss
                    else:
                        limit = self._prr_delivered - self._prr_out
                    sndcnt = min(self._ssthresh - current_pipe, limit)
                self._cwnd = current_pipe + max(0, sndcnt)
            else:
                # RFC 9438 §4.4 / §4.5: when '_cc_mode == CUBIC'
                # AND we are in CA (cwnd >= ssthresh), use the
                # cubic growth formula instead of the linear
                # Reno CA branch. Slow-start (cwnd < ssthresh)
                # is handled inside both helpers and yields the
                # same RFC 5681 §3.1 path either way.
                if self._cc_mode is CcMode.CUBIC and self._cwnd >= self._ssthresh:
                    self._cubic_in_ca = True
                    now_ms = stack.timer.now_ms
                    cubic_cwnd = cubic_grow_per_ack(
                        cwnd=self._cwnd,
                        ssthresh=self._ssthresh,
                        w_max=self._cubic_w_max,
                        K_ms=self._cubic_K_ms,
                        epoch_start_ms=self._cubic_epoch_start_ms,
                        now_ms=now_ms,
                        bytes_acked=bytes_acked,
                        smss=self._snd_mss,
                        srtt_ms=self._rto_state.srtt_ms or 0,
                    )
                    # RFC 9438 §4.3: track the Reno-equivalent
                    # cwnd ('W_est') in parallel; if the cubic
                    # formula yields a smaller cwnd than Reno
                    # would, fall back to W_est so CUBIC never
                    # under-performs Reno on small-BDP / short-
                    # RTT paths. Lazy-initialise on first CA
                    # entry from cwnd_epoch.
                    if self._cubic_w_est == 0:
                        self._cubic_w_est = self._cwnd
                    self._cubic_w_est = cubic_w_est(
                        w_est_prev=self._cubic_w_est,
                        cwnd=self._cwnd,
                        smss=self._snd_mss,
                        bytes_acked=bytes_acked,
                    )
                    self._cwnd = max(cubic_cwnd, self._cubic_w_est)
                else:
                    self._cwnd = cwnd_grow_per_ack(self._cwnd, self._ssthresh, bytes_acked, self._snd_mss)
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
            # RFC 8985 §7.4 TLP loss-detection on inbound ACK.
            # Apply BEFORE the cum-ACK drain hook so a Case-3
            # ('ack > tlp_end_seq') ACK that also drains the
            # tail can invoke the §7.4.2 CC response. Returns
            # the new '_tlp_end_seq' (None on outcome
            # determined; preserved otherwise) and a flag
            # indicating whether to halve cwnd / ssthresh.
            new_tlp_end_seq, invoke_cc = tlp_process_ack(
                tlp_end_seq=self._tlp_end_seq,
                tlp_is_retrans=self._tlp_is_retrans,
                ack_seq=packet_rx_md.tcp__ack,
                has_dsack_for_probe=(self._dsack_received > 0),
                has_sack_blocks=bool(self._sack_scoreboard.blocks()),
            )
            self._tlp_end_seq = new_tlp_end_seq
            if invoke_cc:
                # RFC 8985 §7.4.2: probe repaired a single
                # tail loss; the network signalled a real
                # loss event so apply the conventional
                # cwnd halving (ssthresh = max(flight/2,
                # 2*SMSS); cwnd = ssthresh).
                from pytcp.protocols.tcp.tcp__cwnd import compute_loss_event_ssthresh

                flight_size = (self._snd_max - self._snd_una) & 0xFFFF_FFFF
                self._ssthresh = compute_loss_event_ssthresh(flight_size, self._snd_mss)
                self._cwnd = self._ssthresh
                self._snd_ewn = min(self._cwnd, self._snd_wnd)
                __debug__ and log(
                    "tcp-ss",
                    f"[{self}] - RFC 8985 §7.4.2 TLP probe-repair " f"CC: ssthresh={self._ssthresh} cwnd={self._cwnd}",
                )
            if self._snd_una == self._snd_max:
                stack.timer.unregister_timers_with_prefix(f"{self}-retransmit")
                # RFC 8985 §7.2 TLP cancellation: when a
                # cum-ACK drains all in-flight bytes, there is
                # no tail to probe. Cancel the TLP timer so a
                # late expiry does not fire a stale probe.
                # Also clear the once-per-tail state so the
                # next tail can fire its own probe.
                stack.timer.unregister_timers_with_prefix(f"{self}-tlp")
                self._tlp_end_seq = None
                self._tlp_is_retrans = False
                self._tlp_armed = False
            else:
                stack.timer.register_timer(
                    name=f"{self}-retransmit",
                    timeout=self._rto_state.rto_ms,
                )
            # RFC 5682 §2.1 step 2 / step 3 spurious-RTO
            # detection. The algorithm requires up to two
            # post-RTO ACKs to definitively classify the RTO:
            #
            #   step==1 (first post-RTO ACK):
            #     - SND.UNA covers all pre-RTO data (>= recover):
            #       single-ACK strong-spurious; restore and exit.
            #     - SND.UNA partially advances (still < recover):
            #       step 2b — defer decision to second ACK,
            #       set _frto_step=2 and stay in F-RTO. PyTCP's
            #       existing _transmit_data flow naturally
            #       sends up to 2 new segments after this cum-
            #       ACK because cwnd was reset to 1 SMSS on RTO
            #       and slow-start grows it by 1 SMSS per ACK.
            #   step==2 (second post-RTO ACK):
            #     - SND.UNA advanced further: spurious declared
            #       per step 3b; restore and exit.
            #     - (dup-ACK paths handled in the dup-ACK branch.)
            #
            # 'gt32(self._snd_una, snd_una_before_ack)' is True
            # for any cum-ACK that advances SND.UNA, which is
            # exactly the §2.1 "advances the window" signal.
            if self._frto_active:
                fully_covered = not lt32(self._snd_una, self._frto_pre_snd_max)
                if self._frto_step == 1:
                    if fully_covered:
                        # Single-ACK strong-spurious — restore.
                        self._frto_step = 0
                        self._frto_active = False
                        self._restore_frto_snapshot()
                    else:
                        # Step 2b: partial advance, defer to step 3.
                        self._frto_step = 2
                        __debug__ and log(
                            "tcp-ss",
                            f"[{self}] - RFC 5682 §2.1 step 2b: "
                            f"partial first post-RTO ACK "
                            f"(SND.UNA={self._snd_una} < recover="
                            f"{self._frto_pre_snd_max}); waiting "
                            "for second ACK to declare spurious",
                        )
                elif self._frto_step == 2:
                    # Second ACK that advances the window
                    # declares the timeout spurious per §2.1
                    # step 3b. We landed here because SND.UNA
                    # advanced ('lt32(snd_una_before_ack,
                    # tcp__ack)' was True at the top of this
                    # block); that's the §2.1 "acknowledgment
                    # advances the window" condition.
                    self._frto_step = 0
                    self._frto_active = False
                    self._restore_frto_snapshot()
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
        if self._send_ts and packet_rx_md.tcp__tsecr is not None and packet_rx_md.tcp__tsecr != 0:
            ts_rtt_ms = (stack.timer.now_ms - packet_rx_md.tcp__tsecr) & 0xFFFF_FFFF
            self._rto_state = update(self._rto_state, ts_rtt_ms)
            __debug__ and log(
                "tcp-ss",
                f"[{self}] - RFC 7323 §4 TSecr-driven RTTM: "
                f"rtt={ts_rtt_ms} ms via TSecr="
                f"{packet_rx_md.tcp__tsecr}; rto_state="
                f"{self._rto_state}",
            )
            self._rtt_sample_seq = None
            self._rtt_sample_send_time_ms = None
            self._rtt_sample_retransmitted = False

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
        for entry_seq in [s for s, e in self._rack_segments.items() if le32(e.end_seq, self._snd_una)]:
            del self._rack_segments[entry_seq]
            self._rack_acked_seqs.discard(entry_seq)
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
            # RFC 9438 §4.9.2 snapshot is scoped to a single
            # recovery episode; clear on exit so a stray DSACK
            # post-recovery does not roll back unrelated state.
            self._fr_cubic_snapshot_valid = False
            # RFC 6937 §3.1 PRR: per-recovery state is scoped
            # to a single recovery episode. Reset on exit so
            # the next loss event snapshots a fresh
            # 'RecoverFS' and re-accumulates from zero.
            self._recover_fs = 0
            self._prr_delivered = 0
            self._prr_out = 0
            # RFC 8985 §6.2 step 4 reo_wnd_persist decay. Each
            # recovery exit decrements the persist counter; on
            # reaching zero, reset 'reo_wnd_mult' back to 1
            # and refresh persist back to 16 so the connection
            # eventually decays back to the canonical
            # reordering tolerance after a long stretch of
            # recoveries without DSACK.
            self._rack_reo_wnd_persist -= 1
            if self._rack_reo_wnd_persist == 0:
                self._rack_reo_wnd_mult = 1
                self._rack_reo_wnd_persist = 16
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
        # RFC 5961 §5 'MAX.SND.WND': running maximum of peer's
        # advertised window. Used as the lower-bound tolerance
        # for ACK acceptability ('SND.UNA - MAX.SND.WND <=
        # SEG.ACK <= SND.NXT').
        if self._snd_wnd > self._max_window:
            self._max_window = self._snd_wnd
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
            # RFC 3168 §6.1.2 / §6.1.3 receiver-side CE echo
            # tracking. Run BEFORE the FSM dispatch so the
            # state-handler-emitted ACK on this segment already
            # carries ECE, and the sender's CWR confirmation
            # observed on the same segment clears the flag.
            if self._ecn_enabled and packet_rx_md is not None:
                if packet_rx_md.tcp__flag_cwr:
                    self._send_ece = False
                if packet_rx_md.ip__ecn == 3:
                    self._send_ece = True
            # RFC 9768 §3.2.2 / §3.2.3 receiver-side counter
            # accumulation. On AccECN-enabled connections,
            # count inbound segments per IP-ECN codepoint: the
            # r.cep packet counter increments on CE only (low
            # 3 bits feed the ACE field); the three byte
            # counters increment by the TCP-payload length on
            # every codepoint (the option carries them on
            # outbound segments). Counters wrap at 2^24 per
            # the AccECN option width.
            if self._accecn_enabled and packet_rx_md is not None:
                payload_len = len(packet_rx_md.tcp__data)
                if packet_rx_md.ip__ecn == 3:
                    self._accecn_r_cep = (self._accecn_r_cep + 1) & 0xFF_FFFF
                    self._accecn_r_ce_b = (self._accecn_r_ce_b + payload_len) & 0xFF_FFFF
                elif packet_rx_md.ip__ecn == 2:
                    self._accecn_r_ect0_b = (self._accecn_r_ect0_b + payload_len) & 0xFF_FFFF
                elif packet_rx_md.ip__ecn == 1:
                    self._accecn_r_ect1_b = (self._accecn_r_ect1_b + payload_len) & 0xFF_FFFF
            # RFC 3168 §6.1.2 sender-side response to inbound
            # ECE. Halve ssthresh per RFC 5681 §3.1, collapse
            # cwnd to ssthresh, and arm '_ecn_send_cwr' so the
            # next outbound data segment confirms the response
            # via CWR. One-shot per RTT: '_ecn_recovery_point'
            # = SND.NXT at the moment of response; subsequent
            # ECEs within the same window of data are ignored
            # until SND.UNA crosses the recovery point.
            if (
                self._ecn_enabled
                and packet_rx_md is not None
                and packet_rx_md.tcp__flag_ece
                and (self._ecn_recovery_point == 0 or le32(self._ecn_recovery_point, self._snd_una))
            ):
                flight_size = sub32(self._snd_max, self._snd_una)
                # RFC 8511 ABE: ECN signals early-warning
                # congestion (no actual loss yet); reduce
                # ssthresh by the less-aggressive 0.85
                # multiplier instead of the 0.5 used for
                # genuine packet-loss events.
                self._ssthresh = compute_ecn_event_ssthresh(flight_size, self._snd_mss)
                self._cwnd = self._ssthresh
                self._snd_ewn = min(self._cwnd, self._snd_wnd)
                self._ecn_send_cwr = True
                self._ecn_recovery_point = self._snd_nxt
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
                self._accecn_enabled
                and packet_rx_md is not None
                and packet_rx_md.tcp__accecn0_counters is not None
                and packet_rx_md.tcp__accecn0_counters[1] is not None
                and packet_rx_md.tcp__accecn0_counters[1] > self._accecn_s_ce_b
                and (self._ecn_recovery_point == 0 or le32(self._ecn_recovery_point, self._snd_una))
            ):
                flight_size = sub32(self._snd_max, self._snd_una)
                # RFC 8511 ABE: same as the RFC 3168 ECN path
                # above - on ECN-class events the sender uses
                # the less-aggressive 0.85 multiplier rather
                # than the 0.5 reserved for genuine packet
                # loss events.
                self._ssthresh = compute_ecn_event_ssthresh(flight_size, self._snd_mss)
                self._cwnd = self._ssthresh
                self._snd_ewn = min(self._cwnd, self._snd_wnd)
                self._ecn_recovery_point = self._snd_nxt
            # Always update '_accecn_s_ce_b' to the latest
            # peer-reported value so subsequent ACKs reporting
            # the same cumulative count do not fire the
            # response branch redundantly. Done outside the
            # 'if' so the tracker advances even when the
            # recovery-point guard suppresses the response
            # itself.
            if (
                self._accecn_enabled
                and packet_rx_md is not None
                and packet_rx_md.tcp__accecn0_counters is not None
                and packet_rx_md.tcp__accecn0_counters[1] is not None
            ):
                self._accecn_s_ce_b = packet_rx_md.tcp__accecn0_counters[1]
            # RFC 9768 §3.2.1 sender-side ECT(0) / ECT(1) byte
            # counter trackers. Updated alongside s.ce_b so the
            # sender's view stays synchronised with the
            # receiver's r.e0b / r.e1b. Skipped per-slot when
            # the inbound option's abbreviated form omitted
            # the counter (None) - per §3.2.3 'unchanged from
            # prior emission' semantics.
            if self._accecn_enabled and packet_rx_md is not None and packet_rx_md.tcp__accecn0_counters is not None:
                if packet_rx_md.tcp__accecn0_counters[0] is not None:
                    self._accecn_s_ect0_b = packet_rx_md.tcp__accecn0_counters[0]
                if packet_rx_md.tcp__accecn0_counters[2] is not None:
                    self._accecn_s_ect1_b = packet_rx_md.tcp__accecn0_counters[2]
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
                self._accecn_enabled
                and packet_rx_md is not None
                and packet_rx_md.tcp__accecn0_counters is None
                and not packet_rx_md.tcp__flag_syn
            ):
                incoming_ace = (
                    (int(packet_rx_md.tcp__flag_ns) << 2)
                    | (int(packet_rx_md.tcp__flag_cwr) << 1)
                    | int(packet_rx_md.tcp__flag_ece)
                )
                apparent_delta = (incoming_ace - (self._accecn_s_cep & 0b111)) & 0b111
                if apparent_delta > 0 and (
                    self._ecn_recovery_point == 0 or le32(self._ecn_recovery_point, self._snd_una)
                ):
                    flight_size = sub32(self._snd_max, self._snd_una)
                    self._ssthresh = compute_ecn_event_ssthresh(flight_size, self._snd_mss)
                    self._cwnd = self._ssthresh
                    self._snd_ewn = min(self._cwnd, self._snd_wnd)
                    self._ecn_recovery_point = self._snd_nxt
                # Always advance s.cep so subsequent ACKs
                # reporting the same ACE value are idempotent.
                self._accecn_s_cep = (self._accecn_s_cep + apparent_delta) & 0xFF_FFFF
            # Route to the per-event-kind dispatcher.
            # 'tcp_fsm()' is invoked with exactly one of the
            # three kwargs set; pick the matching dispatcher.
            if packet_rx_md is not None:
                tcp_fsm_dispatch_packet(self, packet_rx_md)
            elif syscall is not None:
                tcp_fsm_dispatch_syscall(self, syscall)
            elif timer:
                tcp_fsm_dispatch_timer(self)
