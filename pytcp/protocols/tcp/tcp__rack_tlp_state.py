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
This module contains the per-session RACK + TLP state container,
decomposed out of 'TcpSession' so the RFC 8985 segment scoreboard,
RTT trackers, reorder-window state, DSACK round marker, and Tail
Loss Probe state live as one coherent object.

RACK and TLP share this container because they are defined under
one RFC (RFC 8985) and operate on overlapping concerns: RACK
provides the loss-detection primitive that TLP uses on probe
ACKs (§7.4), and the §6.2 step 4 reo_wnd_persist counter decays
on every recovery exit regardless of whether a TLP probe was the
trigger.

pytcp/protocols/tcp/tcp__rack_tlp_state.py

ver 3.0.4
"""

from dataclasses import dataclass, field

from pytcp.protocols.tcp.tcp__rack import RackSegment
from pytcp.protocols.tcp.tcp__seq import Seq32

# RFC 8985 §6.2 step 4 reorder-window persist counter default.
# Decrements on each recovery exit; resets the multiplier back
# to 1 after this many consecutive recoveries without DSACK so
# the connection eventually decays back to the canonical
# reordering tolerance.
RACK__REO_WND_PERSIST_DEFAULT: int = 16

# RFC 8985 §6.2 step 4 reo_wnd_mult initial value. Multiplier on
# the 'min_RTT / 4' base; bumped by DSACK-round closure when the
# peer reports spurious retransmits.
RACK__REO_WND_MULT_INITIAL: int = 1

# RFC 8985 §7.2 TLP receiver-delay upper bound (Linux default).
# Used by the TLP PTO formula to inflate the probe timeout
# enough to outlast a delayed-ACK without overlapping the RTO.
TLP__MAX_ACK_DELAY_MS_DEFAULT: int = 25


@dataclass(slots=True)
class RackTlpState:
    """
    Per-session RACK + TLP state. Owned by 'TcpSession'; mutated
    in place by '_phase4_advance_send_state' (record on send),
    '_phase4_loss_detection_and_recovery_exit' (RACK fold + dict
    prune + reo_wnd_persist decay), and the TLP arming /
    cancellation paths in '_phase5_post_send_timers' /
    '_phase1_cum_ack_side_effects'.
    """

    # RFC 8985 §5.2 / §6.1 per-segment scoreboard. One
    # 'RackSegment' entry per outbound segment that consumes
    # sequence space (data / SYN / FIN). Keyed by the
    # segment's starting seq. Pruned when SND.UNA advances
    # past the entry's 'end_seq'.
    rack_segments: dict[Seq32, RackSegment] = field(default_factory=dict)

    # RFC 8985 §5.3 / §6.2 step 1-2 RACK per-connection
    # scalars. Updated by 'rack_update' on every accepted
    # ACK whose cum-ACK boundary newly covers segments in
    # 'rack_segments':
    #   - 'rack_min_rtt_ms' as the lower bound for the §6.2
    #     step 2 spurious-retransmit heuristic and as a
    #     floor for the §6.2 step 4 reordering-window calc.
    #   - 'rack_rtt_ms' as the freshest accepted-sample RTT,
    #     used in §6.2 step 5's loss-detection timeout.
    #   - 'rack_xmit_ts' / 'rack_end_seq' as the latest
    #     'sent_after' lexicographic-key pair for the §6.2
    #     step 5 'rack_sent_after' branch.
    rack_min_rtt_ms: int = 0
    rack_rtt_ms: int = 0
    rack_xmit_ts: int = 0
    rack_end_seq: Seq32 = 0

    # RFC 8985 §6.2 step 1-2 'newly acknowledged' guard.
    # rack_update only takes RTT samples from segments that
    # have not been folded yet on a prior ACK; an entry is
    # added here once it has contributed to the rack_update
    # scalars, and removed when the entry is pruned from
    # 'rack_segments' on cum-ACK. Distinct from cum-ACK
    # pruning so SACK-acked segments are tracked here even
    # while their dict entry stays alive.
    rack_acked_seqs: set[Seq32] = field(default_factory=set)

    # RFC 8985 §6.2 step 3 reordering detection state.
    # 'rack_reordering_seen' becomes True the first time an
    # ACK delivers a segment whose 'end_seq' is strictly
    # below 'rack_fack' (the highest end_seq cumulatively or
    # selectively acked so far); once seen it stays True for
    # the lifetime of the connection.
    rack_reordering_seen: bool = False
    rack_fack: Seq32 = 0

    # RFC 8985 §6.2 step 4 reo_wnd_mult / persist counter.
    # The multiplier scales the 'min_RTT / 4' base when DSACK
    # indicates spurious retransmits. The persist counter
    # decrements on each recovery exit and resets the
    # multiplier to 1 after RACK__REO_WND_PERSIST_DEFAULT
    # consecutive recoveries without DSACK.
    rack_reo_wnd_mult: int = RACK__REO_WND_MULT_INITIAL
    rack_reo_wnd_persist: int = RACK__REO_WND_PERSIST_DEFAULT

    # RFC 8985 §6.2 step 4 DSACK-round marker. Holds the
    # SND.MAX value at the moment a DSACK was observed; the
    # next ACK that advances SND.UNA past this marker closes
    # the round and increments 'rack_reo_wnd_mult'. None
    # means no DSACK round is in progress.
    rack_dsack_round: Seq32 | None = None

    # RFC 8985 §7 Tail Loss Probe state. The TLP timer
    # 'f"{self}-tlp"' is armed on every outbound data
    # segment send when no recovery is in progress and
    # cancelled on cum-ACK that drains all in-flight bytes.
    # When the timer fires, the §7.3 probe-emission path
    # sends a probe to elicit an ACK that lets RACK detect
    # tail-of-flow losses faster than the RTO timer.
    #
    # 'tlp_is_retrans' marks whether the most recent probe
    # was a retransmit (vs new data); the §7.4 loss-
    # detection path uses this to decide whether to invoke
    # the CC response. 'tlp_end_seq' is SND.MAX at probe
    # send; cleared by §7.4 once the outcome is known.
    # 'tlp_max_ack_delay_ms' is the receiver's delayed-ACK
    # upper bound used by the §7.2 PTO inflation path.
    # 'tlp_armed' gates _tlp_pto_tick firing on actual arming
    # (distinct from 'stack.timer.is_expired' which conflates
    # 'expired' with 'never registered').
    tlp_is_retrans: bool = False
    tlp_end_seq: Seq32 | None = None
    tlp_max_ack_delay_ms: int = TLP__MAX_ACK_DELAY_MS_DEFAULT
    tlp_armed: bool = False
