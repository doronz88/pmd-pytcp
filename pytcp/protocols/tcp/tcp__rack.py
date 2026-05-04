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
This module contains the RFC 8985 RACK-TLP per-segment state
primitives.

RFC 8985 §5.2 specifies a per-segment 'Segment' tuple that the
sender maintains for every outbound segment that consumes
sequence space. RACK consumes the tuple to drive time-based loss
detection (§6.2 step 5) and the reordering window adaptation
(§6.2 steps 3-4); TLP consumes it to identify the highest-seq
in-flight segment for retransmit-style probes (§7.3).

Phase 1 of the RACK-TLP project (per
'.claude/rules/tcp_rack_tlp.md' §4) ships only this dataclass
plus the 'INFINITE_TS' invalid-timestamp marker. Subsequent
phases consume the substrate:

    Phase 2 (RACK §6.2 step 1-2)  RACK.xmit_ts / RACK.end_seq
                                  / RACK.rtt / RACK.min_RTT
                                  per-connection scalars.
    Phase 3 (RACK §6.2 step 5)    Time-based loss detection
                                  iterating over the dict.
    Phase 5 (RACK reorder timer)  Reordering-window timer.
    Phase 7 (TLP §7.3)            Probe segment selection.

Reference RFCs:
    RFC 8985 §5.2  Per-Segment Variables
    RFC 8985 §6.1  Transmitting a data segment
    RFC 8985 §6.2  Upon receiving an ACK
    RFC 8985 §7.3  Sending a loss probe upon PTO expiration

pytcp/protocols/tcp/tcp__rack.py

ver 3.0.4
"""

from dataclasses import dataclass

# RFC 8985 §5.2 invalid-timestamp marker. A segment's 'xmit_ts'
# field is set to 'INFINITE_TS' when the segment is no longer
# considered in flight (e.g. after RACK has marked it lost via
# 'Segment.lost = True'). Subsequent ACK-processing iterations
# use the marker to skip lost segments during the §6.2 step 2
# RACK_sent_after lexicographic comparison: a segment whose
# xmit_ts is INFINITE_TS cannot be 'sent after' any real-valued
# xmit_ts because INFINITE_TS lies outside the live transmission
# window. The canonical value (0xFFFFFFFF, the maximum 32-bit
# unsigned) doubles as a sentinel that fits the 32-bit timestamp
# field width used throughout the RFC pseudocode.
INFINITE_TS: int = 0xFFFF_FFFF


@dataclass(frozen=True, slots=True)
class RackSegment:
    """
    The RFC 8985 §5.2 per-segment 'Segment' tuple.

    Stored in 'TcpSession._rack_segments' keyed by the segment's
    starting sequence number. Constructed once at transmission
    time (or replaced wholesale on retransmit, since the
    dataclass is frozen) and removed on cumulative-ACK pruning.

    Fields:
        end_seq        seq + payload_length (RFC 8985 §5.2:
                       'Segment.end_seq')
        xmit_ts        most recent transmission timestamp in
                       milliseconds; 'INFINITE_TS' iff
                       'lost == True' (RFC 8985 §5.2:
                       'Segment.xmit_ts')
        retransmitted  True iff the segment has ever been
                       retransmitted (RFC 8985 §5.2:
                       'Segment.retransmitted'). Used by RACK
                       §6.2 step 2 to skip spurious retransmit
                       samples when the TSecr cannot
                       disambiguate.
        lost           True iff RACK has declared the segment
                       lost (RFC 8985 §5.2: 'Segment.lost').
                       Used by §6.2 step 5 to drive the
                       retransmit walk and by §7.3 to skip
                       lost-but-not-yet-retransmitted bytes.
    """

    end_seq: int
    xmit_ts: int
    retransmitted: bool
    lost: bool


def rack_sent_after(t1_xmit_ts: int, t1_end_seq: int, t2_xmit_ts: int, t2_end_seq: int) -> bool:
    """
    Return True if segment 1 was 'sent after' segment 2 in the
    RFC 8985 §6.2 step 2 lexicographic sense:

        (t1.xmit_ts, t1.end_seq) > (t2.xmit_ts, t2.end_seq)

    Ties on 'xmit_ts' are broken by the segment's 'end_seq' so
    two segments transmitted in the same millisecond keep a
    stable relative order.

    The 'end_seq' tie-breaker uses modular comparison via the
    ordinary signed delta: when both segments belong to the
    same flight (i.e. their end_seqs are within UINT_31 of each
    other in modular space) the comparison is unambiguous. The
    pseudocode in RFC 8985 uses '>' on the seq field, which
    PyTCP implements via the modular helpers in
    'pytcp.protocols.tcp.tcp__seq'.
    """

    if t1_xmit_ts != t2_xmit_ts:
        return t1_xmit_ts > t2_xmit_ts
    # Modular '>' on end_seq via the standard PyTCP helper.
    from pytcp.protocols.tcp.tcp__seq import gt32

    return gt32(t1_end_seq, t2_end_seq)


def rack_update(
    *,
    newly_acked_segments: list[RackSegment],
    now_ms: int,
    ts_recent_echo_ms: int | None,
    prior_min_rtt_ms: int,
    prior_rack_rtt_ms: int,
    prior_rack_xmit_ts: int,
    prior_rack_end_seq: int,
) -> tuple[int, int, int, int]:
    """
    Apply the RFC 8985 §6.2 step 1-2 update on the per-connection
    RACK scalars given a list of segments freshly acknowledged
    by an inbound ACK.

    Pseudocode (RFC 8985 §6.2 step 2):

        For each newly-acked segment in ascending xmit_ts order:
            rtt = now_ms - segment.xmit_ts
            If segment.retransmitted:
                If TSecr < segment.xmit_ts: continue
                If rtt < min_RTT: continue
            min_RTT = min(min_RTT, rtt)   # §B.1 algorithm
            RACK.rtt = rtt
            If RACK_sent_after(segment.xmit_ts, segment.end_seq,
                               RACK.xmit_ts, RACK.end_seq):
                RACK.xmit_ts = segment.xmit_ts
                RACK.end_seq = segment.end_seq

    The two retransmit-skip conditions guard against using a
    spurious retransmit's RTT to update RACK.rtt: 'TSecr <
    segment.xmit_ts' indicates the ACK is for an earlier
    transmission of this segment (RFC 7323 §4 disambiguation),
    while 'rtt < min_RTT' is a heuristic for the same condition
    when timestamps are unavailable.

    Parameters:
        newly_acked_segments: segments whose 'end_seq' is
                              newly covered by SND.UNA on this
                              ACK; the caller computes this
                              set before the cum-ACK pruning
                              fires.
        now_ms:               virtual clock at the moment the
                              ACK was received.
        ts_recent_echo_ms:    peer's TSecr value if RFC 7323
                              timestamps are negotiated; None
                              otherwise.
        prior_min_rtt_ms:     RACK.min_RTT before this ACK
                              (0 means uninitialized).
        prior_rack_rtt_ms:    RACK.rtt before this ACK.
        prior_rack_xmit_ts:   RACK.xmit_ts before this ACK.
        prior_rack_end_seq:   RACK.end_seq before this ACK.

    Returns: (new_min_rtt_ms, new_rack_rtt_ms,
              new_rack_xmit_ts, new_rack_end_seq).
    """

    min_rtt_ms = prior_min_rtt_ms
    rack_rtt_ms = prior_rack_rtt_ms
    rack_xmit_ts = prior_rack_xmit_ts
    rack_end_seq = prior_rack_end_seq

    # Iterate in ascending xmit_ts order per the RFC pseudocode.
    # Sort by (xmit_ts, end_seq) so segments transmitted in the
    # same millisecond remain in seq order.
    for seg in sorted(newly_acked_segments, key=lambda s: (s.xmit_ts, s.end_seq)):
        rtt_ms = now_ms - seg.xmit_ts

        if seg.retransmitted:
            # Skip if peer's TSecr identifies an earlier
            # transmission of this segment (RFC 7323 §4
            # disambiguation, RFC 8985 §6.2 step 2 condition 1).
            if ts_recent_echo_ms is not None and ts_recent_echo_ms < seg.xmit_ts:
                continue
            # Skip if rtt is implausibly small compared to the
            # minimum observed RTT - heuristic guard against
            # spurious-retransmit samples in non-TSopt
            # connections (RFC 8985 §6.2 step 2 condition 2).
            if min_rtt_ms > 0 and rtt_ms < min_rtt_ms:
                continue

        # RFC 8985 §B.1 min_RTT update: track the minimum across
        # all accepted samples. 'min_rtt_ms == 0' is the
        # uninitialized sentinel; on the first sample seed it
        # rather than taking the minimum with zero.
        if min_rtt_ms == 0 or rtt_ms < min_rtt_ms:
            min_rtt_ms = rtt_ms
        rack_rtt_ms = rtt_ms

        if rack_sent_after(seg.xmit_ts, seg.end_seq, rack_xmit_ts, rack_end_seq):
            rack_xmit_ts = seg.xmit_ts
            rack_end_seq = seg.end_seq

    return min_rtt_ms, rack_rtt_ms, rack_xmit_ts, rack_end_seq
