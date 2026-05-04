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
