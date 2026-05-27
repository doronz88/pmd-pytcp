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
This module contains the inbound IGMP packet handler for one interface.

pytcp/runtime/packet_handler/packet_handler__igmp__rx.py

ver 3.0.6
"""

import random
from typing import TYPE_CHECKING

from net_proto import IgmpType, PacketValidationError
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.igmp.igmp__parser import IgmpParser
from net_proto.protocols.igmp.message.igmp__message__query import (
    IgmpMessageQuery,
)
from pytcp import stack
from pytcp.lib.logger import log

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler

# IGMP Max Resp Time is expressed in units of 1/10 second (RFC 3376
# §4.1.1); the host state machine works in milliseconds.
IGMP__MAX_RESP_TIME__UNIT_MS = 100


class IgmpRxHandler:
    """
    The inbound IGMP packet handler for one interface.
    """

    _if: "PacketHandler"

    def __init__(self, *, interface: "PacketHandler") -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface

    def _phrx_igmp(self, packet_rx: PacketRx, /) -> None:
        """
        Handle an inbound IGMP packet — parse it, then dispatch a
        Membership Query to the query-response state machine. Reports
        and Leaves received from other hosts are counted and ignored
        (a host does not act on another host's Report; IGMPv3 has no
        Report suppression, and v2 suppression is deferred).
        """

        self._if._packet_stats_rx.igmp__pre_parse += 1

        # RFC 3376 §4 — IGMP messages are sent with an IP TTL of 1; Linux
        # drops inbound IGMP with TTL != 1 as martian. The Router Alert
        # option is NOT required on receipt (IGMPv2 senders predate it),
        # matching Linux leniency.
        if packet_rx.ip4.ttl != 1:
            __debug__ and log(
                "igmp",
                f"{packet_rx.tracker} - <CRIT>Dropping IGMP with TTL {packet_rx.ip4.ttl} (expected 1)</>",
            )
            self._if._packet_stats_rx.igmp__ttl_invalid__drop += 1
            return

        try:
            IgmpParser(packet_rx)

        except PacketValidationError as error:
            __debug__ and log("igmp", f"{packet_rx.tracker} - <CRIT>{error}</>")
            self._if._packet_stats_rx.igmp__failed_parse__drop += 1
            return

        __debug__ and log("igmp", f"{packet_rx.tracker} - {packet_rx.igmp}")

        match packet_rx.igmp.message.type:
            case IgmpType.MEMBERSHIP_QUERY:
                self.__phrx_igmp__membership_query(packet_rx)
            case _:
                # A Report (v1/v2/v3) or Leave received from another
                # host — silently ignored by a host listener.
                self._if._packet_stats_rx.igmp__membership_report += 1
                __debug__ and log(
                    "igmp",
                    f"{packet_rx.tracker} - Received IGMP Report/Leave from {packet_rx.ip4.src} (ignored)",
                )

    def __phrx_igmp__membership_query(self, packet_rx: PacketRx) -> None:
        """
        Handle an inbound IGMP Membership Query.

        Reference: RFC 3376 §5.2 (host Query-response state machine).

        The host schedules a current-state IGMPv3 Report at a uniformly-
        random delay in [0, Max Resp Time] so a link with many members
        spreads its Report burst across the response window. A Query
        whose computed response time is later than an already-pending
        Report is absorbed; an earlier one supersedes the pending timer.

        Phase-5 refinements (deferred): per-group response to a Group-
        Specific Query, the IGMPv1 default Max Resp Time, and the
        querier-version (v1/v2) report-form fallback.
        """

        self._if._packet_stats_rx.igmp__membership_query += 1
        __debug__ and log(
            "igmp",
            f"{packet_rx.tracker} - Received IGMP Membership Query from {packet_rx.ip4.src}",
        )

        message = packet_rx.igmp.message
        assert isinstance(message, IgmpMessageQuery)

        max_resp_ms = message.max_response_time * IGMP__MAX_RESP_TIME__UNIT_MS
        delay_ms = self._igmp_query__pick_response_delay_ms(max_resp_ms)

        # Delay 0 is the "respond now" case — bypass the timer (the
        # Timer subsystem only fires when its countdown reaches 0, so a
        # 0-delay registration would dangle).
        if delay_ms == 0:
            self._igmp_query__send_now()
            return

        response_at = stack.timer.now_ms + delay_ms
        pending = self._if._igmp_query__pending_response_at_ms
        if pending is not None and pending <= response_at:
            # Existing pending Report fires sooner; absorb this Query.
            return

        if pending is not None:
            # This Query supersedes the pending one; cancel its timer.
            if self._if._igmp_query__handle is not None:
                stack.timer.cancel(self._if._igmp_query__handle)
            self._if._packet_stats_rx.igmp__membership_query__superseded += 1

        self._if._igmp_query__pending_response_at_ms = response_at
        self._if._igmp_query__handle = stack.timer.call_later(delay_ms, self._igmp_query__deferred_send)
        self._if._packet_stats_rx.igmp__membership_query__scheduled += 1

    def _igmp_query__pick_response_delay_ms(self, max_resp_ms: int, /) -> int:
        """
        RFC 3376 §5.2 random-response delay: a uniformly-random integer
        in [0, max_resp_ms]. Extracted so tests can patch it
        deterministically.
        """

        return random.randint(0, max_resp_ms)

    def _igmp_query__deferred_send(self) -> None:
        """
        Timer-fired callback that emits the pending IGMPv3 Report and
        clears the per-interface pending-response state.
        """

        self._if._igmp_query__pending_response_at_ms = None
        self._if._igmp_query__handle = None
        self._igmp_query__send_now()

    def _igmp_query__send_now(self) -> None:
        """
        Emit the current-state IGMPv3 Report and bump the canonical
        'igmp__membership_query__respond' counter. Shared between the
        immediate-send (delay 0) and deferred-send (timer-fired) paths.
        """

        self._if._send_igmp_v3_report()
        self._if._packet_stats_rx.igmp__membership_query__respond += 1
