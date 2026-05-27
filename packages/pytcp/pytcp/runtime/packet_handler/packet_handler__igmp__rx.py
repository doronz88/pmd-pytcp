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

from net_proto import (
    IgmpMessageV1Report,
    IgmpMessageV2Report,
    IgmpType,
    IgmpVersion,
    PacketValidationError,
)
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.igmp.igmp__parser import IgmpParser
from net_proto.protocols.igmp.message.igmp__message__query import (
    IgmpMessageQuery,
)
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.igmp import igmp__constants

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
                self.__phrx_igmp__report(packet_rx)

    def __phrx_igmp__report(self, packet_rx: PacketRx) -> None:
        """
        Handle an inbound IGMP Report/Leave from another host.

        An IGMPv3 host does not suppress its reports (RFC 3376 §7.2.2 is
        a MAY) — it counts and ignores. In IGMPv1/v2 compatibility mode
        (RFC 2236 §3), hearing another host's v1/v2 Membership Report for
        a group this host has joined, while a Query response is pending,
        suppresses this host's own pending Report for that group.
        """

        self._if._packet_stats_rx.igmp__membership_report += 1

        message = packet_rx.igmp.message
        if (
            self._if._igmp_host_compatibility_mode() is not IgmpVersion.V3
            and self._if._igmp_query__pending_response_at_ms is not None
            and isinstance(message, (IgmpMessageV1Report, IgmpMessageV2Report))
            and message.group_address in self._if._ip4_multicast
            and message.group_address not in self._if._igmp_query__suppressed_groups
        ):
            self._if._igmp_query__suppressed_groups.add(message.group_address)
            self._if._packet_stats_rx.igmp__membership_query__suppressed += 1
            __debug__ and log(
                "igmp",
                f"{packet_rx.tracker} - Suppressing pending Report for {message.group_address}",
            )
            return

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

        The response form follows the Host Compatibility Mode (RFC 3376
        §7); deferred refinements are the per-group response to a
        Group-Specific Query and the IGMPv1 default Max Resp Time.
        """

        self._if._packet_stats_rx.igmp__membership_query += 1
        __debug__ and log(
            "igmp",
            f"{packet_rx.tracker} - Received IGMP Membership Query from {packet_rx.ip4.src}",
        )

        message = packet_rx.igmp.message
        assert isinstance(message, IgmpMessageQuery)

        # RFC 3376 §7.2.1 — arm the Older Version Querier Present timer
        # and, on a mode change, cancel pending IGMP timers, before
        # scheduling this Query's response.
        self._igmp_update_compatibility_mode(message)

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
            # This Query supersedes the pending one; cancel its timer and
            # reset the suppression set for the new response window.
            if self._if._igmp_query__handle is not None:
                stack.timer.cancel(self._if._igmp_query__handle)
            self._if._igmp_query__suppressed_groups.clear()
            self._if._packet_stats_rx.igmp__membership_query__superseded += 1

        self._if._igmp_query__pending_response_at_ms = response_at
        self._if._igmp_query__handle = stack.timer.call_later(delay_ms, self._igmp_query__deferred_send)
        self._if._packet_stats_rx.igmp__membership_query__scheduled += 1

    def _igmp_update_compatibility_mode(self, message: IgmpMessageQuery, /) -> None:
        """
        Arm the RFC 3376 §7.2.1 Older Version Querier Present timer for
        an older-version (v1/v2) General Query and, if that changes the
        interface's Host Compatibility Mode, cancel all pending IGMP
        response and retransmission timers (the mode switch is
        immediate). A v3 Query never lowers the mode.

        The §8.12 timeout is [Robustness Variable] × [Query Interval] +
        [Query Response Interval]; a v1/v2 Query carries no QQIC so the
        default 'igmp.query_interval' is used, and a v1 Query's Max Resp
        Code of 0 is interpreted as 100 (10 s) per §7.2.1.
        """

        if message.version is IgmpVersion.V3:
            return

        old_mode = self._if._igmp_host_compatibility_mode()

        query_response_interval_deci = message.max_response_time if message.version is IgmpVersion.V2 else 100
        timeout_ms = (
            igmp__constants.IGMP__ROBUSTNESS_VARIABLE * igmp__constants.IGMP__QUERY_INTERVAL__MS
            + query_response_interval_deci * IGMP__MAX_RESP_TIME__UNIT_MS
        )
        deadline_ms = stack.timer.now_ms + timeout_ms

        if message.version is IgmpVersion.V1:
            self._if._igmp__v1_querier_present_until_ms = deadline_ms
        else:
            self._if._igmp__v2_querier_present_until_ms = deadline_ms

        if self._if._igmp_host_compatibility_mode() is not old_mode:
            self._igmp_cancel_pending_timers()

    def _igmp_cancel_pending_timers(self) -> None:
        """
        Cancel the pending query-response timer and the state-change
        retransmit train (RFC 3376 §7.2.1 — a compatibility-mode change
        cancels all pending response and retransmission timers).
        """

        if self._if._igmp_query__handle is not None:
            stack.timer.cancel(self._if._igmp_query__handle)
            self._if._igmp_query__handle = None
        self._if._igmp_query__pending_response_at_ms = None
        self._if._igmp_tx._cancel_state_change_retransmits()

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
        Emit the Query response in the form dictated by the interface's
        Host Compatibility Mode (RFC 3376 §7) and bump the canonical
        'igmp__membership_query__respond' counter. Shared between the
        immediate-send (delay 0) and deferred-send (timer-fired) paths.

        IGMPv3 emits one current-state Report covering all joined
        groups; IGMPv1/v2 emit a per-group Membership Report to each
        joined group's address (RFC 2236 §3 / RFC 1112 §6).
        """

        mode = self._if._igmp_host_compatibility_mode()
        if mode is IgmpVersion.V3:
            self._if._send_igmp_v3_report()
        else:
            for group in dict.fromkeys(self._if._ip4_multicast):
                if group not in self._if._igmp_query__suppressed_groups:
                    self._if._igmp_tx._emit_group_membership_report(group, mode)

        self._if._igmp_query__suppressed_groups.clear()
        self._if._packet_stats_rx.igmp__membership_query__respond += 1
