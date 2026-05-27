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
This module contains the outbound IGMP packet handler for one
interface.

pytcp/runtime/packet_handler/packet_handler__igmp__tx.py

ver 3.0.6
"""

import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

from net_addr import Ip4Address
from net_proto import (
    IgmpAssembler,
    IgmpMessage,
    IgmpMessageV1Report,
    IgmpMessageV2Leave,
    IgmpMessageV2Report,
    IgmpMessageV3Report,
    IgmpV3GroupRecord,
    IgmpV3RecordType,
    IgmpVersion,
    Ip4OptionRouterAlert,
    Ip4Options,
)
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.protocols.igmp import igmp__constants
from pytcp.runtime.timer import TimerHandle

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler

# The IPv4 destinations defined by RFC 3376 §4 / RFC 2236 §3: every
# host belongs to the all-systems group; IGMPv3 Reports go to the
# IGMPv3-routers group; an IGMPv2 Leave Group goes to the all-routers
# group.
IGMP__ALL_SYSTEMS = Ip4Address("224.0.0.1")
IGMP__ALL_ROUTERS = Ip4Address("224.0.0.2")
IGMP__ALL_IGMPV3_ROUTERS = Ip4Address("224.0.0.22")


@dataclass(frozen=True, kw_only=True, slots=True)
class _IgmpPendingChange:
    """
    A pending IGMPv3 state-change record awaiting robustness
    retransmission — the record type to re-send and the number of
    retransmissions still owed for it.
    """

    record_type: IgmpV3RecordType
    remaining: int


class IgmpTxHandler:
    """
    The outbound IGMP packet handler for one interface.
    """

    _if: "PacketHandler"
    _igmp_state_change__pending: dict[Ip4Address, _IgmpPendingChange]
    _igmp_state_change__handle: TimerHandle | None

    def __init__(self, *, interface: "PacketHandler") -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface
        self._igmp_state_change__pending = {}
        self._igmp_state_change__handle = None

    def _send_igmp_v3_report(
        self,
        *,
        record_type: IgmpV3RecordType = IgmpV3RecordType.MODE_IS_EXCLUDE,
    ) -> None:
        """
        Send an IGMPv3 Membership Report describing the interface's
        current multicast reception state — one group record per joined
        group, excluding the all-systems group 224.0.0.1 which is never
        reported (RFC 3376 §6).

        'record_type' is MODE_IS_EXCLUDE for a current-state report (the
        query-response default). The single-group state-change forms are
        emitted by '_send_igmp_state_change'.
        """

        # Dedup while preserving join order; the all-systems group is
        # exempt from reporting.
        records = [
            IgmpV3GroupRecord(type=record_type, multicast_address=group)
            for group in dict.fromkeys(self._if._ip4_multicast)
            if group != IGMP__ALL_SYSTEMS
        ]

        self._emit_v3_report(records)

    def _send_igmp_leave_all(self) -> None:
        """
        Emit a single combined IGMPv3 state-change Report transitioning
        every joined group (except the permanent all-systems group
        224.0.0.1, never reported per RFC 3376 §6) to INCLUDE{} — the
        graceful Leave a host sends on shutdown so routers prune its
        memberships immediately rather than waiting for a query timeout
        (RFC 3376 §5.1; Linux 'ip_mc_down'). No robustness retransmits
        are scheduled: this runs during teardown with the timer about to
        stop, and a report carrying no records is not emitted.
        """

        records = [
            IgmpV3GroupRecord(type=IgmpV3RecordType.CHANGE_TO_INCLUDE_MODE, multicast_address=group)
            for group in dict.fromkeys(self._if._ip4_multicast)
            if group != IGMP__ALL_SYSTEMS
        ]

        self._emit_v3_report(records)

    def _send_igmp_state_change(
        self,
        *,
        group: Ip4Address,
        record_type: IgmpV3RecordType,
    ) -> None:
        """
        Emit an unsolicited state-change report for 'group' in the form
        dictated by the interface's Host Compatibility Mode (RFC 3376
        §5.1 / §7) and schedule its robustness retransmissions.
        'record_type' is CHANGE_TO_EXCLUDE_MODE on join,
        CHANGE_TO_INCLUDE_MODE on leave; the all-systems group 224.0.0.1
        is never reported (RFC 3376 §6).

        A new change supersedes any retransmit train still pending for
        the same group (overwrite + re-seed); the retransmits recompute
        their form from the live mode + pending-change map at fire time,
        so a join cancelled by a quick leave never retransmits the stale
        join. A form that emits nothing (an IGMPv1 leave) schedules no
        retransmit.
        """

        if group == IGMP__ALL_SYSTEMS:
            return

        emitted = self._emit_state_change(group, record_type)

        repeats = igmp__constants.IGMP__ROBUSTNESS_VARIABLE - 1
        if not emitted or repeats <= 0:
            self._igmp_state_change__pending.pop(group, None)
            return

        self._igmp_state_change__pending[group] = _IgmpPendingChange(
            record_type=record_type,
            remaining=repeats,
        )
        self._arm_state_change_retransmit()

    def _arm_state_change_retransmit(self) -> None:
        """
        Ensure a single retransmit ticket is scheduled for the pending
        state-change records. RFC 3376 §5.1 spaces the robustness
        retransmissions at intervals drawn uniformly at random from (0,
        'igmp.unsolicited_report_interval' ms]; the ticket re-arms itself
        from each fire (the Linux 'igmp_ifc_timer' model) rather than
        scheduling the whole train up front, so a change arriving
        mid-train is picked up by the next fire. Reading the interval
        knob via qualified module access so an operator override resolves
        on each re-arm.
        """

        if self._igmp_state_change__handle is not None:
            return

        delay_ms = random.randint(1, igmp__constants.IGMP__UNSOLICITED_REPORT_INTERVAL__MS)
        self._igmp_state_change__handle = stack.timer.call_later(delay_ms, self._fire_state_change_retransmit)

    def _fire_state_change_retransmit(self) -> None:
        """
        Emit one robustness retransmission of the currently-pending
        state-change records in the current Host Compatibility Mode's
        form — IGMPv3 coalesces them into a single Report, IGMPv1/v2 emit
        one per group (recomputed from the live mode + pending-change
        map, so a superseded change carries its latest form) — then
        decrement each entry's remaining-repeat count, drop the exhausted
        ones, and re-arm the ticket while any repeats remain (RFC 3376
        §5.1 / §7).
        """

        self._igmp_state_change__handle = None

        groups = list(self._igmp_state_change__pending)

        if self._if._igmp_host_compatibility_mode() is IgmpVersion.V3:
            self._emit_v3_report(
                [
                    IgmpV3GroupRecord(type=self._igmp_state_change__pending[group].record_type, multicast_address=group)
                    for group in groups
                ]
            )
        else:
            for group in groups:
                self._emit_state_change(group, self._igmp_state_change__pending[group].record_type)

        for group in groups:
            pending = self._igmp_state_change__pending[group]
            if pending.remaining <= 1:
                del self._igmp_state_change__pending[group]
            else:
                self._igmp_state_change__pending[group] = _IgmpPendingChange(
                    record_type=pending.record_type,
                    remaining=pending.remaining - 1,
                )

        if self._igmp_state_change__pending:
            self._arm_state_change_retransmit()

    def _cancel_state_change_retransmits(self) -> None:
        """
        Cancel the in-flight state-change retransmit ticket and drop
        every pending per-group change record (RFC 3376 §7.2.1 — a
        compatibility-mode change cancels all pending retransmissions).
        """

        if self._igmp_state_change__handle is not None:
            stack.timer.cancel(self._igmp_state_change__handle)
            self._igmp_state_change__handle = None
        self._igmp_state_change__pending.clear()

    def _emit_igmp(self, message: IgmpMessage, ip4__dst: Ip4Address, /) -> None:
        """
        Assemble 'message' and send it to 'ip4__dst' with the IPv4
        Router Alert option and TTL=1 (RFC 3376 §4 / RFC 2236 §2). Bumps
        the shared 'igmp__pre_assemble' counter; callers bump the
        per-form send counter.
        """

        igmp_packet_tx = IgmpAssembler(igmp__message=message)

        __debug__ and log("igmp", f"{igmp_packet_tx.tracker} - {igmp_packet_tx}")

        self._if._packet_stats_tx.igmp__pre_assemble += 1

        ip4__src = self._if._ip4_unicast[0] if self._if._ip4_unicast else Ip4Address()

        self._if._marshal_tx(
            lambda: self._if._phtx_ip4(
                ip4__src=ip4__src,
                ip4__dst=ip4__dst,
                ip4__ttl=1,
                ip4__options=Ip4Options(Ip4OptionRouterAlert()),
                ip4__payload=igmp_packet_tx,
            )
        )

    def _emit_v3_report(self, records: list[IgmpV3GroupRecord], /) -> None:
        """
        Assemble and send an IGMPv3 Membership Report carrying 'records'
        to the all-IGMPv3-routers group 224.0.0.22 (RFC 3376 §4 / §9). A
        report with no records is not emitted.
        """

        if not records:
            return

        self._if._packet_stats_tx.igmp__v3_report__send += 1
        self._emit_igmp(IgmpMessageV3Report(records=records), IGMP__ALL_IGMPV3_ROUTERS)

    def _send_igmp_v3_group_current_state(self, group: Ip4Address, /) -> None:
        """
        Emit an IGMPv3 current-state Report carrying a single
        MODE_IS_EXCLUDE record for 'group' — the response to a
        Group-Specific Query (RFC 3376 §5.2).
        """

        self._emit_v3_report([IgmpV3GroupRecord(type=IgmpV3RecordType.MODE_IS_EXCLUDE, multicast_address=group)])

    def _emit_group_membership_report(self, group: Ip4Address, version: IgmpVersion, /) -> None:
        """
        Emit a per-group IGMPv1 / IGMPv2 Membership Report to the group
        address — the older-version compatibility-mode form (RFC 2236
        §3 / RFC 1112 §6). The all-systems group 224.0.0.1 is never
        reported (RFC 3376 §6).
        """

        if group == IGMP__ALL_SYSTEMS:
            return

        if version is IgmpVersion.V2:
            self._if._packet_stats_tx.igmp__v2_report__send += 1
            self._emit_igmp(IgmpMessageV2Report(group_address=group), group)
        else:
            self._if._packet_stats_tx.igmp__v1_report__send += 1
            self._emit_igmp(IgmpMessageV1Report(group_address=group), group)

    def _emit_v2_leave(self, group: Ip4Address, /) -> None:
        """
        Emit an IGMPv2 Leave Group for 'group' to the all-routers group
        224.0.0.2 (RFC 2236 §3).
        """

        self._if._packet_stats_tx.igmp__v2_leave__send += 1
        self._emit_igmp(IgmpMessageV2Leave(group_address=group), IGMP__ALL_ROUTERS)

    def _emit_state_change(self, group: Ip4Address, record_type: IgmpV3RecordType, /) -> bool:
        """
        Emit one state-change report for 'group' in the form dictated by
        the interface's RFC 3376 §7.2.1 Host Compatibility Mode, and
        return whether a packet was actually emitted:

        - IGMPv3: a single-record Membership Report (CHANGE_TO_EXCLUDE on
          join, CHANGE_TO_INCLUDE on leave) to 224.0.0.22.
        - IGMPv2: a per-group Membership Report to the group on join, an
          IGMPv2 Leave Group to 224.0.0.2 on leave (RFC 2236 §3).
        - IGMPv1: a per-group Membership Report on join; nothing on leave
          (IGMPv1 has no Leave message → returns False).
        """

        mode = self._if._igmp_host_compatibility_mode()
        is_leave = record_type is IgmpV3RecordType.CHANGE_TO_INCLUDE_MODE

        if mode is IgmpVersion.V3:
            self._emit_v3_report([IgmpV3GroupRecord(type=record_type, multicast_address=group)])
            return True
        if mode is IgmpVersion.V2:
            if is_leave:
                self._emit_v2_leave(group)
            else:
                self._emit_group_membership_report(group, IgmpVersion.V2)
            return True
        if not is_leave:  # IGMPv1 join only; v1 has no Leave message
            self._emit_group_membership_report(group, IgmpVersion.V1)
            return True
        return False
