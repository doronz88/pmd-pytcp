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

from typing import TYPE_CHECKING

from net_addr import Ip4Address
from net_proto import (
    IgmpAssembler,
    IgmpMessageV3Report,
    IgmpV3GroupRecord,
    IgmpV3RecordType,
    Ip4OptionRouterAlert,
    Ip4Options,
)
from pytcp.lib.logger import log

if TYPE_CHECKING:
    from pytcp.runtime.packet_handler import PacketHandler

# The IPv4 destinations defined by RFC 3376 §4: every host belongs to
# the all-systems group and all IGMPv3 Reports are sent to the
# IGMPv3-routers group.
IGMP__ALL_SYSTEMS = Ip4Address("224.0.0.1")
IGMP__ALL_IGMPV3_ROUTERS = Ip4Address("224.0.0.22")


class IgmpTxHandler:
    """
    The outbound IGMP packet handler for one interface.
    """

    _if: "PacketHandler"

    def __init__(self, *, interface: "PacketHandler") -> None:
        """
        Bind the handler to its owning interface.
        """

        self._if = interface

    def _send_igmp_v3_report(
        self,
        *,
        record_type: IgmpV3RecordType = IgmpV3RecordType.MODE_IS_EXCLUDE,
    ) -> None:
        """
        Send an IGMPv3 Membership Report describing the interface's
        current multicast reception state — one group record per joined
        group, excluding the all-systems group 224.0.0.1 which is never
        reported (RFC 3376 §6). The report is sent to the all-IGMPv3-
        routers group 224.0.0.22 with the IPv4 Router Alert option and
        TTL=1 (RFC 3376 §4 / §9).

        'record_type' is MODE_IS_EXCLUDE for a current-state report (the
        query-response default); the state-change forms
        (CHANGE_TO_EXCLUDE_MODE on join, CHANGE_TO_INCLUDE_MODE on
        leave) are passed by the membership-change callers.
        """

        # Dedup while preserving join order; the all-systems group is
        # exempt from reporting.
        records = [
            IgmpV3GroupRecord(type=record_type, multicast_address=group)
            for group in dict.fromkeys(self._if._ip4_multicast)
            if group != IGMP__ALL_SYSTEMS
        ]

        if not records:
            return

        igmp_packet_tx = IgmpAssembler(igmp__message=IgmpMessageV3Report(records=records))

        __debug__ and log("igmp", f"{igmp_packet_tx.tracker} - {igmp_packet_tx}")

        self._if._packet_stats_tx.igmp__pre_assemble += 1
        self._if._packet_stats_tx.igmp__v3_report__send += 1

        ip4__src = self._if._ip4_unicast[0] if self._if._ip4_unicast else Ip4Address()

        self._if._marshal_tx(
            lambda: self._if._phtx_ip4(
                ip4__src=ip4__src,
                ip4__dst=IGMP__ALL_IGMPV3_ROUTERS,
                ip4__ttl=1,
                ip4__options=Ip4Options(Ip4OptionRouterAlert()),
                ip4__payload=igmp_packet_tx,
            )
        )
