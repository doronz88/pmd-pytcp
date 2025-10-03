#!/usr/bin/env python3

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
This module contains packet handler for the inbound ARP packets.

pytcp/subsystems/packet_handler/packet_handler__arp__rx.py

ver 3.0.4
"""


from abc import ABC
from typing import TYPE_CHECKING

from net_proto import ArpOperation, ArpParser, PacketRx, PacketValidationError
from pytcp import stack
from pytcp.lib.logger import log


class PacketHandlerArpRx(ABC):
    """
    Class implementing packet handler for the inbound ARP packets.
    """

    if TYPE_CHECKING:
        from net_addr import Ip4Address, Ip4Host, MacAddress
        from net_proto import Tracker
        from pytcp.lib.packet_stats import PacketStatsRx
        from pytcp.lib.tx_status import TxStatus

        _mac_unicast: MacAddress
        _ip4_host: list[Ip4Host]
        _packet_stats_rx: PacketStatsRx
        _ip4_host_candidate: list[Ip4Host]

        # pylint: disable=unused-argument

        def _phtx_arp(
            self,
            *,
            ethernet__src: MacAddress,
            ethernet__dst: MacAddress,
            arp__oper: ArpOperation,
            arp__sha: MacAddress,
            arp__spa: Ip4Address,
            arp__tha: MacAddress,
            arp__tpa: Ip4Address,
            echo_tracker: Tracker | None = None,
        ) -> TxStatus: ...

        def _send_arp_reply(
            self,
            *,
            arp__spa: Ip4Address,
            arp__tha: MacAddress,
            arp__tpa: Ip4Address,
            tracker: Tracker | None = None,
        ) -> None: ...

        def _send_gratuitous_arp(self, *, ip4_unicast: Ip4Address) -> None: ...

        # pylint: disable=missing-function-docstring

        @property
        def _ip4_unicast(self) -> list[Ip4Address]: ...

    def _phrx_arp(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound ARP packets.
        """

        self._packet_stats_rx.inc("arp__pre_parse")

        try:
            ArpParser(packet_rx)

        except PacketValidationError as error:
            self._packet_stats_rx.inc("arp__failed_parse__drop")
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            return

        __debug__ and log("arp", f"{packet_rx.tracker} - {packet_rx.arp}")

        match packet_rx.arp.oper:
            case ArpOperation.REQUEST:
                self.__phrx_arp__request(packet_rx)
            case ArpOperation.REPLY:
                self.__phrx_arp__reply(packet_rx)
            case _:
                self._packet_stats_rx.inc("arp__op_unknown__drop")
                __debug__ and log(
                    "ether",
                    f"{packet_rx.tracker} - Unsupported operation "
                    f"{packet_rx.arp.oper}, dropping.",
                )

    def __update_arp_cache(
        self, *, packet_rx: PacketRx, counter_name: str
    ) -> None:
        """
        Update ARP cache with the SPA<->SHA mapping if the packet is intended for us.
        """

        # If SPA matches on of our subnets then update ARP cache with the SPA<->SHA mapping.
        # Also ensure we update cache only if the packet is either direct or broadcast to
        # avoid updating cache with packets not intended for us in case interface is in
        # promiscuous mode.
        if any(
            packet_rx.arp.spa in host.network for host in self._ip4_host
        ) and (
            packet_rx.ethernet.dst == self._mac_unicast
            or packet_rx.ethernet.dst.is_broadcast
        ):
            self._packet_stats_rx.inc(counter_name)
            stack.arp_cache.add_entry(
                ip4_address=packet_rx.arp.spa,
                mac_address=packet_rx.arp.sha,
            )

    def __phrx_arp__request(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ARP request packets.
        """

        self._packet_stats_rx.inc("arp__op_request")

        # Drop any ARP request if it is originated from us and looped for whatever.
        if (
            packet_rx.arp.spa in self._ip4_unicast
            or packet_rx.arp.spa.is_unspecified
        ) and packet_rx.arp.sha == self._mac_unicast:
            self._packet_stats_rx.inc("arp__op_request__looped")
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <WARN>IP Received our own ARP request for "
                f"{packet_rx.arp.tpa} from {packet_rx.arp.spa}, dropping.</>",
            )
            return

        # Defend against IP address conflict if we got ARP request from another host
        # that is trying to claim one of our IP addresses.
        if (
            packet_rx.arp.spa in self._ip4_unicast
            and packet_rx.arp.sha != self._mac_unicast
        ):
            self._packet_stats_rx.inc("arp__op_request__ip_conflict__defend")
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <WARN>IP {packet_rx.arp.spa} "
                f"conflict detected with host at {packet_rx.arp.sha}</>",
            )
            self._send_gratuitous_arp(ip4_unicast=packet_rx.arp.spa)
            return

        # Note receiving gratuitous ARP request.
        if (
            packet_rx.ethernet.dst.is_broadcast
            and packet_rx.arp.spa.is_unicast
            and packet_rx.arp.spa == packet_rx.arp.tpa
            and packet_rx.arp.tha.is_unspecified
        ):
            self._packet_stats_rx.inc("arp__op_request__gratuitous")

        # Note receiving ARP request not for our IP address.
        elif packet_rx.arp.tpa not in self._ip4_unicast:
            self._packet_stats_rx.inc("arp__op_request__tpa_unknown")
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <INFO>Dropping ARP request for unknown TPA "
                f"{packet_rx.arp.tpa} from {packet_rx.arp.spa}</>",
            )

        else:
            # Note receiving ARP probe (RFC 5227).
            if packet_rx.arp.spa.is_unspecified:
                self._packet_stats_rx.inc("arp__op_request__probe")
                __debug__ and log(
                    "arp",
                    f"{packet_rx.tracker} - <INFO>Replying to the ARP probe for TPA "
                    f"{packet_rx.arp.tpa} from {packet_rx.arp.spa}</>",
                )

            # Note receiving regular ARP request.
            if packet_rx.arp.spa.is_unicast:
                self._packet_stats_rx.inc("arp__op_request__tpa_stack")
                __debug__ and log(
                    "arp",
                    f"{packet_rx.tracker} - <INFO>Replying to ARP request for TPA "
                    f"{packet_rx.arp.tpa} from {packet_rx.arp.spa}</>",
                )

            # Send ARP reply packet to requester.
            if (
                packet_rx.ethernet.dst.is_broadcast
                or packet_rx.ethernet.dst == self._mac_unicast
            ):
                self._packet_stats_rx.inc("arp__op_request__respond")
                self._send_arp_reply(
                    arp__spa=packet_rx.arp.tpa,
                    arp__tha=packet_rx.arp.sha,
                    arp__tpa=packet_rx.arp.spa,
                    tracker=packet_rx.tracker,
                )

        self.__update_arp_cache(
            packet_rx=packet_rx,
            counter_name="arp__op_request__update_arp_cache",
        )

    def __phrx_arp__reply(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ARP reply packets.
        """

        self._packet_stats_rx.inc("arp__op_reply")

        # Drop any ARP reply if it is originated from us and looped for whatever.
        if (
            packet_rx.arp.spa in self._ip4_unicast
            and packet_rx.arp.sha == self._mac_unicast
        ):
            self._packet_stats_rx.inc("arp__op_reply__looped__drop")
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <WARN>IP Received our own ARP reply for "
                f"{packet_rx.arp.tpa} from {packet_rx.arp.spa}, dropping.</>",
            )
            return

        # Defend against IP address conflict if we got ARP reply from another host
        # that is trying to claim one of our IP addresses.
        if (
            packet_rx.arp.spa in self._ip4_unicast
            and packet_rx.arp.sha != self._mac_unicast
        ):
            self._packet_stats_rx.inc("arp__op_reply__ip_conflict__defend")
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <WARN>IP {packet_rx.arp.spa} "
                f"conflict detected with host at {packet_rx.arp.sha}</>",
            )
            self._send_gratuitous_arp(ip4_unicast=packet_rx.arp.spa)
            return

        # Check for ARP reply that is response to our ARP probe, this indicates
        # the IP address we trying to claim is in use.
        if packet_rx.arp.tha == self._mac_unicast:
            if (
                packet_rx.arp.spa
                in [_.address for _ in self._ip4_host_candidate]
                and packet_rx.arp.tha == self._mac_unicast
                and packet_rx.arp.tpa.is_unspecified
            ):
                self._packet_stats_rx.inc("arp__op_reply__ip_conflict")
                __debug__ and log(
                    "arp",
                    f"{packet_rx.tracker} - <WARN>ARP probe detected "
                    f"conflict for IP {packet_rx.arp.spa} with host at "
                    f"{packet_rx.arp.sha}</>",
                )
                stack.arp_probe_unicast_conflict.add(packet_rx.arp.spa)
                return

        # Note receiving packet as direct ARP reply.
        if packet_rx.ethernet.dst == self._mac_unicast:
            self._packet_stats_rx.inc("arp__op_reply__direct")
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <INFO>Received direct ARP reply, "
                f"{packet_rx.arp.spa} -> {packet_rx.arp.sha}</>",
            )

        # Note receiving packet as gratuitous ARP reply.
        if (
            packet_rx.ethernet.dst.is_broadcast
            and packet_rx.arp.spa == packet_rx.arp.tpa
        ):
            self._packet_stats_rx.inc("arp__op_reply__gratuitous")
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <INFO>Received gratuitous ARP reply, "
                f"{packet_rx.arp.spa} -> {packet_rx.arp.sha}</>",
            )

        self.__update_arp_cache(
            packet_rx=packet_rx, counter_name="arp__op_reply__update_arp_cache"
        )
