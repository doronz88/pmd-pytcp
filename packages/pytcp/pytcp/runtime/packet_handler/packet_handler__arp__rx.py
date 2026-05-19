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

ver 3.0.6
"""

import time
from abc import ABC
from typing import TYPE_CHECKING

from net_proto import ArpOperation, ArpParser, PacketRx, PacketValidationError
from pytcp import stack
from pytcp.lib.dad_slot_registry import DadSlotRegistry
from pytcp.lib.logger import log
from pytcp.protocols.arp import arp__constants
from pytcp.protocols.arp.arp__constants import ARP__DEFEND_INTERVAL


class PacketHandlerArpRx(ABC):
    """
    Class implementing packet handler for the inbound ARP packets.
    """

    if TYPE_CHECKING:
        from net_addr import Ip4Address, Ip4IfAddr, MacAddress
        from net_proto import Tracker
        from pytcp.lib.packet_stats import PacketStatsRx
        from pytcp.lib.tx_status import TxStatus

        _mac_unicast: MacAddress
        _ip4_ifaddr: list[Ip4IfAddr]
        _packet_stats_rx: PacketStatsRx
        _ip4_ifaddr_candidate: list[Ip4IfAddr]
        _ip4_arp_dad__registry: DadSlotRegistry[Ip4Address]
        _arp_defend__last_emitted: dict[Ip4Address, float]
        _arp_defend__last_conflict_at: dict[Ip4Address, float]

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

    def _handle_arp_conflict(self, *, ip4_unicast: "Ip4Address") -> None:
        """
        Handle an observed conflicting ARP packet for one of
        our IPv4 addresses. Implements RFC 5227 §2.4(b) MUST
        plus the §2.4(c) rate-limit:

          - Second conflict within DEFEND_INTERVAL of the
            previous conflict → abandon the address (the §2.4(b)
            MUST). No defense is emitted; the address is removed
            from '_ip4_ifaddr'; bound TcpSessions are aborted
            (§2.4 final SHOULD).
          - Otherwise → fire a defensive gratuitous ARP, gated by
            the per-IP last-defended-at rate-limit (§2.4(c)
            MUST NOT defend more than once per DEFEND_INTERVAL).

        Replaces the old '_maybe_send_arp_defense' helper —
        same call sites in the conflict-defense paths of
        '__phrx_arp__request' and '__phrx_arp__reply'.
        """

        now = time.monotonic()
        prior_conflict = self._arp_defend__last_conflict_at.get(ip4_unicast)
        self._arp_defend__last_conflict_at[ip4_unicast] = now

        if prior_conflict is not None and now - prior_conflict < ARP__DEFEND_INTERVAL:
            # Second conflict within window — RFC 5227 §2.4(b) MUST abandon.
            self._abandon_ipv4_address(ip4_unicast=ip4_unicast)
            return

        # First conflict (or after window) — defend, gated by
        # the §2.4(c) per-IP rate-limit on emitted defenses.
        last_defense = self._arp_defend__last_emitted.get(ip4_unicast)
        if last_defense is not None and now - last_defense < ARP__DEFEND_INTERVAL:
            return
        self._arp_defend__last_emitted[ip4_unicast] = now
        self._send_gratuitous_arp(ip4_unicast=ip4_unicast)

    def _abandon_ipv4_address(self, *, ip4_unicast: "Ip4Address") -> None:
        """
        Tear down all TCP sessions bound to 'ip4_unicast' and
        remove it from '_ip4_ifaddr' — RFC 5227 §2.4(b) MUST
        ("immediately cease using this address") plus the
        §2.4-final SHOULD ("hosts SHOULD actively attempt to
        reset any existing connections using that address").
        """

        # RFC 5227 §2.4-final SHOULD: ABORT any TcpSession
        # bound to this address. The session-side ABORT
        # syscall sends RST and tears down the session per
        # RFC 9293 §3.10.7.4.
        from pytcp.protocols.tcp.tcp__enums import SysCall

        for socket_id in list(stack.sockets):
            if socket_id.local_address == ip4_unicast:
                sock = stack.sockets[socket_id]
                session = getattr(sock, "_tcp_session", None)
                if session is not None:
                    session.tcp_fsm(syscall=SysCall.ABORT)

        # Remove the abandoned address from '_ip4_ifaddr' so
        # the stack stops claiming it. Future RX-side conflict
        # detection on this IP will see it is no longer in
        # '_ip4_unicast' and skip the defense path entirely.
        self._ip4_ifaddr = [host for host in self._ip4_ifaddr if host.address != ip4_unicast]

        self._packet_stats_rx.arp__conflict__abandon += 1
        __debug__ and log(
            "arp",
            f"<CRIT>RFC 5227 §2.4(b) abandoning IPv4 address {ip4_unicast} "
            f"after second conflict within DEFEND_INTERVAL</>",
        )

    def _phrx_arp(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound ARP packets.
        """

        self._packet_stats_rx.arp__pre_parse += 1

        try:
            ArpParser(packet_rx)

        except PacketValidationError as error:
            self._packet_stats_rx.arp__failed_parse__drop += 1
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
                    f"{packet_rx.tracker} - Unsupported operation " f"{packet_rx.arp.oper}, dropping.",
                )

    def __update_arp_cache(
        self,
        *,
        packet_rx: PacketRx,
        operation: ArpOperation,
    ) -> None:
        """
        Update ARP cache with the SPA<->SHA mapping if the packet is intended for us.
        """

        # If SPA matches one of our subnets — or 'arp.accept = 1'
        # admits off-subnet senders (Linux
        # net.ipv4.conf.<iface>.arp_accept) — update ARP cache
        # with the SPA<->SHA mapping. Also ensure we update cache
        # only if the packet is either direct or broadcast to
        # avoid updating cache with packets not intended for us
        # in case the interface is in promiscuous mode. Finally,
        # do not update cache if SPA matches one of our IP
        # addresses to avoid updating cache with our own IP
        # address that could be spoofed by an attacker.
        spa_on_local_subnet = any(packet_rx.arp.spa in host.network for host in self._ip4_ifaddr)
        if (
            (spa_on_local_subnet or arp__constants.ARP__ACCEPT == 1)
            and (packet_rx.ethernet.dst == self._mac_unicast or packet_rx.ethernet.dst.is_broadcast)
            and packet_rx.arp.spa not in self._ip4_unicast
        ):
            match operation:
                case ArpOperation.REQUEST:
                    self._packet_stats_rx.arp__op_request__update_arp_cache += 1
                case ArpOperation.REPLY:
                    self._packet_stats_rx.arp__op_reply__update_arp_cache += 1
                case _:
                    raise ValueError("Invalid ARP operation")

            stack.arp_cache.add_entry(
                ip4_address=packet_rx.arp.spa,
                mac_address=packet_rx.arp.sha,
            )

    def __phrx_arp__request(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ARP request packets.
        """

        self._packet_stats_rx.arp__op_request += 1

        # Drop any ARP request if it is originated from us and looped for whatever.
        if (
            packet_rx.arp.spa in self._ip4_unicast or packet_rx.arp.spa.is_unspecified
        ) and packet_rx.arp.sha == self._mac_unicast:
            self._packet_stats_rx.arp__op_request__looped__drop += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <WARN>IP Received our own ARP request for "
                f"{packet_rx.arp.tpa} from {packet_rx.arp.spa}, dropping.</>",
            )
            return

        # Defend against IP address conflict if we got ARP request from another host
        # that is trying to claim one of our IP addresses.
        if packet_rx.arp.spa in self._ip4_unicast and packet_rx.arp.sha != self._mac_unicast:
            self._packet_stats_rx.arp__op_request__conflict__defend += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <WARN>IP {packet_rx.arp.spa} "
                f"conflict detected with host at {packet_rx.arp.sha}</>",
            )
            self._handle_arp_conflict(ip4_unicast=packet_rx.arp.spa)
            return

        # RFC 5227 §2.1.1 simultaneous-probe conflict: a peer is probing
        # the same address (their SPA = 0, TPA = our candidate). The
        # gratuitous / direct-reply branches below all key on
        # arp.spa being unicast / matching our candidate, so the SPA = 0
        # case would otherwise fall through to the 'tpa_unknown' drop
        # (a candidate is not yet in '_ip4_unicast' during DAD). The
        # earlier loop-drop check already filtered out our own SHA.
        if packet_rx.arp.spa.is_unspecified and packet_rx.arp.tpa in {c.address for c in self._ip4_ifaddr_candidate}:
            self._packet_stats_rx.arp__op_request__simultaneous_probe += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <WARN>Simultaneous-probe conflict "
                f"detected for candidate {packet_rx.arp.tpa} from peer "
                f"{packet_rx.arp.sha}</>",
            )
            self._ip4_arp_dad__registry.try_signal_conflict(
                packet_rx.arp.tpa,
                peer_info=None,
                inbound_nonce=None,
            )
            return

        # Note receiving gratuitous ARP request.
        if (
            packet_rx.ethernet.dst.is_broadcast
            and packet_rx.arp.spa.is_unicast
            and packet_rx.arp.spa == packet_rx.arp.tpa
            and packet_rx.arp.tha.is_unspecified
        ):
            self._packet_stats_rx.arp__op_request__gratuitous += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <INFO>Received gratuitous ARP request, "
                f"{packet_rx.arp.spa} -> {packet_rx.arp.sha}</>",
            )

            # If we’re probing this address, mark conflict too.
            if packet_rx.arp.spa in {c.address for c in self._ip4_ifaddr_candidate}:
                self._packet_stats_rx.arp__op_request__probe_conflict__gratuitous += 1
                self._ip4_arp_dad__registry.try_signal_conflict(
                    packet_rx.arp.spa,
                    peer_info=None,
                    inbound_nonce=None,
                )
                # Recommended during DAD: Don't learn ARP here.
                return

        # Note receiving ARP request not for our IP address.
        elif packet_rx.arp.tpa not in self._ip4_unicast:
            self._packet_stats_rx.arp__op_request__tpa_unknown += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <INFO>Dropping ARP request for unknown TPA "
                f"{packet_rx.arp.tpa} from {packet_rx.arp.spa}</>",
            )

        else:
            # Note receiving ARP probe (RFC 5227).
            if packet_rx.arp.spa.is_unspecified:
                self._packet_stats_rx.arp__op_request__probe += 1
                __debug__ and log(
                    "arp",
                    f"{packet_rx.tracker} - <INFO>Replying to the ARP probe for TPA "
                    f"{packet_rx.arp.tpa} from {packet_rx.arp.spa}</>",
                )

            # Note receiving regular ARP request.
            elif packet_rx.arp.spa.is_unicast:
                self._packet_stats_rx.arp__op_request__tpa_stack += 1
                __debug__ and log(
                    "arp",
                    f"{packet_rx.tracker} - <INFO>Replying to ARP request for TPA "
                    f"{packet_rx.arp.tpa} from {packet_rx.arp.spa}</>",
                )

            # Decide whether to emit a Reply. Modes 2 and 8 of
            # 'arp.ignore' suppress the Reply; cache learning
            # (the '__update_arp_cache' call below) still runs
            # so the stack can reach the peer once outbound
            # traffic initiates. Linux's per-mode semantics:
            #   8 = kill switch — never reply (useful for
            #       "stealth" interfaces in fail-over /
            #       clustering that own the IP at L3 but should
            #       not advertise it via ARP).
            #   2 = sender-subnet-match — reply only when SPA is
            #       on one of our local subnets (anti-spoof gate
            #       on hosts that should answer only neighbours).
            # Probes (SPA = 0) are exempt from the mode-2 check —
            # a probe is the peer's "is this IP free?" wire
            # signal and has no SPA yet.
            should_reply = True
            if arp__constants.ARP__IGNORE == 8:
                __debug__ and log(
                    "arp",
                    f"{packet_rx.tracker} - <INFO>arp.ignore=8 dropped Reply: " f"kill switch active",
                )
                should_reply = False
            else:
                sender_on_local_subnet = packet_rx.arp.spa.is_unspecified or any(
                    packet_rx.arp.spa in host.network for host in self._ip4_ifaddr
                )
                if arp__constants.ARP__IGNORE == 2 and not sender_on_local_subnet:
                    __debug__ and log(
                        "arp",
                        f"{packet_rx.tracker} - <INFO>arp.ignore=2 dropped Reply: "
                        f"sender {packet_rx.arp.spa} is not on any local subnet",
                    )
                    should_reply = False

            # Send ARP reply packet to requester.
            if should_reply and (packet_rx.ethernet.dst.is_broadcast or packet_rx.ethernet.dst == self._mac_unicast):
                self._packet_stats_rx.arp__op_request__respond += 1
                self._send_arp_reply(
                    arp__spa=packet_rx.arp.tpa,
                    arp__tha=packet_rx.arp.sha,
                    arp__tpa=packet_rx.arp.spa,
                    tracker=packet_rx.tracker,
                )

        self.__update_arp_cache(
            packet_rx=packet_rx,
            operation=ArpOperation.REQUEST,
        )

    def __phrx_arp__reply(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ARP reply packets.
        """

        self._packet_stats_rx.arp__op_reply += 1

        # Drop any ARP reply if it is originated from us and looped for whatever.
        if packet_rx.arp.spa in self._ip4_unicast and packet_rx.arp.sha == self._mac_unicast:
            self._packet_stats_rx.arp__op_reply__looped__drop += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <WARN>IP Received our own ARP reply for "
                f"{packet_rx.arp.tpa} from {packet_rx.arp.spa}, dropping.</>",
            )
            return

        # Defend against IP address conflict if we got ARP reply from another host
        # that is trying to claim one of our IP addresses.
        if packet_rx.arp.spa in self._ip4_unicast and packet_rx.arp.sha != self._mac_unicast:
            self._packet_stats_rx.arp__op_reply__conflict__defend += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <WARN>IP {packet_rx.arp.spa} "
                f"conflict detected with host at {packet_rx.arp.sha}</>",
            )
            self._handle_arp_conflict(ip4_unicast=packet_rx.arp.spa)
            return

        # Check for ARP reply that is response to our ARP probe, this indicates
        # the IP address we trying to claim is in use.
        if (
            packet_rx.arp.spa in [_.address for _ in self._ip4_ifaddr_candidate]
            and packet_rx.ethernet.dst == packet_rx.arp.tha == self._mac_unicast
            and packet_rx.arp.tpa.is_unspecified
        ):
            self._packet_stats_rx.arp__op_reply__probe_conflict += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <WARN>ARP probe detected "
                f"conflict for IP {packet_rx.arp.spa} with host at "
                f"{packet_rx.arp.sha}</>",
            )
            self._ip4_arp_dad__registry.try_signal_conflict(
                packet_rx.arp.spa,
                peer_info=None,
                inbound_nonce=None,
            )
            # Recommended during DAD: Don't learn ARP here.
            return

        # Note receiving packet as direct ARP reply.
        if packet_rx.ethernet.dst == self._mac_unicast:
            self._packet_stats_rx.arp__op_reply__direct += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <INFO>Received direct ARP reply, "
                f"{packet_rx.arp.spa} -> {packet_rx.arp.sha}</>",
            )

        # Note receiving packet as gratuitous ARP reply.
        elif (
            packet_rx.ethernet.dst.is_broadcast
            and packet_rx.arp.spa == packet_rx.arp.tpa
            and packet_rx.arp.tha.is_unspecified
        ):
            self._packet_stats_rx.arp__op_reply__gratuitous += 1
            __debug__ and log(
                "arp",
                f"{packet_rx.tracker} - <INFO>Received gratuitous ARP reply, "
                f"{packet_rx.arp.spa} -> {packet_rx.arp.sha}</>",
            )

            if packet_rx.arp.spa in {c.address for c in self._ip4_ifaddr_candidate}:
                self._packet_stats_rx.arp__op_reply__probe_conflict__gratuitous += 1
                self._ip4_arp_dad__registry.try_signal_conflict(
                    packet_rx.arp.spa,
                    peer_info=None,
                    inbound_nonce=None,
                )
                # Recommended during DAD: Don't learn ARP here.
                return

        self.__update_arp_cache(packet_rx=packet_rx, operation=ArpOperation.REPLY)
