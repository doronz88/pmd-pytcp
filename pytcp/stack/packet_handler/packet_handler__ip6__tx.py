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
This module contains packet handler for the outbound IPv6 packets.

pytcp/subsystems/packet_handler/packet_handler__ip6__tx.py

ver 3.0.4
"""

import time
from abc import ABC
from typing import TYPE_CHECKING, Any

from net_addr import Ip6Address, MacAddress
from net_proto import (
    Icmp6,
    Icmp6Mld2MessageReport,
    Icmp6NdMessageNeighborSolicitation,
    Ip6Assembler,
    IpProto,
    RawAssembler,
)
from pytcp import stack
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.ip6_source_selection import (
    common_prefix_len,
    ip6_address_scope,
)
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus
from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6SlaacAddressState


class PacketHandlerIp6Tx(ABC):
    """
    Class implements packet handler for the outbound IPv6 packets.
    """

    if TYPE_CHECKING:
        from net_addr import Ip6Host
        from net_proto import EthernetPayload, Ip6Payload, Tracker
        from pytcp.lib.packet_stats import PacketStatsTx
        from pytcp.protocols.icmp6.nd.nd__router_state import Icmp6SlaacAddress

        _interface_layer: InterfaceLayer
        _packet_stats_tx: PacketStatsTx
        _ip6_host: list[Ip6Host]
        _ip6_multicast: list[Ip6Address]
        _ip6_support: bool
        _interface_mtu: int
        _icmp6_slaac_addresses: list[Icmp6SlaacAddress]

        # pylint: disable=unused-argument

        def _phtx_ethernet(
            self,
            *,
            ethernet__src: MacAddress = MacAddress(),
            ethernet__dst: MacAddress = MacAddress(),
            ethernet__payload: EthernetPayload = RawAssembler(),
        ) -> TxStatus: ...

        def _phtx_ip6_frag(self, *, ip6_packet_tx: Ip6Assembler) -> TxStatus: ...

        def _effective_ip6_hop_limit(self) -> int: ...

        # pylint: disable=missing-function-docstring

        @property
        def _ip6_unicast(self) -> list[Ip6Address]: ...

    def _phtx_ip6(
        self,
        *,
        ip6__dst: Ip6Address,
        ip6__src: Ip6Address,
        ip6__hop: int | None = None,
        ip6__ecn: int = 0,
        ip6__payload: Ip6Payload = RawAssembler(),
    ) -> TxStatus:
        """
        Handle outbound IP packets.

        'ip6__hop=None' (the default) lets the packet handler
        pick the effective Hop Limit per RFC 4861 §6.3.4: the
        most recent RA-advertised Cur-Hop-Limit if observed,
        otherwise IP6__DEFAULT_HOP_LIMIT (64). Callers that
        protocol-mandate a specific value (e.g. ND with 255,
        MLD with 1) pass it explicitly and short-circuit the
        lookup.
        """

        self._packet_stats_tx.ip6__pre_assemble += 1

        if ip6__hop is None:
            ip6__hop = self._effective_ip6_hop_limit()

        assert 0 < ip6__hop < 256

        # Check if IPv6 protocol support is enabled, if not then silently
        # drop the packet.
        if not self._ip6_support:
            self._packet_stats_tx.ip6__no_proto_support__drop += 1
            return TxStatus.DROPPED__IP6__NO_PROTOCOL_SUPPORT

        # Validate source address.
        result = self.__validate_src_ip6_address(
            ip6__src=ip6__src,
            ip6__dst=ip6__dst,
            ip6__payload=ip6__payload,
        )
        if isinstance(result, TxStatus):
            return result
        ip6__src = result

        # Validate destination address.
        result = self.__validate_dst_ip6_address(
            ip6__dst=ip6__dst,
            tracker=ip6__payload.tracker,
        )
        if isinstance(result, TxStatus):
            return result
        ip6__dst = result

        # assemble IPv6 apcket
        ip6_packet_tx = Ip6Assembler(
            ip6__src=ip6__src,
            ip6__dst=ip6__dst,
            ip6__hop=ip6__hop,
            ip6__ecn=ip6__ecn,
            ip6__payload=ip6__payload,
        )

        # Check if IP packet can be sent out without fragmentation,
        # if so send it out.
        if len(ip6_packet_tx) <= self._interface_mtu:
            self._packet_stats_tx.ip6__mtu_ok__send += 1
            __debug__ and log("ip6", f"{ip6_packet_tx.tracker} - {ip6_packet_tx}")
            match self._interface_layer:
                case InterfaceLayer.L2:
                    return self._phtx_ethernet(
                        ethernet__src=MacAddress(),
                        ethernet__dst=MacAddress(),
                        ethernet__payload=ip6_packet_tx,
                    )
                case InterfaceLayer.L3:
                    self.__send_out_packet(ip6_packet_tx=ip6_packet_tx)
                    return TxStatus.PASSED__IP6__TO_TX_RING

        # Fragment packet and send out.
        self._packet_stats_tx.ip6__mtu_exceed__frag += 1
        __debug__ and log(
            "ip6",
            f"{ip6_packet_tx.tracker} - IPv6 packet len " f"{len(ip6_packet_tx)} bytes, fragmentation needed",
        )
        return self._phtx_ip6_frag(ip6_packet_tx=ip6_packet_tx)

    def __validate_src_ip6_address(
        self,
        *,
        ip6__src: Ip6Address,
        ip6__dst: Ip6Address,
        ip6__payload: Ip6Payload,
    ) -> Ip6Address | TxStatus:
        """
        Make sure source ip address is valid, supplement with valid one
        as appropriate.
        """

        tracker = ip6__payload.tracker

        # Check if the the source IP address belongs to this stack
        # or its unspecified.
        if ip6__src not in {
            *self._ip6_unicast,
            *self._ip6_multicast,
            Ip6Address(),
        }:
            self._packet_stats_tx.ip6__src_not_owned__drop += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Unable to sent out IPv6 packet, stack "
                f"doesn't own IPv6 address {ip6__src}, dropping</>",
            )
            return TxStatus.DROPPED__IP6__SRC_NOT_OWNED

        # If packet is a response to multicast then replace source address with link
        # local address of the stack.
        if ip6__src in self._ip6_multicast:
            if self._ip6_unicast:
                self._packet_stats_tx.ip6__src_multicast__replace += 1
                ip6__src = self._ip6_unicast[0]
                __debug__ and log(
                    "ip6",
                    f"{tracker} - Packet is response to multicast, replaced "
                    f"source with stack link local IPv6 address {ip6__src}",
                )
                return ip6__src
            self._packet_stats_tx.ip6__src_multicast__drop += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Unable to sent out IPv6 packet, no stack "
                "link local unicast IPv6 address available</>",
            )
            return TxStatus.DROPPED__IP6__SRC_MULTICAST

        # If src is unspecified and stack is sending an ICMPv6
        # ND Neighbor Solicitation. Per RFC 4861 §4.3 / §7.2.2 a
        # DAD probe is the canonical NS form with src=:: and
        # targets the solicited-node multicast; it MUST NOT carry
        # an SLLA option (RFC 4861 §7.2.2). RFC 7527 §4.1
        # additionally allows a Nonce option for Enhanced DAD,
        # so the option list is no longer a reliable
        # "is DAD probe" proxy — match on message type instead.
        # This branch precedes RFC 6724 source selection: a DAD
        # probe MUST emit src=:: regardless of the stack's other
        # owned addresses.
        if (
            ip6__src.is_unspecified
            and isinstance(ip6__payload, Icmp6)
            and isinstance(ip6__payload.message, Icmp6NdMessageNeighborSolicitation)
            and ip6__payload.message.option_slla is None
        ):
            self._packet_stats_tx.ip6__src_unspecified__send += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - Packet source is unspecified, ICMPv6 ND DAD " "packet, sending",
            )
            return ip6__src

        # If src is unspecified and stack is sending ICMPv6 MLDv2 report.
        if (
            ip6__src.is_unspecified
            and isinstance(ip6__payload, Icmp6)
            and isinstance(ip6__payload.message, Icmp6Mld2MessageReport)
        ):
            self._packet_stats_tx.ip6__src_unspecified__send += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - Packet source is unspecified, ICMPv6 MLDv2 " "report, sending",
            )
            return ip6__src

        # If source is unspecified and destination is unicast,
        # run RFC 6724 default source-address selection across
        # the owned candidate set. Multicast destinations with
        # src=:: are intentionally not handled here — the
        # DAD-probe and MLDv2-report branches above carry the
        # only legitimate src=:: multicast forms, and any other
        # multicast packet with src=:: is treated as malformed
        # and falls through to the drop branch below. The
        # local/external split is preserved at the stat-counter
        # level for backwards compatibility with existing
        # observability dashboards.
        if ip6__src.is_unspecified and ip6__dst.is_unicast:
            selected = self._select_ip6_source(ip6__dst=ip6__dst)
            if selected is not None:
                if any(ip6__dst in host.network for host in self._ip6_host):
                    self._packet_stats_tx.ip6__src_network_unspecified__replace_local += 1
                else:
                    self._packet_stats_tx.ip6__src_network_unspecified__replace_external += 1
                __debug__ and log(
                    "ip6",
                    f"{tracker} - Packet source is unspecified, RFC 6724 "
                    f"selector picked source IPv6 address {selected}",
                )
                return selected

        # If src is unspecified and stack can't replace it.
        if ip6__src.is_unspecified:
            self._packet_stats_tx.ip6__src_unspecified__drop += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Packet source is unspecified, unable to " "replace with valid source, dropping</>",
            )
            return TxStatus.DROPPED__IP6__SRC_UNSPECIFIED

        # If nothing above applies return the src address intact.
        return ip6__src

    def _select_ip6_source(self, *, ip6__dst: Ip6Address) -> Ip6Address | None:
        """
        Run RFC 6724 default source-address selection over the
        candidate set in '_ip6_host' and return the winner.

        The candidate set is the addresses owned by the stack;
        rule 1 short-circuits when the destination is itself
        owned. Otherwise the candidates are sorted by a
        lexicographic key that encodes rules 2 (scope), 3 (avoid
        deprecated), and 8 (longest matching prefix), in that
        priority order. Rules 4 (home address), 5 (outgoing
        interface), 5.5 (next-hop), 6 (matching label), and 7
        (temp-address preference) are out of scope for this
        phase. Rules 4/5/5.5 do not apply to a single-interface
        host stack; rule 6 (policy table) and rule 7 ship in
        follow-up phases.

        Returns None when no candidate exists. The TX path
        falls back to the existing
        DROPPED__IP6__SRC_UNSPECIFIED handling.
        """

        candidates = [host.address for host in self._ip6_host]
        if not candidates:
            return None

        # Rule 1 — prefer same address.
        if ip6__dst in candidates:
            return ip6__dst

        now = time.monotonic()
        deprecated_addresses = {
            entry.address
            for entry in self._icmp6_slaac_addresses
            if entry.state(now) is Icmp6SlaacAddressState.DEPRECATED
        }
        dst_scope = ip6_address_scope(ip6__dst)

        def sort_key(src: Ip6Address) -> tuple[tuple[int, int], int, int]:
            """
            Build the rule-2/3/8 lexicographic sort key. Higher
            tuples win under descending sort.
            """

            src_scope = ip6_address_scope(src)
            # Rule 2 — partition by 'scope >= dst_scope', then
            # prefer the smallest scope still >= dst_scope; for
            # candidates below dst_scope, prefer the largest
            # available.
            if src_scope >= dst_scope:
                rule2 = (1, -src_scope)
            else:
                rule2 = (0, src_scope)
            # Rule 3 — prefer non-deprecated.
            rule3 = 0 if src in deprecated_addresses else 1
            # Rule 8 — prefer longest common prefix.
            rule8 = common_prefix_len(src, ip6__dst)
            return (rule2, rule3, rule8)

        candidates.sort(key=sort_key, reverse=True)
        return candidates[0]

    def __validate_dst_ip6_address(
        self,
        *,
        ip6__dst: Ip6Address,
        tracker: Tracker,
    ) -> Ip6Address | TxStatus:
        """
        Make sure destination ip address is valid.
        """

        # Drop packet if the destination address is unspecified.
        if ip6__dst.is_unspecified:
            self._packet_stats_tx.ip6__dst_unspecified__drop += 1
            __debug__ and log(
                "ip6",
                f"{tracker} - <WARN>Destination address is unspecified, " "dropping</>",
            )
            return TxStatus.DROPPED__IP6__DST_UNSPECIFIED

        return ip6__dst

    def send_ip6_packet(
        self,
        *,
        ip6__local_address: Ip6Address,
        ip6__remote_address: Ip6Address,
        ip6__next: IpProto,
        ip6__payload: bytes = bytes(),
        ip6__hop: int | None = None,
        ip6__ecn: int = 0,
    ) -> TxStatus:
        """
        Interface method for RAW Socket -> Packet Assembler communication.
        """

        kwargs: dict[str, Any] = {
            "ip6__src": ip6__local_address,
            "ip6__dst": ip6__remote_address,
            "ip6__payload": RawAssembler(
                raw__payload=ip6__payload,
                ip_proto=ip6__next,
            ),
            "ip6__ecn": ip6__ecn,
        }
        if ip6__hop is not None:
            kwargs["ip6__hop"] = ip6__hop
        return self._phtx_ip6(**kwargs)

    @staticmethod
    def __send_out_packet(ip6_packet_tx: Ip6Assembler) -> None:
        stack.tx_ring.enqueue(ip6_packet_tx)
