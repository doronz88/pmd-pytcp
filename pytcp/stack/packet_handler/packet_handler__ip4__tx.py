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
This module contains packet handler for the outbound IPv4 packets.

pytcp/subsystems/packet_handler/packet_handler__ip4__tx.py

ver 3.0.4
"""

from abc import ABC
from typing import TYPE_CHECKING, Any

from net_addr import Ip4Address, MacAddress
from net_proto import (
    IP4__DEFAULT_TTL,
    Ip4Assembler,
    Ip4FragAssembler,
    Ip4Options,
    Ip4Payload,
    IpProto,
    RawAssembler,
    TcpAssembler,
    Tracker,
    UdpAssembler,
)
from pytcp import stack
from pytcp.lib.interface_layer import InterfaceLayer
from pytcp.lib.ip4_source_selection import (
    common_prefix_len,
    ip4_address_scope,
)
from pytcp.lib.logger import log
from pytcp.lib.tx_status import TxStatus


class PacketHandlerIp4Tx(ABC):
    """
    Abstract class for outbound IPv4 packet handler.
    """

    if TYPE_CHECKING:
        from net_addr import Ip4Host
        from net_proto import EthernetPayload
        from pytcp.lib.packet_stats import PacketStatsTx

        _interface_layer: InterfaceLayer
        _packet_stats_tx: PacketStatsTx
        _ip4_host: list[Ip4Host]
        _ip4_multicast: list[Ip4Address]
        _ip4_id: int
        _ip4_support: bool
        _interface_mtu: int

        # pylint: disable=unused-argument

        def _phtx_ethernet(
            self,
            *,
            ethernet__src: MacAddress = MacAddress(),
            ethernet__dst: MacAddress = MacAddress(),
            ethernet__payload: EthernetPayload = RawAssembler(),
        ) -> TxStatus: ...

        # pylint: disable=missing-function-docstring

        @property
        def _ip4_unicast(self) -> list[Ip4Address]: ...

        @property
        def _ip4_broadcast(self) -> list[Ip4Address]: ...

    def _phtx_ip4(
        self,
        *,
        ip4__dst: Ip4Address,
        ip4__src: Ip4Address,
        ip4__ttl: int = IP4__DEFAULT_TTL,
        ip4__ecn: int = 0,
        ip4__flag_df: bool = False,
        ip4__options: Ip4Options = Ip4Options(),
        ip4__payload: Ip4Payload = RawAssembler(),
    ) -> TxStatus:
        """
        Handle outbound IP packets.
        """

        self._packet_stats_tx.ip4__pre_assemble += 1

        assert 0 < ip4__ttl < 256

        # Check if IPv4 protocol support is enabled, if not then silently drop
        # the packet.
        if not self._ip4_support:
            self._packet_stats_tx.ip4__no_proto_support__drop += 1
            return TxStatus.DROPPED__IP4__NO_PROTOCOL_SUPPORT

        # Validate source address.
        result = self.__validate_src_ip4_address(
            ip4__src=ip4__src,
            ip4__dst=ip4__dst,
            ip4__payload=ip4__payload,
        )
        if isinstance(result, TxStatus):
            return result
        ip4__src = result

        # Validate destination address.
        result = self.__validate_dst_ip4_address(
            ip4__dst=ip4__dst,
            tracker=ip4__payload.tracker,
        )
        if isinstance(result, TxStatus):
            return result
        ip4__dst = result

        # Assemble IPv4 packet.
        ip4_packet_tx = Ip4Assembler(
            ip4__src=ip4__src,
            ip4__dst=ip4__dst,
            ip4__ttl=ip4__ttl,
            ip4__ecn=ip4__ecn,
            ip4__flag_df=ip4__flag_df,
            ip4__options=ip4__options,
            ip4__payload=ip4__payload,
        )

        # Send packet out if it's size doesn't exceed mtu.
        if len(ip4_packet_tx) <= self._interface_mtu:
            self._packet_stats_tx.ip4__mtu_ok__send += 1
            __debug__ and log("ip4", f"{ip4_packet_tx.tracker} - {ip4_packet_tx}")
            match self._interface_layer:
                case InterfaceLayer.L2:
                    return self._phtx_ethernet(
                        ethernet__src=MacAddress(),
                        ethernet__dst=MacAddress(),
                        ethernet__payload=ip4_packet_tx,
                    )
                case InterfaceLayer.L3:
                    self.__send_out_packet(ip4_packet_tx)
                    return TxStatus.PASSED__IP4__TO_TX_RING

        # RFC 791 §3.1: a datagram with DF=1 that exceeds the link
        # MTU MUST be discarded. Fragmenting it locally would emit
        # MF=1 fragments that contradict the DF=1 contract the upper
        # layer asked for.
        if ip4__flag_df:
            self._packet_stats_tx.ip4__mtu_exceed__df_set__drop += 1
            __debug__ and log(
                "ip4",
                f"{ip4_packet_tx.tracker} - <CRIT>IPv4 packet len {len(ip4_packet_tx)} "
                f"bytes exceeds MTU and DF=1; dropping</>",
            )
            return TxStatus.DROPPED__IP4__MTU_EXCEED_DF

        # Fragment packet and send out.
        self._packet_stats_tx.ip4__mtu_exceed__frag += 1
        __debug__ and log(
            "ip4",
            f"{ip4_packet_tx.tracker} - IPv4 packet len {len(ip4_packet_tx)} " "bytes, fragmentation needed",
        )

        if isinstance(ip4_packet_tx.payload, (TcpAssembler, UdpAssembler)):
            ip4_packet_tx.payload.pshdr_sum = ip4_packet_tx.pshdr_sum

        payload = bytearray(bytes(ip4_packet_tx.payload))

        payload_mtu = (self._interface_mtu - ip4_packet_tx.hlen) & 0b1111111111111000
        payload_frags = [payload[_ : payload_mtu + _] for _ in range(0, len(payload), payload_mtu)]
        offset = 0
        self._ip4_id += 1
        outbound_tx_status: set[TxStatus] = set()
        for payload_frag in payload_frags:
            ip4_frag_tx = Ip4FragAssembler(
                ip4_frag__src=ip4__src,
                ip4_frag__dst=ip4__dst,
                ip4_frag__ttl=ip4__ttl,
                ip4_frag__payload=payload_frag,
                ip4_frag__offset=offset,
                ip4_frag__flag_mf=payload_frag is not payload_frags[-1],
                ip4_frag__id=self._ip4_id,
                ip4_frag__proto=ip4_packet_tx.proto,
            )
            __debug__ and log("ip4", f"{ip4_frag_tx.tracker} - {ip4_frag_tx}")
            offset += len(payload_frag)
            self._packet_stats_tx.ip4__mtu_exceed__frag__send += 1

            match self._interface_layer:
                case InterfaceLayer.L2:
                    outbound_tx_status.add(
                        self._phtx_ethernet(
                            ethernet__src=MacAddress(),
                            ethernet__dst=MacAddress(),
                            ethernet__payload=ip4_frag_tx,
                        )
                    )
                case InterfaceLayer.L3:
                    self.__send_out_packet(ip4_frag_tx)
                    tx_status = TxStatus.PASSED__IP4__TO_TX_RING

        # Return the most severe code.
        for tx_status in [
            TxStatus.DROPPED__ETHERNET__DST_RESOLUTION_FAIL,
            TxStatus.DROPPED__ETHERNET__DST_NO_GATEWAY_IP4,
            TxStatus.DROPPED__ETHERNET__DST_ARP_CACHE_MISS,
            TxStatus.DROPPED__ETHERNET__DST_GATEWAY_ARP_CACHE_MISS,
            TxStatus.PASSED__ETHERNET__TO_TX_RING,
            TxStatus.PASSED__IP4__TO_TX_RING,
        ]:
            if tx_status in outbound_tx_status:
                return tx_status

        return TxStatus.DROPPED__IP4__UNKNOWN

    def __validate_src_ip4_address(
        self,
        *,
        ip4__src: Ip4Address,
        ip4__dst: Ip4Address,
        ip4__payload: Ip4Payload,
    ) -> Ip4Address | TxStatus:
        """
        Make sure source ip address is valid, supplement with valid one
        as appropriate.
        """

        tracker = ip4__payload.tracker

        # Check if the the source IP address belongs to this stack or is set to all
        # zeros (for DHCP client communication).
        if ip4__src not in {
            *self._ip4_unicast,
            *self._ip4_multicast,
            *self._ip4_broadcast,
            Ip4Address(),
        }:
            self._packet_stats_tx.ip4__src_not_owned__drop += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - <WARN>Unable to sent out IPv4 packet, stack "
                f"doesn't own IPv4 address {ip4__src}, dropping</>",
            )
            return TxStatus.DROPPED__IP4__SRC_NOT_OWNED

        # If packet is a response to multicast then replace source address with
        # primary address of the stack.
        if ip4__src in self._ip4_multicast:
            if self._ip4_unicast:
                self._packet_stats_tx.ip4__src_multicast__replace += 1
                ip4__src = self._ip4_unicast[0]
                __debug__ and log(
                    "ip4",
                    f"{tracker} - Packet is response to multicast, replaced "
                    f"source with stack primary IPv4 address {ip4__src}",
                )
                return ip4__src
            self._packet_stats_tx.ip4__src_multicast__drop += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - <WARN>Unable to sent out IPv4 packet, no stack "
                f"primary unicast IPv4 address available, dropping</>",
            )
            return TxStatus.DROPPED__IP4__SRC_MULTICAST

        # If packet is a response to limited broadcast then replace source address
        # with primary address of the stack.
        if ip4__src.is_limited_broadcast:
            if self._ip4_unicast:
                self._packet_stats_tx.ip4__src_limited_broadcast__replace += 1
                ip4__src = self._ip4_unicast[0]
                __debug__ and log(
                    "ip4",
                    f"{tracker} - Packet is response to limited broadcast, "
                    "replaced source with stack primary IPv4 "
                    f"address {ip4__src}",
                )
                return ip4__src
            self._packet_stats_tx.ip4__src_limited_broadcast__drop += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - <WARN>Unable to sent out IPv4 packet, no stack "
                f"primary unicast IPv4 address available, dropping</>",
            )
            return TxStatus.DROPPED__IP4__SRC_LIMITED_BROADCAST

        # If packet is a response to network broadcast then replace source address
        # with first stack address that belongs to appropriate subnet.
        if ip4__src in self._ip4_broadcast:
            ip4_src_list = [ip4_host.address for ip4_host in self._ip4_host if ip4_host.network.broadcast == ip4__src]
            if ip4_src_list:
                self._packet_stats_tx.ip4__src_network_broadcast__replace += 1
                ip4__src = ip4_src_list[0]
                __debug__ and log(
                    "ip4",
                    f"{tracker} - Packet is response to network broadcast, "
                    f"replaced source with appropriate IPv4 address {ip4__src}",
                )
                return ip4__src

        # If src is unspecified and stack is sending DHCP packet.
        # Per RFC 2131 §3.1 a DHCPDISCOVER / DHCPREQUEST MUST
        # carry src=0.0.0.0 — keep the unspec-src short-circuit
        # before RFC 6724 source selection so the selector
        # cannot replace it with an owned address.
        if (
            ip4__src.is_unspecified
            and isinstance(ip4__payload, UdpAssembler)
            and ip4__payload.sport == 68
            and ip4__payload.dport == 67
        ):
            self._packet_stats_tx.ip4__src_unspecified__send += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - Packet source is unspecified, DHCPv4 packet, " "sending",
            )
            return ip4__src

        # If source is unspecified, run RFC 6724 §6 default
        # source-address selection (rules 1, 2, and 8 — the
        # only ones applicable to IPv4) across the owned
        # candidate set. The local/external split is preserved
        # at the stat-counter level for backwards compatibility
        # with existing observability dashboards.
        if ip4__src.is_unspecified:
            selected = self._select_ip4_source(ip4__dst=ip4__dst)
            if selected is not None:
                if any(ip4__dst in host.network for host in self._ip4_host):
                    self._packet_stats_tx.ip4__src_network_unspecified__replace_local += 1
                else:
                    self._packet_stats_tx.ip4__src_network_unspecified__replace_external += 1
                __debug__ and log(
                    "ip4",
                    f"{tracker} - Packet source is unspecified, RFC 6724 "
                    f"selector picked source IPv4 address {selected}",
                )
                return selected

        # If src is unspecified and stack can't replace it.
        if ip4__src.is_unspecified:
            self._packet_stats_tx.ip4__src_unspecified__drop += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - <WARN>Packet source is unspecified, unable to " "replace with valid source, dropping</>",
            )
            return TxStatus.DROPPED__IP4__SRC_UNSPECIFIED

        # If nothing above applies return the src address intact.
        return ip4__src

    def _select_ip4_source(self, *, ip4__dst: Ip4Address) -> Ip4Address | None:
        """
        Run RFC 6724 §6 default source-address selection over
        the candidate set in '_ip4_host' and return the winner.

        Only rules 1 (same address), 2 (scope), and 8 (longest
        matching prefix) apply to IPv4: rule 3 (avoid
        deprecated) has no IPv4 equivalent (no SLAAC), rule 6
        (matching label) and rule 7 (temp addresses) likewise
        have no IPv4 analog, and rules 4 / 5 / 5.5 are no-ops on
        a single-interface host stack. The lex-tuple sort key
        encodes rules 2 and 8 in priority order; rule 1
        short-circuits.

        Returns None when no candidate exists. The TX path
        falls back to the existing
        DROPPED__IP4__SRC_UNSPECIFIED handling.
        """

        candidates = [host.address for host in self._ip4_host]
        if not candidates:
            return None

        # Rule 1 — prefer same address.
        if ip4__dst in candidates:
            return ip4__dst

        dst_scope = ip4_address_scope(ip4__dst)

        def sort_key(src: Ip4Address) -> tuple[tuple[int, int], int]:
            """
            Build the rule-2/8 lexicographic sort key. Higher
            tuples win under descending sort.
            """

            src_scope = ip4_address_scope(src)
            if src_scope >= dst_scope:
                rule2 = (1, -src_scope)
            else:
                rule2 = (0, src_scope)
            rule8 = common_prefix_len(src, ip4__dst)
            return (rule2, rule8)

        candidates.sort(key=sort_key, reverse=True)
        return candidates[0]

    def __validate_dst_ip4_address(
        self,
        *,
        ip4__dst: Ip4Address,
        tracker: Tracker,
    ) -> Ip4Address | TxStatus:
        """
        Make sure destination ip address is valid.
        """

        # Drop packet if the destination address is unspecified.
        if ip4__dst.is_unspecified:
            self._packet_stats_tx.ip4__dst_unspecified__drop += 1
            __debug__ and log(
                "ip4",
                f"{tracker} - <WARN>Destination address is unspecified, " "dropping</>",
            )
            return TxStatus.DROPPED__IP4__DST_UNSPECIFIED

        return ip4__dst

    def send_ip4_packet(
        self,
        *,
        ip4__local_address: Ip4Address,
        ip4__remote_address: Ip4Address,
        ip4__proto: IpProto,
        ip4__payload: bytes = bytes(),
        ip4__ttl: int | None = None,
        ip4__ecn: int = 0,
    ) -> TxStatus:
        """
        Interface method for RAW Socket -> Packet Assembler communication.
        """

        kwargs: dict[str, Any] = {
            "ip4__src": ip4__local_address,
            "ip4__dst": ip4__remote_address,
            "ip4__payload": RawAssembler(
                raw__payload=ip4__payload,
                ip_proto=ip4__proto,
            ),
            "ip4__ecn": ip4__ecn,
        }
        if ip4__ttl is not None:
            kwargs["ip4__ttl"] = ip4__ttl
        return self._phtx_ip4(**kwargs)

    @staticmethod
    def __send_out_packet(
        ip4_packet_tx: Ip4Assembler | Ip4FragAssembler,
    ) -> None:
        stack.tx_ring.enqueue(ip4_packet_tx)
