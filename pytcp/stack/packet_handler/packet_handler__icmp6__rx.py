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
This module contains packet handler for the inbound ICMPv6 packets.

pytcp/subsystems/packet_handler/packet_handler__icmp6__rx.py

ver 3.0.4
"""

from abc import ABC
from typing import TYPE_CHECKING, cast

from net_addr import Ip6Address, IpVersion
from net_proto import (
    Icmp6MessageDestinationUnreachable,
    Icmp6MessageEchoReply,
    Icmp6MessageEchoRequest,
    Icmp6MessagePacketTooBig,
    Icmp6NdMessageNeighborAdvertisement,
    Icmp6NdMessageNeighborSolicitation,
    Icmp6NdMessageRouterAdvertisement,
    Icmp6NdMessageRouterSolicitation,
    Icmp6NdOptions,
    Icmp6NdOptionTlla,
    Icmp6Parser,
    Icmp6Type,
    IpProto,
    PacketRx,
    PacketValidationError,
)
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.socket import AddressFamily, SocketType
from pytcp.socket.raw__metadata import RawMetadata
from pytcp.socket.raw__socket import RawSocket
from pytcp.socket.socket_id import SocketId
from pytcp.socket.tcp__socket import TcpSocket
from pytcp.socket.udp__metadata import UdpMetadata
from pytcp.socket.udp__socket import UdpSocket
from pytcp.stack.packet_handler._icmp_error_demux import EmbeddedL4, parse_embedded_l4


class PacketHandlerIcmp6Rx(ABC):
    """
    Class implements packet handler for the inbound ICMPv6 packets.
    """

    if TYPE_CHECKING:
        from threading import Semaphore

        from net_addr import Ip6Network, MacAddress
        from net_proto import Icmp6Message, Tracker
        from pytcp.lib.packet_stats import PacketStatsRx
        from pytcp.lib.tx_status import TxStatus

        _packet_stats_rx: PacketStatsRx
        _mac_unicast: MacAddress
        _icmp6_nd_dad__ip6_unicast_candidate: Ip6Address | None
        _icmp6_nd_dad__event: Semaphore
        _icmp6_nd_dad__tlla: MacAddress | None
        _icmp6_ra__event: Semaphore
        _icmp6_ra__prefixes: list[tuple[Ip6Network, Ip6Address]]

        # pylint: disable=unused-argument

        def _phtx_icmp6(
            self,
            *,
            ip6__src: Ip6Address,
            ip6__dst: Ip6Address,
            ip6__hop: int = 64,
            icmp6__message: Icmp6Message,
            echo_tracker: Tracker | None = None,
        ) -> TxStatus: ...

        # pylint: disable=missing-function-docstring

        @property
        def ip6_unicast(self) -> list[Ip6Address]: ...

    def _phrx_icmp6(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound ICMPv6 packets.
        """

        self._packet_stats_rx.icmp6__pre_parse += 1

        try:
            Icmp6Parser(packet_rx)

        except PacketValidationError as error:
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            self._packet_stats_rx.icmp6__failed_parse__drop += 1
            return

        __debug__ and log("icmp6", f"{packet_rx.tracker} - {packet_rx.icmp6}")

        match packet_rx.icmp6.message.type:
            case Icmp6Type.DESTINATION_UNREACHABLE:
                self.__phrx_icmp6__destination_unreachable(packet_rx)
            case Icmp6Type.PACKET_TOO_BIG:
                self.__phrx_icmp6__packet_too_big(packet_rx)
            case Icmp6Type.ECHO_REQUEST:
                self.__phrx_icmp6__echo_request(packet_rx)
            case Icmp6Type.ECHO_REPLY:
                self.__phrx_icmp6__echo_reply(packet_rx)
            case Icmp6Type.ND__ROUTER_SOLICITATION:
                self.__phrx_icmp6__nd_router_solicitation(packet_rx)
            case Icmp6Type.ND__ROUTER_ADVERTISEMENT:
                self.__phrx_icmp6__nd_router_advertisement(packet_rx)
            case Icmp6Type.ND__NEIGHBOR_SOLICITATION:
                self.__phrx_icmp6__nd_neighbor_solicitation(packet_rx)
            case Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT:
                self.__phrx_icmp6__nd_neighbor_advertisement(packet_rx)
            case Icmp6Type.MLD2__REPORT:
                self.__phrx_icmp6__mld2_report(packet_rx)
            case _:
                self.__phrx_icmp6__unknown(packet_rx)

    def __phrx_icmp6__destination_unreachable(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 Port Unreachbale packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6MessageDestinationUnreachable)

        self._packet_stats_rx.icmp6__destination_unreachable += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Unreachable packet "
            f"from {packet_rx.ip6.src}, will try to match UDP socket",
        )

        # IPv6 extension headers in the embedded packet are not
        # supported by the helper — those frames fall through to the
        # 'no demux possible' log path.
        embedded = parse_embedded_l4(packet_rx.icmp6.message.data, IpVersion.IP6)
        if embedded is None:
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - Unreachable data doesn't pass basic " "IPv4/UDP integrity check",
            )
            return

        message = packet_rx.icmp6.message

        if embedded.proto is IpProto.UDP:
            self.__phrx_icmp6__dispatch_udp_unreachable(packet_rx, embedded)
            return

        if embedded.proto is IpProto.TCP:
            self.__phrx_icmp6__dispatch_tcp_unreachable(packet_rx, embedded, icmp_code=int(message.code))
            return

    def __phrx_icmp6__dispatch_udp_unreachable(self, packet_rx: PacketRx, embedded: EmbeddedL4) -> None:
        """
        Route an ICMPv6 Destination Unreachable carrying an embedded
        UDP segment to the matching UdpSocket.notify_unreachable.
        """

        packet = UdpMetadata(
            ip__ver=IpVersion.IP6,
            ip__local_address=cast(Ip6Address, embedded.local_ip),
            ip__remote_address=cast(Ip6Address, embedded.remote_ip),
            udp__local_port=embedded.local_port,
            udp__remote_port=embedded.remote_port,
        )

        for socket_id in packet.socket_ids:
            if socket := cast(
                UdpSocket,
                stack.sockets.get(socket_id, None),
            ):
                __debug__ and log(
                    "icmp6",
                    f"{packet_rx.tracker} - <INFO>Found matching "
                    f"listening UDP socket {socket} for Unreachable "
                    f"packet from {packet_rx.ip6.src}</>",
                )
                socket.notify_unreachable()
                return

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Unreachable data doesn't match " "any UDP socket",
        )

    def __phrx_icmp6__dispatch_tcp_unreachable(
        self,
        packet_rx: PacketRx,
        embedded: EmbeddedL4,
        *,
        icmp_code: int,
    ) -> None:
        """
        Route an ICMPv6 Destination Unreachable carrying an embedded
        TCP segment to the matching TcpSession via TcpSocket. Applies
        the RFC 5927 §4 sequence-in-window guard.
        """

        socket_id = SocketId(
            address_family=AddressFamily.INET6,
            socket_type=SocketType.STREAM,
            local_address=cast(Ip6Address, embedded.local_ip),
            local_port=embedded.local_port,
            remote_address=cast(Ip6Address, embedded.remote_ip),
            remote_port=embedded.remote_port,
        )

        socket = cast(TcpSocket, stack.sockets.get(socket_id, None))
        if socket is None or socket._tcp_session is None:
            return

        if embedded.embedded_seq is not None and not socket._tcp_session.is_seq_in_window(embedded.embedded_seq):
            self._packet_stats_rx.icmp6__destination_unreachable__tcp__seq_out_of_window__drop += 1
            return

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - <INFO>Found matching TCP session "
            f"for Unreachable packet from {packet_rx.ip6.src}</>",
        )
        socket._tcp_session.on_unreachable(icmp_type=1, icmp_code=icmp_code)
        self._packet_stats_rx.icmp6__destination_unreachable__tcp__notify += 1

    def __phrx_icmp6__packet_too_big(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 Packet Too Big messages — the IPv6
        PMTUD signal. Updates 'stack.pmtu_cache' for the destination
        and notifies the matching UDP socket via 'notify_pmtu' so it
        can refit subsequent sends to the new path MTU.

        Reference: RFC 4443 §3.2 (Packet Too Big Message).
        Reference: RFC 8201 §4 (IPv6 Path MTU Discovery).
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6MessagePacketTooBig)

        message = packet_rx.icmp6.message

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Packet Too Big " f"from {packet_rx.ip6.src}, mtu={message.mtu}",
        )
        self._packet_stats_rx.icmp6__packet_too_big += 1

        embedded = parse_embedded_l4(message.data, IpVersion.IP6)
        if embedded is None:
            return

        if embedded.proto is not IpProto.UDP:
            return

        packet = UdpMetadata(
            ip__ver=IpVersion.IP6,
            ip__local_address=cast(Ip6Address, embedded.local_ip),
            ip__remote_address=cast(Ip6Address, embedded.remote_ip),
            udp__local_port=embedded.local_port,
            udp__remote_port=embedded.remote_port,
        )

        for socket_id in packet.socket_ids:
            if socket := cast(UdpSocket, stack.sockets.get(socket_id, None)):
                stack.pmtu_cache[cast(Ip6Address, embedded.remote_ip)] = message.mtu
                socket.notify_pmtu(next_hop_mtu=message.mtu)
                self._packet_stats_rx.icmp6__packet_too_big__notify_pmtu += 1
                return

    def __phrx_icmp6__echo_request(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 Echo Request packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6MessageEchoRequest)

        self._packet_stats_rx.icmp6__echo_request__respond_echo_reply += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - <INFO>Received ICMPv6 Echo Request "
            f"packet from {packet_rx.ip6.src}, sending reply</>",
        )

        self._phtx_icmp6(
            ip6__src=packet_rx.ip6.dst,
            ip6__dst=packet_rx.ip6.src,
            ip6__hop=255,
            icmp6__message=Icmp6MessageEchoReply(
                id=packet_rx.icmp6.message.id,
                seq=packet_rx.icmp6.message.seq,
                data=packet_rx.icmp6.message.data,
            ),
            echo_tracker=packet_rx.tracker,
        )

    def __phrx_icmp6__echo_reply(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 Echo Reply packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6MessageEchoReply)

        self._packet_stats_rx.icmp6__echo_reply += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Echo Reply packet " f"from {packet_rx.ip6.src}",
        )

        # Create RawMetadata object and try to find matching RAW socket.
        # The serialized ICMP message bytes are what 'RawSocket' consumes
        # via its 'raw__data: bytes' field.
        packet_rx_md = RawMetadata(
            ip__ver=packet_rx.ip.ver,
            ip__local_address=packet_rx.ip.dst,
            ip__remote_address=packet_rx.ip.src,
            ip__proto=IpProto.ICMP6,
            raw__data=bytes(packet_rx.icmp6.message),
        )

        for socket_id in packet_rx_md.socket_ids:
            if socket := cast(RawSocket, stack.sockets.get(socket_id, None)):
                self._packet_stats_rx.raw__socket_match += 1
                __debug__ and log(
                    "raw",
                    f"{packet_rx_md.tracker} - <INFO>Found matching listening " f"socket [{socket}]</>",
                )
                socket.process_raw_packet(packet_rx_md)
                return

    def __phrx_icmp6__nd_router_solicitation(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 ND Router Solicitation packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6NdMessageRouterSolicitation)

        self._packet_stats_rx.icmp6__nd_router_solicitation += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Router Solicitation " f"packet from {packet_rx.ip6.src}",
        )

    def __phrx_icmp6__nd_router_advertisement(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 ND Router Advertisement packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6NdMessageRouterAdvertisement)

        self._packet_stats_rx.icmp6__nd_router_advertisement += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Router Advertisement " f"packet from {packet_rx.ip6.src}",
        )
        # Make note of prefixes that can be used for address autoconfiguration.
        self._icmp6_ra__prefixes = [(option.prefix, packet_rx.ip6.src) for option in packet_rx.icmp6.message.option_pi]
        self._icmp6_ra__event.release()

    def __phrx_icmp6__nd_neighbor_solicitation(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 ND Neighbor Solicitation packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6NdMessageNeighborSolicitation)

        self._packet_stats_rx.icmp6__nd_neighbor_solicitation += 1
        # Check if request is for one of stack's IPv6 unicast addresses.
        if packet_rx.icmp6.message.target_address not in self.ip6_unicast:
            __debug__ and log(
                "icmp6",
                f"{packet_rx.tracker} - Received ICMPv6 Neighbor "
                f"Solicitation packet from {packet_rx.ip6.src}, "
                "not matching any of stack's IPv6 unicast addresses, "
                "dropping",
            )
            self._packet_stats_rx.icmp6__nd_neighbor_solicitation__target_unknown__drop += 1
            return

        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - <INFO>Received ICMPv6 Neighbor "
            f"Solicitation packet from {packet_rx.ip6.src}, "
            "sending reply</>",
        )

        # Update ICMPv6 ND cache if valid IPv6 source is set and the ND option
        # SLLA is present.
        if (
            not (packet_rx.ip6.src.is_unspecified or packet_rx.ip6.src.is_multicast)
            and packet_rx.icmp6.message.option_slla
        ):
            self._packet_stats_rx.icmp6__nd_neighbor_solicitation__update_nd_cache += 1
            stack.nd_cache.add_entry(
                ip6_address=packet_rx.ip6.src,
                mac_address=packet_rx.icmp6.message.option_slla,
            )

        # Determine if request is part of DAD request by examining its source
        # address (absence of slla is already tested by sanity check).
        if ip6_nd_dad := packet_rx.ip6.src.is_unspecified:
            self._packet_stats_rx.icmp6__nd_neighbor_solicitation__dad += 1

        # Send response.
        self._packet_stats_rx.icmp6__nd_neighbor_solicitation__target_stack__respond += 1
        self._phtx_icmp6(
            ip6__src=packet_rx.icmp6.message.target_address,
            ip6__dst=(
                Ip6Address("ff02::1") if ip6_nd_dad else packet_rx.ip6.src
            ),  # Use ff02::1 destination address when responding to DAD request.
            ip6__hop=255,
            icmp6__message=Icmp6NdMessageNeighborAdvertisement(
                flag_s=not ip6_nd_dad,  # No S flag when responding to DAD request.
                flag_o=ip6_nd_dad,  # The O flag when responding to DAD request (not necessary but Linux uses it).
                target_address=packet_rx.icmp6.message.target_address,
                options=Icmp6NdOptions(
                    Icmp6NdOptionTlla(tlla=self._mac_unicast),
                ),
            ),
            echo_tracker=packet_rx.tracker,
        )
        return

    def __phrx_icmp6__nd_neighbor_advertisement(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 ND Neighbor Advertisement packets.
        """

        assert isinstance(packet_rx.icmp6.message, Icmp6NdMessageNeighborAdvertisement)

        self._packet_stats_rx.icmp6__nd_neighbor_advertisement += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 Neighbor Advertisement "
            f"packet for {packet_rx.icmp6.message.target_address} "
            f"from {packet_rx.ip6.src}",
        )

        # Run ND Duplicate Address Detection check.
        if packet_rx.icmp6.message.target_address == self._icmp6_nd_dad__ip6_unicast_candidate:
            self._packet_stats_rx.icmp6__nd_neighbor_advertisement__run_dad += 1
            self._icmp6_nd_dad__tlla = packet_rx.icmp6.message.option_tlla
            self._icmp6_nd_dad__event.release()
            return

        # Update ICMPv6 ND cache.
        if packet_rx.icmp6.message.option_tlla:
            self._packet_stats_rx.icmp6__nd_neighbor_advertisement__update_nd_cache += 1
            stack.nd_cache.add_entry(
                ip6_address=packet_rx.icmp6.message.target_address,
                mac_address=packet_rx.icmp6.message.option_tlla,
            )
            return

    def __phrx_icmp6__mld2_report(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv6 MLDv2 Report packets.
        """

        self._packet_stats_rx.icmp6__mld2_report += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received ICMPv6 MLDv2 Report packet " f"from {packet_rx.ip6.src}",
        )

    def __phrx_icmp6__unknown(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound unknown ICMPv6 packets.
        """

        self._packet_stats_rx.icmp6__unknown += 1
        __debug__ and log(
            "icmp6",
            f"{packet_rx.tracker} - Received unknown ICMPv6 packet " f"from {packet_rx.ip6.src}",
        )
