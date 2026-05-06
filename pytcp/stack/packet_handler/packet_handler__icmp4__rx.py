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
This module contains packet handler for the inbound ICMPv4 packets.

pytcp/subsystems/packet_handler/packet_handler__icmp4__rx.py

ver 3.0.4
"""

from abc import ABC
from typing import TYPE_CHECKING, cast

from net_addr import Ip4Address, IpVersion
from net_proto import (
    Icmp4DestinationUnreachableCode,
    Icmp4MessageDestinationUnreachable,
    Icmp4MessageEchoReply,
    Icmp4MessageEchoRequest,
    Icmp4Parser,
    Icmp4Type,
    IpProto,
    PacketRx,
    PacketValidationError,
)
from pytcp import stack
from pytcp.lib.logger import log
from pytcp.socket.raw__metadata import RawMetadata
from pytcp.socket.raw__socket import RawSocket
from pytcp.socket.udp__metadata import UdpMetadata
from pytcp.socket.udp__socket import UdpSocket
from pytcp.stack.packet_handler._icmp_error_demux import parse_embedded_l4


class PacketHandlerIcmp4Rx(ABC):
    """
    Class implements packet handler for the inbound ICMPv4 packets.
    """

    if TYPE_CHECKING:
        from net_proto import Icmp4Message, Tracker
        from pytcp.lib.packet_stats import PacketStatsRx
        from pytcp.lib.tx_status import TxStatus

        _packet_stats_rx: PacketStatsRx

        # pylint: disable=unused-argument

        def _phtx_icmp4(
            self,
            *,
            ip4__src: Ip4Address,
            ip4__dst: Ip4Address,
            icmp4__message: Icmp4Message,
            echo_tracker: Tracker | None = None,
        ) -> TxStatus: ...

    def _phrx_icmp4(self, packet_rx: PacketRx, /) -> None:
        """
        Handle inbound ICMPv4 packets.
        """

        self._packet_stats_rx.icmp4__pre_parse += 1

        try:
            Icmp4Parser(packet_rx)

        except PacketValidationError as error:
            __debug__ and log(
                "icmp4",
                f"{packet_rx.tracker} - <CRIT>{error}</>",
            )
            self._packet_stats_rx.icmp4__failed_parse__drop += 1
            return

        __debug__ and log("icmp4", f"{packet_rx.tracker} - {packet_rx.icmp4}")

        match packet_rx.icmp4.message.type:
            case Icmp4Type.ECHO_REPLY:
                self.__phrx_icmp4__echo_reply(packet_rx)
            case Icmp4Type.DESTINATION_UNREACHABLE:
                self.__phrx_icmp4__destination_unreachable(packet_rx)
            case Icmp4Type.ECHO_REQUEST:
                self.__phrx_icmp4__echo_request(packet_rx)
            case _:
                self.__phrx_icmp4__unknown(packet_rx)

    def __phrx_icmp4__echo_reply(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv4 Echo Reply packets.
        """

        assert isinstance(packet_rx.icmp4.message, Icmp4MessageEchoReply)

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Received ICMPv4 Echo Reply packet " f"from {packet_rx.ip4.src}",
        )
        self._packet_stats_rx.icmp4__echo_reply += 1

        # Create RawMetadata object and try to find matching RAW socket.
        # The serialized ICMP message bytes are what 'RawSocket' consumes
        # via its 'raw__data: bytes' field.
        packet_rx_md = RawMetadata(
            ip__ver=packet_rx.ip.ver,
            ip__local_address=packet_rx.ip.dst,
            ip__remote_address=packet_rx.ip.src,
            ip__proto=IpProto.ICMP4,
            raw__data=bytes(packet_rx.icmp4.message),
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

        return

    def __phrx_icmp4__destination_unreachable(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv4 Destination Unreachable packets. The
        Code 4 (Fragmentation Needed and DF Set) subcase carries the
        next-hop MTU per RFC 1191 §3 and is dispatched to the PMTUD
        path; every other code routes to the UDP-socket
        notify_unreachable lookup.
        """

        assert isinstance(packet_rx.icmp4.message, Icmp4MessageDestinationUnreachable)

        message = packet_rx.icmp4.message

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Received ICMPv4 Destination Unreachable packet "
            f"from {packet_rx.ip4.src}, code={message.code}",
        )
        self._packet_stats_rx.icmp4__destination_unreachable += 1

        is_frag_needed = message.code == Icmp4DestinationUnreachableCode.FRAGMENTATION_NEEDED
        if is_frag_needed:
            self._packet_stats_rx.icmp4__destination_unreachable__fragmentation_needed += 1

        embedded = parse_embedded_l4(message.data, IpVersion.IP4)
        if embedded is None:
            __debug__ and log(
                "icmp4",
                f"{packet_rx.tracker} - Unreachable data doesn't pass basic " "IPv4/UDP integrity check",
            )
            return

        if embedded.proto is not IpProto.UDP:
            return

        # Create UdpMetadata object and try to find matching UDP socket.
        packet = UdpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=cast(Ip4Address, embedded.local_ip),
            ip__remote_address=cast(Ip4Address, embedded.remote_ip),
            udp__local_port=embedded.local_port,
            udp__remote_port=embedded.remote_port,
        )

        for socket_id in packet.socket_ids:
            if socket := cast(UdpSocket, stack.sockets.get(socket_id, None)):
                __debug__ and log(
                    "icmp4",
                    f"{packet_rx.tracker} - <INFO>Found matching "
                    f"listening socket {socket}, for Unreachable "
                    f"packet from {packet_rx.ip4.src}</>",
                )
                if is_frag_needed and message.mtu is not None:
                    stack.pmtu_cache[cast(Ip4Address, embedded.remote_ip)] = message.mtu
                    socket.notify_pmtu(next_hop_mtu=message.mtu)
                    self._packet_stats_rx.icmp4__destination_unreachable__fragmentation_needed__notify_pmtu += 1
                else:
                    socket.notify_unreachable()
                return

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Unreachable data doesn't match " "any UDP socket",
        )

    def __phrx_icmp4__echo_request(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv4 Echo Reply packets.
        """

        assert isinstance(packet_rx.icmp4.message, Icmp4MessageEchoRequest)

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - <INFO>Received ICMPv4 Echo Request "
            f"packet from {packet_rx.ip4.src}, sending reply</>",
        )
        self._packet_stats_rx.icmp4__echo_request__respond_echo_reply += 1

        self._phtx_icmp4(
            ip4__src=packet_rx.ip4.dst,
            ip4__dst=packet_rx.ip4.src,
            icmp4__message=Icmp4MessageEchoReply(
                id=packet_rx.icmp4.message.id,
                seq=packet_rx.icmp4.message.seq,
                data=packet_rx.icmp4.message.data,
            ),
            echo_tracker=packet_rx.tracker,
        )

    def __phrx_icmp4__unknown(self, packet_rx: PacketRx) -> None:
        """
        Handle inbound ICMPv4 packets with unknown type.
        """

        __debug__ and log(
            "icmp4",
            f"{packet_rx.tracker} - Received unknown ICMPv4 packet " f"from {packet_rx.ip4.src}",
        )
        self._packet_stats_rx.icmp4__unknown += 1
