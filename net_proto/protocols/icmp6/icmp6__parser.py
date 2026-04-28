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
This module contains the ICMPv6 packet parser.

net_proto/protocols/icmp6/icmp6__parser.py

ver 3.0.4
"""

from typing import override

from net_proto.lib.inet_cksum import inet_cksum
from net_proto.lib.packet_rx import PacketRx
from net_proto.lib.proto_parser import ProtoParser
from net_proto.protocols.icmp6.icmp6__base import Icmp6
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.icmp6__message import (
    ICMP6__HEADER__LEN,
    Icmp6Message,
    Icmp6Type,
)
from net_proto.protocols.icmp6.message.icmp6__message__destination_unreachable import (
    Icmp6MessageDestinationUnreachable,
)
from net_proto.protocols.icmp6.message.icmp6__message__echo_reply import (
    Icmp6MessageEchoReply,
)
from net_proto.protocols.icmp6.message.icmp6__message__echo_request import (
    Icmp6MessageEchoRequest,
)
from net_proto.protocols.icmp6.message.icmp6__message__unknown import (
    Icmp6MessageUnknown,
)
from net_proto.protocols.icmp6.message.mld2.icmp6__mld2__message__report import (
    Icmp6Mld2MessageReport,
)
from net_proto.protocols.icmp6.message.nd.icmp6__nd__message__neighbor_advertisement import (
    Icmp6NdMessageNeighborAdvertisement,
)
from net_proto.protocols.icmp6.message.nd.icmp6__nd__message__neighbor_solicitation import (
    Icmp6NdMessageNeighborSolicitation,
)
from net_proto.protocols.icmp6.message.nd.icmp6__nd__message__router_advertisement import (
    Icmp6NdMessageRouterAdvertisement,
)
from net_proto.protocols.icmp6.message.nd.icmp6__nd__message__router_solicitation import (
    Icmp6NdMessageRouterSolicitation,
)


class Icmp6Parser(Icmp6, ProtoParser):
    """
    The ICMPv6 packet parser.
    """

    def __init__(self, packet_rx: PacketRx) -> None:
        """
        Initialize the ICMPv6 packet parser.
        """

        self._frame = packet_rx.frame
        self._ip6__dlen = packet_rx.ip6.dlen
        self._ip6__pshdr_sum = packet_rx.ip6.pshdr_sum
        self._ip6__src = packet_rx.ip6.src
        self._ip6__dst = packet_rx.ip6.dst
        self._ip6__hop = packet_rx.ip6.hop

        self._validate_integrity()
        self._parse()
        self._validate_sanity()

        packet_rx.icmp6 = self
        packet_rx.frame = packet_rx.frame[len(self) :]

    def _message_class(self) -> type[Icmp6Message]:
        """
        Resolve the concrete Icmp6Message subclass that matches the frame's
        type byte. Falls back to Icmp6MessageUnknown for unrecognised types.
        """

        match Icmp6Type.from_int(self._frame[0]):
            case Icmp6Type.DESTINATION_UNREACHABLE:
                return Icmp6MessageDestinationUnreachable
            case Icmp6Type.ECHO_REQUEST:
                return Icmp6MessageEchoRequest
            case Icmp6Type.ECHO_REPLY:
                return Icmp6MessageEchoReply
            case Icmp6Type.ND__ROUTER_SOLICITATION:
                return Icmp6NdMessageRouterSolicitation
            case Icmp6Type.ND__ROUTER_ADVERTISEMENT:
                return Icmp6NdMessageRouterAdvertisement
            case Icmp6Type.ND__NEIGHBOR_SOLICITATION:
                return Icmp6NdMessageNeighborSolicitation
            case Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT:
                return Icmp6NdMessageNeighborAdvertisement
            case Icmp6Type.MLD2__REPORT:
                return Icmp6Mld2MessageReport
            case _:
                return Icmp6MessageUnknown

    @override
    def _validate_integrity(self) -> None:
        """
        Ensure integrity of the ICMPv6 packet before parsing it.
        """

        if not (ICMP6__HEADER__LEN <= self._ip6__dlen <= len(self._frame)):
            raise Icmp6IntegrityError(
                "The condition 'ICMP6__HEADER__LEN <= self._ip6__dlen <= "
                f"len(self._frame)' must be met. Got: {ICMP6__HEADER__LEN=}, "
                f"{self._ip6__dlen=}, {len(self._frame)=}"
            )

        self._message_class().validate_integrity(frame=self._frame, ip6__dlen=self._ip6__dlen)

        if inet_cksum(self._frame[: self._ip6__dlen], init=self._ip6__pshdr_sum):
            raise Icmp6IntegrityError(
                "The packet checksum must be valid.",
            )

    @override
    def _parse(self) -> None:
        """
        Parse the ICMPv6 packet.
        """

        self._message = self._message_class().from_buffer(self._frame)

    @override
    def _validate_sanity(self) -> None:
        """
        Ensure sanity of the ICMPv6 packet after parsing it.
        """

        self._message.validate_sanity(
            ip6__hop=self._ip6__hop,
            ip6__src=self._ip6__src,
            ip6__dst=self._ip6__dst,
        )
