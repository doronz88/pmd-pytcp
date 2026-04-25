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
        packet_rx.frame = packet_rx.frame[len(self._frame) :]

    @override
    def _validate_integrity(self) -> None:
        """
        Validate integrity of the ICMPv6 packet before parsing it.
        """

        if not ICMP6__HEADER__LEN <= self._ip6__dlen <= len(self._frame):
            raise Icmp6IntegrityError(
                "The condition 'ICMP6__HEADER__LEN <= self._ip6__dlen <= "
                f"len(self._frame)' must be met. Got: {ICMP6__HEADER__LEN=}, "
                f"{self._ip6__dlen=}, {len(self._frame)=}"
            )

        match Icmp6Type.from_int(self._frame[0]):
            case Icmp6Type.DESTINATION_UNREACHABLE:
                Icmp6MessageDestinationUnreachable.validate_integrity(frame=self._frame, ip6__dlen=self._ip6__dlen)

            case Icmp6Type.ECHO_REQUEST:
                Icmp6MessageEchoRequest.validate_integrity(frame=self._frame, ip6__dlen=self._ip6__dlen)

            case Icmp6Type.ECHO_REPLY:
                Icmp6MessageEchoReply.validate_integrity(frame=self._frame, ip6__dlen=self._ip6__dlen)

            case Icmp6Type.ND__ROUTER_SOLICITATION:
                Icmp6NdMessageRouterSolicitation.validate_integrity(frame=self._frame, ip6__dlen=self._ip6__dlen)

            case Icmp6Type.ND__ROUTER_ADVERTISEMENT:
                Icmp6NdMessageRouterAdvertisement.validate_integrity(frame=self._frame, ip6__dlen=self._ip6__dlen)

            case Icmp6Type.ND__NEIGHBOR_SOLICITATION:
                Icmp6NdMessageNeighborSolicitation.validate_integrity(frame=self._frame, ip6__dlen=self._ip6__dlen)

            case Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT:
                Icmp6NdMessageNeighborAdvertisement.validate_integrity(frame=self._frame, ip6__dlen=self._ip6__dlen)

            case Icmp6Type.MLD2__REPORT:
                Icmp6Mld2MessageReport.validate_integrity(frame=self._frame, ip6__dlen=self._ip6__dlen)

            case _:
                Icmp6MessageUnknown.validate_integrity(frame=self._frame, ip6__dlen=self._ip6__dlen)

        if inet_cksum(self._frame[: self._ip6__dlen], init=self._ip6__pshdr_sum):
            raise Icmp6IntegrityError(
                "The packet checksum must be valid.",
            )

    @override
    def _parse(self) -> None:
        """
        Parse the ICMPv6 packet.
        """

        match Icmp6Type.from_bytes(self._frame[0:1]):
            case Icmp6Type.DESTINATION_UNREACHABLE:
                self._message = Icmp6MessageDestinationUnreachable.from_buffer(
                    self._frame,
                )

            case Icmp6Type.ECHO_REQUEST:
                self._message = Icmp6MessageEchoRequest.from_buffer(
                    self._frame,
                )

            case Icmp6Type.ECHO_REPLY:
                self._message = Icmp6MessageEchoReply.from_buffer(
                    self._frame,
                )

            case Icmp6Type.ND__ROUTER_SOLICITATION:
                self._message = Icmp6NdMessageRouterSolicitation.from_buffer(
                    self._frame,
                )

            case Icmp6Type.ND__ROUTER_ADVERTISEMENT:
                self._message = Icmp6NdMessageRouterAdvertisement.from_buffer(
                    self._frame,
                )

            case Icmp6Type.ND__NEIGHBOR_SOLICITATION:
                self._message = Icmp6NdMessageNeighborSolicitation.from_buffer(
                    self._frame,
                )

            case Icmp6Type.ND__NEIGHBOR_ADVERTISEMENT:
                self._message = Icmp6NdMessageNeighborAdvertisement.from_buffer(
                    self._frame,
                )

            case Icmp6Type.MLD2__REPORT:
                self._message = Icmp6Mld2MessageReport.from_buffer(
                    self._frame,
                )

            case _:
                self._message = Icmp6MessageUnknown.from_buffer(
                    self._frame,
                )

    @override
    def _validate_sanity(self) -> None:
        """
        Validate sanity of the ICMPv6 packet after parsing it.
        """

        self._message.validate_sanity(
            ip6__hop=self._ip6__hop,
            ip6__src=self._ip6__src,
            ip6__dst=self._ip6__dst,
        )
