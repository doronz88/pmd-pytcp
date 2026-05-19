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
This module contains the ICMPv6 message base class.

net_proto/protocols/icmp6/message/icmp6__message.py

ver 3.0.6
"""

from abc import abstractmethod
from dataclasses import dataclass

from net_addr import Ip6Address
from net_proto.lib.buffer import Buffer
from net_proto.lib.proto_enum import ProtoEnumByte
from net_proto.lib.proto_struct import ProtoStruct

# ICMPv6 message header [RFC 4443].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6__HEADER__LEN = 4
ICMP6__HEADER__STRUCT = "! BBH"


class Icmp6Type(ProtoEnumByte):
    """
    The ICMPv6 message 'type' field values.
    """

    DESTINATION_UNREACHABLE = 1
    PACKET_TOO_BIG = 2
    TIME_EXCEEDED = 3
    PARAMETER_PROBLEM = 4
    ECHO_REQUEST = 128
    ECHO_REPLY = 129
    MULTICAST_LISTENER_QUERY = 130
    ND__ROUTER_SOLICITATION = 133
    ND__ROUTER_ADVERTISEMENT = 134
    ND__NEIGHBOR_SOLICITATION = 135
    ND__NEIGHBOR_ADVERTISEMENT = 136
    ND__REDIRECT = 137
    MLD2__REPORT = 143


class Icmp6Code(ProtoEnumByte):
    """
    Base class for ICMPv6 'code' field enums. Concrete code values
    are defined by each message type's subclass.
    """


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6Message(ProtoStruct):
    """
    The ICMPv6 message base.
    """

    type: Icmp6Type
    code: Icmp6Code
    cksum: int

    @abstractmethod
    def _pack_header(self, buffer_len: int, /) -> bytearray:
        """
        Get the ICMPv6 message header as bytes.
        """

        raise NotImplementedError

    @abstractmethod
    def validate_sanity(self, *, ip6__hop: int, ip6__src: Ip6Address, ip6__dst: Ip6Address) -> None:
        """
        Ensure sanity of the ICMPv6 message.
        """

        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def validate_integrity(*, frame: Buffer, ip6__dlen: int) -> None:
        """
        Ensure integrity of the ICMPv6 message.
        """

        raise NotImplementedError

    @abstractmethod
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the ICMPv6 message.
        """

        raise NotImplementedError
