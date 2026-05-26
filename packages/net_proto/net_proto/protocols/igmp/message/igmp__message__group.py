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
This module contains the legacy 8-octet group-bearing IGMP message
support class — the IGMPv2 Membership Report, IGMPv2 Leave Group, and
IGMPv1 Membership Report, which share an identical wire shape and
differ only by the 'type' field.

net_proto/protocols/igmp/message/igmp__message__group.py

ver 3.0.6
"""

import struct
from dataclasses import dataclass
from typing import Self, override

from net_addr import Ip4Address
from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_uint16
from net_proto.protocols.igmp.igmp__errors import (
    IgmpIntegrityError,
    IgmpSanityError,
)
from net_proto.protocols.igmp.message.igmp__message import (
    IgmpMessage,
    IgmpType,
)

# The legacy 8-octet group-bearing IGMP message [RFC 2236 §2 / RFC 1112].
#
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      Type     | Max Resp Time |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Group Address                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Type is one of: 0x16 (V2 Membership Report), 0x17 (V2 Leave Group),
# 0x12 (V1 Membership Report). The Max Resp Time octet is set to zero
# by the sender and ignored on receipt (RFC 2236 §2.2).

IGMP__GROUP__LEN = 8
IGMP__GROUP__STRUCT = "! BBH 4s"

# The 'type' values this message carries (RFC 1112 / RFC 2236).
IGMP__GROUP__TYPES = frozenset(
    {
        IgmpType.V1_MEMBERSHIP_REPORT,
        IgmpType.V2_MEMBERSHIP_REPORT,
        IgmpType.V2_LEAVE_GROUP,
    }
)


@dataclass(frozen=True, kw_only=True, slots=True)
class IgmpMessageGroup(IgmpMessage):
    """
    The legacy 8-octet group-bearing IGMP message (IGMPv2 Membership
    Report / IGMPv2 Leave Group / IGMPv1 Membership Report). The 'type'
    field selects which of the three the instance represents.
    """

    type: IgmpType
    cksum: int = 0
    group_address: Ip4Address = Ip4Address()

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the legacy IGMP group message fields.
        """

        assert (
            self.type in IGMP__GROUP__TYPES
        ), f"The 'type' field must be one of {sorted(IGMP__GROUP__TYPES, key=int)}. Got: {self.type!r}"

        assert is_uint16(self.cksum), f"The 'cksum' field must be a 16-bit unsigned integer. Got: {self.cksum}"

    @override
    def __len__(self) -> int:
        """
        Get the legacy IGMP group message length.
        """

        return IGMP__GROUP__LEN

    @override
    def __str__(self) -> str:
        """
        Get the legacy IGMP group message log string.
        """

        return f"IGMP {self.type} group {self.group_address}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the legacy IGMP group message as a memoryview, with the
        checksum slot left zero for the IGMP base to inject.
        """

        struct.pack_into(
            IGMP__GROUP__STRUCT,
            buffer := bytearray(IGMP__GROUP__LEN),
            0,
            int(self.type),
            0,
            0,
            bytes(self.group_address),
        )

        return memoryview(buffer)

    @override
    def validate_sanity(self) -> None:
        """
        Ensure sanity of the legacy IGMP group message after parsing it.
        """

        # RFC 2236 §2.4 — in a Membership Report or Leave Group message
        # the Group Address field holds the IP multicast group being
        # reported or left, so a non-multicast group is invalid.
        if not self.group_address.is_multicast:
            raise IgmpSanityError(f"The 'group_address' field must be a multicast address. Got: {self.group_address!r}")

    @override
    @staticmethod
    def validate_integrity(*, frame: Buffer, ip4__payload_len: int) -> None:
        """
        Ensure integrity of the legacy IGMP group message before parsing
        it.
        """

        # RFC 2236 §2.5 — a message may be longer than 8 octets; only
        # the first 8 are processed (the rest are still checksum-covered
        # but otherwise ignored).
        if not (IGMP__GROUP__LEN <= ip4__payload_len <= len(frame)):
            raise IgmpIntegrityError(
                "The condition 'IGMP__GROUP__LEN <= ip4__payload_len <= len(frame)' is not met. "
                f"Got: {IGMP__GROUP__LEN=}, {ip4__payload_len=}, {len(frame)=}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the legacy IGMP group message from buffer.
        """

        type_, _, cksum, group_bytes = struct.unpack(IGMP__GROUP__STRUCT, buffer[:IGMP__GROUP__LEN])

        assert (
            received_type := IgmpType.from_int(type_)
        ) in IGMP__GROUP__TYPES, (
            f"The 'type' field must be one of {sorted(IGMP__GROUP__TYPES, key=int)}. Got: {received_type!r}"
        )

        return cls(
            type=received_type,
            cksum=cksum,
            group_address=Ip4Address(bytes(group_bytes)),
        )

    @override
    def assemble(self, buffers: list[Buffer], /) -> None:
        """
        Assemble the legacy IGMP group message into the buffer list.
        """

        buffers.append(bytearray(memoryview(self)))
