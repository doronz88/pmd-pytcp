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
This module contains the DHCPv4 Subnet Mask option support code.

net_proto/protocols/dhcp4/options/dhcp4_option__subnet_mask.py

ver 3.0.4
"""


import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr.ip4_mask import Ip4Mask
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4_option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Subnet Mask option [RFC 2132].

# Subnet Mask (Option 1)
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Code = 1    |    Length = 4   |        Subnet Mask
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#              Subnet Mask            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__OPTION__SUBNET_MASK__LEN = 6
DHCP4__OPTION__SUBNET_MASK__STRUCT = "! BB 4s"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp4OptionSubnetMask(Dhcp4Option):
    """
    The DHCPv4 Subnet Mask option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.SUBNET_MASK,
    )
    len: int = field(
        repr=False,
        init=False,
        default=DHCP4__OPTION__SUBNET_MASK__LEN,
    )

    subnet_mask: Ip4Mask

    @override
    def __post_init__(self) -> None:
        """
        Validate the DHCPv4 Subnet Mask option fields.
        """

        assert isinstance(self.subnet_mask, Ip4Mask), (
            f"The 'subnet_mask' field must be an Ip4Mask. "
            f"Got: {type(self.subnet_mask)!r}"
        )

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Subnet Mask option log string.
        """

        return f"subnet_mask {self.subnet_mask}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the DHCPv4 Subnet Mask option as bytes.
        """

        return struct.pack(
            DHCP4__OPTION__SUBNET_MASK__STRUCT,
            int(self.type),
            self.len - DHCP4__OPTION__LEN,
            bytes(self.subnet_mask),
        )

    @staticmethod
    def _validate_integrity(_bytes: bytes, /) -> None:
        """
        Validate the DHCPv4 Subnet Mask option integrity before parsing it.
        """

        if (value := _bytes[1]) != DHCP4__OPTION__SUBNET_MASK__LEN:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Subnet Mask option length must be "
                f"{DHCP4__OPTION__SUBNET_MASK__LEN} bytes. Got: {value!r}"
            )

        if (value := _bytes[1]) > len(_bytes):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Subnet Mask option length must be less than or equal "
                f"to the length of provided bytes ({len(_bytes)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_bytes(cls, _bytes: bytes, /) -> Self:
        """
        Initialize the DHCPv4 Subnet Mask option from bytes.
        """

        assert (value := len(_bytes)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Subnet Mask option must "
            f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := _bytes[0]) == int(Dhcp4OptionType.SUBNET_MASK), (
            f"The DHCPv4 Subnet Mask option type must be {Dhcp4OptionType.SUBNET_MASK!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(_bytes)

        return cls(subnet_mask=Ip4Mask(_bytes[2:6]))
