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
This module contains the unknown ICMPv6 option support code.

net_proto/protocols/icmp6/options/icmp6_nd_option__unknown.py

ver 3.0.4
"""


import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.int_checks import is_8_byte_alligned, is_uint8
from net_proto.protocols.icmp6.icmp6__errors import Icmp6IntegrityError
from net_proto.protocols.icmp6.message.nd.option.icmp6_nd_option import (
    ICMP6__ND__OPTION__LEN,
    ICMP6__ND__OPTION__STRUCT,
    Icmp6NdOption,
    Icmp6NdOptionType,
)


@dataclass(frozen=True, kw_only=True, slots=True)
class Icmp6NdOptionUnknown(Icmp6NdOption):
    """
    The ICMPv6 ND unknown option support class.
    """

    type: Icmp6NdOptionType = field(
        repr=True,
        init=True,
        default=Icmp6NdOptionType.from_int(255),
    )
    len: int = field(
        repr=True,
        init=False,
    )

    data: bytes

    @override
    def __post_init__(self) -> None:
        """
        Validate the ICMPv6 unknown option fields.
        """

        # Ensure the 'type' field is a valid Icmp6NdOptionType enum member.
        assert isinstance(self.type, Icmp6NdOptionType), (
            f"The 'type' field must be an Icmp6NdOptionType. "
            f"Got: {type(self.type)!r}"
        )

        # Ensure the 'type' field is not a known Icmp6NdOptionType.
        assert int(self.type) not in Icmp6NdOptionType.get_known_values(), (
            "The 'type' field must not be a known Icmp6NdOptionType. "
            f"Got: {self.type!r}"
        )

        # Update the option 'len' field based on the length of the 'data' field.
        object.__setattr__(self, "len", ICMP6__ND__OPTION__LEN + len(self.data))

        # Ensure the 'len' field is a valid 8-bit unsigned integer.
        assert is_uint8(self.len), (
            f"The 'len' field must be an 8-bit unsigned integer. "
            f"Got: {self.len!r}"
        )

        # Ensure the 'len' field is 8-byte aligned.
        assert is_8_byte_alligned(
            self.len
        ), f"The 'len' field must be 8-byte aligned. Got: {self.len!r}"

    @override
    def __str__(self) -> str:
        """
        Get the unknown ICMPv6 option log string.
        """

        return f"unk-{int(self.type)}-{self.len}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the unknown ICMPv6 option as bytes.
        """

        return (
            struct.pack(
                ICMP6__ND__OPTION__STRUCT,
                int(self.type),
                self.len >> 3,
            )
            + self.data
        )

    @staticmethod
    def _validate_integrity(_bytes: memoryview, /) -> None:
        """
        Validate the unknown ICMPv6 option integrity before parsing it.
        """

        # Raise integrity error if there is not enough bytes to parse the option.
        if (value := _bytes[1] << 3) > len(_bytes):
            raise Icmp6IntegrityError(
                "The unknown ICMPv6 ND option length value must be less than or equal to "
                f"the length of provided bytes ({len(_bytes)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_bytes(cls, _bytes: memoryview, /) -> Self:
        """
        Initialize the unknown ICMPv6 option from bytes.
        """

        # Ensure we got enough bytes to parse the option header.
        assert (value := len(_bytes)) >= ICMP6__ND__OPTION__LEN, (
            f"The minimum length of the unknown ICMPv6 ND option must be "
            f"{ICMP6__ND__OPTION__LEN} bytes. Got: {value!r}"
        )

        # Ensure the option type is not known.
        assert (
            value := _bytes[0]
        ) not in Icmp6NdOptionType.get_known_values(), (
            f"The unknown ICMPv6 ND option type must not be known. "
            f"Got: {Icmp6NdOptionType.from_int(value)!r}"
        )

        Icmp6NdOptionUnknown._validate_integrity(_bytes)

        return cls(
            type=Icmp6NdOptionType(_bytes[0]),
            data=_bytes[ICMP6__ND__OPTION__LEN : _bytes[1] << 3],
        )
