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
This module contains the unknown DHCPv4 option support code.

net_proto/protocols/dhcp4/options/dhcp4_option__unknown.py

ver 3.0.4
"""


import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.int_checks import is_uint8
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4_option import (
    DHCP4__OPTION__LEN,
    DHCP4__OPTION__STRUCT,
    Dhcp4Option,
    Dhcp4OptionType,
)


@dataclass(frozen=True, kw_only=True, slots=True)
class Dhcp4OptionUnknown(Dhcp4Option):
    """
    The DHCPv4 unknown option support class.
    """

    type: Dhcp4OptionType = field(
        repr=True,
        init=True,
        default=Dhcp4OptionType.from_int(255),
    )
    len: int = field(
        repr=True,
        init=False,
    )

    data: bytes

    @override
    def __post_init__(self) -> None:
        """
        Validate the DHCPv4 unknown option fields.
        """

        # Ensure the 'type' field is a valid Dhcp4OptionType enum member.
        assert isinstance(self.type, Dhcp4OptionType), (
            f"The 'type' field must be a Dhcp4OptionType. "
            f"Got: {type(self.type)!r}"
        )

        # Ensure the 'type' field is not a known Dhcp4OptionType.
        assert int(self.type) not in Dhcp4OptionType.get_known_values(), (
            "The 'type' field must not be a known Dhcp4OptionType. "
            f"Got: {self.type!r}"
        )

        # Update the option 'len' field based on the length of the 'data' field.
        object.__setattr__(self, "len", DHCP4__OPTION__LEN + len(self.data))

        # Ensure the 'len' field is a valid 8-bit unsigned integer.
        assert is_uint8(self.len - DHCP4__OPTION__LEN), (
            f"The 'len' field must be an 8-bit unsigned integer. "
            f"Got: {self.len!r}"
        )

    @override
    def __str__(self) -> str:
        """
        Get the unknown DHCPv4 option log string.
        """

        return f"unk-{int(self.type)}-{self.len}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the unknown DHCPv4 option as bytes.
        """

        return (
            struct.pack(
                DHCP4__OPTION__STRUCT,
                int(self.type),
                self.len,
            )
            + self.data
        )

    @staticmethod
    def _validate_integrity(_bytes: memoryview, /) -> None:
        """
        Validate the unknown DHCPv4 option integrity before parsing it.
        """

        # Raise integrity error if there is not enough bytes to parse the option.
        if (value := DHCP4__OPTION__LEN + _bytes[1]) > len(_bytes):
            raise Dhcp4IntegrityError(
                "The unknown DHCPv4 option length value must be less than or equal to "
                f"the length of provided bytes ({len(_bytes)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_bytes(cls, _bytes: memoryview, /) -> Self:
        """
        Initialize the unknown DHCPv4 option from bytes.
        """

        # Ensure the '_bytes' argument is a memoryview.
        assert isinstance(
            _bytes, memoryview
        ), f"The '_bytes' argument must be a memoryview. Got: {type(_bytes)!r}"

        # Ensure we got enough bytes to parse the option header.
        assert (value := len(_bytes)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the unknown DHCPv4 option must be "
            f"{DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        # Ensure the option type is not known.
        assert (value := _bytes[0]) not in Dhcp4OptionType.get_known_values(), (
            f"The unknown DHCPv4 option type must not be known. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        Dhcp4OptionUnknown._validate_integrity(_bytes)

        return cls(
            type=Dhcp4OptionType(_bytes[0]),
            data=bytes(
                _bytes[DHCP4__OPTION__LEN : DHCP4__OPTION__LEN + _bytes[1]]
            ),  # NOTE: Conversion: memoryview -> bytes
        )
