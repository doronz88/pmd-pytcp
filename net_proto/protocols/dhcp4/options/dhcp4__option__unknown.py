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

from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_uint8
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4__option import (
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
            f"The 'type' field must be a Dhcp4OptionType. " f"Got: {type(self.type)!r}"
        )

        # Ensure the 'type' field is not a known Dhcp4OptionType.
        assert int(self.type) not in Dhcp4OptionType.get_known_values(), (
            "The 'type' field must not be a known Dhcp4OptionType. " f"Got: {self.type!r}"
        )

        # Update the option 'len' field based on the length of the 'data' field.
        object.__setattr__(self, "len", DHCP4__OPTION__LEN + len(self.data))

        # Ensure the 'len' field is a valid 8-bit unsigned integer.
        assert is_uint8(self.len - DHCP4__OPTION__LEN), (
            f"The 'len' field must be an 8-bit unsigned integer. " f"Got: {self.len!r}"
        )

    @override
    def __str__(self) -> str:
        """
        Get the unknown DHCPv4 option log string.
        """

        return f"unk-{int(self.type)}-{self.len}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the unknown DHCPv4 option as memoryview.
        """

        struct.pack_into(
            DHCP4__OPTION__STRUCT,
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len,
        )

        buffer[DHCP4__OPTION__LEN:] = self.data

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Validate the unknown DHCPv4 option integrity before parsing it.
        """

        # Raise integrity error if there is not enough bytes to parse the option.
        if (value := DHCP4__OPTION__LEN + buffer[1]) > len(buffer):
            raise Dhcp4IntegrityError(
                "The unknown DHCPv4 option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the unknown DHCPv4 option from buffer.
        """

        # Ensure we got enough bytes to parse the option header.
        assert (value := len(buffer)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the unknown DHCPv4 option must be " f"{DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        # Ensure the option type is not known.
        assert (value := buffer[0]) not in Dhcp4OptionType.get_known_values(), (
            f"The unknown DHCPv4 option type must not be known. " f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        Dhcp4OptionUnknown._validate_integrity(buffer)

        return cls(
            type=Dhcp4OptionType(buffer[0]),
            data=bytes(
                buffer[DHCP4__OPTION__LEN : DHCP4__OPTION__LEN + buffer[1]]
            ),  # NOTE: Conversion: memoryview -> bytes
        )
