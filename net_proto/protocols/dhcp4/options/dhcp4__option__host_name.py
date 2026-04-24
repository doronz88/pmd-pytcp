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
This module contains the DHCPv4 Host Name option support code.

net_proto/protocols/dhcp4/options/dhcp4__option__host_name.py

ver 3.0.4
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4__option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Host Name option [RFC 2132].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Code=12   |     Len=N     |           Hostname           ...
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__OPTION__HOST_NAME__STRUCT = "! BB"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp4OptionHostName(Dhcp4Option):
    """
    The DHCPv4 Host Name option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.HOST_NAME,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    host_name: str

    @override
    def __post_init__(self) -> None:
        """
        Validate the DHCPv4 Host Name option fields.
        """

        # Ensure that the 'host_name' field is str.
        assert isinstance(self.host_name, str), f"The 'host_name' field must be a str. Got: {type(self.host_name)!r}"

        # Update the option 'len' field based on the length of the 'host_name' field.
        object.__setattr__(self, "len", DHCP4__OPTION__LEN + len(self.host_name))

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Host Name option log string.
        """

        return f"host_name {self.host_name}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 Host Name option as a memoryview.
        """

        struct.pack_into(
            DHCP4__OPTION__HOST_NAME__STRUCT + f"{len(self.host_name)}s",
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            len(self.host_name),
            self.host_name.encode("utf-8"),
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Validate the DHCPv4 Host Name option integrity before parsing it.
        """

        # Raise integrity error if there is not enough bytes to parse the option.
        if (value := DHCP4__OPTION__LEN + buffer[1]) > len(buffer):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Host Name option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 Host Name option from buffer.
        """

        # Ensure we got enough bytes to parse the option header.
        assert (value := len(buffer)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Host Name option must " f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        # Ensure the option type is the expected value.
        assert (value := buffer[0]) == int(Dhcp4OptionType.HOST_NAME), (
            f"The DHCPv4 Host Name option type must be {Dhcp4OptionType.HOST_NAME!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls((bytes(buffer[2 : 2 + buffer[1]])).decode("utf-8"))  # Note: Conversion: memoryview -> bytes
