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
This module contains the DHCPv4 Router option support code.

net_proto/protocols/dhcp4/options/dhcp4_option__router.py

ver 3.0.4
"""


import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr.ip4_address import Ip4Address
from net_proto.lib.buffer import Buffer
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4_option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Router option [RFC 2132].

#                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                 |    Code = 3   |   Length = 4n |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Router IP Address                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Router IP Address                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                              ...                              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__OPTION__ROUTER__STRUCT = "! BB"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp4OptionRouter(Dhcp4Option):
    """
    The DHCPv4 Router option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.ROUTER,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    routers: list[Ip4Address]

    @override
    def __post_init__(self) -> None:
        """
        Validate the DHCPv4 Router option fields.
        """

        # Ensure that the 'routers' field is a list.
        assert isinstance(
            self.routers, list
        ), f"The 'routers' field must be a list. Got: {type(self.routers)!r}"

        # Ensure that each element of the  'routers' field is an Ip4Address instance.
        assert all(isinstance(item, Ip4Address) for item in self.routers), (
            f"The 'routers' field must be a list of Ip4Address elements. "
            f"Got: {[type(element) for element in self.routers]!r}"
        )

        # Update the option 'len' field based on the length of the 'routers' field.
        object.__setattr__(
            self, "len", DHCP4__OPTION__LEN + len(self.routers) * 4
        )

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Router option log string.
        """

        return f"router {[str(router) for router in self.routers]}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 Router option as memoryview.
        """

        struct.pack_into(
            DHCP4__OPTION__ROUTER__STRUCT + f"{len(self.routers) * 4}s",
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP4__OPTION__LEN,
            b"".join(bytes(router) for router in self.routers),
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Validate the DHCPv4 Router option integrity before parsing it.
        """

        # Raise integrity error if there is not enough bytes to parse the option.
        if (value := DHCP4__OPTION__LEN + buffer[1]) > len(buffer):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Router option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

        # Raise integrity error when the option length value (less header) is not a multiple of 4.
        if (value := buffer[1] % 4) != 0:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Router option length value (less header) must be a multiple of 4. "
                f"Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 Router option from buffer.
        """

        # Ensure we got enough bytes to parse the option header.
        assert (value := len(buffer)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Router option must "
            f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        # Ensure the option type is the expected value.
        assert (value := buffer[0]) == int(Dhcp4OptionType.ROUTER), (
            f"The DHCPv4 Router option type must be {Dhcp4OptionType.ROUTER!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(
            [Ip4Address(buffer[i : i + 4]) for i in range(2, buffer[1] + 2, 4)],
        )
