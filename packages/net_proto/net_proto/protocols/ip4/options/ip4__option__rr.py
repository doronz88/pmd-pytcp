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
This module contains the IPv4 Record Route option support code.

net_proto/protocols/ip4/options/ip4__option__rr.py

ver 3.0.6
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_addr import Ip4Address
from net_proto.lib.buffer import Buffer
from net_proto.lib.int_checks import is_uint8
from net_proto.protocols.ip4.ip4__errors import Ip4IntegrityError
from net_proto.protocols.ip4.options.ip4__option import Ip4Option, Ip4OptionType

# The IPv4 Record Route option [RFC 791].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Type = 7   |    Length     |    Pointer    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Recorded address 1               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                      ...                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Recorded address N               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

IP4__OPTION__RR__HDR_LEN = 3
IP4__OPTION__RR__SLOT_LEN = 4
IP4__OPTION__RR__MIN_LEN = IP4__OPTION__RR__HDR_LEN + IP4__OPTION__RR__SLOT_LEN
IP4__OPTION__RR__POINTER_BASE = 4
IP4__OPTION__RR__STRUCT = "! BBB"


@dataclass(frozen=True, kw_only=False, slots=True)
class Ip4OptionRr(Ip4Option):
    """
    The IPv4 Record Route option support class.
    """

    type: Ip4OptionType = field(
        repr=False,
        init=False,
        default=Ip4OptionType.RR,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    pointer: int
    route: list[Ip4Address]

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IPv4 Record Route option fields.
        """

        assert is_uint8(self.pointer), f"The 'pointer' field must be an 8-bit unsigned integer. Got: {self.pointer!r}"

        assert self.pointer >= IP4__OPTION__RR__POINTER_BASE, (
            f"The 'pointer' field must be at least {IP4__OPTION__RR__POINTER_BASE}. " f"Got: {self.pointer!r}"
        )

        assert (self.pointer - IP4__OPTION__RR__POINTER_BASE) % IP4__OPTION__RR__SLOT_LEN == 0, (
            f"The 'pointer' field must be aligned to the {IP4__OPTION__RR__SLOT_LEN}-byte slot "
            f"boundary. Got: {self.pointer!r}"
        )

        assert len(self.route) >= 1, f"The 'route' field must have at least 1 entry. Got: {len(self.route)!r}"

        assert all(
            isinstance(hop, Ip4Address) for hop in self.route
        ), f"The 'route' field must be a list of Ip4Address. Got: {self.route!r}"

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(
            self,
            "len",
            IP4__OPTION__RR__HDR_LEN + IP4__OPTION__RR__SLOT_LEN * len(self.route),
        )

    @override
    def __str__(self) -> str:
        """
        Get the IPv4 Record Route option log string.
        """

        return f"rr [{', '.join(str(hop) for hop in self.route)}] ptr={self.pointer}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv4 Record Route option as a memoryview.
        """

        struct.pack_into(
            IP4__OPTION__RR__STRUCT,
            buffer := bytearray(self.len),
            0,
            int(self.type),
            self.len,
            self.pointer,
        )

        for index, hop in enumerate(self.route):
            offset = IP4__OPTION__RR__HDR_LEN + IP4__OPTION__RR__SLOT_LEN * index
            buffer[offset : offset + IP4__OPTION__RR__SLOT_LEN] = bytes(hop)

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the IPv4 Record Route option before parsing it.
        """

        if (value := buffer[1]) < IP4__OPTION__RR__MIN_LEN:
            raise Ip4IntegrityError(
                f"The IPv4 Record Route option length must be at least {IP4__OPTION__RR__MIN_LEN} "
                f"bytes. Got: {value!r}"
            )

        if (buffer[1] - IP4__OPTION__RR__HDR_LEN) % IP4__OPTION__RR__SLOT_LEN:
            raise Ip4IntegrityError(
                "The IPv4 Record Route option route data length must be a multiple of "
                f"{IP4__OPTION__RR__SLOT_LEN} bytes. Got: {buffer[1]!r}"
            )

        if (value := buffer[1]) > len(buffer):
            raise Ip4IntegrityError(
                "The IPv4 Record Route option length value must be less than or equal to the "
                f"length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IPv4 Record Route option from buffer.
        """

        assert (value := len(buffer)) >= IP4__OPTION__RR__MIN_LEN, (
            f"The minimum length of the IPv4 Record Route option must be {IP4__OPTION__RR__MIN_LEN} "
            f"bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Ip4OptionType.RR), (
            f"The IPv4 Record Route option type must be {Ip4OptionType.RR!r}. "
            f"Got: {Ip4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls(
            pointer=buffer[2],
            route=[
                Ip4Address(bytes(buffer[offset : offset + IP4__OPTION__RR__SLOT_LEN]))
                for offset in range(
                    IP4__OPTION__RR__HDR_LEN,
                    buffer[1],
                    IP4__OPTION__RR__SLOT_LEN,
                )
            ],
        )
