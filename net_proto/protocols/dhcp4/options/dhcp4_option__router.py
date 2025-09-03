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
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4_option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Router option [RFC 2132].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Code = 3    |    Length = 4n  |          Router IP Address
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#            Router IP Address       ...
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__OPTION__ROUTER__LEN = 2
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
        default=DHCP4__OPTION__ROUTER__LEN,
    )

    routers: list[Ip4Address]

    @override
    def __post_init__(self) -> None:
        """
        Validate the DHCPv4 Router option fields.
        """

        assert isinstance(self.routers, list) and all(
            isinstance(router, Ip4Address) for router in self.routers
        ), (
            f"The 'router' field must be a list of Ip4Address. "
            f"Got: {type(self.routers)!r}"
        )

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Router option log string.
        """

        return f"router {self.routers}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the DHCPv4 Router option as bytes.
        """

        return struct.pack(
            DHCP4__OPTION__ROUTER__STRUCT + f"{len(self.routers) * 4}s",
            int(self.type),
            self.len - DHCP4__OPTION__LEN,
            b"".join(bytes(router) for router in self.routers),
        )

    @staticmethod
    def _validate_integrity(_bytes: bytes, /) -> None:
        """
        Validate the DHCPv4 Router option integrity before parsing it.
        """

        if (
            value := DHCP4__OPTION__LEN + _bytes[1]
        ) != DHCP4__OPTION__ROUTER__LEN:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Router option length value must be "
                f"{DHCP4__OPTION__ROUTER__LEN} bytes. Got: {value!r}"
            )

        if (value := DHCP4__OPTION__LEN + _bytes[1]) > len(_bytes):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Router option length value must be less than or equal "
                f"to the length of provided bytes ({len(_bytes)}). Got: {value!r}"
            )

        if (value := _bytes[1] % 4) != 0:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Router option length value (less header) must be a multiplication of 4. "
                f"Got: {value!r}"
            )

    @override
    @classmethod
    def from_bytes(cls, _bytes: bytes, /) -> Self:
        """
        Initialize the DHCPv4 Router option from bytes.
        """

        assert (value := len(_bytes)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Router option must "
            f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := _bytes[0]) == int(Dhcp4OptionType.ROUTER), (
            f"The DHCPv4 Router option type must be {Dhcp4OptionType.ROUTER!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(_bytes)

        return cls(
            routers=[
                Ip4Address(_bytes[i : i + 4])
                for i in range(2, _bytes[1] + 2, 4)
            ]
        )
