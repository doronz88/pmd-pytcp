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
This module contains the DHCPv4 Host Name option support code.

net_proto/protocols/dhcp4/options/dhcp4_option__host_name.py

ver 3.0.4
"""


import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4_option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 Parameter Request List option [RFC 2132].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Code=12   |     Len=N     |           Hostname           ...
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__OPTION__HOST_NAME__LEN = 2
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
        default=DHCP4__OPTION__HOST_NAME__LEN,
    )

    host_name: str

    @override
    def __post_init__(self) -> None:
        """
        Validate the DHCPv4 Host Name option fields.
        """

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Host Name option log string.
        """

        return f"host_name {self.host_name}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the DHCPv4 Host Name option as bytes.
        """

        return struct.pack(
            DHCP4__OPTION__HOST_NAME__STRUCT + f"{len(self.host_name)}s",
            int(self.type),
            len(self.host_name),
            self.host_name.encode("utf-8"),
        )

    @staticmethod
    def _validate_integrity(_bytes: bytes, /) -> None:
        """
        Validate the DHCPv4 Host Name option integrity before parsing it.
        """

        if (value := _bytes[1]) >= DHCP4__OPTION__HOST_NAME__LEN:
            raise Dhcp4IntegrityError(
                "The DHCPv4 Host Name option length must be "
                f"at least {DHCP4__OPTION__HOST_NAME__LEN} bytes. Got: {value!r}"
            )

        if (value := _bytes[1]) > len(_bytes):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Host Name option length must be less than or equal "
                f"to the length of provided bytes ({len(_bytes)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_bytes(cls, _bytes: bytes, /) -> Self:
        """
        Initialize the DHCPv4 Host Name option from bytes.
        """

        assert (value := len(_bytes)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Host Name option must "
            f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        assert (value := _bytes[0]) == int(Dhcp4OptionType.HOST_NAME), (
            f"The DHCPv4 Host Name option type must be {Dhcp4OptionType.HOST_NAME!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(_bytes)

        return cls(
            host_name=_bytes[2 : 2 + _bytes[1]].decode("utf-8"),
        )
