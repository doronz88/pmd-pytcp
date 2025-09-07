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
This module contains the DHCPv4 IP Address Lease Time option support code.

net_proto/protocols/dhcp4/options/dhcp4_option__lease_time.py

ver 3.0.4
"""


import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.int_checks import is_uint32
from net_proto.protocols.dhcp4.dhcp4__errors import Dhcp4IntegrityError
from net_proto.protocols.dhcp4.options.dhcp4_option import (
    DHCP4__OPTION__LEN,
    Dhcp4Option,
    Dhcp4OptionType,
)

# The DHCPv4 IP Address Lease Time option [RFC 2132].
#
#                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                 |    Code = 51  |   Length = 4  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Lease Time (seconds)                    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__OPTION__LEASE_TIME__LEN = 6
DHCP4__OPTION__LEASE_TIME__STRUCT = "! BB I"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp4OptionLeaseTime(Dhcp4Option):
    """
    The DHCPv4 IP Address Lease Time option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.LEASE_TIME,
    )
    len: int = field(
        repr=False,
        init=False,
        default=DHCP4__OPTION__LEASE_TIME__LEN,
    )

    lease_time: int

    @override
    def __post_init__(self) -> None:
        """
        Validate the DHCPv4 IP Address Lease Time option fields.
        """

        # Ensure the 'lease_time' field is 32-bit unsigned integer.
        assert is_uint32(self.lease_time), (
            f"The 'lease_time' field must be a 32-bit unsigned integer. "
            f"Got: {self.lease_time}"
        )

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 IP Address Lease Time option log string.
        """

        return f"lease_time {self.lease_time}"

    @override
    def __bytes__(self) -> bytes:
        """
        Get the DHCPv4 IP Address Lease Time option as bytes.
        """

        return struct.pack(
            DHCP4__OPTION__LEASE_TIME__STRUCT,
            int(self.type),
            self.len - DHCP4__OPTION__LEN,
            int(self.lease_time),
        )

    @staticmethod
    def _validate_integrity(_bytes: bytes, /) -> None:
        """
        Validate the DHCPv4 IP Address Lease Time option integrity before parsing it.
        """

        # Raise integrity error when the option length value is incorrect.
        if (
            value := DHCP4__OPTION__LEN + _bytes[1]
        ) != DHCP4__OPTION__LEASE_TIME__LEN:
            raise Dhcp4IntegrityError(
                "The DHCPv4 IP Address Lease Time option length value must be "
                f"{DHCP4__OPTION__LEASE_TIME__LEN} bytes. Got: {value!r}"
            )

        # Raise integrity error if there is not enough bytes to parse the option.
        if (value := DHCP4__OPTION__LEN + _bytes[1]) > len(_bytes):
            raise Dhcp4IntegrityError(
                "The DHCPv4 IP Address Lease Time option length value must be less than or equal "
                f"to the length of provided bytes ({len(_bytes)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_bytes(cls, _bytes: bytes, /) -> Self:
        """
        Initialize the DHCPv4 IP Address Lease Time option from bytes.
        """

        # Ensure we got enough bytes to parse the option header.
        assert (value := len(_bytes)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 IP Address Lease Time option must "
            f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        # Ensure the option type is the expected value.
        assert (value := _bytes[0]) == int(Dhcp4OptionType.LEASE_TIME), (
            f"The DHCPv4 IP Address Lease Time option type must be {Dhcp4OptionType.LEASE_TIME!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(_bytes)

        return cls(lease_time=int.from_bytes(_bytes[2:6], "big"))
