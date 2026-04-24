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
This module contains the DHCPv4 Parameter Request List option support code.

net_proto/protocols/dhcp4/options/dhcp4__option__param_req_list.py

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

# The DHCPv4 Parameter Request List option [RFC 2132].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Code=55   |     Len=N     |  Option Code  |  Option Code  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Option Code  |  Option Code  | ...
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


DHCP4__OPTION__PARAM_REQ_LIST__STRUCT = "! BB"


@dataclass(frozen=True, kw_only=False, slots=True)
class Dhcp4OptionParamReqList(Dhcp4Option):
    """
    The DHCPv4 Parameter Request List option support class.
    """

    type: Dhcp4OptionType = field(
        repr=False,
        init=False,
        default=Dhcp4OptionType.PARAM_REQ_LIST,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    param_req_list: list[Dhcp4OptionType]

    @override
    def __post_init__(self) -> None:
        """
        Validate the DHCPv4 Parameter Request List option fields.
        """

        # Ensure that the 'param_req_list' field is a list.
        assert isinstance(
            self.param_req_list, list
        ), f"The 'param_req_list' field must be a list. Got: {type(self.param_req_list)!r}"

        # Ensure that each element of the 'param_req_list' field is a Dhcp4OptionType instance.
        assert all(isinstance(item, Dhcp4OptionType) for item in self.param_req_list), (
            f"The 'param_req_list' field must be a list of Dhcp4OptionType elements. "
            f"Got: {[type(element) for element in self.param_req_list]!r}"
        )

        # Update the option 'len' field based on the length of the 'param_req_list' field.
        object.__setattr__(self, "len", DHCP4__OPTION__LEN + len(self.param_req_list))

    @override
    def __str__(self) -> str:
        """
        Get the DHCPv4 Parameter Request List option log string.
        """

        return f"param_req_list {[param.name for param in self.param_req_list]}"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the DHCPv4 Parameter Request List option as a memoryview.
        """

        struct.pack_into(
            DHCP4__OPTION__PARAM_REQ_LIST__STRUCT + f"{len(self.param_req_list)}s",
            buffer := bytearray(len(self)),
            0,
            int(self.type),
            self.len - DHCP4__OPTION__LEN,
            bytes([int(option) for option in self.param_req_list]),
        )

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Validate the DHCPv4 Parameter Request List option integrity before parsing it.
        """

        # Raise integrity error if there is not enough bytes to parse the option.
        if (value := DHCP4__OPTION__LEN + buffer[1]) > len(buffer):
            raise Dhcp4IntegrityError(
                "The DHCPv4 Parameter Request List option length value must be less than or equal "
                f"to the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the DHCPv4 Parameter Request List option from buffer.
        """

        # Ensure we got enough bytes to parse the option header.
        assert (value := len(buffer)) >= DHCP4__OPTION__LEN, (
            f"The minimum length of the DHCPv4 Parameter Request List option must "
            f"be {DHCP4__OPTION__LEN} bytes. Got: {value!r}"
        )

        # Ensure the option type is the expected value.
        assert (value := buffer[0]) == int(Dhcp4OptionType.PARAM_REQ_LIST), (
            f"The DHCPv4 Parameter Request List option type must be {Dhcp4OptionType.PARAM_REQ_LIST!r}. "
            f"Got: {Dhcp4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        return cls([Dhcp4OptionType.from_int(option) for option in buffer[2 : 2 + buffer[1]]])
