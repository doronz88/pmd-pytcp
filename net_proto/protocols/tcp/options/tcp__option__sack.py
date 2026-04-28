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
This module contains the TCP Sack (Selective ACK) option support code.

net_proto/protocols/tcp/options/tcp__option__sack.py

ver 3.0.4
"""

import struct
from dataclasses import dataclass, field
from typing import Self, override

from net_proto.lib.buffer import Buffer
from net_proto.protocols.tcp.options.tcp__option import (
    TCP__OPTION__LEN,
    TcpOption,
    TcpOptionType,
)
from net_proto.protocols.tcp.tcp__errors import TcpIntegrityError

# The TCP Sack option [RFC 2018].

#                                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                 |    Type = 5   |   Length = N  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Left Edge of 1st Block                     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                   Right Edge of 1st Block                     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    . . .                                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Left Edge of nth Block                     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                   Right Edge of nth Block                     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

TCP__OPTION__SACK__STRUCT = "! BB"
TCP__OPTION__SACK__LEN = 2
TCP__OPTION__SACK__BLOCK_LEN = 8
TCP__OPTION__SACK__BLOCK_STRUCT = "! LL"
TCP__OPTION__SACK__MAX_BLOCK_NUM = 4


@dataclass(frozen=True, kw_only=False, slots=True)
class TcpSackBlock:
    """
    The TCP Sack block support class.
    """

    left: int
    right: int

    def __len__(self) -> int:
        """
        Get the TCP Sack block length.
        """

        return TCP__OPTION__SACK__BLOCK_LEN

    def __buffer__(self, _: int) -> memoryview:
        """
        Get the TCP Sack block as a memoryview.
        """

        struct.pack_into(
            TCP__OPTION__SACK__BLOCK_STRUCT,
            buffer := bytearray(len(self)),
            0,
            self.left,
            self.right,
        )

        return memoryview(buffer)

    def __str__(self) -> str:
        """
        Get the TCP Sack block log string.
        """

        return f"{self.left}-{self.right}"


@dataclass(frozen=True, kw_only=False, slots=True)
class TcpOptionSack(TcpOption):
    """
    The TCP Sack option support class.
    """

    type: TcpOptionType = field(
        repr=False,
        init=False,
        default=TcpOptionType.SACK,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    blocks: list[TcpSackBlock]

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the TCP Sack option fields.
        """

        # Ensure the number of blocks is within the allowed range.
        assert (value := len(self.blocks)) <= TCP__OPTION__SACK__MAX_BLOCK_NUM, (
            f"The 'blocks' field must have at most {TCP__OPTION__SACK__MAX_BLOCK_NUM} " f"elements. Got: {value!r}"
        )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(
            self,
            "len",
            TCP__OPTION__LEN + TCP__OPTION__SACK__BLOCK_LEN * len(self.blocks),
        )

    @override
    def __str__(self) -> str:
        """
        Get the TCP Sack option log string.
        """

        return f"sack [{', '.join([str(block) for block in self.blocks])}]"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the TCP Sack option as a memoryview.
        """

        struct.pack_into(
            TCP__OPTION__SACK__STRUCT,
            buffer := bytearray(TCP__OPTION__SACK__LEN),
            0,
            int(self.type),
            self.len,
        )

        for block in self.blocks:
            buffer.extend(bytearray(block))

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Validate the TCP Sack option integrity before parsing it.
        """

        # Raise integrity error if there is not enough bytes to parse the option.
        if (value := buffer[1]) > len(buffer):
            raise TcpIntegrityError(
                "The TCP Sack option length value must be less than or equal to "
                f"the length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

        # Raise integrity error when the option length doesn't align properly with block size.
        if (value := buffer[1] - TCP__OPTION__LEN) % TCP__OPTION__SACK__BLOCK_LEN:
            raise TcpIntegrityError(
                "The TCP Sack option blocks length value must be a multiple of "
                f"{TCP__OPTION__SACK__BLOCK_LEN}. Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the TCP Sack option from buffer.
        """

        # Ensure we got enough bytes to parse the option header.
        assert (
            value := len(buffer)
        ) >= TCP__OPTION__LEN, (
            f"The minimum length of the TCP Sack option must be {TCP__OPTION__LEN} bytes. Got: {value!r}"
        )

        # Ensure the option type is the expected value.
        assert (value := buffer[0]) == int(
            TcpOptionType.SACK
        ), f"The TCP Sack option type must be {TcpOptionType.SACK!r}. Got: {TcpOptionType.from_int(value)!r}"

        cls._validate_integrity(buffer)

        return cls(
            blocks=[
                TcpSackBlock(
                    left=int.from_bytes(buffer[offset : offset + TCP__OPTION__SACK__BLOCK_LEN // 2]),
                    right=int.from_bytes(
                        buffer[offset + TCP__OPTION__SACK__BLOCK_LEN // 2 : offset + TCP__OPTION__SACK__BLOCK_LEN]
                    ),
                )
                for offset in range(
                    TCP__OPTION__LEN,
                    buffer[1],
                    TCP__OPTION__SACK__BLOCK_LEN,
                )
            ]
        )
