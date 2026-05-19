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
This module contains the IPv4 Timestamp option support code.

net_proto/protocols/ip4/options/ip4__option__timestamp.py

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

# The IPv4 Timestamp option [RFC 791].

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Type = 68  |    Length     |    Pointer    | oflw  |  flag |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |               (Internet address per flag=1/3)                 |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                          Timestamp                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

IP4__OPTION__TIMESTAMP__HDR_LEN = 4
IP4__OPTION__TIMESTAMP__POINTER_BASE = 5

# Flag values (RFC 791 §3.1):
IP4__OPTION__TIMESTAMP__FLAG__TS_ONLY = 0  # timestamps only
IP4__OPTION__TIMESTAMP__FLAG__TS_AND_ADDR = 1  # each timestamp preceded by recording host's IP
IP4__OPTION__TIMESTAMP__FLAG__TS_PRESPEC = 3  # only listed routers may record (addresses prespecified)

# Entry sizes per flag.
IP4__OPTION__TIMESTAMP__ENTRY_LEN__TS_ONLY = 4
IP4__OPTION__TIMESTAMP__ENTRY_LEN__WITH_ADDR = 8

IP4__OPTION__TIMESTAMP__STRUCT = "! BBBB"

_FLAG_VALUES_WITH_ADDRESS: frozenset[int] = frozenset(
    {
        IP4__OPTION__TIMESTAMP__FLAG__TS_AND_ADDR,
        IP4__OPTION__TIMESTAMP__FLAG__TS_PRESPEC,
    }
)
_FLAG_VALUES_ALL: frozenset[int] = frozenset(
    {
        IP4__OPTION__TIMESTAMP__FLAG__TS_ONLY,
        IP4__OPTION__TIMESTAMP__FLAG__TS_AND_ADDR,
        IP4__OPTION__TIMESTAMP__FLAG__TS_PRESPEC,
    }
)


def _entry_len_for_flag(flag: int) -> int:
    """
    Return the per-entry byte size implied by the timestamp option flag.
    """

    if flag in _FLAG_VALUES_WITH_ADDRESS:
        return IP4__OPTION__TIMESTAMP__ENTRY_LEN__WITH_ADDR
    return IP4__OPTION__TIMESTAMP__ENTRY_LEN__TS_ONLY


@dataclass(frozen=True, kw_only=False, slots=True)
class Ip4TimestampEntry:
    """
    A single IPv4 Timestamp option entry. Carries a 32-bit timestamp
    and (for flag=1/3) the recording host's IPv4 address.
    """

    timestamp: int
    address: Ip4Address | None = None

    def __len__(self) -> int:
        """
        Get the entry length in bytes (4 for timestamp-only, 8 with
        address).
        """

        if self.address is None:
            return IP4__OPTION__TIMESTAMP__ENTRY_LEN__TS_ONLY
        return IP4__OPTION__TIMESTAMP__ENTRY_LEN__WITH_ADDR

    def __buffer__(self, _: int) -> memoryview:
        """
        Get the entry as a memoryview (network byte order).
        """

        buffer = bytearray(len(self))
        if self.address is not None:
            buffer[0:4] = bytes(self.address)
            struct.pack_into("! L", buffer, 4, self.timestamp)
        else:
            struct.pack_into("! L", buffer, 0, self.timestamp)
        return memoryview(buffer)

    def __str__(self) -> str:
        """
        Get the entry as a single-line log string.
        """

        if self.address is not None:
            return f"{self.address}:{self.timestamp}"
        return str(self.timestamp)


@dataclass(frozen=True, kw_only=False, slots=True)
class Ip4OptionTimestamp(Ip4Option):
    """
    The IPv4 Timestamp option support class.
    """

    type: Ip4OptionType = field(
        repr=False,
        init=False,
        default=Ip4OptionType.TIMESTAMP,
    )
    len: int = field(
        repr=False,
        init=False,
    )

    pointer: int
    overflow: int
    flag: int
    entries: list[Ip4TimestampEntry]

    @override
    def __post_init__(self) -> None:
        """
        Ensure integrity of the IPv4 Timestamp option fields.
        """

        assert is_uint8(self.pointer), f"The 'pointer' field must be an 8-bit unsigned integer. Got: {self.pointer!r}"

        assert self.pointer >= IP4__OPTION__TIMESTAMP__POINTER_BASE, (
            f"The 'pointer' field must be at least {IP4__OPTION__TIMESTAMP__POINTER_BASE}. " f"Got: {self.pointer!r}"
        )

        assert 0 <= self.overflow <= 15, f"The 'overflow' field must fit in 4 bits (0..15). Got: {self.overflow!r}"

        assert self.flag in _FLAG_VALUES_ALL, f"The 'flag' field must be one of {{0, 1, 3}}. Got: {self.flag!r}"

        entry_len = _entry_len_for_flag(self.flag)
        assert (self.pointer - IP4__OPTION__TIMESTAMP__POINTER_BASE) % entry_len == 0, (
            f"The 'pointer' field must be aligned to the {entry_len}-byte entry "
            f"boundary for flag={self.flag}. Got: {self.pointer!r}"
        )

        assert len(self.entries) >= 1, f"The 'entries' field must have at least 1 entry. Got: {len(self.entries)!r}"

        if self.flag == IP4__OPTION__TIMESTAMP__FLAG__TS_ONLY:
            assert all(entry.address is None for entry in self.entries), (
                "All entries must be timestamp-only (no address) when flag=0. " f"Got: {self.entries!r}"
            )
        else:
            assert all(entry.address is not None for entry in self.entries), (
                f"All entries must carry an address when flag={self.flag}. " f"Got: {self.entries!r}"
            )

        # Hack to bypass the 'frozen=True' dataclass decorator.
        object.__setattr__(
            self,
            "len",
            IP4__OPTION__TIMESTAMP__HDR_LEN + entry_len * len(self.entries),
        )

    @override
    def __str__(self) -> str:
        """
        Get the IPv4 Timestamp option log string.
        """

        return (
            f"timestamp [{', '.join(str(entry) for entry in self.entries)}] "
            f"ptr={self.pointer} oflw={self.overflow} flag={self.flag}"
        )

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv4 Timestamp option as a memoryview.
        """

        struct.pack_into(
            IP4__OPTION__TIMESTAMP__STRUCT,
            buffer := bytearray(self.len),
            0,
            int(self.type),
            self.len,
            self.pointer,
            (self.overflow << 4) | (self.flag & 0x0F),
        )

        offset = IP4__OPTION__TIMESTAMP__HDR_LEN
        for entry in self.entries:
            buffer[offset : offset + len(entry)] = bytes(entry)
            offset += len(entry)

        return memoryview(buffer)

    @staticmethod
    def _validate_integrity(buffer: Buffer, /) -> None:
        """
        Ensure integrity of the IPv4 Timestamp option before parsing it.
        """

        flag = buffer[3] & 0x0F

        if flag not in _FLAG_VALUES_ALL:
            raise Ip4IntegrityError(
                f"The IPv4 Timestamp option flag value must be one of {{0, 1, 3}}. " f"Got: {flag!r}"
            )

        entry_len = _entry_len_for_flag(flag)
        min_len = IP4__OPTION__TIMESTAMP__HDR_LEN + entry_len

        if (value := buffer[1]) < min_len:
            raise Ip4IntegrityError(
                f"The IPv4 Timestamp option length must be at least {min_len} bytes " f"for flag={flag}. Got: {value!r}"
            )

        if (buffer[1] - IP4__OPTION__TIMESTAMP__HDR_LEN) % entry_len:
            raise Ip4IntegrityError(
                "The IPv4 Timestamp option entries length must be a multiple of "
                f"{entry_len} bytes for flag={flag}. Got: {buffer[1]!r}"
            )

        if (value := buffer[1]) > len(buffer):
            raise Ip4IntegrityError(
                "The IPv4 Timestamp option length value must be less than or equal to the "
                f"length of provided bytes ({len(buffer)}). Got: {value!r}"
            )

    @override
    @classmethod
    def from_buffer(cls, buffer: Buffer, /) -> Self:
        """
        Initialize the IPv4 Timestamp option from buffer.
        """

        assert (value := len(buffer)) >= IP4__OPTION__TIMESTAMP__HDR_LEN, (
            f"The minimum length of the IPv4 Timestamp option must be "
            f"{IP4__OPTION__TIMESTAMP__HDR_LEN} bytes. Got: {value!r}"
        )

        assert (value := buffer[0]) == int(Ip4OptionType.TIMESTAMP), (
            f"The IPv4 Timestamp option type must be {Ip4OptionType.TIMESTAMP!r}. "
            f"Got: {Ip4OptionType.from_int(value)!r}"
        )

        cls._validate_integrity(buffer)

        flag = buffer[3] & 0x0F
        overflow = (buffer[3] >> 4) & 0x0F
        pointer = buffer[2]
        entry_len = _entry_len_for_flag(flag)

        entries: list[Ip4TimestampEntry] = []
        for offset in range(IP4__OPTION__TIMESTAMP__HDR_LEN, buffer[1], entry_len):
            if entry_len == IP4__OPTION__TIMESTAMP__ENTRY_LEN__WITH_ADDR:
                entries.append(
                    Ip4TimestampEntry(
                        timestamp=int.from_bytes(bytes(buffer[offset + 4 : offset + 8])),
                        address=Ip4Address(bytes(buffer[offset : offset + 4])),
                    )
                )
            else:
                entries.append(
                    Ip4TimestampEntry(
                        timestamp=int.from_bytes(bytes(buffer[offset : offset + 4])),
                    )
                )

        return cls(
            pointer=pointer,
            overflow=overflow,
            flag=flag,
            entries=entries,
        )
