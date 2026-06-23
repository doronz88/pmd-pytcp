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
This module contains IPv4 mask support class.

pmd_net_addr/ip4_mask.py

ver 3.0.7
"""

from __future__ import annotations

import re
import socket

from pmd_net_addr.errors import Ip4MaskFormatError
from pmd_net_addr.ip4_address import IP4__ADDRESS_LEN, IP4__MASK
from pmd_net_addr.ip_mask import IpMask
from pmd_net_addr.ip_version import IpVersion
from pmd_net_addr._compat import as_buffer
from typing_extensions import Self, final, override


@final
class Ip4Mask(IpMask):
    """
    IPv4 mask support class.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP4

    def __init__(
        self,
        mask: Self | str | bytes | bytearray | memoryview | int | None = None,
        /,
    ) -> None:
        """
        Initialize the IPv4 mask object.
        """

        if mask is None:
            self._mask = 0
            return

        if isinstance(mask, Ip4Mask):
            self._mask = int(mask)
            return

        if isinstance(mask, int):
            if 0 <= mask <= IP4__MASK and self._is_contiguous_mask(mask, IP4__ADDRESS_LEN * 8):
                self._mask = mask
                return

        if isinstance(mask, (memoryview, bytes, bytearray)):
            if len(mask) == IP4__ADDRESS_LEN:
                candidate = int.from_bytes(mask, "big")
                if self._is_contiguous_mask(candidate, IP4__ADDRESS_LEN * 8):
                    self._mask = candidate
                    return

        if isinstance(mask, str):
            # Surrounding whitespace is stripped uniformly across
            # every pmd_net_addr string constructor.
            text = mask.strip()

            if re.search(r"^/(0|[1-9][0-9]?)$", text):
                bit_count = int(text[1:])
                if 0 <= bit_count <= IP4__ADDRESS_LEN * 8:
                    self._mask = ((1 << bit_count) - 1) << (IP4__ADDRESS_LEN * 8 - bit_count)
                    return

            # 'socket.inet_pton' is the strict POSIX parser; the
            # legacy 'socket.inet_aton' would accept octal / hex
            # octets and leading zeros and silently reinterpret the
            # dotted netmask.
            try:
                candidate = int.from_bytes(socket.inet_pton(socket.AF_INET, text), "big")
            except OSError:
                pass
            else:
                if self._is_contiguous_mask(candidate, IP4__ADDRESS_LEN * 8):
                    self._mask = candidate
                    return

        raise Ip4MaskFormatError(mask)

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv4 mask as a memoryview.
        """

        return memoryview(bytearray(as_buffer(self._mask.to_bytes(IP4__ADDRESS_LEN, "big"))))
    @override
    def __bytes__(self) -> bytes:
        """
        Get the object as bytes (Python 3.9+ fallback for the
        PEP 688 '__buffer__' protocol, which is 3.12+).
        """

        return bytes(self.__buffer__(0))

