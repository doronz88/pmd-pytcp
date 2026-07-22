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
This module contains IPv4 wildcard support class.

pmd_net_addr/ip4_wildcard.py

ver 3.0.7
"""

from __future__ import annotations

import socket

from pmd_net_addr._compat import as_buffer
from pmd_net_addr.errors import Ip4WildcardFormatError
from pmd_net_addr.ip4_address import IP4__ADDRESS_LEN, IP4__MASK, parse_ip4_dotted_decimal
from pmd_net_addr.ip_version import IpVersion
from pmd_net_addr.ip_wildcard import IpWildcard
from typing_extensions import Self, final, override


@final
class Ip4Wildcard(IpWildcard):
    """
    IPv4 wildcard support class.

    Any in-range 32-bit value is a valid wildcard (arbitrary,
    possibly non-contiguous bits) — Cisco/ACL semantics.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP4

    def __init__(
        self,
        wildcard: Self | str | bytes | bytearray | memoryview | int | None = None,
        /,
    ) -> None:
        """
        Initialize the IPv4 wildcard object.
        """

        if wildcard is None:
            self._wildcard = 0
            return

        if isinstance(wildcard, Ip4Wildcard):
            self._wildcard = int(wildcard)
            return

        if isinstance(wildcard, int):
            if 0 <= wildcard <= IP4__MASK:
                self._wildcard = wildcard
                return

        if isinstance(wildcard, (memoryview, bytes, bytearray)):
            if len(wildcard) == IP4__ADDRESS_LEN:
                self._wildcard = int.from_bytes(wildcard, "big")
                return

        if isinstance(wildcard, str):
            # Surrounding whitespace is stripped uniformly across
            # every pmd_net_addr string constructor. The canonical
            # dotted-decimal parse is done in-package
            # ('parse_ip4_dotted_decimal') rather than via
            # 'socket.inet_pton', whose strictness is platform-
            # dependent (Darwin accepts leading-zero octets, which
            # would silently reinterpret the dotted wildcard).
            if (value := parse_ip4_dotted_decimal(wildcard.strip())) is not None:
                self._wildcard = value
                return

        raise Ip4WildcardFormatError(wildcard)

    @override
    def __str__(self) -> str:
        """
        Get the IPv4 wildcard log string.
        """

        return socket.inet_ntoa(bytes(self))

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv4 wildcard as a memoryview.
        """

        return memoryview(bytearray(as_buffer(self._wildcard.to_bytes(IP4__ADDRESS_LEN, "big"))))

    @override
    def __bytes__(self) -> bytes:
        """
        Get the object as bytes (Python 3.9+ fallback for the
        PEP 688 '__buffer__' protocol, which is 3.12+).
        """

        return bytes(self.__buffer__(0))
