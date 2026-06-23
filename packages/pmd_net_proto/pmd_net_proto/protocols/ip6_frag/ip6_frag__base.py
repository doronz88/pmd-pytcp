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
This module contains the IPv6 Frag protocol base class.

pmd_net_proto/protocols/ip6_frag/ip6_frag__base.py

ver 3.0.7
"""

from __future__ import annotations

from typing_extensions import override

from pmd_net_proto.lib.buffer import Buffer
from pmd_net_proto.lib.proto import Proto
from pmd_net_proto.protocols.ip6_frag.ip6_frag__header import (
    Ip6FragHeader,
    Ip6FragHeaderProperties,
)
from pmd_net_proto._compat import as_buffer


class Ip6Frag(Proto, Ip6FragHeaderProperties):
    """
    The IPv6 Frag protocol base.
    """

    _header: Ip6FragHeader
    _payload: Buffer

    @override
    def __len__(self) -> int:
        """
        Get the IPv6 Frag packet length.
        """

        return len(self._header) + len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the IPv6 Frag packet log string.
        """

        return (
            f"IPv6_FRAG id {self._header.id}{', MF' if self._header.flag_mf else ''}, "
            f"offset {self._header.offset}, next {self._header.next}, "
            f"len {len(self._header) + len(self._payload)} "
            f"({len(self._header)}+{len(self._payload)})"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the IPv6 Frag packet representation string.
        """

        return f"{type(self).__name__}(header={self._header!r}, payload={self._payload!r})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 Frag packet as a memoryview.
        """

        buffer = bytearray(as_buffer(self._header))
        buffer += as_buffer(self._payload)

        return memoryview(buffer)
    @override
    def __bytes__(self) -> bytes:
        """
        Get the object as bytes (Python 3.9+ fallback for the
        PEP 688 '__buffer__' protocol, which is 3.12+).
        """

        return bytes(self.__buffer__(0))


    @property
    def header(self) -> Ip6FragHeader:
        """
        Get the IPv6 Frag packet '_header' attribute.
        """

        return self._header

    @property
    def payload(self) -> Buffer:
        """
        Get the IPv6 Frag packet '_payload' attribute.
        """

        return self._payload
