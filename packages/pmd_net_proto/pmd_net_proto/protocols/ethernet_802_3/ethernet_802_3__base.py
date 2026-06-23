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
This module contains the Ethernet 802.3 protocol base class.

pmd_net_proto/protocols/ethernet_802_3/ethernet_802_3__base.py

ver 3.0.7
"""

from __future__ import annotations

from typing_extensions import TypeAliasType, override

from pmd_net_proto.lib.buffer import Buffer
from pmd_net_proto.lib.proto import Proto
from pmd_net_proto.protocols.ethernet_802_3.ethernet_802_3__header import (
    Ethernet8023Header,
    Ethernet8023HeaderProperties,
)
from pmd_net_proto.protocols.raw.raw__assembler import RawAssembler
from typing import Generic, TypeVar
from pmd_net_proto._compat import as_buffer

Ethernet8023Payload = TypeAliasType("Ethernet8023Payload", RawAssembler)


P = TypeVar("P", RawAssembler, Buffer)
class Ethernet8023(Proto, Ethernet8023HeaderProperties, Generic[P]):
    """
    The Ethernet 802.3 protocol base.
    """

    _header: Ethernet8023Header
    _payload: P

    @override
    def __len__(self) -> int:
        """
        Get the Ethernet 802.3 packet length.
        """

        return len(self._header) + len(self._payload)

    @override
    def __str__(self) -> str:
        """
        Get the Ethernet 802.3 packet log string.
        """

        return (
            f"ETHER_802.3 {self._header.src} > {self._header.dst}, dlen {self._header.dlen}, "
            f"len {len(self)} ({len(self._header)}+{len(self) - len(self._header)})"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the Ethernet 802.3 packet representation string.
        """

        return f"{type(self).__name__}(header={self._header!r}, payload={self._payload!r})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the Ethernet 802.3 packet as a memoryview.
        """

        buffer = bytearray(as_buffer(self._header))
        buffer += bytearray(as_buffer(self._payload))

        return memoryview(buffer)
    @override
    def __bytes__(self) -> bytes:
        """
        Get the object as bytes (Python 3.9+ fallback for the
        PEP 688 '__buffer__' protocol, which is 3.12+).
        """

        return bytes(self.__buffer__(0))


    @property
    def header(self) -> Ethernet8023Header:
        """
        Get the Ethernet 802.3 packet '_header' attribute.
        """

        return self._header

    @property
    def payload(self) -> P:
        """
        Get the Ethernet 802.3 packet '_payload' attribute.
        """

        return self._payload
