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
This module contains the ARP protocol base class.

pmd_net_proto/protocols/arp/arp__base.py

ver 3.0.7
"""

from __future__ import annotations

from typing_extensions import override

from pmd_net_proto.lib.proto import Proto
from pmd_net_proto.protocols.arp.arp__header import ArpHeader, ArpHeaderProperties
from pmd_net_proto._compat import as_buffer


class Arp(Proto, ArpHeaderProperties):
    """
    The ARP protocol base.
    """

    _header: ArpHeader

    @override
    def __len__(self) -> int:
        """
        Get the ARP packet length.
        """

        return len(self._header)

    @override
    def __str__(self) -> str:
        """
        Get the ARP packet log string.
        """

        return (
            f"ARP {self._header.oper} {self._header.spa} / {self._header.sha}"
            f" > {self._header.tpa} / {self._header.tha}"
            f", len {len(self._header)}"
        )

    @override
    def __repr__(self) -> str:
        """
        Get the ARP packet representation string.
        """

        return f"{type(self).__name__}(header={self._header!r})"

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the ARP packet as a memoryview.
        """

        return memoryview(as_buffer(self._header))
    @override
    def __bytes__(self) -> bytes:
        """
        Get the object as bytes (Python 3.9+ fallback for the
        PEP 688 '__buffer__' protocol, which is 3.12+).
        """

        return bytes(self.__buffer__(0))


    @property
    def header(self) -> ArpHeader:
        """
        Get the ARP packet '_header' attribute.
        """

        return self._header
