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
This module contains IPv4 network support class.

net_addr/ip4_network.py

ver 3.0.5
"""

from collections.abc import Iterator
from typing import Self, override

from net_addr.errors import (
    Ip4AddressFormatError,
    Ip4MaskFormatError,
    Ip4NetworkFormatError,
)
from net_addr.ip4_address import IP4__MASK, Ip4Address
from net_addr.ip4_mask import Ip4Mask
from net_addr.ip_network import IpNetwork
from net_addr.ip_version import IpVersion


class Ip4Network(IpNetwork[Ip4Address, Ip4Mask]):
    """
    IPv4 network support class.
    """

    __slots__ = ()

    _version = IpVersion.IP4

    def __init__(
        self,
        network: Self | tuple[Ip4Address, Ip4Mask] | str | None = None,
        /,
    ) -> None:
        """
        Initialize the IPv4 network object.
        """

        if network is None:
            self._address = Ip4Address()
            self._mask = Ip4Mask()
            return

        if isinstance(network, Ip4Network):
            self._mask = network.mask
            self._address = Ip4Address(int(network.address) & int(network.mask))
            return

        if isinstance(network, tuple):
            tuple_address, tuple_mask = network
            self._mask = tuple_mask
            self._address = Ip4Address(int(tuple_address) & int(tuple_mask))
            return

        if isinstance(network, str):
            parts = network.split("/", 1) if "/" in network else network.split(" ", 1)
            if len(parts) == 2:
                try:
                    address_str, mask_str = parts
                    self._mask = Ip4Mask(f"/{mask_str}" if "/" in network else mask_str)
                    self._address = Ip4Address(int(Ip4Address(address_str)) & int(self._mask))
                    return
                except Ip4AddressFormatError, Ip4MaskFormatError:
                    pass

        raise Ip4NetworkFormatError(network)

    @property
    @override
    def last(self) -> Ip4Address:
        """
        Last address in the network.
        """

        return Ip4Address(int(self._address) + (~int(self._mask) & IP4__MASK))

    @property
    def broadcast(self) -> Ip4Address:
        """
        Broadcast address (same as last address in the network).
        """

        return self.last

    @override
    def hosts(self) -> Iterator[Ip4Address]:
        """
        Iterate over the usable host addresses, excluding the
        network and broadcast addresses. A /31 (RFC 3021) and a
        single-host /32 yield every address instead.
        """

        if len(self._mask) >= 31:
            yield from self
            return

        for value in range(int(self._address) + 1, int(self.last)):
            yield Ip4Address(value)
