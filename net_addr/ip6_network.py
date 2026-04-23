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
This module contains IPv6 network support class.

net_addr/ip6_network.py

ver 3.0.4
"""

from typing import Self, override

from net_addr.errors import (
    Ip6AddressFormatError,
    Ip6MaskFormatError,
    Ip6NetworkFormatError,
)
from net_addr.ip6_address import IP6__MASK, Ip6Address
from net_addr.ip6_mask import Ip6Mask
from net_addr.ip_network import IpNetwork
from net_addr.ip_version import IpVersion


class Ip6Network(IpNetwork[Ip6Address, Ip6Mask]):
    """
    IPv6 network support class.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP6

    def __init__(
        self,
        network: Self | tuple[Ip6Address, Ip6Mask] | str | None = None,
        /,
    ) -> None:
        """
        Initialize the IPv6 network object.
        """

        if network is None:
            self._address = Ip6Address()
            self._mask = Ip6Mask()
            return

        if isinstance(network, Ip6Network):
            self._mask = network.mask
            self._address = Ip6Address(int(network.address) & int(network.mask))
            return

        if isinstance(network, tuple):
            tuple_address, tuple_mask = network
            self._mask = tuple_mask
            self._address = Ip6Address(int(tuple_address) & int(tuple_mask))
            return

        if isinstance(network, str):
            try:
                address, mask = network.split("/")
                self._mask = Ip6Mask("/" + mask)
                self._address = Ip6Address(int(Ip6Address(address)) & int(self._mask))
                return
            except ValueError, Ip6AddressFormatError, Ip6MaskFormatError:
                pass

        raise Ip6NetworkFormatError(network)

    @property
    @override
    def last(self) -> Ip6Address:
        """
        Last address in the network.
        """

        return Ip6Address(int(self._address) + (~int(self._mask) & IP6__MASK))
