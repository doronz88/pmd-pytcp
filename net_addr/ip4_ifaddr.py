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
This module contains IPv4 interface address support class.

net_addr/ip4_ifaddr.py

ver 3.0.5
"""

from typing import Self, override

from net_addr.errors import (
    Ip4AddressFormatError,
    Ip4IfAddrFormatError,
    Ip4IfAddrGatewayError,
    Ip4IfAddrSanityError,
    Ip4MaskFormatError,
    Ip4NetworkFormatError,
)
from net_addr.ip4_address import Ip4Address
from net_addr.ip4_mask import Ip4Mask
from net_addr.ip4_network import Ip4Network
from net_addr.ip_ifaddr import IfAddr
from net_addr.ip_version import IpVersion


class Ip4IfAddr(IfAddr[Ip4Address, Ip4Network]):
    """
    IPv4 interface address support class.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP4
    _gateway: Ip4Address | None

    def __init__(
        self,
        host: Self | tuple[Ip4Address, Ip4Network] | tuple[Ip4Address, Ip4Mask] | str,
        /,
        *,
        gateway: Ip4Address | None = None,
    ) -> None:
        """
        Initialize the IPv4 interface address object.
        """

        if isinstance(host, Ip4IfAddr):
            assert gateway is None, f"Gateway cannot be set when copying an interface address. Got: {gateway!r}"
            self._address = host.address
            self._network = host.network
            self._gateway = host.gateway
            return

        self._gateway = gateway

        if isinstance(host, tuple):
            tuple_address, network_or_mask = host
            self._address = tuple_address
            if isinstance(network_or_mask, Ip4Network):
                self._network = network_or_mask
            elif isinstance(network_or_mask, Ip4Mask):
                self._network = Ip4Network((tuple_address, network_or_mask))
            else:
                raise Ip4IfAddrFormatError(host)
            if self._address not in self._network:
                raise Ip4IfAddrSanityError(host)
            self._validate_gateway(gateway)
            return

        if isinstance(host, str):
            try:
                # Accept both the CIDR 'addr/prefix' form and the
                # standard IPv4 'addr netmask' space form, matching
                # what Ip4Network parses.
                address = host.split("/", 1)[0] if "/" in host else host.split(" ", 1)[0]
                self._address = Ip4Address(address)
                self._network = Ip4Network(host)
                self._validate_gateway(gateway)
                return
            except ValueError, Ip4AddressFormatError, Ip4MaskFormatError, Ip4NetworkFormatError:
                pass

        raise Ip4IfAddrFormatError(host)

    @override
    def _validate_gateway(self, address: Ip4Address | None, /) -> None:
        """
        Validate the IPv4 interface address gateway.
        """

        if address is not None and (
            address not in self.network
            or address == self._network.address
            or address == self._network.broadcast
            or address == self._address
        ):
            raise Ip4IfAddrGatewayError(address)
