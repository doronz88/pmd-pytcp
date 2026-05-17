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
This module contains IP address base class.

net_addr/ip_address.py

ver 3.0.5
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from net_addr.address import Address
from net_addr.errors import IpAddressFormatError
from net_addr.ip import Ip
from net_addr.mac_address import MacAddress

if TYPE_CHECKING:
    from net_addr.ip4_address import Ip4Address
    from net_addr.ip6_address import Ip6Address


class IpAddress(Address, Ip, ABC):
    """
    IP address support base class.
    """

    __slots__ = ()

    @staticmethod
    def from_value(value: str | bytes | bytearray | memoryview | int, /) -> "Ip4Address | Ip6Address":
        """
        Build the concrete IPv4 or IPv6 address from a value of
        unknown family (IPv4 attempted first). Raises
        'IpAddressFormatError' when the value parses as neither.
        """

        from net_addr.ip4_address import Ip4Address
        from net_addr.ip6_address import Ip6Address

        try:
            return Ip4Address(value)
        except IpAddressFormatError:
            pass

        try:
            return Ip6Address(value)
        except IpAddressFormatError:
            pass

        raise IpAddressFormatError(value)

    @property
    @abstractmethod
    def multicast_mac(self) -> MacAddress:
        """
        Get the multicast MAC address for this IP address.
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def reverse_pointer(self) -> str:
        """
        Get the reverse-DNS PTR name for this IP address.
        """

        raise NotImplementedError

    @property
    def compressed(self) -> str:
        """
        Get the address in its canonical compressed text form.
        """

        return str(self)

    @property
    def max_prefixlen(self) -> int:
        """
        Get the address-family width in bits (32 for IPv4,
        128 for IPv6).
        """

        return len(memoryview(self)) * 8

    @property
    @abstractmethod
    def exploded(self) -> str:
        """
        Get the address in its fully expanded text form.
        """

        raise NotImplementedError

    @property
    def is_unicast(self) -> bool:
        """
        Check if the IP address is an unicast address.
        """

        return self.is_global or self.is_private or self.is_link_local or self.is_loopback

    @property
    @abstractmethod
    def is_loopback(self) -> bool:
        """
        Check if IP address is a loopback address.
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def is_global(self) -> bool:
        """
        Check if IP address is a global address.
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def is_private(self) -> bool:
        """
        Check if IP address is a private address.
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def is_link_local(self) -> bool:
        """
        Check if IP address is a link local address.
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def is_multicast(self) -> bool:
        """
        Check if IP address is a multicast address.
        """

        raise NotImplementedError
