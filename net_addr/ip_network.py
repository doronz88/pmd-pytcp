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
This module contains IP network base class.

net_addr/ip_network.py

ver 3.0.5
"""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import TYPE_CHECKING, Self, override

from net_addr.base import Base
from net_addr.errors import IpNetworkFormatError
from net_addr.ip import Ip
from net_addr.ip4_address import Ip4Address
from net_addr.ip4_mask import Ip4Mask
from net_addr.ip4_wildcard import Ip4Wildcard
from net_addr.ip6_address import Ip6Address
from net_addr.ip6_mask import Ip6Mask
from net_addr.ip6_wildcard import Ip6Wildcard

if TYPE_CHECKING:
    from net_addr.ip4_network import Ip4Network
    from net_addr.ip6_network import Ip6Network


class IpNetwork[A: (Ip6Address, Ip4Address), M: (Ip6Mask, Ip4Mask)](Base, Ip, ABC):
    """
    IP network support base class.
    """

    __slots__ = (
        "_address",
        "_mask",
    )

    _address: A
    _mask: M

    @abstractmethod
    def __init__(self, network: Self | tuple[A, M] | str | None = None, /) -> None:
        """
        Initialize the IP network object. Concrete subclasses
        bind the version-specific address / mask types and the
        accepted input forms.
        """

        raise NotImplementedError

    @staticmethod
    def from_value(value: str, /) -> "Ip4Network | Ip6Network":
        """
        Build the concrete IPv4 or IPv6 network from a CIDR /
        address-mask string of unknown family (IPv4 attempted
        first). Raises 'IpNetworkFormatError' when the value
        parses as neither.
        """

        from net_addr.ip4_network import Ip4Network
        from net_addr.ip6_network import Ip6Network

        try:
            return Ip4Network(value)
        except IpNetworkFormatError:
            pass

        try:
            return Ip6Network(value)
        except IpNetworkFormatError:
            pass

        raise IpNetworkFormatError(value)

    @override
    def __str__(self) -> str:
        """
        Get the IP network log string.
        """

        return f"{self._address}/{len(self._mask)}"

    @override
    def __eq__(self, other: object, /) -> bool:
        """
        Compare IP network with another object.
        """

        return other is self or (
            isinstance(other, type(self)) and self._address == other._address and self._mask == other._mask
        )

    @override
    def __hash__(self) -> int:
        """
        Get the IP network hash value.
        """

        return hash((type(self), self._address, self._mask))

    def __lt__(self, other: object, /) -> bool:
        """
        Order the IP network by network address then prefix
        length. Ordering across IP versions is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return (int(self._address), int(self._mask)) < (int(other._address), int(other._mask))

    def __le__(self, other: object, /) -> bool:
        """
        Order the IP network by network address then prefix
        length. Ordering across IP versions is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return (int(self._address), int(self._mask)) <= (int(other._address), int(other._mask))

    def __gt__(self, other: object, /) -> bool:
        """
        Order the IP network by network address then prefix
        length. Ordering across IP versions is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return (int(self._address), int(self._mask)) > (int(other._address), int(other._mask))

    def __ge__(self, other: object, /) -> bool:
        """
        Order the IP network by network address then prefix
        length. Ordering across IP versions is undefined and
        raises TypeError.
        """

        if not isinstance(other, type(self)):
            return NotImplemented

        return (int(self._address), int(self._mask)) >= (int(other._address), int(other._mask))

    def __contains__(self, other: object, /) -> bool:
        """
        Check if the IP network contains the IP address or host.
        """

        from net_addr.ip4_ifaddr import Ip4IfAddr
        from net_addr.ip6_ifaddr import Ip6IfAddr

        if isinstance(other, (Ip6Address, Ip4Address)):
            return self.version == other.version and int(self.address) <= int(other) <= int(self.last)

        if isinstance(other, (Ip4IfAddr, Ip6IfAddr)):
            return self.version == other.version and int(self.address) <= int(other.address) <= int(self.last)

        return False

    @property
    def address(self) -> A:
        """
        Get the IP network '_address' attribute.
        """

        return self._address

    @property
    def mask(self) -> M:
        """
        Get the IP network '_mask' attribute.
        """

        return self._mask

    @property
    def prefixlen(self) -> int:
        """
        Get the IP network prefix length.
        """

        return len(self._mask)

    @property
    @abstractmethod
    def last(self) -> A:
        """
        Get the IP network last address.
        """

        raise NotImplementedError

    @property
    @abstractmethod
    def hostmask(self) -> "Ip4Wildcard | Ip6Wildcard":
        """
        Get the network wildcard (inverted netmask) — the
        contiguous special case of an ACL/firewall wildcard.
        """

        raise NotImplementedError

    @property
    def with_prefixlen(self) -> str:
        """
        Get the network in 'address/prefixlen' notation.
        """

        return str(self)

    @property
    def with_netmask(self) -> str:
        """
        Get the network in 'address/netmask' notation.
        """

        return f"{self._address}/{type(self._address)(int(self._mask))}"

    @property
    def with_hostmask(self) -> str:
        """
        Get the network in 'address/hostmask' (wildcard)
        notation.
        """

        return f"{self._address}/{self.hostmask}"

    @property
    def max_prefixlen(self) -> int:
        """
        Get the address-family width in bits (32 for IPv4,
        128 for IPv6).
        """

        return len(memoryview(self._address)) * 8

    @property
    def num_addresses(self) -> int:
        """
        Get the total number of addresses in the network,
        network and broadcast inclusive.
        """

        return int(self.last) - int(self._address) + 1

    def __iter__(self) -> Iterator[A]:
        """
        Iterate over every address in the network, network and
        broadcast inclusive.
        """

        address_type = type(self._address)
        for value in range(int(self._address), int(self.last) + 1):
            yield address_type(value)

    def __getitem__(self, index: int, /) -> A:
        """
        Get the address at the given index within the network.
        A negative index counts back from the last address; an
        out-of-range index raises IndexError. Slicing is not
        supported.
        """

        count = self.num_addresses

        if index < 0:
            index += count

        if not 0 <= index < count:
            raise IndexError(f"network index out of range: {index}")

        return type(self._address)(int(self._address) + index)

    @abstractmethod
    def hosts(self) -> Iterator[A]:
        """
        Iterate over the usable host addresses in the network.
        """

        raise NotImplementedError

    def subnets(self, *, prefixlen_diff: int = 1, new_prefix: int | None = None) -> Iterator[Self]:
        """
        Iterate over the subnets that tile this network at a
        longer prefix length.
        """

        prefixlen = len(self._mask)

        if prefixlen == self.max_prefixlen:
            yield self
            return

        if new_prefix is not None:
            if new_prefix <= prefixlen:
                raise ValueError(f"new prefix must be longer than {prefixlen}; got {new_prefix}")
            prefixlen_diff = new_prefix - prefixlen
        else:
            if prefixlen_diff < 1:
                raise ValueError(f"prefixlen_diff must be a positive integer; got {prefixlen_diff}")
            new_prefix = prefixlen + prefixlen_diff

        if new_prefix > self.max_prefixlen:
            raise ValueError(f"prefixlen_diff {prefixlen_diff} is invalid for a /{prefixlen} network")

        network_type = type(self)
        address_type = type(self._address)
        mask = type(self._mask)(self._mask_int(new_prefix))
        step = 1 << (self.max_prefixlen - new_prefix)
        for start in range(int(self._address), int(self.last) + 1, step):
            yield network_type((address_type(start), mask))

    def supernet(self, *, prefixlen_diff: int = 1, new_prefix: int | None = None) -> Self:
        """
        Get the supernet containing this network at a shorter
        prefix length.
        """

        prefixlen = len(self._mask)

        if new_prefix is not None:
            if new_prefix >= prefixlen:
                raise ValueError(f"new prefix must be shorter than {prefixlen}; got {new_prefix}")
        else:
            new_prefix = prefixlen - prefixlen_diff

        if new_prefix < 0:
            raise ValueError(f"prefixlen_diff {prefixlen_diff} is invalid for a /{prefixlen} network")

        return type(self)((type(self._address)(int(self._address)), type(self._mask)(self._mask_int(new_prefix))))

    def overlaps(self, other: object, /) -> bool:
        """
        Check whether this network shares any address with
        another network. A non-network or cross-version operand
        compares as non-overlapping.
        """

        return (
            isinstance(other, IpNetwork)
            and self.version == other.version
            and int(self._address) <= int(other.last)
            and int(other.address) <= int(self.last)
        )

    def subnet_of(self, other: object, /) -> bool:
        """
        Check whether this network is fully contained within
        another network. A non-network or cross-version operand
        compares as not-contained.
        """

        return (
            isinstance(other, IpNetwork)
            and self.version == other.version
            and int(other.address) <= int(self._address)
            and int(self.last) <= int(other.last)
        )

    def supernet_of(self, other: object, /) -> bool:
        """
        Check whether this network fully contains another
        network. A non-network or cross-version operand
        compares as not-contained.
        """

        return isinstance(other, IpNetwork) and other.subnet_of(self)

    def _mask_int(self, prefixlen: int, /) -> int:
        """
        Build the integer mask value for a given prefix length.
        """

        if prefixlen == 0:
            return 0
        return ((1 << prefixlen) - 1) << (self.max_prefixlen - prefixlen)
