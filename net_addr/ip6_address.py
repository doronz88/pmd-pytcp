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
This module contains IPv6 address support class.

net_addr/ip6_address.py

ver 3.0.5
"""

import re
import socket
from typing import Self, override

from net_addr.errors import Ip6AddressFormatError
from net_addr.ip_address import IpAddress
from net_addr.ip_version import IpVersion
from net_addr.mac_address import MAC__IP6_MULTICAST_PREFIX, MacAddress

IP6__ADDRESS_LEN = 16
IP6__MASK = 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF

IP6__GLOBAL_PREFIX = 0x2000_0000_0000_0000_0000_0000_0000_0000  # RFC 4291 2000::/3
IP6__GLOBAL_PREFIX_MASK = 0xE000_0000_0000_0000_0000_0000_0000_0000

IP6__LINK_LOCAL_PREFIX = 0xFE80_0000_0000_0000_0000_0000_0000_0000  # RFC 4291 fe80::/10
IP6__LINK_LOCAL_PREFIX_MASK = 0xFFC0_0000_0000_0000_0000_0000_0000_0000

IP6__LOOPBACK = 0x0000_0000_0000_0000_0000_0000_0000_0001  # RFC 4291 ::1/128

IP6__MULTICAST_PREFIX = 0xFF00_0000_0000_0000_0000_0000_0000_0000  # RFC 4291 ff00::/8
IP6__MULTICAST_PREFIX_MASK = 0xFF00_0000_0000_0000_0000_0000_0000_0000

IP6__MULTICAST_ALL_NODES = 0xFF02_0000_0000_0000_0000_0000_0000_0001  # RFC 4291 ff02::1
IP6__MULTICAST_ALL_ROUTERS = 0xFF02_0000_0000_0000_0000_0000_0000_0002  # RFC 4291 ff02::2

IP6__SOLICITED_NODE_PREFIX = 0xFF02_0000_0000_0000_0000_0001_FF00_0000  # RFC 4291 ff02::1:ff00:0/104
IP6__SOLICITED_NODE_PREFIX_MASK = 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FF00_0000
IP6__SOLICITED_NODE_HOST_MASK = 0x0000_0000_0000_0000_0000_0000_00FF_FFFF

IP6__PRIVATE_PREFIX = 0xFC00_0000_0000_0000_0000_0000_0000_0000  # RFC 4193 fc00::/7
IP6__PRIVATE_PREFIX_MASK = 0xFE00_0000_0000_0000_0000_0000_0000_0000

# RFC 3849 Documentation prefix — 2001:db8::/32
IP6__DOCUMENTATION_PREFIX = 0x2001_0DB8_0000_0000_0000_0000_0000_0000
IP6__DOCUMENTATION_PREFIX_MASK = 0xFFFF_FFFF_0000_0000_0000_0000_0000_0000

# RFC 6666 Discard-Only Address Block — 100::/64
IP6__DISCARD_PREFIX = 0x0100_0000_0000_0000_0000_0000_0000_0000
IP6__DISCARD_PREFIX_MASK = 0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0000

# RFC 5180 Benchmarking — 2001:2::/48
IP6__BENCHMARK_PREFIX = 0x2001_0002_0000_0000_0000_0000_0000_0000
IP6__BENCHMARK_PREFIX_MASK = 0xFFFF_FFFF_FFFF_0000_0000_0000_0000_0000

# RFC 4291 §2.5.5.2 IPv4-mapped IPv6 — ::ffff:0:0/96
IP6__IPV4_MAPPED_PREFIX = 0x0000_0000_0000_0000_0000_FFFF_0000_0000
IP6__IPV4_MAPPED_PREFIX_MASK = 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0000_0000

IP6__REGEX = (
    r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,7}:|"
    r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
    r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
    r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
    r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
    r":((:[0-9a-fA-F]{1,4}){1,7}|:))"
)


class Ip6Address(IpAddress):
    """
    IPv6 address support class.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP6

    def __init__(
        self,
        address: Self | str | bytes | bytearray | memoryview | int | None = None,
        /,
    ) -> None:
        """
        Initialize the IPv6 address object.
        """

        if address is None:
            self._address = 0
            return

        if isinstance(address, Ip6Address):
            self._address = int(address)
            return

        if isinstance(address, int):
            if 0 <= address <= IP6__MASK:
                self._address = address
                return

        if isinstance(address, (memoryview, bytes, bytearray)):
            if len(address) == IP6__ADDRESS_LEN:
                self._address = int.from_bytes(address)
                return

        if isinstance(address, str):
            if re.search(IP6__REGEX, address):
                try:
                    self._address = int.from_bytes(socket.inet_pton(socket.AF_INET6, address))
                    return
                except OSError:
                    pass

        raise Ip6AddressFormatError(address)

    @override
    def __str__(self) -> str:
        """
        Get the IPv6 address log string.
        """

        return socket.inet_ntop(socket.AF_INET6, bytes(self))

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv6 address as a memoryview.
        """

        return memoryview(bytearray(self._address.to_bytes(IP6__ADDRESS_LEN)))

    @property
    @override
    def multicast_mac(self) -> MacAddress:
        """
        Get the IPv6 multicast MAC address.
        """

        assert (
            self.is_multicast
        ), f"The IPv6 address must be a multicast address to get a multicast MAC address. Got: {self}"

        return MacAddress(MAC__IP6_MULTICAST_PREFIX | self._address & 0x0000_FFFF_FFFF)

    @property
    @override
    def reverse_pointer(self) -> str:
        """
        Get the IPv6 reverse-DNS PTR name (all 32 reversed
        nibbles in the ip6.arpa zone).
        """

        return ".".join(reversed(f"{self._address:032x}")) + ".ip6.arpa"

    @property
    def solicited_node_multicast(self) -> Self:
        """
        Create IPv6 solicited node multicast address.
        """

        assert self.is_unicast or self.is_unspecified, (
            "The IPv6 address must be a unicast or unspecified address "
            f"to get a solicited node multicast address. Got: {self}"
        )

        return type(self)(self._address & IP6__SOLICITED_NODE_HOST_MASK | IP6__SOLICITED_NODE_PREFIX)

    @property
    @override
    def is_global(self) -> bool:
        """
        Check if IPv6 address is global.
        """

        return self._address & IP6__GLOBAL_PREFIX_MASK == IP6__GLOBAL_PREFIX

    @property
    @override
    def is_link_local(self) -> bool:
        """
        Check if IPv6 address is link local.
        """

        return self._address & IP6__LINK_LOCAL_PREFIX_MASK == IP6__LINK_LOCAL_PREFIX

    @property
    @override
    def is_loopback(self) -> bool:
        """
        Check if the IPv6 address is a loopback address.
        """

        return self._address == IP6__LOOPBACK

    @property
    @override
    def is_multicast(self) -> bool:
        """
        Check if IPv6 address is multicast.
        """

        return self._address & IP6__MULTICAST_PREFIX_MASK == IP6__MULTICAST_PREFIX

    @property
    def is_multicast__all_nodes(self) -> bool:
        """
        Check if address is IPv6 all nodes multicast address.
        """

        return self._address == IP6__MULTICAST_ALL_NODES

    @property
    def is_multicast__all_routers(self) -> bool:
        """
        Check if address is IPv6 all routers multicast address.
        """

        return self._address == IP6__MULTICAST_ALL_ROUTERS

    @property
    def is_multicast__solicited_node(self) -> bool:
        """
        Check if address is IPv6 solicited node multicast address.
        """

        return self._address & IP6__SOLICITED_NODE_PREFIX_MASK == IP6__SOLICITED_NODE_PREFIX

    @property
    @override
    def is_private(self) -> bool:
        """
        Check if IPv6 address is private.
        """

        return self._address & IP6__PRIVATE_PREFIX_MASK == IP6__PRIVATE_PREFIX

    @property
    def is_documentation(self) -> bool:
        """
        Check if IPv6 address is in the 2001:db8::/32
        documentation prefix (RFC 3849).
        """

        return self._address & IP6__DOCUMENTATION_PREFIX_MASK == IP6__DOCUMENTATION_PREFIX

    @property
    def is_reserved(self) -> bool:
        """
        Check if IPv6 address belongs to a special-purpose
        prefix from the IANA IPv6 Special-Purpose Address
        Registry (RFC 6890 / RFC 8190) that is NOT already
        covered by another predicate (is_loopback,
        is_link_local, is_multicast, is_private,
        is_unspecified). Currently recognises:

        - 100::/64       (RFC 6666 Discard-Only)
        - ::ffff:0:0/96  (RFC 4291 §2.5.5.2 IPv4-mapped)
        - 2001:2::/48    (RFC 5180 Benchmarking)
        - 2001:db8::/32  (RFC 3849 Documentation)

        Additional prefixes (TEREDO, 6to4, ORCHIDv2, etc.)
        will be folded in as PyTCP gains consumers that
        need to distinguish them. See
        `docs/rfc/ip6/rfc8190__ipv6_special_purpose/adherence.md`
        for the per-prefix walk-through.
        """

        return (
            self._address & IP6__DISCARD_PREFIX_MASK == IP6__DISCARD_PREFIX
            or self._address & IP6__IPV4_MAPPED_PREFIX_MASK == IP6__IPV4_MAPPED_PREFIX
            or self._address & IP6__BENCHMARK_PREFIX_MASK == IP6__BENCHMARK_PREFIX
            or self._address & IP6__DOCUMENTATION_PREFIX_MASK == IP6__DOCUMENTATION_PREFIX
        )
