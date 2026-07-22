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
This module contains IPv4 address support class.

pmd_net_addr/ip4_address.py

ver 3.0.7
"""

from __future__ import annotations

import re
import socket
from typing import ClassVar, Optional

from pmd_net_addr._compat import as_buffer
from pmd_net_addr.errors import Ip4AddressFormatError, Ip4AddressSanityError, NetAddrError
from pmd_net_addr.ip_address import IpAddress
from pmd_net_addr.ip_version import IpVersion
from pmd_net_addr.mac_address import MAC__IP4_MULTICAST_PREFIX, MacAddress
from typing_extensions import Self, final, override

IP4__ADDRESS_LEN = 4
IP4__MASK = 0xFF_FF_FF_FF

# Canonical dotted-decimal: exactly four decimal octets, each either '0' or
# starting with a nonzero digit (leading zeros rejected — an '010' octet is
# octal to 'inet_aton' and decimal to a human, and that ambiguity is a
# documented address-spoofing vector; Python's own 'ipaddress' module rejects
# leading zeros for the same reason since CVE-2021-29921).
_IP4_DOTTED_DECIMAL_RE = re.compile(
    r"^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$"
)


def parse_ip4_dotted_decimal(text: str, /) -> Optional[int]:
    """
    Parse a canonical four-octet dotted-decimal IPv4 string into its 32-bit
    integer value, or return None when the string is not canonical.

    This deliberately does NOT delegate to 'socket.inet_pton': POSIX requires
    it to be strict, and glibc's is, but Darwin's 'inet_pton(AF_INET)'
    accepts 'inet_aton' leniencies (leading-zero octets), so a libc-backed
    parse is platform-dependent exactly where strictness matters.
    """

    match = _IP4_DOTTED_DECIMAL_RE.match(text)
    if match is None:
        return None
    octets = [int(octet) for octet in match.groups()]
    if any(octet > 255 for octet in octets):
        return None
    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]


@final
class Ip4Address(IpAddress):
    """
    IPv4 address support class.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP4

    _address_len: ClassVar[int] = IP4__ADDRESS_LEN

    _sanity_error: ClassVar[type[NetAddrError]] = Ip4AddressSanityError

    def __init__(
        self,
        address: Self | str | bytes | bytearray | memoryview | int | None = None,
        /,
    ) -> None:
        """
        Initialize the IPv4 address object.
        """

        if address is None:
            self._address = 0
            return

        if isinstance(address, Ip4Address):
            self._address = int(address)
            return

        if isinstance(address, int):
            if 0 <= address <= IP4__MASK:
                self._address = address
                return

        if isinstance(address, (memoryview, bytes, bytearray)):
            if len(address) == 4:
                self._address = int.from_bytes(address, "big")
                return

        if isinstance(address, str):
            # Surrounding whitespace is stripped uniformly across
            # every pmd_net_addr string constructor. The canonical
            # dotted-decimal parse is done in-package
            # ('parse_ip4_dotted_decimal') rather than via
            # 'socket.inet_pton', whose strictness is platform-
            # dependent (Darwin accepts leading-zero octets).
            if (value := parse_ip4_dotted_decimal(address.strip())) is not None:
                self._address = value
                return

        raise Ip4AddressFormatError(address)

    @override
    def __str__(self) -> str:
        """
        Get the IPv4 address log string.
        """

        return socket.inet_ntoa(bytes(self))

    @override
    def __buffer__(self, _: int) -> memoryview:
        """
        Get the IPv4 address as a memoryview.
        """

        return memoryview(bytearray(as_buffer(self._address.to_bytes(IP4__ADDRESS_LEN, "big"))))

    @override
    def __bytes__(self) -> bytes:
        """
        Get the object as bytes (Python 3.9+ fallback for the
        PEP 688 '__buffer__' protocol, which is 3.12+).
        """

        return bytes(self.__buffer__(0))

    @property
    @override
    def multicast_mac(self) -> MacAddress:
        """
        Get the IPv4 multicast MAC address.
        """

        if not self.is_multicast:
            raise Ip4AddressSanityError(
                f"The IPv4 address must be a multicast address to get a multicast MAC address. Got: {self}"
            )

        return MacAddress(MAC__IP4_MULTICAST_PREFIX | self._address & 0x7F_FFFF)

    @property
    @override
    def reverse_pointer(self) -> str:
        """
        Get the IPv4 reverse-DNS PTR name (reversed octets in
        the in-addr.arpa zone).
        """

        return ".".join(str(octet) for octet in reversed(bytes(self))) + ".in-addr.arpa"

    @override
    def _format_alt(self, format_spec: str, /) -> str | None:
        """
        Render the 'ex' (expanded) text code. IPv4 has no zero
        compression, so the expanded form is the dotted-decimal
        string. Any other code is not recognised.
        """

        if format_spec == "ex":
            return str(self)

        return None

    # Known deliberate divergence: this is "global unicast" in
    # the addressing-architecture sense, NOT RFC 6890 "Globally
    # Reachable". It does not exclude the IANA Special-Purpose
    # blocks 100.64.0.0/10 (RFC 6598), 192.0.0.0/24 (RFC 6890),
    # 192.0.2.0/24 / 198.51.100.0/24 / 203.0.113.0/24 (RFC 5737
    # TEST-NET) or 198.18.0.0/15 (RFC 2544), so it returns True
    # for them. Tightening to RFC-6890 reachability was verified
    # correct but is intentionally NOT applied: is_global has no
    # PyTCP consumer, so the strict form buys no functional
    # correctness while destabilising unrelated stack tests —
    # same disposition as is_site_local.
    @property
    @override
    def is_global(self) -> bool:
        """
        Check if the IPv4 address is a global address.
        """

        return not (
            self.is_unspecified
            or self.is_invalid
            or self.is_link_local
            or self.is_loopback
            or self.is_multicast
            or self.is_private
            or self.is_reserved
            or self.is_limited_broadcast
        )

    @property
    @override
    def is_link_local(self) -> bool:
        """
        Check if the IPv4 address is a link local address.
        """

        return self._address & 0xFF_FF_00_00 == 0xA9_FE_00_00  # 169.254.0.0 - 169.254.255.255

    @property
    @override
    def is_loopback(self) -> bool:
        """
        Check if the IPv4 address is a loopback address.
        """

        return self._address & 0xFF_00_00_00 == 0x7F_00_00_00  # 127.0.0.0 - 127.255.255.255

    @property
    @override
    def is_multicast(self) -> bool:
        """
        Check if the IPv4 address is a multicast address.
        """

        return self._address & 0xF0_00_00_00 == 0xE0_00_00_00  # 224.0.0.0 - 239.255.255.255

    @property
    @override
    def is_private(self) -> bool:
        """
        Check if the IPv4 address is a private address.
        """

        return (
            self._address & 0xFF_00_00_00 == 0x0A_00_00_00  # 10.0.0.0 - 10.255.255.255
            or self._address & 0xFF_F0_00_00 == 0xAC_10_00_00  # 172.16.0.0 - 172.31.255.255
            or self._address & 0xFF_FF_00_00 == 0xC0_A8_00_00  # 192.168.0.0 - 192.168.255.255
        )

    @property
    def is_reserved(self) -> bool:
        """
        Check if the IPv4 address is a reserved address.
        """

        return (
            self._address & 0xF0_00_00_00 == 0xF0_00_00_00 and self._address != 0xFF_FF_FF_FF
        )  # 240.0.0.0 - 255.255.255.254

    @property
    def is_limited_broadcast(self) -> bool:
        """
        Check if the IPv4 address is a limited broadcast address.
        """

        return self._address == 0xFF_FF_FF_FF  # 255.255.255.255

    @property
    def is_invalid(self) -> bool:
        """
        Check if the IPv4 address is an invalid address.
        """

        return (
            self._address & 0xFF_00_00_00 == 0x00_00_00_00
        ) and self._address != 0x00_00_00_00  # 0.0.0.1 - 0.255.255.255
