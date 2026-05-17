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
This module contains error classes for the NetAddr library.

net_addr/errors.py

ver 3.0.5
"""


class NetAddrError(Exception):
    """
    Base class for all NetAddr exceptions.
    """


class IpAddressFormatError(NetAddrError):
    """
    Base class for all IP address format exceptions.
    """


class IpMaskFormatError(NetAddrError):
    """
    Base class for all IP mask format exceptions.
    """


class IpNetworkFormatError(NetAddrError):
    """
    Base class for all IP network format exceptions.
    """


class IfAddrFormatError(NetAddrError):
    """
    Base class for all IP interface address format exceptions.
    """


class IfAddrGatewayError(NetAddrError):
    """
    Base class for all IP interface address gateway exceptions.
    """


class IfAddrSanityError(NetAddrError):
    """
    Base class for all IP interface address sanity exceptions.
    """


class Ip4AddressFormatError(IpAddressFormatError):
    """
    Exception raised when IPv4 address format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv4 address format is invalid: {value!r}")


class Ip4MaskFormatError(IpMaskFormatError):
    """
    Exception raised when IPv4 mask format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv4 mask format is invalid: {value!r}")


class Ip4NetworkFormatError(IpNetworkFormatError):
    """
    Exception raised when IPv4 network format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv4 network format is invalid: {value!r}")


class Ip4IfAddrFormatError(IfAddrFormatError):
    """
    Exception raised when IPv4 interface address format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv4 interface address format is invalid: {value!r}")


class Ip4IfAddrSanityError(IfAddrSanityError):
    """
    Exception raised when IPv4 interface address doesn't belong to provided network.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv4 address doesn't belong to the provided network: {value!r}")


class Ip4IfAddrGatewayError(IfAddrGatewayError):
    """
    Exception raised when IPv4 interface address gateway is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv4 interface address gateway is invalid: {value!r}")


class Ip6AddressFormatError(IpAddressFormatError):
    """
    Exception raised when IPv6 address format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv6 address format is invalid: {value!r}")


class Ip6MaskFormatError(IpMaskFormatError):
    """
    Exception raised when IPv6 mask format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv6 mask format is invalid: {value!r}")


class Ip6NetworkFormatError(IpNetworkFormatError):
    """
    Exception raised when IPv6 network format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv6 network format is invalid: {value!r}")


class Ip6IfAddrFormatError(IfAddrFormatError):
    """
    Exception raised when IPv6 interface address format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv6 interface address format is invalid: {value!r}")


class Ip6IfAddrSanityError(IfAddrSanityError):
    """
    Exception raised when IPv6 interface address doesn't belong to provided network.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv6 address doesn't belong to the provided network: {value!r}")


class Ip6IfAddrGatewayError(IfAddrGatewayError):
    """
    Exception raised when IPv6 interface address gateway is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The IPv6 interface address gateway is invalid: {value!r}")


class MacAddressFormatError(NetAddrError):
    """
    Exception raised when MAC address format is invalid.
    """

    def __init__(self, value: object, /) -> None:
        super().__init__(f"The MAC address format is invalid: {value!r}")
