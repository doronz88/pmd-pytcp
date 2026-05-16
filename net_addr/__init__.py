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
This package contains classes used to represent network addresses.

net_addr/__init__.py

ver 3.0.5
"""

from net_addr.click_types import (
    ClickTypeIfAddr,
    ClickTypeIp4Address,
    ClickTypeIp4IfAddr,
    ClickTypeIp4Network,
    ClickTypeIp6Address,
    ClickTypeIp6IfAddr,
    ClickTypeIp6Network,
    ClickTypeIpAddress,
    ClickTypeIpNetwork,
    ClickTypeMacAddress,
)
from net_addr.errors import (
    IfAddrFormatError,
    IfAddrGatewayError,
    IfAddrSanityError,
    Ip4AddressFormatError,
    Ip4IfAddrFormatError,
    Ip4IfAddrGatewayError,
    Ip4IfAddrSanityError,
    Ip4MaskFormatError,
    Ip4NetworkFormatError,
    Ip6AddressFormatError,
    Ip6IfAddrFormatError,
    Ip6IfAddrGatewayError,
    Ip6IfAddrSanityError,
    Ip6MaskFormatError,
    Ip6NetworkFormatError,
    IpAddressFormatError,
    IpMaskFormatError,
    IpNetworkFormatError,
    MacAddressFormatError,
    NetAddrError,
)
from net_addr.ip4_address import IP4__ADDRESS_LEN, Ip4Address
from net_addr.ip4_ifaddr import Ip4IfAddr
from net_addr.ip4_ifaddr_source import Ip4IfAddrSource
from net_addr.ip4_mask import Ip4Mask
from net_addr.ip4_network import Ip4Network
from net_addr.ip6_address import IP6__ADDRESS_LEN, Ip6Address
from net_addr.ip6_ifaddr import Ip6IfAddr
from net_addr.ip6_ifaddr_source import Ip6IfAddrSource
from net_addr.ip6_mask import Ip6Mask
from net_addr.ip6_network import Ip6Network
from net_addr.ip_address import IpAddress
from net_addr.ip_ifaddr import IfAddr
from net_addr.ip_ifaddr_source import IfAddrSource
from net_addr.ip_mask import IpMask
from net_addr.ip_network import IpNetwork
from net_addr.ip_version import IpVersion
from net_addr.mac_address import MAC__ADDRESS_LEN, MacAddress

__all__ = [
    "ClickTypeIfAddr",
    "ClickTypeIp4Address",
    "ClickTypeIp4IfAddr",
    "ClickTypeIp4Network",
    "ClickTypeIp6Address",
    "ClickTypeIp6IfAddr",
    "ClickTypeIp6Network",
    "ClickTypeIpAddress",
    "ClickTypeIpNetwork",
    "ClickTypeMacAddress",
    "IP4__ADDRESS_LEN",
    "IP6__ADDRESS_LEN",
    "IfAddr",
    "IfAddrFormatError",
    "IfAddrGatewayError",
    "IfAddrSanityError",
    "IfAddrSource",
    "Ip4Address",
    "Ip4AddressFormatError",
    "Ip4IfAddr",
    "Ip4IfAddrFormatError",
    "Ip4IfAddrGatewayError",
    "Ip4IfAddrSanityError",
    "Ip4IfAddrSource",
    "Ip4Mask",
    "Ip4MaskFormatError",
    "Ip4Network",
    "Ip4NetworkFormatError",
    "Ip6Address",
    "Ip6AddressFormatError",
    "Ip6IfAddr",
    "Ip6IfAddrFormatError",
    "Ip6IfAddrGatewayError",
    "Ip6IfAddrSanityError",
    "Ip6IfAddrSource",
    "Ip6Mask",
    "Ip6MaskFormatError",
    "Ip6Network",
    "Ip6NetworkFormatError",
    "IpAddress",
    "IpAddressFormatError",
    "IpMask",
    "IpMaskFormatError",
    "IpNetwork",
    "IpNetworkFormatError",
    "IpVersion",
    "MAC__ADDRESS_LEN",
    "MacAddress",
    "MacAddressFormatError",
    "NetAddrError",
]
