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
This module contains tests for the NetAddr package IPv4 address support class.

net_addr/tests/unit/test__ip4_address.py

ver 3.0.4
"""


from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore

from net_addr import Ip4Address, Ip4AddressFormatError, Ip4Mask, Ip6Address, IpVersion, MacAddress


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 address: 0.0.0.0 (str)",
            "_args": [
                "0.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.0",
                "__repr__": "Ip4Address('0.0.0.0')",
                "__bytes__": b"\x00\x00\x00\x00",
                "__int__": 0,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": True,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": True,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 0.0.0.0 (None)",
            "_args": [
                None,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.0",
                "__repr__": "Ip4Address('0.0.0.0')",
                "__bytes__": b"\x00\x00\x00\x00",
                "__int__": 0,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": True,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": True,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 0.0.0.1 (str)",
            "_args": [
                "0.0.0.1",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.1",
                "__repr__": "Ip4Address('0.0.0.1')",
                "__bytes__": b"\x00\x00\x00\x01",
                "__int__": 1,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": True,
                "is_limited_broadcast": False,
                "is_class_a": True,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 0.255.255.255 (str)",
            "_args": [
                "0.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "0.255.255.255",
                "__repr__": "Ip4Address('0.255.255.255')",
                "__bytes__": b"\x00\xff\xff\xff",
                "__int__": 16777215,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": True,
                "is_limited_broadcast": False,
                "is_class_a": True,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 1.0.0.0 (str)",
            "_args": [
                "1.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "1.0.0.0",
                "__repr__": "Ip4Address('1.0.0.0')",
                "__bytes__": b"\x01\x00\x00\x00",
                "__int__": 16777216,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": True,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 9.255.255.255 (str)",
            "_args": [
                "9.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "9.255.255.255",
                "__repr__": "Ip4Address('9.255.255.255')",
                "__bytes__": b"\x09\xff\xff\xff",
                "__int__": 167772159,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": True,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 10.0.0.0 (str)",
            "_args": [
                "10.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "10.0.0.0",
                "__repr__": "Ip4Address('10.0.0.0')",
                "__bytes__": b"\x0a\x00\x00\x00",
                "__int__": 167772160,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": True,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 10.255.255.255 (str)",
            "_args": [
                "10.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "10.255.255.255",
                "__repr__": "Ip4Address('10.255.255.255')",
                "__bytes__": b"\x0a\xff\xff\xff",
                "__int__": 184549375,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": True,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 11.0.0.0 (str)",
            "_args": [
                "11.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "11.0.0.0",
                "__repr__": "Ip4Address('11.0.0.0')",
                "__bytes__": b"\x0b\x00\x00\x00",
                "__int__": 184549376,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": True,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 126.255.255.255 (str)",
            "_args": [
                "126.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "126.255.255.255",
                "__repr__": "Ip4Address('126.255.255.255')",
                "__bytes__": b"\x7e\xff\xff\xff",
                "__int__": 2130706431,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": True,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 127.0.0.0 (str)",
            "_args": [
                "127.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "127.0.0.0",
                "__repr__": "Ip4Address('127.0.0.0')",
                "__bytes__": b"\x7f\x00\x00\x00",
                "__int__": 2130706432,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": True,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": True,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 127.255.255.255 (str)",
            "_args": [
                "127.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "127.255.255.255",
                "__repr__": "Ip4Address('127.255.255.255')",
                "__bytes__": b"\x7f\xff\xff\xff",
                "__int__": 2147483647,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": True,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": True,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 128.0.0.0 (str)",
            "_args": [
                "128.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "128.0.0.0",
                "__repr__": "Ip4Address('128.0.0.0')",
                "__bytes__": b"\x80\x00\x00\x00",
                "__int__": 2147483648,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": True,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 169.253.255.255 (str)",
            "_args": [
                "169.253.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "169.253.255.255",
                "__repr__": "Ip4Address('169.253.255.255')",
                "__bytes__": b"\xa9\xfd\xff\xff",
                "__int__": 2851995647,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": True,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 169.254.0.0 (str)",
            "_args": [
                "169.254.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "169.254.0.0",
                "__repr__": "Ip4Address('169.254.0.0')",
                "__bytes__": b"\xa9\xfe\x00\x00",
                "__int__": 2851995648,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": True,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": True,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 169.254.255.255 (str)",
            "_args": [
                "169.254.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "169.254.255.255",
                "__repr__": "Ip4Address('169.254.255.255')",
                "__bytes__": b"\xa9\xfe\xff\xff",
                "__int__": 2852061183,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": True,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": True,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 169.255.0.0 (str)",
            "_args": [
                "169.255.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "169.255.0.0",
                "__repr__": "Ip4Address('169.255.0.0')",
                "__bytes__": b"\xa9\xff\x00\x00",
                "__int__": 2852061184,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": True,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 170.0.0.0 (str)",
            "_args": [
                "170.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "170.0.0.0",
                "__repr__": "Ip4Address('170.0.0.0')",
                "__bytes__": b"\xaa\x00\x00\x00",
                "__int__": 2852126720,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": True,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 172.15.255.255 (str)",
            "_args": [
                "172.15.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "172.15.255.255",
                "__repr__": "Ip4Address('172.15.255.255')",
                "__bytes__": b"\xac\x0f\xff\xff",
                "__int__": 2886729727,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": True,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 172.16.0.0 (str)",
            "_args": [
                "172.16.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "172.16.0.0",
                "__repr__": "Ip4Address('172.16.0.0')",
                "__bytes__": b"\xac\x10\x00\x00",
                "__int__": 2886729728,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": True,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 172.31.255.255 (str)",
            "_args": [
                "172.31.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "172.31.255.255",
                "__repr__": "Ip4Address('172.31.255.255')",
                "__bytes__": b"\xac\x1f\xff\xff",
                "__int__": 2887778303,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": True,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 172.32.0.0 (str)",
            "_args": [
                "172.32.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "172.32.0.0",
                "__repr__": "Ip4Address('172.32.0.0')",
                "__bytes__": b"\xac\x20\x00\x00",
                "__int__": 2887778304,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": True,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 191.255.255.255 (str)",
            "_args": [
                "191.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "191.255.255.255",
                "__repr__": "Ip4Address('191.255.255.255')",
                "__bytes__": b"\xbf\xff\xff\xff",
                "__int__": 3221225471,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": True,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.0.0.0 (str)",
            "_args": [
                "192.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.0.0.0",
                "__repr__": "Ip4Address('192.0.0.0')",
                "__bytes__": b"\xc0\x00\x00\x00",
                "__int__": 3221225472,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": True,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 0 (int, unspecified boundary)",
            "_args": [
                0,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "0.0.0.0",
                "__repr__": "Ip4Address('0.0.0.0')",
                "__bytes__": b"\x00\x00\x00\x00",
                "__int__": 0,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": True,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": True,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 4294967295 (int, limited broadcast boundary)",
            "_args": [
                4294967295,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "255.255.255.255",
                "__repr__": "Ip4Address('255.255.255.255')",
                "__bytes__": b"\xff\xff\xff\xff",
                "__int__": 4294967295,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": True,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": True,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.167.255.255 (str)",
            "_args": [
                "192.167.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.167.255.255",
                "__repr__": "Ip4Address('192.167.255.255')",
                "__bytes__": b"\xc0\xa7\xff\xff",
                "__int__": 3232235519,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": True,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.168.0.0 (str)",
            "_args": [
                "192.168.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.0.0",
                "__repr__": "Ip4Address('192.168.0.0')",
                "__bytes__": b"\xc0\xa8\x00\x00",
                "__int__": 3232235520,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": True,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.168.255.255 (str)",
            "_args": [
                "192.168.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": True,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.168.255.255 (Ip4Address)",
            "_args": [
                Ip4Address("192.168.255.255"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": True,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.168.255.255 (int)",
            "_args": [
                3232301055,
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": True,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.168.255.255 (bytes)",
            "_args": [
                b"\xc0\xa8\xff\xff",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": True,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.168.255.255 (bytearray)",
            "_args": [
                bytearray(b"\xc0\xa8\xff\xff"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": True,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.168.255.255 (memoryview)",
            "_args": [
                memoryview(b"\xc0\xa8\xff\xff"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.168.255.255",
                "__repr__": "Ip4Address('192.168.255.255')",
                "__bytes__": b"\xc0\xa8\xff\xff",
                "__int__": 3232301055,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": True,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": True,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 192.169.0.0 (str)",
            "_args": [
                "192.169.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "192.169.0.0",
                "__repr__": "Ip4Address('192.169.0.0')",
                "__bytes__": b"\xc0\xa9\x00\x00",
                "__int__": 3232301056,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": True,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 223.255.255.255 (str)",
            "_args": [
                "223.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "223.255.255.255",
                "__repr__": "Ip4Address('223.255.255.255')",
                "__bytes__": b"\xdf\xff\xff\xff",
                "__int__": 3758096383,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": True,
                "is_global": True,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": True,
                "is_class_d": False,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 224.0.0.0 (str)",
            "_args": [
                "224.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "224.0.0.0",
                "__repr__": "Ip4Address('224.0.0.0')",
                "__bytes__": b"\xe0\x00\x00\x00",
                "__int__": 3758096384,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": True,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 239.255.255.255 (str)",
            "_args": ["239.255.255.255"],
            "_kwargs": {},
            "_results": {
                "__str__": "239.255.255.255",
                "__repr__": "Ip4Address('239.255.255.255')",
                "__bytes__": b"\xef\xff\xff\xff",
                "__int__": 4026531839,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": True,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": True,
                "is_class_e": False,
            },
        },
        {
            "_description": "Test the IPv4 address: 240.0.0.0 (str)",
            "_args": [
                "240.0.0.0",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "240.0.0.0",
                "__repr__": "Ip4Address('240.0.0.0')",
                "__bytes__": b"\xf0\x00\x00\x00",
                "__int__": 4026531840,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": True,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": True,
            },
        },
        {
            "_description": "Test the IPv4 address: 255.255.255.254 (str)",
            "_args": [
                "255.255.255.254",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "255.255.255.254",
                "__repr__": "Ip4Address('255.255.255.254')",
                "__bytes__": b"\xff\xff\xff\xfe",
                "__int__": 4294967294,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": True,
                "is_invalid": False,
                "is_limited_broadcast": False,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": True,
            },
        },
        {
            "_description": "Test the IPv4 address: 255.255.255.255 (str)",
            "_args": [
                "255.255.255.255",
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "255.255.255.255",
                "__repr__": "Ip4Address('255.255.255.255')",
                "__bytes__": b"\xff\xff\xff\xff",
                "__int__": 4294967295,
                "version": IpVersion.IP4,
                "unspecified": Ip4Address(),
                "is_ip6": False,
                "is_ip4": True,
                "is_unspecified": False,
                "is_unicast": False,
                "is_global": False,
                "is_link_local": False,
                "is_loopback": False,
                "is_multicast": False,
                "is_private": False,
                "is_reserved": False,
                "is_invalid": False,
                "is_limited_broadcast": True,
                "is_class_a": False,
                "is_class_b": False,
                "is_class_c": False,
                "is_class_d": False,
                "is_class_e": True,
            },
        },
    ]
)
class TestNetAddrIp4Address(TestCase):
    """
    The NetAddr IPv4 address tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv4 address object with testcase arguments.
        """

        self._ip4_address = Ip4Address(*self._args, **self._kwargs)

    def test__net_addr__ip4_address__str(self) -> None:
        """
        Ensure the IPv4 address '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._ip4_address),
            self._results["__str__"],
        )

    def test__net_addr__ip4_address__repr(self) -> None:
        """
        Ensure the IPv4 address '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._ip4_address),
            self._results["__repr__"],
        )

    def test__net_addr__ip4_address__bytes(self) -> None:
        """
        Ensure the IPv4 address '__bytes__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(self._ip4_address),
            self._results["__bytes__"],
        )

    def test__net_addr__ip4_address__buffer(self) -> None:
        """
        Ensure the IPv4 address '__buffer__()' method returns a correct value.
        """

        self.assertEqual(
            bytes(memoryview(self._ip4_address)),
            self._results["__bytes__"],
        )

    def test__net_addr__ip4_address__int(self) -> None:
        """
        Ensure the IPv4 address '__int__()' method returns a correct value.
        """

        self.assertEqual(
            int(self._ip4_address),
            self._results["__int__"],
        )

    def test__net_addr__ip4_address__version(self) -> None:
        """
        Ensure the IPv4 address 'version' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_address.version,
            self._results["version"],
        )

    def test__net_addr__ip4_address__unspecified(self) -> None:
        """
        Ensure the IPv4 address 'unspecified' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_address.unspecified,
            self._results["unspecified"],
        )

    def test__net_addr__ip4_address__is_ip4(self) -> None:
        """
        Ensure the IPv4 address 'is_ip4' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip4_address__is_ip6(self) -> None:
        """
        Ensure the IPv4 address 'is_ip6' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip4_address__is_unspecified(self) -> None:
        """
        Ensure the IPv4 address 'is_unspecified' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_unspecified,
            self._results["is_unspecified"],
        )

    def test__net_addr__ip4_address__is_unicast(self) -> None:
        """
        Ensure the IPv4 address 'is_unicast' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_unicast,
            self._results["is_unicast"],
        )

    def test__net_addr__ip4_address__is_global(self) -> None:
        """
        Ensure the IPv4 address 'is_global' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_global,
            self._results["is_global"],
        )

    def test__net_addr__ip4_address__is_link_local(self) -> None:
        """
        Ensure the IPv4 address 'is_link_local' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_link_local,
            self._results["is_link_local"],
        )

    def test__net_addr__ip4_address__is_loopback(self) -> None:
        """
        Ensure the IPv4 address 'is_loopback' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_loopback,
            self._results["is_loopback"],
        )

    def test__net_addr__ip4_address__is_multicast(self) -> None:
        """
        Ensure the IPv4 address 'is_multicast' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_multicast,
            self._results["is_multicast"],
        )

    def test__net_addr__ip4_address__is_private(self) -> None:
        """
        Ensure the IPv4 address 'is_private' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_private,
            self._results["is_private"],
        )

    def test__net_addr__ip4_address__is_reserved(self) -> None:
        """
        Ensure the IPv4 address 'is_reserved' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_reserved,
            self._results["is_reserved"],
        )

    def test__net_addr__ip4_address__is_invalid(self) -> None:
        """
        Ensure the IPv4 address 'is_invalid' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip4_address.is_invalid,
            self._results["is_invalid"],
        )

    def test__net_addr__ip4_address__is_limited_broadcast(self) -> None:
        """
        Ensure the IPv4 address 'is_limited_broadcast' property returns
        a correct value.
        """

        self.assertEqual(
            self._ip4_address.is_limited_broadcast,
            self._results["is_limited_broadcast"],
        )

    def test__net_addr__ip4_address__is_class_a(self) -> None:
        """
        Ensure the IPv4 address 'is_class_a' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_address.is_class_a,
            self._results["is_class_a"],
        )

    def test__net_addr__ip4_address__is_class_b(self) -> None:
        """
        Ensure the IPv4 address 'is_class_b' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_address.is_class_b,
            self._results["is_class_b"],
        )

    def test__net_addr__ip4_address__is_class_c(self) -> None:
        """
        Ensure the IPv4 address 'is_class_c' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_address.is_class_c,
            self._results["is_class_c"],
        )

    def test__net_addr__ip4_address__is_class_d(self) -> None:
        """
        Ensure the IPv4 address 'is_class_d' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_address.is_class_d,
            self._results["is_class_d"],
        )

    def test__net_addr__ip4_address__is_class_e(self) -> None:
        """
        Ensure the IPv4 address 'is_class_e' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_address.is_class_e,
            self._results["is_class_e"],
        )

    def test__net_addr__ip4_address__class__mutually_exclusive(self) -> None:
        """
        Ensure every IPv4 address belongs to exactly one of the five
        address classes (A, B, C, D, E).
        """

        flags = [
            self._ip4_address.is_class_a,
            self._ip4_address.is_class_b,
            self._ip4_address.is_class_c,
            self._ip4_address.is_class_d,
            self._ip4_address.is_class_e,
        ]

        self.assertEqual(
            sum(flags),
            1,
            msg=f"Address {self._ip4_address} must belong to exactly one class; got flags {flags}.",
        )


@parameterized_class(
    [
        {
            "_description": "Test the IPv4 address format: '10.10.10.256'",
            "_args": [
                "10.10.10.256",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": ("The IPv4 address format is invalid: '10.10.10.256'"),
            },
        },
        {
            "_description": "Test the IPv4 address format: '1.2.3' (too few octets)",
            "_args": [
                "1.2.3",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: '1.2.3'",
            },
        },
        {
            "_description": "Test the IPv4 address format: '1.2.3.4.5' (too many octets)",
            "_args": [
                "1.2.3.4.5",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: '1.2.3.4.5'",
            },
        },
        {
            "_description": "Test the IPv4 address format: '300.300.300.300'",
            "_args": [
                "300.300.300.300",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: '300.300.300.300'",
            },
        },
        {
            "_description": "Test the IPv4 address format: '10.10..10'",
            "_args": [
                "10.10..10",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": ("The IPv4 address format is invalid: '10.10..10'"),
            },
        },
        {
            "_description": "Test the IPv4 address format: '10.10.10,10'",
            "_args": [
                "10.10.10,10",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": ("The IPv4 address format is invalid: '10.10.10,10'"),
            },
        },
        {
            "_description": "Test the IPv4 address format: ''",
            "_args": [
                "",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: ''",
            },
        },
        {
            "_description": "Test the IPv4 address format: ' 1.2.3.4'",
            "_args": [
                " 1.2.3.4",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: ' 1.2.3.4'",
            },
        },
        {
            "_description": "Test the IPv4 address format: b'\\xff\\xff\\xff'",
            "_args": [
                b"\xff\xff\xff",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": (r"The IPv4 address format is invalid: b'\xff\xff\xff'"),
            },
        },
        {
            "_description": "Test the IPv4 address format: b'\\xff\\xff\\xff\\xff\\xff'",
            "_args": [
                b"\xff\xff\xff\xff\xff",
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": (r"The IPv4 address format is invalid: b'\xff\xff\xff\xff\xff'"),
            },
        },
        {
            "_description": "Test the IPv4 address format: bytearray(b'\\xff\\xff\\xff')",
            "_args": [
                bytearray(b"\xff\xff\xff"),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: bytearray(b'\\xff\\xff\\xff')",
            },
        },
        {
            "_description": "Test the IPv4 address format: bytearray(b'\\xff\\xff\\xff\\xff\\xff')",
            "_args": [
                bytearray(b"\xff\xff\xff\xff\xff"),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: bytearray(b'\\xff\\xff\\xff\\xff\\xff')",
            },
        },
        {
            "_description": "Test the IPv4 address format: memoryview(b'\\xff\\xff\\xff')",
            "_args": [
                memoryview(b"\xff\xff\xff"),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: <memory at 0x",
            },
        },
        {
            "_description": "Test the IPv4 address format: -1",
            "_args": [
                -1,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": ("The IPv4 address format is invalid: -1"),
            },
        },
        {
            "_description": "Test the IPv4 address format: 4294967296",
            "_args": [
                4294967296,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": ("The IPv4 address format is invalid: 4294967296"),
            },
        },
        {
            "_description": "Test the IPv4 address format: Ip6Address()",
            "_args": [
                Ip6Address(),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: Ip6Address('::')",
            },
        },
        {
            "_description": "Test the IPv4 address format: {}",
            "_args": [
                {},
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: {}",
            },
        },
        {
            "_description": "Test the IPv4 address format: 1.1",
            "_args": [
                1.1,
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip4AddressFormatError,
                "error_message": "The IPv4 address format is invalid: 1.1",
            },
        },
    ]
)
class TestNetAddrIp4AddressErrors(TestCase):
    """
    The NetAddr IPv4 address error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip4_address__errors(self) -> None:
        """
        Ensure the IPv4 address raises an error on invalid input.
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip4Address(*self._args, **self._kwargs)

        self.assertTrue(
            str(error.exception).startswith(self._results["error_message"]),
            msg=(
                f"Expected exception message to start with "
                f"{self._results['error_message']!r}, got {str(error.exception)!r}."
            ),
        )


@parameterized_class(
    [
        {
            "_description": "Test classful_mask for Class A boundary: 0.0.0.0",
            "_args": ["0.0.0.0"],
            "_kwargs": {},
            "_results": {
                "classful_mask": Ip4Mask("255.0.0.0"),
            },
        },
        {
            "_description": "Test classful_mask for Class A address: 1.0.0.0",
            "_args": ["1.0.0.0"],
            "_kwargs": {},
            "_results": {
                "classful_mask": Ip4Mask("255.0.0.0"),
            },
        },
        {
            "_description": "Test classful_mask for Class A address: 10.0.0.0",
            "_args": ["10.0.0.0"],
            "_kwargs": {},
            "_results": {
                "classful_mask": Ip4Mask("255.0.0.0"),
            },
        },
        {
            "_description": "Test classful_mask for Class A boundary: 127.255.255.255",
            "_args": ["127.255.255.255"],
            "_kwargs": {},
            "_results": {
                "classful_mask": Ip4Mask("255.0.0.0"),
            },
        },
        {
            "_description": "Test classful_mask for Class B boundary: 128.0.0.0",
            "_args": ["128.0.0.0"],
            "_kwargs": {},
            "_results": {
                "classful_mask": Ip4Mask("255.255.0.0"),
            },
        },
        {
            "_description": "Test classful_mask for Class B address: 169.254.0.0",
            "_args": ["169.254.0.0"],
            "_kwargs": {},
            "_results": {
                "classful_mask": Ip4Mask("255.255.0.0"),
            },
        },
        {
            "_description": "Test classful_mask for Class B address: 172.16.0.0",
            "_args": ["172.16.0.0"],
            "_kwargs": {},
            "_results": {
                "classful_mask": Ip4Mask("255.255.0.0"),
            },
        },
        {
            "_description": "Test classful_mask for Class B boundary: 191.255.255.255",
            "_args": ["191.255.255.255"],
            "_kwargs": {},
            "_results": {
                "classful_mask": Ip4Mask("255.255.0.0"),
            },
        },
        {
            "_description": "Test classful_mask for Class C boundary: 192.0.0.0",
            "_args": ["192.0.0.0"],
            "_kwargs": {},
            "_results": {
                "classful_mask": Ip4Mask("255.255.255.0"),
            },
        },
        {
            "_description": "Test classful_mask for Class C address: 192.168.1.0",
            "_args": ["192.168.1.0"],
            "_kwargs": {},
            "_results": {
                "classful_mask": Ip4Mask("255.255.255.0"),
            },
        },
        {
            "_description": "Test classful_mask for Class C address: 223.255.255.0",
            "_args": ["223.255.255.0"],
            "_kwargs": {},
            "_results": {
                "classful_mask": Ip4Mask("255.255.255.0"),
            },
        },
        {
            "_description": "Test classful_mask for Class C boundary: 223.255.255.255",
            "_args": ["223.255.255.255"],
            "_kwargs": {},
            "_results": {
                "classful_mask": Ip4Mask("255.255.255.0"),
            },
        },
    ]
)
class TestNetAddrIp4AddressClassfulMask(TestCase):
    """
    The NetAddr IPv4 address classful mask tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv4 address object with testcase arguments.
        """

        self._ip4_address = Ip4Address(*self._args, **self._kwargs)

    def test__net_addr__ip4_address__classful_mask(self) -> None:
        """
        Ensure the IPv4 address 'classful_mask' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_address.classful_mask,
            self._results["classful_mask"],
        )


@parameterized_class(
    [
        {
            "_description": "Test classful_mask raises ValueError for Class D address: 224.0.0.0",
            "_args": ["224.0.0.0"],
            "_kwargs": {},
        },
        {
            "_description": "Test classful_mask raises ValueError for Class D address: 239.255.255.255",
            "_args": ["239.255.255.255"],
            "_kwargs": {},
        },
        {
            "_description": "Test classful_mask raises ValueError for Class E address: 240.0.0.0",
            "_args": ["240.0.0.0"],
            "_kwargs": {},
        },
        {
            "_description": "Test classful_mask raises ValueError for Class E address: 255.255.255.255",
            "_args": ["255.255.255.255"],
            "_kwargs": {},
        },
    ]
)
class TestNetAddrIp4AddressClassfulMaskErrors(TestCase):
    """
    The NetAddr IPv4 address classful mask error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv4 address object with testcase arguments.
        """

        self._ip4_address = Ip4Address(*self._args, **self._kwargs)

    def test__net_addr__ip4_address__classful_mask__error(self) -> None:
        """
        Ensure 'classful_mask' raises ValueError for Class D and Class E addresses.
        """

        with self.assertRaises(ValueError) as error:
            _ = self._ip4_address.classful_mask

        self.assertEqual(
            str(error.exception),
            "Unable to assign classful mask to IPv4 address.",
        )


@parameterized_class(
    [
        {
            "_description": "Test multicast_mac for 224.0.0.0",
            "_args": ["224.0.0.0"],
            "_kwargs": {},
            "_results": {
                "multicast_mac": MacAddress("01:00:5e:00:00:00"),
            },
        },
        {
            "_description": "Test multicast_mac for 224.0.0.1",
            "_args": ["224.0.0.1"],
            "_kwargs": {},
            "_results": {
                "multicast_mac": MacAddress("01:00:5e:00:00:01"),
            },
        },
        {
            "_description": "Test multicast_mac for 239.255.255.255",
            "_args": ["239.255.255.255"],
            "_kwargs": {},
            "_results": {
                "multicast_mac": MacAddress("01:00:5e:7f:ff:ff"),
            },
        },
        {
            "_description": "Test multicast_mac masking collision: 224.128.0.1 shares MAC with 224.0.0.1",
            "_args": ["224.128.0.1"],
            "_kwargs": {},
            "_results": {
                "multicast_mac": MacAddress("01:00:5e:00:00:01"),
            },
        },
        {
            "_description": "Test multicast_mac masking collision: 239.128.0.1 shares MAC with 224.0.0.1",
            "_args": ["239.128.0.1"],
            "_kwargs": {},
            "_results": {
                "multicast_mac": MacAddress("01:00:5e:00:00:01"),
            },
        },
    ]
)
class TestNetAddrIp4AddressMulticastMac(TestCase):
    """
    The NetAddr IPv4 address multicast MAC tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv4 address object with testcase arguments.
        """

        self._ip4_address = Ip4Address(*self._args, **self._kwargs)

    def test__net_addr__ip4_address__multicast_mac(self) -> None:
        """
        Ensure the IPv4 address 'multicast_mac' property returns a correct value.
        """

        self.assertEqual(
            self._ip4_address.multicast_mac,
            self._results["multicast_mac"],
        )


class TestNetAddrIp4AddressMulticastMacError(TestCase):
    """
    The NetAddr IPv4 address multicast MAC assertion error test.
    """

    def test__net_addr__ip4_address__multicast_mac__error(self) -> None:
        """
        Ensure 'multicast_mac' raises AssertionError with the expected
        message when called on a non-multicast address.
        """

        with self.assertRaises(AssertionError) as error:
            _ = Ip4Address("192.168.1.1").multicast_mac

        self.assertEqual(
            str(error.exception),
            "The IPv4 address must be a multicast address to get a multicast " "MAC address. Got: 192.168.1.1",
        )


class TestNetAddrIp4AddressEquality(TestCase):
    """
    The NetAddr IPv4 address equality tests across value and type boundaries.
    """

    def test__net_addr__ip4_address__eq__identity(self) -> None:
        """
        Ensure the IPv4 address equals itself.
        """

        address = Ip4Address("192.168.1.1")
        self.assertTrue(
            address == address,
            msg="An Ip4Address instance must compare equal to itself.",
        )

    def test__net_addr__ip4_address__eq__same_value(self) -> None:
        """
        Ensure two IPv4 addresses with the same underlying value are equal
        regardless of which constructor form was used.
        """

        self.assertEqual(
            Ip4Address("192.168.1.1"),
            Ip4Address(b"\xc0\xa8\x01\x01"),
            msg="Ip4Address built from string and from bytes must compare equal.",
        )
        self.assertEqual(
            Ip4Address("192.168.1.1"),
            Ip4Address(3232235777),
            msg="Ip4Address built from string and from int must compare equal.",
        )

    def test__net_addr__ip4_address__eq__different_value(self) -> None:
        """
        Ensure two IPv4 addresses with different values are not equal.
        """

        self.assertNotEqual(
            Ip4Address("192.168.1.1"),
            Ip4Address("192.168.1.2"),
            msg="Ip4Address instances with different values must not compare equal.",
        )

    def test__net_addr__ip4_address__eq__foreign_types(self) -> None:
        """
        Ensure the IPv4 address is never equal to a value of a foreign type,
        even when the underlying integer/bytes would match.
        """

        address = Ip4Address("192.168.1.1")

        self.assertFalse(
            address == "192.168.1.1",
            msg="Ip4Address must not compare equal to its string representation.",
        )
        self.assertFalse(
            address == int(address),
            msg="Ip4Address must not compare equal to its integer representation.",
        )
        self.assertFalse(
            address == bytes(address),
            msg="Ip4Address must not compare equal to its bytes representation.",
        )
        self.assertFalse(
            address == None,  # noqa: E711
            msg="Ip4Address must not compare equal to None.",
        )
        self.assertFalse(
            address == Ip6Address(),
            msg="Ip4Address must not compare equal to an Ip6Address.",
        )
        self.assertFalse(
            address == MacAddress(),
            msg="Ip4Address must not compare equal to a MacAddress.",
        )

    def test__net_addr__ip4_address__ne(self) -> None:
        """
        Ensure the IPv4 address '__ne__()' method returns a correct value.
        """

        address = Ip4Address("192.168.1.1")
        self.assertTrue(
            address != Ip4Address("192.168.1.2"),
            msg="Ip4Address instances with different values must be unequal.",
        )
        self.assertFalse(
            address != Ip4Address("192.168.1.1"),
            msg="Ip4Address instances with the same value must not be unequal.",
        )
        self.assertTrue(
            address != "192.168.1.1",
            msg="Ip4Address must be unequal to its string representation.",
        )


class TestNetAddrIp4AddressHashConsistency(TestCase):
    """
    The NetAddr IPv4 address hash and container usability tests.
    """

    def test__net_addr__ip4_address__hash__equal_addresses_hash_equal(self) -> None:
        """
        Ensure equal IPv4 addresses built from different input forms produce
        identical hash values.
        """

        from_str = Ip4Address("192.168.1.1")
        from_bytes = Ip4Address(b"\xc0\xa8\x01\x01")
        from_int = Ip4Address(3232235777)
        from_bytearray = Ip4Address(bytearray(b"\xc0\xa8\x01\x01"))
        from_memoryview = Ip4Address(memoryview(b"\xc0\xa8\x01\x01"))
        from_copy = Ip4Address(from_str)

        self.assertEqual(
            hash(from_str),
            hash(from_bytes),
            msg="Equal Ip4Address values (str, bytes) must hash to the same value.",
        )
        self.assertEqual(
            hash(from_str),
            hash(from_int),
            msg="Equal Ip4Address values (str, int) must hash to the same value.",
        )
        self.assertEqual(
            hash(from_str),
            hash(from_bytearray),
            msg="Equal Ip4Address values (str, bytearray) must hash to the same value.",
        )
        self.assertEqual(
            hash(from_str),
            hash(from_memoryview),
            msg="Equal Ip4Address values (str, memoryview) must hash to the same value.",
        )
        self.assertEqual(
            hash(from_str),
            hash(from_copy),
            msg="Ip4Address copied from another Ip4Address must preserve its hash.",
        )

    def test__net_addr__ip4_address__usable_in_set(self) -> None:
        """
        Ensure equal IPv4 addresses collapse into a single element when used
        in a set.
        """

        a = Ip4Address("192.168.1.1")
        b = Ip4Address(b"\xc0\xa8\x01\x01")
        c = Ip4Address("192.168.1.2")

        self.assertEqual(
            len({a, b}),
            1,
            msg="Two equal Ip4Address values must collapse into one set element.",
        )
        self.assertEqual(
            len({a, b, c}),
            2,
            msg="Distinct Ip4Address values must occupy distinct set elements.",
        )
        self.assertIn(
            a,
            {b},
            msg="Set membership lookup must treat equal Ip4Address values as the same key.",
        )

    def test__net_addr__ip4_address__usable_in_dict(self) -> None:
        """
        Ensure equal IPv4 addresses refer to the same dict entry regardless
        of which constructor form was used to build the key.
        """

        a = Ip4Address("192.168.1.1")
        b = Ip4Address(b"\xc0\xa8\x01\x01")

        mapping = {a: "value"}

        self.assertEqual(
            mapping[b],
            "value",
            msg="Ip4Address must behave consistently as a dict key across input forms.",
        )


class TestNetAddrIp4AddressRoundtrip(TestCase):
    """
    The NetAddr IPv4 address serialization roundtrip tests.
    """

    def test__net_addr__ip4_address__roundtrip__str(self) -> None:
        """
        Ensure 'Ip4Address(str(x))' yields an address equal to 'x'.
        """

        for value in ("0.0.0.0", "127.0.0.1", "192.168.1.1", "255.255.255.255"):
            with self.subTest(value=value):
                address = Ip4Address(value)
                self.assertEqual(
                    Ip4Address(str(address)),
                    address,
                    msg=f"Roundtrip through str() must preserve address {value!r}.",
                )

    def test__net_addr__ip4_address__roundtrip__int(self) -> None:
        """
        Ensure 'Ip4Address(int(x))' yields an address equal to 'x'.
        """

        for value in (0, 1, 2130706433, 3232235777, 4294967295):
            with self.subTest(value=value):
                address = Ip4Address(value)
                self.assertEqual(
                    Ip4Address(int(address)),
                    address,
                    msg=f"Roundtrip through int() must preserve address {value}.",
                )

    def test__net_addr__ip4_address__roundtrip__bytes(self) -> None:
        """
        Ensure 'Ip4Address(bytes(x))' yields an address equal to 'x'.
        """

        for value in (
            b"\x00\x00\x00\x00",
            b"\x7f\x00\x00\x01",
            b"\xc0\xa8\x01\x01",
            b"\xff\xff\xff\xff",
        ):
            with self.subTest(value=value):
                address = Ip4Address(value)
                self.assertEqual(
                    Ip4Address(bytes(address)),
                    address,
                    msg=f"Roundtrip through bytes() must preserve address {value!r}.",
                )

    def test__net_addr__ip4_address__roundtrip__copy(self) -> None:
        """
        Ensure 'Ip4Address(x)' where 'x' is an Ip4Address yields an address
        equal to the source.
        """

        source = Ip4Address("192.168.1.1")
        clone = Ip4Address(source)

        self.assertEqual(
            clone,
            source,
            msg="Ip4Address copied from another Ip4Address must compare equal to the source.",
        )
        self.assertEqual(
            int(clone),
            int(source),
            msg="Ip4Address copied from another Ip4Address must preserve the integer value.",
        )
