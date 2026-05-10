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
This module contains tests for the NetAddr package IPv6 host support class.

net_addr/tests/unit/test__ip6_host.py

ver 3.0.4
"""

import time
from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore

from net_addr import (
    Ip4Host,
    Ip6Address,
    Ip6Host,
    Ip6HostFormatError,
    Ip6HostGatewayError,
    Ip6HostOrigin,
    Ip6HostSanityError,
    Ip6Mask,
    Ip6Network,
    IpVersion,
    MacAddress,
)

IP6_ADDRESS_EXPIRATION_TIME = int(time.time() + 3600)


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 host: 2001:b:c:d:1:2:3:4/64 (str)",
            "_args": [
                "2001:b:c:d:1:2:3:4/64",
            ],
            "_kwargs": {
                "gateway": Ip6Address("2001:b:c:d::1"),
                "origin": Ip6HostOrigin.AUTOCONFIG,
                "expiration_time": IP6_ADDRESS_EXPIRATION_TIME,
            },
            "_results": {
                "__str__": "2001:b:c:d:1:2:3:4/64",
                "__repr__": "Ip6Host('2001:b:c:d:1:2:3:4/64')",
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("2001:b:c:d:1:2:3:4"),
                "network": Ip6Network("2001:b:c:d:1::/64"),
                "gateway": Ip6Address("2001:b:c:d::1"),
                "origin": Ip6HostOrigin.AUTOCONFIG,
                "expiration_time": IP6_ADDRESS_EXPIRATION_TIME,
            },
        },
        {
            "_description": "Test the IPv6 host: 2001:b:c:d:1:2:3:4/64 (Ip6Host)",
            "_args": [
                Ip6Host("2001:b:c:d:1:2:3:4/64"),
            ],
            "_kwargs": {},
            "_results": {
                "__str__": "2001:b:c:d:1:2:3:4/64",
                "__repr__": "Ip6Host('2001:b:c:d:1:2:3:4/64')",
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("2001:b:c:d:1:2:3:4"),
                "network": Ip6Network("2001:b:c:d:1::/64"),
                "gateway": None,
                "origin": Ip6HostOrigin.UNKNOWN,
                "expiration_time": 0,
            },
        },
        {
            "_description": "Test the IPv6 host: 2001:b:c:d:1:2:3:4/64 (Ip6Address, Ip6Mask)",
            "_args": [
                (Ip6Address("2001:b:c:d:1:2:3:4"), Ip6Mask("/64")),
            ],
            "_kwargs": {
                "gateway": Ip6Address("2001:b:c:d::1"),
                "origin": Ip6HostOrigin.DHCP,
                "expiration_time": IP6_ADDRESS_EXPIRATION_TIME,
            },
            "_results": {
                "__str__": "2001:b:c:d:1:2:3:4/64",
                "__repr__": "Ip6Host('2001:b:c:d:1:2:3:4/64')",
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("2001:b:c:d:1:2:3:4"),
                "network": Ip6Network("2001:b:c:d:1::/64"),
                "gateway": Ip6Address("2001:b:c:d::1"),
                "origin": Ip6HostOrigin.DHCP,
                "expiration_time": IP6_ADDRESS_EXPIRATION_TIME,
            },
        },
        {
            "_description": "Test the IPv6 host: 2001:b:c:d:1:2:3:4/64 (Ip6Address, Ip6Network)",
            "_args": [
                (
                    Ip6Address("2001:b:c:d:1:2:3:4"),
                    Ip6Network("2001:b:c:d::/64"),
                ),
            ],
            "_kwargs": {
                "gateway": Ip6Address("2001:b:c:d::1"),
                "origin": Ip6HostOrigin.STATIC,
            },
            "_results": {
                "__str__": "2001:b:c:d:1:2:3:4/64",
                "__repr__": "Ip6Host('2001:b:c:d:1:2:3:4/64')",
                "version": IpVersion.IP6,
                "is_ip6": True,
                "is_ip4": False,
                "address": Ip6Address("2001:b:c:d:1:2:3:4"),
                "network": Ip6Network("2001:b:c:d:1::/64"),
                "gateway": Ip6Address("2001:b:c:d::1"),
                "origin": Ip6HostOrigin.STATIC,
                "expiration_time": 0,
            },
        },
    ]
)
class TestNetAddrIp6Host(TestCase):
    """
    The NetAddr IPv6 Host tests.
    """

    _description: str
    _args: dict[str, Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def setUp(self) -> None:
        """
        Initialize the IPv6 host object with testcase arguments.
        """

        self._ip6_host = Ip6Host(*self._args, **self._kwargs)

    def test__net_addr__ip6_host__str(self) -> None:
        """
        Ensure the IPv6 host '__str__()' method returns a correct value.
        """

        self.assertEqual(
            str(self._ip6_host),
            self._results["__str__"],
        )

    def test__net_addr__ip6_host__repr(self) -> None:
        """
        Ensure the IPv6 host '__repr__()' method returns a correct value.
        """

        self.assertEqual(
            repr(self._ip6_host),
            self._results["__repr__"],
        )

    def test__net_addr__ip6_host__eq(self) -> None:
        """
        Ensure the IPv6 host '__eq__()' method returns a correct value.
        """

        self.assertTrue(
            self._ip6_host == self._ip6_host,
            msg="An Ip6Host instance must compare equal to itself.",
        )

        self.assertTrue(
            self._ip6_host == Ip6Host(str(self._ip6_host)),
            msg="Ip6Host must compare equal to one reconstructed from its string representation.",
        )

        self.assertFalse(
            self._ip6_host == "not an IPv6 host",
            msg="Ip6Host must not compare equal to a foreign string value.",
        )

        self.assertFalse(
            self._ip6_host == None,  # noqa: E711
            msg="Ip6Host must not compare equal to None.",
        )

        self.assertFalse(
            self._ip6_host
            == Ip6Host(
                (
                    Ip6Address((int(self._ip6_host.address) ^ 0x01) & 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF),
                    self._ip6_host.network,
                ),
            ),
            msg="Ip6Host instances with different addresses must not compare equal.",
        )

    def test__net_addr__ip6_host__version(self) -> None:
        """
        Ensure the IPv6 host 'version' property returns a correct value.
        """

        self.assertEqual(
            self._ip6_host.version,
            self._results["version"],
        )

    def test__net_addr__ip6_host__is_ip4(self) -> None:
        """
        Ensure the IPv6 host 'is_ip4' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_host.is_ip4,
            self._results["is_ip4"],
        )

    def test__net_addr__ip6_host__is_ip6(self) -> None:
        """
        Ensure the IPv6 host 'is_ip6' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_host.is_ip6,
            self._results["is_ip6"],
        )

    def test__net_addr__ip6_host__address(self) -> None:
        """
        Ensure the IPv6 host 'address' property returns a correct value.
        """

        self.assertEqual(
            self._ip6_host.address,
            self._results["address"],
        )

    def test__net_addr__ip6_host__network(self) -> None:
        """
        Ensure the IPv6 host 'network' property returns a correct value.
        """

        self.assertEqual(
            self._ip6_host.network,
            self._results["network"],
        )

    def test__net_addr__ip6_host__gateway(self) -> None:
        """
        Ensure the IPv6 host 'gateway' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_host.gateway,
            self._results["gateway"],
        )

    def test__net_addr__ip6_host__origin(self) -> None:
        """
        Ensure the IPv6 host 'origin' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_host.origin,
            self._results["origin"],
        )

    def test__net_addr__ip6_host__expiration_time(self) -> None:
        """
        Ensure the IPv6 host 'expiration_time' property returns a correct
        value.
        """

        self.assertEqual(
            self._ip6_host.expiration_time,
            self._results["expiration_time"],
        )


class TestNetAddrIp6HostSemantics(TestCase):
    """
    The NetAddr IPv6 host semantic tests not tied to a parameterized matrix.
    """

    def test__net_addr__ip6_host__eq__ignores_metadata(self) -> None:
        """
        Ensure '__eq__()' compares only address and network, ignoring
        gateway, origin, and expiration_time.
        """

        plain = Ip6Host("2001:db8::1/64")
        decorated = Ip6Host(
            "2001:db8::1/64",
            gateway=Ip6Address("2001:db8::ffff"),
            origin=Ip6HostOrigin.DHCP,
            expiration_time=IP6_ADDRESS_EXPIRATION_TIME,
        )

        self.assertEqual(
            plain,
            decorated,
            msg="Ip6Host equality must ignore gateway, origin, and expiration_time.",
        )
        self.assertEqual(
            hash(plain),
            hash(decorated),
            msg="Equal Ip6Host values must hash to the same value regardless of metadata.",
        )

    def test__net_addr__ip6_host__eq__cross_version(self) -> None:
        """
        Ensure '__eq__()' returns False when compared to an Ip4Host.
        """

        self.assertNotEqual(
            Ip6Host("2001:db8::c0a8:164/64"),
            Ip4Host("192.168.1.100/24"),
            msg="Ip6Host must not compare equal to an Ip4Host.",
        )

    def test__net_addr__ip6_host__eq__foreign_types(self) -> None:
        """
        Ensure the IPv6 host is never equal to a value of a foreign type,
        including its own component pieces.
        """

        host = Ip6Host("2001:db8::1/64")

        self.assertFalse(
            host == "2001:db8::1/64",
            msg="Ip6Host must not compare equal to its string representation.",
        )
        self.assertFalse(
            host == host.address,
            msg="Ip6Host must not compare equal to its Ip6Address component.",
        )
        self.assertFalse(
            host == host.network,
            msg="Ip6Host must not compare equal to its Ip6Network component.",
        )
        self.assertFalse(
            host == 0,
            msg="Ip6Host must not compare equal to an integer.",
        )

    def test__net_addr__ip6_host__ne(self) -> None:
        """
        Ensure the IPv6 host '__ne__()' method returns a correct value.
        """

        host = Ip6Host("2001:db8::1/64")
        self.assertTrue(
            host != Ip6Host("2001:db8::2/64"),
            msg="Ip6Host instances with different addresses must be unequal.",
        )
        self.assertFalse(
            host != Ip6Host("2001:db8::1/64"),
            msg="Ip6Host instances with the same address and network must not be unequal.",
        )
        self.assertTrue(
            host != "2001:db8::1/64",
            msg="Ip6Host must be unequal to its string representation.",
        )

    def test__net_addr__ip6_host__hash__distinct_instances(self) -> None:
        """
        Ensure two independently constructed equal hosts hash identically.
        """

        a = Ip6Host("2001:db8::1/64")
        b = Ip6Host((Ip6Address("2001:db8::1"), Ip6Mask("/64")))
        self.assertEqual(
            a,
            b,
            msg="Ip6Host built from string and (address, mask) tuple must compare equal.",
        )
        self.assertEqual(
            hash(a),
            hash(b),
            msg="Equal Ip6Host values must hash to the same value across constructor forms.",
        )

    def test__net_addr__ip6_host__usable_in_set(self) -> None:
        """
        Ensure equal IPv6 hosts collapse into a single element when used
        in a set.
        """

        a = Ip6Host("2001:db8::1/64")
        b = Ip6Host((Ip6Address("2001:db8::1"), Ip6Mask("/64")))
        c = Ip6Host("2001:db8::2/64")

        self.assertEqual(
            len({a, b}),
            1,
            msg="Two equal Ip6Host values must collapse into one set element.",
        )
        self.assertEqual(
            len({a, b, c}),
            2,
            msg="Distinct Ip6Host values must occupy distinct set elements.",
        )
        self.assertIn(
            a,
            {b},
            msg="Set membership lookup must treat equal Ip6Host values as the same key.",
        )

    def test__net_addr__ip6_host__usable_in_dict(self) -> None:
        """
        Ensure equal IPv6 hosts refer to the same dict entry regardless
        of which constructor form was used to build the key.
        """

        a = Ip6Host("2001:db8::1/64")
        b = Ip6Host((Ip6Address("2001:db8::1"), Ip6Mask("/64")))

        mapping = {a: "value"}

        self.assertEqual(
            mapping[b],
            "value",
            msg="Ip6Host must behave consistently as a dict key across input forms.",
        )

    def test__net_addr__ip6_host__roundtrip__str(self) -> None:
        """
        Ensure 'Ip6Host(str(x))' yields a host equal to 'x' (metadata-free).
        """

        for spec in ("::/0", "::1/128", "2001:db8::1/64", "fe80::1/10", "ff02::1/128"):
            with self.subTest(spec=spec):
                host = Ip6Host(spec)
                self.assertEqual(
                    Ip6Host(str(host)),
                    host,
                    msg=f"Roundtrip through str() must preserve host {spec!r}.",
                )

    def test__net_addr__ip6_host__copy_preserves_fields(self) -> None:
        """
        Ensure copying an Ip6Host preserves gateway, origin, and expiration_time.
        """

        source = Ip6Host(
            "2001:db8::1/64",
            gateway=Ip6Address("fe80::1"),
            origin=Ip6HostOrigin.DHCP,
            expiration_time=IP6_ADDRESS_EXPIRATION_TIME,
        )
        clone = Ip6Host(source)

        self.assertEqual(
            clone.address,
            source.address,
            msg="Copying an Ip6Host must preserve its address.",
        )
        self.assertEqual(
            clone.network,
            source.network,
            msg="Copying an Ip6Host must preserve its network.",
        )
        self.assertEqual(
            clone.gateway,
            source.gateway,
            msg="Copying an Ip6Host must preserve its gateway.",
        )
        self.assertEqual(
            clone.origin,
            source.origin,
            msg="Copying an Ip6Host must preserve its origin.",
        )
        self.assertEqual(
            clone.expiration_time,
            source.expiration_time,
            msg="Copying an Ip6Host must preserve its expiration_time.",
        )


class TestNetAddrIp6HostFromEui64(TestCase):
    """
    The NetAddr IPv6 host 'from_eui64()' classmethod tests.
    """

    def test__net_addr__ip6_host__from_eui64(self) -> None:
        """
        Ensure 'from_eui64()' builds a /64 host from a MAC and network.
        """

        host = Ip6Host.from_eui64(
            mac_address=MacAddress("02:00:00:11:22:33"),
            ip6_network=Ip6Network("2001:db8::/64"),
        )

        self.assertEqual(
            host.network,
            Ip6Network("2001:db8::/64"),
            msg="EUI64 host must keep the source /64 network.",
        )
        self.assertEqual(
            host.address,
            Ip6Address("2001:db8::ff:fe11:2233"),
            msg="EUI64 address must flip the U/L bit and embed the MAC.",
        )

    def test__net_addr__ip6_host__from_eui64__non_64_mask_raises(self) -> None:
        """
        Ensure 'from_eui64()' rejects a network whose mask is not /64.
        """

        with self.assertRaises(
            AssertionError,
            msg="from_eui64() must reject a network whose mask is not /64.",
        ):
            Ip6Host.from_eui64(
                mac_address=MacAddress("02:00:00:11:22:33"),
                ip6_network=Ip6Network("2001:db8::/48"),
            )


class TestNetAddrIp6HostFromRfc7217(TestCase):
    """
    The NetAddr IPv6 host 'from_rfc7217()' classmethod tests
    — cryptographic stable-opaque IIDs.
    """

    def test__net_addr__ip6_host__from_rfc7217__deterministic(self) -> None:
        """
        Ensure two calls with identical inputs produce the
        same address (the IID is a deterministic PRF output).

        Reference: RFC 7217 §5 (Algorithm Specification).
        """

        host_a = Ip6Host.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
        )
        host_b = Ip6Host.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
        )

        self.assertEqual(
            host_a.address,
            host_b.address,
            msg=f"Same inputs must produce the same RFC 7217 address. Got: {host_a!r} vs {host_b!r}",
        )

    def test__net_addr__ip6_host__from_rfc7217__different_prefix(self) -> None:
        """
        Ensure two different prefixes produce different IIDs —
        the design goal that prevents host correlation across
        networks.

        Reference: RFC 7217 §3 (design goals).
        """

        host_a = Ip6Host.from_rfc7217(
            ip6_network=Ip6Network("2001:db8:0:1::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
        )
        host_b = Ip6Host.from_rfc7217(
            ip6_network=Ip6Network("2001:db8:0:2::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
        )

        self.assertNotEqual(
            int(host_a.address) & ((1 << 64) - 1),
            int(host_b.address) & ((1 << 64) - 1),
            msg=(
                "Different prefixes must yield different IIDs "
                f"(unlinkability). Got IID(a)={int(host_a.address) & ((1 << 64) - 1):x}, "
                f"IID(b)={int(host_b.address) & ((1 << 64) - 1):x}"
            ),
        )

    def test__net_addr__ip6_host__from_rfc7217__different_mac(self) -> None:
        """
        Ensure different MAC addresses produce different IIDs.

        Reference: RFC 7217 §5 (Net_Iface in PRF input).
        """

        host_a = Ip6Host.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
        )
        host_b = Ip6Host.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:aa:bb:cc"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
        )

        self.assertNotEqual(
            host_a.address,
            host_b.address,
            msg=f"Different MACs must yield different addresses. Got: {host_a!r} vs {host_b!r}",
        )

    def test__net_addr__ip6_host__from_rfc7217__different_secret_key(self) -> None:
        """
        Ensure different secret keys produce different IIDs.

        Reference: RFC 7217 §5 (secret_key in PRF input).
        """

        host_a = Ip6Host.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"first-128-bit-secret-key-bytes--",
        )
        host_b = Ip6Host.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"second-128-bit-secret-key-bytes-",
        )

        self.assertNotEqual(
            host_a.address,
            host_b.address,
            msg=f"Different secret keys must yield different addresses. Got: {host_a!r} vs {host_b!r}",
        )

    def test__net_addr__ip6_host__from_rfc7217__dad_counter_changes_iid(self) -> None:
        """
        Ensure incrementing the DAD counter (which the host
        does on a DAD conflict) yields a different IID for the
        same {prefix, mac, secret_key} tuple.

        Reference: RFC 7217 §5 (DAD_Counter input + §6 conflict resolution).
        """

        host_0 = Ip6Host.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
            dad_counter=0,
        )
        host_1 = Ip6Host.from_rfc7217(
            ip6_network=Ip6Network("2001:db8::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
            dad_counter=1,
        )

        self.assertNotEqual(
            host_0.address,
            host_1.address,
            msg=f"Different DAD counters must yield different IIDs. Got: {host_0!r} vs {host_1!r}",
        )

    def test__net_addr__ip6_host__from_rfc7217__keeps_prefix(self) -> None:
        """
        Ensure the resulting address keeps the source /64
        network — only the IID changes.

        Reference: RFC 7217 §5 (PRF output replaces IID, prefix preserved).
        """

        host = Ip6Host.from_rfc7217(
            ip6_network=Ip6Network("2001:db8:cafe::/64"),
            mac_address=MacAddress("02:00:00:11:22:33"),
            secret_key=b"a-fixed-128-bit-secret-key-bytes",
        )

        self.assertEqual(
            host.network,
            Ip6Network("2001:db8:cafe::/64"),
            msg=f"RFC 7217 host must keep the source /64 network. Got: {host!r}",
        )
        # Address upper 64 bits = network upper 64 bits.
        self.assertEqual(
            int(host.address) >> 64,
            int(Ip6Address("2001:db8:cafe::")) >> 64,
            msg=f"Address upper-64 must equal prefix. Got: {host.address!r}",
        )

    def test__net_addr__ip6_host__from_rfc7217__non_64_mask_raises(self) -> None:
        """
        Ensure 'from_rfc7217()' rejects a network whose mask is
        not /64 (the same constraint as 'from_eui64').

        Reference: RFC 4291 §2.5.1 (modified EUI-64 IIDs are 64 bits).
        """

        with self.assertRaises(
            AssertionError,
            msg="from_rfc7217() must reject a network whose mask is not /64.",
        ):
            Ip6Host.from_rfc7217(
                ip6_network=Ip6Network("2001:db8::/48"),
                mac_address=MacAddress("02:00:00:11:22:33"),
                secret_key=b"a-fixed-128-bit-secret-key-bytes",
            )

    def test__net_addr__ip6_host__from_rfc7217__rejects_short_secret_key(self) -> None:
        """
        Ensure 'from_rfc7217()' rejects a secret_key shorter
        than 16 bytes (the spec-mandated minimum).

        Reference: RFC 7217 §5 (secret_key SHOULD be ≥ 128 bits).
        """

        with self.assertRaises(
            AssertionError,
            msg="from_rfc7217() must reject a secret_key < 16 bytes (128 bits).",
        ):
            Ip6Host.from_rfc7217(
                ip6_network=Ip6Network("2001:db8::/64"),
                mac_address=MacAddress("02:00:00:11:22:33"),
                secret_key=b"too-short",
            )


class TestNetAddrIp6HostFromRfc8981Temp(TestCase):
    """
    The NetAddr IPv6 host 'from_rfc8981_temp()' classmethod
    tests — random IIDs for RFC 8981 temporary addresses.
    """

    def test__net_addr__ip6_host__from_rfc8981_temp__keeps_prefix(self) -> None:
        """
        Ensure the resulting host keeps the source /64 network
        and that the address upper-64 bits equal the prefix.

        Reference: RFC 8981 §3.3.2 (random IID + prefix concat).
        """

        prefix = Ip6Network("2001:db8:cafe::/64")
        host = Ip6Host.from_rfc8981_temp(ip6_network=prefix)

        self.assertEqual(
            host.network,
            prefix,
            msg=f"Temporary host must keep the source /64 network. Got: {host!r}",
        )
        self.assertEqual(
            int(host.address) >> 64,
            int(Ip6Address("2001:db8:cafe::")) >> 64,
            msg=f"Address upper-64 must equal prefix. Got: {host.address!r}",
        )

    def test__net_addr__ip6_host__from_rfc8981_temp__different_each_call(self) -> None:
        """
        Ensure two consecutive calls yield different IIDs —
        the IID is derived from a fresh 64-bit random draw, so
        collision probability is negligible.

        Reference: RFC 8981 §3.3.2 (random IID).
        """

        prefix = Ip6Network("2001:db8::/64")
        host_a = Ip6Host.from_rfc8981_temp(ip6_network=prefix)
        host_b = Ip6Host.from_rfc8981_temp(ip6_network=prefix)

        self.assertNotEqual(
            host_a.address,
            host_b.address,
            msg=f"Two random IIDs must differ. Got: {host_a!r} vs {host_b!r}",
        )

    def test__net_addr__ip6_host__from_rfc8981_temp__non_64_mask_raises(self) -> None:
        """
        Ensure 'from_rfc8981_temp()' rejects a network whose
        mask is not /64 (the IID width is fixed at 64 bits).

        Reference: RFC 4291 §2.5.1 (IIDs are 64 bits for unicast addresses).
        """

        with self.assertRaises(
            AssertionError,
            msg="from_rfc8981_temp() must reject a network whose mask is not /64.",
        ):
            Ip6Host.from_rfc8981_temp(ip6_network=Ip6Network("2001:db8::/48"))

    def test__net_addr__ip6_host__from_rfc8981_temp__avoids_reserved_iid(self) -> None:
        """
        Ensure the generator regenerates if the random draw
        produces a reserved IID — Subnet-Router Anycast
        (all-zero IID) and Reserved Subnet Anycast IIDs must
        NOT be returned.

        Reference: RFC 5453 (reserved IIDs).
        Reference: RFC 8981 §3.3.2 (avoidance requirement).
        """

        from unittest.mock import patch

        prefix = Ip6Network("2001:db8::/64")
        # First three draws return reserved IIDs; the fourth
        # returns a usable random value.
        reserved_iids = [
            (0).to_bytes(8, "big"),  # Subnet-Router Anycast.
            (0xFDFFFFFFFFFFFF80).to_bytes(8, "big"),  # Reserved Anycast lower bound.
            (0xFDFFFFFFFFFFFFFF).to_bytes(8, "big"),  # Reserved Anycast upper bound.
            (0x1234567890ABCDEF).to_bytes(8, "big"),  # Acceptable random value.
        ]
        with patch(
            "net_addr.ip6_host.secrets.token_bytes",
            side_effect=reserved_iids,
        ):
            host = Ip6Host.from_rfc8981_temp(ip6_network=prefix)

        self.assertEqual(
            int(host.address) & ((1 << 64) - 1),
            0x1234567890ABCDEF,
            msg=(
                "Generator must regenerate past reserved IIDs and return "
                f"the first acceptable random value. Got: {host!r}"
            ),
        )

    def test__net_addr__ip6_host__from_rfc8981_temp__exhaustion_raises(self) -> None:
        """
        Ensure the generator raises after exhausting its retry
        budget without finding a non-reserved IID — protects
        against a (practically impossible) starvation loop.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        from unittest.mock import patch

        prefix = Ip6Network("2001:db8::/64")
        # Every draw returns a reserved IID; the generator
        # should give up.
        with patch(
            "net_addr.ip6_host.secrets.token_bytes",
            return_value=(0).to_bytes(8, "big"),
        ):
            with self.assertRaises(
                RuntimeError,
                msg="Exhausting reserved-IID retries must raise RuntimeError.",
            ):
                Ip6Host.from_rfc8981_temp(ip6_network=prefix)


@parameterized_class(
    [
        {
            "_description": "Test the IPv6 host where address is not part of the network.",
            "_args": [
                (Ip6Address("a::1:2:3:4"), Ip6Network("b::/64")),
            ],
            "_kwargs": {},
            "_results": {
                "error": Ip6HostSanityError,
                "error_message": (
                    "The IPv6 address doesn't belong to the provided network: "
                    "(Ip6Address('a::1:2:3:4'), Ip6Network('b::/64'))"
                ),
            },
        },
        {
            "_description": "Test Ip6HostFormatError: invalid input type.",
            "_args": [12345],
            "_kwargs": {},
            "_results": {
                "error": Ip6HostFormatError,
                "error_message": "The IPv6 host format is invalid: 12345",
            },
        },
        {
            "_description": "Test Ip6HostFormatError: invalid string.",
            "_args": ["not-a-host"],
            "_kwargs": {},
            "_results": {
                "error": Ip6HostFormatError,
                "error_message": "The IPv6 host format is invalid: 'not-a-host'",
            },
        },
        {
            "_description": "Test Ip6HostFormatError: None input.",
            "_args": [None],
            "_kwargs": {},
            "_results": {
                "error": Ip6HostFormatError,
                "error_message": "The IPv6 host format is invalid: None",
            },
        },
        {
            "_description": "Test Ip6HostGatewayError: gateway equals network address.",
            "_args": [(Ip6Address("2001:db8::1"), Ip6Network("2001:db8::/64"))],
            "_kwargs": {"gateway": Ip6Address("2001:db8::")},
            "_results": {
                "error": Ip6HostGatewayError,
                "error_message": "The IPv6 host gateway is invalid: Ip6Address('2001:db8::')",
            },
        },
        {
            "_description": "Test Ip6HostGatewayError: gateway equals host address.",
            "_args": [(Ip6Address("2001:db8::1"), Ip6Network("2001:db8::/64"))],
            "_kwargs": {"gateway": Ip6Address("2001:db8::1")},
            "_results": {
                "error": Ip6HostGatewayError,
                "error_message": "The IPv6 host gateway is invalid: Ip6Address('2001:db8::1')",
            },
        },
        {
            "_description": "Test Ip6HostGatewayError: gateway is neither global nor link-local.",
            "_args": [(Ip6Address("2001:db8::1"), Ip6Network("2001:db8::/64"))],
            "_kwargs": {"gateway": Ip6Address("fc00::1")},
            "_results": {
                "error": Ip6HostGatewayError,
                "error_message": "The IPv6 host gateway is invalid: Ip6Address('fc00::1')",
            },
        },
    ]
)
class TestNetAddrIp6HostErrors(TestCase):
    """
    The NetAddr IPv6 host error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    def test__net_addr__ip6_host__errors(self) -> None:
        """
        Ensure the IPv6 host raises an error on invalid input.
        """

        with self.assertRaises(self._results["error"]) as error:
            Ip6Host(*self._args, **self._kwargs)

        self.assertEqual(
            str(error.exception),
            self._results["error_message"],
            msg=f"Expected error message does not match for case: {self._description}.",
        )


@parameterized_class(
    [
        {
            "_description": "AssertionError: DHCP origin requires expiration_time.",
            "_args": ["2001:db8::1/64"],
            "_kwargs": {"origin": Ip6HostOrigin.DHCP},
        },
        {
            "_description": "AssertionError: AUTOCONFIG origin requires expiration_time.",
            "_args": ["2001:db8::1/64"],
            "_kwargs": {"origin": Ip6HostOrigin.AUTOCONFIG},
        },
        {
            "_description": "AssertionError: STATIC origin with expiration_time set.",
            "_args": ["2001:db8::1/64"],
            "_kwargs": {
                "origin": Ip6HostOrigin.STATIC,
                "expiration_time": 9999999999,
            },
        },
        {
            "_description": "AssertionError: DHCP origin with expiration_time in the past.",
            "_args": ["2001:db8::1/64"],
            "_kwargs": {
                "origin": Ip6HostOrigin.DHCP,
                "expiration_time": 1,
            },
        },
        {
            "_description": "AssertionError: copying Ip6Host with gateway set.",
            "_args": [Ip6Host("2001:db8::1/64")],
            "_kwargs": {"gateway": Ip6Address("fe80::1")},
        },
        {
            "_description": "AssertionError: copying Ip6Host with origin set.",
            "_args": [Ip6Host("2001:db8::1/64")],
            "_kwargs": {"origin": Ip6HostOrigin.STATIC},
        },
        {
            "_description": "AssertionError: copying Ip6Host with expiration_time set.",
            "_args": [Ip6Host("2001:db8::1/64")],
            "_kwargs": {"expiration_time": 9999999999},
        },
    ]
)
class TestNetAddrIp6HostAssertionErrors(TestCase):
    """
    The NetAddr IPv6 host assertion error tests.
    """

    _description: str
    _args: list[Any]
    _kwargs: dict[str, Any]

    def test__net_addr__ip6_host__assertion_errors(self) -> None:
        """
        Ensure the IPv6 host raises AssertionError on constraint violations.
        """

        with self.assertRaises(
            AssertionError,
            msg=f"Expected AssertionError for case: {self._description}.",
        ):
            Ip6Host(*self._args, **self._kwargs)


class TestNetAddrIp6HostSetters(TestCase):
    """
    The NetAddr IPv6 host property setter tests.
    """

    def setUp(self) -> None:
        """
        Initialize a base IPv6 host for setter tests.
        """

        self._ip6_host = Ip6Host("2001:db8::1/64", origin=Ip6HostOrigin.STATIC)

    def test__net_addr__ip6_host__origin_setter(self) -> None:
        """
        Ensure the IPv6 host 'origin' setter stores the new value.
        """

        self._ip6_host.origin = Ip6HostOrigin.UNKNOWN
        self.assertEqual(
            self._ip6_host.origin,
            Ip6HostOrigin.UNKNOWN,
            msg="The 'origin' setter must store the assigned value.",
        )

    def test__net_addr__ip6_host__expiration_time_setter(self) -> None:
        """
        Ensure the IPv6 host 'expiration_time' setter stores the new value.
        """

        self._ip6_host.expiration_time = 9999999999
        self.assertEqual(
            self._ip6_host.expiration_time,
            9999999999,
            msg="The 'expiration_time' setter must store the assigned value.",
        )

    def test__net_addr__ip6_host__gateway_setter__link_local(self) -> None:
        """
        Ensure the IPv6 host 'gateway' setter accepts a link-local address.
        """

        self._ip6_host.gateway = Ip6Address("fe80::1")
        self.assertEqual(
            self._ip6_host.gateway,
            Ip6Address("fe80::1"),
            msg="The 'gateway' setter must store a valid link-local address.",
        )

    def test__net_addr__ip6_host__gateway_setter__global(self) -> None:
        """
        Ensure the IPv6 host 'gateway' setter accepts a global address.
        """

        self._ip6_host.gateway = Ip6Address("2001:db8::ffff")
        self.assertEqual(
            self._ip6_host.gateway,
            Ip6Address("2001:db8::ffff"),
            msg="The 'gateway' setter must store a valid global address.",
        )

    def test__net_addr__ip6_host__gateway_setter__clear(self) -> None:
        """
        Ensure the IPv6 host 'gateway' setter accepts None to clear the gateway.
        """

        self._ip6_host.gateway = Ip6Address("fe80::1")
        self._ip6_host.gateway = None
        self.assertIsNone(
            self._ip6_host.gateway,
            msg="Assigning None to 'gateway' must clear the stored gateway.",
        )

    def test__net_addr__ip6_host__gateway_setter__error__not_routable(self) -> None:
        """
        Ensure the 'gateway' setter rejects an address that is neither
        global nor link-local.
        """

        with self.assertRaises(
            Ip6HostGatewayError,
            msg="The 'gateway' setter must reject a non-global, non-link-local address.",
        ):
            self._ip6_host.gateway = Ip6Address("fc00::1")

    def test__net_addr__ip6_host__gateway_setter__error__network_address(self) -> None:
        """
        Ensure the 'gateway' setter rejects the network address.
        """

        with self.assertRaises(
            Ip6HostGatewayError,
            msg="The 'gateway' setter must reject the network address.",
        ):
            self._ip6_host.gateway = Ip6Address("2001:db8::")

    def test__net_addr__ip6_host__gateway_setter__error__host_address(self) -> None:
        """
        Ensure the 'gateway' setter rejects the host's own address.
        """

        with self.assertRaises(
            Ip6HostGatewayError,
            msg="The 'gateway' setter must reject the host's own address.",
        ):
            self._ip6_host.gateway = Ip6Address("2001:db8::1")
