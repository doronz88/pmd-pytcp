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
This module contains tests that exercise abstract stub bodies in the NetAddr
base classes so the 'NotImplementedError' fallback lines are covered.

net_addr/tests/unit/test__abstract_stubs.py

ver 3.0.5
"""

from unittest import TestCase

from net_addr.address import Address
from net_addr.base import Base
from net_addr.ip4_address import Ip4Address
from net_addr.ip4_ifaddr import Ip4IfAddr
from net_addr.ip4_mask import Ip4Mask
from net_addr.ip4_network import Ip4Network
from net_addr.ip4_wildcard import Ip4Wildcard
from net_addr.ip_address import IpAddress
from net_addr.ip_ifaddr import IfAddr
from net_addr.ip_mask import IpMask
from net_addr.ip_network import IpNetwork
from net_addr.ip_version import IpVersion
from net_addr.ip_wildcard import IpWildcard


class TestNetAddrBaseAbstractStubs(TestCase):
    """
    The NetAddr 'Base' abstract stub body tests.
    """

    def test__net_addr__base__str_stub_raises(self) -> None:
        """
        Ensure the abstract 'Base.__str__()' stub body raises 'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            Base.__str__(Ip4Address())

    def test__net_addr__base__eq_stub_raises(self) -> None:
        """
        Ensure the abstract 'Base.__eq__()' stub body raises 'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            Base.__eq__(Ip4Address(), Ip4Address())


class TestNetAddrAddressAbstractStubs(TestCase):
    """
    The NetAddr 'Address' abstract stub body tests.
    """

    def test__net_addr__address__buffer_stub_raises(self) -> None:
        """
        Ensure the abstract 'Address.__buffer__()' stub body raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            Address.__buffer__(Ip4Address(), 0)


class TestNetAddrIpAddressAbstractStubs(TestCase):
    """
    The NetAddr 'IpAddress' abstract property stub body tests.
    """

    def test__net_addr__ip_address__multicast_mac_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpAddress.multicast_mac' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpAddress.multicast_mac.fget(Ip4Address())  # type: ignore[attr-defined]

    def test__net_addr__ip_address__reverse_pointer_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpAddress.reverse_pointer' stub
        raises 'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpAddress.reverse_pointer.fget(Ip4Address())  # type: ignore[attr-defined]

    def test__net_addr__ip_address__exploded_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpAddress.exploded' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpAddress.exploded.fget(Ip4Address())  # type: ignore[attr-defined]

    def test__net_addr__ip_address__is_loopback_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpAddress.is_loopback' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpAddress.is_loopback.fget(Ip4Address())  # type: ignore[attr-defined]

    def test__net_addr__ip_address__is_global_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpAddress.is_global' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpAddress.is_global.fget(Ip4Address())  # type: ignore[attr-defined]

    def test__net_addr__ip_address__is_private_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpAddress.is_private' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpAddress.is_private.fget(Ip4Address())  # type: ignore[attr-defined]

    def test__net_addr__ip_address__is_link_local_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpAddress.is_link_local' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpAddress.is_link_local.fget(Ip4Address())  # type: ignore[attr-defined]

    def test__net_addr__ip_address__is_multicast_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpAddress.is_multicast' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpAddress.is_multicast.fget(Ip4Address())  # type: ignore[attr-defined]


class TestNetAddrIpMaskAbstractStubs(TestCase):
    """
    The NetAddr 'IpMask' abstract stub body tests.
    """

    def test__net_addr__ip_mask__buffer_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpMask.__buffer__()' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpMask.__buffer__(Ip4Mask(), 0)


class TestNetAddrIpWildcardAbstractStubs(TestCase):
    """
    The NetAddr 'IpWildcard' abstract stub body tests.
    """

    def test__net_addr__ip_wildcard__buffer_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpWildcard.__buffer__()' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpWildcard.__buffer__(Ip4Wildcard(), 0)


class TestNetAddrIpNetworkAbstractStubs(TestCase):
    """
    The NetAddr 'IpNetwork' abstract property stub body tests.
    """

    def test__net_addr__ip_network__last_stub_raises(self) -> None:
        """
        Ensure the abstract 'IpNetwork.last' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(NotImplementedError):
            IpNetwork.last.fget(Ip4Network())  # type: ignore[attr-defined]


class TestNetAddrIpHostAbstractStubs(TestCase):
    """
    The NetAddr 'IfAddr' abstract stub body tests.
    """

    def test__net_addr__ip_host__validate_gateway_stub_raises(self) -> None:
        """
        Ensure the abstract 'IfAddr._validate_gateway()' stub raises
        'NotImplementedError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        host = Ip4IfAddr("192.0.2.1/24")

        with self.assertRaises(NotImplementedError):
            IfAddr._validate_gateway(host, None)


class TestNetAddrIpVersion(TestCase):
    """
    The NetAddr 'IpVersion' enum tests.
    """

    def test__net_addr__ip_version__values(self) -> None:
        """
        Ensure the 'IpVersion' enum exposes IP4 and IP6 members.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(IpVersion.IP4.value, 4)
        self.assertEqual(IpVersion.IP6.value, 6)

    def test__net_addr__ip_version__int_conversion(self) -> None:
        """
        Ensure 'int(IpVersion.x)' returns the underlying numeric value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(int(IpVersion.IP4), 4)
        self.assertEqual(int(IpVersion.IP6), 6)
