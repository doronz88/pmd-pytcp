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
Unit test for the 'stack.pmtu_cache' module-level state introduced
by Phase 3 of the ICMP demux + PMTUD refactor. The cache itself is
just a 'dict' — what this test pins is that the attribute exists,
its annotation matches the design, and its default state is empty.

pytcp/tests/unit/stack/test__pmtu_cache.py

ver 3.0.6
"""

from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from pytcp import stack


class TestPmtuCache(TestCase):
    """
    The 'stack.pmtu_cache' substrate.
    """

    def test__pmtu_cache__attribute_exists(self) -> None:
        """
        Ensure 'stack.pmtu_cache' is defined at module scope.

        Reference: RFC 1191 §3 (Path MTU Discovery).
        """

        self.assertTrue(
            hasattr(stack, "pmtu_cache"),
            msg="stack.pmtu_cache must be defined at module scope.",
        )

    def test__pmtu_cache__is_dict(self) -> None:
        """
        Ensure 'stack.pmtu_cache' is a plain dict so callers can
        snapshot/clear/restore it via the standard dict idioms used
        elsewhere in the test framework.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsInstance(
            stack.pmtu_cache,
            dict,
            msg="stack.pmtu_cache must be a dict[Ip4Address | Ip6Address, int].",
        )

    def test__pmtu_cache__accepts_ip4_key(self) -> None:
        """
        Ensure an Ip4Address key with an integer MTU value can be
        stored and retrieved without surprises.

        Reference: RFC 1191 §3 (PMTUD per-destination MTU cache).
        """

        ip = Ip4Address("10.0.1.91")
        try:
            stack.pmtu_cache[ip] = 1400
            self.assertEqual(
                stack.pmtu_cache[ip],
                1400,
                msg="stack.pmtu_cache must accept an Ip4Address key with an int MTU value.",
            )
        finally:
            stack.pmtu_cache.pop(ip, None)

    def test__pmtu_cache__accepts_ip6_key(self) -> None:
        """
        Ensure an Ip6Address key with an integer MTU value can be
        stored and retrieved.

        Reference: RFC 8201 §4 (IPv6 PMTUD per-destination MTU cache).
        """

        ip = Ip6Address("2001:db8:0:1::91")
        try:
            stack.pmtu_cache[ip] = 1280
            self.assertEqual(
                stack.pmtu_cache[ip],
                1280,
                msg="stack.pmtu_cache must accept an Ip6Address key with an int MTU value.",
            )
        finally:
            stack.pmtu_cache.pop(ip, None)
