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

pmd_pytcp/tests/unit/stack/test__pmtu_cache.py

ver 3.0.7
"""

from __future__ import annotations

from unittest import TestCase

from pmd_net_addr import Ip4Address, Ip6Address
from pmd_pytcp import stack
from pmd_pytcp.lib.plpmtud import PmtuSearch


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


class TestPmtuCacheAccessors(TestCase):
    """
    The 'stack' Path-MTU accessors — 'current_pmtu' reads the maps and
    'record_classical_pmtu' / 'record_pmtu_engine' write them. On the
    pure-asyncio runtime the whole stack runs on one event loop, so the
    former shared pmtu lock is gone; these tests pin the read/write
    behaviour of the accessors (see 'docs/refactor/pure_asyncio.md').
    """

    def setUp(self) -> None:
        """
        Snapshot the pmtu maps so each test's mutations are restored.
        """

        self._cache_prior = stack.pmtu_cache
        self._state_prior = stack.pmtu_state

    def tearDown(self) -> None:
        """
        Restore the original pmtu maps.
        """

        stack.pmtu_cache = self._cache_prior
        stack.pmtu_state = self._state_prior

    def test__pmtu__current_pmtu_reads_classical_cache(self) -> None:
        """
        Ensure 'current_pmtu' returns the cached classical next-hop MTU.

        Reference: RFC 8201 §5.2 (a host caches and reads PMTU per destination).
        """

        destination = Ip4Address("10.0.1.42")
        stack.pmtu_cache = {destination: 1400}
        stack.pmtu_state = {}

        self.assertEqual(
            stack.current_pmtu(destination),
            1400,
            msg="current_pmtu must return the cached classical next-hop MTU.",
        )

    def test__pmtu__record_classical_writes_cache(self) -> None:
        """
        Ensure recording a classical per-destination next-hop MTU mutates
        the 'pmtu_cache' map.

        Reference: RFC 1191 §3 (Path MTU Discovery per-destination cache).
        """

        destination = Ip4Address("10.0.1.43")
        stack.pmtu_cache = {}
        stack.pmtu_state = {}

        stack.record_classical_pmtu(destination, 1380)

        self.assertEqual(
            stack.pmtu_cache[destination],
            1380,
            msg="record_classical_pmtu must store the next-hop MTU.",
        )

    def test__pmtu__record_engine_writes_state(self) -> None:
        """
        Ensure recording a PLPMTUD engine for a destination mutates the
        'pmtu_state' map.

        Reference: RFC 8899 §5.2 (PLPMTUD maintains per-path search state).
        """

        destination = Ip4Address("10.0.1.44")
        engine: PmtuSearch[Ip4Address] = PmtuSearch(address=destination, interface_mtu=1500)
        stack.pmtu_cache = {}
        stack.pmtu_state = {}

        stack.record_pmtu_engine(destination, engine)

        self.assertIs(
            stack.pmtu_state[destination],
            engine,
            msg="record_pmtu_engine must store the engine for the destination.",
        )
