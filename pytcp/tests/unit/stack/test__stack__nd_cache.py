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
This module contains tests for the 'NdCache' ICMPv6 Neighbor Discovery
cache subsystem and its 'CacheEntry' helper.

pytcp/tests/unit/stack/test__stack__nd_cache.py

ver 3.0.4
"""


from dataclasses import FrozenInstanceError
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip6Address, MacAddress
from pytcp.stack.nd_cache import CacheEntry, NdCache


class TestNdCacheEntry(TestCase):
    """
    The 'CacheEntry' hit-count and immutability tests.
    """

    def test__nd_cache__entry_defaults(self) -> None:
        """
        Ensure a fresh 'CacheEntry' starts non-permanent, with
        'hit_count' at 0 and 'create_time' populated by the factory.
        """

        entry = CacheEntry(mac_address=MacAddress("02:00:00:00:00:01"))
        self.assertFalse(
            entry.permanent,
            msg="CacheEntry.permanent must default to False.",
        )
        self.assertEqual(
            entry.hit_count,
            0,
            msg="CacheEntry.hit_count must default to 0.",
        )
        self.assertGreater(
            entry.create_time,
            0,
            msg="CacheEntry.create_time must be populated with a positive epoch timestamp.",
        )

    def test__nd_cache__entry_hit_count_increment(self) -> None:
        """
        Ensure 'hit_count__increment' bumps 'hit_count' by 1.
        """

        entry = CacheEntry(mac_address=MacAddress("02:00:00:00:00:01"))
        entry.hit_count__increment()
        entry.hit_count__increment()
        self.assertEqual(
            entry.hit_count,
            2,
            msg="hit_count__increment must add 1 per call.",
        )

    def test__nd_cache__entry_hit_count_reset(self) -> None:
        """
        Ensure 'hit_count__reset' zeroes 'hit_count' after any
        number of prior increments.
        """

        entry = CacheEntry(mac_address=MacAddress("02:00:00:00:00:01"))
        entry.hit_count__increment()
        entry.hit_count__reset()
        self.assertEqual(
            entry.hit_count,
            0,
            msg="hit_count__reset must zero the hit_count counter.",
        )

    def test__nd_cache__entry_is_frozen(self) -> None:
        """
        Ensure normal attribute assignment is blocked by
        'frozen=True'.
        """

        entry = CacheEntry(mac_address=MacAddress("02:00:00:00:00:01"))
        with self.assertRaises(FrozenInstanceError):
            entry.mac_address = MacAddress("02:00:00:00:00:02")  # type: ignore[misc]


class _NdCacheFixture(TestCase):
    """
    Shared fixture: patches the module-level 'log' and provides a
    fresh 'NdCache'.
    """

    def setUp(self) -> None:
        """
        Install the log patches and build the cache.
        """

        self._log_patch = patch("pytcp.stack.nd_cache.log")
        self._log_patch.start()
        self._subsystem_log_patch = patch("pytcp.lib.subsystem.log")
        self._subsystem_log_patch.start()
        self._cache = NdCache()

    def tearDown(self) -> None:
        """
        Remove the log patches.
        """

        self._log_patch.stop()
        self._subsystem_log_patch.stop()


class TestNdCacheAddFind(_NdCacheFixture):
    """
    The 'NdCache.add_entry' / 'NdCache.find_entry' happy-path tests.
    """

    def test__nd_cache__add_entry_stores_mac(self) -> None:
        """
        Ensure 'add_entry' inserts a 'CacheEntry' keyed by the IPv6
        address, with the supplied MAC.
        """

        self._cache.add_entry(
            ip6_address=Ip6Address("2001:db8::1"),
            mac_address=MacAddress("02:00:00:00:00:01"),
        )
        entry = self._cache._nd_cache[Ip6Address("2001:db8::1")]
        self.assertEqual(
            entry.mac_address,
            MacAddress("02:00:00:00:00:01"),
            msg="add_entry must store the MAC address on the CacheEntry.",
        )

    def test__nd_cache__add_entry_overwrites(self) -> None:
        """
        Ensure a second 'add_entry' call replaces the prior entry —
        refresh creates a new CacheEntry.
        """

        self._cache.add_entry(
            ip6_address=Ip6Address("2001:db8::1"),
            mac_address=MacAddress("02:00:00:00:00:01"),
        )
        self._cache.add_entry(
            ip6_address=Ip6Address("2001:db8::1"),
            mac_address=MacAddress("02:00:00:00:00:02"),
        )
        self.assertEqual(
            self._cache._nd_cache[Ip6Address("2001:db8::1")].mac_address,
            MacAddress("02:00:00:00:00:02"),
            msg="A second add_entry call must overwrite the prior MAC.",
        )

    def test__nd_cache__find_entry_returns_mac_and_increments_hit(self) -> None:
        """
        Ensure 'find_entry' returns the stored MAC and increments the
        hit counter on a hit.
        """

        self._cache.add_entry(
            ip6_address=Ip6Address("2001:db8::1"),
            mac_address=MacAddress("02:00:00:00:00:01"),
        )
        result = self._cache.find_entry(ip6_address=Ip6Address("2001:db8::1"))
        self.assertEqual(
            result,
            MacAddress("02:00:00:00:00:01"),
            msg="find_entry must return the stored MAC address for a hit.",
        )
        self.assertEqual(
            self._cache._nd_cache[Ip6Address("2001:db8::1")].hit_count,
            1,
            msg="find_entry must increment hit_count on a hit.",
        )

    def test__nd_cache__find_entry_miss_sends_neighbor_solicitation(self) -> None:
        """
        Ensure a miss returns None and dispatches an ICMPv6 Neighbor
        Solicitation via 'stack.packet_handler' with the target IPv6
        as 'icmp6_ns_target_address'.
        """

        handler = MagicMock()
        with patch("pytcp.stack.nd_cache.stack.packet_handler", handler):
            result = self._cache.find_entry(
                ip6_address=Ip6Address("2001:db8::5"),
            )

        self.assertIsNone(
            result,
            msg="find_entry must return None on a miss.",
        )
        handler.send_icmp6_neighbor_solicitation.assert_called_once_with(
            icmp6_ns_target_address=Ip6Address("2001:db8::5"),
        )


class TestNdCacheRepr(_NdCacheFixture):
    """
    The 'NdCache.__repr__' formatting tests.
    """

    def test__nd_cache__repr_empty(self) -> None:
        """
        Ensure repr() of an empty cache is the repr of an empty dict.
        """

        self.assertEqual(
            repr(self._cache),
            "{}",
            msg="NdCache.__repr__ on an empty cache must be '{}'.",
        )

    def test__nd_cache__repr_contains_entry(self) -> None:
        """
        Ensure repr() surfaces added entries via the underlying dict.
        """

        self._cache.add_entry(
            ip6_address=Ip6Address("2001:db8::1"),
            mac_address=MacAddress("02:00:00:00:00:01"),
        )
        self.assertIn(
            "2001:db8::1",
            repr(self._cache),
            msg="NdCache.__repr__ must surface the stored IPv6 addresses.",
        )


class TestNdCacheSubsystemLoop(_NdCacheFixture):
    """
    The 'NdCache._subsystem_loop' maintenance tests.
    """

    def test__nd_cache__loop_skips_permanent_entry(self) -> None:
        """
        Ensure permanent entries are never aged out regardless of
        their apparent age.
        """

        import pytcp.stack as stack_module

        ip = Ip6Address("2001:db8::1")
        self._cache._nd_cache[ip] = CacheEntry(
            mac_address=MacAddress("02:00:00:00:00:01"),
            permanent=True,
        )

        with (
            patch("pytcp.stack.nd_cache.time.time", return_value=10_000_000),
            patch.object(
                self._cache._event__stop_subsystem,
                "wait",
                return_value=False,
            ),
            patch.object(
                stack_module,
                "ICMP6__ND__CACHE__ENTRY_MAX_AGE",
                1,
                create=True,
            ),
        ):
            self._cache._subsystem_loop()

        self.assertIn(
            ip,
            self._cache._nd_cache,
            msg="Permanent ND entries must not be aged out of the cache.",
        )

    def test__nd_cache__loop_expires_old_entry(self) -> None:
        """
        Ensure a non-permanent entry older than
        'ICMP6__ND__CACHE__ENTRY_MAX_AGE' is removed from the cache.
        """

        import pytcp.stack as stack_module

        ip = Ip6Address("2001:db8::1")
        with patch("pytcp.stack.nd_cache.time.time", return_value=1000):
            self._cache.add_entry(
                ip6_address=ip,
                mac_address=MacAddress("02:00:00:00:00:01"),
            )

        with (
            patch("pytcp.stack.nd_cache.time.time", return_value=10_000),
            patch.object(
                self._cache._event__stop_subsystem,
                "wait",
                return_value=False,
            ),
            patch.object(
                stack_module,
                "ICMP6__ND__CACHE__ENTRY_MAX_AGE",
                1,
                create=True,
            ),
        ):
            self._cache._subsystem_loop()

        self.assertNotIn(
            ip,
            self._cache._nd_cache,
            msg="Non-permanent entries older than ICMP6__ND__CACHE__ENTRY_MAX_AGE must be evicted.",
        )

    def test__nd_cache__loop_refreshes_near_expiry_used_entry(self) -> None:
        """
        Ensure an entry between 'MAX_AGE - REFRESH_TIME' and
        'MAX_AGE' with a non-zero hit_count triggers an ICMPv6
        Neighbor Solicitation and resets its hit_count.
        """

        import pytcp.stack as stack_module

        ip = Ip6Address("2001:db8::1")
        self._cache.add_entry(
            ip6_address=ip,
            mac_address=MacAddress("02:00:00:00:00:01"),
        )
        self._cache._nd_cache[ip].hit_count__increment()

        handler = MagicMock()

        with (
            patch(
                "pytcp.stack.nd_cache.time.time",
                side_effect=lambda: self._cache._nd_cache[ip].create_time + 5,
            ),
            patch.object(
                self._cache._event__stop_subsystem,
                "wait",
                return_value=False,
            ),
            patch.object(
                stack_module,
                "ICMP6__ND__CACHE__ENTRY_MAX_AGE",
                10,
                create=True,
            ),
            patch.object(
                stack_module,
                "ICMP6__ND__CACHE__ENTRY_REFRESH_TIME",
                8,
                create=True,
            ),
            patch("pytcp.stack.nd_cache.stack.packet_handler", handler),
        ):
            self._cache._subsystem_loop()

        handler.send_icmp6_neighbor_solicitation.assert_called_once_with(
            icmp6_ns_target_address=ip,
        )
        self.assertEqual(
            self._cache._nd_cache[ip].hit_count,
            0,
            msg="Refresh path must zero hit_count so the next window starts clean.",
        )
