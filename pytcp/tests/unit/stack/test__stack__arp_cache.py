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
This module contains tests for the 'ArpCache' subsystem and its
'CacheEntry' helper.

pytcp/tests/unit/stack/test__stack__arp_cache.py

ver 3.0.4
"""


from dataclasses import FrozenInstanceError
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, MacAddress
from pytcp.stack.arp_cache import ArpCache, CacheEntry


class TestArpCacheEntry(TestCase):
    """
    The 'CacheEntry' hit-count and immutability tests.
    """

    def test__arp_cache__entry_defaults(self) -> None:
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

    def test__arp_cache__entry_hit_count_increment(self) -> None:
        """
        Ensure 'hit_count__increment' bumps 'hit_count' by 1, even
        though the dataclass is frozen — the method uses
        'object.__setattr__' to bypass the freeze.
        """

        entry = CacheEntry(mac_address=MacAddress("02:00:00:00:00:01"))
        entry.hit_count__increment()
        entry.hit_count__increment()
        self.assertEqual(
            entry.hit_count,
            2,
            msg="hit_count__increment must add 1 per call.",
        )

    def test__arp_cache__entry_hit_count_reset(self) -> None:
        """
        Ensure 'hit_count__reset' zeroes 'hit_count' after any number
        of prior increments.
        """

        entry = CacheEntry(mac_address=MacAddress("02:00:00:00:00:01"))
        entry.hit_count__increment()
        entry.hit_count__increment()
        entry.hit_count__reset()
        self.assertEqual(
            entry.hit_count,
            0,
            msg="hit_count__reset must zero the hit_count counter.",
        )

    def test__arp_cache__entry_is_frozen(self) -> None:
        """
        Ensure normal attribute assignment (without
        'object.__setattr__') is blocked by 'frozen=True'.
        """

        entry = CacheEntry(mac_address=MacAddress("02:00:00:00:00:01"))
        with self.assertRaises(FrozenInstanceError):
            entry.mac_address = MacAddress("02:00:00:00:00:02")  # type: ignore[misc]


class _ArpCacheFixture(TestCase):
    """
    Shared fixture: patches the module-level 'log' and provides a
    fresh 'ArpCache'.
    """

    def setUp(self) -> None:
        """
        Install the log patches and build the cache.
        """

        self._log_patch = patch("pytcp.stack.arp_cache.log")
        self._log_patch.start()
        self._subsystem_log_patch = patch("pytcp.lib.subsystem.log")
        self._subsystem_log_patch.start()
        self._cache = ArpCache()

    def tearDown(self) -> None:
        """
        Remove the log patches.
        """

        self._log_patch.stop()
        self._subsystem_log_patch.stop()


class TestArpCacheAddFind(_ArpCacheFixture):
    """
    The 'ArpCache.add_entry' / 'ArpCache.find_entry' happy-path tests.
    """

    def test__arp_cache__add_entry_stores_mac(self) -> None:
        """
        Ensure 'add_entry' inserts a 'CacheEntry' keyed by the IP
        address, with the supplied MAC.
        """

        self._cache.add_entry(
            ip4_address=Ip4Address("10.0.0.1"),
            mac_address=MacAddress("02:00:00:00:00:01"),
        )
        entry = self._cache._arp_cache[Ip4Address("10.0.0.1")]
        self.assertEqual(
            entry.mac_address,
            MacAddress("02:00:00:00:00:01"),
            msg="add_entry must store the MAC address on the CacheEntry.",
        )

    def test__arp_cache__add_entry_overwrites(self) -> None:
        """
        Ensure calling 'add_entry' twice on the same IP replaces the
        old entry with a fresh one — creating a new CacheEntry per
        call is how refreshes happen.
        """

        self._cache.add_entry(
            ip4_address=Ip4Address("10.0.0.1"),
            mac_address=MacAddress("02:00:00:00:00:01"),
        )
        self._cache.add_entry(
            ip4_address=Ip4Address("10.0.0.1"),
            mac_address=MacAddress("02:00:00:00:00:02"),
        )
        self.assertEqual(
            self._cache._arp_cache[Ip4Address("10.0.0.1")].mac_address,
            MacAddress("02:00:00:00:00:02"),
            msg="A second add_entry call must overwrite the prior MAC.",
        )

    def test__arp_cache__find_entry_returns_mac_and_increments_hit(self) -> None:
        """
        Ensure 'find_entry' returns the stored MAC and increments the
        hit counter — the counter drives the refresh logic in the
        background maintenance loop.
        """

        self._cache.add_entry(
            ip4_address=Ip4Address("10.0.0.1"),
            mac_address=MacAddress("02:00:00:00:00:01"),
        )
        result = self._cache.find_entry(ip4_address=Ip4Address("10.0.0.1"))
        self.assertEqual(
            result,
            MacAddress("02:00:00:00:00:01"),
            msg="find_entry must return the stored MAC address for a hit.",
        )
        self.assertEqual(
            self._cache._arp_cache[Ip4Address("10.0.0.1")].hit_count,
            1,
            msg="find_entry must increment the CacheEntry hit_count on a hit.",
        )

    def test__arp_cache__find_entry_miss_sends_arp_request(self) -> None:
        """
        Ensure a miss returns None and dispatches an ARP request via
        'stack.packet_handler.send_arp_request' with the target IP as
        'arp__tpa'.
        """

        from pytcp.stack.packet_handler import PacketHandlerL2

        handler = MagicMock(spec=PacketHandlerL2)
        with patch("pytcp.stack.arp_cache.stack.packet_handler", handler):
            result = self._cache.find_entry(ip4_address=Ip4Address("10.0.0.5"))

        self.assertIsNone(
            result,
            msg="find_entry must return None on a miss.",
        )
        handler.send_arp_request.assert_called_once_with(
            arp__tpa=Ip4Address("10.0.0.5"),
        )


class TestArpCacheRepr(_ArpCacheFixture):
    """
    The 'ArpCache.__repr__' formatting tests.
    """

    def test__arp_cache__repr_empty(self) -> None:
        """
        Ensure repr() of an empty cache is the repr of an empty dict
        — repr delegates directly to the underlying mapping.
        """

        self.assertEqual(
            repr(self._cache),
            "{}",
            msg="ArpCache.__repr__ on an empty cache must be '{}'.",
        )

    def test__arp_cache__repr_contains_entry(self) -> None:
        """
        Ensure repr() shows the added entries by delegating to the
        underlying dict.
        """

        self._cache.add_entry(
            ip4_address=Ip4Address("10.0.0.1"),
            mac_address=MacAddress("02:00:00:00:00:01"),
        )
        rendered = repr(self._cache)
        self.assertIn(
            "10.0.0.1",
            rendered,
            msg="ArpCache.__repr__ must surface the stored IP addresses.",
        )


class TestArpCacheSubsystemLoop(_ArpCacheFixture):
    """
    The 'ArpCache._subsystem_loop' maintenance tests.
    """

    def test__arp_cache__loop_skips_permanent_entry(self) -> None:
        """
        Ensure permanent entries are never aged out regardless of how
        old they look. 'permanent' is the escape hatch for statically
        configured neighbors.
        """

        import pytcp.stack as stack_module
        from net_addr import MacAddress

        ip = Ip4Address("10.0.0.1")
        self._cache._arp_cache[ip] = CacheEntry(
            mac_address=MacAddress("02:00:00:00:00:01"),
            permanent=True,
        )

        # Force the entry's age to be > max age.
        with (
            patch("pytcp.stack.arp_cache.time.time", return_value=10_000_000),
            patch.object(
                self._cache._event__stop_subsystem,
                "wait",
                return_value=False,
            ),
            patch.object(
                stack_module,
                "ARP__CACHE__ENTRY_MAX_AGE",
                1,
                create=True,
            ),
        ):
            self._cache._subsystem_loop()

        self.assertIn(
            ip,
            self._cache._arp_cache,
            msg="Permanent ARP entries must not be aged out of the cache.",
        )

    def test__arp_cache__loop_expires_old_entry(self) -> None:
        """
        Ensure a non-permanent entry older than
        'ARP__CACHE__ENTRY_MAX_AGE' is removed from the cache.
        """

        import pytcp.stack as stack_module

        ip = Ip4Address("10.0.0.1")
        # Build the entry at t=1000, then advance the clock to t=10000.
        with patch("pytcp.stack.arp_cache.time.time", return_value=1000):
            self._cache.add_entry(
                ip4_address=ip,
                mac_address=MacAddress("02:00:00:00:00:01"),
            )

        with (
            patch("pytcp.stack.arp_cache.time.time", return_value=10_000),
            patch.object(
                self._cache._event__stop_subsystem,
                "wait",
                return_value=False,
            ),
            patch.object(
                stack_module,
                "ARP__CACHE__ENTRY_MAX_AGE",
                1,
                create=True,
            ),
        ):
            self._cache._subsystem_loop()

        self.assertNotIn(
            ip,
            self._cache._arp_cache,
            msg="Non-permanent entries older than ARP__CACHE__ENTRY_MAX_AGE must be evicted.",
        )

    def test__arp_cache__loop_refreshes_near_expiry_used_entry(self) -> None:
        """
        Ensure an entry that is between 'MAX_AGE - REFRESH_TIME' and
        'MAX_AGE' and has a non-zero hit_count triggers an ARP request
        to refresh it, and resets its hit_count.
        """

        import pytcp.stack as stack_module
        from pytcp.stack.packet_handler import PacketHandlerL2

        ip = Ip4Address("10.0.0.1")
        self._cache.add_entry(
            ip4_address=ip,
            mac_address=MacAddress("02:00:00:00:00:01"),
        )
        # Simulate the entry having been hit since last refresh.
        self._cache._arp_cache[ip].hit_count__increment()

        handler = MagicMock(spec=PacketHandlerL2)

        # Age between (MAX_AGE - REFRESH_TIME)=2 and MAX_AGE=10 -> force 5.
        with (
            patch(
                "pytcp.stack.arp_cache.time.time",
                side_effect=lambda: self._cache._arp_cache[ip].create_time + 5,
            ),
            patch.object(
                self._cache._event__stop_subsystem,
                "wait",
                return_value=False,
            ),
            patch.object(
                stack_module,
                "ARP__CACHE__ENTRY_MAX_AGE",
                10,
                create=True,
            ),
            patch.object(
                stack_module,
                "ARP__CACHE__ENTRY_REFRESH_TIME",
                8,
                create=True,
            ),
            patch("pytcp.stack.arp_cache.stack.packet_handler", handler),
        ):
            self._cache._subsystem_loop()

        handler.send_arp_request.assert_called_once_with(arp__tpa=ip)
        self.assertEqual(
            self._cache._arp_cache[ip].hit_count,
            0,
            msg="Refresh path must zero hit_count so the next window starts clean.",
        )
