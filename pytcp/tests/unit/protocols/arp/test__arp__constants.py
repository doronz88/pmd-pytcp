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
Unit tests for the ARP runtime configuration constants
('pytcp/protocols/arp/arp__constants.py').

pytcp/tests/unit/protocols/arp/test__arp__constants.py

ver 3.0.4
"""

from unittest import TestCase

from pytcp.protocols.arp.arp__constants import (
    ARP__ANNOUNCE_INTERVAL,
    ARP__ANNOUNCE_NUM,
    ARP__CACHE__ENTRY_MAX_AGE,
    ARP__CACHE__ENTRY_REFRESH_TIME,
    ARP__DEFEND_INTERVAL,
    ARP__REQUEST_RATE_LIMIT,
)


class TestArpConstants(TestCase):
    """
    The ARP runtime-configuration constants tests.
    """

    def test__arp__constants__cache_timers_are_positive(self) -> None:
        """
        Ensure the ARP cache maximum age and refresh window are
        both positive, with refresh time strictly less than max
        age — the invariant the refresh-path arithmetic in
        'ArpCache._subsystem_loop' relies on.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertGreater(
            ARP__CACHE__ENTRY_MAX_AGE,
            0,
            msg="ARP__CACHE__ENTRY_MAX_AGE must be positive.",
        )
        self.assertGreater(
            ARP__CACHE__ENTRY_REFRESH_TIME,
            0,
            msg="ARP__CACHE__ENTRY_REFRESH_TIME must be positive.",
        )
        self.assertLess(
            ARP__CACHE__ENTRY_REFRESH_TIME,
            ARP__CACHE__ENTRY_MAX_AGE,
            msg="REFRESH_TIME < MAX_AGE is required by the refresh-window arithmetic.",
        )

    def test__arp__constants__defend_interval_matches_rfc_5227(self) -> None:
        """
        Ensure 'ARP__DEFEND_INTERVAL' equals 10 seconds — the
        defensive-ARP rate-limit window. Pinning the constant
        catches a regression that would silently weaken (or
        strengthen) the conflict-defense rate-limit.

        Reference: RFC 5227 §1.1 (DEFEND_INTERVAL = 10 seconds).
        """

        self.assertEqual(
            ARP__DEFEND_INTERVAL,
            10,
            msg=f"DEFEND_INTERVAL must equal 10 s. Got: {ARP__DEFEND_INTERVAL}.",
        )

    def test__arp__constants__request_rate_limit_matches_rfc_1122(self) -> None:
        """
        Ensure 'ARP__REQUEST_RATE_LIMIT' equals 1 second — the
        recommended max of 1 ARP Request per second per
        destination.

        Reference: RFC 1122 §2.3.2.1 (max 1 Request/sec/destination).
        """

        self.assertEqual(
            ARP__REQUEST_RATE_LIMIT,
            1,
            msg=f"REQUEST_RATE_LIMIT must equal 1 s. Got: {ARP__REQUEST_RATE_LIMIT}.",
        )

    def test__arp__constants__announce_num_matches_rfc_5227(self) -> None:
        """
        Ensure 'ARP__ANNOUNCE_NUM' equals 2 — Announcements per
        successful DAD claim.

        Reference: RFC 5227 §1.1 (ANNOUNCE_NUM = 2).
        """

        self.assertEqual(
            ARP__ANNOUNCE_NUM,
            2,
            msg=f"ANNOUNCE_NUM must equal 2. Got: {ARP__ANNOUNCE_NUM}.",
        )

    def test__arp__constants__announce_interval_matches_rfc_5227(self) -> None:
        """
        Ensure 'ARP__ANNOUNCE_INTERVAL' equals 2 seconds — the
        spacing between back-to-back Announcements.

        Reference: RFC 5227 §1.1 (ANNOUNCE_INTERVAL = 2 seconds).
        """

        self.assertEqual(
            ARP__ANNOUNCE_INTERVAL,
            2,
            msg=f"ANNOUNCE_INTERVAL must equal 2 s. Got: {ARP__ANNOUNCE_INTERVAL}.",
        )
