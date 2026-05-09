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
    ARP__ANNOUNCE_WAIT,
    ARP__DEFEND_INTERVAL,
    ARP__PROBE_MAX,
    ARP__PROBE_MIN,
    ARP__PROBE_NUM,
    ARP__PROBE_WAIT,
)


class TestArpConstants(TestCase):
    """
    The ARP runtime-configuration constants tests.
    """

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

    def test__arp__constants__announce_wait_matches_rfc_5227(self) -> None:
        """
        Ensure 'ARP__ANNOUNCE_WAIT' equals 2 seconds — the
        post-probe quiet period during which a late conflicting
        ARP can still abort the claim before the first
        Announcement is emitted.

        Reference: RFC 5227 §1.1 (ANNOUNCE_WAIT = 2 seconds).
        """

        self.assertEqual(
            ARP__ANNOUNCE_WAIT,
            2,
            msg=f"ANNOUNCE_WAIT must equal 2 s. Got: {ARP__ANNOUNCE_WAIT}.",
        )

    def test__arp__constants__probe_wait_matches_rfc_5227(self) -> None:
        """
        Ensure 'ARP__PROBE_WAIT' equals 1 second — the upper
        bound of the initial random delay before the first
        ARP Probe.

        Reference: RFC 5227 §1.1 (PROBE_WAIT = 1 second).
        """

        self.assertEqual(
            ARP__PROBE_WAIT,
            1,
            msg=f"PROBE_WAIT must equal 1 s. Got: {ARP__PROBE_WAIT}.",
        )

    def test__arp__constants__probe_num_matches_rfc_5227(self) -> None:
        """
        Ensure 'ARP__PROBE_NUM' equals 3 — number of ARP
        Probes broadcast per candidate during DAD.

        Reference: RFC 5227 §1.1 (PROBE_NUM = 3).
        """

        self.assertEqual(
            ARP__PROBE_NUM,
            3,
            msg=f"PROBE_NUM must equal 3. Got: {ARP__PROBE_NUM}.",
        )

    def test__arp__constants__probe_min_max_window(self) -> None:
        """
        Ensure 'ARP__PROBE_MIN' equals 1 second and
        'ARP__PROBE_MAX' equals 2 seconds, with MIN < MAX so
        the uniform-random spacing produces a non-degenerate
        distribution.

        Reference: RFC 5227 §1.1 (PROBE_MIN = 1 s, PROBE_MAX = 2 s).
        """

        self.assertEqual(
            ARP__PROBE_MIN,
            1,
            msg=f"PROBE_MIN must equal 1 s. Got: {ARP__PROBE_MIN}.",
        )
        self.assertEqual(
            ARP__PROBE_MAX,
            2,
            msg=f"PROBE_MAX must equal 2 s. Got: {ARP__PROBE_MAX}.",
        )
        self.assertLess(
            ARP__PROBE_MIN,
            ARP__PROBE_MAX,
            msg="PROBE_MIN < PROBE_MAX is required by random.uniform.",
        )
