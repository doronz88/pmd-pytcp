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
This module contains tests for the DHCPv6 client constants in
'pytcp/protocols/dhcp6/dhcp6__constants.py'.

pytcp/tests/unit/protocols/dhcp6/test__dhcp6__constants.py

ver 3.0.6
"""

from typing import override
from unittest import TestCase

from net_addr import Ip6Address
from pytcp.protocols.dhcp6 import dhcp6__constants
from pytcp.stack import sysctl


class TestDhcp6ConstantsInvariants(TestCase):
    """
    The RFC-pinned DHCPv6 invariant constants (ports, multicast group,
    randomization factor).
    """

    def test__dhcp6_constants__client_port(self) -> None:
        """
        Ensure the DHCPv6 client port is 546.

        Reference: RFC 8415 §7.2 (UDP port assignments).
        """

        self.assertEqual(dhcp6__constants.DHCP6__CLIENT_PORT, 546, msg="DHCPv6 client port must be 546.")

    def test__dhcp6_constants__server_port(self) -> None:
        """
        Ensure the DHCPv6 server port is 547.

        Reference: RFC 8415 §7.2 (UDP port assignments).
        """

        self.assertEqual(dhcp6__constants.DHCP6__SERVER_PORT, 547, msg="DHCPv6 server port must be 547.")

    def test__dhcp6_constants__all_dhcp_multicast(self) -> None:
        """
        Ensure the All_DHCP_Relay_Agents_and_Servers group is ff02::1:2.

        Reference: RFC 8415 §7.1 (multicast addresses).
        """

        self.assertEqual(
            dhcp6__constants.DHCP6__ALL_DHCP_RELAY_AGENTS_AND_SERVERS,
            Ip6Address("ff02::1:2"),
            msg="All_DHCP_Relay_Agents_and_Servers must be ff02::1:2.",
        )

    def test__dhcp6_constants__rand_factor(self) -> None:
        """
        Ensure the retransmission randomization factor magnitude is 0.1.

        Reference: RFC 8415 §15 (RAND in [-0.1, +0.1]).
        """

        self.assertEqual(dhcp6__constants.DHCP6__RAND_FACTOR, 0.1, msg="RAND factor magnitude must be 0.1.")


class TestDhcp6ConstantsDefaults(TestCase):
    """
    Defaults for every DHCPv6 sysctl knob registered by
    'dhcp6__constants.py'.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore every registered knob to its default so a knob mutated by a
        sibling test does not leak into the next test.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__dhcp6_constants__inf_timeout_ms_default(self) -> None:
        """
        Ensure 'dhcp6.inf_timeout_ms' defaults to 1000 ms (INF_TIMEOUT).

        Reference: RFC 8415 §7.6 (INF_TIMEOUT = 1 second).
        """

        self.assertEqual(sysctl.get("dhcp6.inf_timeout_ms"), 1000, msg="dhcp6.inf_timeout_ms must default to 1000.")
        self.assertEqual(
            dhcp6__constants.DHCP6__INF_TIMEOUT_MS, 1000, msg="The module attribute must match the sysctl default."
        )

    def test__dhcp6_constants__inf_max_rt_ms_default(self) -> None:
        """
        Ensure 'dhcp6.inf_max_rt_ms' defaults to 3600000 ms (INF_MAX_RT).

        Reference: RFC 8415 §7.6 (INF_MAX_RT = 3600 seconds).
        """

        self.assertEqual(sysctl.get("dhcp6.inf_max_rt_ms"), 3600000, msg="dhcp6.inf_max_rt_ms must default to 3600000.")

    def test__dhcp6_constants__inf_max_delay_ms_default(self) -> None:
        """
        Ensure 'dhcp6.inf_max_delay_ms' defaults to 1000 ms (INF_MAX_DELAY).

        Reference: RFC 8415 §7.6 (INF_MAX_DELAY = 1 second).
        """

        self.assertEqual(sysctl.get("dhcp6.inf_max_delay_ms"), 1000, msg="dhcp6.inf_max_delay_ms must default to 1000.")

    def test__dhcp6_constants__retrans_max_attempts_default(self) -> None:
        """
        Ensure 'dhcp6.retrans_max_attempts' defaults to 5 recv attempts.

        Reference: RFC 8415 §7.6 (INF MRC/MRD = 0; PyTCP bounds the recv loop).
        """

        self.assertEqual(
            sysctl.get("dhcp6.retrans_max_attempts"), 5, msg="dhcp6.retrans_max_attempts must default to 5."
        )


class TestDhcp6ConstantsValidators(TestCase):
    """
    Validator rejection for the DHCPv6 sysctl knobs.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore every registered knob to its default after each test.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__dhcp6_constants__inf_timeout_ms_rejects_zero(self) -> None:
        """
        Ensure 'dhcp6.inf_timeout_ms' rejects a non-positive value.

        Reference: RFC 8415 §7.6 (INF_TIMEOUT must be a positive duration).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp6.inf_timeout_ms", 0)

    def test__dhcp6_constants__retrans_max_attempts_rejects_zero(self) -> None:
        """
        Ensure 'dhcp6.retrans_max_attempts' rejects a non-positive value.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp6.retrans_max_attempts", 0)

    def test__dhcp6_constants__inf_max_delay_ms_rejects_negative(self) -> None:
        """
        Ensure 'dhcp6.inf_max_delay_ms' rejects a negative value but accepts 0.

        Reference: RFC 8415 §18.2.6 (INF_MAX_DELAY ≥ 0; 0 transmits immediately).
        """

        with self.assertRaises(ValueError):
            sysctl.set("dhcp6.inf_max_delay_ms", -1)

        sysctl.set("dhcp6.inf_max_delay_ms", 0)  # must not raise

        self.assertEqual(sysctl.get("dhcp6.inf_max_delay_ms"), 0, msg="dhcp6.inf_max_delay_ms must accept 0.")


class TestDhcp6ConstantsFinalize(TestCase):
    """
    The DHCPv6 cross-knob finalize validator.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore every registered knob to its default after each test.
        """

        sysctl.reset_to_defaults()
        super().tearDown()

    def test__dhcp6_constants__finalize_rejects_timeout_greater_than_max_rt(self) -> None:
        """
        Ensure 'finalize_validators()' raises when 'dhcp6.inf_timeout_ms'
        exceeds 'dhcp6.inf_max_rt_ms' (IRT must not exceed MRT).

        Reference: RFC 8415 §15 (doubled-and-capped retransmission backoff).
        """

        sysctl.set("dhcp6.inf_max_rt_ms", 500)
        sysctl.set("dhcp6.inf_timeout_ms", 1000)

        with self.assertRaises(ValueError):
            sysctl.finalize_validators()

    def test__dhcp6_constants__finalize_accepts_equal_timeout_and_max_rt(self) -> None:
        """
        Ensure 'finalize_validators()' accepts the boundary case where
        'dhcp6.inf_timeout_ms' equals 'dhcp6.inf_max_rt_ms'.

        Reference: RFC 8415 §15 (doubled-and-capped retransmission backoff).
        """

        sysctl.set("dhcp6.inf_max_rt_ms", 1000)
        sysctl.set("dhcp6.inf_timeout_ms", 1000)

        sysctl.finalize_validators()  # must not raise
