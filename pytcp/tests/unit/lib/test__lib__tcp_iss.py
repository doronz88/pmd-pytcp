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
This module contains unit tests for the RFC 6528 §3 Initial Sequence
Number generator in 'pytcp/lib/tcp_iss.py'.

RFC 6528 §3 mandates a hash-based ISN to defend against blind
sequence-number prediction attacks:

    ISN = M + F(localip, localport, remoteip, remoteport, secretkey)

The tests in this file are tests-first: they assert the RFC 6528
properties against the planned implementation. Until the fix
commit replaces the 'NotImplementedError' stub with the actual
SHA-256-based hash, every test fails with NotImplementedError -
the unambiguous '[FLAGS BUG]' signal that the feature is not yet
shipped.

Reference RFCs:
    RFC 6528 §3   Defending Against Sequence Number Attacks
    RFC 1948      Defending Against Sequence Number Attacks (orig)

pytcp/tests/unit/lib/test__lib__tcp_iss.py

ver 3.0.4
"""

from unittest import TestCase

from net_addr import Ip4Address, Ip6Address
from pytcp.lib.tcp_iss import ISS_CLOCK_RATE_US, compute_iss

# A fixed test secret (NOT for production; tests pin a known value
# so outputs are deterministic and known-vector tests are
# reproducible across runs).
TEST_SECRET: bytes = b"\x00" * 16

# Two arbitrary 4-tuples used across the test class to vary one
# component at a time. The fixed shape:
#   local 10.0.0.1:12345 <-> remote 10.0.0.2:80
TEST_LOCAL_IP4: Ip4Address = Ip4Address("10.0.0.1")
TEST_LOCAL_PORT: int = 12345
TEST_REMOTE_IP4: Ip4Address = Ip4Address("10.0.0.2")
TEST_REMOTE_PORT: int = 80


class TestComputeIss(TestCase):
    """
    Unit tests for 'compute_iss' covering the RFC 6528 §3
    determinism, distinguishability, time-driven, and bit-range
    invariants.
    """

    def test__compute_iss__same_args_same_iss(self) -> None:
        """
        [FLAGS BUG]

        Ensure 'compute_iss' is deterministic: identical inputs
        produce identical outputs. RFC 6528 §3 requires the hash
        component F to be a pure function of its arguments;
        without determinism, blind-attack defence is no stronger
        than the legacy 'random.randint' approach because peer
        retransmits couldn't even reach a stable target.
        """

        first = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )
        second = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertEqual(
            first,
            second,
            msg="compute_iss must be deterministic for identical inputs.",
        )

    def test__compute_iss__different_local_address__different_iss(self) -> None:
        """
        [FLAGS BUG]

        Ensure changing the local address changes the ISS. RFC 6528
        §3 binds ISN to the full 4-tuple so an attacker who learns
        one ISN cannot predict ISNs for any other 4-tuple.
        """

        first = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )
        second = compute_iss(
            Ip4Address("10.0.0.99"),
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertNotEqual(
            first,
            second,
            msg=("compute_iss must distinguish different local addresses " "(RFC 6528 §3 4-tuple binding)."),
        )

    def test__compute_iss__different_remote_address__different_iss(self) -> None:
        """
        [FLAGS BUG]

        Ensure changing the remote address changes the ISS.
        Symmetric to the local-address case.
        """

        first = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )
        second = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            Ip4Address("10.0.0.99"),
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertNotEqual(
            first,
            second,
            msg=("compute_iss must distinguish different remote addresses " "(RFC 6528 §3 4-tuple binding)."),
        )

    def test__compute_iss__different_local_port__different_iss(self) -> None:
        """
        [FLAGS BUG]

        Ensure changing the local port changes the ISS.
        """

        first = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )
        second = compute_iss(
            TEST_LOCAL_IP4,
            54321,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertNotEqual(
            first,
            second,
            msg="compute_iss must distinguish different local ports.",
        )

    def test__compute_iss__different_remote_port__different_iss(self) -> None:
        """
        [FLAGS BUG]

        Ensure changing the remote port changes the ISS.
        """

        first = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )
        second = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            8080,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertNotEqual(
            first,
            second,
            msg="compute_iss must distinguish different remote ports.",
        )

    def test__compute_iss__different_secret__different_iss(self) -> None:
        """
        [FLAGS BUG]

        Ensure changing the secret changes the ISS. The secret is
        the load-bearing keying material for RFC 6528 §3's PRF F;
        without secret-dependence an attacker could compute ISNs
        for any 4-tuple just by knowing the algorithm.
        """

        first = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            b"\x00" * 16,
            clock_us=0,
        )
        second = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            b"\xff" * 16,
            clock_us=0,
        )

        self.assertNotEqual(
            first,
            second,
            msg=(
                "compute_iss must distinguish different secrets - the "
                "PRF F's keying material is load-bearing for RFC 6528 §3."
            ),
        )

    def test__compute_iss__output_is_uint32(self) -> None:
        """
        [FLAGS BUG]

        Ensure 'compute_iss' returns a value within the 32-bit
        unsigned integer range '[0, 2**32 - 1]'. TCP sequence
        numbers are 32-bit (RFC 9293 §3.4); a return value
        outside the range would corrupt outbound segment
        construction.
        """

        result = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertGreaterEqual(
            result,
            0,
            msg="compute_iss output must be >= 0 (32-bit unsigned).",
        )
        self.assertLess(
            result,
            2**32,
            msg=f"compute_iss output must be < 2**32; got {result}.",
        )

    def test__compute_iss__monotonic_in_clock_us(self) -> None:
        """
        [FLAGS BUG]

        Ensure the time-driven 'M' component of the ISN advances
        with 'clock_us' per RFC 6528 §3. Specifically, two ISN
        values for the same 4-tuple computed at clocks differing
        by 'delta_us' must differ by 'delta_us / ISS_CLOCK_RATE_US'
        (modulo the 32-bit wrap), because M advances one tick
        per ISS_CLOCK_RATE_US µs and F is identical for identical
        4-tuples.

        The delta uses 32 ticks so the test is robust to the M
        component's resolution while still well below the 32-bit
        wrap window (~4.77 h).
        """

        delta_ticks = 32
        delta_us = delta_ticks * ISS_CLOCK_RATE_US

        iss_t0 = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )
        iss_t1 = compute_iss(
            TEST_LOCAL_IP4,
            TEST_LOCAL_PORT,
            TEST_REMOTE_IP4,
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=delta_us,
        )

        observed_delta = (iss_t1 - iss_t0) & 0xFFFF_FFFF

        self.assertEqual(
            observed_delta,
            delta_ticks,
            msg=(
                f"compute_iss M-component must advance one tick per "
                f"{ISS_CLOCK_RATE_US} µs of 'clock_us'; expected delta of "
                f"{delta_ticks} ticks for {delta_us} µs of clock advance, "
                f"got {observed_delta}."
            ),
        )

    def test__compute_iss__different_4tuple_at_same_clock_yields_different_iss(self) -> None:
        """
        [FLAGS BUG]

        Ensure that for a SAME clock value, two unrelated 4-tuples
        produce different ISN values. This is the 4-tuple-binding
        property in aggregate: the F component must dominate the
        ISN bits (the M component is identical when clocks match,
        so any difference between two ISNs at the same clock
        comes entirely from F).
        """

        iss_a = compute_iss(
            Ip4Address("10.0.0.1"),
            11111,
            Ip4Address("10.0.0.2"),
            22222,
            TEST_SECRET,
            clock_us=1234,
        )
        iss_b = compute_iss(
            Ip4Address("10.0.0.3"),
            33333,
            Ip4Address("10.0.0.4"),
            44444,
            TEST_SECRET,
            clock_us=1234,
        )

        self.assertNotEqual(
            iss_a,
            iss_b,
            msg=("Two distinct 4-tuples at the same clock must yield " "different ISN values (F component must vary)."),
        )

    def test__compute_iss__ip6_addresses_supported(self) -> None:
        """
        [FLAGS BUG]

        Ensure 'compute_iss' accepts IPv6 addresses for both
        local and remote endpoints. PyTCP supports both address
        families; the ISN generator must too.
        """

        result = compute_iss(
            Ip6Address("2001:db8::1"),
            TEST_LOCAL_PORT,
            Ip6Address("2001:db8::2"),
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertGreaterEqual(result, 0)
        self.assertLess(result, 2**32)

    def test__compute_iss__ip4_and_ip6_for_same_logical_4tuple_differ(self) -> None:
        """
        [FLAGS BUG]

        Ensure an IPv4 4-tuple and a (notional) IPv6 4-tuple
        with the "same" port shape produce different ISNs. The
        binding includes the address bytes, not just an
        abstract identity, so a host running parallel IPv4 / IPv6
        services on the same port pair MUST get different ISNs
        per address family.
        """

        iss_v4 = compute_iss(
            Ip4Address("10.0.0.1"),
            TEST_LOCAL_PORT,
            Ip4Address("10.0.0.2"),
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )
        iss_v6 = compute_iss(
            Ip6Address("2001:db8::1"),
            TEST_LOCAL_PORT,
            Ip6Address("2001:db8::2"),
            TEST_REMOTE_PORT,
            TEST_SECRET,
            clock_us=0,
        )

        self.assertNotEqual(
            iss_v4,
            iss_v6,
            msg=(
                "IPv4 and IPv6 'same-shape' 4-tuples must produce "
                "different ISNs - the binding includes address bytes."
            ),
        )
