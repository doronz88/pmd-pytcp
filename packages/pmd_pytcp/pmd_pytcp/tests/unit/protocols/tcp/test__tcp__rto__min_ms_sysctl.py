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
Unit tests for the 'tcp.rto.min_ms' sysctl — the operator-tunable
RFC 6298 §2.4 lower bound consumed by 'tcp__rto.clamp_rto'.

pmd_pytcp/tests/unit/protocols/tcp/test__tcp__rto__min_ms_sysctl.py

ver 3.0.7
"""

from __future__ import annotations

from unittest import TestCase

from pmd_pytcp.protocols.tcp import tcp__constants
from pmd_pytcp.protocols.tcp.tcp__rto import MAX_RTO_MS, clamp_rto


class TestClampRto__MinMsSysctl(TestCase):
    """
    'clamp_rto' against the 'tcp.rto.min_ms' backing attribute.
    """

    def setUp(self) -> None:
        """
        Snapshot and restore the sysctl-backed floor around each
        test so the module-level knob never leaks across tests.
        """

        self._saved = tcp__constants.TCP__RTO__MIN_MS
        self.addCleanup(setattr, tcp__constants, "TCP__RTO__MIN_MS", self._saved)

    def test__rto__default_floor_is_rfc_1000ms(self) -> None:
        """
        Ensure the untouched default keeps the RFC 6298 §2.4
        SHOULD of a 1 s floor — stock behaviour is unchanged.
        """

        self.assertEqual(
            clamp_rto(1),
            1000,
            msg="With the default floor a sub-second RTO MUST clamp up to 1000 ms.",
        )

    def test__rto__lowered_floor_is_honoured(self) -> None:
        """
        Ensure a lowered 'tcp.rto.min_ms' (the Linux-style 200 ms
        floor for known-low-RTT paths) is honoured by the clamp —
        this is what makes PLPMTUD black-hole reverts cost ~RTT
        scale instead of a fixed second on tunnel transports.
        """

        tcp__constants.TCP__RTO__MIN_MS = 200

        self.assertEqual(
            clamp_rto(1),
            200,
            msg="A lowered tcp.rto.min_ms MUST become the clamp floor.",
        )
        self.assertEqual(
            clamp_rto(750),
            750,
            msg="Values between the lowered floor and MAX_RTO_MS MUST pass through.",
        )

    def test__rto__upper_bound_unchanged(self) -> None:
        """
        Ensure the §2.5 upper bound still applies regardless of
        the floor setting.
        """

        tcp__constants.TCP__RTO__MIN_MS = 200

        self.assertEqual(
            clamp_rto(10**9),
            MAX_RTO_MS,
            msg="The MAX_RTO_MS ceiling MUST be unaffected by the floor knob.",
        )

    def test__rto__sysctl_is_registered(self) -> None:
        """
        Ensure the knob is actually reachable through the sysctl
        registry (the operator surface pymobiledevice3 uses via
        'stack.init(sysctls={"tcp.rto.min_ms": ...})').
        """

        from pmd_pytcp.stack import sysctl

        self.assertIn(
            "tcp.rto.min_ms",
            sysctl.list_keys(),
            msg="'tcp.rto.min_ms' MUST be registered in the sysctl registry.",
        )
