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
This module contains integration tests for the RFC 3376 §5.1
robustness retransmission of the IGMP state-change Report.

net_proto/../pytcp/tests/integration/protocols/igmp/test__igmp__robustness_retransmit.py

ver 3.0.6
"""

from unittest.mock import patch

from net_addr import Ip4Address
from pytcp.stack import sysctl
from pytcp.tests.lib.icmp_testcase import IcmpTestCase


class TestIgmpRobustnessRetransmit(IcmpTestCase):
    """
    The IGMP state-change-Report robustness-retransmit tests.
    """

    def _patch_retransmit_delay(self, *, delay_ms: int) -> None:
        """Force the retransmit interval draw to a deterministic value."""

        self.enterContext(
            patch(
                "pytcp.runtime.packet_handler.packet_handler__igmp__tx.random.randint",
                return_value=delay_ms,
            )
        )

    def test__igmp__retransmit__default_robustness_sends_one_repeat(self) -> None:
        """
        Ensure the default Robustness Variable of 2 schedules exactly one
        retransmit of the state-change Report, firing after the chosen
        Unsolicited-Report-Interval delay.

        Reference: RFC 3376 §5.1 (state-change Report sent RV times).
        Reference: RFC 3376 §8.1 (Robustness Variable default 2).
        """

        self._patch_retransmit_delay(delay_ms=200)

        before = len(self._frames_tx)
        self._packet_handler._assign_ip4_multicast(Ip4Address("239.1.1.1"))

        self.assertEqual(
            len(self._frames_tx[before:]),
            1,
            msg="The join must emit one immediate state-change Report.",
        )
        self.assertEqual(len(self._advance(ms=199)), 0, msg="The retransmit must not fire before its delay.")

        tx_fire = self._advance(ms=1)
        self.assertEqual(len(tx_fire), 1, msg="The single robustness retransmit must fire at the delay.")

    def test__igmp__retransmit__robustness_three_sends_two_repeats(self) -> None:
        """
        Ensure raising 'igmp.robustness' to 3 schedules two retransmits.

        Reference: RFC 3376 §5.1 (RV-1 retransmits of the state-change Report).
        Reference: RFC 3376 §8.1 (Robustness Variable).
        """

        self._patch_retransmit_delay(delay_ms=200)

        with sysctl.override("igmp.robustness", 3):
            before = len(self._frames_tx)
            self._packet_handler._assign_ip4_multicast(Ip4Address("239.1.1.1"))

            # One immediate Report, then two retransmits both scheduled
            # at the patched 200 ms delay.
            self.assertEqual(len(self._frames_tx[before:]), 1, msg="One immediate Report.")
            tx_fire = self._advance(ms=200)
            self.assertEqual(len(tx_fire), 2, msg="Two robustness retransmits must fire (RV-1 = 2).")

    def test__igmp__retransmit__robustness_one_sends_no_repeat(self) -> None:
        """
        Ensure 'igmp.robustness' = 1 sends only the immediate Report and
        schedules no retransmit.

        Reference: RFC 3376 §5.1 (RV total transmissions).
        """

        self._patch_retransmit_delay(delay_ms=200)

        with sysctl.override("igmp.robustness", 1):
            before = len(self._frames_tx)
            self._packet_handler._assign_ip4_multicast(Ip4Address("239.1.1.1"))

            self.assertEqual(len(self._frames_tx[before:]), 1, msg="One immediate Report only.")
            self.assertEqual(len(self._advance(ms=5000)), 0, msg="RV=1 must schedule no retransmit.")
