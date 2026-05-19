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
Module contains tests for the ICMPv4 packet assembler miscellaneous functions.

net_proto/tests/unit/protocols/icmp4/test__icmp4__assembler__misc.py

ver 3.0.6
"""

from unittest import TestCase

from net_proto import Icmp4Assembler, Icmp4MessageEchoReply, Tracker


class TestIcmp4AssemblerMisc(TestCase):
    """
    The ICMPv4 packet assembler miscellaneous functions tests.
    """

    def test__icmp4__assembler__echo_tracker(self) -> None:
        """
        Ensure the ICMPv4 packet assembler 'tracker' property forwards the
        provided 'echo_tracker' so that RX/TX log lines stay correlated with
        the originating packet.
        """

        echo_tracker = Tracker(prefix="RX")

        icmp4__assembler = Icmp4Assembler(
            icmp4__message=Icmp4MessageEchoReply(),
            echo_tracker=echo_tracker,
        )

        self.assertIs(
            icmp4__assembler.tracker.echo_tracker,
            echo_tracker,
            msg="Assembler tracker must forward the provided echo_tracker instance.",
        )

    def test__icmp4__assembler__tx_prefix(self) -> None:
        """
        Ensure the ICMPv4 packet assembler 'tracker' is created with the 'TX'
        prefix so that outbound log lines are distinguishable from the inbound
        'RX' side (the prefix is embedded in the tracker serial).
        """

        icmp4__assembler = Icmp4Assembler(
            icmp4__message=Icmp4MessageEchoReply(),
        )

        self.assertIn(
            "TX",
            str(icmp4__assembler.tracker),
            msg="Assembler tracker serial must embed the 'TX' prefix.",
        )

    def test__icmp4__assembler__defaults_echo_tracker_to_none(self) -> None:
        """
        Ensure that when no 'echo_tracker' is provided the assembler tracker's
        'echo_tracker' attribute is None (standalone transmit, not tied to an
        incoming request).
        """

        icmp4__assembler = Icmp4Assembler(
            icmp4__message=Icmp4MessageEchoReply(),
        )

        self.assertIsNone(
            icmp4__assembler.tracker.echo_tracker,
            msg="Assembler tracker echo_tracker must default to None when not provided.",
        )
