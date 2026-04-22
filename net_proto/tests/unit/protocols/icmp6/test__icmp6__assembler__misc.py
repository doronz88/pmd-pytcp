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
Module contains tests for the ICMPv6 packet assembler miscellaneous functions.

net_proto/tests/unit/protocols/icmp6/test__icmp6__assembler__misc.py

ver 3.0.4
"""


from unittest import TestCase

from net_proto import Icmp6Assembler, Icmp6MessageEchoReply, Tracker


class TestIcmp6AssemblerMisc(TestCase):
    """
    The ICMPv6 packet assembler miscellaneous functions tests.
    """

    def test__icmp6__assembler__echo_tracker(self) -> None:
        """
        Ensure the ICMPv6 packet assembler 'tracker' property forwards the
        provided 'echo_tracker' so that RX/TX log lines stay correlated with
        the originating packet.
        """

        echo_tracker = Tracker(prefix="RX")

        icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6MessageEchoReply(),
            echo_tracker=echo_tracker,
        )

        self.assertIs(
            icmp6__assembler.tracker.echo_tracker,
            echo_tracker,
            msg="Assembler tracker must forward the provided echo_tracker instance.",
        )

    def test__icmp6__assembler__tx_prefix(self) -> None:
        """
        Ensure the ICMPv6 packet assembler 'tracker' is created with the 'TX'
        prefix so that outbound log lines are distinguishable from the inbound
        'RX' side (the prefix is embedded in the tracker serial).
        """

        icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6MessageEchoReply(),
        )

        self.assertIn(
            "TX",
            str(icmp6__assembler.tracker),
            msg="Assembler tracker serial must embed the 'TX' prefix.",
        )

    def test__icmp6__assembler__defaults_echo_tracker_to_none(self) -> None:
        """
        Ensure that when no 'echo_tracker' is provided the assembler tracker's
        'echo_tracker' attribute is None (standalone transmit, not tied to an
        incoming request).
        """

        icmp6__assembler = Icmp6Assembler(
            icmp6__message=Icmp6MessageEchoReply(),
        )

        self.assertIsNone(
            icmp6__assembler.tracker.echo_tracker,
            msg="Assembler tracker echo_tracker must default to None when not provided.",
        )
