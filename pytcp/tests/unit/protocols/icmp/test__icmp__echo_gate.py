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
This module contains tests for the ICMP Echo Reply emission gate.

pytcp/tests/unit/protocols/icmp/test__icmp__echo_gate.py

ver 3.0.4
"""

from typing import Any
from unittest import TestCase

from parameterized import parameterized_class  # type: ignore

from pytcp.protocols.icmp.icmp__echo_gate import should_emit_echo_reply


class TestShouldEmitEchoReply__Permit(TestCase):
    """
    The 'should_emit_echo_reply()' permit-path tests.
    """

    def test__icmp__echo_gate__clean_unicast_permits(self) -> None:
        """
        Ensure that an Echo Request whose destination is a unicast IP
        address (neither broadcast nor multicast) permits the Echo
        Reply emission.

        Reference: RFC 1122 §3.2.2.6 (host SHOULD reply to unicast
        Echo Request).
        """

        permitted = should_emit_echo_reply(
            dst_is_broadcast=False,
            dst_is_multicast=False,
        )

        self.assertTrue(
            permitted,
            msg="Clean unicast destination must permit Echo Reply emission.",
        )


@parameterized_class(
    [
        {
            "_description": "Broadcast destination (Smurf vector).",
            "_kwargs": {"dst_is_broadcast": True, "dst_is_multicast": False},
        },
        {
            "_description": "Multicast destination.",
            "_kwargs": {"dst_is_broadcast": False, "dst_is_multicast": True},
        },
        {
            "_description": "Both broadcast and multicast flagged (defensive).",
            "_kwargs": {"dst_is_broadcast": True, "dst_is_multicast": True},
        },
    ]
)
class TestShouldEmitEchoReply__Block(TestCase):
    """
    The 'should_emit_echo_reply()' Smurf-mitigation tests.
    """

    _description: str
    _kwargs: dict[str, Any]

    def test__icmp__echo_gate__bcast_or_mcast_blocks(self) -> None:
        """
        Ensure that an Echo Request whose destination is a broadcast
        or multicast IPv4 address blocks the Echo Reply emission.

        Reference: RFC 1122 §3.2.2.6 (host MUST NOT reply to Echo
        Request received on a broadcast/multicast destination).
        Reference: RFC 1812 §4.3.3.6 (analogous router rule, applies
        to hosts via RFC 1122).
        """

        permitted = should_emit_echo_reply(**self._kwargs)

        self.assertFalse(
            permitted,
            msg=f"Echo Reply must be blocked for case: {self._description}",
        )
