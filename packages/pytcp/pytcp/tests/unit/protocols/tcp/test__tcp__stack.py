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
This module contains unit tests for the TCP-specific stack-level
state container in 'pytcp/protocols/tcp/tcp__stack.py'.

pytcp/tests/unit/protocols/tcp/test__tcp__stack.py

ver 3.0.5
"""

from unittest import TestCase

from pytcp.protocols.tcp.tcp__stack import TcpStack


class TestTcpStack__Defaults(TestCase):
    """
    Per-field default values pinning the post-construction state
    of 'TcpStack'.
    """

    def setUp(self) -> None:
        """
        Construct a default state instance for every test.
        """

        self._stack = TcpStack()

    def test__tcp_stack__fastopen_cookies_default_empty(self) -> None:
        """
        Ensure 'fastopen_cookies' defaults to an empty dict so a
        freshly-constructed stack has no cached TFO cookies — a
        first active-open SYN to any peer will issue an empty
        cookie-request rather than a stale replay.

        Reference: RFC 7413 §3.1 (Fast Open cookie cache).
        """

        self.assertEqual(
            self._stack.fastopen_cookies,
            {},
            msg="TcpStack.fastopen_cookies must default to {}.",
        )

    def test__tcp_stack__fastopen_negative_default_empty(self) -> None:
        """
        Ensure 'fastopen_negative' defaults to an empty set so a
        freshly-constructed stack does not bypass TFO for any
        peer — every peer gets a TFO-bearing SYN on the first
        active-open attempt.

        Reference: RFC 7413 §4.1.3.1 (negative-response cache).
        """

        self.assertEqual(
            self._stack.fastopen_negative,
            set(),
            msg="TcpStack.fastopen_negative must default to set().",
        )

    def test__tcp_stack__fastopen_pending_count_default_zero(self) -> None:
        """
        Ensure 'fastopen_pending_count' defaults to 0 so a
        freshly-constructed stack admits TFO-accepted SYNs up
        to the 'fastopen_qlen' configured on the listening
        socket without the gate triggering on a phantom prior
        count.

        Reference: RFC 7413 §4.2 (PendingFastOpenRequests).
        """

        self.assertEqual(
            self._stack.fastopen_pending_count,
            0,
            msg="TcpStack.fastopen_pending_count must default to 0.",
        )

    def test__tcp_stack__instances_own_independent_collections(self) -> None:
        """
        Ensure two distinct 'TcpStack' instances own independent
        'fastopen_cookies' and 'fastopen_negative' collections via
        'default_factory'. A test fixture that replaces
        'stack.tcp_stack' with a fresh instance must not share
        mutable state with the prior instance.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stack_a = TcpStack()
        stack_b = TcpStack()

        self.assertIsNot(
            stack_a.fastopen_cookies,
            stack_b.fastopen_cookies,
            msg="Distinct TcpStack instances must own distinct fastopen_cookies dicts.",
        )
        self.assertIsNot(
            stack_a.fastopen_negative,
            stack_b.fastopen_negative,
            msg="Distinct TcpStack instances must own distinct fastopen_negative sets.",
        )
