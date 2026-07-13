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
state container in 'pmd_pytcp/protocols/tcp/tcp__stack.py'.

pmd_pytcp/tests/unit/protocols/tcp/test__tcp__stack.py

ver 3.0.7
"""

from __future__ import annotations

from unittest import TestCase

from pmd_net_addr import Ip4Address
from pmd_pytcp.protocols.tcp.tcp__stack import TcpStack

_PEER_A = Ip4Address("203.0.113.1")


class TestTcpStack__Accessors(TestCase):
    """
    The lock-guarded Fast-Open accessor surface tests.
    """

    def setUp(self) -> None:
        """
        Construct a default state instance for every test.
        """

        self._stack = TcpStack()

    def test__tcp_stack__cache_fastopen_cookie_stores_and_reads_back(self) -> None:
        """
        Ensure 'cache_fastopen_cookie' inserts a peer cookie that
        'fastopen_cookie' then returns, so the client-side cache
        round-trips through the guarded accessors.

        Reference: RFC 7413 §3.1 (Fast Open cookie cache).
        """

        self._stack.cache_fastopen_cookie(peer=_PEER_A, cookie=b"abcd", max_size=4)

        self.assertEqual(
            self._stack.fastopen_cookie(_PEER_A),
            b"abcd",
            msg="cache_fastopen_cookie must store a cookie that fastopen_cookie returns.",
        )

    def test__tcp_stack__fastopen_cookie_absent_returns_none(self) -> None:
        """
        Ensure 'fastopen_cookie' returns None for a peer with no
        cached cookie so a first active-open SYN issues an empty
        cookie-request rather than replaying a stale value.

        Reference: RFC 7413 §3.1 (Fast Open cookie cache).
        """

        self.assertIsNone(
            self._stack.fastopen_cookie(_PEER_A),
            msg="fastopen_cookie must return None for an uncached peer.",
        )

    def test__tcp_stack__cache_fastopen_cookie_fifo_evicts_at_max_size(self) -> None:
        """
        Ensure 'cache_fastopen_cookie' evicts the oldest entry
        once the cache exceeds 'max_size', bounding the cookie
        cache to the configured cap.

        Reference: RFC 7413 §3.1 (Fast Open cookie cache eviction).
        """

        peers = [Ip4Address(f"198.51.100.{octet}") for octet in range(1, 5)]
        for peer in peers:
            self._stack.cache_fastopen_cookie(peer=peer, cookie=b"ck", max_size=2)

        self.assertIsNone(
            self._stack.fastopen_cookie(peers[0]),
            msg="The oldest cookie must be FIFO-evicted once the cache exceeds max_size.",
        )
        self.assertEqual(
            self._stack.fastopen_cookie(peers[-1]),
            b"ck",
            msg="The most-recently-cached cookie must survive eviction.",
        )

    def test__tcp_stack__mark_and_query_fastopen_negative(self) -> None:
        """
        Ensure 'mark_fastopen_negative' records a peer that
        'is_fastopen_negative' then reports, so subsequent
        active-open attempts bypass the TFO option for that peer.

        Reference: RFC 7413 §4.1.3.1 (negative-response cache).
        """

        self.assertFalse(
            self._stack.is_fastopen_negative(_PEER_A),
            msg="is_fastopen_negative must be False before the peer is marked.",
        )

        self._stack.mark_fastopen_negative(_PEER_A)

        self.assertTrue(
            self._stack.is_fastopen_negative(_PEER_A),
            msg="is_fastopen_negative must be True after mark_fastopen_negative.",
        )

    def test__tcp_stack__pending_increment_and_decrement(self) -> None:
        """
        Ensure 'incr_fastopen_pending' / 'decr_fastopen_pending'
        move the PendingFastOpenRequests count that
        'fastopen_pending' reports, gating TFO acceptance.

        Reference: RFC 7413 §4.2 (PendingFastOpenRequests).
        """

        self._stack.incr_fastopen_pending()
        self._stack.incr_fastopen_pending()
        self._stack.decr_fastopen_pending()

        self.assertEqual(
            self._stack.fastopen_pending(),
            1,
            msg="fastopen_pending must reflect two increments and one decrement.",
        )

    def test__tcp_stack__decr_fastopen_pending_clamps_at_zero(self) -> None:
        """
        Ensure 'decr_fastopen_pending' never drives the count
        below zero so a spurious decrement cannot wrap the gate
        into permanently admitting TFO.

        Reference: RFC 7413 §4.2 (PendingFastOpenRequests).
        """

        self._stack.decr_fastopen_pending()

        self.assertEqual(
            self._stack.fastopen_pending(),
            0,
            msg="decr_fastopen_pending must clamp the count at zero.",
        )

    # The pre-asyncio '_holds_lock_on_write' / '_acquire_lock' suite
    # was deleted with the pure-asyncio refactor: 'TcpStack' no longer
    # carries a lock because every accessor runs on the one stack
    # event loop (docs/refactor/pure_asyncio.md).


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
