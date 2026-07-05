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
This module contains tests for the 'stop()'-side socket abort walk in
'pmd_pytcp/stack/lifecycle.py' — the teardown step that unblocks any
application thread parked in a blocking 'recv()' / 'connect()' on an
open TCP session (after teardown nothing ever sets those sessions'
events again, so a still-parked thread would survive 'stop()' for the
process lifetime).

pmd_pytcp/tests/unit/stack/test__stack__lifecycle_stop.py

ver 3.0.7
"""

from __future__ import annotations

from unittest import TestCase
from unittest.mock import MagicMock, patch

import pmd_pytcp.stack as stack
import pmd_pytcp.stack.lifecycle as lifecycle


class TestStopAbortsOpenSockets(TestCase):
    """
    The '_abort_open_sockets' teardown-walk tests.
    """

    def setUp(self) -> None:
        """
        Suppress log output.
        """

        self._log_patch = patch("pmd_pytcp.stack.lifecycle.log")
        self._log_patch.start()

    def tearDown(self) -> None:
        """
        Tear down patches.
        """

        self._log_patch.stop()

    def test__lifecycle__abort_open_sockets_aborts_every_tcp_socket(self) -> None:
        """
        Ensure the walk calls 'abort()' exactly once on every
        registered socket exposing it (the TCP sockets), so blocked
        'recv()' / 'connect()' callers unblock at stack teardown.

        Reference: RFC 9293 §3.9.1 (ABORT call semantics).
        """

        tcp_sockets = [MagicMock(spec=["abort"]) for _ in range(3)]
        table = MagicMock()
        table.values.return_value = list(tcp_sockets)

        with patch.object(stack, "sockets", table):
            lifecycle._abort_open_sockets()

        for sock in tcp_sockets:
            sock.abort.assert_called_once_with()

    def test__lifecycle__abort_open_sockets_skips_sockets_without_abort(self) -> None:
        """
        Ensure datagram / raw sockets (no 'abort' attribute — nothing
        blocks on them beyond per-call timeouts) are skipped without
        error while their TCP neighbours are still aborted.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        udp_socket = MagicMock(spec=["recv", "close"])  # no 'abort'
        tcp_socket = MagicMock(spec=["abort"])
        table = MagicMock()
        table.values.return_value = [udp_socket, tcp_socket]

        with patch.object(stack, "sockets", table):
            lifecycle._abort_open_sockets()

        tcp_socket.abort.assert_called_once_with()

    def test__lifecycle__abort_open_sockets_survives_raising_abort(self) -> None:
        """
        Ensure one session whose 'abort()' raises cannot stall stack
        teardown: the error is swallowed (logged) and the remaining
        sockets are still aborted.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        raising_socket = MagicMock(spec=["abort"])
        raising_socket.abort.side_effect = RuntimeError("session gone sideways")
        tcp_socket = MagicMock(spec=["abort"])
        table = MagicMock()
        table.values.return_value = [raising_socket, tcp_socket]

        with patch.object(stack, "sockets", table):
            # Must not propagate the RuntimeError.
            lifecycle._abort_open_sockets()

        tcp_socket.abort.assert_called_once_with()
