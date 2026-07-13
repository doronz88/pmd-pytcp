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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
This module contains the per-session TCP timer-service behaviour
tests. The pre-asyncio lock-discipline suite ('_TrackingLock' +
'TestTcpTimerServiceLocking') was deleted with the refactor — the
service's dedicated lock no longer exists because every mutator and
the coalesced service callback run on the one stack event loop
(docs/refactor/pure_asyncio.md), so the guarantee those tests pinned
is now structural.

packages/pmd_pytcp/pmd_pytcp/tests/integration/protocols/tcp/test__tcp__session__timer_service.py

ver 3.0.7
"""

from __future__ import annotations

from typing_extensions import override

from pmd_pytcp.protocols.tcp.tcp__enums import FsmState
from pmd_pytcp.tests.lib.tcp_testcase import TcpTestCase

_LOCAL__ISS: int = 0x0000_1000


class TestTcpTimerServiceBehaviourParity(TcpTestCase):
    """
    The per-session TCP timer-service behaviour-parity tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build the harness and construct an active TCP session for the
        behaviour-parity round-trips.
        """

        super().setUp()
        self._session = self._make_active_session(iss=_LOCAL__ISS)

    def test__tcp__timers__arm_then_armed_is_true(self) -> None:
        """
        Ensure arming a logical timer leaves it observable as armed via
        '_timer_armed' until its deadline passes, matching the
        pre-refactor semantics so the FSM handlers' arm-then-check
        pattern keeps working.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 100)

        self.assertTrue(
            self._session._timer_armed("retransmit"),
            msg="An armed logical timer must report '_timer_armed' True before its deadline.",
        )
        self.assertFalse(
            self._session._timer_expired("retransmit"),
            msg="A logical timer must NOT report expired before its deadline.",
        )

    def test__tcp__timers__advance_past_deadline_expires(self) -> None:
        """
        Ensure advancing the FakeTimer past a logical timer's deadline
        flips '_timer_expired' to True while '_timer_armed' goes
        False, matching the pre-refactor semantics so the FSM
        handlers' expiry-check pattern keeps working.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 100)
        # Cancel the coalesced service handle so the FakeTimer advance
        # does not also drive the FSM tail (we want to observe the
        # deadline-map state directly).
        self._session._cancel_all_timers()
        self._session._timers._deadlines["retransmit"] = self._timer.now_ms + 50
        self._timer.advance(ms=60)

        self.assertTrue(
            self._session._timer_expired("retransmit"),
            msg="A logical timer must report '_timer_expired' True after its deadline passes.",
        )
        self.assertFalse(
            self._session._timer_armed("retransmit"),
            msg="An expired logical timer must NOT report '_timer_armed' True.",
        )

    def test__tcp__timers__cancel_clears_armed(self) -> None:
        """
        Ensure cancelling a logical timer clears '_timer_armed', so the
        pre-refactor invariant that '_cancel_timer' removes the
        deadline-map entry is preserved by the service extraction.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 100)
        self._session._cancel_timer("retransmit")

        self.assertFalse(
            self._session._timer_armed("retransmit"),
            msg="A cancelled logical timer must NOT report '_timer_armed' True.",
        )

    def test__tcp__timers__cancel_all_clears_every_armed(self) -> None:
        """
        Ensure '_cancel_all_timers' drops every armed logical timer at
        once and releases the coalesced service handle, so the
        teardown sweep on the CLOSED transition still leaves the
        deadline map empty.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._arm_timer("retransmit", 100)
        self._session._arm_timer("delayed_ack", 40)
        self._session._arm_timer("persist", 1000)

        self._session._cancel_all_timers()

        self.assertEqual(
            self._session._timers._deadlines,
            {},
            msg="'_cancel_all_timers' must empty the deadline map.",
        )
        self.assertIsNone(
            self._session._timers._service_handle,
            msg="'_cancel_all_timers' must release the coalesced service handle.",
        )

    def test__tcp__timers__kick_pump_arms_when_not_closed(self) -> None:
        """
        Ensure '_kick_pump' arms the tx-pump logical timer when the
        session is in a non-CLOSED state and is a no-op when the
        session is CLOSED, matching the pre-refactor '_kick_pump'
        contract so 'send()' continues to drive the FSM-pump.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._session._state = FsmState.ESTABLISHED
        self._session._kick_pump()
        self.assertTrue(
            self._session._timer_armed("tx_pump"),
            msg="'_kick_pump' from a non-CLOSED state must arm the tx-pump timer.",
        )

        self._session._cancel_all_timers()
        self._session._state = FsmState.CLOSED
        self._session._kick_pump()
        self.assertFalse(
            self._session._timer_armed("tx_pump"),
            msg="'_kick_pump' from the CLOSED state must NOT arm the tx-pump timer.",
        )
