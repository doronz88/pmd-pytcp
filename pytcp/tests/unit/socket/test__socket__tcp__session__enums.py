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
This module contains tests for the 'FsmState', 'SysCall', and
'ConnError' enums plus the 'TcpSessionError' exception class exposed
by 'pytcp/socket/tcp__session.py'.

pytcp/tests/unit/socket/test__socket__tcp__session__enums.py

ver 3.0.4
"""


from unittest import TestCase

from pytcp.socket.tcp__session import (
    DELAYED_ACK_DELAY,
    PACKET_RETRANSMIT_MAX_COUNT,
    PACKET_RETRANSMIT_TIMEOUT,
    TIME_WAIT_DELAY,
    ConnError,
    FsmState,
    SysCall,
    TcpSessionError,
)


class TestTcpSessionModuleConstants(TestCase):
    """
    The 'tcp__session' module-level constant tests.
    """

    def test__tcp_session__retransmit_timeout_is_1000(self) -> None:
        """
        Ensure 'PACKET_RETRANSMIT_TIMEOUT' stays at the canonical 1000
        ms base delay. Changing it shifts every retransmit cadence, so
        any drift must be an intentional, reviewed change.
        """

        self.assertEqual(
            PACKET_RETRANSMIT_TIMEOUT,
            1000,
            msg="PACKET_RETRANSMIT_TIMEOUT must remain 1000 ms.",
        )

    def test__tcp_session__retransmit_max_count(self) -> None:
        """
        Ensure 'PACKET_RETRANSMIT_MAX_COUNT' stays at the canonical 3
        retries before the session escalates to connection-failure.
        """

        self.assertEqual(
            PACKET_RETRANSMIT_MAX_COUNT,
            3,
            msg="PACKET_RETRANSMIT_MAX_COUNT must remain 3 retries.",
        )

    def test__tcp_session__time_wait_delay(self) -> None:
        """
        Ensure 'TIME_WAIT_DELAY' stays at the canonical 30-second
        value used for the TCP TIME_WAIT state.
        """

        self.assertEqual(
            TIME_WAIT_DELAY,
            30000,
            msg="TIME_WAIT_DELAY must remain 30000 ms (30 seconds).",
        )

    def test__tcp_session__delayed_ack_delay(self) -> None:
        """
        Ensure 'DELAYED_ACK_DELAY' stays at the canonical 100 ms delay
        for consecutive delayed ACKs.
        """

        self.assertEqual(
            DELAYED_ACK_DELAY,
            100,
            msg="DELAYED_ACK_DELAY must remain 100 ms.",
        )


class TestFsmState(TestCase):
    """
    The 'FsmState' enum tests.
    """

    def test__tcp_session__fsm_state_has_every_tcp_state(self) -> None:
        """
        Ensure 'FsmState' exposes every standard TCP state name
        (RFC 793). Missing or renamed members would silently break
        the state-transition machinery.
        """

        expected = {
            "CLOSED",
            "LISTEN",
            "SYN_SENT",
            "SYN_RCVD",
            "ESTABLISHED",
            "FIN_WAIT_1",
            "FIN_WAIT_2",
            "CLOSING",
            "CLOSE_WAIT",
            "LAST_ACK",
            "TIME_WAIT",
        }
        self.assertEqual(
            {member.name for member in FsmState},
            expected,
            msg="FsmState must expose the canonical eleven RFC 793 TCP state names.",
        )

    def test__tcp_session__fsm_state_str_is_name(self) -> None:
        """
        Ensure FsmState members stringify as their member name (the
        'NameEnum' base overrides '__str__') so log lines are
        readable.
        """

        self.assertEqual(
            str(FsmState.ESTABLISHED),
            "ESTABLISHED",
            msg="FsmState members must stringify as their name.",
        )


class TestSysCall(TestCase):
    """
    The 'SysCall' enum tests.
    """

    def test__tcp_session__syscall_members(self) -> None:
        """
        Ensure 'SysCall' exposes the three syscalls the session
        recognizes: LISTEN, CONNECT, CLOSE.
        """

        self.assertEqual(
            {member.name for member in SysCall},
            {"LISTEN", "CONNECT", "CLOSE"},
            msg="SysCall must expose exactly LISTEN, CONNECT, CLOSE.",
        )

    def test__tcp_session__syscall_str_is_name(self) -> None:
        """
        Ensure SysCall members stringify as their name (NameEnum
        override).
        """

        self.assertEqual(str(SysCall.CONNECT), "CONNECT", msg="SysCall.CONNECT must stringify as 'CONNECT'.")


class TestConnError(TestCase):
    """
    The 'ConnError' enum tests.
    """

    def test__tcp_session__conn_error_members(self) -> None:
        """
        Ensure 'ConnError' exposes the three connection-failure codes
        used by the session: NONE, REFUSED, TIMEOUT.
        """

        self.assertEqual(
            {member.name for member in ConnError},
            {"NONE", "REFUSED", "TIMEOUT"},
            msg="ConnError must expose exactly NONE, REFUSED, TIMEOUT.",
        )


class TestTcpSessionError(TestCase):
    """
    The 'TcpSessionError' exception tests.
    """

    def test__tcp_session__error_is_exception_subclass(self) -> None:
        """
        Ensure 'TcpSessionError' inherits from 'Exception' so callers
        using a broad except clause catch it.
        """

        self.assertTrue(
            issubclass(TcpSessionError, Exception),
            msg="TcpSessionError must inherit from Exception.",
        )

    def test__tcp_session__error_preserves_message(self) -> None:
        """
        Ensure the exception's 'str()' returns the constructor
        message verbatim — test fixtures match on exact text.
        """

        try:
            raise TcpSessionError("Connection refused")
        except TcpSessionError as exc:
            self.assertEqual(
                str(exc),
                "Connection refused",
                msg="TcpSessionError must preserve its constructor message in str().",
            )
