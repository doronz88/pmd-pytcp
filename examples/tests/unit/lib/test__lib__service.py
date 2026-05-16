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
This module contains tests for the example 'Service' socket-acquire retry.

examples/tests/unit/lib/test__lib__service.py

ver 3.0.4
"""

import threading
from typing import override
from unittest import TestCase
from unittest.mock import create_autospec, patch

from examples.lib import service as service_module
from examples.lib.service import Service
from examples.lib.tcp_service import TcpService
from examples.lib.udp_service import UdpService
from pytcp.socket import socket


class _StubService(Service):
    """
    Minimal concrete 'Service' for exercising the base retry helper.
    """

    _subsystem_name = "Stub Service"
    _service_name = "Stub"
    _protocol_name = "TCP"

    @override
    def _thread__service(self) -> None:
        """
        No-op service thread.
        """

    @override
    def _service(self, *, socket: socket) -> None:
        """
        No-op service handler.
        """


class _StubTcpService(TcpService):
    """
    Minimal concrete 'TcpService' for the wiring test.
    """

    _subsystem_name = "Stub TCP Service"
    _service_name = "Stub"

    @override
    def _service(self, *, socket: socket) -> None:
        """
        No-op service handler.
        """


class _StubUdpService(UdpService):
    """
    Minimal concrete 'UdpService' for the wiring test.
    """

    _subsystem_name = "Stub UDP Service"
    _service_name = "Stub"

    @override
    def _service(self, *, socket: socket) -> None:
        """
        No-op service handler.
        """


class TestServiceAcquireSocket(TestCase):
    """
    The 'Service._acquire_service_socket' retry-until-available tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a stub service with a mocked stop event and logger.
        """

        self._service = _StubService()
        self._event = create_autospec(threading.Event, spec_set=True)
        self._service._event__stop_subsystem = self._event
        self._log = self.enterContext(patch.object(_StubService, "_log"))
        self._socket = create_autospec(socket, spec_set=True)

    def test__lib__service__acquire_retries_until_socket_available(self) -> None:
        """
        Ensure '_acquire_service_socket' keeps retrying the bind and
        returns the socket once the stack finally owns the address,
        rather than giving up on the first failed attempt.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._event.is_set.return_value = False
        with patch.object(
            _StubService,
            "_get_service_socket",
            side_effect=[None, None, self._socket],
        ) as get_socket:
            result = self._service._acquire_service_socket()

        self.assertIs(
            result,
            self._socket,
            msg="Must return the socket from the first successful bind.",
        )
        self.assertEqual(
            get_socket.call_count,
            3,
            msg="Must retry '_get_service_socket' until it succeeds.",
        )
        self._event.wait.assert_called_with(
            timeout=service_module.SERVICE_SOCKET_RETRY__SEC,
        )

    def test__lib__service__acquire_returns_none_when_stopped_first(self) -> None:
        """
        Ensure '_acquire_service_socket' returns None without
        attempting a bind when the subsystem is already stopping.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._event.is_set.return_value = True
        with patch.object(_StubService, "_get_service_socket") as get_socket:
            result = self._service._acquire_service_socket()

        self.assertIsNone(
            result,
            msg="A stopped subsystem must not return a socket.",
        )
        get_socket.assert_not_called()

    def test__lib__service__acquire_stops_mid_retry(self) -> None:
        """
        Ensure '_acquire_service_socket' breaks out of the retry
        loop and returns None when the stop event fires between
        failed bind attempts.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._event.is_set.side_effect = [False, True]
        with patch.object(
            _StubService,
            "_get_service_socket",
            return_value=None,
        ) as get_socket:
            result = self._service._acquire_service_socket()

        self.assertIsNone(
            result,
            msg="Must return None once the subsystem is stopping.",
        )
        self.assertEqual(
            get_socket.call_count,
            1,
            msg="Must not keep binding after the stop event fires.",
        )


class TestServiceThreadUsesRetry(TestCase):
    """
    The TCP/UDP service threads use the retrying acquire helper.
    """

    def test__lib__tcp_service__thread_uses_acquire_helper(self) -> None:
        """
        Ensure 'TcpService._thread__service' obtains its listening
        socket through the retrying '_acquire_service_socket' helper,
        not the one-shot '_get_service_socket'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        svc = _StubTcpService()
        with patch.object(
            _StubTcpService,
            "_acquire_service_socket",
            return_value=None,
        ) as acquire:
            svc._thread__service()

        acquire.assert_called_once_with()

    def test__lib__udp_service__thread_uses_acquire_helper(self) -> None:
        """
        Ensure 'UdpService._thread__service' obtains its socket
        through the retrying '_acquire_service_socket' helper, not
        the one-shot '_get_service_socket'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        svc = _StubUdpService()
        with patch.object(
            _StubUdpService,
            "_acquire_service_socket",
            return_value=None,
        ) as acquire:
            svc._thread__service()

        acquire.assert_called_once_with()
