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

ver 3.0.7
"""

import asyncio
from typing import override
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import AsyncMock, Mock, create_autospec, patch

from examples.lib import service as service_module
from examples.lib.service import Service
from examples.lib.tcp_service import TcpService
from examples.lib.udp_service import UdpService
from pmd_net_addr import Ip4Address, Ip4IfAddr, Ip6Address, Ip6IfAddr
from pmd_pytcp.socket import socket


class _StubService(Service):
    """
    Minimal concrete 'Service' for exercising the base retry helper.
    """

    _subsystem_name = "Stub Service"
    _service_name = "Stub"
    _protocol_name = "TCP"

    @override
    async def _task__service(self) -> None:
        """
        No-op service task.
        """

    @override
    async def _service(self, *, socket: socket) -> None:
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
    async def _service(self, *, socket: socket) -> None:
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
    async def _service(self, *, socket: socket) -> None:
        """
        No-op service handler.
        """


class TestServiceAcquireSocket(IsolatedAsyncioTestCase):
    """
    The 'Service._acquire_service_socket' retry-until-available tests.
    """

    @override
    def setUp(self) -> None:
        """
        Build a stub service with a mocked stop event and logger. The
        stop event is exercised only through its sync 'is_set()'; the
        inter-attempt sleep is the async 'wait_event' helper in the
        service module's namespace, patched per-test as an 'AsyncMock'.
        """

        self._service = _StubService()
        self._event = Mock(spec_set=asyncio.Event)
        self._service._event__stop_subsystem = self._event
        self._wait_event = self.enterContext(
            patch.object(service_module, "wait_event", new=AsyncMock(return_value=False)),
        )
        self._log = self.enterContext(patch.object(_StubService, "_log"))
        self._socket = create_autospec(socket, spec_set=True)

    async def test__lib__service__acquire_retries_until_socket_available(self) -> None:
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
            result = await self._service._acquire_service_socket()

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
        self._wait_event.assert_awaited_with(
            self._event,
            service_module.SERVICE_SOCKET_RETRY__SEC,
        )

    async def test__lib__service__acquire_returns_none_when_stopped_first(self) -> None:
        """
        Ensure '_acquire_service_socket' returns None without
        attempting a bind when the subsystem is already stopping.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._event.is_set.return_value = True
        with patch.object(_StubService, "_get_service_socket") as get_socket:
            result = await self._service._acquire_service_socket()

        self.assertIsNone(
            result,
            msg="A stopped subsystem must not return a socket.",
        )
        get_socket.assert_not_called()

    async def test__lib__service__acquire_stops_mid_retry(self) -> None:
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
            result = await self._service._acquire_service_socket()

        self.assertIsNone(
            result,
            msg="Must return None once the subsystem is stopping.",
        )
        self.assertEqual(
            get_socket.call_count,
            1,
            msg="Must not keep binding after the stop event fires.",
        )


class TestServiceThreadUsesRetry(IsolatedAsyncioTestCase):
    """
    The TCP/UDP service tasks use the retrying acquire helper.
    """

    async def test__lib__tcp_service__task_uses_acquire_helper(self) -> None:
        """
        Ensure 'TcpService._task__service' obtains its listening
        socket through the retrying '_acquire_service_socket' helper,
        not the one-shot '_get_service_socket'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        svc = _StubTcpService()
        with patch.object(
            _StubTcpService,
            "_acquire_service_socket",
            new=AsyncMock(return_value=None),
        ) as acquire:
            await svc._task__service()

        acquire.assert_awaited_once_with()

    async def test__lib__udp_service__task_uses_acquire_helper(self) -> None:
        """
        Ensure 'UdpService._task__service' obtains its socket
        through the retrying '_acquire_service_socket' helper, not
        the one-shot '_get_service_socket'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        svc = _StubUdpService()
        with patch.object(
            _StubUdpService,
            "_acquire_service_socket",
            new=AsyncMock(return_value=None),
        ) as acquire:
            await svc._task__service()

        acquire.assert_awaited_once_with()


class _EchoStub(Service):
    """
    Minimal echo-style service that records its constructor args.
    """

    _subsystem_name = "Echo Stub"
    _service_name = "Stub"
    _protocol_name = "TCP"

    def __init__(self, *, local_ip_address: object, local_port: int) -> None:
        """
        Record the bind target and port, then init the subsystem.
        """

        self._local_ip_address = local_ip_address  # type: ignore[assignment]
        self._local_port = local_port
        super().__init__()

    @override
    async def _task__service(self) -> None:
        """
        No-op service task.
        """

    @override
    async def _service(self, *, socket: socket) -> None:
        """
        No-op service handler.
        """


class TestBuildEchoServices(TestCase):
    """
    The 'build_echo_services' family-gated construction tests.
    """

    def test__lib__service__build_skips_disabled_ipv6(self) -> None:
        """
        Ensure no IPv6 service is constructed when IPv6 support is
        disabled, so the retrying acquire helper cannot spin forever
        on an address family the stack will never own.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        services = service_module.build_echo_services(
            _EchoStub,
            local_port=7,
            ip4_support=True,
            ip4_host=Ip4IfAddr("192.0.2.5/24"),
            ip6_support=False,
            ip6_host=None,
        )

        self.assertEqual(
            len(services),
            1,
            msg="Only the IPv4 service must be built when IPv6 is off.",
        )
        self.assertEqual(
            services[0]._local_ip_address,
            Ip4Address("192.0.2.5"),
            msg="The single service must bind the configured IPv4 host.",
        )

    def test__lib__service__build_skips_disabled_ipv4(self) -> None:
        """
        Ensure no IPv4 service is constructed when IPv4 support is
        disabled.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        services = service_module.build_echo_services(
            _EchoStub,
            local_port=7,
            ip4_support=False,
            ip4_host=None,
            ip6_support=True,
            ip6_host=Ip6IfAddr("2001:db8::5/64"),
        )

        self.assertEqual(
            len(services),
            1,
            msg="Only the IPv6 service must be built when IPv4 is off.",
        )
        self.assertEqual(
            services[0]._local_ip_address,
            Ip6Address("2001:db8::5"),
            msg="The single service must bind the configured IPv6 host.",
        )

    def test__lib__service__build_both_families(self) -> None:
        """
        Ensure both services are built (IPv6 first, IPv4 second)
        when both families are enabled with configured hosts.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        services = service_module.build_echo_services(
            _EchoStub,
            local_port=7,
            ip4_support=True,
            ip4_host=Ip4IfAddr("192.0.2.5/24"),
            ip6_support=True,
            ip6_host=Ip6IfAddr("2001:db8::5/64"),
        )

        self.assertEqual(
            len(services),
            2,
            msg="Both families enabled must build two services.",
        )
        self.assertEqual(
            services[0]._local_ip_address,
            Ip6Address("2001:db8::5"),
            msg="IPv6 service must come first.",
        )
        self.assertEqual(
            services[1]._local_ip_address,
            Ip4Address("192.0.2.5"),
            msg="IPv4 service must come second.",
        )

    def test__lib__service__build_wildcard_when_host_unset(self) -> None:
        """
        Ensure an enabled family with no static host binds the
        unspecified (wildcard) address, the intended behaviour for
        the DHCPv4 / SLAAC case.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        services = service_module.build_echo_services(
            _EchoStub,
            local_port=7,
            ip4_support=True,
            ip4_host=None,
            ip6_support=True,
            ip6_host=None,
        )

        self.assertEqual(
            services[0]._local_ip_address,
            Ip6Address(),
            msg="No IPv6 host must fall back to the wildcard address.",
        )
        self.assertEqual(
            services[1]._local_ip_address,
            Ip4Address(),
            msg="No IPv4 host must fall back to the wildcard address.",
        )
