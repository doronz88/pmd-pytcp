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
This module contains the session-level behaviour pins for the two TCP
throughput sysctls: 'tcp.rcv_wnd_max' (the advertised receive-window
ceiling, seeded into 'WindowState.rcv_wnd_max' at session creation) and
'tcp.snd_mss_max' (the send-side MSS cap applied in '_mss_ceiling()'
independently of the advertised receive MSS).

The registration / validator / override-round-trip pins live in
'test__tcp__sysctls.py'; this file pins that a live session actually
honours the knobs.

pmd_pytcp/tests/integration/protocols/tcp/test__tcp__session__throughput_knobs.py

ver 3.0.7
"""

from __future__ import annotations

from typing_extensions import override

from pmd_net_addr import Ip4Address
from pmd_pytcp import stack
from pmd_pytcp.protocols.tcp.session import TcpSession
from pmd_pytcp.socket import AddressFamily
from pmd_pytcp.socket.tcp__socket import TcpSocket
from pmd_pytcp.stack import sysctl as sysctl_module
from pmd_pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pmd_pytcp.tests.lib.tcp_testcase import TcpTestCase

STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80
LOCAL__ISS: int = 0x0000_1000


class _ThroughputKnobFixture(TcpTestCase):
    """
    Shared fixture — resets every sysctl slot on teardown so a
    knob write in one test does not leak into the next.
    """

    @override
    def tearDown(self) -> None:
        """
        Restore the registered sysctl defaults after each test.
        """

        sysctl_module.reset_to_defaults()
        super().tearDown()

    def _make_session(self) -> TcpSession:
        """
        Build an unstarted IPv4 session against PEER, useful for
        pinning '__init__'-time window state and '_mss_ceiling()'
        without a handshake.
        """

        self._force_iss(LOCAL__ISS)
        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = STACK__PORT
        sock._remote_ip_address = PEER__IP
        sock._remote_port = PEER__PORT
        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=STACK__PORT,
            remote_ip_address=PEER__IP,
            remote_port=PEER__PORT,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        return session


class TestTcpRcvWndMax(_ThroughputKnobFixture):
    """
    The 'tcp.rcv_wnd_max' session-seeding behaviour tests.
    """

    def test__tcp__rcv_wnd_max__default_seeds_65535(self) -> None:
        """
        Ensure a fresh session seeds 'WindowState.rcv_wnd_max' from
        the registered default, preserving the historical 65535-byte
        advertised-window ceiling.

        Reference: Linux net.ipv4.tcp_rmem (receive-window max).
        """

        session = self._make_session()
        self.assertEqual(
            session._win.rcv_wnd_max,
            65535,
            msg="Default 'tcp.rcv_wnd_max' must seed the session window ceiling at 65535.",
        )

    def test__tcp__rcv_wnd_max__override_seeds_session(self) -> None:
        """
        Ensure raising 'tcp.rcv_wnd_max' is picked up by a session
        created afterwards — the per-session ceiling reflects the
        live sysctl value, letting a high-BDP path keep a full
        window in flight.

        Reference: Linux net.ipv4.tcp_rmem (receive-window max).
        """

        sysctl_module.set("tcp.rcv_wnd_max", 4 * 1024 * 1024)
        session = self._make_session()
        self.assertEqual(
            session._win.rcv_wnd_max,
            4 * 1024 * 1024,
            msg="A session must seed 'rcv_wnd_max' from the live 'tcp.rcv_wnd_max' value.",
        )


class TestTcpSndMssMax(_ThroughputKnobFixture):
    """
    The 'tcp.snd_mss_max' '_mss_ceiling()' cap behaviour tests.
    """

    def test__tcp__snd_mss_max__default_uncapped(self) -> None:
        """
        Ensure with 'tcp.snd_mss_max=0' (default) the send-side MSS
        ceiling is the interface ceiling ('interface_mtu - overhead'),
        i.e. the cap is inert.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        session = self._make_session()
        expected = session._egress_interface_mtu() - session._ip_tcp_overhead
        self.assertEqual(
            session._mss_ceiling(),
            expected,
            msg="With the cap disabled, '_mss_ceiling()' must equal 'interface_mtu - overhead'.",
        )

    def test__tcp__snd_mss_max__caps_send_ceiling(self) -> None:
        """
        Ensure a non-zero 'tcp.snd_mss_max' clamps '_mss_ceiling()'
        to the configured value while leaving the advertised receive
        MSS ('rcv_mss') at the interface ceiling — so a large MTU can
        still invite large inbound segments while output stays small.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        sysctl_module.set("tcp.default.snd_mss_max", 576)
        session = self._make_session()
        iface_ceiling = session._egress_interface_mtu() - session._ip_tcp_overhead

        self.assertEqual(
            session._mss_ceiling(),
            576,
            msg="A non-zero 'tcp.snd_mss_max' must cap the send-side MSS ceiling.",
        )
        self.assertEqual(
            session._win.rcv_mss,
            iface_ceiling,
            msg="'tcp.snd_mss_max' must NOT lower the advertised receive MSS.",
        )

    def test__tcp__snd_mss_max__cap_above_interface_is_inert(self) -> None:
        """
        Ensure a 'tcp.snd_mss_max' larger than the interface ceiling
        leaves '_mss_ceiling()' at the interface ceiling — the cap
        only ever lowers, never raises, the send MSS.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        session_default = self._make_session()
        iface_ceiling = session_default._egress_interface_mtu() - session_default._ip_tcp_overhead

        sysctl_module.set("tcp.default.snd_mss_max", iface_ceiling + 1000)
        session = self._make_session()
        self.assertEqual(
            session._mss_ceiling(),
            iface_ceiling,
            msg="A cap above the interface ceiling must be inert.",
        )
