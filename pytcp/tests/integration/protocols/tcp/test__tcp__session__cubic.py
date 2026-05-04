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
This module contains integration tests for the RFC 9438 CUBIC
congestion control surface (phases 2-7 of
'.claude/rules/tcp_rfc9438_cubic.md').

The tests progress from Phase 2 (substrate: CcMode default
RENO) through Phase 7 (default flip + setsockopt).

pytcp/tests/integration/protocols/tcp/test__tcp__session__cubic.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.tcp__enums import CcMode
from pytcp.protocols.tcp.tcp__session import TcpSession
from pytcp.socket import AddressFamily
from pytcp.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_session_testcase import TcpSessionTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers, well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN+ACK reply (1500 - 20 - 20 IPv4).
PEER__MSS: int = 1460


class TestTcpCubicPhase2(TcpSessionTestCase):
    """
    Integration tests for Phase 2 of RFC 9438 CUBIC: the
    substrate field declarations on TcpSession defaulting
    '_cc_mode' to RENO so behaviour is unchanged.
    """

    def _make_active_session(self, *, iss: int) -> TcpSession:
        self._force_iss(iss)

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

    def test__cubic__fresh_session_defaults_to_reno(self) -> None:
        """
        Ensure a fresh TcpSession's '_cc_mode' is CcMode.RENO
        through phases 2-6. Phase 7 flips the default to CUBIC
        and updates this test.

        Reference: RFC 9438 §1 (CUBIC algorithm selector).
        """

        session = self._make_active_session(iss=LOCAL__ISS)

        self.assertIs(
            session._cc_mode,
            CcMode.RENO,
            msg=(
                "Phase 2 default '_cc_mode' must be RENO so existing "
                "Reno-based tests continue to pass; Phase 7 flips this."
            ),
        )

    def test__cubic__fresh_session_initialises_cubic_state_to_zero(self) -> None:
        """
        Ensure a fresh TcpSession's CUBIC state fields are all
        initialised to 0 (or False for the CA-mode flag), so
        Reno-mode behaviour is unaffected by their presence.

        Reference: RFC 9438 §4.1.2 (variables of interest).
        """

        session = self._make_active_session(iss=LOCAL__ISS)

        self.assertEqual(session._cubic_w_max, 0, msg="W_max default 0.")
        self.assertEqual(session._cubic_w_last_max, 0, msg="W_last_max default 0.")
        self.assertEqual(session._cubic_K_ms, 0, msg="K default 0 ms.")
        self.assertEqual(session._cubic_epoch_start_ms, 0, msg="epoch_start default 0 ms.")
        self.assertEqual(session._cubic_w_est, 0, msg="W_est default 0.")
        self.assertFalse(session._cubic_in_ca, msg="in_ca default False.")
