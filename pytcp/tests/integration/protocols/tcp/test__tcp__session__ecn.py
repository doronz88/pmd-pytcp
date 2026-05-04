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
This module contains integration tests for RFC 3168 Explicit
Congestion Notification (ECN) in 'TcpSession'. ECN lets routers
mark IP packets as having experienced congestion (CE bit) instead
of dropping them; the receiving TCP echoes the mark back via the
ECE flag and the sender reduces cwnd accordingly. The mechanism
saves the latency penalty of detecting congestion via packet loss
and is the substrate L4S (RFC 9332) builds on.

The negotiation handshake (RFC 3168 §6.1.1):

  Active-open SYN:    ECE=1, CWR=1, IP ECT(0) on data packets
  Passive-open SYN+ACK: ECE=1, CWR=0  (ECN-Echo only confirms support)

Once both sides have advertised, '_ecn_enabled' is True and the
session emits IP-layer ECT(0) on data packets, echoes peer's CE
marks via outbound ECE, and reduces cwnd / ssthresh on inbound
ECE per RFC 5681 §3.1 (same response as fast-retransmit).

pytcp/tests/integration/protocols/tcp/test__tcp__session__ecn.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.tcp__session import (
    SysCall,
    TcpSession,
)
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

# Peer's advertised window + MSS on its SYN+ACK reply.
PEER__WIN: int = 64240
PEER__MSS: int = 1460


class TestTcpSession__Ecn(TcpSessionTestCase):
    """
    Integration tests for the RFC 3168 ECN negotiation,
    marking, echo, and cwnd-reduce response paths.
    """

    def _make_active_session(self, *, iss: int) -> TcpSession:
        """Build a 'TcpSocket' / 'TcpSession' pair."""

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

    def test__ecn__active_open_syn_advertises_ece_and_cwr(self) -> None:
        """
        Ensure the active-open SYN sets both ECE and CWR
        flags - the canonical RFC 3168 §6.1.1 client-side
        ECN advertisement. A peer that supports ECN
        responds with SYN+ACK setting only ECE (not CWR);
        a peer that does not support ECN responds with
        neither flag, and the session falls back to non-
        ECN operation per the bilateral non-offer rule.

        Reference: RFC 3168 §6.1.1 (ECN-setup SYN: ECE+CWR).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN MUST fire on the first tick.",
        )
        syn = self._parse_tx(syn_tx[0])

        self.assertIn(
            "SYN",
            syn.flags,
            msg="Setup precondition: outbound segment must be a SYN.",
        )
        self.assertIn(
            "ECE",
            syn.flags,
            msg=("RFC 3168 §6.1.1: client-side ECN-setup SYN " "MUST carry the ECE flag. Got " f"flags={syn.flags!r}."),
        )
        self.assertIn(
            "CWR",
            syn.flags,
            msg=("RFC 3168 §6.1.1: client-side ECN-setup SYN " "MUST carry the CWR flag. Got " f"flags={syn.flags!r}."),
        )
