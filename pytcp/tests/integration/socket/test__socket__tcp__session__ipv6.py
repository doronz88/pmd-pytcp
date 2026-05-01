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
This module contains integration tests for 'TcpSession' over IPv6,
re-running canonical scenarios (handshake, ESTABLISHED data
transfer, normal close) on the IPv6 carrier and surfacing the
IPv6-specific MSS calculation bug.

PyTCP's MSS calculation in 'tcp__session.py' uses 'mtu - 40'
unconditionally regardless of IP version. For IPv4 this is correct
(IPv4 header = 20 bytes, TCP header = 20 bytes, total overhead =
40). For IPv6 the IP header is 40 bytes, so the correct overhead
is 60 bytes - the current code over-advertises and over-accepts
the MSS by 20 bytes on IPv6 sessions.

Reference RFCs:
    RFC 9293 §3.7.1     Maximum Segment Size Option
    RFC 6691            TCP Options and Maximum Segment Size
    RFC 8200            Internet Protocol, Version 6 - 40-byte
                        fixed header

pytcp/tests/integration/socket/test__socket__tcp__session__ipv6.py

ver 3.0.4
"""

from net_addr import Ip6Address
from pytcp import stack
from pytcp.socket import AddressFamily
from pytcp.socket.tcp__session import (
    FsmState,
    SysCall,
    TcpSession,
)
from pytcp.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP6_ADDRESS,
    STACK__IP6_HOST,
)
from pytcp.tests.lib.tcp_session_testcase import TcpSessionTestCase

# Deterministic IPv6 addressing.
STACK__IP6: Ip6Address = STACK__IP6_HOST.address
STACK__PORT: int = 12345
PEER__IP6: Ip6Address = HOST_A__IP6_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers chosen well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240

# Peer's MSS option value on its SYN+ACK reply (large; will be
# clamped to our local 'mtu - 60' on a 1500-MTU IPv6 link).
PEER__MSS: int = 9000


class TestTcpSession__Ip6(TcpSessionTestCase):
    """
    Integration tests for 'TcpSession' over IPv6: re-runs canonical
    scenarios on the IPv6 carrier and asserts the IPv6-specific
    MSS overhead (mtu - 60, NOT mtu - 40).
    """

    def _make_active_session_ip6(self, *, iss: int) -> TcpSession:
        """
        Build a 'TcpSocket' / 'TcpSession' pair the way 'connect()'
        would for an IPv6 4-tuple. Returns the session in CLOSED.
        """

        self._force_iss(iss)

        sock = TcpSocket(family=AddressFamily.INET6)
        sock._local_ip_address = STACK__IP6
        sock._local_port = STACK__PORT
        sock._remote_ip_address = PEER__IP6
        sock._remote_port = PEER__PORT

        session = TcpSession(
            local_ip_address=STACK__IP6,
            local_port=STACK__PORT,
            remote_ip_address=PEER__IP6,
            remote_port=PEER__PORT,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock

        return session

    def test__ipv6__outbound_syn_advertises_mss_mtu_minus_60(self) -> None:
        """
        Ensure that the outbound SYN on an IPv6 session advertises
        MSS = 'mtu - 60' (not 'mtu - 40' as the IPv4 case uses),
        per RFC 6691 §3 and RFC 8200's 40-byte IPv6 fixed header.

        RFC 6691 §3:

            "An MSS option ... is the size of the largest segment
             the sender of the option is willing to receive ...
             based on the size of the largest IP datagram that the
             sending host can support without fragmentation, which
             can in turn be limited by the IP layer or by the link
             layer. ... The minimum size of the IP+TCP headers is
             40 octets ..."

        The "minimum 40 octets" is the IPv4 case (20 IPv4 + 20 TCP).
        For IPv6 the fixed header is 40 octets (RFC 8200 §3), so
        the IP+TCP overhead is 40 + 20 = 60 octets. An IPv6
        endpoint advertising 'mtu - 40' over-advertises by 20
        bytes; the peer would then send segments larger than the
        local link can carry without fragmentation, leading to
        either path-MTU-driven retransmits or silent drops at
        misbehaving middleboxes that do not propagate ICMPv6
        Packet-Too-Big.

        Scenario:

            1. Build a session bound to the IPv6 4-tuple. The
               harness's 'stack.interface_mtu = 1500' applies
               regardless of IP version.
            2. Drive 'CONNECT'. Tick once to fire the outbound
               SYN.
            3. Parse the outbound SYN as an Ethernet/IPv6/TCP
               frame and inspect the advertised MSS option.

        Assertions:

            * The outbound frame's IP version is IPv6 (sanity).
            * The advertised MSS = 1500 - 60 = 1440 (NOT 1460,
              which would be the over-advertised IPv4 value).

        [FLAGS BUG] - 'TcpSession.__init__' (line 219) initialises
        '_rcv_mss = stack.interface_mtu - 40' unconditionally,
        and the active-open / passive-open MSS clamps at lines
        1075 and 1177 also use 'mtu - 40' verbatim. None of these
        sites check the session's IP version.

        On IPv6 (40-byte IP header), the correct overhead is 60
        bytes (40 + 20 TCP), so all three sites need IP-version-
        aware logic. Concretely:

            ip_overhead = 40 if isinstance(self._local_ip_address, Ip6Address) else 20
            mss_ceiling = stack.interface_mtu - ip_overhead - 20

        applied at all three sites. The fix is small and self-
        contained but the call sites are scattered, so the right
        cleanup is probably to introduce a 'self._ip_tcp_overhead'
        property computed once at construction.

        On current code this test will see 'mss = 1460' on the
        outbound SYN (the IPv4 value), failing the equality
        check.
        """

        session = self._make_active_session_ip6(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )

        syn_probe = self._parse_tx(syn_tx[0])

        # Sanity: this is an IPv6 frame.
        self.assertIsInstance(
            syn_probe.ip_src,
            Ip6Address,
            msg="Setup precondition: outbound frame's source IP must be IPv6.",
        )

        # The spec encoding: IPv6 sessions use 'mtu - 60'.
        expected_mss = 1500 - 60
        self.assertEqual(
            syn_probe.mss,
            expected_mss,
            msg=(
                f"Outbound SYN on an IPv6 session must advertise "
                f"MSS = mtu - 60 = {expected_mss} (RFC 8200's 40-"
                "byte IPv6 fixed header + 20-byte TCP header). "
                "Current code uses 'mtu - 40' verbatim - the "
                "IPv4 value - in 'TcpSession.__init__' line 219, "
                "and at the active/passive-open MSS clamps "
                "(lines 1075 and 1177). On a 1500 MTU link, this "
                "over-advertises by 20 bytes; peer-respecting "
                "segments would land at 1460 bytes and fragment "
                "or drop on the way out the local interface."
            ),
        )

        # Sanity: state has progressed to SYN_SENT.
        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="State must be SYN_SENT after the outbound SYN fires.",
        )
