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
This module contains integration tests for the TCP options handling
in the 'TcpSession' state machine: MSS clamping (above and below
the legal range), unknown options, and SACK-permitted handling per
RFC 9293 §3.7.1 / RFC 6691 / RFC 2018.

The WSCALE-when-not-advertised rule is covered by
'data_transfer__window.py' scenario #2.

Reference RFCs:
    RFC 9293 §3.7.1     Maximum Segment Size Option
    RFC 6691            TCP Options and Maximum Segment Size
    RFC 879             The TCP Maximum Segment Size and Related
                        Topics (TCP__MIN_MSS = 536)
    RFC 2018            TCP Selective Acknowledgment Options

pytcp/tests/integration/socket/test__socket__tcp__session__options.py

ver 3.0.4
"""

from net_addr import Ip4Address
from net_proto.protocols.tcp.tcp__header import TCP__MIN_MSS
from pytcp import stack
from pytcp.socket import AddressFamily
from pytcp.socket.tcp__session import (
    FsmState,
    SysCall,
    TcpSession,
)
from pytcp.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_session_testcase import TcpSessionTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers chosen well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window on its SYN+ACK reply.
PEER__WIN: int = 64240


class TestTcpSession__Options(TcpSessionTestCase):
    """
    Integration tests for TCP options handling: MSS clamping,
    unknown options, SACK-permitted, etc.
    """

    def _make_active_session(self, *, iss: int) -> TcpSession:
        """
        Build a 'TcpSocket' / 'TcpSession' pair the way 'connect()'
        would. Returns the session in CLOSED state.
        """

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

    def test__options__peer_mss_zero_clamped_to_tcp_min_mss(self) -> None:
        """
        Ensure that a peer SYN+ACK carrying MSS=0 results in
        '_snd_mss' being clamped to 'TCP__MIN_MSS' (536), not
        accepted as zero. RFC 9293 §3.7.1 / RFC 6691 / RFC 879.

        RFC 879 (the original MSS spec, now folded into RFC 6691):

            "The MSS counts only data octets in the segment, it
             does not count the TCP header or the IP header.  ...
             When sending TCP data, a TCP MUST send segments not
             larger than the MSS value (or the negotiated MSS
             value, see below) of the remote host. The default
             MSS is 536 octets (RFC 1122)."

        RFC 6691 §2 reaffirms the floor:

            "A TCP that does not receive an MSS option MUST
             assume the default of 536 bytes for the SMSS."

        While the RFCs do not explicitly address MSS=0 in the
        option (since it is nonsensical - segments must carry at
        least one byte of data to be useful), the safe and
        consistent interpretation per the floor rule is to clamp
        to the same default a missing MSS option would yield. An
        MSS=0 setting is either malformed, an off-path attacker
        probe, or a bug in the peer's stack; in all cases the
        receiver should treat it as if no MSS option was
        advertised.

        Scenario:

            1. Build a session and emit our outbound SYN.
            2. Peer replies with a SYN+ACK carrying MSS=0
               (deliberately malformed). Other fields are valid.
            3. Drive RX. The handshake completes to ESTABLISHED.

        Assertions:

            * 'session._snd_mss' equals 'TCP__MIN_MSS' (536) -
              clamped from peer's malformed MSS=0.
            * State is ESTABLISHED.

        [FLAGS BUG] - 'TcpSession._tcp_fsm_syn_sent' (line 1066,
        and parallel line 1138 in '_tcp_fsm_listen' for passive-
        open) computes:

            self._snd_mss = min(packet_rx_md.tcp__mss, stack.interface_mtu - 40)

        with NO lower bound. When peer's MSS is 0, this yields
        '_snd_mss = 0', which propagates into '_transmit_data':

            transmit_data_len = min(self._snd_mss, usable_window, remaining_data_len)

        Anything 'min'-ed with 0 is 0, so the session can never
        send any data after the handshake - it is permanently
        gridlocked.

        The fix is to add 'TCP__MIN_MSS' as a lower bound:

            self._snd_mss = max(
                TCP__MIN_MSS,
                min(packet_rx_md.tcp__mss, stack.interface_mtu - 40),
            )

        applied at both the active-open ('_tcp_fsm_syn_sent') and
        passive-open ('_tcp_fsm_listen') sites. Equivalently, a
        per-segment treatment of 'tcp__mss == 0' as 'option absent'
        in the upstream parser path would also work, but the
        '_snd_mss' clamp is more localised and harder to bypass.

        On current code this test will see '_snd_mss = 0' and
        fail the equality check.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack_mss_zero = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=0,
        )
        self._drive_rx(frame=peer_syn_ack_mss_zero)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: handshake must complete to ESTABLISHED.",
        )
        self.assertEqual(
            session._snd_mss,
            TCP__MIN_MSS,
            msg=(
                f"Peer's MSS=0 must be clamped to TCP__MIN_MSS "
                f"({TCP__MIN_MSS}), not accepted verbatim. RFC 6691 "
                "§2 mandates 536 as the SMSS floor; MSS=0 is "
                "nonsensical and must be treated as 'option absent' "
                "for the floor purposes. Without the clamp, "
                "'_transmit_data's 'min(self._snd_mss, ...)' produces "
                "'transmit_data_len=0' and the session can never send "
                "any application data."
            ),
        )

    def test__options__peer_mss_above_local_mtu_clamped_to_mtu_minus_40(self) -> None:
        """
        Ensure that a peer SYN+ACK carrying an MSS larger than our
        local interface MTU minus the IPv4+TCP header overhead
        (40 bytes) results in '_snd_mss' being clamped to the local
        ceiling, preserving the invariant that no segment we
        transmit will ever exceed our path MTU. RFC 6691 §2:

            "The MSS value to be sent in an MSS option ... must be
             based on the size of the largest IP datagram that the
             sending host can support without fragmentation, which
             can in turn be limited by the IP layer or by the link
             layer.  The minimum size of the IP+TCP headers is 40
             octets, so the largest possible MSS value would be
             65495 (= 65535 - 40)."

        and §3 (Effect of an MSS option):

            "An MSS option ... is the size of the largest segment
             the sender of the option is willing to receive.  If
             ... no MSS option is sent, the SMSS [Sender Maximum
             Segment Size] is 536 bytes [RFC 1122].  If the local
             host configuration allows for a larger SMSS, the SMSS
             can be no larger than 65495 ..."

        The local-MTU clamp is what prevents PyTCP from emitting
        a segment that would fragment on the wire (or get dropped
        by an intermediate device with a smaller MTU). 'TcpSession'
        applies the clamp at handshake completion via:

            self._snd_mss = min(peer_mss, stack.interface_mtu - 40)

        For the standard 1500-byte Ethernet MTU and IPv4 carrier,
        that yields '1500 - 40 = 1460' as the effective ceiling
        regardless of how generous the peer's advertised MSS is.

        Scenario:

            1. Build a session and emit our outbound SYN.
            2. Peer replies with SYN+ACK carrying MSS=9000 - a
               jumbo-frame value that would only be valid on a
               peer's 9000-MTU link, but we are on a standard
               1500-MTU interface.
            3. Drive RX. Handshake completes to ESTABLISHED.

        Assertions:

            * 'session._snd_mss == 1460' (= 1500 - 40, our local
              ceiling), NOT 9000.
            * State is ESTABLISHED.

        This test passes on current code as a positive control
        regression guard for the MTU-clamp at line 1066. A future
        change that removed the local 'min()' bound (e.g. trusting
        peer's MSS verbatim) would let us emit segments large
        enough to fragment on our local link, hurting throughput
        and potentially breaking deployments behind PMTUD-broken
        middleboxes.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_jumbo_mss = 9000
        peer_syn_ack_jumbo = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=peer_jumbo_mss,
        )
        self._drive_rx(frame=peer_syn_ack_jumbo)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: handshake must complete to ESTABLISHED.",
        )

        # 'stack.interface_mtu' is 1500 in the harness (set by
        # 'TcpSessionTestCase.setUp'). The IPv4+TCP header overhead
        # is 40 bytes, so the effective MSS ceiling is 1460.
        expected_snd_mss = 1500 - 40
        self.assertEqual(
            session._snd_mss,
            expected_snd_mss,
            msg=(
                f"Peer's MSS={peer_jumbo_mss} must be clamped down "
                f"to 'mtu - 40' = {expected_snd_mss} so we never emit "
                "segments larger than our local link can carry "
                "without fragmentation. RFC 6691 §3 / RFC 9293 "
                "§3.7.1."
            ),
        )

    def test__options__peer_sack_permitted_on_inbound_syn_silently_ignored(self) -> None:
        """
        Ensure that a peer SYN+ACK carrying the SACK-Permitted option
        is processed normally without enabling SACK on our side: we
        do not advertise SACK-Permitted on our outbound SYN, so per
        RFC 2018 the bilateral negotiation does not complete and
        peer's offer must be silently ignored. None of our
        subsequent outbound segments should carry SACK-Permitted
        either.

        RFC 2018 §2 (negotiation):

            "An SACK-permitted option may be sent in a SYN by a TCP
             that has been extended to receive (and presumably
             process) the SACK option once the connection has
             opened.  It MUST NOT be sent on non-SYN segments."

        and §3 (using the SACK option):

            "The receiver SHOULD send an ACK for every valid segment
             that arrives containing new data, and each of these
             'duplicate' ACKs SHOULD bear a SACK option ... if the
             SACK-permitted option was negotiated during the SYN
             exchange."

        i.e. SACK is bilateral. Without our SACK-Permitted on the
        outbound SYN, the negotiation fails closed and peer's
        offer is dead on arrival. PyTCP currently does not
        implement SACK at all - the harness factory's 'sack_block='
        slot raises NotImplementedError, '_transmit_packet' has no
        SACK-Permitted parameter, and 'TcpSession' has no SACK-
        related state - so the only RFC-relevant behaviour is the
        no-echo / no-effect rule asserted below.

        Scenario:

            1. Build a session and emit our outbound SYN. Confirm
               that SYN does NOT carry the SACK-Permitted option
               (we do not advertise it).
            2. Peer replies with a SYN+ACK that carries
               SACK-Permitted. Other fields are valid.
            3. Drive RX. Handshake completes to ESTABLISHED.
            4. Application sends one byte of data so we emit a
               post-handshake outbound segment.
            5. Inspect that outbound segment: no SACK-Permitted
               option (SACK-Permitted is illegal on non-SYN
               segments per RFC 2018 §2 anyway), no SACK blocks.

        Assertions:

            * Our outbound SYN carries 'sackperm = False' (option
              absent on the wire).
            * Handshake completes to ESTABLISHED.
            * The outbound data segment carries 'sackperm = False'
              (option absent).

        This test passes on current code as a positive-control
        regression guard. The no-advertise / no-echo invariant is
        structural in PyTCP today: '_transmit_packet' (line 543)
        has no 'sack_permitted' parameter, so it is impossible
        for any outbound segment to carry the option. A future
        SACK-implementation patch that wires up SACK-Permitted
        on outbound SYNs without gating on a 'we_negotiated_sack'
        flag would echo peer's offer accidentally and be caught
        by this test.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        # Inspect our outbound SYN.
        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        syn_probe = self._parse_tx(syn_tx[0])
        self._assert_segment(
            syn_probe,
            flags=frozenset({"SYN"}),
            sackperm=False,
        )

        # Peer SYN+ACK with SACK-Permitted option.
        peer_syn_ack_with_sack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=1460,
            sackperm=True,
        )
        self._drive_rx(frame=peer_syn_ack_with_sack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Handshake must complete normally despite peer's "
                "SACK-Permitted offer - the option is silently "
                "ignored, not rejected."
            ),
        )

        # Application sends data so we emit a post-handshake segment.
        session._snd_ewn = PEER__WIN
        session.send(data=b"X")
        data_tx = self._advance(ms=1)
        self.assertEqual(
            len(data_tx),
            1,
            msg="Application data must produce exactly one outbound segment.",
        )

        # Outbound data segment must NOT carry SACK-Permitted.
        data_probe = self._parse_tx(data_tx[0])
        self._assert_segment(
            data_probe,
            sackperm=False,
        )
