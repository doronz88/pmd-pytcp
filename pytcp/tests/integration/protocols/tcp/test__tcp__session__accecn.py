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
This module contains integration tests for RFC 9768 Accurate
ECN (AccECN) in 'TcpSession'. AccECN replaces RFC 3168's
binary CE/ECE feedback channel with byte-counter-based
feedback that is granular enough for L4S-style scalable
congestion control. The negotiation handshake (RFC 9768
§3.1.1) uses different SYN flag combinations from RFC 3168;
when both peers are AccECN-capable, '_accecn_enabled' is
True post-handshake and the data path uses the AccECN
option (kind 172/173) to carry per-segment byte counters.

The negotiation handshake (RFC 9768 §3.1.1):

  Active-open SYN:    AE=1, CWR=1, ECE=1 (the canonical
                      AccECN-setup SYN; AE=0 is RFC 3168).
  Server SYN+ACK:     One of four AccECN-capable codepoints
                      that encodes the IP-ECN of the SYN
                      received; AccECN-incapable servers
                      respond with classic RFC 3168 ECE
                      alone (AE=0, CWR=0, ECE=1).

When AccECN negotiation succeeds, '_accecn_enabled' is True.
When the peer falls back to RFC 3168 (AE=0, CWR=0, ECE=1
SYN+ACK), '_ecn_enabled' is True instead. When neither
applies (no ECN flags on the SYN+ACK), neither flag is set.

pytcp/tests/integration/protocols/tcp/test__tcp__session__accecn.py

ver 3.0.4
"""

from net_addr import Ip4Address  # noqa: F401
from pytcp import stack
from pytcp.protocols.tcp.tcp__session import (
    FsmState,
    SysCall,
    TcpSession,
)
from pytcp.socket import AddressFamily
from pytcp.socket.tcp__socket import TcpSocket
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pytcp.tests.lib.tcp_session_testcase import TcpProbe, TcpSessionTestCase

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


class TestTcpSession__Accecn(TcpSessionTestCase):
    """
    Integration tests for the RFC 9768 AccECN negotiation,
    counter encoding, byte-count emission, and proportional
    cwnd response paths.
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

    def test__accecn__active_open_syn_advertises_ae_cwr_ece(self) -> None:
        """
        Ensure the active-open SYN sets all three of AE, CWR,
        and ECE - the canonical client-side AccECN-setup
        signal. The AE bit (the legacy NS bit position) is
        what distinguishes an AccECN-capable SYN from a
        classic ECN SYN which sets only CWR+ECE. Servers
        that recognise AccECN respond with one of four
        AE/CWR/ECE codepoints encoding the IP-ECN of the
        received SYN; servers that do not recognise AccECN
        respond with classic ECE alone, and the session
        falls back gracefully.

        Reference: RFC 9768 §3.1.1 (AccECN-setup SYN: AE+CWR+ECE).
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
            msg=("RFC 9768 §3.1.1: AccECN-setup SYN MUST carry " f"the ECE flag. Got flags={syn.flags!r}."),
        )
        self.assertIn(
            "CWR",
            syn.flags,
            msg=("RFC 9768 §3.1.1: AccECN-setup SYN MUST carry " f"the CWR flag. Got flags={syn.flags!r}."),
        )
        self.assertIn(
            "NS",
            syn.flags,
            msg=(
                "RFC 9768 §3.1.1: AccECN-setup SYN MUST carry "
                "the AE flag (the legacy NS bit position). The "
                "AE bit is what distinguishes an AccECN SYN from "
                "a classic RFC 3168 SYN; without it a peer that "
                "recognises AccECN cannot tell our intent. Got "
                f"flags={syn.flags!r}."
            ),
        )

    def test__accecn__bilateral_negotiation_via_accecn_capable_synack(self) -> None:
        """
        Ensure that when our active-open SYN advertised
        AccECN (AE+CWR+ECE) and the peer's SYN+ACK responds
        with one of the four AccECN-capable codepoints, the
        session sets '_accecn_enabled = True' post-handshake.
        The four codepoints encode which IP-ECN codepoint
        the peer received on our SYN; in this test we use
        the (AE=0, CWR=1, ECE=0) codepoint that signals
        "saw Not-ECT". Once '_accecn_enabled' is True the
        data-path uses the AccECN option (kind 172/173) to
        carry per-segment byte counters.

        Reference: RFC 9768 §3.1.1 (server AccECN-capable SYN+ACK).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        # AccECN-capable peer responds with the (AE=0, CWR=1,
        # ECE=0) codepoint - "I am AccECN-capable; I saw Not-
        # ECT on your SYN". The presence of CWR (without ECE)
        # is the wire signal an AccECN-capable client uses to
        # disambiguate from RFC 3168's (CWR=0, ECE=1) form.
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK", "CWR"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=(
                "Setup precondition: handshake MUST reach ESTABLISHED "
                f"on the AccECN-capable SYN+ACK. Got state={session.state!r}."
            ),
        )
        self.assertTrue(
            session._accecn_enabled,
            msg=(
                "RFC 9768 §3.1.1: when our SYN advertised AccECN "
                "and the peer's SYN+ACK carries one of the four "
                "AccECN-capable codepoints (here: AE=0, CWR=1, "
                "ECE=0 = saw Not-ECT), '_accecn_enabled' MUST "
                f"become True. Got _accecn_enabled={session._accecn_enabled}."
            ),
        )
        self.assertFalse(
            session._ecn_enabled,
            msg=(
                "When AccECN negotiation succeeds, the session "
                "uses AccECN (not RFC 3168 ECN). "
                "'_ecn_enabled' MUST remain False so the two "
                "paths cannot both fire. Got "
                f"_ecn_enabled={session._ecn_enabled}."
            ),
        )

    def test__accecn__active_open_rfc3168_only_synack_falls_back_to_classic_ecn(self) -> None:
        """
        Ensure that when our active-open SYN advertised
        AccECN (AE+CWR+ECE) and the peer's SYN+ACK responds
        with the classic RFC 3168 (AE=0, CWR=0, ECE=1) form
        - i.e. the peer recognised our SYN as ECN-setup but
        does not understand AccECN - the session falls back
        gracefully to RFC 3168 ECN: '_ecn_enabled' becomes
        True and '_accecn_enabled' stays False. This is the
        backward-compatibility guarantee that lets AccECN
        deploy incrementally on the internet.

        Reference: RFC 9768 §3.1.2 (active-open RFC 3168 fallback).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        # RFC-3168-only server: SYN+ACK with ECE alone, no
        # AE, no CWR. This is the codepoint a classic-ECN-
        # only server uses to confirm ECN; an AccECN-capable
        # server would set CWR or AE alongside.
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK", "ECE"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: handshake MUST reach ESTABLISHED.",
        )
        self.assertTrue(
            session._ecn_enabled,
            msg=(
                "RFC 9768 §3.1.2: when the peer's SYN+ACK is "
                "the RFC 3168 form (AE=0, CWR=0, ECE=1), the "
                "session MUST fall back to classic ECN. "
                f"Got _ecn_enabled={session._ecn_enabled}."
            ),
        )
        self.assertFalse(
            session._accecn_enabled,
            msg=(
                "RFC 9768 §3.1.2: classic RFC 3168 fallback "
                "MUST leave '_accecn_enabled' False. Got "
                f"_accecn_enabled={session._accecn_enabled}."
            ),
        )

    def _make_listen_session(self) -> TcpSession:
        """Build a wildcard-LISTEN 'TcpSocket' / 'TcpSession' pair."""

        self._force_iss(LOCAL__ISS)
        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = STACK__PORT
        sock._remote_ip_address = Ip4Address()
        sock._remote_port = 0
        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=STACK__PORT,
            remote_ip_address=Ip4Address(),
            remote_port=0,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock
        session.tcp_fsm(syscall=SysCall.LISTEN)
        return session

    def test__accecn__passive_open_syn_with_not_ect_emits_codepoint_a_synack(self) -> None:
        """
        Ensure that when a peer's AccECN-setup SYN
        (AE+CWR+ECE) arrives with the IP-ECN codepoint
        Not-ECT (00), the outbound SYN+ACK carries the
        canonical (AE=0, CWR=1, ECE=0) codepoint - the
        wire signal "AccECN-capable, saw Not-ECT on your
        SYN". The CWR-without-ECE encoding is what
        distinguishes the AccECN-capable response from a
        classic RFC 3168 (CWR=0, ECE=1) reply.

        Reference: RFC 9768 §3.1.1 (server SYN+ACK codepoint for received Not-ECT).
        """

        self._make_listen_session()

        # AccECN-setup SYN with IP-ECN = Not-ECT (00).
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN", "ECE", "CWR", "NS"),
            ip_ecn=0,
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)

        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK MUST fire on the next tick.",
        )
        syn_ack = self._parse_tx(syn_ack_tx[0])

        self.assertNotIn(
            "NS",
            syn_ack.flags,
            msg=(
                "RFC 9768 §3.1.1: SYN+ACK responding to a "
                "Not-ECT AccECN SYN MUST clear the AE flag "
                "(the canonical codepoint is AE=0, CWR=1, "
                f"ECE=0). Got flags={syn_ack.flags!r}."
            ),
        )
        self.assertIn(
            "CWR",
            syn_ack.flags,
            msg=(
                "RFC 9768 §3.1.1: SYN+ACK responding to a "
                "Not-ECT AccECN SYN MUST set the CWR flag "
                "(the canonical codepoint is AE=0, CWR=1, "
                f"ECE=0). Got flags={syn_ack.flags!r}."
            ),
        )
        self.assertNotIn(
            "ECE",
            syn_ack.flags,
            msg=(
                "RFC 9768 §3.1.1: SYN+ACK responding to a "
                "Not-ECT AccECN SYN MUST clear the ECE flag "
                "(the canonical codepoint is AE=0, CWR=1, "
                f"ECE=0). Got flags={syn_ack.flags!r}."
            ),
        )

    def test__accecn__passive_open_syn_with_ect_zero_emits_codepoint_c_synack(self) -> None:
        """
        Ensure that when a peer's AccECN-setup SYN
        (AE+CWR+ECE) arrives with the IP-ECN codepoint
        ECT(0) (10 - the canonical ECN-Capable codepoint),
        the outbound SYN+ACK carries the (AE=1, CWR=0,
        ECE=0) codepoint. This is one of the two codepoints
        with AE=1 set, the wire signal that the received
        SYN was a marked packet (ECT(0) or CE) rather than
        an unmarked one.

        Reference: RFC 9768 §3.1.1 (server SYN+ACK codepoint for received ECT(0)).
        """

        self._make_listen_session()

        # AccECN-setup SYN with IP-ECN = ECT(0) (10).
        peer_syn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN", "ECE", "CWR", "NS"),
            ip_ecn=2,
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn)

        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK MUST fire on the next tick.",
        )
        syn_ack = self._parse_tx(syn_ack_tx[0])

        self.assertIn(
            "NS",
            syn_ack.flags,
            msg=(
                "RFC 9768 §3.1.1: SYN+ACK responding to an "
                "ECT(0) AccECN SYN MUST set the AE flag "
                "(the canonical codepoint is AE=1, CWR=0, "
                f"ECE=0). Got flags={syn_ack.flags!r}."
            ),
        )
        self.assertNotIn(
            "CWR",
            syn_ack.flags,
            msg=(
                "RFC 9768 §3.1.1: SYN+ACK responding to an "
                "ECT(0) AccECN SYN MUST clear the CWR flag "
                "(the canonical codepoint is AE=1, CWR=0, "
                f"ECE=0). Got flags={syn_ack.flags!r}."
            ),
        )
        self.assertNotIn(
            "ECE",
            syn_ack.flags,
            msg=(
                "RFC 9768 §3.1.1: SYN+ACK responding to an "
                "ECT(0) AccECN SYN MUST clear the ECE flag "
                "(the canonical codepoint is AE=1, CWR=0, "
                f"ECE=0). Got flags={syn_ack.flags!r}."
            ),
        )

    def _drive_handshake_to_established_with_accecn(self) -> TcpSession:
        """
        Drive an active-open three-way handshake to ESTABLISHED
        with bilateral AccECN successfully negotiated. Returns
        the session AND the third-leg ACK frame so tests can
        inspect the post-handshake ACE encoding.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        # AccECN-capable peer SYN+ACK (AE=0, CWR=1, ECE=0
        # codepoint: "I am AccECN-capable; saw Not-ECT").
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK", "CWR"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        assert session.state is FsmState.ESTABLISHED, (
            "Setup precondition: handshake must reach ESTABLISHED. " f"Got state={session.state!r}."
        )
        assert session._accecn_enabled, (
            "Setup precondition: bilateral AccECN must succeed. " f"Got _accecn_enabled={session._accecn_enabled}."
        )
        return session

    def _drive_third_leg_ack_with_synack_ipecn(self, ip_ecn: int) -> TcpProbe:
        """
        Drive an active-open through the third-leg ACK, with the
        peer's SYN+ACK carrying the supplied IP-ECN codepoint.
        Returns the parsed third-leg ACK probe.
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK", "CWR"),
            win=PEER__WIN,
            mss=PEER__MSS,
            ip_ecn=ip_ecn,
        )
        third_leg_tx = self._drive_rx(frame=peer_syn_ack)

        assert session.state is FsmState.ESTABLISHED, (
            "Setup precondition: handshake reaches ESTABLISHED. " f"Got state={session.state!r}."
        )
        assert len(third_leg_tx) == 1, (
            "Setup precondition: third-leg ACK MUST fire inline. " f"Got {len(third_leg_tx)} TX frames."
        )
        self._last_handshake_session = session
        return self._parse_tx(third_leg_tx[0])

    def test__accecn__handshake_encoding_not_ect_synack_emits_ace_010(self) -> None:
        """
        Ensure that on the active-open third-leg ACK following a
        SYN+ACK whose IP-ECN was Not-ECT (00), the AE+CWR+ECE
        flags carry the handshake encoding 010 (AE=0, CWR=1,
        ECE=0). The handshake encoding lets the server compare
        what IP-ECN it set on its SYN+ACK against what the
        client reports it received, enabling detection of IP-ECN
        mangling along the path.

        Reference: RFC 9768 §3.2.2.1 (Table 3 handshake encoding for ACK of SYN/ACK).
        """

        ack = self._drive_third_leg_ack_with_synack_ipecn(ip_ecn=0)

        self.assertNotIn("NS", ack.flags, msg=f"AE MUST be 0 for Not-ECT-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertIn("CWR", ack.flags, msg=f"CWR MUST be 1 for Not-ECT-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertNotIn("ECE", ack.flags, msg=f"ECE MUST be 0 for Not-ECT-on-SYN/ACK. Got flags={ack.flags!r}.")

    def test__accecn__handshake_encoding_ect1_synack_emits_ace_011(self) -> None:
        """
        Ensure that on the active-open third-leg ACK following a
        SYN+ACK whose IP-ECN was ECT(1) (01), the AE+CWR+ECE
        flags carry the handshake encoding 011 (AE=0, CWR=1,
        ECE=1).

        Reference: RFC 9768 §3.2.2.1 (Table 3 handshake encoding for ACK of SYN/ACK).
        """

        ack = self._drive_third_leg_ack_with_synack_ipecn(ip_ecn=1)

        self.assertNotIn("NS", ack.flags, msg=f"AE MUST be 0 for ECT(1)-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertIn("CWR", ack.flags, msg=f"CWR MUST be 1 for ECT(1)-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertIn("ECE", ack.flags, msg=f"ECE MUST be 1 for ECT(1)-on-SYN/ACK. Got flags={ack.flags!r}.")

    def test__accecn__handshake_encoding_ect0_synack_emits_ace_100(self) -> None:
        """
        Ensure that on the active-open third-leg ACK following a
        SYN+ACK whose IP-ECN was ECT(0) (10), the AE+CWR+ECE
        flags carry the handshake encoding 100 (AE=1, CWR=0,
        ECE=0).

        Reference: RFC 9768 §3.2.2.1 (Table 3 handshake encoding for ACK of SYN/ACK).
        """

        ack = self._drive_third_leg_ack_with_synack_ipecn(ip_ecn=2)

        self.assertIn("NS", ack.flags, msg=f"AE MUST be 1 for ECT(0)-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertNotIn("CWR", ack.flags, msg=f"CWR MUST be 0 for ECT(0)-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertNotIn("ECE", ack.flags, msg=f"ECE MUST be 0 for ECT(0)-on-SYN/ACK. Got flags={ack.flags!r}.")

    def test__accecn__handshake_encoding_ce_synack_emits_ace_110(self) -> None:
        """
        Ensure that on the active-open third-leg ACK following a
        SYN+ACK whose IP-ECN was CE (11), the AE+CWR+ECE flags
        carry the handshake encoding 110 (AE=1, CWR=1, ECE=0).

        Reference: RFC 9768 §3.2.2.1 (Table 3 handshake encoding for ACK of SYN/ACK).
        """

        ack = self._drive_third_leg_ack_with_synack_ipecn(ip_ecn=3)

        self.assertIn("NS", ack.flags, msg=f"AE MUST be 1 for CE-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertIn("CWR", ack.flags, msg=f"CWR MUST be 1 for CE-on-SYN/ACK. Got flags={ack.flags!r}.")
        self.assertNotIn("ECE", ack.flags, msg=f"ECE MUST be 0 for CE-on-SYN/ACK. Got flags={ack.flags!r}.")

    def test__accecn__ce_marked_synack_increments_r_cep_to_6(self) -> None:
        """
        Ensure that when the active-open client receives a CE-
        marked SYN+ACK, the receiver-side 'r.cep' counter
        increments from its initial value 5 to 6. This ensures
        the CE marking is reliably delivered back to the server
        once the client starts using the ACE field on subsequent
        post-handshake segments. The increment is a one-shot
        cap: even multiple CE-marked SYN+ACKs (retransmissions)
        only advance r.cep by 1.

        Reference: RFC 9768 §3.2.2.2 (CE on SYN/ACK increments r.cep, capped at +1).
        """

        self._drive_third_leg_ack_with_synack_ipecn(ip_ecn=3)
        session = self._last_handshake_session

        self.assertEqual(
            session._accecn_r_cep,
            6,
            msg=(
                "RFC 9768 §3.2.2.2: a CE-marked SYN+ACK MUST "
                "increment r.cep from 5 to 6 so the marking is "
                "reliably delivered to the peer via the ACE "
                f"field. Got _accecn_r_cep={session._accecn_r_cep}."
            ),
        )

    def test__accecn__post_handshake_data_ack_uses_regular_ace_encoding(self) -> None:
        """
        Ensure that after the handshake-encoded third-leg ACK,
        a subsequent outbound ACK (e.g. acknowledging an inbound
        data segment) uses the regular 'r.cep & 7' ACE encoding
        instead of the handshake encoding. The handshake encoding
        is one-shot per connection setup.

        Reference: RFC 9768 §3.2.2 (regular ACE encoding on non-handshake segments).
        """

        # Drive handshake with Not-ECT SYN+ACK so r.cep stays at 5
        # → regular encoding ACE = 5 = 0b101 = (AE=1, CWR=0, ECE=1).
        self._drive_third_leg_ack_with_synack_ipecn(ip_ecn=0)
        session = self._last_handshake_session

        # Send an inbound data segment to elicit a non-handshake
        # outbound ACK after the delayed-ACK timer fires.
        peer_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=b"hello",
        )
        self._drive_rx(frame=peer_data)
        ack_tx = self._advance(ms=200)

        self.assertEqual(
            len(ack_tx),
            1,
            msg=f"Setup precondition: delayed-ACK must fire. Got {len(ack_tx)} TX frames.",
        )
        ack = self._parse_tx(ack_tx[0])

        self.assertIn(
            "NS",
            ack.flags,
            msg=f"Regular ACE = 5 (binary 101) MUST set AE = 1. Got flags={ack.flags!r}.",
        )
        self.assertNotIn(
            "CWR",
            ack.flags,
            msg=f"Regular ACE = 5 (binary 101) MUST clear CWR. Got flags={ack.flags!r}.",
        )
        self.assertIn(
            "ECE",
            ack.flags,
            msg=f"Regular ACE = 5 (binary 101) MUST set ECE = 1. Got flags={ack.flags!r}.",
        )
        self.assertEqual(
            session._accecn_r_cep,
            5,
            msg=(
                "Setup precondition: r.cep MUST stay at 5 after a "
                "non-CE inbound segment (the inbound data is "
                "Not-ECT). Got "
                f"_accecn_r_cep={session._accecn_r_cep}."
            ),
        )

    def test__accecn__inbound_ce_increments_ace_counter(self) -> None:
        """
        Ensure that when an inbound segment arrives with the
        IP-ECN codepoint CE (11) on an AccECN-enabled
        connection, the receiver-side r.cep counter
        increments and the next outbound segment encodes the
        new value (6 = binary 110 = AE=1, CWR=1, ECE=0) in
        the AE+CWR+ECE flags. This is the substrate granular
        feedback that AccECN provides over RFC 3168's binary
        signal: the sender reads counter deltas across ACKs
        to count CE marks accurately.

        Reference: RFC 9768 §3.2.2 (r.cep counter increment on inbound CE).
        """

        session = self._drive_handshake_to_established_with_accecn()

        # Peer sends one CE-marked data segment.
        ce_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            ip_ecn=3,
            payload=b"congested!",
        )
        self._drive_rx(frame=ce_data)

        # Drain the delayed-ACK timer; the cumulative ACK
        # fires after the timer expiry.
        ack_tx = self._advance(ms=200)
        self.assertEqual(
            len(ack_tx),
            1,
            msg=(
                "Setup precondition: cumulative ACK MUST fire after "
                f"the delayed-ACK timer. Got {len(ack_tx)} TX frames."
            ),
        )
        ack = self._parse_tx(ack_tx[0])

        # ACE = 6 = binary 110 -> AE=1, CWR=1, ECE=0.
        self.assertEqual(
            session._accecn_r_cep,
            6,
            msg=(
                "RFC 9768 §3.2.2: r.cep MUST advance from 5 to 6 "
                "on receipt of one CE-marked inbound segment. Got "
                f"_accecn_r_cep={session._accecn_r_cep}."
            ),
        )
        self.assertIn(
            "NS",
            ack.flags,
            msg=(
                "RFC 9768 §3.2.2: ACE = 6 (binary 110) MUST "
                "encode AE (NS bit) = 1 on the next outbound "
                f"segment. Got flags={ack.flags!r}."
            ),
        )
        self.assertIn(
            "CWR",
            ack.flags,
            msg=(
                "RFC 9768 §3.2.2: ACE = 6 (binary 110) MUST "
                "encode CWR = 1 on the next outbound segment. "
                f"Got flags={ack.flags!r}."
            ),
        )
        self.assertNotIn(
            "ECE",
            ack.flags,
            msg=(
                "RFC 9768 §3.2.2: ACE = 6 (binary 110) MUST "
                "encode ECE = 0 on the next outbound segment. "
                f"Got flags={ack.flags!r}."
            ),
        )

    def test__accecn__post_handshake_first_segment_carries_accecn_option_with_initial_counters(self) -> None:
        """
        Ensure that the first outbound non-SYN segment after
        an AccECN handshake carries the AccECN option (kind
        172, AccECN0 form) with the spec-mandated initial
        counter values: r.ECT(0)=1, r.CE=0, r.ECT(1)=1. The
        non-zero r.ECT(0) and r.ECT(1) initial values
        distinguish a freshly-negotiated session from
        middlebox-zeroed fields; r.CE starts at 0 because
        zero CE marks at connection start is the expected
        steady state.

        Reference: RFC 9768 §3.2.1 (Initialization of Feedback Counters).
        Reference: RFC 9768 §3.2.3 (AccECN option emission post-handshake).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK", "CWR"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        third_leg_tx = self._drive_rx(frame=peer_syn_ack)

        self.assertEqual(
            len(third_leg_tx),
            1,
            msg="Setup precondition: third-leg ACK MUST fire inline.",
        )
        ack = self._parse_tx(third_leg_tx[0])

        self.assertIsNotNone(
            ack.accecn,
            msg=(
                "RFC 9768 §3.2.3: the first outbound non-SYN "
                "segment of an AccECN-enabled connection MUST "
                "carry the AccECN option (kind 172). Got "
                f"accecn={ack.accecn!r}."
            ),
        )
        self.assertEqual(
            ack.accecn,
            (1, 0, 1),
            msg=(
                "RFC 9768 §3.2.1: the AccECN option's three "
                "byte counters MUST start at (r.ECT(0)=1, "
                "r.CE=0, r.ECT(1)=1) immediately after the "
                "handshake. Non-zero ECT counters distinguish "
                "a freshly-negotiated session from middlebox-"
                f"zeroed fields. Got accecn={ack.accecn!r}."
            ),
        )

    def test__accecn__inbound_ce_data_segment_increments_r_ce_byte_counter(self) -> None:
        """
        Ensure that when an inbound data segment arrives with
        the IP-ECN codepoint CE (11) on an AccECN-enabled
        connection, the r.CE byte counter increments by the
        TCP-payload byte length (not by 1) and the next
        outbound segment's AccECN option carries the new
        value in its second slot. The byte-precision counter
        is what gives AccECN its granularity over RFC 3168's
        binary signal: a sender can read the delta in
        r.CE-bytes across two ACKs to compute exactly how
        many bytes the network marked.

        Reference: RFC 9768 §3.2.3 (r.CE byte counter increment by payload length).
        """

        session = self._drive_handshake_to_established_with_accecn()

        payload = b"congested-data"
        ce_data = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            ip_ecn=3,
            payload=payload,
        )
        self._drive_rx(frame=ce_data)

        ack_tx = self._advance(ms=200)
        self.assertEqual(
            len(ack_tx),
            1,
            msg="Setup precondition: cumulative ACK MUST fire after delayed-ACK timer.",
        )
        ack = self._parse_tx(ack_tx[0])

        self.assertEqual(
            session._accecn_r_ce_b,
            len(payload),
            msg=(
                "RFC 9768 §3.2.3: r.CEB MUST advance by the "
                f"TCP-payload byte length ({len(payload)}). Got "
                f"_accecn_r_ce_b={session._accecn_r_ce_b}."
            ),
        )
        self.assertIsNotNone(
            ack.accecn,
            msg="RFC 9768 §3.2.3: outbound ACK MUST carry the AccECN option.",
        )
        self.assertEqual(
            ack.accecn,
            (1, len(payload), 1),
            msg=(
                "RFC 9768 §3.2.3: the AccECN option's r.CE "
                "byte counter (second slot) MUST equal the "
                f"cumulative CE-marked payload bytes ({len(payload)}). "
                "r.ECT(0) and r.ECT(1) remain at their §3.2.1 "
                f"initial value of 1. Got accecn={ack.accecn!r}."
            ),
        )

    def test__accecn__inbound_option_with_increased_r_ce_triggers_cwnd_reduction(self) -> None:
        """
        Ensure that on an AccECN-enabled connection, when a
        peer's inbound ACK carries an AccECN option whose r.CE
        byte counter has increased since the last received
        option, the sender treats it as a congestion event:
        ssthresh is halved and cwnd is collapsed to ssthresh.
        This is the substrate proportional-response that
        AccECN provides; for a full L4S-style scalable
        response a CC-mode-aware formula would weight the
        reduction by the marked-byte fraction, but the per-
        RTT halving is the canonical backwards-compatible
        fallback.

        Reference: RFC 9768 §3.4 (sender response to AccECN feedback).
        Reference: RFC 5681 §3.1 (ssthresh halving on congestion event).
        """

        session = self._drive_handshake_to_established_with_accecn()
        # Send enough data for flight_size to exceed the
        # 2*SMSS ABE floor; PyTCP fires one segment per ms
        # tick so advance ms=10 to drain the send buffer
        # before we capture flight_size_before.
        payload = b"x" * 6000
        session.send(data=payload)
        self._advance(ms=10)

        snd_mss = session._snd_mss
        flight_size_before = (session._snd_max - session._snd_una) & 0xFFFF_FFFF
        # RFC 8511 ABE: on ECN-class events the sender uses a
        # less aggressive multiplier (0.85) than the RFC 5681
        # §3.1 0.5 used for loss events. The 17/20 integer
        # ratio yields the canonical ABE value 0.85.
        expected_ssthresh = max(flight_size_before * 17 // 20, 2 * snd_mss)

        # Peer's ACK reporting a non-zero r.CE byte count
        # (1500 bytes marked CE - one MSS-sized packet).
        ack_with_ce = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            accecn0_counters=(0, 1500, 0),
        )
        self._drive_rx(frame=ack_with_ce)

        self.assertEqual(
            session._ssthresh,
            expected_ssthresh,
            msg=(
                "RFC 8511 §3 ABE: on AccECN feedback with positive "
                "r.CE delta the sender uses the less-aggressive "
                "ABE backoff multiplier (0.85) instead of RFC 5681 "
                "§3.1's 0.5 used for loss events. Expected "
                "'max(flight_size * 17 // 20, 2*SMSS)' = "
                f"{expected_ssthresh}, got {session._ssthresh}. "
                f"Pre-event flight_size was {flight_size_before}."
            ),
        )
        self.assertEqual(
            session._cwnd,
            expected_ssthresh,
            msg=(
                "RFC 9768 §3.4: on AccECN feedback with positive "
                "r.CE delta the sender MUST collapse cwnd to "
                f"ssthresh. Got cwnd={session._cwnd}, "
                f"ssthresh={session._ssthresh}."
            ),
        )
        self.assertEqual(
            session._accecn_s_ce_b,
            1500,
            msg=(
                "RFC 9768 §3.4: the sender-side r.CE tracker "
                "MUST advance to the latest value reported by "
                "the peer (1500). Got "
                f"_accecn_s_ce_b={session._accecn_s_ce_b}."
            ),
        )

    def test__accecn__inbound_option_with_unchanged_r_ce_does_not_reduce_cwnd(self) -> None:
        """
        Ensure that an inbound AccECN option carrying the
        same r.CE byte counter as the previously-tracked
        value does not trigger a spurious cwnd reduction.
        Without this idempotency guard, a sender that
        receives multiple ACKs all reporting the same
        cumulative r.CE byte count would reduce cwnd on
        every ACK, defeating the per-RTT-event semantics.

        Reference: RFC 9768 §3.4 (no reduction without delta).
        """

        session = self._drive_handshake_to_established_with_accecn()
        session.send(data=b"x" * 4000)
        self._advance(ms=1)

        cwnd_before = session._cwnd
        ssthresh_before = session._ssthresh

        # Peer's ACK with r.CE=0 (no congestion observed).
        clean_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            accecn0_counters=(0, 0, 0),
        )
        self._drive_rx(frame=clean_ack)

        self.assertEqual(
            session._ssthresh,
            ssthresh_before,
            msg=(
                "RFC 9768 §3.4: a peer's AccECN option with "
                "r.CE unchanged from the prior tracker value "
                "MUST NOT trigger ssthresh reduction. Got "
                f"ssthresh_before={ssthresh_before}, "
                f"ssthresh={session._ssthresh}."
            ),
        )
        self.assertEqual(
            session._cwnd,
            cwnd_before,
            msg=(
                "RFC 9768 §3.4: a peer's AccECN option with "
                "r.CE unchanged from the prior tracker value "
                "MUST NOT trigger cwnd reduction. Got "
                f"cwnd_before={cwnd_before}, "
                f"cwnd={session._cwnd}."
            ),
        )
