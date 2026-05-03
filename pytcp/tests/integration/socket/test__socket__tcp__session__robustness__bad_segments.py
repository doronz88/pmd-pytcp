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
This module contains integration tests for 'TcpSession' robustness
against malformed inbound TCP segments. The TCP parser handles the
checksum / structural-integrity layer (covered by parser unit
tests); this file covers the FSM's behaviour when the parser does
let a structurally-valid but semantically-malformed segment through
- e.g. illegal flag combinations like FIN+RST.

Reference RFCs:
    RFC 9293 §3.1        Control Bits semantics
    RFC 9293 §3.10.7.4   Synchronized state segment processing

pytcp/tests/integration/socket/test__socket__tcp__session__robustness__bad_segments.py

ver 3.0.4
"""

from net_addr import Ip4Address
from pytcp import stack
from pytcp.protocols.tcp.tcp__session import (
    DELAYED_ACK_DELAY,
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

# Peer's MSS option value on its SYN+ACK reply.
PEER__MSS: int = 1460


class TestTcpRobustness__BadSegments(TcpSessionTestCase):
    """
    Integration tests for 'TcpSession' robustness against malformed
    inbound TCP segments that the parser passes through but the FSM
    must reject (illegal flag combinations, etc.).
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

    def _drive_handshake_to_established(self, *, iss: int, peer_iss: int) -> TcpSession:
        """
        Drive the active-open three-way handshake to ESTABLISHED.
        """

        session = self._make_active_session(iss=iss)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=peer_iss,
            ack=iss + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
        )
        self._drive_rx(frame=peer_syn_ack)

        assert (
            session.state is FsmState.ESTABLISHED
        ), f"Handshake setup failed: state is {session.state!r}, expected ESTABLISHED."
        return session

    def test__bad_segments__fin_plus_rst_in_established_drops_silently(self) -> None:
        """
        Ensure that a segment carrying BOTH the FIN and RST flags
        - an illegal combination per RFC 9293 §3.1 - is silently
        dropped on receipt: state is unchanged, no segment is
        emitted in response, and 'RCV.NXT' / 'SND.UNA' do not
        advance.

        FIN and RST encode mutually exclusive intents (graceful
        connection termination vs. abortive reset) and no
        legitimate conformant TCP will send a segment with both
        flags set. Such a segment can come from:

            - A malformed implementation (rare).
            - An off-path attacker probing for confused-state
              behaviour (the blind-attack threat model from RFC
              5961).
            - A stale segment from a previous connection where
              flag bits became corrupted in transit.

        In all three cases the safe response is to drop. RFC 9293
        §3.10.7.4's branches for synchronized states cleanly
        separate FIN and RST: the FIN+ACK branch (line 1469-1485)
        excludes RST, and the RST+ACK branch (line 1487-1511)
        excludes FIN. A FIN+RST segment matches neither and falls
        through, which is the spec-correct outcome - drop silently
        without any state change or reply.

        Scenario:

            1. Drive handshake to ESTABLISHED. Snapshot 'SND.UNA',
               'RCV.NXT', and state.
            2. Peer sends FIN+RST+ACK at 'SEQ = PEER__ISS + 1' (in
               window; valid seq) and 'ACK = LOCAL__ISS + 1' (in
               window; valid ack). The flags include the canonical
               ACK piggyback alongside the malformed FIN+RST.
            3. Drive RX. The FSM dispatcher routes to
               '_tcp_fsm_established'. None of the FIN+ACK,
               RST+ACK, ACK-only, or SYN-on-syn branches match
               (FIN+RST is excluded by all of them), so the
               segment falls through.

        Assertions:

            * No outbound segment in response.
            * State is unchanged (still ESTABLISHED).
            * 'SND.UNA' is unchanged - the malformed segment must
              not advance the send sequence space, even though
              its ACK field is in [SND.UNA, SND.MAX].
            * 'RCV.NXT' is unchanged - the FIN's potential
              consumption of one byte of sequence space is
              forfeited because the segment is dropped before
              processing.

        This test passes on current code as a positive-control
        regression guard for the FSM's parser-tolerant rejection
        of malformed flag combinations. Future changes that
        relaxed the 'not any({tcp__flag_rst})' or 'not any(
        {tcp__flag_fin})' exclusions in any of the
        '_tcp_fsm_established' branches would let the malformed
        segment match a handler and cause incorrect state
        progression.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        snd_una_before = session._snd_una
        rcv_nxt_before = session._rcv_nxt

        # Peer sends FIN+RST+ACK - the malformed flag combination.
        peer_fin_rst = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("FIN", "RST", "ACK"),
            win=PEER__WIN,
        )
        rst_inline = self._drive_rx(frame=peer_fin_rst)

        self.assertEqual(
            rst_inline,
            [],
            msg=(
                "A FIN+RST segment in ESTABLISHED MUST produce no "
                "outbound segment - the flag combination is malformed "
                "per RFC 9293 §3.1 and must be silently dropped before "
                "any state-changing branch sees it."
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg=("State must remain ESTABLISHED after a FIN+RST drop - " "neither the FIN nor the RST is processed."),
        )
        self.assertEqual(
            session._snd_una,
            snd_una_before,
            msg="'SND.UNA' must not advance on a dropped FIN+RST segment.",
        )
        self.assertEqual(
            session._rcv_nxt,
            rcv_nxt_before,
            msg=(
                "'RCV.NXT' must not advance on a dropped FIN+RST "
                "segment - the FIN's potential one-byte consumption "
                "is forfeited because the segment is rejected at the "
                "branch-matching layer."
            ),
        )

    def test__bad_segments__all_zero_flags_segment_in_established_drops_silently(self) -> None:
        """
        Ensure that a segment with NO flags set (the all-zero
        flags byte - no ACK, no SYN, no FIN, no RST, no PSH, no
        URG) is silently dropped on receipt in ESTABLISHED.

        RFC 9293 §3.10.7.4 (synchronized state segment processing,
        ACK validation):

            "If the ACK bit is off, drop the segment and return."

        i.e. once the connection is synchronized, every segment
        the peer sends MUST carry an ACK piggyback - the receiver
        is constantly observing the cumulative ACK as a heartbeat
        and a flow-control-window update. A flag-less segment is
        either malformed, stale, or an attacker probe; in all
        cases the safe response is to drop without reply.

        Scenario:

            1. Drive handshake to ESTABLISHED. Snapshot 'SND.UNA',
               'RCV.NXT', and state.
            2. Peer sends a segment with flags = empty tuple (the
               all-zero flags byte). 'SEQ' and 'ACK' fields are
               populated with valid in-window values to rule out
               other rejection paths.
            3. Drive RX. None of '_tcp_fsm_established's branches
               match: the ACK-only branch (line 1389) requires
               'all({tcp__flag_ack})'; the FIN+ACK / RST+ACK / SYN-
               on-syn branches all also require ACK. The segment
               falls through silently.

        Assertions:

            * No outbound segment in response.
            * State remains ESTABLISHED.
            * 'SND.UNA' is unchanged.
            * 'RCV.NXT' is unchanged.

        This test passes on current code as a positive-control
        regression guard for the FSM's ACK-required invariant.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        snd_una_before = session._snd_una
        rcv_nxt_before = session._rcv_nxt

        # Peer sends a flag-less segment.
        peer_no_flags = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=(),
            win=PEER__WIN,
        )
        no_flags_inline = self._drive_rx(frame=peer_no_flags)

        self.assertEqual(
            no_flags_inline,
            [],
            msg=(
                "An all-zero-flags segment in ESTABLISHED MUST "
                "produce no outbound reply - RFC 9293 §3.10.7.4: "
                "'If the ACK bit is off, drop the segment and "
                "return.'"
            ),
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED after a no-flags drop.",
        )
        self.assertEqual(
            session._snd_una,
            snd_una_before,
            msg="'SND.UNA' must not advance on a dropped no-flags segment.",
        )
        self.assertEqual(
            session._rcv_nxt,
            rcv_nxt_before,
            msg="'RCV.NXT' must not advance on a dropped no-flags segment.",
        )

    def test__bad_segments__ecn_flags_accepted_and_not_echoed(self) -> None:
        """
        Ensure that a non-ECN endpoint (which PyTCP is - we never
        negotiate ECN on the SYN handshake) correctly handles the
        two ECN-related flag bits that may appear on inbound
        segments per RFC 3168 / RFC 9293 §3.1:

            * Accept the segment normally (ECE / CWR are not
              segment-rejection criteria).
            * Do NOT echo ECE / CWR in our outbound reply (we
              haven't agreed to speak ECN, so any ECE/CWR we
              emit would be a misencoding peer might
              misinterpret).

        RFC 3168 §6.1.1 (originally introducing ECN to TCP):

            "If a TCP host has not agreed to negotiate ECN with its
             peer (using the ECE and CWR flags during the SYN
             exchange), the host MUST NOT set the ECE or CWR flags
             on any subsequent segment it transmits, and MUST treat
             any received ECE / CWR flags as having no effect."

        RFC 9293 §3.1 inherits this: the flag-bits diagram lists
        ECE / CWR as control bits, and §3.10.7.4's branch predicates
        do not test for ECE/CWR (only SYN/ACK/FIN/RST). So a
        conformant non-ECN implementation processes the segment as
        if those bits weren't there, and emits its own segments
        without setting them.

        Scenario:

            1. Drive handshake to ESTABLISHED. (Both SYNs in the
               handshake had no ECE/CWR, so ECN is not negotiated.)
            2. Peer sends a data segment of 5 bytes 'b"hello"' with
               flags = {ACK, PSH, ECE, CWR} - i.e. claiming ECN
               feedback even though we never agreed to ECN.
            3. Drive RX. The ESTABLISHED ACK-only data branch (line
               1389) does NOT exclude ECE/CWR (it only checks
               'all({tcp__flag_ack}) and not any({syn, rst, fin})'),
               so the segment matches and is processed normally:
               the data is enqueued into '_rx_buffer', RCV.NXT
               advances, and the delayed-ACK timer is armed.
            4. Tick past the delayed-ACK boundary so an outbound
               ACK fires.
            5. Inspect the outbound ACK: its flags must be exactly
               {ACK} - no ECE, no CWR.

        Assertions:

            * '_rx_buffer' contains the 5 bytes peer sent.
            * 'RCV.NXT' advanced by 5.
            * The outbound ACK carries flags = {ACK} only - ECE
              and CWR are absent. Asserted via the strict
              'frozenset({"ACK"})' equality check.

        This test passes on current code as a positive-control
        regression guard. PyTCP's '_transmit_packet' does not
        accept any 'flag_ece' / 'flag_cwr' parameter, so by
        construction it never sets those bits on outbound
        segments - the no-echo half of the contract is
        structurally guaranteed. The accept-and-process half
        relies on the FSM branch predicates not checking for
        ECN bits. A future change that added '"ECE"' to a
        'not any({...})' exclusion (e.g. as part of a misguided
        "tighten the predicate" cleanup) would silently start
        dropping ECN-marked segments and break this test.
        """

        session = self._drive_handshake_to_established(iss=LOCAL__ISS, peer_iss=PEER__ISS)

        # Peer sends a data segment with ECE+CWR set despite us
        # never having negotiated ECN on the SYN handshake.
        peer_payload = b"hello"
        peer_data_with_ecn = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK", "PSH", "ECE", "CWR"),
            win=PEER__WIN,
            payload=peer_payload,
        )
        ecn_inline = self._drive_rx(frame=peer_data_with_ecn)
        self.assertEqual(
            ecn_inline,
            [],
            msg=(
                "An ECN-marked data segment must follow the same "
                "delayed-ACK path as a plain data segment - no "
                "inline ACK fires for the first segment of a stream."
            ),
        )

        # Data was accepted and enqueued.
        self.assertEqual(
            bytes(session._rx_buffer),
            peer_payload,
            msg=(
                "Peer's data must be delivered to '_rx_buffer' even "
                "with ECE+CWR flags set. RFC 3168 §6.1.1 / RFC 9293 "
                "§3.1: non-ECN endpoint treats ECE/CWR as having no "
                "effect, processing the segment normally."
            ),
        )
        self.assertEqual(
            session._rcv_nxt,
            PEER__ISS + 1 + len(peer_payload),
            msg="'RCV.NXT' must advance by len(peer_payload) after the data is enqueued.",
        )

        # Tick past the delayed-ACK boundary to fire the outbound ACK.
        ack_window_tx = self._advance(ms=DELAYED_ACK_DELAY)
        self.assertEqual(
            len(ack_window_tx),
            1,
            msg=(
                f"Within {DELAYED_ACK_DELAY} ms of receipt the delayed-" "ACK timer must fire exactly one outbound ACK."
            ),
        )

        # The ACK must NOT echo ECE / CWR - we never agreed to ECN.
        outbound_ack = self._parse_tx(ack_window_tx[0])
        self.assertEqual(
            outbound_ack.flags,
            frozenset({"ACK"}),
            msg=(
                "Outbound ACK must carry flags = {ACK} only - no ECE, "
                "no CWR. PyTCP did not negotiate ECN on the SYN "
                "handshake, so RFC 3168 §6.1.1 forbids us from "
                "setting ECE or CWR on any subsequent transmission."
            ),
        )
