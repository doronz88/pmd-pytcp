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
This module contains integration tests for the TCP Window Scale
option (RFC 7323 §2) in the 'TcpSession' state machine. WSCALE is
the bilateral SYN-time option that lets either side advertise
windows larger than 65535 bytes by left-shifting the wire-level
'win' field by an agreed-upon factor on every post-handshake
segment. Without WSCALE the receive window is permanently capped
at 64 KB / RTT regardless of bandwidth - a 100 ms RTT link is
limited to ~5 Mbps even on a 1 Gbps physical pipe.

Reference RFCs:
    RFC 7323 §2.2    Window Scale Option negotiation
    RFC 7323 §2.3    Using the Window Scale Option

pytcp/tests/integration/socket/test__socket__tcp__session__wscale.py

ver 3.0.4
"""

from net_addr import Ip4Address
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
PEER__MSS: int = 1460

# The default WSCALE factor PyTCP advertises on its outbound SYN
# / SYN+ACK once the implementation lands. 7 yields a maximum
# advertised window of 65535 << 7 = 8_388_480 bytes (~8 MB),
# which matches the Linux / FreeBSD default and is sufficient
# for typical long-fat-pipe scenarios.
LOCAL__RCV_WSCALE: int = 7


class TestTcpSession__Wscale(TcpSessionTestCase):
    """
    Integration tests for the WSCALE option bilateral negotiation
    and post-handshake application to inbound and outbound window
    fields.
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

    def test__wscale__outbound_syn_advertises_wscale_option(self) -> None:
        """
        Ensure that an active-open session emits its initial SYN
        with the WSCALE option carrying a non-zero scaling factor,
        per RFC 7323 §2.2. Without our advertisement the bilateral
        negotiation fails closed (peer would have no reason to
        offer reciprocal scaling), and the connection is
        permanently throughput-capped at 64 KB / RTT regardless
        of how much bandwidth or buffer is available.

        RFC 7323 §2.2 (Window Scale Option):

            "The Window Scale option is sent only in a <SYN>
             segment ... A TCP MAY send the WSopt in only the
             <SYN> segment of the connection ... All windows
             field values in the segment exchanged on the
             connection are relative to the WSopt-Permitted
             Window Scale option (WSopt) value advertised in the
             initial SYN."

        Concretely:

            * The outbound SYN MUST carry the WSCALE option with a
              non-zero shift count. PyTCP defaults to '7' (yields
              max advertised window = 65535 << 7 ~= 8 MB),
              matching Linux/FreeBSD defaults.
            * The SYN's own 'win' field is NOT shifted (per RFC
              7323 §2.2 "WSopt is not used to scale the value in
              the window field of the SYN segment itself").

        Scenario:

            1. Build a session and emit our outbound SYN.
            2. Parse the SYN frame and inspect the WSCALE option.

        Assertions:

            * The outbound SYN carries 'wscale = LOCAL__RCV_WSCALE'
              (= 7) on the WSCALE option (the spec encoding).
            * The SYN's 'win' field equals the initial '_rcv_wnd'
              (65535) - NOT shifted.

        [FLAGS BUG] - 'TcpSession._transmit_packet' (line 568)
        currently emits 'tcp__wscale=0 if flag_syn else None'
        unconditionally, hard-coded. The session class has no
        '_advertise_wscale' / '_rcv_wsc' state to override this
        with a non-zero shift, so the WSCALE option is never
        emitted on outbound SYNs and the bilateral negotiation
        cannot complete.

        The fix is the WSCALE implementation:

            1. Add 'self._rcv_wsc: int = 7' (or a configurable
               default) to 'TcpSession.__init__'.
            2. Update '_transmit_packet' to emit
               'tcp__wscale=self._rcv_wsc' on SYN/SYN+ACK
               segments (gated on a 'self._advertise_wscale'
               bool that callers can flip if asymmetric-offer
               testing is needed).
            3. Apply the shift to outbound 'win' fields on
               post-handshake segments only (the SYN's own
               'win' stays unshifted).
            4. On inbound SYN/SYN+ACK with WSCALE, set
               'self._snd_wsc = peer.wscale' (gated on
               'self._advertise_wscale' so the asymmetric-
               offer rule from RFC 7323 §2.2 still holds).

        On current code this test fails at the
        'syn_probe.wscale == 7' assertion - the option is
        absent on the wire (probe.wscale == None).
        """

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)

        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        syn_probe = self._parse_tx(syn_tx[0])

        # Sanity: this is the SYN.
        self.assertEqual(
            syn_probe.flags,
            frozenset({"SYN"}),
            msg="Setup precondition: outbound segment must be a pure SYN.",
        )

        # The spec encoding: WSCALE option present with our
        # default shift count.
        self.assertEqual(
            syn_probe.wscale,
            LOCAL__RCV_WSCALE,
            msg=(
                f"Outbound SYN MUST carry the WSCALE option with "
                f"shift = {LOCAL__RCV_WSCALE} per RFC 7323 §2.2. "
                "Without our advertisement, peer cannot offer "
                "reciprocal scaling, and the connection is "
                "permanently throughput-capped at 64 KB / RTT. "
                "Current code's '_transmit_packet' line 568 "
                "hard-codes 'tcp__wscale=0', producing an "
                "option-absent wire form."
            ),
        )

        # Sanity: SYN's own 'win' field is NOT shifted (RFC 7323
        # §2.2). If the implementation accidentally shifted, the
        # advertised value would be capped at 65535 (the wire
        # limit) and we'd lose the no-scaling-in-SYN invariant.
        self.assertEqual(
            syn_probe.win,
            65535,
            msg=(
                "SYN's 'win' field MUST equal the unshifted "
                "initial '_rcv_wnd' (65535). Per RFC 7323 §2.2 "
                "'WSopt is not used to scale the value in the "
                "window field of the SYN segment itself' - the "
                "shift only applies to post-handshake segments."
            ),
        )

        # Side-state assertion: the session tracks its advertised
        # shift in '_rcv_wsc' so the post-handshake outbound
        # segments can apply the inverse shift to the
        # advertised window.
        self.assertEqual(
            session._rcv_wsc,
            LOCAL__RCV_WSCALE,
            msg=(
                f"Session '_rcv_wsc' must equal the advertised "
                f"shift ({LOCAL__RCV_WSCALE}) - it is the canonical "
                "place for post-handshake code to read 'how much "
                "to shift our outbound win field by'."
            ),
        )

    def test__wscale__bilateral_handshake_sets_both_directions(self) -> None:
        """
        Ensure that when both sides advertise WSCALE on the SYN /
        SYN+ACK exchange, the session ends up with both directions
        of scale state set: '_rcv_wsc' equal to OUR advertised
        shift (governs how we shift outbound 'win' fields) and
        '_snd_wsc' equal to PEER'S advertised shift (governs how
        we interpret inbound 'win' fields).

        RFC 7323 §2.2:

            "If a Window Scale option is received with a shift.cnt
             value larger than 14, the TCP SHOULD log the error but
             MUST use 14 instead of the specified value. ... A WSopt
             is sent only in <SYN> and <SYN,ACK> segments."

        and §2.3 (using WSCALE):

            "After the connection setup, the value of the WSopt
             received from the peer is used to scale the values of
             the window field of any received <ACK> segment, and
             the WSopt sent by this host is used to scale the
             window-field values of <ACK> segments sent by this
             host."

        Concretely, post-handshake:

            * Outbound segments carry 'win = (rcv_wnd) >> _rcv_wsc'.
            * Inbound segments are interpreted as
              '_snd_wnd = peer.win << _snd_wsc'.

        Scenario:

            1. Build session, drive 'CONNECT'. Outbound SYN carries
               our default WSCALE = 7 (covered by scenario #1).
            2. Peer replies with SYN+ACK carrying a DIFFERENT
               WSCALE value (10) so the two directions are
               distinguishable in assertions. RFC 7323 permits
               asymmetric shift counts; the values do not have to
               match.
            3. Drive RX. Handshake completes to ESTABLISHED.

        Assertions:

            * 'session.state' is ESTABLISHED.
            * 'session._rcv_wsc == 7' - our advertised shift,
              unchanged by peer's offer (the 'rcv' side is what
              we apply to OUR receive window for outbound 'win'
              fields).
            * 'session._snd_wsc == 10' - peer's advertised shift,
              applied to inbound 'win' fields. The bilateral
              negotiation succeeded because we offered WSCALE
              first.

        [FLAGS BUG] - same root cause as scenario #1. Without the
        WSCALE implementation, '_snd_wsc' currently stays at 0
        (the asymmetric-offer rule from 'data_transfer__window.py'
        scenario #2's fix kicks in). Once we DO advertise on
        outbound SYN, peer's WSCALE on the SYN+ACK becomes legal
        bilateral and must be honoured.
        """

        peer_wscale = 10
        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            wscale=peer_wscale,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: handshake must complete to ESTABLISHED.",
        )

        # Our advertised shift (governs outbound win shifts).
        self.assertEqual(
            session._rcv_wsc,
            LOCAL__RCV_WSCALE,
            msg=(
                f"Session '_rcv_wsc' must equal our advertised "
                f"shift ({LOCAL__RCV_WSCALE}). It is unchanged by "
                "peer's offer; the 'rcv' side governs the shift we "
                "apply to OUR receive window when filling the "
                "outbound 'win' field."
            ),
        )

        # Peer's advertised shift (governs inbound win interpretation).
        self.assertEqual(
            session._snd_wsc,
            peer_wscale,
            msg=(
                f"Session '_snd_wsc' must equal peer's advertised "
                f"shift ({peer_wscale}) per RFC 7323 §2.3 - the "
                "'snd' side governs how we interpret peer's "
                "inbound 'win' fields. The bilateral negotiation "
                "succeeded because we advertised WSCALE on our "
                "outbound SYN (scenario #1), so peer's offer is "
                "now legal bilateral. With no advertisement on "
                "our side, the asymmetric-offer rule from "
                "'data_transfer__window.py' #2 would force this "
                "to remain 0; that test will need to flip its "
                "expected behaviour once WSCALE lands."
            ),
        )

    def test__wscale__peer_wscale_applied_to_inbound_window(self) -> None:
        """
        Ensure that after a bilateral WSCALE negotiation, the peer's
        post-handshake 'win' field is interpreted as
        '_snd_wnd = peer.win << _snd_wsc' per RFC 7323 §2.3. The
        SYN+ACK's own 'win' field is NOT shifted (RFC 7323 §2.2);
        the shift applies only to subsequent segments.

        RFC 7323 §2.3 (Using the Window Scale Option):

            "After the connection setup, the value of the WSopt
             received from the peer is used to scale the values of
             the window field of any received <ACK> segment..."

        This is the wire-level consequence of scenario #2's
        '_snd_wsc' state assertion: the shift state is only useful
        if the code actually applies it. The existing
        '_process_ack_packet' shifts via 'packet_rx_md.tcp__win <<
        self._snd_wsc' (line ~915), so once '_snd_wsc' is set
        correctly post-handshake, the application is automatic.

        Scenario:

            1. Drive bilateral WSCALE handshake (us=7, peer=10).
            2. Peer sends a post-handshake bare ACK with
               'win=1024'.
            3. Verify '_snd_wnd = 1024 << 10 = 1_048_576'.

        Assertions:

            * After peer's post-handshake ACK with 'win=1024' and
              negotiated 'snd_wsc=10', 'session._snd_wnd' equals
              '1_048_576' (~1 MB) - clearly above the 65535
              unscaled cap.
            * State remains ESTABLISHED.

        [FLAGS BUG] - Same root cause as #1 / #2. Once those
        flip green via the WSCALE implementation, this test
        flips green automatically because the shift logic
        already exists in '_process_ack_packet' line ~915.
        """

        peer_wscale = 10
        peer_post_handshake_win = 1024

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            wscale=peer_wscale,
        )
        self._drive_rx(frame=peer_syn_ack)
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: bilateral WSCALE handshake must complete.",
        )

        # Peer post-handshake ACK + 1 byte of data with win=1024.
        # The 1-byte payload steers the segment through the
        # data-handling branch (and thus '_process_ack_packet'
        # which updates '_snd_wnd'); a bare ACK at 'ack ==
        # SND.UNA, no data' would be intercepted as a duplicate
        # ACK and would not refresh the send-window state.
        peer_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK", "PSH"),
            win=peer_post_handshake_win,
            payload=b"x",
        )
        self._drive_rx(frame=peer_ack)

        # The spec encoding: _snd_wnd is shifted.
        expected_snd_wnd = peer_post_handshake_win << peer_wscale
        self.assertEqual(
            session._snd_wnd,
            expected_snd_wnd,
            msg=(
                f"Peer's post-handshake 'win = {peer_post_handshake_win}' "
                f"with negotiated 'snd_wsc = {peer_wscale}' must "
                f"yield '_snd_wnd = {peer_post_handshake_win} << "
                f"{peer_wscale} = {expected_snd_wnd}' per RFC 7323 "
                "§2.3. Catching 1024 here would mean the shift "
                "did NOT get applied (the unscaled value leaked "
                "through), confirming the bilateral negotiation "
                "did not record peer's wscale."
            ),
        )

        # Sanity: state still ESTABLISHED.
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED after a normal post-handshake ACK.",
        )

    def test__wscale__outbound_window_advertised_with_local_wscale_shift(self) -> None:
        """
        Ensure that the wire-level 'win' field in our post-handshake
        outbound segments is right-shifted by '_rcv_wsc', so the
        peer reconstructs our actual receive window via 'peer_snd_wnd
        = wire_win << our_wsc'. Without the shift, our advertisable
        receive window stays capped at 65535 bytes regardless of
        '_rcv_wnd_max'; with the shift, we can advertise effective
        windows up to '65535 << 7 = 8_388_480' bytes (~8 MB) even
        though the wire field is only 16 bits.

        RFC 7323 §2.3:

            "After the connection setup ... the WSopt sent by this
             host is used to scale the window-field values of <ACK>
             segments sent by this host."

        Concretely: 'wire_win = _rcv_wnd >> _rcv_wsc'. The shift is
        lossy in the low '_rcv_wsc' bits (peer reconstructs to
        'wire_win << _rcv_wsc' which truncates the LSBs). This is
        a documented and accepted property of WSCALE - the
        "granularity" of the advertised window is '2 ** _rcv_wsc'
        bytes.

        Scenario:

            1. Drive bilateral WSCALE handshake (us=7, peer=10).
            2. Peer sends two back-to-back 100-byte data segments
               so the every-other-segment rule produces an inline
               cumulative ACK.
            3. Inspect the outbound ACK's 'win' field.

        Assertions:

            * 'wire_win = (_rcv_wnd_max - len(_rx_buffer)) >> 7'.
              With '_rcv_wnd_max = 65535' and 200 bytes in
              '_rx_buffer', actual rcv_wnd = 65335 and
              'wire_win = 65335 >> 7 = 510'.
            * State remains ESTABLISHED.

        [FLAGS BUG] - Same root cause as #1 / #2. Once those flip
        green via the WSCALE implementation, this test asserts the
        outbound 'win' is correctly shifted. Without the shift,
        the outbound 'win' would stay at 'rcv_wnd' clamped to 65535
        - good for non-WSCALE peers but throws away the bandwidth
        opportunity for WSCALE-capable peers.

        The fix in '_transmit_packet' is a one-line change: pass
        'tcp__win=self._rcv_wnd >> self._rcv_wsc' instead of
        'tcp__win=self._rcv_wnd' (gated on 'state in synchronized
        states' so the SYN's own 'win' stays unshifted per scenario
        #6).
        """

        peer_wscale = 10

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=PEER__WIN,
            mss=PEER__MSS,
            wscale=peer_wscale,
        )
        self._drive_rx(frame=peer_syn_ack)
        self.assertIs(session.state, FsmState.ESTABLISHED)

        # Two 100-byte data segments back-to-back; second one
        # triggers inline ACK via every-other-segment rule.
        seg_len = 100
        seg1 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1,
            ack=LOCAL__ISS + 1,
            flags=("ACK", "PSH"),
            win=1024,
            payload=b"X" * seg_len,
        )
        seg1_inline = self._drive_rx(frame=seg1)
        self.assertEqual(
            seg1_inline,
            [],
            msg="Setup precondition: first segment must not produce an inline ACK.",
        )

        seg2 = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + seg_len,
            ack=LOCAL__ISS + 1,
            flags=("ACK", "PSH"),
            win=1024,
            payload=b"Y" * seg_len,
        )
        seg2_inline = self._drive_rx(frame=seg2)
        self.assertEqual(
            len(seg2_inline),
            1,
            msg=(
                "Setup precondition: second segment must produce "
                "exactly one inline cumulative ACK via the "
                "every-other-segment rule."
            ),
        )

        ack_probe = self._parse_tx(seg2_inline[0])

        # The spec encoding: wire_win = (rcv_wnd_max - buffer_fill)
        # >> _rcv_wsc.
        actual_rcv_wnd = 65535 - 2 * seg_len
        expected_wire_win = actual_rcv_wnd >> LOCAL__RCV_WSCALE
        self.assertEqual(
            ack_probe.win,
            expected_wire_win,
            msg=(
                f"Outbound ACK's 'win' field MUST equal "
                f"'rcv_wnd >> _rcv_wsc' = {actual_rcv_wnd} >> "
                f"{LOCAL__RCV_WSCALE} = {expected_wire_win} per "
                "RFC 7323 §2.3. Catching the unshifted value "
                f"({actual_rcv_wnd}) would mean we are advertising "
                "the actual byte count on the wire - peer's WSCALE "
                "shift on the inbound side would then misinterpret "
                "our window as far larger than reality."
            ),
        )

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="State must remain ESTABLISHED.",
        )

    def _make_listen_session(self, *, iss: int) -> tuple[TcpSocket, TcpSession]:
        """
        Build a 'TcpSocket' / 'TcpSession' pair wired up the way
        'TcpSocket.listen()' would wire them. After a SYN arrives,
        '_tcp_fsm_listen' mutates the original session in place into
        the child (in SYN_RCVD) and grafts a fresh listening session
        onto the original 'TcpSocket'. So the returned 'session' here
        is the listening session, and after one SYN it becomes the
        child; the listening socket's '_tcp_session' is then a new
        listening session.
        """

        self._force_iss(iss)

        sock = TcpSocket(family=AddressFamily.INET4)
        sock._local_ip_address = STACK__IP
        sock._local_port = PEER__PORT  # the listen port
        sock._remote_ip_address = Ip4Address()
        sock._remote_port = 0

        session = TcpSession(
            local_ip_address=STACK__IP,
            local_port=PEER__PORT,
            remote_ip_address=Ip4Address(),
            remote_port=0,
            socket=sock,
        )
        sock._tcp_session = session
        stack.sockets[sock.socket_id] = sock

        session.tcp_fsm(syscall=SysCall.LISTEN)
        return sock, session

    def test__wscale__passive_open_mirrors_peer_wscale_offer(self) -> None:
        """
        Ensure that when an inbound SYN to a listening socket carries
        the WSCALE option, our SYN+ACK reply mirrors the offer
        (carrying our own WSCALE) and the resulting child session
        records peer's wscale as '_snd_wsc'.

        RFC 7323 §2.2:

            "A TCP MAY send the WSopt in only the <SYN> segment of
             the connection, but if it is sent in only that segment,
             the connection is opened with the no-window-scaling
             default. ... A WSopt is not legal unless it is offered
             in both directions."

        Concretely for the passive-open path:

            * Peer SYN with WSCALE -> our SYN+ACK MUST carry WSCALE
              (otherwise the bilateral negotiation fails closed and
              we'd need to set our '_rcv_wsc' to 0).
            * Peer SYN without WSCALE -> our SYN+ACK MUST NOT carry
              WSCALE (covered by scenario #5b).

        Scenario:

            1. Set up a listening session.
            2. Drive a SYN from a peer with 'wscale=12'.
            3. Tick to fire the SYN+ACK.
            4. Inspect the SYN+ACK and the child session state.

        Assertions:

            * SYN+ACK carries 'wscale = LOCAL__RCV_WSCALE' (= 7,
              our default).
            * Child session's '_rcv_wsc == 7' (the value we
              advertised; governs our outbound shifts).
            * Child session's '_snd_wsc == 12' (peer's value;
              governs our inbound interpretation).
            * Child session is in SYN_RCVD.

        [FLAGS BUG] - same root cause as the other wscale
        scenarios. Without the WSCALE implementation:
          - Outbound SYN+ACK doesn't carry WSCALE.
          - '_rcv_wsc' stays at the default 0.
          - '_snd_wsc' stays at 0 (asymmetric-rejection rule).
        """

        peer_wscale = 12
        listen_sock, listen_session = self._make_listen_session(iss=LOCAL__ISS)

        # Peer sends SYN with WSCALE.
        peer_syn = build_tcp4(
            sport=PEER__PORT + 1000,  # arbitrary distinct peer port
            dport=PEER__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            wscale=peer_wscale,
        )
        self._drive_rx(frame=peer_syn)

        # The original listen_session is now the child (in SYN_RCVD).
        child_session = listen_session
        self.assertIs(
            child_session.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: original listen_session is now the child in SYN_RCVD.",
        )

        # Tick to fire SYN+ACK.
        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK must fire on the first tick.",
        )
        syn_ack_probe = self._parse_tx(syn_ack_tx[0])

        # The spec encoding: SYN+ACK carries our WSCALE (we mirror
        # peer's offer) and the child session records both values.
        self.assertEqual(
            syn_ack_probe.flags,
            frozenset({"SYN", "ACK"}),
            msg="Setup precondition: outbound segment must be a SYN+ACK.",
        )
        self.assertEqual(
            syn_ack_probe.wscale,
            LOCAL__RCV_WSCALE,
            msg=(
                f"Outbound SYN+ACK MUST carry WSCALE = "
                f"{LOCAL__RCV_WSCALE} per RFC 7323 §2.2 - peer "
                "offered, we mirror, bilateral negotiation succeeds."
            ),
        )
        self.assertEqual(
            child_session._rcv_wsc,
            LOCAL__RCV_WSCALE,
            msg=(f"Child session '_rcv_wsc' must equal our advertised " f"shift ({LOCAL__RCV_WSCALE})."),
        )
        self.assertEqual(
            child_session._snd_wsc,
            peer_wscale,
            msg=(
                f"Child session '_snd_wsc' must equal peer's "
                f"advertised shift ({peer_wscale}) - bilateral "
                "negotiation succeeded because our SYN+ACK mirrors "
                "peer's WSCALE."
            ),
        )

        # Sanity: the listening socket still has a fresh listening
        # session ready for further inbound SYNs.
        new_listen_session = listen_sock._tcp_session
        assert new_listen_session is not None
        self.assertIs(
            new_listen_session.state,
            FsmState.LISTEN,
            msg=(
                "After a SYN spawns a child, the listening socket's "
                "'_tcp_session' must be a fresh listening session "
                "ready to accept further connections."
            ),
        )

    def test__wscale__passive_open_omits_wscale_when_peer_did_not_offer(self) -> None:
        """
        Ensure that when an inbound SYN to a listening socket does
        NOT carry the WSCALE option, our SYN+ACK reply also omits
        it and the resulting child session keeps both '_rcv_wsc'
        and '_snd_wsc' at 0 for the connection lifetime per RFC
        7323 §2.2's bilateral non-offer rule.

        RFC 7323 §2.2:

            "A WSopt is not legal unless it is offered in both
             directions; if it is offered in only one direction,
             it MUST be ignored."

        For the passive-open path, this means: peer SYN without
        WSCALE -> we MUST NOT advertise WSCALE on our SYN+ACK
        either. Otherwise we'd be "offering" without prior peer
        advertisement, which the RFC forbids.

        Scenario:

            1. Set up a listening session.
            2. Drive a SYN from a peer with NO 'wscale=' parameter
               (the option is absent on the wire).
            3. Tick to fire the SYN+ACK.
            4. Inspect the SYN+ACK and the child session state.

        Assertions:

            * SYN+ACK has 'wscale = None' (option absent on wire).
            * Child session's '_rcv_wsc == 0' - we did NOT
              advertise; the bilateral negotiation failed closed.
            * Child session's '_snd_wsc == 0' - peer did NOT
              advertise; nothing to apply to inbound 'win' fields.
            * Child session is in SYN_RCVD.

        [FLAGS BUG] - PyTCP's current code (without WSCALE
        implementation) actually passes this test as a
        positive-control side effect because '_rcv_wsc' and
        '_snd_wsc' default to 0 and outbound SYN+ACK never
        carries WSCALE anyway. Once the WSCALE implementation
        lands and the active-open path always advertises, the
        passive-open path needs the conditional logic: 'if peer
        offered, mirror; else stay quiet'. This test pins that
        post-WSCALE-implementation behaviour as a regression
        guard.
        """

        listen_sock, listen_session = self._make_listen_session(iss=LOCAL__ISS)

        # Peer sends SYN WITHOUT WSCALE option.
        peer_syn = build_tcp4(
            sport=PEER__PORT + 1000,
            dport=PEER__PORT,
            seq=PEER__ISS,
            ack=0,
            flags=("SYN",),
            win=PEER__WIN,
            mss=PEER__MSS,
            # No wscale= parameter.
        )
        self._drive_rx(frame=peer_syn)

        child_session = listen_session
        self.assertIs(
            child_session.state,
            FsmState.SYN_RCVD,
            msg="Setup precondition: original listen_session is now the child in SYN_RCVD.",
        )

        # Tick to fire SYN+ACK.
        syn_ack_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_ack_tx),
            1,
            msg="Setup precondition: SYN+ACK must fire on the first tick.",
        )
        syn_ack_probe = self._parse_tx(syn_ack_tx[0])

        # The spec encoding: SYN+ACK omits WSCALE; both wscale
        # state fields stay at 0.
        self.assertEqual(
            syn_ack_probe.flags,
            frozenset({"SYN", "ACK"}),
            msg="Setup precondition: outbound segment must be a SYN+ACK.",
        )
        self.assertIsNone(
            syn_ack_probe.wscale,
            msg=(
                "Outbound SYN+ACK MUST NOT carry WSCALE when peer's "
                "SYN did not offer it - RFC 7323 §2.2 forbids "
                "unilateral offering. Mirroring peer's non-offer "
                "keeps the bilateral non-offer rule intact."
            ),
        )
        self.assertEqual(
            child_session._rcv_wsc,
            0,
            msg=(
                "Child session '_rcv_wsc' must equal 0 when peer "
                "did not offer WSCALE - bilateral non-offer means "
                "no scaling on either direction."
            ),
        )
        self.assertEqual(
            child_session._snd_wsc,
            0,
            msg=(
                "Child session '_snd_wsc' must equal 0 when peer "
                "did not offer WSCALE - nothing to apply to "
                "inbound 'win' fields."
            ),
        )

    def test__wscale__syn_ack_own_win_field_is_not_wscale_shifted(self) -> None:
        """
        Ensure that peer's SYN+ACK 'win' field is NOT left-shifted
        by the negotiated WSCALE - per RFC 7323 §2.2 the SYN segment
        itself uses an unshifted window value, the shift only applies
        to subsequent post-handshake segments. A bilateral handshake
        with peer wscale=10 and SYN+ACK win=64240 must yield a
        post-handshake '_snd_wnd' of 64240, not '64240 << 10' which
        would over-advertise peer's window by 1024x.

        RFC 7323 §2.2:

            "...All windows field values in the segment exchanged
             on the connection are relative to the WSopt-Permitted
             Window Scale option (WSopt) value advertised in the
             initial SYN. WSopt is not used to scale the value in
             the window field of the SYN segment itself; receiving
             ends always interpret that value as a 16-bit number."

        Concretely: the WSCALE option is exchanged DURING the
        handshake but is only meant to be APPLIED on segments
        AFTER the handshake. The SYN and SYN+ACK segments
        themselves carry literal 16-bit window values.

        Implementation concern: the natural post-WSCALE-fix code
        path inside '_tcp_fsm_syn_sent' looks like:

            self._snd_wnd = packet_rx_md.tcp__win  # raw
            self._snd_wsc = packet_rx_md.tcp__wscale  # peer's wsc
            self._process_ack_packet(packet_rx_md)  # this re-applies

        '_process_ack_packet' has the line:

            self._snd_wnd = packet_rx_md.tcp__win << self._snd_wsc

        which would clobber the previously-set raw value with the
        shifted one, yielding 64240 << 10 = 65_781_760. Over-
        advertising by 1024x is not "robust against attacker" -
        it is a confused-state bug that breaks our flow control
        and silently allows the peer to overrun our buffer.

        The fix in the WSCALE implementation must defer setting
        '_snd_wsc' until AFTER '_process_ack_packet' runs (or,
        equivalently, special-case the first post-handshake
        segment to skip the shift). Either way, post-handshake
        '_snd_wnd' must equal peer's literal SYN+ACK win value.

        Scenario:

            1. Drive bilateral WSCALE handshake with peer SYN+ACK
               carrying 'win=64240' and 'wscale=10'.
            2. Assert post-handshake '_snd_wnd == 64240' (the
               unshifted SYN+ACK win value).

        Assertions:

            * 'session._snd_wnd == 64240' (NOT 64240 << 10).
            * State is ESTABLISHED.

        This test passes on current code as a positive-control
        side effect because '_snd_wsc' stays at 0 (the asymmetric-
        rejection rule from 'data_transfer__window.py' #2). After
        the WSCALE implementation lands the test pins the
        spec-correct deferral as a regression guard.
        """

        peer_wscale = 10
        peer_win_on_syn_ack = 64240

        session = self._make_active_session(iss=LOCAL__ISS)
        session.tcp_fsm(syscall=SysCall.CONNECT)
        self._advance(ms=1)

        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=peer_win_on_syn_ack,
            mss=PEER__MSS,
            wscale=peer_wscale,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: bilateral WSCALE handshake must complete.",
        )

        # The spec encoding: SYN+ACK's win is NOT shifted.
        self.assertEqual(
            session._snd_wnd,
            peer_win_on_syn_ack,
            msg=(
                f"Post-handshake '_snd_wnd' MUST equal the literal "
                f"SYN+ACK win value ({peer_win_on_syn_ack}), NOT "
                f"the shifted value ({peer_win_on_syn_ack << peer_wscale}). "
                "Per RFC 7323 §2.2, 'WSopt is not used to scale the "
                "value in the window field of the SYN segment itself'. "
                "The shift applies only to post-handshake segments."
            ),
        )

    def test__wscale__asymmetric_offer_we_disabled_advertising_ignores_peer_wscale(self) -> None:
        """
        Ensure that when our session is explicitly configured to NOT
        advertise WSCALE on its outbound SYN (via setting
        '_advertise_wscale = False' on the session before CONNECT),
        peer's WSCALE option on the SYN+ACK is ignored per RFC 7323
        §2.2's bilateral non-offer rule. The session ends up with
        '_snd_wsc = 0', '_rcv_wsc = 0', and '_snd_wnd = peer_win'
        unshifted - exactly as the asymmetric-rejection fix covered
        in 'data_transfer__window.py' scenario #2 mandates, but
        with the opt-out toggled deliberately rather than hard-coded.

        Once WSCALE is the default-advertise behaviour, the existing
        'data_transfer__window.py' scenario #2 will be updated to
        flip '_advertise_wscale = False' to preserve its semantics
        (without that flag, default-advertise would mean the SYN
        DOES carry WSCALE and the bilateral rule would change
        outcome). This scenario locks in the opt-out path so the
        flag's behaviour is not silently dropped by future
        implementation changes.

        RFC 7323 §2.2:

            "A WSopt is not legal unless it is offered in both
             directions; if it is offered in only one direction,
             it MUST be ignored."

        Scenario:

            1. Build an active-open session and explicitly set
               'session._advertise_wscale = False'.
            2. Drive 'CONNECT'. The outbound SYN must NOT carry
               WSCALE.
            3. Peer replies with SYN+ACK carrying 'wscale = 8'.
               Per RFC, we must ignore peer's offer because we
               did not offer ourselves.
            4. Verify post-handshake state:
                  _rcv_wsc == 0  (we opted out)
                  _snd_wsc == 0  (peer's offer ignored)
                  _snd_wnd == peer_win  (unshifted, no scaling
                                          applies in either
                                          direction)

        Assertions:

            * Outbound SYN carries no WSCALE option.
            * State is ESTABLISHED.
            * '_rcv_wsc == 0', '_snd_wsc == 0', '_snd_wnd == peer_win'.

        This test passes on current code as a positive control
        (PyTCP doesn't advertise WSCALE today either way, so the
        '_advertise_wscale = False' setting is a no-op). After the
        WSCALE implementation lands the test serves as the
        regression guard for the opt-out path - without it, a
        future change that always-advertised would silently
        violate the bilateral rule when the test passed
        '_advertise_wscale = False'.
        """

        peer_wscale = 8

        session = self._make_active_session(iss=LOCAL__ISS)
        # Explicitly opt out of advertising WSCALE on this session.
        # Once the WSCALE implementation lands and defaults to
        # advertising, this is the API the user (or test) flips to
        # match a non-WSCALE peer or a constrained-buffer profile.
        session._advertise_wscale = False
        session.tcp_fsm(syscall=SysCall.CONNECT)

        syn_tx = self._advance(ms=1)
        self.assertEqual(
            len(syn_tx),
            1,
            msg="Setup precondition: outbound SYN must fire on the first tick.",
        )
        syn_probe = self._parse_tx(syn_tx[0])
        self.assertIsNone(
            syn_probe.wscale,
            msg=(
                "With '_advertise_wscale = False', the outbound SYN "
                "MUST NOT carry the WSCALE option - the bilateral "
                "non-offer rule of RFC 7323 §2.2 applies."
            ),
        )

        # Peer replies with WSCALE.
        peer_post_handshake_win = 32768
        peer_syn_ack = build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS,
            ack=LOCAL__ISS + 1,
            flags=("SYN", "ACK"),
            win=peer_post_handshake_win,
            mss=PEER__MSS,
            wscale=peer_wscale,
        )
        self._drive_rx(frame=peer_syn_ack)

        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="Setup precondition: handshake must complete to ESTABLISHED.",
        )

        # The spec encoding: peer's WSCALE is ignored in both
        # directions; window stays unshifted.
        self.assertEqual(
            session._rcv_wsc,
            0,
            msg=(
                "Session '_rcv_wsc' must equal 0 when we opted out "
                "of advertising - bilateral non-offer rule means no "
                "scaling on outbound win fields either."
            ),
        )
        self.assertEqual(
            session._snd_wsc,
            0,
            msg=(
                "Session '_snd_wsc' must equal 0 when we opted out, "
                "even though peer offered WSCALE - RFC 7323 §2.2: "
                "'if it is offered in only one direction, it MUST "
                "be ignored'."
            ),
        )
        self.assertEqual(
            session._snd_wnd,
            peer_post_handshake_win,
            msg=(
                f"'_snd_wnd' must equal peer's raw advertised window "
                f"({peer_post_handshake_win}) with no left shift - "
                "the asymmetric offer was ignored, so neither side "
                "scales."
            ),
        )
