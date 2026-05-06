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
This module contains tests for the 'TcpSession' FSM state-transition
handlers ('_tcp_fsm_closed' through '_tcp_fsm_time_wait') and the
top-level 'tcp_fsm' dispatch.

pytcp/tests/unit/protocols/tcp/fsm/test__tcp__fsm.py

ver 3.0.4
"""

from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_addr import Ip4Address, IpVersion
from pytcp.protocols.tcp.tcp__session import (
    FsmState,
    SysCall,
    TcpSession,
)
from pytcp.socket.tcp__metadata import TcpMetadata


class _TcpSessionFsmFixture(TestCase):
    """
    Shared fixture that stubs the stack timer, interface MTU, socket
    registry, and logging so FSM state transitions can be driven
    without a running stack.
    """

    def setUp(self) -> None:
        """
        Install per-test stack patches and expose the timer mock on
        'self' so individual tests can observe 'register_timer' calls.
        """

        self._timer = SimpleNamespace(
            register_method=MagicMock(),
            register_timer=MagicMock(),
            is_expired=MagicMock(return_value=False),
            unregister_timers_with_prefix=MagicMock(),
            unregister_method=MagicMock(),
            now_ms=0,
        )
        self._timer_patch = patch(
            "pytcp.protocols.tcp.tcp__session.stack.timer",
            self._timer,
        )
        self._timer_patch.start()

        self._mtu_patch = patch(
            "pytcp.protocols.tcp.tcp__session.stack.interface_mtu",
            1500,
            create=True,
        )
        self._mtu_patch.start()

        self._sockets: dict = {}
        self._sockets_patch = patch(
            "pytcp.protocols.tcp.tcp__session.stack.sockets",
            self._sockets,
        )
        self._sockets_patch.start()

        self._log_patch = patch("pytcp.protocols.tcp.tcp__session.log")
        self._log_patch.start()

    def tearDown(self) -> None:
        """
        Remove the stack patches.
        """

        self._timer_patch.stop()
        self._mtu_patch.stop()
        self._sockets_patch.stop()
        self._log_patch.stop()

    def _make_session(self) -> TcpSession:
        """
        Build a canonical IPv4 TcpSession with a mock socket.
        """

        mock_socket = MagicMock()
        mock_socket.socket_id = object()  # unique sentinel for dict keys
        self._sockets[mock_socket.socket_id] = mock_socket

        return TcpSession(
            local_ip_address=Ip4Address("10.0.0.1"),
            local_port=8080,
            remote_ip_address=Ip4Address("10.0.0.2"),
            remote_port=44444,
            socket=mock_socket,
        )


class TestTcpSessionChangeState(_TcpSessionFsmFixture):
    """
    The '_change_state' helper tests.
    """

    def test__tcp_session__change_state_updates_state(self) -> None:
        """
        Ensure '_change_state' writes the new state into '_state'.
        Reference: RFC 9293 §3.3.2 (state machine).
        """

        session = self._make_session()
        session._change_state(FsmState.LISTEN)

        self.assertIs(
            session.state,
            FsmState.LISTEN,
            msg="_change_state must update the '_state' attribute.",
        )

    def test__tcp_session__change_state_to_closed_unregisters(self) -> None:
        """
        Ensure transitioning to 'CLOSED' pops the associated socket
        from 'stack.sockets' — this is how closed sessions stop
        receiving packets.
        Reference: RFC 9293 §3.3.2 (CLOSED state) + §3.10.4 (CLOSE call).
        """

        session = self._make_session()
        session._state = FsmState.ESTABLISHED

        session._change_state(FsmState.CLOSED)

        self.assertNotIn(
            session.socket.socket_id,
            self._sockets,
            msg="Transitioning to CLOSED must unregister the socket from stack.sockets.",
        )


class TestTcpFsmClosed(_TcpSessionFsmFixture):
    """
    The '_tcp_fsm_closed' state-handler tests.
    """

    def test__tcp_session__closed_connect_to_syn_sent(self) -> None:
        """
        Ensure CONNECT from the CLOSED state transitions the
        FSM to 'SYN_SENT'. This is the active-open path.

        Reference: RFC 9293 §3.10.1 (OPEN call, active open).
        """

        session = self._make_session()
        session.tcp_fsm(syscall=SysCall.CONNECT)

        self.assertIs(
            session.state,
            FsmState.SYN_SENT,
            msg="CONNECT from CLOSED must transition to FsmState.SYN_SENT.",
        )

    def test__tcp_session__closed_listen_to_listen(self) -> None:
        """
        Ensure LISTEN from the CLOSED state transitions the
        FSM to 'LISTEN'. This is the passive-open path.

        Reference: RFC 9293 §3.10.1 (OPEN call, passive open).
        """

        session = self._make_session()
        session.tcp_fsm(syscall=SysCall.LISTEN)

        self.assertIs(
            session.state,
            FsmState.LISTEN,
            msg="LISTEN from CLOSED must transition to FsmState.LISTEN.",
        )

    def test__tcp_session__closed_ignores_close(self) -> None:
        """
        Ensure CLOSE in the CLOSED state is a no-op - the FSM
        stays put and does not crash.

        Reference: RFC 9293 §3.10.4 (CLOSE call from CLOSED).
        """

        session = self._make_session()
        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="CLOSE in CLOSED must leave the FSM in CLOSED.",
        )


class TestTcpFsmListen(_TcpSessionFsmFixture):
    """
    The '_tcp_fsm_listen' state-handler tests.
    """

    def test__tcp_session__listen_close_to_closed(self) -> None:
        """
        Ensure CLOSE in the LISTEN state transitions the FSM
        to 'CLOSED'. Canonical server shutdown path.

        Reference: RFC 9293 §3.10.4 (CLOSE call from LISTEN).
        """

        session = self._make_session()
        session._state = FsmState.LISTEN

        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="CLOSE from LISTEN must transition to FsmState.CLOSED.",
        )


class TestTcpFsmSynSent(_TcpSessionFsmFixture):
    """
    The '_tcp_fsm_syn_sent' state-handler tests.
    """

    def test__tcp_session__syn_sent_close_to_closed(self) -> None:
        """
        Ensure CLOSE in the SYN_SENT state transitions the FSM
        to 'CLOSED'. Happens when the caller abandons a
        pending connect.

        Reference: RFC 9293 §3.10.4 (CLOSE call from SYN-SENT).
        """

        session = self._make_session()
        session._state = FsmState.SYN_SENT

        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertIs(
            session.state,
            FsmState.CLOSED,
            msg="CLOSE from SYN_SENT must transition to FsmState.CLOSED.",
        )

    def test__tcp_session__syn_sent_simultaneous_open_to_syn_rcvd(self) -> None:
        """
        Ensure a bare SYN packet received while in SYN_SENT
        triggers the simultaneous-open branch - the FSM
        transitions to SYN_RCVD and a SYN+ACK is sent.

        Reference: RFC 9293 §3.10.7.3 (simultaneous open).
        """

        session = self._make_session()
        session._state = FsmState.SYN_SENT

        metadata = TcpMetadata(
            ip__ver=IpVersion.IP4,
            ip__local_address=Ip4Address("10.0.0.1"),
            ip__remote_address=Ip4Address("10.0.0.2"),
            tcp__local_port=8080,
            tcp__remote_port=44444,
            tcp__flag_syn=True,
            tcp__flag_ack=False,
            tcp__flag_fin=False,
            tcp__flag_rst=False,
            tcp__flag_ece=False,
            tcp__flag_cwr=False,
            tcp__seq=12345,
            tcp__ack=0,
            tcp__win=65535,
            tcp__wscale=0,
            tcp__mss=1460,
            tcp__sackperm=False,
            tcp__sack_blocks=(),
            tcp__data=memoryview(b""),
        )

        with patch.object(session, "_transmit_packet") as mock_transmit:
            session.tcp_fsm(packet_rx_md=metadata)

        self.assertIs(
            session.state,
            FsmState.SYN_RCVD,
            msg="A bare SYN in SYN_SENT must transition to SYN_RCVD (simultaneous open).",
        )
        # Post-Bug-C fix: simultaneous-open emits SYN+ACK with
        # seq=self._snd_seq.ini (reuses original SYN's seq) rather
        # than letting it default to self._snd_seq.nxt (which would
        # have advanced past LOCAL__ISS to LOCAL__ISS+1 from the
        # initial SYN). The fix bootstraps peer state and emits
        # SYN+ACK at the original SYN's seq so peer accepts it.
        mock_transmit.assert_called_once_with(flag_syn=True, flag_ack=True, seq=session._snd_seq.ini)


class TestTcpFsmEstablished(_TcpSessionFsmFixture):
    """
    The '_tcp_fsm_established' state-handler tests.
    """

    def test__tcp_session__established_close_sets_closing_flag(self) -> None:
        """
        Ensure CLOSE in 'ESTABLISHED' sets the '_closing' flag
        without changing state immediately - the session only
        transitions to 'FIN_WAIT_1' once the TX buffer has
        been flushed (handled in the timer branch).

        Reference: RFC 9293 §3.10.4 (CLOSE call from ESTABLISHED).
        """

        session = self._make_session()
        session._state = FsmState.ESTABLISHED

        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertTrue(
            session._closing,
            msg="CLOSE in ESTABLISHED must set the _closing flag.",
        )
        self.assertIs(
            session.state,
            FsmState.ESTABLISHED,
            msg="CLOSE in ESTABLISHED must NOT change state immediately — waits for TX flush.",
        )


class TestTcpFsmSynRcvd(_TcpSessionFsmFixture):
    """
    The '_tcp_fsm_syn_rcvd' state-handler tests.
    """

    def test__tcp_session__syn_rcvd_close_to_fin_wait_1(self) -> None:
        """
        Ensure CLOSE from 'SYN_RCVD' transitions the FSM to
        'FIN_WAIT_1' so the session can emit a FIN and begin
        active close without waiting for the peer's data path.

        Reference: RFC 9293 §3.10.4 (CLOSE call from SYN-RECEIVED).
        """

        session = self._make_session()
        session._state = FsmState.SYN_RCVD

        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertIs(
            session.state,
            FsmState.FIN_WAIT_1,
            msg="CLOSE from SYN_RCVD must transition to FsmState.FIN_WAIT_1.",
        )


class TestTcpFsmCloseWait(_TcpSessionFsmFixture):
    """
    The '_tcp_fsm_close_wait' state-handler tests.
    """

    def test__tcp_session__close_wait_close_sets_closing_flag(self) -> None:
        """
        Ensure CLOSE from 'CLOSE_WAIT' sets the '_closing'
        flag - the actual transition to 'LAST_ACK' happens
        once the TX buffer drains (in the timer branch).

        Reference: RFC 9293 §3.10.4 (CLOSE call from CLOSE-WAIT).
        """

        session = self._make_session()
        session._state = FsmState.CLOSE_WAIT

        session.tcp_fsm(syscall=SysCall.CLOSE)

        self.assertTrue(
            session._closing,
            msg="CLOSE in CLOSE_WAIT must set the _closing flag.",
        )
        self.assertIs(
            session.state,
            FsmState.CLOSE_WAIT,
            msg="CLOSE in CLOSE_WAIT must NOT change state immediately — waits for TX flush.",
        )


class TestTcpFsmDispatch(_TcpSessionFsmFixture):
    """
    The top-level 'tcp_fsm' dispatch tests.
    """

    def test__tcp_session__fsm_dispatches_packet_by_current_state(self) -> None:
        """
        Ensure 'tcp_fsm' routes an inbound-packet event to the
        per-state packet handler matching the current '_state'.
        Exercised by seeding each packet-handling state in turn
        and verifying the corresponding entry in
        FSM_PACKET_HANDLERS was called with the packet metadata.

        Reference: RFC 9293 §3.3.2 (state machine dispatch).
        """

        from pytcp.protocols.tcp.fsm.tcp__fsm import FSM_PACKET_HANDLERS

        dummy_md = MagicMock()
        for state in FSM_PACKET_HANDLERS:
            with self.subTest(state=state):
                session = self._make_session()
                session._state = state
                mock_handler = MagicMock()
                with patch.dict(FSM_PACKET_HANDLERS, {state: mock_handler}):
                    session.tcp_fsm(packet_rx_md=dummy_md)
                mock_handler.assert_called_once_with(session, dummy_md)

    def test__tcp_session__fsm_dispatches_syscall_by_current_state(self) -> None:
        """
        Ensure 'tcp_fsm' routes a syscall event to the per-state
        syscall handler matching the current '_state'.

        Reference: RFC 9293 §3.3.2 (state machine dispatch).
        """

        from pytcp.protocols.tcp.fsm.tcp__fsm import FSM_SYSCALL_HANDLERS
        from pytcp.protocols.tcp.tcp__enums import SysCall

        for state in FSM_SYSCALL_HANDLERS:
            with self.subTest(state=state):
                session = self._make_session()
                session._state = state
                mock_handler = MagicMock()
                with patch.dict(FSM_SYSCALL_HANDLERS, {state: mock_handler}):
                    session.tcp_fsm(syscall=SysCall.CLOSE)
                mock_handler.assert_called_once_with(session, SysCall.CLOSE)

    def test__tcp_session__fsm_dispatches_timer_by_current_state(self) -> None:
        """
        Ensure 'tcp_fsm' routes a timer-tick event to the
        per-state timer handler matching the current '_state'.

        Reference: RFC 9293 §3.3.2 (state machine dispatch).
        """

        from pytcp.protocols.tcp.fsm.tcp__fsm import FSM_TIMER_HANDLERS

        for state in FSM_TIMER_HANDLERS:
            with self.subTest(state=state):
                session = self._make_session()
                session._state = state
                mock_handler = MagicMock()
                with patch.dict(FSM_TIMER_HANDLERS, {state: mock_handler}):
                    session.tcp_fsm(timer=True)
                mock_handler.assert_called_once_with(session)


class TestTcpSessionTransmitPacket(_TcpSessionFsmFixture):
    """
    The '_transmit_packet' helper tests.
    """

    def test__tcp_session__transmit_packet_routes_through_packet_handler(self) -> None:
        """
        Ensure '_transmit_packet' delegates to
        'stack.packet_handler.send_tcp_packet' with the expected
        keyword arguments (local/remote IPs, ports, seq, ack, flags).
        Reference: RFC 9293 §3.10.3 (SEND call) — segment construction.
        """

        handler = MagicMock()
        handler.send_tcp_packet = MagicMock()

        with patch(
            "pytcp.protocols.tcp.tcp__session.stack.packet_handler",
            handler,
            create=True,
        ):
            session = self._make_session()
            session._transmit_packet(flag_ack=True, data=b"payload")

        handler.send_tcp_packet.assert_called_once()
        kwargs = handler.send_tcp_packet.call_args.kwargs
        self.assertEqual(
            kwargs["ip__local_address"],
            Ip4Address("10.0.0.1"),
            msg="_transmit_packet must forward the session's local IP.",
        )
        self.assertEqual(
            kwargs["ip__remote_address"],
            Ip4Address("10.0.0.2"),
            msg="_transmit_packet must forward the session's remote IP.",
        )
        self.assertEqual(
            kwargs["tcp__local_port"],
            8080,
            msg="_transmit_packet must forward the session's local port.",
        )
        self.assertEqual(
            kwargs["tcp__remote_port"],
            44444,
            msg="_transmit_packet must forward the session's remote port.",
        )
        self.assertEqual(
            kwargs["tcp__payload"],
            b"payload",
            msg="_transmit_packet must forward the data as the payload.",
        )
        self.assertTrue(
            kwargs["tcp__flag_ack"],
            msg="_transmit_packet must forward flag_ack=True.",
        )

    def test__tcp_session__transmit_packet_advances_snd_nxt(self) -> None:
        """
        Ensure '_transmit_packet' advances '_snd_nxt' by
        'len(data) + flag_syn + flag_fin'. This is the
        invariant the retransmit / ACK logic relies on.

        Reference: RFC 9293 §3.4 (sequence numbers consume one for SYN/FIN).
        """

        handler = MagicMock()
        with patch(
            "pytcp.protocols.tcp.tcp__session.stack.packet_handler",
            handler,
            create=True,
        ):
            session = self._make_session()
            initial_nxt = session._snd_seq.nxt
            session._transmit_packet(flag_syn=True, data=b"abc")

        self.assertEqual(
            session._snd_seq.nxt,
            initial_nxt + len(b"abc") + 1,
            msg="_transmit_packet must advance _snd_nxt by len(data) + flag_syn + flag_fin.",
        )

    def test__tcp_session__transmit_packet_records_fin_seq(self) -> None:
        """
        Ensure '_transmit_packet' with 'flag_fin=True' records
        the next sequence number into '_snd_fin' so the
        session can detect the peer's ACK of our FIN.

        Reference: RFC 9293 §3.4 (FIN consumes one sequence number).
        """

        handler = MagicMock()
        with patch(
            "pytcp.protocols.tcp.tcp__session.stack.packet_handler",
            handler,
            create=True,
        ):
            session = self._make_session()
            session._transmit_packet(flag_fin=True, flag_ack=True)

        self.assertEqual(
            session._snd_seq.fin,
            session._snd_seq.nxt,
            msg="_transmit_packet with flag_fin=True must record _snd_fin = _snd_nxt.",
        )


class TestTcpSessionEnqueueRxBuffer(_TcpSessionFsmFixture):
    """
    The '_enqueue_rx_buffer' helper tests.
    """

    def test__tcp_session__enqueue_extends_rx_buffer(self) -> None:
        """
        Ensure '_enqueue_rx_buffer' extends '_rx_buffer' with the
        supplied memoryview and releases the rx-ready event so
        receive() can wake.
        Reference: RFC 9293 §3.10.5 (RECEIVE call) — buffer delivery.
        """

        session = self._make_session()
        session._enqueue_rx_buffer(memoryview(b"hello"))

        self.assertEqual(
            bytes(session._rx_buffer),
            b"hello",
            msg="_enqueue_rx_buffer must extend _rx_buffer with the data.",
        )

    def test__tcp_session__enqueue_requires_memoryview(self) -> None:
        """
        Ensure the assertion guard rejects non-memoryview input — the
        helper only accepts memoryview to keep the data path zero-copy.
        Reference: RFC 9293 §3.10.5 (RECEIVE call) — implementation guard.
        """

        session = self._make_session()
        with self.assertRaises(AssertionError):
            session._enqueue_rx_buffer(b"raw-bytes")  # type: ignore[arg-type]
