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
This module contains smoke tests for the TCP session integration test
harness ('FakeTimer', 'tcp_segment_factory', 'TcpSessionTestCase').

pytcp/tests/integration/socket/test__socket__tcp__session__harness_smoke.py

ver 3.0.4
"""

from unittest import TestCase

from pytcp import stack
from pytcp.tests.lib.fake_timer import FakeTimer
from pytcp.tests.lib.tcp_segment_factory import build_tcp4, build_tcp6
from pytcp.tests.lib.tcp_session_testcase import TcpSessionTestCase


class TestFakeTimer(TestCase):
    """
    Standalone tests for the 'FakeTimer' deterministic clock.
    """

    def test__fake_timer__starts_at_zero(self) -> None:
        """
        Ensure 'FakeTimer.now_ms' starts at 0 with no pending timers.
        """

        timer = FakeTimer()

        self.assertEqual(timer.now_ms, 0, msg="FakeTimer must initialize 'now_ms' to 0.")
        self.assertEqual(timer.pending_timers, {}, msg="FakeTimer must initialize with no pending timers.")

    def test__fake_timer__advance_fires_registered_method_at_each_delay(self) -> None:
        """
        Ensure 'register_method' with the production default (delay=1,
        repeat_count=-1) fires the callback once per virtual ms.
        """

        timer = FakeTimer()
        ticks: list[dict[str, object]] = []
        timer.register_method(method=lambda **kw: ticks.append(kw), kwargs={"timer": True})

        timer.advance(5)

        self.assertEqual(len(ticks), 5, msg="A delay=1, repeat_count=-1 method must fire on every virtual ms.")
        self.assertTrue(
            all(call == {"timer": True} for call in ticks),
            msg="FakeTimer must forward the registered kwargs verbatim on every fire.",
        )
        self.assertEqual(timer.now_ms, 5, msg="FakeTimer.advance(5) must advance the virtual clock by 5 ms.")

    def test__fake_timer__register_timer_expires_after_timeout(self) -> None:
        """
        Ensure a named timer is reported as not expired until exactly
        'timeout' ms have elapsed, then is reported expired thereafter.
        """

        timer = FakeTimer()
        timer.register_timer(name="alpha", timeout=3)

        self.assertFalse(timer.is_expired("alpha"), msg="A freshly registered timer must not be expired.")
        timer.advance(2)
        self.assertFalse(timer.is_expired("alpha"), msg="Timer must remain unexpired before its timeout.")
        timer.advance(1)
        self.assertTrue(timer.is_expired("alpha"), msg="Timer must be reported expired once its timeout has elapsed.")

    def test__fake_timer__is_expired_for_unknown_name_returns_true(self) -> None:
        """
        Ensure 'is_expired' returns True for any name that was never
        registered, matching production 'Timer.is_expired' semantics.
        """

        timer = FakeTimer()

        self.assertTrue(timer.is_expired("unregistered"), msg="Unknown timer name must be reported expired.")

    def test__fake_timer__rejects_negative_advance(self) -> None:
        """
        Ensure 'advance' rejects negative arguments to keep the virtual
        clock monotonic.
        """

        timer = FakeTimer()

        with self.assertRaises(AssertionError):
            timer.advance(-1)


class TestTcpSegmentFactory(TestCase):
    """
    Standalone tests for the peer-side TCP segment builder.
    """

    def test__factory__build_tcp4_minimal_syn_is_parseable(self) -> None:
        """
        Ensure 'build_tcp4' produces a frame that round-trips through
        the Ethernet/IPv4/TCP parsers and exposes the requested fields.
        """

        from net_proto.lib.packet_rx import PacketRx
        from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
        from net_proto.protocols.ip4.ip4__parser import Ip4Parser
        from net_proto.protocols.tcp.tcp__parser import TcpParser

        frame = build_tcp4(sport=12345, dport=80, seq=0x1000, flags=("SYN",), mss=1460, wscale=7)

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)
        Ip4Parser(packet_rx)
        TcpParser(packet_rx)

        self.assertEqual(packet_rx.tcp.sport, 12345, msg="Round-tripped sport must match the requested value.")
        self.assertEqual(packet_rx.tcp.dport, 80, msg="Round-tripped dport must match the requested value.")
        self.assertEqual(packet_rx.tcp.seq, 0x1000, msg="Round-tripped seq must match the requested value.")
        self.assertTrue(packet_rx.tcp.flag_syn, msg="Round-tripped frame must carry the SYN flag.")
        self.assertFalse(
            packet_rx.tcp.flag_ack, msg="Round-tripped frame must not carry the ACK flag when not requested."
        )
        self.assertEqual(packet_rx.tcp.mss, 1460, msg="Round-tripped MSS option must match the requested value.")
        self.assertEqual(packet_rx.tcp.wscale, 7, msg="Round-tripped WSCALE option must match the requested value.")

    def test__factory__build_tcp6_carries_payload(self) -> None:
        """
        Ensure 'build_tcp6' produces an Ethernet/IPv6/TCP frame whose
        payload survives a parser round-trip.
        """

        from net_proto.lib.packet_rx import PacketRx
        from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
        from net_proto.protocols.ip6.ip6__parser import Ip6Parser
        from net_proto.protocols.tcp.tcp__parser import TcpParser

        frame = build_tcp6(sport=80, dport=12345, seq=0x2000, ack=0x1001, flags=("ACK",), payload=b"payload")

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)
        Ip6Parser(packet_rx)
        TcpParser(packet_rx)

        self.assertEqual(
            bytes(packet_rx.tcp.payload),
            b"payload",
            msg="Round-tripped payload must equal the bytes passed to 'build_tcp6'.",
        )
        self.assertTrue(packet_rx.tcp.flag_ack, msg="Round-tripped frame must carry the ACK flag.")

    def test__factory__rejects_unknown_flag_name(self) -> None:
        """
        Ensure the factory rejects a flag name outside the documented
        TCP flag set with a clear assertion.
        """

        with self.assertRaises(AssertionError) as error:
            build_tcp4(sport=1, dport=2, flags=("BOGUS",))

        self.assertIn(
            "Unknown TCP flag",
            str(error.exception),
            msg="Unknown-flag assertion must surface a specific message.",
        )

    def test__factory__paws_ts_slot_raises_not_implemented(self) -> None:
        """
        Ensure the reserved 'paws_ts' slot raises 'NotImplementedError'
        so future PAWS work has a clear failing call site.
        """

        with self.assertRaises(NotImplementedError):
            build_tcp4(sport=1, dport=2, paws_ts=(0, 0))

    def test__factory__sack_blocks_round_trip_through_parser(self) -> None:
        """
        Ensure 'build_tcp4' encodes the requested 'sack_blocks=' as a
        TCP SACK option (RFC 2018 §3) that round-trips through the
        parser as a list of '(left, right)' pairs in the supplied
        order.
        """

        from net_proto.lib.packet_rx import PacketRx
        from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
        from net_proto.protocols.ip4.ip4__parser import Ip4Parser
        from net_proto.protocols.tcp.tcp__parser import TcpParser

        frame = build_tcp4(
            sport=12345,
            dport=80,
            seq=0x1000,
            ack=0x2001,
            flags=("ACK",),
            sack_blocks=[(0x2010, 0x2020), (0x2030, 0x2050)],
        )

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)
        Ip4Parser(packet_rx)
        TcpParser(packet_rx)

        sack = packet_rx.tcp._options.sack
        self.assertIsNotNone(sack, msg="The factory must emit a SACK option when 'sack_blocks=' is supplied.")
        assert sack is not None  # for mypy
        self.assertEqual(
            [(block.left, block.right) for block in sack],
            [(0x2010, 0x2020), (0x2030, 0x2050)],
            msg="Round-tripped SACK blocks must match the supplied (left, right) pairs in order.",
        )


class TestTcpSessionTestCaseHarness(TcpSessionTestCase):
    """
    End-to-end smoke tests exercising 'TcpSessionTestCase' helpers via
    the real packet handler reacting to a synthesized inbound frame.
    """

    def test__harness__stack_timer_is_fake_timer(self) -> None:
        """
        Ensure 'TcpSessionTestCase.setUp' installs the 'FakeTimer' as
        'stack.timer' so production code calling 'stack.timer.*'
        reaches the deterministic clock.
        """

        self.assertIs(
            stack.timer,
            self._timer,
            msg="'stack.timer' must point at the FakeTimer installed by TcpSessionTestCase.setUp.",
        )
        self.assertIsInstance(
            self._timer,
            FakeTimer,
            msg="'self._timer' must be a FakeTimer instance.",
        )

    def test__harness__unsolicited_syn_to_closed_port_yields_rst_ack(self) -> None:
        """
        Ensure '_drive_rx' end-to-end: an unsolicited SYN to a port
        with no listener triggers the packet handler's RST+ACK reply
        and '_parse_tx' / '_assert_segment' read it correctly per
        RFC 9293 §3.10.7.2.
        """

        frame = build_tcp4(sport=33000, dport=2000, seq=0x4D2, flags=("SYN",))

        tx_frames = self._drive_rx(frame=frame)

        self.assertEqual(
            len(tx_frames),
            1,
            msg="An unsolicited SYN to a closed port must produce exactly one TX frame (RST+ACK).",
        )

        probe = self._parse_tx(tx_frames[0])
        self._assert_segment(
            probe,
            flags=frozenset({"RST", "ACK"}),
            sport=2000,
            dport=33000,
            seq=0,
            ack=0x4D2 + 1,
            payload=b"",
        )

    def test__harness__advance_with_no_registered_methods_emits_no_tx(self) -> None:
        """
        Ensure '_advance' with nothing registered on the FakeTimer
        produces no TX frames and is therefore safe to call from
        scenario tests that have not yet opened any session.
        """

        tx_frames = self._advance(ms=100)

        self.assertEqual(
            tx_frames,
            [],
            msg="Advancing the virtual clock with no registered tasks must not produce any TX frames.",
        )

    def test__harness__force_iss_patches_random_randint(self) -> None:
        """
        Ensure '_force_iss' patches 'random.randint' inside the TCP
        session module so any subsequently constructed 'TcpSession'
        receives the chosen ISS - the wrap-aware tests rely on this.
        """

        self._force_iss(0xFFFF_FF00)

        from pytcp.socket.tcp__session import random as tcp_session_random

        self.assertEqual(
            tcp_session_random.randint(0, 0xFFFF_FFFF),
            0xFFFF_FF00,
            msg="'_force_iss' must redirect 'random.randint' to return the supplied ISS.",
        )
