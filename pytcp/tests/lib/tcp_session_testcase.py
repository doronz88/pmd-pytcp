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
This module contains the 'TcpSessionTestCase' base class used by the
TCP session integration tests, layering a deterministic clock and TCP
probe helpers on top of 'NetworkTestCase'.

pytcp/tests/lib/tcp_session_testcase.py

ver 3.0.4
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast
from unittest.mock import _patch, patch

from net_addr import Ip4Address, Ip6Address
from net_proto.lib.enums import EtherType
from net_proto.lib.packet_rx import PacketRx
from net_proto.protocols.ethernet.ethernet__parser import EthernetParser
from net_proto.protocols.ip4.ip4__parser import Ip4Parser
from net_proto.protocols.ip6.ip6__parser import Ip6Parser
from net_proto.protocols.tcp.tcp__parser import TcpParser
from pytcp import stack
from pytcp.tests.lib.fake_timer import FakeTimer
from pytcp.tests.lib.network_testcase import NetworkTestCase

TCP_FLAG_NAMES: tuple[str, ...] = (
    "SYN",
    "ACK",
    "FIN",
    "RST",
    "PSH",
    "URG",
    "ECE",
    "CWR",
    "NS",
)


@dataclass(frozen=True, slots=True)
class TcpProbe:
    """
    Decoded snapshot of a single Ethernet/IP/TCP frame produced by
    the stack under test, used by 'TcpSessionTestCase' assertions.
    """

    ip_src: Ip6Address | Ip4Address
    ip_dst: Ip6Address | Ip4Address
    sport: int
    dport: int
    seq: int
    ack: int
    flags: frozenset[str]
    win: int
    mss: int | None
    wscale: int | None
    payload: bytes


class TcpSessionTestCase(NetworkTestCase):
    """
    Base class for TCP session integration tests. Adds a deterministic
    'FakeTimer' replacement for 'stack.timer', helpers to drive RX
    frames into the packet handler and capture the TX frames the stack
    emits, and a 'TcpProbe' parser for fluent segment-level assertions.
    """

    _timer: FakeTimer
    _patches: list[_patch]

    def setUp(self) -> None:
        """
        Install a 'FakeTimer' over 'stack.timer' on top of the parent
        mock-network setup and initialize the patch tracking list so
        per-test 'mock.patch' handles get torn down deterministically.
        """

        super().setUp()

        self._timer = FakeTimer()
        stack.mock__init(mock__timer=cast(stack.Timer, self._timer))

        self._patches = []

    def tearDown(self) -> None:
        """
        Stop any 'mock.patch' handle started by '_start_patch' before
        deferring to the parent teardown, so test-only patches do not
        leak between tests.
        """

        while self._patches:
            self._patches.pop().stop()

        super().tearDown()

    def _start_patch(self, target: str, new: object) -> None:
        """
        Start a 'mock.patch' on 'target' replacing it with 'new' and
        register the patch so 'tearDown' stops it automatically.
        """

        handle = patch(target, new)
        handle.start()
        self._patches.append(handle)

    def _force_iss(self, value: int) -> None:
        """
        Force the next 'TcpSession' constructed in this test to choose
        'value' as its initial sequence number, so wrap-aware paths
        can be exercised deterministically. Patches 'random.randint'
        in the 'pytcp.socket.tcp__session' module scope.
        """

        self._start_patch("pytcp.socket.tcp__session.random.randint", lambda _lo, _hi: value)

    def _drive_rx(self, *, frame: bytes) -> list[bytes]:
        """
        Feed 'frame' into 'PacketHandler._phrx_ethernet' and return
        the list of TX frames the stack produced as a direct result.
        """

        before = len(self._frames_tx)
        self._packet_handler._phrx_ethernet(PacketRx(frame))
        return list(self._frames_tx[before:])

    def _advance(self, *, ms: int) -> list[bytes]:
        """
        Advance the virtual clock by 'ms' milliseconds and return the
        list of TX frames produced during the tick.
        """

        before = len(self._frames_tx)
        self._timer.advance(ms)
        return list(self._frames_tx[before:])

    def _parse_tx(self, frame: bytes, /) -> TcpProbe:
        """
        Parse a TX frame back into a 'TcpProbe' covering the IP and
        TCP fields the integration tests need to assert on.
        """

        packet_rx = PacketRx(frame)
        EthernetParser(packet_rx)

        if packet_rx.ethernet.type is EtherType.IP4:
            Ip4Parser(packet_rx)
        elif packet_rx.ethernet.type is EtherType.IP6:
            Ip6Parser(packet_rx)
        else:
            raise AssertionError(f"Unexpected EtherType in TX frame: {packet_rx.ethernet.type!r}")

        TcpParser(packet_rx)

        flags: set[str] = set()
        for name in TCP_FLAG_NAMES:
            if getattr(packet_rx.tcp, f"flag_{name.lower()}"):
                flags.add(name)

        return TcpProbe(
            ip_src=packet_rx.ip.src,
            ip_dst=packet_rx.ip.dst,
            sport=packet_rx.tcp.sport,
            dport=packet_rx.tcp.dport,
            seq=packet_rx.tcp.seq,
            ack=packet_rx.tcp.ack,
            flags=frozenset(flags),
            win=packet_rx.tcp.win,
            mss=packet_rx.tcp.mss,
            wscale=packet_rx.tcp.wscale,
            payload=bytes(packet_rx.tcp.payload),
        )

    def _assert_segment(
        self,
        probe: TcpProbe,
        *,
        flags: Iterable[str] | None = None,
        seq: int | None = None,
        ack: int | None = None,
        payload: bytes | None = None,
        win: int | None = None,
        mss: int | None = None,
        wscale: int | None = None,
        sport: int | None = None,
        dport: int | None = None,
    ) -> None:
        """
        Assert that the given 'TcpProbe' matches every supplied field.
        Fields left as 'None' are not checked, so callers express only
        the invariants relevant to the test.
        """

        if flags is not None:
            self.assertEqual(
                probe.flags,
                frozenset(flags),
                msg=f"Unexpected TCP flag set on outbound segment: {probe!r}",
            )
        if seq is not None:
            self.assertEqual(
                probe.seq,
                seq,
                msg=f"Unexpected TCP seq on outbound segment: {probe!r}",
            )
        if ack is not None:
            self.assertEqual(
                probe.ack,
                ack,
                msg=f"Unexpected TCP ack on outbound segment: {probe!r}",
            )
        if payload is not None:
            self.assertEqual(
                probe.payload,
                payload,
                msg=f"Unexpected TCP payload on outbound segment: {probe!r}",
            )
        if win is not None:
            self.assertEqual(
                probe.win,
                win,
                msg=f"Unexpected TCP advertised window on outbound segment: {probe!r}",
            )
        if mss is not None:
            self.assertEqual(
                probe.mss,
                mss,
                msg=f"Unexpected TCP MSS option on outbound segment: {probe!r}",
            )
        if wscale is not None:
            self.assertEqual(
                probe.wscale,
                wscale,
                msg=f"Unexpected TCP WSCALE option on outbound segment: {probe!r}",
            )
        if sport is not None:
            self.assertEqual(
                probe.sport,
                sport,
                msg=f"Unexpected TCP sport on outbound segment: {probe!r}",
            )
        if dport is not None:
            self.assertEqual(
                probe.dport,
                dport,
                msg=f"Unexpected TCP dport on outbound segment: {probe!r}",
            )

    def _assert_no_tx(self) -> None:
        """
        Assert that no TX frames have been recorded since the last
        explicit drain (tests that drain via '_drive_rx' / '_advance'
        get a fresh list back; this method checks the global slot).
        """

        self.assertEqual(
            self._frames_tx,
            [],
            msg=f"Expected no TX frames, got {len(self._frames_tx)}: {self._frames_tx!r}",
        )
