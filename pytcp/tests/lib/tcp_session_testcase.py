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
from typing import Any, cast
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

# Sentinel used by '_assert_segment' to distinguish "caller supplied no
# expected value, skip this check" from "caller explicitly asserted the
# field is None / absent". 'None' alone is ambiguous because option
# fields ('mss', 'wscale') legitimately use 'None' to mean "option not
# present on the wire".
_UNSET: object = object()


@dataclass(frozen=True, slots=True)
class TcpProbe:
    """
    Decoded snapshot of a single Ethernet/IP/TCP frame produced by
    the stack under test, used by 'TcpSessionTestCase' assertions.
    """

    ip_src: Ip6Address | Ip4Address
    ip_dst: Ip6Address | Ip4Address
    # RFC 3168 §5: IP ECN field - 0=Not-ECT, 1=ECT(1), 2=ECT(0), 3=CE.
    ip_ecn: int
    sport: int
    dport: int
    seq: int
    ack: int
    flags: frozenset[str]
    win: int
    mss: int | None
    wscale: int | None
    sackperm: bool
    sack_blocks: tuple[tuple[int, int], ...]
    tsval: int | None
    tsecr: int | None
    # RFC 7413 §2 TFO option: None = absent on the wire,
    # b"" = empty-cookie request form, b"..." = cookie
    # response/use form.
    fastopen_cookie: bytes | None
    # RFC 9768 §3.2.3 AccECN option: tuple of three 24-bit
    # byte counters (ee0b, eceb, ee1b) when present, None
    # when absent on the wire. The ordering is the AccECN0
    # convention (ECT(0), CE, ECT(1)) regardless of which
    # kind appeared on the wire.
    accecn: tuple[int, int, int] | None
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
    _interface_mtu_was_set: bool
    _interface_mtu_prior: object
    _sockets_prior: dict[Any, Any]

    def setUp(self) -> None:
        """
        Install a 'FakeTimer' over 'stack.timer' on top of the parent
        mock-network setup, set 'stack.interface_mtu' so 'TcpSession'
        construction succeeds, snapshot+clear the module-global
        'stack.sockets' dict so tests start with no leftover socket
        registrations, and initialize the patch tracking list so
        per-test 'mock.patch' handles get torn down deterministically.
        """

        super().setUp()

        self._timer = FakeTimer()
        stack.mock__init(mock__timer=cast(stack.Timer, self._timer))

        self._interface_mtu_was_set = hasattr(stack, "interface_mtu") and "interface_mtu" in stack.__dict__
        self._interface_mtu_prior = stack.__dict__.get("interface_mtu")
        stack.interface_mtu = 1500

        # 'stack.sockets' is a module-level dict that accumulates
        # registrations across tests if not cleared. Snapshot the prior
        # contents, then start each test with an empty dict; tearDown
        # restores so unrelated tests outside this class are unaffected.
        self._sockets_prior = cast(dict[Any, Any], dict(stack.sockets))
        stack.sockets.clear()

        self._patches = []

    def tearDown(self) -> None:
        """
        Stop any 'mock.patch' handle started by '_start_patch', restore
        'stack.interface_mtu' to its pre-test value, then defer to the
        parent teardown so test-only state does not leak between tests.
        """

        while self._patches:
            self._patches.pop().stop()

        if self._interface_mtu_was_set:
            stack.interface_mtu = cast(int, self._interface_mtu_prior)
        else:
            stack.__dict__.pop("interface_mtu", None)

        stack.sockets.clear()
        stack.sockets.update(self._sockets_prior)

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
        can be exercised deterministically. Patches 'compute_iss' in
        the 'pytcp.protocols.tcp.tcp__session' module scope; the
        canonical ISN choice was migrated from 'random.randint' to
        the RFC 6528 §3 hash in commit 'ac0d98b' / wired into
        TcpSession in the follow-up.
        """

        self._start_patch(
            "pytcp.protocols.tcp.tcp__session.compute_iss",
            lambda *_args, **_kwargs: value,
        )

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

        # Read the option presence via the underlying TcpOptions container
        # ('_options.mss' / '_options.wscale' / '_options.sack' return None
        # when absent), not via the parser's 'OptionsProperties' mixin (which
        # substitutes defaults like TCP__MIN_MSS=536 / wscale=0 and so cannot
        # distinguish 'option absent' from 'option present with the default
        # value').
        sack_blocks_raw = packet_rx.tcp._options.sack
        sack_blocks: tuple[tuple[int, int], ...] = (
            () if sack_blocks_raw is None else tuple((block.left, block.right) for block in sack_blocks_raw)
        )
        timestamps_raw = packet_rx.tcp._options.timestamps
        tsval = timestamps_raw.tsval if timestamps_raw is not None else None
        tsecr = timestamps_raw.tsecr if timestamps_raw is not None else None
        # RFC 7413 §2 TFO option: pulled via the typed
        # 'fastopen' property on TcpOptions. Returns 'None'
        # when the option is absent on the wire, 'b""' for
        # the cookie-request form, and the cookie bytes for
        # the cookie-response/use form.
        fastopen_cookie = packet_rx.tcp._options.fastopen
        accecn_raw = packet_rx.tcp._options.accecn
        accecn = None if accecn_raw is None else (accecn_raw.ee0b, accecn_raw.eceb, accecn_raw.ee1b)
        return TcpProbe(
            ip_src=packet_rx.ip.src,
            ip_dst=packet_rx.ip.dst,
            ip_ecn=packet_rx.ip.ecn,
            sport=packet_rx.tcp.sport,
            dport=packet_rx.tcp.dport,
            seq=packet_rx.tcp.seq,
            ack=packet_rx.tcp.ack,
            flags=frozenset(flags),
            win=packet_rx.tcp.win,
            mss=packet_rx.tcp._options.mss,
            wscale=packet_rx.tcp._options.wscale,
            sackperm=bool(packet_rx.tcp._options.sackperm),
            sack_blocks=sack_blocks,
            tsval=tsval,
            tsecr=tsecr,
            fastopen_cookie=fastopen_cookie,
            accecn=accecn,
            payload=bytes(packet_rx.tcp.payload),
        )

    def _assert_segment(
        self,
        probe: TcpProbe,
        *,
        flags: object = _UNSET,
        seq: object = _UNSET,
        ack: object = _UNSET,
        payload: object = _UNSET,
        win: object = _UNSET,
        mss: object = _UNSET,
        wscale: object = _UNSET,
        sackperm: object = _UNSET,
        sack_blocks: object = _UNSET,
        sport: object = _UNSET,
        dport: object = _UNSET,
    ) -> None:
        """
        Assert that the given 'TcpProbe' matches every supplied field.
        Fields left at the '_UNSET' sentinel are not checked. Pass
        'None' explicitly to assert that an option-bearing field
        ('mss', 'wscale') is absent from the wire.
        """

        if flags is not _UNSET:
            assert flags is not None, "'flags' must be an iterable of flag names, not None."
            # Connection-control flags only; ECN-related
            # flags (ECE, CWR, NS) are orthogonal and are
            # asserted directly via 'probe.flags' in the
            # ECN-specific tests. This lets non-ECN tests
            # specify expected flags as
            # 'frozenset({"SYN"})' without having to
            # enumerate the ECN advertisement state of
            # every active-open SYN.
            connection_control = frozenset({"SYN", "ACK", "FIN", "RST", "PSH", "URG"})
            self.assertEqual(
                probe.flags & connection_control,
                frozenset(cast(Iterable[str], flags)) & connection_control,
                msg=f"Unexpected TCP flag set on outbound segment: {probe!r}",
            )
        if seq is not _UNSET:
            self.assertEqual(
                probe.seq,
                seq,
                msg=f"Unexpected TCP seq on outbound segment: {probe!r}",
            )
        if ack is not _UNSET:
            self.assertEqual(
                probe.ack,
                ack,
                msg=f"Unexpected TCP ack on outbound segment: {probe!r}",
            )
        if payload is not _UNSET:
            self.assertEqual(
                probe.payload,
                payload,
                msg=f"Unexpected TCP payload on outbound segment: {probe!r}",
            )
        if win is not _UNSET:
            self.assertEqual(
                probe.win,
                win,
                msg=f"Unexpected TCP advertised window on outbound segment: {probe!r}",
            )
        if mss is not _UNSET:
            self.assertEqual(
                probe.mss,
                mss,
                msg=f"Unexpected TCP MSS option on outbound segment: {probe!r}",
            )
        if wscale is not _UNSET:
            self.assertEqual(
                probe.wscale,
                wscale,
                msg=f"Unexpected TCP WSCALE option on outbound segment: {probe!r}",
            )
        if sackperm is not _UNSET:
            self.assertEqual(
                probe.sackperm,
                sackperm,
                msg=f"Unexpected TCP SACK-permitted option on outbound segment: {probe!r}",
            )
        if sack_blocks is not _UNSET:
            expected_blocks: tuple[tuple[int, int], ...] = (
                () if sack_blocks is None else tuple(cast(Iterable[tuple[int, int]], sack_blocks))
            )
            self.assertEqual(
                probe.sack_blocks,
                expected_blocks,
                msg=f"Unexpected TCP SACK blocks on outbound segment: {probe!r}",
            )
        if sport is not _UNSET:
            self.assertEqual(
                probe.sport,
                sport,
                msg=f"Unexpected TCP sport on outbound segment: {probe!r}",
            )
        if dport is not _UNSET:
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
