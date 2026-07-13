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
This module contains tests for the 'RxRing' class — the pure-asyncio
readiness-callback ingress ('docs/refactor/pure_asyncio.md'): the fd
is armed with 'loop.add_reader', every readiness callback burst-drains
the kernel buffer, and each parsed 'PacketRx' is delivered
synchronously to the deliver callback the packet handler installs.
There is no rx queue, no eventfd and no worker thread.

pmd_pytcp/tests/unit/runtime/test__runtime__rx_ring.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import os
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import MagicMock, patch

from pmd_net_proto.lib.packet_rx import PacketRx
from pmd_pytcp.lib.packet_stats import LinkStatsCounters, PacketStatsRx
from pmd_pytcp.runtime.rx_ring import RX_RING__READ_HEADROOM, RxRing

_TEST_FD = 7
_TEST_MTU = 1500
_TEST_FRAME = b"\x02" * 60


class _RxRingFixture(TestCase):
    """
    Shared fixture: a bare 'RxRing' over a fake fd with logging
    suppressed. No loop is armed — the ingress mechanics
    ('_handle_frame' / '_on_readable') are driven directly.
    """

    def setUp(self) -> None:
        """
        Suppress rx-ring logging and build a fresh 'RxRing'.
        """

        self._log_patch = patch("pmd_pytcp.runtime.rx_ring.log")
        self._log = self._log_patch.start()
        self.addCleanup(self._log_patch.stop)

        self._ring = RxRing(fd=_TEST_FD, mtu=_TEST_MTU)


class TestRxRingInit(_RxRingFixture):
    """
    The 'RxRing.__init__()' tests.
    """

    def test__rx_ring__stores_fd_and_mtu(self) -> None:
        """
        Ensure the constructor records the fd and MTU used by the
        readiness-callback reads.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ring._fd,
            _TEST_FD,
            msg="RxRing must store the fd it reads from.",
        )
        self.assertEqual(
            self._ring._mtu,
            _TEST_MTU,
            msg="RxRing must store the interface MTU.",
        )

    def test__rx_ring__no_deliver_callback_by_default(self) -> None:
        """
        Ensure a fresh ring has no deliver callback installed — the
        packet handler installs one at 'start()' time.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertIsNone(
            self._ring._deliver,
            msg="A fresh RxRing must have no deliver callback.",
        )

    def test__rx_ring__custom_queue_size_bounds_burst(self) -> None:
        """
        Ensure the former 'queue_max_size' kwarg now bounds the
        per-readiness-callback drain burst so one hot interface
        cannot starve the loop.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = RxRing(fd=_TEST_FD, mtu=_TEST_MTU, queue_max_size=5)

        self.assertEqual(
            ring._burst_max,
            5,
            msg="queue_max_size must bound the per-callback drain burst.",
        )


class TestRxRingDeliver(_RxRingFixture):
    """
    The '_handle_frame' deliver-callback tests.
    """

    def test__rx_ring__delivers_parsed_packet(self) -> None:
        """
        Ensure a read frame is parsed into a 'PacketRx' and handed
        synchronously to the installed deliver callback.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        delivered: list[PacketRx] = []
        self._ring.set_deliver_callback(delivered.append)

        self._ring._handle_frame(_TEST_FRAME)

        self.assertEqual(
            len(delivered),
            1,
            msg="The deliver callback must receive exactly one packet per frame.",
        )
        self.assertEqual(
            bytes(delivered[0].frame),
            _TEST_FRAME,
            msg="The delivered PacketRx must wrap the read frame verbatim.",
        )

    def test__rx_ring__drops_frame_without_deliver_callback(self) -> None:
        """
        Ensure a frame read while no deliver callback is installed is
        dropped and counted under the legacy 'queue_full_drop_count'
        name (kept so unified-stats consumers keep their field).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._ring._handle_frame(_TEST_FRAME)

        self.assertEqual(
            self._ring.queue_full_drop_count,
            1,
            msg="A frame dropped for lack of a deliver callback must be counted.",
        )

    def test__rx_ring__uninstalling_callback_reverts_to_drop(self) -> None:
        """
        Ensure 'set_deliver_callback(None)' (the packet handler's
        stop() path) uninstalls the callback so later frames drop.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._ring.set_deliver_callback(MagicMock())
        self._ring.set_deliver_callback(None)

        self._ring._handle_frame(_TEST_FRAME)

        self.assertEqual(
            self._ring.queue_full_drop_count,
            1,
            msg="Frames after callback uninstall must be dropped + counted.",
        )

    def test__rx_ring__raising_deliver_callback_is_swallowed(self) -> None:
        """
        Ensure a raising deliver callback is logged and swallowed so a
        handler bug cannot disarm the RX ingress.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._ring.set_deliver_callback(MagicMock(side_effect=RuntimeError("boom")))

        self._ring._handle_frame(_TEST_FRAME)  # must not raise

        logged = " ".join(str(call_args) for call_args in self._log.call_args_list)
        self.assertIn(
            "Deliver callback raised",
            logged,
            msg="A raising deliver callback must be logged.",
        )

    def test__rx_ring__link_stats_rx_bytes_bumped(self) -> None:
        """
        Ensure the shared 'LinkStatsCounters.rx_bytes' is bumped per
        frame at the canonical RX entry point (RFC 1213 'ifInOctets'
        semantics for the Link API).

        Reference: RFC 1213 (MIB-II ifInOctets).
        """

        link_stats = LinkStatsCounters()
        ring = RxRing(fd=_TEST_FD, mtu=_TEST_MTU, link_stats=link_stats)
        ring.set_deliver_callback(MagicMock())

        ring._handle_frame(_TEST_FRAME)

        self.assertEqual(
            link_stats.rx_bytes,
            len(_TEST_FRAME),
            msg="rx_bytes must count wire-level frame bytes received.",
        )


class TestRxRingOnReadable(_RxRingFixture):
    """
    The '_on_readable' burst-drain tests.
    """

    def test__rx_ring__drains_until_would_block(self) -> None:
        """
        Ensure one readiness callback drains every pending frame until
        the kernel buffer reports 'BlockingIOError'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        delivered: list[PacketRx] = []
        self._ring.set_deliver_callback(delivered.append)

        with patch(
            "pmd_pytcp.runtime.rx_ring.io_backend.read",
            side_effect=[_TEST_FRAME, _TEST_FRAME, _TEST_FRAME, BlockingIOError()],
        ):
            self._ring._on_readable()

        self.assertEqual(
            len(delivered),
            3,
            msg="One readiness callback must drain every pending frame.",
        )

    def test__rx_ring__burst_bounded_by_queue_max_size(self) -> None:
        """
        Ensure the per-callback drain burst is bounded by the
        configured 'queue_max_size' so a hot interface cannot starve
        the rest of the loop.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = RxRing(fd=_TEST_FD, mtu=_TEST_MTU, queue_max_size=2)
        delivered: list[PacketRx] = []
        ring.set_deliver_callback(delivered.append)

        with patch(
            "pmd_pytcp.runtime.rx_ring.io_backend.read",
            return_value=_TEST_FRAME,
        ) as mock_read:
            ring._on_readable()

        self.assertEqual(
            mock_read.call_count,
            2,
            msg="The drain burst must stop at the configured budget.",
        )
        self.assertEqual(
            len(delivered),
            2,
            msg="Only the budgeted frames may be delivered per callback.",
        )

    def test__rx_ring__read_size_honors_mtu_headroom(self) -> None:
        """
        Ensure the per-read kernel-buffer size is
        'mtu + RX_RING__READ_HEADROOM' so jumbo-Ethernet frames
        (MTU 9000) fit with the L2 framing overhead.

        Reference: RFC 2675 (IPv6 jumbograms).
        """

        ring = RxRing(fd=_TEST_FD, mtu=9000)
        ring.set_deliver_callback(MagicMock())

        with patch(
            "pmd_pytcp.runtime.rx_ring.io_backend.read",
            side_effect=[_TEST_FRAME, BlockingIOError()],
        ) as mock_read:
            ring._on_readable()

        mock_read.assert_any_call(_TEST_FD, 9000 + RX_RING__READ_HEADROOM)

    def test__rx_ring__os_error_counted_and_stops_drain(self) -> None:
        """
        Ensure a transient read 'OSError' (EINTR / EBADF on shutdown
        race / EIO / ENOMEM) increments the drop counter and ends the
        drain without unwinding the loop callback.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._ring.set_deliver_callback(MagicMock())

        with patch(
            "pmd_pytcp.runtime.rx_ring.io_backend.read",
            side_effect=OSError(5, "EIO"),
        ):
            self._ring._on_readable()  # must not raise

        self.assertEqual(
            self._ring.os_error_drop_count,
            1,
            msg="A read OSError must increment os_error_drop_count.",
        )

    def test__rx_ring__drop_counters_start_at_zero(self) -> None:
        """
        Ensure both drop counters start at zero on a fresh ring.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(self._ring.queue_full_drop_count, 0)
        self.assertEqual(self._ring.os_error_drop_count, 0)


class TestRxRingSharedPacketStats(_RxRingFixture):
    """
    The shared-'PacketStatsRx' counter-dispatch tests.
    """

    def test__rx_ring__no_deliver_drop_increments_shared_stats(self) -> None:
        """
        Ensure the no-deliver-callback drop lands on the shared
        'PacketStatsRx.rx_ring__queue_full__drop' field when a shared
        stats object is wired, keeping the ring property in sync.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stats = PacketStatsRx()
        ring = RxRing(fd=_TEST_FD, mtu=_TEST_MTU, packet_stats=stats)

        ring._handle_frame(_TEST_FRAME)

        self.assertEqual(
            stats.rx_ring__queue_full__drop,
            1,
            msg="The drop must land on the shared stats field.",
        )
        self.assertEqual(
            ring.queue_full_drop_count,
            1,
            msg="The ring property must source from the shared stats.",
        )

    def test__rx_ring__os_error_drop_increments_shared_stats(self) -> None:
        """
        Ensure the read-OSError drop lands on the shared
        'PacketStatsRx.rx_ring__os_error__drop' field when wired.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stats = PacketStatsRx()
        ring = RxRing(fd=_TEST_FD, mtu=_TEST_MTU, packet_stats=stats)
        ring.set_deliver_callback(MagicMock())

        with patch(
            "pmd_pytcp.runtime.rx_ring.io_backend.read",
            side_effect=OSError(5, "EIO"),
        ):
            ring._on_readable()

        self.assertEqual(
            stats.rx_ring__os_error__drop,
            1,
            msg="The OSError drop must land on the shared stats field.",
        )
        self.assertEqual(
            ring.os_error_drop_count,
            1,
            msg="The ring property must source from the shared stats.",
        )

    def test__rx_ring__without_shared_stats_uses_internal_counters(self) -> None:
        """
        Ensure a ring without a shared stats object falls back to its
        private counters (the standalone unit-test configuration).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._ring._handle_frame(_TEST_FRAME)

        self.assertEqual(
            self._ring._no_deliver_drop_count,
            1,
            msg="Without shared stats the internal counter must be used.",
        )


class TestRxRingLoopIntegration(IsolatedAsyncioTestCase):
    """
    The 'start()' / 'stop()' loop-integration tests over a real pipe
    fd — 'add_reader' arms the ingress, frames written to the pipe are
    delivered, 'stop()' disarms.
    """

    async def asyncSetUp(self) -> None:
        """
        Suppress logging and build a ring over the read end of a real
        pipe so 'loop.add_reader' has an OS-level fd to watch.
        """

        self._log_patch = patch("pmd_pytcp.runtime.rx_ring.log")
        self._log_patch.start()
        self.addCleanup(self._log_patch.stop)

        self._rd, self._wr = os.pipe()
        self.addCleanup(os.close, self._rd)
        self.addCleanup(os.close, self._wr)

        self._ring = RxRing(fd=self._rd, mtu=_TEST_MTU)

    async def asyncTearDown(self) -> None:
        """
        Disarm the ingress so the loop holds no reader on the pipe.
        """

        self._ring.stop()

    async def test__rx_ring__start_arms_reader_and_delivers(self) -> None:
        """
        Ensure 'start()' arms the fd with 'add_reader' and a frame
        written to the pipe is delivered to the callback on the next
        loop turn.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        delivered: "asyncio.Queue[PacketRx]" = asyncio.Queue()
        self._ring.set_deliver_callback(delivered.put_nowait)
        self._ring.start()

        os.write(self._wr, _TEST_FRAME)

        packet_rx = await asyncio.wait_for(delivered.get(), timeout=2.0)
        self.assertEqual(
            bytes(packet_rx.frame),
            _TEST_FRAME,
            msg="A frame written to the armed fd must be delivered.",
        )

    async def test__rx_ring__stop_disarms_reader(self) -> None:
        """
        Ensure 'stop()' removes the reader — frames written after stop
        are not delivered.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        deliver = MagicMock()
        self._ring.set_deliver_callback(deliver)
        self._ring.start()
        self._ring.stop()

        os.write(self._wr, _TEST_FRAME)
        await asyncio.sleep(0.05)

        deliver.assert_not_called()
