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
This module contains tests for the 'TxRing' class — the pure-asyncio
egress ('docs/refactor/pure_asyncio.md'): producers run on the one
stack loop, so 'enqueue' appends to the deque and schedules a drain
with 'loop.call_soon'; the drain writes with 'io_backend.writev' until
the deque is empty or the fd would block, in which case it re-arms via
'loop.add_writer'. There is no worker thread, no eventfd, and no
'_TxRequest' marshaling — single-writer holds by construction on a
single loop.

pmd_pytcp/tests/unit/runtime/test__runtime__tx_ring.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import os
from typing import Any
from typing_extensions import override
from unittest import IsolatedAsyncioTestCase, TestCase
from unittest.mock import MagicMock, patch

import pmd_pytcp.runtime.tx_ring as tx_ring_module
from pmd_net_proto import (
    Ethernet8023Assembler,
    EthernetAssembler,
    Ip4Assembler,
    Ip4FragAssembler,
    Ip6Assembler,
)
from pmd_net_proto.lib.buffer import Buffer
from pmd_pytcp._compat import as_buffer
from pmd_pytcp.lib.packet_stats import PacketStatsTx
from pmd_pytcp.runtime.tx_ring import TxRing


def _make_ethernet() -> MagicMock:
    """
    Build a MagicMock that behaves like an 'EthernetAssembler':
    passes 'isinstance(packet, EthernetAssembler)', has __len__,
    and has an 'assemble()' method that appends a stub buffer.
    """

    pkt = MagicMock(spec=EthernetAssembler)
    pkt.__len__.return_value = 64

    def assemble(buffers: list[Buffer]) -> None:
        buffers.append(as_buffer(b"x" * 64))

    pkt.assemble.side_effect = assemble
    return pkt


class _TxRingFixture(TestCase):
    """
    Shared synchronous fixture that opens a pipe (the write end stands
    in for the TX file descriptor) and suppresses module-level
    logging. No event loop runs — these tests exercise the
    enqueue-side behavior only, where 'enqueue' appends to the deque
    and '_schedule_drain' is a no-op on a never-started ring.
    """

    @override
    def setUp(self) -> None:
        """
        Install the logging patch and open the pipe.
        """

        self._log_patch = patch("pmd_pytcp.runtime.tx_ring.log")
        self._log_patch.start()
        self.addCleanup(self._log_patch.stop)

        self._read_fd, self._write_fd = os.pipe()
        self.addCleanup(self._close_fd, self._read_fd)
        self.addCleanup(self._close_fd, self._write_fd)
        self._ring = TxRing(fd=self._write_fd, mtu=1500)
        # 'stop' is idempotent and safe on a never-started ring — no
        # loop, no armed writer, nothing to disarm.
        self.addCleanup(self._ring.stop)

    @staticmethod
    def _close_fd(fd: int) -> None:
        """
        Close a file descriptor, tolerating an already-closed fd.
        """

        try:
            os.close(fd)
        except OSError:
            pass


class TestTxRingInit(_TxRingFixture):
    """
    The 'TxRing.__init__' tests.
    """

    def test__tx_ring__stores_fd_mtu_queue_size(self) -> None:
        """
        Ensure '__init__' stores the 'fd', 'mtu', and
        'queue_max_size' fields on private attributes.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ring._fd,
            self._write_fd,
            msg="TxRing.__init__ must store the fd argument verbatim.",
        )
        self.assertEqual(
            self._ring._mtu,
            1500,
            msg="TxRing.__init__ must store the mtu argument verbatim.",
        )
        self.assertEqual(
            self._ring._queue_max_size,
            1000,
            msg="TxRing._queue_max_size must default to 1000.",
        )

    def test__tx_ring__creates_empty_deque_and_disarmed_egress(self) -> None:
        """
        Ensure '__init__' creates an empty deque and leaves the
        egress disarmed — no loop bound, not running, no drain
        scheduled, no writability callback armed. 'start()' on the
        running loop is what arms the machinery.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            len(self._ring._tx_deque),
            0,
            msg="TxRing._tx_deque must start empty.",
        )
        self.assertIsNone(
            self._ring._loop,
            msg="A fresh TxRing must not be bound to any event loop.",
        )
        self.assertFalse(
            self._ring._running,
            msg="A fresh TxRing must not be running.",
        )
        self.assertFalse(
            self._ring._drain_scheduled,
            msg="A fresh TxRing must have no drain scheduled.",
        )
        self.assertFalse(
            self._ring._writer_armed,
            msg="A fresh TxRing must have no writability callback armed.",
        )


class TestTxRingEnqueue(_TxRingFixture):
    """
    The 'TxRing.enqueue' tests.
    """

    def test__tx_ring__enqueue_appends_packet(self) -> None:
        """
        Ensure enqueue() places the packet on the internal deque.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = MagicMock(spec=EthernetAssembler)
        self._ring.enqueue(pkt)
        self.assertEqual(
            list(self._ring._tx_deque),
            [pkt],
            msg="enqueue() must place the packet on the TX ring.",
        )

    def test__tx_ring__enqueue_on_unstarted_ring_schedules_nothing(self) -> None:
        """
        Ensure enqueue() on a never-started ring leaves the packet
        queued and does NOT schedule a drain — '_schedule_drain' is
        a no-op until 'start()' binds the running loop. Pre-'start()'
        boot enqueues drain on 'start()'; unit tests (like this one)
        enqueue and assert on the deque.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = MagicMock(spec=EthernetAssembler)
        self._ring.enqueue(pkt)

        self.assertEqual(
            list(self._ring._tx_deque),
            [pkt],
            msg="The packet must stay queued on an unstarted ring.",
        )
        self.assertFalse(
            self._ring._drain_scheduled,
            msg="enqueue() before start() must not schedule a drain.",
        )
        self.assertFalse(
            self._ring._writer_armed,
            msg="enqueue() before start() must not arm the writability callback.",
        )

    def test__tx_ring__enqueue_drops_when_full(self) -> None:
        """
        Ensure enqueue() silently drops the packet when the deque is
        at capacity rather than blocking — dropping an outbound
        frame is preferable to stalling the caller.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = TxRing(fd=self._write_fd, mtu=1500, queue_max_size=1)
        self.addCleanup(ring.stop)
        ring._tx_deque.append(MagicMock(spec=EthernetAssembler))
        ring.enqueue(MagicMock(spec=EthernetAssembler))  # must not raise
        self.assertEqual(
            len(ring._tx_deque),
            1,
            msg="enqueue() on a full TX ring must drop the new packet (size unchanged).",
        )


class TestTxRingDropCounters(_TxRingFixture):
    """
    The 'TxRing' drop-counter observability tests.
    """

    def test__tx_ring__queue_full_drop_count_starts_at_zero(self) -> None:
        """
        Ensure 'queue_full_drop_count' starts at 0 on a freshly
        constructed ring so monitors have a clean baseline.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ring.queue_full_drop_count,
            0,
            msg="A fresh TxRing must report queue_full_drop_count == 0.",
        )

    def test__tx_ring__os_error_drop_count_starts_at_zero(self) -> None:
        """
        Ensure 'os_error_drop_count' starts at 0.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self.assertEqual(
            self._ring.os_error_drop_count,
            0,
            msg="A fresh TxRing must report os_error_drop_count == 0.",
        )

    def test__tx_ring__enqueue_increments_drop_count_on_full_queue(self) -> None:
        """
        Ensure 'queue_full_drop_count' bumps each time
        'enqueue' is called on a full ring. Without the counter,
        a saturated TX queue silently drops outbound packets.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = TxRing(fd=self._write_fd, mtu=1500, queue_max_size=1)
        self.addCleanup(ring.stop)
        ring._tx_deque.append(MagicMock(spec=EthernetAssembler))

        ring.enqueue(MagicMock(spec=EthernetAssembler))
        ring.enqueue(MagicMock(spec=EthernetAssembler))
        ring.enqueue(MagicMock(spec=EthernetAssembler))

        self.assertEqual(
            ring.queue_full_drop_count,
            3,
            msg="Each full-queue drop must bump 'queue_full_drop_count' by exactly one.",
        )


class TestTxRingSharedPacketStats(_TxRingFixture):
    """
    The 'TxRing' shared-PacketStats integration tests (enqueue side —
    the write-side shared-stats test lives with the drain tests).
    """

    def test__tx_ring__queue_full_drop_increments_shared_stats(self) -> None:
        """
        Ensure that when a 'PacketStatsTx' instance is wired in via
        the constructor's 'packet_stats=' kwarg, queue-full drops
        bump 'stats.tx_ring__queue_full__drop' instead of the
        ring's private internal counter.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stats = PacketStatsTx()
        ring = TxRing(fd=self._write_fd, mtu=1500, queue_max_size=1, packet_stats=stats)
        self.addCleanup(ring.stop)
        ring._tx_deque.append(MagicMock(spec=EthernetAssembler))

        ring.enqueue(MagicMock(spec=EthernetAssembler))
        ring.enqueue(MagicMock(spec=EthernetAssembler))

        self.assertEqual(
            stats.tx_ring__queue_full__drop,
            2,
            msg="Each enqueue-on-full drop must bump the shared PacketStatsTx field.",
        )
        self.assertEqual(
            ring.queue_full_drop_count,
            2,
            msg="queue_full_drop_count property must read the shared stats value.",
        )


class TestTxRingRawFrame(_TxRingFixture):
    """
    The 'TxRing.enqueue_raw_frame' enqueue-side tests (the drain-side
    verbatim-write test lives with the drain tests).
    """

    def test__tx_ring__enqueue_raw_frame_appends(self) -> None:
        """
        Ensure 'enqueue_raw_frame' places the verbatim frame bytes on
        the internal deque (the AF_PACKET egress primitive that skips
        the assembler / IP layers).

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06payload"
        self._ring.enqueue_raw_frame(frame)

        self.assertEqual(
            list(self._ring._tx_deque),
            [frame],
            msg="enqueue_raw_frame() must place the verbatim frame on the TX ring.",
        )

    def test__tx_ring__enqueue_raw_frame_drops_when_full(self) -> None:
        """
        Ensure 'enqueue_raw_frame' silently drops the frame when the
        deque is already at capacity.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        ring = TxRing(fd=self._write_fd, mtu=1500, queue_max_size=1)
        self.addCleanup(ring.stop)
        ring.enqueue_raw_frame(b"first-frame")

        ring.enqueue_raw_frame(b"second-frame")  # must not raise

        self.assertEqual(
            len(ring._tx_deque),
            1,
            msg="enqueue_raw_frame() on a full TX ring must drop the new frame.",
        )


class TestTxRingDrain(IsolatedAsyncioTestCase):
    """
    The 'TxRing._drain' write-path tests over a real event loop. The
    ring is started on the test loop; 'enqueue' schedules the drain
    with 'loop.call_soon', so a loop tick ('asyncio.sleep(0)') runs
    it. 'io_backend.writev' is patched so no bytes hit the pipe —
    the assertions target the writev calls, the buffer contents
    (ethertype prefixes per protocol), and the deque state.
    """

    async def asyncSetUp(self) -> None:
        """
        Suppress logging, open the pipe, and build a fresh 'TxRing'
        over the write end so 'start()' has an OS-level fd to put
        into non-blocking mode (and 'add_writer' has one to arm on
        the backpressure path).
        """

        self._log_patch = patch("pmd_pytcp.runtime.tx_ring.log")
        self._log_patch.start()
        self.addCleanup(self._log_patch.stop)

        self._read_fd, self._write_fd = os.pipe()
        self.addCleanup(self._close_fd, self._read_fd)
        self.addCleanup(self._close_fd, self._write_fd)
        self._ring = TxRing(fd=self._write_fd, mtu=1500)
        # 'stop' disarms any writer left armed by a backpressure test
        # before the loop shuts down (and is safe if never started).
        self.addCleanup(self._ring.stop)

    @staticmethod
    def _close_fd(fd: int) -> None:
        """
        Close a file descriptor, tolerating an already-closed fd.
        """

        try:
            os.close(fd)
        except OSError:
            pass

    @staticmethod
    async def _tick() -> None:
        """
        Let the 'call_soon'-scheduled drain run: yield to the loop a
        couple of times so both the drain callback and anything it
        schedules get a turn.
        """

        await asyncio.sleep(0)
        await asyncio.sleep(0)

    async def test__tx_ring__drain_skips_writev_when_queue_empty(self) -> None:
        """
        Ensure a started ring with an empty deque never touches the
        fd — there is nothing to transmit so 'io_backend.writev'
        must not be called.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pmd_pytcp.runtime.tx_ring.io_backend.writev") as mock_writev:
            self._ring.start()
            await self._tick()

        mock_writev.assert_not_called()

    async def test__tx_ring__enqueue_after_start_writes_ethernet_frame(self) -> None:
        """
        Ensure 'enqueue' on a started ring schedules the drain by
        itself — one loop tick later the 'EthernetAssembler' frame
        is written to the TX fd via 'io_backend.writev' with the
        assembled buffer list (the Ethernet branch uses an empty
        ethertype prefix), and no explicit drain call is needed.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch("pmd_pytcp.runtime.tx_ring.io_backend.writev") as mock_writev:
            self._ring.start()
            self._ring.enqueue(_make_ethernet())
            await self._tick()

        mock_writev.assert_called_once()
        fd_arg, buffers_arg = mock_writev.call_args.args
        self.assertEqual(
            fd_arg,
            self._write_fd,
            msg="io_backend.writev must be called with the TX ring fd.",
        )
        self.assertEqual(
            buffers_arg,
            [b"x" * 64],
            msg="io_backend.writev must be called with the assembled buffer list.",
        )
        self.assertEqual(
            len(self._ring._tx_deque),
            0,
            msg="The written frame must be popped off the deque.",
        )

    async def test__tx_ring__start_drains_pre_queued_frames(self) -> None:
        """
        Ensure frames enqueued BEFORE 'start()' (the boot path — the
        packet handler can emit its gratuitous ARP / ND solicitations
        while the ring is still cold) are drained once 'start()'
        arms the egress on the running loop.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        self._ring.enqueue(_make_ethernet())

        with patch("pmd_pytcp.runtime.tx_ring.io_backend.writev") as mock_writev:
            self._ring.start()
            await self._tick()

        mock_writev.assert_called_once()
        self.assertEqual(
            len(self._ring._tx_deque),
            0,
            msg="start() must drain frames enqueued before the ring was started.",
        )

    async def test__tx_ring__drain_ip6_uses_ipv6_ethertype_prefix(self) -> None:
        """
        Ensure the drain prepends the IPv6 EtherType prefix
        (b'\\x00\\x00\\x86\\xdd') to the buffer list for an
        'Ip6Assembler' packet.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = MagicMock(spec=Ip6Assembler)
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"p6")

        with patch("pmd_pytcp.runtime.tx_ring.io_backend.writev") as mock_writev:
            self._ring.start()
            self._ring.enqueue(pkt)
            await self._tick()

        buffers_arg = mock_writev.call_args.args[1]
        self.assertEqual(
            buffers_arg[0],
            b"\x00\x00\x86\xdd",
            msg="The Ip6Assembler branch must prepend the IPv6 EtherType prefix.",
        )

    async def test__tx_ring__drain_ip4_uses_ipv4_ethertype_prefix(self) -> None:
        """
        Ensure the drain prepends the IPv4 EtherType prefix
        (b'\\x00\\x00\\x08\\x00') to the buffer list for an
        'Ip4Assembler' packet.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = MagicMock(spec=Ip4Assembler)
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"p4")

        with patch("pmd_pytcp.runtime.tx_ring.io_backend.writev") as mock_writev:
            self._ring.start()
            self._ring.enqueue(pkt)
            await self._tick()

        buffers_arg = mock_writev.call_args.args[1]
        self.assertEqual(
            buffers_arg[0],
            b"\x00\x00\x08\x00",
            msg="The Ip4Assembler branch must prepend the IPv4 EtherType prefix.",
        )

    async def test__tx_ring__drain_ip4_frag_uses_ipv4_prefix(self) -> None:
        """
        Ensure 'Ip4FragAssembler' packets also receive the IPv4
        EtherType prefix — they share a dispatch entry with
        'Ip4Assembler'.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = MagicMock(spec=Ip4FragAssembler)
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"frag")

        with patch("pmd_pytcp.runtime.tx_ring.io_backend.writev") as mock_writev:
            self._ring.start()
            self._ring.enqueue(pkt)
            await self._tick()

        buffers_arg = mock_writev.call_args.args[1]
        self.assertEqual(
            buffers_arg[0],
            b"\x00\x00\x08\x00",
            msg="The Ip4FragAssembler branch must share the IPv4 EtherType prefix.",
        )

    async def test__tx_ring__drain_eth802_3_branch_writes(self) -> None:
        """
        Ensure 'Ethernet8023Assembler' packets exercise the
        corresponding dispatch entry and get written out — the test
        only verifies the dispatch, not the 802.3 framing internals.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = MagicMock(spec=Ethernet8023Assembler)
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"z")

        with patch("pmd_pytcp.runtime.tx_ring.io_backend.writev") as mock_writev:
            self._ring.start()
            self._ring.enqueue(pkt)
            await self._tick()

        mock_writev.assert_called_once()

    async def test__tx_ring__drain_drops_oversized_frame(self) -> None:
        """
        Ensure the drain drops a frame whose length exceeds the MTU
        (plus Ethernet header overhead) without calling
        'io_backend.writev' — a silent non-fatal drop, and the item
        is popped so it cannot wedge the head of the queue.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = _make_ethernet()
        pkt.__len__.return_value = 65535  # way bigger than MTU + 14

        with patch("pmd_pytcp.runtime.tx_ring.io_backend.writev") as mock_writev:
            self._ring.start()
            self._ring.enqueue(pkt)
            await self._tick()

        mock_writev.assert_not_called()
        self.assertEqual(
            len(self._ring._tx_deque),
            0,
            msg="An oversized frame must be popped off the deque when dropped.",
        )

    async def test__tx_ring__drain_unknown_packet_type_dropped(self) -> None:
        """
        Ensure packets of an unexpected type (not one of the five
        accepted assemblers) are logged and dropped — writev must
        not be called and the item must not wedge the queue head.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = MagicMock()  # plain MagicMock, no spec -> unknown type
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"x")

        with patch("pmd_pytcp.runtime.tx_ring.io_backend.writev") as mock_writev:
            self._ring.start()
            self._ring._tx_deque.append(pkt)
            self._ring._schedule_drain()
            await self._tick()

        mock_writev.assert_not_called()
        self.assertEqual(
            len(self._ring._tx_deque),
            0,
            msg="An unknown-type packet must be popped off the deque when dropped.",
        )

    async def test__tx_ring__drain_counts_oserror_and_continues(self) -> None:
        """
        Ensure a plain 'OSError' from 'io_backend.writev' (interface
        down, ENOBUFS, EIO) is counted per frame and the drain
        CONTINUES with the next queued item — unlike EAGAIN there is
        no writability event coming to resume a broken-out drain, so
        stalling the queue on a hard error would strand every frame
        behind it. Two queued frames + an always-raising writev must
        yield two writev attempts, two counted drops, and an empty
        deque.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        with patch(
            "pmd_pytcp.runtime.tx_ring.io_backend.writev",
            side_effect=OSError("link down"),
        ) as mock_writev:
            self._ring.start()
            self._ring.enqueue(_make_ethernet())
            self._ring.enqueue(_make_ethernet())
            await self._tick()

        self.assertEqual(
            mock_writev.call_count,
            2,
            msg=(
                "The drain must attempt every queued frame despite writev OSError. "
                f"Expected 2 writev calls; got {mock_writev.call_count}."
            ),
        )
        self.assertEqual(
            self._ring.os_error_drop_count,
            2,
            msg="Each writev OSError must bump 'os_error_drop_count' by exactly one.",
        )
        self.assertEqual(
            len(self._ring._tx_deque),
            0,
            msg="Frames dropped on OSError must be popped so the queue drains.",
        )

    async def test__tx_ring__os_error_drop_increments_shared_stats(self) -> None:
        """
        Ensure a writev 'OSError' increments the shared
        'PacketStatsTx.tx_ring__os_error__drop' field when a shared
        stats object is wired in, keeping the ring property in sync.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        stats = PacketStatsTx()
        ring = TxRing(fd=self._write_fd, mtu=1500, packet_stats=stats)
        self.addCleanup(ring.stop)

        with patch(
            "pmd_pytcp.runtime.tx_ring.io_backend.writev",
            side_effect=OSError("link down"),
        ):
            ring.start()
            ring.enqueue(_make_ethernet())
            await self._tick()

        self.assertEqual(
            stats.tx_ring__os_error__drop,
            1,
            msg="The writev OSError must bump the shared PacketStatsTx field.",
        )
        self.assertEqual(
            ring.os_error_drop_count,
            1,
            msg="os_error_drop_count property must read the shared stats value.",
        )

    async def test__tx_ring__drain_writes_all_pending_frames_per_wake(self) -> None:
        """
        Ensure a single drain wake writes every frame currently in
        the TX ring queue, not just one. The drain loops on the
        deque until it is empty (or the fd would block) — one
        'call_soon' scheduling per enqueue burst, not one per frame.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        n_frames = 10

        with patch("pmd_pytcp.runtime.tx_ring.io_backend.writev") as mock_writev:
            self._ring.start()
            for _ in range(n_frames):
                self._ring.enqueue(_make_ethernet())
            await self._tick()

        self.assertEqual(
            mock_writev.call_count,
            n_frames,
            msg=(
                f"A single drain wake must write all {n_frames} queued frames "
                f"in one pass. Got {mock_writev.call_count} writev calls."
            ),
        )
        self.assertEqual(
            len(self._ring._tx_deque),
            0,
            msg="After the drain the deque must be empty.",
        )

    async def test__tx_ring__drain_backpressure_arms_writer_and_resumes(self) -> None:
        """
        Ensure the EAGAIN backpressure path: when 'io_backend.writev'
        raises 'BlockingIOError' (kernel buffer full) the drain
        leaves the frame at the HEAD of the deque (no data loss) and
        arms the writability callback via 'loop.add_writer'
        ('_writer_armed' set); once the fd is writable again a drain
        pass writes the frame and disarms the callback.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        pkt = _make_ethernet()

        with patch("pmd_pytcp.runtime.tx_ring.io_backend.writev") as mock_writev:
            mock_writev.side_effect = BlockingIOError()
            self._ring.start()
            self._ring.enqueue(pkt)
            await self._tick()

            # The frame must survive the failed write attempt at the
            # head of the queue, with the writability callback armed
            # to resume the drain.
            self.assertEqual(
                len(self._ring._tx_deque),
                1,
                msg="A frame hitting EAGAIN must stay queued (no data loss).",
            )
            self.assertIs(
                self._ring._tx_deque[0],
                pkt,
                msg="The EAGAIN frame must remain at the HEAD of the deque.",
            )
            self.assertTrue(
                self._ring._writer_armed,
                msg="EAGAIN must arm the writability callback via add_writer.",
            )

            # Simulate the fd becoming writable: writev now succeeds
            # and the resumed drain (the add_writer callback invokes
            # '_drain'; calling it directly is equivalent and keeps
            # the test deterministic) writes the frame and disarms.
            mock_writev.side_effect = None
            mock_writev.return_value = 64
            self._ring._drain()

            self.assertEqual(
                len(self._ring._tx_deque),
                0,
                msg="The resumed drain must write the frame that hit EAGAIN.",
            )
            self.assertFalse(
                self._ring._writer_armed,
                msg="A completed drain must disarm the writability callback.",
            )

    async def test__tx_ring__drain_writes_raw_frame_verbatim(self) -> None:
        """
        Ensure the drain writes a queued raw frame to the TX fd
        verbatim via 'io_backend.writev', without prepending any
        ethertype framing prefix.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        frame = b"\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x00\x07\x08\x06payload"

        with patch("pmd_pytcp.runtime.tx_ring.io_backend.writev") as mock_writev:
            self._ring.start()
            self._ring.enqueue_raw_frame(frame)
            await self._tick()

        mock_writev.assert_called_once()
        fd_arg, buffers_arg = mock_writev.call_args.args
        self.assertEqual(
            fd_arg,
            self._write_fd,
            msg="io_backend.writev must target the TX ring fd.",
        )
        self.assertEqual(
            b"".join(bytes(b) for b in buffers_arg),
            frame,
            msg="A raw frame must be written verbatim, with no framing prefix added.",
        )


class TestTxRingDispatchFastPath(_TxRingFixture):
    """
    The '_TX_PROTO_DISPATCH' production fast-path tests — verify the
    dict is keyed by the actual production assembler classes so a
    real (non-mock) packet resolves via a single 'type()' lookup
    rather than the 'isinstance' fallback loop reserved for
    'MagicMock(spec=...)' fixtures.
    """

    def test__tx_ring__dispatch_dict_keys_are_production_assembler_classes(self) -> None:
        """
        Ensure '_TX_PROTO_DISPATCH' contains every production assembler
        class as a literal 'type' key. If a key were ever replaced with
        a string, a subclass, or removed, real packets would skip the
        O(1) fast path and silently degrade to the 'isinstance' walk —
        a regression mocked-only unit tests cannot catch.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for cls in (
            EthernetAssembler,
            Ethernet8023Assembler,
            Ip6Assembler,
            Ip4Assembler,
            Ip4FragAssembler,
        ):
            self.assertIn(
                cls,
                tx_ring_module._TX_PROTO_DISPATCH,
                msg=(
                    f"{cls.__name__} must be a literal key of _TX_PROTO_DISPATCH so "
                    "type(packet) lookup hits the O(1) fast path. Missing keys force "
                    "the isinstance fallback loop on every send."
                ),
            )

    def test__tx_ring__send_item_real_assembler_resolves_via_type_lookup(self) -> None:
        """
        Ensure '_send_item' on a real (non-mock) 'EthernetAssembler'
        resolves its dispatch entry via the 'type()' dict-lookup fast
        path: 'dict.get' returns non-None and the 'isinstance' fallback
        loop is not entered. Existing unit tests use 'MagicMock(spec=X)'
        whose 'type(...)' is 'MagicMock', so they always exercise the
        fallback path — this test pins the production behaviour.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        get_calls: list[type] = []

        class _SpyDict(dict[type, tuple[bytes, int]]):
            """
            Wraps the production dispatch dict; records every '.get'
            key and fail-louds if the 'isinstance' fallback path
            iterates '.items()'.
            """

            def get(self, key: Any, default: Any = None) -> Any:
                get_calls.append(key)
                return super().get(key, default)

            def items(self) -> Any:
                raise AssertionError(
                    "isinstance fallback path entered — real EthernetAssembler should "
                    "resolve via 'type()' dict-lookup fast path, not via the "
                    "'.items()' iteration reserved for MagicMock(spec=...) fixtures."
                )

        spy_dispatch = _SpyDict(tx_ring_module._TX_PROTO_DISPATCH)
        real_assembler = EthernetAssembler()

        with (
            patch.object(tx_ring_module, "_TX_PROTO_DISPATCH", spy_dispatch),
            patch("pmd_pytcp.runtime.tx_ring.io_backend.writev", return_value=14) as writev,
        ):
            sent_ok = self._ring._send_item(real_assembler)

        self.assertTrue(
            sent_ok,
            msg="_send_item on a real EthernetAssembler must return True (success).",
        )
        self.assertEqual(
            get_calls,
            [EthernetAssembler],
            msg=("_send_item must call _TX_PROTO_DISPATCH.get exactly once with type(packet); " f"got: {get_calls!r}"),
        )
        self.assertEqual(
            writev.call_count,
            1,
            msg="_send_item must invoke io_backend.writev exactly once on a successful dispatch.",
        )
