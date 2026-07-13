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
This module contains class supporting stack TX Ring operations.

pmd_pytcp/runtime/tx_ring.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
import collections
from typing_extensions import TypeAliasType

from pmd_net_proto import (
    Ethernet8023Assembler,
    EthernetAssembler,
    Ip4Assembler,
    Ip4FragAssembler,
    Ip6Assembler,
)
from pmd_net_proto.lib.buffer import Buffer
from pmd_net_proto.protocols.ethernet.ethernet__header import ETHERNET__HEADER__LEN
from pmd_net_proto.protocols.ethernet_802_3.ethernet_802_3__header import (
    ETHERNET_802_3__HEADER__LEN,
)
from pmd_pytcp.lib import io_backend
from pmd_pytcp.lib.logger import log
from pmd_pytcp.lib.packet_stats import LinkStatsCounters, PacketStatsTx
from typing import Union

# A fully-built outbound frame ready for the egress write. The TX
# deque carries these alongside verbatim raw frames (AF_PACKET
# egress): the drain writes both kinds in queue order.
TxFrame = TypeAliasType("TxFrame", Union[EthernetAssembler, Ethernet8023Assembler, Ip6Assembler, Ip4Assembler, Ip4FragAssembler])

# Per-protocol-class dispatch table mapping the TX-side Assembler
# concrete class to its (Ethernet-type prefix, MTU overhead) tuple.
# Used by '_send_one' to look up the wire-framing without an
# 'isinstance' chain — single 'type()' dict lookup on the production
# fast path, with an 'isinstance' fallback for test fixtures using
# 'unittest.mock.MagicMock(spec=...)' (where 'type(mock)' is
# 'MagicMock', not the spec class).
_TX_PROTO_DISPATCH: dict[type, tuple[bytes, int]] = {
    EthernetAssembler: (b"", ETHERNET__HEADER__LEN),
    Ethernet8023Assembler: (b"", ETHERNET_802_3__HEADER__LEN),
    Ip6Assembler: (b"\x00\x00\x86\xdd", 0),
    Ip4Assembler: (b"\x00\x00\x08\x00", 0),
    Ip4FragAssembler: (b"\x00\x00\x08\x00", 0),
}


class TxRing:
    """
    Support for sending packets to the network.

    Pure-asyncio egress ('docs/refactor/pure_asyncio.md'): producers
    run on the one stack loop, so 'enqueue' appends to the deque and
    schedules a drain with 'loop.call_soon' — no worker thread, no
    eventfd, and no '_TxRequest' marshaling (single-writer holds by
    construction on a single loop; former 'dispatch(run)' callers
    now just call 'run()'). The drain writes with 'io_backend.writev'
    until the deque is empty or the fd would block, in which case it
    re-arms via 'loop.add_writer'. On the socket-I/O path (Windows /
    'PYTCP_FORCE_SOCK_IO') a writer task drives 'loop.sock_sendall'
    instead — proactor loops lack 'add_writer' for arbitrary fds.
    """

    _subsystem_name = "TX Ring"

    _fd: int
    _mtu: int
    _queue_max_size: int

    _tx_deque: "collections.deque[TxFrame | Buffer]"
    _loop: asyncio.AbstractEventLoop | None
    _running: bool
    _drain_scheduled: bool
    _writer_armed: bool
    _writer_task: "asyncio.Task[None] | None"
    _writer_wakeup: asyncio.Event | None
    _queue_full_drop_count: int
    _os_error_drop_count: int
    _packet_stats: PacketStatsTx | None
    _link_stats: LinkStatsCounters | None

    def __init__(
        self,
        *,
        fd: int,
        mtu: int,
        queue_max_size: int = 1000,
        packet_stats: PacketStatsTx | None = None,
        link_stats: LinkStatsCounters | None = None,
    ) -> None:
        """
        Initialize access to TX file descriptor and the outbound queue.
        """

        self._fd = fd
        self._mtu = mtu
        self._queue_max_size = queue_max_size

        __debug__ and log(
            "stack",
            f"Initializing {self._subsystem_name} [fd={fd}, mtu={mtu}, queue_max_size={queue_max_size}]",
        )

        self._tx_deque = collections.deque()
        self._loop = None
        self._running = False
        self._drain_scheduled = False
        self._writer_armed = False
        self._writer_task = None
        self._writer_wakeup = None
        self._queue_full_drop_count = 0
        self._os_error_drop_count = 0
        # Optional shared 'PacketStatsTx' object — see RxRing for
        # the same pattern; ring drop counters live as fields on
        # the shared stats when wired so unified-stats consumers
        # see them alongside per-protocol drops.
        self._packet_stats = packet_stats
        # Optional shared 'LinkStatsCounters' object — when set,
        # 'tx_bytes' is bumped here per successful 'enqueue'. The
        # PacketHandler owns the canonical instance; sharing it
        # gives the Link API a single source of truth for
        # 'stats.tx_bytes'.
        self._link_stats = link_stats

    @property
    def queue_full_drop_count(self) -> int:
        """
        Get the cumulative count of outbound packets dropped because
        the TX ring was at capacity at 'enqueue' time. A non-zero
        rate signals the producer (the packet handler) is generating
        packets faster than the egress write can drain them. Sources
        from the shared 'PacketStatsTx' field when wired, falls back
        to the internal counter otherwise.
        """

        if self._packet_stats is not None:
            return self._packet_stats.tx_ring__queue_full__drop
        return self._queue_full_drop_count

    @property
    def os_error_drop_count(self) -> int:
        """
        Get the cumulative count of outbound packets dropped because
        the egress write raised 'OSError' (typically ENOBUFS,
        ENETDOWN, EIO on link failure). A non-zero rate signals
        interface trouble the application would otherwise have no
        visibility into.
        """

        if self._packet_stats is not None:
            return self._packet_stats.tx_ring__os_error__drop
        return self._os_error_drop_count

    @property
    def qsize(self) -> int:
        """
        Get the current depth of the TX deque. Useful for live
        observability — steady-state qsize > 0 indicates the egress
        write is falling behind the producers.
        """

        return len(self._tx_deque)

    def start(self) -> None:
        """
        Arm the egress on the running event loop. On the socket-I/O
        path this spawns the writer task; on the fd path drains are
        scheduled on demand by 'enqueue'.
        """

        __debug__ and log("stack", f"Starting {self._subsystem_name}")

        self._loop = asyncio.get_running_loop()
        self._running = True

        sock = io_backend.sock_for_fd(self._fd)
        if sock is not None:
            sock.setblocking(False)
            self._writer_wakeup = asyncio.Event()
            self._writer_task = self._loop.create_task(self._task__sock_writer(), name=self._subsystem_name)
            return

        io_backend.set_nonblocking(self._fd)
        if self._tx_deque:
            self._schedule_drain()

    def stop(self) -> None:
        """
        Disarm the egress. Anything still queued is dropped with the
        deque (acceptable during shutdown — same contract the
        threaded worker had).
        """

        __debug__ and log("stack", f"Stopping {self._subsystem_name}")

        self._running = False
        if self._writer_armed and self._loop is not None:
            try:
                self._loop.remove_writer(self._fd)
            except (OSError, ValueError):
                pass
            self._writer_armed = False
        if self._writer_task is not None and not self._writer_task.done():
            self._writer_task.cancel()

    def _schedule_drain(self) -> None:
        """
        Ensure exactly one pending drain: 'call_soon' on the fd
        path, a wakeup-event set on the socket-I/O path. No-op when
        the ring is not started (pre-'start()' boot enqueues drain
        on 'start()'; unit tests enqueue and assert on the deque).
        """

        if not self._running or self._loop is None:
            return
        if self._writer_wakeup is not None:
            self._writer_wakeup.set()
            return
        if self._drain_scheduled or self._writer_armed:
            return
        self._drain_scheduled = True
        self._loop.call_soon(self._drain)

    def _drain(self) -> None:
        """
        Write queued frames until the deque is empty or the fd
        would block; on EAGAIN re-arm via 'add_writer' so the drain
        resumes on writability.
        """

        self._drain_scheduled = False
        if not self._running:
            return

        while self._tx_deque:
            item = self._tx_deque[0]
            try:
                self._send_item(item)
            except (BlockingIOError, InterruptedError):
                # Kernel buffer full — resume when writable.
                assert self._loop is not None
                if not self._writer_armed:
                    self._loop.add_writer(self._fd, self._on_writable)
                    self._writer_armed = True
                return
            self._tx_deque.popleft()

        if self._writer_armed and self._loop is not None:
            self._loop.remove_writer(self._fd)
            self._writer_armed = False

    def _on_writable(self) -> None:
        """
        Writability callback (armed after EAGAIN): resume the drain.
        """

        self._drain()

    async def _task__sock_writer(self) -> None:
        """
        Socket-I/O-path writer: 'loop.sock_sendall' works on both
        selector and proactor loops, covering Windows where
        'add_writer' cannot take an arbitrary fd.
        """

        assert self._loop is not None and self._writer_wakeup is not None
        sock = io_backend.sock_for_fd(self._fd)
        assert sock is not None

        while True:
            await self._writer_wakeup.wait()
            self._writer_wakeup.clear()
            while self._tx_deque:
                item = self._tx_deque[0]
                buffers = self._wire_buffers(item)
                if buffers is not None:
                    try:
                        await self._loop.sock_sendall(sock, b"".join(buffers))
                    except asyncio.CancelledError:
                        return
                    except OSError as error:
                        self._count_os_error(error)
                self._tx_deque.popleft()

    def _wire_buffers(self, item: "TxFrame | Buffer", /) -> "list[Buffer] | None":
        """
        Build the wire-buffer list for one queued item — the framing
        prefix + assembled frame for an Assembler, the verbatim
        bytes for a raw frame. Returns None for the silent drops
        (unknown type, frame > MTU) which are non-fatal log-only
        branches.
        """

        if isinstance(item, (bytes, bytearray, memoryview)):
            return [item]

        # Production fast path: 'type(x)' dict lookup is O(1). For
        # 'MagicMock(spec=X)' fixtures whose 'type(mock)' is
        # 'MagicMock', fall back to an 'isinstance' walk so test
        # mocks resolve via '__class__' / '__instancecheck__'.
        proto_info = _TX_PROTO_DISPATCH.get(type(item))
        if proto_info is None:
            for cls, info in _TX_PROTO_DISPATCH.items():
                if isinstance(item, cls):
                    proto_info = info
                    break
        if proto_info is None:
            __debug__ and log(
                "tx-ring",
                f"{item.tracker} - <CRIT>Unknown packet type: " f"{type(item)!r}</>",
            )
            return None

        prefix, mtu_extra = proto_info
        buffers: list[Buffer] = [prefix] if prefix else []
        mtu = self._mtu + mtu_extra

        if (packet_tx_len := len(item)) > mtu:
            __debug__ and log(
                "tx-ring",
                f"{item.tracker} - Unable to send frame, frame" f"len ({packet_tx_len}) > mtu ({mtu})",
            )
            return None

        item.assemble(buffers)
        return buffers

    def _count_os_error(self, error: OSError, /) -> None:
        """
        Count an egress-write 'OSError' drop.
        """

        if self._packet_stats is not None:
            self._packet_stats.tx_ring__os_error__drop += 1
        else:
            self._os_error_drop_count += 1
        __debug__ and log(
            "tx-ring",
            f"<CRIT>Unable to send frame, OSError: {error}</>",
        )

    def _send_item(self, item: "TxFrame | Buffer", /) -> bool:
        """
        Write one queued item via 'io_backend.writev'. Returns True
        on a successful write, False for the silent drops (unknown
        type / oversized frame / non-blocking OSError). Re-raises
        'BlockingIOError' so the drain can arm the writability
        callback with the item still at the head of the queue.
        """

        buffers = self._wire_buffers(item)
        if buffers is None:
            return False

        try:
            io_backend.writev(self._fd, buffers)
        except (BlockingIOError, InterruptedError):
            raise
        except OSError as error:
            self._count_os_error(error)
            return False

        if isinstance(item, (bytes, bytearray, memoryview)):
            __debug__ and log("tx-ring", f"<B><lr>[TX]</> - sent raw frame, {len(item)} bytes")
        else:
            __debug__ and log(
                "tx-ring",
                f"<B><lr>[TX]</> {item.tracker}<y>"
                f"{item.tracker.latency}</> - sent frame, "
                f"{len(item)} bytes",
            )
        return True

    def enqueue_raw_frame(self, frame: Buffer, /) -> None:
        """
        Enqueue a verbatim pre-built link-layer frame for transmission —
        the AF_PACKET (SOCK_RAW) egress primitive. Unlike 'enqueue',
        which takes an Assembler the drain serializes, this puts the
        finished frame bytes straight on the ring; the drain writes
        them as-is, skipping the IP / assembler layers. Same full-queue
        drop and 'tx_bytes' accounting as 'enqueue'.
        """

        if len(self._tx_deque) >= self._queue_max_size:
            if self._packet_stats is not None:
                self._packet_stats.tx_ring__queue_full__drop += 1
            else:
                self._queue_full_drop_count += 1
            __debug__ and log("tx-ring", "TX Queue is full, dropping raw frame")
            return

        self._tx_deque.append(frame)
        self._schedule_drain()

        if self._link_stats is not None:
            self._link_stats.tx_bytes += len(frame)

        __debug__ and log("tx-ring", f"TX Queue len: {len(self._tx_deque)}")

    def enqueue(
        self,
        packet_tx: TxFrame,
    ) -> None:
        """
        Enqueue a fully-built outbound frame into the TX Ring. On a
        full deque the frame is dropped; the drop counter increments
        so monitors can spot saturation.
        """

        if len(self._tx_deque) >= self._queue_max_size:
            if self._packet_stats is not None:
                self._packet_stats.tx_ring__queue_full__drop += 1
            else:
                self._queue_full_drop_count += 1
            __debug__ and log(
                "tx-ring",
                f"{packet_tx.tracker} - TX Queue is full, dropping packet",
            )
            return

        self._tx_deque.append(packet_tx)
        self._schedule_drain()

        # Link API tx_bytes: count wire-level frame bytes enqueued
        # for transmission regardless of whether the kernel write
        # ultimately succeeds. Matches Linux 'ifOutOctets' / 'ip
        # -s link show' TX semantics (frames counted at the qdisc
        # boundary, not at the device-write boundary).
        if self._link_stats is not None:
            self._link_stats.tx_bytes += len(packet_tx)

        __debug__ and log(
            "tx-ring",
            f"{packet_tx.tracker} - TX Queue len: {len(self._tx_deque)}",
        )
