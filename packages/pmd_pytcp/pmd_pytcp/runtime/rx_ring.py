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
This module contains class supporting stack RX Ring operations.

pmd_pytcp/runtime/rx_ring.py

ver 3.0.7
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable

from pmd_net_proto.lib.packet_rx import PacketRx
from pmd_pytcp.lib import io_backend
from pmd_pytcp.lib.logger import log
from pmd_pytcp.lib.packet_stats import LinkStatsCounters, PacketStatsRx

# Per-read kernel-buffer headroom over the configured L3 MTU. Sized
# to accommodate the largest L2 framing PyTCP supports plus slack:
#   14 bytes Ethernet II header
#  +  4 bytes 802.1Q VLAN tag (future-proofing — not parsed today)
#  +  4 bytes BSD TUN protocol-family prefix
#  +  ~40 bytes slack
# A buffer of 'mtu + RX_RING__READ_HEADROOM' fits any frame the
# kernel can hand us, including jumbo-Ethernet (MTU 9000) and IPv6
# jumbograms per RFC 2675 / RFC 9293 §3.7.5.
RX_RING__READ_HEADROOM: int = 64


class RxRing:
    """
    Support for receiving packets from the network.

    Pure-asyncio ingress ('docs/refactor/pure_asyncio.md'): the fd
    is registered with 'loop.add_reader' and every readiness
    callback burst-drains the kernel buffer, delivering each parsed
    'PacketRx' synchronously to the deliver callback the packet
    handler installs. There is no rx queue, no eventfd and no
    worker — the whole rx→parse→FSM→tx pipeline runs inline on the
    loop callback. On the socket-I/O path (Windows /
    'PYTCP_FORCE_SOCK_IO', where proactor loops lack 'add_reader'
    for arbitrary fds) a reader task drives 'loop.sock_recv'
    instead.
    """

    _subsystem_name = "RX Ring"

    _fd: int
    _mtu: int
    _burst_max: int

    _deliver: "Callable[[PacketRx], None] | None"
    _loop: asyncio.AbstractEventLoop | None
    _reader_task: "asyncio.Task[None] | None"
    _reader_armed: bool
    _no_deliver_drop_count: int
    _os_error_drop_count: int
    _packet_stats: PacketStatsRx | None
    _link_stats: LinkStatsCounters | None

    def __init__(
        self,
        *,
        fd: int,
        mtu: int,
        queue_max_size: int = 1000,
        packet_stats: PacketStatsRx | None = None,
        link_stats: LinkStatsCounters | None = None,
    ) -> None:
        """
        Initialize access to the RX file descriptor. The former
        'queue_max_size' now bounds the per-readiness-callback
        drain burst so one hot interface cannot starve the loop.
        """

        self._fd = fd
        self._mtu = mtu
        self._burst_max = queue_max_size

        __debug__ and log(
            "stack",
            f"Initializing {self._subsystem_name} [fd={fd}, mtu={mtu}, burst_max={queue_max_size}]",
        )

        self._deliver = None
        self._loop = None
        self._reader_task = None
        self._reader_armed = False
        self._no_deliver_drop_count = 0
        self._os_error_drop_count = 0
        # Optional shared 'PacketStatsRx' object — when set, ring
        # drop counters live as fields on the shared stats instead
        # of on the ring's private ints, so unified-stats consumers
        # see ring drops alongside per-protocol drops in one
        # dataclass. Ring properties below transparently dispatch
        # to whichever source is authoritative.
        self._packet_stats = packet_stats
        # Optional shared 'LinkStatsCounters' object — when set,
        # 'rx_bytes' is bumped here per successful read. The
        # PacketHandler owns the canonical instance; sharing it
        # mirrors the 'packet_stats' pattern above and gives the
        # Link API a single source of truth for 'stats.rx_bytes'.
        self._link_stats = link_stats

    def set_deliver_callback(self, deliver: "Callable[[PacketRx], None] | None", /) -> None:
        """
        Install the per-frame deliver callback (the packet
        handler's rx entry point). Frames read while no callback
        is installed are dropped and counted.
        """

        self._deliver = deliver

    @property
    def queue_full_drop_count(self) -> int:
        """
        Get the cumulative count of inbound frames dropped because
        no deliver callback was installed (the queue-full slot of
        the threaded design; kept under the same name so
        unified-stats consumers keep their field). Sources from the
        shared 'PacketStatsRx' field when wired, falls back to the
        internal counter otherwise.
        """

        if self._packet_stats is not None:
            return self._packet_stats.rx_ring__queue_full__drop
        return self._no_deliver_drop_count

    @property
    def os_error_drop_count(self) -> int:
        """
        Get the cumulative count of inbound frames dropped because
        the read raised 'OSError' (transient kernel errors: EINTR
        on signal, EBADF on shutdown race, EIO on hardware glitches,
        ENOMEM on tight memory). Without the counter, these errors
        would silently disarm the RX ingress.
        """

        if self._packet_stats is not None:
            return self._packet_stats.rx_ring__os_error__drop
        return self._os_error_drop_count

    def start(self) -> None:
        """
        Arm the ingress on the running event loop: 'add_reader' on
        the fd path, a 'sock_recv' reader task on the socket-I/O
        path.
        """

        __debug__ and log("stack", f"Starting {self._subsystem_name}")

        self._loop = asyncio.get_running_loop()

        sock = io_backend.sock_for_fd(self._fd)
        if sock is not None:
            sock.setblocking(False)
            self._reader_task = self._loop.create_task(self._task__sock_reader(), name=self._subsystem_name)
            return

        io_backend.set_nonblocking(self._fd)
        self._loop.add_reader(self._fd, self._on_readable)
        self._reader_armed = True

    def stop(self) -> None:
        """
        Disarm the ingress. The fd itself belongs to the embedding
        host and is not closed here.
        """

        __debug__ and log("stack", f"Stopping {self._subsystem_name}")

        if self._reader_armed and self._loop is not None:
            try:
                self._loop.remove_reader(self._fd)
            except (OSError, ValueError):
                pass  # fd already closed by the host — nothing to disarm.
            self._reader_armed = False
        if self._reader_task is not None and not self._reader_task.done():
            self._reader_task.cancel()

    def _handle_frame(self, frame: bytes, /) -> None:
        """
        Parse one raw frame and deliver it synchronously to the
        packet handler. A raising handler is logged and swallowed
        so it cannot disarm the ingress.
        """

        packet_rx = PacketRx(frame)

        __debug__ and log(
            "rx-ring",
            f"<B><lg>[RX]</> {packet_rx.tracker} - received frame, " f"{len(packet_rx.frame)} bytes",
        )

        # Link API rx_bytes: count wire-level frame bytes received
        # from the kernel regardless of which protocol consumes
        # them. Bumped here at the canonical RX entry point so both
        # L2 (TAP) and L3 (TUN) paths are covered uniformly.
        if self._link_stats is not None:
            self._link_stats.rx_bytes += len(packet_rx.frame)

        if self._deliver is None:
            if self._packet_stats is not None:
                self._packet_stats.rx_ring__queue_full__drop += 1
            else:
                self._no_deliver_drop_count += 1
            __debug__ and log(
                "rx-ring",
                f"{packet_rx.tracker} - no deliver callback installed, dropping packet",
            )
            return

        try:
            self._deliver(packet_rx)
        except Exception as error:  # pylint: disable=broad-exception-caught
            __debug__ and log(
                "rx-ring",
                f"<CRIT>Deliver callback raised: {error!r}</>",
            )

    def _count_os_error(self, error: OSError, /) -> None:
        """
        Count a transient read 'OSError' (EINTR / EBADF on shutdown
        race / EIO / ENOMEM).
        """

        if self._packet_stats is not None:
            self._packet_stats.rx_ring__os_error__drop += 1
        else:
            self._os_error_drop_count += 1
        __debug__ and log(
            "rx-ring",
            f"<CRIT>RX read failed, OSError: {error}</>",
        )

    def _on_readable(self) -> None:
        """
        Readiness callback: burst-drain the kernel buffer up to
        '_burst_max' frames so one wake-up amortises across the
        whole pending burst without starving the rest of the loop.
        """

        for _ in range(self._burst_max):
            try:
                frame = io_backend.read(self._fd, self._mtu + RX_RING__READ_HEADROOM)
            except (BlockingIOError, InterruptedError):
                return  # kernel buffer drained.
            except OSError as error:
                self._count_os_error(error)
                return
            self._handle_frame(frame)

    async def _task__sock_reader(self) -> None:
        """
        Socket-I/O-path reader: 'loop.sock_recv' works on both
        selector and proactor loops, covering Windows where
        'add_reader' cannot take an arbitrary fd.
        """

        assert self._loop is not None
        sock = io_backend.sock_for_fd(self._fd)
        assert sock is not None

        while True:
            try:
                frame = await self._loop.sock_recv(sock, self._mtu + RX_RING__READ_HEADROOM)
            except asyncio.CancelledError:
                return
            except OSError as error:
                self._count_os_error(error)
                # EBADF and friends during teardown — bail out; a
                # transient error would recur immediately anyway,
                # so yield a beat before retrying.
                await asyncio.sleep(0.1)
                continue
            self._handle_frame(frame)
