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

pytcp/stack/rx_ring.py

ver 3.0.3
"""

import os
import queue
import selectors
from typing import override

from net_proto.lib.packet_rx import PacketRx
from pytcp.lib.logger import log
from pytcp.lib.subsystem import SUBSYSTEM_SLEEP_TIME__SEC, Subsystem

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


class RxRing(Subsystem):
    """
    Support for receiving packets from the network.
    """

    _subsystem_name = "RX Ring"

    _fd: int
    _mtu: int
    _queuse_max_size: int

    _rx_ring: queue.Queue[PacketRx]
    _selector: selectors.DefaultSelector
    _queue_full_drop_count: int

    @override
    def __init__(self, *, fd: int, mtu: int, queue_max_size: int = 1000) -> None:
        """
        Initialize access to RX file descriptor and the inbound queue.
        """

        self._fd = fd
        self._mtu = mtu
        self._queue_max_size = queue_max_size

        super().__init__(info=f"fd={fd}, mtu={mtu}, queue_max_size={queue_max_size}")

        self._rx_ring = queue.Queue(maxsize=queue_max_size)
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._fd, selectors.EVENT_READ)
        self._queue_full_drop_count = 0

    @property
    def queue_full_drop_count(self) -> int:
        """
        Get the cumulative count of inbound frames dropped because
        the RX ring was at capacity. Useful as a saturation signal
        for monitoring — a non-zero rate-of-change indicates the
        consumer is not keeping up with kernel-side packet arrivals.
        """

        return self._queue_full_drop_count

    @override
    def _subsystem_loop(self) -> None:
        """
        Receive and enqueue the incoming packets. After the outer
        'selector.select' wake-up, drain every additional frame the
        kernel TAP / TUN buffer holds via a 'select(timeout=0)'
        inner peek so a single wake-up amortises across the whole
        pending burst — at line rate the kernel queue can hold many
        frames between two selector polls, and reading them one-
        wake-up-at-a-time wastes outer-loop overhead.
        """

        if not self._selector.select(timeout=SUBSYSTEM_SLEEP_TIME__SEC):
            return

        while True:
            packet_rx = PacketRx(os.read(self._fd, self._mtu + RX_RING__READ_HEADROOM))
            __debug__ and log(
                "rx-ring",
                f"<B><lg>[RX]</> {packet_rx.tracker} - received frame, " f"{len(packet_rx.frame)} bytes",
            )

            try:
                self._rx_ring.put(item=packet_rx, block=False)
            except queue.Full:
                self._queue_full_drop_count += 1
                __debug__ and log(
                    "rx-ring",
                    f"{packet_rx.tracker} - RX Queue is full, dropping packet",
                )
                # Stop draining the moment the consumer falls
                # behind — further reads would just keep dropping.
                break

            # Peek for more readable data without blocking. Empty
            # list => kernel buffer drained; exit and let the
            # outer Subsystem driver re-enter on the next wake-up.
            if not self._selector.select(timeout=0):
                break

    @override
    def _stop(self) -> None:
        """
        Release the OS-level epoll/poll/kqueue resource backing the
        'selectors.DefaultSelector' so 'stack.stop()' returns the fd
        to the kernel. Idempotent — the selector's own 'close()' is
        a no-op on an already-closed instance.
        """

        self._selector.close()

    def dequeue(self) -> PacketRx | None:
        """
        Dequeue inbound frame from RX Ring.
        """

        try:
            return self._rx_ring.get(block=True, timeout=SUBSYSTEM_SLEEP_TIME__SEC)
        except queue.Empty:
            return None
