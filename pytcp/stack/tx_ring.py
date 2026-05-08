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

pytcp/stack/tx_ring.py

ver 3.0.3
"""

import os
import queue
from typing import override

from net_proto import (
    Ethernet8023Assembler,
    EthernetAssembler,
    Ip4Assembler,
    Ip4FragAssembler,
    Ip6Assembler,
)
from net_proto.lib.buffer import Buffer
from net_proto.protocols.ethernet.ethernet__header import ETHERNET__HEADER__LEN
from net_proto.protocols.ethernet_802_3.ethernet_802_3__header import (
    ETHERNET_802_3__HEADER__LEN,
)
from pytcp.lib.logger import log
from pytcp.lib.subsystem import SUBSYSTEM_SLEEP_TIME__SEC, Subsystem


class TxRing(Subsystem):
    """
    Support for sending packets to the network.
    """

    _subsystem_name = "TX Ring"

    _fd: int
    _mtu: int
    _queue_max_size: int

    _tx_ring: queue.Queue[EthernetAssembler | Ethernet8023Assembler | Ip6Assembler | Ip4Assembler | Ip4FragAssembler]
    _queue_full_drop_count: int
    _os_error_drop_count: int

    @override
    def __init__(self, *, fd: int, mtu: int, queue_max_size: int = 1000) -> None:
        """
        Initialize access to TX file descriptor and the outbound queue.
        """

        self._fd = fd
        self._mtu = mtu
        self._queue_max_size = queue_max_size

        super().__init__(info=f"fd={fd}, mtu={mtu}, queue_max_size={queue_max_size}")

        self._tx_ring = queue.Queue(maxsize=queue_max_size)
        self._queue_full_drop_count = 0
        self._os_error_drop_count = 0

    @property
    def queue_full_drop_count(self) -> int:
        """
        Get the cumulative count of outbound packets dropped because
        the TX ring was at capacity at 'enqueue' time. A non-zero
        rate signals the producer (the packet handler) is generating
        packets faster than 'os.writev' can drain them.
        """

        return self._queue_full_drop_count

    @property
    def os_error_drop_count(self) -> int:
        """
        Get the cumulative count of outbound packets dropped because
        'os.writev' raised 'OSError' (typically ENOBUFS, ENETDOWN,
        EIO on link failure). A non-zero rate signals interface
        trouble the application would otherwise have no visibility
        into.
        """

        return self._os_error_drop_count

    @override
    def _subsystem_loop(self) -> None:
        """
        Dequeue packets from TX Ring and put them on the wire. After
        the outer 'queue.get(block=True, timeout=...)' wakes, drain
        every additional packet currently queued via cheap
        non-blocking 'queue.get(block=False)' calls in an inner loop
        — the outer-loop overhead (Subsystem driver dispatch,
        blocking queue.get setup) amortises across the whole burst
        instead of one packet per outer cycle.
        """

        try:
            packet_tx = self._tx_ring.get(block=True, timeout=SUBSYSTEM_SLEEP_TIME__SEC)
        except queue.Empty:
            return

        while True:
            if not self._send_one(packet_tx):
                # 'os.writev' errored — stop draining; let the outer
                # loop take a fresh tick so the stop event can be
                # checked and the next pass is a clean restart.
                return

            try:
                packet_tx = self._tx_ring.get(block=False)
            except queue.Empty:
                return

    def _send_one(
        self,
        packet_tx: EthernetAssembler | Ethernet8023Assembler | Ip6Assembler | Ip4Assembler | Ip4FragAssembler,
    ) -> bool:
        """
        Build the wire-buffer list for a single packet and call
        'os.writev'. Returns True on a successful send (including
        the silent oversized-frame and unknown-type drops which
        are non-fatal log-only branches), and False on 'os.writev'
        OSError so the inner drain can break early.
        """

        buffers: list[Buffer]

        if isinstance(packet_tx, EthernetAssembler):
            buffers = []
            mtu = self._mtu + ETHERNET__HEADER__LEN
        elif isinstance(packet_tx, Ethernet8023Assembler):
            buffers = []
            mtu = self._mtu + ETHERNET_802_3__HEADER__LEN
        elif isinstance(packet_tx, Ip6Assembler):
            buffers = [b"\x00\x00\x86\xdd"]
            mtu = self._mtu
        elif isinstance(packet_tx, (Ip4Assembler, Ip4FragAssembler)):
            buffers = [b"\x00\x00\x08\x00"]
            mtu = self._mtu
        else:
            __debug__ and log(
                "tx-ring",
                f"{packet_tx.tracker} - <CRIT>Unknown packet type: " f"{type(packet_tx)!r}</>",
            )
            return True

        if (packet_tx_len := len(packet_tx)) > mtu:
            __debug__ and log(
                "tx-ring",
                f"{packet_tx.tracker} - Unable to send frame, frame" f"len ({packet_tx_len}) > mtu ({mtu})",
            )
            return True

        packet_tx.assemble(buffers)

        try:
            os.writev(self._fd, buffers)
        except OSError as error:
            self._os_error_drop_count += 1
            __debug__ and log(
                "tx-ring",
                f"{packet_tx.tracker} - <CRIT>Unable to send frame, " f"OSError: {error}</>",
            )
            return False

        __debug__ and log(
            "tx-ring",
            f"<B><lr>[TX]</> {packet_tx.tracker}<y>"
            f"{packet_tx.tracker.latency}</> - sent frame, "
            f"{len(packet_tx)} bytes",
        )
        return True

    def enqueue(
        self,
        packet_tx: EthernetAssembler | Ethernet8023Assembler | Ip6Assembler | Ip4Assembler | Ip4FragAssembler,
    ) -> None:
        """
        Enqueue outbound packet into TX Ring.
        """

        try:
            self._tx_ring.put(item=packet_tx, block=False)
        except queue.Full:
            self._queue_full_drop_count += 1
            __debug__ and log(
                "tx-ring",
                f"{packet_tx.tracker} - TX Queue is full, dropping packet",
            )

        __debug__ and log(
            "tx-ring",
            f"{packet_tx.tracker} - TX Queue len: {self._tx_ring.qsize()}",
        )
