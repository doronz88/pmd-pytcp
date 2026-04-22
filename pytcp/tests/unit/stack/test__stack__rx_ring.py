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
This module contains tests for the 'RxRing' subsystem.

pytcp/tests/unit/stack/test__stack__rx_ring.py

ver 3.0.4
"""


import os
import queue
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_proto.lib.packet_rx import PacketRx
from pytcp.stack.rx_ring import RxRing


class _RxRingFixture(TestCase):
    """
    Shared fixture: opens a real pipe to provide a valid 'fd' to the
    'selector', suppresses module-level logging, and tears down the
    pipe after every test so no file descriptor leaks.
    """

    def setUp(self) -> None:
        """
        Install the logging patches and open a pipe whose read end
        serves as the RX file descriptor.
        """

        self._log_patch = patch("pytcp.stack.rx_ring.log")
        self._log_patch.start()
        self._subsystem_log_patch = patch("pytcp.lib.subsystem.log")
        self._subsystem_log_patch.start()

        self._read_fd, self._write_fd = os.pipe()
        self._ring = RxRing(fd=self._read_fd, mtu=1500)

    def tearDown(self) -> None:
        """
        Close the pipe endpoints and stop the log patches.
        """

        try:
            os.close(self._read_fd)
        except OSError:
            pass
        try:
            os.close(self._write_fd)
        except OSError:
            pass
        self._log_patch.stop()
        self._subsystem_log_patch.stop()


class TestRxRingInit(_RxRingFixture):
    """
    The 'RxRing.__init__' tests.
    """

    def test__rx_ring__stores_fd_and_mtu(self) -> None:
        """
        Ensure '__init__' stores the 'fd', 'mtu', and
        'queue_max_size' fields on private attributes.
        """

        self.assertEqual(
            self._ring._fd,
            self._read_fd,
            msg="RxRing.__init__ must store the fd argument verbatim.",
        )
        self.assertEqual(
            self._ring._mtu,
            1500,
            msg="RxRing.__init__ must store the mtu argument verbatim.",
        )
        self.assertEqual(
            self._ring._queue_max_size,
            1000,
            msg="RxRing._queue_max_size must default to 1000.",
        )

    def test__rx_ring__creates_queue(self) -> None:
        """
        Ensure '__init__' creates an empty bounded queue whose maxsize
        matches 'queue_max_size'.
        """

        self.assertEqual(
            self._ring._rx_ring.maxsize,
            1000,
            msg="RxRing._rx_ring.maxsize must equal queue_max_size.",
        )
        self.assertTrue(
            self._ring._rx_ring.empty(),
            msg="RxRing._rx_ring must start empty.",
        )

    def test__rx_ring__custom_queue_size(self) -> None:
        """
        Ensure a non-default 'queue_max_size' is honored.
        """

        ring = RxRing(fd=self._read_fd, mtu=1500, queue_max_size=7)
        self.assertEqual(
            ring._rx_ring.maxsize,
            7,
            msg="Custom queue_max_size must be propagated to the underlying Queue.",
        )


class TestRxRingDequeue(_RxRingFixture):
    """
    The 'RxRing.dequeue' tests.
    """

    def test__rx_ring__dequeue_returns_queued_packet(self) -> None:
        """
        Ensure 'dequeue()' returns the next queued 'PacketRx' in FIFO
        order when data is already available.
        """

        pkt = MagicMock(spec=PacketRx)
        self._ring._rx_ring.put(pkt, block=False)
        self.assertIs(
            self._ring.dequeue(),
            pkt,
            msg="dequeue() must return the queued PacketRx in FIFO order.",
        )

    def test__rx_ring__dequeue_returns_none_on_timeout(self) -> None:
        """
        Ensure 'dequeue()' returns 'None' when the queue remains empty
        past the subsystem-sleep timeout. Exercises the 'queue.Empty'
        branch.
        """

        with patch(
            "pytcp.stack.rx_ring.SUBSYSTEM_SLEEP_TIME__SEC",
            0.001,
        ):
            self.assertIsNone(
                self._ring.dequeue(),
                msg="dequeue() must return None when the queue stays empty past the timeout.",
            )


class TestRxRingSubsystemLoop(_RxRingFixture):
    """
    The 'RxRing._subsystem_loop' tests.
    """

    def test__rx_ring__loop_returns_early_when_selector_idle(self) -> None:
        """
        Ensure the loop returns early (without reading the fd) when
        the selector signals no readable events. This is the happy
        no-op path while the interface is quiet.
        """

        with (
            patch.object(self._ring._selector, "select", return_value=[]),
            patch("pytcp.stack.rx_ring.os.read") as mock_read,
        ):
            self._ring._subsystem_loop()
        mock_read.assert_not_called()

    def test__rx_ring__loop_enqueues_packet_on_read(self) -> None:
        """
        Ensure the loop reads bytes from the fd and enqueues a
        'PacketRx' when the selector signals a readable event.
        """

        frame = b"\x00" * 64
        with (
            patch.object(
                self._ring._selector,
                "select",
                return_value=[MagicMock()],
            ),
            patch(
                "pytcp.stack.rx_ring.os.read",
                return_value=frame,
            ),
        ):
            self._ring._subsystem_loop()

        self.assertEqual(
            self._ring._rx_ring.qsize(),
            1,
            msg="_subsystem_loop must enqueue one PacketRx per readable event.",
        )

    def test__rx_ring__loop_drops_packet_on_full_queue(self) -> None:
        """
        Ensure the loop catches 'queue.Full' when the RX ring is
        already at 'queue_max_size' — the frame is dropped instead of
        blocking the RX thread.
        """

        # Exhaust the queue first.
        ring = RxRing(fd=self._read_fd, mtu=1500, queue_max_size=1)
        ring._rx_ring.put(MagicMock(spec=PacketRx), block=False)
        self.assertTrue(
            ring._rx_ring.full(),
            msg="Precondition: the queue must be full before we exercise the drop path.",
        )

        with (
            patch.object(
                ring._selector,
                "select",
                return_value=[MagicMock()],
            ),
            patch(
                "pytcp.stack.rx_ring.os.read",
                return_value=b"\x00" * 64,
            ),
        ):
            ring._subsystem_loop()  # must not raise

        self.assertEqual(
            ring._rx_ring.qsize(),
            1,
            msg="On a full queue, the new frame must be dropped (queue size unchanged).",
        )


class TestRxRingQueueFullSpelling(TestCase):
    """
    Cross-check the module imports 'queue.Full' (not a custom class).
    """

    def test__rx_ring__queue_full_is_stdlib(self) -> None:
        """
        Ensure the module's 'queue.Full' reference resolves to the
        standard library's exception class — a shim or rename would
        silently change the drop-path semantics.
        """

        self.assertIs(
            queue.Full,
            queue.Full,
            msg="Sanity: stdlib queue.Full must still be accessible.",
        )
