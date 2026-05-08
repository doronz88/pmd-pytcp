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
This module contains tests for the 'TxRing' subsystem.

pytcp/tests/unit/stack/test__stack__tx_ring.py

ver 3.0.4
"""

import os
from unittest import TestCase
from unittest.mock import MagicMock, patch

from net_proto import (
    Ethernet8023Assembler,
    EthernetAssembler,
    Ip4Assembler,
    Ip4FragAssembler,
    Ip6Assembler,
)
from pytcp.stack.tx_ring import TxRing


class _TxRingFixture(TestCase):
    """
    Shared fixture that opens a pipe (the read end stands in for the
    TX file descriptor in tests of enqueue-only behavior) and
    suppresses module-level logging.
    """

    def setUp(self) -> None:
        """
        Install the logging patches and open the pipe.
        """

        self._log_patch = patch("pytcp.stack.tx_ring.log")
        self._log_patch.start()
        self._subsystem_log_patch = patch("pytcp.lib.subsystem.log")
        self._subsystem_log_patch.start()

        self._read_fd, self._write_fd = os.pipe()
        self._ring = TxRing(fd=self._write_fd, mtu=1500)

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


class TestTxRingInit(_TxRingFixture):
    """
    The 'TxRing.__init__' tests.
    """

    def test__tx_ring__stores_fd_mtu_queue_size(self) -> None:
        """
        Ensure '__init__' stores the 'fd', 'mtu', and
        'queue_max_size' fields on private attributes.
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

    def test__tx_ring__creates_empty_queue(self) -> None:
        """
        Ensure '__init__' creates a bounded queue whose maxsize
        matches 'queue_max_size' and starts empty.
        """

        self.assertEqual(
            self._ring._tx_ring.maxsize,
            1000,
            msg="TxRing._tx_ring.maxsize must equal queue_max_size.",
        )
        self.assertTrue(
            self._ring._tx_ring.empty(),
            msg="TxRing._tx_ring must start empty.",
        )


class TestTxRingEnqueue(_TxRingFixture):
    """
    The 'TxRing.enqueue' tests.
    """

    def test__tx_ring__enqueue_appends_packet(self) -> None:
        """
        Ensure enqueue() puts the packet on the internal queue.
        """

        pkt = MagicMock(spec=EthernetAssembler)
        self._ring.enqueue(pkt)
        self.assertEqual(
            self._ring._tx_ring.qsize(),
            1,
            msg="enqueue() must place the packet on the TX ring.",
        )

    def test__tx_ring__enqueue_drops_when_full(self) -> None:
        """
        Ensure enqueue() silently drops the packet when the queue is
        full rather than blocking — dropping an outbound frame is
        preferable to stalling the caller.
        """

        ring = TxRing(fd=self._write_fd, mtu=1500, queue_max_size=1)
        ring._tx_ring.put(MagicMock(spec=EthernetAssembler), block=False)
        ring.enqueue(MagicMock(spec=EthernetAssembler))  # must not raise
        self.assertEqual(
            ring._tx_ring.qsize(),
            1,
            msg="enqueue() on a full TX ring must drop the new packet (size unchanged).",
        )


class TestTxRingSubsystemLoop(_TxRingFixture):
    """
    The 'TxRing._subsystem_loop' tests.
    """

    def test__tx_ring__loop_returns_early_when_queue_empty(self) -> None:
        """
        Ensure the loop returns early on 'queue.Empty' — there is
        nothing to transmit so os.writev() must not be called.
        """

        with (
            patch(
                "pytcp.stack.tx_ring.SUBSYSTEM_SLEEP_TIME__SEC",
                0.001,
            ),
            patch("pytcp.stack.tx_ring.os.writev") as mock_writev,
        ):
            self._ring._subsystem_loop()
        mock_writev.assert_not_called()

    def _make_ethernet(self) -> MagicMock:
        """
        Build a MagicMock that behaves like an 'EthernetAssembler':
        passes 'isinstance(packet, EthernetAssembler)', has __len__,
        and has an 'assemble()' method that appends a stub buffer.
        """

        pkt = MagicMock(spec=EthernetAssembler)
        pkt.__len__.return_value = 64

        def assemble(buffers: list) -> None:
            buffers.append(b"x" * 64)

        pkt.assemble.side_effect = assemble
        return pkt

    def test__tx_ring__loop_writes_ethernet_frame(self) -> None:
        """
        Ensure the loop builds the buffer list for an
        'EthernetAssembler' packet and writes it to the fd via
        'os.writev'. The Ethernet branch uses an empty initial buffer
        list and adds Ethernet-header overhead to the MTU check.
        """

        pkt = self._make_ethernet()
        self._ring._tx_ring.put(pkt, block=False)

        with patch("pytcp.stack.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        mock_writev.assert_called_once()
        fd_arg, buffers_arg = mock_writev.call_args.args
        self.assertEqual(
            fd_arg,
            self._write_fd,
            msg="os.writev must be called with the TX ring fd.",
        )
        self.assertEqual(
            buffers_arg,
            [b"x" * 64],
            msg="os.writev must be called with the assembled buffer list.",
        )

    def test__tx_ring__loop_ip6_uses_ipv6_ethertype_prefix(self) -> None:
        """
        Ensure the loop prepends the IPv6 EtherType prefix
        (b'\\x00\\x00\\x86\\xdd') to the buffer list for an
        'Ip6Assembler' packet.
        """

        pkt = MagicMock(spec=Ip6Assembler)
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"p6")

        self._ring._tx_ring.put(pkt, block=False)

        with patch("pytcp.stack.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        buffers_arg = mock_writev.call_args.args[1]
        self.assertEqual(
            buffers_arg[0],
            b"\x00\x00\x86\xdd",
            msg="The Ip6Assembler branch must prepend the IPv6 EtherType prefix.",
        )

    def test__tx_ring__loop_ip4_uses_ipv4_ethertype_prefix(self) -> None:
        """
        Ensure the loop prepends the IPv4 EtherType prefix
        (b'\\x00\\x00\\x08\\x00') to the buffer list for an
        'Ip4Assembler' packet.
        """

        pkt = MagicMock(spec=Ip4Assembler)
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"p4")

        self._ring._tx_ring.put(pkt, block=False)

        with patch("pytcp.stack.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        buffers_arg = mock_writev.call_args.args[1]
        self.assertEqual(
            buffers_arg[0],
            b"\x00\x00\x08\x00",
            msg="The Ip4Assembler branch must prepend the IPv4 EtherType prefix.",
        )

    def test__tx_ring__loop_ip4_frag_uses_ipv4_prefix(self) -> None:
        """
        Ensure 'Ip4FragAssembler' packets also receive the IPv4
        EtherType prefix — they share a branch with 'Ip4Assembler'.
        """

        pkt = MagicMock(spec=Ip4FragAssembler)
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"frag")

        self._ring._tx_ring.put(pkt, block=False)

        with patch("pytcp.stack.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        buffers_arg = mock_writev.call_args.args[1]
        self.assertEqual(
            buffers_arg[0],
            b"\x00\x00\x08\x00",
            msg="The Ip4FragAssembler branch must share the IPv4 EtherType prefix.",
        )

    def test__tx_ring__loop_eth802_3_branch_writes(self) -> None:
        """
        Ensure 'Ethernet8023Assembler' packets exercise the
        corresponding MTU branch and get written out — the test only
        verifies the dispatch, not the 802.3 framing internals.
        """

        pkt = MagicMock(spec=Ethernet8023Assembler)
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"z")

        self._ring._tx_ring.put(pkt, block=False)

        with patch("pytcp.stack.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        mock_writev.assert_called_once()

    def test__tx_ring__loop_drops_oversized_frame(self) -> None:
        """
        Ensure the loop drops a frame whose length exceeds the MTU
        (plus Ethernet header overhead) without calling os.writev.
        """

        pkt = self._make_ethernet()
        pkt.__len__.return_value = 65535  # way bigger than MTU + 14

        self._ring._tx_ring.put(pkt, block=False)

        with patch("pytcp.stack.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        mock_writev.assert_not_called()

    def test__tx_ring__loop_swallows_oserror(self) -> None:
        """
        Ensure an 'OSError' from 'os.writev' is caught so the TX
        thread does not crash on transient interface errors.
        """

        pkt = self._make_ethernet()
        self._ring._tx_ring.put(pkt, block=False)

        with patch(
            "pytcp.stack.tx_ring.os.writev",
            side_effect=OSError("no buffer space"),
        ):
            self._ring._subsystem_loop()  # must not propagate the error

    def test__tx_ring__loop_unknown_packet_type_dropped(self) -> None:
        """
        Ensure packets of an unexpected type (not one of the five
        accepted assemblers) are logged and dropped — os.writev must
        not be called.
        """

        pkt = MagicMock()  # plain MagicMock, no spec -> unknown type
        pkt.__len__.return_value = 64
        pkt.assemble.side_effect = lambda buffers: buffers.append(b"x")

        self._ring._tx_ring.put(pkt, block=False)

        with patch("pytcp.stack.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        mock_writev.assert_not_called()


class TestTxRingInnerDrain(_TxRingFixture):
    """
    The 'TxRing._subsystem_loop' inner-drain tests.
    """

    def _make_ethernet(self) -> MagicMock:
        """
        Build a MagicMock 'EthernetAssembler' for queue insertion.
        """

        pkt = MagicMock(spec=EthernetAssembler)
        pkt.__len__.return_value = 64

        def assemble(buffers: list) -> None:
            buffers.append(b"x" * 64)

        pkt.assemble.side_effect = assemble
        return pkt

    def test__tx_ring__loop_drains_all_pending_packets_per_get_wake(self) -> None:
        """
        Ensure a single '_subsystem_loop' invocation drains every
        packet currently in the TX ring queue, not just one. The
        inner-drain pattern mirrors the RX-side optimisation: the
        outer 'queue.get(block=True, timeout=0.1)' is the slow path;
        once awoken, the worker should drain the rest of the queue
        via cheap 'queue.get(block=False)' calls until the queue
        is empty, then yield back to the Subsystem driver.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        n_frames = 10
        for _ in range(n_frames):
            self._ring._tx_ring.put(self._make_ethernet(), block=False)

        with patch("pytcp.stack.tx_ring.os.writev") as mock_writev:
            self._ring._subsystem_loop()

        self.assertEqual(
            mock_writev.call_count,
            n_frames,
            msg=(
                f"A single _subsystem_loop call must drain all {n_frames} "
                f"queued packets in one pass. Got {mock_writev.call_count} "
                f"os.writev calls."
            ),
        )
        self.assertTrue(
            self._ring._tx_ring.empty(),
            msg="After the inner drain the queue must be empty.",
        )

    def test__tx_ring__loop_inner_drain_breaks_on_writev_oserror(self) -> None:
        """
        Ensure the inner-drain loop stops on the first 'os.writev'
        OSError. Repeatedly retrying when the interface is down /
        ENOBUFS would only burn cycles — better to yield and let
        the next outer-loop iteration check the stop event.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        for _ in range(5):
            self._ring._tx_ring.put(self._make_ethernet(), block=False)

        with patch(
            "pytcp.stack.tx_ring.os.writev",
            side_effect=OSError("link down"),
        ) as mock_writev:
            self._ring._subsystem_loop()

        # First writev errors → break. No further writev calls,
        # but exactly one drop counted.
        self.assertEqual(
            mock_writev.call_count,
            1,
            msg=(
                "Inner drain must break after the first writev OSError. "
                f"Expected 1 writev call; got {mock_writev.call_count}."
            ),
        )
        self.assertEqual(
            self._ring.os_error_drop_count,
            1,
            msg="Exactly one drop should be counted before the drain breaks.",
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
        ring._tx_ring.put(MagicMock(spec=EthernetAssembler), block=False)

        ring.enqueue(MagicMock(spec=EthernetAssembler))
        ring.enqueue(MagicMock(spec=EthernetAssembler))
        ring.enqueue(MagicMock(spec=EthernetAssembler))

        self.assertEqual(
            ring.queue_full_drop_count,
            3,
            msg="Each full-queue drop must bump 'queue_full_drop_count' by exactly one.",
        )

    def test__tx_ring__loop_increments_os_error_drop_count(self) -> None:
        """
        Ensure 'os_error_drop_count' bumps each time 'os.writev'
        raises 'OSError' (interface down, ENOBUFS, etc.). Without
        the counter, link-down conditions silently lose every
        outbound packet.

        Reference: PyTCP test infrastructure (no RFC clause).
        """

        def _make_pkt() -> MagicMock:
            pkt = MagicMock(spec=EthernetAssembler)
            pkt.__len__.return_value = 64
            pkt.assemble.side_effect = lambda buffers: buffers.append(b"x" * 64)
            return pkt

        for _ in range(2):
            self._ring._tx_ring.put(_make_pkt(), block=False)

        with patch(
            "pytcp.stack.tx_ring.os.writev",
            side_effect=OSError("link down"),
        ):
            self._ring._subsystem_loop()
            self._ring._subsystem_loop()

        self.assertEqual(
            self._ring.os_error_drop_count,
            2,
            msg="Each os.writev OSError must bump 'os_error_drop_count' by exactly one.",
        )
