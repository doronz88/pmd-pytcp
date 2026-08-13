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
This module contains the out-of-order-queue hygiene integration
tests: entries the exact-key consume path can never reach (their
seq fell below RCV.NXT when a re-segmented retransmission covered
several queued entries in one segment) must be purged — a stranded
entry pins its full packet buffer for the session's remaining life
AND keeps being emitted as a SACK block entirely below the peer's
SND.UNA, which RFC 2883-aware peers parse as DSACK (a spurious-
retransmit signal that can wrongly undo their cwnd reductions).
The queue must also be bounded: a hostile peer streaming disjoint
1-byte out-of-order segments could otherwise pin one full packet
buffer per in-window byte.

pmd_pytcp/tests/integration/protocols/tcp/test__tcp__session__ooo_queue_hygiene.py

ver 3.0.7
"""

from __future__ import annotations

from pmd_net_addr import Ip4Address
from pmd_pytcp.protocols.tcp import tcp__constants
from pmd_pytcp.protocols.tcp.session import TcpSession
from pmd_pytcp.protocols.tcp.tcp__seq import ge32
from pmd_pytcp.tests.lib.network_testcase import (
    HOST_A__IP4_ADDRESS,
    STACK__IP4_HOST,
)
from pmd_pytcp.tests.lib.tcp_segment_factory import build_tcp4
from pmd_pytcp.tests.lib.tcp_testcase import TcpTestCase

# Deterministic addressing.
STACK__IP: Ip4Address = STACK__IP4_HOST.address
STACK__PORT: int = 12345
PEER__IP: Ip4Address = HOST_A__IP4_ADDRESS
PEER__PORT: int = 80

# Initial sequence numbers chosen well clear of the 32-bit wrap.
LOCAL__ISS: int = 0x0000_1000
PEER__ISS: int = 0x0000_2000

# Peer's advertised receive window.
PEER__WIN: int = 64240


class TestTcpOooQueueHygiene(TcpTestCase):
    """
    The out-of-order-queue hygiene integration tests.
    """

    def _establish_with_sack(self) -> TcpSession:
        return self._drive_handshake_to_established(
            iss=LOCAL__ISS,
            peer_iss=PEER__ISS,
            peer_sackperm=True,
        )

    def _peer_data(self, *, offset: int, data: bytes) -> bytes:
        """
        Build a peer data segment at 'PEER__ISS + 1 + offset'.
        """

        return build_tcp4(
            sport=PEER__PORT,
            dport=STACK__PORT,
            seq=PEER__ISS + 1 + offset,
            ack=LOCAL__ISS + 1,
            flags=("ACK",),
            win=PEER__WIN,
            payload=data,
        )

    def test__ooo__resegmented_retransmission_purges_covered_entries(self) -> None:
        """
        Ensure entries whose seq fell below RCV.NXT are purged:
        two out-of-order segments are queued behind a gap, then
        the peer's retransmission arrives RE-SEGMENTED as one
        segment covering the gap AND both queued ranges. RCV.NXT
        jumps past the queued keys, the exact-key consume path
        can never pop them again, and without the purge they pin
        their packet buffers until session close while polluting
        every outbound SACK.

        Reference: RFC 9293 §3.10.7.4 (text above RCV.NXT is already consumed);
        RFC 2018 §4 (SACK blocks must be above the cumulative ACK point).
        """

        session = self._establish_with_sack()

        # Gap at [0,100); queue two OOO segments behind it.
        self._drive_rx(frame=self._peer_data(offset=100, data=b"b" * 50))
        self._drive_rx(frame=self._peer_data(offset=200, data=b"c" * 50))
        self.assertEqual(
            len(session._ooo_packet_queue),
            2,
            msg="Test precondition: both out-of-order segments must be queued.",
        )

        # The peer retransmits everything as ONE 300-byte segment
        # covering the gap and both queued ranges.
        self._drive_rx(frame=self._peer_data(offset=0, data=b"a" * 300))

        self.assertEqual(
            session._ooo_packet_queue,
            {},
            msg="Entries covered by the re-segmented retransmission must be purged.",
        )

    def test__ooo__no_sack_block_below_rcv_nxt(self) -> None:
        """
        Ensure outbound SACK never advertises a block below
        RCV.NXT: after the re-segmented consume, a fresh
        out-of-order arrival triggers a dup-ACK whose SACK
        blocks must all sit above the cumulative point — a
        below-SND.UNA block is indistinguishable from a DSACK
        to the peer (RFC 2883 §4).

        Reference: RFC 2018 §4; RFC 2883 §4.
        """

        session = self._establish_with_sack()

        self._drive_rx(frame=self._peer_data(offset=100, data=b"b" * 50))
        self._drive_rx(frame=self._peer_data(offset=0, data=b"a" * 300))
        assert session._rcv_seq.nxt == PEER__ISS + 1 + 300

        # A fresh gap + OOO arrival elicits an immediate dup-ACK.
        frames = self._drive_rx(frame=self._peer_data(offset=400, data=b"d" * 50))
        dup_acks = [probe for probe in map(self._parse_tx, frames) if probe.sack_blocks]
        self.assertTrue(dup_acks, msg="An out-of-order arrival must elicit a SACK-bearing dup-ACK.")
        for probe in dup_acks:
            for left, _right in probe.sack_blocks:
                self.assertTrue(
                    ge32(left, PEER__ISS + 1 + 300),
                    msg=f"SACK block left edge {left:#x} must not sit below RCV.NXT: {probe!r}",
                )

    def test__ooo__queue_is_bounded(self) -> None:
        """
        Ensure the out-of-order queue cannot grow past its cap: a
        peer streaming disjoint 1-byte out-of-order segments
        would otherwise pin one full packet buffer per in-window
        byte (~64k buffers per session at the default window).
        Segments beyond the cap are dropped — the dup-ACK still
        goes out and the peer retransmits them later.

        Reference: Linux 'tcp_prune_ofo_queue' (the out-of-order queue is bounded by rcvbuf).
        """

        session = self._establish_with_sack()

        for i in range(tcp__constants.TCP__OOO_QUEUE__MAX_LEN + 10):
            self._drive_rx(frame=self._peer_data(offset=100 + 2 * i, data=b"x"))

        self.assertLessEqual(
            len(session._ooo_packet_queue),
            tcp__constants.TCP__OOO_QUEUE__MAX_LEN,
            msg="The out-of-order queue must not grow past its cap.",
        )
