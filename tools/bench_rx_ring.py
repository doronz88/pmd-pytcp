#!/usr/bin/env python3
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
RX-ring synthetic micro-benchmark — drives a SOCK_DGRAM
'socketpair' (preserves message boundaries, mirrors TAP packet
semantics) as the ring's source fd, measures per-frame overhead
and sustained throughput under the pure-asyncio ingress
('docs/refactor/pure_asyncio.md'): the ring is armed with
'loop.add_reader' and delivers each parsed frame synchronously to
the installed deliver callback (there is no rx queue and no
'dequeue()' anymore).

Run:
    PYTHONPATH=. python3.14 -O tools/bench_rx_ring.py

Or under cProfile:
    PYTHONPATH=. python3.14 -O -m cProfile -o /tmp/rx_ring.prof \\
        tools/bench_rx_ring.py
    python3.14 -c "import pstats; pstats.Stats('/tmp/rx_ring.prof'\\
        ).strip_dirs().sort_stats('cumulative').print_stats(40)"

A SOCK_DGRAM pair is the closest userspace-only stand-in for a
real TAP fd: each 'send' produces one boundaried datagram; each
read returns exactly one frame (matching how TAP delivers
packets, not bytes). A plain os.pipe coalesces multiple writes
into one read, which under-represents the burst path that the
readiness-callback burst-drain targets.

tools/bench_rx_ring.py

ver 3.0.7
"""

import argparse
import asyncio
import socket
import sys
import time
from unittest.mock import patch

from pmd_net_proto.lib.packet_rx import PacketRx
from pmd_pytcp.runtime.rx_ring import RxRing


async def _bench(n_frames: int, frame_size: int, prefill: int) -> None:
    """
    Run a single benchmark pass and print per-frame timings. The
    'prefill' parameter sends 'prefill' frames into the SOCK_DGRAM
    pair before the ring starts, simulating a burst that the
    readiness-callback burst-drain can absorb in a single wake.
    """

    frame = b"\x00" * frame_size
    rx_sock, tx_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    # AF_UNIX SOCK_DGRAM caps the receive queue at /proc/sys/net/
    # unix/max_dgram_qlen (typically 512). The bench works around
    # that by feeding from a producer task that runs concurrently
    # with the consumer — pre-fill is bounded by qlen.
    qlen_cap = 256

    # 'queue_max_size' now bounds the per-readiness-callback drain
    # burst (there is no rx queue to size).
    ring = RxRing(fd=rx_sock.fileno(), mtu=1500, queue_max_size=qlen_cap)

    # Deliver callback — the packet handler's slot; here it just
    # counts frames and flags completion.
    drained = 0
    done = asyncio.Event()

    def _deliver(_packet_rx: PacketRx) -> None:
        nonlocal drained
        drained += 1
        if drained >= n_frames:
            done.set()

    ring.set_deliver_callback(_deliver)

    # Bound prefill to the qlen cap so the producer doesn't stall
    # before the ring starts.
    actual_prefill = min(prefill, qlen_cap, n_frames)
    for _ in range(actual_prefill):
        tx_sock.send(frame)

    remaining = n_frames - actual_prefill

    # Producer task streams the rest at producer rate so the ring
    # sees sustained pressure throughout the test ('sock_sendall'
    # yields on a full kernel queue instead of blocking the loop).
    loop = asyncio.get_running_loop()
    tx_sock.setblocking(False)

    async def _producer() -> None:
        try:
            for _ in range(remaining):
                await loop.sock_sendall(tx_sock, frame)
        finally:
            tx_sock.close()

    start = time.perf_counter()
    ring.start()
    producer = loop.create_task(_producer())

    await done.wait()
    elapsed = time.perf_counter() - start

    ring.stop()
    await producer
    try:
        rx_sock.close()
    except OSError:
        pass

    pps = drained / elapsed
    per_frame_us = elapsed / drained * 1e6
    print(f"  Frame size:        {frame_size} bytes")
    print(f"  Pre-burst:         {actual_prefill} frames (capped by AF_UNIX qlen)")
    print(f"  Frames drained:    {drained}")
    print(f"  Elapsed:           {elapsed:.3f}s")
    print(f"  Throughput:        {pps:,.0f} pps")
    print(f"  Per-frame overhead: {per_frame_us:.2f} µs")
    print(f"  No-deliver drops:  {ring.queue_full_drop_count}")


def main() -> int:
    """
    Run the benchmark with parsed CLI arguments.
    """

    parser = argparse.ArgumentParser(
        description="RX-ring synthetic micro-benchmark (audit item 5).",
    )
    parser.add_argument(
        "--frames",
        type=int,
        default=50_000,
        help="Number of frames to drain (default: 50000).",
    )
    parser.add_argument(
        "--size",
        type=int,
        default=100,
        help="Per-frame size in bytes (default: 100). Use larger values "
        "to measure copy-bound throughput; small values isolate per-frame "
        "overhead.",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="Number of benchmark passes (default: 3 — pick the median).",
    )
    parser.add_argument(
        "--prefill",
        type=int,
        default=10000,
        help="Frames to pre-buffer in the kernel queue before the "
        "ring starts (default: 10000). Larger values exercise the "
        "burst-drain path; 0 produces a steady-state stream.",
    )
    args = parser.parse_args()

    # Suppress the rx_ring log calls. Under '-O' they are already
    # short-circuited at bytecode time; under default (debug) mode
    # the patch matters so the benchmark isn't dominated by
    # f-string formatting.
    log_patches = [
        patch("pmd_pytcp.runtime.rx_ring.log"),
    ]
    for p in log_patches:
        p.start()

    print(f"=== RX-ring benchmark ({args.runs} run(s)) ===")
    print(f"Python optimized: {not __debug__}  (use -O to strip __debug__)")
    print()

    try:
        for run in range(1, args.runs + 1):
            print(f"--- Run {run}/{args.runs} ---")
            asyncio.run(_bench(n_frames=args.frames, frame_size=args.size, prefill=args.prefill))
            print()
    finally:
        for p in log_patches:
            p.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
