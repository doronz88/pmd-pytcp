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
RX-ring synthetic micro-benchmark — drives a UNIX pipe as the
ring's source fd, measures per-frame overhead and sustained
throughput. Use to A/B the per-iteration 'select() + os.read()'
cost vs an experimental inner-drain branch (audit item 5).

Run:
    PYTHONPATH=. python3.14 -O tools/bench_rx_ring.py

Or under cProfile:
    PYTHONPATH=. python3.14 -O -m cProfile -o /tmp/rx_ring.prof \\
        tools/bench_rx_ring.py
    python3.14 -c "import pstats; pstats.Stats('/tmp/rx_ring.prof'\\
        ).strip_dirs().sort_stats('cumulative').print_stats(40)"

The pipe-based driver under-represents the real-world burst
absorption case (pipes block on full; TAPs drop), but is exact
for measuring per-frame overhead.

tools/bench_rx_ring.py

ver 3.0.4
"""

import argparse
import os
import sys
import threading
import time
from unittest.mock import patch

from pytcp.stack.rx_ring import RxRing


def _bench(n_frames: int, frame_size: int) -> None:
    """
    Run a single benchmark pass and print per-frame timings.
    """

    frame = b"\x00" * frame_size
    read_fd, write_fd = os.pipe()
    ring = RxRing(fd=read_fd, mtu=1500, queue_max_size=n_frames + 1000)

    # Writer keeps the pipe primed; the producer side only stalls
    # if the kernel pipe buffer fills, which the consumer drains
    # via the ring.
    def writer() -> None:
        try:
            for _ in range(n_frames):
                os.write(write_fd, frame)
        finally:
            os.close(write_fd)

    t = threading.Thread(target=writer)
    t.start()

    ring.start()
    start = time.perf_counter()
    drained = 0
    while drained < n_frames:
        if ring.dequeue() is not None:
            drained += 1
    elapsed = time.perf_counter() - start
    ring.stop()
    t.join()
    try:
        os.close(read_fd)
    except OSError:
        pass

    pps = drained / elapsed
    per_frame_us = elapsed / drained * 1e6
    print(f"  Frame size:        {frame_size} bytes")
    print(f"  Frames drained:    {drained}")
    print(f"  Elapsed:           {elapsed:.3f}s")
    print(f"  Throughput:        {pps:,.0f} pps")
    print(f"  Per-frame overhead: {per_frame_us:.2f} µs")
    print(f"  Queue-full drops:  {ring.queue_full_drop_count}")


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
    args = parser.parse_args()

    # Suppress the rx_ring + subsystem log calls. Under '-O' they
    # are already short-circuited at bytecode time; under default
    # (debug) mode the patches matter so the benchmark isn't
    # dominated by f-string formatting.
    log_patches = [
        patch("pytcp.stack.rx_ring.log"),
        patch("pytcp.lib.subsystem.log"),
    ]
    for p in log_patches:
        p.start()

    print(f"=== RX-ring benchmark ({args.runs} run(s)) ===")
    print(f"Python optimized: {not __debug__}  (use -O to strip __debug__)")
    print()

    try:
        for run in range(1, args.runs + 1):
            print(f"--- Run {run}/{args.runs} ---")
            _bench(n_frames=args.frames, frame_size=args.size)
            print()
    finally:
        for p in log_patches:
            p.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
