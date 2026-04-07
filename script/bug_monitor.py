#!/usr/bin/env python3
"""Bug canary shared-memory monitor for FuzzBench experiments.

Polls the /dev/shm/bug_canary shared memory region created by the
bug_canary.c library and logs per-bug reached/triggered counts to CSV.

Designed to run alongside a fuzzer in a FuzzBench trial container.
The output CSV is consumed by fuzzbench_triage.py for survival analysis.

Usage:
    python3 bug_monitor.py \
        --bug-metadata /path/to/bug_metadata.json \
        --output /path/to/canary_log.csv \
        --interval 5

The monitor runs until killed (SIGTERM/SIGINT) or --duration seconds elapse.
"""

import argparse
import csv
import json
import logging
import mmap
import os
import signal
import struct
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Matches bug_canary.h layout (verified with offsetof):
#   struct bug_canary_shm {
#       volatile uint8_t faulty;          // offset 0
#       // 7 bytes padding
#       struct bug_canary canaries[N];    // offset 8
#   };
#   struct bug_canary { uint64_t reached, triggered, ts_first_reached, ts_first_triggered; };
SHM_NAME = "/bug_canary"
SHM_PATH = "/dev/shm/bug_canary"
CANARIES_OFFSET = 8
CANARY_SIZE = 32  # 4 x uint64_t
CANARY_FMT = "<QQQQ"  # reached, triggered, ts_first_reached, ts_first_triggered


def build_canary_index_to_bug_id(bug_metadata: dict) -> dict:
    """Build mapping from canary array index to bug_id string.

    Only includes dispatch-controlled bugs (canary_index >= 0).
    Local bugs (dispatch_value=0, canary_index=-1) are always active
    and not tracked via the canary shared memory.
    """
    mapping = {}
    for bug_id, info in bug_metadata["bugs"].items():
        ci = info.get("canary_index", -1)
        if ci >= 0:
            mapping[ci] = bug_id
    return mapping


def read_canary(mm: mmap.mmap, index: int) -> tuple:
    """Read a single canary entry from the mmap'd shared memory.

    Returns (reached, triggered, ts_first_reached, ts_first_triggered).
    """
    offset = CANARIES_OFFSET + index * CANARY_SIZE
    data = mm[offset:offset + CANARY_SIZE]
    if len(data) < CANARY_SIZE:
        return (0, 0, 0, 0)
    return struct.unpack(CANARY_FMT, data)


def monitor_loop(mm: mmap.mmap, index_to_bug: dict, writer, interval: float,
                 duration: float, start_time: float):
    """Main polling loop. Writes CSV rows when canary state changes."""
    # Track last-seen state to only log changes
    last_state = {}
    deadline = start_time + duration if duration > 0 else float("inf")

    while time.monotonic() < deadline:
        now_ms = int((time.monotonic() - start_time) * 1000)

        for ci, bug_id in sorted(index_to_bug.items()):
            reached, triggered, ts_reached, ts_triggered = read_canary(mm, ci)

            prev = last_state.get(ci)
            if prev is None or prev != (reached, triggered):
                writer.writerow([now_ms, bug_id, reached, triggered])
                last_state[ci] = (reached, triggered)

        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            break


def open_shm() -> mmap.mmap:
    """Open the bug_canary shared memory region (read-only)."""
    fd = os.open(SHM_PATH, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        if size == 0:
            raise RuntimeError("Shared memory region is empty (fuzzer not started?)")
        mm = mmap.mmap(fd, size, access=mmap.ACCESS_READ)
    finally:
        os.close(fd)
    return mm


def wait_for_shm(timeout: float = 300) -> mmap.mmap:
    """Wait for the shared memory file to appear and have nonzero size."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(SHM_PATH):
            try:
                return open_shm()
            except (OSError, RuntimeError):
                pass
        time.sleep(1)
    raise TimeoutError(f"{SHM_PATH} did not appear within {timeout}s")


# Graceful shutdown
_shutdown = False


def _handle_signal(signum, frame):
    global _shutdown
    _shutdown = True


def main():
    parser = argparse.ArgumentParser(
        description="Poll bug_canary shared memory and log to CSV",
    )
    parser.add_argument("--bug-metadata", required=True,
                        help="Path to bug_metadata.json")
    parser.add_argument("--output", required=True,
                        help="Output CSV path")
    parser.add_argument("--interval", type=float, default=5.0,
                        help="Polling interval in seconds (default: 5)")
    parser.add_argument("--duration", type=float, default=0,
                        help="Run for N seconds then exit (0 = run forever)")
    parser.add_argument("--wait-timeout", type=float, default=300,
                        help="Max seconds to wait for shared memory (default: 300)")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # Load metadata
    with open(args.bug_metadata) as f:
        bug_metadata = json.load(f)
    index_to_bug = build_canary_index_to_bug_id(bug_metadata)
    logger.info("Tracking %d dispatch-controlled bugs (canary indices: %s)",
                len(index_to_bug), sorted(index_to_bug.keys()))

    # Wait for shared memory
    logger.info("Waiting for %s ...", SHM_PATH)
    mm = wait_for_shm(timeout=args.wait_timeout)
    logger.info("Shared memory opened (%d bytes)", mm.size())

    # Open CSV output
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    csvfile = open(output_path, "w", newline="")
    writer = csv.writer(csvfile)

    start_time = time.monotonic()
    logger.info("Monitoring started (interval=%.1fs, duration=%s)",
                args.interval, f"{args.duration}s" if args.duration > 0 else "infinite")

    try:
        # Inline the loop here for graceful shutdown support
        deadline = start_time + args.duration if args.duration > 0 else float("inf")
        last_state = {}

        while not _shutdown and time.monotonic() < deadline:
            now_ms = int((time.monotonic() - start_time) * 1000)

            for ci, bug_id in sorted(index_to_bug.items()):
                reached, triggered, ts_reached, ts_triggered = read_canary(mm, ci)
                prev = last_state.get(ci)
                if prev is None or prev != (reached, triggered):
                    writer.writerow([now_ms, bug_id, reached, triggered])
                    last_state[ci] = (reached, triggered)

            csvfile.flush()
            try:
                time.sleep(args.interval)
            except KeyboardInterrupt:
                break
    finally:
        csvfile.close()
        mm.close()
        logger.info("Monitor stopped. Output: %s", output_path)


if __name__ == "__main__":
    main()
