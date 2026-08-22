#!/usr/bin/env python3
"""
KernelGuard Day 6 performance benchmark.

Measures repeated write() syscall latency twice in the same process:

1. Baseline: before KernelGuard is attached.
2. Hooked: after KernelGuard is attached.

The process keeps the same PID for both measurements.

Usage:

    python3 tests/test_performance.py

The script prints its PID and provides time to attach KernelGuard
between the baseline and hooked measurements.
"""

import os
import statistics
import time


TEST_FILE = "/tmp/kernelguard-performance-test.txt"
WRITE_SIZE = 64
ITERATIONS = 5000
ATTACH_WAIT_SECONDS = 30


def benchmark_writes() -> list[int]:
    """Measure individual write() syscall durations in nanoseconds."""
    fd = os.open(TEST_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)

    timings = []

    try:
        data = b"K" * WRITE_SIZE

        for _ in range(ITERATIONS):
            start = time.perf_counter_ns()
            os.write(fd, data)
            end = time.perf_counter_ns()

            timings.append(end - start)

    finally:
        os.close(fd)

    return timings


def summarize(label: str, timings: list[int]) -> float:
    """Print benchmark statistics and return the average in microseconds."""
    average_ns = statistics.mean(timings)
    median_ns = statistics.median(timings)
    minimum_ns = min(timings)
    maximum_ns = max(timings)

    average_us = average_ns / 1_000
    median_us = median_ns / 1_000
    minimum_us = minimum_ns / 1_000
    maximum_us = maximum_ns / 1_000

    print(f"\n{label}")
    print("-" * 50)
    print(f"Iterations : {len(timings)}")
    print(f"Average    : {average_us:.3f} us")
    print(f"Median     : {median_us:.3f} us")
    print(f"Minimum    : {minimum_us:.3f} us")
    print(f"Maximum    : {maximum_us:.3f} us")

    return average_us


def main() -> None:
    pid = os.getpid()

    print(f"BENCHMARK_PID={pid}", flush=True)
    print(
        "Running baseline benchmark in 5 seconds.",
        flush=True,
    )

    time.sleep(5)

    baseline_timings = benchmark_writes()
    baseline_average = summarize(
        "BASELINE — KernelGuard not attached",
        baseline_timings,
    )

    print(
        f"\nBaseline complete. Attach KernelGuard to PID {pid}.",
        flush=True,
    )
    print(
        f"Waiting {ATTACH_WAIT_SECONDS} seconds before hooked benchmark...",
        flush=True,
    )

    time.sleep(ATTACH_WAIT_SECONDS)

    hooked_timings = benchmark_writes()
    hooked_average = summarize(
        "HOOKED — KernelGuard attached",
        hooked_timings,
    )

    overhead_us = hooked_average - baseline_average
    overhead_percent = (
        (overhead_us / baseline_average) * 100
        if baseline_average > 0
        else 0.0
    )

    print("\nPERFORMANCE RESULT")
    print("-" * 50)
    print(f"Baseline average : {baseline_average:.3f} us")
    print(f"Hooked average   : {hooked_average:.3f} us")
    print(f"Overhead         : {overhead_us:.3f} us")
    print(f"Overhead         : {overhead_percent:.2f}%")
    print(f"Under 1 ms       : {'YES' if overhead_us < 1000 else 'NO'}")

    try:
        os.unlink(TEST_FILE)
    except FileNotFoundError:
        pass


if __name__ == "__main__":
    main()
