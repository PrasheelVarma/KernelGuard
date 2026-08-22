#!/usr/bin/env python3
"""
KernelGuard Day 6 interception audit.

The process prints its PID, waits for KernelGuard to attach, then
writes to multiple files so the vfs_write hook can be audited.

Usage:

    python3 tests/test_interception_audit.py

Start KernelGuard in another terminal using the printed PID:

    sudo python3 -m kernelguard.cli --pid <PID>
"""

import os
import time
from pathlib import Path


TEST_FILES = [
    Path("/tmp/kernelguard-audit-one.txt"),
    Path("/tmp/kernelguard-audit-two.txt"),
    Path("/tmp/kernelguard-audit-three.txt"),
]


def write_test_files() -> None:
    """Write to every file used by the interception audit."""
    for index, path in enumerate(TEST_FILES, start=1):
        print(f"Writing to {path}", flush=True)

        path.write_text(
            f"KernelGuard interception audit file {index}\n",
            encoding="utf-8",
        )

        time.sleep(1)


def cleanup() -> None:
    """Remove audit files after the test."""
    for path in TEST_FILES:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def main() -> None:
    pid = os.getpid()

    print(f"TEST_PID={pid}", flush=True)
    print("Waiting 30 seconds for KernelGuard to attach...", flush=True)
    print(
        "Start KernelGuard in another terminal using the PID above.",
        flush=True,
    )

    time.sleep(30)

    try:
        write_test_files()

        print("Interception audit writes complete.", flush=True)

        # Keep the process alive briefly so the final event can be observed.
        time.sleep(5)

    finally:
        cleanup()


if __name__ == "__main__":
    main()
