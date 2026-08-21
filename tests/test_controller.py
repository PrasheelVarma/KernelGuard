#!/usr/bin/env python3
"""
Integration helper for KernelGuard's unified multi-hook controller.

The process prints its PID, waits for the controller to attach,
then generates tcp_connect and vfs_write activity before replacing
itself with /usr/bin/true using execve().

Usage:

    python3 tests/test_controller.py

Start KernelGuard in another terminal using the printed PID:

    sudo python3 -m kernelguard.cli --pid <PID>
"""

import os
import socket
import time
from pathlib import Path


TEST_FILE = Path("/tmp/kernelguard-unified-test.txt")


def generate_tcp_connect_event() -> None:
    """Generate a TCP connection attempt."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.settimeout(2)
        sock.connect(("1.1.1.1", 80))
    except OSError:
        pass
    finally:
        sock.close()


def generate_vfs_write_event() -> None:
    """Generate a filesystem write event."""
    TEST_FILE.write_text(
        "KernelGuard unified multi-hook test\n",
        encoding="utf-8",
    )


def generate_execve_event() -> None:
    """Replace this process with /usr/bin/true using execve()."""
    os.execve(
        "/usr/bin/true",
        ["true"],
        os.environ.copy(),
    )


def main() -> None:
    pid = os.getpid()

    print(f"TEST_PID={pid}", flush=True)
    print("Waiting 30 seconds for KernelGuard to attach...", flush=True)
    print("Start KernelGuard in another terminal using the PID above.", flush=True)

    time.sleep(30)

    print("Generating tcp_connect event...", flush=True)
    generate_tcp_connect_event()

    print("Generating vfs_write event...", flush=True)
    generate_vfs_write_event()

    print("Generating execve event...", flush=True)
    generate_execve_event()


if __name__ == "__main__":
    main()
