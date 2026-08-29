#!/usr/bin/env python3
"""
KernelGuard Day 6 enforcement audit.

The process prints its PID, waits for KernelGuard to attach, then
attempts allowed and denied network connections and filesystem writes
so the enforcement (EPERM) logic can be audited.

Usage:

    python3 tests/test_enforcement_audit.py

Start KernelGuard in another terminal using the printed PID:

    sudo python3 -m kernelguard.cli --enforce --pid <PID>
"""

import os
import socket
import time
from pathlib import Path


def test_network() -> None:
    print("\n--- Network Enforcement Audit ---")
    
    # 1. Allowed IP (1.1.1.1)
    print("Connecting to ALLOWED IP (1.1.1.1)...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect(('1.1.1.1', 80))
        print("✅ SUCCESS: Allowed connection was NOT blocked by EPERM.")
    except PermissionError:
        print("❌ FAIL: Allowed connection was incorrectly blocked (EPERM)!")
    except OSError as e:
        print(f"✅ SUCCESS: Connection failed with '{e}', but NOT EPERM.")
    finally:
        s.close()
        
    # 2. Denied IP (10.0.0.1)
    print("Connecting to DENIED IP (10.0.0.1)...")
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.settimeout(2)
    try:
        s2.connect(('10.0.0.1', 80))
        print("❌ FAIL: Denied connection was unexpectedly allowed!")
    except PermissionError:
        print("✅ SUCCESS: Denied connection correctly blocked with EPERM.")
    except OSError as e:
        print(f"❌ FAIL: Connection failed with '{e}', expected EPERM.")
    finally:
        s2.close()


def test_filesystem() -> None:
    print("\n--- Filesystem Enforcement Audit ---")
    
    allowed_path = Path("/tmp/kernelguard-test.txt")
    denied_path = Path("/tmp/kernelguard-unauthorized.txt")

    print("Waiting a brief moment so you can confirm KernelGuard is running...")
    time.sleep(2)
    
    # 1. Allowed file
    print(f"Writing to ALLOWED file ({allowed_path})...")
    try:
        with open(allowed_path, 'a') as f:
            f.write("KernelGuard allowed write test\n")
        print("✅ SUCCESS: Allowed file write was NOT blocked.")
    except PermissionError:
        print("❌ FAIL: Allowed file write was incorrectly blocked (EPERM)!")
        
    # 2. Denied file
    print(f"Writing to DENIED file ({denied_path})...")
    try:
        with open(denied_path, 'a') as f:
            f.write("KernelGuard denied write test\n")
        print("❌ FAIL: Denied file write was unexpectedly allowed!")
    except PermissionError:
        print("✅ SUCCESS: Denied file write correctly blocked with EPERM.")


def test_pid_isolation() -> None:
    print("\n--- PID Isolation Audit ---")
    print("Spawning a subprocess to test if it gets blocked (it shouldn't be)...")
    import subprocess
    
    # Try connecting to denied IP in subprocess
    network_cmd = (
        "import socket;"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM);"
        "s.settimeout(2);"
        "s.connect(('10.0.0.1', 80))"
    )
    # It might timeout or error, but shouldn't be PermissionError (EPERM)
    proc_net = subprocess.run(
        ["python3", "-c", network_cmd],
        capture_output=True,
        text=True
    )
    if "PermissionError" in proc_net.stderr:
        print("❌ FAIL: Subprocess network connection was incorrectly blocked with EPERM!")
    else:
        print("✅ SUCCESS: Subprocess network connection was NOT blocked by EPERM.")

    # Try writing to denied file in subprocess
    file_cmd = (
        "with open('/tmp/kernelguard-unauthorized.txt', 'a') as f:"
        "    f.write('Subprocess write test\\n')"
    )
    proc_file = subprocess.run(
        ["python3", "-c", file_cmd],
        capture_output=True,
        text=True
    )
    if "PermissionError" in proc_file.stderr:
        print("❌ FAIL: Subprocess file write was incorrectly blocked with EPERM!")
    else:
        print("✅ SUCCESS: Subprocess file write was NOT blocked by EPERM.")


def main() -> None:
    pid = os.getpid()

    # Pre-create the allowed file so os.stat() inside controller.py works properly
    try:
        Path("/tmp/kernelguard-test.txt").touch()
    except Exception:
        pass

    print(f"TEST_PID={pid}", flush=True)
    print("Waiting 15 seconds for KernelGuard to attach...", flush=True)
    print(
        "Start KernelGuard in another terminal using the PID above:",
        flush=True,
    )
    print(f"    sudo python3 -m kernelguard.cli --enforce --pid {pid}", flush=True)

    time.sleep(15)

    test_network()
    test_filesystem()
    test_pid_isolation()

    print("\nEnforcement audit complete.", flush=True)


if __name__ == "__main__":
    main()
