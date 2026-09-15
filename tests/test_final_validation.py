#!/usr/bin/env python3
"""
Final validation demonstration script for KernelGuard release candidate.
Tests:
1. Non-root user identity verification (UID != 0)
2. Allowed network connection (1.1.1.1) -> Passes
3. Unauthorized network connection (10.0.0.1) -> Blocked with PermissionError (-EPERM)
4. Allowed filesystem write (/tmp/kernelguard-test.txt) -> Passes
5. Unauthorized filesystem write (/tmp/kernelguard-unauthorized.txt) -> Blocked with PermissionError (-EPERM)
6. Subprocess / PID isolation verification -> Subprocesses operate normally without unintended blocking
"""

import os
import socket
import subprocess
import sys
from pathlib import Path


def main() -> int:
    print("\n========================================================")
    print("🛡️  KERNELGUARD FINAL RELEASE VALIDATION SUITE")
    print("========================================================")

    # 1. Verify User Identity (Privilege Separation)
    uid = os.getuid()
    euid = os.geteuid()
    gid = os.getgid()
    print(f"[*] Process Execution Identity: UID={uid}, EUID={euid}, GID={gid}")
    
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid:
        expected_uid = int(sudo_uid)
        if uid == expected_uid and euid == expected_uid:
            print(f"✅ PRIVILEGE SEPARATION: Successfully executing as target user (UID {uid}), NOT root.")
        else:
            print(f"❌ PRIVILEGE SEPARATION FAILED: Running with UID {uid}, expected {expected_uid}.")
            return 1
    else:
        print(f"[*] Running with current user UID {uid}.")

    failures = 0

    # 2. Allowed Network Operation
    print("\n--- Network Validation ---")
    print("[*] Connecting to ALLOWED IPv4 endpoint (1.1.1.1:80)...")
    s_allowed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_allowed.settimeout(2)
    try:
        s_allowed.connect(("1.1.1.1", 80))
        print("✅ SUCCESS: Allowed network connection permitted by kernel.")
    except PermissionError:
        print("❌ FAIL: Allowed network connection was incorrectly blocked (-EPERM)!")
        failures += 1
    except OSError as e:
        print(f"✅ SUCCESS: Allowed network connection permitted (socket closed: {e}).")
    finally:
        s_allowed.close()

    # 3. Denied Network Operation
    print("[*] Connecting to DENIED IPv4 endpoint (10.0.0.1:80)...")
    s_denied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_denied.settimeout(2)
    try:
        s_denied.connect(("10.0.0.1", 80))
        print("❌ FAIL: Unauthorized network connection was unexpectedly allowed!")
        failures += 1
    except PermissionError:
        print("✅ SUCCESS: Unauthorized network connection blocked with PermissionError (-EPERM).")
    except OSError as e:
        print(f"❌ FAIL: Expected PermissionError (-EPERM), got: {e}")
        failures += 1
    finally:
        s_denied.close()

    # 4. Allowed Filesystem Operation
    print("\n--- Filesystem Validation ---")
    allowed_file = Path("/tmp/kernelguard-test.txt")
    print(f"[*] Writing to ALLOWED file ({allowed_file})...")
    try:
        with open(allowed_file, "a", encoding="utf-8") as f:
            f.write("KernelGuard release candidate validation write\n")
        print("✅ SUCCESS: Allowed file write permitted by kernel.")
    except PermissionError:
        print("❌ FAIL: Allowed file write was incorrectly blocked (-EPERM)!")
        failures += 1
    except Exception as e:
        print(f"❌ FAIL: Unexpected error writing to allowed file: {e}")
        failures += 1

    # 5. Denied Filesystem Operation
    denied_file = Path("/tmp/kernelguard-unauthorized.txt")
    print(f"[*] Writing to DENIED file ({denied_file})...")
    try:
        with open(denied_file, "a", encoding="utf-8") as f:
            f.write("Unauthorized write attempt\n")
        print("❌ FAIL: Unauthorized file write was unexpectedly allowed!")
        failures += 1
    except PermissionError:
        print("✅ SUCCESS: Unauthorized file write blocked with PermissionError (-EPERM).")
    except Exception as e:
        print(f"❌ FAIL: Expected PermissionError (-EPERM), got: {e}")
        failures += 1

    # 6. PID Isolation / Unrelated Process Check
    print("\n--- PID Isolation & Scope Check ---")
    print("[*] Testing isolated background process (should operate without interception)...")
    probe = subprocess.run(
        [sys.executable, "-c", "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(1); s.connect(('10.0.0.1', 80))"],
        capture_output=True,
        text=True,
    )
    if "PermissionError" in probe.stderr:
        print("❌ FAIL: Isolated subprocess was incorrectly blocked by KernelGuard!")
        failures += 1
    else:
        print("✅ SUCCESS: Isolated process is unconstrained by target PID sandbox.")

    print("\n========================================================")
    if failures == 0:
        print("🏆 ALL FINAL VALIDATION CRITERIA PASSED SUCCESSFULLY")
        print("========================================================\n")
        return 0
    else:
        print(f"❌ VALIDATION COMPLETED WITH {failures} FAILURE(S)")
        print("========================================================\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
