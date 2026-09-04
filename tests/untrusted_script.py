import urllib.request
import socket
import sys

print("[*] Untrusted Script Started")
print(f"[*] PID: {sys.argv[1] if len(sys.argv) > 1 else 'N/A'}")

# Test 1: Network violation
print("[*] Attempting unauthorized network connection to 1.0.0.1...")
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    sock.connect(("1.0.0.1", 80))
    print("[!] FATAL: Connection succeeded! (Should have been blocked)")
except PermissionError:
    print("[+] SUCCESS: Connection blocked by KernelGuard (Permission denied)")
except Exception as e:
    print(f"[!] Other exception: {e}")

# Test 2: Filesystem violation
print("[*] Attempting unauthorized file write to /tmp/unauthorized_write.txt...")
try:
    with open("/tmp/unauthorized_write.txt", "a") as f:
        f.write("\n# KernelGuard test")
    print("[!] FATAL: File write succeeded! (Should have been blocked)")
except PermissionError:
    print("[+] SUCCESS: File write blocked by KernelGuard (Permission denied)")
except Exception as e:
    print(f"[!] Other exception: {e}")
