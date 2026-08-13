#!/usr/bin/env python3
"""
Loads execve_trace.c via BCC, attaches it as a kprobe on execve(),
and prints intercepted events live in a clean, decoded format.

Usage:
    sudo python3 test_load.py

Stop with Ctrl+C.
"""

from bcc import BPF

b = BPF(src_file="ebpf/execve_trace.c")
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="trace_execve")

print("Tracing execve() calls. Press Ctrl+C to stop.\n")

try:
    while True:
        task, pid, cpu, flags, ts, msg = b.trace_fields()
        print(f"[{ts:.6f}] PID {pid:<8} {task.decode():<16} {msg.decode()}")
except KeyboardInterrupt:
    print("\nStopped.")
