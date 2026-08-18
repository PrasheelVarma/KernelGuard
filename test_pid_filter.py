#!/usr/bin/env python3
"""
Verifies eBPF-side PID filtering by setting a target PID in the BPF map
and confirming only that PID's execve events are reported.

Usage:
    sudo python3 test_pid_filter.py <target_pid>

Stop with Ctrl+C.
"""

import sys

from bcc import BPF

if len(sys.argv) != 2:
    print("Usage: sudo python3 test_pid_filter.py <target_pid>")
    sys.exit(1)

target_pid = int(sys.argv[1])

b = BPF(src_file="ebpf/execve_trace.c")
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="trace_execve")

target_pid_map = b["target_pid_map"]
target_pid_map[target_pid_map.Key(0)] = target_pid_map.Leaf(target_pid)

print(f"Filtering execve() events for PID {target_pid} only. Press Ctrl+C to stop.\n")

try:
    while True:
        task, pid, cpu, flags, ts, msg = b.trace_fields()
        print(f"[{ts:.6f}] PID {pid:<8} {task.decode():<16} {msg.decode()}")
except KeyboardInterrupt:
    print("\nStopped.")
