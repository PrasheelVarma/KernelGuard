# KernelGuard — Week 2 Plan

**Week 2 Goal (per project doc):**
- **Kernel Engineering:** Syscall Hooking — expand the eBPF code to hook `tcp_connect` (network) and `vfs_write` (file system), alongside the existing `execve` hook.
- **Python Controller:** PID Filtering — update the controller to accept a target PID, so only a specific process is monitored instead of the whole system.
- **Mid-Project Review:** Prove the tool logs every file a target script writes to, and confirm eBPF hooks add negligible latency (< 1ms) to syscalls.

**Week window:** Monday → Sunday

---

## Day-by-Day Breakdown

### Day 1 (Mon) — PID Filtering (Kernel Side)
- [x] Update `ebpf/execve_trace.c` to accept a target PID as a compile-time or map-based filter.
- [x] Use a BPF map to pass the target PID from user space into the eBPF program.
- [x] Confirm the eBPF program only emits events for the specified PID, not system-wide.

**Goal by end of today:** eBPF-side PID filtering is functional and testable in isolation.

### Day 2 (Tue) — PID Filtering (Controller Side)
- [x] Update `kernelguard/controller.py` — `ExecveController` accepts a `target_pid` parameter.
- [x] Wire the target PID into the BPF map on `load()`.
- [x] Add a small CLI entry point (`--pid <PID>`) to test filtering against a real running process.

**Goal by end of today:** Running the controller against a single PID shows only that process's `execve` events.

### Day 3 (Wed) — `tcp_connect` Hook
- [x] Write a new eBPF hook (`ebpf/tcp_connect_trace.c` or extend existing file) intercepting `tcp_connect`.
- [x] Capture destination IP/port and the calling PID.
- [x] Verify via a manual test (e.g. `curl` or `ping` from the target process) that connection attempts are captured.

**Goal by end of today:** Network connection attempts by a target process are visible in trace output.

### Day 4 (Thu) — `vfs_write` Hook
- [ ] Write a new eBPF hook intercepting `vfs_write`.
- [ ] Capture the file path (or file descriptor) and PID for each write.
- [ ] Verify via a manual test (e.g. target script writing to a file) that writes are captured.

**Goal by end of today:** File write attempts by a target process are visible in trace output.

### Day 5 (Fri) — Unified Multi-Hook Controller
- [ ] Refactor `controller.py` so `execve`, `tcp_connect`, and `vfs_write` hooks can run together under one controller instance.
- [ ] Unify event output format across all three hook types (consistent fields: pid, task, event type, detail).
- [ ] Confirm all three hooks can run simultaneously without conflict.

**Goal by end of today:** A single controller run reports execve, network, and file-write events for a target process.

### Day 6 (Sat) — Mid-Project Review
- [ ] **Interception audit:** Run a test script that writes to multiple files; confirm every write is logged with correct path and PID.
- [ ] **Performance check:** Measure syscall latency with and without the eBPF hooks attached; confirm overhead stays under 1ms.
- [ ] Document audit and performance results.

**Goal by end of today:** Both Mid-Project Review requirements verified and recorded.

### Day 7 (Sun) — Week 2 Wrap-Up
- [ ] End-to-end retest of all three hooks together, with PID filtering active.
- [ ] Commit and push all Week 2 code.
- [ ] Update `README.md` roadmap reference if needed.
- [ ] Prepare summary for Week 3 handoff (policy engine, active blocking).

**Target by end of Sunday:** Week 2 fully matches the project doc's requirement —
> *"Task Routing / Syscall Hooking: hook tcp_connect and vfs_write. PID Filtering: only the target process is monitored."*

---

## Tracking Checklist

| Day | Focus | Status |
|---|---|---|
| Mon | PID filtering (kernel side) | ✅ Done |
| Tue | PID filtering (controller side) | ✅ Done |
| Wed | `tcp_connect` hook | ✅ Done |
| Thu | `vfs_write` hook | 🔲 Pending |
| Fri | Unified multi-hook controller | 🔲 Pending |
| Sat | Mid-Project Review (audit + performance) | 🔲 Pending |
| Sun | Testing, commit, push, Week 3 handoff | 🔲 Pending |

---

## Reference — Week 1 Summary (carried forward)

**Delivered:** Working BCC/eBPF environment, `execve` hook, production `ExecveController` with error handling, full documentation trail, and architecture/flow/roadmap diagrams.
