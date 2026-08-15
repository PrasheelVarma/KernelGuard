# KernelGuard — Week 1 Plan

**Week 1 Goal (per project doc):**
- **Kernel Engineering:** eBPF Foundations — basic eBPF C program that intercepts the `execve` syscall.
- **Python Controller:** BCC Integration — Python `bcc` script that loads the C program into the kernel and prints intercept logs to console.

**Week window:** Monday → Sunday

---

## Day-by-Day Breakdown

### Day 1 (Mon) — Repo Init
- [x] Repository initialized.

### Day 2 (Tue) — Documentation
- [x] README, LICENSE, .gitignore, project structure scaffolded.

### Day 3 (Wed) — Environment Setup
- [x] Confirmed Linux environment (EndeavourOS, Arch-based).
- [x] Installed matching kernel headers.
- [x] Installed BCC toolchain (`bcc`, `bcc-tools`, `python-bcc`).
- [x] Verified toolchain using a stock BCC example (`execsnoop`) and a Python `bcc` import check.
- [x] Confirmed root/sudo access for eBPF loading.

**Result:** Working BCC + eBPF environment, verified functional.

### Day 4 (Thu) — eBPF Foundations
- [x] Wrote `ebpf/execve_trace.c` — eBPF C program hooking the `execve` syscall entry point.
- [x] Used `bpf_trace_printk()` to emit PID and process name from kernel space.
- [x] Wrote a Python loader (`test_load.py`) to compile and attach the program, and verified live output.

**Result:** eBPF program compiles, loads, and successfully intercepts `execve` calls system-wide, with clean formatted output.

> Note: This also satisfies the original Day 5 (BCC Integration) target ahead of schedule — the loader already loads the C program and prints intercept logs to console.

### Day 5 (Fri) — Controller Development
- [x] Converted the verification loader into the permanent `kernelguard/controller.py`.
- [x] Structured as a reusable `ExecveController` class (`load()`, `events()`, `run()`) rather than a standalone script.
- [x] Verified via `sudo python3 -m kernelguard.controller` — live, correctly formatted `execve` trace output confirmed.

**Result:** Production controller module in place, reusable for future syscall hooks and the upcoming policy engine.

### Day 6 (Sat) — Polish & Formatting
- [ ] Refine console output (PID, process name, timestamp per intercepted `execve` call).
- [ ] Add basic error handling (permission errors, missing kernel headers).
- [ ] Validate against multiple processes.

### Day 7 (Sun) — Week 1 Wrap-Up
- [ ] End-to-end retest.
- [ ] Commit and push all Week 1 code.
- [ ] Update `README.md` roadmap reference.
- [ ] Prepare short summary for Week 2 handoff.

**Target by end of Sunday:** Week 1 fully matches the project doc's requirement —
> *"BCC Integration: Write the Python bcc script that loads the C program into the kernel and prints intercept logs to the console."*

---

## Tracking Checklist

| Day | Focus | Status |
|---|---|---|
| Mon | Repo init | ✅ Done |
| Tue | README + docs | ✅ Done |
| Wed | Environment setup (BCC, kernel headers) | ✅ Done |
| Thu | eBPF C program (`execve` hook) + verification loader | ✅ Done |
| Fri | Python `controller.py` (production version) | ✅ Done |
| Sat | Output polish + error handling | 🔲 Pending |
| Sun | Testing, commit, push, review prep | 🔲 Pending |
