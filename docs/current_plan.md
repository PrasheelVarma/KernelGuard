# KernelGuard — Week 1 Plan

**Week 1 Goal (per project doc):**
- **Kernel Engineering:** eBPF Foundations — basic eBPF C program that intercepts the `execve` syscall.
- **Python Controller:** BCC Integration — Python `bcc` script that loads the C program into the kernel and prints intercept logs to console.

**Week window:** Monday → Sunday
**Today:** Wednesday (Day 3)

---

## Day-by-Day Breakdown

### ✅ Day 1 (Mon) — Done
- Repo initialized.

### ✅ Day 2 (Tue) — Done
- README, LICENSE, .gitignore, project structure scaffolded.

### 🔲 Day 3 (Wed) — Today: Environment Setup
- [ ] Confirm Linux environment (native, VM, or WSL2 with kernel access).
- [ ] Install kernel headers: `linux-headers-$(uname -r)`.
- [ ] Install BCC toolchain: `bpfcc-tools`, `python3-bpfcc`.
- [ ] Verify install: run an existing BCC example script (e.g. `hello_world.py` from BCC examples) to confirm the toolchain actually works before writing custom code.
- [ ] Confirm root/sudo access — eBPF loading requires it.

**Goal by end of today:** A working BCC environment where you can run *any* existing eBPF example successfully.

---

### 🔲 Day 4 (Thu) — eBPF Foundations (Part 1)
- [ ] Write `ebpf/execve_trace.c` — minimal eBPF C program hooking the `execve` syscall entry point.
- [ ] Understand and use `bpf_trace_printk()` (or a BPF map) to emit data from kernel space.
- [ ] Test-compile the C snippet standalone (syntax sanity check) before wiring it to Python.

**Goal by end of today:** eBPF C code compiles cleanly (even if not yet loaded via Python).

---

### 🔲 Day 5 (Fri) — BCC Integration (Part 1)
- [ ] Write `kernelguard/controller.py` — Python `bcc` script that:
  - Loads `execve_trace.c` using `BPF(src_file=...)`.
  - Attaches the probe to the `execve` syscall.
- [ ] Get raw kernel trace output printing to console (even unformatted).

**Goal by end of today:** Running `python3 controller.py` shows live `execve` events from your system in the terminal.

---

### 🔲 Day 6 (Sat) — Polish & Formatting
- [ ] Clean up the console output (PID, process name, timestamp per intercepted `execve` call).
- [ ] Basic error handling (e.g. permission errors if not run as root, missing kernel headers).
- [ ] Test against a few different processes (e.g. open a new terminal, run `ls`, confirm it gets logged).

**Goal by end of today:** A readable, working live log of `execve` events triggered on the system.

---

### 🔲 Day 7 (Sun) — Week 1 Wrap-Up & Review Prep
- [ ] Re-test end-to-end: fresh terminal → run script → confirm intercepts show up correctly.
- [ ] Commit and push all Week 1 code (`ebpf/execve_trace.c`, `kernelguard/controller.py`).
- [ ] Update main `README.md` progress checklist (check off Week 1 items).
- [ ] Write short notes/summary of what was built — useful for your mentor review and for your own memory when Week 2 (syscall hooking, PID filtering) begins.

**Goal by end of Sunday:** Week 1 fully matches the project doc's target:
> *"BCC Integration: Write the Python bcc script that loads the C program into the kernel and prints intercept logs to the console."*

---

## Tracking Checklist (quick view)

| Day | Focus | Status |
|---|---|---|
| Mon | Repo init | ✅ Done |
| Tue | README + docs | ✅ Done |
| Wed | Environment setup (BCC, kernel headers) | 🔲 In progress |
| Thu | eBPF C program (`execve` hook) | 🔲 Pending |
| Fri | Python `bcc` controller (load + attach) | 🔲 Pending |
| Sat | Output polish + error handling | 🔲 Pending |
| Sun | Testing, commit, push, review prep | 🔲 Pending |

---
