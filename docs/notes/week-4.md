# KernelGuard — Week 4 Plan

**Week 4 Goal (per official project document):**

- **Packaging:** Package the daemon as a systemd service. Ensure it gracefully cleans up kernel hooks on exit.
- **Refine & Polish:** Finalize the CLI interface, providing clear, colored alert messages when an untrusted script is blocked.
- **Final Review:** A highly advanced security sandbox operating at the Linux Kernel level, completely invisible to the target script. A robust, production-ready Python security wrapper for executing untrusted dependencies safely.

**Week window:** Monday → Sunday

---

## Week 4 Strategy

Week 3 established the core policy engine and active `-EPERM` enforcement:

```text
Policy Definition (JSON)
           │
           ▼
    Python Controller
           │
           ▼
   Active eBPF Blocking (-EPERM)
```

Week 4 changes the focus from core functionality to production readiness and user experience:

```text
Polished CLI (Colored Alerts)
           │
           ▼
Systemd Service Management (Daemon)
           │
           ▼
Graceful Kernel Hook Cleanup
```

The goal is to ensure KernelGuard can run robustly in the background, report security events clearly to the administrator, and cleanly detach from the kernel when stopped.

---

## Day-by-Day Breakdown

### Day 1 (Mon) — CLI Refinement & Colored Alerts

- [x] Refactor the CLI using `argparse` to support advanced flags (e.g., daemon mode).
- [x] Implement colored logging/alerts (using ANSI escape codes or libraries like `rich`/`colorama`).
- [x] Ensure clear, distinct visual alerts are presented when an untrusted script is actively blocked.

**Primary files:**
```text
kernelguard/cli.py
kernelguard/logger.py
```

**Goal by end of today:** The command-line interface is user-friendly and distinctly highlights security enforcement events in color.

---

### Day 2 (Tue) — Graceful Cleanup & Hook Detachment

- [ ] Implement robust signal handling (`SIGINT`, `SIGTERM`) in the Python controller.
- [ ] Ensure that all eBPF hooks are properly detached from the kernel on exit.
- [ ] Ensure BPF maps and other kernel resources are cleanly deallocated.

**Goal by end of today:** Stopping KernelGuard guarantees that the system returns to its original state without leaving orphaned eBPF programs running.

---

### Day 3 (Wed) — systemd Service Integration

- [ ] Create a `kernelguard.service` systemd unit file.
- [ ] Configure the service to start the Python daemon correctly with necessary capabilities/privileges.
- [ ] Ensure systemd can gracefully stop the service using the signal handlers built on Day 2.

**Goal by end of today:** KernelGuard can be managed natively via `systemctl start/stop/status kernelguard`.

---

### Day 4 (Thu) — Packaging

- [ ] Create `setup.py` or `pyproject.toml` to package the Python modules.
- [ ] Ensure the C eBPF source files are correctly included in the package.
- [ ] Provide an installation script or makefile to place the systemd service file in the correct system directory.

**Goal by end of today:** KernelGuard can be installed as a standard Python package and system utility.

---

### Day 5 (Fri) — Final Integration Testing

- [ ] Deploy the newly packaged KernelGuard via systemd.
- [ ] Run an untrusted Python script to verify it is monitored and blocked appropriately in the background.
- [ ] Check `journalctl` for the colored alerts and proper logging.
- [ ] Stop the service and verify full kernel cleanup.

**Goal by end of today:** The production-ready system is verified end-to-end as a background daemon.

---

### Day 6 (Sat) — Final Documentation & Polish

- [ ] Update `README.md` with installation and systemd service instructions.
- [ ] Review all code for final styling, linting, and readability improvements.
- [ ] Finalize any architecture diagrams.

**Goal by end of today:** Project documentation matches the finalized system state.

---

### Day 7 (Sun) — Project Delivery

- [ ] Final review against the official project requirements.
- [ ] Commit and push the final v1.0 release.
- [ ] Prepare the final project summary.

**Target by end of Sunday:** A robust, production-ready Python security wrapper for executing untrusted dependencies safely.

---

## Tracking Checklist

| Day | Focus | Status |
|---|---|---|
| Mon | CLI refinement & colored alerts | ✅ Done |
| Tue | Graceful cleanup & hook detachment | [ ] Pending |
| Wed | systemd service integration | [ ] Pending |
| Thu | Packaging | [ ] Pending |
| Fri | Final integration testing | [ ] Pending |
| Sat | Final documentation & polish | [ ] Pending |
| Sun | Project delivery & final review | [ ] Pending |

---

## Week 3 → Week 4 Handoff

### Already available from Week 3

- Fully functional eBPF syscall hooks (`execve`, `tcp_connect`, `vfs_write`)
- JSON Policy Engine
- Active Blocking (`-EPERM` enforcement)
- PID Filtering & Isolation

### Week 4 builds on these components

```text
Week 3
Active Kernel Enforcement
           │
           ▼
Week 4
Production Daemon & Polish
```

---

## Official Week 4 Requirement

The official project document specifies:

> **Packaging:** Package the daemon as a systemd service. Ensure it gracefully cleans up kernel hooks on exit.
>
> **Refine & Polish:** Finalize the CLI interface, providing clear, colored alert messages when an untrusted script is blocked.
>
> **Final Review:** A highly advanced security sandbox operating at the Linux Kernel level, completely invisible to the target script. A robust, production-ready Python security wrapper for executing untrusted dependencies safely.

These requirements are the source-of-truth for the Week 4 implementation plan.

---

## Notes

- `week-4.md` is the **weekly execution plan** and should be updated with `[x]` only after the corresponding work has actually been implemented and verified.
- Do not add implementation claims to this plan before they are actually completed.
