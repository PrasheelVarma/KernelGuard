# KernelGuard 🛡️

**eBPF-based runtime security sandbox for untrusted Python processes**

[![Status](https://img.shields.io/badge/status-release%20candidate%20(code%20freeze)-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

---

## 📌 Overview

**KernelGuard** is a Linux security sandbox for monitoring and controlling selected activity from a target Python process.

It uses **eBPF** programs loaded into the Linux kernel to observe process execution, network connections, and filesystem activity. A Python controller manages the eBPF programs and applies the configured policy.

KernelGuard supports two main modes:

- **Monitoring:** observe and log supported activity.
- **Enforcement:** apply policy rules and return `-EPERM` for unauthorized operations.

The project has completed its planned development milestones (Weeks 1–4) and is currently in release-candidate / code-freeze status.

---

## 🎯 Problem Statement

Python code from untrusted sources, such as third-party packages or downloaded scripts, normally runs with the permissions available to the process that executes it.

A program with those permissions may be able to access the network, start other processes, or write to files that it should not modify.

KernelGuard provides a kernel-level sandbox where selected activity from a target process is observed and restricted according to a defined JSON security policy.

---

## 💡 The Approach

KernelGuard uses Python's **`bcc`** (BPF Compiler Collection) library to load and manage eBPF programs in the Linux kernel.

The implementation uses eBPF hooks for:

- `execve` for process execution tracing
- `tcp_connect` for IPv4 network connection enforcement
- `vfs_write` for filesystem write enforcement (with dynamic parent inode and djb2 filename hash lookups)

A BPF map (`target_pid_map`) provides process-level targeting. Enforcement is strictly scoped to the configured target PID to ensure unrelated host processes operate unaffected.

When executed via `kernelguard run <script.py>`, KernelGuard establishes an anonymous pipe barrier before child process execution, writes the child PID to the BPF map, drops privileges from root to the invoking user's UID/GID, and unblocks the child to execute under kernel-level confinement.

> *Note on process isolation:* The current security boundary is PID-scoped. Process-tree inheritance (e.g. cgroups v2 containment) is an identified future extension outside the current scope.

---

## 🧩 Key Modules

| Module | Description |
|---|---|
| **eBPF C-Code** | Kernel-side eBPF programs used for process, network, and filesystem monitoring and enforcement. |
| **Python BPF Controller (`bcc`)** | Loads and manages the eBPF programs, configures BPF maps, applies policy data, and handles events. |
| **PID Filtering** | Provides process-level targeting through a PID supplied to the CLI or spawned via `run`. |
| **Policy Engine** | Loads JSON policy rules and populates kernel allowlists for network IPs and filesystem paths. |
| **Security CLI** | Command-line entry point providing `run` (script execution) and `attach` (existing PID monitoring/enforcement) subcommands. |

---

## 🏗️ Architecture

```text
┌──────────────────────────────────────────────┐
│                 Security CLI                 │
│         (kernelguard run / attach)           │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│            Python BPF Controller             │
│   - Privilege dropping (SUDO_UID/GID)        │
│   - Pipe synchronization barrier             │
│   - BPF map configuration (target_pid_map)   │
└──────────────────────┬───────────────────────┘
                       │ loads / configures
                       ▼
┌──────────────────────────────────────────────┐
│                eBPF Programs                 │
│              Linux Kernel Space              │
└──────────────────────┬───────────────────────┘
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
      execve      tcp_connect    vfs_write
         │             │             │
         └─────────────┼─────────────┘
                       ▼
            Event / Policy Evaluation
                       │
                  ┌────┴────┐
                  ▼         ▼
               Monitor   Enforce
                           │
                           ▼
                         -EPERM
```

---

## 🛠️ Tech Stack

- **Kernel Layer:** eBPF, C
- **Controller Layer:** Python 3, `bcc`
- **Process Targeting:** Linux PID filtering through BPF map
- **Policy:** JSON policy configuration and Python policy handling
- **CLI:** `argparse`
- **Output:** Terminal event and security logging with ANSI color highlights
- **Packaging:** Python package with entry points and systemd service unit

---

## 🚀 Getting Started

> ⚠️ KernelGuard requires a Linux environment with kernel headers and BCC installed. Loading eBPF programs requires elevated privileges (`sudo`).

### Prerequisites

**Arch / EndeavourOS:**
```bash
sudo pacman -S --needed linux-headers bcc bcc-tools
```

**Debian / Ubuntu:**
```bash
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
```

Verify the BCC installation:

```bash
sudo python3 -c "from bcc import BPF; print('BCC import OK')"
```

### Clone & Setup

```bash
git clone https://github.com/PrasheelVarma/KernelGuard.git
cd KernelGuard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Usage

Safely execute an untrusted Python script under kernel sandboxing (default enforcement enabled):

```bash
sudo python3 -m kernelguard.cli run script.py
```

Pass custom arguments and select a specific policy:

```bash
sudo python3 -m kernelguard.cli run --policy policy.json script.py arg1 --flag
```

Execute in monitoring-only mode (logs actions without blocking):

```bash
sudo python3 -m kernelguard.cli run --no-enforce script.py
```

Attach monitoring or enforcement to an existing running process by PID:

```bash
sudo python3 -m kernelguard.cli attach --pid <PID> --enforce
```

Monitor supported events system-wide (monitoring only):

```bash
sudo python3 -m kernelguard.cli --pid 0
```

KernelGuard currently monitors and handles:

- `execve` (process tracing)
- `tcp_connect` (IPv4 connection filtering)
- `vfs_write` (filesystem write filtering)

> **Safety note:** In `run` mode, KernelGuard drops child process privileges to the invoking user's `SUDO_UID`/`SUDO_GID` (and supplementary groups) before executing the target script and synchronizes execution via an anonymous pipe until eBPF maps are initialized, establishing confinement before the script begins execution.

---

## 📂 Project Structure

```text
KernelGuard/
├── ebpf/
│   └── execve_trace.c        # Kernel-side eBPF hooks and enforcement logic
├── kernelguard/
│   ├── __init__.py
│   ├── controller.py         # Controller, BCC loader, privilege dropper, event loop
│   ├── policy.py             # JSON policy engine
│   ├── cli.py                # Subcommand CLI (run / attach)
│   ├── logger.py             # Formatted terminal logging and alerts
│   ├── policy.json           # Default policy definition
│   └── ebpf/                 # Package-bundled eBPF source
├── tests/
│   ├── test_cleanup.py       # Signal handling and eBPF cleanup tests
│   ├── test_cli_run.py       # Subcommand parsing and privilege drop tests
│   ├── test_controller.py    # Multi-hook integration test
│   ├── test_enforcement_audit.py # Low-level enforcement audit
│   ├── test_final_validation.py  # End-to-end demonstration validation suite
│   ├── test_interception_audit.py # Multi-file write audit
│   ├── test_performance.py   # Latency benchmarks
│   ├── test_policy_filesystem.py # Filesystem policy & hash equivalence tests
│   └── untrusted_script.py   # Demonstration script with unauthorized operations
├── docs/
│   ├── notes/                # Weekly logs, debugging notes, and testing reports
│   └── diagrams/             # System architecture diagrams
├── kernelguard.service       # systemd service unit (monitoring mode)
├── policy.json               # Default policy definition
├── requirements.txt
├── Makefile
├── pyproject.toml
├── setup.py
├── README.md
└── LICENSE
```

---

## 🗺️ Roadmap & Milestones

- **Week 1 — Foundation ✅:** eBPF/BCC environment established, `execve` tracing implemented, reusable controller.
- **Week 2 — Syscall Hooking & PID Filtering ✅:** Multi-hook interception (`execve`, `tcp_connect`, `vfs_write`), `target_pid_map` filtering, performance verification.
- **Week 3 — Policy Engine & Active Blocking ✅:** JSON policy engine, kernel-side allowlists, `-EPERM` active blocking.
- **Week 4 — Packaging & UX Polish ✅:** `kernelguard run` launcher with privilege separation and startup synchronization barrier, systemd service, cleanup guarantees, comprehensive audit.

---

## 🔒 Security & Scope Considerations

- KernelGuard requires elevated privileges (`sudo`) to load eBPF programs into the kernel.
- Target enforcement is strictly scoped to the specified PID (`target_pid_map`). System-wide enforcement on PID `0` is intentionally disabled for safety.
- Privilege separation restores non-root user credentials (`SUDO_UID`/`SUDO_GID`) for spawned targets.
- This software is an educational security sandbox developed as an internship project and has completed its final release candidate validation.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
