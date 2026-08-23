# KernelGuard 🛡️

**eBPF-Powered Runtime Security Sandbox for Untrusted Python Code**

[![Status](https://img.shields.io/badge/status-in%20development-yellow)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

---

## 📌 Overview

**KernelGuard** is a Linux kernel-level security sandbox for running untrusted Python code — such as third-party pip packages — without exposing the full permissions of the host user. Instead of trying to restrict Python *from within* Python (which is easy to bypass), KernelGuard operates at **Ring 0 (Kernel space)** using **eBPF** to intercept raw system calls made by a target process in real time.

If a monitored script attempts an unauthorized action — opening a network socket, spawning a process, or writing to a protected file — the eBPF program can log it (IDS mode) or block it instantly with `-EPERM` (IPS mode). Active blocking is part of the planned policy/enforcement work and is not yet implemented in the current Week 2 monitoring controller.

---

## 🎯 Problem Statement

Untrusted Python code — like a downloaded pip package — runs with the full permissions of the user who executes it. If a malicious script attempts to open an unauthorized reverse shell or encrypt files (ransomware-style behavior), standard Python-level sandboxes (e.g., Docker containers, `pysandbox`) are either too heavy to spin up for lightweight checks or too easily bypassed since they operate at the same privilege level as the code they're trying to restrict.

## 💡 The Approach

KernelGuard uses Python's **`bcc`** (BPF Compiler Collection) library to write and load eBPF programs directly into the Linux kernel. These programs hook into low-level system calls — `execve`, `tcp_connect`, `vfs_write` — made by a *specifically targeted* Python process through PID filtering, not the whole system.

Because the enforcement happens in kernel space, it is invisible to and independent of the sandboxed script itself — the target process has no way to detect or disable the monitoring from user space.

---

## 🧩 Key Modules

| Module | Description |
|---|---|
| **eBPF C-Code** | Low-level C programs loaded into the Linux kernel to hook `execve`, `tcp_connect`, and `vfs_write`. |
| **Python BPF Controller (`bcc`)** | Loads and manages all eBPF hooks, applies target-PID filtering through a BPF map, and provides unified event output. |
| **PID Filtering** | Restricts monitoring to a specific target process using a PID supplied through the CLI. |
| **Security CLI** | Command-line entry point for starting KernelGuard with an optional target PID, e.g. `sudo python3 -m kernelguard.cli --pid <PID>`. |

---

## 🏗️ Architecture

```text
┌─────────────────────┐        loads/compiles        ┌──────────────────────┐
│   Security CLI       │ ───────────────────────────▶ │  Python BPF Controller│
│  (argparse / Typer)  │                               │        (bcc)          │
└─────────────────────┘                               └──────────┬────────────┘
                                                                    │ injects
                                                                    ▼
                                                       ┌──────────────────────┐
                                                       │     eBPF Program      │
                                                       │  (Kernel Space / C)   │
                                                       └──────────┬────────────┘
                                                                    │ hooks
                          ┌─────────────────────────────────────────┴─────────────────────────────┐
                          ▼                          ▼                          ▼
                     execve()                  tcp_connect()               vfs_write()
                (process spawn)              (network access)           (file system write)
                          │                          │                          │
                          └──────────────► log intercepted events ◄──────────────┘
                                           targeted at monitored PID
```

---

## 🛠️ Tech Stack

- **Kernel Layer:** eBPF, C
- **Controller Layer:** Python 3, `bcc`
- **Process Isolation:** Linux PID filtering through a BPF map
- **CLI:** `argparse`
- **Output/Alerts:** Unified terminal event output
- **Packaging:** Planned for later project stages

---

## 🚀 Getting Started

> ⚠️ Requires a Linux environment with kernel headers and BCC installed, matching your exact running kernel (`uname -r`). eBPF program loading requires root privileges.

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

Verify the install:
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

Monitor all supported events:

```bash
sudo python3 -m kernelguard.cli
```

Monitor a specific target process:

```bash
sudo python3 -m kernelguard.cli --pid <PID>
```

The current controller monitors:

- `execve`
- `tcp_connect`
- `vfs_write`

and applies the optional PID filter through the eBPF `target_pid_map`.

---

## 📂 Project Structure

```text
kernelguard/
├── ebpf/
│   └── execve_trace.c        # eBPF hooks: execve, tcp_connect, vfs_write
├── kernelguard/
│   ├── __init__.py
│   ├── controller.py         # BCC loader, PID filtering, unified event handling
│   ├── policy.py             # Policy engine (Week 3)
│   └── cli.py                # CLI entrypoint
├── tests/
│   ├── test_controller.py
│   ├── test_interception_audit.py
│   └── test_performance.py
├── docs/
│   ├── week-2.md             # Week 2 implementation plan
│   └── week-2 logs.md        # Week 2 development log
├── requirements.txt
├── README.md
└── LICENSE
```

---

## 🗺️ Roadmap

KernelGuard is developed over 4 weeks — kernel-level syscall interception, network/filesystem hooking, active blocking/policy enforcement, then packaging and polish.

### Week 1 — Foundation

- eBPF/BCC environment established
- `execve` tracing implemented
- Production controller with error handling
- Initial CLI and project documentation

### Week 2 — Syscall Hooking & PID Filtering ✅

- PID filtering through a BPF map
- `execve` monitoring
- `tcp_connect` monitoring
- `vfs_write` monitoring
- Unified multi-hook controller
- Multi-file interception audit
- eBPF performance verification

### Week 3 — Policy Engine & Active Blocking

- Policy engine
- Rule evaluation
- Active syscall blocking
- `-EPERM` enforcement for unauthorized actions

### Week 4 — Packaging & Polish

- Final integration
- Packaging
- Documentation
- Testing and project cleanup

For detailed day-by-day development progress, see the Week 2 plan and development logs.

---

## 🔒 Security Note

This tool interacts directly with the Linux kernel and requires elevated privileges to load eBPF programs. It is intended for controlled sandboxing/research use — always review policies before running untrusted code, and test in an isolated VM before deploying against real workloads.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
