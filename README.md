# KernelGuard 🛡️

**eBPF-Powered Runtime Security Sandbox for Untrusted Python Code**

[![Status](https://img.shields.io/badge/status-in%20development-yellow)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

---

## 📌 Overview

**KernelGuard** is a Linux kernel-level security sandbox for running untrusted Python code — such as third-party pip packages — without exposing the full permissions of the host user. Instead of trying to restrict Python *from within* Python (which is easy to bypass), KernelGuard operates at **Ring 0 (Kernel space)** using **eBPF** to intercept raw system calls made by a target process in real time.

If a monitored script attempts an unauthorized action — opening a network socket, spawning a process, or writing to a protected file — the eBPF program can log it (IDS mode) or block it instantly with `-EPERM` (IPS mode), before the syscall ever completes.

---

## 🎯 Problem Statement

Untrusted Python code — like a downloaded pip package — runs with the full permissions of the user who executes it. If a malicious script attempts to open an unauthorized reverse shell or encrypt files (ransomware-style behavior), standard Python-level sandboxes (e.g., Docker containers, `pysandbox`) are either too heavy to spin up for lightweight checks or too easily bypassed since they operate at the same privilege level as the code they're trying to restrict.

## 💡 The Approach

KernelGuard uses Python's **`bcc`** (BPF Compiler Collection) library to write and load eBPF programs directly into the Linux kernel. These programs hook into low-level system calls — `execve`, `tcp_connect`, `vfs_write` — made by a *specifically targeted* Python process (via PID/cgroup filtering), not the whole system.

Because the enforcement happens in kernel space, it is invisible to and independent of the sandboxed script itself — the target process has no way to detect or disable the monitoring from user space.

---

## 🧩 Key Modules

| Module | Description |
|---|---|
| **eBPF C-Code** | Low-level C programs injected into the Linux kernel to hook into system calls. |
| **Python BPF Controller (`bcc`)** | The Python daemon that compiles the eBPF code, loads it into the kernel, and manages security policies. |
| **cgroups Integration** | Isolates tracing to specifically targeted Python PIDs rather than the whole system. |
| **Security CLI** | Command-line interface to define security policies, e.g. `kernelguard run untrusted.py --block-network`. |

---

## 🏗️ Architecture

```
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
                          └──────────────► allow / log / block (-EPERM) ◄───────┘
                                           targeted at monitored PID only
```

---

## 🛠️ Tech Stack

- **Kernel Layer:** eBPF, C
- **Controller Layer:** Python 3, `bcc`
- **Process Isolation:** Linux `cgroups`
- **CLI:** `argparse` / `Typer`
- **Output/Alerts:** `rich` (colored terminal alerts)
- **Packaging:** `systemd` service

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

### Usage (planned CLI)
```bash
sudo python3 kernelguard.py run untrusted.py --block-network
```

---

## 📂 Project Structure
```
kernelguard/
├── ebpf/
│   └── execve_trace.c        # eBPF C programs
├── kernelguard/
│   ├── __init__.py
│   ├── controller.py         # bcc loader + PID filtering
│   ├── policy.py             # JSON-based policy engine
│   └── cli.py                # CLI entrypoint
├── tests/
├── docs/
│   └── current_plan.md       # Active development tracking (week/day plan, progress)
├── requirements.txt
├── README.md
└── LICENSE
```

---

## 🗺️ Roadmap

KernelGuard is developed over 4 weeks — kernel-level syscall interception, then network/filesystem hooking, then active blocking/policy enforcement, then packaging & polish.

For the current week's tasks, day-by-day progress, and active status, see **[`docs/current_plan.md`](docs/current_plan.md)**.

---

## 🔒 Security Note
This tool interacts directly with the Linux kernel and requires elevated privileges to load eBPF programs. It is intended for controlled sandboxing/research use — always review policies before running untrusted code, and test in an isolated VM before deploying against real workloads.

---

## 📄 License
This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
