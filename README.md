# KernelGuard 🛡️

**eBPF-Powered Runtime Security Sandbox for Untrusted Python Code**

[![Status](https://img.shields.io/badge/status-in%20development-yellow)]()
[![Week](https://img.shields.io/badge/week-1%2F4-blue)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey)]()
[![License](https://img.shields.io/badge/license-MIT-green)]()

---

## 📌 Overview

**KernelGuard** is a Linux kernel-level security sandbox for running untrusted Python code — such as third-party pip packages — without exposing the full permissions of the host user. Instead of trying to restrict Python *from within* Python (which is easy to bypass), KernelGuard operates at **Ring 0 (Kernel space)** using **eBPF** to intercept raw system calls made by a target process in real time.

If a monitored script attempts an unauthorized action — opening a network socket, spawning a process, or writing to a protected file — the eBPF program can log it (IDS mode) or block it instantly with `-EPERM` (IPS mode), before the syscall ever completes.

> This is **Project 3** of the *Advanced Python Engineering* track at Infotact Solutions, following **PyChronicle** (Project 1 — completed) and preceding **MeshWeaver** (Project 2).

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

## 🗓️ Week-wise Development Plan

### Week 1 — Foundations
| Track | Task |
|---|---|
| Kernel Engineering (C, eBPF) | **eBPF Foundations** — Write a basic eBPF C program that intercepts the `execve` (process execution) syscall. |
| Python Controller (bcc, argparse) | **BCC Integration** — Write the Python `bcc` script that loads the C program into the kernel and prints intercept logs to the console. |

### Week 2 — Expansion
| Track | Task |
|---|---|
| Kernel Engineering | **Syscall Hooking** — Expand the eBPF code to hook into `tcp_connect` (network) and `vfs_write` (file system). |
| Python Controller | **PID Filtering** — Update the Python daemon to pass a specific target PID to the kernel, ensuring only that process is monitored. |

**Mid-Project Review**
- **Interception Audit:** Prove the tool can successfully log every file a target Python script attempts to write to.
- **Performance Check:** Ensure eBPF hooks add negligible latency (< 1ms) to system calls.

### Week 3 — Enforcement
| Track | Task |
|---|---|
| Kernel Engineering | **Active Blocking** — Upgrade the eBPF program from an IDS (logging) to an IPS (blocking). Return `-EPERM` for unauthorized syscalls. |
| Python Controller | **Policy Engine** — Build a JSON-based policy engine allowing users to define exactly which IP addresses or file paths are allowed. |

### Week 4 — Packaging & Polish
| Track | Task |
|---|---|
| Kernel Engineering | **Packaging** — Package the daemon as a `systemd` service. Ensure it gracefully cleans up kernel hooks on exit. |
| Python Controller | **Refine & Polish** — Finalize the CLI, with clear, colored alert messages when an untrusted script is blocked. |

### Final Deliverable
A production-ready, kernel-level security sandbox — invisible to the target script — paired with a robust Python security wrapper (`kernelguard`) for safely executing untrusted dependencies.

---

## ✅ Current Progress

- [x] **Day 1:** Repository initialized.
- [x] **Day 2 (today):** Project documentation (this README).
- [ ] eBPF C program to intercept `execve`.
- [ ] Python `bcc` controller script.
- [ ] Console logging of intercepted events.

---

## 🚀 Getting Started

> ⚠️ Requires a Linux environment with kernel headers and BCC installed. eBPF development typically requires root privileges.

### Prerequisites
```bash
# Debian/Ubuntu/Arch 
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
```

### Clone & Setup
```bash
git clone https://github.com/PrasheelVarma/KernelGuard.git
cd kernelguard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Usage (planned CLI)
```bash
sudo python3 kernelguard.py run untrusted.py --block-network
```

---

## 📂 Project Structure (proposed)
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
├── requirements.txt
├── README.md
└── LICENSE
```

---

## 🔒 Security Note
This tool interacts directly with the Linux kernel and requires elevated privileges to load eBPF programs. It is intended for controlled sandboxing/research use — always review policies before running untrusted code, and test in an isolated VM before deploying against real workloads.

---

## 🏢 Internship Context
This project is being developed as part of an Advanced Python Engineering internship track at **Infotact Solutions**.

## 📄 License
This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
