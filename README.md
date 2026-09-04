# KernelGuard 🛡️

**eBPF-based runtime security sandbox for untrusted Python processes**

[![Status](https://img.shields.io/badge/status-in%20development-yellow)]()
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

The project is currently under development and is being tested and refined as the implementation progresses.

---

## 🎯 Problem Statement

Python code from untrusted sources, such as third-party packages or downloaded scripts, normally runs with the permissions available to the process that executes it.

A program with those permissions may be able to access the network, start other processes, or write to files that it should not modify.

KernelGuard explores a lightweight kernel-level approach where selected activity from a target process can be observed and, when enforcement is enabled, restricted according to a policy.

---

## 💡 The Approach

KernelGuard uses Python's **`bcc`** (BPF Compiler Collection) library to load and manage eBPF programs in the Linux kernel.

The current implementation uses eBPF hooks for:

- `execve` for process execution
- `tcp_connect` for network connections
- `vfs_write` for filesystem writes

A BPF map is used to provide target-process filtering. When a target PID is specified, the enforcement and monitoring logic can be limited to that process.

The enforcement system can use policy data to allow or deny supported operations. Unauthorized operations can be rejected with `-EPERM`.

---

## 🧩 Key Modules

| Module | Description |
|---|---|
| **eBPF C-Code** | Kernel-side eBPF programs used for process, network, and filesystem monitoring and enforcement. |
| **Python BPF Controller (`bcc`)** | Loads and manages the eBPF programs, configures BPF maps, applies policy data, and handles events. |
| **PID Filtering** | Provides process-level targeting through a PID supplied to the CLI. |
| **Policy Engine** | Loads policy rules and prepares the corresponding allowlists and enforcement state. |
| **Security CLI** | Command-line entry point for starting KernelGuard with monitoring, enforcement, policy, and target-PID options. |

---

## 🏗️ Architecture

```text
┌─────────────────────┐
│    Security CLI     │
│      argparse       │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────┐
│  Python BPF Controller  │
│          (bcc)          │
└──────────┬──────────────┘
           │ loads / configures
           ▼
┌─────────────────────────┐
│       eBPF Programs     │
│    Linux Kernel Space   │
└──────────┬──────────────┘
           │
     ┌─────┼──────────┐
     ▼     ▼          ▼
  execve  tcp_connect  vfs_write
     │     │          │
     └─────┼──────────┘
           ▼
     Event / Policy
       Processing
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
- **Process Targeting:** Linux PID filtering through a BPF map
- **Policy:** JSON policy configuration and Python policy handling
- **CLI:** `argparse`
- **Output:** Terminal event and security logging
- **Packaging:** Python package with a dedicated virtual environment

---

## 🚀 Getting Started

> ⚠️ KernelGuard requires a Linux environment with the required kernel support and BCC installation. Loading eBPF programs and enabling enforcement requires elevated privileges.

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

Monitor supported events:

```bash
sudo python3 -m kernelguard.cli
```

Monitor a specific target process:

```bash
sudo python3 -m kernelguard.cli --pid <PID>
```

Enable enforcement for a target process:

```bash
sudo python3 -m kernelguard.cli --pid <PID> --enforce
```

Use a specific policy:

```bash
sudo python3 -m kernelguard.cli --pid <PID> --enforce --policy policy.json
```

KernelGuard currently monitors and handles:

- `execve`
- `tcp_connect`
- `vfs_write`

Target-process filtering is provided through the eBPF `target_pid_map`.

> **Development note:** Active enforcement can affect real system operations depending on the target scope and policy. Review the policy and target PID before enabling enforcement.

---

## 📂 Project Structure

```text
KernelGuard/
├── ebpf/
│   └── execve_trace.c        # eBPF hooks and kernel-side logic
├── kernelguard/
│   ├── __init__.py
│   ├── controller.py         # BCC loader, policy setup, PID filtering, event handling
│   ├── policy.py             # Policy engine
│   ├── cli.py                # CLI entrypoint and daemon handling
│   └── logger.py             # Logging and terminal output
├── tests/
│   ├── test_controller.py
│   ├── test_interception_audit.py
│   └── test_performance.py
├── docs/
│   ├── week-2.md             # Development plan
│   └── week-2 logs.md        # Development log
├── policy.json
├── requirements.txt
├── Makefile
├── pyproject.toml
├── setup.py
├── README.md
└── LICENSE
```

---

## 🗺️ Roadmap

KernelGuard is being developed over 4 weeks, covering kernel-level event interception, network and filesystem monitoring, policy-based enforcement, packaging, testing, and project cleanup.

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

### Week 3 — Policy Engine & Active Blocking ✅

- Policy engine
- Rule evaluation
- Active syscall blocking
- `-EPERM` enforcement for unauthorized actions

### Week 4 — Packaging & Polish

- Final integration
- Packaging
- Documentation
- Testing and project cleanup

The Week 4 work is still in progress. The roadmap will be updated after the planned implementation is completed.

For detailed development progress, implementation notes, and logs, see the documentation in the `docs/` directory.

---

## 🔒 Security Note

KernelGuard loads eBPF programs into the Linux kernel and requires elevated privileges for active enforcement.

This project is currently under development and should only be used for controlled testing. Review the policy and target scope before enabling enforcement, especially when running KernelGuard directly on a host system.

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
