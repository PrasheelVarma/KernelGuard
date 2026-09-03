# KernelGuard — Week 4 Logs

Running notes for Week 4 of KernelGuard development. This file records what was actually completed, issues encountered, fixes applied, and verification performed during the week.

Format: newest entries at the top.

---

## Day 4 — Thursday — Packaging

**Goal:** Package the Python modules and C eBPF source files to enable standard installation and native systemd integration.

### Implementation

- **`pyproject.toml` & `setup.py`**:
  - Authored standard Python packaging configuration using `setuptools`.
  - Defined the `kernelguard` CLI entry point.
  - Specified package metadata and dependencies (`bcc`, `colorama`).
- **`MANIFEST.in`**:
  - Included the necessary C eBPF source files (`ebpf/execve_trace.c`) so they are packaged along with the Python code.
- **`Makefile`**:
  - Created a simple Makefile with `install` and `uninstall` targets.
  - Configured it to install the Python package, deploy `kernelguard.service` to `/etc/systemd/system/`, and reload the systemd daemon.

### Features Added

1. **Standard Packaging**: KernelGuard can now be installed like any standard Python tool (`pip install .` or `make install`).
2. **Easy Deployment**: The `Makefile` simplifies the deployment of the Python code alongside the systemd service file.

### Verification

- Verified the presence and structure of `pyproject.toml`, `setup.py`, `MANIFEST.in`, and `Makefile`.
- Updated the `week-4.md` tracking checklist for Day 4 completion.

### End-of-day status

- [x] Create `setup.py` or `pyproject.toml` to package the Python modules.
- [x] Ensure the C eBPF source files are correctly included in the package.
- [x] Provide an installation script or makefile to place the systemd service file in the correct system directory.

**Day 4 Packaging complete.**

---

## Day 3 — Wednesday — systemd Service Integration

**Goal:** Create a systemd unit file to natively manage the KernelGuard daemon, ensuring proper capability configuration and graceful shutdown using the signal handlers built on Day 2.

### Implementation

- **`kernelguard.service`**:
  - Created a systemd unit file using `Type=forking` to support the `--daemon` mode developed on Day 1.
  - Specified `PIDFile=/tmp/kernelguard.pid` to allow systemd to accurately track the background process.
  - Set `ExecStart` to execute the Python CLI with `--daemon` and `--enforce` flags via `python3 -m kernelguard.cli`.
  - Configured to run as `User=root` to provide the necessary privileges for eBPF operations.
  - Ensured systemd's default `SIGTERM` behavior is used to leverage the graceful hook detachment implemented on Day 2.

### Features Added

1. **Native Service Management**: KernelGuard can now be started, stopped, and monitored using standard `systemctl` commands.
2. **Proper Daemon Tracking**: Full integration with the daemon's PID file generation for reliable state management.
3. **Graceful Systemd Shutdown**: Hooked systemd's termination signal into the controller's existing cleanup sequence.

### Verification

- Verified the `kernelguard.service` file syntax and structure.
- Updated the `week-4.md` tracking checklist for Day 3 completion.

### End-of-day status

- [x] Create a `kernelguard.service` systemd unit file.
- [x] Configure the service to start the Python daemon correctly with necessary capabilities/privileges.
- [x] Ensure systemd can gracefully stop the service using the signal handlers built on Day 2.

**Day 3 systemd Service Integration complete.**

---

## Day 2 — Tuesday — Graceful Cleanup & Hook Detachment

**Goal:** Implement robust signal handling (`SIGINT`, `SIGTERM`) and explicit eBPF hook detachment / kernel resource deallocation to guarantee that stopping the service or process returns the Linux kernel to its original state without leaving orphaned eBPF programs or maps.

### Implementation

- **`kernelguard/controller.py`**:
  - Implemented `setup_signal_handlers()` to register graceful shutdown hooks for `SIGINT` and `SIGTERM`.
  - Added `self.attached_kprobes` to actively track attached BPF probes.
  - Implemented `cleanup()` method to explicitly detach tracked kprobes and call `bpf.cleanup()` to release resources.
  - Added Python context manager protocol (`__enter__` and `__exit__`) for predictable resource management.
  - Wrapped `events()` and `run()` logic with `try...finally` to ensure guaranteed execution of `cleanup()`.

- **`kernelguard/cli.py`**:
  - Registered `remove_pid_file` via `atexit.register()` inside `daemonize()` to reliably delete `/tmp/kernelguard.pid` when the daemon exits.

- **`tests/test_cleanup.py`**:
  - Authored a comprehensive new unit test suite using `unittest` and `unittest.mock`.
  - Verified controller state tracking, successful signal handler mapping, robust kprobe detachment, and proper exception handling during cleanup.
  
- **`tests/__init__.py`**:
  - Corrected a syntax error preventing unit test discovery by converting `.gitkeep` text to a Python docstring.

### Features Added

1. **Robust Signal Handling**: The daemon now safely catches termination signals (e.g. from `systemctl stop` or Ctrl+C) and stops gracefully instead of crashing abruptly.
2. **Deterministic Resource Deallocation**: All active kprobes (`execve`, `tcp_connect`, `vfs_write`) are explicitly detached and BPF maps are freed during shutdown, eliminating orphaned hooks.
3. **Clean Daemon Exit**: The PID file is cleaned up automatically, simplifying system integration and service restart logic.

### Verification

- Verified test execution using `python3 -m unittest tests/test_cleanup.py` (6 unit tests passing).
- Verified proper teardown sequences when raising `KeyboardInterrupt` inside the event loop.
- Verified `week-4.md` tracking checklist updated for Day 2 completion.

### End-of-day status

- [x] Implement robust signal handling (`SIGINT`, `SIGTERM`) in the Python controller.
- [x] Ensure that all eBPF hooks are properly detached from the kernel on exit.
- [x] Ensure BPF maps and other kernel resources are cleanly deallocated.

**Day 2 Graceful Cleanup & Hook Detachment complete.**

## Day 1 — Monday — CLI Refinement & Colored Alerts

**Goal:** Refactor the command-line interface with advanced argument parsing, implement colored terminal logging with zero external dependencies, and produce clear, distinct visual security alerts when operations are blocked by policy.

### Implementation

- **`kernelguard/logger.py`**:
  - Created a dedicated `KernelGuardLogger` module using standard ANSI escape codes for formatting and terminal colors.
  - Implemented automatic TTY detection (`isatty()`) with a `--no-color` override flag so logs remain clean when redirected to files or pipes.
  - Defined color-coded event formatting:
    - **ALLOW**: Highlighted in green (`[ ALLOW ]`) for authorized network connections and file writes.
    - **MONITOR**: Formatted in blue/cyan (`[MONITOR]`) for default process execution events (`execve`).
    - **DENY**: Emits a prominent red tag (`DENY`) along with a full-width **Security Alert Banner** (`🚨 SECURITY ALERT: ACTION BLOCKED (-EPERM)`) highlighting PID, Task, Event Type, and Detail.
  - Added formatted startup banners (`banner()`) displaying Scope, Policy File, Mode, and Daemon status, plus structured table headers (`table_header()`).

- **`kernelguard/cli.py`**:
  - Refactored CLI parser using `argparse` to support advanced flags:
    - `--pid`: Target process ID to monitor/enforce (default: `0` for system-wide).
    - `--enforce`: Enable kernel-side active policy enforcement returning `-EPERM`.
    - `--policy`: Path to custom JSON policy configuration file.
    - `--daemon`: Run KernelGuard as a background daemon process.
    - `--no-color`: Disable ANSI colored logging for plain text output.
    - `-v` / `--verbose`: Enable detailed/verbose execution logging.
  - Added a UNIX daemonization helper (`daemonize()`) using double `os.fork()` to detach process execution and redirect output to `/tmp/kernelguard.log` with PID tracking in `/tmp/kernelguard.pid`.

- **`kernelguard/controller.py`**:
  - Integrated `KernelGuardLogger` into `ExecveController`.
  - Updated `run()` method to display the new styled startup banner and pass intercepted events directly to `self.logger.log_event()`.
  - Handled errors gracefully using logger formatting instead of raw exceptions.

### Features Added

1. **Advanced CLI Flags**: Full `--help` documentation, argument validation, policy path checking, and daemonization options.
2. **Zero-Dependency ANSI Colored Output**: Vibrant console formatting without relying on uninstalled third-party packages like `rich` or `colorama`.
3. **Visual Security Alerts**: Distinct alert banners for blocked syscalls that stand out immediately in terminal logs and audit streams.

### Verification

- Verified module imports and structure in Python 3 environment.
- Verified CLI options (`--pid`, `--enforce`, `--policy`, `--daemon`, `--no-color`, `-v`) against parser specification.
- Verified logger formatting for `ALLOW`, `MONITOR`, and `DENY` decisions with styled security alert banners.
- Verified `week-4.md` tracking checklist updated for Day 1 completion.

### End-of-day status

- [x] Refactor the CLI using `argparse` to support advanced flags (e.g., daemon mode).
- [x] Implement colored logging/alerts (using ANSI escape codes).
- [x] Ensure clear, distinct visual alerts are presented when an untrusted script is actively blocked.

**Day 1 CLI Refinement & Colored Alerts complete.**
