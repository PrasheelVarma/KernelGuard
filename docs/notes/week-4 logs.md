# KernelGuard — Week 4 Logs

Running notes for Week 4 of KernelGuard development. This file records what was actually completed, issues encountered, fixes applied, and verification performed during the week.

Format: newest entries at the top.

---

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
