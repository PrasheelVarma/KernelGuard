# KernelGuard — Dev Log & Learnings

Running notes on environment setup, manual tweaks, gotchas, and things learned along the way that don't show up in the code itself. Unlike `docs/current_plan.md` (which tracks *what's planned* and gets overwritten as the project moves forward), this file is **append-only** — a permanent record of what was actually done and why.

Format: newest entries at the top.

---
## Supplementary : Architecture & Flow Diagrams

**Goal:** Produce visual documentation of the system design to accompany the written docs.

### Deliverables
- `docs/diagrams/architecture_diagram.svg` — system architecture showing user space (Security CLI → Python BPF Controller → Policy Engine) versus kernel space (eBPF program hooking `execve`, `tcp_connect`, `vfs_write`), replacing the ASCII version previously embedded in `README.md`.
- `docs/diagrams/execve_flow_diagram.svg` — step-by-step flow of `execve()` interception: kernel kprobe trigger → `trace_execve()` execution → PID filter decision point (Week 2) → event emission → `ExecveController.events()` → policy enforcement decision point (Week 3).
- `docs/diagrams/roadmap_diagram.svg` — 4-week development roadmap as a milestone timeline, with Week 1 marked complete.

### Notes
- The flow diagram intentionally includes decision points for features not yet built (PID filtering, policy enforcement) to serve as a visual reference for upcoming Week 2–3 work, not just a record of what already exists.
- SVG format chosen for direct rendering support in GitHub-flavored markdown.

---

## Day 6 — Saturday — Output Polish & Error Handling

**Goal for the day:** Refine console output and add proper error handling to the controller.

### Implementation
- Replaced raw kernel timestamps with wall-clock time (`HH:MM:SS`) for readability.
- Added a column header + separator line to the console output.
- Introduced a `ControllerError` exception hierarchy:
  - `InsufficientPrivilegesError` — raised via an explicit `os.geteuid() != 0` check before attempting to load, producing a clear message instead of an opaque kernel permission failure.
  - `BPFLoadError` — wraps both the compile step and kprobe-attach step, surfacing readable errors instead of raw tracebacks on failure.
- `run()` catches `ControllerError` and exits cleanly with a message and non-zero exit code rather than crashing.
- Trace field decoding now uses `errors="replace"` to avoid crashes on malformed process names.

### Observation — `<...>` in process name column
Some intercepted events show `<...>` instead of a process name. This is a known BCC/kernel behavior, not a bug: very short-lived processes can trigger the kprobe before the kernel's task info is fully resolvable, so the process name isn't available at capture time.

### Verification
- Ran `sudo python3 -m kernelguard.controller` — confirmed clean, aligned table output across a range of processes (`bash`, `sh`, `auto-cpufreq`, `cpufreqctl.auto`, `grep`, `cat`, etc.), and graceful shutdown on `Ctrl+C`.
- Ran `python3 -m kernelguard.controller` (without `sudo`) — confirmed clean error message (`Error: eBPF programs require root privileges to load. Re-run with 'sudo'.`) and non-zero exit, no traceback.

### End-of-day status
- ✅ Console output polished and readable.
- ✅ Error handling verified for both the privilege-check and no-sudo paths.
- Ready for Day 7: end-to-end retest, commit/push, and Week 1 wrap-up.

---

## Day 5 — Friday — BCC Controller

**Goal for the day:** Replace the Day 4 verification loader with a permanent, reusable controller module.

### Implementation
- `kernelguard/controller.py` — introduces `ExecveController`, a class wrapping the eBPF load/attach lifecycle:
  - `load()` — compiles `ebpf/execve_trace.c` and attaches the kprobe.
  - `events()` — generator yielding decoded trace events as structured dicts (`pid`, `task`, `message`, `timestamp`, `cpu`).
  - `run()` — convenience method for console output, used by the CLI entry point.
- eBPF source path is resolved relative to the package location (`Path(__file__).resolve().parent.parent / "ebpf" / "execve_trace.c"`), removing the working-directory assumption the Day 4 script had.
- `test_load.py` retired; its functionality is fully superseded by this module.

### Design note — generator-based event API
`events()` yields structured data rather than printing directly, so downstream components (the Week 3 policy engine, future syscall hooks) can consume trace data programmatically instead of parsing console text.

### Verification
- Ran via `sudo python3 -m kernelguard.controller`.
- Confirmed correct, live-formatted `execve` trace output matching Day 4 results.

### End-of-day status
- ✅ `kernelguard/controller.py` — production controller module, verified working.
- Ready for Day 6: output polish and error handling.

---

## Day 4 — Thursday — eBPF Foundations

**Goal for the day:** Write a minimal eBPF C program that hooks the `execve` syscall, and verify it loads and traces correctly.

### Implementation
- `ebpf/execve_trace.c` — a kprobe attached to `execve`, using `bpf_get_current_pid_tgid()` and `bpf_get_current_comm()` to capture the calling process's PID and name, emitted via `bpf_trace_printk()`.
- `test_load.py` — a loader script using BCC to compile the C program, attach it via `attach_kprobe()`, and stream trace output to the console. Serves as the verification step for today; will be superseded by `kernelguard/controller.py` on Day 5.

### Issue 1 — Literal `\n` appearing in output instead of a newline
Initial version of `execve_trace.c` used `\\n` (double backslash) in the `bpf_trace_printk()` format string, which produced a literal backslash-n in the trace output rather than a line break.
- **Fix:** Corrected to a single `\n`.

### Issue 2 — Raw byte-string output (`b'...'`) instead of clean text
Using `b.trace_print()` in the loader printed raw Python byte-string representations of each trace line.
- **Fix:** Switched to `b.trace_fields()`, which parses each trace line into its individual fields (task, PID, CPU, timestamp, message) and returns them decoded, allowing a custom formatted print.

### Verification
- Loaded and attached the eBPF program successfully via `sudo python3 test_load.py`.
- Confirmed live interception of `execve()` calls system-wide, correctly reporting PID and process name for a range of processes (shell invocations, `auto-cpufreq`, `cpufreqctl.auto`, `grep`, `wc`, etc.) with clean, readable output after the fixes above.

### End-of-day status
- ✅ `ebpf/execve_trace.c` — compiles and runs correctly.
- ✅ `test_load.py` — loads the program, attaches the kprobe, and prints clean live trace output.
- Ready for Day 5: converting the verification loader into the permanent `kernelguard/controller.py`.

---

## Day 3 — Wednesday — Environment Setup (BCC / eBPF)

**Goal for the day:** Get a working BCC + eBPF toolchain on the dev machine before writing any custom code.

### System
- OS: EndeavourOS (Arch-based)
- Kernel: `linux` (plain, not `-lts` or `-zen`)
- Python: 3.14.7

### Issue 1 — Mirror timeout during `pacman -Sy`
`core.db` failed to download from a Fastly mirror (connection timeout). Packages `endeavouros`, `core`, `extra`, `multilib` had already synced 100% before the error hit on a retry — turned out to be a transient mirror issue, not a real failure.
- **Fix:** Simple retry of `pacman -Sy` resolved it. (Alternative if it persists: `reflector` to regenerate the mirrorlist with faster/closer mirrors.)

### Issue 2 — Kernel headers version mismatch
After installing `linux-headers`, the installed headers version (`7.1.8.arch1-3`) didn't match the *running* kernel (`uname -r` → `7.1.5-arch1-2`).
- **Why:** Arch is a rolling release — the `linux` package in the repos had moved ahead of what was actually booted, since a kernel update hadn't been applied+rebooted into yet.
- **Fix:** `sudo pacman -Syu` (full system upgrade, not just headers) → **reboot** → re-verified both `uname -r` and `pacman -Qi linux-headers` matched (`7.1.8` both).
- **Lesson:** Never do a partial upgrade (installing/upgrading a single package without a full `-Syu`) on Arch — it can cause exactly this kind of version drift between the running kernel and installed headers/modules.

### Issue 3 — BCC tool naming differs from Debian/Ubuntu tutorials
Most online BCC guides reference tools like `execsnoop-bpfcc` (Debian/Ubuntu naming convention, suffixed to avoid package clashes). On Arch, the `bcc-tools`/`bcc-libbpf-tools` package installs the same tools **without the suffix**.
- **Fix:** Use `execsnoop` (not `execsnoop-bpfcc`) on Arch. Confirmed via `pacman -Ql bcc-tools | grep bin` — full tool is installed at `/usr/bin/execsnoop`.
- **Verified working:** `sudo execsnoop` correctly live-traced `execve()` calls system-wide (caught background processes like `auto-cpufreq` polling `/proc/cpuinfo`, and the test terminal itself spawning).

### Issue 4 — `from bcc import BPF` failed with `ModuleNotFoundError`
Even with `bcc` installed via pacman, `sudo python3 -c "from bcc import BPF"` failed. Diagnosis:
- `pacman -Ql bcc | grep site-packages` → returned nothing (no Python files in the `bcc` package at all).
- `pacman -Qi bcc` → Installed Size: 2.73 MiB — far too small to include Python bindings.
- `pacman -Ss bcc` revealed the real cause: **Arch splits `bcc` into separate packages** —
  - `bcc` → just the C library + headers
  - `bcc-libbpf-tools` → the prebuilt CLI tools (execsnoop, opensnoop, etc.)
  - `python-bcc` → the actual Python bindings (**this was missing**)
- **Fix:** `sudo pacman -S python-bcc` → re-ran the import test → `BCC import OK`.
- **Lesson:** On Arch, always check `pacman -Ss <pkgname>` for split packages before assuming something's broken — Arch tends to separate bindings/tools/libraries into distinct packages more aggressively than Debian/Ubuntu.

### Design note — Python environment strategy for `bcc`
`python-bcc` is a thin wrapper around `libbcc.so`, a compiled system library installed by pacman to `/usr/lib`. A venv only isolates pip-installed Python packages and has no concept of system shared libraries — so `bcc` cannot be meaningfully isolated in a venv; it is inherently a system-level dependency, consistent with other kernel-facing bindings (GPU drivers, `python-systemd`, etc.).

**Resulting workflow:**
- **Project code + pure-Python deps** (`typer`, `rich`, the `kernelguard` package) → managed inside a `venv`, as normal.
- **`bcc`/eBPF loading** → always run with `sudo python3` using the system Python, since it requires root privileges and the system-level compiled bindings.

### End-of-day status
- ✅ `sudo execsnoop` — confirmed working, live syscall tracing verified.
- ✅ `sudo python3 -c "from bcc import BPF; print('BCC import OK')"` — confirmed working.
- Environment ready for Day 4.

---

## Day 2 — Tuesday — Documentation
- Created `README.md`, `LICENSE` (MIT), `.gitignore`.
- Scaffolded project structure (`ebpf/`, `kernelguard/`, `tests/`, `requirements.txt`).
- Established documentation split: `README.md` = stable, professional-facing doc. `docs/current_plan.md` = living tracker (week/day tasks, checkboxes), replaced or removed once the project is finished. `docs/notes/DEV_LOG.md` (this file) = permanent append-only log of setup steps, gotchas, and decisions.

## Day 1 — Monday — Repo Init
- Repository created on GitHub.
