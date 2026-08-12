# KernelGuard — Dev Log & Learnings

Running notes on environment setup, manual tweaks, gotchas, and things learned along the way that don't show up in the code itself. Unlike `docs/current_plan.md` (which tracks *what's planned* and gets overwritten as the project moves forward), this file is **append-only** — a permanent record of what was actually done and why.

Format: newest entries at the top.

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

### Question raised — "Should this be isolated in a venv?"
Asked whether `bcc` should be installed inside a Python venv instead of system-wide, out of caution about modifying the base OS.
- **Answer:** No — and this isn't really a choice, it's a constraint of what `bcc` *is*. `python-bcc` is a thin wrapper around `libbcc.so`, a compiled system library that pacman installs to `/usr/lib`. A venv only isolates pip-installed Python packages — it has no concept of system shared libraries. Even from inside a venv, `from bcc import BPF` still needs `libbcc.so` to exist on the system, so the C library (and its Python bindings) will always effectively be "global." This is normal for anything binding directly to the kernel (same category as GPU drivers, `python-systemd`, etc.).
- **Resulting workflow going forward:**
  - **Project code + pure-Python deps** (`typer`, `rich`, our own `kernelguard` package) → managed inside `venv`, as normal.
  - **`bcc`/eBPF loading** → always run with `sudo python3` using the **system** Python, since it needs root privileges to load into the kernel and needs the system-level compiled bindings. The venv's Python won't have access to `bcc` even if activated.

### End-of-day status
- ✅ `sudo execsnoop` — confirmed working, live syscall tracing verified.
- ✅ `sudo python3 -c "from bcc import BPF; print('BCC import OK')"` — confirmed working.
- Environment is ready for Day 4: writing `ebpf/execve_trace.c`.

---

## Day 2 — Tuesday — Documentation
- Created `README.md`, `LICENSE` (MIT), `.gitignore`.
- Scaffolded project structure (`ebpf/`, `kernelguard/`, `tests/`, `requirements.txt`).
- Decided on doc split going forward: `README.md` = stable, professional-facing doc. `docs/current_plan.md` = living tracker (week/day tasks, checkboxes), replaced or removed once the project is finished. `docs/notes/DEV_LOG.md` (this file) = permanent append-only log of setup steps, gotchas, and decisions.

## Day 1 — Monday — Repo Init
- Repository created on GitHub.
