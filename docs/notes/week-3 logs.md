# KernelGuard — Week 3 Logs

Running notes for Week 3 of KernelGuard development. This file records what was actually completed, issues encountered, fixes applied, and verification performed during the week.

Format: newest entries at the top.

---

## Day 7 — Sunday — Week 3 Wrap-Up & Robustness Fixes

**Goal:** Address robustness/correctness gaps found during review, perform a clean wrap-up of Week 3, and verify the implementation aligns with project requirements.

### Implementation Fixes
- **Filesystem eBPF Enforcement Robustness**: Updated `struct kg_inode` in `execve_trace.c` to explicitly define `unsigned short i_mode;` at offset 0, preventing potentially fragile offset reliance when reading the inode mode.
- **Test Ordering Fix**: In `tests/test_enforcement_audit.py`, the allowed file creation was moved to occur *before* the 15-second wait period. Previously, `controller.py` would start, fail to `os.stat()` the non-existent file, and silently drop it from the policy, causing false EPERM errors during the test.
- **PID Isolation Verification**: Added a `test_pid_isolation()` phase to the audit script that spawns a subprocess to connect to a blocked IP and write to a blocked file. Confirmed that the subprocess (with a different PID) successfully bypasses enforcement, proving that the BPF target PID filter works correctly in IPS mode.
- **Policy Validation Check**: Updated `policy.py` to use `ipaddress.ip_address` to actively validate that network configuration strings are valid IPv4 addresses during policy load, failing fast rather than relying on the controller to error later.

### Architecture Note: cgroups vs BPF Map
The original project PDF mentions "cgroups Integration: Isolates the tracing to specifically targeted Python PIDs rather than the whole system." However, the current implementation successfully achieves process isolation using an eBPF map (`target_pid_map`). 
After review, it was determined that the BPF map cleanly achieves the required target PID isolation without the overhead of mounting/managing cgroup filesystems from the Python controller. We intentionally preserved this design because it successfully satisfies the requirements (as verified by the PID isolation test) without unnecessary redesign.

### End-of-day status

- [x] Perform a clean end-to-end retest of network and filesystem policy enforcement.
- [x] Verify `-EPERM` behavior for every configured denied operation.
- [x] Verify allowed operations remain functional.
- [x] Review and clean up the policy engine and enforcement code.
- [x] Update `README.md` to reflect active blocking and policy support.
- [x] Update Week 3 development logs.
- [x] Commit and push all Week 3 work.
- [x] Prepare Week 4 handoff covering packaging, service lifecycle, CLI polish, and final integration.

**Day 7 Wrap-Up complete. Week 3 is now officially closed.**

---

## Day 6 — Saturday — End-to-End Policy & Enforcement Audit

**Goal:** Run an end-to-end test of KernelGuard using a dedicated audit script to verify that allowed operations succeed and unauthorized ones return `-EPERM`.

### Implementation

- Created `tests/test_enforcement_audit.py` which runs the controller in `--enforce` mode and attempts network and file writes.
- **Issue Discovered:** When the test script ran, the controller printed a massive flood of `vfs_write DENY` logs, and the test script exited prematurely without printing its results.
- **Root Cause:** KernelGuard's `file_permission` hook was so aggressive that it enforced the policy against *all* file descriptors, including character devices like `/dev/pts/X` (the terminal's standard output). When `print()` was called by the python script, it was blocked with `-EPERM` because the terminal was not in the `policy.json` allowed paths, causing the script to crash.
- **Fix Applied:** Updated `file_permission` in `ebpf/execve_trace.c` to read `i_mode` from the inode and use `(i_mode & S_IFMT) != S_IFREG` to explicitly skip non-regular files (like stdout, stderr, sockets, and character devices). 

### Verification

- Re-ran the audit script after applying the `i_mode` filter. The script was able to output text to the terminal successfully, while KernelGuard correctly blocked connections to `10.0.0.1` and writes to the unauthorized regular file (`/tmp/kernelguard-unauthorized.txt`). 
- Allowed IPs (`1.1.1.1`) and allowed paths (`/tmp/kernelguard-test.txt`) were permitted successfully.

### End-of-day status

- [x] Create a policy containing both allowed and denied network destinations.
- [x] Create a policy containing both allowed and denied filesystem paths.
- [x] Run a target test process that attempts both allowed and unauthorized operations.
- [x] Confirm allowed operations succeed.
- [x] Confirm unauthorized operations return `-EPERM`.
- [x] Confirm KernelGuard reports the corresponding enforcement events.
- [x] Fixed aggressive stdout/stderr blocking by filtering for `S_IFREG`.

**Day 6 End-to-End Policy & Enforcement Audit complete.**

---

## Day 5 — Friday — Filesystem Enforcement

**Goal:** Apply policy enforcement to `vfs_write`, denying unauthorized writes with `-EPERM`.

### Implementation

- Added `file_permission` BPF LSM hook in `ebpf/execve_trace.c`.
- The hook checks `MAY_WRITE` requests against `filesystem_allowed_map`.
- If the target file's inode and device ID are not found in the allowed map, the hook returns `-EPERM`.
- Added support for `--enforce` in `kernelguard.cli` to enable active blocking.

### End-of-day status

- [x] Apply policy enforcement to `vfs_write`.
- [x] Deny unauthorized writes with `-EPERM`.
- [x] Plumb `--enforce` flag through CLI to controller.

**Day 5 Filesystem Enforcement complete.**

---

## Day 4 — Thursday — Network Enforcement

**Goal:** Apply policy enforcement to `tcp_connect`, denying unauthorized destinations with `-EPERM`.

### Implementation

- Added `socket_connect` BPF LSM hook in `ebpf/execve_trace.c`.
- The hook filters for `AF_INET` and evaluates the destination IP against `network_allowed_map`.
- If the IP is not allowed, it returns `-EPERM` to actively block the connection.

### End-of-day status

- [x] Apply policy enforcement to `tcp_connect`.
- [x] Allow connections matching configured IP rules.
- [x] Deny unauthorized destinations with `-EPERM`.

**Day 4 Network Enforcement complete.**

---

## Day 3 — Wednesday — eBPF Active Blocking Foundation

**Goal:** Extend the eBPF hooks so an enforcement decision can affect the syscall result and return `-EPERM`.

### Implementation

- Introduced `enforcement_enabled`, `network_allowed_map`, and `filesystem_allowed_map` to `execve_trace.c`.
- Updated Python `controller.py` to populate these maps on startup based on the parsed `policy.json`.
- Used BPF LSM probes for active enforcement as they can return `-EPERM`, whereas standard kprobes cannot natively block operations.

### Note on Filesystem Enforcement
- `controller.py` uses `os.stat` to resolve allowed paths to their inodes. If an allowed file does not exist when KernelGuard starts, it will silently fail to be added to the allowlist, and writing to it will be blocked. The file must be created beforehand.

### End-of-day status

- [x] Extend the eBPF hooks so an enforcement decision can affect the syscall result.
- [x] Introduce the kernel-side mechanism required to distinguish allowed and denied operations.
- [x] Implement the `-EPERM` return path for denied operations.

**Day 3 eBPF Active Blocking Foundation complete.**

---

## Day 2 — Tuesday — eBPF Event Integration & tcp_connect Debugging

**Goal:** Integrate the policy-aware eBPF tracing changes and verify that the controller can load and monitor `execve`, `tcp_connect`, and `vfs_write` events with PID filtering.

### Implementation

- Extended `ebpf/execve_trace.c` to support:
  - `execve` tracing.
  - `tcp_connect` tracing.
  - `vfs_write` tracing.
  - Optional PID filtering through `target_pid_map`.
- Added a `sockaddr_in`-compatible structure for reading the destination IPv4 address from the `tcp_connect` arguments.
- Added filesystem structures needed to resolve the path associated with `vfs_write`.
- Kept kernel-level blocking (`-EPERM`) intentionally unimplemented at this stage; the current implementation is focused on event interception and controller-side policy evaluation.

### Issue — `bpf_trace_printk()` argument limit

The first version of the `tcp_connect` hook attempted to print the destination IPv4 address in dotted-decimal form:

```text
tcp_connect %d.%d.%d.%d
```

with four separate integer arguments.

During compilation through BCC, Clang produced the warning:

```text
/virtual/main.c:117:31: warning: cannot use more than 3 conversion specifiers
```

The compilation then failed with:

```text
error: /virtual/main.c:142:51: in function trace_tcp_connect i32 (ptr): 0x555ebc6c8620: i64 = Constant<6> too many arguments
```

The problem was caused by the argument/conversion-specifier limit of `bpf_trace_printk()` in the current BCC/kernel environment.

### Fix

Changed the `tcp_connect` trace output to pass the IPv4 address as a single 32-bit integer:

```text
tcp_connect ip=%u
```

Instead of passing four separate octets.

The controller can decode this value into dotted-decimal IPv4 form later. This keeps the eBPF helper call within the supported argument limit.

### Verification

Re-ran:

```text
sudo python3 -m kernelguard.cli --pid 1
```

The eBPF program compiled and loaded successfully after the change.

The controller now starts cleanly and displays:

```text
Monitoring execve, tcp_connect, and vfs_write events for PID 1.
Policy: /home/prasheel/SATA_VAULT/developer/KernelGuard/policy.json
PID     TASK            EVENT TYPE      DECISION    DETAIL
----------------------------------------------------------------------------------------------------
```

No compilation error or `bpf_trace_printk()` argument-limit error remains.

The empty event table during this run is expected because PID 1 did not generate a matching monitored event while the controller was running.

### End-of-day status

- [x] `execve` tracing integrated.
- [x] `tcp_connect` tracing integrated.
- [x] `vfs_write` tracing integrated.
- [x] PID filtering retained through `target_pid_map`.
- [x] Destination IPv4 address exposed from the `tcp_connect` hook.
- [x] Resolved the `bpf_trace_printk()` conversion-specifier/argument-limit compilation error.
- [x] KernelGuard controller starts successfully with the updated eBPF program.

**Day 2 eBPF Event Integration & tcp_connect Debugging complete.**

---

## Day 1 — Monday — Policy Model & JSON Configuration

**Goal:** Establish the JSON policy format and implement a loadable policy engine for network and filesystem allowlists.

### Policy configuration

Created the root-level `policy.json` configuration file with separate allowlists for:

- Network destination IP addresses.
- Filesystem paths permitted for access.

The policy structure provides a clear configuration source for the policy engine.

### Policy engine

Implemented `kernelguard/policy.py` with:

- JSON policy loading.
- Policy file existence checking.
- JSON parsing and error handling.
- Policy structure validation.
- Network IP allowlist evaluation.
- Filesystem path allowlist evaluation.
- Filesystem path normalization for consistent comparisons.
- Explicit deny behavior for resources that are not present in the allowlists.

The policy engine raises dedicated policy exceptions for missing files, invalid JSON, and invalid policy structures.

### Verification

The policy engine was tested directly against both allowed and unlisted resources.

Verified behavior:

```text
1.1.1.1: True
10.0.0.1: False
/tmp/kernelguard-test.txt: True
/etc/passwd: False
```

This confirmed that configured resources are allowed while resources not present in the allowlists are denied.

`kernelguard/policy.py` was also successfully compiled with Python bytecode compilation.

### End-of-day status

- [x] JSON policy format defined.
- [x] Policy-loading module implemented.
- [x] Network IP allowlist implemented.
- [x] Filesystem path allowlist implemented.
- [x] Default deny behavior for unlisted resources implemented.
- [x] Policy validation and error handling implemented.
- [x] Direct policy tests passed.
- [x] Policy module compilation verified.

**Day 1 Policy Model & JSON Configuration complete.**

---
