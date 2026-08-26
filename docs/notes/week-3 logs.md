# KernelGuard — Week 3 Logs

Running notes for Week 3 of KernelGuard development. This file records what was actually completed, issues encountered, fixes applied, and verification performed during the week.

Format: newest entries at the top.

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
