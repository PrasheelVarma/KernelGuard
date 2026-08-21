# KernelGuard — Week 2 Dev Log & Learnings

Running notes on Week 2 implementation, verification, manual tweaks, gotchas, and decisions. This file records what was actually done during the week rather than what was planned.

Format: newest entries at the top.

---
## Day 4 — Thursday — `vfs_write` Hook

**Goal for the day:** Extend the eBPF monitoring from `execve` and `tcp_connect` to `vfs_write` while preserving the existing PID filtering mechanism.

### Implementation

- Updated `ebpf/execve_trace.c`:
  - Added a `trace_vfs_write()` kprobe handler.
  - Reused the existing `target_pid_map` for PID filtering.
  - The new hook reports the PID and process name when a `vfs_write` event occurs.

- Updated `kernelguard/controller.py`:
  - Added a kprobe attachment for the kernel `vfs_write` function.
  - Kept the existing `execve` and `tcp_connect` kprobe attachments.
  - Updated the controller status message to report all three monitored hooks.

### Verification

- Confirmed `kernelguard/controller.py` compiles successfully.
- Loaded the updated eBPF program successfully through the controller.
- Confirmed the `execve`, `tcp_connect`, and `vfs_write` kprobes attach successfully.
- Ran KernelGuard with a specific target PID.
- Created a temporary Python process that performed a real file write.
- Confirmed KernelGuard captured the filesystem write event for the target process.

Observed event:

```text
vfs_write called by PID 172194 (python3)
```

This confirmed that the target PID was correctly propagated through the controller and that the `vfs_write` eBPF hook successfully captured a real filesystem write from the target process.

### Observation

The same `target_pid_map` is shared across all three hooks:

```text
target_pid_map
      │
      ├── execve
      ├── tcp_connect
      └── vfs_write
             │
             ▼
        target PID only
```

The current `vfs_write` event reports the PID and process name. File path extraction is not part of today's implementation.

### End-of-day status

- [x] `vfs_write` eBPF hook implemented.
- [x] Existing PID filtering reused for `vfs_write`.
- [x] Controller updated to attach the `vfs_write` kprobe.
- [x] eBPF program successfully compiled and loaded.
- [x] All three hooks successfully attached.
- [x] Real filesystem write successfully captured.
- [x] Day 4 `vfs_write` hooking complete.

Ready for the next task in the Week 2 plan.

---

## Day 3 — Wednesday — `tcp_connect` Hook

**Goal for the day:** Extend the eBPF monitoring from `execve` to `tcp_connect` while preserving the existing PID filtering mechanism.

### Implementation

- Updated `ebpf/execve_trace.c`:
  - Added a `trace_tcp_connect()` kprobe handler.
  - Reused the existing `target_pid_map` for PID filtering.
  - Added a shared `is_target_pid()` helper so both `execve` and `tcp_connect` use the same filtering logic.
  - The new hook reports the PID and process name when a TCP connection attempt occurs.

- Updated `kernelguard/controller.py`:
  - Added a kprobe attachment for the kernel `tcp_connect` function.
  - The existing `execve` hook remains attached.
  - The controller now monitors both `execve` and `tcp_connect` events.

### Verification

- Confirmed `kernelguard/controller.py` compiles successfully.
- Loaded the updated eBPF program successfully through the controller.
- Confirmed both the `execve` and `tcp_connect` kprobes attach without errors.
- Ran KernelGuard with a specific target PID.
- Generated a real TCP connection attempt from the target process.
- Confirmed KernelGuard captured:

```text
tcp_connect called by PID 15596 (python3)
This confirmed that the target PID was correctly propagated through the controller and that the new `tcp_connect` eBPF hook captured the network connection event.
```
### End-of-day status

- [x] `tcp_connect` eBPF hook implemented.
- [x] Existing PID filtering reused for `tcp_connect`.
- [x] Controller updated to attach the `tcp_connect` kprobe.
- [x] eBPF program successfully compiled and loaded.
- [x] Real TCP connection attempt successfully captured.
- [x] Day 3 `tcp_connect` hooking complete.

Ready for Day 4: `vfs_write` hook.

---

## Day 2 — Tuesday — PID Filtering (Controller Side)

**Goal for the day:** Update the Python controller so a target PID can be supplied at runtime and passed into the eBPF PID filter, allowing KernelGuard to monitor only the selected process.

### Implementation

- Updated `kernelguard/controller.py`:
  - `ExecveController` now accepts an optional `target_pid` parameter.
  - `target_pid=0` preserves the existing system-wide monitoring behavior.
  - Negative PIDs are rejected.
  - Added `_configure_target_pid()` to write the selected PID into the `target_pid_map` BPF map during `load()`.
  - Used the BCC-generated map `Key` and `Leaf` types when writing the map value to match the installed BCC version.

- Created `kernelguard/cli.py`:
  - Added an `argparse`-based command-line interface.
  - Added `--pid <PID>` for selecting the process to monitor at runtime.
  - Added validation to reject negative PID values.
  - The CLI passes the runtime PID into `ExecveController(target_pid=...)`.

### Issue — BPF map value type

The first controller implementation attempted to write the PID directly into the BPF map:

```python
target_pid_map[0] = self.target_pid
```

This produced:

```text
byref() argument 1 must be _ctypes._CData, not int
```

**Fix:** Used the BCC map key/value types explicitly:

```python
key = target_pid_map.Key(0)
value = target_pid_map.Leaf(self.target_pid)
target_pid_map[key] = value
```

After this change, the BPF program loaded and the kprobe attached successfully.

### Verification

- `python3 -m kernelguard.cli --help`
  - Confirmed the new `--pid PID` option is exposed correctly.

- `python3 -m kernelguard.cli --pid -1`
  - Confirmed invalid negative PID values are rejected.

- `python3 -m kernelguard.cli --pid 12345` without root
  - Confirmed the controller reports the expected root privilege error.

- `sudo python3 -m kernelguard.cli --pid 12345`
  - Confirmed the eBPF program loaded successfully and the controller entered PID-filtered monitoring mode after fixing the BPF map type issue.

- End-to-end runtime test:
  - Started a temporary shell process and obtained its PID.
  - Started KernelGuard using `sudo python3 -m kernelguard.cli --pid <target_pid>`.
  - Confirmed the controller reported:
    `Monitoring execve events for PID <target_pid>.`
  - Confirmed an `execve` event was captured with the target PID.
  - Target PID `98430` was observed in the final successful test.

### Observation

The PID is supplied dynamically at execution time through `--pid`; no PID is hardcoded into the controller or eBPF source.

The resulting flow is:

```text
CLI --pid <PID>
      ↓
ExecveController(target_pid=<PID>)
      ↓
target_pid_map
      ↓
eBPF PID filter
      ↓
target process execve event
```

### End-of-day status

- [x] `ExecveController` accepts `target_pid`.
- [x] Target PID is written into the eBPF map during `load()`.
- [x] `--pid <PID>` CLI implemented.
- [x] Runtime PID filtering verified with a real process.
- [x] Day 2 controller-side PID filtering complete.

Ready for Day 3: `tcp_connect` hook.

---

## Day 1 — Monday — PID Filtering (Kernel Side)

**Goal for the day:** Add PID filtering to the eBPF `execve` hook using a BPF map so the kernel-side filter can restrict events to a specific process.

### Implementation

- Updated `ebpf/execve_trace.c` to add:

```c
BPF_ARRAY(target_pid_map, u32, 1);
```

- The `trace_execve()` function reads the target PID from the BPF map.
- A target PID of `0` means no filtering and preserves the existing system-wide behavior.
- When a non-zero target PID is configured, events from other PIDs are ignored before event output is generated.

### Verification

- Used `test_pid_filter.py` to load the eBPF program and manually populate `target_pid_map`.
- The test accepts a target PID as a runtime command-line argument.
- Confirmed the eBPF-side PID filter can be exercised independently before integrating it with the Python controller.

### End-of-day status

- [x] BPF map-based target PID filter implemented.
- [x] Kernel-side PID filtering testable in isolation.
- [x] Day 1 kernel-side PID filtering complete.

Ready for Day 2: controller-side PID filtering.
