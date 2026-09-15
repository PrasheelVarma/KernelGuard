# KernelGuard Safe Testing

KernelGuard enforces security policy at the kernel level via eBPF, so testing must be conducted with a controlled target process scope.

## Safe Testing Rules

### 1. Prefer `kernelguard run` for Script Testing

The recommended way to test policy enforcement on an untrusted script is using the `run` launcher:

```bash
sudo /opt/kernelguard/venv/bin/python3 -m kernelguard.cli run \
  --policy /home/prasheel/SATA_VAULT/developer/KernelGuard/policy.json \
  tests/untrusted_script.py
```

This ensures:
- The target is bound to an exact PID barrier before script execution begins.
- Privileges are dropped to the invoking user's `SUDO_UID`/`SUDO_GID`.
- Active enforcement is strictly confined to that target PID.

### 2. Use PID-Targeted `attach` for Pre-Existing Processes

When testing against an existing process, supply its explicit PID:

```bash
sudo /opt/kernelguard/venv/bin/python3 -m kernelguard.cli attach \
  --pid <PID> \
  --enforce \
  --policy /home/prasheel/SATA_VAULT/developer/KernelGuard/policy.json
```

### 3. System-Wide Enforcement (PID 0) is Strictly Prohibited

Never attempt:

```bash
--enforce --pid 0
```

KernelGuard's CLI and Controller actively reject `--enforce` with PID `0` as a fail-safe measure to prevent taking down or disrupting host system processes.

### 4. systemd Service Configuration is Monitoring-Only

The packaged `kernelguard.service` systemd unit starts KernelGuard in background **monitoring-only** mode without active syscall blocking (`--enforce` is not passed). Active `-EPERM` enforcement is reserved for targeted PID executions (`run` or `attach --pid <PID>`).

### 5. Clean Up Test Processes

When running disposable background test processes, ensure they are cleanly terminated after testing:

```bash
kill <PID>
ps -p <PID>
```

---

## Safety Principles

1. **Fail toward safety:** Any error in environment setup, privilege dropping, or target registration halts execution rather than falling back to unconfined execution.
2. **Strict PID scoping:** Enforcement is exclusively evaluated against the registered target PID in the kernel's `target_pid_map`.
3. **Graceful cleanup:** eBPF kprobes and BPF maps are detached and freed on exit (`SIGINT`, `SIGTERM`, or normal script completion).
