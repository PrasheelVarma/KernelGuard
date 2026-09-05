# KernelGuard Safe Testing

KernelGuard can enforce policy at the kernel level, so testing must be done with a controlled target process.

## Safe testing rules

### 1. Prefer PID-targeted testing

Use a specific PID when testing monitoring or enforcement:

```bash
sudo /opt/kernelguard/venv/bin/python3 -m kernelguard.cli \
  --pid <PID> \
  --policy /home/prasheel/SATA_VAULT/developer/KernelGuard/policy.json
```

This keeps KernelGuard focused on the intended test process.

### 2. Do not use broad enforcement during normal testing

Avoid running:

```bash
--enforce --pid 0
```

PID `0` means that there is no PID restriction. Combined with enforcement, this can affect unrelated system processes.

### 3. Do not start the systemd enforcement service casually

The installed service currently starts KernelGuard with enforcement enabled and without a specific PID.

Before using the service, confirm that the policy and enforcement behavior are safe for the current test environment.

### 4. Use disposable test processes

Testing should use small Python processes created specifically for KernelGuard testing.

Example:

```bash
python3 -c 'import os,time; print(os.getpid(), flush=True); time.sleep(300)'
```

Use the printed PID as the KernelGuard target.

### 5. Clean up test processes

After testing:

```bash
kill <PID>
```

Check that the process is gone:

```bash
ps -p <PID>
```

## Current safety principle

KernelGuard should fail toward safety.

A policy mistake must not unintentionally turn a targeted security test into system-wide enforcement.

This guide is for the current alpha/testing stage and should be updated as the enforcement architecture becomes safer and more isolated.
