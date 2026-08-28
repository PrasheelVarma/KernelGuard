# KernelGuard — Week 3 Plan

**Week 3 Goal (per official project document):**

- **Active Blocking:** Upgrade the eBPF program from IDS (logging) to IPS (blocking), returning `-EPERM` (`Operation Not Permitted`) for unauthorized syscalls.
- **Policy Engine:** Build a JSON-based policy engine allowing users to define exactly which IP addresses or file paths are allowed.

The official project document defines Week 3 around these two capabilities. fileciteturn9file7L1-L8

**Week window:** Monday → Sunday

---

## Week 3 Strategy

Week 2 established the monitoring foundation:

```text
Target PID
    │
    ▼
BPF PID filter
    │
    ├── execve
    ├── tcp_connect
    └── vfs_write
            │
            ▼
       Unified logging
```

Week 3 changes the final stage from observation to enforcement:

```text
Target PID
    │
    ▼
BPF PID filter
    │
    ├── execve
    ├── tcp_connect
    └── vfs_write
            │
            ▼
      Policy evaluation
            │
       ┌────┴────┐
       ▼         ▼
     ALLOW      DENY
       │         │
       ▼         ▼
   syscall    -EPERM
```

The goal is to keep the existing Week 2 monitoring behavior intact while adding policy-driven blocking.

---

## Day-by-Day Breakdown

### Day 1 (Mon) — Policy Model & JSON Configuration

- [x] Define the JSON policy format for network and filesystem rules.
- [x] Implement the initial policy-loading module.
- [x] Support explicit allowed IP addresses.
- [x] Support explicit allowed file paths.
- [x] Define clear default behavior for resources not present in the allow lists.
- [x] Validate malformed or missing policy configuration with useful errors.

**Primary files:**

```text
kernelguard/policy.py
policy.json
```

**Goal by end of today:** KernelGuard has a clear, loadable policy representation that can answer whether a network destination or file path is allowed.

---

### Day 2 (Tue) — Policy Engine Integration

- [x] Connect the Python policy engine to the existing controller.
- [x] Load the policy when KernelGuard starts.
- [x] Convert monitored event information into policy-check inputs.
- [x] Implement allow/deny decisions for `tcp_connect`.
- [x] Implement allow/deny decisions for `vfs_write`.
- [x] Keep `execve` monitoring available while policy support is introduced.

**Goal by end of today:** The controller can evaluate intercepted network and filesystem activity against the JSON policy.

---

### Day 3 (Wed) — eBPF Active Blocking Foundation

- [x] Extend the eBPF hooks so an enforcement decision can affect the syscall result.
- [x] Introduce the kernel-side mechanism required to distinguish allowed and denied operations.
- [x] Implement the `-EPERM` return path for denied operations.
- [x] Preserve PID filtering while enforcement is enabled.
- [x] Ensure allowed operations continue normally.

**Goal by end of today:** KernelGuard can technically deny a selected operation at the kernel level without breaking the existing monitoring path.

---

### Day 4 (Thu) — Network Enforcement

- [x] Apply policy enforcement to `tcp_connect`.
- [x] Allow connections matching configured IP rules.
- [x] Deny unauthorized destinations with `-EPERM`.
- [x] Verify the target process receives the expected failure for a blocked connection.
- [x] Verify an allowed connection still succeeds.
- [x] Confirm another PID is not affected when PID filtering is active.

**Goal by end of today:** Unauthorized network connections from the monitored process are actively blocked.

---

### Day 5 (Fri) — Filesystem Enforcement

- [x] Apply policy enforcement to `vfs_write`.
- [x] Allow writes matching configured file-path rules.
- [x] Deny unauthorized writes with `-EPERM`.
- [x] Verify an allowed file write succeeds.
- [x] Verify a denied file write fails.
- [x] Confirm PID filtering remains active during enforcement.

**Goal by end of today:** Unauthorized filesystem writes from the monitored process are actively blocked.

---

### Day 6 (Sat) — End-to-End Policy & Enforcement Audit

- [ ] Create a policy containing both allowed and denied network destinations.
- [ ] Create a policy containing both allowed and denied filesystem paths.
- [ ] Run a target test process that attempts both allowed and unauthorized operations.
- [ ] Confirm allowed operations succeed.
- [ ] Confirm unauthorized operations return `-EPERM`.
- [ ] Confirm KernelGuard reports the corresponding enforcement events.
- [ ] Confirm unrelated processes remain unaffected by target-PID filtering.
- [ ] Verify policy reload/error behavior if applicable.

**Goal by end of today:** The complete policy → controller → eBPF enforcement path is verified end-to-end.

---

### Day 7 (Sun) — Week 3 Wrap-Up

- [ ] Perform a clean end-to-end retest of network and filesystem policy enforcement.
- [ ] Verify `-EPERM` behavior for every configured denied operation.
- [ ] Verify allowed operations remain functional.
- [ ] Review and clean up the policy engine and enforcement code.
- [ ] Update `README.md` to reflect active blocking and policy support.
- [ ] Update Week 3 development logs.
- [ ] Commit and push all Week 3 work.
- [ ] Prepare Week 4 handoff covering packaging, service lifecycle, CLI polish, and final integration.

**Target by end of Sunday:** KernelGuard has moved from an IDS-style monitoring tool to an IPS-style enforcement tool with a JSON policy engine, matching the official Week 3 requirement.

---

## Tracking Checklist

| Day | Focus | Status |
|---|---|---|
| Mon | Policy model & JSON configuration | ✅ Done |
| Tue | Policy engine integration | ✅ Done |
| Wed | eBPF active blocking foundation | ✅ Done |
| Thu | Network enforcement | ✅ Done |
| Fri | Filesystem enforcement | ✅ Done |
| Sat | End-to-end policy & enforcement audit | 🔲 Pending |
| Sun | Week 3 wrap-up & Week 4 handoff | 🔲 Pending |

---

## Week 2 → Week 3 Handoff

### Already available from Week 2

- `execve` eBPF hook
- `tcp_connect` eBPF hook
- `vfs_write` eBPF hook
- BPF-map-based target PID filtering
- Unified Python controller
- CLI `--pid` support
- Unified event output
- Multi-hook integration tests
- Interception audit
- Performance verification

### Week 3 builds on these components

```text
Week 2
Monitoring + PID Filtering
          │
          ▼
Week 3
Policy Evaluation
          │
          ▼
Active Enforcement
          │
     ┌────┴────┐
     ▼         ▼
   ALLOW      DENY
               │
               ▼
             -EPERM
```

---

## Official Week 3 Requirement

The official project document specifies:

> **Active Blocking:** Upgrade the eBPF program from an IDS (logging) to an IPS (blocking), returning `-EPERM` (Operation Not Permitted) to unauthorized syscalls.

> **Policy Engine:** Build a JSON-based policy engine allowing users to define exactly which IP addresses or file paths are allowed.

These two requirements are the source-of-truth for the Week 3 implementation plan. fileciteturn9file7L1-L8

---

## Notes

- `week-3.md` is the **weekly execution plan** and should be updated with `[x]` only after the corresponding work has actually been implemented and verified.
- Week 3 logs will be maintained separately from this plan, following the same approach used during Week 2.
- Do not add implementation claims to this plan before they are actually completed.
- The exact eBPF enforcement mechanism will be selected during Day 3 based on what is compatible with the existing BCC/kernel environment.
