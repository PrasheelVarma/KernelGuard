# Plan-B

## Purpose

The main plan remains unchanged.

I will finish the implementation planned for Week 4 and complete the required testing and documentation within the timeline.

Plan-B is not a replacement for that plan.

It is the list of improvements and further development that I want to work on after the planned scope is complete, depending on the time available and the condition of the project.

## Why Plan-B Exists

During development and alpha testing, I found that some parts of KernelGuard still need more work.

These issues do not need to become additional requirements for the current version 1.0 deliverable.

The important thing for now is to finish the planned scope properly instead of continuously adding new problems and features to the current deadline.

After that, I can continue improving the project.

## Current Known Areas

### 1. Enforcement Safety

Make the enforcement system safer during development and normal operation.

### 2. Process Scope

Improve PID based targeting and make sure system-wide enforcement cannot be enabled accidentally during testing.

### 3. Cleanup

Make sure KernelGuard completely cleans up its eBPF programs, hooks and enforcement state when it stops or crashes.

### 4. Daemon and systemd Integration

Improve the relationship between KernelGuard's daemon mode and systemd so that process tracking, startup, shutdown and failure recovery are reliable.

### 5. Policy System

Review the current allowlist and enforcement behaviour and make sure legitimate Linux operations are not unnecessarily blocked.

### 6. Testing

Expand the tests beyond the current prototype tests and test failure conditions, cleanup, process isolation and system recovery.

### 7. Performance

Measure the effect of KernelGuard's monitoring and enforcement on the system and improve it where necessary.

### 8. Long-Term Development

After the current plan, continue developing KernelGuard toward the larger vision of the project. -- PLAN-B

## Rule For This Plan

I do not need to solve everything immediately.

The planned deadline comes first.

The planned Week 4 implementation should be completed before I start treating every discovered flaw as a new deadline.

Plan-B exists so that I do not forget the problems I found while trying to finish the current work.
