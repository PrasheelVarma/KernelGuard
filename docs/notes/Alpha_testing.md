# Alpha Testing

## Current Phase
Time: 4:00PM; Friday, 4 September 2026

KernelGuard is currently in the alpha testing phase.

The main implementation is already built and the project has reached the stage where I am testing and verifying the system, finding flaws, fixing them, and making sure the complete planned implementation works properly.

This is still development. The project is not supposed to be treated as a production ready Linux security product yet.

## What Happened Today

Today I was testing KernelGuard on my actual EndeavourOS system.

KernelGuard is designed to work close to the Linux kernel using eBPF and kernel side enforcement. Because of that, I decided from the beginning to test it directly on my own operating system instead of trying to completely isolate it inside a virtual machine or similar environment.

The project itself is kept inside my project directory and its Python environment is separate from the normal system Python environment. This part is fine.

The important thing I learned today is that keeping the project files separate does not mean the running KernelGuard process is isolated from the operating system.

Once KernelGuard runs with the required privileges and attaches its eBPF enforcement logic, it is capable of affecting real system operations.

## The Incident

During testing, KernelGuard was started through systemd with enforcement enabled.

The system started behaving abnormally after that. Applications stopped launching properly, system services started getting `Operation not permitted` errors, TTYs were also affected, and eventually even normal shutdown was not working correctly.

I had to force the system to shut down.

After restarting the laptop, everything returned to normal because KernelGuard was no longer running.

At first I was concerned that I might have accidentally triggered an unrelated `kernelguard` package from PyPI because there is another package with the same name.

I checked the installed package and its location.

The installed package was:

`/opt/kernelguard/venv/lib/python3.14/site-packages/kernelguard/`

and the package information showed version `1.0.0`, with the author listed as `KernelGuard Team`.

I also compared the installed `cli.py` with my actual project source. They contain the same KernelGuard implementation.

So the unrelated PyPI package was not the root cause of this incident.

## What Actually Happened

The actual KernelGuard service was running my own project.

The systemd service starts:

`python3 -m kernelguard.cli --daemon --enforce --policy ...`

The important part is `--enforce`.

KernelGuard's enforcement system can return `-EPERM` for operations that are not allowed by the policy.

Another important part is the PID scope.

The CLI has a PID option and its default value is `0`, which means that when no specific PID is provided, the enforcement can apply to all processes.

Therefore, the service configuration was effectively enabling KernelGuard enforcement at system-wide scope.

This is very different from the controlled testing I was doing with a specific test process.

The system-wide enforcement caused legitimate Linux operations to be denied because the current enforcement and policy implementation is still being developed.

That explains why systemd, logind, networking, TTYs and other parts of the operating system started receiving `Operation not permitted`.

## What I Learned

The biggest lesson from this test is that there are two different kinds of isolation involved.

The KernelGuard source code being inside my project folder does not automatically affect the operating system.

The Python environment being separate also helps keep the project's dependencies separate from the normal system Python.

However, once KernelGuard is running with root privileges and has attached its eBPF enforcement hooks, it is no longer isolated from the operating system.

The running process has the ability to influence the real kernel and therefore the rest of the system.

So I should not think:

"KernelGuard is just a program inside my folder, so I can always safely stop it."

The correct understanding is:

"The project files and Python environment can be kept separate, but the running enforcement component has real system level power."

## What Needs To Be Improved

This incident does not mean the overall project approach is wrong.

I intentionally chose to test KernelGuard on the real operating system because the project is about Linux kernel level security and I need real kernel behaviour during development.

The problem is that the enforcement lifecycle needs stronger safety mechanisms.

Some of the things that need to be improved are:

- safer enforcement scope during development
- better PID based testing
- reliable cleanup when KernelGuard stops
- making sure enforcement is disabled when the daemon exits
- making sure eBPF hooks are properly detached
- safer systemd integration
- better failure handling
- better protection against accidentally enabling system-wide enforcement during testing

These are development and refinement issues, not a reason to abandon testing on the real system.

## Current State

After the incident, KernelGuard was left inactive.

I am not continuing development work on it today.

The purpose of documenting this incident is to remember what happened and what I learned from it.

This incident is therefore part of the alpha testing stage and is useful because it exposed real problems that need to be considered before taking the project further.
