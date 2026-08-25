"""
BPF controller for KernelGuard.

Loads the eBPF execve, tcp_connect, and vfs_write tracers,
applies an optional target PID filter, loads the JSON policy,
normalizes events, and evaluates network/filesystem events
against the policy.

Day 2 adds policy decisions only. Actual kernel-level blocking
(-EPERM) is intentionally deferred to the Week 3 enforcement work.
"""

import os
import sys
from pathlib import Path

from bcc import BPF

from .policy import Policy, PolicyError


EBPF_SOURCE_PATH = Path(__file__).resolve().parent.parent / "ebpf" / "execve_trace.c"
DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent / "policy.json"


class ControllerError(Exception):
    """Base exception for controller-level failures."""


class InsufficientPrivilegesError(ControllerError):
    """Raised when the process lacks privileges required to load eBPF programs."""


class BPFLoadError(ControllerError):
    """Raised when the eBPF program fails to compile or attach."""


class ExecveController:
    """Loads, manages, and evaluates KernelGuard eBPF tracing hooks."""

    def __init__(
        self,
        target_pid: int = 0,
        source_path: Path = EBPF_SOURCE_PATH,
        policy_path: Path = DEFAULT_POLICY_PATH,
    ):
        if target_pid < 0:
            raise ValueError("target_pid must be 0 or a positive PID")

        self.target_pid = target_pid
        self.source_path = source_path
        self.policy_path = policy_path
        self.bpf = None
        self.policy = None

    def _check_privileges(self) -> None:
        if os.geteuid() != 0:
            raise InsufficientPrivilegesError(
                "eBPF programs require root privileges to load. Re-run with 'sudo'."
            )

    def _check_source_exists(self) -> None:
        if not self.source_path.exists():
            raise ControllerError(f"eBPF source not found: {self.source_path}")

    def _load_policy(self) -> None:
        try:
            self.policy = Policy(self.policy_path)
        except PolicyError as exc:
            raise ControllerError(f"Failed to load policy: {exc}") from exc

    def _configure_target_pid(self) -> None:
        """Write the target PID into the eBPF target_pid_map."""
        if self.bpf is None:
            raise RuntimeError("BPF program not loaded.")

        target_pid_map = self.bpf["target_pid_map"]

        key = target_pid_map.Key(0)
        value = target_pid_map.Leaf(self.target_pid)

        target_pid_map[key] = value

    def load(self) -> None:
        """Load the policy, compile the eBPF program, and attach all hooks."""
        self._check_privileges()
        self._check_source_exists()
        self._load_policy()

        try:
            self.bpf = BPF(src_file=str(self.source_path))
        except Exception as exc:
            raise BPFLoadError(
                f"Failed to compile/load eBPF program: {exc}"
            ) from exc

        try:
            self._configure_target_pid()

            self.bpf.attach_kprobe(
                event=self.bpf.get_syscall_fnname("execve"),
                fn_name="trace_execve",
            )

            self.bpf.attach_kprobe(
                event="tcp_connect",
                fn_name="trace_tcp_connect",
            )

            self.bpf.attach_kprobe(
                event="vfs_write",
                fn_name="trace_vfs_write",
            )

        except Exception as exc:
            raise BPFLoadError(
                f"Failed to configure or attach eBPF kprobes: {exc}"
            ) from exc

    @staticmethod
    def _extract_detail_value(message: str, prefix: str) -> str | None:
        """Extract a value following a known event prefix."""
        if not message.startswith(prefix):
            return None

        value = message[len(prefix):].strip()
        return value or None

    def _evaluate_policy(self, event_type: str, detail: str) -> str:
        """Return ALLOW, DENY, or MONITOR for a normalized event."""
        if self.policy is None:
            raise RuntimeError("Policy not loaded.")

        if event_type == "execve":
            return "MONITOR"

        if event_type == "tcp_connect":
            destination = self._extract_detail_value(
                detail,
                "tcp_connect PID ",
            )

            if destination is None:
                return "DENY"

            return (
                "ALLOW"
                if self.policy.check_network(destination)
                else "DENY"
            )

        if event_type == "vfs_write":
            filename = self._extract_detail_value(
                detail,
                "vfs_write PID ",
            )

            if filename is None:
                return "DENY"

            return (
                "ALLOW"
                if self.policy.check_filesystem(filename)
                else "DENY"
            )

        return "MONITOR"

    def events(self):
        """
        Yield normalized events from all attached eBPF hooks.

        Every event has:
            pid
            task
            event_type
            detail
            decision
        """
        if self.bpf is None:
            raise RuntimeError("BPF program not loaded. Call load() first.")

        while True:
            task, pid, cpu, flags, ts, msg = self.bpf.trace_fields()

            task_name = task.decode(errors="replace")
            message = msg.decode(errors="replace")

            if message.startswith("execve called"):
                event_type = "execve"
            elif message.startswith("tcp_connect called"):
                event_type = "tcp_connect"
            elif message.startswith("vfs_write"):
                event_type = "vfs_write"
            else:
                event_type = "unknown"

            decision = self._evaluate_policy(event_type, message)

            yield {
                "pid": pid,
                "task": task_name,
                "event_type": event_type,
                "detail": message,
                "decision": decision,
            }

    def run(self) -> None:
        """Load the program and print policy-aware events until interrupted."""
        try:
            self.load()
        except ControllerError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

        if self.target_pid:
            print(
                f"Monitoring execve, tcp_connect, and vfs_write events "
                f"for PID {self.target_pid}."
            )
        else:
            print(
                "Monitoring execve, tcp_connect, and vfs_write events "
                "for all processes."
            )

        print(f"Policy: {self.policy_path}")
        print(f"{'PID':<8} {'TASK':<16} {'EVENT TYPE':<16} {'DECISION':<10} DETAIL")
        print("-" * 100)

        try:
            for event in self.events():
                print(
                    f"{event['pid']:<8} "
                    f"{event['task']:<16} "
                    f"{event['event_type']:<16} "
                    f"{event['decision']:<10} "
                    f"{event['detail']}"
                )

        except KeyboardInterrupt:
            print("\nStopped.")


def main() -> None:
    controller = ExecveController()
    controller.run()


if __name__ == "__main__":
    main()
