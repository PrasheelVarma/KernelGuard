"""
BPF controller for KernelGuard.

Loads the eBPF execve tracer, attaches it to the kernel, and streams
intercepted events.
"""

import os
import sys
from datetime import datetime
from pathlib import Path

from bcc import BPF

EBPF_SOURCE_PATH = Path(__file__).resolve().parent.parent / "ebpf" / "execve_trace.c"


class ControllerError(Exception):
    """Base exception for controller-level failures."""


class InsufficientPrivilegesError(ControllerError):
    """Raised when the process lacks the privileges required to load eBPF programs."""


class BPFLoadError(ControllerError):
    """Raised when the eBPF program fails to compile or attach."""


class ExecveController:
    """Loads and manages the execve tracing eBPF program."""

    def __init__(self, source_path: Path = EBPF_SOURCE_PATH):
        self.source_path = source_path
        self.bpf = None

    def _check_privileges(self) -> None:
        if os.geteuid() != 0:
            raise InsufficientPrivilegesError(
                "eBPF programs require root privileges to load. Re-run with 'sudo'."
            )

    def _check_source_exists(self) -> None:
        if not self.source_path.exists():
            raise ControllerError(f"eBPF source not found: {self.source_path}")

    def load(self) -> None:
        """Compile and load the eBPF program, and attach the kprobe."""
        self._check_privileges()
        self._check_source_exists()

        try:
            self.bpf = BPF(src_file=str(self.source_path))
        except Exception as exc:
            raise BPFLoadError(f"Failed to compile/load eBPF program: {exc}") from exc

        try:
            self.bpf.attach_kprobe(
                event=self.bpf.get_syscall_fnname("execve"),
                fn_name="trace_execve",
            )
        except Exception as exc:
            raise BPFLoadError(f"Failed to attach kprobe to execve: {exc}") from exc

    def events(self):
        """Yield decoded trace events as they occur. Generator; blocks until data is available."""
        if self.bpf is None:
            raise RuntimeError("BPF program not loaded. Call load() first.")

        while True:
            task, pid, cpu, flags, ts, msg = self.bpf.trace_fields()
            yield {
                "timestamp": ts,
                "pid": pid,
                "task": task.decode(errors="replace"),
                "cpu": cpu,
                "message": msg.decode(errors="replace"),
            }

    def run(self) -> None:
        """Load the program and print formatted events to the console until interrupted."""
        try:
            self.load()
        except ControllerError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)

        print(f"{'TIME':<12} {'PID':<8} {'PROCESS':<16} EVENT")
        print("-" * 60)

        try:
            for event in self.events():
                clock = datetime.now().strftime("%H:%M:%S")
                print(
                    f"{clock:<12} "
                    f"{event['pid']:<8} "
                    f"{event['task']:<16} "
                    f"{event['message']}"
                )
        except KeyboardInterrupt:
            print("\nStopped.")


def main() -> None:
    controller = ExecveController()
    controller.run()


if __name__ == "__main__":
    main()
