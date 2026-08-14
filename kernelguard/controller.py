"""
BPF controller for KernelGuard.

Loads the eBPF execve tracer, attaches it to the kernel, and streams
intercepted events.
"""

from pathlib import Path

from bcc import BPF

EBPF_SOURCE_PATH = Path(__file__).resolve().parent.parent / "ebpf" / "execve_trace.c"


class ExecveController:
    """Loads and manages the execve tracing eBPF program."""

    def __init__(self, source_path: Path = EBPF_SOURCE_PATH):
        self.source_path = source_path
        self.bpf = None

    def load(self) -> None:
        """Compile and load the eBPF program, and attach the kprobe."""
        if not self.source_path.exists():
            raise FileNotFoundError(f"eBPF source not found: {self.source_path}")

        self.bpf = BPF(src_file=str(self.source_path))
        self.bpf.attach_kprobe(
            event=self.bpf.get_syscall_fnname("execve"),
            fn_name="trace_execve",
        )

    def events(self):
        """Yield decoded trace events as they occur. Generator; blocks until data is available."""
        if self.bpf is None:
            raise RuntimeError("BPF program not loaded. Call load() first.")

        while True:
            task, pid, cpu, flags, ts, msg = self.bpf.trace_fields()
            yield {
                "timestamp": ts,
                "pid": pid,
                "task": task.decode(),
                "cpu": cpu,
                "message": msg.decode(),
            }

    def run(self) -> None:
        """Load the program and print events to the console until interrupted."""
        self.load()
        print("Tracing execve() calls. Press Ctrl+C to stop.\n")

        try:
            for event in self.events():
                print(
                    f"[{event['timestamp']:.6f}] "
                    f"PID {event['pid']:<8} "
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
