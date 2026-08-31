"""
BPF controller for KernelGuard.

Loads the eBPF execve, tcp_connect, and vfs_write tracers,
applies an optional target PID filter, loads the JSON policy,
normalizes events, and evaluates network/filesystem events
against the policy.

Week 3 Day 3 adds the kernel-side enforcement foundation:
policy entries are loaded into BPF maps and BPF LSM hooks can
return -EPERM for denied IPv4 connections and file writes.

Enforcement is opt-in so normal monitoring remains unchanged
unless the CLI is started with --enforce.
"""

import ctypes as ct
import ipaddress
import os
import sys
from pathlib import Path

from bcc import BPF

from .logger import KernelGuardLogger
from .policy import Policy, PolicyError


EBPF_SOURCE_PATH = (
    Path(__file__).resolve().parent.parent
    / "ebpf"
    / "execve_trace.c"
)
DEFAULT_POLICY_PATH = (
    Path(__file__).resolve().parent.parent
    / "policy.json"
)


class ControllerError(Exception):
    """Base exception for controller-level failures."""


class InsufficientPrivilegesError(ControllerError):
    """Raised when the process lacks privileges required to load eBPF programs."""


class BPFLoadError(ControllerError):
    """Raised when the eBPF program fails to compile or attach."""


class ExecveController:
    """Loads, manages, evaluates, and optionally enforces KernelGuard policy."""

    def __init__(
        self,
        target_pid: int = 0,
        enforce: bool = False,
        source_path: Path = EBPF_SOURCE_PATH,
        policy_path: Path = DEFAULT_POLICY_PATH,
        logger: KernelGuardLogger | None = None,
    ):
        if target_pid < 0:
            raise ValueError("target_pid must be 0 or a positive PID")

        self.target_pid = target_pid
        self.enforce = enforce
        self.source_path = source_path
        self.policy_path = policy_path
        self.logger = logger or KernelGuardLogger()
        self.bpf = None
        self.policy = None

    def _check_privileges(self) -> None:
        if os.geteuid() != 0:
            raise InsufficientPrivilegesError(
                "eBPF programs require root privileges to load. "
                "Re-run with 'sudo'."
            )

    def _check_source_exists(self) -> None:
        if not self.source_path.exists():
            raise ControllerError(
                f"eBPF source not found: {self.source_path}"
            )

    def _load_policy(self) -> None:
        try:
            self.policy = Policy(self.policy_path)
        except PolicyError as exc:
            raise ControllerError(
                f"Failed to load policy: {exc}"
            ) from exc

    def _configure_target_pid(self) -> None:
        """Write the target PID into the eBPF target_pid_map."""
        target_pid_map = self.bpf["target_pid_map"]
        key = target_pid_map.Key(0)
        value = target_pid_map.Leaf(self.target_pid)
        target_pid_map[key] = value

    def _configure_enforcement(self) -> None:
        """Enable or disable kernel-side enforcement in the eBPF program."""
        enforcement_map = self.bpf["enforcement_enabled"]
        key = enforcement_map.Key(0)
        value = enforcement_map.Leaf(1 if self.enforce else 0)
        enforcement_map[key] = value

    @staticmethod
    def _network_key(ip_address: str) -> int:
        """
        Convert an IPv4 address into the native u32 representation used
        by the BPF map when the sockaddr bytes are read on x86_64.
        """
        address = ipaddress.ip_address(ip_address)

        if address.version != 4:
            raise ValueError(
                f"Only IPv4 policy entries are supported: {ip_address}"
            )

        return int.from_bytes(
            address.packed,
            byteorder="little",
        )

    def _load_network_policy(self) -> None:
        """Populate the BPF IPv4 allowlist from the loaded policy."""
        network_map = self.bpf["network_allowed_map"]

        for ip_address in self.policy.network_allowed_ips:
            try:
                key = network_map.Key(
                    self._network_key(ip_address)
                )
                value = network_map.Leaf(1)
                network_map[key] = value
            except ValueError as exc:
                raise ControllerError(
                    f"Invalid network policy entry: {ip_address}"
                ) from exc

    def _load_filesystem_policy(self) -> None:
        """
        Populate the BPF filesystem allowlist with device/inode pairs.

        The kernel LSM hook works with the inode attached to the file,
        so user space resolves each configured path once with stat().
        """
        filesystem_map = self.bpf["filesystem_allowed_map"]

        for file_path in self.policy.filesystem_allowed_paths:
            try:
                stat_result = os.stat(file_path)
            except OSError:
                # A path that does not exist cannot currently be mapped
                # to an inode. The policy engine still retains the path.
                continue

            key = filesystem_map.Key()
            key.dev = stat_result.st_dev
            key.ino = stat_result.st_ino

            value = filesystem_map.Leaf(1)
            filesystem_map[key] = value

    def _configure_policy_maps(self) -> None:
        """Load policy allowlists and enforcement state into BPF maps."""
        self._configure_target_pid()
        self._load_network_policy()
        self._load_filesystem_policy()
        self._configure_enforcement()

    def load(self) -> None:
        """Load policy, compile eBPF, configure maps, and attach kprobes."""
        self._check_privileges()
        self._check_source_exists()
        self._load_policy()

        if not BPF.support_lsm():
            raise BPFLoadError(
                "BPF LSM is not available on this kernel. "
                "KernelGuard active enforcement requires "
                "CONFIG_BPF_LSM and the BPF LSM enabled in CONFIG_LSM."
            )

        try:
            self.bpf = BPF(src_file=str(self.source_path))
        except Exception as exc:
            raise BPFLoadError(
                f"Failed to compile/load eBPF program: {exc}"
            ) from exc

        try:
            self._configure_policy_maps()

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
                f"Failed to configure or attach eBPF enforcement/tracing hooks: {exc}"
            ) from exc

    @staticmethod
    def _decode_ipv4(value: str) -> str | None:
        """Convert the u32 emitted by tcp_connect tracing to dotted IPv4."""
        try:
            ip_value = int(value)

            if not 0 <= ip_value <= 0xFFFFFFFF:
                return None

            return str(
                ipaddress.ip_address(
                    int.from_bytes(
                        ip_value.to_bytes(4, byteorder="little"),
                        byteorder="big",
                    )
                )
            )
        except ValueError:
            return None

    @staticmethod
    def _normalize_event(message: str) -> tuple[str, str]:
        """Convert a raw trace message into an event type and policy detail."""
        if message.startswith("execve called"):
            return "execve", message

        if message.startswith("tcp_connect ip="):
            raw_ip = message[len("tcp_connect ip="):].strip()
            ip_address = ExecveController._decode_ipv4(raw_ip)

            return "tcp_connect", ip_address or raw_ip

        if message.startswith("vfs_write PID "):
            separator = ": "

            if separator in message:
                _, filename = message.split(separator, 1)
                return "vfs_write", filename.strip()

            return "vfs_write", message

        if message.startswith("BLOCK tcp_connect ip="):
            raw_ip = message[len("BLOCK tcp_connect ip="):].strip()
            ip_address = ExecveController._decode_ipv4(raw_ip)

            return "tcp_connect", ip_address or raw_ip

        if message.startswith("BLOCK vfs_write PID "):
            return "vfs_write", message

        return "unknown", message

    def _evaluate_policy(self, event_type: str, detail: str) -> str:
        """Return ALLOW, DENY, or MONITOR for a normalized event."""
        if self.policy is None:
            raise RuntimeError("Policy not loaded.")

        if event_type == "execve":
            return "MONITOR"

        if event_type == "tcp_connect":
            return (
                "ALLOW"
                if self.policy.check_network(detail)
                else "DENY"
            )

        if event_type == "vfs_write":
            if detail.startswith("vfs_write PID "):
                return "DENY"

            return (
                "ALLOW"
                if self.policy.check_filesystem(detail)
                else "DENY"
            )

        return "MONITOR"

    def events(self):
        """Yield normalized events with controller-side policy decisions."""
        if self.bpf is None:
            raise RuntimeError(
                "BPF program not loaded. Call load() first."
            )

        while True:
            try:
                task, pid, cpu, flags, ts, msg = self.bpf.trace_fields()
            except ValueError:
                continue

            task_name = task.decode(errors="replace")
            message = msg.decode(errors="replace")

            event_type, detail = self._normalize_event(message)
            decision = self._evaluate_policy(
                event_type,
                detail,
            )

            yield {
                "pid": pid,
                "task": task_name,
                "event_type": event_type,
                "detail": detail,
                "decision": decision,
            }

    def run(self, daemon: bool = False) -> None:
        """Load the program and print policy-aware events until interrupted."""
        try:
            self.load()
        except ControllerError as exc:
            self.logger.error(str(exc))
            sys.exit(1)

        scope = (
            f"PID {self.target_pid}"
            if self.target_pid
            else "All System Processes"
        )

        mode = "ENFORCEMENT ENABLED (-EPERM)" if self.enforce else "MONITORING ONLY"

        self.logger.banner(
            scope=scope,
            policy_path=str(self.policy_path),
            mode=mode,
            daemon=daemon,
        )

        self.logger.table_header()

        try:
            for event in self.events():
                self.logger.log_event(event)

        except KeyboardInterrupt:
            self.logger.info("\nStopping KernelGuard...")


def main() -> None:
    controller = ExecveController()
    controller.run()


if __name__ == "__main__":
    main()
