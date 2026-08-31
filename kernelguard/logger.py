"""
Logging and colored alerts module for KernelGuard.

Provides ANSI color formatting, structured event logging,
and prominent security alerts for policy violations (blocked syscalls).
"""

import sys
from typing import Any


class Colors:
    """ANSI color codes for terminal formatting."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Foreground colors
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright foreground colors
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_CYAN = "\033[96m"

    # Background colors
    BG_RED = "\033[41m"
    ALERT_BG = "\033[1;37;41m"  # Bold white on red background


class KernelGuardLogger:
    """Handles formatted console logging and colored alerts for KernelGuard."""

    def __init__(self, use_color: bool = True, verbose: bool = False):
        if use_color is True:
            # Auto-detect TTY support unless explicitly overridden
            self.use_color = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        else:
            self.use_color = bool(use_color)

        self.verbose = verbose

    def _style(self, text: str, style_code: str) -> str:
        """Apply ANSI styling if color is enabled."""
        if not self.use_color or not style_code:
            return text
        return f"{style_code}{text}{Colors.RESET}"

    def info(self, message: str) -> None:
        """Print an informational message."""
        tag = self._style("[INFO]", Colors.BRIGHT_CYAN + Colors.BOLD)
        print(f"{tag} {message}")

    def warning(self, message: str) -> None:
        """Print a warning message."""
        tag = self._style("[WARN]", Colors.BRIGHT_YELLOW + Colors.BOLD)
        print(f"{tag} {message}", file=sys.stderr)

    def error(self, message: str) -> None:
        """Print an error message."""
        tag = self._style("[ERROR]", Colors.BRIGHT_RED + Colors.BOLD)
        print(f"{tag} {message}", file=sys.stderr)

    def alert(self, pid: int, task: str, event_type: str, detail: str) -> None:
        """Print a prominent security alert for blocked actions."""
        badge = self._style(" 🚨 SECURITY ALERT: ACTION BLOCKED (-EPERM) ", Colors.ALERT_BG)
        details = (
            f"{self._style('PID:', Colors.BOLD)} {pid} | "
            f"{self._style('Task:', Colors.BOLD)} {task} | "
            f"{self._style('Event:', Colors.BOLD)} {event_type} | "
            f"{self._style('Detail:', Colors.BOLD)} {detail}"
        )
        border = self._style("=" * 72, Colors.BRIGHT_RED + Colors.BOLD)

        print(f"\n{border}")
        print(badge)
        print(details)
        print(f"{border}\n")

    def banner(self, scope: str, policy_path: str, mode: str, daemon: bool = False) -> None:
        """Print the KernelGuard startup banner."""
        title = self._style("🛡️  KernelGuard eBPF Security Monitor", Colors.BOLD + Colors.BRIGHT_CYAN)
        status_mode = (
            self._style(mode, Colors.BOLD + Colors.BRIGHT_RED)
            if "ENFORCEMENT" in mode
            else self._style(mode, Colors.BOLD + Colors.BRIGHT_GREEN)
        )
        daemon_str = self._style("Enabled", Colors.BRIGHT_YELLOW) if daemon else "Disabled"

        print(f"\n{title}")
        print(self._style("=" * 60, Colors.DIM))
        print(f"  {self._style('Scope:', Colors.BOLD)}       {scope}")
        print(f"  {self._style('Policy File:', Colors.BOLD)} {policy_path}")
        print(f"  {self._style('Mode:', Colors.BOLD)}        {status_mode}")
        print(f"  {self._style('Daemon:', Colors.BOLD)}      {daemon_str}")
        print(self._style("=" * 60, Colors.DIM) + "\n")

    def table_header(self) -> None:
        """Print table header for monitoring output."""
        pid_hdr = self._style(f"{'PID':<8}", Colors.BOLD)
        task_hdr = self._style(f"{'TASK':<16}", Colors.BOLD)
        event_hdr = self._style(f"{'EVENT TYPE':<16}", Colors.BOLD)
        dec_hdr = self._style(f"{'DECISION':<10}", Colors.BOLD)
        det_hdr = self._style("DETAIL", Colors.BOLD)

        print(f"{pid_hdr} {task_hdr} {event_hdr} {dec_hdr} {det_hdr}")
        print(self._style("-" * 90, Colors.DIM))

    def log_event(self, event: dict[str, Any]) -> None:
        """Format and log an intercepted event with color highlights."""
        pid = event.get("pid", 0)
        task = event.get("task", "unknown")
        event_type = event.get("event_type", "unknown")
        decision = event.get("decision", "MONITOR")
        detail = event.get("detail", "")

        if decision == "DENY":
            # Highlight DENY decision with bright red / alert badge
            dec_str = self._style("DENY      ", Colors.ALERT_BG)
            task_str = self._style(f"{task:<16}", Colors.BRIGHT_RED)
            event_str = self._style(f"{event_type:<16}", Colors.BRIGHT_RED)
            det_str = self._style(f"{detail} [BLOCKED -EPERM]", Colors.BRIGHT_RED + Colors.BOLD)
            
            # Print tabular line
            print(f"{pid:<8} {task_str} {event_str} {dec_str} {det_str}")

            # Also output dedicated visual security alert banner
            self.alert(pid=pid, task=task, event_type=event_type, detail=detail)

        elif decision == "ALLOW":
            dec_str = self._style("ALLOW     ", Colors.BRIGHT_GREEN + Colors.BOLD)
            task_str = f"{task:<16}"
            event_str = f"{event_type:<16}"
            det_str = self._style(detail, Colors.DIM)
            print(f"{pid:<8} {task_str} {event_str} {dec_str} {det_str}")

        else:  # MONITOR
            dec_str = self._style("MONITOR   ", Colors.BRIGHT_BLUE)
            task_str = f"{task:<16}"
            event_str = f"{event_type:<16}"
            print(f"{pid:<8} {task_str} {event_str} {dec_str} {detail}")
