"""
Command-line interface for KernelGuard.
"""

import argparse
import os
import sys
from pathlib import Path

from kernelguard.controller import DEFAULT_POLICY_PATH, ExecveController
from kernelguard.logger import KernelGuardLogger


def daemonize(pid_file: str = "/tmp/kernelguard.pid", log_file: str = "/tmp/kernelguard.log") -> None:
    """Detach current process to run as a UNIX daemon."""
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as exc:
        sys.stderr.write(f"Fork #1 failed: {exc}\n")
        sys.exit(1)

    os.setsid()
    os.umask(0)

    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as exc:
        sys.stderr.write(f"Fork #2 failed: {exc}\n")
        sys.exit(1)

    sys.stdout.flush()
    sys.stderr.flush()

    with open(log_file, "a", encoding="utf-8") as log_out:
        os.dup2(log_out.fileno(), sys.stdout.fileno())
        os.dup2(log_out.fileno(), sys.stderr.fileno())

    with open(pid_file, "w", encoding="utf-8") as pfile:
        pfile.write(str(os.getpid()))

    def remove_pid_file() -> None:
        try:
            if os.path.exists(pid_file):
                os.remove(pid_file)
        except OSError:
            pass

    import atexit
    atexit.register(remove_pid_file)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="KernelGuard — Linux Kernel-Level Runtime Security & Policy Enforcement Monitor."
    )

    parser.add_argument(
        "--pid",
        type=int,
        default=0,
        help="Target process ID to monitor/enforce (default: 0 for all processes).",
    )

    parser.add_argument(
        "--enforce",
        action="store_true",
        help="Enable kernel-side policy enforcement (return -EPERM for unauthorized operations).",
    )

    parser.add_argument(
        "--policy",
        type=Path,
        default=DEFAULT_POLICY_PATH,
        help=f"Path to JSON policy file (default: {DEFAULT_POLICY_PATH}).",
    )

    parser.add_argument(
        "--daemon",
        action="store_true",
        help="Run KernelGuard in background daemon mode.",
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in console output.",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output logging.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.pid < 0:
        parser.error("--pid must be 0 or a positive PID")

    if not args.policy.exists():
        parser.error(f"Policy file does not exist: {args.policy}")

    logger = KernelGuardLogger(
        use_color=not args.no_color,
        verbose=args.verbose,
    )

    if args.daemon:
        logger.info("Starting KernelGuard daemon in background...")
        daemonize()

    controller = ExecveController(
        target_pid=args.pid,
        enforce=args.enforce,
        policy_path=args.policy,
        logger=logger,
    )
    controller.run(daemon=args.daemon)


if __name__ == "__main__":
    main()
