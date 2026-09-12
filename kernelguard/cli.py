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

    # Global options for top-level / legacy invocations
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

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 'run' subcommand
    parser_run = subparsers.add_parser(
        "run",
        help="Safely execute a Python script under zero-day eBPF sandbox confinement.",
    )
    parser_run.add_argument(
        "--policy",
        type=Path,
        default=DEFAULT_POLICY_PATH,
        help=f"Path to JSON policy file (default: {DEFAULT_POLICY_PATH}).",
    )
    parser_run.add_argument(
        "--enforce",
        action="store_true",
        default=True,
        help="Enable kernel-side policy enforcement (default: True).",
    )
    parser_run.add_argument(
        "--no-enforce",
        action="store_false",
        dest="enforce",
        help="Disable enforcement (monitoring only).",
    )
    parser_run.add_argument(
        "--daemon",
        action="store_true",
        help="Run KernelGuard in background daemon mode.",
    )
    parser_run.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in console output.",
    )
    parser_run.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output logging.",
    )
    parser_run.add_argument(
        "script",
        type=Path,
        help="Path to Python script to execute.",
    )
    parser_run.add_argument(
        "script_args",
        nargs=argparse.REMAINDER,
        help="Optional arguments to pass to the script.",
    )

    # 'attach' subcommand
    parser_attach = subparsers.add_parser(
        "attach",
        help="Attach KernelGuard to an existing running process by PID.",
    )
    parser_attach.add_argument(
        "--pid",
        type=int,
        required=True,
        help="Target process ID to monitor/enforce.",
    )
    parser_attach.add_argument(
        "--enforce",
        action="store_true",
        help="Enable kernel-side policy enforcement (return -EPERM for unauthorized operations).",
    )
    parser_attach.add_argument(
        "--policy",
        type=Path,
        default=DEFAULT_POLICY_PATH,
        help=f"Path to JSON policy file (default: {DEFAULT_POLICY_PATH}).",
    )
    parser_attach.add_argument(
        "--daemon",
        action="store_true",
        help="Run KernelGuard in background daemon mode.",
    )
    parser_attach.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in console output.",
    )
    parser_attach.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output logging.",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Handle 'run' subcommand
    if args.command == "run":
        if not args.script.exists():
            parser.error(f"Script file does not exist: {args.script}")

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
            target_pid=0,  # Will be assigned from child_pid before load()
            enforce=args.enforce,
            policy_path=args.policy,
            logger=logger,
        )
        exit_code = controller.run_script(
            script_path=args.script,
            script_args=args.script_args,
            daemon=args.daemon,
        )
        sys.exit(exit_code)

    # Handle 'attach' or legacy root flags
    pid = getattr(args, "pid", 0)
    enforce = getattr(args, "enforce", False)

    if pid < 0:
        parser.error("--pid must be 0 or a positive PID")

    if enforce and pid == 0:
        parser.error(
            "System-wide enforcement (PID 0) is disabled for safety. "
            "You must specify a target --pid > 0 when using --enforce."
        )

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
        target_pid=pid,
        enforce=enforce,
        policy_path=args.policy,
        logger=logger,
    )
    controller.run(daemon=args.daemon)


if __name__ == "__main__":
    main()
