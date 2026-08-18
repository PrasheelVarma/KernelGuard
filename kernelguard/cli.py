"""
Command-line interface for KernelGuard.
"""

import argparse

from kernelguard.controller import ExecveController


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="KernelGuard eBPF runtime security monitor."
    )

    parser.add_argument(
        "--pid",
        type=int,
        default=0,
        help="only report execve events from this process",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.pid < 0:
        parser.error("--pid must be 0 or a positive PID")

    controller = ExecveController(target_pid=args.pid)
    controller.run()


if __name__ == "__main__":
    main()
