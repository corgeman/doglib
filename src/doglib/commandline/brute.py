"""dog brute — run a solve script in parallel until one attempt wins."""

import argparse
import ast
import os
import sys
import time


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "brute",
        help="Run a solve script in parallel until dog.finish() is called",
        description=(
            "Spawn multiple workers running the same solve script. When one "
            "worker calls dog.finish(), dog brute hands that worker's terminal "
            "back to you for interactive use."
        ),
    )
    p.add_argument(
        "-n",
        "--workers",
        type=_positive_int,
        default=min(8, os.cpu_count() or 1),
        metavar="N",
        help="Initial worker count (default: min(8, os.cpu_count()))",
    )
    p.add_argument(
        "--timeout",
        type=_positive_float,
        default=60.0,
        metavar="SEC",
        help="Per-attempt timeout in seconds (default: 60)",
    )
    p.add_argument(
        "--delay",
        type=_nonnegative_float,
        default=0.0,
        metavar="SEC",
        help="Delay before respawning a finished attempt (default: 0)",
    )
    p.add_argument(
        "--instant",
        action="store_true",
        help="Immediately hand off to a worker when it calls dog.finish()",
    )
    p.add_argument(
        "--no-finish-check",
        action="store_true",
        help="Skip the static check that warns when solve.py has no finish() call",
    )
    p.add_argument("solve_path", metavar="solve.py", help="Solve script to run")
    p.add_argument(
        "script_args",
        nargs=argparse.REMAINDER,
        metavar="script-arg",
        help="Arguments passed to solve.py",
    )
    p.set_defaults(func=main)


def main(args) -> None:
    from doglib.brute._orchestrator import run

    script_args = list(args.script_args)
    if script_args[:1] == ["--"]:
        script_args = script_args[1:]

    if not args.no_finish_check and _has_finish_call(args.solve_path) is False:
        print(
            f"warning: no call to finish() found in {args.solve_path} — "
            "dog brute will not work as intended!!",
            "see docs/CLI/brute.md",
            file=sys.stderr,
        )
        time.sleep(5)

    sys.exit(
        run(
            args.solve_path,
            script_args,
            args.workers,
            args.timeout,
            args.delay,
            args.instant,
        )
    )


def _has_finish_call(path: str) -> bool | None:
    """True if the script appears to call finish(); False if not; None if undetermined."""
    try:
        with open(path, "rb") as f:
            tree = ast.parse(f.read(), filename=path)
    except (OSError, SyntaxError, ValueError):
        return None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "finish":
            return True
        if isinstance(func, ast.Attribute) and func.attr == "finish":
            return True
    return False


def _positive_int(value: str) -> int:
    parsed = int(value, 0)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _nonnegative_float(value: str) -> float:
    parsed = float(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed
