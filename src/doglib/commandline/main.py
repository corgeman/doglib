import argparse
import sys

from pwnlib.context import context


def main() -> None:
    context.log_console = sys.stderr

    from doglib.commandline import fetchld, solve

    parser = argparse.ArgumentParser(
        prog="dog",
        description="doglib CLI",
    )
    sub = parser.add_subparsers(dest="command")
    fetchld.register(sub)
    solve.register(sub)

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    args.func(args)
