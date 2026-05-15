import argparse
import sys


def main() -> None:
    from doglib.commandline import fetch, solve, flagguesser, orc, brute
    from doglib.commandline import pow as pow_cli

    parser = argparse.ArgumentParser(
        prog="dog",
        description="doglib CLI",
    )
    sub = parser.add_subparsers(dest="command")
    fetch.register(sub)
    solve.register(sub)
    pow_cli.register(sub)
    flagguesser.register(sub)
    orc.register(sub)
    brute.register(sub)

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    from pwnlib.context import context
    context.log_console = sys.stderr

    args.func(args)


if __name__ == "__main__":
    main()
