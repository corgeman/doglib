"""dog dopow — connect to a host, auto-solve its PoW, then go interactive."""

import sys


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "dopow",
        help="Connect to host:port, auto-solve PoW, then go interactive",
        description=(
            "Connects to HOST on PORT, waits for and solves any recognised "
            "proof-of-work challenge, then hands control to you interactively. "
        ),
    )
    p.add_argument("host", metavar="HOST", help="Remote hostname or IP")
    p.add_argument("port", metavar="PORT", type=int, help="Remote port")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show connection and PoW progress info")
    p.set_defaults(func=main)


def main(args) -> None:
    from pwnlib.tubes.remote import remote
    from pwnlib.log import getLogger, install_default_handler
    from pwnlib.context import context
    from doglib.pow import do_pow

    install_default_handler()
    context.log_level = "debug" if args.verbose else "error"

    log = getLogger("pwnlib.doglib.dopow")

    p = remote(args.host, args.port)

    try:
        do_pow(p)
    except ValueError as e:
        log.critical(f"PoW solving failed: {e}")
        sys.exit(1)

    p.interactive()
    print()
