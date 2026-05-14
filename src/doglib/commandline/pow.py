"""dog pow — proof-of-work tools: connect+solve, offline solve, backend check."""

import sys


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "pow",
        help="Proof-of-work tools",
        description="Proof-of-work tools. Sub-commands: nc, solve, check.",
    )
    sub = p.add_subparsers(dest="pow_cmd")

    nc = sub.add_parser(
        "nc",
        help="Connect to HOST:PORT, auto-solve PoW, then go interactive",
        description=(
            "Connects to HOST on PORT, waits for and solves any recognised "
            "proof-of-work challenge, then hands control to you interactively."
        ),
    )
    nc.add_argument("host", metavar="HOST", help="Remote hostname or IP")
    nc.add_argument("port", metavar="PORT", type=int, help="Remote port")
    nc.add_argument("-v", "--verbose", action="store_true",
                    help="Show connection and PoW progress info")
    nc.set_defaults(func=_nc)

    sv = sub.add_parser(
        "solve",
        help="Solve a PoW challenge string (no network)",
        description=(
            "Auto-detect the PoW format from CHALLENGE and print the solution. "
            "Pass '-' as CHALLENGE to read the challenge from stdin."
        ),
    )
    sv.add_argument(
        "challenge",
        metavar="CHALLENGE",
        help="Challenge string (or '-' to read from stdin)",
    )
    sv.set_defaults(func=_solve)

    ck = sub.add_parser(
        "check",
        help="Show PoW backend / GPU acceleration status",
        description="Report which solver backends are available (rust, CUDA).",
    )
    ck.set_defaults(func=_check)

    p.set_defaults(func=lambda args: (p.print_help(), sys.exit(1)))


def _nc(args) -> None:
    from pwnlib.tubes.remote import remote
    from pwnlib.log import install_default_handler
    from pwnlib.context import context
    from pwnlib import term
    from doglib.pow import do_pow

    install_default_handler()
    context.log_level = "debug" if args.verbose else "error"

    p = remote(args.host, args.port)

    from pwnlib.log import getLogger
    log = getLogger("pwnlib.doglib.pow")
    try:
        do_pow(p)
    except ValueError as e:
        log.critical(f"PoW solving failed: {e}")
        sys.exit(1)

    if sys.stdout.isatty() and not term.term_mode:
        term.init()

    p.interactive()
    print()


def _solve(args) -> None:
    from doglib.pow import detect_and_solve

    if args.challenge == "-":
        data = sys.stdin.buffer.read()
    else:
        data = args.challenge.encode()

    solution = detect_and_solve(data)
    if solution is None:
        print("error: no known PoW format detected", file=sys.stderr)
        sys.exit(2)

    sys.stdout.buffer.write(solution + b"\n")


def _check(args) -> None:
    try:
        from doglib_rs import pow_solver as _rs_pow
        rs_installed = True
    except ImportError:
        _rs_pow = None
        rs_installed = False

    try:
        from importlib.metadata import version as _meta_version
        rs_version = _meta_version("doglib_rs")
        rs_label = f"installed ({rs_version})"
    except Exception:
        rs_label = "installed" if rs_installed else "not installed"

    if not rs_installed:
        print(f"doglib_rs:     not installed")
        print(f"cuda feature:  n/a")
        print(f"cuda init:     n/a")
        print()
        print("status: CPU-only Python fallback (very slow)")
        return

    info = _rs_pow.backend_info()

    cuda_compiled = info in ("cuda", "cuda-init-failed")
    cuda_ok = info == "cuda"

    print(f"doglib_rs:     {rs_label}")
    print(f"cuda feature:  {'compiled in' if cuda_compiled else 'not compiled'}")
    print(f"cuda init:     {'ok' if cuda_ok else 'failed' if cuda_compiled else 'n/a'}")
    print()

    if cuda_ok:
        print("status: GPU acceleration available")
    elif cuda_compiled:
        print("status: CPU-only (cuda compiled but driver/init failed)")
    else:
        print("status: CPU-only (rust, no GPU)")
