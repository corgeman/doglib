"""dog guesser — train and query the byte-level n-gram flag guesser."""

import sys


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "guesser",
        help="Train or query the flag guesser",
        description="Byte-level n-gram flag guesser. Sub-commands: train, guess.",
    )
    sub = p.add_subparsers(dest="guesser_cmd")

    # --- train ---
    t = sub.add_parser(
        "train",
        help="Train a model from a flags file",
        description="Train a byte-level n-gram model from a file of flags (one per line).",
    )
    t.add_argument("flags_file", help="Path to a file with one flag per line.")
    t.add_argument(
        "-o", "--output",
        default="model.json.gz",
        help="Output model path (gzip-compressed JSON). Default: model.json.gz",
    )
    t.add_argument("--order", type=int, default=5, help="N-gram order (default: 5).")
    t.add_argument(
        "--generic",
        action="store_true",
        help="Train on raw lines without stripping the flag prefix before '{'.",
    )
    t.set_defaults(func=_train)

    # --- guess ---
    g = sub.add_parser(
        "guess",
        help="Show top-N likely next bytes for a flag prefix",
        description="Load a model and print the most likely next bytes for a given prefix.",
    )
    g.add_argument(
        "prefix",
        help="Flag prefix (UTF-8 string, or hex bytes with --hex).",
    )
    g.add_argument(
        "-m", "--model",
        default=None,
        help="Path to a trained model (.json.gz). Omit to use the bundled model.",
    )
    g.add_argument("--top", type=int, default=5, help="How many guesses to show (default: 5).")
    g.add_argument("--hex", action="store_true", help="Interpret PREFIX as hex bytes.")
    g.set_defaults(func=_guess)

    p.set_defaults(func=lambda args: (p.print_help(), sys.exit(1)))


def _train(args) -> None:
    import os
    from doglib.flagguesser import NGramModel

    flags: list[bytes] = []
    with open(args.flags_file, "rb") as f:
        for raw in f:
            line = raw.rstrip(b"\r\n")
            if not line:
                continue
            if not args.generic:
                brace = line.find(b"{")
                if brace != -1:
                    line = line[brace + 1:]
            flags.append(line)

    if not flags:
        print(f"No flags found in {args.flags_file}", file=sys.stderr)
        sys.exit(1)

    model = NGramModel(order=args.order)
    model.fit(flags)
    model.save(args.output)

    size = os.path.getsize(args.output)
    print(
        f"trained on {len(flags)} flags, order={args.order}, "
        f"{model.num_contexts()} unique contexts, "
        f"saved to {args.output} ({size} bytes)"
    )


def _printable(b: int) -> str:
    if 32 <= b < 127:
        return chr(b)
    named = {0x09: "\\t", 0x0A: "\\n", 0x0D: "\\r"}
    if b in named:
        return named[b]
    return f"\\x{b:02x}"


def _guess(args) -> None:
    from doglib.flagguesser import Guesser, NGramModel, guesser as _bundled

    if args.hex:
        try:
            prefix = bytes.fromhex(args.prefix)
        except ValueError as e:
            print(f"invalid hex prefix: {e}", file=sys.stderr)
            sys.exit(2)
    else:
        prefix = args.prefix.encode("utf-8")

    if args.model:
        g = Guesser(NGramModel.load(args.model))
    else:
        g = _bundled

    ranked = g.guess(prefix, stats=True)[: max(1, args.top)]

    try:
        shown = prefix.decode("utf-8")
    except UnicodeDecodeError:
        shown = prefix.hex()

    print()
    print(f"  {shown} →")
    print()
    for b, prob in ranked:
        print(f"    {_printable(b):<5} {prob * 100:5.1f}%")
    print()
