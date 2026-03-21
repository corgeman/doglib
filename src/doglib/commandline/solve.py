"""dog solve — write a solve.py exploit template."""

import os
import sys
from pathlib import Path


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "solve",
        help="Write a pwntools solve.py template",
        description=(
            "Fills in TEMPLATE with ELF bindings for the given binary, libc, "
            "and ld, then writes the result to OUTPUT (default: solve.py).  "
            "Does nothing if the output file already exists and --no-overwrite "
            "is passed."
        ),
    )
    p.add_argument("--bin", required=True, dest="bin_path", metavar="PATH",
                   help="Path to the binary (becomes the 'exe' ELF binding)")
    p.add_argument("--libc", dest="libc_path", metavar="PATH",
                   help="Path to the libc (becomes the 'libc' ELF binding)")
    p.add_argument("--ld", dest="ld_path", metavar="PATH",
                   help="Path to the ld linker (becomes the 'ld' ELF binding)")
    p.add_argument("--template", required=True, metavar="PATH",
                   help="Path to the template file")
    p.add_argument("--out", default="solve.py", metavar="PATH",
                   help="Output path (default: solve.py)")
    p.add_argument("--no-overwrite", action="store_true",
                   help="Do nothing if the output file already exists")
    p.set_defaults(func=main)


def main(args) -> None:
    out = Path(args.out)

    if out.exists() and args.no_overwrite:
        print(f"[*] {args.out} already exists, skipping.", file=sys.stderr)
        return

    template_path = Path(args.template)
    if not template_path.is_file():
        print(f"[-] Template not found: {args.template}", file=sys.stderr)
        sys.exit(1)

    lines = []
    if args.bin_path:
        lines.append(f'exe = ELF("{args.bin_path}")')
    if args.libc_path:
        lines.append(f'libc = ELF("{args.libc_path}")')
    if args.ld_path:
        lines.append(f'ld = ELF("{args.ld_path}")')
    bindings = "\n".join(lines)

    template = template_path.read_text()
    try:
        stub = template.format_map({
            "bindings": bindings,
            "bin_name": "exe",
            "proc_args": "[exe.path]",
        })
    except KeyError as e:
        print(f"[-] Unknown placeholder in template: {e}", file=sys.stderr)
        sys.exit(1)

    out.write_text(stub)
    out.chmod(0o755)
    print(f"[+] Written {args.out}", file=sys.stderr)
