"""dog fetchld — download the ld linker that matches a given libc."""

import os
import sys


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "fetchld",
        help="Download the ld linker matching a given libc file",
        description=(
            "Reads the glibc version string embedded in LIBC, downloads the "
            "matching libc6 .deb from the Ubuntu/Debian package mirror, and "
            "extracts the ld linker from it.  Prints the output path to stdout."
        ),
    )
    p.add_argument("libc", metavar="LIBC", help="Path to the libc shared library")
    p.add_argument(
        "-o", "--out",
        metavar="PATH",
        help=(
            "Where to write the ld linker "
            "(default: ld-VERSION.so next to the libc file)"
        ),
    )
    p.set_defaults(func=main)


def main(args) -> None:
    from doglib.dumpelf._libc import (
        elf_deb_arch,
        fetch_ld_by_version,
        find_version_string,
    )

    libc_path = os.path.realpath(args.libc)
    if not os.path.isfile(libc_path):
        print(f"[-] File not found: {libc_path}", file=sys.stderr)
        sys.exit(1)

    try:
        data = open(libc_path, "rb").read()
    except OSError as e:
        print(f"[-] Cannot read {libc_path}: {e}", file=sys.stderr)
        sys.exit(1)

    result = find_version_string(data)
    if result is None:
        print(
            f"[-] No Ubuntu/Debian glibc version string found in {libc_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    version, distro = result
    version_short = version.split("-")[0]
    arch = elf_deb_arch(libc_path)

    if args.out:
        out_path = os.path.realpath(args.out)
    else:
        out_path = os.path.join(os.path.dirname(libc_path), f"ld-{version_short}.so")

    if os.path.exists(out_path):
        print(f"[*] {out_path} already exists, skipping download.", file=sys.stderr)
        print(out_path)
        return

    result_path = fetch_ld_by_version(version, distro, arch=arch, out_path=out_path)
    if result_path is None:
        print(
            f"[-] Failed to download ld for {version} ({distro}/{arch})",
            file=sys.stderr,
        )
        sys.exit(1)

    os.chmod(result_path, 0o755)
    print(result_path)
