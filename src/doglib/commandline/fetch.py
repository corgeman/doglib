"""dog fetch — download glibc counterparts and optionally apply debug symbols.

Given any glibc artifact (libc or ld), auto-detects what it is, downloads the
missing counterpart from Ubuntu/Debian package mirrors, and prints the path of
the fetched file to stdout.  With --dbg, also downloads libc6-dbg and applies
debug symbols via eu-unstrip.
"""

import os
import shutil
import subprocess
import sys
import tempfile


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "fetch",
        help="Download glibc counterpart (ld↔libc) and optionally apply debug symbols",
        description=(
            "Auto-detects whether FILE is a libc or ld linker by scanning for "
            "the embedded glibc version string, then downloads the missing "
            "counterpart from Ubuntu/Debian package mirrors.  With --dbg, also "
            "fetches and applies debug symbols from the libc6-dbg package."
        ),
    )
    p.add_argument(
        "file", metavar="FILE",
        help="Path to a glibc artifact (libc or ld linker)",
    )
    p.add_argument(
        "--ld", metavar="LD",
        help="Explicitly provide the ld linker (when FILE is a libc)",
    )
    p.add_argument(
        "--dbg", action="store_true",
        help="Also download and apply debug symbols from libc6-dbg",
    )
    p.add_argument(
        "-f", "--force", action="store_true",
        help="Re-apply debug symbols even if .debug_info already present",
    )
    p.add_argument(
        "-o", "--out", metavar="PATH",
        help="Where to write the fetched counterpart (default: next to FILE)",
    )
    p.set_defaults(func=main)


def _has_debug_info(path: str) -> bool:
    try:
        out = subprocess.check_output(
            ["readelf", "-S", path], stderr=subprocess.DEVNULL, text=True,
        )
        return ".debug_info" in out
    except Exception:
        return False


def _read_build_id(path: str) -> str | None:
    try:
        out = subprocess.check_output(
            ["readelf", "-n", path], stderr=subprocess.DEVNULL, text=True,
        )
        for line in out.splitlines():
            if "Build ID:" in line:
                return line.split("Build ID:")[-1].strip()
    except Exception:
        pass
    return None


def _apply_debug(target_path: str, debug_path: str, label: str) -> bool:
    """Run eu-unstrip to merge debug symbols into *target_path*."""
    tmp_out = target_path + ".fetch.tmp"
    try:
        proc = subprocess.run(
            ["eu-unstrip", "-o", tmp_out, target_path, debug_path],
            capture_output=True,
        )
        if proc.returncode == 0 and os.path.exists(tmp_out):
            os.replace(tmp_out, target_path)
            print(
                f"[+] Debug symbols applied to {label} '{target_path}'.",
                file=sys.stderr,
            )
            return True
        else:
            print(
                f"[-] eu-unstrip failed for {label}: "
                f"{proc.stderr.decode(errors='replace')}",
                file=sys.stderr,
            )
            return False
    except FileNotFoundError:
        print(
            "[-] eu-unstrip not found; please install elfutils.",
            file=sys.stderr,
        )
        return False
    finally:
        if os.path.exists(tmp_out):
            os.unlink(tmp_out)


def main(args) -> None:
    from doglib.libc import (
        download_libc_by_version,
        elf_deb_arch,
        fetch_debug_by_version,
        fetch_ld_by_version,
        find_version_string,
    )

    input_path = os.path.realpath(args.file)
    if not os.path.isfile(input_path):
        print(f"[-] File not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    ld_explicit = os.path.realpath(args.ld) if args.ld else None
    if ld_explicit and not os.path.isfile(ld_explicit):
        print(f"[-] File not found: {ld_explicit}", file=sys.stderr)
        sys.exit(1)

    try:
        data = open(input_path, "rb").read()
    except OSError as e:
        print(f"[-] Cannot read {input_path}: {e}", file=sys.stderr)
        sys.exit(1)

    result = find_version_string(data)
    if result is None:
        print(
            f"[-] No Ubuntu/Debian glibc version string found in {input_path}",
            file=sys.stderr,
        )
        sys.exit(1)

    version, distro, kind = result
    version_short = version.split("-")[0]
    arch = elf_deb_arch(input_path)
    input_dir = os.path.dirname(input_path)

    # Determine libc_path and ld_path based on what was provided.
    libc_path: str | None = None
    ld_path: str | None = None
    fetched_path: str | None = None

    if kind == "libc":
        libc_path = input_path
        ld_path = ld_explicit

        if ld_path is None:
            if args.out:
                out = os.path.realpath(args.out)
            else:
                out = os.path.join(input_dir, f"ld-{version_short}.so")

            if os.path.exists(out):
                print(
                    f"[*] {out} already exists, skipping download.",
                    file=sys.stderr,
                )
                ld_path = out
            else:
                ld_path = fetch_ld_by_version(
                    version, distro, arch=arch, out_path=out,
                )
                if ld_path is None:
                    print(
                        f"[-] Failed to download ld for {version} ({distro}/{arch})",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                os.chmod(ld_path, 0o755)

            fetched_path = ld_path

    elif kind == "ld":
        ld_path = input_path

        if args.out:
            out = os.path.realpath(args.out)
        else:
            out = os.path.join(input_dir, "libc.so.6")

        if os.path.exists(out):
            print(
                f"[*] {out} already exists, skipping download.",
                file=sys.stderr,
            )
            libc_path = out
        else:
            cached = download_libc_by_version(version, distro, arch=arch)
            if cached is None:
                print(
                    f"[-] Failed to download libc for {version} ({distro}/{arch})",
                    file=sys.stderr,
                )
                sys.exit(1)
            shutil.copy2(cached, out)
            os.chmod(out, 0o755)
            libc_path = out

        fetched_path = libc_path

    # Print the fetched file path to stdout for script consumption.
    if fetched_path:
        print(fetched_path)

    # --dbg: download libc6-dbg and apply debug symbols.
    if args.dbg:
        targets: list[tuple[str, str]] = []
        if libc_path and (args.force or not _has_debug_info(libc_path)):
            targets.append((libc_path, "libc"))
        if ld_path and (args.force or not _has_debug_info(ld_path)):
            targets.append((ld_path, "ld"))

        if not targets:
            print(
                "[+] All files already have debug symbols. "
                "Skipping. (use --force to override)",
                file=sys.stderr,
            )
            return

        libc_bid = _read_build_id(libc_path) if libc_path else None
        ld_bid = _read_build_id(ld_path) if ld_path else None

        debug = fetch_debug_by_version(
            version, distro, arch=arch,
            build_id=libc_bid,
            ld_build_id=ld_bid,
        )

        try:
            for path, label in targets:
                dbg_file = debug.get(label)
                if dbg_file:
                    _apply_debug(path, dbg_file, label)
                else:
                    print(
                        f"[-] Could not find {label} debug symbols in libc6-dbg deb.",
                        file=sys.stderr,
                    )
        finally:
            for p in (debug.get("libc"), debug.get("ld")):
                if p and os.path.exists(p):
                    tmp_dir = os.path.dirname(p)
                    if os.path.commonpath(
                        [tmp_dir, tempfile.gettempdir()]
                    ) == tempfile.gettempdir():
                        shutil.rmtree(tmp_dir, ignore_errors=True)
                        break
