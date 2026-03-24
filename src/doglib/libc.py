"""
Glibc identification and download from Ubuntu/Debian package mirrors.

Provides version-string scanning, build-ID lookups via libcdb, and
.deb downloading/extraction for libc, ld, and debug symbols.
"""
from __future__ import annotations

import io
import json
import os
import tarfile
import urllib.parse
from typing import Optional, Tuple

from pwnlib import libcdb
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util.fiddling import enhex
from pwnlib.util.web import wget

log = getLogger(__name__)

# ── Version string identifiers (from pwninit) ───────────────────────

_VERSION_IDENTIFIERS: list[Tuple[bytes, str, str]] = [
    (b"GNU C Library (Ubuntu GLIBC ", "ubuntu", "libc"),
    (b"GNU C Library (Ubuntu EGLIBC ", "ubuntu", "libc"),
    (b"GNU C Library (Debian GLIBC ", "debian", "libc"),
    (b"ld.so (Ubuntu GLIBC ",         "ubuntu", "ld"),
    (b"ld.so (Debian GLIBC ",         "debian", "ld"),
]


def find_version_string(data: bytes) -> Optional[Tuple[str, str, str]]:
    """Scan raw bytes for a glibc version string.

    Works on both libc and ld binaries — the ld linker embeds a similar
    version string starting with ``ld.so (`` instead of ``GNU C Library (``.

    Arguments:
        data: raw bytes from a glibc artifact (libc or ld)

    Returns:
        ``(version, distro, kind)`` tuple, e.g.
        ``("2.31-0ubuntu9.2", "ubuntu", "libc")``, where *kind* is
        ``"libc"`` or ``"ld"``.  Returns ``None`` if no version string
        is found.
    """
    for identifier, distro, kind in _VERSION_IDENTIFIERS:
        idx = data.find(identifier)
        if idx < 0:
            continue
        start = idx + len(identifier)
        end = data.find(b")", start)
        if end < 0:
            continue
        version = data[start:end].decode("ascii", errors="replace")
        log.success("Found glibc version string: %s (%s, %s)", version, distro, kind)
        return version, distro, kind
    return None


def download_libc_by_build_id(build_id: str) -> Optional[str]:
    """Download a libc from libcdb using a hex-encoded build ID.

    Returns:
        Path to the downloaded file on disk, or None.
    """
    log.info("Searching libcdb for build ID %s", build_id)
    path = libcdb.search_by_build_id(build_id)
    if path:
        log.success("Downloaded libc to %s", path)
    else:
        log.warning("Could not find libc for build ID %s", build_id)
    return path


# ── Mirror URLs ──────────────────────────────────────────────────────

_UBUNTU_PKG_URL = "https://launchpad.net/ubuntu/+archive/primary/+files"
_DEBIAN_PKG_URL = "https://deb.debian.org/debian/pool/main/g/glibc"
_DEBIAN_SEC_PKG_URL = "https://security.debian.org/debian-security/pool/updates/main/g/glibc"
_DEBIAN_SNAPSHOT_API = "https://snapshot.debian.org/mr/binary/{pkg}/{version}/binfiles?fileinfo=1"
_DEBIAN_SNAPSHOT_FILE = "https://snapshot.debian.org/file/{hash}"

_LIBC_BASENAMES = {"libc.so.6", "libc-2.so", "libc.so"}

_LD_NAME_GE_234: dict[str, str] = {
    "amd64": "ld-linux-x86-64.so.2",
    "i386":  "ld-linux.so.2",
    "arm64": "ld-linux-aarch64.so.1",
    "armhf": "ld-linux-armhf.so.3",
}

_EMACHINE_TO_DEB_ARCH: dict[int, str] = {
    0x03: "i386",
    0x28: "armhf",
    0x3E: "amd64",
    0xB7: "arm64",
}

# ── .deb / ar parsing ────────────────────────────────────────────────

_AR_MAGIC = b"!<arch>\n"
_AR_HDR_SIZE = 60
_AR_HDR_FMT = "16s12s6s6s8s10sbb"


def _iter_ar(data: bytes):
    """Yield ``(name, content_bytes)`` from an ``ar`` archive."""
    import struct as _struct

    if data[:8] != _AR_MAGIC:
        return
    f = io.BytesIO(data)
    f.seek(8)

    while True:
        hdr = f.read(_AR_HDR_SIZE)
        if len(hdr) < _AR_HDR_SIZE:
            break
        name, _, _, _, _, size_s, _, _ = _struct.unpack(_AR_HDR_FMT, hdr)
        name = name.decode().rstrip().rstrip("/")
        size = int(size_s.decode().rstrip())

        content = f.read(size)
        if size & 1:
            f.seek(1, 1)

        if name in ("/", "//"):
            continue
        yield name, content


def _extract_libc_from_deb(deb_data: bytes, out_dir: str) -> Optional[str]:
    """Extract ``libc.so.6`` from a ``.deb`` package."""
    tar_name = None
    tar_data = None
    for name, content in _iter_ar(deb_data):
        if name.startswith("data.tar"):
            tar_name = name
            tar_data = content
            break

    if tar_data is None:
        return None

    if tar_name.endswith(".zst") or tar_name.endswith(".zstd"):
        import zstandard
        tar_data = zstandard.ZstdDecompressor().decompress(
            tar_data, max_output_size=256 * 1024 * 1024,
        )

    with tarfile.open(fileobj=io.BytesIO(tar_data)) as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            basename = os.path.basename(member.name)
            if basename in _LIBC_BASENAMES:
                f = tf.extractfile(member)
                if f is None:
                    continue
                final = os.path.join(out_dir, basename)
                with open(final, "wb") as out:
                    out.write(f.read())
                return final

    return None


def _extract_named_file_from_deb(
    deb_data: bytes, target_basename: str, out_path: str
) -> Optional[str]:
    """Extract a single file by basename from a ``.deb``."""
    tar_name = None
    tar_data = None
    for name, content in _iter_ar(deb_data):
        if name.startswith("data.tar"):
            tar_name = name
            tar_data = content
            break

    if tar_data is None:
        return None

    if tar_name.endswith(".zst") or tar_name.endswith(".zstd"):
        import zstandard
        tar_data = zstandard.ZstdDecompressor().decompress(
            tar_data, max_output_size=256 * 1024 * 1024,
        )

    with tarfile.open(fileobj=io.BytesIO(tar_data)) as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            if os.path.basename(member.name) == target_basename:
                f = tf.extractfile(member)
                if f is None:
                    continue
                with open(out_path, "wb") as out:
                    out.write(f.read())
                return out_path

    return None


def _query_debian_snapshot(deb_name: str, version: str, pkg: str = "libc6") -> Optional[str]:
    """Query snapshot.debian.org for a stable download URL."""
    api_url = _DEBIAN_SNAPSHOT_API.format(
        pkg=urllib.parse.quote(pkg, safe=""),
        version=urllib.parse.quote(version, safe=""),
    )
    try:
        raw = wget(api_url, timeout=20)
        if not raw:
            return None
        data = json.loads(raw)
        for hash_val, file_infos in data.get("fileinfo", {}).items():
            for fi in file_infos:
                if fi.get("name") == deb_name:
                    return _DEBIAN_SNAPSHOT_FILE.format(hash=hash_val)
    except Exception:
        pass
    return None


def _download_deb(deb_name: str, distro: str, version: str, w, pkg: str = "libc6") -> Optional[bytes]:
    """Download a glibc ``.deb``, trying all appropriate mirrors in order."""
    if distro == "ubuntu":
        url = "%s/%s" % (_UBUNTU_PKG_URL, deb_name)
        w.status(url)
        return wget(url, timeout=20)

    if distro == "debian":
        for url in (
            "%s/%s" % (_DEBIAN_PKG_URL, deb_name),
            "%s/%s" % (_DEBIAN_SEC_PKG_URL, deb_name),
        ):
            w.status(url)
            deb_data = wget(url, timeout=20)
            if deb_data:
                return deb_data
        w.status("querying snapshot.debian.org...")
        snapshot_url = _query_debian_snapshot(deb_name, version, pkg=pkg)
        if snapshot_url:
            w.status(snapshot_url)
            return wget(snapshot_url, timeout=60)

    return None


def download_libc_by_version(
    version: str,
    distro: str,
    arch: str = "amd64",
) -> Optional[str]:
    """Download a libc from Ubuntu/Debian package mirrors by version string.

    Arguments:
        version: Full version string, e.g. ``"2.39-0ubuntu8.5"``.
        distro:  ``"ubuntu"`` or ``"debian"``.
        arch:    ``"amd64"`` or ``"i386"``.

    Returns:
        Path to the extracted libc on disk, or ``None``.
    """
    if distro not in ("ubuntu", "debian"):
        log.warning("Unknown distro %r, cannot download libc", distro)
        return None

    deb_name = "libc6_%s_%s.deb" % (version, arch)

    cache_dir = os.path.join(context.cache_dir, "dumpelf_libc",
                             "%s_%s_%s" % (distro, version, arch))
    cached = os.path.join(cache_dir, "libc.so.6")
    if os.path.exists(cached):
        log.success("Using cached libc at %s", cached)
        return cached

    w = log.waitfor("Downloading libc from %s" % distro)

    package = _download_deb(deb_name, distro, version, w)
    if not package:
        w.failure("package not found on any mirror")
        return None

    os.makedirs(cache_dir, exist_ok=True)
    w.status("extracting libc from deb")

    try:
        libc_path = _extract_libc_from_deb(package, cache_dir)
    except Exception as e:
        w.failure("extraction failed: %s" % e)
        return None

    if libc_path and os.path.exists(libc_path):
        w.success("saved to %s" % libc_path)
        return libc_path

    w.failure("could not find libc.so.6 inside deb")
    return None


def elf_deb_arch(libc_path: str) -> str:
    """Return the Debian architecture name for the ELF at *libc_path*.

    Reads the ``e_machine`` field from the ELF header and maps it to the
    Debian multiarch name (e.g. ``"amd64"``, ``"arm64"``).  Falls back to
    ``"amd64"`` for unrecognised machines.
    """
    import struct

    try:
        with open(libc_path, "rb") as f:
            header = f.read(20)
        if len(header) >= 20 and header[:4] == b"\x7fELF":
            e_machine = struct.unpack_from("<H", header, 18)[0]
            return _EMACHINE_TO_DEB_ARCH.get(e_machine, "amd64")
    except OSError:
        pass
    return "amd64"


def fetch_ld_by_version(
    version: str,
    distro: str,
    arch: str = "amd64",
    out_path: Optional[str] = None,
) -> Optional[str]:
    """Download the ld linker matching a given glibc version from package mirrors.

    Arguments:
        version:  Full version string, e.g. ``"2.35-0ubuntu3.6"``.
        distro:   ``"ubuntu"`` or ``"debian"``.
        arch:     Debian arch name: ``"amd64"``, ``"i386"``, ``"arm64"``,
                  ``"armhf"``.
        out_path: Where to write the ld.  Defaults to ``"ld-SHORT.so"`` in
                  the current working directory.

    Returns:
        Path to the downloaded ld on disk, or ``None``.
    """
    version_short = version.split("-")[0]
    out_name = f"ld-{version_short}.so"
    final_out = out_path or out_name

    ver_tuple = tuple(int(x) for x in version_short.split(".")[:2])
    if ver_tuple < (2, 34):
        ld_in_deb = f"ld-{version_short}.so"
    else:
        ld_in_deb = _LD_NAME_GE_234.get(arch, "ld-linux-x86-64.so.2")

    cache_dir = os.path.join(
        context.cache_dir, "dumpelf_ld", "%s_%s_%s" % (distro, version, arch)
    )
    cached = os.path.join(cache_dir, out_name)
    if os.path.exists(cached):
        log.success("Using cached ld at %s", cached)
        if final_out != cached:
            import shutil
            shutil.copy2(cached, final_out)
        return final_out

    if distro not in ("ubuntu", "debian"):
        log.warning("Unknown distro %r, cannot download ld", distro)
        return None

    deb_name = "libc6_%s_%s.deb" % (version, arch)

    w = log.waitfor("Downloading ld from %s" % distro)

    package = _download_deb(deb_name, distro, version, w)
    if not package:
        w.failure("package not found on any mirror")
        return None

    os.makedirs(cache_dir, exist_ok=True)
    w.status("extracting %s from deb" % ld_in_deb)

    try:
        result = _extract_named_file_from_deb(package, ld_in_deb, cached)
    except Exception as e:
        w.failure("extraction failed: %s" % e)
        return None

    if result and os.path.exists(result):
        w.success("saved to %s" % result)
        if final_out != cached:
            import shutil
            shutil.copy2(cached, final_out)
        return final_out

    w.failure("could not find %s inside deb" % ld_in_deb)
    return None


def _download_debug_deb(
    version: str,
    distro: str,
    arch: str = "amd64",
) -> Optional[bytes]:
    """Download the ``libc6-dbg`` ``.deb`` for the given glibc version."""
    if distro not in ("ubuntu", "debian"):
        log.warning("Unknown distro %r, cannot download libc6-dbg", distro)
        return None

    deb_name = "libc6-dbg_%s_%s.deb" % (version, arch)
    w = log.waitfor("Downloading libc6-dbg from %s" % distro)

    package = _download_deb(deb_name, distro, version, w, pkg="libc6-dbg")
    if not package:
        w.failure("libc6-dbg package not found on any mirror")
        return None

    w.success("downloaded %s" % deb_name)
    return package


def _extract_debug_file(
    deb_data: bytes,
    build_id: Optional[str],
    fallback_basename: str,
    tmp_dir: str,
) -> Optional[str]:
    """Extract a debug symbols file from a ``libc6-dbg`` deb."""
    candidates: list[str] = []
    if build_id and len(build_id) > 2:
        candidates.append(build_id[2:] + ".debug")
    candidates.append(fallback_basename)

    for candidate in candidates:
        out_path = os.path.join(tmp_dir, candidate)
        try:
            result = _extract_named_file_from_deb(deb_data, candidate, out_path)
        except Exception:
            result = None
        if result and os.path.exists(result):
            return result

    return None


def fetch_debug_by_version(
    version: str,
    distro: str,
    arch: str = "amd64",
    build_id: Optional[str] = None,
    ld_build_id: Optional[str] = None,
) -> dict[str, Optional[str]]:
    """Download debug symbols for glibc from the ``libc6-dbg`` .deb.

    Arguments:
        version:     Full glibc version string, e.g. ``"2.38-1ubuntu6.3"``.
        distro:      ``"ubuntu"`` or ``"debian"``.
        arch:        Debian arch name: ``"amd64"``, ``"i386"``, ``"arm64"``,
                     ``"armhf"``.
        build_id:    Hex build-ID of the **libc**.
        ld_build_id: Hex build-ID of the **ld** linker.

    Returns:
        Dict with keys ``"libc"`` and ``"ld"``, each mapping to the
        extracted debug file path or ``None``.
    """
    import tempfile

    version_short = version.split("-")[0]
    ver_tuple = tuple(int(x) for x in version_short.split(".")[:2])

    package = _download_debug_deb(version, distro, arch)
    if package is None:
        return {"libc": None, "ld": None}

    tmp_dir = tempfile.mkdtemp(prefix="doglib_dbg_")
    results: dict[str, Optional[str]] = {"libc": None, "ld": None}

    libc_fallback = "libc-%s.so" % version_short
    libc_dbg = _extract_debug_file(package, build_id, libc_fallback, tmp_dir)
    if libc_dbg:
        log.success("extracted libc debug: %s", os.path.basename(libc_dbg))
        results["libc"] = libc_dbg

    if ld_build_id is not None:
        if ver_tuple < (2, 34):
            ld_fallback = "ld-%s.so" % version_short
        else:
            ld_fallback = _LD_NAME_GE_234.get(arch, "ld-linux-x86-64.so.2")
        ld_dbg = _extract_debug_file(package, ld_build_id, ld_fallback, tmp_dir)
        if ld_dbg:
            log.success("extracted ld debug: %s", os.path.basename(ld_dbg))
            results["ld"] = ld_dbg

    if results["libc"] is None and results["ld"] is None:
        import shutil
        shutil.rmtree(tmp_dir, ignore_errors=True)
        log.warning("could not find debug symbols inside libc6-dbg deb")

    return results
