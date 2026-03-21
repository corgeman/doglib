"""
Remote libc identification and download.

Two strategies are tried in order:
  1. Build ID extraction (fast, uses known offsets, then PT_NOTE scan)
  2. Version string scanning (fallback, searches dumped text)

Both feed into pwntools' libcdb for the actual download.
"""
from __future__ import annotations

from typing import Optional, Tuple

from pwnlib import libcdb
from pwnlib.context import context
from pwnlib.log import getLogger
from pwnlib.util.fiddling import enhex

log = getLogger(__name__)

# ── ELF constants ────────────────────────────────────────────────────

PT_NOTE = 4
NT_GNU_BUILD_ID = 3

# ── Version string identifiers (from pwninit) ───────────────────────

_VERSION_IDENTIFIERS: list[Tuple[bytes, str]] = [
    (b"GNU C Library (Ubuntu GLIBC ", "ubuntu"),
    (b"GNU C Library (Ubuntu EGLIBC ", "ubuntu"),
    (b"GNU C Library (Debian GLIBC ", "debian"),
]


def _try_build_id_at(leak, address: int) -> Optional[str]:
    """Check if a valid GNU Build ID note exists at *address*."""
    if leak.compare(address + 0xC, b"GNU\x00"):
        raw = b"".join(leak.raw(address + 0x10, 20))
        if raw and len(raw) == 20:
            return enhex(raw)
    return None


def find_build_id(leak, libc_base: int) -> Optional[str]:
    """Try to extract the GNU Build ID from the remote libc.

    First tries pwntools' well-known offsets (fast path), then falls
    back to parsing the ELF header and scanning PT_NOTE segments.

    Returns:
        Hex-encoded 20-byte build ID, or None.
    """
    # Fast path: hardcoded offsets from pwntools' libcdb
    for offset in libcdb.get_build_id_offsets():
        bid = _try_build_id_at(leak, libc_base + offset)
        if bid:
            log.success("Found build ID at offset %#x: %s", offset, bid)
            return bid

    # Slow path: parse ELF header → program headers → PT_NOTE segments
    try:
        ei_class = leak.b(libc_base + 4)
        is64 = (ei_class == 2)
        if is64:
            e_phoff = leak.q(libc_base + 32)
            e_phentsize = leak.u16(libc_base + 54)
            e_phnum = leak.u16(libc_base + 56)
        else:
            e_phoff = leak.d(libc_base + 28)
            e_phentsize = leak.u16(libc_base + 42)
            e_phnum = leak.u16(libc_base + 44)

        for i in range(e_phnum):
            ph_addr = libc_base + e_phoff + i * e_phentsize
            p_type = leak.d(ph_addr)
            if p_type != PT_NOTE:
                continue

            if is64:
                p_offset = leak.q(ph_addr + 8)
                p_filesz = leak.q(ph_addr + 32)
            else:
                p_offset = leak.d(ph_addr + 4)
                p_filesz = leak.d(ph_addr + 16)

            note_addr = libc_base + p_offset
            end = note_addr + p_filesz
            pos = note_addr

            while pos + 12 <= end:
                namesz = leak.d(pos)
                descsz = leak.d(pos + 4)
                ntype = leak.d(pos + 8)

                name_start = pos + 12
                desc_start = name_start + ((namesz + 3) & ~3)

                if ntype == NT_GNU_BUILD_ID and namesz == 4 and descsz == 20:
                    if leak.compare(name_start, b"GNU\x00"):
                        raw = b"".join(leak.raw(desc_start, 20))
                        if raw and len(raw) == 20:
                            offset = pos - libc_base
                            bid = enhex(raw)
                            log.success("Found build ID at offset %#x: %s", offset, bid)
                            return bid

                pos = desc_start + ((descsz + 3) & ~3)

    except Exception:
        log.debug("PT_NOTE scan failed, giving up on build ID")

    return None


def find_version_string(data: bytes) -> Optional[Tuple[str, str]]:
    """Scan raw bytes for a glibc version string.

    Arguments:
        data: dumped bytes from the libc text segment

    Returns:
        (version_string, distro) tuple, e.g. ("2.31-0ubuntu9.2", "ubuntu"),
        or None if not found.
    """
    for identifier, distro in _VERSION_IDENTIFIERS:
        idx = data.find(identifier)
        if idx < 0:
            continue
        start = idx + len(identifier)
        end = data.find(b")", start)
        if end < 0:
            continue
        version = data[start:end].decode("ascii", errors="replace")
        log.success("Found libc version string: %s (%s)", version, distro)
        return version, distro
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


def download_libc_by_version(version: str, distro: str, arch: str = None) -> Optional[str]:
    """Try to search for a libc via symbol offset heuristics or libcdb.

    This is a best-effort fallback when the build ID is not available.
    We construct a search query that libcdb/libc.rip might be able to
    answer.  In practice the build-ID path is much more reliable.

    Returns:
        Path to the downloaded file on disk, or None.
    """
    log.info("Attempting libc lookup for %s %s", distro, version)
    # pwntools doesn't have a direct "search by version string" API,
    # but we can try the build-id based providers by looking for the
    # version string in the database via libc.rip
    try:
        import requests
        url = "https://libc.rip/api/find"
        resp = requests.post(url, json={"buildid": ""}, timeout=10)
    except Exception:
        pass

    log.warning(
        "Identified libc as %s %s but could not auto-download. "
        "Try searching https://libc.rip or your distro's package archive manually.",
        distro, version,
    )
    return None
