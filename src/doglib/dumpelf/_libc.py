"""
Remote libc identification via leak primitives.

The build-ID extraction here requires a remote arbitrary-read (leak
function) and is specific to the DumpELF workflow.  General-purpose
download/identification utilities live in :mod:`doglib.libc`.
"""
from __future__ import annotations

from typing import Optional

from pwnlib import libcdb
from pwnlib.log import getLogger
from pwnlib.util.fiddling import enhex

log = getLogger(__name__)

# Re-export the general-purpose functions so existing internal imports
# (e.g. from _dumper.py) continue to work without changes everywhere.
from doglib.libc import (  # noqa: F401
    find_version_string,
    download_libc_by_build_id,
    download_libc_by_version,
)

# ── ELF constants ────────────────────────────────────────────────────

PT_NOTE = 4
NT_GNU_BUILD_ID = 3


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
    for offset in libcdb.get_build_id_offsets():
        bid = _try_build_id_at(leak, libc_base + offset)
        if bid:
            log.success("Found build ID at offset %#x: %s", offset, bid)
            return bid

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
