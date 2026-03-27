"""
Main DumpELF class: remote ELF dumping via an arbitrary-read primitive.

Handles all remote interaction (leak calls), then delegates to
``_reconstruct`` for building the final ELF file and ``_libc`` for
remote library identification.
"""
from __future__ import annotations

import ctypes
from typing import Callable, Dict, Optional, Union

from pwnlib import elf as pwnelf
from pwnlib.context import context
from pwnlib.elf.elf import ELF
from pwnlib.elf.datatypes import (
    Elf32_Ehdr, Elf64_Ehdr,
    Elf32_Phdr, Elf64_Phdr,
    Elf32_Dyn, Elf64_Dyn,
    Elf32_Link_Map, Elf64_Link_Map,
    Elf_eident,
    Elf_i386_GOT, Elf_x86_64_GOT,
    Elf32_r_debug, Elf64_r_debug,
    constants,
)
from pwnlib.log import getLogger
from pwnlib.memleak import MemLeak

from doglib.dumpelf._reconstruct import reconstruct_elf
from doglib.dumpelf._libc import (
    find_build_id,
    find_version_string,
    download_libc_by_build_id,
    download_libc_by_version,
)

log = getLogger(__name__)
sizeof = ctypes.sizeof

# ── DT constants needed for link-map discovery ──────────────────────
DT_NULL    = 0
DT_PLTGOT  = 3
DT_DEBUG   = 21
DT_BIND_NOW = 24

PT_LOAD    = 1
PT_DYNAMIC = 2


class DumpELF:
    """Remote ELF dumper.

    Given an arbitrary-read primitive and a pointer into the target
    binary, ``DumpELF`` can:

    * Find the binary's base address
    * Dump all loaded segments from memory
    * Reconstruct a valid ELF file (with section headers and fixed GOT)
    * Walk the link map to discover loaded libraries
    * Identify the remote libc (by build ID or version string)

    Arguments:
        leak: A callable ``(addr) -> bytes`` that leaks one or more
              bytes starting at *addr*, or a ``MemLeak`` instance.
              When *bulk* is ``True``, the signature must be
              ``(addr, count) -> bytes`` instead — *count* is the
              maximum number of bytes wanted; return as many as your
              vulnerability can deliver in one trip (up to *count*),
              and ``DumpELF`` will loop to fill the remainder.
        pointer: Any valid address inside the target binary.
        elf: Optional local ``ELF`` object to speed up base-finding.
        bulk: If ``True``, treat *leak* as a bulk-capable function
              ``(addr, count) -> bytes``.  Segment dumps will call it
              once per segment (looping only when a short read occurs),
              dramatically reducing round-trips for high-latency leaks.

    Example (standard)::

        def leak(addr):
            p.send(p64(addr))
            return p.recvn(1)

        d = DumpELF(leak, known_ptr)
        d.dump('dumped.elf')

    Example (bulk — format-string loop that can pipeline many reads)::

        def leak(addr, count):
            # pipeline `count` single-byte reads in one send/recv
            p.send(b''.join(fmtstr_read(addr + i) for i in range(count)))
            return p.recvn(count)

        d = DumpELF(leak, known_ptr, bulk=True)
        d.dump('dumped.elf')
        libc = d.libc
    """

    def __init__(
        self,
        leak: Union[Callable, MemLeak],
        pointer: int,
        elf: Optional[ELF] = None,
        bulk: bool = False,
    ):
        self._bulk_leak: Optional[Callable] = None

        if bulk:
            # leak(addr, count) -> bytes; wrap a single-byte version for MemLeak
            self._bulk_leak = leak
            def _single(addr: int) -> bytes:
                return self._bulk_leak(addr, context.bytes)  # type: ignore[misc]
            leak = MemLeak(_single)
        elif not isinstance(leak, MemLeak):
            leak = MemLeak(leak)

        self.leak = leak
        self._bulk = bulk
        self._elf = elf
        self._elfclass: Optional[int] = None
        self._elftype: Optional[str] = None
        self._base: Optional[int] = None
        self._dynamic: Optional[int] = None
        self._link_map: Optional[int] = None
        self._bases: Optional[Dict[bytes, int]] = None
        self._segments: Optional[Dict[int, bytes]] = None
        self._libc: Optional[ELF] = None

        self._pointer = pointer

        if elf:
            self._elfclass = elf.elfclass
            self._elftype = elf.elftype

    # ── Properties ──────────────────────────────────────────────────

    @property
    def elfclass(self) -> int:
        """32 or 64."""
        if self._elfclass is None:
            ec = self.leak.field(self.base, Elf_eident.EI_CLASS)
            self._elfclass = {constants.ELFCLASS32: 32,
                              constants.ELFCLASS64: 64}[ec]
        return self._elfclass

    @property
    def elftype(self) -> str:
        """``'EXEC'`` or ``'DYN'`` (PIE)."""
        if self._elftype is None:
            Ehdr = {32: Elf32_Ehdr, 64: Elf64_Ehdr}[self.elfclass]
            et = self.leak.field(self.base, Ehdr.e_type)
            self._elftype = {constants.ET_EXEC: "EXEC",
                             constants.ET_DYN: "DYN"}.get(et, "UNKNOWN")
        return self._elftype

    @property
    def is_pie(self) -> bool:
        return self.elftype == "DYN"

    @property
    def base(self) -> int:
        """Base address of the remote binary."""
        if self._base is None:
            self._base = self._find_base(self._pointer)
        return self._base

    @property
    def dynamic(self) -> Optional[int]:
        """Address of the DYNAMIC segment."""
        if self._dynamic is None:
            self._dynamic = self._find_dynamic()
        return self._dynamic

    @property
    def link_map(self) -> Optional[int]:
        """Pointer to the runtime ``link_map`` structure."""
        if self._link_map is None:
            self._link_map = self._find_link_map()
        return self._link_map

    @property
    def bases(self) -> Dict[bytes, int]:
        """Map of library name to base address, via the link map."""
        if self._bases is None:
            self._bases = self._walk_link_map()
        return self._bases

    # ── Base address finding ────────────────────────────────────────

    def _find_base(self, ptr: int) -> int:
        page_size = 0x1000
        ptr &= ~(page_size - 1)

        w = log.waitfor("Finding base address")
        while True:
            if self.leak.compare(ptr, b"\x7fELF"):
                w.success("%#x" % ptr)
                return ptr

            if self._elf:
                fast = self._find_base_optimized(ptr)
                if fast is not None:
                    ptr = fast
                    continue

            ptr -= page_size
            if ptr < 0:
                w.failure("address went negative")
                raise ValueError("Could not find ELF base (address went negative)")
            w.status("%#x" % ptr)

    def _find_base_optimized(self, ptr: int) -> Optional[int]:
        """Use a local ELF copy to skip pages faster."""
        if not self._elf:
            return None

        probe = ptr + 0x20
        data = self.leak.n(probe, 32)
        if not data:
            return None

        matches = list(self._elf.search(data))
        if len(matches) != 1:
            return None

        candidate = matches[0] - self._elf.address
        if candidate & 0xfff != 0x20:
            return None

        return ptr - candidate + 0x20

    # ── PHDR / DYNAMIC finding ──────────────────────────────────────

    def _find_dynamic(self) -> Optional[int]:
        leak = self.leak
        base = self.base
        Ehdr = {32: Elf32_Ehdr, 64: Elf64_Ehdr}[self.elfclass]
        Phdr = {32: Elf32_Phdr, 64: Elf64_Phdr}[self.elfclass]

        phead = base + leak.field(base, Ehdr.e_phoff)
        phnum = leak.field(base, Ehdr.e_phnum)

        for i in range(phnum):
            if leak.field_compare(phead, Phdr.p_type, constants.PT_DYNAMIC):
                dyn = leak.field(phead, Phdr.p_vaddr)
                dyn = self._make_absolute(dyn)
                log.info("PT_DYNAMIC at %#x", dyn)
                return dyn
            phead += sizeof(Phdr)
        log.warning("Could not find PT_DYNAMIC")
        return None

    def _find_dt(self, tag: int) -> Optional[int]:
        """Find an entry in the DYNAMIC array by tag."""
        leak = self.leak
        dynamic = self.dynamic
        if dynamic is None:
            return None
        Dyn = {32: Elf32_Dyn, 64: Elf64_Dyn}[self.elfclass]

        while not leak.field_compare(dynamic, Dyn.d_tag, DT_NULL):
            if leak.field_compare(dynamic, Dyn.d_tag, tag):
                ptr = leak.field(dynamic, Dyn.d_ptr)
                return self._make_absolute(ptr)
            dynamic += sizeof(Dyn)
        return None

    # ── Link map ────────────────────────────────────────────────────

    def _find_link_map(self) -> Optional[int]:
        leak = self.leak
        Got = {32: Elf_i386_GOT, 64: Elf_x86_64_GOT}[self.elfclass]
        r_debug = {32: Elf32_r_debug, 64: Elf64_r_debug}[self.elfclass]

        w = log.waitfor("Finding link_map")
        linkmap = None

        pltgot = self._find_dt(constants.DT_PLTGOT)
        if pltgot:
            linkmap = leak.field(pltgot, Got.linkmap)
            if linkmap:
                w.status("GOT.linkmap %#x" % linkmap)

        if not linkmap:
            debug = self._find_dt(constants.DT_DEBUG)
            if debug:
                linkmap = leak.field(debug, r_debug.r_map)
                if linkmap:
                    w.status("r_debug.r_map %#x" % linkmap)

        if not linkmap:
            w.failure("could not find link_map")
            return None

        linkmap = self._make_absolute(linkmap)
        w.success("%#x" % linkmap)
        return linkmap

    def _walk_link_map(self) -> Dict[bytes, int]:
        if self.link_map is None:
            return {}

        leak = self.leak
        LinkMap = {32: Elf32_Link_Map, 64: Elf64_Link_Map}[self.elfclass]
        result: Dict[bytes, int] = {}

        cur = self.link_map
        # Rewind to start
        while leak.field(cur, LinkMap.l_prev):
            cur = leak.field(cur, LinkMap.l_prev)

        while cur:
            p_name = leak.field(cur, LinkMap.l_name)
            name = leak.s(p_name) if p_name else b""
            addr = leak.field(cur, LinkMap.l_addr)
            log.debug("link_map: %r @ %#x", name, addr)
            result[name] = addr
            cur = leak.field(cur, LinkMap.l_next)

        return result

    # ── Bulk read helper ────────────────────────────────────────────

    def _bulk_read(self, addr: int, total: int) -> Optional[bytes]:
        """Read *total* bytes starting at *addr* using the bulk leak callable.

        Loops when the user's function returns a short read, so the caller
        always gets exactly *total* bytes (or ``None`` on the first failure).
        """
        buf = b""
        while len(buf) < total:
            chunk = self._bulk_leak(addr + len(buf), total - len(buf))  # type: ignore[misc]
            if not chunk:
                return buf if buf else None
            buf += chunk
        return buf

    # ── Segment dumping ─────────────────────────────────────────────

    def _dump_segments(self) -> Dict[int, bytes]:
        """Dump all PT_LOAD segments from the remote binary."""
        leak = self.leak
        base = self.base

        Ehdr = {32: Elf32_Ehdr, 64: Elf64_Ehdr}[self.elfclass]
        Phdr = {32: Elf32_Phdr, 64: Elf64_Phdr}[self.elfclass]

        phead = base + leak.field(base, Ehdr.e_phoff)
        phnum = leak.field(base, Ehdr.e_phnum)

        segments: Dict[int, bytes] = {}
        w = log.waitfor("Dumping segments")

        for i in range(phnum):
            p_type = leak.field(phead, Phdr.p_type)
            if p_type == PT_LOAD:
                vaddr = leak.field(phead, Phdr.p_vaddr)
                memsz = leak.field(phead, Phdr.p_memsz)

                vaddr = self._make_absolute(vaddr)

                # Page-align
                page_off = vaddr & 0xfff
                if page_off:
                    memsz += page_off
                    vaddr -= page_off
                memsz = (memsz + 0xfff) & ~0xfff

                w.status("segment %d: %#x (%#x bytes)" % (i, vaddr, memsz))
                data = (self._bulk_read(vaddr, memsz)
                        if self._bulk_leak else leak.n(vaddr, memsz))
                if data:
                    segments[vaddr] = data

            phead += sizeof(Phdr)

        w.success("dumped %d segments" % len(segments))
        return segments

    @property
    def segments(self) -> Dict[int, bytes]:
        """Cached dumped segments."""
        if self._segments is None:
            self._segments = self._dump_segments()
        return self._segments

    # ── Public API ──────────────────────────────────────────────────

    def dump(self, path: Optional[str] = None) -> bytes:
        """Dump and reconstruct the remote ELF.

        Arguments:
            path: If given, write the reconstructed ELF to this file.

        Returns:
            The reconstructed ELF as bytes.
        """
        elf_bytes = reconstruct_elf(self.segments, self.base, self.elfclass)

        if path:
            with open(path, "wb") as f:
                f.write(elf_bytes)
            log.success("Wrote reconstructed ELF to %s", path)

        return elf_bytes

    def dump_lib(self, name: Union[str, bytes], path: Optional[str] = None) -> bytes:
        """Dump a loaded library by (substring) name.

        Arguments:
            name: Substring to match in the link map (e.g. ``"libc"``).
            path: If given, write the reconstructed ELF to this file.

        Returns:
            The reconstructed ELF as bytes.
        """
        if isinstance(name, str):
            name = name.encode()

        for lib_name, lib_base in self.bases.items():
            if name in lib_name:
                log.info("Found %r at %#x", lib_name, lib_base)
                lib_dumper = DumpELF(self._bulk_leak or self.leak, lib_base,
                                     bulk=bool(self._bulk_leak))
                return lib_dumper.dump(path)

        raise ValueError(f"library matching {name!r} not found in link map")

    @property
    def libc(self) -> Optional[ELF]:
        """Identify the remote libc, download it, and return an ELF object.

        Tries build-ID extraction first, then version-string scanning.
        The returned ELF has its base address set to the remote libc's base.
        """
        if self._libc is not None:
            return self._libc

        w = log.waitfor("Identifying remote libc")

        # Find libc base from link map
        libc_base = None
        for lib_name, addr in self.bases.items():
            if b"libc" in lib_name and b".so" in lib_name:
                libc_base = addr
                w.status("libc base: %#x" % libc_base)
                break

        if libc_base is None:
            w.failure("could not find libc in link map")
            return None

        # Strategy 1: build ID
        w.status("trying build ID extraction")
        build_id = find_build_id(self.leak, libc_base)
        if build_id:
            libc_path = download_libc_by_build_id(build_id)
            if libc_path:
                with context.local(log_level="error"):
                    libc = ELF(libc_path)
                libc.address = libc_base
                self._libc = libc
                w.success("identified via build ID: %s" % build_id)
                return libc

        # Strategy 2: version string → download from distro mirror
        w.status("trying version string scan")
        try:
            lib_dumper = DumpELF(self._bulk_leak or self.leak, libc_base,
                                 bulk=bool(self._bulk_leak))
            for seg_data in lib_dumper.segments.values():
                result = find_version_string(seg_data)
                if result:
                    version, distro, _kind = result
                    arch = "amd64" if self.elfclass == 64 else "i386"
                    libc_path = download_libc_by_version(version, distro, arch)
                    if libc_path:
                        with context.local(log_level="error"):
                            libc = ELF(libc_path)
                        libc.address = libc_base
                        self._libc = libc
                        w.success("identified as %s %s via version string" % (distro, version))
                        return libc
                    w.failure("identified as %s %s but download failed" % (distro, version))
                    return None
        except Exception as e:
            log.debug("Version string scan failed: %s", e)

        w.failure("could not identify remote libc")
        return None

    # ── Helpers ──────────────────────────────────────────────────────

    def _make_absolute(self, ptr_or_offset: int) -> int:
        """Convert a potential offset to an absolute address for PIE/DYN binaries."""
        if self.elftype != "DYN":
            return ptr_or_offset
        if 0 <= ptr_or_offset < self.base:
            return ptr_or_offset + self.base
        return ptr_or_offset
