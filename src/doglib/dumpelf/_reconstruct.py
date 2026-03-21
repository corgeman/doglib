"""
ELF reconstruction from dumped memory segments.

Takes raw PT_LOAD segment data (as dumped from a remote process) and
rebuilds a valid ELF file with section headers, fixed GOT, and
corrected PIE offsets.  Based on the approach from core2ELF64.
"""
from __future__ import annotations

import ctypes
import struct
from typing import Dict, List, Optional, Tuple

from pwnlib.log import getLogger

log = getLogger(__name__)

# ── DT_ constants not exported by pwntools ──────────────────────────
DT_NULL         = 0
DT_NEEDED       = 1
DT_PLTRELSZ     = 2
DT_PLTGOT       = 3
DT_HASH         = 4
DT_STRTAB       = 5
DT_SYMTAB       = 6
DT_RELA         = 7
DT_RELASZ       = 8
DT_RELAENT      = 9
DT_STRSZ        = 10
DT_SYMENT       = 11
DT_INIT         = 12
DT_FINI         = 13
DT_PLTREL       = 20
DT_DEBUG        = 21
DT_JMPREL       = 23
DT_BIND_NOW     = 24
DT_INIT_ARRAY   = 25
DT_FINI_ARRAY   = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
DT_FLAGS        = 30
DT_FLAGS_1      = 0x6ffffffb
DT_VERNEED      = 0x6ffffffe
DT_VERNEEDNUM   = 0x6fffffff
DT_VERSYM       = 0x6ffffff0
DT_GNU_HASH     = 0x6ffffef5
DT_REL          = 17
DT_RELSZ        = 18
DT_RELENT       = 19

# ELF type
ET_DYN  = 3
ET_EXEC = 2

# p_type
PT_NULL          = 0
PT_LOAD          = 1
PT_DYNAMIC       = 2
PT_INTERP        = 3
PT_NOTE          = 4
PT_TLS           = 7
PT_GNU_EH_FRAME  = 0x6474e550
PT_GNU_STACK     = 0x6474e551
PT_GNU_RELRO     = 0x6474e552
PT_PHDR          = 6

# p_flags
PF_X = 1
PF_W = 2
PF_R = 4

# sh_type
SHT_NULL        = 0
SHT_PROGBITS    = 1
SHT_SYMTAB      = 2
SHT_STRTAB      = 3
SHT_RELA        = 4
SHT_HASH        = 5
SHT_DYNAMIC     = 6
SHT_NOTE        = 7
SHT_NOBITS      = 8
SHT_REL         = 9
SHT_DYNSYM      = 11
SHT_INIT_ARRAY  = 14
SHT_FINI_ARRAY  = 15
SHT_GNU_HASH    = 0x6ffffff6
SHT_GNU_versym  = 0x6fffffff
SHT_GNU_verneed = 0x6ffffffe

# sh_flags
SHF_WRITE     = 0x1
SHF_ALLOC     = 0x2
SHF_EXECINSTR = 0x4
SHF_TLS       = 0x400

# ── Section string table ────────────────────────────────────────────
SHSTRTAB = (
    b"\0"
    b".shstrtab\0"
    b".interp\0"
    b".note\0"
    b".dynamic\0"
    b".dynsym\0"
    b".dynstr\0"
    b".gnu.hash\0"
    b".gnu.version\0"
    b".gnu.version_r\0"
    b".rela.dyn\0"
    b".rela.plt\0"
    b".rel.dyn\0"
    b".rel.plt\0"
    b".init\0"
    b".plt\0"
    b".text\0"
    b".fini\0"
    b".eh_frame_hdr\0"
    b".eh_frame\0"
    b".init_array\0"
    b".fini_array\0"
    b".got.plt\0"
    b".got\0"
    b".data\0"
    b".bss\0"
    b".tbss\0"
)


def _shstr_index(name: bytes) -> int:
    """Return the offset of *name* inside SHSTRTAB."""
    idx = SHSTRTAB.find(name + b"\0")
    if idx < 0:
        raise ValueError(f"section name {name!r} not in shstrtab")
    return idx


# ── Struct helpers ──────────────────────────────────────────────────

def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]

def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]

def _u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]

def _p16(v: int) -> bytes:
    return struct.pack("<H", v & 0xFFFF)

def _p32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)

def _p64(v: int) -> bytes:
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


class _ElfHeader:
    """Lightweight parser for an in-memory ELF header."""

    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF header")
        self.elfclass = {1: 32, 2: 64}[data[4]]
        self.is64 = self.elfclass == 64

        if self.is64:
            self.e_type      = _u16(data, 16)
            self.e_machine   = _u16(data, 18)
            self.e_entry     = _u64(data, 24)
            self.e_phoff     = _u64(data, 32)
            self.e_shoff     = _u64(data, 40)
            self.e_ehsize    = _u16(data, 52)
            self.e_phentsize = _u16(data, 54)
            self.e_phnum     = _u16(data, 56)
            self.e_shentsize = _u16(data, 58)
            self.e_shnum     = _u16(data, 60)
            self.e_shstrndx  = _u16(data, 62)
        else:
            self.e_type      = _u16(data, 16)
            self.e_machine   = _u16(data, 18)
            self.e_entry     = _u32(data, 24)
            self.e_phoff     = _u32(data, 28)
            self.e_shoff     = _u32(data, 32)
            self.e_ehsize    = _u16(data, 40)
            self.e_phentsize = _u16(data, 42)
            self.e_phnum     = _u16(data, 44)
            self.e_shentsize = _u16(data, 46)
            self.e_shnum     = _u16(data, 48)
            self.e_shstrndx  = _u16(data, 50)

    @property
    def is_pie(self) -> bool:
        return self.e_type == ET_DYN


class _Phdr:
    """Lightweight PHDR parser."""

    __slots__ = ("p_type", "p_flags", "p_offset", "p_vaddr", "p_paddr",
                 "p_filesz", "p_memsz", "p_align")

    @classmethod
    def from_bytes(cls, data: bytes, is64: bool) -> "_Phdr":
        p = cls()
        if is64:
            (p.p_type, p.p_flags, p.p_offset, p.p_vaddr, p.p_paddr,
             p.p_filesz, p.p_memsz, p.p_align) = struct.unpack_from("<IIQQQQQQ", data)
        else:
            (p.p_type, p.p_offset, p.p_vaddr, p.p_paddr,
             p.p_filesz, p.p_memsz, p.p_flags, p.p_align) = struct.unpack_from("<IIIIIIII", data)
        return p


class _Shdr:
    """Builder for an ELF section header."""

    SIZE_32 = 40
    SIZE_64 = 64

    def __init__(self):
        self.sh_name      = 0
        self.sh_type      = SHT_NULL
        self.sh_flags     = 0
        self.sh_addr      = 0
        self.sh_offset    = 0
        self.sh_size      = 0
        self.sh_link      = 0
        self.sh_info      = 0
        self.sh_addralign = 0
        self.sh_entsize   = 0

    def pack(self, is64: bool) -> bytes:
        if is64:
            return struct.pack("<IIQQQQIIQQ",
                self.sh_name, self.sh_type, self.sh_flags,
                self.sh_addr, self.sh_offset, self.sh_size,
                self.sh_link, self.sh_info,
                self.sh_addralign, self.sh_entsize)
        return struct.pack("<IIIIIIIIII",
            self.sh_name, self.sh_type, self.sh_flags,
            self.sh_addr, self.sh_offset, self.sh_size,
            self.sh_link, self.sh_info,
            self.sh_addralign, self.sh_entsize)


# ── DYNAMIC section parser ──────────────────────────────────────────

class _DynInfo:
    """Parsed values from the DYNAMIC segment."""

    def __init__(self):
        self.init = 0
        self.fini = 0
        self.init_array = 0
        self.init_arraysz = 0
        self.fini_array = 0
        self.fini_arraysz = 0
        self.gnu_hash = 0
        self.hash = 0
        self.strtab = 0
        self.symtab = 0
        self.strsz = 0
        self.syment = 0
        self.pltgot = 0
        self.pltrelsz = 0
        self.pltrel = 0
        self.jmprel = 0
        self.rela = 0
        self.relasz = 0
        self.relaent = 0
        self.rel = 0
        self.relsz = 0
        self.relent = 0
        self.verneed = 0
        self.verneednum = 0
        self.versym = 0
        self.bind_now = False
        self.debug = 0

    @classmethod
    def parse(cls, dyn_data: bytes, is64: bool, pie_base: int = 0) -> "_DynInfo":
        """Parse a DYNAMIC section from raw bytes.

        *pie_base* is the text segment vaddr for PIE binaries; absolute
        pointer fields that the dynamic linker has already resolved are
        adjusted back to file offsets.
        """
        info = cls()
        entry_size = 16 if is64 else 8
        unpack = "<qQ" if is64 else "<iI"

        for off in range(0, len(dyn_data) - entry_size + 1, entry_size):
            d_tag, d_val = struct.unpack_from(unpack, dyn_data, off)
            if d_tag == DT_NULL:
                break

            _TAG_MAP = {
                DT_INIT:         "init",
                DT_FINI:         "fini",
                DT_INIT_ARRAY:   "init_array",
                DT_INIT_ARRAYSZ: "init_arraysz",
                DT_FINI_ARRAY:   "fini_array",
                DT_FINI_ARRAYSZ: "fini_arraysz",
                DT_GNU_HASH:     "gnu_hash",
                DT_HASH:         "hash",
                DT_STRTAB:       "strtab",
                DT_SYMTAB:       "symtab",
                DT_STRSZ:        "strsz",
                DT_SYMENT:       "syment",
                DT_PLTGOT:       "pltgot",
                DT_PLTRELSZ:     "pltrelsz",
                DT_PLTREL:       "pltrel",
                DT_JMPREL:       "jmprel",
                DT_RELA:         "rela",
                DT_RELASZ:       "relasz",
                DT_RELAENT:      "relaent",
                DT_REL:          "rel",
                DT_RELSZ:        "relsz",
                DT_RELENT:       "relent",
                DT_VERNEED:      "verneed",
                DT_VERNEEDNUM:   "verneednum",
                DT_VERSYM:       "versym",
                DT_DEBUG:        "debug",
            }

            if d_tag == DT_BIND_NOW:
                info.bind_now = True
            elif d_tag == DT_FLAGS and (d_val & 0x08):  # DF_BIND_NOW
                info.bind_now = True
            elif d_tag == DT_FLAGS_1 and (d_val & 0x01):  # DF_1_NOW
                info.bind_now = True
            elif d_tag in _TAG_MAP:
                setattr(info, _TAG_MAP[d_tag], d_val)

        return info


# ── PIE fixup helpers ───────────────────────────────────────────────

# Tags whose d_ptr values are absolute addresses that need rebasing for PIE
_PIE_PTR_TAGS = frozenset({
    DT_GNU_HASH, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_PLTGOT,
    DT_JMPREL, DT_RELA, DT_REL, DT_VERSYM, DT_VERNEED,
    DT_INIT, DT_FINI, DT_INIT_ARRAY, DT_FINI_ARRAY,
})


def _fix_dynamic_for_pie(dyn_data: bytearray, is64: bool, pie_base: int) -> bytearray:
    """Subtract *pie_base* from absolute-pointer DT entries in-place."""
    entry_size = 16 if is64 else 8
    unpack_tag = "<q" if is64 else "<i"
    ptr_off = 8 if is64 else 4
    ptr_fmt = "<Q" if is64 else "<I"

    for off in range(0, len(dyn_data) - entry_size + 1, entry_size):
        d_tag = struct.unpack_from(unpack_tag, dyn_data, off)[0]
        if d_tag == DT_NULL:
            break
        if d_tag in _PIE_PTR_TAGS:
            val = struct.unpack_from(ptr_fmt, dyn_data, off + ptr_off)[0]
            # Some entries (DT_INIT, DT_FINI, etc.) stay as relative offsets
            # at runtime — the linker adds the base internally without
            # rewriting the DYNAMIC entry.  Only rebase if the value looks
            # like an absolute address.
            if val >= pie_base:
                struct.pack_into(ptr_fmt, dyn_data, off + ptr_off, val - pie_base)

    return dyn_data


# ── PLT detection ──────────────────────────────────────────────────

def _find_plt_64(text_data: bytes, text_vaddr: int,
                 init_vaddr: int, pltgot: int) -> Optional[int]:
    """Scan for the PLT[0] stub pattern in x86-64 code.

    Pattern: ff 35 XX XX XX XX   push [rip + GOT+8]
             ff 25 XX XX XX XX   jmp  [rip + GOT+16]
    """
    start = init_vaddr - text_vaddr
    if start < 0:
        start = 0
    end = len(text_data) - 14

    for i in range(start, end):
        if text_data[i] != 0xff or text_data[i + 1] != 0x35:
            continue
        if text_data[i + 6] != 0xff or text_data[i + 7] != 0x25:
            continue

        cur_vaddr = text_vaddr + i
        # The operand of push is a rip-relative offset to GOT+8
        # rip after push instruction = cur_vaddr + 6
        push_target = (cur_vaddr + 6) + struct.unpack_from("<i", text_data, i + 2)[0]
        # The operand of jmp is a rip-relative offset to GOT+16
        jmp_target = (cur_vaddr + 12) + struct.unpack_from("<i", text_data, i + 8)[0]

        if push_target == pltgot + 8 and jmp_target == pltgot + 16:
            return cur_vaddr

    return None


def _find_plt_32(text_data: bytes, text_vaddr: int,
                 init_vaddr: int, pltgot: int) -> Optional[int]:
    """Scan for PLT[0] stub in x86-32.

    Pattern: ff 35 [GOT+4]  push [GOT+4]
             ff 25 [GOT+8]  jmp  [GOT+8]
    """
    start = init_vaddr - text_vaddr
    if start < 0:
        start = 0
    end = len(text_data) - 12

    for i in range(start, end):
        if text_data[i] != 0xff or text_data[i + 1] != 0x35:
            continue
        if text_data[i + 6] != 0xff or text_data[i + 7] != 0x25:
            continue

        push_target = struct.unpack_from("<I", text_data, i + 2)[0]
        jmp_target = struct.unpack_from("<I", text_data, i + 8)[0]

        if push_target == pltgot + 4 and jmp_target == pltgot + 8:
            return text_vaddr + i

    return None


# ── Main reconstruction entry point ────────────────────────────────

def reconstruct_elf(
    segments: Dict[int, bytes],
    base: int,
    elfclass: int,
) -> bytes:
    """Reconstruct a valid ELF from dumped PT_LOAD segments.

    Arguments:
        segments: mapping of vaddr → bytes for each dumped PT_LOAD
        base: base address of the binary (where \\x7fELF magic lives)
        elfclass: 32 or 64

    Returns:
        The reconstructed ELF file as bytes.
    """
    is64 = elfclass == 64
    ptr_size = 8 if is64 else 4

    # ── 1. Parse ELF header from base ──
    if base not in segments:
        for vaddr, data in sorted(segments.items()):
            if vaddr <= base < vaddr + len(data):
                break
        else:
            raise ValueError(f"base address {base:#x} not found in any dumped segment")
    else:
        vaddr, data = base, segments[base]

    ehdr_data = data[base - vaddr:]
    ehdr = _ElfHeader(ehdr_data)

    # ── 2. Parse program headers ──
    phdr_offset = ehdr.e_phoff
    phdr_size = ehdr.e_phentsize
    phdrs: List[_Phdr] = []
    for i in range(ehdr.e_phnum):
        off = phdr_offset + i * phdr_size
        phdrs.append(_Phdr.from_bytes(ehdr_data[off:off + phdr_size], is64))

    # ── 3. Identify key segments ──
    text_seg_idx = -1
    data_seg_idx = -1
    dyn_seg_idx  = -1

    for i, p in enumerate(phdrs):
        if p.p_type == PT_LOAD and (p.p_flags & PF_X) and p.p_vaddr <= ehdr.e_entry:
            if text_seg_idx == -1 or p.p_vaddr <= phdrs[text_seg_idx].p_vaddr:
                text_seg_idx = i
        if p.p_type == PT_LOAD and (p.p_flags & PF_W):
            data_seg_idx = i
        if p.p_type == PT_DYNAMIC:
            dyn_seg_idx = i

    if text_seg_idx == -1:
        for i, p in enumerate(phdrs):
            if p.p_type == PT_LOAD and (p.p_flags & PF_R) and (p.p_flags & PF_X):
                text_seg_idx = i
                break

    if text_seg_idx == -1:
        raise ValueError("could not identify text segment")

    pie_base = base if ehdr.is_pie else 0

    # ── 4. Collect segment data ──
    seg_data: Dict[int, bytes] = {}
    for i, p in enumerate(phdrs):
        if p.p_type not in (PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE,
                            PT_TLS, PT_GNU_EH_FRAME, PT_GNU_RELRO, PT_PHDR):
            if p.p_filesz == 0:
                continue

        abs_vaddr = p.p_vaddr
        if ehdr.is_pie:
            abs_vaddr += pie_base

        for sv, sd in sorted(segments.items()):
            if sv <= abs_vaddr < sv + len(sd):
                local_off = abs_vaddr - sv
                seg_data[i] = sd[local_off:local_off + p.p_filesz]
                break

    # ── 5. Build output buffer ──
    eof = 0
    for p in phdrs:
        end = p.p_offset + p.p_filesz
        if end > eof:
            eof = end
    output = bytearray(eof)

    for i, p in enumerate(phdrs):
        if i in seg_data:
            d = seg_data[i]
            actual_len = min(len(d), p.p_filesz, len(output) - p.p_offset)
            if actual_len > 0:
                output[p.p_offset:p.p_offset + actual_len] = d[:actual_len]

    # ── 6. Parse DYNAMIC ──
    dyn_info: Optional[_DynInfo] = None
    if dyn_seg_idx != -1 and dyn_seg_idx in seg_data:
        raw_dyn = bytearray(seg_data[dyn_seg_idx])
        dyn_phdr = phdrs[dyn_seg_idx]

        if ehdr.is_pie:
            _fix_dynamic_for_pie(raw_dyn, is64, pie_base)
            output[dyn_phdr.p_offset:dyn_phdr.p_offset + len(raw_dyn)] = raw_dyn

        dyn_info = _DynInfo.parse(bytes(raw_dyn), is64, pie_base)

        # Zero out DT_DEBUG d_val — it contains a stale runtime pointer
        # to the old process's r_debug struct.
        entry_size = 16 if is64 else 8
        ptr_off = 8 if is64 else 4
        ptr_fmt = "<Q" if is64 else "<I"
        for off in range(0, len(raw_dyn) - entry_size + 1, entry_size):
            d_tag = struct.unpack_from("<q" if is64 else "<i", raw_dyn, off)[0]
            if d_tag == DT_DEBUG:
                file_off = dyn_phdr.p_offset + off + ptr_off
                output[file_off:file_off + (8 if is64 else 4)] = b"\x00" * (8 if is64 else 4)
                break

    # ── 7. Build section headers ──
    sections: List[_Shdr] = []

    # NULL section
    sections.append(_Shdr())

    # Track indices for link fields
    dynstr_idx = 0
    dynsym_idx = 0
    plt_shdr_idx = 0

    # Sections derived directly from program headers
    for i, p in enumerate(phdrs):
        s = _Shdr()
        if p.p_type == PT_INTERP:
            s.sh_name = _shstr_index(b".interp")
            s.sh_type = SHT_PROGBITS
            s.sh_addr = p.p_vaddr
            s.sh_offset = p.p_offset
            s.sh_size = p.p_filesz
            s.sh_flags = SHF_ALLOC
            s.sh_addralign = 1
            sections.append(s)

        elif p.p_type == PT_DYNAMIC:
            s.sh_name = _shstr_index(b".dynamic")
            s.sh_type = SHT_DYNAMIC
            s.sh_addr = p.p_vaddr
            s.sh_offset = p.p_offset
            s.sh_size = p.p_filesz
            s.sh_flags = SHF_ALLOC
            s.sh_addralign = 8 if is64 else 4
            s.sh_entsize = 16 if is64 else 8
            sections.append(s)

        elif p.p_type == PT_NOTE:
            s.sh_name = _shstr_index(b".note")
            s.sh_type = SHT_NOTE
            s.sh_addr = p.p_vaddr
            s.sh_offset = p.p_offset
            s.sh_size = p.p_filesz
            s.sh_flags = SHF_ALLOC
            s.sh_addralign = 4
            sections.append(s)

        elif p.p_type == PT_TLS:
            s.sh_name = _shstr_index(b".tbss")
            s.sh_type = SHT_NOBITS
            s.sh_addr = p.p_vaddr
            s.sh_offset = p.p_offset
            s.sh_size = p.p_memsz
            s.sh_flags = SHF_ALLOC | SHF_WRITE | SHF_TLS
            s.sh_addralign = 8 if is64 else 4
            sections.append(s)

        elif p.p_type == PT_GNU_EH_FRAME:
            s.sh_name = _shstr_index(b".eh_frame_hdr")
            s.sh_type = SHT_PROGBITS
            s.sh_addr = p.p_vaddr
            s.sh_offset = p.p_offset
            s.sh_size = p.p_filesz
            s.sh_flags = SHF_ALLOC
            s.sh_addralign = 4
            sections.append(s)

            # .eh_frame follows .eh_frame_hdr and extends to the end
            # of whichever PT_LOAD segment contains it
            eh_start = p.p_vaddr + p.p_filesz
            containing_end = 0
            for lp in phdrs:
                if lp.p_type == PT_LOAD and lp.p_vaddr <= p.p_vaddr < lp.p_vaddr + lp.p_memsz:
                    containing_end = lp.p_vaddr + lp.p_filesz
                    break
            eh_size = max(0, containing_end - eh_start)
            if eh_size > 0:
                eh_frame = _Shdr()
                eh_frame.sh_name = _shstr_index(b".eh_frame")
                eh_frame.sh_type = SHT_PROGBITS
                eh_frame.sh_addr = eh_start
                eh_frame.sh_offset = p.p_offset + p.p_filesz
                eh_frame.sh_size = eh_size
                eh_frame.sh_flags = SHF_ALLOC
                eh_frame.sh_addralign = 8 if is64 else 4
                sections.append(eh_frame)

    # .bss (end of data segment)
    if data_seg_idx != -1:
        dp = phdrs[data_seg_idx]
        if dp.p_memsz > dp.p_filesz:
            s = _Shdr()
            s.sh_name = _shstr_index(b".bss")
            s.sh_type = SHT_NOBITS
            s.sh_addr = dp.p_vaddr + dp.p_filesz
            s.sh_offset = dp.p_offset + dp.p_filesz
            s.sh_size = dp.p_memsz - dp.p_filesz
            s.sh_flags = SHF_ALLOC | SHF_WRITE
            s.sh_addralign = 16 if is64 else 4
            sections.append(s)

    # ── 8. DYNAMIC-derived sections ──
    if dyn_info is not None:
        text_p = phdrs[text_seg_idx]

        def _vaddr_to_offset(vaddr: int) -> int:
            """Convert a virtual address to a file offset using PHDR mapping."""
            for p in phdrs:
                if p.p_type == PT_LOAD and p.p_vaddr <= vaddr < p.p_vaddr + p.p_memsz:
                    return p.p_offset + (vaddr - p.p_vaddr)
            return vaddr - text_p.p_vaddr

        def _data_vaddr_to_offset(vaddr: int) -> int:
            """Convert a data-segment virtual address to file offset."""
            for p in phdrs:
                if p.p_type == PT_LOAD and p.p_vaddr <= vaddr < p.p_vaddr + p.p_memsz:
                    return p.p_offset + (vaddr - p.p_vaddr)
            if data_seg_idx == -1:
                return vaddr
            dp = phdrs[data_seg_idx]
            return vaddr - dp.p_vaddr + dp.p_offset

        # .gnu.hash
        if dyn_info.gnu_hash and dyn_info.symtab:
            s = _Shdr()
            s.sh_name = _shstr_index(b".gnu.hash")
            s.sh_type = SHT_GNU_HASH
            s.sh_addr = dyn_info.gnu_hash
            s.sh_offset = _vaddr_to_offset(dyn_info.gnu_hash)
            s.sh_size = dyn_info.symtab - dyn_info.gnu_hash
            s.sh_flags = SHF_ALLOC
            s.sh_addralign = 8 if is64 else 4
            sections.append(s)

        # .dynsym
        if dyn_info.symtab and dyn_info.strtab:
            s = _Shdr()
            s.sh_name = _shstr_index(b".dynsym")
            s.sh_type = SHT_DYNSYM
            s.sh_addr = dyn_info.symtab
            s.sh_offset = _vaddr_to_offset(dyn_info.symtab)
            s.sh_size = dyn_info.strtab - dyn_info.symtab
            s.sh_flags = SHF_ALLOC
            s.sh_addralign = 8 if is64 else 4
            s.sh_entsize = 24 if is64 else 16  # sizeof(Elf64_Sym) / Elf32_Sym
            dynsym_idx = len(sections)
            sections.append(s)

        # .dynstr
        if dyn_info.strtab and dyn_info.strsz:
            s = _Shdr()
            s.sh_name = _shstr_index(b".dynstr")
            s.sh_type = SHT_STRTAB
            s.sh_addr = dyn_info.strtab
            s.sh_offset = _vaddr_to_offset(dyn_info.strtab)
            if dyn_info.versym:
                s.sh_size = dyn_info.versym - dyn_info.strtab
            else:
                s.sh_size = dyn_info.strsz
            s.sh_flags = SHF_ALLOC
            s.sh_addralign = 1
            dynstr_idx = len(sections)
            sections.append(s)

        # .gnu.version
        if dyn_info.versym and dyn_info.symtab and dyn_info.strtab:
            s = _Shdr()
            s.sh_name = _shstr_index(b".gnu.version")
            s.sh_type = SHT_GNU_versym
            s.sh_addr = dyn_info.versym
            s.sh_offset = _vaddr_to_offset(dyn_info.versym)
            num_syms = (dyn_info.strtab - dyn_info.symtab) // (24 if is64 else 16)
            s.sh_size = num_syms * 2
            s.sh_flags = SHF_ALLOC
            s.sh_link = dynsym_idx
            s.sh_addralign = 2
            s.sh_entsize = 2
            sections.append(s)

        # .gnu.version_r
        if dyn_info.verneed and dyn_info.verneednum:
            s = _Shdr()
            s.sh_name = _shstr_index(b".gnu.version_r")
            s.sh_type = SHT_GNU_verneed
            s.sh_addr = dyn_info.verneed
            s.sh_offset = _vaddr_to_offset(dyn_info.verneed)
            if dyn_info.rela:
                s.sh_size = dyn_info.rela - dyn_info.verneed
            elif dyn_info.rel:
                s.sh_size = dyn_info.rel - dyn_info.verneed
            else:
                s.sh_size = 0x40
            s.sh_flags = SHF_ALLOC
            s.sh_link = dynstr_idx
            s.sh_info = dyn_info.verneednum
            s.sh_addralign = 8 if is64 else 4
            sections.append(s)

        # .rela.dyn / .rel.dyn
        if dyn_info.rela and dyn_info.relaent:
            s = _Shdr()
            s.sh_name = _shstr_index(b".rela.dyn")
            s.sh_type = SHT_RELA
            s.sh_addr = dyn_info.rela
            s.sh_offset = _vaddr_to_offset(dyn_info.rela)
            s.sh_size = dyn_info.jmprel - dyn_info.rela if dyn_info.jmprel else dyn_info.relasz
            s.sh_flags = SHF_ALLOC
            s.sh_link = dynsym_idx
            s.sh_addralign = 8 if is64 else 4
            s.sh_entsize = dyn_info.relaent
            sections.append(s)
        elif dyn_info.rel and dyn_info.relent:
            s = _Shdr()
            s.sh_name = _shstr_index(b".rel.dyn")
            s.sh_type = SHT_REL
            s.sh_addr = dyn_info.rel
            s.sh_offset = _vaddr_to_offset(dyn_info.rel)
            s.sh_size = dyn_info.jmprel - dyn_info.rel if dyn_info.jmprel else dyn_info.relsz
            s.sh_flags = SHF_ALLOC
            s.sh_link = dynsym_idx
            s.sh_addralign = 8 if is64 else 4
            s.sh_entsize = dyn_info.relent
            sections.append(s)

        # .rela.plt / .rel.plt
        if dyn_info.jmprel and dyn_info.pltrelsz:
            s = _Shdr()
            if dyn_info.pltrel == DT_RELA:
                s.sh_name = _shstr_index(b".rela.plt")
                s.sh_type = SHT_RELA
                s.sh_entsize = dyn_info.relaent or (24 if is64 else 12)
            else:
                s.sh_name = _shstr_index(b".rel.plt")
                s.sh_type = SHT_REL
                s.sh_entsize = dyn_info.relent or (8 if is64 else 8)
            s.sh_addr = dyn_info.jmprel
            s.sh_offset = _vaddr_to_offset(dyn_info.jmprel)
            s.sh_size = dyn_info.pltrelsz
            s.sh_flags = SHF_ALLOC
            s.sh_link = dynsym_idx
            s.sh_addralign = 8 if is64 else 4
            sections.append(s)

        # Compute GOT entry count
        got_entries = 0
        if dyn_info.pltrel and dyn_info.pltrelsz and dyn_info.pltgot:
            entry_sz = dyn_info.relaent or dyn_info.relent
            if entry_sz:
                got_entries = (dyn_info.pltrelsz // entry_sz) + 3

        # .init, .plt, .text, .fini (require PLT detection)
        plt_addr = 0
        if dyn_info.init and dyn_info.pltgot and got_entries and text_seg_idx != -1:
            text_p = phdrs[text_seg_idx]
            abs_text_vaddr = text_p.p_vaddr + pie_base if ehdr.is_pie else text_p.p_vaddr
            text_data_bytes = bytes(output[text_p.p_offset:text_p.p_offset + text_p.p_filesz])

            if is64:
                plt_addr = _find_plt_64(text_data_bytes, text_p.p_vaddr,
                                        dyn_info.init, dyn_info.pltgot) or 0
            else:
                plt_addr = _find_plt_32(text_data_bytes, text_p.p_vaddr,
                                        dyn_info.init, dyn_info.pltgot) or 0

        if plt_addr:
            # .init
            s = _Shdr()
            s.sh_name = _shstr_index(b".init")
            s.sh_type = SHT_PROGBITS
            s.sh_addr = dyn_info.init
            s.sh_offset = _vaddr_to_offset(dyn_info.init)
            s.sh_size = plt_addr - dyn_info.init
            s.sh_flags = SHF_ALLOC | SHF_EXECINSTR
            s.sh_addralign = 4
            sections.append(s)

            # .plt
            plt_size = (got_entries - 2) * 16 if got_entries > 2 else 16
            s = _Shdr()
            s.sh_name = _shstr_index(b".plt")
            s.sh_type = SHT_PROGBITS
            s.sh_addr = plt_addr
            s.sh_offset = _vaddr_to_offset(plt_addr)
            s.sh_size = plt_size
            s.sh_flags = SHF_ALLOC | SHF_EXECINSTR
            s.sh_addralign = 16
            s.sh_entsize = 16
            plt_shdr_idx = len(sections)
            sections.append(s)

            # .text
            if dyn_info.fini:
                text_start = plt_addr + plt_size
                # Align to 16
                text_start = (text_start + 0xf) & ~0xf
                s = _Shdr()
                s.sh_name = _shstr_index(b".text")
                s.sh_type = SHT_PROGBITS
                s.sh_addr = text_start
                s.sh_offset = _vaddr_to_offset(text_start)
                s.sh_size = dyn_info.fini - text_start
                s.sh_flags = SHF_ALLOC | SHF_EXECINSTR
                s.sh_addralign = 16
                sections.append(s)

            # .fini
            s = _Shdr()
            s.sh_name = _shstr_index(b".fini")
            s.sh_type = SHT_PROGBITS
            s.sh_addr = dyn_info.fini
            s.sh_offset = _vaddr_to_offset(dyn_info.fini)
            s.sh_size = 9 if is64 else 4
            s.sh_flags = SHF_ALLOC | SHF_EXECINSTR
            s.sh_addralign = 4
            sections.append(s)
        elif dyn_info.init:
            # No PLT found, but still emit .init
            s = _Shdr()
            s.sh_name = _shstr_index(b".init")
            s.sh_type = SHT_PROGBITS
            s.sh_addr = dyn_info.init
            s.sh_offset = _vaddr_to_offset(dyn_info.init)
            s.sh_size = 0x20
            s.sh_flags = SHF_ALLOC | SHF_EXECINSTR
            s.sh_addralign = 4
            sections.append(s)

        # .init_array
        if dyn_info.init_array and dyn_info.init_arraysz and data_seg_idx != -1:
            s = _Shdr()
            s.sh_name = _shstr_index(b".init_array")
            s.sh_type = SHT_INIT_ARRAY
            s.sh_addr = dyn_info.init_array
            s.sh_offset = _data_vaddr_to_offset(dyn_info.init_array)
            s.sh_size = dyn_info.init_arraysz
            s.sh_flags = SHF_ALLOC | SHF_WRITE
            s.sh_addralign = ptr_size
            sections.append(s)

        # .fini_array
        if dyn_info.fini_array and dyn_info.fini_arraysz and data_seg_idx != -1:
            s = _Shdr()
            s.sh_name = _shstr_index(b".fini_array")
            s.sh_type = SHT_FINI_ARRAY
            s.sh_addr = dyn_info.fini_array
            s.sh_offset = _data_vaddr_to_offset(dyn_info.fini_array)
            s.sh_size = dyn_info.fini_arraysz
            s.sh_flags = SHF_ALLOC | SHF_WRITE
            s.sh_addralign = ptr_size
            sections.append(s)

        # .got.plt
        if dyn_info.pltgot and got_entries and data_seg_idx != -1:
            s = _Shdr()
            s.sh_name = _shstr_index(b".got.plt")
            s.sh_type = SHT_PROGBITS
            s.sh_addr = dyn_info.pltgot
            s.sh_offset = _data_vaddr_to_offset(dyn_info.pltgot)
            s.sh_size = got_entries * ptr_size
            s.sh_flags = SHF_ALLOC | SHF_WRITE
            s.sh_addralign = ptr_size
            sections.append(s)

        # .data (after .got.plt)
        if dyn_info.pltgot and got_entries and data_seg_idx != -1:
            dp = phdrs[data_seg_idx]
            data_start = dyn_info.pltgot + got_entries * ptr_size
            data_end = dp.p_vaddr + dp.p_filesz
            if data_end > data_start:
                s = _Shdr()
                s.sh_name = _shstr_index(b".data")
                s.sh_type = SHT_PROGBITS
                s.sh_addr = data_start
                s.sh_offset = _data_vaddr_to_offset(data_start)
                s.sh_size = data_end - data_start
                s.sh_flags = SHF_ALLOC | SHF_WRITE
                s.sh_addralign = ptr_size
                sections.append(s)

    # ── 9. Fix GOT ──
    if dyn_info and not dyn_info.bind_now and got_entries > 0 and plt_addr and data_seg_idx != -1:
        dp = phdrs[data_seg_idx]
        got_file_off = dyn_info.pltgot - dp.p_vaddr + dp.p_offset

        # GOT[1] = 0, GOT[2] = 0
        for i in range(1, min(3, got_entries)):
            off = got_file_off + i * ptr_size
            if off + ptr_size <= len(output):
                output[off:off + ptr_size] = b"\x00" * ptr_size

        # Detect CET PLT: PLT[1] (at plt_addr + 0x10) starts with endbr64
        plt1_file_off = _vaddr_to_offset(plt_addr + 0x10)
        is_cet_plt = (plt1_file_off + 4 <= len(output)
                      and output[plt1_file_off:plt1_file_off + 4] == b"\xf3\x0f\x1e\xfa")

        # CET PLT: GOT → PLT[n] start (endbr64 landing pad)
        # Classic PLT: GOT → PLT[n]+6 (push stub after the jmp)
        stub_offset = 0x10 if is_cet_plt else 0x16

        for i in range(3, got_entries):
            off = got_file_off + i * ptr_size
            if off + ptr_size <= len(output):
                target = plt_addr + stub_offset + 0x10 * (i - 3)
                if is64:
                    output[off:off + ptr_size] = _p64(target)
                else:
                    output[off:off + ptr_size] = _p32(target)

        log.info("Patched %d GOT entries to point back to PLT stubs", got_entries - 3)
    elif dyn_info and dyn_info.bind_now:
        log.info("Full RELRO binary, skipping GOT reconstruction")

    # ── 10. Append shstrtab + section headers ──
    shstrtab_offset = len(output)
    output.extend(SHSTRTAB)

    # .shstrtab section header
    shstrtab_shdr = _Shdr()
    shstrtab_shdr.sh_name = _shstr_index(b".shstrtab")
    shstrtab_shdr.sh_type = SHT_STRTAB
    shstrtab_shdr.sh_offset = shstrtab_offset
    shstrtab_shdr.sh_size = len(SHSTRTAB)
    shstrtab_shdr.sh_addralign = 1
    shstrtab_idx = len(sections)
    sections.append(shstrtab_shdr)

    # Fix cross-references between section headers
    for s in sections:
        # .dynamic -> .dynstr
        if s.sh_type == SHT_DYNAMIC and dynstr_idx:
            s.sh_link = dynstr_idx
        # .dynsym -> .dynstr
        if s.sh_type == SHT_DYNSYM and dynstr_idx:
            s.sh_link = dynstr_idx
        # .gnu.hash -> .dynsym
        if s.sh_type == SHT_GNU_HASH and dynsym_idx:
            s.sh_link = dynsym_idx
        # .gnu.version -> .dynsym
        if s.sh_type == SHT_GNU_versym and dynsym_idx:
            s.sh_link = dynsym_idx
        # .gnu.version_r -> .dynstr
        if s.sh_type == SHT_GNU_verneed and dynstr_idx:
            s.sh_link = dynstr_idx
        # relocation sections -> .dynsym
        if s.sh_type in (SHT_REL, SHT_RELA) and dynsym_idx:
            s.sh_link = dynsym_idx

    # Fix relocation section sh_info to point to .plt
    if plt_shdr_idx:
        for s in sections:
            if s.sh_type in (SHT_REL, SHT_RELA) and b".plt" in SHSTRTAB[s.sh_name:s.sh_name+10]:
                s.sh_info = plt_shdr_idx

    shdr_offset = len(output)
    shdr_size = _Shdr.SIZE_64 if is64 else _Shdr.SIZE_32

    for s in sections:
        output.extend(s.pack(is64))

    # ── 11. Patch ELF header ──
    if is64:
        # e_shoff
        output[40:48] = _p64(shdr_offset)
        # e_shnum
        output[60:62] = _p16(len(sections))
        # e_shstrndx
        output[62:64] = _p16(shstrtab_idx)
        # e_shentsize
        output[58:60] = _p16(shdr_size)
    else:
        output[32:36] = _p32(shdr_offset)
        output[48:50] = _p16(len(sections))
        output[50:52] = _p16(shstrtab_idx)
        output[46:48] = _p16(shdr_size)

    log.success("Reconstructed ELF with %d sections (%d bytes)", len(sections), len(output))

    return bytes(output)
