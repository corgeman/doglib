"""
Assembly/disassembly functions because pwntools is freakishly slow.

Arch names match pwntools' ``context.arch`` values where supported.

Usage::

    from doglib.asm import kasm, cdis

    kasm.amd64("nop; ret")
    cdis.arm(shellcode_bytes)
"""
from pwnlib.context import context as _ctx


# Each entry: (keystone arch, keystone mode(s), capstone arch, capstone mode(s))
# Mode can be a single string or a tuple of strings OR'd together at call time.
_ARCHES = {
    "amd64":   ("KS_ARCH_X86",   "KS_MODE_64",
                "CS_ARCH_X86",   "CS_MODE_64"),
    "i386":    ("KS_ARCH_X86",   "KS_MODE_32",
                "CS_ARCH_X86",   "CS_MODE_32"),
    "arm":     ("KS_ARCH_ARM",   "KS_MODE_ARM",
                "CS_ARCH_ARM",   "CS_MODE_ARM"),
    "thumb":   ("KS_ARCH_ARM",   "KS_MODE_THUMB",
                "CS_ARCH_ARM",   "CS_MODE_THUMB"),
    "aarch64": ("KS_ARCH_ARM64", "KS_MODE_LITTLE_ENDIAN",
                "CS_ARCH_ARM64", "CS_MODE_ARM"),
    "mips":    ("KS_ARCH_MIPS",  ("KS_MODE_MIPS32", "KS_MODE_BIG_ENDIAN"),
                "CS_ARCH_MIPS",  ("CS_MODE_MIPS32", "CS_MODE_BIG_ENDIAN")),
    "mipsel":  ("KS_ARCH_MIPS",  ("KS_MODE_MIPS32", "KS_MODE_LITTLE_ENDIAN"),
                "CS_ARCH_MIPS",  ("CS_MODE_MIPS32", "CS_MODE_LITTLE_ENDIAN")),
    "powerpc": ("KS_ARCH_PPC",   ("KS_MODE_PPC32",  "KS_MODE_BIG_ENDIAN"),
                "CS_ARCH_PPC",   ("CS_MODE_32",      "CS_MODE_BIG_ENDIAN")),
    "sparc":   ("KS_ARCH_SPARC", ("KS_MODE_SPARC32", "KS_MODE_BIG_ENDIAN"),
                "CS_ARCH_SPARC", "CS_MODE_BIG_ENDIAN"),
    "riscv32": ("KS_ARCH_RISCV", "KS_MODE_RISCV32",
                "CS_ARCH_RISCV", "CS_MODE_RISCV32"),
    "riscv64": ("KS_ARCH_RISCV", "KS_MODE_RISCV64",
                "CS_ARCH_RISCV", "CS_MODE_RISCV64"),
}


def _mode(mod, spec):
    if isinstance(spec, tuple):
        result = 0
        for name in spec:
            result |= getattr(mod, name)
        return result
    return getattr(mod, spec)


def _make_asm(ks_arch, ks_mode):
    def fn(code: str) -> bytes:
        import keystone as _ks
        encoding, _ = _ks.Ks(getattr(_ks, ks_arch), _mode(_ks, ks_mode)).asm(code)
        return bytes(encoding)
    return fn


def _make_dis(cs_arch, cs_mode):
    def fn(code: bytes, addr: int = 0) -> str:
        import capstone as _cs
        md = _cs.Cs(getattr(_cs, cs_arch), _mode(_cs, cs_mode))
        return "\n".join(f"{i.mnemonic} {i.op_str};" for i in md.disasm(code, addr))
    return fn


class _AsmDis:
    def __init__(self, make_fn, start: int):
        self._make = make_fn
        self._start = start
        self._cache: dict = {}

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in _ARCHES:
            raise AttributeError(f"No arch {name!r}. Available: {list(_ARCHES)}")
        if name not in self._cache:
            entry = _ARCHES[name]
            self._cache[name] = self._make(entry[self._start], entry[self._start + 1])
        return self._cache[name]
    
    def __getitem__(self, name: str):
        return self.__getattr__(name)

    def __call__(self, *args, **kwargs):
        return self[_ctx.arch](*args, **kwargs)

    def __repr__(self):
        return f"{self.__class__.__name__}(arches={list(_ARCHES)})"


kasm = _AsmDis(_make_asm, 0)
cdis = _AsmDis(_make_dis, 2)

__all__ = ["kasm", "cdis"]
