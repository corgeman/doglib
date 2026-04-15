# adding more methods to existing pwntools features
# feel free to merge this (or the rest of this library i don't care)
from pwnlib.tubes.tube import tube
from pwnlib.elf.elf import ELF
from pwnlib.log import getLogger
from functools import cached_property
from .orc import ORC
from .orc._sym import _CVarAccessor
from .orc._constants import va_mask
from .asm import kasm

log = getLogger(__name__)

def _get_func_name(func):
    if isinstance(func, property):
        return func.fget.__name__
    if isinstance(func, cached_property):
        return func.func.__name__
    return func.__name__

def patch(target_cls, force=False):
    def decorator(func):
        name = _get_func_name(func)
        if not force and hasattr(target_cls, name):
            raise AttributeError(
                f"patch: {target_cls.__name__} already has attribute '{name}'. "
                f"Use force=True to override."
            )
        setattr(target_cls, name, func)
        if isinstance(func, cached_property):
            func.__set_name__(target_cls, name)
        return func
    return decorator


# ---- tube -------------------------------------------------------------
@patch(tube)
def readlineafter(self, needle):
    self.readuntil(needle)
    return self.readline()

@patch(tube)
def readuntildrop(self, needle):
    return self.readuntil(needle, drop=True)

_cdelim = b':'

@patch(tube)
def sendlinecolon(self, dat):
    self.sendlineafter(_cdelim, dat)

@patch(tube)
def sendaftercolon(self, dat):
    self.sendafter(_cdelim, dat)

@patch(tube)
def sendintcolon(self, dat):
    self.sendlineafter(_cdelim, str(dat).encode())

@patch(tube)
def readlinecolon(self):
    self.readuntil(_cdelim)
    return self.readline()

@patch(tube)
def readint(self,base=0):
    return int(self.recv(),base)

@patch(tube)
def readlineint(self,base=0):
    return int(self.readline(),base)

@patch(tube)
def recvpointer(self):
    self.readuntil(b"0x")
    buf = b""
    while True:
        c = self.recv(1, timeout=0.3)
        if c not in b"0123456789abcdefABCDEF":
            if c:
                self.unrecv(c)
            break
        buf += c
    return int(buf, 16)

# shorthands
tube.sla = tube.sendlineafter
tube.sl = tube.sendline
tube.sa = tube.sendafter
tube.s = tube.send
tube.ru = tube.readuntil
tube.rl = tube.readline
tube.slc = tube.sendlinecolon
tube.sc = tube.sendaftercolon
tube.sic = tube.sendintcolon
tube.rla = tube.readlineafter
tube.rld = tube.readlinecolon
tube.rud = tube.readuntildrop
tube.ri = tube.readint
tube.rli = tube.readlineint
tube.rp = tube.recvpointer

# ---- elf -------------------------------------------------------------
@patch(ELF)
def gadget(self, asm):
    asm = kasm[self.arch](asm)
    return next(self.search(asm,executable=True))

@patch(ELF)
@property
def binsh(self):
    return next(self.search(b"/bin/sh\0"))

@patch(ELF)
@cached_property
def orc(self):
    return ORC(self.path)

@patch(ELF)
def onegadgets(self, level=100):
    import subprocess, shutil
    if shutil.which('one_gadget') is None:
        raise FileNotFoundError("one_gadget not found in PATH")
    result = subprocess.run(['one_gadget', '-r', '-l', str(int(level)), self.path], capture_output=True, text=True)
    out = result.stdout.strip()
    if not out or out.startswith('[OneGadget]'):
        raise RuntimeError(f"one_gadget failed: {out}")
    offsets = [int(x) for x in out.split()]
    if self.pie:
        offsets = [self.address + o for o in offsets]
    return offsets


# ---- orc on elf -------------------------------------------------------
@patch(ELF)
@cached_property
def o(self):
    return self.orc

@patch(ELF)
@cached_property
def sym_obj(self):
    return _CVarAccessor(self)

@patch(ELF)
@property
def symo(self):
    return self.sym_obj

@patch(ELF)
def resolve_field(self, symbol_name, field_path=None, struct_name=None):
    """
    Dynamically calculates the exact memory address of a field inside a struct/array.
    Supports multi-dimensional array paths like 'matrix[1][2]'.
    """
    base_addr = self.symbols.get(symbol_name)
    if base_addr is None:
        log.error(f"Symbol '{symbol_name}' not found in standard ELF symbol table.")

    if not field_path:
        return base_addr

    orc = self.orc
    orc._build_dwarf_cache()
    if struct_name:
        start_ref = orc._resolve_type_name(struct_name)
        if not start_ref:
            log.error(f"Struct '{struct_name}' not found in DWARF info.")
    else:
        var_ref = orc._dwarf_vars.get(symbol_name)
        if not var_ref:
            log.error(f"Variable '{symbol_name}' not found in DWARF info. Try passing struct_name explicitly.")
        var_die = orc._get_die(var_ref)
        type_die = orc._get_die_from_attr(var_die, 'DW_AT_type')
        if not type_die:
            return None
        start_ref = orc._ref(type_die)

    start_die = orc._get_die(start_ref)
    tokens = orc._tokenize_path(field_path)

    try:
        offset, _ = orc._walk_field_path(start_die, tokens)
    except ValueError as e:
        log.error(str(e))

    return (base_addr + offset) & va_mask(orc.bits)
