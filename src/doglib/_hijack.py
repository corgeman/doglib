# adding more methods to existing pwntools features
# feel free to merge this (or the rest of this library i don't care)
from pwnlib.tubes.tube import tube
from pwnlib.elf.elf import ELF
from .asm import kasm

def patch(target_cls, force=False):
    def decorator(func):
        name = func.fget.__name__ if isinstance(func, property) else func.__name__
        if not force and hasattr(target_cls, name):
            raise AttributeError(
                f"patch: {target_cls.__name__} already has attribute '{name}'. "
                f"Use force=True to override."
            )
        setattr(target_cls, name, func)
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

# ---- elf -------------------------------------------------------------
@patch(ELF)
def gadget(self, asm):
    asm = kasm[self.arch](asm)
    return next(self.search(asm,executable=True))

@patch(ELF)
@property
def binsh(self):
    return next(self.search(b"/bin/sh\0"))

# maybe add extelf stuff l8r