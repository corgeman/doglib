# from dog import * — brings in pwntools + all doglib goodies in one shot.
from pwn import *

# ── misc ────────────────────────────────────────────────────────────────────
from doglib.misc import (
    proc_maps_parser,
    ror,
    rol,
    mangle,
    demangle,
    fake_exit_function,
    setcontext,
    setcontext32,
    house_of_context,
    pack_file,
    find_libc_leak,
)

# ── heap ─────────────────────────────────────────────────────────────────────
from doglib.heap import (
    protect_ptr,
    reveal_ptr,
    Tcache,
)

# ── io_file ──────────────────────────────────────────────────────────────────
from doglib.io_file import (
    IO_FILE_plus_struct,
)

# ── muney ────────────────────────────────────────────────────────────────────
from doglib.muney import house_of_muney

# ── ezrop ────────────────────────────────────────────────────────────────────
from doglib.ezrop import quickrop

# ── asm ──────────────────────────────────────────────────────────────────────
from doglib.asm import (
    asm_x64,
    asm_x86,
    asm_arm,
    asm_arm64,
    dis_x64,
    dis_x86,
    dis_arm,
    dis_arm64,
    runcmd,
)

# ── fmt ──────────────────────────────────────────────────────────────────────
from doglib.fmt import DumpELF

# ── extelf ───────────────────────────────────────────────────────────────────
from doglib.extelf import (
    # DWARFAddress,
    # DWARFArray,
    # DWARFEnum,
    # DWARFCrafter,
    # DWARFArrayCrafter,
    ExtendedELF,
    CHeader,
    CInline,
    ExtELF,
    # CTypes,
)

# C / C32 / C64 are lazy singletons in doglib.extelf (they spin up GCC on first
# access, so we keep them lazy).  They are NOT included in "from dog import *"
# but work fine as:  from dog import C64  — or —  import dog; dog.C64
from doglib import extelf as _extelf


def __getattr__(name):
    if name in ("C", "C32", "C64"):
        return getattr(_extelf, name)
    raise AttributeError(name)
