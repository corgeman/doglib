from pwn import *

# use amd64 as default arch instead of i386
from pwnlib.context import ContextType as _ContextType
_ContextType.defaults['arch'] = 'amd64'
_ContextType.defaults['bits'] = 64

from doglib.misc import *
from doglib.heap import *
from doglib.io_file import *
from doglib.muney import *
from doglib.ezrop import *
from doglib.asm import *
from doglib.pow import *
from doglib.log import *
from doglib.dumpelf import *
from doglib.orc import *
from doglib.packer import *
from doglib.rand import *
from doglib.fmt import *
from doglib.flagguesser import *
from doglib.brute import *
import doglib.shellcode as shellcode

import doglib._hijack


# ctypes imports are explicit since they use gcc
from doglib import orc as _orc
def __getattr__(name):
    if name in ("C", "C32", "C64"):
        return getattr(_orc, name)
    raise AttributeError(name)
