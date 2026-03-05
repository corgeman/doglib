from ._address import DWARFAddress, DWARFArray
from ._enum import DWARFEnum
from ._crafter import DWARFCrafter, DWARFArrayCrafter
from ._elf import ExtendedELF, CHeader, _CVarAccessor
from ._ctypes import CTypes

# Lazy singleton instances of CTypes for the three common bit widths.
# Access as:  from doglib.extelf import C64
# or:         import doglib.extelf; doglib.extelf.C64
_CTYPES_SINGLETONS = {}


def __getattr__(name):
    if name in ('C', 'C32', 'C64'):
        inst = _CTYPES_SINGLETONS.get(name)
        if inst is None:
            if name == 'C':
                inst = CTypes()
            elif name == 'C32':
                inst = CTypes(bits=32)
            else:  # 'C64'
                inst = CTypes(bits=64)
            _CTYPES_SINGLETONS[name] = inst
        return inst
    raise AttributeError(name)
