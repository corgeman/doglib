import re
from pwn import *

class DWARFEnum:
    """
    Provides named access to enum constants from DWARF debug info.
    Supports attribute access, 'in' checks, and iteration.
    """
    def __init__(self, elf, type_die_offset):
        self._elf = elf
        self._type_die_offset = type_die_offset
        self._constants = {}
        dwarfinfo = elf._get_dwarfinfo()
        die = dwarfinfo.get_DIE_from_refaddr(type_die_offset)
        die = elf._unwrap_type(die)
        if die and die.tag == 'DW_TAG_enumeration_type':
            for child in die.iter_children():
                if child.tag == 'DW_TAG_enumerator':
                    name_attr = child.attributes.get('DW_AT_name')
                    val_attr = child.attributes.get('DW_AT_const_value')
                    if name_attr and val_attr:
                        self._constants[name_attr.value.decode('utf-8')] = val_attr.value

    def __getattr__(self, name):
        if name.startswith('__') and name.endswith('__'):
            raise AttributeError(name)
        if name in self._constants:
            return self._constants[name]
        raise AttributeError(f"Enum constant '{name}' not found")

    def __contains__(self, name):
        return name in self._constants

    def __iter__(self):
        return iter(self._constants.items())

    def __repr__(self):
        return f"<DWARFEnum {self._constants}>"

