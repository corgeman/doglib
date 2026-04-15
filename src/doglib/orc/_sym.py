"""
_CVarAccessor: bridges pwntools ELF symbols with ORC DWARF type info.

Used by _hijack.py to patch sym_obj onto pwntools ELF.
"""
from ._address import DWARFAddress


class _CVarAccessor:
    """
    Provides sym_obj['name'] access on a pwntools ELF: looks up the symbol
    address from the ELF and the type layout from ORC's DWARF cache, returning
    a DWARFAddress that supports field traversal.
    """
    def __init__(self, elf):
        self._elf = elf

    def __getitem__(self, name):
        orc = self._elf.orc
        orc._build_dwarf_cache()

        base_addr = self._elf.symbols.get(name)
        if base_addr is None:
            raise KeyError(f"Symbol '{name}' not found in ELF symbol table.")

        var_ref = orc._dwarf_vars.get(name)
        if not var_ref:
            raise KeyError(f"Variable '{name}' not found in DWARF info. Does it have debug symbols?")

        var_die = orc._get_die(var_ref)
        type_die = orc._get_die_from_attr(var_die, 'DW_AT_type')

        if not type_die:
            raise KeyError(f"Missing type info for variable '{name}'.")

        return DWARFAddress(base_addr, orc, orc._ref(type_die))

    def __contains__(self, name):
        orc = self._elf.orc
        orc._build_dwarf_cache()
        return name in self._elf.symbols and name in orc._dwarf_vars
