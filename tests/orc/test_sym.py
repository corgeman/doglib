"""
Tests for _CVarAccessor error branches in _sym.py.

Covers the three KeyError paths in __getitem__:
  1. Symbol not in ELF symbol table
  2. Symbol in ELF table but no DWARF variable entry
  3. DWARF variable found but type DIE is missing (patched case)
"""
import pytest


# ============================================================
# _sym.py error branches
# ============================================================

def test_sym_obj_getitem_not_in_elf(chal_pwn_elf):
    """KeyError when name is not in ELF symbol table at all."""
    with pytest.raises(KeyError, match="not found in ELF symbol table"):
        _ = chal_pwn_elf.sym_obj['this_symbol_definitely_does_not_exist_xyzzy']


def test_sym_obj_getitem_not_in_dwarf(chal_pwn_elf):
    """KeyError when name is an ELF symbol but has no DW_TAG_variable entry.

    'main' is in the ELF symbol table as a function symbol, but the DWARF
    cache only indexes DW_TAG_variable entries, so it will not appear there.
    """
    assert 'main' in chal_pwn_elf.symbols, "challenge binary must export 'main'"
    with pytest.raises(KeyError, match="not found in DWARF info"):
        _ = chal_pwn_elf.sym_obj['main']


def test_sym_obj_getitem_missing_type_die(chal_pwn_elf, monkeypatch):
    """KeyError when DWARF variable exists but _get_die_from_attr returns None.

    This is a defensive branch that should not fire with well-formed DWARF.
    We trigger it by patching the ORC instance.
    """
    orc = chal_pwn_elf.orc
    orc._build_dwarf_cache()

    original = orc._get_die_from_attr
    monkeypatch.setattr(orc, '_get_die_from_attr', lambda *a, **kw: None)

    with pytest.raises(KeyError, match="Missing type info"):
        _ = chal_pwn_elf.sym_obj['target_sym']
